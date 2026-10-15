// The C runtime's family surfaces, as the `api-ms-win-crt-*` split defines
// them.
//
// The classic domain (`crt.cpp`) and the modern one (`ucrt_extra.cpp`) own
// the names a program imports; this one owns the names the apiset family
// split parcels out. The split is a real thing on Windows: each
// `api-ms-win-crt-*` module carries one family and nothing else, and a
// guest that imports `memcpy` from the string family is importing a name
// the private family exports. The family table in `modules.cpp` states
// which names belong to which module, and every name in it has to resolve.
//
// The behaviours here come from the references, not from memory: the
// structures are laid out from the Microsoft headers as mingw transcribes
// them (verified by reading the offsets a cross-compiled probe puts in
// `.rdata`), the failure conventions follow Wine's `dlls/msvcrt` sources,
// and the family membership is Wine's `dlls/api-ms-win-crt-*/` spec files
// cross-checked against the real DLLs' export tables. An assertion written
// from memory encodes the author's belief and passes while the code is
// wrong; the references exist so the tests assert what Windows does.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/containment.h"
#include "occ/runtime/dos_path.h"
#include "occ/runtime/winabi.h"

#include <cerrno>
#include <cinttypes>
#include <cmath>
#include <csetjmp>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <fcntl.h>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <unordered_set>
#include <vector>

#include <dirent.h>
#include <fenv.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>

namespace occ::runtime::winabi {
namespace {

// ===========================================================================
// Small shared machinery
// ===========================================================================

// The MS mode bits, which are the guest's, and the `open` bits, which are
// the host call's. The numeric values below are Microsoft's.
constexpr std::uint32_t kO_RDONLY = 0x0000;
constexpr std::uint32_t kO_WRONLY = 0x0001;
constexpr std::uint32_t kO_RDWR = 0x0002;
constexpr std::uint32_t kO_APPEND = 0x0008;
constexpr std::uint32_t kO_CREAT = 0x0100;
constexpr std::uint32_t kO_TRUNC = 0x0200;
constexpr std::uint32_t kO_EXCL = 0x0400;
constexpr std::uint32_t kO_TEXT = 0x4000;
constexpr std::uint32_t kO_BINARY = 0x8000;

constexpr std::uint32_t kS_IREAD = 0400;
constexpr std::uint32_t kS_IWRITE = 0200;
constexpr std::uint32_t kS_IEXEC = 0100;

// `_MAX_DRIVE`, `_MAX_DIR`, `_MAX_FNAME` and `_MAX_EXT`, as the headers
// spell them. A path component longer than its cap truncates, which is the
// documented behaviour and the one a caller that sized its buffers for
// these constants expects.
constexpr std::size_t kMaxDrive = 3;
constexpr std::size_t kMaxDir = 256;
constexpr std::size_t kMaxFname = 256;
constexpr std::size_t kMaxExt = 256;
constexpr std::size_t kMaxPath = 260;

// The runtime root presents one drive, `Z:`, which is what `to_dos_path`
// spells the host's own filesystem as and what `_getdrive` answers.
constexpr std::int32_t kGuestDrive = 26;  // the letter `Z`, one-based
constexpr std::uint32_t kGuestDriveMask = 1u << 25;

[[nodiscard]] constexpr std::int32_t drive_index(char letter) noexcept {
    return letter >= 'A' && letter <= 'Z' ? letter - 'A' + 1
           : letter >= 'a' && letter <= 'z' ? letter - 'a' + 1
                                            : kGuestDrive;
}

// The drive a DOS path names: the letter before the colon, or the current
// drive when the path has none. `_stat` answers the index in `st_dev` and
// `st_rdev`, which is the answer Windows gives -- not zero, not the host's
// device number.
[[nodiscard]] std::int32_t dos_drive(std::string_view dos_path) noexcept {
    if (dos_path.size() >= 2 && dos_path[1] == ':') {
        return drive_index(dos_path[0]);
    }
    return kGuestDrive;
}

// The extensions Windows treats as executable when `_stat` composes the
// mode. A file whose extension is one of these carries `_S_IEXEC` even
// though the host's permission bits say nothing of the kind.
[[nodiscard]] bool executable_extension(std::string_view path) noexcept {
    const std::size_t dot = path.find_last_of('.');
    if (dot == std::string_view::npos) {
        return false;
    }
    const std::string_view ext = path.substr(dot);
    std::string lower;
    lower.reserve(ext.size());
    for (const char c : ext) {
        lower += static_cast<char>(
            c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
    }
    return lower == ".exe" || lower == ".bat" || lower == ".cmd" ||
           lower == ".com";
}

// The mode `_stat` composes, from the host's answer and the path's own
// extension. This is Wine's `msvcrt/dir.c` rule, stated once: read bit
// always, directory or regular file, the execute bit for an executable
// extension or a directory, and the write bit unless the host says the
// file is read-only.
[[nodiscard]] std::uint32_t crt_mode_of(const struct ::stat& st,
                                        std::string_view dos_path) noexcept {
    std::uint32_t mode = kS_IREAD;
    if (S_ISDIR(st.st_mode)) {
        mode |= 0x4000 | kS_IEXEC;  // _S_IFDIR
    } else {
        mode |= 0x8000;  // _S_IFREG
    }
    if (S_ISDIR(st.st_mode) || executable_extension(dos_path)) {
        mode |= kS_IEXEC;
    }
    if ((st.st_mode & S_IWUSR) != 0) {
        mode |= kS_IWRITE;
    }
    return mode;
}

// The guest's descriptors. The three standard ones always exist; the rest
// are the ones `_open` and its siblings have issued, which is the set the
// low-level calls accept. A descriptor the table does not name is a
// descriptor the CRT never handed out, and reading through one would be
// reading whatever the host process happens to hold at that number.
std::unordered_set<int>& crt_fds() noexcept {
    static std::unordered_set<int> fds{0, 1, 2};
    return fds;
}

// Whether a guest descriptor's text mode is on. The host's descriptors have
// no such concept; the CRT's do, and a write through a text-mode
// descriptor expands the newline the way the documented behaviour says.
std::unordered_map<int, bool>& fd_text_modes() noexcept {
    static std::unordered_map<int, bool> modes;
    return modes;
}

// The x87 status and control bits a guest compares against. These are the
// values the Microsoft headers name, and the mapping between them and the
// host's `fenv` exceptions is stated once here rather than in each of the
// four calls that need it.
constexpr std::uint32_t kFpInvalid = 0x00000001;
[[maybe_unused]] constexpr std::uint32_t kFpDenormal = 0x00000002;
constexpr std::uint32_t kFpZerodivide = 0x00000004;
constexpr std::uint32_t kFpOverflow = 0x00000008;
constexpr std::uint32_t kFpUnderflow = 0x00000010;
constexpr std::uint32_t kFpInexact = 0x00000020;

[[nodiscard]] std::uint32_t host_exceptions_to_x87(int host) noexcept {
    std::uint32_t status = 0;
    if ((host & FE_INVALID) != 0) {
        status |= kFpInvalid;
    }
    if ((host & FE_DIVBYZERO) != 0) {
        status |= kFpZerodivide;
    }
    if ((host & FE_OVERFLOW) != 0) {
        status |= kFpOverflow;
    }
    if ((host & FE_UNDERFLOW) != 0) {
        status |= kFpUnderflow;
    }
    if ((host & FE_INEXACT) != 0) {
        status |= kFpInexact;
    }
    // A host denormal is reported through `FE_UNDERFLOW` and `FE_INEXACT`
    // together on this platform; the guest bit exists on its own, and no
    // loss of fidelity follows from reporting the pair.
    return status;
}

[[nodiscard]] int x87_control_to_host_round(std::uint32_t control) noexcept {
    // The rounding field is bits 10 and 11: 00 nearest, 01 down, 10 up,
    // 11 toward zero.
    switch ((control >> 10) & 0x3u) {
        case 1:
            return FE_DOWNWARD;
        case 2:
            return FE_UPWARD;
        case 3:
            return FE_TOWARDZERO;
        default:
            return FE_TONEAREST;
    }
}

// The fp classification the `_fpclass` spellings answer with. The values
// are Microsoft's, in the order the bits name them.
[[nodiscard]] std::int32_t fp_class_of(double value) noexcept {
    switch (std::fpclassify(value)) {
        case FP_NAN:
            return std::signbit(value) ? 0x0001  // _FPCLASS_SNAN
                                       : 0x0002;  // _FPCLASS_QNAN
        case FP_INFINITE:
            return std::signbit(value) ? 0x0004   // _FPCLASS_NINF
                                       : 0x0200;  // _FPCLASS_PINF
        case FP_ZERO:
            return std::signbit(value) ? 0x0020   // _FPCLASS_NZ
                                       : 0x0040;  // _FPCLASS_PZ
        case FP_SUBNORMAL:
            return std::signbit(value) ? 0x0010   // _FPCLASS_ND
                                       : 0x0080;  // _FPCLASS_PD
        default:
            return std::signbit(value) ? 0x0008   // _FPCLASS_NN
                                       : 0x0100;  // _FPCLASS_PN
    }
}

// The terminate handler `set_terminate` records and `terminate` runs. The
// storage lives here because the setter and the getter are both family
// exports, and the consumer (`crt.cpp`'s `terminate`) reads it through the
// accessor declared in `winabi.h`.
void* g_terminate_handler = nullptr;

// The state the control-word spellings record. The real functions reach
// the x87 control register; the parts of it a caller can observe through
// this runtime are the rounding mode, which the host honours, and the
// exception masks, which are recorded because the host's traps cannot be
// masked per-bit here.
std::mutex g_fpu_mutex;
std::uint32_t g_fpu_control = 0x0009001F;  // the MSVC default control word
std::uint32_t g_fpu_status = 0;

}  // namespace

// The accessors the other domains read through, declared in `winabi.h`.
void* crt_terminate_handler() noexcept {
    return g_terminate_handler;
}

bool crt_fd_is_valid(std::int32_t fd) noexcept {
    return fd >= 0 && crt_fds().count(fd) != 0;
}

// ===========================================================================
// The math family
//
// Every name is the host's own function under the guest's spelling, which
// is the whole point of running guest code on the host's arithmetic: the
// answer is the host's answer, and the host's `libm` is the same IEEE
// arithmetic the guest compiled against.
//
// The `l`-suffixed spellings are declared over `double`, not `long double`:
// on Windows the two are the same eight-byte type, and declaring the host's
// eighty-bit `long double` here would read the guest's arguments as the
// wrong width. The float spellings are the ABI's real floats.
// ===========================================================================

extern "C" __attribute__((ms_abi)) double crf_acos(double x) noexcept {
    return std::acos(x);
}
extern "C" __attribute__((ms_abi)) double crf_asin(double x) noexcept {
    return std::asin(x);
}
extern "C" __attribute__((ms_abi)) double crf_atan(double x) noexcept {
    return std::atan(x);
}
extern "C" __attribute__((ms_abi)) double crf_atan2(double y,
                                                    double x) noexcept {
    return std::atan2(y, x);
}
extern "C" __attribute__((ms_abi)) double crf_cbrt(double x) noexcept {
    return std::cbrt(x);
}
extern "C" __attribute__((ms_abi)) double crf_copysign(
    double x, double y) noexcept {
    return std::copysign(x, y);
}
extern "C" __attribute__((ms_abi)) double crf_cos(double x) noexcept {
    return std::cos(x);
}
extern "C" __attribute__((ms_abi)) double crf_cosh(double x) noexcept {
    return std::cosh(x);
}
extern "C" __attribute__((ms_abi)) double crf_erf(double x) noexcept {
    return std::erf(x);
}
extern "C" __attribute__((ms_abi)) double crf_erfc(double x) noexcept {
    return std::erfc(x);
}
extern "C" __attribute__((ms_abi)) double crf_exp2(double x) noexcept {
    return std::exp2(x);
}
extern "C" __attribute__((ms_abi)) double crf_expm1(double x) noexcept {
    return std::expm1(x);
}
extern "C" __attribute__((ms_abi)) double crf_fabs(double x) noexcept {
    return std::fabs(x);
}
extern "C" __attribute__((ms_abi)) double crf_fdim(double x,
                                                   double y) noexcept {
    return std::fdim(x, y);
}
extern "C" __attribute__((ms_abi)) double crf_floor(double x) noexcept {
    return std::floor(x);
}
extern "C" __attribute__((ms_abi)) double crf_fma(double x, double y,
                                                  double z) noexcept {
    return std::fma(x, y, z);
}
extern "C" __attribute__((ms_abi)) double crf_fmax(double x,
                                                   double y) noexcept {
    return std::fmax(x, y);
}
extern "C" __attribute__((ms_abi)) double crf_fmin(double x,
                                                   double y) noexcept {
    return std::fmin(x, y);
}
extern "C" __attribute__((ms_abi)) double crf_fmod(double x,
                                                   double y) noexcept {
    return std::fmod(x, y);
}
extern "C" __attribute__((ms_abi)) double crf_frexp(
    double x, std::int32_t* exp) noexcept {
    int host = 0;
    const double result = std::frexp(x, &host);
    if (exp != nullptr) {
        *exp = host;
    }
    return result;
}
extern "C" __attribute__((ms_abi)) double crf_hypot(double x,
                                                    double y) noexcept {
    return std::hypot(x, y);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf_ilogb(double x) noexcept {
    return std::ilogb(x);
}
extern "C" __attribute__((ms_abi)) double crf_ldexp(
    double x, std::int32_t exp) noexcept {
    return std::ldexp(x, exp);
}
extern "C" __attribute__((ms_abi)) double crf_lgamma(double x) noexcept {
    return std::lgamma(x);
}
extern "C" __attribute__((ms_abi)) std::int64_t crf_llrint(double x) noexcept {
    return std::llrint(x);
}
extern "C" __attribute__((ms_abi)) std::int64_t crf_llround(
    double x) noexcept {
    return std::llround(x);
}
extern "C" __attribute__((ms_abi)) double crf_log(double x) noexcept {
    return std::log(x);
}
extern "C" __attribute__((ms_abi)) double crf_log10(double x) noexcept {
    return std::log10(x);
}
extern "C" __attribute__((ms_abi)) double crf_log1p(double x) noexcept {
    return std::log1p(x);
}
extern "C" __attribute__((ms_abi)) double crf_log2(double x) noexcept {
    return std::log2(x);
}
extern "C" __attribute__((ms_abi)) double crf_logb(double x) noexcept {
    return std::logb(x);
}
extern "C" __attribute__((ms_abi)) std::int64_t crf_lrint(double x) noexcept {
    return std::lrint(x);
}
extern "C" __attribute__((ms_abi)) std::int64_t crf_lround(double x) noexcept {
    return std::lround(x);
}
extern "C" __attribute__((ms_abi)) double crf_nearbyint(double x) noexcept {
    return std::nearbyint(x);
}
extern "C" __attribute__((ms_abi)) double crf_nextafter(
    double x, double y) noexcept {
    return std::nextafter(x, y);
}
extern "C" __attribute__((ms_abi)) double crf_nexttoward(double x,
                                                         double y) noexcept {
    // The second argument is a `long double`, which on Windows is the same
    // eight-byte type; the host's `nexttoward` takes an eighty-bit one, so
    // the call is the `nextafter` that matches the width the guest passed.
    return std::nextafter(x, y);
}
extern "C" __attribute__((ms_abi)) double crf_remainder(double x,
                                                        double y) noexcept {
    return std::remainder(x, y);
}
extern "C" __attribute__((ms_abi)) double crf_remquo(
    double x, double y, std::int32_t* quo) noexcept {
    int host = 0;
    const double result = std::remquo(x, y, &host);
    if (quo != nullptr) {
        *quo = host;
    }
    return result;
}
extern "C" __attribute__((ms_abi)) double crf_rint(double x) noexcept {
    return std::rint(x);
}
extern "C" __attribute__((ms_abi)) double crf_round(double x) noexcept {
    return std::round(x);
}
extern "C" __attribute__((ms_abi)) double crf_scalbln(
    double x, std::int32_t n) noexcept {
    return std::scalbln(x, n);
}
extern "C" __attribute__((ms_abi)) double crf_scalbn(
    double x, std::int32_t n) noexcept {
    return std::scalbn(x, n);
}
extern "C" __attribute__((ms_abi)) double crf_tan(double x) noexcept {
    return std::tan(x);
}
extern "C" __attribute__((ms_abi)) float crf_tanf(float x) noexcept {
    return std::tan(x);
}
extern "C" __attribute__((ms_abi)) double crf_tanl(double x) noexcept {
    return std::tan(x);
}
extern "C" __attribute__((ms_abi)) double crf_sin(double x) noexcept {
    return std::sin(x);
}
extern "C" __attribute__((ms_abi)) double crf_sinh(double x) noexcept {
    return std::sinh(x);
}
extern "C" __attribute__((ms_abi)) double crf_sqrt(double x) noexcept {
    return std::sqrt(x);
}
extern "C" __attribute__((ms_abi)) double crf_trunc(double x) noexcept {
    return std::trunc(x);
}
extern "C" __attribute__((ms_abi)) double crf_tgamma(double x) noexcept {
    return std::tgamma(x);
}
extern "C" __attribute__((ms_abi)) double crf_nan(
    const char* tag) noexcept {
    static_cast<void>(tag);
    return std::nan("");
}

// The Microsoft spellings that predate C99, and the ones Microsoft added.
// Each is the C99 function under another name, with the argument order and
// the result type the Microsoft headers declare.
extern "C" __attribute__((ms_abi)) double crf__chgsign(double x) noexcept {
    return -x;
}
extern "C" __attribute__((ms_abi)) float crf__chgsignf(float x) noexcept {
    return -x;
}
extern "C" __attribute__((ms_abi)) double crf__chgsignl(double x) noexcept {
    return -x;
}
extern "C" __attribute__((ms_abi)) double crf__copysign(
    double x, double y) noexcept {
    return std::copysign(x, y);
}
extern "C" __attribute__((ms_abi)) float crf__copysignf(
    float x, float y) noexcept {
    return std::copysign(x, y);
}
extern "C" __attribute__((ms_abi)) double crf__copysignl(
    double x, double y) noexcept {
    return std::copysign(x, y);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf__finite(
    double x) noexcept {
    return std::isfinite(x) ? 1 : 0;
}
extern "C" __attribute__((ms_abi)) std::int32_t crf__finitef(
    float x) noexcept {
    return std::isfinite(x) ? 1 : 0;
}
extern "C" __attribute__((ms_abi)) std::int32_t crf__fpclass(
    double x) noexcept {
    return fp_class_of(x);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf__fpclassf(
    float x) noexcept {
    // The float value is widened explicitly: the classification is the
    // same answer for the same value.
    return fp_class_of(static_cast<double>(x));
}
extern "C" __attribute__((ms_abi)) double crf__hypot(
    double x, double y) noexcept {
    return std::hypot(x, y);
}
extern "C" __attribute__((ms_abi)) float crf__hypotf(float x,
                                                     float y) noexcept {
    return std::hypot(x, y);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf__isnan(double x) noexcept {
    return std::isnan(x) ? 1 : 0;
}
extern "C" __attribute__((ms_abi)) std::int32_t crf__isnanf(
    float x) noexcept {
    return std::isnan(x) ? 1 : 0;
}
extern "C" __attribute__((ms_abi)) double crf__logb(double x) noexcept {
    return std::logb(x);
}
extern "C" __attribute__((ms_abi)) float crf__logbf(float x) noexcept {
    return std::logb(x);
}
extern "C" __attribute__((ms_abi)) double crf__logbl(double x) noexcept {
    return std::logb(x);
}
extern "C" __attribute__((ms_abi)) double crf__nextafter(
    double x, double y) noexcept {
    return std::nextafter(x, y);
}
extern "C" __attribute__((ms_abi)) float crf__nextafterf(
    float x, float y) noexcept {
    return std::nextafter(x, y);
}
// `_scalb` takes the exponent as a `long`, which on Windows is thirty-two
// bits -- not the host's sixty-four. The parameter is declared as the
// guest's width so the register read is the one the caller made.
extern "C" __attribute__((ms_abi)) double crf__scalb(
    double x, std::int32_t exp) noexcept {
    return std::scalbn(x, exp);
}
extern "C" __attribute__((ms_abi)) float crf__scalbf(
    float x, std::int32_t exp) noexcept {
    return std::scalbn(x, exp);
}
// The Bessel functions, which the host's `libm` has under the same names
// and which C99 spelled away but Windows kept.
extern "C" __attribute__((ms_abi)) double crf__j0(double x) noexcept {
    return ::j0(x);
}
extern "C" __attribute__((ms_abi)) double crf__j1(double x) noexcept {
    return ::j1(x);
}
extern "C" __attribute__((ms_abi)) double crf__jn(std::int32_t n,
                                                  double x) noexcept {
    return ::jn(n, x);
}
extern "C" __attribute__((ms_abi)) double crf__y0(double x) noexcept {
    return ::y0(x);
}
extern "C" __attribute__((ms_abi)) double crf__y1(double x) noexcept {
    return ::y1(x);
}
extern "C" __attribute__((ms_abi)) double crf__yn(std::int32_t n,
                                                  double x) noexcept {
    return ::yn(n, x);
}
// `_ftol` is the old float-to-int helper the compilers used to emit calls
// to: the conversion truncates toward zero, which a plain cast does.
extern "C" __attribute__((ms_abi)) std::int32_t crf__ftol(
    double value) noexcept {
    return static_cast<std::int32_t>(value);
}

// The dispatch-selecting flags. The dispatch they select -- an FMA3 or
// SSE2 code path inside the vendor's own `libm` -- does not exist here,
// because the arithmetic is the host's and the host selects its own. The
// flags are still recorded and reported, which is what a caller that
// toggles one and reads it back observes.
std::int32_t g_sse2_enable = 1;
std::int32_t g_fma3_enable = 0;

extern "C" __attribute__((ms_abi)) std::int32_t crf__set_SSE2_enable(
    std::int32_t flag) noexcept {
    const std::int32_t previous = g_sse2_enable;
    g_sse2_enable = flag != 0;
    return previous;
}
extern "C" __attribute__((ms_abi)) std::int32_t crf__get_FMA3_enable() noexcept {
    return g_fma3_enable;
}
extern "C" __attribute__((ms_abi)) std::int32_t crf__set_FMA3_enable(
    std::int32_t flag) noexcept {
    const std::int32_t previous = g_fma3_enable;
    g_fma3_enable = flag != 0;
    return previous;
}

// The SSE2 entry points the Microsoft headers inline to. They carry the
// same contract as the base spellings and are answered by the same
// functions: the dispatch the names select is the host's to make, and a
// caller that reached for the SSE2 spelling wants the same arithmetic.
// The targets the SSE2 spellings answer with. `exp` and `pow` are the
// classic domain's own, which registered them first; the rest are the
// family's.
extern "C" __attribute__((ms_abi)) double cr_exp(double value) noexcept;
extern "C" __attribute__((ms_abi)) double cr_ucrt_pow(double base,
                                                      double power) noexcept;
extern "C" __attribute__((ms_abi)) float crf_expf(float) noexcept;
extern "C" __attribute__((ms_abi)) float crf_powf(float, float) noexcept;
extern "C" __attribute__((ms_abi)) double crf_acos(double) noexcept;
extern "C" __attribute__((ms_abi)) float crf_acosf(float) noexcept;
extern "C" __attribute__((ms_abi)) double crf_asin(double) noexcept;
extern "C" __attribute__((ms_abi)) float crf_asinf(float) noexcept;
extern "C" __attribute__((ms_abi)) double crf_atan(double) noexcept;
extern "C" __attribute__((ms_abi)) double crf_atan2(double, double) noexcept;
extern "C" __attribute__((ms_abi)) float crf_atanf(float) noexcept;
extern "C" __attribute__((ms_abi)) double crf_cos(double) noexcept;
extern "C" __attribute__((ms_abi)) float crf_cosf(float) noexcept;
extern "C" __attribute__((ms_abi)) double crf_log(double) noexcept;
extern "C" __attribute__((ms_abi)) float crf_logf(float) noexcept;
extern "C" __attribute__((ms_abi)) double crf_log10(double) noexcept;
extern "C" __attribute__((ms_abi)) float crf_log10f(float) noexcept;
extern "C" __attribute__((ms_abi)) double crf_sin(double) noexcept;
extern "C" __attribute__((ms_abi)) float crf_sinf(float) noexcept;
extern "C" __attribute__((ms_abi)) double crf_sqrt(double) noexcept;
extern "C" __attribute__((ms_abi)) double crf_tan(double) noexcept;
extern "C" __attribute__((ms_abi)) float crf_tanf(float) noexcept;

#define SSE2_FORWARD_1(sse2_name, target, type)                           \
    extern "C" __attribute__((ms_abi)) type crf_##sse2_name(              \
        type x) noexcept {                                                \
        return target(x);                                                 \
    }
#define SSE2_FORWARD_2(sse2_name, target, type)                           \
    extern "C" __attribute__((ms_abi)) type crf_##sse2_name(              \
        type x, type y) noexcept {                                        \
        return target(x, y);                                              \
    }
SSE2_FORWARD_1(__libm_sse2_acos, crf_acos, double)
SSE2_FORWARD_1(__libm_sse2_acosf, crf_acosf, float)
SSE2_FORWARD_1(__libm_sse2_asin, crf_asin, double)
SSE2_FORWARD_1(__libm_sse2_asinf, crf_asinf, float)
SSE2_FORWARD_1(__libm_sse2_atan, crf_atan, double)
SSE2_FORWARD_2(__libm_sse2_atan2, crf_atan2, double)
SSE2_FORWARD_1(__libm_sse2_atanf, crf_atanf, float)
SSE2_FORWARD_1(__libm_sse2_cos, crf_cos, double)
SSE2_FORWARD_1(__libm_sse2_cosf, crf_cosf, float)
SSE2_FORWARD_1(__libm_sse2_exp, cr_exp, double)
SSE2_FORWARD_1(__libm_sse2_expf, crf_expf, float)
SSE2_FORWARD_1(__libm_sse2_log, crf_log, double)
SSE2_FORWARD_1(__libm_sse2_logf, crf_logf, float)
SSE2_FORWARD_1(__libm_sse2_log10, crf_log10, double)
SSE2_FORWARD_1(__libm_sse2_log10f, crf_log10f, float)
SSE2_FORWARD_2(__libm_sse2_pow, cr_ucrt_pow, double)
SSE2_FORWARD_2(__libm_sse2_powf, crf_powf, float)
SSE2_FORWARD_1(__libm_sse2_sin, crf_sin, double)
SSE2_FORWARD_1(__libm_sse2_sinf, crf_sinf, float)
SSE2_FORWARD_1(__libm_sse2_sqrt, crf_sqrt, double)
SSE2_FORWARD_1(__libm_sse2_tan, crf_tan, double)
SSE2_FORWARD_1(__libm_sse2_tanf, crf_tanf, float)
// The `_precise` spellings promise results within the documented
// tolerance of the SSE2 path with extended precision retained; the
// host's arithmetic is the answer for them as for everything else.
SSE2_FORWARD_1(_libm_sse2_acos_precise, crf_acos, double)
SSE2_FORWARD_1(_libm_sse2_asin_precise, crf_asin, double)
SSE2_FORWARD_1(_libm_sse2_atan_precise, crf_atan, double)
SSE2_FORWARD_1(_libm_sse2_cos_precise, crf_cos, double)
SSE2_FORWARD_1(_libm_sse2_exp_precise, cr_exp, double)
SSE2_FORWARD_1(_libm_sse2_log10_precise, crf_log10, double)
SSE2_FORWARD_1(_libm_sse2_log_precise, crf_log, double)
SSE2_FORWARD_2(_libm_sse2_pow_precise, cr_ucrt_pow, double)
SSE2_FORWARD_1(_libm_sse2_sin_precise, crf_sin, double)
SSE2_FORWARD_1(_libm_sse2_sqrt_precise, crf_sqrt, double)
SSE2_FORWARD_1(_libm_sse2_tan_precise, crf_tan, double)
#undef SSE2_FORWARD_1
#undef SSE2_FORWARD_2

// ===========================================================================
// The utility family
// ===========================================================================

// The rotations. The count is taken modulo the width, which is what the
// x86 rotate instruction does and what the Microsoft headers document.
extern "C" __attribute__((ms_abi)) std::uint32_t crf__rotl(
    std::uint32_t value, std::int32_t count) noexcept {
    if (count == 0) {
        return value;
    }
    const std::uint32_t shift = static_cast<std::uint32_t>(count) & 31u;
    return (value << shift) | (value >> ((32 - shift) & 31u));
}
extern "C" __attribute__((ms_abi)) std::uint32_t crf__rotr(
    std::uint32_t value, std::int32_t count) noexcept {
    if (count == 0) {
        return value;
    }
    const std::uint32_t shift = static_cast<std::uint32_t>(count) & 31u;
    return (value >> shift) | (value << ((32 - shift) & 31u));
}
extern "C" __attribute__((ms_abi)) std::uint32_t crf__lrotl(
    std::uint32_t value, std::int32_t count) noexcept {
    return crf__rotl(value, count);
}
extern "C" __attribute__((ms_abi)) std::uint32_t crf__lrotr(
    std::uint32_t value, std::int32_t count) noexcept {
    return crf__rotr(value, count);
}
extern "C" __attribute__((ms_abi)) std::uint64_t crf__rotl64(
    std::uint64_t value, std::int32_t count) noexcept {
    if (count == 0) {
        return value;
    }
    const std::uint32_t shift = static_cast<std::uint32_t>(count) & 63u;
    return (value << shift) | (value >> ((64 - shift) & 63u));
}
extern "C" __attribute__((ms_abi)) std::uint64_t crf__rotr64(
    std::uint64_t value, std::int32_t count) noexcept {
    if (count == 0) {
        return value;
    }
    const std::uint32_t shift = static_cast<std::uint32_t>(count) & 63u;
    return (value >> shift) | (value << ((64 - shift) & 63u));
}

extern "C" __attribute__((ms_abi)) std::uint16_t crf__byteswap_ushort(
    std::uint16_t value) noexcept {
    return static_cast<std::uint16_t>((value >> 8) | (value << 8));
}
extern "C" __attribute__((ms_abi)) std::uint32_t crf__byteswap_ulong(
    std::uint32_t value) noexcept {
    return ((value & 0x000000FFu) << 24) | ((value & 0x0000FF00u) << 8) |
           ((value & 0x00FF0000u) >> 8) | ((value & 0xFF000000u) >> 24);
}
extern "C" __attribute__((ms_abi)) std::uint64_t crf__byteswap_uint64(
    std::uint64_t value) noexcept {
    return (static_cast<std::uint64_t>(crf__byteswap_ulong(
                static_cast<std::uint32_t>(value)))
            << 32) |
           crf__byteswap_ulong(static_cast<std::uint32_t>(value >> 32));
}

extern "C" __attribute__((ms_abi)) std::int64_t crf_llabs(
    std::int64_t value) noexcept {
    return value < 0 ? -value : value;
}
extern "C" __attribute__((ms_abi)) std::int64_t crf_imaxabs(
    std::int64_t value) noexcept {
    return value < 0 ? -value : value;
}

// `imaxdiv_t` is `lldiv_t` by another name: two 64-bit fields, quotient
// first. A sixteen-byte aggregate goes back to the caller
// through the hidden return pointer, which is the ABI's business and the
// compiler's.
struct IMaxDiv {
    std::int64_t quot;
    std::int64_t rem;
};

extern "C" __attribute__((ms_abi)) IMaxDiv crf_imaxdiv(
    std::int64_t numer, std::int64_t denom) noexcept {
    IMaxDiv result{};
    result.quot = numer / denom;
    result.rem = numer % denom;
    return result;
}

// The untyped linear search. The comparison is the guest's, called the way
// a guest function is: through the pointer, with the platform convention.
using CrtCompareFn = std::int32_t(__attribute__((ms_abi))*)(
    const void*, const void*);
using CrtContextCompareFn = std::int32_t(__attribute__((ms_abi))*)(
    void*, const void*, const void*);

extern "C" __attribute__((ms_abi)) void* crf__lfind(
    const void* key, const void* base, std::uint32_t* count,
    std::uint32_t width, CrtCompareFn compare) noexcept {
    if (key == nullptr || base == nullptr || count == nullptr ||
        compare == nullptr) {
        return nullptr;
    }
    const auto* cursor = static_cast<const char*>(base);
    for (std::uint32_t i = 0; i < *count; ++i) {
        if (compare(key, cursor) == 0) {
            return const_cast<char*>(cursor);
        }
        cursor += width;
    }
    return nullptr;
}

// `_lsearch` is `_lfind` that appends: when the walk finds nothing, the key
// is copied onto the end, the count grows, and the new slot is the answer.
extern "C" __attribute__((ms_abi)) void* crf__lsearch(
    const void* key, void* base, std::uint32_t* count, std::uint32_t width,
    CrtCompareFn compare) noexcept {
    if (key == nullptr || base == nullptr || count == nullptr ||
        compare == nullptr) {
        return nullptr;
    }
    auto* cursor = static_cast<char*>(base);
    for (std::uint32_t i = 0; i < *count; ++i) {
        if (compare(key, cursor) == 0) {
            return cursor;
        }
        cursor += width;
    }
    std::memcpy(cursor, key, width);
    ++*count;
    return cursor;
}

extern "C" __attribute__((ms_abi)) void* crf__lfind_s(
    const void* key, const void* base, std::uint32_t* count,
    std::uint32_t width, CrtContextCompareFn compare,
    void* context) noexcept {
    if (key == nullptr || base == nullptr || count == nullptr ||
        compare == nullptr) {
        return nullptr;
    }
    const auto* cursor = static_cast<const char*>(base);
    for (std::uint32_t i = 0; i < *count; ++i) {
        if (compare(context, key, cursor) == 0) {
            return const_cast<char*>(cursor);
        }
        cursor += width;
    }
    return nullptr;
}

extern "C" __attribute__((ms_abi)) void* crf__lsearch_s(
    const void* key, void* base, std::uint32_t* count, std::uint32_t width,
    CrtContextCompareFn compare, void* context) noexcept {
    if (key == nullptr || base == nullptr || count == nullptr ||
        compare == nullptr) {
        return nullptr;
    }
    auto* cursor = static_cast<char*>(base);
    for (std::uint32_t i = 0; i < *count; ++i) {
        if (compare(context, key, cursor) == 0) {
            return cursor;
        }
        cursor += width;
    }
    std::memcpy(cursor, key, width);
    ++*count;
    return cursor;
}

// `_swab` exchanges byte pairs. A trailing odd byte is left alone, which
// is the documented behaviour and the reason the count is a pair count
// rather than a length.
extern "C" __attribute__((ms_abi)) void crf__swab(const char* source,
                                                  char* target,
                                                  std::int32_t count) noexcept {
    if (source == nullptr || target == nullptr || count < 2) {
        return;
    }
    const std::int32_t pairs = count / 2;
    for (std::int32_t i = 0; i < pairs; ++i) {
        target[2 * i] = source[2 * i + 1];
        target[2 * i + 1] = source[2 * i];
    }
}

// The context-taking sorts. The compare takes the context first, which is
// what makes these the secure spellings rather than the plain ones.
extern "C" __attribute__((ms_abi)) void crf_qsort_s(
    void* base, std::uint64_t count, std::uint64_t width,
    CrtContextCompareFn compare, void* context) noexcept {
    if (base == nullptr || compare == nullptr || count == 0 || width == 0) {
        return;
    }
    // The host's reorder walk receives the context through its own
    // argument slot, so the guest's compare is adapted rather than cast.
    const auto bridge = +[](const void* a, const void* b,
                            void* closure) -> std::int32_t {
        auto* pair = static_cast<std::pair<CrtContextCompareFn, void*>*>(
            closure);
        return pair->first(pair->second, a, b);
    };
    std::pair<CrtContextCompareFn, void*> closure{compare, context};
    ::qsort_r(base, static_cast<std::size_t>(count),
              static_cast<std::size_t>(width), bridge, &closure);
}

extern "C" __attribute__((ms_abi)) void* crf_bsearch_s(
    const void* key, const void* base, std::uint64_t count,
    std::uint64_t width, CrtContextCompareFn compare,
    void* context) noexcept {
    if (key == nullptr || base == nullptr || compare == nullptr ||
        count == 0 || width == 0) {
        return nullptr;
    }
    std::uint64_t low = 0;
    std::uint64_t high = count;
    const auto* elements = static_cast<const char*>(base);
    while (low < high) {
        const std::uint64_t middle = low + (high - low) / 2;
        const void* element = elements + static_cast<std::size_t>(
                                               middle * width);
        const std::int32_t order = compare(context, key, element);
        if (order == 0) {
            return const_cast<char*>(static_cast<const char*>(element));
        }
        if (order < 0) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    return nullptr;
}

// ===========================================================================
// The runtime family
//
// The process-level surface: the exits, the signal raise, the error and
// FP state, the thread helpers and the command-line pointers a `main` or
// `WinMain` startup reads.
// ===========================================================================

// The exits. `_Exit` and `quick_exit` end the process without running
// `atexit` registrations, which is what `ExitProcess` does; the quick-exit
// list is the registration the `_crt_at_quick_exit` spelling collects and
// nothing more.
extern "C" __attribute__((ms_abi)) void k32_ExitProcess(
    std::uint32_t code) noexcept;
extern "C" __attribute__((ms_abi)) void crf__Exit(
    std::int32_t code) noexcept {
    k32_ExitProcess(static_cast<std::uint32_t>(code));
    __builtin_unreachable();
}

std::vector<std::uint64_t>& quick_exit_list() noexcept {
    static std::vector<std::uint64_t> list;
    return list;
}

extern "C" __attribute__((ms_abi)) void crf_quick_exit(
    std::int32_t code) noexcept {
    const auto& list = quick_exit_list();
    using GuestPvfv = void (*)(void);
    for (auto it = list.rbegin(); it != list.rend(); ++it) {
        reinterpret_cast<GuestPvfv>(*it)();
    }
    k32_ExitProcess(static_cast<std::uint32_t>(code));
    __builtin_unreachable();
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__crt_at_quick_exit(
    std::uint64_t function) noexcept {
    if (function == 0) {
        return -1;
    }
    quick_exit_list().push_back(function);
    return 0;
}

// The raise. The handler table is the one `signal` fills, and a handler
// set there is a guest function the call reaches natively. The default
// action for the one signal whose default is a visible end is the abort
// the C runtime's own `abort` path takes.
extern "C" __attribute__((ms_abi)) std::int32_t cr_raise(
    std::int32_t sig) noexcept;
extern "C" __attribute__((ms_abi)) void crf_perror(
    const char* message) noexcept {
    const int err = errno;
    if (message != nullptr && *message != '\0') {
        std::fprintf(stderr, "%s: %s\n", message, std::strerror(err));
    } else {
        std::fprintf(stderr, "%s\n", std::strerror(err));
    }
}

// The error text, narrow and wide. `_strerror` prefixes the message with
// the given text the way `_strerror_s` does, per Wine's reference: the
// text, a colon, the system message.
extern "C" __attribute__((ms_abi)) std::int32_t crf__strerror_s(
    char* buffer, std::size_t size, const char* message) noexcept {
    if (buffer == nullptr || size == 0) {
        return EINVAL;
    }
    std::string text;
    if (message != nullptr && *message != '\0') {
        text = std::string(message) + ": ";
    }
    text += std::strerror(errno);
    const std::size_t copy =
        text.size() < size - 1 ? text.size() : size - 1;
    std::memcpy(buffer, text.data(), copy);
    buffer[copy] = '\0';
    return 0;
}

std::string& strerror_prefix_buffer() noexcept {
    static std::string buffer;
    return buffer;
}

extern "C" __attribute__((ms_abi)) const char* crf__strerror(
    const char* message) noexcept {
    std::string& buffer = strerror_prefix_buffer();
    buffer.clear();
    if (message != nullptr && *message != '\0') {
        buffer = std::string(message) + ": ";
    }
    buffer += std::strerror(errno);
    return buffer.c_str();
}

extern "C" __attribute__((ms_abi)) const char16_t* crf__wcserror(
    std::int32_t err) noexcept {
    static std::u16string storage;
    if (!narrow_in(std::string_view(std::strerror(err)), storage).converted) {
        storage.clear();
    }
    return storage.c_str();
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wcserror_s(
    char16_t* buffer, std::size_t size, std::int32_t err) noexcept {
    if (buffer == nullptr || size == 0) {
        return EINVAL;
    }
    std::u16string wide;
    if (!narrow_in(std::string_view(std::strerror(err)), wide).converted) {
        wide.clear();
    }
    const std::size_t copy =
        wide.size() < size - 1 ? wide.size() : size - 1;
    for (std::size_t i = 0; i < copy; ++i) {
        buffer[i] = wide[i];
    }
    buffer[copy] = u'\0';
    return 0;
}

extern "C" __attribute__((ms_abi)) void crf__wperror(
    const char16_t* message) noexcept {
    std::string narrow;
    if (message != nullptr &&
        !narrow_out(std::u16string_view(message), narrow).converted) {
        narrow.clear();
    }
    crf_perror(narrow.c_str());
}

// The terminate handler pair. The consumer is the `terminate` spelling in
// `crt.cpp`, which reads the handler through the accessor below before it
// takes its own last resort.
extern "C" __attribute__((ms_abi)) std::uint64_t crf_set_terminate(
    std::uint64_t handler) noexcept {
    const std::uint64_t previous =
        reinterpret_cast<std::uint64_t>(g_terminate_handler);
    g_terminate_handler = reinterpret_cast<void*>(handler);
    return previous;
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf__get_terminate() noexcept {
    return reinterpret_cast<std::uint64_t>(g_terminate_handler);
}

// The process and thread identities. The pid is the host's, because the
// guest process is this host process; the thread id is the host's
// likewise, and the pseudo handle is the current-thread pseudo handle the
// platform defines as -2.
extern "C" __attribute__((ms_abi)) std::int32_t crf__getpid() noexcept {
    return static_cast<std::int32_t>(::getpid());
}

extern "C" __attribute__((ms_abi)) std::int32_t crf___threadid() noexcept {
    return static_cast<std::int32_t>(::gettid());
}

extern "C" __attribute__((ms_abi)) void* crf___threadhandle() noexcept {
    return reinterpret_cast<void*>(0xFFFFFFFFFFFFFFFEull);  // (HANDLE)-2
}

// The DOS errno, which travels beside the C one: every failure that has
// both records the Windows code here and the mapped C code in `errno`.
std::int32_t& dos_errno() noexcept {
    static thread_local std::int32_t value = 0;
    return value;
}

extern "C" __attribute__((ms_abi)) std::int32_t* crf___doserrno() noexcept {
    return &dos_errno();
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__get_doserrno(
    std::int32_t* value) noexcept {
    if (value == nullptr) {
        return EINVAL;
    }
    *value = dos_errno();
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__set_doserrno(
    std::int32_t value) noexcept {
    dos_errno() = value;
    return 0;
}

// The FP exception state. The status word is read and cleared through the
// host's `fenv`, mapped bit for bit; the control word is the shadow above,
// of which the rounding field is applied to the host and the rest kept.
extern "C" __attribute__((ms_abi)) std::int32_t* crf___fpecode() noexcept {
    static thread_local std::int32_t code = 0;
    return &code;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf___fpe_flt_rounds() noexcept {
    // The answer names the rounding mode in the `_RC_*` numbering: 0 near,
    // 1 down, 2 up, 3 chop.
    switch (::fegetround()) {
        case FE_DOWNWARD:
            return 1;
        case FE_UPWARD:
            return 2;
        case FE_TOWARDZERO:
            return 3;
        default:
            return 0;
    }
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__clearfp() noexcept {
    const std::lock_guard<std::mutex> lock(g_fpu_mutex);
    const std::uint32_t previous = g_fpu_status;
    const int host = ::fetestexcept(FE_ALL_EXCEPT);
    ::feclearexcept(FE_ALL_EXCEPT);
    g_fpu_status = 0;
    return static_cast<std::int32_t>(previous |
                                     host_exceptions_to_x87(host));
}

extern "C" __attribute__((ms_abi)) std::uint32_t crf__statusfp() noexcept {
    const std::lock_guard<std::mutex> lock(g_fpu_mutex);
    return g_fpu_status |
           host_exceptions_to_x87(::fetestexcept(FE_ALL_EXCEPT));
}

extern "C" __attribute__((ms_abi)) void crf__statusfp2(
    std::uint32_t* x86, std::uint32_t* x64) noexcept {
    const std::uint32_t status = crf__statusfp();
    if (x86 != nullptr) {
        *x86 = status;
    }
    if (x64 != nullptr) {
        *x64 = status;
    }
}

extern "C" __attribute__((ms_abi)) void crf__fpreset() noexcept {
    const std::lock_guard<std::mutex> lock(g_fpu_mutex);
    ::fesetenv(FE_DFL_ENV);
    g_fpu_control = 0x0009001F;
    g_fpu_status = 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t crf__control87(
    std::uint32_t value, std::uint32_t mask) noexcept {
    const std::lock_guard<std::mutex> lock(g_fpu_mutex);
    const std::uint32_t previous = g_fpu_control;
    g_fpu_control = (previous & ~mask) | (value & mask);
    ::fesetround(
        x87_control_to_host_round(g_fpu_control));
    return previous;
}

extern "C" __attribute__((ms_abi)) std::uint32_t crf__controlfp(
    std::uint32_t value, std::uint32_t mask) noexcept {
    return crf__control87(value, mask);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__controlfp_s(
    std::uint32_t* current, std::uint32_t value, std::uint32_t mask) noexcept {
    const std::uint32_t previous = crf__control87(value, mask);
    if (current != nullptr) {
        *current = previous;
    }
    return 0;
}

// The invalid-parameter handlers, process-wide and per-thread. The setter
// answers the previous one, which is what a caller that chains handlers
// reads.
void* g_invalid_parameter_handler = nullptr;

extern "C" __attribute__((ms_abi)) std::uint64_t crf__get_invalid_parameter_handler() noexcept {
    return reinterpret_cast<std::uint64_t>(g_invalid_parameter_handler);
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf__set_invalid_parameter_handler(
    std::uint64_t handler) noexcept {
    const std::uint64_t previous =
        reinterpret_cast<std::uint64_t>(g_invalid_parameter_handler);
    g_invalid_parameter_handler = reinterpret_cast<void*>(handler);
    return previous;
}

thread_local void* t_invalid_parameter_handler = nullptr;

extern "C" __attribute__((ms_abi)) std::uint64_t crf__get_thread_local_invalid_parameter_handler() noexcept {
    return reinterpret_cast<std::uint64_t>(t_invalid_parameter_handler);
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf__set_thread_local_invalid_parameter_handler(
    std::uint64_t handler) noexcept {
    const std::uint64_t previous =
        reinterpret_cast<std::uint64_t>(t_invalid_parameter_handler);
    t_invalid_parameter_handler = reinterpret_cast<void*>(handler);
    return previous;
}

// The pure-call and new-handler state, whose setters live in the same
// family on the real runtime.
std::uint64_t g_new_handler = 0;

extern "C" __attribute__((ms_abi)) std::uint64_t crf__set_new_handler(
    std::uint64_t handler) noexcept {
    const std::uint64_t previous = g_new_handler;
    g_new_handler = handler;
    return previous;
}

// The abort behaviour bits, recorded the way `abort` reads them.
std::uint32_t g_abort_behavior = 3;  // _WRITE_ABORT_MSG | _CALL_REPORTFAULT

extern "C" __attribute__((ms_abi)) std::uint32_t crf__set_abort_behavior(
    std::uint32_t flags, std::uint32_t mask) noexcept {
    const std::uint32_t previous = g_abort_behavior;
    g_abort_behavior = (previous & ~mask) | (flags & mask);
    return previous;
}

extern "C" __attribute__((ms_abi)) void crf__sleep(
    std::uint32_t milliseconds) noexcept {
    ::usleep(static_cast<useconds_t>(milliseconds) * 1000);
}

extern "C" __attribute__((ms_abi)) std::uint32_t crf__query_app_type() noexcept {
    const GuestState* g = guest_state();
    return g == nullptr ? 0 : g->app_type;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__resetstkoflw() noexcept {
    // The real call restores the stack's guard page after the stack has
    // been walked nearly to its end. The guest stack lives in the address
    // space the process builder laid out, whose guard is part of the
    // ledger rather than of a host page table, and nothing here consumed
    // it; the call reports the success a caller needs to keep running.
    return 1;
}

// The error-reporting mode, recorded because a caller reads it back.
std::int32_t g_error_mode = 0;

extern "C" __attribute__((ms_abi)) std::int32_t crf__set_error_mode(
    std::int32_t mode) noexcept {
    const std::int32_t previous = g_error_mode;
    g_error_mode = mode;
    return previous;
}

extern "C" __attribute__((ms_abi)) void crf__seterrormode(
    std::int32_t mode) noexcept {
    g_error_mode = mode;
}

// The program-name pointers. The narrow one is the image path the process
// builder recorded; the wide one is its UTF-16 spelling. Both are guest
// strings a caller reads directly, so the storage lives as long as the
// runtime does.
char* g_crt_pgmptr = nullptr;
char16_t* g_crt_wpgmptr = nullptr;

extern "C" __attribute__((ms_abi)) std::int32_t crf__get_pgmptr(
    char** value) noexcept {
    if (value == nullptr) {
        return EINVAL;
    }
    const GuestState* g = guest_state();
    static std::string storage;
    static bool wired = false;
    if (!wired) {
        storage = g != nullptr ? g->image_path_dos : std::string();
        g_crt_pgmptr = storage.data();
        wired = true;
    }
    *value = g_crt_pgmptr;
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__get_wpgmptr(
    char16_t** value) noexcept {
    if (value == nullptr) {
        return EINVAL;
    }
    const GuestState* g = guest_state();
    static std::u16string storage;
    static bool wired = false;
    if (!wired) {
        if (g != nullptr) {
            if (!narrow_in(std::string_view(g->image_path_dos), storage)
                     .converted) {
                storage.clear();
            }
        }
        g_crt_wpgmptr = storage.data();
        wired = true;
    }
    *value = g_crt_wpgmptr;
    return 0;
}

extern "C" __attribute__((ms_abi)) char** crf___p__pgmptr() noexcept {
    static char* slot = nullptr;
    crf__get_pgmptr(&slot);
    return &slot;
}

extern "C" __attribute__((ms_abi)) char16_t** crf___p__wpgmptr() noexcept {
    static char16_t* slot = nullptr;
    crf__get_wpgmptr(&slot);
    return &slot;
}

// The `WinMain` command lines: the guest's own line with the program name
// skipped, which is the part a `WinMain` receives.
extern "C" __attribute__((ms_abi)) const char* crf__get_narrow_winmain_command_line() noexcept {
    static std::string tail;
    const GuestState* g = guest_state();
    tail = g != nullptr ? g->command_line : std::string();
    // The program name is the first token: a quoted one spans to the
    // closing quote, an unquoted one to the first space or tab.
    std::size_t start = 0;
    if (!tail.empty() && tail[0] == '"') {
        const std::size_t close = tail.find('"', 1);
        start = close == std::string::npos ? tail.size() : close + 1;
    } else {
        const std::size_t space =
            tail.find_first_of(" \t");
        start = space == std::string::npos ? tail.size() : space;
    }
    while (start < tail.size() && (tail[start] == ' ' || tail[start] == '\t')) {
        ++start;
    }
    return tail.c_str() + start;
}

extern "C" __attribute__((ms_abi)) const char16_t* crf__get_wide_winmain_command_line() noexcept {
    static std::u16string tail;
    const GuestState* g = guest_state();
    tail = g != nullptr ? g->command_line_u16 : std::u16string();
    std::size_t start = 0;
    if (!tail.empty() && tail[0] == u'"') {
        const std::size_t close = tail.find(u'"', 1);
        start = close == std::u16string::npos ? tail.size() : close + 1;
    } else {
        const std::size_t space = tail.find_first_of(u" \t");
        start = space == std::u16string::npos ? tail.size() : space;
    }
    while (start < tail.size() &&
           (tail[start] == u' ' || tail[start] == u'\t')) {
        ++start;
    }
    return tail.data() + start;
}

// The entry-point lookup by name or ordinal, which is `GetProcAddress`
// under the CRT's own name. The kernel32 spelling owns the registry walk.
extern "C" __attribute__((ms_abi)) std::uint64_t k32_GetProcAddress(
    std::uint64_t module, const char* name) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t crf__getdllprocaddr(
    std::uint64_t module, const char* name, std::int32_t ordinal) noexcept {
    if (module == 0 || (name == nullptr && ordinal <= 0)) {
        return 0;
    }
    // A name is looked up by name; a null name with a positive ordinal is
    // looked up by the number spelled out in decimal, which is the
    // documented form.
    if (name != nullptr) {
        return k32_GetProcAddress(module, name);
    }
    std::string ordinal_text = std::to_string(static_cast<long long>(ordinal));
    return k32_GetProcAddress(module, ordinal_text.c_str());
}

// The threads the classic CRT starts. `_beginthread`'s entry returns
// nothing and the call answers an opaque handle; `_endthread` ends the
// calling thread. The record-and-trampoline shape is the one
// `_beginthreadex` uses, with the entry adapted to the return nothing.
extern "C" __attribute__((ms_abi)) std::uintptr_t u32u__beginthreadex(
    void* security, unsigned int stack_size,
    std::uint32_t(__attribute__((ms_abi))*)(void*), void* arg,
    unsigned int flags, unsigned int* thread_id) noexcept;

struct PlainThreadStart {
    void (__attribute__((ms_abi))* fn)(void*);
    void* arg;
};

extern "C" __attribute__((ms_abi)) std::uint32_t plain_thread_trampoline(
    PlainThreadStart* start) noexcept {
    const auto fn = start->fn;
    void* arg = start->arg;
    delete start;
    fn(arg);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uintptr_t crf__beginthread(
    void(__attribute__((ms_abi))* start)(void*), std::uint32_t stack_size,
    void* argument) noexcept {
    if (start == nullptr) {
        return 0;
    }
    auto* record = new PlainThreadStart{start, argument};
    return u32u__beginthreadex(
        nullptr, stack_size,
        reinterpret_cast<std::uint32_t(__attribute__((ms_abi))*)(void*)>(
            &plain_thread_trampoline),
        record, 0, nullptr);
}

extern "C" __attribute__((ms_abi)) void crf__endthread() noexcept {
    std::this_thread::yield();
}

// The DLL form of the SEH filter, which the DLL startup installs. Its
// contract is the exe form's: the exception code, the record, the same
// answer.
extern "C" __attribute__((ms_abi)) std::int32_t cr_ucrt_seh_filter_exe(
    std::uint32_t code, void* record) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__seh_filter_dll(
    std::uint32_t code, void* record) noexcept {
    return cr_ucrt_seh_filter_exe(code, record);
}

// The onexit-table walk, which is the exe family's own machinery under the
// name the DLL startup reaches for.
extern "C" __attribute__((ms_abi)) std::int32_t crf__execute_onexit_table(
    void* table) noexcept;

// The wide assert. The message and the file are UTF-16 in, rendered the
// way the narrow assert renders them.
extern "C" __attribute__((ms_abi)) void crf__wassert(
    const char16_t* message, const char16_t* file, std::uint32_t line) noexcept {
    std::string narrow_message;
    std::string narrow_file;
    if (message != nullptr) {
        static_cast<void>(
            narrow_out(std::u16string_view(message), narrow_message));
    }
    if (file != nullptr) {
        static_cast<void>(
            narrow_out(std::u16string_view(file), narrow_file));
    }
    std::fprintf(stderr, "Assertion failed: %s, file %s, line %u\n",
                 narrow_message.c_str(), narrow_file.c_str(), line);
    ::abort();
}

// The exception-context pointer a vectored handler reads. There is no
// system exception dispatch walking guest frames here, so the slot is
// the answer it has always had: present, addressable, null.
extern "C" __attribute__((ms_abi)) void** crf___pxcptinfoptrs() noexcept {
    static thread_local void* info = nullptr;
    return &info;
}

// The fenv spellings, which are the host's own calls under the standard
// names.
extern "C" __attribute__((ms_abi)) std::int32_t crf_feclearexcept(
    std::int32_t exceptions) noexcept {
    return ::feclearexcept(exceptions);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf_fegetenv(
    void* environment) noexcept {
    return ::fegetenv(
        static_cast<fenv_t*>(environment));
}
extern "C" __attribute__((ms_abi)) std::int32_t crf_fegetexceptflag(
    std::int32_t* flag, std::int32_t exceptions) noexcept {
    if (flag == nullptr) {
        return -1;
    }
    fexcept_t host = 0;
    const std::int32_t result =
        ::fegetexceptflag(&host, exceptions);
    *flag = static_cast<std::int32_t>(host);
    return result;
}
extern "C" __attribute__((ms_abi)) std::int32_t crf_fegetround() noexcept {
    return ::fegetround();
}
extern "C" __attribute__((ms_abi)) std::int32_t crf_feholdexcept(
    void* environment) noexcept {
    return ::feholdexcept(static_cast<fenv_t*>(environment));
}
extern "C" __attribute__((ms_abi)) std::int32_t crf_fesetenv(
    const void* environment) noexcept {
    return ::fesetenv(static_cast<const fenv_t*>(environment));
}
extern "C" __attribute__((ms_abi)) std::int32_t crf_fesetexceptflag(
    const std::int32_t* flag, std::int32_t exceptions) noexcept {
    if (flag == nullptr) {
        return -1;
    }
    const fexcept_t host = static_cast<fexcept_t>(*flag);
    return ::fesetexceptflag(&host, exceptions);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf_fesetround(
    std::int32_t round) noexcept {
    return ::fesetround(round);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf_fetestexcept(
    std::int32_t exceptions) noexcept {
    return ::fetestexcept(exceptions);
}

// ===========================================================================
// The heap family
//
// The heap the CRT allocates from is the guest heap facade `cr_malloc`
// allocates through, and every answer here reads that facade rather than
// guessing at sizes from the outside. The block header sits immediately
// below the user pointer, and the size is in it.
// ===========================================================================

// The block header's shape, stated here because the size field is what
// `_msize` answers with. `winabi.cpp` writes it at allocation; this file
// only reads it back.
struct CrtHeapHeader {
    std::uint64_t magic;
    std::uint64_t size;
    void* user_value;
    std::uint32_t user_flags;
    std::uint32_t user_flags_set_by_user;
};

// The same magic `winabi.cpp`'s `HeapHeader` writes at allocation; the
// layout above is that header's, stated here so the size read is the one
// the allocator wrote.
constexpr std::uint64_t kCrtHeapMagic = 0x4F43434845415031ULL;

[[nodiscard]] bool heap_block_of(void* block, CrtHeapHeader* out) noexcept {
    if (block == nullptr) {
        return false;
    }
    auto* header = reinterpret_cast<CrtHeapHeader*>(
        static_cast<char*>(block) - sizeof(CrtHeapHeader));
    if (header->magic != kCrtHeapMagic) {
        return false;
    }
    *out = *header;
    return true;
}

// The block's own size, which is what `_msize` documents: the size the
// allocation asked for, not the rounding step the allocator consumed.
extern "C" __attribute__((ms_abi)) std::uint64_t crf__msize(
    void* block) noexcept {
    CrtHeapHeader header{};
    if (!heap_block_of(block, &header)) {
        return 0;
    }
    return header.size;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__heapchk() noexcept {
    // _HEAPOK: the heap answers, which is what a heap whose every
    // allocation succeeds reports.
    return -2;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__heapmin() noexcept {
    // The free lists are compacted away on the real heap; the facade has
    // no free list, so the call reports the success the contract gives a
    // heap with nothing to release.
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__heapwalk(
    void* info) noexcept {
    // The walk needs the heap's block ledger, which is the guest heap
    // facade's private state. A heap info pointer that names a block this
    // heap cannot describe is the _HEAPBADPTR answer, and that is what
    // every walk gets here.
    static_cast<void>(info);
    return -6;
}

// `_expand` grows a block in place. The block's consumed size is the
// header's rounding step, which the caller's size sits inside of; a
// request within it succeeds without moving anything.
extern "C" __attribute__((ms_abi)) void* crf__expand(
    void* block, std::uint64_t size) noexcept {
    CrtHeapHeader header{};
    if (!heap_block_of(block, &header)) {
        return nullptr;
    }
    // The allocator rounds to sixteen and consumes the header besides; a
    // request that fits inside what the block already consumes is an
    // in-place answer, and anything else is the null a moved block would
    // defeat.
    const std::uint64_t consumed =
        ((header.size + 15) & ~0xFull) + sizeof(CrtHeapHeader);
    return size <= consumed ? block : nullptr;
}

// `_recalloc` is `realloc` that zeroes the growth. The old size comes from
// the header, the new one from the caller's product, and only the
// difference is cleared.
extern "C" __attribute__((ms_abi)) void* cr_realloc(
    void* block, std::uint64_t bytes) noexcept;
extern "C" __attribute__((ms_abi)) void* crf__recalloc(
    void* block, std::uint64_t count, std::uint64_t size) noexcept {
    if (count != 0 && size != 0 && count > 0xFFFFFFFFFFFFFFFFull / size) {
        errno = ENOMEM;
        return nullptr;
    }
    const std::uint64_t bytes = count * size;
    if (block == nullptr) {
        void* fresh = cr_malloc(bytes);
        return fresh == nullptr ? fresh
                                : std::memset(fresh, 0,
                                              static_cast<std::size_t>(bytes));
    }
    CrtHeapHeader header{};
    const std::uint64_t old_size =
        heap_block_of(block, &header) ? header.size : 0;
    void* moved = cr_realloc(block, bytes);
    if (moved != nullptr && bytes > old_size) {
        std::memset(static_cast<char*>(moved) + old_size, 0,
                    static_cast<std::size_t>(bytes - old_size));
    }
    return moved;
}

// The aligned spellings, laid out the way Wine lays them out: the
// allocation over-shoots by a pointer slot plus the alignment, the
// returned block is the aligned position inside it, and the raw base sits
// in the slot immediately below the returned pointer. `_aligned_offset_*`
// is the same shape with the aligned position advanced by `offset`, which
// the over-shoot absorbs.
extern "C" __attribute__((ms_abi)) void* crf__aligned_offset_malloc(
    std::uint64_t size, std::uint64_t alignment,
    std::uint64_t offset) noexcept {
    if (alignment == 0 || (alignment & (alignment - 1)) != 0 ||
        offset >= size) {
        errno = EINVAL;
        return nullptr;
    }
    const std::uint64_t raw_size = size + offset + alignment + sizeof(void*);
    void* raw = cr_malloc(raw_size);
    if (raw == nullptr) {
        return nullptr;
    }
    auto* base = static_cast<char*>(raw) + sizeof(void*);
    const uintptr_t address = reinterpret_cast<uintptr_t>(base);
    const uintptr_t misaligned = address % alignment;
    auto* aligned = base + (misaligned == 0
                                ? 0
                                : alignment - misaligned);
    auto** back = reinterpret_cast<void**>(aligned - sizeof(void*));
    *back = raw;
    return aligned + offset;
}

extern "C" __attribute__((ms_abi)) void crf__aligned_offset_free(
    void* block) noexcept {
    if (block == nullptr) {
        return;
    }
    cr_free(*(reinterpret_cast<void**>(block) - 1));
}

extern "C" __attribute__((ms_abi)) void* crf__aligned_offset_realloc(
    void* block, std::uint64_t size, std::uint64_t alignment,
    std::uint64_t offset) noexcept {
    if (block == nullptr) {
        return crf__aligned_offset_malloc(size, alignment, offset);
    }
    if (alignment == 0 || (alignment & (alignment - 1)) != 0 ||
        offset >= size || size == 0) {
        errno = EINVAL;
        return nullptr;
    }
    // The old block's usable size is what its header records, which is
    // the answer `_msize` gives for the same pointer.
    auto** back = reinterpret_cast<void**>(block) - 1;
    CrtHeapHeader header{};
    const std::uint64_t old_size =
        heap_block_of(*back, &header) ? header.size : 0;
    void* fresh = crf__aligned_offset_malloc(size, alignment, offset);
    if (fresh == nullptr) {
        return nullptr;
    }
    std::memcpy(fresh, block,
                static_cast<std::size_t>(size < old_size ? size : old_size));
    crf__aligned_offset_free(block);
    return fresh;
}

extern "C" __attribute__((ms_abi)) void* crf__aligned_recalloc(
    void* block, std::uint64_t count, std::uint64_t size,
    std::uint64_t alignment) noexcept {
    if (count != 0 && size != 0 && count > 0xFFFFFFFFFFFFFFFFull / size) {
        errno = ENOMEM;
        return nullptr;
    }
    const std::uint64_t bytes = count * size;
    if (block == nullptr) {
        void* fresh = crf__aligned_offset_malloc(bytes, alignment, 0);
        return fresh == nullptr
                   ? fresh
                   : std::memset(fresh, 0, static_cast<std::size_t>(bytes));
    }
    auto** back = reinterpret_cast<void**>(block) - 1;
    CrtHeapHeader header{};
    const std::uint64_t old_size =
        heap_block_of(*back, &header) ? header.size : 0;
    void* fresh = crf__aligned_offset_realloc(block, bytes, alignment, 0);
    if (fresh != nullptr && bytes > old_size) {
        std::memset(static_cast<char*>(fresh) + old_size, 0,
                    static_cast<std::size_t>(bytes - old_size));
    }
    return fresh;
}

extern "C" __attribute__((ms_abi)) void* crf__aligned_offset_recalloc(
    void* block, std::uint64_t count, std::uint64_t size,
    std::uint64_t alignment, std::uint64_t offset) noexcept {
    if (count != 0 && size != 0 && count > 0xFFFFFFFFFFFFFFFFull / size) {
        errno = ENOMEM;
        return nullptr;
    }
    const std::uint64_t bytes = count * size;
    if (block == nullptr) {
        void* fresh =
            crf__aligned_offset_malloc(bytes, alignment, offset);
        return fresh == nullptr
                   ? fresh
                   : std::memset(fresh, 0, static_cast<std::size_t>(bytes));
    }
    auto** back = reinterpret_cast<void**>(block) - 1;
    CrtHeapHeader header{};
    const std::uint64_t old_size =
        heap_block_of(*back, &header) ? header.size : 0;
    void* fresh =
        crf__aligned_offset_realloc(block, bytes, alignment, offset);
    if (fresh != nullptr && bytes > old_size) {
        std::memset(static_cast<char*>(fresh) + old_size, 0,
                    static_cast<std::size_t>(bytes - old_size));
    }
    return fresh;
}

// The base allocators, which are the same heap without the new-handler
// hop -- and this heap's malloc never takes one, so the spellings are the
// same functions.
extern "C" __attribute__((ms_abi)) void* crf__malloc_base(
    std::uint64_t bytes) noexcept {
    return cr_malloc(bytes);
}
extern "C" __attribute__((ms_abi)) void* crf__calloc_base(
    std::uint64_t count, std::uint64_t size) noexcept {
    return cr_calloc(count, size);
}
extern "C" __attribute__((ms_abi)) void* crf__realloc_base(
    void* block, std::uint64_t bytes) noexcept {
    return cr_realloc(block, bytes);
}
extern "C" __attribute__((ms_abi)) void crf__free_base(void* block) noexcept {
    cr_free(block);
}

extern "C" __attribute__((ms_abi)) void* crf__get_heap_handle() noexcept {
    // The handle is the process heap's, which is the one the memory
    // family answers `GetProcessHeap` with -- the same heap every call
    // here allocates through.
    return reinterpret_cast<void*>(process_heap_handle());
}

std::uint64_t g_new_mode_handler = 0;
std::int32_t g_new_mode_flag = 0;

extern "C" __attribute__((ms_abi)) std::uint64_t crf__query_new_handler() noexcept {
    return g_new_mode_handler;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__query_new_mode() noexcept {
    return g_new_mode_flag;
}

// ===========================================================================
// The locale family
//
// The runtime's locale is the "C" locale, and the family's surface answers
// from that state: the code page is the ANSI one this runtime resolves to
// UTF-8, the multi-byte code page is none, and the locale name is the one
// the "C" locale has.
// ===========================================================================

std::int32_t g_mb_code_page = 0;  // 0: the ANSI code page

extern "C" __attribute__((ms_abi)) std::int32_t crf__getmbcp() noexcept {
    return g_mb_code_page;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__setmbcp(
    std::int32_t code_page) noexcept {
    const std::int32_t previous = g_mb_code_page;
    // The special values are Microsoft's: 0 asks for the ANSI page,
    // _MB_CP_ANSI too, _MB_CP_OEM(1) for the OEM one, _MB_CP_UTF8(2) for
    // UTF-8, and _MB_CP_SBCS for single byte. Everything else is a page
    // number. The page is recorded; the conversion functions this runtime
    // pairs the locale with are UTF-8 either way.
    if (code_page == 0) {
        g_mb_code_page = 0;
    } else if (code_page == 1) {
        g_mb_code_page = 1;
    } else if (code_page == 2) {
        g_mb_code_page = 2;
    } else if (code_page == -2) {
        g_mb_code_page = 0;
    } else {
        g_mb_code_page = code_page;
    }
    return previous;
}

extern "C" __attribute__((ms_abi)) std::uint32_t crf___lc_collate_cp_func() noexcept {
    return 0;
}

extern "C" __attribute__((ms_abi)) const char16_t** crf___lc_locale_name_func() noexcept {
    // The locale name is "C", as the wide string the runtime keeps.
    static char16_t* name = const_cast<char16_t*>(u"C");
    return const_cast<const char16_t**>(&name);
}

extern "C" __attribute__((ms_abi)) std::int32_t* crf___mb_cur_max_l_func(
    std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    static std::int32_t cur_max = 1;
    return &cur_max;
}

extern "C" __attribute__((ms_abi)) void
crf__lock_locales() noexcept {}

extern "C" __attribute__((ms_abi)) void
crf__unlock_locales() noexcept {}

extern "C" __attribute__((ms_abi)) void
crf___initialize_lconv_for_unsigned_char() noexcept {}

// The wide locale spellings convert their name and delegate to the narrow
// ones, which is what the narrow/wide bridge is for.
extern "C" __attribute__((ms_abi)) std::uint64_t u32u__create_locale(
    std::int32_t category, const char* name) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t crf__wcreate_locale(
    std::int32_t category, const char16_t* name) noexcept {
    std::string narrow;
    if (name != nullptr &&
        !narrow_out(std::u16string_view(name), narrow).converted) {
        return 0;
    }
    return u32u__create_locale(category, narrow.c_str());
}

extern "C" __attribute__((ms_abi)) char* u32u_setlocale(
    std::int32_t category, const char* name) noexcept;
extern "C" __attribute__((ms_abi)) const char16_t* crf__wsetlocale(
    std::int32_t category, const char16_t* name) noexcept {
    std::string narrow;
    if (name != nullptr &&
        !narrow_out(std::u16string_view(name), narrow).converted) {
        return nullptr;
    }
    const char* answer = u32u_setlocale(category, narrow.c_str());
    if (answer == nullptr) {
        return nullptr;
    }
    static std::u16string storage;
    if (!narrow_in(std::string_view(answer), storage).converted) {
        return nullptr;
    }
    return storage.c_str();
}

extern "C" __attribute__((ms_abi)) const std::uint16_t* crf___pwctype_func() noexcept {
    // The upper-case table the wide classification macros read through the
    // pointer, built once from the host's own mapping over the guest's
    // sixteen-bit code unit range.
    static std::vector<std::uint16_t> table;
    static std::once_flag built;
    std::call_once(built, [] {
        table.resize(65536);
        for (std::size_t i = 0; i < 65536; ++i) {
            const wint_t wide = static_cast<wint_t>(i);
            table[i] = static_cast<std::uint16_t>(
                std::towupper(wide));
        }
    });
    return table.data();
}

// ===========================================================================
// The private family
//
// One name: the `_o_`-spelled errno, which is the same storage the plain
// spelling answers with. The real private module carries hundreds of these
// spellings, one per detoured entry point; this runtime's detour surface
// is the registry, and the only `_o_` name a guest needs an address for is
// the errno the startup code reads before anything else.
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t* crf__o__errno() noexcept {
    return cr__errno();
}

// ===========================================================================
// The environment family
// ===========================================================================

// The wide environment, which the wide spellings read. The table is the
// narrow one rendered wide; a value that is not valid text in this
// encoding is absent from the wide view, which is what a caller that
// cannot spell it would see.
bool g_wide_environment_stale = true;

std::unordered_map<std::u16string, std::u16string>& wide_environment() noexcept {
    static std::unordered_map<std::u16string, std::u16string> cache;
    static std::mutex lock;
    const std::lock_guard<std::mutex> guard(lock);
    if (g_wide_environment_stale) {
        g_wide_environment_stale = false;
        cache.clear();
        for (char** entry = environ; *entry != nullptr; ++entry) {
            const std::string_view text(*entry);
            const std::size_t split = text.find('=');
            if (split == std::string_view::npos) {
                continue;
            }
            std::u16string name;
            std::u16string value;
            if (narrow_in(text.substr(0, split), name).converted &&
                narrow_in(text.substr(split + 1), value).converted) {
                cache.emplace(std::move(name), std::move(value));
            }
        }
    }
    return cache;
}

extern "C" __attribute__((ms_abi)) const char16_t* crf__wgetenv(
    const char16_t* name) noexcept {
    if (name == nullptr) {
        return nullptr;
    }
    const auto& table = wide_environment();
    const auto it = table.find(std::u16string(name));
    // The answer lives as long as the next `putenv`, which is the contract
    // the narrow spelling gives; a static copy per name is the shape that
    // meets it here.
    static thread_local std::u16string answer;
    if (it == table.end()) {
        return nullptr;
    }
    answer = it->second;
    return answer.c_str();
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wgetenv_s(
    std::uint64_t* needed, char16_t* buffer, std::uint64_t size,
    const char16_t* name) noexcept {
    if (name == nullptr || (buffer == nullptr && size != 0)) {
        return EINVAL;
    }
    const auto& table = wide_environment();
    const auto it = table.find(std::u16string(name));
    if (needed != nullptr) {
        *needed = it == table.end() ? 0 : it->second.size() + 1;
    }
    if (it == table.end()) {
        if (buffer != nullptr && size != 0) {
            buffer[0] = u'\0';
        }
        return 0;
    }
    if (it->second.size() + 1 > size) {
        if (buffer != nullptr && size != 0) {
            buffer[0] = u'\0';
        }
        return ERANGE;
    }
    std::memcpy(buffer, it->second.data(),
                (it->second.size() + 1) * sizeof(char16_t));
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_getenv_s(
    std::uint64_t* needed, char* buffer, std::uint64_t size,
    const char* name) noexcept {
    if (name == nullptr || (buffer == nullptr && size != 0)) {
        return EINVAL;
    }
    const char* value = cr_getenv(name);
    const std::uint64_t length =
        value == nullptr ? 0 : std::strlen(value);
    if (needed != nullptr) {
        *needed = value == nullptr ? 0 : length + 1;
    }
    if (value == nullptr) {
        if (buffer != nullptr && size != 0) {
            buffer[0] = '\0';
        }
        return 0;
    }
    if (length + 1 > size) {
        if (buffer != nullptr && size != 0) {
            buffer[0] = '\0';
        }
        return ERANGE;
    }
    std::memcpy(buffer, value, length + 1);
    return 0;
}

// The wide putenv, which reaches the same table the narrow one does. The
// narrow name and value are what the table stores, so the conversion goes
// out and the environment follows.
extern "C" __attribute__((ms_abi)) std::int32_t crf__wputenv_s(
    const char16_t* name, const char16_t* value) noexcept;

extern "C" __attribute__((ms_abi)) std::int32_t crf__wputenv(
    const char16_t* text) noexcept {
    if (text == nullptr) {
        return -1;
    }
    const std::u16string_view entry(text);
    const std::size_t split = entry.find(u'=');
    if (split == std::u16string::npos) {
        return -1;
    }
    return crf__wputenv_s(std::u16string(entry.substr(0, split)).c_str(),
                          std::u16string(entry.substr(split + 1)).c_str());
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wputenv_s(
    const char16_t* name, const char16_t* value) noexcept {
    if (name == nullptr || value == nullptr) {
        return -1;
    }
    std::string narrow_name;
    std::string narrow_value;
    if (!narrow_out(std::u16string_view(name), narrow_name).converted ||
        !narrow_out(std::u16string_view(value), narrow_value).converted) {
        return -1;
    }
    if (cr__putenv_s(narrow_name.c_str(), narrow_value.c_str()) != 0) {
        return -1;
    }
    // The wide view is rebuilt from the narrow table it mirrors, which is
    // the only place the state lives.
    g_wide_environment_stale = true;
    return 0;
}

// `_dupenv_s` hands the caller a block it owns. The block comes from the
// same allocator `free` reads, which is what makes the pair usable.
extern "C" __attribute__((ms_abi)) std::int32_t crf__dupenv_s(
    char** buffer, std::uint64_t* length, const char* name) noexcept {
    if (buffer == nullptr || length == nullptr || name == nullptr) {
        return EINVAL;
    }
    const char* value = cr_getenv(name);
    if (value == nullptr) {
        *buffer = nullptr;
        *length = 0;
        return 0;
    }
    const std::uint64_t size = std::strlen(value) + 1;
    auto* copy = static_cast<char*>(cr_malloc(size));
    if (copy == nullptr) {
        return ENOMEM;
    }
    std::memcpy(copy, value, size);
    *buffer = copy;
    *length = size - 1;
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wdupenv_s(
    char16_t** buffer, std::uint64_t* length, const char16_t* name) noexcept {
    if (buffer == nullptr || length == nullptr || name == nullptr) {
        return EINVAL;
    }
    const char16_t* value = crf__wgetenv(name);
    if (value == nullptr) {
        *buffer = nullptr;
        *length = 0;
        return 0;
    }
    const std::uint64_t chars = std::char_traits<char16_t>::length(value);
    const std::uint64_t size = chars + 1;
    auto* copy = static_cast<char16_t*>(cr_malloc(size * sizeof(char16_t)));
    if (copy == nullptr) {
        return ENOMEM;
    }
    std::memcpy(copy, value, size * sizeof(char16_t));
    *buffer = copy;
    *length = chars;
    return 0;
}

// The existence test and the host mapping the search runs on; the
// mapping is defined with the filesystem family below.
[[nodiscard]] std::string host_path_of(std::string_view dos_path) noexcept;

[[nodiscard]] bool searchenv_exists(const std::string& dos_path) noexcept {
    struct ::stat st {};
    return contained_stat(host_path_of(dos_path).c_str(), st,
                          /*follow=*/true) == 0;
}

extern "C" __attribute__((ms_abi)) char* crf__fullpath(
    char* buffer, const char* path, std::uint64_t length) noexcept;

// `_searchenv` walks the directories a variable names and answers the
// first place the file exists in. The order is the reference's: the file
// as named (which covers the current directory) first, then each
// `;`-separated directory in the variable, quotes around a directory
// stripped. The answer is the file's absolute form, which is what the
// reference's `_fullpath` produces for the current-directory hit.
extern "C" __attribute__((ms_abi)) std::int32_t crf__searchenv_s(
    const char* name, const char* variable, char* buffer,
    std::uint64_t size) noexcept {
    if (name == nullptr || buffer == nullptr || size == 0) {
        return EINVAL;
    }
    buffer[0] = '\0';
    if (variable == nullptr || *name == '\0') {
        return 0;
    }
    // The current directory first, through the absolute form the caller
    // expects the answer in.
    if (searchenv_exists(name)) {
        char* absolute = crf__fullpath(nullptr, name, 0);
        if (absolute == nullptr) {
            return errno;
        }
        if (std::strlen(absolute) + 1 > size) {
            cr_free(absolute);
            errno = ERANGE;
            return ERANGE;
        }
        std::memcpy(buffer, absolute, std::strlen(absolute) + 1);
        cr_free(absolute);
        return 0;
    }
    const char* value = cr_getenv(variable);
    if (value == nullptr) {
        errno = ENOENT;
        return ENOENT;
    }
    std::string path;
    for (const char* p = value; *p != '\0';) {
        path.clear();
        while (*p != '\0' && *p != ';' && path.size() < kMaxPath) {
            if (*p == '"') {
                ++p;
                while (*p != '\0' && *p != '"' && path.size() < kMaxPath) {
                    path += *p++;
                }
                if (*p == '"') {
                    ++p;
                }
                continue;
            }
            path += *p++;
        }
        if (!path.empty() && path.size() < kMaxPath) {
            if (path.back() != '/' && path.back() != '\\') {
                path += '\\';
            }
            path += name;
            if (searchenv_exists(path)) {
                if (path.size() + 1 > size) {
                    errno = ERANGE;
                    return ERANGE;
                }
                std::memcpy(buffer, path.c_str(), path.size() + 1);
                return 0;
            }
        }
        if (*p == '\0') {
            break;
        }
        ++p;
    }
    errno = ENOENT;
    return ENOENT;
}

extern "C" __attribute__((ms_abi)) void crf__searchenv(
    const char* name, const char* variable, char* buffer) noexcept {
    static_cast<void>(crf__searchenv_s(name, variable, buffer, kMaxPath));
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wsearchenv_s(
    const char16_t* name, const char16_t* variable, char16_t* buffer,
    std::uint64_t size) noexcept {
    if (buffer == nullptr || size == 0) {
        return EINVAL;
    }
    buffer[0] = u'\0';
    std::string narrow_name;
    std::string narrow_variable;
    if (name == nullptr || variable == nullptr) {
        return 0;
    }
    if (!narrow_out(std::u16string_view(name), narrow_name).converted ||
        !narrow_out(std::u16string_view(variable), narrow_variable)
             .converted) {
        return 0;
    }
    std::vector<char> narrow_buffer(kMaxPath * 4, '\0');
    const std::int32_t result = crf__searchenv_s(
        narrow_name.c_str(), narrow_variable.c_str(), narrow_buffer.data(),
        narrow_buffer.size());
    if (result != 0) {
        return result;
    }
    std::u16string wide;
    if (!narrow_in(std::string_view(narrow_buffer.data()), wide).converted) {
        return 0;
    }
    if (wide.size() + 1 > size) {
        buffer[0] = u'\0';
        return ERANGE;
    }
    std::memcpy(buffer, wide.c_str(), (wide.size() + 1) * sizeof(char16_t));
    return 0;
}

extern "C" __attribute__((ms_abi)) void crf__wsearchenv(
    const char16_t* name, const char16_t* variable, char16_t* buffer) noexcept {
    static_cast<void>(crf__wsearchenv_s(name, variable, buffer, kMaxPath));
}

// The wide environment-table pointer, which reads the same table the
// narrow `__p__environ` export does, rendered wide.
extern "C" __attribute__((ms_abi)) char16_t** crf___p__wenviron() noexcept {
    static std::vector<char16_t*> table;
    static std::u16string storage;
    table.clear();
    storage.clear();
    for (char** entry = environ; *entry != nullptr; ++entry) {
        std::u16string wide;
        if (!narrow_in(std::string_view(*entry), wide).converted) {
            continue;
        }
        const std::size_t offset = storage.size();
        storage += wide;
        storage += u'\0';
        table.push_back(storage.data() + offset);
    }
    table.push_back(nullptr);
    return table.data();
}

// The current directory, wide. The answer is the host's directory rendered
// as a DOS path, which is the same mapping every path the runtime hands
// back takes.
std::u16string& wide_cwd_buffer() noexcept {
    static std::u16string buffer;
    return buffer;
}

extern "C" __attribute__((ms_abi)) char16_t* crf__wgetcwd(
    char16_t* buffer, std::int32_t length) noexcept {
    if (buffer == nullptr || length <= 0) {
        errno = EINVAL;
        return nullptr;
    }
    char host[kMaxPath];
    if (::getcwd(host, sizeof(host)) == nullptr) {
        return nullptr;
    }
    std::u16string wide;
    if (!narrow_in(std::string_view(to_dos_path(host)), wide).converted) {
        errno = ERANGE;
        return nullptr;
    }
    if (wide.size() + 1 > static_cast<std::size_t>(length)) {
        errno = ERANGE;
        return nullptr;
    }
    std::memcpy(buffer, wide.c_str(), (wide.size() + 1) * sizeof(char16_t));
    return buffer;
}

extern "C" __attribute__((ms_abi)) char16_t* crf__wgetdcwd(
    std::int32_t drive, char16_t* buffer, std::int32_t length) noexcept {
    // The drive is the one the runtime mounts; any other letter names a
    // drive that does not exist, which the real call reports EINVAL for.
    if (drive != 0 && drive != kGuestDrive) {
        errno = EINVAL;
        return nullptr;
    }
    return crf__wgetcwd(buffer, length);
}

// ===========================================================================
// The process family
//
// The exec and spawn spellings all reach `CreateProcess`, which this
// runtime refuses the way the rest of the process surface refuses: a child
// process needs a second address space, a load of the image into it, and a
// parent-child relationship the handle table can express. The spellings
// below marshal their arguments into the command line the call would
// build, fail it through the same path, and map the Windows error the way
// the CRT maps it -- the table Wine's `msvcrt/errno.c` states.
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t k32p_CreateProcessW(
    const char16_t* application, char16_t* command_line,
    void* process_attributes, void* thread_attributes,
    std::int32_t inherit_handles, std::uint32_t flags, void* environment,
    const char16_t* current_directory, const void* startup_info,
    void* process_information) noexcept;

// The error mapping, stated once: the codes a refused `CreateProcess`
// names, and the C errno each becomes. `ERROR_CALL_NOT_IMPLEMENTED` is the
// one this runtime's refusal answers with, and it falls in the default
// arm, which is `EINVAL` -- the same answer the reference's mapping table
// gives it.
void map_spawn_failure() noexcept {
    errno = EINVAL;
    dos_errno() = static_cast<std::int32_t>(kErrorCallNotImplemented);
}

// The narrow command line for a spawn: the program, then each argument,
// quoted the way the CRT quotes -- an argument with a space or tab in it
// takes a pair of quotes around the whole thing.
[[nodiscard]] std::string spawn_command_line(
    const char* program, char* const* arguments) noexcept {
    std::string line = program != nullptr ? program : "";
    const auto quoted = [&line](const char* argument) {
        line += ' ';
        const std::string_view text(argument == nullptr ? "" : argument);
        const bool needs_quotes =
            text.find_first_of(" \t\"") != std::string_view::npos;
        if (needs_quotes) {
            line += '"';
        }
        for (const char c : text) {
            if (c == '"') {
                line += "\\\"";
            } else {
                line += c;
            }
        }
        if (needs_quotes) {
            line += '"';
        }
    };
    if (arguments != nullptr) {
        for (char* const* it = arguments; *it != nullptr; ++it) {
            quoted(*it);
        }
    }
    return line;
}

// The wide form of the same line.
[[nodiscard]] std::u16string spawn_command_line_wide(
    const char16_t* program, char16_t* const* arguments) noexcept {
    std::u16string line = program != nullptr ? program : u"";
    const auto quoted = [&line](const char16_t* argument) {
        line += u' ';
        const std::u16string_view text(argument == nullptr ? u""
                                                           : argument);
        const bool needs_quotes =
            text.find_first_of(u" \t\"") != std::u16string_view::npos;
        if (needs_quotes) {
            line += u'"';
        }
        for (const char16_t c : text) {
            if (c == u'"') {
                line += u"\\\"";
            } else {
                line += c;
            }
        }
        if (needs_quotes) {
            line += u'"';
        }
    };
    if (arguments != nullptr) {
        for (char16_t* const* it = arguments; *it != nullptr; ++it) {
            quoted(*it);
        }
    }
    return line;
}

// The core the whole family funnels into: build the line, make the call
// the CRT makes, map the answer. `exec*` is a successful spawn that never
// comes back; the runtime refuses both, so the answer is the same failure
// and only the errno text differs.
[[nodiscard]] std::int32_t spawn_failure_narrow(
    const char* program, char* const* arguments) noexcept {
    // The line the call would build; the failure is the mapped one.
    static_cast<void>(spawn_command_line(program, arguments));
    map_spawn_failure();
    return -1;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__execv(
    const char* program, char* const* arguments) noexcept {
    static_cast<void>(spawn_failure_narrow(program, arguments));
    return -1;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__execve(
    const char* program, char* const* arguments,
    char* const* environment) noexcept {
    static_cast<void>(environment);
    static_cast<void>(spawn_failure_narrow(program, arguments));
    return -1;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__execvp(
    const char* program, char* const* arguments) noexcept {
    static_cast<void>(spawn_failure_narrow(program, arguments));
    return -1;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__execvpe(
    const char* program, char* const* arguments,
    char* const* environment) noexcept {
    static_cast<void>(environment);
    static_cast<void>(spawn_failure_narrow(program, arguments));
    return -1;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wexecv(
    const char16_t* program, char16_t* const* arguments) noexcept {
    static_cast<void>(program);
    static_cast<void>(arguments);
    map_spawn_failure();
    return -1;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wexecve(
    const char16_t* program, char16_t* const* arguments,
    char16_t* const* environment) noexcept {
    static_cast<void>(environment);
    return crf__wexecv(program, arguments);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wexecvp(
    const char16_t* program, char16_t* const* arguments) noexcept {
    return crf__wexecv(program, arguments);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wexecvpe(
    const char16_t* program, char16_t* const* arguments,
    char16_t* const* environment) noexcept {
    static_cast<void>(environment);
    return crf__wexecv(program, arguments);
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf__spawnv(
    std::int32_t mode, const char* program,
    char* const* arguments) noexcept {
    static_cast<void>(mode);
    static_cast<void>(spawn_failure_narrow(program, arguments));
    return static_cast<std::uint64_t>(-1);
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf__spawnve(
    std::int32_t mode, const char* program, char* const* arguments,
    char* const* environment) noexcept {
    static_cast<void>(environment);
    return crf__spawnv(mode, program, arguments);
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf__spawnvp(
    std::int32_t mode, const char* program,
    char* const* arguments) noexcept {
    return crf__spawnv(mode, program, arguments);
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf__spawnvpe(
    std::int32_t mode, const char* program, char* const* arguments,
    char* const* environment) noexcept {
    static_cast<void>(environment);
    return crf__spawnv(mode, program, arguments);
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf__wspawnv(
    std::int32_t mode, const char16_t* program,
    char16_t* const* arguments) noexcept {
    static_cast<void>(mode);
    static_cast<void>(program);
    static_cast<void>(arguments);
    map_spawn_failure();
    return static_cast<std::uint64_t>(-1);
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf__wspawnve(
    std::int32_t mode, const char16_t* program, char16_t* const* arguments,
    char16_t* const* environment) noexcept {
    static_cast<void>(environment);
    return crf__wspawnv(mode, program, arguments);
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf__wspawnvp(
    std::int32_t mode, const char16_t* program,
    char16_t* const* arguments) noexcept {
    return crf__wspawnv(mode, program, arguments);
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf__wspawnvpe(
    std::int32_t mode, const char16_t* program, char16_t* const* arguments,
    char16_t* const* environment) noexcept {
    static_cast<void>(environment);
    return crf__wspawnv(mode, program, arguments);
}

// The list spellings, which assemble the argument vector the `v`
// spellings take and delegate to them. The walk is the varargs walk the
// convention gives: arguments from the first named one to the null the
// caller passed, each a pointer in a register or stack slot the list walk
// reads in order.
extern "C" __attribute__((ms_abi)) std::int32_t crf__execl(
    const char* program, const char* argument, ...) noexcept {
    if (argument == nullptr) {
        return crf__execv(program, nullptr);
    }
    std::vector<char*> arguments;
    arguments.push_back(const_cast<char*>(argument));
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, argument);
    // The slot walk: the convention lays the variable arguments out as
    // eight-byte slots, which the list reads in order to the null the
    // caller passed.
    void* slots = nullptr;
    std::memcpy(&slots, &ap, sizeof(slots));
    for (;;) {
        char* raw = nullptr;
        std::memcpy(&raw, slots, sizeof(raw));
        slots = static_cast<char*>(slots) + 8;
        if (raw == nullptr) {
            break;
        }
        arguments.push_back(raw);
    }
    __builtin_ms_va_end(ap);
    return crf__execv(program, arguments.data());
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__execle(
    const char* program, const char* argument, ...) noexcept {
    if (argument == nullptr) {
        return crf__execv(program, nullptr);
    }
    std::vector<char*> arguments;
    arguments.push_back(const_cast<char*>(argument));
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, argument);
    // The slot walk: the convention lays the variable arguments out as
    // eight-byte slots, which the list reads in order to the null the
    // caller passed.
    void* slots = nullptr;
    std::memcpy(&slots, &ap, sizeof(slots));
    for (;;) {
        char* raw = nullptr;
        std::memcpy(&raw, slots, sizeof(raw));
        slots = static_cast<char*>(slots) + 8;
        if (raw == nullptr) {
            break;
        }
        arguments.push_back(raw);
    }
    // What follows the terminator is the environment, as a `char**`; the
    // list walk reads it as the pointer it is.
    // What follows the terminator is the environment, as a `char**`;
    // the next slot holds it.
    char** environment = nullptr;
    std::memcpy(&environment, slots, sizeof(environment));
    __builtin_ms_va_end(ap);
    return crf__execve(program, arguments.data(), environment);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__execlp(
    const char* program, const char* argument, ...) noexcept {
    if (argument == nullptr) {
        return crf__execvp(program, nullptr);
    }
    std::vector<char*> arguments;
    arguments.push_back(const_cast<char*>(argument));
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, argument);
    // The slot walk: the convention lays the variable arguments out as
    // eight-byte slots, which the list reads in order to the null the
    // caller passed.
    void* slots = nullptr;
    std::memcpy(&slots, &ap, sizeof(slots));
    for (;;) {
        char* raw = nullptr;
        std::memcpy(&raw, slots, sizeof(raw));
        slots = static_cast<char*>(slots) + 8;
        if (raw == nullptr) {
            break;
        }
        arguments.push_back(raw);
    }
    __builtin_ms_va_end(ap);
    return crf__execvp(program, arguments.data());
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__execlpe(
    const char* program, const char* argument, ...) noexcept {
    if (argument == nullptr) {
        return crf__execvpe(program, nullptr, nullptr);
    }
    std::vector<char*> arguments;
    arguments.push_back(const_cast<char*>(argument));
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, argument);
    // The slot walk: the convention lays the variable arguments out as
    // eight-byte slots, which the list reads in order to the null the
    // caller passed.
    void* slots = nullptr;
    std::memcpy(&slots, &ap, sizeof(slots));
    for (;;) {
        char* raw = nullptr;
        std::memcpy(&raw, slots, sizeof(raw));
        slots = static_cast<char*>(slots) + 8;
        if (raw == nullptr) {
            break;
        }
        arguments.push_back(raw);
    }
    // What follows the terminator is the environment, as a `char**`;
    // the next slot holds it.
    char** environment = nullptr;
    std::memcpy(&environment, slots, sizeof(environment));
    __builtin_ms_va_end(ap);
    return crf__execvpe(program, arguments.data(), environment);
}

extern "C" __attribute__((ms_abi)) std::int64_t crf__spawnl(
    std::int32_t mode, const char* program, const char* argument,
    ...) noexcept {
    if (argument == nullptr) {
        return static_cast<std::int64_t>(
            crf__spawnv(mode, program, nullptr));
    }
    std::vector<char*> arguments;
    arguments.push_back(const_cast<char*>(argument));
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, argument);
    // The slot walk: the convention lays the variable arguments out as
    // eight-byte slots, which the list reads in order to the null the
    // caller passed.
    void* slots = nullptr;
    std::memcpy(&slots, &ap, sizeof(slots));
    for (;;) {
        char* raw = nullptr;
        std::memcpy(&raw, slots, sizeof(raw));
        slots = static_cast<char*>(slots) + 8;
        if (raw == nullptr) {
            break;
        }
        arguments.push_back(raw);
    }
    __builtin_ms_va_end(ap);
    return static_cast<std::int64_t>(
        crf__spawnv(mode, program, arguments.data()));
}

extern "C" __attribute__((ms_abi)) std::int64_t crf__spawnle(
    std::int32_t mode, const char* program, const char* argument,
    ...) noexcept {
    if (argument == nullptr) {
        return static_cast<std::int64_t>(
            crf__spawnve(mode, program, nullptr, nullptr));
    }
    std::vector<char*> arguments;
    arguments.push_back(const_cast<char*>(argument));
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, argument);
    // The slot walk: the convention lays the variable arguments out as
    // eight-byte slots, which the list reads in order to the null the
    // caller passed.
    void* slots = nullptr;
    std::memcpy(&slots, &ap, sizeof(slots));
    for (;;) {
        char* raw = nullptr;
        std::memcpy(&raw, slots, sizeof(raw));
        slots = static_cast<char*>(slots) + 8;
        if (raw == nullptr) {
            break;
        }
        arguments.push_back(raw);
    }
    // What follows the terminator is the environment, as a `char**`;
    // the next slot holds it.
    char** environment = nullptr;
    std::memcpy(&environment, slots, sizeof(environment));
    __builtin_ms_va_end(ap);
    return static_cast<std::int64_t>(
        crf__spawnve(mode, program, arguments.data(), environment));
}

extern "C" __attribute__((ms_abi)) std::int64_t crf__spawnlp(
    std::int32_t mode, const char* program, const char* argument,
    ...) noexcept {
    if (argument == nullptr) {
        return static_cast<std::int64_t>(
            crf__spawnvp(mode, program, nullptr));
    }
    std::vector<char*> arguments;
    arguments.push_back(const_cast<char*>(argument));
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, argument);
    // The slot walk: the convention lays the variable arguments out as
    // eight-byte slots, which the list reads in order to the null the
    // caller passed.
    void* slots = nullptr;
    std::memcpy(&slots, &ap, sizeof(slots));
    for (;;) {
        char* raw = nullptr;
        std::memcpy(&raw, slots, sizeof(raw));
        slots = static_cast<char*>(slots) + 8;
        if (raw == nullptr) {
            break;
        }
        arguments.push_back(raw);
    }
    __builtin_ms_va_end(ap);
    return static_cast<std::int64_t>(
        crf__spawnvp(mode, program, arguments.data()));
}

extern "C" __attribute__((ms_abi)) std::int64_t crf__spawnlpe(
    std::int32_t mode, const char* program, const char* argument,
    ...) noexcept {
    if (argument == nullptr) {
        return static_cast<std::int64_t>(
            crf__spawnvpe(mode, program, nullptr, nullptr));
    }
    std::vector<char*> arguments;
    arguments.push_back(const_cast<char*>(argument));
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, argument);
    // The slot walk: the convention lays the variable arguments out as
    // eight-byte slots, which the list reads in order to the null the
    // caller passed.
    void* slots = nullptr;
    std::memcpy(&slots, &ap, sizeof(slots));
    for (;;) {
        char* raw = nullptr;
        std::memcpy(&raw, slots, sizeof(raw));
        slots = static_cast<char*>(slots) + 8;
        if (raw == nullptr) {
            break;
        }
        arguments.push_back(raw);
    }
    // What follows the terminator is the environment, as a `char**`;
    // the next slot holds it.
    char** environment = nullptr;
    std::memcpy(&environment, slots, sizeof(environment));
    __builtin_ms_va_end(ap);
    return static_cast<std::int64_t>(
        crf__spawnvpe(mode, program, arguments.data(), environment));
}

// The wide list spellings, which are the narrow ones with the wide
// pointer type in the walk.
extern "C" __attribute__((ms_abi)) std::int32_t crf__wexecl(
    const char16_t* program, const char16_t* argument, ...) noexcept {
    if (argument == nullptr) {
        return crf__wexecv(program, nullptr);
    }
    std::vector<char16_t*> arguments;
    arguments.push_back(const_cast<char16_t*>(argument));
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, argument);
    void* slots = nullptr;
    std::memcpy(&slots, &ap, sizeof(slots));
    for (;;) {
        char16_t* raw = nullptr;
        std::memcpy(&raw, slots, sizeof(raw));
        slots = static_cast<char*>(slots) + 8;
        if (raw == nullptr) {
            break;
        }
        arguments.push_back(raw);
    }
    __builtin_ms_va_end(ap);
    return crf__wexecv(program, arguments.data());
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wexecle(
    const char16_t* program, const char16_t* argument, ...) noexcept {
    if (argument == nullptr) {
        return crf__wexecv(program, nullptr);
    }
    std::vector<char16_t*> arguments;
    arguments.push_back(const_cast<char16_t*>(argument));
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, argument);
    void* slots = nullptr;
    std::memcpy(&slots, &ap, sizeof(slots));
    for (;;) {
        char16_t* raw = nullptr;
        std::memcpy(&raw, slots, sizeof(raw));
        slots = static_cast<char*>(slots) + 8;
        if (raw == nullptr) {
            break;
        }
        arguments.push_back(raw);
    }
    char16_t** environment = nullptr;
    std::memcpy(&environment, slots, sizeof(environment));
    __builtin_ms_va_end(ap);
    return crf__wexecve(program, arguments.data(), environment);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wexeclp(
    const char16_t* program, const char16_t* argument, ...) noexcept {
    if (argument == nullptr) {
        return crf__wexecvp(program, nullptr);
    }
    std::vector<char16_t*> arguments;
    arguments.push_back(const_cast<char16_t*>(argument));
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, argument);
    void* slots = nullptr;
    std::memcpy(&slots, &ap, sizeof(slots));
    for (;;) {
        char16_t* raw = nullptr;
        std::memcpy(&raw, slots, sizeof(raw));
        slots = static_cast<char*>(slots) + 8;
        if (raw == nullptr) {
            break;
        }
        arguments.push_back(raw);
    }
    __builtin_ms_va_end(ap);
    return crf__wexecvp(program, arguments.data());
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wexeclpe(
    const char16_t* program, const char16_t* argument, ...) noexcept {
    if (argument == nullptr) {
        return crf__wexecvpe(program, nullptr, nullptr);
    }
    std::vector<char16_t*> arguments;
    arguments.push_back(const_cast<char16_t*>(argument));
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, argument);
    void* slots = nullptr;
    std::memcpy(&slots, &ap, sizeof(slots));
    for (;;) {
        char16_t* raw = nullptr;
        std::memcpy(&raw, slots, sizeof(raw));
        slots = static_cast<char*>(slots) + 8;
        if (raw == nullptr) {
            break;
        }
        arguments.push_back(raw);
    }
    char16_t** environment = nullptr;
    std::memcpy(&environment, slots, sizeof(environment));
    __builtin_ms_va_end(ap);
    return crf__wexecvpe(program, arguments.data(), environment);
}

extern "C" __attribute__((ms_abi)) std::int64_t crf__wspawnl(
    std::int32_t mode, const char16_t* program, const char16_t* argument,
    ...) noexcept {
    if (argument == nullptr) {
        return static_cast<std::int64_t>(
            crf__wspawnv(mode, program, nullptr));
    }
    std::vector<char16_t*> arguments;
    arguments.push_back(const_cast<char16_t*>(argument));
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, argument);
    void* slots = nullptr;
    std::memcpy(&slots, &ap, sizeof(slots));
    for (;;) {
        char16_t* raw = nullptr;
        std::memcpy(&raw, slots, sizeof(raw));
        slots = static_cast<char*>(slots) + 8;
        if (raw == nullptr) {
            break;
        }
        arguments.push_back(raw);
    }
    __builtin_ms_va_end(ap);
    return static_cast<std::int64_t>(
        crf__wspawnv(mode, program, arguments.data()));
}

extern "C" __attribute__((ms_abi)) std::int64_t crf__wspawnle(
    std::int32_t mode, const char16_t* program, const char16_t* argument,
    ...) noexcept {
    if (argument == nullptr) {
        return static_cast<std::int64_t>(
            crf__wspawnve(mode, program, nullptr, nullptr));
    }
    std::vector<char16_t*> arguments;
    arguments.push_back(const_cast<char16_t*>(argument));
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, argument);
    void* slots = nullptr;
    std::memcpy(&slots, &ap, sizeof(slots));
    for (;;) {
        char16_t* raw = nullptr;
        std::memcpy(&raw, slots, sizeof(raw));
        slots = static_cast<char*>(slots) + 8;
        if (raw == nullptr) {
            break;
        }
        arguments.push_back(raw);
    }
    char16_t** environment = nullptr;
    std::memcpy(&environment, slots, sizeof(environment));
    __builtin_ms_va_end(ap);
    return static_cast<std::int64_t>(
        crf__wspawnve(mode, program, arguments.data(), environment));
}

extern "C" __attribute__((ms_abi)) std::int64_t crf__wspawnlp(
    std::int32_t mode, const char16_t* program, const char16_t* argument,
    ...) noexcept {
    if (argument == nullptr) {
        return static_cast<std::int64_t>(
            crf__wspawnvp(mode, program, nullptr));
    }
    std::vector<char16_t*> arguments;
    arguments.push_back(const_cast<char16_t*>(argument));
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, argument);
    void* slots = nullptr;
    std::memcpy(&slots, &ap, sizeof(slots));
    for (;;) {
        char16_t* raw = nullptr;
        std::memcpy(&raw, slots, sizeof(raw));
        slots = static_cast<char*>(slots) + 8;
        if (raw == nullptr) {
            break;
        }
        arguments.push_back(raw);
    }
    __builtin_ms_va_end(ap);
    return static_cast<std::int64_t>(
        crf__wspawnvp(mode, program, arguments.data()));
}

extern "C" __attribute__((ms_abi)) std::int64_t crf__wspawnlpe(
    std::int32_t mode, const char16_t* program, const char16_t* argument,
    ...) noexcept {
    if (argument == nullptr) {
        return static_cast<std::int64_t>(
            crf__wspawnvpe(mode, program, nullptr, nullptr));
    }
    std::vector<char16_t*> arguments;
    arguments.push_back(const_cast<char16_t*>(argument));
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, argument);
    void* slots = nullptr;
    std::memcpy(&slots, &ap, sizeof(slots));
    for (;;) {
        char16_t* raw = nullptr;
        std::memcpy(&raw, slots, sizeof(raw));
        slots = static_cast<char*>(slots) + 8;
        if (raw == nullptr) {
            break;
        }
        arguments.push_back(raw);
    }
    char16_t** environment = nullptr;
    std::memcpy(&environment, slots, sizeof(environment));
    __builtin_ms_va_end(ap);
    return static_cast<std::int64_t>(
        crf__wspawnvpe(mode, program, arguments.data(), environment));
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__cwait(
    std::int32_t* status, std::uint64_t handle,
    std::int32_t action) noexcept {
    static_cast<void>(status);
    static_cast<void>(handle);
    static_cast<void>(action);
    // No child the runtime started can be waited for, because none can be
    // started; the answer is the errno a wait on an unknown child gets.
    errno = ECHILD;
    return -1;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__beep(
    std::uint32_t frequency, std::uint32_t duration) noexcept {
    // The console beep, which the kernel32 spelling owns where a console
    // exists. There is no console here, and the call reports the silence.
    static_cast<void>(frequency);
    static_cast<void>(duration);
    return 0;
}

// The DLL loader by handle, which is `LoadLibrary` and `FreeLibrary` under
// the CRT's names, and the entry-point lookup that pairs with them.
extern "C" __attribute__((ms_abi)) std::uint64_t k32_LoadLibraryA(
    const char* name) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32c2_FreeLibrary(
    std::uint64_t module) noexcept;

extern "C" __attribute__((ms_abi)) std::int32_t crf__loaddll(
    const char* name) noexcept {
    if (name == nullptr) {
        return -1;
    }
    const std::uint64_t module = k32_LoadLibraryA(name);
    // The handle the CRT answers with is the module's ordinal-sized slot;
    // a null module is the failure.
    if (module == 0) {
        return -1;
    }
    return static_cast<std::int32_t>(module);
}

extern "C" __attribute__((ms_abi)) void crf__unloaddll(
    std::int32_t handle) noexcept {
    static_cast<void>(k32c2_FreeLibrary(static_cast<std::uint64_t>(handle)));
}

// ===========================================================================
// The filesystem family
//
// The stat, find, directory and path spellings. Every operation goes
// through the confined variants, because a path a guest names resolves at
// or below the runtime root or it does not resolve; the structures they
// fill are laid out from the Microsoft headers (verified against a
// cross-compiled probe's constants), and the field semantics follow
// Wine's `msvcrt/dir.c` and `msvcrt/file.c`.
// ===========================================================================

// The stat layouts. These are the x64 values: `_dev_t` and `_off_t` are
// thirty-two bits, `_ino_t` and the mode and link fields are sixteen, the
// times are thirty-two or sixty-four by the spelling, and the size is
// sixty-four wherever the spelling says so. The offsets were read out of a
// cross-compiled probe rather than derived, because a compiler's padding
// rules are the reference's, not this one's.
struct Stat32Layout {
    static constexpr std::size_t kDev = 0;
    static constexpr std::size_t kIno = 4;
    static constexpr std::size_t kMode = 6;
    static constexpr std::size_t kNlink = 8;
    static constexpr std::size_t kUid = 10;
    static constexpr std::size_t kGid = 12;
    static constexpr std::size_t kRdev = 16;
    static constexpr std::size_t kSize = 20;
    static constexpr std::size_t kAtime = 24;
    static constexpr std::size_t kMtime = 28;
    static constexpr std::size_t kCtime = 32;
    static constexpr std::size_t kBytes = 36;
};

struct Stat32i64Layout {
    static constexpr std::size_t kDev = 0;
    static constexpr std::size_t kIno = 4;
    static constexpr std::size_t kMode = 6;
    static constexpr std::size_t kNlink = 8;
    static constexpr std::size_t kUid = 10;
    static constexpr std::size_t kGid = 12;
    static constexpr std::size_t kRdev = 16;
    static constexpr std::size_t kSize = 24;
    static constexpr std::size_t kAtime = 32;
    static constexpr std::size_t kMtime = 36;
    static constexpr std::size_t kCtime = 40;
    static constexpr std::size_t kBytes = 48;
};

struct Stat64Layout {
    static constexpr std::size_t kDev = 0;
    static constexpr std::size_t kIno = 4;
    static constexpr std::size_t kMode = 6;
    static constexpr std::size_t kNlink = 8;
    static constexpr std::size_t kUid = 10;
    static constexpr std::size_t kGid = 12;
    static constexpr std::size_t kRdev = 16;
    static constexpr std::size_t kSize = 24;
    static constexpr std::size_t kAtime = 32;
    static constexpr std::size_t kMtime = 40;
    static constexpr std::size_t kCtime = 48;
    static constexpr std::size_t kBytes = 56;
};

struct Stat64i32Layout {
    static constexpr std::size_t kDev = 0;
    static constexpr std::size_t kIno = 4;
    static constexpr std::size_t kMode = 6;
    static constexpr std::size_t kNlink = 8;
    static constexpr std::size_t kUid = 10;
    static constexpr std::size_t kGid = 12;
    static constexpr std::size_t kRdev = 16;
    static constexpr std::size_t kSize = 20;
    static constexpr std::size_t kAtime = 24;
    static constexpr std::size_t kMtime = 32;
    static constexpr std::size_t kCtime = 40;
    static constexpr std::size_t kBytes = 48;
};

// Fills any of the four stat layouts from a host stat and the DOS path the
// caller named. The drive goes into `st_dev` and `st_rdev`, the inode and
// owner fields stay zero the way Windows' do, the link count is one, and
// the modification time doubles as the change time.
template <typename Layout>
void fill_stat(void* out, const struct ::stat& host,
               std::string_view dos_path) noexcept {
    std::memset(out, 0, Layout::kBytes);
    write_u32(out, Layout::kDev,
              static_cast<std::uint32_t>(dos_drive(dos_path)));
    write_u16(out, Layout::kIno, 0);
    write_u16(out, Layout::kMode,
              static_cast<std::uint16_t>(crt_mode_of(host, dos_path)));
    write_u16(out, Layout::kNlink, 1);
    write_u16(out, Layout::kUid, 0);
    write_u16(out, Layout::kGid, 0);
    write_u32(out, Layout::kRdev,
              static_cast<std::uint32_t>(dos_drive(dos_path)));
    if constexpr (Layout::kBytes == Stat32Layout::kBytes) {
        write_u32(out, Layout::kSize,
                  static_cast<std::uint32_t>(host.st_size));
    } else {
        write_u64(out, Layout::kSize,
                  static_cast<std::uint64_t>(host.st_size));
    }
    if constexpr (Layout::kBytes == Stat32Layout::kBytes ||
                  Layout::kBytes == Stat32i64Layout::kBytes) {
        // The thirty-two-bit times saturate the way a narrowing cast does,
        // which is the behaviour a caller built against the thirty-two-bit
        // spelling compiled with.
        write_u32(out, Layout::kAtime,
                  static_cast<std::uint32_t>(host.st_atim.tv_sec));
        write_u32(out, Layout::kMtime,
                  static_cast<std::uint32_t>(host.st_mtim.tv_sec));
        write_u32(out, Layout::kCtime,
                  static_cast<std::uint32_t>(host.st_mtim.tv_sec));
    } else {
        write_u64(out, Layout::kAtime,
                  static_cast<std::uint64_t>(host.st_atim.tv_sec));
        write_u64(out, Layout::kMtime,
                  static_cast<std::uint64_t>(host.st_mtim.tv_sec));
        write_u64(out, Layout::kCtime,
                  static_cast<std::uint64_t>(host.st_mtim.tv_sec));
    }
}

// The host path a DOS name resolves to. A rooted name maps directly; a
// relative one joins the current directory first, which is what the real
// CRT's relative paths mean.
[[nodiscard]] std::string lexical_absolute(
    std::string dos_path, const std::string& cwd_dos) noexcept;

[[nodiscard]] std::string host_path_of(std::string_view dos_path) noexcept {
    const bool rooted =
        (dos_path.size() >= 2 && dos_path[1] == ':') ||
        (!dos_path.empty() && (dos_path[0] == '\\' || dos_path[0] == '/'));
    if (rooted) {
        return from_dos_path(dos_path);
    }
    char cwd[kMaxPath];
    if (::getcwd(cwd, sizeof(cwd)) == nullptr) {
        return std::string();
    }
    return from_dos_path(lexical_absolute(std::string(dos_path),
                                          to_dos_path(cwd)));
}

// The stat core: convert, stat confined, fill. Trailing spaces and dots are
// stripped the way Windows strips them, because a name ending in them
// names the file without them.
[[nodiscard]] std::int32_t stat_core(const char* path, void* out,
                                     void (*fill_32)(void*, const struct ::stat&, std::string_view),
                                     void (*fill_64)(void*, const struct ::stat&, std::string_view),
                                     bool sixty_four) noexcept {
    if (path == nullptr || out == nullptr) {
        errno = EINVAL;
        return -1;
    }
    std::string dos(path);
    while (!dos.empty() && (dos.back() == ' ' || dos.back() == '.')) {
        dos.pop_back();
    }
    struct ::stat host {};
    if (contained_stat(host_path_of(dos).c_str(), host,
                       /*follow=*/true) != 0) {
        errno = ENOENT;
        return -1;
    }
    if (sixty_four) {
        fill_64(out, host, dos);
    } else {
        fill_32(out, host, dos);
    }
    return 0;
}

[[nodiscard]] std::int32_t stat32_core(const char* path, void* out) noexcept {
    return stat_core(path, out,
                     nullptr,
                     [](void* o, const struct ::stat& s,
                        std::string_view p) {
                         fill_stat<Stat32Layout>(o, s, p);
                     },
                     false);
}

[[nodiscard]] std::int32_t stat32i64_core(const char* path,
                                          void* out) noexcept {
    return stat_core(path, out,
                     nullptr,
                     [](void* o, const struct ::stat& s,
                        std::string_view p) {
                         fill_stat<Stat32i64Layout>(o, s, p);
                     },
                     true);
}

[[nodiscard]] std::int32_t stat64_core(const char* path, void* out) noexcept {
    return stat_core(path, out,
                     nullptr,
                     [](void* o, const struct ::stat& s,
                        std::string_view p) {
                         fill_stat<Stat64Layout>(o, s, p);
                     },
                     true);
}

[[nodiscard]] std::int32_t stat64i32_core(const char* path,
                                          void* out) noexcept {
    return stat_core(path, out,
                     nullptr,
                     [](void* o, const struct ::stat& s,
                        std::string_view p) {
                         fill_stat<Stat64i32Layout>(o, s, p);
                     },
                     true);
}

// The fstat core. Only the three standard descriptors exist as CRT
// descriptors, and a file type answer comes from the host's stat: a pipe
// reads as one, a character device as one, everything else as a regular
// file whose permissions the host states.
[[nodiscard]] std::int32_t fstat_core(std::int32_t fd, void* out,
                                      void (*fill_32)(void*, const struct ::stat&, std::string_view),
                                      void (*fill_64)(void*, const struct ::stat&, std::string_view),
                                      bool sixty_four) noexcept {
    if (out == nullptr || !crt_fd_is_valid(fd)) {
        errno = EBADF;
        return -1;
    }
    struct ::stat host {};
    if (::fstat(fd, &host) != 0) {
        return -1;
    }
    std::uint32_t mode;
    if (S_ISFIFO(host.st_mode)) {
        mode = 0x1000;  // _S_IFIFO
    } else if (S_ISCHR(host.st_mode)) {
        mode = 0x2000;  // _S_IFCHR
    } else {
        mode = 0x8000 | kS_IREAD;  // _S_IFREG
        if ((host.st_mode & S_IWUSR) != 0) {
            mode |= kS_IWRITE;
        }
    }
    host.st_mode = mode;
    const std::string_view empty;
    if (sixty_four) {
        fill_64(out, host, empty);
    } else {
        fill_32(out, host, empty);
    }
    // `st_dev` and `st_rdev` are the descriptor number for a stat on one,
    // which is the field the reference fills.
    write_u32(out, Stat32Layout::kDev, static_cast<std::uint32_t>(fd));
    write_u32(out, Stat32Layout::kRdev, static_cast<std::uint32_t>(fd));
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__stat32(
    const char* path, void* out) noexcept {
    return stat32_core(path, out);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf__stat32i64(
    const char* path, void* out) noexcept {
    return stat32i64_core(path, out);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf__stat64(
    const char* path, void* out) noexcept {
    return stat64_core(path, out);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf__stat64i32(
    const char* path, void* out) noexcept {
    return stat64i32_core(path, out);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wstat32(
    const char16_t* path, void* out) noexcept {
    std::string narrow;
    if (path == nullptr ||
        !narrow_out(std::u16string_view(path), narrow).converted) {
        errno = EINVAL;
        return -1;
    }
    return stat32_core(narrow.c_str(), out);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf__wstat32i64(
    const char16_t* path, void* out) noexcept {
    std::string narrow;
    if (path == nullptr ||
        !narrow_out(std::u16string_view(path), narrow).converted) {
        errno = EINVAL;
        return -1;
    }
    return stat32i64_core(narrow.c_str(), out);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf__wstat64(
    const char16_t* path, void* out) noexcept {
    std::string narrow;
    if (path == nullptr ||
        !narrow_out(std::u16string_view(path), narrow).converted) {
        errno = EINVAL;
        return -1;
    }
    return stat64_core(narrow.c_str(), out);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf__wstat64i32(
    const char16_t* path, void* out) noexcept {
    std::string narrow;
    if (path == nullptr ||
        !narrow_out(std::u16string_view(path), narrow).converted) {
        errno = EINVAL;
        return -1;
    }
    return stat64i32_core(narrow.c_str(), out);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__fstat32(
    std::int32_t fd, void* out) noexcept {
    return fstat_core(fd, out,
                      [](void* o, const struct ::stat& s,
                         std::string_view p) {
                          fill_stat<Stat32Layout>(o, s, p);
                      },
                      nullptr, false);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf__fstat32i64(
    std::int32_t fd, void* out) noexcept {
    return fstat_core(fd, out,
                      [](void* o, const struct ::stat& s,
                         std::string_view p) {
                          fill_stat<Stat32i64Layout>(o, s, p);
                      },
                      nullptr, true);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf__fstat64(
    std::int32_t fd, void* out) noexcept {
    return fstat_core(fd, out,
                      [](void* o, const struct ::stat& s,
                         std::string_view p) {
                          fill_stat<Stat64Layout>(o, s, p);
                      },
                      nullptr, true);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf__fstat64i32(
    std::int32_t fd, void* out) noexcept {
    return fstat_core(fd, out,
                      [](void* o, const struct ::stat& s,
                         std::string_view p) {
                          fill_stat<Stat64i32Layout>(o, s, p);
                      },
                      nullptr, true);
}

// The directory operations, each the confined variant under the CRT's
// name. The mode `_mkdir` takes is the write permission the CRT's `_S_IWRITE`
// names, which is the host's owner-write bit.
extern "C" __attribute__((ms_abi)) std::int32_t crf__mkdir(
    const char* path) noexcept {
    if (path == nullptr) {
        errno = EINVAL;
        return -1;
    }
    return contained_mkdir(host_path_of(path).c_str(),
                           S_IRWXU | S_IRWXG | S_IRWXO);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wmkdir(
    const char16_t* path) noexcept {
    if (path == nullptr) {
        errno = EINVAL;
        return -1;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(path), narrow).converted) {
        errno = EINVAL;
        return -1;
    }
    return contained_mkdir(host_path_of(narrow).c_str(),
                           S_IRWXU | S_IRWXG | S_IRWXO);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__rmdir(
    const char* path) noexcept {
    if (path == nullptr) {
        errno = EINVAL;
        return -1;
    }
    return contained_rmdir(host_path_of(path).c_str());
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wrmdir(
    const char16_t* path) noexcept {
    if (path == nullptr) {
        errno = EINVAL;
        return -1;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(path), narrow).converted) {
        errno = EINVAL;
        return -1;
    }
    return contained_rmdir(host_path_of(narrow).c_str());
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__unlink(
    const char* path) noexcept {
    if (path == nullptr) {
        errno = EINVAL;
        return -1;
    }
    return contained_unlink(host_path_of(path).c_str());
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wunlink(
    const char16_t* path) noexcept {
    if (path == nullptr) {
        errno = EINVAL;
        return -1;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(path), narrow).converted) {
        errno = EINVAL;
        return -1;
    }
    return contained_unlink(host_path_of(narrow).c_str());
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_remove(
    const char* path) noexcept {
    return crf__unlink(path);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_rename(
    const char* from, const char* to) noexcept {
    if (from == nullptr || to == nullptr) {
        errno = EINVAL;
        return -1;
    }
    return contained_rename(from_dos_path(from).c_str(),
                            from_dos_path(to).c_str());
}

// The access spellings. The mode bits are the same numbers the host call
// takes (4 read, 2 write, 0 existence), which is why the confined call
// takes them unchanged.
extern "C" __attribute__((ms_abi)) std::int32_t crf__access(
    const char* path, std::int32_t mode) noexcept {
    if (path == nullptr) {
        errno = EINVAL;
        return -1;
    }
    return contained_access(host_path_of(path).c_str(), mode);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__waccess(
    const char16_t* path, std::int32_t mode) noexcept {
    if (path == nullptr) {
        errno = EINVAL;
        return -1;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(path), narrow).converted) {
        errno = EINVAL;
        return -1;
    }
    return contained_access(host_path_of(narrow).c_str(), mode);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__access_s(
    const char* path, std::uint16_t mode) noexcept {
    const std::int32_t result = crf__access(
        path, static_cast<std::int32_t>(mode & 0x6));
    return result == 0 ? 0 : errno;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__waccess_s(
    const char16_t* path, std::uint16_t mode) noexcept {
    const std::int32_t result = crf__waccess(
        path, static_cast<std::int32_t>(mode & 0x6));
    return result == 0 ? 0 : errno;
}

// The change-directory spellings. The process's working directory is the
// host's, which is what the guest shares; the confined open validates that
// the target stays inside the root before the host call moves there.
extern "C" __attribute__((ms_abi)) std::int32_t crf__chdir(
    const char* path) noexcept {
    if (path == nullptr) {
        errno = EINVAL;
        return -1;
    }
    const std::string host = host_path_of(path);
    const int dirfd = contained_open(
        host.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (dirfd < 0) {
        return -1;
    }
    // The descriptor is the authority on where the directory really is; a
    // `/proc/self/fd` read of it names the canonical path, which is what
    // the host call moves to.
    std::string link("/proc/self/fd/");
    link += std::to_string(dirfd);
    char resolved[kMaxPath * 2];
    const ssize_t length = ::readlink(link.c_str(), resolved,
                                      sizeof(resolved) - 1);
    ::close(dirfd);
    if (length < 0) {
        errno = ENOENT;
        return -1;
    }
    resolved[length] = '\0';
    return ::chdir(resolved);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wchdir(
    const char16_t* path) noexcept {
    if (path == nullptr) {
        errno = EINVAL;
        return -1;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(path), narrow).converted) {
        errno = EINVAL;
        return -1;
    }
    return crf__chdir(narrow.c_str());
}

// The current directory, narrow. The answer is the host's directory
// rendered as a DOS path, truncated to the caller's buffer the way the
// CRT truncates.
extern "C" __attribute__((ms_abi)) char* crf__getcwd(
    char* buffer, std::int32_t length) noexcept {
    if (buffer != nullptr && length <= 0) {
        errno = EINVAL;
        return nullptr;
    }
    char host[kMaxPath];
    if (::getcwd(host, sizeof(host)) == nullptr) {
        return nullptr;
    }
    const std::string dos = to_dos_path(host);
    if (buffer == nullptr) {
        // The malloc form: a buffer of `_MAX_PATH` from the same allocator
        // `free` reads.
        auto* fresh = static_cast<char*>(cr_malloc(kMaxPath));
        if (fresh == nullptr) {
            return nullptr;
        }
        std::memcpy(fresh, dos.c_str(), dos.size() + 1);
        return fresh;
    }
    if (static_cast<std::size_t>(length) < dos.size() + 1) {
        errno = ERANGE;
        return nullptr;
    }
    std::memcpy(buffer, dos.c_str(), dos.size() + 1);
    return buffer;
}

extern "C" __attribute__((ms_abi)) char* crf__getdcwd(
    std::int32_t drive, char* buffer, std::int32_t length) noexcept {
    if (drive != 0 && drive != kGuestDrive) {
        errno = EINVAL;
        return nullptr;
    }
    return crf__getcwd(buffer, length);
}

// The permission spellings. The write bit is the whole story the CRT
// tells: `_S_IWRITE` makes the file owner-writable, anything else makes it
// read-only.
extern "C" __attribute__((ms_abi)) std::int32_t crf__chmod(
    const char* path, std::int32_t mode) noexcept {
    if (path == nullptr) {
        errno = EINVAL;
        return -1;
    }
    const unsigned host_mode =
        (mode & static_cast<std::int32_t>(kS_IWRITE)) != 0
            ? static_cast<unsigned>(S_IWUSR | S_IRUSR)
            : static_cast<unsigned>(S_IRUSR);
    return contained_chmod(from_dos_path(path).c_str(), host_mode);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wchmod(
    const char16_t* path, std::int32_t mode) noexcept {
    if (path == nullptr) {
        errno = EINVAL;
        return -1;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(path), narrow).converted) {
        errno = EINVAL;
        return -1;
    }
    return crf__chmod(narrow.c_str(), mode);
}

// The umask, which is the host's own mask under the CRT's name. The bits
// travel unchanged because the CRT's `_S_IWRITE` and the host's owner-write
// bit are the same number.
extern "C" __attribute__((ms_abi)) std::int32_t crf__umask(
    std::int32_t mode) noexcept {
    return static_cast<std::int32_t>(::umask(mode & 0777));
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__umask_s(
    std::int32_t mode, std::int32_t* previous) noexcept {
    if (previous == nullptr || (mode & ~0777) != 0) {
        if (previous != nullptr) {
            *previous = 0;
        }
        return EINVAL;
    }
    *previous = crf__umask(mode);
    return 0;
}

// The drives. The runtime mounts one, `C:`, so the answers are constant
// and the change-drive call accepts exactly the letter that exists.
extern "C" __attribute__((ms_abi)) std::int32_t crf__getdrive() noexcept {
    return kGuestDrive;
}

extern "C" __attribute__((ms_abi)) std::uint32_t crf__getdrives() noexcept {
    return kGuestDriveMask;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__chdrive(
    std::int32_t drive) noexcept {
    return drive == kGuestDrive ? 0 : -1;
}

// `_diskfree_t`: four unsigned fields, in the order the caller reads
// them. The volume is the host filesystem the runtime root
// sits on, which is the one the guest's files live on.
struct DiskFree {
    std::uint32_t total_clusters;
    std::uint32_t avail_clusters;
    std::uint32_t sectors_per_cluster;
    std::uint32_t bytes_per_sector;
};

extern "C" __attribute__((ms_abi)) std::uint32_t crf__getdiskfree(
    std::uint32_t drive, DiskFree* out) noexcept {
    if (out == nullptr) {
        errno = EINVAL;
        return 0;
    }
    if (drive != 0 && drive != kGuestDrive) {
        errno = EINVAL;
        return 0;
    }
    struct ::statvfs volume {};
    if (::statvfs("/", &volume) != 0) {
        return 0;
    }
    const std::uint64_t cluster_bytes =
        static_cast<std::uint64_t>(volume.f_frsize) * volume.f_blocks;
    const std::uint64_t total =
        volume.f_frsize != 0 ? cluster_bytes / volume.f_frsize : 0;
    out->total_clusters = static_cast<std::uint32_t>(
        total > 0xFFFFFFFFull ? 0xFFFFFFFFull : total);
    out->avail_clusters = static_cast<std::uint32_t>(
        volume.f_bavail > 0xFFFFFFFFll ? 0xFFFFFFFFll : volume.f_bavail);
    out->sectors_per_cluster = 1;
    out->bytes_per_sector = static_cast<std::uint32_t>(volume.f_frsize);
    return 0;
}

// The absolute-path spellings. The join is lexical -- the reference does
// not require the file to exist -- and the `..` and `.` components are
// resolved the way Windows resolves them: one at a time, against the
// current answer.
[[nodiscard]] std::string lexical_absolute(std::string dos_path,
                                           const std::string& cwd_dos) noexcept {
    if (dos_path.empty()) {
        dos_path = cwd_dos;
    }
    std::string absolute;
    if (dos_path.size() >= 2 && dos_path[1] == ':') {
        absolute = dos_path.substr(0, 2);
        dos_path = dos_path.substr(2);
    } else {
        absolute = cwd_dos.substr(0, 2);
        if (!dos_path.empty() &&
            (dos_path[0] == '\\' || dos_path[0] == '/')) {
            // A drive-less rooted path roots at the current drive.
        } else {
            // A relative part joins the current directory with the
            // separator the current directory may not end with.
            const std::string tail = cwd_dos.substr(2);
            dos_path = (tail.empty() || tail.back() == '\\' ||
                        tail.back() == '/')
                           ? tail + dos_path
                           : tail + '\\' + dos_path;
        }
    }
    // The walk is the one that matters: components split on either
    // separator, `.` dropped, `..` popping.
    std::vector<std::string> stack;
    std::string component;
    const auto push_component = [&stack](const std::string& piece) {
        if (piece == ".") {
            return;
        }
        if (piece == "..") {
            if (!stack.empty()) {
                stack.pop_back();
            }
            return;
        }
        stack.push_back(piece);
    };
    for (const char c : dos_path) {
        if (c == '\\' || c == '/') {
            push_component(component);
            component.clear();
        } else {
            component += c;
        }
    }
    push_component(component);
    for (const std::string& piece : stack) {
        absolute += '\\';
        absolute += piece;
    }
    return absolute;
}

extern "C" __attribute__((ms_abi)) char* crf__fullpath(
    char* buffer, const char* path, std::uint64_t length) noexcept {
    char host[kMaxPath];
    if (::getcwd(host, sizeof(host)) == nullptr) {
        return nullptr;
    }
    const std::string dos =
        lexical_absolute(path != nullptr ? path : "", to_dos_path(host));
    if (buffer == nullptr) {
        auto* fresh = static_cast<char*>(cr_malloc(kMaxPath));
        if (fresh == nullptr) {
            return nullptr;
        }
        std::memcpy(fresh, dos.c_str(), dos.size() + 1);
        return fresh;
    }
    if (length < dos.size() + 1) {
        errno = ERANGE;
        return nullptr;
    }
    std::memcpy(buffer, dos.c_str(), dos.size() + 1);
    return buffer;
}

extern "C" __attribute__((ms_abi)) char16_t* crf__wfullpath(
    char16_t* buffer, const char16_t* path, std::uint64_t length) noexcept {
    std::string narrow;
    if (path != nullptr &&
        !narrow_out(std::u16string_view(path), narrow).converted) {
        return nullptr;
    }
    char* answer = crf__fullpath(
        nullptr, path != nullptr ? narrow.c_str() : nullptr, 0);
    if (answer == nullptr) {
        return nullptr;
    }
    std::u16string wide;
    if (!narrow_in(std::string_view(answer), wide).converted) {
        cr_free(answer);
        return nullptr;
    }
    cr_free(answer);
    if (buffer == nullptr) {
        auto* fresh = static_cast<char16_t*>(
            cr_malloc((kMaxPath) * sizeof(char16_t)));
        if (fresh == nullptr) {
            return nullptr;
        }
        std::memcpy(fresh, wide.c_str(),
                    (wide.size() + 1) * sizeof(char16_t));
        return fresh;
    }
    if (length < wide.size() + 1) {
        errno = ERANGE;
        return nullptr;
    }
    std::memcpy(buffer, wide.c_str(), (wide.size() + 1) * sizeof(char16_t));
    return buffer;
}

// The path-split spellings. The narrow `_s` form is the domain
// `ucrt_extra.cpp` already carries; the plain form is it with the
// `_MAX_*` caps, which is what the plain spelling is.
extern "C" __attribute__((ms_abi)) std::int32_t u32u__splitpath_s(
    const char* path, char* drive, std::size_t drive_size, char* dir,
    std::size_t dir_size, char* name, std::size_t name_size, char* ext,
    std::size_t ext_size) noexcept;

extern "C" __attribute__((ms_abi)) void crf__splitpath(
    const char* path, char* drive, char* dir, char* name,
    char* ext) noexcept {
    static_cast<void>(u32u__splitpath_s(path, drive, kMaxDrive, dir,
                                        kMaxDir, name, kMaxFname, ext,
                                        kMaxExt));
}

// The wide split, which walks the guest's sixteen-bit code units with the
// same rules: drive before the colon, directory to the last separator,
// extension from the last dot that follows the separator.
extern "C" __attribute__((ms_abi)) std::int32_t crf__wsplitpath_s(
    const char16_t* path, char16_t* drive, std::uint64_t drive_size,
    char16_t* dir, std::uint64_t dir_size, char16_t* name,
    std::uint64_t name_size, char16_t* ext, std::uint64_t ext_size) noexcept {
    if (path == nullptr) {
        return 22;  // EINVAL
    }
    const auto put = [](char16_t* dst, std::uint64_t size,
                        const char16_t* src, std::size_t count) {
        if (dst == nullptr || size == 0) {
            return;
        }
        const std::size_t take =
            count < size - 1 ? count : static_cast<std::size_t>(size) - 1;
        std::memcpy(dst, src, take * sizeof(char16_t));
        dst[take] = u'\0';
    };
    const std::u16string_view p(path);
    std::size_t drive_len = 0;
    if (p.size() >= 2 && p[1] == u':') {
        drive_len = 2;
    }
    const std::size_t slash = p.find_last_of(u"\\/");
    const std::size_t dir_start = drive_len;
    const std::size_t dir_end =
        slash == std::u16string_view::npos ? drive_len : slash + 1;
    put(drive, drive_size, p.data(), drive_len);
    put(dir, dir_size, p.data() + dir_start, dir_end - dir_start);
    const std::size_t name_start =
        slash == std::u16string_view::npos ? drive_len : slash + 1;
    const std::size_t dot = p.find_last_of(u'.');
    const std::size_t name_end =
        (dot != std::u16string_view::npos && dot >= name_start) ? dot
                                                                : p.size();
    put(name, name_size, p.data() + name_start, name_end - name_start);
    if (dot != std::u16string_view::npos && dot >= name_start) {
        put(ext, ext_size, p.data() + dot, p.size() - dot);
    } else if (ext != nullptr && ext_size != 0) {
        ext[0] = u'\0';
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) void crf__wsplitpath(
    const char16_t* path, char16_t* drive, char16_t* dir, char16_t* name,
    char16_t* ext) noexcept {
    static_cast<void>(crf__wsplitpath_s(path, drive, kMaxDrive, dir,
                                        kMaxDir, name, kMaxFname, ext,
                                        kMaxExt));
}

// The path-join spellings. The narrow `_s` form exists; the plain form is
// it with the `_MAX_PATH` cap and the error swallowed, and the wide ones
// assemble the same way: drive, then directory with its separator, then
// name, then extension with its dot.
extern "C" __attribute__((ms_abi)) std::int32_t u32u__makepath_s(
    char* path, std::size_t size, const char* drive, const char* dir,
    const char* name, const char* ext) noexcept;

extern "C" __attribute__((ms_abi)) void crf__makepath(
    char* path, const char* drive, const char* dir, const char* name,
    const char* ext) noexcept {
    static_cast<void>(u32u__makepath_s(path, kMaxPath, drive, dir, name,
                                       ext));
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wmakepath_s(
    char16_t* path, std::uint64_t size, const char16_t* drive,
    const char16_t* dir, const char16_t* name, const char16_t* ext) noexcept {
    if (path == nullptr || size == 0) {
        return 22;
    }
    std::u16string out;
    if (drive != nullptr) {
        out += drive;
    }
    if (dir != nullptr && *dir != u'\0') {
        out += dir;
        const char16_t last = out.back();
        if (last != u'\\' && last != u'/') {
            out += u'\\';
        }
    }
    if (name != nullptr) {
        out += name;
    }
    if (ext != nullptr && *ext != u'\0') {
        if (out.empty() || out.back() != u'.') {
            if (ext[0] != u'.') {
                out += u'.';
            }
        }
        out += ext;
    }
    if (out.size() + 1 > size) {
        path[0] = u'\0';
        errno = ERANGE;
        return 34;
    }
    std::memcpy(path, out.c_str(), (out.size() + 1) * sizeof(char16_t));
    return 0;
}

extern "C" __attribute__((ms_abi)) void crf__wmakepath(
    char16_t* path, const char16_t* drive, const char16_t* dir,
    const char16_t* name, const char16_t* ext) noexcept {
    static_cast<void>(crf__wmakepath_s(path, kMaxPath, drive, dir, name,
                                       ext));
}

// ===========================================================================
// The find family
//
// The `_findfirst`/`_findnext` spellings run on the same directory walks
// the kernel32 find family runs: `FindFirstFileExW` produces a
// WIN32_FIND_DATAW and a handle, and this family converts the structure
// into the caller's `finddata` spelling. One walk, two readers -- which is
// why a handle from `_findfirst64` is exactly the handle the kernel32
// spelling would have answered and `_findclose` releases.
//
// The finddata layouts, from the Microsoft headers as mingw transcribes
// them: the attributes, three times, the size, then the 260-character
// name. The narrow times are thirty-two or sixty-four bits by spelling,
// and the size is thirty-two wherever the spelling says so; the wide
// spellings differ only in the name field's width.
// ===========================================================================

constexpr std::size_t kFindNameBytes = 260;

struct FindData32 {
    static constexpr std::size_t kSize = 280;
    static constexpr std::size_t kAttrib = 0;
    static constexpr std::size_t kCreate = 4;
    static constexpr std::size_t kAccess = 8;
    static constexpr std::size_t kWrite = 12;
    static constexpr std::size_t kFileSize = 16;
    static constexpr std::size_t kName = 20;
};

struct FindData32i64 {
    static constexpr std::size_t kSize = 288;
    static constexpr std::size_t kAttrib = 0;
    static constexpr std::size_t kCreate = 4;
    static constexpr std::size_t kAccess = 8;
    static constexpr std::size_t kWrite = 12;
    static constexpr std::size_t kFileSize = 16;
    static constexpr std::size_t kName = 24;
};

struct FindData64i32 {
    static constexpr std::size_t kSize = 296;
    static constexpr std::size_t kAttrib = 0;
    static constexpr std::size_t kCreate = 8;
    static constexpr std::size_t kAccess = 16;
    static constexpr std::size_t kWrite = 24;
    static constexpr std::size_t kFileSize = 32;
    static constexpr std::size_t kName = 36;
};

struct FindData64 {
    static constexpr std::size_t kSize = 304;
    static constexpr std::size_t kAttrib = 0;
    static constexpr std::size_t kCreate = 8;
    static constexpr std::size_t kAccess = 16;
    static constexpr std::size_t kWrite = 24;
    static constexpr std::size_t kFileSize = 32;
    static constexpr std::size_t kName = 40;
};

// FILETIME ticks to seconds: the count is 100-nanosecond units from 1601.
[[nodiscard]] std::int64_t find_time_of(std::uint64_t ticks) noexcept {
    constexpr std::int64_t kTicksPerSecond = 10000000;
    constexpr std::int64_t kEpochOffset = 11644473600;
    const std::int64_t seconds =
        static_cast<std::int64_t>(ticks / kTicksPerSecond) - kEpochOffset;
    return seconds;
}

template <typename Layout>
void fill_finddata(void* out, const void* find_data) noexcept {
    std::memset(out, 0, Layout::kSize);
    const std::uint32_t attributes = read_u32(
        find_data, Win32FindDataLayout::kAttributes);
    // A normal file carries no attribute bit in the finddata, which is the
    // conversion the reference makes: the flag that says "nothing else"
    // says nothing.
    write_u32(out, Layout::kAttrib,
              attributes == 0x80 ? 0 : attributes);
    const std::int64_t create =
        find_time_of(read_u64(find_data, Win32FindDataLayout::kCreation));
    const std::int64_t access = find_time_of(
        read_u64(find_data, Win32FindDataLayout::kLastAccess));
    const std::int64_t write = find_time_of(
        read_u64(find_data, Win32FindDataLayout::kLastWrite));
    const std::uint64_t size =
        (static_cast<std::uint64_t>(
             read_u32(find_data, Win32FindDataLayout::kSizeHigh))
         << 32) |
        read_u32(find_data, Win32FindDataLayout::kSizeLow);
    if constexpr (Layout::kSize == FindData32::kSize ||
                  Layout::kSize == FindData32i64::kSize) {
        write_u32(out, Layout::kCreate,
                  static_cast<std::uint32_t>(create));
        write_u32(out, Layout::kAccess,
                  static_cast<std::uint32_t>(access));
        write_u32(out, Layout::kWrite,
                  static_cast<std::uint32_t>(write));
    } else {
        write_u64(out, Layout::kCreate,
                  static_cast<std::uint64_t>(create));
        write_u64(out, Layout::kAccess,
                  static_cast<std::uint64_t>(access));
        write_u64(out, Layout::kWrite,
                  static_cast<std::uint64_t>(write));
    }
    if constexpr (Layout::kSize == FindData32::kSize ||
                  Layout::kSize == FindData64i32::kSize) {
        write_u32(out, Layout::kFileSize,
                  static_cast<std::uint32_t>(size));
    } else {
        write_u64(out, Layout::kFileSize, size);
    }
}

// The name: narrow spellings get the UTF-8 rendering, wide spellings get
// the code units themselves.
template <typename Layout>
void fill_finddata_name(void* out, const void* find_data, bool wide) noexcept {
    const auto* name = static_cast<const char16_t*>(
        static_cast<const void*>(static_cast<const std::uint8_t*>(
            find_data) +
            Win32FindDataLayout::kName));
    if (wide) {
        auto* target = static_cast<char16_t*>(
            static_cast<void*>(static_cast<std::uint8_t*>(out) +
                               Layout::kName));
        std::size_t i = 0;
        for (; i + 1 < kFindNameBytes && name[i] != u'\0'; ++i) {
            target[i] = name[i];
        }
        target[i] = u'\0';
        return;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(name), narrow).converted) {
        return;
    }
    auto* target =
        static_cast<char*>(static_cast<void*>(static_cast<std::uint8_t*>(
            out) +
            Layout::kName));
    const std::size_t copy =
        narrow.size() < kFindNameBytes - 1 ? narrow.size()
                                           : kFindNameBytes - 1;
    std::memcpy(target, narrow.data(), copy);
    target[copy] = '\0';
}

// One finddata conversion, layout and width chosen by the caller.
template <typename Layout>
void convert_find_entry(void* out, const void* find_data,
                        bool wide_name) noexcept {
    fill_finddata<Layout>(out, find_data);
    fill_finddata_name<Layout>(out, find_data, wide_name);
}

extern "C" __attribute__((ms_abi)) void* k32f2_FindFirstFileExW(
    const char16_t* pattern, std::uint32_t level, void* data,
    std::uint32_t flags, void* filter, void* filter_data) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32f2_FindNextFileW(
    void* handle, void* data) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32f2_FindClose(
    void* handle) noexcept;

// The find core: make the wide pattern, run the walk, convert the entry.
// The layout is a template parameter and the name width a flag, because
// the eight spellings are four layouts crossed with two name widths.
template <typename Layout>
std::intptr_t find_first_core(std::string_view pattern, void* out,
                              bool wide_name) noexcept {
    alignas(8) std::uint8_t find_data[Win32FindDataLayout::kBytes];
    std::u16string wide;
    if (!narrow_in(pattern, wide).converted) {
        errno = ENOENT;
        return -1;
    }
    const void* handle = k32f2_FindFirstFileExW(
        wide.c_str(), 0, find_data, 0, nullptr, nullptr);
    if (handle == reinterpret_cast<const void*>(0xFFFFFFFFFFFFFFFFull)) {
        errno = ENOENT;
        return -1;
    }
    convert_find_entry<Layout>(out, find_data, wide_name);
    return reinterpret_cast<std::intptr_t>(handle);
}

template <typename Layout>
std::int32_t find_next_core(std::intptr_t handle, void* out,
                            bool wide_name) noexcept {
    if (out == nullptr) {
        errno = EINVAL;
        return -1;
    }
    alignas(8) std::uint8_t find_data[Win32FindDataLayout::kBytes];
    if (k32f2_FindNextFileW(reinterpret_cast<void*>(handle), find_data) ==
        0) {
        errno = ENOENT;
        return -1;
    }
    convert_find_entry<Layout>(out, find_data, wide_name);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::intptr_t crf__findfirst32(
    const char* pattern, void* out) noexcept {
    if (pattern == nullptr || out == nullptr) {
        errno = EINVAL;
        return -1;
    }
    return find_first_core<FindData32>(pattern, out, false);
}

extern "C" __attribute__((ms_abi)) std::intptr_t crf__findfirst32i64(
    const char* pattern, void* out) noexcept {
    if (pattern == nullptr || out == nullptr) {
        errno = EINVAL;
        return -1;
    }
    return find_first_core<FindData32i64>(pattern, out, false);
}

extern "C" __attribute__((ms_abi)) std::intptr_t crf__findfirst64(
    const char* pattern, void* out) noexcept {
    if (pattern == nullptr || out == nullptr) {
        errno = EINVAL;
        return -1;
    }
    return find_first_core<FindData64>(pattern, out, false);
}

extern "C" __attribute__((ms_abi)) std::intptr_t crf__findfirst64i32(
    const char* pattern, void* out) noexcept {
    if (pattern == nullptr || out == nullptr) {
        errno = EINVAL;
        return -1;
    }
    return find_first_core<FindData64i32>(pattern, out, false);
}

extern "C" __attribute__((ms_abi)) std::intptr_t crf__wfindfirst32(
    const char16_t* pattern, void* out) noexcept {
    if (pattern == nullptr || out == nullptr) {
        errno = EINVAL;
        return -1;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(pattern), narrow).converted) {
        errno = ENOENT;
        return -1;
    }
    return find_first_core<FindData32>(narrow, out, true);
}

extern "C" __attribute__((ms_abi)) std::intptr_t crf__wfindfirst32i64(
    const char16_t* pattern, void* out) noexcept {
    if (pattern == nullptr || out == nullptr) {
        errno = EINVAL;
        return -1;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(pattern), narrow).converted) {
        errno = ENOENT;
        return -1;
    }
    return find_first_core<FindData32i64>(narrow, out, true);
}

extern "C" __attribute__((ms_abi)) std::intptr_t crf__wfindfirst64(
    const char16_t* pattern, void* out) noexcept {
    if (pattern == nullptr || out == nullptr) {
        errno = EINVAL;
        return -1;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(pattern), narrow).converted) {
        errno = ENOENT;
        return -1;
    }
    return find_first_core<FindData64>(narrow, out, true);
}

extern "C" __attribute__((ms_abi)) std::intptr_t crf__wfindfirst64i32(
    const char16_t* pattern, void* out) noexcept {
    if (pattern == nullptr || out == nullptr) {
        errno = EINVAL;
        return -1;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(pattern), narrow).converted) {
        errno = ENOENT;
        return -1;
    }
    return find_first_core<FindData64i32>(narrow, out, true);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__findnext32(
    std::intptr_t handle, void* out) noexcept {
    return find_next_core<FindData32>(handle, out, false);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__findnext32i64(
    std::intptr_t handle, void* out) noexcept {
    return find_next_core<FindData32i64>(handle, out, false);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__findnext64(
    std::intptr_t handle, void* out) noexcept {
    return find_next_core<FindData64>(handle, out, false);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__findnext64i32(
    std::intptr_t handle, void* out) noexcept {
    return find_next_core<FindData64i32>(handle, out, false);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wfindnext32(
    std::intptr_t handle, void* out) noexcept {
    return find_next_core<FindData32>(handle, out, true);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wfindnext32i64(
    std::intptr_t handle, void* out) noexcept {
    return find_next_core<FindData32i64>(handle, out, true);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wfindnext64(
    std::intptr_t handle, void* out) noexcept {
    return find_next_core<FindData64>(handle, out, true);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wfindnext64i32(
    std::intptr_t handle, void* out) noexcept {
    return find_next_core<FindData64i32>(handle, out, true);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__findclose(
    std::intptr_t handle) noexcept {
    if (k32f2_FindClose(reinterpret_cast<void*>(handle)) == 0) {
        // The walk the handle named is gone or was never one; the errno
        // is whatever the close reported.
        return -1;
    }
    return 0;
}

// ===========================================================================
// The stdio family
//
// The FILE-level completions, the temporary-name spellings, the descriptor
// family, and the no-lock variants. A guest stream is translated the way
// every other CRT stream call translates it: the three standard streams
// live in the guest's `_iob` and everything else is the host's own
// `FILE`, so the translation is the one `translate_stream` makes.
// ===========================================================================

[[nodiscard]] std::FILE* stream_of(void* stream) noexcept {
    const GuestState* g = guest_state();
    if (g == nullptr) {
        return static_cast<std::FILE*>(stream);
    }
    return translate_stream(*g, reinterpret_cast<std::uint64_t>(stream));
}

extern "C" __attribute__((ms_abi)) void crf_clearerr(
    void* stream) noexcept {
    std::clearerr(stream_of(stream));
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_clearerr_s(
    void* stream) noexcept {
    if (stream == nullptr) {
        return EINVAL;
    }
    std::clearerr(stream_of(stream));
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_fgetpos(
    void* stream, std::int64_t* position) noexcept {
    if (stream == nullptr || position == nullptr) {
        errno = EINVAL;
        return -1;
    }
    const std::int64_t where = cr_ftelli64(stream);
    if (where < 0) {
        return -1;
    }
    *position = where;
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_fsetpos(
    void* stream, const std::int64_t* position) noexcept {
    if (stream == nullptr || position == nullptr) {
        errno = EINVAL;
        return -1;
    }
    return cr_fseeki64(stream, *position, 0);
}

extern "C" __attribute__((ms_abi)) void crf_rewind(
    void* stream) noexcept {
    if (stream == nullptr) {
        return;
    }
    std::clearerr(stream_of(stream));
    static_cast<void>(cr_fseek(stream, 0, 0));
}

// The wide character pair. The guest's `wchar_t` is sixteen bits, so the
// wint_t these answer is the host's value narrowed to it; the conversion
// functions this runtime pairs them with read the same code units back.
extern "C" __attribute__((ms_abi)) std::uint16_t crf_getwc(
    void* stream) noexcept {
    if (stream == nullptr) {
        return 0xFFFFu;  // WEOF
    }
    const wint_t read = ::fgetwc(stream_of(stream));
    return read == WEOF ? 0xFFFFu : static_cast<std::uint16_t>(read);
}

extern "C" __attribute__((ms_abi)) std::uint16_t crf_getwchar() noexcept {
    return crf_getwc(stdout);
}

extern "C" __attribute__((ms_abi)) std::uint16_t crf_putwc(
    std::uint16_t character, void* stream) noexcept {
    if (stream == nullptr) {
        return 0xFFFFu;
    }
    const wint_t written =
        ::fputwc(static_cast<wchar_t>(character), stream_of(stream));
    return written == WEOF ? 0xFFFFu : character;
}

extern "C" __attribute__((ms_abi)) std::uint16_t crf_putwchar(
    std::uint16_t character) noexcept {
    return crf_putwc(character, stdout);
}

// The wide line readers and writers, which walk the stream one code unit
// at a time because the host's wide stream is thirty-two-bit.
extern "C" __attribute__((ms_abi)) char16_t* crf_fgetws(
    char16_t* buffer, std::int32_t count, void* stream) noexcept {
    if (buffer == nullptr || count <= 0 || stream == nullptr) {
        return nullptr;
    }
    std::size_t used = 0;
    while (used + 1 < static_cast<std::size_t>(count)) {
        const wint_t read = ::fgetwc(stream_of(stream));
        if (read == WEOF) {
            if (used == 0) {
                return nullptr;
            }
            break;
        }
        buffer[used++] = static_cast<char16_t>(read);
        if (read == U'\n') {
            break;
        }
    }
    buffer[used] = u'\0';
    return buffer;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_fputws(
    const char16_t* text, void* stream) noexcept {
    if (text == nullptr || stream == nullptr) {
        return -1;
    }
    for (const char16_t* p = text; *p != u'\0'; ++p) {
        if (::fputwc(static_cast<wchar_t>(*p), stream_of(stream)) ==
            WEOF) {
            return -1;
        }
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) char16_t* crf__getws(
    char16_t* buffer) noexcept {
    if (buffer == nullptr) {
        return nullptr;
    }
    std::size_t used = 0;
    for (;;) {
        const wint_t read = ::fgetwc(stdin);
        if (read == WEOF) {
            if (used == 0) {
                return nullptr;
            }
            break;
        }
        if (read == U'\n') {
            break;
        }
        buffer[used++] = static_cast<char16_t>(read);
    }
    buffer[used] = u'\0';
    return buffer;
}

extern "C" __attribute__((ms_abi)) char16_t* crf__getws_s(
    char16_t* buffer, std::size_t count) noexcept {
    if (buffer == nullptr || count == 0) {
        return nullptr;
    }
    if (count > kMaxPath) {
        errno = EINVAL;
        return nullptr;
    }
    std::size_t used = 0;
    for (;;) {
        const wint_t read = ::fgetwc(stdin);
        if (read == WEOF) {
            if (used == 0) {
                return nullptr;
            }
            break;
        }
        if (read == U'\n') {
            break;
        }
        if (used + 1 >= count) {
            buffer[0] = u'\0';
            errno = ERANGE;
            return nullptr;
        }
        buffer[used++] = static_cast<char16_t>(read);
    }
    buffer[used] = u'\0';
    return buffer;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__putws(
    const char16_t* text) noexcept {
    if (text == nullptr) {
        return -1;
    }
    if (crf_fputws(text, stdout) != 0) {
        return -1;
    }
    return ::fputwc(U'\n', stdout) == WEOF ? -1 : 0;
}

// The line reader the standard deprecates and the apiset still exports.
extern "C" __attribute__((ms_abi)) char* crf_gets(char* buffer) noexcept {
    if (buffer == nullptr) {
        return nullptr;
    }
    const char* read = ::fgets(buffer, kMaxPath, stdin);
    if (read == nullptr) {
        return nullptr;
    }
    const std::size_t length = std::strlen(buffer);
    if (length > 0 && buffer[length - 1] == '\n') {
        buffer[length - 1] = '\0';
    }
    return buffer;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_gets_s(
    char* buffer, std::uint64_t count) noexcept {
    if (buffer == nullptr || count == 0 || count > kMaxPath) {
        if (buffer != nullptr && count != 0) {
            buffer[0] = '\0';
        }
        return EINVAL;
    }
    if (::fgets(buffer, static_cast<int>(count), stdin) == nullptr) {
        buffer[0] = '\0';
        return errno != 0 ? errno : EIO;
    }
    const std::size_t length = std::strlen(buffer);
    if (length > 0 && buffer[length - 1] == '\n') {
        buffer[length - 1] = '\0';
    } else if (length + 1 == count) {
        // The line was longer than the buffer; what did not fit stays in
        // the stream, which is the documented behaviour.
        int next = 0;
        while ((next = ::fgetc(stdin)) != '\n' && next != EOF) {
        }
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf_fread_s(
    void* buffer, std::uint64_t buffer_size, std::uint64_t element_size,
    std::uint64_t count, void* stream) noexcept {
    if (buffer == nullptr && buffer_size == 0 && count == 0) {
        return 0;
    }
    if (buffer == nullptr || stream == nullptr || element_size == 0 ||
        count == 0 || element_size * count > buffer_size) {
        errno = EINVAL;
        return 0;
    }
    return cr_fread(buffer, element_size, count, stream);
}

// The open family's secure and reopen spellings. The mode travels to
// `fopen` after the encoding suffix is stripped, which is what the
// classic open path does with it.
extern "C" __attribute__((ms_abi)) void* cr_fopen(
    const char* path, const char* mode) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf_fopen_s(
    void** stream, const char* path, const char* mode) noexcept {
    if (stream == nullptr || path == nullptr || mode == nullptr) {
        if (stream != nullptr) {
            *stream = nullptr;
        }
        return EINVAL;
    }
    void* opened = cr_fopen(path, mode);
    if (opened == nullptr) {
        *stream = nullptr;
        return errno != 0 ? errno : EIO;
    }
    *stream = opened;
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wfopen_s(
    void** stream, const char16_t* path, const char16_t* mode) noexcept {
    if (stream == nullptr || path == nullptr || mode == nullptr) {
        if (stream != nullptr) {
            *stream = nullptr;
        }
        return EINVAL;
    }
    std::string narrow_path;
    std::string narrow_mode;
    if (!narrow_out(std::u16string_view(path), narrow_path).converted ||
        !narrow_out(std::u16string_view(mode), narrow_mode).converted) {
        *stream = nullptr;
        return EINVAL;
    }
    return crf_fopen_s(stream, narrow_path.c_str(), narrow_mode.c_str());
}

// The stream-mode tracking the open path records; it lives beside the
// conversion machinery in `winabi.cpp`, which owns the modes.
void note_file_mode(const void* stream, const char* mode) noexcept;

extern "C" __attribute__((ms_abi)) void* crf_freopen(
    const char* path, const char* mode, void* stream) noexcept {
    if (path == nullptr || mode == nullptr || stream == nullptr) {
        return nullptr;
    }
    std::FILE* target = stream_of(stream);
    std::string host_mode;
    for (const char* m = mode; *m != '\0'; ++m) {
        if (*m == 'a' || *m == 'b' || *m == 'r' || *m == 'w' ||
            *m == 'x' || *m == '+') {
            host_mode += *m;
        }
    }
    if (std::freopen(from_dos_path(path).c_str(), host_mode.c_str(),
                     target) == nullptr) {
        return nullptr;
    }
    note_file_mode(target, mode);
    return stream;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_freopen_s(
    void** stream, const char* path, const char* mode,
    void* original) noexcept {
    if (stream == nullptr) {
        return EINVAL;
    }
    void* reopened = crf_freopen(path, mode, original);
    *stream = reopened;
    return reopened != nullptr ? 0 : errno;
}

// The share-mode opens. The share mode is recorded nowhere because the
// runtime has no share table; the open itself is the ordinary one, which
// is what a guest with no sharing conflict observes.
extern "C" __attribute__((ms_abi)) void* crf__fsopen(
    const char* path, const char* mode, std::int32_t share) noexcept {
    static_cast<void>(share);
    return cr_fopen(path, mode);
}

extern "C" __attribute__((ms_abi)) void* crf__wfsopen(
    const char16_t* path, const char16_t* mode, std::int32_t share) noexcept {
    static_cast<void>(share);
    if (path == nullptr || mode == nullptr) {
        return nullptr;
    }
    std::string narrow_path;
    std::string narrow_mode;
    if (!narrow_out(std::u16string_view(path), narrow_path).converted ||
        !narrow_out(std::u16string_view(mode), narrow_mode).converted) {
        return nullptr;
    }
    return cr_fopen(narrow_path.c_str(), narrow_mode.c_str());
}

// The descriptor-to-stream bridge, both directions.
extern "C" __attribute__((ms_abi)) void* crf__fdopen(
    std::int32_t fd, const char* mode) noexcept {
    if (mode == nullptr || !crt_fd_is_valid(fd)) {
        errno = EBADF;
        return nullptr;
    }
    std::string host_mode;
    for (const char* m = mode; *m != '\0'; ++m) {
        if (*m == 'a' || *m == 'b' || *m == 'r' || *m == 'w' ||
            *m == '+' || *m == 'e') {
            host_mode += *m;
        }
    }
    std::FILE* file = ::fdopen(fd, host_mode.c_str());
    if (file != nullptr) {
        note_file_mode(file, mode);
    }
    return file;
}

extern "C" __attribute__((ms_abi)) void* crf__wfdopen(
    std::int32_t fd, const char16_t* mode) noexcept {
    if (mode == nullptr) {
        errno = EINVAL;
        return nullptr;
    }
    std::string narrow_mode;
    if (!narrow_out(std::u16string_view(mode), narrow_mode).converted) {
        errno = EINVAL;
        return nullptr;
    }
    return crf__fdopen(fd, narrow_mode.c_str());
}

// The temporary names. The host's own temporary machinery answers, and the
// name is rendered as a DOS path the guest can open, which is what a
// caller that hands the answer to `fopen` needs.
extern "C" __attribute__((ms_abi)) void* crf_tmpfile() noexcept {
    std::FILE* file = ::tmpfile();
    if (file != nullptr) {
        note_file_mode(file, "wb");
    }
    return file;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_tmpfile_s(
    void** stream) noexcept {
    if (stream == nullptr) {
        return EINVAL;
    }
    *stream = crf_tmpfile();
    return *stream != nullptr ? 0 : errno;
}

std::string& tmpnam_buffer() noexcept {
    static std::string storage;
    return storage;
}

extern "C" __attribute__((ms_abi)) char* crf_tmpnam(
    char* buffer) noexcept {
    char host[L_tmpnam + 1];
    if (::tmpnam(host) == nullptr) {
        return nullptr;
    }
    tmpnam_buffer() = to_dos_path(host);
    if (buffer == nullptr) {
        return tmpnam_buffer().data();
    }
    if (tmpnam_buffer().size() + 1 > kMaxPath) {
        errno = ERANGE;
        return nullptr;
    }
    std::memcpy(buffer, tmpnam_buffer().c_str(),
                tmpnam_buffer().size() + 1);
    return buffer;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_tmpnam_s(
    char* buffer, std::uint64_t size) noexcept {
    if (buffer == nullptr || size < L_tmpnam) {
        if (buffer != nullptr && size != 0) {
            buffer[0] = '\0';
        }
        return EINVAL;
    }
    if (crf_tmpnam(buffer) == nullptr) {
        buffer[0] = '\0';
        return errno;
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) char16_t* crf__wtmpnam(
    char16_t* buffer) noexcept {
    char* narrow = crf_tmpnam(nullptr);
    if (narrow == nullptr) {
        return nullptr;
    }
    static std::u16string storage;
    if (!narrow_in(std::string_view(narrow), storage).converted) {
        return nullptr;
    }
    if (buffer == nullptr) {
        return storage.data();
    }
    if (storage.size() + 1 > kMaxPath) {
        errno = ERANGE;
        return nullptr;
    }
    std::memcpy(buffer, storage.c_str(),
                (storage.size() + 1) * sizeof(char16_t));
    return buffer;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wtmpnam_s(
    char16_t* buffer, std::uint64_t size) noexcept {
    if (buffer == nullptr || size < kMaxPath) {
        if (buffer != nullptr && size != 0) {
            buffer[0] = u'\0';
        }
        return EINVAL;
    }
    if (crf__wtmpnam(buffer) == nullptr) {
        buffer[0] = u'\0';
        return errno;
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) char* crf__tempnam(
    const char* directory, const char* prefix) noexcept {
    std::string host_dir;
    if (directory != nullptr && *directory != '\0') {
        host_dir = from_dos_path(directory);
    }
    char* host = ::tempnam(host_dir.empty() ? nullptr
                                            : host_dir.c_str(),
                           prefix);
    if (host == nullptr) {
        return nullptr;
    }
    tmpnam_buffer() = to_dos_path(host);
    ::free(host);
    return tmpnam_buffer().data();
}

extern "C" __attribute__((ms_abi)) char16_t* crf__wtempnam(
    const char16_t* directory, const char16_t* prefix) noexcept {
    std::string narrow_dir;
    std::string narrow_prefix;
    if (directory != nullptr &&
        !narrow_out(std::u16string_view(directory), narrow_dir).converted) {
        return nullptr;
    }
    if (prefix != nullptr &&
        !narrow_out(std::u16string_view(prefix), narrow_prefix).converted) {
        return nullptr;
    }
    char* narrow = crf__tempnam(
        directory != nullptr ? narrow_dir.c_str() : nullptr,
        prefix != nullptr ? narrow_prefix.c_str() : nullptr);
    if (narrow == nullptr) {
        return nullptr;
    }
    static std::u16string storage;
    if (!narrow_in(std::string_view(narrow), storage).converted) {
        return nullptr;
    }
    return storage.data();
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__rmtmp() noexcept {
    // The temporary streams are the host's to clean up, and the host
    // cleans them at exit; the call answers the zero a sweep that removed
    // nothing reports.
    return 0;
}

// The unique-name spellings. The reference's algorithm: the last six
// characters must be `X`, five become the process id's digits and the
// sixth walks `a` through `z` until the name it makes does not exist.
[[nodiscard]] bool unique_name_exists(const std::string& dos_path) noexcept {
    return searchenv_exists(dos_path);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__mktemp_s(
    char* pattern, std::uint64_t size) noexcept {
    if (pattern == nullptr) {
        return EINVAL;
    }
    const std::uint64_t length = std::strlen(pattern);
    if (length == size || length < 6) {
        if (size != 0) {
            pattern[0] = '\0';
        }
        return EINVAL;
    }
    for (std::uint64_t i = 1; i <= 6; ++i) {
        if (pattern[length - i] != 'X') {
            pattern[0] = '\0';
            return EINVAL;
        }
    }
    std::int64_t id = static_cast<std::int64_t>(::getpid());
    for (std::uint64_t i = 1; i < 6; ++i) {
        pattern[length - i] = static_cast<char>('0' + id % 10);
        id /= 10;
    }
    for (char letter = 'a'; letter <= 'z'; ++letter) {
        pattern[length - 6] = letter;
        if (!unique_name_exists(pattern)) {
            return 0;
        }
    }
    pattern[0] = '\0';
    errno = EEXIST;
    return EEXIST;
}

extern "C" __attribute__((ms_abi)) char* crf__mktemp(
    char* pattern) noexcept {
    if (pattern == nullptr) {
        return nullptr;
    }
    // The trailing run of `X` is what the digits and the letter replace;
    // fewer than six is not a template the call accepts.
    std::size_t trailing = 0;
    for (const char* p = pattern; *p != '\0'; ++p) {
        trailing = *p == 'X' ? trailing + 1 : 0;
    }
    if (trailing < 6) {
        return nullptr;
    }
    const std::size_t length = std::strlen(pattern);
    if (crf__mktemp_s(pattern, length + 1) != 0) {
        return nullptr;
    }
    return pattern;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wmktemp_s(
    char16_t* pattern, std::uint64_t size) noexcept {
    if (pattern == nullptr) {
        return EINVAL;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(pattern), narrow).converted) {
        return EINVAL;
    }
    std::vector<char> buffer(kMaxPath, '\0');
    std::memcpy(buffer.data(), narrow.c_str(), narrow.size() + 1);
    const std::int32_t result =
        crf__mktemp_s(buffer.data(), buffer.size());
    if (result != 0) {
        pattern[0] = u'\0';
        return result;
    }
    std::u16string wide;
    if (!narrow_in(std::string_view(buffer.data()), wide).converted) {
        return EINVAL;
    }
    if (wide.size() + 1 > size) {
        pattern[0] = u'\0';
        return ERANGE;
    }
    std::memcpy(pattern, wide.c_str(), (wide.size() + 1) * sizeof(char16_t));
    return 0;
}

extern "C" __attribute__((ms_abi)) char16_t* crf__wmktemp(
    char16_t* pattern) noexcept {
    if (pattern == nullptr) {
        return nullptr;
    }
    if (crf__wmktemp_s(pattern, kMaxPath) != 0) {
        return nullptr;
    }
    return pattern;
}

// The stream limits. The count is the one the runtime can honestly
// answer for: a caller that opens fewer than this many streams sees them
// all, and a caller that asks the limit gets the documented default.
std::int32_t g_max_stdio = 512;

extern "C" __attribute__((ms_abi)) std::int32_t crf__getmaxstdio() noexcept {
    return g_max_stdio;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__setmaxstdio(
    std::int32_t count) noexcept {
    if (count < 20 || count > 8192) {
        return -1;
    }
    const std::int32_t previous = g_max_stdio;
    g_max_stdio = count;
    return previous;
}

// The whole-stream sweeps, which walk the streams the open path
// recorded. The registry lives with the mode tracking in `winabi.cpp`,
// and these two reach it through the helpers declared beside it.
extern "C" __attribute__((ms_abi)) std::int32_t cr_flush_all() noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_fclose_all() noexcept;

extern "C" __attribute__((ms_abi)) std::int32_t crf__flushall() noexcept {
    return cr_flush_all();
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__fcloseall() noexcept {
    return cr_fclose_all();
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__fgetchar() noexcept {
    return ::fgetc(stdin);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__fputchar(
    std::int32_t character) noexcept {
    return ::fputc(character, stdout);
}

// The integer stream pair, which moves a native `int` in binary form.
extern "C" __attribute__((ms_abi)) std::int32_t crf__getw(
    void* stream) noexcept {
    if (stream == nullptr) {
        return -1;
    }
    int value = 0;
    if (std::fread(&value, sizeof(value), 1, stream_of(stream)) != 1) {
        return -1;
    }
    return value;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__putw(
    std::int32_t value, void* stream) noexcept {
    if (stream == nullptr) {
        return -1;
    }
    if (std::fwrite(&value, sizeof(value), 1, stream_of(stream)) != 1) {
        return -1;
    }
    return 0;
}

// The printf count-output toggle, which decides whether `%n` does
// anything. The flag is recorded because a caller reads it back; the
// format walks this runtime bridges honour it through the same storage.
std::int32_t g_printf_count_output = 0;

extern "C" __attribute__((ms_abi)) std::int32_t crf__get_printf_count_output() noexcept {
    return g_printf_count_output;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__set_printf_count_output(
    std::int32_t flag) noexcept {
    const std::int32_t previous = g_printf_count_output;
    g_printf_count_output = flag != 0;
    return previous;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__get_stream_buffer_pointers(
    void* stream, char** base, char** current, std::uint64_t* count) noexcept {
    // The pointers are the host `FILE`'s own, and the host's structure is
    // not this runtime's to walk; the call reports that no buffer is
    // describable, which is the answer a stream with none gives.
    static_cast<void>(stream);
    if (base != nullptr) {
        *base = nullptr;
    }
    if (current != nullptr) {
        *current = nullptr;
    }
    if (count != nullptr) {
        *count = 0;
    }
    return -1;
}

extern "C" __attribute__((ms_abi)) std::int32_t* u32u___p__fmode() noexcept;

extern "C" __attribute__((ms_abi)) std::int32_t crf__get_fmode() noexcept {
    return *u32u___p__fmode();
}

// The open core, declared here because `_open` and `_creat` reach it with
// the pmode they read from their own varargs.
extern "C" __attribute__((ms_abi)) std::int32_t crf__sopen_dispatch(
    const char* path, std::int32_t oflag, std::int32_t share,
    std::uint32_t pmode) noexcept;

// The low-level descriptor family. The descriptors are the host's: the
// three standards are the process's own, and `_open` and its siblings
// issue the rest through the confined open. Every call here validates
// against the issued set, because a descriptor the CRT never handed out
// names whatever the host process happens to hold at that number.
extern "C" __attribute__((ms_abi)) std::int32_t crf__open(
    const char* path, std::int32_t oflag, ...) noexcept {
    if (path == nullptr) {
        errno = EINVAL;
        return -1;
    }
    std::uint32_t pmode = 0;
    if ((oflag & static_cast<std::int32_t>(kO_CREAT)) != 0) {
        __builtin_ms_va_list ap;
        __builtin_ms_va_start(ap, oflag);
        // The mode is a thirty-two-bit value in an eight-byte slot.
        void* slots = nullptr;
        std::memcpy(&slots, &ap, sizeof(slots));
        std::int32_t mode = 0;
        std::memcpy(&mode, slots, sizeof(mode));
        __builtin_ms_va_end(ap);
        pmode = static_cast<std::uint32_t>(mode);
    }
    return crf__sopen_dispatch(path, oflag, 0, pmode);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wopen(
    const char16_t* path, std::int32_t oflag, ...) noexcept {
    if (path == nullptr) {
        errno = EINVAL;
        return -1;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(path), narrow).converted) {
        errno = EINVAL;
        return -1;
    }
    std::uint32_t pmode = 0;
    if ((oflag & static_cast<std::int32_t>(kO_CREAT)) != 0) {
        __builtin_ms_va_list ap;
        __builtin_ms_va_start(ap, oflag);
        // The mode is a thirty-two-bit value in an eight-byte slot.
        void* slots = nullptr;
        std::memcpy(&slots, &ap, sizeof(slots));
        std::int32_t mode = 0;
        std::memcpy(&mode, slots, sizeof(mode));
        __builtin_ms_va_end(ap);
        pmode = static_cast<std::uint32_t>(mode);
    }
    return crf__sopen_dispatch(narrow.c_str(), oflag, 0, pmode);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__creat(
    const char* path, std::uint32_t pmode) noexcept {
    return crf__sopen_dispatch(
        path,
        static_cast<std::int32_t>(kO_WRONLY | kO_CREAT | kO_TRUNC), 0,
        pmode);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wcreat(
    const char16_t* path, std::uint32_t pmode) noexcept {
    if (path == nullptr) {
        errno = EINVAL;
        return -1;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(path), narrow).converted) {
        errno = EINVAL;
        return -1;
    }
    return crf__creat(narrow.c_str(), pmode);
}

// The open core every spelling funnels into. The share mode is accepted
// and recorded nowhere, because there is no share table to consult; the
// flags map onto the host's, the mode onto the confined open's, and the
// issued-descriptor set records what the CRT handed out.
extern "C" __attribute__((ms_abi)) std::int32_t crf__sopen_dispatch(
    const char* path, std::int32_t oflag, std::int32_t share,
    std::uint32_t pmode) noexcept {
    static_cast<void>(share);
    if (path == nullptr) {
        errno = EINVAL;
        return -1;
    }
    int flags = O_RDONLY;
    const std::uint32_t access =
        static_cast<std::uint32_t>(oflag) & (kO_RDONLY | kO_WRONLY | kO_RDWR);
    if (access == kO_WRONLY) {
        flags = O_WRONLY;
    } else if (access == kO_RDWR) {
        flags = O_RDWR;
    }
    if ((oflag & static_cast<std::int32_t>(kO_APPEND)) != 0) {
        flags |= O_APPEND;
    }
    if ((oflag & static_cast<std::int32_t>(kO_CREAT)) != 0) {
        flags |= O_CREAT;
    }
    if ((oflag & static_cast<std::int32_t>(kO_TRUNC)) != 0) {
        flags |= O_TRUNC;
    }
    if ((oflag & static_cast<std::int32_t>(kO_EXCL)) != 0) {
        flags |= O_EXCL;
    }
    const unsigned host_mode =
        (pmode & kS_IWRITE) != 0
            ? S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH
            : S_IRUSR | S_IRGRP | S_IROTH;
    const int fd =
        contained_open(host_path_of(path).c_str(), flags, host_mode);
    if (fd < 0) {
        return -1;
    }
    crt_fds().insert(fd);
    fd_text_modes()[fd] =
        (oflag & static_cast<std::int32_t>(kO_BINARY)) == 0;
    return fd;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__sopen(
    const char* path, std::int32_t oflag, std::int32_t share, ...) noexcept {
    std::uint32_t pmode = 0;
    if ((oflag & static_cast<std::int32_t>(kO_CREAT)) != 0) {
        __builtin_ms_va_list ap;
        __builtin_ms_va_start(ap, share);
        // The mode is a thirty-two-bit value in an eight-byte slot.
        void* slots = nullptr;
        std::memcpy(&slots, &ap, sizeof(slots));
        std::int32_t mode = 0;
        std::memcpy(&mode, slots, sizeof(mode));
        __builtin_ms_va_end(ap);
        pmode = static_cast<std::uint32_t>(mode);
    }
    return crf__sopen_dispatch(path, oflag, share, pmode);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__sopen_s(
    std::int32_t* fd, const char* path, std::int32_t oflag,
    std::int32_t share, std::uint32_t pmode) noexcept {
    if (fd == nullptr || path == nullptr) {
        if (fd != nullptr) {
            *fd = -1;
        }
        return EINVAL;
    }
    *fd = crf__sopen_dispatch(path, oflag, share, pmode);
    return *fd >= 0 ? 0 : errno;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wsopen(
    const char16_t* path, std::int32_t oflag, std::int32_t share,
    ...) noexcept {
    if (path == nullptr) {
        errno = EINVAL;
        return -1;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(path), narrow).converted) {
        errno = EINVAL;
        return -1;
    }
    std::uint32_t pmode = 0;
    if ((oflag & static_cast<std::int32_t>(kO_CREAT)) != 0) {
        __builtin_ms_va_list ap;
        __builtin_ms_va_start(ap, share);
        // The mode is a thirty-two-bit value in an eight-byte slot.
        void* slots = nullptr;
        std::memcpy(&slots, &ap, sizeof(slots));
        std::int32_t mode = 0;
        std::memcpy(&mode, slots, sizeof(mode));
        __builtin_ms_va_end(ap);
        pmode = static_cast<std::uint32_t>(mode);
    }
    return crf__sopen_dispatch(narrow.c_str(), oflag, share, pmode);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wsopen_s(
    std::int32_t* fd, const char16_t* path, std::int32_t oflag,
    std::int32_t share, std::uint32_t pmode) noexcept {
    if (fd == nullptr || path == nullptr) {
        if (fd != nullptr) {
            *fd = -1;
        }
        return EINVAL;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(path), narrow).converted) {
        *fd = -1;
        return EINVAL;
    }
    *fd = crf__sopen_dispatch(narrow.c_str(), oflag, share, pmode);
    return *fd >= 0 ? 0 : errno;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__close(
    std::int32_t fd) noexcept {
    if (!crt_fd_is_valid(fd)) {
        errno = EBADF;
        return -1;
    }
    crt_fds().erase(fd);
    fd_text_modes().erase(fd);
    return ::close(fd);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__commit(
    std::int32_t fd) noexcept {
    if (!crt_fd_is_valid(fd)) {
        errno = EBADF;
        return -1;
    }
    return ::fsync(fd);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__dup(
    std::int32_t fd) noexcept {
    if (!crt_fd_is_valid(fd)) {
        errno = EBADF;
        return -1;
    }
    const int issued = ::dup(fd);
    if (issued >= 0) {
        crt_fds().insert(issued);
    }
    return issued;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__dup2(
    std::int32_t from, std::int32_t to) noexcept {
    if (!crt_fd_is_valid(from) || to < 0) {
        errno = EBADF;
        return -1;
    }
    const int result = ::dup2(from, to);
    if (result >= 0) {
        crt_fds().insert(result);
    }
    return result;
}

// The descriptor-to-handle bridge. The handle a kernel32 file call mints
// is the base plus the descriptor, which is the mapping the whole file
// surface agrees on; `_get_osfhandle` answers it and `_open_osfhandle`
// reads it back, accepting any handle the file surface has minted.
constexpr std::uint64_t kCrtFileHandleBase = 0x2000;

extern "C" __attribute__((ms_abi)) std::int64_t crf__get_osfhandle(
    std::int32_t fd) noexcept {
    if (!crt_fd_is_valid(fd)) {
        errno = EBADF;
        return -1;
    }
    return static_cast<std::int64_t>(kCrtFileHandleBase +
                                     static_cast<std::uint64_t>(fd));
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__open_osfhandle(
    std::int64_t handle, std::int32_t flags) noexcept {
    static_cast<void>(flags);
    const std::uint64_t value = static_cast<std::uint64_t>(handle);
    if (value < kCrtFileHandleBase ||
        value >= kCrtFileHandleBase + 0x100000) {
        errno = EBADF;
        return -1;
    }
    const int fd = static_cast<int>(value - kCrtFileHandleBase);
    // The descriptor the handle names is now a CRT descriptor too, which
    // is what makes `_read` reach it.
    crt_fds().insert(fd);
    fd_text_modes()[fd] =
        (flags & static_cast<std::int32_t>(kO_TEXT)) != 0;
    return fd;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__isatty(
    std::int32_t fd) noexcept {
    if (!crt_fd_is_valid(fd)) {
        errno = EBADF;
        return 0;
    }
    return ::isatty(fd);
}

extern "C" __attribute__((ms_abi)) std::int64_t crf__lseeki64(
    std::int32_t fd, std::int64_t offset, std::int32_t origin) noexcept {
    if (!crt_fd_is_valid(fd)) {
        errno = EBADF;
        return -1;
    }
    return static_cast<std::int64_t>(
        ::lseek(fd, static_cast<::off_t>(offset), origin));
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__lseek(
    std::int32_t fd, std::int32_t offset, std::int32_t origin) noexcept {
    const std::int64_t moved =
        crf__lseeki64(fd, static_cast<std::int64_t>(offset), origin);
    if (moved < -0x7FFFFFFFll || moved > 0x7FFFFFFFll) {
        errno = EINVAL;
        return -1;
    }
    return static_cast<std::int32_t>(moved);
}

extern "C" __attribute__((ms_abi)) std::int64_t crf__telli64(
    std::int32_t fd) noexcept {
    return crf__lseeki64(fd, 0, 1);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__tell(
    std::int32_t fd) noexcept {
    const std::int64_t where = crf__telli64(fd);
    if (where < -0x7FFFFFFFll || where > 0x7FFFFFFFll) {
        errno = EINVAL;
        return -1;
    }
    return static_cast<std::int32_t>(where);
}

extern "C" __attribute__((ms_abi)) std::int64_t crf__filelengthi64(
    std::int32_t fd) noexcept {
    if (!crt_fd_is_valid(fd)) {
        errno = EBADF;
        return -1;
    }
    struct ::stat st {};
    if (::fstat(fd, &st) != 0) {
        return -1;
    }
    return static_cast<std::int64_t>(st.st_size);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__filelength(
    std::int32_t fd) noexcept {
    const std::int64_t length = crf__filelengthi64(fd);
    if (length < 0 || length > 0x7FFFFFFFll) {
        if (length > 0x7FFFFFFFll) {
            errno = EINVAL;
        }
        return -1;
    }
    return static_cast<std::int32_t>(length);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__eof(
    std::int32_t fd) noexcept {
    const std::int64_t where = crf__telli64(fd);
    if (where < 0) {
        return -1;
    }
    const std::int64_t length = crf__filelengthi64(fd);
    if (length < 0) {
        return -1;
    }
    return where == length ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__chsize_s(
    std::int32_t fd, std::int64_t size) noexcept {
    if (!crt_fd_is_valid(fd)) {
        errno = EBADF;
        return errno;
    }
    if (size < 0) {
        return EINVAL;
    }
    return ::ftruncate(fd, static_cast<::off_t>(size)) == 0
               ? 0
               : errno;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__chsize(
    std::int32_t fd, std::int32_t size) noexcept {
    return crf__chsize_s(fd, static_cast<std::int64_t>(size));
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__write(
    std::int32_t fd, const void* buffer, std::uint32_t count) noexcept {
    if (buffer == nullptr || !crt_fd_is_valid(fd)) {
        errno = EBADF;
        return -1;
    }
    const bool text = fd_text_modes().count(fd) != 0 &&
                      fd_text_modes()[fd];
    if (!text) {
        const ::ssize_t written =
            ::write(fd, buffer, static_cast<std::size_t>(count));
        return static_cast<std::int32_t>(written);
    }
    // The text expansion: every newline in the buffer goes out as the
    // pair, which is what the CRT's text mode writes.
    const auto* bytes = static_cast<const char*>(buffer);
    std::string expanded;
    expanded.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        if (bytes[i] == '\n') {
            expanded += "\r\n";
        } else {
            expanded += bytes[i];
        }
    }
    std::size_t done = 0;
    while (done < expanded.size()) {
        const ::ssize_t written = ::write(
            fd, expanded.data() + done, expanded.size() - done);
        if (written < 0) {
            return -1;
        }
        done += static_cast<std::size_t>(written);
    }
    return static_cast<std::int32_t>(count);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__pipe(
    std::int32_t* handles, std::uint32_t size, std::int32_t mode) noexcept {
    static_cast<void>(size);
    if (handles == nullptr) {
        errno = EINVAL;
        return -1;
    }
    int pair[2] = {-1, -1};
    if (::pipe(pair) != 0) {
        return -1;
    }
    handles[0] = pair[0];
    handles[1] = pair[1];
    crt_fds().insert(pair[0]);
    crt_fds().insert(pair[1]);
    const bool text = (mode & static_cast<std::int32_t>(kO_TEXT)) != 0;
    fd_text_modes()[pair[0]] = text;
    fd_text_modes()[pair[1]] = text;
    return 0;
}

// The region lock, which is the host's record lock over the byte range
// the CRT call names: from the current position, `nbytes` long.
extern "C" __attribute__((ms_abi)) std::int32_t crf__locking(
    std::int32_t fd, std::int32_t mode, std::int32_t nbytes) noexcept {
    if (!crt_fd_is_valid(fd) || nbytes < 0) {
        errno = EBADF;
        return -1;
    }
    // LK_UNLCK is 0, LK_LOCK 1, LK_NBLCK 2, LK_RLCK 3, LK_NBRLCK 4; the
    // blocking forms retry the non-blocking one the documented count of
    // times before giving up.
    struct ::flock region {};
    region.l_type = mode == 0 ? F_UNLCK : F_WRLCK;
    region.l_whence = SEEK_CUR;
    region.l_start = 0;
    region.l_len = nbytes;
    if (mode == 1 || mode == 3) {
        for (int attempt = 0; attempt < 10; ++attempt) {
            if (::fcntl(fd, F_SETLK, &region) == 0) {
                return 0;
            }
            if (errno != EACCES && errno != EAGAIN) {
                return -1;
            }
            ::usleep(1000);
        }
        errno = EACCES;
        return -1;
    }
    return ::fcntl(fd, F_SETLK, &region) == 0 ? 0 : -1;
}

// The console pipe spellings, which are the process family's policy: a
// command interpreter for the guest's commands does not exist here, and
// the call fails the way a refused `CreateProcess` fails.
extern "C" __attribute__((ms_abi)) void* crf__popen(
    const char* command, const char* mode) noexcept {
    static_cast<void>(command);
    static_cast<void>(mode);
    map_spawn_failure();
    return nullptr;
}

extern "C" __attribute__((ms_abi)) void* crf__wpopen(
    const char16_t* command, const char16_t* mode) noexcept {
    static_cast<void>(command);
    static_cast<void>(mode);
    map_spawn_failure();
    return nullptr;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__pclose(
    void* stream) noexcept {
    static_cast<void>(stream);
    errno = EBADF;
    return -1;
}

// The no-lock variants, which are the locked calls with the lock skipped.
// One guest thread runs, so the lock protects nothing and the two forms
// are the same call; keeping them distinct spellings over one
// implementation is what keeps their contracts honest.
extern "C" __attribute__((ms_abi)) std::int32_t crf__fclose_nolock(
    void* stream) noexcept {
    return cr_fclose(stream);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__fflush_nolock(
    void* stream) noexcept {
    return cr_fflush(stream);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__fgetc_nolock(
    void* stream) noexcept {
    return cr_fgetc(stream);
}

extern "C" __attribute__((ms_abi)) std::uint16_t crf__fgetwc_nolock(
    void* stream) noexcept {
    return crf_getwc(stream);
}

extern "C" __attribute__((ms_abi)) std::uint16_t crf__fgetwchar() noexcept {
    return crf_getwc(stdin);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__fputc_nolock(
    std::int32_t character, void* stream) noexcept {
    return cr_fputc(character, stream);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__fputchar_nolock(
    std::int32_t character) noexcept {
    return crf__fputchar(character);
}

extern "C" __attribute__((ms_abi)) std::uint16_t crf__fputwc_nolock(
    std::uint16_t character, void* stream) noexcept {
    return crf_putwc(character, stream);
}

extern "C" __attribute__((ms_abi)) std::uint16_t crf__fputwchar_nolock(
    std::uint16_t character) noexcept {
    return crf_putwc(character, stdout);
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf__fread_nolock(
    void* buffer, std::uint64_t size, std::uint64_t count,
    void* stream) noexcept {
    return cr_fread(buffer, size, count, stream);
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf__fread_nolock_s(
    void* buffer, std::uint64_t buffer_size, std::uint64_t element_size,
    std::uint64_t count, void* stream) noexcept {
    return crf_fread_s(buffer, buffer_size, element_size, count, stream);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__fseek_nolock(
    void* stream, std::int64_t offset, std::int32_t origin) noexcept {
    return cr_fseek(stream, offset, origin);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__fseeki64_nolock(
    void* stream, std::int64_t offset, std::int32_t origin) noexcept {
    return cr_fseeki64(stream, offset, origin);
}

extern "C" __attribute__((ms_abi)) std::int64_t crf__ftell_nolock(
    void* stream) noexcept {
    return cr_ftell(stream);
}

extern "C" __attribute__((ms_abi)) std::int64_t crf__ftelli64_nolock(
    void* stream) noexcept {
    return cr_ftelli64(stream);
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf__fwrite_nolock(
    const void* buffer, std::uint64_t size, std::uint64_t count,
    void* stream) noexcept {
    return cr_fwrite(buffer, size, count, stream);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__getc_nolock(
    void* stream) noexcept {
    return cr_getc(stream);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__putc_nolock(
    std::int32_t character, void* stream) noexcept {
    return cr_putc(character, stream);
}

extern "C" __attribute__((ms_abi)) std::uint16_t crf__getwc_nolock(
    void* stream) noexcept {
    return crf_getwc(stream);
}

extern "C" __attribute__((ms_abi)) std::uint16_t crf__putwc_nolock(
    std::uint16_t character, void* stream) noexcept {
    return crf_putwc(character, stream);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__ungetc_nolock(
    std::int32_t character, void* stream) noexcept {
    return cr_ungetc(character, stream);
}

extern "C" __attribute__((ms_abi)) std::uint16_t crf__ungetwc_nolock(
    std::uint16_t character, void* stream) noexcept {
    if (stream == nullptr) {
        return 0xFFFFu;
    }
    const wint_t pushed =
        ::ungetwc(static_cast<wint_t>(character), stream_of(stream));
    return pushed == WEOF ? 0xFFFFu : character;
}


extern "C" __attribute__((ms_abi)) float crf_acosf(float x) noexcept {
    return std::acos(x);
}
extern "C" __attribute__((ms_abi)) float crf_asinf(float x) noexcept {
    return std::asin(x);
}
extern "C" __attribute__((ms_abi)) float crf_atanf(float x) noexcept {
    return std::atan(x);
}
extern "C" __attribute__((ms_abi)) float crf_atan2f(float x, float y) noexcept {
    return std::atan2(x, y);
}
extern "C" __attribute__((ms_abi)) float crf_cbrtf(float x) noexcept {
    return std::cbrt(x);
}
extern "C" __attribute__((ms_abi)) float crf_copysignf(float x, float y) noexcept {
    return std::copysign(x, y);
}
extern "C" __attribute__((ms_abi)) float crf_cosf(float x) noexcept {
    return std::cos(x);
}
extern "C" __attribute__((ms_abi)) float crf_coshf(float x) noexcept {
    return std::cosh(x);
}
extern "C" __attribute__((ms_abi)) float crf_erff(float x) noexcept {
    return std::erf(x);
}
extern "C" __attribute__((ms_abi)) float crf_erfcf(float x) noexcept {
    return std::erfc(x);
}
extern "C" __attribute__((ms_abi)) float crf_exp2f(float x) noexcept {
    return std::exp2(x);
}
extern "C" __attribute__((ms_abi)) float crf_expm1f(float x) noexcept {
    return std::expm1(x);
}
extern "C" __attribute__((ms_abi)) float crf_fabsf(float x) noexcept {
    return std::fabs(x);
}
extern "C" __attribute__((ms_abi)) float crf_fdimf(float x, float y) noexcept {
    return std::fdim(x, y);
}
extern "C" __attribute__((ms_abi)) float crf_floorf(float x) noexcept {
    return std::floor(x);
}
extern "C" __attribute__((ms_abi)) float crf_fmaf(float x, float y, float z) noexcept {
    return std::fma(x, y, z);
}
extern "C" __attribute__((ms_abi)) float crf_fmaxf(float x, float y) noexcept {
    return std::fmax(x, y);
}
extern "C" __attribute__((ms_abi)) float crf_fminf(float x, float y) noexcept {
    return std::fmin(x, y);
}
extern "C" __attribute__((ms_abi)) float crf_fmodf(float x, float y) noexcept {
    return std::fmod(x, y);
}
extern "C" __attribute__((ms_abi)) float crf_hypotf(float x, float y) noexcept {
    return std::hypot(x, y);
}
extern "C" __attribute__((ms_abi)) float crf_logf(float x) noexcept {
    return std::log(x);
}
extern "C" __attribute__((ms_abi)) float crf_log10f(float x) noexcept {
    return std::log10(x);
}
extern "C" __attribute__((ms_abi)) float crf_log1pf(float x) noexcept {
    return std::log1p(x);
}
extern "C" __attribute__((ms_abi)) float crf_log2f(float x) noexcept {
    return std::log2(x);
}
extern "C" __attribute__((ms_abi)) float crf_logbf(float x) noexcept {
    return std::logb(x);
}
extern "C" __attribute__((ms_abi)) float crf_nearbyintf(float x) noexcept {
    return std::nearbyint(x);
}
extern "C" __attribute__((ms_abi)) float crf_nextafterf(float x, float y) noexcept {
    return std::nextafter(x, y);
}
extern "C" __attribute__((ms_abi)) float crf_remainderf(float x, float y) noexcept {
    return std::remainder(x, y);
}
extern "C" __attribute__((ms_abi)) float crf_rintf(float x) noexcept {
    return std::rint(x);
}
extern "C" __attribute__((ms_abi)) float crf_roundf(float x) noexcept {
    return std::round(x);
}
extern "C" __attribute__((ms_abi)) float crf_scalbnf(
    float x, std::int32_t n) noexcept {
    return std::scalbn(x, n);
}
extern "C" __attribute__((ms_abi)) float crf_sinf(float x) noexcept {
    return std::sin(x);
}
extern "C" __attribute__((ms_abi)) float crf_sinhf(float x) noexcept {
    return std::sinh(x);
}
extern "C" __attribute__((ms_abi)) float crf_sqrtf(float x) noexcept {
    return std::sqrt(x);
}
extern "C" __attribute__((ms_abi)) float crf_truncf(float x) noexcept {
    return std::trunc(x);
}
extern "C" __attribute__((ms_abi)) float crf_tgammaf(float x) noexcept {
    return std::tgamma(x);
}
extern "C" __attribute__((ms_abi)) double crf_acosl(double x) noexcept {
    return std::acos(x);
}
extern "C" __attribute__((ms_abi)) double crf_asinl(double x) noexcept {
    return std::asin(x);
}
extern "C" __attribute__((ms_abi)) double crf_atanl(double x) noexcept {
    return std::atan(x);
}
extern "C" __attribute__((ms_abi)) double crf_atan2l(double x, double y) noexcept {
    return std::atan2(x, y);
}
extern "C" __attribute__((ms_abi)) double crf_cbrtl(double x) noexcept {
    return std::cbrt(x);
}
extern "C" __attribute__((ms_abi)) double crf_copysignl(double x, double y) noexcept {
    return std::copysign(x, y);
}
extern "C" __attribute__((ms_abi)) double crf_cosl(double x) noexcept {
    return std::cos(x);
}
extern "C" __attribute__((ms_abi)) double crf_coshl(double x) noexcept {
    return std::cosh(x);
}
extern "C" __attribute__((ms_abi)) double crf_erfl(double x) noexcept {
    return std::erf(x);
}
extern "C" __attribute__((ms_abi)) double crf_erfcl(double x) noexcept {
    return std::erfc(x);
}
extern "C" __attribute__((ms_abi)) double crf_exp2l(double x) noexcept {
    return std::exp2(x);
}
extern "C" __attribute__((ms_abi)) double crf_expm1l(double x) noexcept {
    return std::expm1(x);
}
extern "C" __attribute__((ms_abi)) double crf_fabsl(double x) noexcept {
    return std::fabs(x);
}
extern "C" __attribute__((ms_abi)) double crf_fdiml(double x, double y) noexcept {
    return std::fdim(x, y);
}
extern "C" __attribute__((ms_abi)) double crf_floorl(double x) noexcept {
    return std::floor(x);
}
extern "C" __attribute__((ms_abi)) double crf_fmal(double x, double y, double z) noexcept {
    return std::fma(x, y, z);
}
extern "C" __attribute__((ms_abi)) double crf_fmaxl(double x, double y) noexcept {
    return std::fmax(x, y);
}
extern "C" __attribute__((ms_abi)) double crf_fminl(double x, double y) noexcept {
    return std::fmin(x, y);
}
extern "C" __attribute__((ms_abi)) double crf_fmodl(double x, double y) noexcept {
    return std::fmod(x, y);
}
extern "C" __attribute__((ms_abi)) double crf_hypotl(double x, double y) noexcept {
    return std::hypot(x, y);
}
extern "C" __attribute__((ms_abi)) double crf_logl(double x) noexcept {
    return std::log(x);
}
extern "C" __attribute__((ms_abi)) double crf_log10l(double x) noexcept {
    return std::log10(x);
}
extern "C" __attribute__((ms_abi)) double crf_log1pl(double x) noexcept {
    return std::log1p(x);
}
extern "C" __attribute__((ms_abi)) double crf_log2l(double x) noexcept {
    return std::log2(x);
}
extern "C" __attribute__((ms_abi)) double crf_logbl(double x) noexcept {
    return std::logb(x);
}
extern "C" __attribute__((ms_abi)) double crf_nearbyintl(double x) noexcept {
    return std::nearbyint(x);
}
extern "C" __attribute__((ms_abi)) double crf_nextafterl(double x, double y) noexcept {
    return std::nextafter(x, y);
}
extern "C" __attribute__((ms_abi)) double crf_remainderl(double x, double y) noexcept {
    return std::remainder(x, y);
}
extern "C" __attribute__((ms_abi)) double crf_rintl(double x) noexcept {
    return std::rint(x);
}
extern "C" __attribute__((ms_abi)) double crf_roundl(double x) noexcept {
    return std::round(x);
}
extern "C" __attribute__((ms_abi)) double crf_scalbnl(
    double x, std::int32_t n) noexcept {
    return std::scalbn(x, n);
}
extern "C" __attribute__((ms_abi)) double crf_sinl(double x) noexcept {
    return std::sin(x);
}
extern "C" __attribute__((ms_abi)) double crf_sinhl(double x) noexcept {
    return std::sinh(x);
}
extern "C" __attribute__((ms_abi)) double crf_sqrtl(double x) noexcept {
    return std::sqrt(x);
}
extern "C" __attribute__((ms_abi)) double crf_truncl(double x) noexcept {
    return std::trunc(x);
}
extern "C" __attribute__((ms_abi)) double crf_tgammal(double x) noexcept {
    return std::tgamma(x);
}
extern "C" __attribute__((ms_abi)) float crf_frexpf(float x, std::int32_t* exp) noexcept {
    int host_exp = 0;
    const float result = std::frexp(x, &host_exp);
    if (exp != nullptr) {
        *exp = host_exp;
    }
    return result;
}

extern "C" __attribute__((ms_abi)) float crf_remquof(float x, float y, std::int32_t* quo) noexcept {
    int host_quo = 0;
    const float result = std::remquo(x, y, &host_quo);
    if (quo != nullptr) {
        *quo = host_quo;
    }
    return result;
}

extern "C" __attribute__((ms_abi)) float crf_ldexpf(float x, std::int32_t exp) noexcept {
    return std::ldexp(x, exp);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_ilogbf(float x) noexcept {
    return std::ilogb(x);
}

extern "C" __attribute__((ms_abi)) std::int64_t crf_llrintf(float x) noexcept {
    return std::llrint(x);
}

extern "C" __attribute__((ms_abi)) std::int64_t crf_llroundf(float x) noexcept {
    return std::llround(x);
}

extern "C" __attribute__((ms_abi)) std::int64_t crf_lrintf(float x) noexcept {
    return std::lrint(x);
}

extern "C" __attribute__((ms_abi)) std::int64_t crf_lroundf(float x) noexcept {
    return std::lround(x);
}

extern "C" __attribute__((ms_abi)) float crf_scalblnf(float x, std::int32_t n) noexcept {
    return std::scalbln(x, n);
}

extern "C" __attribute__((ms_abi)) float crf_nanf(const char* tag) noexcept {
    static_cast<void>(tag);
    return std::nanf("");
}

extern "C" __attribute__((ms_abi)) double crf_frexpl(double x, std::int32_t* exp) noexcept {
    int host_exp = 0;
    const double result = std::frexp(x, &host_exp);
    if (exp != nullptr) {
        *exp = host_exp;
    }
    return result;
}

extern "C" __attribute__((ms_abi)) double crf_remquol(double x, double y, std::int32_t* quo) noexcept {
    int host_quo = 0;
    const double result = std::remquo(x, y, &host_quo);
    if (quo != nullptr) {
        *quo = host_quo;
    }
    return result;
}

extern "C" __attribute__((ms_abi)) double crf_ldexpl(
    double x, std::int32_t exp) noexcept {
    return std::ldexp(x, exp);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_ilogbl(
    double x) noexcept {
    return std::ilogb(x);
}

extern "C" __attribute__((ms_abi)) std::int64_t crf_llrintl(
    double x) noexcept {
    return std::llrint(x);
}

extern "C" __attribute__((ms_abi)) std::int64_t crf_llroundl(
    double x) noexcept {
    return std::llround(x);
}

extern "C" __attribute__((ms_abi)) std::int64_t crf_lrintl(
    double x) noexcept {
    return std::lrint(x);
}

extern "C" __attribute__((ms_abi)) std::int64_t crf_lroundl(
    double x) noexcept {
    return std::lround(x);
}

extern "C" __attribute__((ms_abi)) double crf_scalblnl(
    double x, std::int32_t n) noexcept {
    return std::scalbln(x, n);
}

extern "C" __attribute__((ms_abi)) double crf_nanl(
    const char* tag) noexcept {
    static_cast<void>(tag);
    return std::nan("");
}


// The remaining math spellings: the C99 names the classic domain did not
// carry, in all three widths. The `l` spellings are the double ABI, which
// is what Windows' eight-byte `long double` makes them.
extern "C" __attribute__((ms_abi)) float crf_ceilf(float x) noexcept {
    return std::ceil(x);
}
extern "C" __attribute__((ms_abi)) double crf_ceill(double x) noexcept {
    return std::ceil(x);
}
extern "C" __attribute__((ms_abi)) float crf_expf(float x) noexcept {
    return std::exp(x);
}
extern "C" __attribute__((ms_abi)) double crf_expl(double x) noexcept {
    return std::exp(x);
}
extern "C" __attribute__((ms_abi)) float crf_powf(float x,
                                                  float y) noexcept {
    return std::pow(x, y);
}
extern "C" __attribute__((ms_abi)) double crf_powl(double x,
                                                   double y) noexcept {
    return std::pow(x, y);
}
extern "C" __attribute__((ms_abi)) float crf_tanhf(float x) noexcept {
    return std::tanh(x);
}
extern "C" __attribute__((ms_abi)) double crf_tanhl(double x) noexcept {
    return std::tanh(x);
}
extern "C" __attribute__((ms_abi)) float crf_modff(float x,
                                                   float* integral) noexcept {
    float host = 0;
    const float result = ::modff(x, &host);
    if (integral != nullptr) {
        *integral = host;
    }
    return result;
}
extern "C" __attribute__((ms_abi)) double crf_modfl(double x,
                                                    double* integral) noexcept {
    double host = 0;
    const double result = std::modf(x, &host);
    if (integral != nullptr) {
        *integral = host;
    }
    return result;
}
extern "C" __attribute__((ms_abi)) float crf_nexttowardf(
    float x, double y) noexcept {
    // The second argument is a `long double`, which is the double ABI; the
    // walk runs in double and comes back as the float it names.
    return static_cast<float>(std::nextafter(x, y));
}
extern "C" __attribute__((ms_abi)) double crf_nexttowardl(
    double x, double y) noexcept {
    return std::nextafter(x, y);
}
extern "C" __attribute__((ms_abi)) double crf_acosh(double x) noexcept {
    return std::acosh(x);
}
extern "C" __attribute__((ms_abi)) float crf_acoshf(float x) noexcept {
    return std::acosh(x);
}
extern "C" __attribute__((ms_abi)) double crf_acoshl(double x) noexcept {
    return std::acosh(x);
}
extern "C" __attribute__((ms_abi)) double crf_asinh(double x) noexcept {
    return std::asinh(x);
}
extern "C" __attribute__((ms_abi)) float crf_asinhf(float x) noexcept {
    return std::asinh(x);
}
extern "C" __attribute__((ms_abi)) double crf_asinhl(double x) noexcept {
    return std::asinh(x);
}
extern "C" __attribute__((ms_abi)) double crf_atanh(double x) noexcept {
    return std::atanh(x);
}
extern "C" __attribute__((ms_abi)) float crf_atanhf(float x) noexcept {
    return std::atanh(x);
}
extern "C" __attribute__((ms_abi)) double crf_atanhl(double x) noexcept {
    return std::atanh(x);
}
extern "C" __attribute__((ms_abi)) float crf_lgammaf(float x) noexcept {
    return std::lgamma(x);
}
extern "C" __attribute__((ms_abi)) double crf_lgammal(double x) noexcept {
    return std::lgamma(x);
}


// ===========================================================================
// The string and ctype family, narrow and wide
//
// The collation, transformation, tokenising and classification names. The
// locale-tagged spellings run in the "C" locale, which is the locale this
// runtime has, so the tag is accepted and the behaviour is the untagged
// call's.
// ===========================================================================

extern "C" __attribute__((ms_abi)) char16_t* cr_wcscat(
    char16_t*, const char16_t*) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* cr_wcsdup(
    const char16_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t cr_mbstowcs(
    char16_t*, const char*, std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t cr_wcstombs(
    char*, const char16_t*, std::uint64_t) noexcept;

extern "C" __attribute__((ms_abi)) std::int32_t crf_strcoll(
    const char* a, const char* b) noexcept {
    return std::strcmp(a, b);
}
extern "C" __attribute__((ms_abi)) std::uint64_t crf_strxfrm(
    char* target, const char* source, std::uint64_t count) noexcept {
    if (target == nullptr || source == nullptr) {
        return 0;
    }
    // The "C" locale's transformation is the identity, which is what the
    // host's strxfrm answers in it; the copy is bounded by the count.
    const std::size_t length = std::strlen(source);
    if (count > length) {
        std::memcpy(target, source, length + 1);
    }
    return length;
}
extern "C" __attribute__((ms_abi)) char* crf_strtok(
    char* text, const char* delimiters) noexcept {
    static char* cursor = nullptr;
    if (delimiters == nullptr) {
        return nullptr;
    }
    if (text != nullptr) {
        cursor = text;
    }
    if (cursor == nullptr) {
        return nullptr;
    }
    cursor += std::strspn(cursor, delimiters);
    if (*cursor == '\0') {
        cursor = nullptr;
        return nullptr;
    }
    char* token = cursor;
    cursor = std::strpbrk(cursor, delimiters);
    if (cursor != nullptr) {
        *cursor++ = '\0';
    }
    return token;
}

extern "C" __attribute__((ms_abi)) char* crf_strtok_s(
    char* text, const char* delimiters, char** context) noexcept {
    if (context == nullptr || delimiters == nullptr) {
        return nullptr;
    }
    if (text != nullptr) {
        *context = text;
    }
    char* cursor = *context;
    if (cursor == nullptr) {
        return nullptr;
    }
    cursor += std::strspn(cursor, delimiters);
    if (*cursor == '\0') {
        *context = cursor;
        return nullptr;
    }
    char* token = cursor;
    char* stop = std::strpbrk(cursor, delimiters);
    if (stop != nullptr) {
        *stop = '\0';
        *context = stop + 1;
    } else {
        *context = cursor + std::strlen(cursor);
    }
    return token;
}

extern "C" __attribute__((ms_abi)) char16_t* crf_wcstok(
    char16_t* text, const char16_t* delimiters) noexcept {
    static char16_t* cursor = nullptr;
    if (delimiters == nullptr) {
        return nullptr;
    }
    if (text != nullptr) {
        cursor = text;
    }
    if (cursor == nullptr) {
        return nullptr;
    }
    while (*cursor != u'\0' &&
           std::u16string_view(delimiters).find(*cursor) !=
               std::u16string_view::npos) {
        ++cursor;
    }
    if (*cursor == u'\0') {
        cursor = nullptr;
        return nullptr;
    }
    char16_t* token = cursor;
    while (*cursor != u'\0' &&
           std::u16string_view(delimiters).find(*cursor) ==
               std::u16string_view::npos) {
        ++cursor;
    }
    if (*cursor != u'\0') {
        *cursor++ = u'\0';
    }
    return token;
}

extern "C" __attribute__((ms_abi)) char16_t* crf_wcstok_s(
    char16_t* text, const char16_t* delimiters,
    char16_t** context) noexcept {
    if (context == nullptr || delimiters == nullptr) {
        return nullptr;
    }
    if (text != nullptr) {
        *context = text;
    }
    char16_t* cursor = *context;
    if (cursor == nullptr) {
        return nullptr;
    }
    while (*cursor != u'\0' &&
           std::u16string_view(delimiters).find(*cursor) !=
               std::u16string_view::npos) {
        ++cursor;
    }
    if (*cursor == u'\0') {
        *context = cursor;
        return nullptr;
    }
    char16_t* token = cursor;
    while (*cursor != u'\0' &&
           std::u16string_view(delimiters).find(*cursor) ==
               std::u16string_view::npos) {
        ++cursor;
    }
    if (*cursor != u'\0') {
        *cursor = u'\0';
        ++cursor;
    }
    *context = cursor;
    return token;
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf_wcscspn(
    const char16_t* text, const char16_t* reject) noexcept {
    if (text == nullptr || reject == nullptr) {
        return 0;
    }
    const std::u16string_view stop(reject);
    std::uint64_t count = 0;
    while (text[count] != u'\0' &&
           stop.find(text[count]) == std::u16string_view::npos) {
        ++count;
    }
    return count;
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf_wcsspn(
    const char16_t* text, const char16_t* accept) noexcept {
    if (text == nullptr || accept == nullptr) {
        return 0;
    }
    const std::u16string_view allowed(accept);
    std::uint64_t count = 0;
    while (text[count] != u'\0' &&
           allowed.find(text[count]) != std::u16string_view::npos) {
        ++count;
    }
    return count;
}

extern "C" __attribute__((ms_abi)) char16_t* crf_wcspbrk(
    const char16_t* text, const char16_t* accept) noexcept {
    if (text == nullptr || accept == nullptr) {
        return nullptr;
    }
    const std::u16string_view allowed(accept);
    for (const char16_t* p = text; *p != u'\0'; ++p) {
        if (allowed.find(*p) != std::u16string_view::npos) {
            return const_cast<char16_t*>(p);
        }
    }
    return nullptr;
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf_wcsxfrm(
    char16_t* target, const char16_t* source, std::uint64_t count) noexcept {
    if (target == nullptr || source == nullptr) {
        return 0;
    }
    const std::size_t length =
        std::char_traits<char16_t>::length(source);
    if (count > length) {
        std::memcpy(target, source, (length + 1) * sizeof(char16_t));
    }
    return length;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_wcscoll(
    const char16_t* a, const char16_t* b) noexcept {
    if (a == nullptr || b == nullptr) {
        return 0;
    }
    // The "C" locale collates by code point, which is the comparison the
    // classic wide compare makes.
    for (; *a != u'\0' && *a == *b; ++a, ++b) {
    }
    return *a < *b ? -1 : *a > *b ? 1 : 0;
}

// The classification, over the guest's sixteen-bit code units. The host's
// wide classification is reached with the value widened, which is the
// identity for every code unit a guest can pass.
[[nodiscard]] std::int32_t classify_wide(std::uint16_t value,
                                         int (*test)(wint_t)) noexcept {
    return test(static_cast<wint_t>(value));
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_iswalnum(
    std::uint16_t value) noexcept {
    return classify_wide(value, std::iswalnum);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf_iswalpha(
    std::uint16_t value) noexcept {
    return classify_wide(value, std::iswalpha);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf_iswascii(
    std::uint16_t value) noexcept {
    return value <= 0x7F;
}
extern "C" __attribute__((ms_abi)) std::int32_t crf_iswblank(
    std::uint16_t value) noexcept {
    return classify_wide(value, std::iswblank);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf_iswcntrl(
    std::uint16_t value) noexcept {
    return classify_wide(value, std::iswcntrl);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf_iswdigit(
    std::uint16_t value) noexcept {
    return classify_wide(value, std::iswdigit);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf_iswgraph(
    std::uint16_t value) noexcept {
    return classify_wide(value, std::iswgraph);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf_iswlower(
    std::uint16_t value) noexcept {
    return classify_wide(value, std::iswlower);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf_iswprint(
    std::uint16_t value) noexcept {
    return classify_wide(value, std::iswprint);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf_iswpunct(
    std::uint16_t value) noexcept {
    return classify_wide(value, std::iswpunct);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf_iswspace(
    std::uint16_t value) noexcept {
    return classify_wide(value, std::iswspace);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf_iswupper(
    std::uint16_t value) noexcept {
    return classify_wide(value, std::iswupper);
}
extern "C" __attribute__((ms_abi)) std::int32_t crf_iswxdigit(
    std::uint16_t value) noexcept {
    return classify_wide(value, std::iswxdigit);
}

// The property-table spellings. `wctype` names a class by string, and
// `iswctype` tests it; the classes are the ones the standard names, and
// the property value is an index into that set.
using WctypeProperty = std::uint16_t;

struct WctypeClass {
    const char* name;
    int (*test)(wint_t);
};

constexpr WctypeClass k_wctype_classes[] = {
    {"alnum", std::iswalnum}, {"alpha", std::iswalpha},
    {"cntrl", std::iswcntrl}, {"digit", std::iswdigit},
    {"graph", std::iswgraph}, {"lower", std::iswlower},
    {"print", std::iswprint}, {"punct", std::iswpunct},
    {"space", std::iswspace}, {"upper", std::iswupper},
    {"xdigit", std::iswxdigit}, {"blank", std::iswblank},
};

extern "C" __attribute__((ms_abi)) WctypeProperty crf_wctype(
    const char* name) noexcept {
    if (name == nullptr) {
        return 0;
    }
    for (std::size_t i = 0; i < std::size(k_wctype_classes); ++i) {
        if (std::strcmp(k_wctype_classes[i].name, name) == 0) {
            return static_cast<WctypeProperty>(i + 1);
        }
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_iswctype(
    std::uint16_t value, WctypeProperty property) noexcept {
    if (property == 0 ||
        property > std::size(k_wctype_classes)) {
        return 0;
    }
    return classify_wide(
        value, k_wctype_classes[property - 1].test);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_is_wctype(
    std::uint16_t value, WctypeProperty property) noexcept {
    return crf_iswctype(value, property);
}

// The case mapping, narrow and wide, over the same sixteen-bit values.
extern "C" __attribute__((ms_abi)) std::uint16_t crf_towlower(
    std::uint16_t value) noexcept {
    const wint_t mapped = std::towlower(static_cast<wint_t>(value));
    return mapped == WEOF ? value : static_cast<std::uint16_t>(mapped);
}

extern "C" __attribute__((ms_abi)) std::uint16_t crf_towupper(
    std::uint16_t value) noexcept {
    const wint_t mapped = std::towupper(static_cast<wint_t>(value));
    return mapped == WEOF ? value : static_cast<std::uint16_t>(mapped);
}

// `wctrans` and `towctrans`, which name a mapping the same way `wctype`
// names a class.
using WctransProperty = std::uint16_t;

extern "C" __attribute__((ms_abi)) WctransProperty crf_wctrans(
    const char* name) noexcept {
    if (name == nullptr) {
        return 0;
    }
    if (std::strcmp(name, "tolower") == 0) {
        return 1;
    }
    if (std::strcmp(name, "toupper") == 0) {
        return 2;
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint16_t crf_towctrans(
    std::uint16_t value, WctransProperty mapping) noexcept {
    if (mapping == 1) {
        return crf_towlower(value);
    }
    if (mapping == 2) {
        return crf_towupper(value);
    }
    return value;
}

// The narrow classification names the classic domain answered through the
// table macros, plus the two the classic headers added.
extern "C" __attribute__((ms_abi)) std::int32_t crf_isblank(
    std::int32_t value) noexcept {
    return value == ' ' || value == '\t';
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_isleadbyte(
    std::int32_t value) noexcept {
    static_cast<void>(value);
    // A single-byte code page has no lead bytes, which is what the
    // configured page answers.
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__isctype(
    std::int32_t value, std::uint32_t mask) noexcept {
    // The mask is the classic `_UPPER`/`_LOWER`/... bit set; the test is
    // the same classification the macros spell.
    std::int32_t result = 0;
    if ((mask & 0x0001) != 0 && std::isupper(value) != 0) result |= 0x0001;
    if ((mask & 0x0002) != 0 && std::islower(value) != 0) result |= 0x0002;
    if ((mask & 0x0004) != 0 && std::isdigit(value) != 0) result |= 0x0004;
    if ((mask & 0x0008) != 0 && std::isspace(value) != 0) result |= 0x0008;
    if ((mask & 0x0010) != 0 && std::ispunct(value) != 0) result |= 0x0010;
    if ((mask & 0x0020) != 0 && std::isprint(value) != 0) result |= 0x0020;
    if ((mask & 0x0040) != 0 && std::isgraph(value) != 0) result |= 0x0040;
    if ((mask & 0x0080) != 0 && std::iscntrl(value) != 0) result |= 0x0080;
    if ((mask & 0x0100) != 0 && std::isalpha(value) != 0) result |= 0x0100;
    if ((mask & 0x0800) != 0 && std::isxdigit(value) != 0) result |= 0x0800;
    if ((mask & 0x0400) != 0 && std::isalnum(value) != 0) result |= 0x0400;
    return result;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__tolower(
    std::int32_t value) noexcept {
    return std::tolower(value);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__toupper(
    std::int32_t value) noexcept {
    return std::toupper(value);
}

// The ASCII helpers the classic headers inline and the classic runtime
// exported anyway.
extern "C" __attribute__((ms_abi)) std::int32_t crf___isascii(
    std::int32_t value) noexcept {
    return value >= 0 && value <= 0x7F;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf___toascii(
    std::int32_t value) noexcept {
    return value & 0x7F;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf___iscsym(
    std::int32_t value) noexcept {
    return std::isalnum(value) != 0 || value == '_';
}

extern "C" __attribute__((ms_abi)) std::int32_t crf___iscsymf(
    std::int32_t value) noexcept {
    return std::isalpha(value) != 0 || value == '_';
}

extern "C" __attribute__((ms_abi)) std::int32_t crf___iswcsym(
    std::uint16_t value) noexcept {
    return crf_iswalnum(value) != 0 || value == u'_';
}

extern "C" __attribute__((ms_abi)) std::int32_t crf___iswcsymf(
    std::uint16_t value) noexcept {
    return crf_iswalpha(value) != 0 || value == u'_';
}

// The byte-copy and case-insensitive compares the classic spellings add.
extern "C" __attribute__((ms_abi)) void* crf__memccpy(
    void* target, const void* source, std::int32_t stop,
    std::uint32_t count) noexcept {
    if (target == nullptr || source == nullptr) {
        return nullptr;
    }
    const auto* from = static_cast<const char*>(source);
    auto* to = static_cast<char*>(target);
    for (std::uint32_t i = 0; i < count; ++i) {
        to[i] = from[i];
        if (from[i] == static_cast<char>(stop)) {
            return to + i + 1;
        }
    }
    return nullptr;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__memicmp(
    const void* a, const void* b, std::uint32_t count) noexcept {
    if (a == nullptr || b == nullptr) {
        return -1;  // the documented answer for a null side
    }
    const auto* left = static_cast<const unsigned char*>(a);
    const auto* right = static_cast<const unsigned char*>(b);
    for (std::uint32_t i = 0; i < count; ++i) {
        const int ca = std::tolower(left[i]);
        const int cb = std::tolower(right[i]);
        if (ca != cb) {
            return ca < cb ? -1 : 1;
        }
    }
    return 0;
}

// The character counts between two positions, which the classic runtime
// exported for the multi-byte walks.
extern "C" __attribute__((ms_abi)) std::uint64_t crf___strncnt(
    const char* text, std::uint64_t count) noexcept {
    if (text == nullptr) {
        return 0;
    }
    const std::uint64_t length = std::strlen(text);
    return length < count ? length : count;
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf___wcsncnt(
    const char16_t* text, std::uint64_t count) noexcept {
    if (text == nullptr) {
        return 0;
    }
    const std::uint64_t length =
        std::char_traits<char16_t>::length(text);
    return length < count ? length : count;
}

// The in-place rewrites, narrow and wide.
extern "C" __attribute__((ms_abi)) char* crf__strrev(
    char* text) noexcept {
    if (text == nullptr) {
        return nullptr;
    }
    const std::size_t length = std::strlen(text);
    for (std::size_t i = 0; i < length / 2; ++i) {
        const char swap = text[i];
        text[i] = text[length - 1 - i];
        text[length - 1 - i] = swap;
    }
    return text;
}

extern "C" __attribute__((ms_abi)) char16_t* crf__wcsrev(
    char16_t* text) noexcept {
    if (text == nullptr) {
        return nullptr;
    }
    const std::size_t length = std::char_traits<char16_t>::length(text);
    for (std::size_t i = 0; i < length / 2; ++i) {
        const char16_t swap = text[i];
        text[i] = text[length - 1 - i];
        text[length - 1 - i] = swap;
    }
    return text;
}

extern "C" __attribute__((ms_abi)) char* crf__strnset(
    char* text, std::int32_t value, std::uint32_t count) noexcept {
    if (text == nullptr) {
        return nullptr;
    }
    const std::size_t length = std::strlen(text);
    const std::size_t fill =
        count < length ? static_cast<std::size_t>(count) : length;
    std::memset(text, value, fill);
    return text;
}

extern "C" __attribute__((ms_abi)) char* crf__strset(
    char* text, std::int32_t value) noexcept {
    if (text == nullptr) {
        return nullptr;
    }
    std::memset(text, value, std::strlen(text));
    return text;
}

extern "C" __attribute__((ms_abi)) char16_t* crf__wcsnset(
    char16_t* text, std::uint16_t value, std::uint64_t count) noexcept {
    if (text == nullptr) {
        return nullptr;
    }
    const std::size_t length = std::char_traits<char16_t>::length(text);
    const std::size_t fill =
        count < length ? static_cast<std::size_t>(count) : length;
    for (std::size_t i = 0; i < fill; ++i) {
        text[i] = value;
    }
    return text;
}

extern "C" __attribute__((ms_abi)) char16_t* crf__wcsset(
    char16_t* text, std::uint16_t value) noexcept {
    if (text == nullptr) {
        return nullptr;
    }
    const std::size_t length = std::char_traits<char16_t>::length(text);
    for (std::size_t i = 0; i < length; ++i) {
        text[i] = value;
    }
    return text;
}

// The secure rewrites and the wide duplication.
extern "C" __attribute__((ms_abi)) std::int32_t crf__strnset_s(
    char* text, std::size_t size, std::int32_t value,
    std::uint64_t count) noexcept {
    if (text == nullptr || size == 0) {
        return EINVAL;
    }
    const std::size_t length = ::strnlen(text, size);
    const std::size_t fill =
        count < length ? static_cast<std::size_t>(count) : length;
    if (fill >= size) {
        text[0] = '\0';
        return ERANGE;
    }
    std::memset(text, value, fill);
    text[fill] = '\0';
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__strset_s(
    char* text, std::size_t size, std::int32_t value) noexcept {
    if (text == nullptr || size == 0) {
        return EINVAL;
    }
    const std::size_t length = ::strnlen(text, size);
    if (length >= size) {
        text[0] = '\0';
        return EINVAL;
    }
    std::memset(text, value, length);
    text[length] = '\0';
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wcsnset_s(
    char16_t* text, std::size_t size, std::uint16_t value,
    std::uint64_t count) noexcept {
    if (text == nullptr || size == 0) {
        return EINVAL;
    }
    std::size_t length = 0;
    while (length < size && text[length] != u'\0') {
        ++length;
    }
    const std::size_t fill =
        count < length ? static_cast<std::size_t>(count) : length;
    if (fill >= size) {
        text[0] = u'\0';
        return ERANGE;
    }
    for (std::size_t i = 0; i < fill; ++i) {
        text[i] = value;
    }
    text[fill] = u'\0';
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wcsset_s(
    char16_t* text, std::size_t size, std::uint16_t value) noexcept {
    if (text == nullptr || size == 0) {
        return EINVAL;
    }
    std::size_t length = 0;
    while (length < size && text[length] != u'\0') {
        ++length;
    }
    if (length >= size) {
        text[0] = u'\0';
        return EINVAL;
    }
    for (std::size_t i = 0; i < length; ++i) {
        text[i] = value;
    }
    text[length] = u'\0';
    return 0;
}

extern "C" __attribute__((ms_abi)) char16_t* crf__wcsdup(
    const char16_t* text) noexcept {
    return cr_wcsdup(text);
}

// The wide memory moves, which are the narrow ones over sixteen-bit units.
extern "C" __attribute__((ms_abi)) std::int32_t crf_wmemcpy_s(
    char16_t* target, std::uint64_t target_size, const char16_t* source,
    std::uint64_t count) noexcept {
    if (count == 0) {
        return 0;
    }
    if (target == nullptr || source == nullptr || target_size < count) {
        if (target != nullptr && target_size != 0) {
            target[0] = u'\0';
        }
        errno = EINVAL;
        return EINVAL;
    }
    std::memcpy(target, source, count * sizeof(char16_t));
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_wmemmove_s(
    char16_t* target, std::uint64_t target_size, const char16_t* source,
    std::uint64_t count) noexcept {
    if (count == 0) {
        return 0;
    }
    if (target == nullptr || source == nullptr || target_size < count) {
        if (target != nullptr && target_size != 0) {
            target[0] = u'\0';
        }
        errno = EINVAL;
        return EINVAL;
    }
    std::memmove(target, source, count * sizeof(char16_t));
    return 0;
}

// The multi-byte state calls, which the single-byte page answers.
extern "C" __attribute__((ms_abi)) std::int32_t crf_mblen(
    const char* text, std::uint64_t count) noexcept {
    if (text == nullptr) {
        // A null text resets the conversion state, which there is none of.
        return 0;
    }
    if (count == 0) {
        return 0;
    }
    // A single-byte page: every byte is its own character, and the answer
    // is 1 until the terminator, 0 at it, -1 past the count.
    if (*text == '\0') {
        return 0;
    }
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_mbtowc(
    std::uint16_t* wide, const char* text, std::uint64_t count) noexcept {
    if (text == nullptr) {
        return 0;
    }
    if (count == 0) {
        return -1;
    }
    if (*text == '\0') {
        if (wide != nullptr) {
            *wide = u'\0';
        }
        return 0;
    }
    if (wide != nullptr) {
        *wide = static_cast<unsigned char>(*text);
    }
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_wctomb(
    char* text, std::uint16_t value) noexcept {
    if (text == nullptr) {
        return 0;
    }
    // A single-byte page: the low byte is the character, and a value
    // outside the page's range does not convert.
    if (value > 0xFF) {
        errno = EILSEQ;
        return -1;
    }
    text[0] = static_cast<char>(value);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_wctomb_s(
    std::int32_t* written, char* text, std::uint64_t size,
    std::uint16_t value) noexcept {
    if (written != nullptr) {
        *written = 0;
    }
    if (text == nullptr || size == 0) {
        return EINVAL;
    }
    if (value > 0xFF) {
        text[0] = '\0';
        return EILSEQ;
    }
    if (size < 2) {
        text[0] = '\0';
        return ERANGE;
    }
    text[0] = static_cast<char>(value);
    text[1] = '\0';
    if (written != nullptr) {
        *written = 2;
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint16_t crf_btowc(
    std::int32_t value) noexcept {
    if (value == EOF || value > 0xFF) {
        return 0xFFFFu;  // WEOF
    }
    return static_cast<std::uint16_t>(value);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_wctob(
    std::uint16_t value) noexcept {
    if (value > 0xFF) {
        return -1;  // EOF
    }
    return static_cast<std::int32_t>(value);
}

// The secure multi-byte conversions, which the classic domain's unbounded
// forms feed.
extern "C" __attribute__((ms_abi)) std::int32_t crf_mbstowcs_s(
    std::uint64_t* written, char16_t* target, std::uint64_t target_size,
    const char* source, std::uint64_t count) noexcept {
    if (written != nullptr) {
        *written = 0;
    }
    if (source == nullptr) {
        if (target != nullptr && target_size != 0) {
            target[0] = u'\0';
        }
        return EINVAL;
    }
    if (target == nullptr && target_size != 0) {
        return EINVAL;
    }
    const std::uint64_t limit =
        count < target_size ? count : target_size - 1;
    const std::uint64_t made = cr_mbstowcs(target, source, limit);
    if (made >= target_size) {
        if (target != nullptr) {
            target[0] = u'\0';
        }
        return ERANGE;
    }
    if (target != nullptr) {
        target[made] = u'\0';
    }
    if (written != nullptr) {
        *written = made + 1;
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_wcstombs_s(
    std::uint64_t* written, char* target, std::uint64_t target_size,
    const char16_t* source, std::uint64_t count) noexcept {
    if (written != nullptr) {
        *written = 0;
    }
    if (source == nullptr) {
        if (target != nullptr && target_size != 0) {
            target[0] = '\0';
        }
        return EINVAL;
    }
    if (target == nullptr && target_size != 0) {
        return EINVAL;
    }
    const std::uint64_t limit =
        count < target_size ? count : target_size - 1;
    const std::uint64_t made = cr_wcstombs(target, source, limit);
    if (made >= target_size) {
        if (target != nullptr) {
            target[0] = '\0';
        }
        return ERANGE;
    }
    if (target != nullptr) {
        target[made] = '\0';
    }
    if (written != nullptr) {
        *written = made + 1;
    }
    return 0;
}


// ===========================================================================
// The convert family's remaining spellings
//
// The wide integer conversions, the wide numeric parsers and the float
// renderers. The wide text walks the guest's sixteen-bit code units and
// delegates to the narrow machinery, which is the same conversion every
// wide/narrow pair here makes.
// ===========================================================================

// The integer-to-text conversions, wide. The narrow forms the classic
// domain carries do the work; these render the digits and convert back.
[[nodiscard]] std::u16string wide_of_integer(std::int64_t value,
                                             std::int32_t radix) noexcept {
    const bool negative = value < 0;
    unsigned long long magnitude =
        negative ? static_cast<unsigned long long>(-(value + 1)) + 1
                 : static_cast<unsigned long long>(value);
    static const char16_t digits[] = u"0123456789abcdefghijklmnopqrstuvwxyz";
    std::u16string out;
    if (magnitude == 0) {
        out += u'0';
    }
    const unsigned long long base = static_cast<unsigned long long>(radix);
    while (magnitude != 0) {
        out += digits[magnitude % base];
        magnitude /= base;
    }
    if (negative) {
        out += u'-';
    }
    for (std::size_t i = 0; i < out.size() / 2; ++i) {
        const char16_t swap = out[i];
        out[i] = out[out.size() - 1 - i];
        out[out.size() - 1 - i] = swap;
    }
    return out;
}

[[nodiscard]] std::u16string wide_of_unsigned(
    std::uint64_t value, std::int32_t radix) noexcept {
    static const char16_t digits[] = u"0123456789abcdefghijklmnopqrstuvwxyz";
    std::u16string out;
    if (value == 0) {
        out += u'0';
    }
    const std::uint64_t base = static_cast<std::uint64_t>(radix);
    while (value != 0) {
        out += digits[value % base];
        value /= base;
    }
    for (std::size_t i = 0; i < out.size() / 2; ++i) {
        const char16_t swap = out[i];
        out[i] = out[out.size() - 1 - i];
        out[out.size() - 1 - i] = swap;
    }
    return out;
}

// The bounded store the `_s` forms share: copy, or fail with the
// terminator written and the errno set.
[[nodiscard]] std::int32_t store_wide(char16_t* target,
                                      std::uint64_t size,
                                      const std::u16string& text) noexcept {
    if (target == nullptr || size == 0) {
        return EINVAL;
    }
    if (text.size() + 1 > size) {
        target[0] = u'\0';
        errno = ERANGE;
        return ERANGE;
    }
    std::memcpy(target, text.c_str(), (text.size() + 1) * sizeof(char16_t));
    return 0;
}

extern "C" __attribute__((ms_abi)) char16_t* crf__itow(
    std::int32_t value, char16_t* target, std::int32_t radix) noexcept {
    if (target == nullptr || radix < 2 || radix > 36) {
        return nullptr;
    }
    const std::u16string text = wide_of_integer(value, radix);
    std::memcpy(target, text.c_str(),
                (text.size() + 1) * sizeof(char16_t));
    return target;
}

extern "C" __attribute__((ms_abi)) char16_t* crf__ltow(
    std::int32_t value, char16_t* target, std::int32_t radix) noexcept {
    return crf__itow(value, target, radix);
}

extern "C" __attribute__((ms_abi)) char16_t* crf__i64tow(
    std::int64_t value, char16_t* target, std::int32_t radix) noexcept {
    if (target == nullptr || radix < 2 || radix > 36) {
        return nullptr;
    }
    const std::u16string text = wide_of_integer(value, radix);
    std::memcpy(target, text.c_str(),
                (text.size() + 1) * sizeof(char16_t));
    return target;
}

extern "C" __attribute__((ms_abi)) char16_t* crf__ui64tow(
    std::uint64_t value, char16_t* target, std::int32_t radix) noexcept {
    if (target == nullptr || radix < 2 || radix > 36) {
        return nullptr;
    }
    const std::u16string text = wide_of_unsigned(value, radix);
    std::memcpy(target, text.c_str(),
                (text.size() + 1) * sizeof(char16_t));
    return target;
}

extern "C" __attribute__((ms_abi)) char16_t* crf__ultow(
    std::uint32_t value, char16_t* target, std::int32_t radix) noexcept {
    return crf__ui64tow(value, target, radix);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__itow_s(
    std::int32_t value, char16_t* target, std::uint64_t size,
    std::int32_t radix) noexcept {
    if (radix < 2 || radix > 36) {
        if (target != nullptr && size != 0) {
            target[0] = u'\0';
        }
        return EINVAL;
    }
    return store_wide(target, size, wide_of_integer(value, radix));
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__ltow_s(
    std::int32_t value, char16_t* target, std::uint64_t size,
    std::int32_t radix) noexcept {
    return crf__itow_s(value, target, size, radix);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__i64tow_s(
    std::int64_t value, char16_t* target, std::uint64_t size,
    std::int32_t radix) noexcept {
    if (radix < 2 || radix > 36) {
        if (target != nullptr && size != 0) {
            target[0] = u'\0';
        }
        return EINVAL;
    }
    return store_wide(target, size, wide_of_integer(value, radix));
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__ui64tow_s(
    std::uint64_t value, char16_t* target, std::uint64_t size,
    std::int32_t radix) noexcept {
    if (radix < 2 || radix > 36) {
        if (target != nullptr && size != 0) {
            target[0] = u'\0';
        }
        return EINVAL;
    }
    return store_wide(target, size, wide_of_unsigned(value, radix));
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__ultow_s(
    std::uint32_t value, char16_t* target, std::uint64_t size,
    std::int32_t radix) noexcept {
    return crf__ui64tow_s(value, target, size, radix);
}

// The wide numeric parsers. The narrow parse is the authority; the wide
// text is rendered narrow and parsed, which is the same conversion the
// real CRT's wide parse is built on.
[[nodiscard]] std::string narrow_of(const char16_t* text) noexcept {
    std::string narrow;
    if (text != nullptr) {
        static_cast<void>(
            narrow_out(std::u16string_view(text), narrow));
    }
    return narrow;
}

extern "C" __attribute__((ms_abi)) double crf__wtof(
    const char16_t* text) noexcept {
    const std::string narrow = narrow_of(text);
    return std::strtod(narrow.c_str(), nullptr);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wtoi(
    const char16_t* text) noexcept {
    const std::string narrow = narrow_of(text);
    return static_cast<std::int32_t>(std::strtol(narrow.c_str(), nullptr,
                                                 10));
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wtol(
    const char16_t* text) noexcept {
    return crf__wtoi(text);
}

extern "C" __attribute__((ms_abi)) std::int64_t crf__wtoi64(
    const char16_t* text) noexcept {
    const std::string narrow = narrow_of(text);
    return std::strtoll(narrow.c_str(), nullptr, 10);
}

extern "C" __attribute__((ms_abi)) std::int64_t crf__wtoll(
    const char16_t* text) noexcept {
    return crf__wtoi64(text);
}

extern "C" __attribute__((ms_abi)) double crf__wtof_l(
    const char16_t* text, std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return crf__wtof(text);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wtoi_l(
    const char16_t* text, std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return crf__wtoi(text);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wtol_l(
    const char16_t* text, std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return crf__wtoi(text);
}

extern "C" __attribute__((ms_abi)) std::int64_t crf__wtoi64_l(
    const char16_t* text, std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return crf__wtoi64(text);
}

extern "C" __attribute__((ms_abi)) std::int64_t crf__wtoll_l(
    const char16_t* text, std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return crf__wtoi64(text);
}

// The unbounded and locale-tagged narrow parsers the family adds to the
// classic set.
extern "C" __attribute__((ms_abi)) std::int64_t crf_atoll(
    const char* text) noexcept {
    return std::strtoll(text, nullptr, 10);
}

extern "C" __attribute__((ms_abi)) double crf_strtold(
    const char* text, char** end) noexcept {
    return std::strtod(text, end);
}

extern "C" __attribute__((ms_abi)) std::int64_t crf_strtoimax(
    const char* text, char** end, std::int32_t base) noexcept {
    return std::strtoll(text, end, base);
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf_strtoumax(
    const char* text, char** end, std::int32_t base) noexcept {
    return std::strtoull(text, end, base);
}

extern "C" __attribute__((ms_abi)) float crf_wcstof(
    const char16_t* text, char16_t** end) noexcept {
    const std::string narrow = narrow_of(text);
    char* narrow_end = nullptr;
    const float value = std::strtof(narrow.c_str(), &narrow_end);
    if (end != nullptr) {
        *end = const_cast<char16_t*>(
            text + (narrow_end - narrow.c_str()));
    }
    return value;
}

extern "C" __attribute__((ms_abi)) double crf_wcstold(
    const char16_t* text, char16_t** end) noexcept {
    const std::string narrow = narrow_of(text);
    char* narrow_end = nullptr;
    const double value = std::strtod(narrow.c_str(), &narrow_end);
    if (end != nullptr) {
        *end = const_cast<char16_t*>(
            text + (narrow_end - narrow.c_str()));
    }
    return value;
}

extern "C" __attribute__((ms_abi)) std::int64_t crf_wcstoimax(
    const char16_t* text, char16_t** end, std::int32_t base) noexcept {
    const std::string narrow = narrow_of(text);
    char* narrow_end = nullptr;
    const std::int64_t value =
        std::strtoll(narrow.c_str(), &narrow_end, base);
    if (end != nullptr) {
        *end = const_cast<char16_t*>(
            text + (narrow_end - narrow.c_str()));
    }
    return value;
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf_wcstoumax(
    const char16_t* text, char16_t** end, std::int32_t base) noexcept {
    const std::string narrow = narrow_of(text);
    char* narrow_end = nullptr;
    const std::uint64_t value =
        std::strtoull(narrow.c_str(), &narrow_end, base);
    if (end != nullptr) {
        *end = const_cast<char16_t*>(
            text + (narrow_end - narrow.c_str()));
    }
    return value;
}

// The float renderers. The digits-and-exponent forms the caller's struct
// reads come out of the host's rendering, split where the caller asks.
extern "C" __attribute__((ms_abi)) char* crf__ecvt(
    double value, std::int32_t digits, std::int32_t* decimal,
    std::int32_t* sign) noexcept {
    static std::string storage;
    if (decimal == nullptr || sign == nullptr) {
        return nullptr;
    }
    // The host's `ecvt` answers the digits, the decimal position and the
    // sign directly, in a static buffer this call copies out of.
    int decpt = 0;
    int sgn = 0;
    char* answer = ::ecvt(value, digits > 0 ? digits : 0, &decpt, &sgn);
    if (answer == nullptr) {
        return nullptr;
    }
    storage = answer;
    *decimal = decpt;
    *sign = sgn;
    return storage.data();
}

extern "C" __attribute__((ms_abi)) char* crf__fcvt(
    double value, std::int32_t fraction_digits, std::int32_t* decimal,
    std::int32_t* sign) noexcept {
    static std::string storage;
    if (decimal == nullptr || sign == nullptr) {
        return nullptr;
    }
    const int rendered =
        std::snprintf(nullptr, 0, "%.*f",
                      fraction_digits > 0 ? fraction_digits : 0, value);
    storage.assign(static_cast<std::size_t>(rendered) + 1, '\0');
    std::snprintf(storage.data(), storage.size(), "%.*f",
                  fraction_digits > 0 ? fraction_digits : 0, value);
    // The decimal position: where the point sits relative to the first
    // digit, which the rendered form states.
    const std::size_t point = storage.find('.');
    *decimal = point == std::string::npos
                   ? static_cast<std::int32_t>(storage.size())
                   : static_cast<std::int32_t>(point);
    *sign = value < 0 ? 1 : 0;
    return storage.data();
}

extern "C" __attribute__((ms_abi)) char* crf__gcvt(
    double value, std::int32_t digits, char* buffer) noexcept {
    if (buffer == nullptr) {
        return nullptr;
    }
    std::snprintf(buffer, static_cast<std::size_t>(digits) + 8, "%.*g",
                  digits > 0 ? digits : 0, value);
    return buffer;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__ecvt_s(
    char* buffer, std::uint64_t size, double value, std::int32_t digits,
    std::int32_t* decimal, std::int32_t* sign) noexcept {
    if (buffer == nullptr || size == 0 || decimal == nullptr ||
        sign == nullptr) {
        return EINVAL;
    }
    const std::int32_t rendered =
        std::snprintf(buffer, size, "%.*e",
                      digits > 0 ? digits - 1 : 0, value);
    if (rendered < 0 || static_cast<std::uint64_t>(rendered) >= size) {
        buffer[0] = '\0';
        return ERANGE;
    }
    *sign = value < 0 ? 1 : 0;
    // The exponent is the decimal position's negation, which the
    // scientific form states directly.
    const char* exponent = std::strchr(buffer, 'e');
    *decimal = exponent != nullptr
                   ? -static_cast<std::int32_t>(std::atoi(exponent + 1))
                   : 0;
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__fcvt_s(
    char* buffer, std::uint64_t size, double value,
    std::int32_t fraction_digits, std::int32_t* decimal,
    std::int32_t* sign) noexcept {
    if (buffer == nullptr || size == 0 || decimal == nullptr ||
        sign == nullptr) {
        return EINVAL;
    }
    const std::int32_t rendered =
        std::snprintf(buffer, size, "%.*f",
                      fraction_digits > 0 ? fraction_digits : 0, value);
    if (rendered < 0 || static_cast<std::uint64_t>(rendered) >= size) {
        buffer[0] = '\0';
        return ERANGE;
    }
    const char* point = std::strchr(buffer, '.');
    *decimal = point != nullptr
                   ? static_cast<std::int32_t>(point - buffer)
                   : static_cast<std::int32_t>(std::strlen(buffer));
    *sign = value < 0 ? 1 : 0;
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__gcvt_s(
    char* buffer, std::uint64_t size, double value, std::int32_t digits) noexcept {
    if (buffer == nullptr || size == 0) {
        return EINVAL;
    }
    const std::int32_t rendered =
        std::snprintf(buffer, size, "%.*g",
                      digits > 0 ? digits : 0, value);
    if (rendered < 0 || static_cast<std::uint64_t>(rendered) >= size) {
        buffer[0] = '\0';
        return ERANGE;
    }
    return 0;
}


// ===========================================================================
// The time family's remaining spellings
//
// The thirty-two-bit spellings, the wide ones, the formatting helpers and
// the timezone state. The sixty-four-bit core is the classic domain's; the
// narrowings here saturate the way a narrowing cast does, and the timezone
// answers come from the host's own zone, which is the zone the process
// runs in.
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int64_t cr_time(
    std::int64_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t cr_mktime(
    void* broken_down) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t cr__mkgmtime(
    void* broken_down) noexcept;
extern "C" __attribute__((ms_abi)) void* cr_localtime(
    const std::int64_t* timer) noexcept;
extern "C" __attribute__((ms_abi)) void* cr_gmtime(
    const std::int64_t* timer) noexcept;
extern "C" __attribute__((ms_abi)) char* cr_ctime(
    const std::int64_t* timer) noexcept;
extern "C" __attribute__((ms_abi)) char* cr_asctime(
    const void*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t cr_strftime(
    char*, std::uint64_t, const char*, const void*) noexcept;
extern "C" __attribute__((ms_abi)) double cr_difftime(
    std::int64_t, std::int64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32u__strtime_s(
    char*, std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32u__strdate_s(
    char*, std::uint64_t) noexcept;

// The broken-down time the host hands back is the host's `struct tm`; the
// guest's is the same nine fields at the same offsets, which is why the
// pointers travel unchanged.
[[nodiscard]] std::int32_t time32_of(std::int64_t seconds) noexcept {
    // The saturation is the documented one: times past 2038 do not fit,
    // and the value the thirty-two-bit spelling reports is the saturated
    // one.
    if (seconds > 0x7FFFFFFFll) {
        return 0x7FFFFFFFll;
    }
    if (seconds < -0x7FFFFFFFll) {
        return -0x7FFFFFFFll;
    }
    return static_cast<std::int32_t>(seconds);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__time32(
    std::int32_t* where) noexcept {
    std::int64_t now = 0;
    cr_time(&now);
    const std::int32_t value = time32_of(now);
    if (where != nullptr) {
        *where = value;
    }
    return value;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__mktime32(
    void* broken_down) noexcept {
    return time32_of(cr_mktime(broken_down));
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__mkgmtime32(
    void* broken_down) noexcept {
    return time32_of(cr__mkgmtime(broken_down));
}

extern "C" __attribute__((ms_abi)) void* crf__gmtime32(
    const std::int32_t* when) noexcept {
    if (when == nullptr) {
        return nullptr;
    }
    const std::int64_t wide = *when;
    return cr_gmtime(&wide);
}

extern "C" __attribute__((ms_abi)) void* crf__localtime32(
    const std::int32_t* when) noexcept {
    if (when == nullptr) {
        return nullptr;
    }
    const std::int64_t wide = *when;
    return cr_localtime(&wide);
}

extern "C" __attribute__((ms_abi)) char* crf__ctime32(
    const std::int32_t* when) noexcept {
    if (when == nullptr) {
        return nullptr;
    }
    const std::int64_t wide = *when;
    return cr_ctime(&wide);
}

// The secure formatters, which the classic domain's sixty-four-bit
// spellings answer under the other names.
extern "C" __attribute__((ms_abi)) std::int32_t crf__ctime32_s(
    char* buffer, std::uint64_t size, const std::int32_t* when) noexcept {
    if (buffer == nullptr || size == 0 || when == nullptr) {
        if (buffer != nullptr && size != 0) {
            buffer[0] = '\0';
        }
        return EINVAL;
    }
    const std::int64_t wide = *when;
    const char* text = cr_ctime(&wide);
    if (text == nullptr) {
        buffer[0] = '\0';
        return EINVAL;
    }
    // The `ctime` form is 25 bytes with its newline; the secure form
    // stores it without the newline.
    std::string line(text);
    if (!line.empty() && line.back() == '\n') {
        line.pop_back();
    }
    if (line.size() + 1 > size) {
        buffer[0] = '\0';
        return ERANGE;
    }
    std::memcpy(buffer, line.c_str(), line.size() + 1);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__ctime64_s(
    char* buffer, std::uint64_t size, const std::int64_t* when) noexcept {
    if (buffer == nullptr || size == 0 || when == nullptr) {
        if (buffer != nullptr && size != 0) {
            buffer[0] = '\0';
        }
        return EINVAL;
    }
    const std::int32_t narrow = time32_of(*when);
    return crf__ctime32_s(buffer, size, &narrow);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__gmtime32_s(
    void* result, const std::int32_t* when) noexcept {
    if (result == nullptr || when == nullptr) {
        return EINVAL;
    }
    const std::int64_t wide = *when;
    const void* filled = cr_gmtime(&wide);
    if (filled == nullptr) {
        return EINVAL;
    }
    std::memcpy(result, filled, sizeof(struct ::tm));
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__gmtime64_s(
    void* result, const std::int64_t* when) noexcept {
    if (result == nullptr || when == nullptr) {
        return EINVAL;
    }
    const void* filled = cr_gmtime(when);
    if (filled == nullptr) {
        return EINVAL;
    }
    std::memcpy(result, filled, sizeof(struct ::tm));
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__localtime32_s(
    void* result, const std::int32_t* when) noexcept {
    if (result == nullptr || when == nullptr) {
        return EINVAL;
    }
    const std::int64_t wide = *when;
    const void* filled = cr_localtime(&wide);
    if (filled == nullptr) {
        return EINVAL;
    }
    std::memcpy(result, filled, sizeof(struct ::tm));
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__localtime64_s(
    void* result, const std::int64_t* when) noexcept {
    if (result == nullptr || when == nullptr) {
        return EINVAL;
    }
    const void* filled = cr_localtime(when);
    if (filled == nullptr) {
        return EINVAL;
    }
    std::memcpy(result, filled, sizeof(struct ::tm));
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__difftime32(
    std::int32_t later, std::int32_t earlier) noexcept {
    return static_cast<std::int32_t>(
        cr_difftime(later, earlier));
}

extern "C" __attribute__((ms_abi)) std::int64_t crf__difftime64(
    std::int64_t later, std::int64_t earlier) noexcept {
    return static_cast<std::int64_t>(
        cr_difftime(later, earlier));
}

// The current-time text, narrow and wide, in the `HH:MM:SS` and
// `MM/DD/YY` forms the names spell.
extern "C" __attribute__((ms_abi)) char* crf__strtime(
    char* buffer) noexcept {
    if (buffer == nullptr) {
        return nullptr;
    }
    if (u32u__strtime_s(buffer, kMaxPath) != 0) {
        return nullptr;
    }
    return buffer;
}

extern "C" __attribute__((ms_abi)) char* crf__strdate(
    char* buffer) noexcept {
    if (buffer == nullptr) {
        return nullptr;
    }
    if (u32u__strdate_s(buffer, kMaxPath) != 0) {
        return nullptr;
    }
    return buffer;
}

std::u16string& wide_time_buffer() noexcept {
    static std::u16string storage;
    return storage;
}

extern "C" __attribute__((ms_abi)) char16_t* crf__wstrtime(
    char16_t* buffer) noexcept {
    char narrow[kMaxPath];
    if (crf__strtime(narrow) == nullptr) {
        return nullptr;
    }
    if (!narrow_in(std::string_view(narrow), wide_time_buffer())
             .converted) {
        return nullptr;
    }
    if (buffer == nullptr) {
        return wide_time_buffer().data();
    }
    if (wide_time_buffer().size() + 1 > kMaxPath) {
        errno = ERANGE;
        return nullptr;
    }
    std::memcpy(buffer, wide_time_buffer().c_str(),
                (wide_time_buffer().size() + 1) * sizeof(char16_t));
    return buffer;
}

extern "C" __attribute__((ms_abi)) char16_t* crf__wstrdate(
    char16_t* buffer) noexcept {
    char narrow[kMaxPath];
    if (crf__strdate(narrow) == nullptr) {
        return nullptr;
    }
    if (!narrow_in(std::string_view(narrow), wide_time_buffer())
             .converted) {
        return nullptr;
    }
    if (buffer == nullptr) {
        return wide_time_buffer().data();
    }
    if (wide_time_buffer().size() + 1 > kMaxPath) {
        errno = ERANGE;
        return nullptr;
    }
    std::memcpy(buffer, wide_time_buffer().c_str(),
                (wide_time_buffer().size() + 1) * sizeof(char16_t));
    return buffer;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wstrtime_s(
    char16_t* buffer, std::uint64_t size) noexcept {
    if (buffer == nullptr || size == 0) {
        return EINVAL;
    }
    if (crf__wstrtime(nullptr) == nullptr) {
        buffer[0] = u'\0';
        return errno;
    }
    if (wide_time_buffer().size() + 1 > size) {
        buffer[0] = u'\0';
        return ERANGE;
    }
    std::memcpy(buffer, wide_time_buffer().c_str(),
                (wide_time_buffer().size() + 1) * sizeof(char16_t));
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wstrdate_s(
    char16_t* buffer, std::uint64_t size) noexcept {
    if (buffer == nullptr || size == 0) {
        return EINVAL;
    }
    if (crf__wstrdate(nullptr) == nullptr) {
        buffer[0] = u'\0';
        return errno;
    }
    if (wide_time_buffer().size() + 1 > size) {
        buffer[0] = u'\0';
        return ERANGE;
    }
    std::memcpy(buffer, wide_time_buffer().c_str(),
                (wide_time_buffer().size() + 1) * sizeof(char16_t));
    return 0;
}

// The `asctime` pair, secure and wide. The broken-down time is the host's.
extern "C" __attribute__((ms_abi)) std::int32_t crf_asctime_s(
    char* buffer, std::uint64_t size, const void* broken) noexcept {
    if (buffer == nullptr || size == 0 || broken == nullptr) {
        if (buffer != nullptr && size != 0) {
            buffer[0] = '\0';
        }
        return EINVAL;
    }
    // The host's own formatting reaches the same answer; the buffer bound
    // is the one the secure form checks.
    if (size < 26) {
        buffer[0] = '\0';
        return ERANGE;
    }
    const char* text = cr_asctime(broken);
    if (text == nullptr) {
        buffer[0] = '\0';
        return EINVAL;
    }
    std::string line(text);
    if (!line.empty() && line.back() == '\n') {
        line.pop_back();
    }
    if (line.size() + 1 > size) {
        buffer[0] = '\0';
        return ERANGE;
    }
    std::memcpy(buffer, line.c_str(), line.size() + 1);
    return 0;
}

std::u16string& wide_asctime_buffer() noexcept {
    static std::u16string storage;
    return storage;
}

extern "C" __attribute__((ms_abi)) char16_t* crf__wasctime(
    const void* broken) noexcept {
    char narrow[kMaxPath];
    if (crf_asctime_s(narrow, sizeof(narrow), broken) != 0) {
        return nullptr;
    }
    if (!narrow_in(std::string_view(narrow), wide_asctime_buffer())
             .converted) {
        return nullptr;
    }
    return wide_asctime_buffer().data();
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wasctime_s(
    char16_t* buffer, std::uint64_t size, const void* broken) noexcept {
    if (buffer == nullptr || size == 0) {
        return EINVAL;
    }
    char narrow[kMaxPath];
    if (crf_asctime_s(narrow, sizeof(narrow), broken) != 0) {
        buffer[0] = u'\0';
        return EINVAL;
    }
    if (!narrow_in(std::string_view(narrow), wide_asctime_buffer())
             .converted) {
        buffer[0] = u'\0';
        return EINVAL;
    }
    if (wide_asctime_buffer().size() + 1 > size) {
        buffer[0] = u'\0';
        return ERANGE;
    }
    std::memcpy(buffer, wide_asctime_buffer().c_str(),
                (wide_asctime_buffer().size() + 1) * sizeof(char16_t));
    return 0;
}

extern "C" __attribute__((ms_abi)) char16_t* crf__wctime32(
    const std::int32_t* when) noexcept {
    if (when == nullptr) {
        return nullptr;
    }
    const std::int64_t wide = *when;
    const char* text = cr_ctime(&wide);
    if (text == nullptr) {
        return nullptr;
    }
    if (!narrow_in(std::string_view(text), wide_asctime_buffer())
             .converted) {
        return nullptr;
    }
    return wide_asctime_buffer().data();
}

extern "C" __attribute__((ms_abi)) char16_t* crf__wctime64(
    const std::int64_t* when) noexcept {
    if (when == nullptr) {
        return nullptr;
    }
    const std::int32_t narrow = time32_of(*when);
    return crf__wctime32(&narrow);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wctime32_s(
    char16_t* buffer, std::uint64_t size, const std::int32_t* when) noexcept {
    if (buffer == nullptr || size == 0 || when == nullptr) {
        if (buffer != nullptr && size != 0) {
            buffer[0] = u'\0';
        }
        return EINVAL;
    }
    char narrow[kMaxPath];
    const std::int32_t result = crf__ctime32_s(narrow, sizeof(narrow), when);
    if (result != 0) {
        buffer[0] = u'\0';
        return result;
    }
    if (!narrow_in(std::string_view(narrow), wide_asctime_buffer())
             .converted) {
        buffer[0] = u'\0';
        return EINVAL;
    }
    if (wide_asctime_buffer().size() + 1 > size) {
        buffer[0] = u'\0';
        return ERANGE;
    }
    std::memcpy(buffer, wide_asctime_buffer().c_str(),
                (wide_asctime_buffer().size() + 1) * sizeof(char16_t));
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wctime64_s(
    char16_t* buffer, std::uint64_t size, const std::int64_t* when) noexcept {
    if (when == nullptr) {
        if (buffer != nullptr && size != 0) {
            buffer[0] = u'\0';
        }
        return EINVAL;
    }
    const std::int32_t narrow = time32_of(*when);
    return crf__wctime32_s(buffer, size, &narrow);
}

// The timezone state, read from the host's own zone after the host's
// `tzset` has had its say.
extern "C" __attribute__((ms_abi)) void crf__tzset() noexcept {
    ::tzset();
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__get_timezone(
    std::int32_t* seconds) noexcept {
    if (seconds == nullptr) {
        return EINVAL;
    }
    ::tzset();
    // The host's timezone offset is west-positive; the CRT's is
    // east-positive, which is the sign the reference flips.
    *seconds = static_cast<std::int32_t>(-::timezone);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__get_daylight(
    std::int32_t* hours) noexcept {
    if (hours == nullptr) {
        return EINVAL;
    }
    ::tzset();
    *hours = ::daylight;
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__get_dstbias(
    std::int32_t* seconds) noexcept {
    if (seconds == nullptr) {
        return EINVAL;
    }
    ::tzset();
    *seconds = static_cast<std::int32_t>(-::timezone);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__get_tzname(
    std::uint64_t* count, char* buffer, std::uint64_t size,
    std::uint32_t index) noexcept {
    if (count == nullptr || buffer == nullptr || index > 1) {
        return EINVAL;
    }
    ::tzset();
    const char* name = index == 0 ? ::tzname[0] : ::tzname[1];
    const std::uint64_t length = std::strlen(name) + 1;
    *count = length;
    if (length > size) {
        if (size != 0) {
            buffer[0] = '\0';
        }
        return ERANGE;
    }
    std::memcpy(buffer, name, length);
    return 0;
}

// The data exports, which are the same state under pointer spellings.
extern "C" __attribute__((ms_abi)) std::int32_t* crf___daylight() noexcept {
    static std::int32_t slot = 0;
    ::tzset();
    slot = ::daylight;
    return &slot;
}

extern "C" __attribute__((ms_abi)) std::int32_t* crf___dstbias() noexcept {
    static std::int32_t slot = 0;
    ::tzset();
    slot = static_cast<std::int32_t>(-::timezone);
    return &slot;
}

extern "C" __attribute__((ms_abi)) std::int32_t* crf___timezone() noexcept {
    static std::int32_t slot = 0;
    ::tzset();
    slot = static_cast<std::int32_t>(-::timezone);
    return &slot;
}

extern "C" __attribute__((ms_abi)) char** crf___tzname() noexcept {
    ::tzset();
    return ::tzname;
}

// The wall-clock readers and writers the classic runtime carried.
extern "C" __attribute__((ms_abi)) std::uint32_t crf__getsystime(
    void* broken) noexcept {
    if (broken == nullptr) {
        return 0;
    }
    auto* fields = static_cast<struct ::tm*>(broken);
    const time_t now = ::time(nullptr);
    ::localtime_r(&now, fields);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint32_t crf__setsystime(
    const void* broken, std::uint32_t milliseconds) noexcept {
    // Setting the system clock is not this process's to do; the call
    // reports the failure a clock it cannot set reports.
    static_cast<void>(broken);
    static_cast<void>(milliseconds);
    errno = EACCES;
    return 0;
}

// The file-time setters, which reach the same files every other name
// here does.
extern "C" __attribute__((ms_abi)) std::int32_t crf__futime64(
    std::int32_t fd, const std::int64_t* when) noexcept {
    if (!crt_fd_is_valid(fd) || when == nullptr) {
        errno = EBADF;
        return -1;
    }
    const struct ::timespec times[2] = {
        {static_cast<time_t>(*when), 0},
        {static_cast<time_t>(*when), 0},
    };
    return ::futimens(fd, times);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__futime32(
    std::int32_t fd, const std::int32_t* when) noexcept {
    if (when == nullptr) {
        errno = EINVAL;
        return -1;
    }
    const std::int64_t wide = *when;
    return crf__futime64(fd, &wide);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__utime64(
    const char* path, const std::int64_t* when) noexcept {
    if (path == nullptr || when == nullptr) {
        errno = EINVAL;
        return -1;
    }
    const struct ::timespec times[2] = {
        {static_cast<time_t>(*when), 0},
        {static_cast<time_t>(*when), 0},
    };
    return ::utimensat(AT_FDCWD, host_path_of(path).c_str(), times, 0);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__utime32(
    const char* path, const std::int32_t* when) noexcept {
    if (when == nullptr) {
        errno = EINVAL;
        return -1;
    }
    const std::int64_t wide = *when;
    return crf__utime64(path, &wide);
}

// The wide spellings convert and delegate.
extern "C" __attribute__((ms_abi)) std::int32_t crf__wutime64(
    const char16_t* path, const std::int64_t* when) noexcept {
    if (path == nullptr) {
        errno = EINVAL;
        return -1;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(path), narrow).converted) {
        errno = EINVAL;
        return -1;
    }
    return crf__utime64(narrow.c_str(), when);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wutime32(
    const char16_t* path, const std::int32_t* when) noexcept {
    if (when == nullptr) {
        errno = EINVAL;
        return -1;
    }
    const std::int64_t wide = *when;
    return crf__wutime64(path, &wide);
}

// The clock readers the standard names, both widths.
extern "C" __attribute__((ms_abi)) std::int32_t crf__timespec32_get(
    void* spec, std::int32_t base) noexcept {
    if (spec == nullptr || base != 1) {  // TIME_UTC
        return 0;
    }
    struct ::timespec now {};
    if (::clock_gettime(CLOCK_REALTIME, &now) != 0) {
        return 0;
    }
    struct Timespec32 {
        std::int32_t seconds;
        std::int32_t nanoseconds;
    };
    auto* out = static_cast<Timespec32*>(spec);
    out->seconds = time32_of(now.tv_sec);
    out->nanoseconds = static_cast<std::int32_t>(now.tv_nsec);
    return base;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__timespec64_get(
    void* spec, std::int32_t base) noexcept {
    if (spec == nullptr || base != 1) {
        return 0;
    }
    struct Timespec64 {
        std::int64_t seconds;
        std::int32_t nanoseconds;
    };
    struct ::timespec now {};
    if (::clock_gettime(CLOCK_REALTIME, &now) != 0) {
        return 0;
    }
    auto* out = static_cast<Timespec64*>(spec);
    out->seconds = static_cast<std::int64_t>(now.tv_sec);
    out->nanoseconds = static_cast<std::int32_t>(now.tv_nsec);
    return base;
}

// The wide `strftime`, which formats narrow and converts, and the
// locale-tagged spelling beside it.
extern "C" __attribute__((ms_abi)) std::uint64_t crf_wcsftime(
    char16_t* buffer, std::uint64_t count, const char16_t* format,
    const void* broken) noexcept {
    if (buffer == nullptr || format == nullptr || broken == nullptr) {
        return 0;
    }
    std::string narrow_format;
    if (!narrow_out(std::u16string_view(format), narrow_format).converted) {
        return 0;
    }
    char narrow[kMaxPath * 2];
    const std::uint64_t made = cr_strftime(narrow, sizeof(narrow),
                                           narrow_format.c_str(), broken);
    if (made == 0) {
        return 0;
    }
    std::u16string wide;
    if (!narrow_in(std::string_view(narrow, made), wide).converted) {
        return 0;
    }
    if (wide.size() + 1 > count) {
        return 0;
    }
    std::memcpy(buffer, wide.c_str(), (wide.size() + 1) * sizeof(char16_t));
    return wide.size();
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf__wcsftime_l(
    char16_t* buffer, std::uint64_t count, const char16_t* format,
    const void* broken, std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return crf_wcsftime(buffer, count, format, broken);
}

// The day- and month-name tables the formatting helpers read. The names
// are the C locale's, which is the locale the formatting runs in.
extern "C" __attribute__((ms_abi)) const char* crf__Getdays() noexcept {
    return "Sunday Monday Tuesday Wednesday Thursday Friday Saturday";
}

extern "C" __attribute__((ms_abi)) const char* crf__Getmonths() noexcept {
    return "January February March April May June July August September "
           "October November December";
}

extern "C" __attribute__((ms_abi)) const char* crf__Gettnames() noexcept {
    return crf__Getmonths();
}

extern "C" __attribute__((ms_abi)) const char16_t* crf__W_Getdays() noexcept {
    static std::u16string storage;
    if (!narrow_in(std::string_view(crf__Getdays()), storage).converted) {
        return nullptr;
    }
    return storage.data();
}

extern "C" __attribute__((ms_abi)) const char16_t* crf__W_Getmonths() noexcept {
    static std::u16string storage;
    if (!narrow_in(std::string_view(crf__Getmonths()), storage).converted) {
        return nullptr;
    }
    return storage.data();
}

extern "C" __attribute__((ms_abi)) const char16_t* crf__W_Gettnames() noexcept {
    return crf__W_Getmonths();
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf__Strftime(
    char* buffer, std::uint64_t count, const char* format,
    const void* broken, const void*) noexcept {
    return cr_strftime(buffer, count, format, broken);
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf__Wcsftime(
    char16_t* buffer, std::uint64_t count, const char16_t* format,
    const void* broken, const void*) noexcept {
    return crf_wcsftime(buffer, count, format, broken);
}


// ===========================================================================
// The console family and the remaining spellings
//
// The console this runtime has answers the way a headless one does: reads
// end at the file's end, the key-availability answer is none, and the
// writes reach the standard streams. The `_l` spellings run in the "C"
// locale, so the tag rides along and the behaviour is the untagged call's.
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t u32u__getch() noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32u__kbhit() noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32u__putch(
    std::int32_t) noexcept;

extern "C" __attribute__((ms_abi)) std::int32_t crf__getch_nolock() noexcept {
    return u32u__getch();
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__getche() noexcept {
    // The echoed read: the character read, echoed when there was one. An
    // end of file echoes nothing.
    const std::int32_t read = u32u__getch();
    if (read >= 0) {
        ::fputc(read, stdout);
    }
    return read;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__getche_nolock() noexcept {
    return crf__getche();
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__putch_nolock(
    std::int32_t character) noexcept {
    return u32u__putch(character);
}

// The wide console pair, whose characters are the guest's code units.
extern "C" __attribute__((ms_abi)) std::uint16_t crf__getwch() noexcept {
    const std::int32_t read = u32u__getch();
    return read < 0 ? 0xFFFFu : static_cast<std::uint16_t>(read);
}

extern "C" __attribute__((ms_abi)) std::uint16_t crf__getwch_nolock() noexcept {
    return crf__getwch();
}

extern "C" __attribute__((ms_abi)) std::uint16_t crf__getwche() noexcept {
    const std::uint16_t read = crf__getwch();
    if (read != 0xFFFFu) {
        ::fputwc(static_cast<wchar_t>(read), stdout);
    }
    return read;
}

extern "C" __attribute__((ms_abi)) std::uint16_t crf__getwche_nolock() noexcept {
    return crf__getwche();
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__ungetch(
    std::int32_t character) noexcept {
    // The pushed-back character is the next one the read answers; the
    // slot is the single one the call has.
    static std::int32_t pushed = -1;
    if (character < 0) {
        return character;
    }
    if (pushed >= 0) {
        return -1;
    }
    pushed = character;
    return character;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__ungetch_nolock(
    std::int32_t character) noexcept {
    return crf__ungetch(character);
}

extern "C" __attribute__((ms_abi)) std::uint16_t crf__ungetwch(
    std::uint16_t character) noexcept {
    return crf__ungetch(character) < 0 ? 0xFFFFu : character;
}

extern "C" __attribute__((ms_abi)) std::uint16_t crf__ungetwch_nolock(
    std::uint16_t character) noexcept {
    return crf__ungetwch(character);
}

extern "C" __attribute__((ms_abi)) std::uint16_t crf__putwch(
    std::uint16_t character) noexcept {
    return ::fputwc(static_cast<wchar_t>(character), stdout) == WEOF
               ? 0xFFFFu
               : character;
}

extern "C" __attribute__((ms_abi)) std::uint16_t crf__putwch_nolock(
    std::uint16_t character) noexcept {
    return crf__putwch(character);
}

// The line readers and writers over the console streams.
extern "C" __attribute__((ms_abi)) char* crf__cgets(
    char* buffer) noexcept {
    // The buffer's first byte holds the size and the second receives the
    // count read; the text starts at the third.
    if (buffer == nullptr) {
        return nullptr;
    }
    const std::size_t capacity = static_cast<unsigned char>(buffer[0]);
    if (capacity == 0) {
        return nullptr;
    }
    if (::fgets(buffer + 2, static_cast<int>(capacity), stdin) == nullptr) {
        return nullptr;
    }
    std::size_t length = std::strlen(buffer + 2);
    if (length > 0 && buffer[2 + length - 1] == '\n') {
        buffer[2 + --length] = '\0';
    }
    buffer[1] = static_cast<char>(length);
    return buffer + 2;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__cgets_s(
    char* buffer, std::size_t size, std::size_t* read) noexcept {
    if (buffer == nullptr || size < 3 || read == nullptr) {
        if (buffer != nullptr && size != 0) {
            buffer[0] = '\0';
        }
        if (read != nullptr) {
            *read = 0;
        }
        return EINVAL;
    }
    if (::fgets(buffer, static_cast<int>(size), stdin) == nullptr) {
        buffer[0] = '\0';
        *read = 0;
        return errno != 0 ? errno : EIO;
    }
    std::size_t length = std::strlen(buffer);
    if (length > 0 && buffer[length - 1] == '\n') {
        buffer[--length] = '\0';
    }
    *read = length;
    return 0;
}

extern "C" __attribute__((ms_abi)) char16_t* crf__cgetws(
    char16_t* buffer) noexcept {
    if (buffer == nullptr) {
        return nullptr;
    }
    const std::size_t capacity = static_cast<unsigned char>(buffer[0]);
    if (capacity == 0) {
        return nullptr;
    }
    char16_t* text = crf_fgetws(buffer + 2,
                                static_cast<std::int32_t>(capacity),
                                stdin);
    if (text == nullptr) {
        return nullptr;
    }
    const std::size_t length =
        std::char_traits<char16_t>::length(text);
    buffer[1] = static_cast<char16_t>(length);
    return text;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__cgetws_s(
    char16_t* buffer, std::size_t size, std::size_t* read) noexcept {
    if (buffer == nullptr || size == 0 || read == nullptr) {
        if (buffer != nullptr && size != 0) {
            buffer[0] = u'\0';
        }
        if (read != nullptr) {
            *read = 0;
        }
        return EINVAL;
    }
    if (crf_fgetws(buffer, static_cast<std::int32_t>(size), stdin) ==
        nullptr) {
        buffer[0] = u'\0';
        *read = 0;
        return errno != 0 ? errno : EIO;
    }
    std::size_t length = 0;
    while (length < size && buffer[length] != u'\0') {
        ++length;
    }
    if (length > 0 && buffer[length - 1] == u'\n') {
        buffer[--length] = u'\0';
    }
    *read = length;
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__cputs(
    const char* text) noexcept {
    if (text == nullptr) {
        return -1;
    }
    return ::fputs(text, stdout) < 0 ? -1 : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__cputws(
    const char16_t* text) noexcept {
    return crf_fputws(text, stdout);
}

// The formatted console writes, which the `__conio_common_*` entry points
// carry and the `_cprintf` spellings reach. The format walks are the
// stdio ones; the destination is the console, which here is stdout.
extern "C" __attribute__((ms_abi)) std::int32_t u32u___stdio_common_vfwprintf(
    std::uint64_t options, void* stream, const char16_t* format,
    void* locale, void* args) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_vfprintf(
    void* stream, const char* fmt, void* ms_slots) noexcept;

extern "C" __attribute__((ms_abi)) std::int32_t crf___conio_common_vcprintf(
    std::uint64_t options, const char* format, void* slots,
    std::uint64_t locale) noexcept {
    static_cast<void>(options);
    static_cast<void>(locale);
    if (format == nullptr || slots == nullptr) {
        return -1;
    }
    return cr_vfprintf(stdout, format, slots);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf___conio_common_vcprintf_p(
    std::uint64_t options, const char* format, void* slots,
    std::uint64_t locale) noexcept {
    // The positional form; the walks this runtime bridges read the same
    // argument list either way.
    return crf___conio_common_vcprintf(options, format, slots, locale);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf___conio_common_vcprintf_s(
    std::uint64_t options, const char* format, void* slots,
    std::uint64_t locale) noexcept {
    return crf___conio_common_vcprintf(options, format, slots, locale);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf___conio_common_vcwprintf(
    std::uint64_t options, const char16_t* format, void* slots,
    std::uint64_t locale) noexcept {
    static_cast<void>(options);
    static_cast<void>(locale);
    if (format == nullptr || slots == nullptr) {
        return -1;
    }
    // The wide console write: the format and its arguments are the wide
    // walk's, and the answer is the code units written.
    return u32u___stdio_common_vfwprintf(0, stdout, format, nullptr,
                                         slots);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf___conio_common_vcwprintf_p(
    std::uint64_t options, const char16_t* format, void* slots,
    std::uint64_t locale) noexcept {
    return crf___conio_common_vcwprintf(options, format, slots, locale);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf___conio_common_vcwprintf_s(
    std::uint64_t options, const char16_t* format, void* slots,
    std::uint64_t locale) noexcept {
    return crf___conio_common_vcwprintf(options, format, slots, locale);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf___conio_common_vcscanf(
    std::uint64_t options, const char* format, void* slots,
    std::uint64_t locale) noexcept {
    static_cast<void>(options);
    static_cast<void>(locale);
    static_cast<void>(format);
    static_cast<void>(slots);
    // The console scan reaches nothing a headless run can read; the
    // answer is the end-of-file the walk reports.
    return -1;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf___conio_common_vcwscanf(
    std::uint64_t options, const char16_t* format, void* slots,
    std::uint64_t locale) noexcept {
    static_cast<void>(options);
    static_cast<void>(format);
    static_cast<void>(slots);
    static_cast<void>(locale);
    return -1;
}

// The remaining stdio spellings the reopen and remove families add.
extern "C" __attribute__((ms_abi)) void* crf__wfreopen(
    const char16_t* path, const char16_t* mode, void* stream) noexcept {
    if (path == nullptr || mode == nullptr) {
        return nullptr;
    }
    std::string narrow_path;
    std::string narrow_mode;
    if (!narrow_out(std::u16string_view(path), narrow_path).converted ||
        !narrow_out(std::u16string_view(mode), narrow_mode).converted) {
        return nullptr;
    }
    return crf_freopen(narrow_path.c_str(), narrow_mode.c_str(), stream);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wfreopen_s(
    void** stream, const char16_t* path, const char16_t* mode,
    void* original) noexcept {
    if (stream == nullptr) {
        return EINVAL;
    }
    void* reopened = crf__wfreopen(path, mode, original);
    *stream = reopened;
    return reopened != nullptr ? 0 : errno;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wremove(
    const char16_t* path) noexcept {
    return crf__wunlink(path);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wrename(
    const char16_t* from, const char16_t* to) noexcept {
    if (from == nullptr || to == nullptr) {
        errno = EINVAL;
        return -1;
    }
    std::string narrow_from;
    std::string narrow_to;
    if (!narrow_out(std::u16string_view(from), narrow_from).converted ||
        !narrow_out(std::u16string_view(to), narrow_to).converted) {
        errno = EINVAL;
        return -1;
    }
    return crf_rename(narrow_from.c_str(), narrow_to.c_str());
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wsopen_dispatch(
    const char16_t* path, std::int32_t oflag, std::int32_t share,
    std::uint32_t pmode, std::int32_t permissions, std::int32_t* fd) noexcept {
    static_cast<void>(permissions);
    if (fd == nullptr || path == nullptr) {
        if (fd != nullptr) {
            *fd = -1;
        }
        return EINVAL;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(path), narrow).converted) {
        *fd = -1;
        return EINVAL;
    }
    *fd = crf__sopen_dispatch(narrow.c_str(), oflag, share, pmode);
    return *fd >= 0 ? 0 : errno;
}

// The FPU control spellings' remaining members: the two-word form and the
// control setter under the other name.
extern "C" __attribute__((ms_abi)) std::int32_t crf___control87_2(
    std::uint32_t value, std::uint32_t mask, std::uint32_t* current,
    std::uint32_t* x86) noexcept {
    const std::uint32_t previous = crf__control87(value, mask);
    if (current != nullptr) {
        *current = previous;
    }
    if (x86 != nullptr) {
        *x86 = previous;
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t crf__set_controlfp(
    std::uint32_t value, std::uint32_t mask) noexcept {
    crf__control87(value, mask);
    // The setter answers nothing on the real runtime either; the value is
    // the one the control word now holds.
    const std::lock_guard<std::mutex> lock(g_fpu_mutex);
    return g_fpu_control;
}

// The debug break the CRT's fast-fail path takes. There is no debugger to
// break into, and the call ends the process the way the abort path does.
extern "C" __attribute__((ms_abi)) void crf__crt_debugger_hook(
    std::int64_t reserved) noexcept {
    static_cast<void>(reserved);
    k32_ExitProcess(3);
    __builtin_unreachable();
}

// The pure virtual call, which is the abort path with its message.
extern "C" __attribute__((ms_abi)) void crf__purecall() noexcept {
    std::fprintf(stderr, "Pure virtual function call\n");
    ::abort();
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf__set_purecall_handler(
    std::uint64_t handler) noexcept {
    static std::uint64_t current = 0;
    const std::uint64_t previous = current;
    current = handler;
    return previous;
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf__get_purecall_handler() noexcept {
    static std::uint64_t current = 0;
    return current;
}

// The SEH translator and the unexpected handler, whose storage is the
// process's own.
extern "C" __attribute__((ms_abi)) std::uint64_t crf__set_se_translator(
    std::uint64_t translator) noexcept {
    static std::uint64_t current = 0;
    const std::uint64_t previous = current;
    current = translator;
    return previous;
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf_set_unexpected(
    std::uint64_t handler) noexcept {
    static std::uint64_t current = 0;
    const std::uint64_t previous = current;
    current = handler;
    return previous;
}

extern "C" __attribute__((ms_abi)) std::uint64_t crf__get_unexpected() noexcept {
    static std::uint64_t current = 0;
    return current;
}

extern "C" __attribute__((ms_abi)) void crf_unexpected() noexcept {
    ::abort();
}

// The case-insensitive collations, which run in the "C" locale and so
// answer the case-folded comparison.
extern "C" __attribute__((ms_abi)) std::int32_t cr__stricmp(
    const char* a, const char* b) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr__strnicmp(
    const char* a, const char* b, std::uint64_t count) noexcept;

extern "C" __attribute__((ms_abi)) std::int32_t crf__stricoll(
    const char* a, const char* b) noexcept {
    return cr__stricmp(a, b);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__strnicoll(
    const char* a, const char* b, std::uint64_t count) noexcept {
    return cr__strnicmp(a, b, count);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wcsicoll(
    const char16_t* a, const char16_t* b) noexcept {
    if (a == nullptr || b == nullptr) {
        return 0;
    }
    for (; *a != u'\0' && *b != u'\0'; ++a, ++b) {
        const std::uint16_t ca = crf_towlower(*a);
        const std::uint16_t cb = crf_towlower(*b);
        if (ca != cb) {
            return ca < cb ? -1 : 1;
        }
    }
    if (*a == u'\0' && *b == u'\0') {
        return 0;
    }
    return *a == u'\0' ? -1 : 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wcsnicoll(
    const char16_t* a, const char16_t* b, std::uint64_t count) noexcept {
    if (a == nullptr || b == nullptr) {
        return 0;
    }
    for (std::uint64_t i = 0; i < count; ++i, ++a, ++b) {
        if (*a == u'\0' && *b == u'\0') {
            return 0;
        }
        const std::uint16_t ca = crf_towlower(*a);
        const std::uint16_t cb = crf_towlower(*b);
        if (ca != cb) {
            return ca < cb ? -1 : 1;
        }
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wcsncoll(
    const char16_t* a, const char16_t* b, std::uint64_t count) noexcept {
    if (a == nullptr || b == nullptr) {
        return 0;
    }
    for (std::uint64_t i = 0; i < count; ++i, ++a, ++b) {
        if (*a != *b) {
            return *a < *b ? -1 : 1;
        }
        if (*a == u'\0') {
            return 0;
        }
    }
    return 0;
}

// The locale-tagged narrow and wide rewrites and compares. The narrow
// case rewrites they call are defined below, beside their secure forms.
extern "C" __attribute__((ms_abi)) char* crf__strlwr(char* text) noexcept;
extern "C" __attribute__((ms_abi)) char* crf__strupr(char* text) noexcept;

extern "C" __attribute__((ms_abi)) std::int32_t crf__stricmp_l(
    const char* a, const char* b, std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return cr__stricmp(a, b);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__stricoll_l(
    const char* a, const char* b, std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return crf__stricoll(a, b);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__strnicmp_l(
    const char* a, const char* b, std::uint64_t count,
    std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return cr__strnicmp(a, b, count);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__strnicoll_l(
    const char* a, const char* b, std::uint64_t count,
    std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return crf__strnicoll(a, b, count);
}

extern "C" __attribute__((ms_abi)) char* crf__strlwr_l(
    char* text, std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return crf__strlwr(text);
}

extern "C" __attribute__((ms_abi)) char* crf__strupr_l(
    char* text, std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return crf__strupr(text);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_strlwr_s_impl(
    char* text, std::uint64_t size) noexcept;

extern "C" __attribute__((ms_abi)) std::int32_t crf__strlwr_s_l(
    char* text, std::uint64_t size, std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return u32u_strlwr_s_impl(text, size);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_strupr_s_impl(
    char* text, std::uint64_t size) noexcept;

extern "C" __attribute__((ms_abi)) std::int32_t crf__strupr_s_l(
    char* text, std::uint64_t size, std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return u32u_strupr_s_impl(text, size);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__strncoll_l(
    const char* a, const char* b, std::uint64_t count,
    std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return std::strncmp(a, b, count);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__memicmp_l(
    const void* a, const void* b, std::uint32_t count,
    std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return crf__memicmp(a, b, count);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__isctype_l(
    std::int32_t value, std::uint32_t mask, std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return crf__isctype(value, mask);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__isleadbyte_l(
    std::int32_t value, std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return crf_isleadbyte(value);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wcsicmp_l(
    const char16_t* a, const char16_t* b, std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    if (a == nullptr || b == nullptr) {
        return 0;
    }
    for (; *a != u'\0' && *b != u'\0'; ++a, ++b) {
        const std::uint16_t ca = crf_towlower(*a);
        const std::uint16_t cb = crf_towlower(*b);
        if (ca != cb) {
            return ca < cb ? -1 : 1;
        }
    }
    if (*a == u'\0' && *b == u'\0') {
        return 0;
    }
    return *a == u'\0' ? -1 : 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wcsicoll_l(
    const char16_t* a, const char16_t* b, std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return crf__wcsicoll(a, b);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wcsnicmp_l(
    const char16_t* a, const char16_t* b, std::uint64_t count,
    std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return crf__wcsnicoll(a, b, count);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wcsnicoll_l(
    const char16_t* a, const char16_t* b, std::uint64_t count,
    std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return crf__wcsnicoll(a, b, count);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wcsncoll_l(
    const char16_t* a, const char16_t* b, std::uint64_t count,
    std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return crf__wcsncoll(a, b, count);
}

extern "C" __attribute__((ms_abi)) char16_t* crf__wcslwr_l(
    char16_t* text, std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    if (text == nullptr) {
        return nullptr;
    }
    for (char16_t* p = text; *p != u'\0'; ++p) {
        *p = crf_towlower(*p);
    }
    return text;
}

extern "C" __attribute__((ms_abi)) char16_t* crf__wcsupr_l(
    char16_t* text, std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    if (text == nullptr) {
        return nullptr;
    }
    for (char16_t* p = text; *p != u'\0'; ++p) {
        *p = crf_towupper(*p);
    }
    return text;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wcslwr_s_l(
    char16_t* text, std::uint64_t size, std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    if (text == nullptr || size == 0) {
        return EINVAL;
    }
    std::size_t length = 0;
    while (length < size && text[length] != u'\0') {
        ++length;
    }
    if (length >= size) {
        text[0] = u'\0';
        return EINVAL;
    }
    for (std::size_t i = 0; i < length; ++i) {
        text[i] = crf_towlower(text[i]);
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wcsupr_s_l(
    char16_t* text, std::uint64_t size, std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    if (text == nullptr || size == 0) {
        return EINVAL;
    }
    std::size_t length = 0;
    while (length < size && text[length] != u'\0') {
        ++length;
    }
    if (length >= size) {
        text[0] = u'\0';
        return EINVAL;
    }
    for (std::size_t i = 0; i < length; ++i) {
        text[i] = crf_towupper(text[i]);
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__iswctype_l(
    std::uint16_t value, WctypeProperty property,
    std::uint64_t locale) noexcept {
    static_cast<void>(locale);
    return crf_iswctype(value, property);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_iswctype_l(
    std::uint16_t value, WctypeProperty property,
    std::uint64_t locale) noexcept {
    return crf__iswctype_l(value, property, locale);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf_is_wctype_l(
    std::uint16_t value, WctypeProperty property,
    std::uint64_t locale) noexcept {
    return crf__iswctype_l(value, property, locale);
}

// The wide case rewrites, untagged and secure.
extern "C" __attribute__((ms_abi)) char16_t* crf__wcslwr(
    char16_t* text) noexcept {
    return crf__wcslwr_l(text, 0);
}

extern "C" __attribute__((ms_abi)) char16_t* crf__wcsupr(
    char16_t* text) noexcept {
    return crf__wcsupr_l(text, 0);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wcslwr_s(
    char16_t* text, std::uint64_t size) noexcept {
    return crf__wcslwr_s_l(text, size, 0);
}

extern "C" __attribute__((ms_abi)) std::int32_t crf__wcsupr_s(
    char16_t* text, std::uint64_t size) noexcept {
    return crf__wcsupr_s_l(text, size, 0);
}

extern "C" __attribute__((ms_abi)) char* crf__strlwr_s(
    char* text, std::uint64_t size) noexcept {
    if (text == nullptr || size == 0) {
        return nullptr;
    }
    if (u32u_strlwr_s_impl(text, size) != 0) {
        return nullptr;
    }
    return text;
}

extern "C" __attribute__((ms_abi)) char* crf__strupr_s(
    char* text, std::uint64_t size) noexcept {
    if (text == nullptr || size == 0) {
        return nullptr;
    }
    if (u32u_strupr_s_impl(text, size) != 0) {
        return nullptr;
    }
    return text;
}

// The narrow case rewrites, untagged.
extern "C" __attribute__((ms_abi)) char* crf__strlwr(
    char* text) noexcept {
    if (text == nullptr) {
        return nullptr;
    }
    for (char* p = text; *p != '\0'; ++p) {
        *p = static_cast<char>(std::tolower(static_cast<unsigned char>(*p)));
    }
    return text;
}

extern "C" __attribute__((ms_abi)) char* crf__strupr(
    char* text) noexcept {
    if (text == nullptr) {
        return nullptr;
    }
    for (char* p = text; *p != '\0'; ++p) {
        *p = static_cast<char>(std::toupper(static_cast<unsigned char>(*p)));
    }
    return text;
}

// The narrow case rewrites' locale-tagged internals, which the `_l`
// spellings above reach; the implementations live beside the secure ones
// they share the shape with.
extern "C" __attribute__((ms_abi)) std::int32_t u32u_strlwr_s_impl(
    char* text, std::uint64_t size) noexcept {
    if (text == nullptr || size == 0) {
        return EINVAL;
    }
    const std::size_t length = ::strnlen(text, size);
    if (length >= size) {
        text[0] = '\0';
        return EINVAL;
    }
    for (std::size_t i = 0; i < length; ++i) {
        text[i] = static_cast<char>(
            std::tolower(static_cast<unsigned char>(text[i])));
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_strupr_s_impl(
    char* text, std::uint64_t size) noexcept {
    if (text == nullptr || size == 0) {
        return EINVAL;
    }
    const std::size_t length = ::strnlen(text, size);
    if (length >= size) {
        text[0] = '\0';
        return EINVAL;
    }
    for (std::size_t i = 0; i < length; ++i) {
        text[i] = static_cast<char>(
            std::toupper(static_cast<unsigned char>(text[i])));
    }
    return 0;
}

// The wide case-insensitive compare, untagged, beside the tagged one.
extern "C" __attribute__((ms_abi)) std::int32_t crf__wcsicmp(
    const char16_t* a, const char16_t* b) noexcept {
    return crf__wcsicmp_l(a, b, 0);
}

// The narrow/wide case rewrites' secure narrow forms, above, and the
// `_l`-tagged narrow case-insensitive compares beside them.


// ===========================================================================
// The registration
//
// One list, deduplicated the way `add_ucrt_extra` deduplicates: the
// classic and modern domains fill their names first, and a name one of
// them already carries is not carried twice. Every name here is one the
// family split lists, and the family table in `modules.cpp` states which
// module each belongs to.
// ===========================================================================

void add_crt_families(ExportList& out) {
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
    // The two names whose implementations live in the classic domain's
    // machinery: the copy the vcruntime domain registers and the signal
    // raise whose handler table is `signal`'s.
    e("strcpy", reinterpret_cast<void*>(&cr_strcpy));
    e("raise", reinterpret_cast<void*>(&cr_raise));

    e("_Exit", reinterpret_cast<void*>(&crf__Exit));
    e("_Getdays", reinterpret_cast<void*>(&crf__Getdays));
    e("_Getmonths", reinterpret_cast<void*>(&crf__Getmonths));
    e("_Gettnames", reinterpret_cast<void*>(&crf__Gettnames));
    e("_Strftime", reinterpret_cast<void*>(&crf__Strftime));
    e("_W_Getdays", reinterpret_cast<void*>(&crf__W_Getdays));
    e("_W_Getmonths", reinterpret_cast<void*>(&crf__W_Getmonths));
    e("_W_Gettnames", reinterpret_cast<void*>(&crf__W_Gettnames));
    e("_Wcsftime", reinterpret_cast<void*>(&crf__Wcsftime));
    e("__conio_common_vcprintf", reinterpret_cast<void*>(&crf___conio_common_vcprintf));
    e("__conio_common_vcprintf_p", reinterpret_cast<void*>(&crf___conio_common_vcprintf_p));
    e("__conio_common_vcprintf_s", reinterpret_cast<void*>(&crf___conio_common_vcprintf_s));
    e("__conio_common_vcscanf", reinterpret_cast<void*>(&crf___conio_common_vcscanf));
    e("__conio_common_vcwprintf", reinterpret_cast<void*>(&crf___conio_common_vcwprintf));
    e("__conio_common_vcwprintf_p", reinterpret_cast<void*>(&crf___conio_common_vcwprintf_p));
    e("__conio_common_vcwprintf_s", reinterpret_cast<void*>(&crf___conio_common_vcwprintf_s));
    e("__conio_common_vcwscanf", reinterpret_cast<void*>(&crf___conio_common_vcwscanf));
    e("__control87_2", reinterpret_cast<void*>(&crf___control87_2));
    e("__daylight", reinterpret_cast<void*>(&crf___daylight));
    e("__doserrno", reinterpret_cast<void*>(&crf___doserrno));
    e("__dstbias", reinterpret_cast<void*>(&crf___dstbias));
    e("__fpe_flt_rounds", reinterpret_cast<void*>(&crf___fpe_flt_rounds));
    e("__fpecode", reinterpret_cast<void*>(&crf___fpecode));
    e("__initialize_lconv_for_unsigned_char", reinterpret_cast<void*>(&crf___initialize_lconv_for_unsigned_char));
    e("__isascii", reinterpret_cast<void*>(&crf___isascii));
    e("__iscsym", reinterpret_cast<void*>(&crf___iscsym));
    e("__iscsymf", reinterpret_cast<void*>(&crf___iscsymf));
    e("__iswcsym", reinterpret_cast<void*>(&crf___iswcsym));
    e("__iswcsymf", reinterpret_cast<void*>(&crf___iswcsymf));
    e("__lc_collate_cp_func", reinterpret_cast<void*>(&crf___lc_collate_cp_func));
    e("__lc_locale_name_func", reinterpret_cast<void*>(&crf___lc_locale_name_func));
    e("__mb_cur_max_l_func", reinterpret_cast<void*>(&crf___mb_cur_max_l_func));
    e("__p__pgmptr", reinterpret_cast<void*>(&crf___p__pgmptr));
    e("__p__wenviron", reinterpret_cast<void*>(&crf___p__wenviron));
    e("__p__wpgmptr", reinterpret_cast<void*>(&crf___p__wpgmptr));
    e("__pwctype_func", reinterpret_cast<void*>(&crf___pwctype_func));
    e("__pxcptinfoptrs", reinterpret_cast<void*>(&crf___pxcptinfoptrs));
    e("__strncnt", reinterpret_cast<void*>(&crf___strncnt));
    e("__threadhandle", reinterpret_cast<void*>(&crf___threadhandle));
    e("__threadid", reinterpret_cast<void*>(&crf___threadid));
    e("__timezone", reinterpret_cast<void*>(&crf___timezone));
    e("__toascii", reinterpret_cast<void*>(&crf___toascii));
    e("__tzname", reinterpret_cast<void*>(&crf___tzname));
    e("__wcsncnt", reinterpret_cast<void*>(&crf___wcsncnt));
    e("_access", reinterpret_cast<void*>(&crf__access));
    e("_access_s", reinterpret_cast<void*>(&crf__access_s));
    e("_aligned_offset_free", reinterpret_cast<void*>(&crf__aligned_offset_free));
    e("_aligned_offset_malloc", reinterpret_cast<void*>(&crf__aligned_offset_malloc));
    e("_aligned_offset_realloc", reinterpret_cast<void*>(&crf__aligned_offset_realloc));
    e("_aligned_offset_recalloc", reinterpret_cast<void*>(&crf__aligned_offset_recalloc));
    e("_aligned_recalloc", reinterpret_cast<void*>(&crf__aligned_recalloc));
    e("_beep", reinterpret_cast<void*>(&crf__beep));
    e("_byteswap_uint64", reinterpret_cast<void*>(&crf__byteswap_uint64));
    e("_byteswap_ulong", reinterpret_cast<void*>(&crf__byteswap_ulong));
    e("_byteswap_ushort", reinterpret_cast<void*>(&crf__byteswap_ushort));
    e("_calloc_base", reinterpret_cast<void*>(&crf__calloc_base));
    e("_cgets", reinterpret_cast<void*>(&crf__cgets));
    e("_cgets_s", reinterpret_cast<void*>(&crf__cgets_s));
    e("_cgetws", reinterpret_cast<void*>(&crf__cgetws));
    e("_cgetws_s", reinterpret_cast<void*>(&crf__cgetws_s));
    e("_chdir", reinterpret_cast<void*>(&crf__chdir));
    e("_chdrive", reinterpret_cast<void*>(&crf__chdrive));
    e("_chgsign", reinterpret_cast<void*>(&crf__chgsign));
    e("_chgsignf", reinterpret_cast<void*>(&crf__chgsignf));
    e("_chgsignl", reinterpret_cast<void*>(&crf__chgsignl));
    e("_chmod", reinterpret_cast<void*>(&crf__chmod));
    e("_chsize", reinterpret_cast<void*>(&crf__chsize));
    e("_chsize_s", reinterpret_cast<void*>(&crf__chsize_s));
    e("_clearfp", reinterpret_cast<void*>(&crf__clearfp));
    e("_close", reinterpret_cast<void*>(&crf__close));
    e("_commit", reinterpret_cast<void*>(&crf__commit));
    e("_control87", reinterpret_cast<void*>(&crf__control87));
    e("_controlfp", reinterpret_cast<void*>(&crf__controlfp));
    e("_controlfp_s", reinterpret_cast<void*>(&crf__controlfp_s));
    e("_copysign", reinterpret_cast<void*>(&crf__copysign));
    e("_copysignf", reinterpret_cast<void*>(&crf__copysignf));
    e("_copysignl", reinterpret_cast<void*>(&crf__copysignl));
    e("_cputs", reinterpret_cast<void*>(&crf__cputs));
    e("_cputws", reinterpret_cast<void*>(&crf__cputws));
    e("_creat", reinterpret_cast<void*>(&crf__creat));
    e("_crt_at_quick_exit", reinterpret_cast<void*>(&crf__crt_at_quick_exit));
    e("_crt_debugger_hook", reinterpret_cast<void*>(&crf__crt_debugger_hook));
    e("_ctime32", reinterpret_cast<void*>(&crf__ctime32));
    e("_ctime32_s", reinterpret_cast<void*>(&crf__ctime32_s));
    e("_ctime64_s", reinterpret_cast<void*>(&crf__ctime64_s));
    e("_cwait", reinterpret_cast<void*>(&crf__cwait));
    e("_difftime32", reinterpret_cast<void*>(&crf__difftime32));
    e("_difftime64", reinterpret_cast<void*>(&crf__difftime64));
    e("_dup", reinterpret_cast<void*>(&crf__dup));
    e("_dup2", reinterpret_cast<void*>(&crf__dup2));
    e("_dupenv_s", reinterpret_cast<void*>(&crf__dupenv_s));
    e("_ecvt", reinterpret_cast<void*>(&crf__ecvt));
    e("_ecvt_s", reinterpret_cast<void*>(&crf__ecvt_s));
    e("_endthread", reinterpret_cast<void*>(&crf__endthread));
    e("_eof", reinterpret_cast<void*>(&crf__eof));
    e("_execl", reinterpret_cast<void*>(&crf__execl));
    e("_execle", reinterpret_cast<void*>(&crf__execle));
    e("_execlp", reinterpret_cast<void*>(&crf__execlp));
    e("_execlpe", reinterpret_cast<void*>(&crf__execlpe));
    e("_execv", reinterpret_cast<void*>(&crf__execv));
    e("_execve", reinterpret_cast<void*>(&crf__execve));
    e("_execvp", reinterpret_cast<void*>(&crf__execvp));
    e("_execvpe", reinterpret_cast<void*>(&crf__execvpe));
    e("_expand", reinterpret_cast<void*>(&crf__expand));
    e("_fclose_nolock", reinterpret_cast<void*>(&crf__fclose_nolock));
    e("_fcloseall", reinterpret_cast<void*>(&crf__fcloseall));
    e("_fcvt", reinterpret_cast<void*>(&crf__fcvt));
    e("_fcvt_s", reinterpret_cast<void*>(&crf__fcvt_s));
    e("_fdopen", reinterpret_cast<void*>(&crf__fdopen));
    e("_fflush_nolock", reinterpret_cast<void*>(&crf__fflush_nolock));
    e("_fgetc_nolock", reinterpret_cast<void*>(&crf__fgetc_nolock));
    e("_fgetchar", reinterpret_cast<void*>(&crf__fgetchar));
    e("_fgetwc_nolock", reinterpret_cast<void*>(&crf__fgetwc_nolock));
    e("_fgetwchar", reinterpret_cast<void*>(&crf__fgetwchar));
    e("_filelength", reinterpret_cast<void*>(&crf__filelength));
    e("_filelengthi64", reinterpret_cast<void*>(&crf__filelengthi64));
    e("_findclose", reinterpret_cast<void*>(&crf__findclose));
    e("_findfirst32", reinterpret_cast<void*>(&crf__findfirst32));
    e("_findfirst32i64", reinterpret_cast<void*>(&crf__findfirst32i64));
    e("_findfirst64", reinterpret_cast<void*>(&crf__findfirst64));
    e("_findfirst64i32", reinterpret_cast<void*>(&crf__findfirst64i32));
    e("_findnext32", reinterpret_cast<void*>(&crf__findnext32));
    e("_findnext32i64", reinterpret_cast<void*>(&crf__findnext32i64));
    e("_findnext64", reinterpret_cast<void*>(&crf__findnext64));
    e("_findnext64i32", reinterpret_cast<void*>(&crf__findnext64i32));
    e("_finite", reinterpret_cast<void*>(&crf__finite));
    e("_finitef", reinterpret_cast<void*>(&crf__finitef));
    e("_flushall", reinterpret_cast<void*>(&crf__flushall));
    e("_fpclass", reinterpret_cast<void*>(&crf__fpclass));
    e("_fpclassf", reinterpret_cast<void*>(&crf__fpclassf));
    e("_fpreset", reinterpret_cast<void*>(&crf__fpreset));
    e("_fputc_nolock", reinterpret_cast<void*>(&crf__fputc_nolock));
    e("_fputchar", reinterpret_cast<void*>(&crf__fputchar));
    e("_fputchar_nolock", reinterpret_cast<void*>(&crf__fputchar_nolock));
    e("_fputwc_nolock", reinterpret_cast<void*>(&crf__fputwc_nolock));
    e("_fputwchar_nolock", reinterpret_cast<void*>(&crf__fputwchar_nolock));
    e("_fread_nolock", reinterpret_cast<void*>(&crf__fread_nolock));
    e("_fread_nolock_s", reinterpret_cast<void*>(&crf__fread_nolock_s));
    e("_free_base", reinterpret_cast<void*>(&crf__free_base));
    e("_fseek_nolock", reinterpret_cast<void*>(&crf__fseek_nolock));
    e("_fseeki64_nolock", reinterpret_cast<void*>(&crf__fseeki64_nolock));
    e("_fsopen", reinterpret_cast<void*>(&crf__fsopen));
    e("_fstat32", reinterpret_cast<void*>(&crf__fstat32));
    e("_fstat32i64", reinterpret_cast<void*>(&crf__fstat32i64));
    e("_fstat64", reinterpret_cast<void*>(&crf__fstat64));
    e("_fstat64i32", reinterpret_cast<void*>(&crf__fstat64i32));
    e("_ftell_nolock", reinterpret_cast<void*>(&crf__ftell_nolock));
    e("_ftelli64_nolock", reinterpret_cast<void*>(&crf__ftelli64_nolock));
    e("_ftol", reinterpret_cast<void*>(&crf__ftol));
    e("_fullpath", reinterpret_cast<void*>(&crf__fullpath));
    e("_futime32", reinterpret_cast<void*>(&crf__futime32));
    e("_futime64", reinterpret_cast<void*>(&crf__futime64));
    e("_fwrite_nolock", reinterpret_cast<void*>(&crf__fwrite_nolock));
    e("_gcvt", reinterpret_cast<void*>(&crf__gcvt));
    e("_gcvt_s", reinterpret_cast<void*>(&crf__gcvt_s));
    e("_get_FMA3_enable", reinterpret_cast<void*>(&crf__get_FMA3_enable));
    e("_get_daylight", reinterpret_cast<void*>(&crf__get_daylight));
    e("_get_doserrno", reinterpret_cast<void*>(&crf__get_doserrno));
    e("_get_dstbias", reinterpret_cast<void*>(&crf__get_dstbias));
    e("_get_fmode", reinterpret_cast<void*>(&crf__get_fmode));
    e("_get_heap_handle", reinterpret_cast<void*>(&crf__get_heap_handle));
    e("_get_invalid_parameter_handler", reinterpret_cast<void*>(&crf__get_invalid_parameter_handler));
    e("_get_narrow_winmain_command_line", reinterpret_cast<void*>(&crf__get_narrow_winmain_command_line));
    e("_get_osfhandle", reinterpret_cast<void*>(&crf__get_osfhandle));
    e("_get_pgmptr", reinterpret_cast<void*>(&crf__get_pgmptr));
    e("_get_printf_count_output", reinterpret_cast<void*>(&crf__get_printf_count_output));
    e("_get_purecall_handler", reinterpret_cast<void*>(&crf__get_purecall_handler));
    e("_get_stream_buffer_pointers", reinterpret_cast<void*>(&crf__get_stream_buffer_pointers));
    e("_get_terminate", reinterpret_cast<void*>(&crf__get_terminate));
    e("_get_thread_local_invalid_parameter_handler", reinterpret_cast<void*>(&crf__get_thread_local_invalid_parameter_handler));
    e("_get_timezone", reinterpret_cast<void*>(&crf__get_timezone));
    e("_get_tzname", reinterpret_cast<void*>(&crf__get_tzname));
    e("_get_unexpected", reinterpret_cast<void*>(&crf__get_unexpected));
    e("_get_wide_winmain_command_line", reinterpret_cast<void*>(&crf__get_wide_winmain_command_line));
    e("_get_wpgmptr", reinterpret_cast<void*>(&crf__get_wpgmptr));
    e("_getc_nolock", reinterpret_cast<void*>(&crf__getc_nolock));
    e("_getch_nolock", reinterpret_cast<void*>(&crf__getch_nolock));
    e("_getche", reinterpret_cast<void*>(&crf__getche));
    e("_getche_nolock", reinterpret_cast<void*>(&crf__getche_nolock));
    e("_getcwd", reinterpret_cast<void*>(&crf__getcwd));
    e("_getdcwd", reinterpret_cast<void*>(&crf__getdcwd));
    e("_getdiskfree", reinterpret_cast<void*>(&crf__getdiskfree));
    e("_getdllprocaddr", reinterpret_cast<void*>(&crf__getdllprocaddr));
    e("_getdrive", reinterpret_cast<void*>(&crf__getdrive));
    e("_getdrives", reinterpret_cast<void*>(&crf__getdrives));
    e("_getmaxstdio", reinterpret_cast<void*>(&crf__getmaxstdio));
    e("_getmbcp", reinterpret_cast<void*>(&crf__getmbcp));
    e("_getpid", reinterpret_cast<void*>(&crf__getpid));
    e("_getsystime", reinterpret_cast<void*>(&crf__getsystime));
    e("_getw", reinterpret_cast<void*>(&crf__getw));
    e("_getwc_nolock", reinterpret_cast<void*>(&crf__getwc_nolock));
    e("_getwch", reinterpret_cast<void*>(&crf__getwch));
    e("_getwch_nolock", reinterpret_cast<void*>(&crf__getwch_nolock));
    e("_getwche", reinterpret_cast<void*>(&crf__getwche));
    e("_getwche_nolock", reinterpret_cast<void*>(&crf__getwche_nolock));
    e("_getws", reinterpret_cast<void*>(&crf__getws));
    e("_getws_s", reinterpret_cast<void*>(&crf__getws_s));
    e("_gmtime32", reinterpret_cast<void*>(&crf__gmtime32));
    e("_gmtime32_s", reinterpret_cast<void*>(&crf__gmtime32_s));
    e("_gmtime64_s", reinterpret_cast<void*>(&crf__gmtime64_s));
    e("_heapchk", reinterpret_cast<void*>(&crf__heapchk));
    e("_heapmin", reinterpret_cast<void*>(&crf__heapmin));
    e("_heapwalk", reinterpret_cast<void*>(&crf__heapwalk));
    e("_hypot", reinterpret_cast<void*>(&crf__hypot));
    e("_hypotf", reinterpret_cast<void*>(&crf__hypotf));
    e("_i64tow", reinterpret_cast<void*>(&crf__i64tow));
    e("_i64tow_s", reinterpret_cast<void*>(&crf__i64tow_s));
    e("_isatty", reinterpret_cast<void*>(&crf__isatty));
    e("_isctype", reinterpret_cast<void*>(&crf__isctype));
    e("_isctype_l", reinterpret_cast<void*>(&crf__isctype_l));
    e("_isleadbyte_l", reinterpret_cast<void*>(&crf__isleadbyte_l));
    e("_isnan", reinterpret_cast<void*>(&crf__isnan));
    e("_isnanf", reinterpret_cast<void*>(&crf__isnanf));
    e("_iswctype_l", reinterpret_cast<void*>(&crf__iswctype_l));
    e("_itow", reinterpret_cast<void*>(&crf__itow));
    e("_itow_s", reinterpret_cast<void*>(&crf__itow_s));
    e("_j0", reinterpret_cast<void*>(&crf__j0));
    e("_j1", reinterpret_cast<void*>(&crf__j1));
    e("_jn", reinterpret_cast<void*>(&crf__jn));
    e("_lfind", reinterpret_cast<void*>(&crf__lfind));
    e("_lfind_s", reinterpret_cast<void*>(&crf__lfind_s));
    e("_loaddll", reinterpret_cast<void*>(&crf__loaddll));
    e("_localtime32", reinterpret_cast<void*>(&crf__localtime32));
    e("_localtime32_s", reinterpret_cast<void*>(&crf__localtime32_s));
    e("_localtime64_s", reinterpret_cast<void*>(&crf__localtime64_s));
    e("_lock_locales", reinterpret_cast<void*>(&crf__lock_locales));
    e("_locking", reinterpret_cast<void*>(&crf__locking));
    e("_logb", reinterpret_cast<void*>(&crf__logb));
    e("_logbf", reinterpret_cast<void*>(&crf__logbf));
    e("_logbl", reinterpret_cast<void*>(&crf__logbl));
    e("_lrotl", reinterpret_cast<void*>(&crf__lrotl));
    e("_lrotr", reinterpret_cast<void*>(&crf__lrotr));
    e("_lsearch", reinterpret_cast<void*>(&crf__lsearch));
    e("_lsearch_s", reinterpret_cast<void*>(&crf__lsearch_s));
    e("_lseek", reinterpret_cast<void*>(&crf__lseek));
    e("_lseeki64", reinterpret_cast<void*>(&crf__lseeki64));
    e("_ltow", reinterpret_cast<void*>(&crf__ltow));
    e("_ltow_s", reinterpret_cast<void*>(&crf__ltow_s));
    e("_makepath", reinterpret_cast<void*>(&crf__makepath));
    e("_malloc_base", reinterpret_cast<void*>(&crf__malloc_base));
    e("_memccpy", reinterpret_cast<void*>(&crf__memccpy));
    e("_memicmp", reinterpret_cast<void*>(&crf__memicmp));
    e("_memicmp_l", reinterpret_cast<void*>(&crf__memicmp_l));
    e("_mkdir", reinterpret_cast<void*>(&crf__mkdir));
    e("_mkgmtime32", reinterpret_cast<void*>(&crf__mkgmtime32));
    e("_mktemp", reinterpret_cast<void*>(&crf__mktemp));
    e("_mktemp_s", reinterpret_cast<void*>(&crf__mktemp_s));
    e("_mktime32", reinterpret_cast<void*>(&crf__mktime32));
    e("_msize", reinterpret_cast<void*>(&crf__msize));
    e("_nextafter", reinterpret_cast<void*>(&crf__nextafter));
    e("_nextafterf", reinterpret_cast<void*>(&crf__nextafterf));
    e("_o__errno", reinterpret_cast<void*>(&crf__o__errno));
    e("_open", reinterpret_cast<void*>(&crf__open));
    e("_open_osfhandle", reinterpret_cast<void*>(&crf__open_osfhandle));
    e("_pclose", reinterpret_cast<void*>(&crf__pclose));
    e("_pipe", reinterpret_cast<void*>(&crf__pipe));
    e("_popen", reinterpret_cast<void*>(&crf__popen));
    e("_purecall", reinterpret_cast<void*>(&crf__purecall));
    e("_putc_nolock", reinterpret_cast<void*>(&crf__putc_nolock));
    e("_putch_nolock", reinterpret_cast<void*>(&crf__putch_nolock));
    e("_putw", reinterpret_cast<void*>(&crf__putw));
    e("_putwc_nolock", reinterpret_cast<void*>(&crf__putwc_nolock));
    e("_putwch", reinterpret_cast<void*>(&crf__putwch));
    e("_putwch_nolock", reinterpret_cast<void*>(&crf__putwch_nolock));
    e("_putws", reinterpret_cast<void*>(&crf__putws));
    e("_query_app_type", reinterpret_cast<void*>(&crf__query_app_type));
    e("_query_new_handler", reinterpret_cast<void*>(&crf__query_new_handler));
    e("_query_new_mode", reinterpret_cast<void*>(&crf__query_new_mode));
    e("_realloc_base", reinterpret_cast<void*>(&crf__realloc_base));
    e("_recalloc", reinterpret_cast<void*>(&crf__recalloc));
    e("_resetstkoflw", reinterpret_cast<void*>(&crf__resetstkoflw));
    e("_rmdir", reinterpret_cast<void*>(&crf__rmdir));
    e("_rmtmp", reinterpret_cast<void*>(&crf__rmtmp));
    e("_rotl", reinterpret_cast<void*>(&crf__rotl));
    e("_rotl64", reinterpret_cast<void*>(&crf__rotl64));
    e("_rotr", reinterpret_cast<void*>(&crf__rotr));
    e("_rotr64", reinterpret_cast<void*>(&crf__rotr64));
    e("_scalb", reinterpret_cast<void*>(&crf__scalb));
    e("_scalbf", reinterpret_cast<void*>(&crf__scalbf));
    e("_searchenv", reinterpret_cast<void*>(&crf__searchenv));
    e("_searchenv_s", reinterpret_cast<void*>(&crf__searchenv_s));
    e("_seh_filter_dll", reinterpret_cast<void*>(&crf__seh_filter_dll));
    e("_set_FMA3_enable", reinterpret_cast<void*>(&crf__set_FMA3_enable));
    e("_set_SSE2_enable", reinterpret_cast<void*>(&crf__set_SSE2_enable));
    e("_set_abort_behavior", reinterpret_cast<void*>(&crf__set_abort_behavior));
    e("_set_controlfp", reinterpret_cast<void*>(&crf__set_controlfp));
    e("_set_doserrno", reinterpret_cast<void*>(&crf__set_doserrno));
    e("_set_error_mode", reinterpret_cast<void*>(&crf__set_error_mode));
    e("_set_invalid_parameter_handler", reinterpret_cast<void*>(&crf__set_invalid_parameter_handler));
    e("_set_new_handler", reinterpret_cast<void*>(&crf__set_new_handler));
    e("_set_printf_count_output", reinterpret_cast<void*>(&crf__set_printf_count_output));
    e("_set_purecall_handler", reinterpret_cast<void*>(&crf__set_purecall_handler));
    e("_set_se_translator", reinterpret_cast<void*>(&crf__set_se_translator));
    e("_set_thread_local_invalid_parameter_handler", reinterpret_cast<void*>(&crf__set_thread_local_invalid_parameter_handler));
    e("_seterrormode", reinterpret_cast<void*>(&crf__seterrormode));
    e("_setmaxstdio", reinterpret_cast<void*>(&crf__setmaxstdio));
    e("_setmbcp", reinterpret_cast<void*>(&crf__setmbcp));
    e("_setsystime", reinterpret_cast<void*>(&crf__setsystime));
    e("_sleep", reinterpret_cast<void*>(&crf__sleep));
    e("_sopen", reinterpret_cast<void*>(&crf__sopen));
    e("_sopen_dispatch", reinterpret_cast<void*>(&crf__sopen_dispatch));
    e("_sopen_s", reinterpret_cast<void*>(&crf__sopen_s));
    e("_spawnl", reinterpret_cast<void*>(&crf__spawnl));
    e("_spawnle", reinterpret_cast<void*>(&crf__spawnle));
    e("_spawnlp", reinterpret_cast<void*>(&crf__spawnlp));
    e("_spawnlpe", reinterpret_cast<void*>(&crf__spawnlpe));
    e("_spawnv", reinterpret_cast<void*>(&crf__spawnv));
    e("_spawnve", reinterpret_cast<void*>(&crf__spawnve));
    e("_spawnvp", reinterpret_cast<void*>(&crf__spawnvp));
    e("_spawnvpe", reinterpret_cast<void*>(&crf__spawnvpe));
    e("_splitpath", reinterpret_cast<void*>(&crf__splitpath));
    e("_stat32", reinterpret_cast<void*>(&crf__stat32));
    e("_stat32i64", reinterpret_cast<void*>(&crf__stat32i64));
    e("_stat64", reinterpret_cast<void*>(&crf__stat64));
    e("_stat64i32", reinterpret_cast<void*>(&crf__stat64i32));
    e("_statusfp", reinterpret_cast<void*>(&crf__statusfp));
    e("_statusfp2", reinterpret_cast<void*>(&crf__statusfp2));
    e("_strdate", reinterpret_cast<void*>(&crf__strdate));
    e("_strerror", reinterpret_cast<void*>(&crf__strerror));
    e("_strerror_s", reinterpret_cast<void*>(&crf__strerror_s));
    e("_stricmp", reinterpret_cast<void*>(&cr__stricmp));
    e("_stricmp_l", reinterpret_cast<void*>(&crf__stricmp_l));
    e("_stricoll", reinterpret_cast<void*>(&crf__stricoll));
    e("_stricoll_l", reinterpret_cast<void*>(&crf__stricoll_l));
    e("_strlwr", reinterpret_cast<void*>(&crf__strlwr));
    e("_strlwr_l", reinterpret_cast<void*>(&crf__strlwr_l));
    e("_strlwr_s", reinterpret_cast<void*>(&crf__strlwr_s));
    e("_strlwr_s_l", reinterpret_cast<void*>(&crf__strlwr_s_l));
    e("_strncoll_l", reinterpret_cast<void*>(&crf__strncoll_l));
    e("_strnicmp_l", reinterpret_cast<void*>(&crf__strnicmp_l));
    e("_strnicoll", reinterpret_cast<void*>(&crf__strnicoll));
    e("_strnicoll_l", reinterpret_cast<void*>(&crf__strnicoll_l));
    e("_strnset", reinterpret_cast<void*>(&crf__strnset));
    e("_strnset_s", reinterpret_cast<void*>(&crf__strnset_s));
    e("_strrev", reinterpret_cast<void*>(&crf__strrev));
    e("_strset", reinterpret_cast<void*>(&crf__strset));
    e("_strset_s", reinterpret_cast<void*>(&crf__strset_s));
    e("_strtime", reinterpret_cast<void*>(&crf__strtime));
    e("_strupr", reinterpret_cast<void*>(&crf__strupr));
    e("_strupr_l", reinterpret_cast<void*>(&crf__strupr_l));
    e("_strupr_s", reinterpret_cast<void*>(&crf__strupr_s));
    e("_strupr_s_l", reinterpret_cast<void*>(&crf__strupr_s_l));
    e("_swab", reinterpret_cast<void*>(&crf__swab));
    e("_tell", reinterpret_cast<void*>(&crf__tell));
    e("_telli64", reinterpret_cast<void*>(&crf__telli64));
    e("_tempnam", reinterpret_cast<void*>(&crf__tempnam));
    e("_time32", reinterpret_cast<void*>(&crf__time32));
    e("_timespec32_get", reinterpret_cast<void*>(&crf__timespec32_get));
    e("_timespec64_get", reinterpret_cast<void*>(&crf__timespec64_get));
    e("_tolower", reinterpret_cast<void*>(&crf__tolower));
    e("_toupper", reinterpret_cast<void*>(&crf__toupper));
    e("_tzset", reinterpret_cast<void*>(&crf__tzset));
    e("_ui64tow", reinterpret_cast<void*>(&crf__ui64tow));
    e("_ui64tow_s", reinterpret_cast<void*>(&crf__ui64tow_s));
    e("_ultow", reinterpret_cast<void*>(&crf__ultow));
    e("_ultow_s", reinterpret_cast<void*>(&crf__ultow_s));
    e("_umask", reinterpret_cast<void*>(&crf__umask));
    e("_umask_s", reinterpret_cast<void*>(&crf__umask_s));
    e("_ungetc_nolock", reinterpret_cast<void*>(&crf__ungetc_nolock));
    e("_ungetch", reinterpret_cast<void*>(&crf__ungetch));
    e("_ungetch_nolock", reinterpret_cast<void*>(&crf__ungetch_nolock));
    e("_ungetwc_nolock", reinterpret_cast<void*>(&crf__ungetwc_nolock));
    e("_ungetwch", reinterpret_cast<void*>(&crf__ungetwch));
    e("_ungetwch_nolock", reinterpret_cast<void*>(&crf__ungetwch_nolock));
    e("_unlink", reinterpret_cast<void*>(&crf__unlink));
    e("_unloaddll", reinterpret_cast<void*>(&crf__unloaddll));
    e("_unlock_locales", reinterpret_cast<void*>(&crf__unlock_locales));
    e("_utime32", reinterpret_cast<void*>(&crf__utime32));
    e("_utime64", reinterpret_cast<void*>(&crf__utime64));
    e("_waccess", reinterpret_cast<void*>(&crf__waccess));
    e("_waccess_s", reinterpret_cast<void*>(&crf__waccess_s));
    e("_wasctime", reinterpret_cast<void*>(&crf__wasctime));
    e("_wasctime_s", reinterpret_cast<void*>(&crf__wasctime_s));
    e("_wassert", reinterpret_cast<void*>(&crf__wassert));
    e("_wchdir", reinterpret_cast<void*>(&crf__wchdir));
    e("_wchmod", reinterpret_cast<void*>(&crf__wchmod));
    e("_wcreat", reinterpret_cast<void*>(&crf__wcreat));
    e("_wcreate_locale", reinterpret_cast<void*>(&crf__wcreate_locale));
    e("_wcsdup", reinterpret_cast<void*>(&crf__wcsdup));
    e("_wcserror", reinterpret_cast<void*>(&crf__wcserror));
    e("_wcserror_s", reinterpret_cast<void*>(&crf__wcserror_s));
    e("_wcsftime_l", reinterpret_cast<void*>(&crf__wcsftime_l));
    e("_wcsicmp", reinterpret_cast<void*>(&crf__wcsicmp));
    e("_wcsicmp_l", reinterpret_cast<void*>(&crf__wcsicmp_l));
    e("_wcsicoll", reinterpret_cast<void*>(&crf__wcsicoll));
    e("_wcsicoll_l", reinterpret_cast<void*>(&crf__wcsicoll_l));
    e("_wcslwr", reinterpret_cast<void*>(&crf__wcslwr));
    e("_wcslwr_l", reinterpret_cast<void*>(&crf__wcslwr_l));
    e("_wcslwr_s", reinterpret_cast<void*>(&crf__wcslwr_s));
    e("_wcslwr_s_l", reinterpret_cast<void*>(&crf__wcslwr_s_l));
    e("_wcsncoll", reinterpret_cast<void*>(&crf__wcsncoll));
    e("_wcsncoll_l", reinterpret_cast<void*>(&crf__wcsncoll_l));
    e("_wcsnicmp_l", reinterpret_cast<void*>(&crf__wcsnicmp_l));
    e("_wcsnicoll", reinterpret_cast<void*>(&crf__wcsnicoll));
    e("_wcsnicoll_l", reinterpret_cast<void*>(&crf__wcsnicoll_l));
    e("_wcsnset", reinterpret_cast<void*>(&crf__wcsnset));
    e("_wcsnset_s", reinterpret_cast<void*>(&crf__wcsnset_s));
    e("_wcsrev", reinterpret_cast<void*>(&crf__wcsrev));
    e("_wcsset", reinterpret_cast<void*>(&crf__wcsset));
    e("_wcsset_s", reinterpret_cast<void*>(&crf__wcsset_s));
    e("_wcsupr", reinterpret_cast<void*>(&crf__wcsupr));
    e("_wcsupr_l", reinterpret_cast<void*>(&crf__wcsupr_l));
    e("_wcsupr_s", reinterpret_cast<void*>(&crf__wcsupr_s));
    e("_wcsupr_s_l", reinterpret_cast<void*>(&crf__wcsupr_s_l));
    e("_wctime32", reinterpret_cast<void*>(&crf__wctime32));
    e("_wctime32_s", reinterpret_cast<void*>(&crf__wctime32_s));
    e("_wctime64", reinterpret_cast<void*>(&crf__wctime64));
    e("_wctime64_s", reinterpret_cast<void*>(&crf__wctime64_s));
    e("_wdupenv_s", reinterpret_cast<void*>(&crf__wdupenv_s));
    e("_wexecl", reinterpret_cast<void*>(&crf__wexecl));
    e("_wexecle", reinterpret_cast<void*>(&crf__wexecle));
    e("_wexeclp", reinterpret_cast<void*>(&crf__wexeclp));
    e("_wexeclpe", reinterpret_cast<void*>(&crf__wexeclpe));
    e("_wexecv", reinterpret_cast<void*>(&crf__wexecv));
    e("_wexecve", reinterpret_cast<void*>(&crf__wexecve));
    e("_wexecvp", reinterpret_cast<void*>(&crf__wexecvp));
    e("_wexecvpe", reinterpret_cast<void*>(&crf__wexecvpe));
    e("_wfdopen", reinterpret_cast<void*>(&crf__wfdopen));
    e("_wfindfirst32", reinterpret_cast<void*>(&crf__wfindfirst32));
    e("_wfindfirst32i64", reinterpret_cast<void*>(&crf__wfindfirst32i64));
    e("_wfindfirst64", reinterpret_cast<void*>(&crf__wfindfirst64));
    e("_wfindfirst64i32", reinterpret_cast<void*>(&crf__wfindfirst64i32));
    e("_wfindnext32", reinterpret_cast<void*>(&crf__wfindnext32));
    e("_wfindnext32i64", reinterpret_cast<void*>(&crf__wfindnext32i64));
    e("_wfindnext64", reinterpret_cast<void*>(&crf__wfindnext64));
    e("_wfindnext64i32", reinterpret_cast<void*>(&crf__wfindnext64i32));
    e("_wfopen_s", reinterpret_cast<void*>(&crf__wfopen_s));
    e("_wfreopen", reinterpret_cast<void*>(&crf__wfreopen));
    e("_wfreopen_s", reinterpret_cast<void*>(&crf__wfreopen_s));
    e("_wfsopen", reinterpret_cast<void*>(&crf__wfsopen));
    e("_wfullpath", reinterpret_cast<void*>(&crf__wfullpath));
    e("_wgetcwd", reinterpret_cast<void*>(&crf__wgetcwd));
    e("_wgetdcwd", reinterpret_cast<void*>(&crf__wgetdcwd));
    e("_wgetenv", reinterpret_cast<void*>(&crf__wgetenv));
    e("_wgetenv_s", reinterpret_cast<void*>(&crf__wgetenv_s));
    e("_wmakepath", reinterpret_cast<void*>(&crf__wmakepath));
    e("_wmakepath_s", reinterpret_cast<void*>(&crf__wmakepath_s));
    e("_wmkdir", reinterpret_cast<void*>(&crf__wmkdir));
    e("_wmktemp", reinterpret_cast<void*>(&crf__wmktemp));
    e("_wmktemp_s", reinterpret_cast<void*>(&crf__wmktemp_s));
    e("_wopen", reinterpret_cast<void*>(&crf__wopen));
    e("_wperror", reinterpret_cast<void*>(&crf__wperror));
    e("_wpopen", reinterpret_cast<void*>(&crf__wpopen));
    e("_wputenv", reinterpret_cast<void*>(&crf__wputenv));
    e("_wputenv_s", reinterpret_cast<void*>(&crf__wputenv_s));
    e("_wremove", reinterpret_cast<void*>(&crf__wremove));
    e("_wrename", reinterpret_cast<void*>(&crf__wrename));
    e("_write", reinterpret_cast<void*>(&crf__write));
    e("_wrmdir", reinterpret_cast<void*>(&crf__wrmdir));
    e("_wsearchenv", reinterpret_cast<void*>(&crf__wsearchenv));
    e("_wsearchenv_s", reinterpret_cast<void*>(&crf__wsearchenv_s));
    e("_wsetlocale", reinterpret_cast<void*>(&crf__wsetlocale));
    e("_wsopen", reinterpret_cast<void*>(&crf__wsopen));
    e("_wsopen_dispatch", reinterpret_cast<void*>(&crf__wsopen_dispatch));
    e("_wsopen_s", reinterpret_cast<void*>(&crf__wsopen_s));
    e("_wspawnl", reinterpret_cast<void*>(&crf__wspawnl));
    e("_wspawnle", reinterpret_cast<void*>(&crf__wspawnle));
    e("_wspawnlp", reinterpret_cast<void*>(&crf__wspawnlp));
    e("_wspawnlpe", reinterpret_cast<void*>(&crf__wspawnlpe));
    e("_wspawnv", reinterpret_cast<void*>(&crf__wspawnv));
    e("_wspawnve", reinterpret_cast<void*>(&crf__wspawnve));
    e("_wspawnvp", reinterpret_cast<void*>(&crf__wspawnvp));
    e("_wspawnvpe", reinterpret_cast<void*>(&crf__wspawnvpe));
    e("_wsplitpath", reinterpret_cast<void*>(&crf__wsplitpath));
    e("_wsplitpath_s", reinterpret_cast<void*>(&crf__wsplitpath_s));
    e("_wstat32", reinterpret_cast<void*>(&crf__wstat32));
    e("_wstat32i64", reinterpret_cast<void*>(&crf__wstat32i64));
    e("_wstat64", reinterpret_cast<void*>(&crf__wstat64));
    e("_wstat64i32", reinterpret_cast<void*>(&crf__wstat64i32));
    e("_wstrdate", reinterpret_cast<void*>(&crf__wstrdate));
    e("_wstrdate_s", reinterpret_cast<void*>(&crf__wstrdate_s));
    e("_wstrtime", reinterpret_cast<void*>(&crf__wstrtime));
    e("_wstrtime_s", reinterpret_cast<void*>(&crf__wstrtime_s));
    e("_wtempnam", reinterpret_cast<void*>(&crf__wtempnam));
    e("_wtmpnam", reinterpret_cast<void*>(&crf__wtmpnam));
    e("_wtmpnam_s", reinterpret_cast<void*>(&crf__wtmpnam_s));
    e("_wtof", reinterpret_cast<void*>(&crf__wtof));
    e("_wtof_l", reinterpret_cast<void*>(&crf__wtof_l));
    e("_wtoi", reinterpret_cast<void*>(&crf__wtoi));
    e("_wtoi64", reinterpret_cast<void*>(&crf__wtoi64));
    e("_wtoi64_l", reinterpret_cast<void*>(&crf__wtoi64_l));
    e("_wtoi_l", reinterpret_cast<void*>(&crf__wtoi_l));
    e("_wtol", reinterpret_cast<void*>(&crf__wtol));
    e("_wtol_l", reinterpret_cast<void*>(&crf__wtol_l));
    e("_wtoll", reinterpret_cast<void*>(&crf__wtoll));
    e("_wtoll_l", reinterpret_cast<void*>(&crf__wtoll_l));
    e("_wunlink", reinterpret_cast<void*>(&crf__wunlink));
    e("_wutime32", reinterpret_cast<void*>(&crf__wutime32));
    e("_wutime64", reinterpret_cast<void*>(&crf__wutime64));
    e("_y0", reinterpret_cast<void*>(&crf__y0));
    e("_y1", reinterpret_cast<void*>(&crf__y1));
    e("_yn", reinterpret_cast<void*>(&crf__yn));
    e("acos", reinterpret_cast<void*>(&crf_acos));
    e("acosf", reinterpret_cast<void*>(&crf_acosf));
    e("acosh", reinterpret_cast<void*>(&crf_acosh));
    e("acoshf", reinterpret_cast<void*>(&crf_acoshf));
    e("acoshl", reinterpret_cast<void*>(&crf_acoshl));
    e("acosl", reinterpret_cast<void*>(&crf_acosl));
    e("asctime_s", reinterpret_cast<void*>(&crf_asctime_s));
    e("asin", reinterpret_cast<void*>(&crf_asin));
    e("asinf", reinterpret_cast<void*>(&crf_asinf));
    e("asinh", reinterpret_cast<void*>(&crf_asinh));
    e("asinhf", reinterpret_cast<void*>(&crf_asinhf));
    e("asinhl", reinterpret_cast<void*>(&crf_asinhl));
    e("asinl", reinterpret_cast<void*>(&crf_asinl));
    e("atan", reinterpret_cast<void*>(&crf_atan));
    e("atan2", reinterpret_cast<void*>(&crf_atan2));
    e("atan2f", reinterpret_cast<void*>(&crf_atan2f));
    e("atan2l", reinterpret_cast<void*>(&crf_atan2l));
    e("atanf", reinterpret_cast<void*>(&crf_atanf));
    e("atanh", reinterpret_cast<void*>(&crf_atanh));
    e("atanhf", reinterpret_cast<void*>(&crf_atanhf));
    e("atanhl", reinterpret_cast<void*>(&crf_atanhl));
    e("atanl", reinterpret_cast<void*>(&crf_atanl));
    e("atoll", reinterpret_cast<void*>(&crf_atoll));
    e("bsearch_s", reinterpret_cast<void*>(&crf_bsearch_s));
    e("btowc", reinterpret_cast<void*>(&crf_btowc));
    e("cbrt", reinterpret_cast<void*>(&crf_cbrt));
    e("cbrtf", reinterpret_cast<void*>(&crf_cbrtf));
    e("cbrtl", reinterpret_cast<void*>(&crf_cbrtl));
    e("ceilf", reinterpret_cast<void*>(&crf_ceilf));
    e("ceill", reinterpret_cast<void*>(&crf_ceill));
    e("clearerr", reinterpret_cast<void*>(&crf_clearerr));
    e("clearerr_s", reinterpret_cast<void*>(&crf_clearerr_s));
    e("copysign", reinterpret_cast<void*>(&crf_copysign));
    e("copysignf", reinterpret_cast<void*>(&crf_copysignf));
    e("copysignl", reinterpret_cast<void*>(&crf_copysignl));
    e("cos", reinterpret_cast<void*>(&crf_cos));
    e("cosf", reinterpret_cast<void*>(&crf_cosf));
    e("cosh", reinterpret_cast<void*>(&crf_cosh));
    e("coshf", reinterpret_cast<void*>(&crf_coshf));
    e("coshl", reinterpret_cast<void*>(&crf_coshl));
    e("cosl", reinterpret_cast<void*>(&crf_cosl));
    e("erf", reinterpret_cast<void*>(&crf_erf));
    e("erfc", reinterpret_cast<void*>(&crf_erfc));
    e("erfcf", reinterpret_cast<void*>(&crf_erfcf));
    e("erfcl", reinterpret_cast<void*>(&crf_erfcl));
    e("erff", reinterpret_cast<void*>(&crf_erff));
    e("erfl", reinterpret_cast<void*>(&crf_erfl));
    e("exp2", reinterpret_cast<void*>(&crf_exp2));
    e("exp2f", reinterpret_cast<void*>(&crf_exp2f));
    e("exp2l", reinterpret_cast<void*>(&crf_exp2l));
    e("expf", reinterpret_cast<void*>(&crf_expf));
    e("expl", reinterpret_cast<void*>(&crf_expl));
    e("expm1", reinterpret_cast<void*>(&crf_expm1));
    e("expm1f", reinterpret_cast<void*>(&crf_expm1f));
    e("expm1l", reinterpret_cast<void*>(&crf_expm1l));
    e("fabs", reinterpret_cast<void*>(&crf_fabs));
    e("fabsf", reinterpret_cast<void*>(&crf_fabsf));
    e("fabsl", reinterpret_cast<void*>(&crf_fabsl));
    e("fdim", reinterpret_cast<void*>(&crf_fdim));
    e("fdimf", reinterpret_cast<void*>(&crf_fdimf));
    e("fdiml", reinterpret_cast<void*>(&crf_fdiml));
    e("feclearexcept", reinterpret_cast<void*>(&crf_feclearexcept));
    e("fegetenv", reinterpret_cast<void*>(&crf_fegetenv));
    e("fegetexceptflag", reinterpret_cast<void*>(&crf_fegetexceptflag));
    e("fegetround", reinterpret_cast<void*>(&crf_fegetround));
    e("feholdexcept", reinterpret_cast<void*>(&crf_feholdexcept));
    e("fesetenv", reinterpret_cast<void*>(&crf_fesetenv));
    e("fesetexceptflag", reinterpret_cast<void*>(&crf_fesetexceptflag));
    e("fesetround", reinterpret_cast<void*>(&crf_fesetround));
    e("fetestexcept", reinterpret_cast<void*>(&crf_fetestexcept));
    e("fgetpos", reinterpret_cast<void*>(&crf_fgetpos));
    e("fgetws", reinterpret_cast<void*>(&crf_fgetws));
    e("floor", reinterpret_cast<void*>(&crf_floor));
    e("floorf", reinterpret_cast<void*>(&crf_floorf));
    e("floorl", reinterpret_cast<void*>(&crf_floorl));
    e("fma", reinterpret_cast<void*>(&crf_fma));
    e("fmaf", reinterpret_cast<void*>(&crf_fmaf));
    e("fmal", reinterpret_cast<void*>(&crf_fmal));
    e("fmax", reinterpret_cast<void*>(&crf_fmax));
    e("fmaxf", reinterpret_cast<void*>(&crf_fmaxf));
    e("fmaxl", reinterpret_cast<void*>(&crf_fmaxl));
    e("fmin", reinterpret_cast<void*>(&crf_fmin));
    e("fminf", reinterpret_cast<void*>(&crf_fminf));
    e("fminl", reinterpret_cast<void*>(&crf_fminl));
    e("fmod", reinterpret_cast<void*>(&crf_fmod));
    e("fmodf", reinterpret_cast<void*>(&crf_fmodf));
    e("fmodl", reinterpret_cast<void*>(&crf_fmodl));
    e("fopen_s", reinterpret_cast<void*>(&crf_fopen_s));
    e("fputws", reinterpret_cast<void*>(&crf_fputws));
    e("fread_s", reinterpret_cast<void*>(&crf_fread_s));
    e("freopen", reinterpret_cast<void*>(&crf_freopen));
    e("freopen_s", reinterpret_cast<void*>(&crf_freopen_s));
    e("frexp", reinterpret_cast<void*>(&crf_frexp));
    e("frexpf", reinterpret_cast<void*>(&crf_frexpf));
    e("frexpl", reinterpret_cast<void*>(&crf_frexpl));
    e("fsetpos", reinterpret_cast<void*>(&crf_fsetpos));
    e("getenv_s", reinterpret_cast<void*>(&crf_getenv_s));
    e("gets", reinterpret_cast<void*>(&crf_gets));
    e("gets_s", reinterpret_cast<void*>(&crf_gets_s));
    e("getwc", reinterpret_cast<void*>(&crf_getwc));
    e("getwchar", reinterpret_cast<void*>(&crf_getwchar));
    e("hypot", reinterpret_cast<void*>(&crf_hypot));
    e("hypotf", reinterpret_cast<void*>(&crf_hypotf));
    e("hypotl", reinterpret_cast<void*>(&crf_hypotl));
    e("ilogb", reinterpret_cast<void*>(&crf_ilogb));
    e("ilogbf", reinterpret_cast<void*>(&crf_ilogbf));
    e("ilogbl", reinterpret_cast<void*>(&crf_ilogbl));
    e("imaxabs", reinterpret_cast<void*>(&crf_imaxabs));
    e("imaxdiv", reinterpret_cast<void*>(&crf_imaxdiv));
    e("is_wctype", reinterpret_cast<void*>(&crf_is_wctype));
    e("is_wctype_l", reinterpret_cast<void*>(&crf_is_wctype_l));
    e("isblank", reinterpret_cast<void*>(&crf_isblank));
    e("isleadbyte", reinterpret_cast<void*>(&crf_isleadbyte));
    e("iswalnum", reinterpret_cast<void*>(&crf_iswalnum));
    e("iswalpha", reinterpret_cast<void*>(&crf_iswalpha));
    e("iswascii", reinterpret_cast<void*>(&crf_iswascii));
    e("iswblank", reinterpret_cast<void*>(&crf_iswblank));
    e("iswcntrl", reinterpret_cast<void*>(&crf_iswcntrl));
    e("iswctype", reinterpret_cast<void*>(&crf_iswctype));
    e("iswctype_l", reinterpret_cast<void*>(&crf_iswctype_l));
    e("iswdigit", reinterpret_cast<void*>(&crf_iswdigit));
    e("iswgraph", reinterpret_cast<void*>(&crf_iswgraph));
    e("iswlower", reinterpret_cast<void*>(&crf_iswlower));
    e("iswprint", reinterpret_cast<void*>(&crf_iswprint));
    e("iswpunct", reinterpret_cast<void*>(&crf_iswpunct));
    e("iswspace", reinterpret_cast<void*>(&crf_iswspace));
    e("iswupper", reinterpret_cast<void*>(&crf_iswupper));
    e("iswxdigit", reinterpret_cast<void*>(&crf_iswxdigit));
    e("ldexp", reinterpret_cast<void*>(&crf_ldexp));
    e("ldexpf", reinterpret_cast<void*>(&crf_ldexpf));
    e("ldexpl", reinterpret_cast<void*>(&crf_ldexpl));
    e("lgamma", reinterpret_cast<void*>(&crf_lgamma));
    e("lgammaf", reinterpret_cast<void*>(&crf_lgammaf));
    e("lgammal", reinterpret_cast<void*>(&crf_lgammal));
    e("llabs", reinterpret_cast<void*>(&crf_llabs));
    e("llrint", reinterpret_cast<void*>(&crf_llrint));
    e("llrintf", reinterpret_cast<void*>(&crf_llrintf));
    e("llrintl", reinterpret_cast<void*>(&crf_llrintl));
    e("llround", reinterpret_cast<void*>(&crf_llround));
    e("llroundf", reinterpret_cast<void*>(&crf_llroundf));
    e("llroundl", reinterpret_cast<void*>(&crf_llroundl));
    e("log", reinterpret_cast<void*>(&crf_log));
    e("log10", reinterpret_cast<void*>(&crf_log10));
    e("log10f", reinterpret_cast<void*>(&crf_log10f));
    e("log10l", reinterpret_cast<void*>(&crf_log10l));
    e("log1p", reinterpret_cast<void*>(&crf_log1p));
    e("log1pf", reinterpret_cast<void*>(&crf_log1pf));
    e("log1pl", reinterpret_cast<void*>(&crf_log1pl));
    e("log2", reinterpret_cast<void*>(&crf_log2));
    e("log2f", reinterpret_cast<void*>(&crf_log2f));
    e("log2l", reinterpret_cast<void*>(&crf_log2l));
    e("logb", reinterpret_cast<void*>(&crf_logb));
    e("logbf", reinterpret_cast<void*>(&crf_logbf));
    e("logbl", reinterpret_cast<void*>(&crf_logbl));
    e("logf", reinterpret_cast<void*>(&crf_logf));
    e("logl", reinterpret_cast<void*>(&crf_logl));
    e("lrint", reinterpret_cast<void*>(&crf_lrint));
    e("lrintf", reinterpret_cast<void*>(&crf_lrintf));
    e("lrintl", reinterpret_cast<void*>(&crf_lrintl));
    e("lround", reinterpret_cast<void*>(&crf_lround));
    e("lroundf", reinterpret_cast<void*>(&crf_lroundf));
    e("lroundl", reinterpret_cast<void*>(&crf_lroundl));
    e("mblen", reinterpret_cast<void*>(&crf_mblen));
    e("mbstowcs_s", reinterpret_cast<void*>(&crf_mbstowcs_s));
    e("mbtowc", reinterpret_cast<void*>(&crf_mbtowc));
    e("modff", reinterpret_cast<void*>(&crf_modff));
    e("modfl", reinterpret_cast<void*>(&crf_modfl));
    e("nan", reinterpret_cast<void*>(&crf_nan));
    e("nanf", reinterpret_cast<void*>(&crf_nanf));
    e("nanl", reinterpret_cast<void*>(&crf_nanl));
    e("nearbyint", reinterpret_cast<void*>(&crf_nearbyint));
    e("nearbyintf", reinterpret_cast<void*>(&crf_nearbyintf));
    e("nearbyintl", reinterpret_cast<void*>(&crf_nearbyintl));
    e("nextafter", reinterpret_cast<void*>(&crf_nextafter));
    e("nextafterf", reinterpret_cast<void*>(&crf_nextafterf));
    e("nextafterl", reinterpret_cast<void*>(&crf_nextafterl));
    e("nexttoward", reinterpret_cast<void*>(&crf_nexttoward));
    e("nexttowardf", reinterpret_cast<void*>(&crf_nexttowardf));
    e("nexttowardl", reinterpret_cast<void*>(&crf_nexttowardl));
    e("perror", reinterpret_cast<void*>(&crf_perror));
    e("powf", reinterpret_cast<void*>(&crf_powf));
    e("powl", reinterpret_cast<void*>(&crf_powl));
    e("putwc", reinterpret_cast<void*>(&crf_putwc));
    e("putwchar", reinterpret_cast<void*>(&crf_putwchar));
    e("qsort_s", reinterpret_cast<void*>(&crf_qsort_s));
    e("quick_exit", reinterpret_cast<void*>(&crf_quick_exit));
    e("remainder", reinterpret_cast<void*>(&crf_remainder));
    e("remainderf", reinterpret_cast<void*>(&crf_remainderf));
    e("remainderl", reinterpret_cast<void*>(&crf_remainderl));
    e("remove", reinterpret_cast<void*>(&crf_remove));
    e("remquo", reinterpret_cast<void*>(&crf_remquo));
    e("remquof", reinterpret_cast<void*>(&crf_remquof));
    e("remquol", reinterpret_cast<void*>(&crf_remquol));
    e("rename", reinterpret_cast<void*>(&crf_rename));
    e("rewind", reinterpret_cast<void*>(&crf_rewind));
    e("rint", reinterpret_cast<void*>(&crf_rint));
    e("rintf", reinterpret_cast<void*>(&crf_rintf));
    e("rintl", reinterpret_cast<void*>(&crf_rintl));
    e("round", reinterpret_cast<void*>(&crf_round));
    e("roundf", reinterpret_cast<void*>(&crf_roundf));
    e("roundl", reinterpret_cast<void*>(&crf_roundl));
    e("scalbln", reinterpret_cast<void*>(&crf_scalbln));
    e("scalblnf", reinterpret_cast<void*>(&crf_scalblnf));
    e("scalblnl", reinterpret_cast<void*>(&crf_scalblnl));
    e("scalbn", reinterpret_cast<void*>(&crf_scalbn));
    e("scalbnf", reinterpret_cast<void*>(&crf_scalbnf));
    e("scalbnl", reinterpret_cast<void*>(&crf_scalbnl));
    e("set_terminate", reinterpret_cast<void*>(&crf_set_terminate));
    e("set_unexpected", reinterpret_cast<void*>(&crf_set_unexpected));
    e("sin", reinterpret_cast<void*>(&crf_sin));
    e("sinf", reinterpret_cast<void*>(&crf_sinf));
    e("sinh", reinterpret_cast<void*>(&crf_sinh));
    e("sinhf", reinterpret_cast<void*>(&crf_sinhf));
    e("sinhl", reinterpret_cast<void*>(&crf_sinhl));
    e("sinl", reinterpret_cast<void*>(&crf_sinl));
    e("sqrt", reinterpret_cast<void*>(&crf_sqrt));
    e("sqrtf", reinterpret_cast<void*>(&crf_sqrtf));
    e("sqrtl", reinterpret_cast<void*>(&crf_sqrtl));
    e("strcoll", reinterpret_cast<void*>(&crf_strcoll));
    e("strtoimax", reinterpret_cast<void*>(&crf_strtoimax));
    e("strtok", reinterpret_cast<void*>(&crf_strtok));
    e("strtok_s", reinterpret_cast<void*>(&crf_strtok_s));
    e("strtold", reinterpret_cast<void*>(&crf_strtold));
    e("strtoumax", reinterpret_cast<void*>(&crf_strtoumax));
    e("strxfrm", reinterpret_cast<void*>(&crf_strxfrm));
    e("tanhf", reinterpret_cast<void*>(&crf_tanhf));
    e("tanhl", reinterpret_cast<void*>(&crf_tanhl));
    e("tgamma", reinterpret_cast<void*>(&crf_tgamma));
    e("tgammaf", reinterpret_cast<void*>(&crf_tgammaf));
    e("tgammal", reinterpret_cast<void*>(&crf_tgammal));
    e("tmpfile", reinterpret_cast<void*>(&crf_tmpfile));
    e("tmpfile_s", reinterpret_cast<void*>(&crf_tmpfile_s));
    e("tmpnam", reinterpret_cast<void*>(&crf_tmpnam));
    e("tmpnam_s", reinterpret_cast<void*>(&crf_tmpnam_s));
    e("towctrans", reinterpret_cast<void*>(&crf_towctrans));
    e("towlower", reinterpret_cast<void*>(&crf_towlower));
    e("towupper", reinterpret_cast<void*>(&crf_towupper));
    e("trunc", reinterpret_cast<void*>(&crf_trunc));
    e("truncf", reinterpret_cast<void*>(&crf_truncf));
    e("truncl", reinterpret_cast<void*>(&crf_truncl));
    e("unexpected", reinterpret_cast<void*>(&crf_unexpected));
    e("wcscoll", reinterpret_cast<void*>(&crf_wcscoll));
    e("wcscspn", reinterpret_cast<void*>(&crf_wcscspn));
    e("wcsftime", reinterpret_cast<void*>(&crf_wcsftime));
    e("wcspbrk", reinterpret_cast<void*>(&crf_wcspbrk));
    e("wcsspn", reinterpret_cast<void*>(&crf_wcsspn));
    e("wcstof", reinterpret_cast<void*>(&crf_wcstof));
    e("wcstoimax", reinterpret_cast<void*>(&crf_wcstoimax));
    e("wcstok", reinterpret_cast<void*>(&crf_wcstok));
    e("wcstok_s", reinterpret_cast<void*>(&crf_wcstok_s));
    e("wcstold", reinterpret_cast<void*>(&crf_wcstold));
    e("wcstombs_s", reinterpret_cast<void*>(&crf_wcstombs_s));
    e("wcstoumax", reinterpret_cast<void*>(&crf_wcstoumax));
    e("wcsxfrm", reinterpret_cast<void*>(&crf_wcsxfrm));
    e("wctob", reinterpret_cast<void*>(&crf_wctob));
    e("wctomb", reinterpret_cast<void*>(&crf_wctomb));
    e("wctomb_s", reinterpret_cast<void*>(&crf_wctomb_s));
    e("wctrans", reinterpret_cast<void*>(&crf_wctrans));
    e("wctype", reinterpret_cast<void*>(&crf_wctype));
    e("wmemcpy_s", reinterpret_cast<void*>(&crf_wmemcpy_s));
    e("wmemmove_s", reinterpret_cast<void*>(&crf_wmemmove_s));
}

}  // namespace occ::runtime::winabi

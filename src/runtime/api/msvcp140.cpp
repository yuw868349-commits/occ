// The Microsoft C++ standard-library runtime, as a program that imports
// it by name sees it.
//
// A C++ binary links its stream objects and its allocation operators
// against `MSVCP140.dll`. The names it imports are the mangled ones the
// Microsoft ABI assigns: `?cout@std@@...` for the stream object, `??6@...`
// for each `operator<<`, `??2@...` for `operator new`. The mangled forms
// are stable across toolchain versions because the ABI they name is, so
// each entry below is the exact string a modern binary resolves.
//
// What this domain implements is the part of the standard library a
// packed or otherwise self-contained guest actually reaches for:
//
//  - the allocation operators, which are the real host heap;
//  - the three standard streams as data exports -- objects large enough
//    for the members a stream touches, so a guest that references
//    `std::cout` reads and writes its own object without faulting;
//  - the insertion operators for the types a `cout` chain names, each
//    rendering to the host's stdout;
//  - the manipulators `endl` and `flush`;
//  - the few `basic_ostream` and `basic_istream` methods a chain calls
//    through the vtable, which operate on the same objects.
//
// The stream objects here are deliberately dumb: their real
// implementation lives in the guest's own static initialization, and the
// calls this module answers are the ones a binary still resolves
// dynamically. The object's address is returned untouched so a chain
// keeps working, and the characters land where a stream should.

#include "occ/runtime/api.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>

namespace occ::runtime::winabi {

namespace {

// The stream objects a guest references by symbol. A real
// `basic_ostream` is a few pointers and a streambuf; a buffer this size
// is far past the members any call this runtime answers touches.
unsigned char g_msvcp_cout[64];
unsigned char g_msvcp_cin[64];
unsigned char g_msvcp_cerr[64];
unsigned char g_msvcp_wcout[64];
unsigned char g_msvcp_wcin[64];
unsigned char g_msvcp_wcerr[64];

// The insertion core: the object address is passed through untouched and
// the rendered text goes to stdout, which is where a standard stream
// writes on this runtime.
void* msvcp_render(void* ostream, const char* text, std::size_t len) noexcept {
    if (ostream == nullptr) {
        return ostream;
    }
    if (text != nullptr && len != 0) {
        std::fwrite(text, 1, len, stdout);
    }
    return ostream;
}

// The guest's `wchar_t` is sixteen bits, which is not the host's. A wide
// stream writes UTF-8 -- the one byte encoding the host side of stdout
// carries -- and the encoder below is this file's own, so no library call
// ever sees the guest's units as thirty-two-bit wide characters. The
// surrogate pair a run of units contains is assembled here, exactly as
// the wide CRT formatter assembles it.
void msvcp_write_utf8(const char16_t* text, std::size_t len) noexcept {
    std::size_t i = 0;
    while (i < len) {
        const std::uint32_t c = static_cast<std::uint32_t>(text[i]);
        if (c >= 0xD800u && c <= 0xDBFFu && i + 1 < len) {
            const std::uint32_t low =
                static_cast<std::uint32_t>(text[i + 1]);
            if (low >= 0xDC00u && low <= 0xDFFFu) {
                const std::uint32_t cp =
                    0x10000u + ((c - 0xD800u) << 10) + (low - 0xDC00u);
                const char bytes[4] = {
                    static_cast<char>(0xF0u | (cp >> 18)),
                    static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu)),
                    static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)),
                    static_cast<char>(0x80u | (cp & 0x3Fu))};
                std::fwrite(bytes, 1, 4, stdout);
                i += 2;
                continue;
            }
        }
        if (c < 0x80u) {
            const char b = static_cast<char>(c);
            std::fwrite(&b, 1, 1, stdout);
        } else if (c < 0x800u) {
            const char bytes[2] = {
                static_cast<char>(0xC0u | (c >> 6)),
                static_cast<char>(0x80u | (c & 0x3Fu))};
            std::fwrite(bytes, 1, 2, stdout);
        } else {
            const char bytes[3] = {
                static_cast<char>(0xE0u | (c >> 12)),
                static_cast<char>(0x80u | ((c >> 6) & 0x3Fu)),
                static_cast<char>(0x80u | (c & 0x3Fu))};
            std::fwrite(bytes, 1, 3, stdout);
        }
        ++i;
    }
}

// The read face of a stream. The guest's stdin is the host's stdin, the
// same object the CRT's `getchar` answers; a unit is the stream's own
// width -- one byte for the narrow streambuf, one byte widened for the
// wide one, which is what the C locale's stream decoding does. `peek`
// returns the next unit without consuming it.
std::int32_t msvcp_stdin_peek() noexcept {
    const int c = std::fgetc(stdin);
    if (c != EOF) {
        std::ungetc(c, stdin);
    }
    return c;
}

std::int32_t msvcp_stdin_next() noexcept {
    return std::fgetc(stdin);
}

// -------------------------------------------------------------------------
// The `basic_streambuf` face.
//
// A streambuf is the character source and sink behind a stream object.
// The methods below are the ones a binary still resolves dynamically:
// the direct `sgetc`/`snextc`/`sputc`/`sputn` calls and the protected
// virtuals a derived buffer overrides, whose base behavior this runtime
// answers honestly. Output lands on stdout; input comes from stdin; the
// bookkeeping members of a real buffer have no meaning on this runtime
// and are answered with the no-op that keeps the call site valid.
// -------------------------------------------------------------------------

// `sgetc`: the current input unit, without consuming it.
extern "C" __attribute__((ms_abi)) std::int32_t msvcp_sb_sgetc(
    void* sb) noexcept {
    (void)sb;
    return msvcp_stdin_peek();
}

// `snextc`: consume one unit, then return the following one, peeked.
extern "C" __attribute__((ms_abi)) std::int32_t msvcp_sb_snextc(
    void* sb) noexcept {
    (void)sb;
    if (msvcp_stdin_next() == EOF) {
        return EOF;
    }
    return msvcp_stdin_peek();
}

// `sbumpc`: consume and return one unit.
extern "C" __attribute__((ms_abi)) std::int32_t msvcp_sb_sbumpc(
    void* sb) noexcept {
    (void)sb;
    return msvcp_stdin_next();
}

// `sputc`: write one character, returning it.
extern "C" __attribute__((ms_abi)) std::int32_t msvcp_sb_sputc(
    void* sb, char c) noexcept {
    (void)sb;
    std::fputc(static_cast<unsigned char>(c), stdout);
    return static_cast<unsigned char>(c);
}

// `sputn`: write a run, returning how many were written -- all of them.
extern "C" __attribute__((ms_abi)) std::int64_t msvcp_sb_sputn(
    void* sb, const char* s, std::int64_t count) noexcept {
    (void)sb;
    if (s == nullptr || count <= 0) {
        return 0;
    }
    std::fwrite(s, 1, static_cast<std::size_t>(count), stdout);
    return count;
}

// `xsgetn`: the buffered read a derived buffer calls through to. Reads
// what the input offers, ending at the stream's end.
extern "C" __attribute__((ms_abi)) std::int64_t msvcp_sb_xsgetn(
    void* sb, char* dst, std::int64_t count) noexcept {
    (void)sb;
    if (dst == nullptr || count <= 0) {
        return 0;
    }
    std::int64_t got = 0;
    while (got < count) {
        const int c = msvcp_stdin_next();
        if (c == EOF) {
            break;
        }
        dst[got++] = static_cast<char>(c);
    }
    return got;
}

// `xsputn`: the buffered write a derived buffer calls through to.
extern "C" __attribute__((ms_abi)) std::int64_t msvcp_sb_xsputn(
    void* sb, const char* s, std::int64_t count) noexcept {
    (void)sb;
    if (s == nullptr || count <= 0) {
        return 0;
    }
    std::fwrite(s, 1, static_cast<std::size_t>(count), stdout);
    return count;
}

// `uflow`: the unbuffered read -- consume and return one unit.
extern "C" __attribute__((ms_abi)) std::int32_t msvcp_sb_uflow(
    void* sb) noexcept {
    (void)sb;
    return msvcp_stdin_next();
}

// `showmanyc`: the count of units known to be available. A buffer with
// no internal storage answers zero, which is what this runtime's
// streams are.
extern "C" __attribute__((ms_abi)) std::int64_t msvcp_sb_showmanyc(
    void* sb) noexcept {
    (void)sb;
    return 0;
}

// `setbuf`: install a buffer. This runtime's streams do not buffer;
// the call is accepted and the buffer itself is returned.
extern "C" __attribute__((ms_abi)) void* msvcp_sb_setbuf(
    void* sb, char* buffer, std::int64_t size) noexcept {
    (void)buffer;
    (void)size;
    return sb;
}

// `sync`: bring the buffer in line with its device -- the flush side.
extern "C" __attribute__((ms_abi)) std::int32_t msvcp_sb_sync(
    void* sb) noexcept {
    (void)sb;
    std::fflush(stdout);
    return 0;
}

// `imbue`: a locale change; the C locale this runtime presents needs
// nothing done.
extern "C" __attribute__((ms_abi)) void msvcp_sb_imbue(
    void* sb, const void* locale) noexcept {
    (void)sb;
    (void)locale;
}

// `_Lock` / `_Unlock`: the buffer's internal mutex. This runtime is
// single-threaded per stream; the pair is a no-op.
extern "C" __attribute__((ms_abi)) void msvcp_sb_lock(
    void* sb) noexcept {
    (void)sb;
}

extern "C" __attribute__((ms_abi)) void msvcp_sb_unlock(
    void* sb) noexcept {
    (void)sb;
}

// The constructors and destructors a derived buffer's initialization
// chain reaches. The object lives in guest memory; there is nothing to
// build or tear down on this side.
extern "C" __attribute__((ms_abi)) void msvcp_sb_ctor(
    void* sb) noexcept {
    (void)sb;
}

extern "C" __attribute__((ms_abi)) void msvcp_sb_dtor(
    void* sb) noexcept {
    (void)sb;
}

// -------------------------------------------------------------------------
// The `basic_ios` face: the state and the character widening a stream
// carries. State on this runtime is always good -- a stream either
// writes to stdout or reads stdin, neither of which fails -- and widen
// is the identity the C locale gives.
// -------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) void msvcp_ios_ctor(
    void* ios) noexcept {
    (void)ios;
}

extern "C" __attribute__((ms_abi)) void msvcp_ios_dtor(
    void* ios) noexcept {
    (void)ios;
}

extern "C" __attribute__((ms_abi)) void msvcp_ios_setstate(
    void* ios, std::int32_t state, bool rdbuf_set) noexcept {
    (void)ios;
    (void)state;
    (void)rdbuf_set;
}

extern "C" __attribute__((ms_abi)) char msvcp_ios_widen_narrow(
    void* ios, char c) noexcept {
    (void)ios;
    return c;
}

extern "C" __attribute__((ms_abi)) char16_t msvcp_ios_widen_wide(
    void* ios, char c) noexcept {
    (void)ios;
    return static_cast<char16_t>(static_cast<unsigned char>(c));
}

// -------------------------------------------------------------------------
// The `basic_ostream` face: construction, the flush teardown, and the
// manipulator insertions that call through a function pointer.
// -------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) void msvcp_ostream_ctor(
    void* ostream, void* streambuf, bool owns_buffer) noexcept {
    (void)ostream;
    (void)streambuf;
    (void)owns_buffer;
}

extern "C" __attribute__((ms_abi)) void msvcp_ostream_dtor(
    void* ostream) noexcept {
    if (ostream != nullptr) {
        std::fflush(stdout);
    }
}

// `_Osfx`: the flush and state-clear a stream performs at the end of a
// chain of insertions.
extern "C" __attribute__((ms_abi)) void msvcp_ostream_osfx(
    void* ostream) noexcept {
    if (ostream != nullptr) {
        std::fflush(stdout);
    }
}

// `operator<<(ostream&(*)(ostream&))`: a manipulator such as `endl` or
// `flush`, invoked on the stream itself.
extern "C" __attribute__((ms_abi)) void* msvcp_ostream_op_fn(
    void* ostream, void* fn) noexcept {
    if (fn != nullptr) {
        using Manip = void* (*)(void*);
        auto* call = reinterpret_cast<Manip>(fn);
        call(ostream);
    }
    return ostream;
}

// `operator<<(ios_base&(*)(ios_base&))`: the same, for a manipulator
// typed against the base class.
extern "C" __attribute__((ms_abi)) void* msvcp_ostream_op_iosfn(
    void* ostream, void* fn) noexcept {
    return msvcp_ostream_op_fn(ostream, fn);
}

// `operator<<(ostream&, unsigned __int64)`
extern "C" __attribute__((ms_abi)) void* msvcp_ostream_ull(
    void* ostream, std::uint64_t value) noexcept {
    char buf[32];
    const int n = std::snprintf(buf, sizeof(buf), "%llu",
                                static_cast<unsigned long long>(value));
    return msvcp_render(ostream, buf, static_cast<std::size_t>(n < 0 ? 0 : n));
}

// The wide face of the same families: the units are sixteen bits, the
// input is one byte widened, and the output leaves as UTF-8.
extern "C" __attribute__((ms_abi)) std::int32_t msvcp_wb_sgetc(
    void* sb) noexcept {
    (void)sb;
    return msvcp_stdin_peek();
}

extern "C" __attribute__((ms_abi)) std::int32_t msvcp_wb_snextc(
    void* sb) noexcept {
    (void)sb;
    if (msvcp_stdin_next() == EOF) {
        return EOF;
    }
    return msvcp_stdin_peek();
}

extern "C" __attribute__((ms_abi)) std::int32_t msvcp_wb_sbumpc(
    void* sb) noexcept {
    (void)sb;
    return msvcp_stdin_next();
}

extern "C" __attribute__((ms_abi)) std::int32_t msvcp_wb_sputc(
    void* sb, char16_t c) noexcept {
    (void)sb;
    msvcp_write_utf8(&c, 1);
    return static_cast<std::int32_t>(c);
}

extern "C" __attribute__((ms_abi)) std::int64_t msvcp_wb_sputn(
    void* sb, const char16_t* s, std::int64_t count) noexcept {
    (void)sb;
    if (s == nullptr || count <= 0) {
        return 0;
    }
    msvcp_write_utf8(s, static_cast<std::size_t>(count));
    return count;
}

extern "C" __attribute__((ms_abi)) std::int64_t msvcp_wb_xsgetn(
    void* sb, char16_t* dst, std::int64_t count) noexcept {
    (void)sb;
    if (dst == nullptr || count <= 0) {
        return 0;
    }
    std::int64_t got = 0;
    while (got < count) {
        const int c = msvcp_stdin_next();
        if (c == EOF) {
            break;
        }
        dst[got++] = static_cast<char16_t>(static_cast<unsigned char>(c));
    }
    return got;
}

extern "C" __attribute__((ms_abi)) std::int64_t msvcp_wb_xsputn(
    void* sb, const char16_t* s, std::int64_t count) noexcept {
    (void)sb;
    if (s == nullptr || count <= 0) {
        return 0;
    }
    msvcp_write_utf8(s, static_cast<std::size_t>(count));
    return count;
}

extern "C" __attribute__((ms_abi)) std::int32_t msvcp_wb_uflow(
    void* sb) noexcept {
    (void)sb;
    return msvcp_stdin_next();
}

extern "C" __attribute__((ms_abi)) std::int64_t msvcp_wb_showmanyc(
    void* sb) noexcept {
    (void)sb;
    return 0;
}

extern "C" __attribute__((ms_abi)) void* msvcp_wb_setbuf(
    void* sb, char16_t* buffer, std::int64_t size) noexcept {
    (void)buffer;
    (void)size;
    return sb;
}

extern "C" __attribute__((ms_abi)) std::int32_t msvcp_wb_sync(
    void* sb) noexcept {
    (void)sb;
    std::fflush(stdout);
    return 0;
}

extern "C" __attribute__((ms_abi)) void msvcp_wb_imbue(
    void* sb, const void* locale) noexcept {
    (void)sb;
    (void)locale;
}

extern "C" __attribute__((ms_abi)) void msvcp_wb_lock(
    void* sb) noexcept {
    (void)sb;
}

extern "C" __attribute__((ms_abi)) void msvcp_wb_unlock(
    void* sb) noexcept {
    (void)sb;
}

extern "C" __attribute__((ms_abi)) void msvcp_wb_ctor(
    void* sb) noexcept {
    (void)sb;
}

extern "C" __attribute__((ms_abi)) void msvcp_wb_dtor(
    void* sb) noexcept {
    (void)sb;
}

extern "C" __attribute__((ms_abi)) void msvcp_wios_ctor(
    void* ios) noexcept {
    (void)ios;
}

extern "C" __attribute__((ms_abi)) void msvcp_wios_dtor(
    void* ios) noexcept {
    (void)ios;
}

extern "C" __attribute__((ms_abi)) void msvcp_wios_setstate(
    void* ios, std::int32_t state, bool rdbuf_set) noexcept {
    (void)ios;
    (void)state;
    (void)rdbuf_set;
}

extern "C" __attribute__((ms_abi)) void msvcp_wostream_ctor(
    void* ostream, void* streambuf, bool owns_buffer) noexcept {
    (void)ostream;
    (void)streambuf;
    (void)owns_buffer;
}

extern "C" __attribute__((ms_abi)) void msvcp_wostream_dtor(
    void* ostream) noexcept {
    if (ostream != nullptr) {
        std::fflush(stdout);
    }
}

extern "C" __attribute__((ms_abi)) void msvcp_wostream_osfx(
    void* ostream) noexcept {
    if (ostream != nullptr) {
        std::fflush(stdout);
    }
}

extern "C" __attribute__((ms_abi)) void* msvcp_wostream_op_fn(
    void* ostream, void* fn) noexcept {
    return msvcp_ostream_op_fn(ostream, fn);
}

extern "C" __attribute__((ms_abi)) void* msvcp_wostream_op_iosfn(
    void* ostream, void* fn) noexcept {
    return msvcp_ostream_op_fn(ostream, fn);
}

extern "C" __attribute__((ms_abi)) void* msvcp_wostream_ull(
    void* ostream, std::uint64_t value) noexcept {
    return msvcp_ostream_ull(ostream, value);
}

// `ios_base::good`: the stream is in a good state, which every stream
// this runtime hands out is -- writes go to stdout and reads to stdin,
// neither of which fails.
extern "C" __attribute__((ms_abi)) bool msvcp_iosbase_good(
    void* ios) noexcept {
    (void)ios;
    return true;
}

// `basic_istream::_Ipfx`: the prefix of an extraction -- the state check
// and, unless skipped, the leading-whitespace discard. The state is good
// and the whitespace discard is what the read itself would skip anyway,
// so the extraction is admitted.
extern "C" __attribute__((ms_abi)) bool msvcp_istream_ipfx(
    void* istream, bool noskipws) noexcept {
    (void)istream;
    (void)noskipws;
    return true;
}

// `std::_Xlength_error`: the length-violation throw. A guest that asks
// for more than a container holds reaches this; the runtime presents no
// exception handler for it, and the termination that follows is the one
// the real library performs when nothing catches the throw.
extern "C" __attribute__((ms_abi)) void msvcp_xlength_error(
    const char* what) noexcept {
    std::fprintf(stderr, "terminate: %s\n", what == nullptr ? "" : what);
    ::abort();
}

// `std::uncaught_exception`: whether an exception is being propagated.
// The runtime never has one in flight while a guest API runs.
extern "C" __attribute__((ms_abi)) bool msvcp_uncaught_exception() noexcept {
    return false;
}

}  // namespace

extern "C" __attribute__((ms_abi)) void* msvcp_operator_new(
    std::size_t size) noexcept {
    return std::malloc(size == 0 ? 1 : size);
}

extern "C" __attribute__((ms_abi)) void* msvcp_operator_new_array(
    std::size_t size) noexcept {
    return std::malloc(size == 0 ? 1 : size);
}

extern "C" __attribute__((ms_abi)) void msvcp_operator_delete(
    void* p) noexcept {
    std::free(p);
}

extern "C" __attribute__((ms_abi)) void msvcp_operator_delete_array(
    void* p) noexcept {
    std::free(p);
}

// `operator<<(ostream&, const char*)`
extern "C" __attribute__((ms_abi)) void* msvcp_ostream_char_ptr(
    void* ostream, const char* s) noexcept {
    if (s == nullptr) {
        return ostream;
    }
    std::size_t len = 0;
    while (s[len] != '\0') {
        ++len;
    }
    return msvcp_render(ostream, s, len);
}

// `operator<<(ostream&, char)`
extern "C" __attribute__((ms_abi)) void* msvcp_ostream_char(
    void* ostream, char c) noexcept {
    return msvcp_render(ostream, &c, 1);
}

// The numeric insertions. Each formats the value the way an ostream
// insertion does -- the decimal spelling, signed where the type is --
// into a small buffer and renders it.
extern "C" __attribute__((ms_abi)) void* msvcp_ostream_int(
    void* ostream, std::int32_t value) noexcept {
    char buf[24];
    const int n = std::snprintf(buf, sizeof(buf), "%d", value);
    return msvcp_render(ostream, buf, static_cast<std::size_t>(n < 0 ? 0 : n));
}

extern "C" __attribute__((ms_abi)) void* msvcp_ostream_uint(
    void* ostream, std::uint32_t value) noexcept {
    char buf[24];
    const int n = std::snprintf(buf, sizeof(buf), "%u", value);
    return msvcp_render(ostream, buf, static_cast<std::size_t>(n < 0 ? 0 : n));
}

extern "C" __attribute__((ms_abi)) void* msvcp_ostream_long(
    void* ostream, std::int64_t value) noexcept {
    char buf[32];
    const int n = std::snprintf(buf, sizeof(buf), "%lld",
                                static_cast<long long>(value));
    return msvcp_render(ostream, buf, static_cast<std::size_t>(n < 0 ? 0 : n));
}

extern "C" __attribute__((ms_abi)) void* msvcp_ostream_ulong(
    void* ostream, std::uint64_t value) noexcept {
    char buf[32];
    const int n = std::snprintf(buf, sizeof(buf), "%llu",
                                static_cast<unsigned long long>(value));
    return msvcp_render(ostream, buf, static_cast<std::size_t>(n < 0 ? 0 : n));
}

extern "C" __attribute__((ms_abi)) void* msvcp_ostream_double(
    void* ostream, double value) noexcept {
    char buf[48];
    const int n = std::snprintf(buf, sizeof(buf), "%g", value);
    return msvcp_render(ostream, buf, static_cast<std::size_t>(n < 0 ? 0 : n));
}

// `std::endl(ostream&)`: the newline and the flush.
extern "C" __attribute__((ms_abi)) void* msvcp_endl(void* ostream) noexcept {
    const char nl = '\n';
    return msvcp_render(ostream, &nl, 1);
}

// `std::flush(ostream&)`
extern "C" __attribute__((ms_abi)) void* msvcp_flush(void* ostream) noexcept {
    if (ostream != nullptr) {
        std::fflush(stdout);
    }
    return ostream;
}

// The stream methods a chain calls through the vtable. `put` renders one
// character; `write` renders a run; `flush` flushes; the read methods
// answer the end-of-input condition, which is the honest state of a
// stream nothing has fed.
extern "C" __attribute__((ms_abi)) void* msvcp_ostream_put(
    void* ostream, char c) noexcept {
    return msvcp_render(ostream, &c, 1);
}

extern "C" __attribute__((ms_abi)) void* msvcp_ostream_write(
    void* ostream, const char* s, std::int64_t count) noexcept {
    if (s == nullptr || count <= 0) {
        return ostream;
    }
    return msvcp_render(ostream, s, static_cast<std::size_t>(count));
}

extern "C" __attribute__((ms_abi)) void* msvcp_ostream_flush(
    void* ostream) noexcept {
    if (ostream != nullptr) {
        std::fflush(stdout);
    }
    return ostream;
}

extern "C" __attribute__((ms_abi)) std::int32_t msvcp_istream_get(
    void* istream) noexcept {
    (void)istream;
    return -1;  // EOF: the stream carries no input.
}

extern "C" __attribute__((ms_abi)) void* msvcp_istream_read(
    void* istream, char* buffer, std::int64_t count) noexcept {
    (void)istream;
    (void)buffer;
    (void)count;
    return istream;
}

// -------------------------------------------------------------------------
// The registration
// -------------------------------------------------------------------------

void add_msvcp140(ExportList& out) {
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
    // The allocation operators.
    e("??2@YAPEAX_K@Z", reinterpret_cast<void*>(&msvcp_operator_new));
    e("??_U@YAPEAX_K@Z", reinterpret_cast<void*>(&msvcp_operator_new_array));
    e("??3@YAXPEAX@Z", reinterpret_cast<void*>(&msvcp_operator_delete));
    e("??_V@YAXPEAX@Z", reinterpret_cast<void*>(&msvcp_operator_delete_array));
    // The standard streams, as data exports. The address handed out is
    // the object itself; a guest that references `std::cout` reads and
    // writes this buffer, and the insertion calls below operate on it.
    e("?cout@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@std@@A",
      &g_msvcp_cout);
    e("?cin@std@@3V?$basic_istream@DU?$char_traits@D@std@@@std@@A",
      &g_msvcp_cin);
    e("?cerr@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@std@@A",
      &g_msvcp_cerr);
    e("?wcout@std@@3V?$basic_ostream@_WU?$char_traits@_W@std@@@std@@A",
      &g_msvcp_wcout);
    e("?wcin@std@@3V?$basic_istream@_WU?$char_traits@_W@std@@@std@@A",
      &g_msvcp_wcin);
    e("?wcerr@std@@3V?$basic_ostream@_WU?$char_traits@_W@std@@@std@@A",
      &g_msvcp_wcerr);
    // The insertions.
    e("??6@YAAEAV?$basic_ostream@DU?$char_traits@D@std@@@std@@AEAV01@PEBD@Z",
      reinterpret_cast<void*>(&msvcp_ostream_char_ptr));
    e("??6@YAAEAV?$basic_ostream@DU?$char_traits@D@std@@@std@@AEAV01@D@Z",
      reinterpret_cast<void*>(&msvcp_ostream_char));
    e("??6@YAAEAV?$basic_ostream@DU?$char_traits@D@std@@@std@@AEAV01@H@Z",
      reinterpret_cast<void*>(&msvcp_ostream_int));
    e("??6@YAAEAV?$basic_ostream@DU?$char_traits@D@std@@@std@@AEAV01@I@Z",
      reinterpret_cast<void*>(&msvcp_ostream_uint));
    e("??6@YAAEAV?$basic_ostream@DU?$char_traits@D@std@@@std@@AEAV01@J@Z",
      reinterpret_cast<void*>(&msvcp_ostream_long));
    e("??6@YAAEAV?$basic_ostream@DU?$char_traits@D@std@@@std@@AEAV01@K@Z",
      reinterpret_cast<void*>(&msvcp_ostream_ulong));
    e("??6@YAAEAV?$basic_ostream@DU?$char_traits@D@std@@@std@@AEAV01@N@Z",
      reinterpret_cast<void*>(&msvcp_ostream_double));
    e("??6@YAAEAV?$basic_ostream@DU?$char_traits@D@std@@@std@@AEAV01@M@Z",
      reinterpret_cast<void*>(&msvcp_ostream_double));
    // The manipulators.
    e("?endl@std@@YAAEAV?$basic_ostream@DU?$char_traits@D@std@@@std@@AEAV12@@Z",
      reinterpret_cast<void*>(&msvcp_endl));
    e("?flush@std@@YAAEAV?$basic_ostream@DU?$char_traits@D@std@@@std@@AEAV12@@Z",
      reinterpret_cast<void*>(&msvcp_flush));
    // The stream methods.
    e("?put@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@D@Z",
      reinterpret_cast<void*>(&msvcp_ostream_put));
    e("?write@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@PEBD_J@Z",
      reinterpret_cast<void*>(&msvcp_ostream_write));
    e("?flush@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@XZ",
      reinterpret_cast<void*>(&msvcp_ostream_flush));
    e("?get@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA_HD@Z",
      reinterpret_cast<void*>(&msvcp_istream_get));
    e("?read@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@PEAD_J@Z",
      reinterpret_cast<void*>(&msvcp_istream_read));
    // The streambuf face: the direct calls a binary resolves and the
    // protected virtuals a derived buffer reaches through to.
    e("?sgetc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHXZ",
      reinterpret_cast<void*>(&msvcp_sb_sgetc));
    e("?snextc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHXZ",
      reinterpret_cast<void*>(&msvcp_sb_snextc));
    e("?sbumpc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHXZ",
      reinterpret_cast<void*>(&msvcp_sb_sbumpc));
    e("?sputc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHD@Z",
      reinterpret_cast<void*>(&msvcp_sb_sputc));
    e("?sputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA_JPEBD_J@Z",
      reinterpret_cast<void*>(&msvcp_sb_sputn));
    e("?xsgetn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_JPEAD_J@Z",
      reinterpret_cast<void*>(&msvcp_sb_xsgetn));
    e("?xsputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_JPEBD_J@Z",
      reinterpret_cast<void*>(&msvcp_sb_xsputn));
    e("?uflow@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHXZ",
      reinterpret_cast<void*>(&msvcp_sb_uflow));
    e("?showmanyc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_JXZ",
      reinterpret_cast<void*>(&msvcp_sb_showmanyc));
    e("?setbuf@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAPEAV12@PEAD_J@Z",
      reinterpret_cast<void*>(&msvcp_sb_setbuf));
    e("?sync@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHXZ",
      reinterpret_cast<void*>(&msvcp_sb_sync));
    e("?imbue@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAXAEBVlocale@2@@Z",
      reinterpret_cast<void*>(&msvcp_sb_imbue));
    e("?_Lock@?$basic_streambuf@DU?$char_traits@D@std@@@std@@UEAAXXZ",
      reinterpret_cast<void*>(&msvcp_sb_lock));
    e("?_Unlock@?$basic_streambuf@DU?$char_traits@D@std@@@std@@UEAAXXZ",
      reinterpret_cast<void*>(&msvcp_sb_unlock));
    e("??0?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAA@XZ",
      reinterpret_cast<void*>(&msvcp_sb_ctor));
    e("??1?$basic_streambuf@DU?$char_traits@D@std@@@std@@UEAA@XZ",
      reinterpret_cast<void*>(&msvcp_sb_dtor));
    // The ios face.
    e("?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXH_N@Z",
      reinterpret_cast<void*>(&msvcp_ios_setstate));
    e("?widen@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBADD@Z",
      reinterpret_cast<void*>(&msvcp_ios_widen_narrow));
    e("??0?$basic_ios@DU?$char_traits@D@std@@@std@@IEAA@XZ",
      reinterpret_cast<void*>(&msvcp_ios_ctor));
    e("??1?$basic_ios@DU?$char_traits@D@std@@@std@@UEAA@XZ",
      reinterpret_cast<void*>(&msvcp_ios_dtor));
    // The ostream face: construction, teardown, and the insertions that
    // take a function pointer or a sixty-four-bit integer.
    e("??0?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAA@PEAV?$basic_streambuf@DU?$char_traits@D@std@@@1@_N@Z",
      reinterpret_cast<void*>(&msvcp_ostream_ctor));
    e("??1?$basic_ostream@DU?$char_traits@D@std@@@std@@UEAA@XZ",
      reinterpret_cast<void*>(&msvcp_ostream_dtor));
    e("?_Osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAXXZ",
      reinterpret_cast<void*>(&msvcp_ostream_osfx));
    e("??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@P6AAEAV01@AEAV01@@Z@Z",
      reinterpret_cast<void*>(&msvcp_ostream_op_fn));
    e("??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@P6AAEAVios_base@1@AEAV21@@Z@Z",
      reinterpret_cast<void*>(&msvcp_ostream_op_iosfn));
    e("??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@_K@Z",
      reinterpret_cast<void*>(&msvcp_ostream_ull));
    // The member-typed insertions and the state methods a chain resolves.
    e("??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@K@Z",
      reinterpret_cast<void*>(&msvcp_ostream_ulong));
    e("?good@ios_base@std@@QEBA_NXZ",
      reinterpret_cast<void*>(&msvcp_iosbase_good));
    e("?_Ipfx@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA_N_N@Z",
      reinterpret_cast<void*>(&msvcp_istream_ipfx));
    e("?_Xlength_error@std@@YAXPEBD@Z",
      reinterpret_cast<void*>(&msvcp_xlength_error));
    e("?uncaught_exception@std@@YA_NXZ",
      reinterpret_cast<void*>(&msvcp_uncaught_exception));
    // The stream objects as an older mangling names them: `@1@A` is the
    // class-scope reference the pre-2017 toolchains wrote, resolved to
    // the same buffers the modern spelling answers.
    e("?cout@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A",
      &g_msvcp_cout);
    e("?cin@std@@3V?$basic_istream@DU?$char_traits@D@std@@@1@A",
      &g_msvcp_cin);
    // The wide face of the same families: `_W` is the guest's wchar_t.
    e("?sgetc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAAHXZ",
      reinterpret_cast<void*>(&msvcp_wb_sgetc));
    e("?snextc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAAHXZ",
      reinterpret_cast<void*>(&msvcp_wb_snextc));
    e("?sbumpc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAAHXZ",
      reinterpret_cast<void*>(&msvcp_wb_sbumpc));
    e("?sputc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAAH_W@Z",
      reinterpret_cast<void*>(&msvcp_wb_sputc));
    e("?sputn@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAA_JPEB_W_J@Z",
      reinterpret_cast<void*>(&msvcp_wb_sputn));
    e("?xsgetn@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAA_JPEA_W_J@Z",
      reinterpret_cast<void*>(&msvcp_wb_xsgetn));
    e("?xsputn@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAA_JPEB_W_J@Z",
      reinterpret_cast<void*>(&msvcp_wb_xsputn));
    e("?uflow@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAAHXZ",
      reinterpret_cast<void*>(&msvcp_wb_uflow));
    e("?showmanyc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAA_JXZ",
      reinterpret_cast<void*>(&msvcp_wb_showmanyc));
    e("?setbuf@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAAPEAV12@PEA_W_J@Z",
      reinterpret_cast<void*>(&msvcp_wb_setbuf));
    e("?sync@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAAHXZ",
      reinterpret_cast<void*>(&msvcp_wb_sync));
    e("?imbue@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAAXAEBVlocale@2@@Z",
      reinterpret_cast<void*>(&msvcp_wb_imbue));
    e("?_Lock@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@UEAAXXZ",
      reinterpret_cast<void*>(&msvcp_wb_lock));
    e("?_Unlock@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@UEAAXXZ",
      reinterpret_cast<void*>(&msvcp_wb_unlock));
    e("??0?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAA@XZ",
      reinterpret_cast<void*>(&msvcp_wb_ctor));
    e("??1?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@UEAA@XZ",
      reinterpret_cast<void*>(&msvcp_wb_dtor));
    e("?setstate@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAXH_N@Z",
      reinterpret_cast<void*>(&msvcp_wios_setstate));
    e("??0?$basic_ios@_WU?$char_traits@_W@std@@@std@@IEAA@XZ",
      reinterpret_cast<void*>(&msvcp_wios_ctor));
    e("??1?$basic_ios@_WU?$char_traits@_W@std@@@std@@UEAA@XZ",
      reinterpret_cast<void*>(&msvcp_wios_dtor));
    e("??0?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAA@PEAV?$basic_streambuf@_WU?$char_traits@_W@std@@@1@_N@Z",
      reinterpret_cast<void*>(&msvcp_wostream_ctor));
    e("??1?$basic_ostream@_WU?$char_traits@_W@std@@@std@@UEAA@XZ",
      reinterpret_cast<void*>(&msvcp_wostream_dtor));
    e("?_Osfx@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAXXZ",
      reinterpret_cast<void*>(&msvcp_wostream_osfx));
    e("??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@P6AAEAV01@AEAV01@@Z@Z",
      reinterpret_cast<void*>(&msvcp_wostream_op_fn));
    e("??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@P6AAEAVios_base@1@AEAV21@@Z@Z",
      reinterpret_cast<void*>(&msvcp_wostream_op_iosfn));
    e("??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@_K@Z",
      reinterpret_cast<void*>(&msvcp_wostream_ull));
}

}  // namespace occ::runtime::winabi

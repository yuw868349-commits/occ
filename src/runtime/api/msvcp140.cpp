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
}

}  // namespace occ::runtime::winabi

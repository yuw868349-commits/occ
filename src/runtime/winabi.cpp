#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <utility>
#include <vector>

#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "occ/runtime/address_space.h"
#include "occ/runtime/mapper.h"
#include "occ/runtime/ntdll.h"

namespace occ::runtime::winabi {

namespace {

// --------------------------------------------------------------------------
// Guest execution state
// --------------------------------------------------------------------------

// One pointer, one thread, one guest. The runtime runs its guest to
// completion on the thread that called `run_pe_process`, so a thread-local
// is the whole of the dispatch: no handle, no lookup, no chance for a thunk
// to serve the wrong guest.
thread_local GuestState* g_guest = nullptr;

// The exit path the process layer installs. A terminate from inside an
// export -- `ExitProcess`, `exit`, `abort`, a fault the filter declined --
// has to leave through the jump that returns to `run_pe_process`, which only
// that layer can provide. Before it is installed the only honest exit is the
// process's own, and the code is narrowed the way an exit status is.
using TerminateFn = void(std::uint32_t) noexcept;
TerminateFn* g_terminate = nullptr;

void terminate(std::uint32_t code) noexcept {
    if (g_terminate != nullptr) {
        g_terminate(code);
        return;
    }
    ::_Exit(static_cast<int>(code & 0xFFu));
}

// --------------------------------------------------------------------------
// Guest-side constants
// --------------------------------------------------------------------------

// Offsets into the guest TEB, matching the layout `pe_process.cpp` writes.
// They are restated here rather than shared because the layout is the
// interface: both files write the same numbers, and a mismatch shows up as a
// guest reading the wrong last error rather than as a compile error. The
// comments name the field each one is.
constexpr std::uint64_t kTebLastError = 0x68;   // LastErrorValue
constexpr std::uint64_t kTebProcessId = 0x40;   // ClientId.UniqueProcess
constexpr std::uint64_t kTebThreadId = 0x48;    // ClientId.UniqueThread
constexpr std::uint64_t kTebTlsArray = 0x1480;  // TlsSlots, 64 entries

constexpr std::uint64_t kTlsSlotCount = 64;
constexpr std::uint32_t kTlsOutOfRange = 0xFFFFFFFFu;

// The standard handles. Fixed values the guest passes back to `WriteFile`,
// mapped to the host descriptors 0, 1 and 2 -- the mapping a console program
// actually observes.
constexpr std::uint64_t kStdInputHandle = 0x1001;
constexpr std::uint64_t kStdOutputHandle = 0x1002;
constexpr std::uint64_t kStdErrorHandle = 0x1003;
constexpr std::uint64_t kCurrentProcessHandle = 0xFFFFFFFFFFFFFFFFULL;

constexpr std::uint32_t kHeapZeroMemory = 0x00000008u;

// Win32 errors this layer reports, as Windows spells them.
constexpr std::uint32_t kErrorInvalidHandle = 6;
constexpr std::uint32_t kErrorNotSupported = 50;
constexpr std::uint32_t kErrorInsufficientBuffer = 122;
constexpr std::uint32_t kErrorNoMoreItems = 381;

// --------------------------------------------------------------------------
// TEB access
// --------------------------------------------------------------------------

void store_teb_u32(std::uint64_t offset, std::uint32_t value) noexcept {
    const GuestState* g = g_guest;
    if (g == nullptr || g->teb == 0) {
        return;
    }
    std::uint64_t address = g->teb + offset;
    __builtin_memcpy(reinterpret_cast<void*>(address), &value,
                     sizeof(value));
}

[[nodiscard]] std::uint32_t load_teb_u32(std::uint64_t offset) noexcept {
    const GuestState* g = g_guest;
    if (g == nullptr || g->teb == 0) {
        return 0;
    }
    std::uint64_t address = g->teb + offset;
    std::uint32_t value = 0;
    __builtin_memcpy(&value, reinterpret_cast<const void*>(address),
                     sizeof(value));
    return value;
}

void set_last_error(std::uint32_t error) noexcept {
    store_teb_u32(kTebLastError, error);
}

[[nodiscard]] std::uint32_t guest_thread_id() noexcept {
    return load_teb_u32(kTebThreadId);
}

// --------------------------------------------------------------------------
// The stdio translation
// --------------------------------------------------------------------------

// The iob table lives in the guest state, at an address the guest cannot
// distinguish from any other allocation. Each slot holds the host's own
// stream object pointer, so a guest that reads `_iob[1]`'s *contents* gets a
// valid `FILE*` directly, and a guest that uses `_iob[1]`'s *address* -- the
// way every `stdout` macro expands -- is recognised by the translation below.
void init_stdio(GuestState& state) noexcept {
    state.iob[0] = ::stdin;
    state.iob[1] = ::stdout;
    state.iob[2] = ::stderr;
    state.iob_base =
        reinterpret_cast<std::uint64_t>(state.iob);
}

// The stride of the guest's iob table. `stdout` in a guest expands to
// `(&__iob_func()[1])`, whose arithmetic steps by the MSVCRT `FILE` size --
// three pointers and five ints on this model, padded to 48 bytes -- and not
// by the host's `FILE`, which is a different structure the guest never
// sees. A stream address the guest passes is only ever handed to the
// printf family, so the stride is what the translation recognises, not a
// layout the guest could read.
constexpr std::uint64_t kGuestFileSlot = 48;

}  // namespace

std::FILE* translate_stream(const GuestState& state,
                            std::uint64_t stream) noexcept {
    if (state.iob_base == 0 || stream < state.iob_base) {
        return reinterpret_cast<std::FILE*>(stream);
    }
    const std::uint64_t offset = stream - state.iob_base;
    if (offset % kGuestFileSlot != 0) {
        return reinterpret_cast<std::FILE*>(stream);
    }
    const std::uint64_t index = offset / kGuestFileSlot;
    if (index >= 3) {
        return reinterpret_cast<std::FILE*>(stream);
    }
    return state.iob[index];
}

GuestState* guest_state() noexcept {
    return g_guest;
}

void set_guest_state(GuestState* state) noexcept {
    if (state != nullptr) {
        init_stdio(*state);
    }
    g_guest = state;
}

void install_terminate_path(TerminateFn* fn) noexcept {
    g_terminate = fn;
}

// --------------------------------------------------------------------------
// Paths and the command line
// --------------------------------------------------------------------------

std::string to_dos_path(std::string_view unix_path) {
    if (unix_path.empty() || unix_path.front() != '/') {
        return std::string(unix_path);
    }
    std::string out;
    out.reserve(unix_path.size() + 2);
    out += "Z:";
    for (const char c : unix_path) {
        out += (c == '/') ? '\\' : c;
    }
    return out;
}

std::string build_command_line(const std::string& program,
                               const std::vector<std::string>& args) {
    // An argument needs quoting when it is empty, contains whitespace, or
    // contains a quote -- the cases where the raw text would parse to
    // something else. Everything else goes through untouched, which is what
    // keeps `argv` looking like what was typed.
    const auto needs_quotes = [](std::string_view s) {
        if (s.empty()) {
            return true;
        }
        for (const char c : s) {
            if (c == ' ' || c == '\t' || c == '"') {
                return true;
            }
        }
        return false;
    };

    const auto append_one = [&needs_quotes](std::string& out,
                                            std::string_view s) {
        if (!needs_quotes(s)) {
            out += s;
            return;
        }
        out += '"';
        std::size_t backslashes = 0;
        for (const char c : s) {
            if (c == '\\') {
                ++backslashes;
                continue;
            }
            if (c == '"') {
                // `2n+1` backslashes then a quote: the quote is literal, so
                // it is escaped with one more backslash than the run had.
                out.append(backslashes * 2 + 1, '\\');
                out += '"';
                backslashes = 0;
                continue;
            }
            out.append(backslashes, '\\');
            backslashes = 0;
            out += c;
        }
        // Trailing backslashes sit in front of the closing quote and are
        // doubled, for the same reason the ones before a quote are.
        out.append(backslashes * 2, '\\');
        out += '"';
    };

    std::string out;
    append_one(out, program);
    for (const std::string& arg : args) {
        out += ' ';
        append_one(out, arg);
    }
    return out;
}

std::vector<std::string> split_command_line(std::string_view command_line) {
    std::vector<std::string> out;
    std::string current;
    bool in_quotes = false;
    // Whether the argument being accumulated exists. `current` alone cannot
    // answer that: `""` contributes no characters and yet is an argument,
    // and dropping it would shift every later index. A quote marks the
    // argument as existing whether or not anything lands inside it.
    bool arg_exists = false;
    std::size_t backslashes = 0;

    const auto flush = [&]() {
        out.push_back(current);
        current.clear();
        arg_exists = false;
    };

    for (const char c : command_line) {
        if (c == '\\') {
            // Backslashes are not decided until what follows them is known:
            // doubled before a quote they collapse, before anything else
            // they are themselves.
            ++backslashes;
            continue;
        }
        if (c == '"') {
            // A quote marks the argument as existing, whether it opens or
            // closes one: the `""` that ends a command line is an argument
            // the caller wrote, and quotes are the only way to write one.
            arg_exists = true;
            current.append(backslashes / 2, '\\');
            if ((backslashes % 2) != 0) {
                // An odd run escapes the quote: it is a character.
                current += '"';
            } else {
                in_quotes = !in_quotes;
            }
            backslashes = 0;
            continue;
        }
        current.append(backslashes, '\\');
        backslashes = 0;
        if (!in_quotes && (c == ' ' || c == '\t')) {
            // A separator ends an argument only when one exists: the
            // second space of a run separates nothing, and flushing here
            // would invent an argument the caller never wrote.
            if (!current.empty() || arg_exists) {
                flush();
            }
            continue;
        }
        current += c;
    }
    current.append(backslashes, '\\');
    // The final argument exists when it gathered characters, or when a
    // quote marked it -- the trailing `""` of `a b ""` is an argument the
    // guest asked for, and dropping it would shift every later index. A
    // line of pure whitespace gathers neither and produces none.
    if (!current.empty() || arg_exists) {
        flush();
    }
    return out;
}

// --------------------------------------------------------------------------
// Text conversion
// --------------------------------------------------------------------------

bool utf8_to_utf16(std::string_view text, std::u16string& out) noexcept {
    out.clear();
    const auto n = text.size();
    std::size_t i = 0;
    while (i < n) {
        const unsigned char lead = static_cast<unsigned char>(text[i]);
        if (lead < 0x80) {
            out.push_back(static_cast<char16_t>(lead));
            ++i;
            continue;
        }
        std::size_t length = 0;
        std::uint32_t code = 0;
        if (lead >= 0xC2 && lead <= 0xDF) {
            length = 2;
            code = static_cast<std::uint32_t>(lead & 0x1F);
        } else if (lead >= 0xE0 && lead <= 0xEF) {
            length = 3;
            code = static_cast<std::uint32_t>(lead & 0x0F);
        } else if (lead >= 0xF0 && lead <= 0xF4) {
            length = 4;
            code = static_cast<std::uint32_t>(lead & 0x07);
        } else {
            // A continuation byte or an overlong lead with no legal length.
            return false;
        }
        if (i + length > n) {
            return false;
        }
        for (std::size_t k = 1; k < length; ++k) {
            const unsigned char cont = static_cast<unsigned char>(text[i + k]);
            if (cont < 0x80 || cont > 0xBF) {
                return false;
            }
            code = (code << 6) | static_cast<std::uint32_t>(cont & 0x3F);
        }
        // Overlong encodings and surrogates are the two ways UTF-8 can name
        // something UTF-16 cannot represent faithfully. Both are rejected
        // rather than re-encoded, because a runtime that silently rewrites a
        // program's strings is not translating them.
        if ((length == 2 && code < 0x80) || (length == 3 && code < 0x800) ||
            (code >= 0xD800 && code <= 0xDFFF) ||
            (length == 4 && code < 0x10000) || code > 0x10FFFF) {
            return false;
        }
        if (code < 0x10000) {
            out.push_back(static_cast<char16_t>(code));
        } else {
            const std::uint32_t adjusted = code - 0x10000;
            out.push_back(static_cast<char16_t>(
                0xD800u + (adjusted >> 10)));
            out.push_back(static_cast<char16_t>(
                0xDC00u + (adjusted & 0x3FFu)));
        }
        i += length;
    }
    return true;
}

bool utf16_to_utf8(std::u16string_view text, std::string& out) noexcept {
    out.clear();
    const auto n = text.size();
    std::size_t i = 0;
    while (i < n) {
        std::uint32_t code = static_cast<unsigned char>(text[i] & 0xFF);
        code = static_cast<std::uint32_t>(text[i]);
        i += 1;
        if (code >= 0xD800 && code <= 0xDBFF) {
            if (i >= n) {
                return false;
            }
            const std::uint32_t low = static_cast<std::uint32_t>(
                static_cast<std::uint16_t>(text[i]));
            if (low < 0xDC00 || low > 0xDFFF) {
                return false;
            }
            code = 0x10000u + ((code - 0xD800u) << 10) + (low - 0xDC00u);
            i += 1;
        } else if (code >= 0xDC00 && code <= 0xDFFF) {
            return false;
        }
        if (code < 0x80) {
            out.push_back(static_cast<char>(code));
        } else if (code < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (code >> 6)));
            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        } else if (code < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (code >> 12)));
            out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (code >> 18)));
            out.push_back(static_cast<char>(0x80 | ((code >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        }
    }
    return true;
}

// --------------------------------------------------------------------------
// The heap
// --------------------------------------------------------------------------

namespace {

// "OCCHEAP1" read little-endian. A magic rather than a flag: the bytes sit
// in front of every heap block in memory the guest can reach, and a value
// that reads as text in a hex dump is worth more than an arbitrary constant
// when someone is staring at one.
constexpr std::uint64_t kHeapMagic = 0x4F43434845415031ULL;

struct HeapHeader {
    std::uint64_t magic;
    std::uint64_t size;  // what the guest asked for, not what was rounded to
};

[[nodiscard]] HeapHeader* header_of(void* block) noexcept {
    return reinterpret_cast<HeapHeader*>(static_cast<char*>(block) -
                                         sizeof(HeapHeader));
}

}  // namespace

void* heap_alloc(std::uint32_t flags, std::uint64_t bytes) noexcept {
    if (bytes == 0) {
        // A zero-byte allocation succeeds on Windows and hands back a
        // pointer the guest can pass to HeapSize. A null here would turn a
        // program's `alloc != NULL` check into a false failure.
        bytes = 1;
    }
    if (bytes > (0xFFFFFFFFFFFFFFFFULL - sizeof(HeapHeader) - 16)) {
        return nullptr;
    }
    void* raw = ::malloc(static_cast<std::size_t>(bytes + sizeof(HeapHeader)));
    if (raw == nullptr) {
        return nullptr;
    }
    auto* header = static_cast<HeapHeader*>(raw);
    header->magic = kHeapMagic;
    header->size = bytes;
    void* block = static_cast<char*>(raw) + sizeof(HeapHeader);
    if ((flags & kHeapZeroMemory) != 0) {
        ::memset(block, 0, static_cast<std::size_t>(bytes));
    }
    return block;
}

void* heap_realloc(std::uint32_t flags, void* block,
                   std::uint64_t bytes) noexcept {
    if (block == nullptr) {
        return heap_alloc(flags, bytes);
    }
    const HeapHeader* old = header_of(block);
    if (old->magic != kHeapMagic) {
        return nullptr;
    }
    const std::uint64_t old_size = old->size;
    void* fresh = heap_alloc(0, bytes);
    if (fresh == nullptr) {
        return nullptr;
    }
    const std::uint64_t carried =
        old_size < bytes ? old_size : bytes;
    if (carried != 0) {
        ::memcpy(fresh, block, static_cast<std::size_t>(carried));
    }
    if ((flags & kHeapZeroMemory) != 0 && bytes > carried) {
        // The zero flag on a realloc zeroes what grew, not what was carried:
        // the carried bytes hold the guest's own data and rewriting them
        // would be a corruption that reports success.
        ::memset(static_cast<char*>(fresh) + carried, 0,
                 static_cast<std::size_t>(bytes - carried));
    }
    ::free(static_cast<char*>(block) - sizeof(HeapHeader));
    return fresh;
}

std::uint64_t heap_size(const void* block) noexcept {
    if (block == nullptr) {
        return 0;
    }
    const HeapHeader* header = header_of(const_cast<void*>(block));
    if (header->magic != kHeapMagic) {
        // Not ours. Answering 0 is the honest "unknown"; answering the
        // bytes in front of a foreign pointer would be a read of memory
        // this allocator never wrote.
        return 0;
    }
    return header->size;
}

bool heap_free(void* block) noexcept {
    if (block == nullptr) {
        // Windows answers HeapFree(NULL) with success, and a CRT that frees
        // what was never allocated relies on that.
        return true;
    }
    // A second free of the same block would read the header of memory this
    // allocator has already handed back to malloc. Windows leaves the double
    // free undefined -- RtlFreeHeap's refusal runs on heap entry flags it
    // owns, which is a lifetime this header, allocated with the block, does
    // not have -- and so does this: there is no honest answer to give from
    // memory the caller no longer owns.
    const HeapHeader* header = header_of(block);
    if (header->magic != kHeapMagic) {
        return false;
    }
    ::free(static_cast<char*>(block) - sizeof(HeapHeader));
    return true;
}

// --------------------------------------------------------------------------
// The stdio bridge: a Microsoft save area into a System V descriptor
// --------------------------------------------------------------------------

namespace {

// The System V `va_list`, spelled out so it can be *built* rather than only
// consumed. The layout is the ABI: two 32-bit cursors, the overflow area and
// the register save area, 24 bytes in that order.
struct SysvVaList {
    std::uint32_t gp_offset;
    std::uint32_t fp_offset;
    void* overflow_arg_area;
    void* reg_save_area;
};
static_assert(sizeof(SysvVaList) == 24, "the ABI is 24 bytes");

// The register save area: six general-purpose slots, then eight 16-byte SSE
// slots. The GP part is addressed at 8-byte steps from 0; the SSE part at
// 16-byte steps from 48, with the double in the low half of each slot.
constexpr std::size_t kRegSaveBytes = 48 + 8 * 16;
constexpr std::uint32_t kGpStart = 24;  // RDI, RSI and RDX are the three
                                        // fixed parameters of vfprintf
constexpr std::uint32_t kFpStart = 48;

// Reads the low half of a slot: an `int` argument occupies four bytes and
// the upper four are whatever the guest's save left there.
[[nodiscard]] std::uint32_t slot_u32(const void* ms, std::size_t index) noexcept {
    std::uint32_t value = 0;
    __builtin_memcpy(&value,
                     static_cast<const char*>(ms) + index * 8,
                     sizeof(value));
    return value;
}

[[nodiscard]] std::uint64_t slot_u64(const void* ms, std::size_t index) noexcept {
    std::uint64_t value = 0;
    __builtin_memcpy(&value,
                     static_cast<const char*>(ms) + index * 8,
                     sizeof(value));
    return value;
}

void append_unsigned(std::string& out, std::uint32_t value) {
    char digits[10];
    std::size_t n = 0;
    do {
        digits[n++] = static_cast<char>('0' + value % 10);
        value /= 10;
    } while (value != 0);
    while (n > 0) {
        out += digits[--n];
    }
}

// The text-mode translation the guest's CRT writes with. A Windows
// program's stdout and stderr open in text mode, so the "\n" its printf
// prints becomes \r\n in the pipe -- which is what everything reading a
// Windows program's output sees, and what wine reproduces. The host's
// stdio has no such mode, so the bridge performs the conversion on the
// way through, and *only* here: WriteFile is not the CRT and does not
// translate, which is the same layering Windows has. A program that
// writes through the kernel gets its bytes verbatim; a program that
// writes through printf gets its newlines expanded.
[[nodiscard]] std::string text_mode_expand(const char* text,
                                           std::size_t length) {
    std::size_t newlines = 0;
    for (std::size_t i = 0; i < length; ++i) {
        if (text[i] == '\n') {
            ++newlines;
        }
    }
    if (newlines == 0) {
        return std::string(text, length);
    }
    std::string out;
    out.reserve(length + newlines);
    for (std::size_t i = 0; i < length; ++i) {
        if (text[i] == '\n') {
            out += "\r\n";
        } else {
            out += text[i];
        }
    }
    return out;
}

// How one conversion consumes the save area. `Int` reads four bytes, the
// wide forms read eight, `Floating` reads the bit pattern of a double.
enum class ArgClass : std::uint8_t {
    Int,
    Wide,
    Floating,
};

struct Conversion {
    ArgClass arg_class = ArgClass::Int;
    char specifier = 0;
};

// One conversion, decided by the format. The length modifier decides how
// wide the *guest's* argument was -- and on this data model that is the
// whole subtlety: Windows `long` is 32 bits, so `%ld` reads four bytes
// where a System V program would read eight.
[[nodiscard]] bool classify(char specifier, bool ll, bool size_t_len,
                            Conversion& out) noexcept {
    out.specifier = specifier;
    switch (specifier) {
    case 'd': case 'i': case 'u': case 'o': case 'x': case 'X': case 'c':
        out.arg_class = (ll || size_t_len) ? ArgClass::Wide : ArgClass::Int;
        return true;
    case 's': case 'p': case 'n': case 'S': case 'C':
        // A pointer is eight bytes whatever the conversion does with it;
        // `%C` carries a wide character promoted to its slot width.
        out.arg_class = ArgClass::Wide;
        return true;
    case 'f': case 'e': case 'g': case 'a':
    case 'F': case 'E': case 'G': case 'A':
        out.arg_class = ArgClass::Floating;
        return true;
    default:
        // An unknown specifier would leave the slot cursor wrong for every
        // argument after it, which is the one failure this bridge refuses
        // rather than guesses about.
        return false;
    }
}

}  // namespace

int host_vfprintf(std::FILE* stream, const char* fmt,
                  const void* ms_slots) noexcept {
    if (stream == nullptr || fmt == nullptr || ms_slots == nullptr) {
        return -1;
    }

    // The rebuilt format. `*` widths and precisions are folded into the
    // text: the System V `vfprintf` would read its own dynamic widths from
    // the descriptor, and building a descriptor whose parameter order the
    // text does not describe is the mistake that turns a printf into a
    // crash. Folding keeps the descriptor holding exactly the parameters
    // the text says it holds.
    std::string rebuilt;
    // Reserve rather than grow one byte at a time; the worst case is every
    // character becoming itself.
    rebuilt.reserve(::strlen(fmt) + 16);

    alignas(16) unsigned char reg_save[kRegSaveBytes];
    ::memset(reg_save, 0, sizeof(reg_save));
    std::vector<std::uint64_t> overflow;
    std::size_t gp_used = 0;
    std::size_t fp_used = 0;
    std::size_t slot = 0;

    const auto push_gp = [&](std::uint64_t value) {
        if (gp_used < 3) {
            __builtin_memcpy(reg_save + kGpStart + gp_used * 8, &value,
                             sizeof(value));
        } else {
            overflow.push_back(value);
        }
        ++gp_used;
    };
    const auto push_fp = [&](std::uint64_t bits) {
        if (fp_used < 8) {
            __builtin_memcpy(reg_save + kFpStart + fp_used * 16, &bits,
                             sizeof(bits));
        } else {
            overflow.push_back(bits);
        }
        ++fp_used;
    };

    const char* p = fmt;
    while (*p != '\0') {
        if (*p != '%') {
            rebuilt += *p++;
            continue;
        }
        ++p;
        if (*p == '%') {
            // The literal percent re-escapes: the rebuilt text has to
            // still be a printf format, and a bare `%` in it would start
            // a conversion the host would read -- at the end of the text
            // an unterminated one, which glibc answers with failure.
            rebuilt += "%%";
            ++p;
            continue;
        }

        // A conversion keeps its percent. Everything from here to the
        // specifier is copied through verbatim, and the rebuilt text has
        // to still be a printf format -- without the percent the host's
        // vfprintf would print the specifier as a literal character and
        // hand the arguments to no one.
        rebuilt += '%';

        // Flags and width pass through verbatim except where a `*` says the
        // width is an argument.
        while (*p == '-' || *p == '+' || *p == ' ' || *p == '#' ||
               *p == '0' || *p == '\'') {
            rebuilt += *p++;
        }
        if (*p == '*') {
            ++p;
            append_unsigned(rebuilt, slot_u32(ms_slots, slot++));
        } else {
            while (*p >= '0' && *p <= '9') {
                rebuilt += *p++;
            }
        }
        if (*p == '.') {
            rebuilt += '.';
            ++p;
            if (*p == '*') {
                ++p;
                const std::uint32_t precision =
                    slot_u32(ms_slots, slot++);
                if (precision != 0) {
                    // A negative precision is "no precision" and the dot
                    // goes with it; zero is a real precision.
                    const std::int32_t signed_precision =
                        static_cast<std::int32_t>(precision);
                    if (signed_precision < 0) {
                        rebuilt.pop_back();
                    } else {
                        append_unsigned(rebuilt, precision);
                    }
                } else {
                    append_unsigned(rebuilt, precision);
                }
            } else {
                while (*p >= '0' && *p <= '9') {
                    rebuilt += *p++;
                }
            }
        }

        // Length modifiers. They say how wide the *guest's* argument was,
        // which decides what the slot cursor reads; what the rebuilt text
        // carries is the *host's* spelling of the same width, and the two
        // agree only sometimes. On this data model a Windows `long` is 32
        // bits where the host's is 64, so a single `l` is consumed and not
        // rewritten -- the host then reads the low half of the slot, which
        // is the value the guest passed. An `I64` is Windows for `ll`. A
        // floating `L` is Windows for "double", where the host's `L` would
        // read a 16-byte long double the slot does not hold.
        bool wide = false;
        for (;;) {
            if (p[0] == 'l' && p[1] == 'l') {
                wide = true;
                rebuilt += "ll";
                p += 2;
            } else if (p[0] == 'I' && p[1] == '6' && p[2] == '4') {
                wide = true;
                rebuilt += "ll";
                p += 3;
            } else if (p[0] == 'I' && p[1] == '3' && p[2] == '2') {
                // `I32` is Windows for "plain int": consumed, nothing to
                // write, the slot cursor reads four bytes.
                p += 3;
            } else if (p[0] == 'h' && p[1] == 'h') {
                rebuilt += "hh";
                p += 2;
            } else if (*p == 'h') {
                rebuilt += 'h';
                p += 1;
            } else if (*p == 'l') {
                // On an integer conversion the single `l` is the 32-bit
                // `long`, consumed for the reason above. On a wide
                // conversion it names a `wchar_t` string, and there the
                // host's 32-bit `wchar_t` would misread the guest's 16-bit
                // text -- a bridge that passed it through would print
                // half a string, which is a lie told one character at a
                // time. Refused.
                if (p[1] == 's' || p[1] == 'S' || p[1] == 'c' ||
                    p[1] == 'C') {
                    return -1;
                }
                p += 1;
            } else if (*p == 'j' || *p == 'z' || *p == 't') {
                wide = true;
                rebuilt += *p++;
            } else if (*p == 'I') {
                // `I` alone, or paired with anything but the two widths,
                // is a modifier this bridge does not translate.
                return -1;
            } else if (*p == 'L') {
                // `L` on a floating conversion: consumed, the guest's
                // long double is a double and the slot holds its pattern.
                p += 1;
            } else if (*p == 'w') {
                return -1;
            } else {
                break;
            }
        }

        if (*p == '\0') {
            return -1;
        }
        Conversion conversion;
        if (!classify(*p++, wide, false, conversion)) {
            return -1;
        }
        if (conversion.specifier == 'S' || conversion.specifier == 'C') {
            // Windows spells the wide conversions both ways; the host's
            // `S` and `C` are the 32-bit `wchar_t` forms and the guest's
            // are 16. Refusing is the answer that does not misread.
            return -1;
        }
        if (conversion.specifier == 'n') {
            // A conversion whose answer is an address to write to cannot
            // cross: the host's fortify level aborts the process on `%n`
            // into a writable format rather than fail it, and an abort is
            // not an answer a runtime gives its guest for a format it
            // could have refused.
            return -1;
        }
        rebuilt += conversion.specifier;

        switch (conversion.arg_class) {
        case ArgClass::Int:
            push_gp(slot_u32(ms_slots, slot++));
            break;
        case ArgClass::Wide:
            push_gp(slot_u64(ms_slots, slot++));
            break;
        case ArgClass::Floating:
            push_fp(slot_u64(ms_slots, slot++));
            break;
        }
    }

    SysvVaList built;
    // The descriptor mimics the `va_list` a caller of `vfprintf` holds at
    // entry: the next general-purpose argument is the first one after the
    // three fixed parameters -- the RCX slot, offset 24 -- and the next
    // floating-point one is XMM0 at 48. The cursors are *initial* values:
    // `vfprintf` advances them itself as it consumes, which is what makes
    // the handover seamless -- what was written lands where it will read,
    // and what exceeded the registers sits in the overflow area it falls
    // through to once the cursor walks past the register slots.
    built.gp_offset = kGpStart;
    built.fp_offset = kFpStart;
    built.overflow_arg_area =
        overflow.empty()
            ? static_cast<void*>(reg_save + kRegSaveBytes)
            : static_cast<void*>(overflow.data());
    built.reg_save_area = reg_save;

    // The guest's format string may itself contain a conversion the
    // descriptor has no parameter for -- it cannot, because every
    // conversion above pushed what it asked for -- so the call is the
    // host's own and runs unmodified. It runs into a memory stream
    // rather than the caller's, because the text-mode translation below
    // has to see the formatted bytes before the stream does.
    char* text = nullptr;
    std::size_t length = 0;
    std::FILE* mem = ::open_memstream(&text, &length);
    if (mem == nullptr) {
        return -1;
    }
    va_list ap;
    static_assert(sizeof(ap) == sizeof(SysvVaList),
                  "the host descriptor must be the ABI's");
    __builtin_memcpy(&ap, &built, sizeof(ap));
    const int written = ::vfprintf(mem, rebuilt.c_str(), ap);
    ::fclose(mem);
    if (written < 0 || text == nullptr) {
        ::free(text);
        return -1;
    }

    // The formatted text is the guest's own; the delivery is the CRT's
    // text mode, which stands between the format and the stream: a
    // newline leaves as a carriage return and a newline, the way the
    // Windows CRT hands bytes to WriteFile. The answer the guest sees is
    // still the format's own count -- the carriage returns are the
    // stream's doing, not characters the format produced.
    const std::string delivered = text_mode_expand(text, length);
    ::free(text);
    if (::fwrite(delivered.data(), 1, delivered.size(), stream) !=
        delivered.size()) {
        return -1;
    }
    return written;
}

// --------------------------------------------------------------------------
// The thunks
// --------------------------------------------------------------------------
//
// Every function below is the whole of one export: it is declared with the
// Microsoft ABI, so a guest's `call [iat]` reaches it through the compiler's
// translation, and every host call it makes -- libc, the ntdll layer, the
// TEB stores -- is the System V side of the same translation. There is no
// hand-written assembly and no second signature per export.
//
// The names carry a prefix because these are the host's implementations, not
// redefinitions of the libc symbols they reach; `cr_malloc` calls `::malloc`
// and is registered under the name the guest imports, which is `malloc`.

// Calling a guest function pointer. `_initterm`, the `_onexit` list and the
// exception filter are all guest addresses, and the compiler bridges the
// call the same way it bridges the thunks -- in the other direction.
using GuestVoidFn = void (__attribute__((ms_abi))*)();

namespace {

[[nodiscard]] std::uint64_t std_handle_for(std::uint32_t type) noexcept {
    // The three standard handles are named by negative constants; the
    // narrowing conversion of -10, -11 and -12 is what the guest wrote.
    if (type == 0xFFFFFFF6u) {  // STD_INPUT_HANDLE
        return kStdInputHandle;
    }
    if (type == 0xFFFFFFF5u) {  // STD_OUTPUT_HANDLE
        return kStdOutputHandle;
    }
    if (type == 0xFFFFFFF4u) {  // STD_ERROR_HANDLE
        return kStdErrorHandle;
    }
    return 0;
}

[[nodiscard]] int fd_for_handle(std::uint64_t handle) noexcept {
    switch (handle) {
    case kStdInputHandle:
        return 0;
    case kStdOutputHandle:
        return 1;
    case kStdErrorHandle:
        return 2;
    default:
        return -1;
    }
}

[[nodiscard]] GuestState* require_state() noexcept {
    return g_guest;
}

// The msvcrt internal locks. The real library has one per stdio stream and a
// handful for its own state; the guest's startup takes two and releases them
// in the same order. The table is indexed by the number the guest passed and
// owned by the guest's thread id, which makes a nested `_lock` a count and a
// foreign one -- if there ever is one -- a different thread's row.
struct CrLock {
    std::uint64_t owner = 0;
    std::uint32_t count = 0;
};
constexpr std::size_t kCrLockCount = 64;
CrLock g_locks[kCrLockCount] = {};

std::uint64_t g_signal_handlers[32] = {};
// Windows' signal constants, at the numbers the guest spells them.
constexpr int kGuestSigNull = 0;   // SIG_DFL
constexpr int kGuestSigIgnore = 1; // SIG_IGN
constexpr int kGuestSigAbrt = 22;  // SIGABRT on Windows

}  // namespace

// ---- process and module -------------------------------------------------

extern "C" __attribute__((ms_abi)) void k32_ExitProcess(
    std::uint32_t code) noexcept {
    // Nothing after this runs: the guest has said it is done, and the exit
    // path belongs to the process layer from here.
    ::fflush(nullptr);
    terminate(code);
    __builtin_unreachable();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_TerminateProcess(
    std::uint64_t handle, std::uint32_t code) noexcept {
    if (handle != kCurrentProcessHandle) {
        // Another process's handle is one this runtime cannot name, and
        // killing the caller because it asked about a stranger would be the
        // exact failure the cross-process refusal elsewhere refuses to make.
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    ::fflush(nullptr);
    terminate(code);
    __builtin_unreachable();
}

extern "C" __attribute__((ms_abi)) const char* k32_GetCommandLineA() noexcept {
    const GuestState* g = require_state();
    if (g == nullptr) {
        return "";
    }
    return g->command_line.c_str();
}

extern "C" __attribute__((ms_abi)) const char16_t* k32_GetCommandLineW() noexcept {
    const GuestState* g = require_state();
    if (g == nullptr) {
        return u"";
    }
    // A guest `WCHAR` is two bytes and a `char16_t` is two bytes; the guest
    // reads the buffer through its own pointer type and the layout is the
    // same UTF-16 code units either way.
    return g->command_line_u16.c_str();
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetModuleFileNameA(
    void* module, char* buffer, std::uint32_t size) noexcept {
    const GuestState* g = require_state();
    if (g == nullptr || buffer == nullptr) {
        return 0;
    }
    if (module != nullptr) {
        // Only the image is known by name here; a non-null module asks for a
        // library this runtime has not loaded, and reporting the image's
        // name would be a lie the caller then prints.
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    const std::string& path = g->image_path_dos;
    const std::size_t limit = size == 0 ? 0 : size - 1;
    const std::size_t copied = path.size() < limit ? path.size() : limit;
    ::memcpy(buffer, path.data(), copied);
    if (copied < path.size()) {
        buffer[copied] = '\0';
        set_last_error(kErrorInsufficientBuffer);
        return size;
    }
    buffer[copied] = '\0';
    return static_cast<std::uint32_t>(copied);
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetModuleFileNameW(
    void* module, char16_t* buffer, std::uint32_t size) noexcept {
    const GuestState* g = require_state();
    if (g == nullptr || buffer == nullptr) {
        return 0;
    }
    if (module != nullptr) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    std::u16string wide;
    if (!utf8_to_utf16(g->image_path_dos, wide)) {
        return 0;
    }
    const std::size_t limit = size == 0 ? 0 : size - 1;
    const std::size_t copied = wide.size() < limit ? wide.size() : limit;
    ::memcpy(buffer, wide.data(), copied * sizeof(char16_t));
    if (copied < wide.size()) {
        buffer[copied] = u'\0';
        set_last_error(kErrorInsufficientBuffer);
        return size;
    }
    buffer[copied] = u'\0';
    return static_cast<std::uint32_t>(copied);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32_GetModuleHandleA(
    const char* name) noexcept {
    const GuestState* g = require_state();
    if (g == nullptr) {
        return 0;
    }
    // A null name is the image itself. A named module would be a library
    // this runtime has no file for; answering zero is what Windows answers
    // for "not loaded", and GetLastError stays whatever it was, which is
    // Windows' own behaviour for a lookup that found nothing.
    if (name == nullptr) {
        return g->image_base;
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32_GetModuleHandleW(
    const char16_t* name) noexcept {
    const GuestState* g = require_state();
    if (g == nullptr) {
        return 0;
    }
    if (name == nullptr) {
        return g->image_base;
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) void k32_GetStartupInfoA(
    void* info) noexcept {
    // The structure is 104 bytes on x64 and every field a console program
    // reads sits at the tail: the three standard handles at 80, 88 and 96.
    // They are filled with the handles `GetStdHandle` answers with, so a
    // program that starts from the startup info and one that asks for a
    // handle see the same console.
    constexpr std::uint32_t kStartupInfoBytes = 104;
    constexpr std::uint64_t kStdInputOffset = 80;
    constexpr std::uint64_t kStdOutputOffset = 88;
    constexpr std::uint64_t kStdErrorOffset = 96;
    if (info == nullptr) {
        return;
    }
    ::memset(info, 0, kStartupInfoBytes);
    std::uint32_t cb = kStartupInfoBytes;
    __builtin_memcpy(info, &cb, sizeof(cb));
    __builtin_memcpy(static_cast<char*>(info) + kStdInputOffset,
                     &kStdInputHandle, sizeof(kStdInputHandle));
    __builtin_memcpy(static_cast<char*>(info) + kStdOutputOffset,
                     &kStdOutputHandle, sizeof(kStdOutputHandle));
    __builtin_memcpy(static_cast<char*>(info) + kStdErrorOffset,
                     &kStdErrorHandle, sizeof(kStdErrorHandle));
}

extern "C" __attribute__((ms_abi)) void k32_GetStartupInfoW(
    void* info) noexcept {
    k32_GetStartupInfoA(info);
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetLastError() noexcept {
    return load_teb_u32(kTebLastError);
}

extern "C" __attribute__((ms_abi)) void k32_SetLastError(
    std::uint32_t error) noexcept {
    set_last_error(error);
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetCurrentProcessId() noexcept {
    return load_teb_u32(kTebProcessId);
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetCurrentThreadId() noexcept {
    return load_teb_u32(kTebThreadId);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32_GetCurrentProcess() noexcept {
    return kCurrentProcessHandle;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32_GetCurrentThread() noexcept {
    return 0xFFFFFFFFFFFFFFFEULL;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_IsDebuggerPresent() noexcept {
    return 0;
}

// ---- the console --------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::uint64_t k32_GetStdHandle(
    std::uint32_t type) noexcept {
    const std::uint64_t handle = std_handle_for(type);
    if (handle == 0) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    return handle;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_WriteFile(
    std::uint64_t handle, const void* buffer, std::uint32_t to_write,
    std::uint32_t* written, void* overlapped) noexcept {
    if (overlapped != nullptr) {
        // Overlapped I/O is a completion-port shape this runtime has no
        // ports for, and a caller that passed one asked for asynchronous
        // semantics that a synchronous write would silently break.
        set_last_error(kErrorNotSupported);
        return 0;
    }
    const int fd = fd_for_handle(handle);
    if (fd < 0) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    std::size_t done = 0;
    while (done < to_write) {
        const ssize_t n = ::write(
            fd, static_cast<const char*>(buffer) + done,
            static_cast<std::size_t>(to_write - done));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (written != nullptr) {
                *written = static_cast<std::uint32_t>(done);
            }
            set_last_error(kErrorInvalidHandle);
            return 0;
        }
        done += static_cast<std::size_t>(n);
    }
    if (written != nullptr) {
        *written = static_cast<std::uint32_t>(done);
    }
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_CloseHandle(
    std::uint64_t handle) noexcept {
    // The standard handles belong to the console and outlive the call. There
    // is no object table yet for anything else, and closing a handle that
    // names nothing is answered as Windows answers a valid handle with no
    // resources behind it: successfully.
    (void)handle;
    return 1;
}

extern "C" __attribute__((ms_abi)) void k32_Sleep(std::uint32_t ms) noexcept {
    if (ms == 0) {
        ::sched_yield();
        return;
    }
    timespec request;
    request.tv_sec = static_cast<time_t>(ms / 1000u);
    request.tv_nsec = static_cast<long>(ms % 1000u) * 1000000L;
    while (::nanosleep(&request, &request) < 0 && errno == EINTR) {
        // Restart with whatever is left: a signal that interrupted the wait
        // consumed part of it, and the guest asked for the whole.
    }
}

// ---- critical sections --------------------------------------------------
//
// A CRITICAL_SECTION is 40 bytes in the guest's memory and this runtime
// keeps the Windows layout of it: LockCount at 8, RecursionCount at 12,
// OwningThread at 16, SpinCount at 24. The lock word is this
// implementation's own encoding -- bit 0 is "held", bit 1 is "a waiter has
// been woken" -- because a guest never reads inside the structure it only
// hands back, and the encoding is what makes the futex pair honest.

namespace {

constexpr std::uint32_t kCsLockedBit = 1u;
constexpr std::uint32_t kCsWakeupBit = 2u;

[[nodiscard]] std::uint32_t cs_compare_exchange(void* cs,
                                                std::uint32_t expected,
                                                std::uint32_t desired) noexcept {
    return __sync_val_compare_and_swap(
        reinterpret_cast<volatile std::uint32_t*>(
            static_cast<char*>(cs) + 8),
        expected, desired);
}

void cs_futex_wait(void* cs, std::uint32_t expected) noexcept {
    ::syscall(static_cast<long>(202) /* SYS_futex */,
              static_cast<char*>(cs) + 8,
              0 /* FUTEX_WAIT_PRIVATE */, expected, nullptr);
}

void cs_futex_wake(void* cs) noexcept {
    ::syscall(static_cast<long>(202) /* SYS_futex */,
              static_cast<char*>(cs) + 8,
              1 /* FUTEX_WAKE_PRIVATE */, 1);
}

}  // namespace

extern "C" __attribute__((ms_abi)) void k32_InitializeCriticalSection(
    void* cs) noexcept {
    if (cs == nullptr) {
        return;
    }
    ::memset(cs, 0, 40);
}

extern "C" __attribute__((ms_abi)) void k32_EnterCriticalSection(
    void* cs) noexcept {
    if (cs == nullptr) {
        return;
    }
    const std::uint64_t self = guest_thread_id();
    for (;;) {
        std::uint32_t state = 0;
        __builtin_memcpy(&state, static_cast<char*>(cs) + 8, sizeof(state));
        const std::uint64_t owner = [cs]() {
            std::uint64_t value = 0;
            __builtin_memcpy(&value, static_cast<char*>(cs) + 16,
                             sizeof(value));
            return value;
        }();
        if (owner == self && owner != 0) {
            // Recursive entry. The recursion count is the guest's own view
            // of how many times it holds the lock, and it is the field the
            // matching Leave decrements first.
            std::uint32_t recursion = 0;
            __builtin_memcpy(&recursion, static_cast<char*>(cs) + 12,
                             sizeof(recursion));
            ++recursion;
            __builtin_memcpy(static_cast<char*>(cs) + 12, &recursion,
                             sizeof(recursion));
            return;
        }
        std::uint32_t desired = state | kCsLockedBit;
        if ((state & kCsWakeupBit) == 0) {
            desired |= kCsWakeupBit;
        }
        if (cs_compare_exchange(cs, state, desired) == state) {
            std::uint64_t own = self;
            __builtin_memcpy(static_cast<char*>(cs) + 16, &own, sizeof(own));
            std::uint32_t one = 1;
            __builtin_memcpy(static_cast<char*>(cs) + 12, &one, sizeof(one));
            return;
        }
        // Failed to take it. Sleep until the wake bit says someone is coming
        // out; the value checked is the one seen, which is what makes a lost
        // wake-up impossible rather than unlikely.
        std::uint32_t now = 0;
        __builtin_memcpy(&now, static_cast<char*>(cs) + 8, sizeof(now));
        if ((now & kCsWakeupBit) != 0) {
            cs_futex_wait(cs, now);
        }
    }
}

extern "C" __attribute__((ms_abi)) void k32_LeaveCriticalSection(
    void* cs) noexcept {
    if (cs == nullptr) {
        return;
    }
    std::uint32_t recursion = 0;
    __builtin_memcpy(&recursion, static_cast<char*>(cs) + 12,
                     sizeof(recursion));
    if (recursion > 1) {
        --recursion;
        __builtin_memcpy(static_cast<char*>(cs) + 12, &recursion,
                         sizeof(recursion));
        return;
    }
    std::uint64_t zero = 0;
    __builtin_memcpy(static_cast<char*>(cs) + 16, &zero, sizeof(zero));
    std::uint32_t one = 1;
    __builtin_memcpy(static_cast<char*>(cs) + 12, &one, sizeof(one));

    std::uint32_t state = 0;
    __builtin_memcpy(&state, static_cast<char*>(cs) + 8, sizeof(state));
    // Clearing both bits and waking one waiter is the release: the wake bit
    // is handed to the woken thread, which sets it again on its own attempt.
    (void)cs_compare_exchange(cs, state,
                              state & ~(kCsLockedBit | kCsWakeupBit));
    cs_futex_wake(cs);
}

extern "C" __attribute__((ms_abi)) void k32_DeleteCriticalSection(
    void* cs) noexcept {
    // The futex has no kernel-side resource to release; the guest's memory
    // is the whole of the object and it is the guest's to free.
    (void)cs;
}

// ---- TLS ----------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::uint32_t k32_TlsAlloc() noexcept {
    const GuestState* g = require_state();
    if (g == nullptr || g->teb == 0) {
        return kTlsOutOfRange;
    }
    for (std::uint64_t index = 0; index < kTlsSlotCount; ++index) {
        const std::uint64_t address = g->teb + kTebTlsArray + index * 8;
        std::uint64_t value = 0;
        __builtin_memcpy(&value, reinterpret_cast<const void*>(address),
                         sizeof(value));
        if (value == 0) {
            return static_cast<std::uint32_t>(index);
        }
    }
    return kTlsOutOfRange;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_TlsSetValue(
    std::uint32_t index, std::uint64_t value) noexcept {
    const GuestState* g = require_state();
    if (g == nullptr || g->teb == 0 || index >= kTlsSlotCount) {
        return 0;
    }
    const std::uint64_t address = g->teb + kTebTlsArray + index * 8;
    __builtin_memcpy(reinterpret_cast<void*>(address), &value,
                     sizeof(value));
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32_TlsGetValue(
    std::uint32_t index) noexcept {
    const GuestState* g = require_state();
    if (g == nullptr || g->teb == 0 || index >= kTlsSlotCount) {
        return 0;
    }
    const std::uint64_t address = g->teb + kTebTlsArray + index * 8;
    std::uint64_t value = 0;
    __builtin_memcpy(&value, reinterpret_cast<const void*>(address),
                     sizeof(value));
    // Deliberately no SetLastError: `TlsGetValue` is the one TLS call whose
    // contract says the last error survives it, so a caller can distinguish
    // "slot holds null" from "the call failed" by what GetLastError says.
    return value;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_TlsFree(
    std::uint32_t index) noexcept {
    if (index >= kTlsSlotCount) {
        return 0;
    }
    return k32_TlsSetValue(index, 0);
}

// ---- virtual memory -----------------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t k32_VirtualProtect(
    void* address, std::uint64_t size, std::uint32_t protect,
    std::uint32_t* old_protect) noexcept {
    GuestState* g = require_state();
    if (g == nullptr || g->space == nullptr || g->mapper == nullptr) {
        return 0;
    }
    NtContext ctx;
    ctx.space = g->space;
    ctx.placement = g->mapper;
    std::uint64_t addr = reinterpret_cast<std::uint64_t>(address);
    std::uint64_t len = size;
    std::uint32_t old = 0;
    const Result<std::uint64_t> r =
        nt_protect_virtual_memory(ctx, &addr, &len, protect, &old);
    if (!r.ok()) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    if (old_protect != nullptr) {
        *old_protect = old;
    }
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32_VirtualQuery(
    const void* address, void* buffer, std::uint64_t length) noexcept {
    GuestState* g = require_state();
    if (g == nullptr || g->space == nullptr || g->mapper == nullptr) {
        return 0;
    }
    NtContext ctx;
    ctx.space = g->space;
    ctx.placement = g->mapper;
    std::uint64_t got = 0;
    const Result<std::uint64_t> r = nt_query_virtual_memory(
        ctx, reinterpret_cast<std::uint64_t>(address),
        MemoryInformationClass::BasicInformation, buffer, length, &got);
    if (!r.ok()) {
        return 0;
    }
    return r.value;
}

// ---- the heap -----------------------------------------------------------

constexpr std::uint64_t kProcessHeapHandle = 1;
std::uint64_t g_next_heap_handle = 0x10;

extern "C" __attribute__((ms_abi)) std::uint64_t k32_GetProcessHeap() noexcept {
    return kProcessHeapHandle;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32_HeapCreate(
    std::uint32_t options, std::uint64_t initial_size,
    std::uint64_t maximum_size) noexcept {
    // The options and the sizes describe a serialised growable heap, which
    // is what every block below already is: the host allocator serialises,
    // and growth is its own concern. The handle is real in the sense that
    // the heap functions accept it, and that is the whole of what a handle
    // is here.
    (void)options;
    (void)initial_size;
    (void)maximum_size;
    const std::uint64_t handle = g_next_heap_handle;
    g_next_heap_handle += 0x10;
    return handle;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_HeapDestroy(
    std::uint64_t heap) noexcept {
    // Blocks from a destroyed heap belong to the guest to misuse; the heap
    // itself owns nothing this side has to return.
    (void)heap;
    return 1;
}

extern "C" __attribute__((ms_abi)) void* k32_HeapAlloc(
    std::uint64_t heap, std::uint32_t flags, std::uint64_t bytes) noexcept {
    (void)heap;
    return heap_alloc(flags, bytes);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_HeapFree(
    std::uint64_t heap, std::uint32_t flags, void* block) noexcept {
    (void)heap;
    (void)flags;
    if (!heap_free(block)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32_HeapSize(
    std::uint64_t heap, std::uint32_t flags, const void* block) noexcept {
    (void)heap;
    (void)flags;
    return heap_size(block);
}

extern "C" __attribute__((ms_abi)) void* k32_HeapReAlloc(
    std::uint64_t heap, std::uint32_t flags, void* block,
    std::uint64_t bytes) noexcept {
    (void)heap;
    return heap_realloc(flags, block, bytes);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_HeapValidate(
    std::uint64_t heap, std::uint32_t flags, const void* block) noexcept {
    (void)heap;
    (void)flags;
    if (block == nullptr) {
        // A null block validates the whole heap, which is trivially true of
        // an allocator the host already keeps consistent.
        return 1;
    }
    return heap_size(block) != 0 ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32_HeapCompact(
    std::uint64_t heap, std::uint32_t flags) noexcept {
    (void)heap;
    (void)flags;
    // The largest free block a compacted heap could offer. Zero is the
    // answer that says "nothing decommitted to hand back", which is the
    // truth of an allocator that does not decommit.
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_HeapSetInformation(
    std::uint64_t heap, std::uint32_t info_class, void* info,
    std::uint64_t length) noexcept {
    // HeapEnableTerminationOnCorruption and the LFH enablement a CRT asks
    // for are both accepted: the first because every free here validates the
    // magic already, the second because the low-fragmentation choice is the
    // allocator's and the guest's answer to it changes nothing observable.
    (void)heap;
    (void)info_class;
    (void)info;
    (void)length;
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_HeapQueryInformation(
    std::uint64_t heap, std::uint32_t info_class, void* info,
    std::uint32_t length, std::uint32_t* returned) noexcept {
    (void)heap;
    (void)info_class;
    (void)info;
    (void)length;
    if (returned != nullptr) {
        *returned = 0;
    }
    return 1;
}

// ---- the exception filter ----------------------------------------------

extern "C" __attribute__((ms_abi)) std::uint64_t k32_SetUnhandledExceptionFilter(
    std::uint64_t filter) noexcept {
    GuestState* g = require_state();
    if (g == nullptr) {
        return 0;
    }
    const std::uint64_t previous = g->unhandled_filter;
    g->unhandled_filter = filter;
    return previous;
}

// ---- text and code page -------------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t k32_IsDBCSLeadByteEx(
    std::uint32_t code_page, std::uint8_t byte) noexcept {
    // The ANSI code page this runtime answers for is UTF-8, which has no
    // lead bytes in the DBCS sense: every byte of a multi-byte sequence is
    // in the 0x80..0xBF continuation range and no byte signals "more to
    // come" on its own.
    (void)code_page;
    (void)byte;
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_MultiByteToWideChar(
    std::uint32_t code_page, std::uint32_t flags, const char* source,
    std::int32_t source_length, char16_t* target,
    std::int32_t target_length) noexcept {
    (void)code_page;  // UTF-8 is the answer for the ACP and for 65001 alike
    (void)flags;
    if (source == nullptr) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    std::size_t bytes;
    bool null_terminated = false;
    if (source_length < 0) {
        bytes = ::strlen(source);
        null_terminated = true;
    } else {
        bytes = static_cast<std::size_t>(source_length);
    }
    std::u16string wide;
    if (!utf8_to_utf16(std::string_view(source, bytes), wide)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    const std::size_t needed =
        wide.size() + (null_terminated ? 1u : 0u);
    if (target == nullptr) {
        return static_cast<std::int32_t>(needed);
    }
    if (static_cast<std::size_t>(target_length) < needed) {
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    ::memcpy(target, wide.data(), wide.size() * sizeof(char16_t));
    if (null_terminated) {
        target[wide.size()] = u'\0';
    }
    return static_cast<std::int32_t>(needed);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_WideCharToMultiByte(
    std::uint32_t code_page, std::uint32_t flags, const char16_t* source,
    std::int32_t source_length, char* target, std::int32_t target_length,
    const char* default_char, std::int32_t* default_used) noexcept {
    (void)code_page;
    (void)flags;
    (void)default_char;
    if (source == nullptr) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    std::size_t chars;
    bool null_terminated = false;
    if (source_length < 0) {
        chars = 0;
        while (source[chars] != u'\0') {
            ++chars;
        }
        null_terminated = true;
    } else {
        chars = static_cast<std::size_t>(source_length);
    }
    std::string narrow;
    if (!utf16_to_utf8(std::u16string_view(source, chars), narrow)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    const std::size_t needed =
        narrow.size() + (null_terminated ? 1u : 0u);
    if (target == nullptr) {
        if (default_used != nullptr) {
            *default_used = 0;
        }
        return static_cast<std::int32_t>(needed);
    }
    if (static_cast<std::size_t>(target_length) < needed) {
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    ::memcpy(target, narrow.data(), narrow.size());
    if (null_terminated) {
        target[narrow.size()] = '\0';
    }
    if (default_used != nullptr) {
        *default_used = 0;
    }
    return static_cast<std::int32_t>(needed);
}

// ---- the C runtime ------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t cr___getmainargs(
    std::int32_t* argc, char*** argv, char*** env, std::int32_t wildcard,
    void* start_info) noexcept {
    (void)wildcard;
    (void)start_info;
    const GuestState* g = require_state();
    if (g == nullptr || argc == nullptr || argv == nullptr || env == nullptr) {
        return -1;
    }
    *argc = static_cast<std::int32_t>(g->arguments.size());
    // The tables are const char* by the host's taste and char* by the C
    // startup's; the guest receives pointers into strings it never writes.
    *argv = const_cast<char**>(g->argv_table.data());
    *env = const_cast<char**>(g->env_table.data());
    return 0;
}

extern "C" __attribute__((ms_abi)) void cr___set_app_type(
    std::uint32_t type) noexcept {
    GuestState* g = require_state();
    if (g != nullptr) {
        g->app_type = type;
    }
}

extern "C" __attribute__((ms_abi)) void cr___setusermatherr(
    std::uint64_t handler) noexcept {
    GuestState* g = require_state();
    if (g != nullptr) {
        g->matherr = handler;
    }
}

extern "C" __attribute__((ms_abi)) void cr__initterm(
    std::uint64_t* begin, std::uint64_t* end) noexcept {
    if (begin == nullptr || end == nullptr) {
        return;
    }
    for (std::uint64_t* p = begin; p < end; ++p) {
        if (*p != 0) {
            reinterpret_cast<GuestVoidFn>(*p)();
        }
    }
}

extern "C" __attribute__((ms_abi)) std::uint64_t cr__onexit(
    std::uint64_t function) noexcept {
    GuestState* g = require_state();
    if (g == nullptr || function == 0) {
        return 0;
    }
    g->onexit_list.push_back(function);
    return function;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_atexit(
    std::uint64_t function) noexcept {
    GuestState* g = require_state();
    if (g == nullptr || function == 0) {
        return -1;
    }
    g->atexit_list.push_back(function);
    return 0;
}

namespace {

// The exit walk: `atexit` and `_onexit` in reverse registration order, which
// is the order Windows gives them and the order that lets a destructor named
// later tear down something registered earlier. Both tables clear as they
// run, because `_cexit` followed by `exit` must not run them twice.
void run_exit_lists() noexcept {
    GuestState* g = require_state();
    if (g == nullptr) {
        return;
    }
    while (!g->atexit_list.empty() || !g->onexit_list.empty()) {
        std::uint64_t fn = 0;
        if (!g->atexit_list.empty()) {
            fn = g->atexit_list.back();
            g->atexit_list.pop_back();
        } else {
            fn = g->onexit_list.back();
            g->onexit_list.pop_back();
        }
        reinterpret_cast<GuestVoidFn>(fn)();
    }
}

}  // namespace

extern "C" __attribute__((ms_abi)) void cr__cexit() noexcept {
    run_exit_lists();
}

extern "C" __attribute__((ms_abi)) void cr_exit(
    std::int32_t code) noexcept {
    run_exit_lists();
    ::fflush(nullptr);
    terminate(static_cast<std::uint32_t>(code));
    __builtin_unreachable();
}

extern "C" __attribute__((ms_abi)) void cr__amsg_exit(
    std::int32_t code) noexcept {
    // The startup's fast failure. The message the real library prints names
    // an internal error code; the exit code it leaves is the code itself.
    terminate(static_cast<std::uint32_t>(code));
    __builtin_unreachable();
}

extern "C" __attribute__((ms_abi)) void cr_abort() noexcept {
    const std::uint64_t handler = g_signal_handlers[kGuestSigAbrt];
    if (handler != kGuestSigNull && handler != kGuestSigIgnore) {
        reinterpret_cast<GuestVoidFn>(handler)();
    }
    ::fflush(nullptr);
    terminate(3);  // the exit status Windows gives an unhandled abort
    __builtin_unreachable();
}

extern "C" __attribute__((ms_abi)) std::uint64_t cr_signal(
    std::int32_t sig, std::uint64_t handler) noexcept {
    if (sig < 0 || static_cast<std::size_t>(sig) >= 32) {
        set_last_error(kErrorInvalidHandle);
        return kGuestSigNull;
    }
    const std::uint64_t previous = g_signal_handlers[sig];
    g_signal_handlers[sig] = handler;
    return previous;
}

extern "C" __attribute__((ms_abi)) std::int32_t* cr__errno() noexcept {
    return &errno;
}

extern "C" __attribute__((ms_abi)) void* cr___iob_func() noexcept {
    const GuestState* g = require_state();
    if (g == nullptr) {
        return nullptr;
    }
    return reinterpret_cast<void*>(g->iob_base);
}

extern "C" __attribute__((ms_abi)) void cr__lock(
    std::int32_t index) noexcept {
    if (index < 0 || static_cast<std::size_t>(index) >= kCrLockCount) {
        return;
    }
    CrLock& lock = g_locks[index];
    const std::uint64_t self = guest_thread_id();
    if (lock.owner == self && lock.count != 0) {
        ++lock.count;
        return;
    }
    lock.owner = self;
    lock.count = 1;
}

extern "C" __attribute__((ms_abi)) void cr__unlock(
    std::int32_t index) noexcept {
    if (index < 0 || static_cast<std::size_t>(index) >= kCrLockCount) {
        return;
    }
    CrLock& lock = g_locks[index];
    if (lock.count == 0) {
        return;
    }
    if (--lock.count == 0) {
        lock.owner = 0;
    }
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr___lc_codepage_func() noexcept {
    // The ANSI code page is 0 (CP_ACP), and the page it resolves to here is
    // UTF-8: the conversion functions this runtime pairs it with are UTF-8
    // in both directions.
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr___mb_cur_max_func() noexcept {
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint64_t cr___C_specific_handler(
    void* exception_record, void* establisher_frame, void* context_record,
    void* dispatcher_context) noexcept {
    // The scope-table walker a guest with __try reaches. No current guest
    // path dispatches an exception through here -- the fault handler decides
    // before the unwind starts -- so the honest answer is the one that says
    // "not handled": the search continues, and a report that looked for this
    // function would find it rather than a claim.
    (void)exception_record;
    (void)establisher_frame;
    (void)context_record;
    (void)dispatcher_context;
    return 1;  // ExceptionContinueSearch
}

// ---- stdio and the C library -------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t cr_vfprintf(
    void* stream, const char* fmt, void* ms_slots) noexcept {
    const GuestState* g = require_state();
    if (g == nullptr) {
        return -1;
    }
    return host_vfprintf(
        translate_stream(*g, reinterpret_cast<std::uint64_t>(stream)), fmt,
        ms_slots);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_fprintf(
    void* stream, const char* fmt, ...) noexcept {
    const GuestState* g = require_state();
    if (g == nullptr) {
        return -1;
    }
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, fmt);
    void* slots = nullptr;
    __builtin_memcpy(&slots, &ap, sizeof(slots));
    const std::int32_t r = host_vfprintf(
        translate_stream(*g, reinterpret_cast<std::uint64_t>(stream)), fmt,
        slots);
    __builtin_ms_va_end(ap);
    return r;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_fputc(
    std::int32_t c, void* stream) noexcept {
    const GuestState* g = require_state();
    if (g == nullptr) {
        return -1;
    }
    // A character going out through the CRT travels in the stream's text
    // mode: a newline becomes a carriage return and a newline, exactly as
    // the Windows CRT's own fputc delivers it. WriteFile never sees this
    // path, and the guest's return value is still the character, not the
    // bytes the expansion added.
    const unsigned char byte = static_cast<unsigned char>(c);
    const std::string expanded =
        text_mode_expand(reinterpret_cast<const char*>(&byte), 1);
    std::FILE* target =
        translate_stream(*g, reinterpret_cast<std::uint64_t>(stream));
    if (::fwrite(expanded.data(), 1, expanded.size(), target) !=
        expanded.size()) {
        return -1;
    }
    return byte;
}

extern "C" __attribute__((ms_abi)) std::uint64_t cr_fwrite(
    const void* buffer, std::uint64_t size, std::uint64_t count,
    void* stream) noexcept {
    const GuestState* g = require_state();
    if (g == nullptr) {
        return 0;
    }
    // A degenerate request -- a zero dimension, or a total that overflows
    // the host's address space -- writes nothing, as the C contract says.
    if (size == 0 || count == 0 || count > SIZE_MAX / size) {
        return 0;
    }
    const auto* bytes = static_cast<const char*>(buffer);
    const std::size_t requested = static_cast<std::size_t>(size * count);
    // Bytes going out through the CRT travel in the stream's text mode:
    // newlines are expanded on the way to the host, so the bytes the host
    // writes are not the bytes the guest asked for. The item count the
    // guest sees is its own -- walk its buffer back through the
    // expansion, and how many of its bytes fit in what the host took,
    // carriages and all, is how many of its items were written.
    const std::string expanded = text_mode_expand(bytes, requested);
    const std::size_t written = ::fwrite(
        expanded.data(), 1, expanded.size(),
        translate_stream(*g, reinterpret_cast<std::uint64_t>(stream)));
    std::size_t taken = 0;
    std::size_t produced = 0;
    while (taken < requested) {
        const std::size_t next =
            produced + (bytes[taken] == '\n' ? 2 : 1);
        if (next > written) {
            break;
        }
        produced = next;
        ++taken;
    }
    return static_cast<std::uint64_t>(taken / size);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_fputs(
    const char* text, void* stream) noexcept {
    const GuestState* g = require_state();
    if (g == nullptr || text == nullptr) {
        return -1;
    }
    // A string through the CRT leaves in the stream's text mode, like any
    // CRT byte does; fputs adds no newline of its own, and the answer is
    // nonnegative on success, the way the Windows CRT answers.
    const std::string expanded = text_mode_expand(text, ::strlen(text));
    std::FILE* target =
        translate_stream(*g, reinterpret_cast<std::uint64_t>(stream));
    return ::fwrite(expanded.data(), 1, expanded.size(), target) ==
                   expanded.size()
               ? 0
               : -1;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_puts(
    const char* text) noexcept {
    const GuestState* g = require_state();
    if (g == nullptr || text == nullptr || g->iob_base == 0) {
        return -1;
    }
    // puts appends its own newline, and the whole line -- appended newline
    // included -- leaves through the stream's text mode. The guest's
    // stdout is slot one of its own file table.
    std::string line(text);
    line += '\n';
    const std::string expanded = text_mode_expand(line.data(), line.size());
    std::FILE* target = translate_stream(*g, g->iob_base + kGuestFileSlot);
    return ::fwrite(expanded.data(), 1, expanded.size(), target) ==
                   expanded.size()
               ? 0
               : -1;
}

extern "C" __attribute__((ms_abi)) void* cr_malloc(
    std::uint64_t bytes) noexcept {
    return ::malloc(static_cast<std::size_t>(bytes));
}

extern "C" __attribute__((ms_abi)) void* cr_calloc(
    std::uint64_t count, std::uint64_t size) noexcept {
    return ::calloc(static_cast<std::size_t>(count),
                    static_cast<std::size_t>(size));
}

extern "C" __attribute__((ms_abi)) void cr_free(void* block) noexcept {
    ::free(block);
}

extern "C" __attribute__((ms_abi)) void* cr_memcpy(
    void* target, const void* source, std::uint64_t bytes) noexcept {
    return ::memcpy(target, source, static_cast<std::size_t>(bytes));
}

extern "C" __attribute__((ms_abi)) void* cr_memset(
    void* target, std::int32_t value, std::uint64_t bytes) noexcept {
    return ::memset(target, value, static_cast<std::size_t>(bytes));
}

extern "C" __attribute__((ms_abi)) std::uint64_t cr_strlen(
    const char* text) noexcept {
    return ::strlen(text);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_strncmp(
    const char* a, const char* b, std::uint64_t n) noexcept {
    return ::strncmp(a, b, static_cast<std::size_t>(n));
}

extern "C" __attribute__((ms_abi)) std::uint64_t cr_wcslen(
    const char16_t* text) noexcept {
    std::uint64_t n = 0;
    if (text == nullptr) {
        return 0;
    }
    while (text[n] != u'\0') {
        ++n;
    }
    return n;
}

extern "C" __attribute__((ms_abi)) const char* cr_strerror(
    std::int32_t err) noexcept {
    return ::strerror(err);
}

extern "C" __attribute__((ms_abi)) void* cr_localeconv() noexcept {
    return ::localeconv();
}

// --------------------------------------------------------------------------
// The CRT's computational face
// --------------------------------------------------------------------------
//
// The string, memory, conversion, sorting and random functions a C program
// calls by name. Most are the host's own functions reached through the
// same ms_abi translation every thunk uses. The ones the host spells
// differently are written here: the `itoa` family the host has never had,
// the strtol family clipped to the guest's 32-bit long, a `rand` that has
// to produce the very sequence Windows produces rather than a sequence of
// its own, the sort that hands a guest's comparison function back across
// the ABI, and the 16-bit `wchar_t` family, whose step the host's 32-bit
// spelling would get wrong.

namespace {

// Windows' `rand`, verbatim: one 32-bit seed, stepped by 214013 and
// 2531011, the answer in bits 16 through 30. A guest that seeds and
// expects the sequence Windows produces -- 41, 18467, 6334, ... from
// srand(1) -- sees exactly that sequence, and the seed Windows starts
// from without an srand call is 1.
std::uint32_t g_rand_seed = 1;

constexpr std::int64_t kMsLongMax = 2147483647;
constexpr std::int64_t kMsLongMin = -2147483647 - 1;

// The guest's `long` is 32 bits while the host's own strtol works in 64.
// Windows clips an out-of-range conversion to LONG_MAX or LONG_MIN and
// marks ERANGE; the clip below is that answer, not a silent truncation.
std::int32_t clip_to_ms_long(std::int64_t value) noexcept {
    if (value > kMsLongMax) {
        errno = ERANGE;
        return static_cast<std::int32_t>(kMsLongMax);
    }
    if (value < kMsLongMin) {
        errno = ERANGE;
        return static_cast<std::int32_t>(kMsLongMin);
    }
    return static_cast<std::int32_t>(value);
}

// Writes `magnitude` in `base`, digits and lower-case letters, which is
// what the Windows spellings produce, into `out`, NUL terminated.
void write_unsigned_radix(std::uint64_t magnitude, unsigned base,
                          char* out) noexcept {
    char digits[64];
    std::size_t n = 0;
    do {
        const unsigned digit = static_cast<unsigned>(magnitude % base);
        digits[n++] = digit < 10 ? static_cast<char>('0' + digit)
                                 : static_cast<char>('a' + (digit - 10));
        magnitude /= base;
    } while (magnitude != 0);
    char* p = out;
    while (n > 0) {
        *p++ = digits[--n];
    }
    *p = '\0';
}

// The signed spelling: base 10 carries a leading minus and the magnitude
// of the value, negated in unsigned so the minimum negates safely. Any
// other base is Windows' bit-pattern form -- _itoa(-1, 16) is "ffffffff",
// the complement, not a sign and a half.
void write_signed_radix(std::int64_t value, unsigned base,
                        char* out) noexcept {
    char* p = out;
    std::uint64_t magnitude = static_cast<std::uint64_t>(value);
    if (base == 10 && value < 0) {
        *p++ = '-';
        magnitude = ~magnitude + 1ULL;
    }
    write_unsigned_radix(magnitude, base, p);
}

// The 32-bit spellings: base 10 reads the value as the signed number it
// is, and any other base reads the 32 bits themselves -- a 64-bit helper
// would sign-extend "-1" into sixteen f's where Windows writes eight.
char* write_itoa32(std::int32_t value, unsigned base, char* buffer) noexcept {
    if (base == 10) {
        write_signed_radix(value, base, buffer);
    } else {
        write_unsigned_radix(static_cast<std::uint32_t>(value), base, buffer);
    }
    return buffer;
}

// The guest comparison a sort or search calls back with is guest code,
// which speaks the Microsoft ABI; the host's qsort speaks System V. The
// bridge below is the System V side, and the context slot is the guest's
// own function pointer.

std::int32_t compare_bridge(const void* a, const void* b,
                            void* context) noexcept {
    return (*static_cast<GuestCompare*>(context))(a, b);
}

}  // namespace

// --- strings and memory: the host's own functions ---

extern "C" __attribute__((ms_abi)) char* cr_strcpy(
    char* target, const char* source) noexcept {
    return ::strcpy(target, source);
}

extern "C" __attribute__((ms_abi)) char* cr_strncpy(
    char* target, const char* source, std::uint64_t n) noexcept {
    return ::strncpy(target, source, static_cast<std::size_t>(n));
}

extern "C" __attribute__((ms_abi)) char* cr_strcat(
    char* target, const char* source) noexcept {
    return ::strcat(target, source);
}

extern "C" __attribute__((ms_abi)) char* cr_strncat(
    char* target, const char* source, std::uint64_t n) noexcept {
    return ::strncat(target, source, static_cast<std::size_t>(n));
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_strcmp(
    const char* a, const char* b) noexcept {
    return ::strcmp(a, b);
}

extern "C" __attribute__((ms_abi)) char* cr_strchr(
    const char* text, std::int32_t c) noexcept {
    // The character sought is the guest's int folded to one byte, which
    // is the fold the C definition itself prescribes.
    return const_cast<char*>(::strchr(text, static_cast<char>(c)));
}

extern "C" __attribute__((ms_abi)) char* cr_strrchr(
    const char* text, std::int32_t c) noexcept {
    return const_cast<char*>(::strrchr(text, static_cast<char>(c)));
}

extern "C" __attribute__((ms_abi)) char* cr_strstr(
    const char* haystack, const char* needle) noexcept {
    return const_cast<char*>(::strstr(haystack, needle));
}

extern "C" __attribute__((ms_abi)) std::uint64_t cr_strspn(
    const char* text, const char* accept) noexcept {
    return ::strspn(text, accept);
}

extern "C" __attribute__((ms_abi)) std::uint64_t cr_strcspn(
    const char* text, const char* reject) noexcept {
    return ::strcspn(text, reject);
}

extern "C" __attribute__((ms_abi)) char* cr_strpbrk(
    const char* text, const char* accept) noexcept {
    return const_cast<char*>(::strpbrk(text, accept));
}

extern "C" __attribute__((ms_abi)) std::uint64_t cr_strnlen(
    const char* text, std::uint64_t limit) noexcept {
    return ::strnlen(text, static_cast<std::size_t>(limit));
}

extern "C" __attribute__((ms_abi)) std::int32_t cr__stricmp(
    const char* a, const char* b) noexcept {
    return ::strcasecmp(a, b);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr__strnicmp(
    const char* a, const char* b, std::uint64_t n) noexcept {
    return ::strncasecmp(a, b, static_cast<std::size_t>(n));
}

extern "C" __attribute__((ms_abi)) char* cr__strupr(char* text) noexcept {
    for (char* p = text; *p != '\0'; ++p) {
        *p = static_cast<char>(
            ::toupper(static_cast<unsigned char>(*p)));
    }
    return text;
}

extern "C" __attribute__((ms_abi)) char* cr__strlwr(char* text) noexcept {
    for (char* p = text; *p != '\0'; ++p) {
        *p = static_cast<char>(
            ::tolower(static_cast<unsigned char>(*p)));
    }
    return text;
}

extern "C" __attribute__((ms_abi)) void* cr_memmove(
    void* target, const void* source, std::uint64_t bytes) noexcept {
    return ::memmove(target, source, static_cast<std::size_t>(bytes));
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_memcmp(
    const void* a, const void* b, std::uint64_t bytes) noexcept {
    return ::memcmp(a, b, static_cast<std::size_t>(bytes));
}

// --- conversions ---

extern "C" __attribute__((ms_abi)) std::int32_t cr_atoi(
    const char* text) noexcept {
    return ::atoi(text);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_atol(
    const char* text) noexcept {
    // The guest's long is 32 bits, so the answer is the low half of the
    // host's -- identical wherever the answer is in range, and the
    // overflow a C program cannot rely on either way.
    return static_cast<std::int32_t>(::atol(text));
}

extern "C" __attribute__((ms_abi)) std::int64_t cr__atoi64(
    const char* text) noexcept {
    return ::strtoll(text, nullptr, 10);
}

extern "C" __attribute__((ms_abi)) double cr_atof(
    const char* text) noexcept {
    return ::atof(text);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_strtol(
    const char* text, char** end, std::int32_t base) noexcept {
    errno = 0;
    return clip_to_ms_long(::strtoll(text, end, base));
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr_strtoul(
    const char* text, char** end, std::int32_t base) noexcept {
    errno = 0;
    const std::int64_t value = ::strtoll(text, end, base);
    // A leading minus is Windows' way to spell a complement: -1 reads as
    // 0xffffffff without a range error, which is the magnitude negated in
    // the *32-bit* domain, and the error starts only past what 32 bits
    // can hold.
    if (value < 0) {
        const std::uint64_t magnitude =
            ~static_cast<std::uint64_t>(value) + 1ULL;
        if (magnitude > 0xFFFFFFFFULL) {
            errno = ERANGE;
            return 0xFFFFFFFFu;
        }
        return static_cast<std::uint32_t>(
            0u - static_cast<std::uint32_t>(magnitude));
    }
    if (value > 0xFFFFFFFFLL) {
        errno = ERANGE;
        return 0xFFFFFFFFu;
    }
    return static_cast<std::uint32_t>(value);
}

extern "C" __attribute__((ms_abi)) std::int64_t cr_strtoll(
    const char* text, char** end, std::int32_t base) noexcept {
    return ::strtoll(text, end, base);
}

extern "C" __attribute__((ms_abi)) std::uint64_t cr_strtoull(
    const char* text, char** end, std::int32_t base) noexcept {
    return ::strtoull(text, end, base);
}

extern "C" __attribute__((ms_abi)) double cr_strtod(
    const char* text, char** end) noexcept {
    return ::strtod(text, end);
}

// The `itoa` family the host has never had. The base runs from 2 to 36;
// base 10 spells the value signed, and any other base spells the value's
// own bit pattern, which is why _itoa(-1, 16) is "ffffffff".
extern "C" __attribute__((ms_abi)) char* cr_itoa(
    std::int32_t value, char* buffer, std::int32_t base) noexcept {
    return write_itoa32(value, static_cast<unsigned>(base), buffer);
}

extern "C" __attribute__((ms_abi)) char* cr__itoa(
    std::int32_t value, char* buffer, std::int32_t base) noexcept {
    return write_itoa32(value, static_cast<unsigned>(base), buffer);
}

extern "C" __attribute__((ms_abi)) char* cr_ltoa(
    std::int32_t value, char* buffer, std::int32_t base) noexcept {
    // The guest's long is 32 bits, and the spelling is the same one.
    return write_itoa32(value, static_cast<unsigned>(base), buffer);
}

extern "C" __attribute__((ms_abi)) char* cr__ltoa(
    std::int32_t value, char* buffer, std::int32_t base) noexcept {
    return write_itoa32(value, static_cast<unsigned>(base), buffer);
}

extern "C" __attribute__((ms_abi)) char* cr_ultoa(
    std::uint32_t value, char* buffer, std::int32_t base) noexcept {
    write_unsigned_radix(value, static_cast<unsigned>(base), buffer);
    return buffer;
}

extern "C" __attribute__((ms_abi)) char* cr__ultoa(
    std::uint32_t value, char* buffer, std::int32_t base) noexcept {
    write_unsigned_radix(value, static_cast<unsigned>(base), buffer);
    return buffer;
}

extern "C" __attribute__((ms_abi)) char* cr__i64toa(
    std::int64_t value, char* buffer, std::int32_t base) noexcept {
    write_signed_radix(value, static_cast<unsigned>(base), buffer);
    return buffer;
}

extern "C" __attribute__((ms_abi)) char* cr__ui64toa(
    std::uint64_t value, char* buffer, std::int32_t base) noexcept {
    write_unsigned_radix(value, static_cast<unsigned>(base), buffer);
    return buffer;
}

// --- character classification: the host's own tables ---

extern "C" __attribute__((ms_abi)) std::int32_t cr_isalpha(
    std::int32_t c) noexcept {
    return ::isalpha(c);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_isalnum(
    std::int32_t c) noexcept {
    return ::isalnum(c);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_isdigit(
    std::int32_t c) noexcept {
    return ::isdigit(c);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_isxdigit(
    std::int32_t c) noexcept {
    return ::isxdigit(c);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_isspace(
    std::int32_t c) noexcept {
    return ::isspace(c);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_isupper(
    std::int32_t c) noexcept {
    return ::isupper(c);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_islower(
    std::int32_t c) noexcept {
    return ::islower(c);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_ispunct(
    std::int32_t c) noexcept {
    return ::ispunct(c);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_isprint(
    std::int32_t c) noexcept {
    return ::isprint(c);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_isgraph(
    std::int32_t c) noexcept {
    return ::isgraph(c);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_iscntrl(
    std::int32_t c) noexcept {
    return ::iscntrl(c);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_tolower(
    std::int32_t c) noexcept {
    return ::tolower(c);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_toupper(
    std::int32_t c) noexcept {
    return ::toupper(c);
}

// --- sorting and searching ---

extern "C" __attribute__((ms_abi)) void cr_qsort(
    void* base, std::uint64_t count, std::uint64_t size,
    GuestCompare compare) noexcept {
    if (compare == nullptr) {
        return;
    }
    // The guest's comparison function goes back across the ABI through
    // the bridge, in the context slot qsort_r exists to carry.
    ::qsort_r(base, static_cast<std::size_t>(count),
              static_cast<std::size_t>(size), compare_bridge, &compare);
}

extern "C" __attribute__((ms_abi)) void* cr_bsearch(
    const void* key, const void* base, std::uint64_t count,
    std::uint64_t size, GuestCompare compare) noexcept {
    // The host's bsearch has nowhere to carry the guest's own convention
    // through, so the binary walk happens here, calling the guest
    // function the same direct way the qsort bridge does.
    const char* cursor = static_cast<const char*>(base);
    while (count > 0) {
        const std::uint64_t half = count / 2;
        const void* element = cursor + half * size;
        const std::int32_t order = compare(key, element);
        if (order == 0) {
            return const_cast<void*>(element);
        }
        if (order < 0) {
            count = half;
        } else {
            cursor = static_cast<const char*>(element) + size;
            count -= half + 1;
        }
    }
    return nullptr;
}

// --- the random sequence Windows itself produces ---

extern "C" __attribute__((ms_abi)) void cr_srand(
    std::uint32_t seed) noexcept {
    g_rand_seed = seed;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_rand() noexcept {
    g_rand_seed = g_rand_seed * 214013u + 2531011u;
    return static_cast<std::int32_t>((g_rand_seed >> 16) & 0x7FFFu);
}

// --- integer arithmetic ---

extern "C" __attribute__((ms_abi)) std::int32_t cr_abs(
    std::int32_t value) noexcept {
    return ::abs(value);
}

extern "C" __attribute__((ms_abi)) std::int64_t cr_labs(
    std::int64_t value) noexcept {
    // The guest hands a 32-bit long in the low half of the register and
    // reads the low half back; the host's 64-bit answer narrows to the
    // same bits wherever the answer is defined.
    return ::labs(value);
}

extern "C" __attribute__((ms_abi)) std::int64_t cr_llabs(
    std::int64_t value) noexcept {
    return ::llabs(value);
}

extern "C" __attribute__((ms_abi)) std::int64_t cr__abs64(
    std::int64_t value) noexcept {
    return ::llabs(value);
}

// The quotient/remainder pairs. The host's own div_t is two ints -- 8
// bytes, one register under the Microsoft ABI, the same layout the guest
// spells -- so it answers through unchanged. ldiv_t is the same 8 bytes
// with the guest's 32-bit longs, and lldiv_t is 16 bytes, which the
// Microsoft ABI carries through a hidden pointer the compiler spells for
// both sides of this call.
extern "C" __attribute__((ms_abi)) div_t cr_div(
    std::int32_t n, std::int32_t d) noexcept {
    return ::div(n, d);
}

extern "C" __attribute__((ms_abi)) LdivPair cr_ldiv(
    std::int32_t n, std::int32_t d) noexcept {
    return {n / d, n % d};
}

extern "C" __attribute__((ms_abi)) LldivPair cr_lldiv(
    std::int64_t n, std::int64_t d) noexcept {
    return {n / d, n % d};
}

// --- the 16-bit wchar_t family ---

extern "C" __attribute__((ms_abi)) char16_t* cr_wcscpy(
    char16_t* target, const char16_t* source) noexcept {
    char16_t* p = target;
    while ((*p++ = *source++) != u'\0') {}
    return target;
}

extern "C" __attribute__((ms_abi)) char16_t* cr_wcsncpy(
    char16_t* target, const char16_t* source, std::uint64_t n) noexcept {
    char16_t* start = target;
    for (; n > 0 && *source != u'\0'; --n) {
        *target++ = *source++;
    }
    for (; n > 0; --n) {
        *target++ = u'\0';
    }
    return start;
}

extern "C" __attribute__((ms_abi)) char16_t* cr_wcscat(
    char16_t* target, const char16_t* source) noexcept {
    char16_t* p = target;
    while (*p != u'\0') {
        ++p;
    }
    while ((*p++ = *source++) != u'\0') {}
    return target;
}

extern "C" __attribute__((ms_abi)) char16_t* cr_wcsncat(
    char16_t* target, const char16_t* source, std::uint64_t n) noexcept {
    char16_t* start = target;
    while (*target != u'\0') {
        ++target;
    }
    for (; n > 0 && *source != u'\0'; --n) {
        *target++ = *source++;
    }
    *target = u'\0';
    return start;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_wcscmp(
    const char16_t* a, const char16_t* b) noexcept {
    // The guest's wchar_t is unsigned, and the answer is the difference
    // of the two units, which is what the Windows CRT answers.
    while (*a != u'\0' && *a == *b) {
        ++a;
        ++b;
    }
    return static_cast<std::int32_t>(*a) - static_cast<std::int32_t>(*b);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_wcsncmp(
    const char16_t* a, const char16_t* b, std::uint64_t n) noexcept {
    while (n > 0 && *a != u'\0' && *a == *b) {
        ++a;
        ++b;
        --n;
    }
    if (n == 0) {
        return 0;
    }
    return static_cast<std::int32_t>(*a) - static_cast<std::int32_t>(*b);
}

extern "C" __attribute__((ms_abi)) char16_t* cr_wcschr(
    const char16_t* text, std::uint32_t c) noexcept {
    // The character the guest seeks is the low 16 bits of its own value,
    // the fold from its 32-bit int to its 16-bit wchar_t.
    const auto needle = static_cast<char16_t>(c);
    for (; *text != u'\0'; ++text) {
        if (*text == needle) {
            return const_cast<char16_t*>(text);
        }
    }
    return needle == u'\0' ? const_cast<char16_t*>(text) : nullptr;
}

extern "C" __attribute__((ms_abi)) char16_t* cr_wcsrchr(
    const char16_t* text, std::uint32_t c) noexcept {
    const auto needle = static_cast<char16_t>(c);
    const char16_t* last = nullptr;
    const char16_t* p = text;
    for (; *p != u'\0'; ++p) {
        if (*p == needle) {
            last = p;
        }
    }
    if (needle == u'\0') {
        return const_cast<char16_t*>(p);
    }
    return const_cast<char16_t*>(last);
}

extern "C" __attribute__((ms_abi)) char16_t* cr_wcsstr(
    const char16_t* haystack, const char16_t* needle) noexcept {
    if (*needle == u'\0') {
        return const_cast<char16_t*>(haystack);
    }
    for (; *haystack != u'\0'; ++haystack) {
        const char16_t* h = haystack;
        const char16_t* p = needle;
        while (*p != u'\0' && *h == *p) {
            ++h;
            ++p;
        }
        if (*p == u'\0') {
            return const_cast<char16_t*>(haystack);
        }
    }
    return nullptr;
}

extern "C" __attribute__((ms_abi)) char16_t* cr_wcsdup(
    const char16_t* text) noexcept {
    std::size_t units = 0;
    while (text[units] != u'\0') {
        ++units;
    }
    auto* copy = static_cast<char16_t*>(
        ::malloc((units + 1) * sizeof(char16_t)));
    if (copy == nullptr) {
        return nullptr;
    }
    ::memcpy(copy, text, (units + 1) * sizeof(char16_t));
    return copy;
}

extern "C" __attribute__((ms_abi)) std::uint64_t cr_wcsnlen(
    const char16_t* text, std::uint64_t limit) noexcept {
    std::uint64_t n = 0;
    while (n < limit && text[n] != u'\0') {
        ++n;
    }
    return n;
}

// The multibyte bridge. The guest's narrow bytes are this runtime's
// UTF-8 -- the same text its file system paths arrive in -- and its
// wchar_t is 16-bit UTF-16, so the conversion is the one the utf helpers
// already carry.
extern "C" __attribute__((ms_abi)) std::uint64_t cr_mbstowcs(
    char16_t* target, const char* source, std::uint64_t units) noexcept {
    std::u16string wide;
    if (!utf8_to_utf16(std::string_view(source), wide)) {
        return static_cast<std::uint64_t>(-1);  // an invalid byte is EILSEQ
    }
    if (target == nullptr) {
        return wide.size();  // the room the text needs, terminator excluded
    }
    const std::uint64_t stored = wide.size() < units ? wide.size() : units;
    if (stored > 0) {
        ::memcpy(target, wide.data(),
                 static_cast<std::size_t>(stored) * sizeof(char16_t));
    }
    if (stored < units) {
        target[stored] = u'\0';
    }
    return stored;
}

extern "C" __attribute__((ms_abi)) std::uint64_t cr_wcstombs(
    char* target, const char16_t* source, std::uint64_t bytes) noexcept {
    std::string narrow;
    if (!utf16_to_utf8(std::u16string_view(source), narrow)) {
        return static_cast<std::uint64_t>(-1);
    }
    if (target == nullptr) {
        return narrow.size();
    }
    const std::uint64_t stored = narrow.size() < bytes ? narrow.size() : bytes;
    if (stored > 0) {
        ::memcpy(target, narrow.data(), static_cast<std::size_t>(stored));
    }
    if (stored < bytes) {
        target[stored] = '\0';
    }
    return stored;
}

// ---- time ---------------------------------------------------------------

extern "C" __attribute__((ms_abi)) void k32_GetSystemTimeAsFileTime(
    std::uint64_t* out) noexcept {
    // The FILETIME epoch is 1601-01-01 and the unit is 100 nanoseconds; the
    // difference from the Unix epoch is the constant below, in 100ns units.
    constexpr std::uint64_t kEpochDelta100ns = 116444736000000000ULL;
    timespec now;
    ::clock_gettime(CLOCK_REALTIME, &now);
    const std::uint64_t hundred_ns =
        static_cast<std::uint64_t>(now.tv_sec) * 10000000ULL +
        static_cast<std::uint64_t>(now.tv_nsec) / 100ULL;
    if (out != nullptr) {
        *out = hundred_ns + kEpochDelta100ns;
    }
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_QueryPerformanceCounter(
    std::uint64_t* out) noexcept {
    timespec now;
    ::clock_gettime(CLOCK_MONOTONIC, &now);
    if (out != nullptr) {
        *out = static_cast<std::uint64_t>(now.tv_sec) * 10000000ULL +
               static_cast<std::uint64_t>(now.tv_nsec) / 100ULL;
    }
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_QueryPerformanceFrequency(
    std::uint64_t* out) noexcept {
    // The frequency the counter above advances at: 10 MHz, one tick per 100
    // nanoseconds. A pair this simple has no calibration to lie about.
    if (out != nullptr) {
        *out = 10000000ULL;
    }
    return 1;
}

// --------------------------------------------------------------------------
// Registration
// --------------------------------------------------------------------------

namespace {

// The data exports. Their addresses are the whole of the answer; the
// variables live for the process and their values are whatever the guest's
// startup leaves in them.
int g_fmode = 0;
int g_commode = 0;
char** g_initenv = nullptr;

void add_kernel32(ExportModule& module) {
    module.name = "KERNEL32.dll";
    const auto e = [](const char* n, void* fn) {
        HostExport out;
        out.name = n;
        out.address = reinterpret_cast<std::uint64_t>(fn);
        return out;
    };
    module.host_exports = {
        e("GetStdHandle", reinterpret_cast<void*>(&k32_GetStdHandle)),
        e("WriteFile", reinterpret_cast<void*>(&k32_WriteFile)),
        e("CloseHandle", reinterpret_cast<void*>(&k32_CloseHandle)),
        e("ExitProcess", reinterpret_cast<void*>(&k32_ExitProcess)),
        e("TerminateProcess", reinterpret_cast<void*>(&k32_TerminateProcess)),
        e("GetCommandLineA", reinterpret_cast<void*>(&k32_GetCommandLineA)),
        e("GetCommandLineW", reinterpret_cast<void*>(&k32_GetCommandLineW)),
        e("GetModuleFileNameA",
          reinterpret_cast<void*>(&k32_GetModuleFileNameA)),
        e("GetModuleFileNameW",
          reinterpret_cast<void*>(&k32_GetModuleFileNameW)),
        e("GetModuleHandleA", reinterpret_cast<void*>(&k32_GetModuleHandleA)),
        e("GetModuleHandleW", reinterpret_cast<void*>(&k32_GetModuleHandleW)),
        e("GetStartupInfoA", reinterpret_cast<void*>(&k32_GetStartupInfoA)),
        e("GetStartupInfoW", reinterpret_cast<void*>(&k32_GetStartupInfoW)),
        e("GetCurrentProcessId",
          reinterpret_cast<void*>(&k32_GetCurrentProcessId)),
        e("GetCurrentThreadId",
          reinterpret_cast<void*>(&k32_GetCurrentThreadId)),
        e("GetCurrentProcess", reinterpret_cast<void*>(&k32_GetCurrentProcess)),
        e("GetCurrentThread", reinterpret_cast<void*>(&k32_GetCurrentThread)),
        e("IsDebuggerPresent", reinterpret_cast<void*>(&k32_IsDebuggerPresent)),
        e("GetLastError", reinterpret_cast<void*>(&k32_GetLastError)),
        e("SetLastError", reinterpret_cast<void*>(&k32_SetLastError)),
        e("InitializeCriticalSection",
          reinterpret_cast<void*>(&k32_InitializeCriticalSection)),
        e("EnterCriticalSection",
          reinterpret_cast<void*>(&k32_EnterCriticalSection)),
        e("LeaveCriticalSection",
          reinterpret_cast<void*>(&k32_LeaveCriticalSection)),
        e("DeleteCriticalSection",
          reinterpret_cast<void*>(&k32_DeleteCriticalSection)),
        e("SetUnhandledExceptionFilter",
          reinterpret_cast<void*>(&k32_SetUnhandledExceptionFilter)),
        e("Sleep", reinterpret_cast<void*>(&k32_Sleep)),
        e("TlsAlloc", reinterpret_cast<void*>(&k32_TlsAlloc)),
        e("TlsGetValue", reinterpret_cast<void*>(&k32_TlsGetValue)),
        e("TlsSetValue", reinterpret_cast<void*>(&k32_TlsSetValue)),
        e("TlsFree", reinterpret_cast<void*>(&k32_TlsFree)),
        e("VirtualProtect", reinterpret_cast<void*>(&k32_VirtualProtect)),
        e("VirtualQuery", reinterpret_cast<void*>(&k32_VirtualQuery)),
        e("GetProcessHeap", reinterpret_cast<void*>(&k32_GetProcessHeap)),
        e("HeapCreate", reinterpret_cast<void*>(&k32_HeapCreate)),
        e("HeapDestroy", reinterpret_cast<void*>(&k32_HeapDestroy)),
        e("HeapAlloc", reinterpret_cast<void*>(&k32_HeapAlloc)),
        e("HeapFree", reinterpret_cast<void*>(&k32_HeapFree)),
        e("HeapSize", reinterpret_cast<void*>(&k32_HeapSize)),
        e("HeapReAlloc", reinterpret_cast<void*>(&k32_HeapReAlloc)),
        e("HeapValidate", reinterpret_cast<void*>(&k32_HeapValidate)),
        e("HeapCompact", reinterpret_cast<void*>(&k32_HeapCompact)),
        e("HeapSetInformation",
          reinterpret_cast<void*>(&k32_HeapSetInformation)),
        e("HeapQueryInformation",
          reinterpret_cast<void*>(&k32_HeapQueryInformation)),
        e("IsDBCSLeadByteEx", reinterpret_cast<void*>(&k32_IsDBCSLeadByteEx)),
        e("MultiByteToWideChar",
          reinterpret_cast<void*>(&k32_MultiByteToWideChar)),
        e("WideCharToMultiByte",
          reinterpret_cast<void*>(&k32_WideCharToMultiByte)),
        e("GetSystemTimeAsFileTime",
          reinterpret_cast<void*>(&k32_GetSystemTimeAsFileTime)),
        e("QueryPerformanceCounter",
          reinterpret_cast<void*>(&k32_QueryPerformanceCounter)),
        e("QueryPerformanceFrequency",
          reinterpret_cast<void*>(&k32_QueryPerformanceFrequency)),
    };
}

void add_msvcrt(ExportModule& module) {
    module.name = "msvcrt.dll";
    const auto e = [](const char* n, void* fn) {
        HostExport out;
        out.name = n;
        out.address = reinterpret_cast<std::uint64_t>(fn);
        return out;
    };
    const auto d = [](const char* n, void* var) {
        HostExport out;
        out.name = n;
        out.address = reinterpret_cast<std::uint64_t>(var);
        return out;
    };
    module.host_exports = {
        e("__getmainargs", reinterpret_cast<void*>(&cr___getmainargs)),
        d("__initenv", &g_initenv),
        e("__iob_func", reinterpret_cast<void*>(&cr___iob_func)),
        e("__set_app_type", reinterpret_cast<void*>(&cr___set_app_type)),
        e("__setusermatherr", reinterpret_cast<void*>(&cr___setusermatherr)),
        e("__C_specific_handler",
          reinterpret_cast<void*>(&cr___C_specific_handler)),
        e("___lc_codepage_func",
          reinterpret_cast<void*>(&cr___lc_codepage_func)),
        e("___mb_cur_max_func",
          reinterpret_cast<void*>(&cr___mb_cur_max_func)),
        e("_amsg_exit", reinterpret_cast<void*>(&cr__amsg_exit)),
        e("_abs64", reinterpret_cast<void*>(&cr__abs64)),
        e("_atoi64", reinterpret_cast<void*>(&cr__atoi64)),
        e("_cexit", reinterpret_cast<void*>(&cr__cexit)),
        d("_commode", &g_commode),
        e("_errno", reinterpret_cast<void*>(&cr__errno)),
        e("_fmode", &g_fmode),
        e("_i64toa", reinterpret_cast<void*>(&cr__i64toa)),
        e("_initterm", reinterpret_cast<void*>(&cr__initterm)),
        e("_itoa", reinterpret_cast<void*>(&cr__itoa)),
        e("_lock", reinterpret_cast<void*>(&cr__lock)),
        e("_ltoa", reinterpret_cast<void*>(&cr__ltoa)),
        e("_onexit", reinterpret_cast<void*>(&cr__onexit)),
        e("_stricmp", reinterpret_cast<void*>(&cr__stricmp)),
        e("_strlwr", reinterpret_cast<void*>(&cr__strlwr)),
        e("_strnicmp", reinterpret_cast<void*>(&cr__strnicmp)),
        e("_strupr", reinterpret_cast<void*>(&cr__strupr)),
        e("_ui64toa", reinterpret_cast<void*>(&cr__ui64toa)),
        e("_ultoa", reinterpret_cast<void*>(&cr__ultoa)),
        e("_unlock", reinterpret_cast<void*>(&cr__unlock)),
        e("abs", reinterpret_cast<void*>(&cr_abs)),
        e("atexit", reinterpret_cast<void*>(&cr_atexit)),
        e("atof", reinterpret_cast<void*>(&cr_atof)),
        e("atoi", reinterpret_cast<void*>(&cr_atoi)),
        e("atol", reinterpret_cast<void*>(&cr_atol)),
        e("abort", reinterpret_cast<void*>(&cr_abort)),
        e("bsearch", reinterpret_cast<void*>(&cr_bsearch)),
        e("calloc", reinterpret_cast<void*>(&cr_calloc)),
        e("div", reinterpret_cast<void*>(&cr_div)),
        e("exit", reinterpret_cast<void*>(&cr_exit)),
        e("fprintf", reinterpret_cast<void*>(&cr_fprintf)),
        e("fputc", reinterpret_cast<void*>(&cr_fputc)),
        e("fputs", reinterpret_cast<void*>(&cr_fputs)),
        e("free", reinterpret_cast<void*>(&cr_free)),
        e("fwrite", reinterpret_cast<void*>(&cr_fwrite)),
        e("isalnum", reinterpret_cast<void*>(&cr_isalnum)),
        e("isalpha", reinterpret_cast<void*>(&cr_isalpha)),
        e("iscntrl", reinterpret_cast<void*>(&cr_iscntrl)),
        e("isdigit", reinterpret_cast<void*>(&cr_isdigit)),
        e("isgraph", reinterpret_cast<void*>(&cr_isgraph)),
        e("islower", reinterpret_cast<void*>(&cr_islower)),
        e("isprint", reinterpret_cast<void*>(&cr_isprint)),
        e("ispunct", reinterpret_cast<void*>(&cr_ispunct)),
        e("isspace", reinterpret_cast<void*>(&cr_isspace)),
        e("isupper", reinterpret_cast<void*>(&cr_isupper)),
        e("isxdigit", reinterpret_cast<void*>(&cr_isxdigit)),
        e("itoa", reinterpret_cast<void*>(&cr_itoa)),
        e("labs", reinterpret_cast<void*>(&cr_labs)),
        e("ldiv", reinterpret_cast<void*>(&cr_ldiv)),
        e("lldiv", reinterpret_cast<void*>(&cr_lldiv)),
        e("localeconv", reinterpret_cast<void*>(&cr_localeconv)),
        e("malloc", reinterpret_cast<void*>(&cr_malloc)),
        e("mbstowcs", reinterpret_cast<void*>(&cr_mbstowcs)),
        e("memcmp", reinterpret_cast<void*>(&cr_memcmp)),
        e("memcpy", reinterpret_cast<void*>(&cr_memcpy)),
        e("memmove", reinterpret_cast<void*>(&cr_memmove)),
        e("memset", reinterpret_cast<void*>(&cr_memset)),
        e("puts", reinterpret_cast<void*>(&cr_puts)),
        e("qsort", reinterpret_cast<void*>(&cr_qsort)),
        e("rand", reinterpret_cast<void*>(&cr_rand)),
        e("srand", reinterpret_cast<void*>(&cr_srand)),
        e("signal", reinterpret_cast<void*>(&cr_signal)),
        e("strcat", reinterpret_cast<void*>(&cr_strcat)),
        e("strchr", reinterpret_cast<void*>(&cr_strchr)),
        e("strcmp", reinterpret_cast<void*>(&cr_strcmp)),
        e("strcspn", reinterpret_cast<void*>(&cr_strcspn)),
        e("strerror", reinterpret_cast<void*>(&cr_strerror)),
        e("strlen", reinterpret_cast<void*>(&cr_strlen)),
        e("strncat", reinterpret_cast<void*>(&cr_strncat)),
        e("strncmp", reinterpret_cast<void*>(&cr_strncmp)),
        e("strncpy", reinterpret_cast<void*>(&cr_strncpy)),
        e("strnlen", reinterpret_cast<void*>(&cr_strnlen)),
        e("strpbrk", reinterpret_cast<void*>(&cr_strpbrk)),
        e("strrchr", reinterpret_cast<void*>(&cr_strrchr)),
        e("strspn", reinterpret_cast<void*>(&cr_strspn)),
        e("strstr", reinterpret_cast<void*>(&cr_strstr)),
        e("strtod", reinterpret_cast<void*>(&cr_strtod)),
        e("strtol", reinterpret_cast<void*>(&cr_strtol)),
        e("strtoll", reinterpret_cast<void*>(&cr_strtoll)),
        e("strtoul", reinterpret_cast<void*>(&cr_strtoul)),
        e("strtoull", reinterpret_cast<void*>(&cr_strtoull)),
        e("tolower", reinterpret_cast<void*>(&cr_tolower)),
        e("toupper", reinterpret_cast<void*>(&cr_toupper)),
        e("vfprintf", reinterpret_cast<void*>(&cr_vfprintf)),
        e("wcschr", reinterpret_cast<void*>(&cr_wcschr)),
        e("wcscmp", reinterpret_cast<void*>(&cr_wcscmp)),
        e("wcscpy", reinterpret_cast<void*>(&cr_wcscpy)),
        e("wcsdup", reinterpret_cast<void*>(&cr_wcsdup)),
        e("wcslen", reinterpret_cast<void*>(&cr_wcslen)),
        e("wcsncat", reinterpret_cast<void*>(&cr_wcsncat)),
        e("wcsncmp", reinterpret_cast<void*>(&cr_wcsncmp)),
        e("wcsncpy", reinterpret_cast<void*>(&cr_wcsncpy)),
        e("wcsnlen", reinterpret_cast<void*>(&cr_wcsnlen)),
        e("wcsrchr", reinterpret_cast<void*>(&cr_wcsrchr)),
        e("wcsstr", reinterpret_cast<void*>(&cr_wcsstr)),
        e("wcstombs", reinterpret_cast<void*>(&cr_wcstombs)),
    };
}

}  // namespace

void register_host_modules(ExportRegistry& registry) {
    ExportModule kernel32;
    add_kernel32(kernel32);
    registry.add(std::move(kernel32));

    ExportModule msvcrt;
    add_msvcrt(msvcrt);
    registry.add(std::move(msvcrt));
}

}  // namespace occ::runtime::winabi

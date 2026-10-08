#include "occ/runtime/winabi.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "occ/runtime/address_space.h"
#include "occ/runtime/dos_path.h"
#include "occ/runtime/api.h"
#include "occ/runtime/mapper.h"
#include "occ/runtime/ntdll.h"
#include "occ/runtime/objects.h"
#include "occ/runtime/seh.h"

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
// File handles this runtime issues sit at the base: the value is the host
// descriptor plus it, a range the standard handles and the pseudo-handles
// never enter.
constexpr std::uint64_t kFileHandleBase = 0x2000;
constexpr std::uint64_t kCurrentProcessHandle = 0xFFFFFFFFFFFFFFFFULL;

constexpr std::uint32_t kHeapZeroMemory = 0x00000008u;

// Win32 errors this layer reports, as Windows spells them. A constant here
// is one a function below actually returns; an error this layer has no
// place to report yet is not listed, because a value nothing reads is a
// value nothing checks. (`ERROR_NO_MORE_ITEMS` is 259 and
// `ERROR_NO_MORE_FILES` is 18, and they arrive with `FindNextFile`,
// `FindNextVolume` and `HeapWalk`, which are not implemented here yet.)
constexpr std::uint32_t kErrorInvalidHandle = 6;
constexpr std::uint32_t kErrorFileNotFound = 2;
constexpr std::uint32_t kErrorNotSupported = 50;
constexpr std::uint32_t kErrorInsufficientBuffer = 122;
constexpr std::uint32_t kErrorInvalidParameter = 87;
constexpr std::uint32_t kErrorEnvVarNotFound = 203;
constexpr std::uint32_t kErrorProcNotFound = 127;
constexpr std::uint32_t kErrorModNotFound = 126;

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



// The DOS spelling of a host path. The mapping itself lives in
// `runtime/dos_path.cpp`, beside the inverse and the reasoning for both; this
// is the name the rest of this layer already calls it by, and it stays so
// that a caller does not have to know where the pair moved to.
std::string to_dos_path(std::string_view unix_path) {
    return ::occ::runtime::to_dos_path(unix_path);
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
    // The bookkeeping the heap APIs let a caller hang off a block. It is in
    // the header rather than a side table so that the two cannot disagree
    // about which block a value belongs to, and so that freeing the block
    // releases the value with it.
    void* user_value;
    std::uint32_t user_flags;
    std::uint32_t user_flags_set_by_user;
};

[[nodiscard]] HeapHeader* header_of(void* block) noexcept {
    return reinterpret_cast<HeapHeader*>(static_cast<char*>(block) -
                                         sizeof(HeapHeader));
}

// The blocks this allocator has handed out and has not taken back. Every
// header peek below is reached through this list first, because the magic
// test alone reads the eight bytes in front of whatever pointer the caller
// supplies -- and a pointer a caller invented, or one that names a stack
// buffer or a foreign allocation, has no eight bytes in front of it that
// this allocator may read. The guest runs on one host thread, so there is
// no lock, for the same reason the atom-table list has none.
std::vector<void*>& heap_blocks() noexcept {
    static std::vector<void*> blocks;
    return blocks;
}

[[nodiscard]] bool heap_is_ours(void* block) noexcept {
    for (void* live : heap_blocks()) {
        if (live == block) {
            return true;
        }
    }
    return false;
}

void heap_forget(void* block) noexcept {
    auto& blocks = heap_blocks();
    for (std::size_t i = 0; i < blocks.size(); ++i) {
        if (blocks[i] == block) {
            blocks.erase(blocks.begin() + static_cast<std::ptrdiff_t>(i));
            return;
        }
    }
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
    header->user_value = nullptr;
    header->user_flags = 0;
    header->user_flags_set_by_user = 0;
    void* block = static_cast<char*>(raw) + sizeof(HeapHeader);
    heap_blocks().push_back(block);
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
    if (!heap_is_ours(block)) {
        return nullptr;
    }
    const HeapHeader* old = header_of(block);
    if (old->magic != kHeapMagic) {
        return nullptr;
    }
    const std::uint64_t old_size = old->size;
    // The new block is taken before the old one leaves the ledger. Doing
    // it the other way round would drop the old block on a failed
    // allocation: it would still hold the caller's data, and the caller
    // could no longer free it, because the ledger is what says a block is
    // this allocator's.
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
    heap_forget(block);
    ::free(static_cast<char*>(block) - sizeof(HeapHeader));
    return fresh;
}

std::uint64_t heap_size(const void* block) noexcept {
    if (block == nullptr) {
        return 0;
    }
    if (!heap_is_ours(const_cast<void*>(block))) {
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

std::vector<void*> heap_live_blocks() {
    const std::vector<void*>& blocks = heap_blocks();
    return std::vector<void*>(blocks.begin(), blocks.end());
}

bool heap_owns(const void* block) noexcept {
    if (block == nullptr) {
        return false;
    }
    return heap_is_ours(const_cast<void*>(block));
}

bool heap_user_info(const void* block, HeapUserInfo& out) noexcept {
    if (!heap_owns(block)) {
        return false;
    }
    const HeapHeader* header = header_of(const_cast<void*>(block));
    if (header->magic != kHeapMagic) {
        return false;
    }
    out.value = header->user_value;
    out.flags = header->user_flags;
    out.flags_set_by_user = header->user_flags_set_by_user;
    return true;
}

bool heap_set_user_info(void* block, const HeapUserInfo& info) noexcept {
    if (!heap_owns(block)) {
        return false;
    }
    HeapHeader* header = header_of(block);
    if (header->magic != kHeapMagic) {
        return false;
    }
    header->user_value = info.value;
    // The flags the caller did not touch keep whatever allocator-set value
    // they had: the user flags and the allocator's own bits share the
    // field, and the mask is what says which half a write reaches.
    header->user_flags = info.flags;
    header->user_flags_set_by_user = info.flags_set_by_user;
    return true;
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
    if (!heap_is_ours(block)) {
        // A second free of the same block lands here too: the block came off
        // the list at the first free, so the second one is refused without
        // reading the header of memory this allocator has already handed
        // back to malloc.
        return false;
    }
    const HeapHeader* header = header_of(block);
    if (header->magic != kHeapMagic) {
        return false;
    }
    heap_forget(block);
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

int host_vformat(std::string& text, const char* fmt,
                 const void* ms_slots) noexcept {
    if (fmt == nullptr || ms_slots == nullptr) {
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
    char* raw = nullptr;
    std::size_t length = 0;
    std::FILE* mem = ::open_memstream(&raw, &length);
    if (mem == nullptr) {
        return -1;
    }
    va_list ap;
    static_assert(sizeof(ap) == sizeof(SysvVaList),
                  "the host descriptor must be the ABI's");
    __builtin_memcpy(&ap, &built, sizeof(ap));
    // The format is not a literal, and that is the design rather than an
    // oversight: it is built above from the guest's own format string,
    // conversion by conversion, and the rebuild is what makes the call safe
    // -- every conversion the guest wrote was read against the descriptor
    // it will consume, so what reaches the host is a format whose
    // conversions match the arguments behind it.
    //
    // A warning about non-literal formats is right in general and wrong
    // here, so it is turned off for this call rather than for the file. The
    // guard is Clang's because Clang is the compiler that raises it: GCC
    // accepts the same call without a diagnostic, which is one of the
    // differences between the two that `docs/BUILD.md` keeps a list of.
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif
    const int written = ::vfprintf(mem, rebuilt.c_str(), ap);
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
    ::fclose(mem);
    if (written < 0 || raw == nullptr) {
        ::free(raw);
        return -1;
    }
    text.assign(raw, length);
    ::free(raw);
    return written;
}

int host_vfprintf(std::FILE* stream, const char* fmt,
                  const void* ms_slots) noexcept {
    if (stream == nullptr) {
        return -1;
    }
    // The formatted text is the guest's own; the delivery is the CRT's
    // text mode, which stands between the format and the stream: a
    // newline leaves as a carriage return and a newline, the way the
    // Windows CRT hands bytes to WriteFile. The answer the guest sees is
    // still the format's own count -- the carriage returns are the
    // stream's doing, not characters the format produced.
    std::string text;
    const int written = host_vformat(text, fmt, ms_slots);
    if (written < 0) {
        return -1;
    }
    const std::string delivered = text_mode_expand(text.data(), text.size());
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
        // A file handle this runtime issued: the descriptor it names rides
        // above a base the standard handles never reach.
        if (handle >= kFileHandleBase && handle < kFileHandleBase + 0x100000) {
            return static_cast<int>(handle - kFileHandleBase);
        }
        return -1;
    }
}

[[nodiscard]] GuestState* require_state() noexcept {
    return g_guest;
}

// The error a host caller reads when there is no guest thread to store it
// in. A test, or a tool that reaches the same thunks, has no TEB, and
// without this the pair would be a write nothing reads followed by a read
// that always answers zero -- which is a worse answer than a process-wide
// slot, because it looks like a real error code of zero.
std::uint32_t g_host_last_error = 0;

// The stream a CRT file function receives is the host's own FILE* when it
// came from the host's fopen, and a position in the guest's iob table when
// the guest spells one of its three standard streams. With a guest running
// the table is where the translation happens; without one -- a host tool
// reaching the same thunks -- every pointer is already a host FILE*, and
// the pass-through is the whole of the answer.
[[nodiscard]] std::FILE* resolve_stream(std::uint64_t stream) noexcept {
    const GuestState* g = require_state();
    return g == nullptr ? reinterpret_cast<std::FILE*>(stream)
                        : translate_stream(*g, stream);
}

// The data exports. Their addresses are the whole of the answer; the
// variables live for the process and their values are whatever the guest's
// startup leaves in them.
int g_fmode = 0;
int g_commode = 0;
char** g_initenv = nullptr;

// Windows' FILE carries a text mode in both directions: writes expand,
// and reads press a carriage return and a newline back into one newline.
// The host's FILE has no such concept, so the mode the fopen named -- or
// the `_fmode` default when it named neither -- is recorded here, and the
// read path takes it from there.
struct FileMode {
    bool text = false;
};

std::mutex g_file_mode_mutex;
std::unordered_map<const void*, FileMode> g_file_modes;

// The mode a stream travels in: the ones fopen recorded answer from their
// entry, and the ones that predate any fopen -- the guest's stdout and
// stderr among them -- are text, which is what the Windows CRT starts a
// console stream in.
[[nodiscard]] bool stream_is_text(std::FILE* stream) noexcept {
    const std::lock_guard<std::mutex> lock(g_file_mode_mutex);
    const auto it = g_file_modes.find(stream);
    return it == g_file_modes.end() || it->second.text;
}

void note_file_mode(const void* stream, const char* mode) noexcept {
    bool text = true;
    bool named = false;
    if (mode != nullptr) {
        for (const char* m = mode; *m != '\0'; ++m) {
            if (*m == 'b') {
                text = false;
                named = true;
                break;
            }
            if (*m == 't') {
                text = true;
                named = true;
                break;
            }
        }
    }
    if (!named) {
        // The `_fmode` default answers when the mode names neither
        // spelling; O_BINARY is the one value that flips it.
        text = g_fmode != 0x8000;
    }
    const std::lock_guard<std::mutex> lock(g_file_mode_mutex);
    g_file_modes[stream] = FileMode{text};
}

void forget_file_mode(const void* stream) noexcept {
    const std::lock_guard<std::mutex> lock(g_file_mode_mutex);
    g_file_modes.erase(stream);
}

// ---- the process environment --------------------------------------------
//
// The environment the guest starts with is the one the runtime was handed
// in `options.environment`, and the startup's `__getmainargs` hands the
// guest that same table through `__initenv` and `_environ`. What the guest
// changes afterwards cannot go into that frozen table, so the changes land
// here: an override map for the names a call set, a deleted set for the
// ones it cleared, and a flat table rebuilt from the three of them every
// time either changes -- the same shape `_environ` has on Windows, where a
// program that walks it sees the merged truth.

std::mutex g_env_mutex;
std::map<std::string, std::string> g_env_overrides;
std::set<std::string> g_env_deleted;
std::vector<std::string> g_env_storage;
std::vector<char*> g_env_flat;
char** g_environ_ptr = nullptr;

// "NAME=VALUE" spells its name in the part before the first '='; a form
// without one has no name this table can carry.
[[nodiscard]] std::string environment_name_of(const char* entry) noexcept {
    const char* equals = ::strchr(entry, '=');
    return equals == nullptr ? std::string(entry)
                             : std::string(entry, static_cast<std::size_t>(
                                                          equals - entry));
}

// The caller holds the mutex. Base entries first -- first spelling wins,
// as it does on Windows -- each carrying its override if one exists and
// nothing at all if it was deleted; then the names the base never had.
void rebuild_environment(const GuestState& g) noexcept {
    g_env_storage.clear();
    g_env_flat.clear();
    std::set<std::string> carried;
    for (const char* entry : g.env_table) {
        if (entry == nullptr) {
            break;
        }
        const std::string name = environment_name_of(entry);
        if (carried.count(name) > 0) {
            continue;
        }
        carried.insert(name);
        const auto over = g_env_overrides.find(name);
        if (over != g_env_overrides.end()) {
            g_env_storage.push_back(name + "=" + over->second);
        } else if (g_env_deleted.count(name) == 0) {
            g_env_storage.push_back(entry);
        }
    }
    for (const auto& [name, value] : g_env_overrides) {
        if (carried.count(name) == 0) {
            g_env_storage.push_back(name + "=" + value);
        }
    }
    g_env_flat.reserve(g_env_storage.size() + 1);
    for (const std::string& entry : g_env_storage) {
        // The flat table is what `_environ` spells, and `_environ` is
        // `char**` on Windows; the storage itself stays const-owned here.
        g_env_flat.push_back(const_cast<char*>(entry.data()));
    }
    g_env_flat.push_back(nullptr);
    g_environ_ptr = g_env_flat.data();
}

// The value a name spells right now. Without a guest there is no table of
// this runtime's own -- a host tool reaches the same thunks, and the
// host's own environment is the environment it means.
[[nodiscard]] char* lookup_environment(const char* name) noexcept {
    const GuestState* g = require_state();
    if (g == nullptr) {
        return ::getenv(name);
    }
    if (name == nullptr) {
        return nullptr;
    }
    const std::lock_guard<std::mutex> lock(g_env_mutex);
    if (g_env_flat.empty() && !g->env_table.empty()) {
        rebuild_environment(*g);
    }
    const std::size_t length = ::strlen(name);
    for (char* entry : g_env_flat) {
        if (entry == nullptr) {
            break;
        }
        if (::strncmp(entry, name, length) == 0 && entry[length] == '=') {
            return entry + length + 1;
        }
    }
    return nullptr;
}

// ---- the clock and the calendar ------------------------------------------
//
// Windows' `clock` counts *wall* time since the process started, in
// thousandths of a second, and wraps with its 32-bit answer the same way
// the real library does; the host's `clock` counts processor time in
// millionths, which is a different quantity under the same name. The boot
// mark below is taken when this translation unit loads -- the earliest a
// static initializer in the guest-facing side can run, and close enough to
// the process start no guest code could have observed the difference.
const std::chrono::steady_clock::time_point g_boot_steady =
    std::chrono::steady_clock::now();

// `localtime` and `gmtime` answer a pointer to a `struct tm` the library
// owns; the guest's struct carries the same nine ints the host's does, so
// the answer is this static copy, and the mutex makes the shared-buffer
// race behave the way the real library's single-threaded answer does.
std::mutex g_time_mutex;
int g_guest_tm[9] = {};
char g_ctime_buffer[26] = {};

// The bridge in both directions. Host and guest agree on the nine ints --
// seconds, minutes, hours, month day, month, years since 1900, week day,
// year day, DST flag -- and the host's struct carries two fields more
// after them that the guest's does not know about.
void bridge_tm_out(const std::tm& host_tm, int* out) noexcept {
    out[0] = host_tm.tm_sec;
    out[1] = host_tm.tm_min;
    out[2] = host_tm.tm_hour;
    out[3] = host_tm.tm_mday;
    out[4] = host_tm.tm_mon;
    out[5] = host_tm.tm_year;
    out[6] = host_tm.tm_wday;
    out[7] = host_tm.tm_yday;
    out[8] = host_tm.tm_isdst;
}

void bridge_tm_in(const int* in, std::tm& host_tm) noexcept {
    host_tm = std::tm{};
    host_tm.tm_sec = in[0];
    host_tm.tm_min = in[1];
    host_tm.tm_hour = in[2];
    host_tm.tm_mday = in[3];
    host_tm.tm_mon = in[4];
    host_tm.tm_year = in[5];
    host_tm.tm_wday = in[6];
    host_tm.tm_yday = in[7];
    host_tm.tm_isdst = in[8];
    // %Z spells the zone name from here; the offset stays zero, which is
    // the UTC reading, since a nine-int struct carries no offset of its
    // own. `mktime` fills its own back below.
    host_tm.tm_zone = ::tzname[host_tm.tm_isdst > 0 ? 1 : 0];
}

// The line Windows' asctime spells: "Www Mmm dd hh:mm:ss yyyy\n", with the
// day of the month zero-padded -- the one place the host's own spelling
// differs, a space standing where Windows puts the zero. The weekday and
// month names come from the struct's own fields, exactly as the real
// library spells them.
void spell_ctime_line(const std::tm& broken, char* out) noexcept {
    static const char* const weekdays[7] = {
        "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static const char* const months[12] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    // The line is spelled into a roomy scratch first -- every int the
    // format names fits here whatever it carries -- and the first 26
    // bytes land in the caller's buffer, which is the exact width the
    // Windows answer has and the width a guest has to be ready for.
    char line[64] = {};
    ::snprintf(line, sizeof(line), "%.3s %.3s %02d %02d:%02d:%02d %04d\n",
               (broken.tm_wday >= 0 && broken.tm_wday < 7)
                   ? weekdays[broken.tm_wday]
                   : "   ",
               (broken.tm_mon >= 0 && broken.tm_mon < 12)
                   ? months[broken.tm_mon]
                   : "   ",
               broken.tm_mday, broken.tm_hour, broken.tm_min, broken.tm_sec,
               broken.tm_year + 1900);
    std::memcpy(out, line, 26);
    out[25] = '\0';
}

// ---- the guest's one-time initialization ---------------------------------

// The startup's own call wires the two data exports to the table the
// runtime was handed; until it runs, `_environ` spells null, which is what
// the real library's does before its startup too.
void wire_environment(const GuestState& g) noexcept {
    const std::lock_guard<std::mutex> lock(g_env_mutex);
    g_initenv = const_cast<char**>(g.env_table.data());
    if (g_env_flat.empty()) {
        rebuild_environment(g);
    }
}

void set_environment_value(const GuestState& g, const std::string& name,
                           const char* value) noexcept {
    const std::lock_guard<std::mutex> lock(g_env_mutex);
    if (value == nullptr || value[0] == '\0') {
        // Windows deletes the name when a set names no value or an empty
        // one; `_putenv` spells the same rule with "NAME=".
        g_env_overrides.erase(name);
        g_env_deleted.insert(name);
    } else {
        g_env_overrides[name] = value;
        g_env_deleted.erase(name);
    }
    rebuild_environment(g);
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

// ---- LoadLibrary and GetProcAddress ---------------------------------------
//
// The handle a LoadLibrary answers is this runtime's own small number,
// recorded beside the module name it stands for. The registry the guest's
// imports resolve through is the runner's, and a handle issued here is
// issued only for a module the same registry can name -- which is what
// keeps `GetProcAddress(handle, ...)` a lookup in the same table the
// import walk used, rather than a second answer that could disagree.
//
// The image's own module is its base, as `GetModuleHandle` already says,
// and a lookup there reads the exports the process builder copied from
// the image's own export directory.

namespace {

// The host modules this runtime implements, as the lookup `GetProcAddress`
// answers for a handle `LoadLibrary` issued. Filled when the host modules
// are registered, which is the one moment the same table is known to the
// registry and to the handle lookup; a name registered later would not be
// visible to either half of a load that already ran.
std::map<std::string, std::map<std::string, std::uint64_t>>&
own_export_index() noexcept {
    static std::map<std::string, std::map<std::string, std::uint64_t>> index;
    return index;
}

// A module name with its case folded, for use as a map key.
//
// Windows matches a module name without regard to case, so `kernel32.dll`,
// `KERNEL32.DLL` and `Kernel32.Dll` are one name. `module_basename` strips
// the path and leaves the case alone, which is right for the registry --
// an import table is compared against the spelling the module declares --
// and wrong for a key: a `std::map<std::string, ...>` built under
// `KERNEL32.dll` does not answer a lookup for `kernel32.dll`, and the
// `LoadLibraryA` below passes what the guest wrote rather than what the
// table holds. Folding here is what makes the two meet.
[[nodiscard]] std::string fold_module_name(std::string_view name) noexcept {
    std::string folded(name);
    for (char& c : folded) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return folded;
}

// The module name a LoadLibrary argument asks for: the bare name, folded
// the way the registry folds, because `LoadLibraryW("KERNEL32.DLL")` and
// `LoadLibraryW(L"C:\\Windows\\System32\\kernel32.dll")` are the same ask.
// The same name hands back the same handle, which is what a program that
// loads twice and compares the handles expects to see.
[[nodiscard]] std::uint64_t handle_for_library(GuestState& g,
                                               const std::string& bare) {
    for (const auto& [handle, name] : g.libraries) {
        if (name == bare) {
            return handle;
        }
    }
    const std::uint64_t handle =
        0x00005E1700000000ULL + g.next_library_handle * 0x1000ULL;
    ++g.next_library_handle;
    g.libraries.emplace(handle, bare);
    return handle;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint64_t k32_LoadLibraryA(
    const char* name) noexcept {
    GuestState* g = require_state();
    if (g == nullptr || name == nullptr || name[0] == '\0') {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::string bare = fold_module_name(module_basename(name));
    // A module this runtime implements is a handle the registry could have
    // named; anything else is a file this runtime has no spelling for.
    if (own_export_index().count(bare) != 0) {
        return handle_for_library(*g, bare);
    }
    set_last_error(kErrorModNotFound);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32_LoadLibraryW(
    const char16_t* name) noexcept {
    GuestState* g = require_state();
    if (g == nullptr || name == nullptr || name[0] == u'\0') {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string narrow;
    if (!utf16_to_utf8(std::u16string_view(name), narrow)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::string bare = fold_module_name(module_basename(narrow));
    if (own_export_index().count(bare) != 0) {
        return handle_for_library(*g, bare);
    }
    set_last_error(kErrorModNotFound);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32_LoadLibraryExW(
    const char16_t* name, void* file, std::uint32_t flags) noexcept {
    // The flags name search-path and sharing decisions this runtime does
    // not have; the module table is the whole of the answer either way.
    (void)file;
    (void)flags;
    return k32_LoadLibraryW(name);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32_GetProcAddress(
    std::uint64_t module, const char* name) noexcept {
    GuestState* g = require_state();
    if (g == nullptr || module == 0) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    // An ordinal ask travels as MAKEINTRESOURCE: the value is the ordinal
    // itself, and a real name is never that small.
    if (reinterpret_cast<std::uint64_t>(name) <= 0xFFFFULL) {
        const std::uint32_t ordinal =
            static_cast<std::uint32_t>(reinterpret_cast<std::uint64_t>(name));
        if (module == g->image_base) {
            for (const auto& entry : g->own_exports) {
                if (entry.ordinal == ordinal) {
                    return entry.address;
                }
            }
        }
        set_last_error(kErrorProcNotFound);
        return 0;
    }

    // The image's own module: the export directory the builder copied.
    if (module == g->image_base) {
        for (const auto& entry : g->own_exports) {
            if (entry.name == name) {
                return entry.is_forwarder ? entry.forwarder_text
                                          : entry.address;
            }
        }
        set_last_error(kErrorProcNotFound);
        return 0;
    }

    // A handle LoadLibrary issued: the host table under the name it was
    // issued for.
    const auto held = g->libraries.find(module);
    if (held == g->libraries.end()) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    const auto module_exports = own_export_index().find(held->second);
    if (module_exports == own_export_index().end()) {
        set_last_error(kErrorProcNotFound);
        return 0;
    }
    const auto found = module_exports->second.find(name);
    if (found == module_exports->second.end()) {
        set_last_error(kErrorProcNotFound);
        return 0;
    }
    return found->second;
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
    // The same two paths as the writer, so that a guest and a host caller
    // each read back what they set.
    if (require_state() == nullptr) {
        return g_host_last_error;
    }
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

extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetThreadId(
    std::uint64_t thread) noexcept {
    // One thread runs the guest, so the handle's only interesting property
    // is whether it names that thread: the current pseudo-handle does, and
    // so does the answer `GetCurrentThread` gave. A null handle names
    // nothing, which is the zero Windows answers.
    if (thread == 0) {
        return 0;
    }
    return guest_thread_id();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_IsDebuggerPresent() noexcept {
    return 0;
}

// ---- the environment, the kernel32 spelling ------------------------------
//
// The narrow call answers the character count of the value, not counting
// the terminator, and answers zero twice over: when the name has no value
// (and the last error says which of "not found" and "found but empty"
// it was), and when the caller's buffer would not have held it -- that
// one is the count the caller needed, terminator included. Setting a name
// to an empty value deletes it, the way the real call does.

extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetEnvironmentVariableA(
    const char* name, char* buffer, std::uint32_t size) noexcept {
    const char* value = lookup_environment(name);
    if (value == nullptr) {
        set_last_error(kErrorEnvVarNotFound);
        return 0;
    }
    const std::uint64_t length = ::strlen(value);
    if (length == 0) {
        set_last_error(0);
        return 0;
    }
    if (length + 1 > size) {
        set_last_error(kErrorInsufficientBuffer);
        return static_cast<std::uint32_t>(length + 1);
    }
    if (buffer != nullptr) {
        ::memcpy(buffer, value, length + 1);
    }
    set_last_error(0);
    return static_cast<std::uint32_t>(length);
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetEnvironmentVariableW(
    const char16_t* name, char16_t* buffer, std::uint32_t size) noexcept {
    std::string narrow_name;
    if (!utf16_to_utf8(name == nullptr ? std::u16string_view()
                                       : std::u16string_view(name),
                       narrow_name)) {
        set_last_error(kErrorEnvVarNotFound);
        return 0;
    }
    const char* value = lookup_environment(narrow_name.c_str());
    if (value == nullptr) {
        set_last_error(kErrorEnvVarNotFound);
        return 0;
    }
    std::u16string wide;
    if (!utf8_to_utf16(std::string_view(value), wide)) {
        set_last_error(0);
        return 0;
    }
    if (wide.empty()) {
        set_last_error(0);
        return 0;
    }
    if (wide.size() + 1 > size) {
        set_last_error(kErrorInsufficientBuffer);
        return static_cast<std::uint32_t>(wide.size() + 1);
    }
    if (buffer != nullptr) {
        ::memcpy(buffer, wide.data(), (wide.size() + 1) * sizeof(char16_t));
    }
    set_last_error(0);
    return static_cast<std::uint32_t>(wide.size());
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_SetEnvironmentVariableA(
    const char* name, const char* value) noexcept {
    if (name == nullptr || name[0] == '\0' || ::strchr(name, '=') != nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const GuestState* g = require_state();
    if (g == nullptr) {
        // A host tool speaks to the host's own environment, the same way
        // its getenv does.
        if (value == nullptr || value[0] == '\0') {
            ::unsetenv(name);
        } else {
            ::setenv(name, value, 1);
        }
        set_last_error(0);
        return 1;
    }
    set_environment_value(*g, name, value);
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_SetEnvironmentVariableW(
    const char16_t* name, const char16_t* value) noexcept {
    std::string narrow_name;
    std::string narrow_value;
    if (name != nullptr &&
        !utf16_to_utf8(std::u16string_view(name), narrow_name)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (value != nullptr &&
        !utf16_to_utf8(std::u16string_view(value), narrow_value)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return k32_SetEnvironmentVariableA(
        narrow_name.c_str(),
        value == nullptr ? nullptr : narrow_value.c_str());
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

// The handle table for the file handles this runtime issued. A handle that
// is on it names a descriptor `CreateFile` opened, and `CloseHandle` ends
// it; a handle that is not is the console's or the pseudo-handles, which
// outlive the call.
std::mutex g_file_handle_mutex;
std::set<std::uint64_t> g_k32_file_handles;

[[nodiscard]] bool take_file_handle(std::uint64_t handle) noexcept {
    const std::lock_guard<std::mutex> held(g_file_handle_mutex);
    return g_k32_file_handles.erase(handle) != 0;
}

void add_file_handle(std::uint64_t handle) noexcept {
    const std::lock_guard<std::mutex> held(g_file_handle_mutex);
    g_k32_file_handles.insert(handle);
}

// `CreateFileA`. The disposition maps onto the host's open flags, the
// access onto the read/write bits, and the name through the same DOS-path
// translation the CRT spellings use. Share modes, security attributes and
// the template file are a single-open-at-a-time world's absent features,
// and a disposition this table does not name is a call that fails with the
// error Windows would give a malformed one.
extern "C" __attribute__((ms_abi)) void* k32_CreateFileA(
    const char* name, std::uint32_t access, std::uint32_t share,
    void* security, std::uint32_t disposition, std::uint32_t flags,
    void* template_file) noexcept {
    (void)share;
    (void)security;
    (void)flags;
    (void)template_file;
    if (name == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return reinterpret_cast<void*>(kCurrentProcessHandle);
    }
    const bool want_read =
        (access & 0x80000000u) != 0;  // GENERIC_READ
    const bool want_write =
        (access & 0x40000000u) != 0;  // GENERIC_WRITE
    int host_flags = 0;
    switch (disposition) {
    case 1:  // CREATE_NEW
        host_flags = O_CREAT | O_EXCL;
        break;
    case 2:  // CREATE_ALWAYS
        host_flags = O_CREAT | O_TRUNC;
        break;
    case 3:  // OPEN_EXISTING
        break;
    case 4:  // OPEN_ALWAYS
        host_flags = O_CREAT;
        break;
    case 5:  // TRUNCATE_EXISTING
        host_flags = O_TRUNC;
        break;
    default:
        set_last_error(kErrorInvalidParameter);
        return reinterpret_cast<void*>(kCurrentProcessHandle);
    }
    if (want_read && want_write) {
        host_flags |= O_RDWR;
    } else if (want_write) {
        host_flags |= O_WRONLY;
    } else {
        host_flags |= O_RDONLY;
    }
    const int fd = ::open(from_dos_path(name).c_str(), host_flags, 0666);
    if (fd < 0) {
        set_last_error(errno == ENOENT ? kErrorFileNotFound
                                       : kErrorInvalidParameter);
        return reinterpret_cast<void*>(kCurrentProcessHandle);
    }
    const std::uint64_t handle = kFileHandleBase + static_cast<std::uint64_t>(fd);
    add_file_handle(handle);
    return reinterpret_cast<void*>(handle);
}

// `ReadFile`. A read at the end of the file is Windows' own success: TRUE
// with nothing transferred, which is what lets a caller loop until `got`
// comes back zero.
extern "C" __attribute__((ms_abi)) std::int32_t k32_ReadFile(
    std::uint64_t handle, void* buffer, std::uint32_t to_read,
    std::uint32_t* read_out, void* overlapped) noexcept {
    if (overlapped != nullptr) {
        set_last_error(kErrorNotSupported);
        return 0;
    }
    const int fd = fd_for_handle(handle);
    if (fd < 0 || buffer == nullptr) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    ::ssize_t got = 0;
    do {
        got = ::read(fd, buffer, to_read);
    } while (got < 0 && errno == EINTR);
    if (got < 0) {
        set_last_error(kErrorInvalidHandle);
        if (read_out != nullptr) {
            *read_out = 0;
        }
        return 0;
    }
    if (read_out != nullptr) {
        *read_out = static_cast<std::uint32_t>(got);
    }
    return 1;
}

// `GetFileSizeEx`: the descriptor's own size, with the position the read
// left untouched.
extern "C" __attribute__((ms_abi)) std::int32_t k32_GetFileSizeEx(
    std::uint64_t handle, void* size_out) noexcept {
    const int fd = fd_for_handle(handle);
    if (fd < 0 || size_out == nullptr) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    struct ::stat info;
    if (::fstat(fd, &info) != 0) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    __builtin_memcpy(size_out, &info.st_size, sizeof(info.st_size));
    return 1;
}

// `DeleteFileA`: the unlink, through the same path translation. A file the
// caller still holds open elsewhere is this filesystem's business, not the
// call's.
extern "C" __attribute__((ms_abi)) std::int32_t k32_DeleteFileA(
    const char* name) noexcept {
    if (name == nullptr || ::unlink(from_dos_path(name).c_str()) != 0) {
        set_last_error(errno == ENOENT ? kErrorFileNotFound
                                       : kErrorInvalidParameter);
        return 0;
    }
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_CloseHandle(
    std::uint64_t handle) noexcept {
    // A file handle this runtime issued ends its descriptor. An object
    // handle ends its table entry. The standard handles belong to the
    // console and outlive the call, and a handle that names nothing is
    // answered as Windows answers a valid handle with no resources behind
    // it: successfully.
    if (take_file_handle(handle)) {
        const int fd = static_cast<int>(handle - kFileHandleBase);
        ::close(fd);
        return 1;
    }
    (void)objects::close(handle);
    return 1;
}

// ---- the synchronization objects ----------------------------------------
//
// A handle from this section is an index into the object table in
// `runtime/objects.cpp`, above every file handle, so the two namespaces
// cannot be mistaken for one another and `CloseHandle` can tell which one a
// value came from without consulting a table that holds both.
//
// What each function does with the handle is the Windows contract and
// nothing more. `CreateEvent` with a null name is an anonymous event, one
// nothing else can open; `SetEvent` marks an event signalled and releases a
// waiter; `WaitForSingleObject` is the one call here that can block, and it
// blocks on this runtime's own object table rather than on a kernel object,
// because the object is this runtime's.

constexpr std::uint32_t kWaitObject0 = 0x00000000u;
constexpr std::uint32_t kWaitTimeout = 0x00000102u;
constexpr std::uint32_t kWaitFailed = 0xFFFFFFFFu;

// The two `CreateEvent` spellings differ in the type of the name and in
// nothing else, and a named event is not implemented. A name is a
// cross-process key -- it is how a program asks for an event another
// process already made -- and this runtime has no namespace to put one in.
// The refusal is the honest answer to a request for one: `ERROR_NOT_SUPPORTED`
// and a null handle, rather than an anonymous event quietly standing in for
// the named one that was asked for.
[[nodiscard]] std::uint64_t create_event_checked(
    std::int32_t manual_reset, std::int32_t initial_state,
    bool named) noexcept {
    if (named) {
        set_last_error(kErrorNotSupported);
        return 0;
    }
    const std::uint64_t handle =
        objects::create_event(manual_reset != 0, initial_state != 0);
    if (handle == 0) {
        set_last_error(kErrorNotSupported);
    }
    return handle;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32_CreateEventA(
    std::uint64_t attributes, std::int32_t manual_reset,
    std::int32_t initial_state, const char* name) noexcept {
    (void)attributes;
    return create_event_checked(manual_reset, initial_state, name != nullptr);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32_CreateEventW(
    std::uint64_t attributes, std::int32_t manual_reset,
    std::int32_t initial_state, const char16_t* name) noexcept {
    (void)attributes;
    return create_event_checked(manual_reset, initial_state, name != nullptr);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_SetEvent(
    std::uint64_t handle) noexcept {
    if (objects::set_event(handle)) {
        return 1;
    }
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_ResetEvent(
    std::uint64_t handle) noexcept {
    if (objects::reset_event(handle)) {
        return 1;
    }
    set_last_error(kErrorInvalidHandle);
    return 0;
}

// The status `WaitForSingleObject` answers with, from the outcome the object
// table reports. The three outcomes are three different statuses rather
// than one failure, because a program distinguishes them: a timeout is a
// poll that found nothing, and an invalid handle is a bug in the caller.
[[nodiscard]] std::uint32_t wait_status(objects::WaitOutcome outcome) noexcept {
    switch (outcome) {
    case objects::WaitOutcome::Signalled:
        return kWaitObject0;
    case objects::WaitOutcome::TimedOut:
        return kWaitTimeout;
    case objects::WaitOutcome::NoSuchObject:
        break;
    }
    set_last_error(kErrorInvalidHandle);
    return kWaitFailed;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32_WaitForSingleObject(
    std::uint64_t handle, std::uint32_t milliseconds) noexcept {
    return wait_status(objects::wait_one(handle, milliseconds));
}

// The alertable variant. This runtime delivers no asynchronous procedure
// calls, so there is nothing a wait could be alerted by, and a caller that
// asked for alertable waiting gets the same wait. The alternative -- a
// wait that returned `WAIT_IO_COMPLETION` for an APC this runtime cannot
// run -- would be a status no program could act on.
extern "C" __attribute__((ms_abi)) std::uint32_t k32_WaitForSingleObjectEx(
    std::uint64_t handle, std::uint32_t milliseconds,
    std::int32_t alertable) noexcept {
    (void)alertable;
    return wait_status(objects::wait_one(handle, milliseconds));
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

extern "C" __attribute__((ms_abi)) std::int32_t k32_TryEnterCriticalSection(
    void* cs) noexcept {
    // Enter without the wait: the same fields, read once. Free means the
    // exchange takes it; held by this thread means the recursion count
    // climbs and the try succeeds, the way an Enter from the owner would;
    // held by anyone else means the answer is no, without the sleep an
    // Enter would reach.
    if (cs == nullptr) {
        return 0;
    }
    const std::uint64_t self = guest_thread_id();
    std::uint64_t owner = 0;
    __builtin_memcpy(&owner, static_cast<char*>(cs) + 16, sizeof(owner));
    if (owner == self && owner != 0) {
        std::uint32_t recursion = 0;
        __builtin_memcpy(&recursion, static_cast<char*>(cs) + 12,
                         sizeof(recursion));
        ++recursion;
        __builtin_memcpy(static_cast<char*>(cs) + 12, &recursion,
                         sizeof(recursion));
        return 1;
    }
    std::uint32_t state = 0;
    __builtin_memcpy(&state, static_cast<char*>(cs) + 8, sizeof(state));
    std::uint32_t desired = state | kCsLockedBit;
    if ((state & kCsWakeupBit) == 0) {
        desired |= kCsWakeupBit;
    }
    if (cs_compare_exchange(cs, state, desired) == state) {
        std::uint64_t own = self;
        __builtin_memcpy(static_cast<char*>(cs) + 16, &own, sizeof(own));
        std::uint32_t one = 1;
        __builtin_memcpy(static_cast<char*>(cs) + 12, &one, sizeof(one));
        return 1;
    }
    return 0;
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
    return process_heap_handle();
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
    // A negative target length is not a small buffer and not a large one:
    // Windows refuses the call outright. Widening it to unsigned would
    // turn it into the larger number of the two, which reads as a buffer
    // big enough for anything -- and the copy below would then write past
    // the end of whatever the caller really had.
    if (target_length < 0 ||
        static_cast<std::size_t>(target_length) < needed) {
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
    // The same refusal the other direction makes: a negative length is
    // Windows' "the buffer is not usable", and reading it as unsigned
    // would make it the largest value of the type, which no buffer is
    // shorter than.
    if (target_length < 0 ||
        static_cast<std::size_t>(target_length) < needed) {
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
    // The same table is what `__initenv` and `_environ` spell until a
    // `_putenv` rebuilds the flat one over it.
    wire_environment(*g);
    return 0;
}

// ---- the calendar --------------------------------------------------------
//
// The guest's `time_t` is the host's -- sixty-four bits of seconds from
// the epoch, which is the same answer Windows' 64-bit `time` gives -- and
// the calendar calls are the host's own, bridged through the nine ints
// both sides spell a `struct tm` with.

extern "C" __attribute__((ms_abi)) std::int64_t cr_time(
    std::int64_t* store) noexcept {
    const std::time_t now = ::time(nullptr);
    if (store != nullptr) {
        *store = static_cast<std::int64_t>(now);
    }
    return static_cast<std::int64_t>(now);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_clock() noexcept {
    const auto milliseconds = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - g_boot_steady)
            .count());
    // Windows answers a 32-bit long here, and a long enough run wraps it;
    // the truncation is the same answer the real library would give.
    return static_cast<std::int32_t>(milliseconds);
}

extern "C" __attribute__((ms_abi)) void* cr_localtime(
    const std::int64_t* timer) noexcept {
    if (timer == nullptr) {
        return nullptr;
    }
    std::tm broken;
    const std::time_t when = static_cast<std::time_t>(*timer);
    const std::lock_guard<std::mutex> lock(g_time_mutex);
    if (::localtime_r(&when, &broken) == nullptr) {
        return nullptr;
    }
    bridge_tm_out(broken, g_guest_tm);
    return g_guest_tm;
}

extern "C" __attribute__((ms_abi)) void* cr_gmtime(
    const std::int64_t* timer) noexcept {
    if (timer == nullptr) {
        return nullptr;
    }
    std::tm broken;
    const std::time_t when = static_cast<std::time_t>(*timer);
    const std::lock_guard<std::mutex> lock(g_time_mutex);
    if (::gmtime_r(&when, &broken) == nullptr) {
        return nullptr;
    }
    bridge_tm_out(broken, g_guest_tm);
    return g_guest_tm;
}

extern "C" __attribute__((ms_abi)) std::int64_t cr_mktime(
    void* broken_down) noexcept {
    if (broken_down == nullptr) {
        errno = EINVAL;
        return -1;
    }
    auto* fields = static_cast<int*>(broken_down);
    std::tm broken;
    bridge_tm_in(fields, broken);
    const std::time_t answer = ::mktime(&broken);
    // mktime normalizes the struct either way -- a time it cannot name
    // still tells the caller which day of the week it would have been --
    // and the Windows one writes the nine fields back the same way.
    bridge_tm_out(broken, fields);
    return static_cast<std::int64_t>(answer);
}

extern "C" __attribute__((ms_abi)) std::int64_t cr__mkgmtime(
    void* broken_down) noexcept {
    if (broken_down == nullptr) {
        errno = EINVAL;
        return -1;
    }
    auto* fields = static_cast<int*>(broken_down);
    std::tm broken;
    bridge_tm_in(fields, broken);
    const std::time_t answer = ::timegm(&broken);
    bridge_tm_out(broken, fields);
    return static_cast<std::int64_t>(answer);
}

extern "C" __attribute__((ms_abi)) std::uint64_t cr_strftime(
    char* buffer, std::uint64_t max, const char* format,
    const void* broken_down) noexcept {
    if (buffer == nullptr || max == 0 || format == nullptr ||
        broken_down == nullptr) {
        return 0;
    }
    std::tm broken;
    ::tzset();
    bridge_tm_in(static_cast<const int*>(broken_down), broken);
    // The format is the guest's own spelling -- its correctness is the
    // guest's contract with its users, not something this side re-checks.
    // The call goes through the pointer because the compiler's literal
    // check applies to direct calls only.
    static constexpr auto host_strftime = ::strftime;
    const std::size_t written = host_strftime(
        buffer, static_cast<std::size_t>(max), format, &broken);
    return static_cast<std::uint64_t>(written);
}

extern "C" __attribute__((ms_abi)) double cr_difftime(
    std::int64_t later, std::int64_t earlier) noexcept {
    return ::difftime(static_cast<std::time_t>(later),
                      static_cast<std::time_t>(earlier));
}

extern "C" __attribute__((ms_abi)) char* cr_ctime(
    const std::int64_t* timer) noexcept {
    if (timer == nullptr) {
        return nullptr;
    }
    std::tm broken;
    const std::time_t when = static_cast<std::time_t>(*timer);
    const std::lock_guard<std::mutex> lock(g_time_mutex);
    // ctime is asctime over localtime's reading, and both halves of that
    // answer spell the Windows line.
    if (::localtime_r(&when, &broken) == nullptr) {
        return nullptr;
    }
    spell_ctime_line(broken, g_ctime_buffer);
    return g_ctime_buffer;
}

extern "C" __attribute__((ms_abi)) char* cr_asctime(
    const void* broken_down) noexcept {
    if (broken_down == nullptr) {
        return nullptr;
    }
    std::tm broken;
    bridge_tm_in(static_cast<const int*>(broken_down), broken);
    const std::lock_guard<std::mutex> lock(g_time_mutex);
    spell_ctime_line(broken, g_ctime_buffer);
    return g_ctime_buffer;
}

// ---- the environment, the C spelling -------------------------------------

extern "C" __attribute__((ms_abi)) char* cr_getenv(
    const char* name) noexcept {
    return lookup_environment(name);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr__putenv(
    const char* text) noexcept {
    if (text == nullptr) {
        return -1;
    }
    const char* equals = ::strchr(text, '=');
    if (equals == nullptr || equals == text) {
        // Windows answers failure for a form with no name or no equals;
        // a bare name is not a spelling this contract carries.
        return -1;
    }
    const std::string name(text, static_cast<std::size_t>(equals - text));
    const GuestState* g = require_state();
    if (g == nullptr) {
        // The host's own environment, the way a host tool's getenv reads.
        if (equals[1] == '\0') {
            return ::unsetenv(name.c_str()) == 0 ? 0 : -1;
        }
        return ::setenv(name.c_str(), equals + 1, 1) == 0 ? 0 : -1;
    }
    set_environment_value(*g, name, equals + 1);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr__putenv_s(
    const char* name, const char* value) noexcept {
    if (name == nullptr || name[0] == '\0' ||
        ::strchr(name, '=') != nullptr) {
        return -1;
    }
    const GuestState* g = require_state();
    if (g == nullptr) {
        if (value == nullptr) {
            return ::unsetenv(name) == 0 ? 0 : -1;
        }
        return ::setenv(name, value, 1) == 0 ? 0 : -1;
    }
    set_environment_value(*g, name, value);
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

// The one spelling of the process heap's handle. `GetProcessHeap` answers
// with it, and the PEB's heap list is filled from this rather than from a
// second copy of the number, so a guest that enumerates the heaps and then
// asks for the process heap finds the same one both times.
std::uint64_t process_heap_handle() noexcept {
    return kProcessHeapHandle;
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
    if (stream == nullptr) {
        return -1;
    }
    // A character going out through the CRT travels in the stream's text
    // mode: a newline becomes a carriage return and a newline, exactly as
    // the Windows CRT's own fputc delivers it. WriteFile never sees this
    // path, and the guest's return value is still the character, not the
    // bytes the expansion added.
    const unsigned char byte = static_cast<unsigned char>(c);
    std::FILE* target = resolve_stream(
        reinterpret_cast<std::uint64_t>(stream));
    if (stream_is_text(target)) {
        const std::string expanded =
            text_mode_expand(reinterpret_cast<const char*>(&byte), 1);
        if (::fwrite(expanded.data(), 1, expanded.size(), target) !=
            expanded.size()) {
            return -1;
        }
    } else if (::fwrite(&byte, 1, 1, target) != 1) {
        return -1;
    }
    return byte;
}

extern "C" __attribute__((ms_abi)) std::uint64_t cr_fwrite(
    const void* buffer, std::uint64_t size, std::uint64_t count,
    void* stream) noexcept {
    if (size == 0 || count == 0 || count > SIZE_MAX / size) {
        return 0;
    }
    const auto* bytes = static_cast<const char*>(buffer);
    const std::size_t requested = static_cast<std::size_t>(size * count);
    std::FILE* target = resolve_stream(
        reinterpret_cast<std::uint64_t>(stream));
    // Bytes going out through the CRT travel in the stream's text mode,
    // which a binary file does not name: newlines expand only where the
    // mode says they do. The item count the guest sees is its own -- walk
    // its buffer back through the expansion, and how many of its bytes
    // fit in what the host took, carriages and all, is how many of its
    // items were written.
    const bool text = stream_is_text(target);
    const std::string expanded =
        text ? text_mode_expand(bytes, requested)
             : std::string(bytes, requested);
    const std::size_t written =
        ::fwrite(expanded.data(), 1, expanded.size(), target);
    std::size_t taken = 0;
    if (text) {
        // The item count the guest sees is its own -- walk its buffer
        // back through the expansion, and how many of its bytes fit in
        // what the host took, carriages and all, is how many of its
        // items were written.
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
    } else {
        // A binary stream carries every byte as it is: the count the
        // host took is the count the guest's items were made of.
        taken = requested < written ? requested : written;
    }
    return static_cast<std::uint64_t>(taken / size);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_fputs(
    const char* text, void* stream) noexcept {
    if (text == nullptr || stream == nullptr) {
        return -1;
    }
    // A string through the CRT leaves in the stream's text mode, like any
    // CRT byte does; fputs adds no newline of its own, and the answer is
    // nonnegative on success, the way the Windows CRT answers.
    std::FILE* target = resolve_stream(
        reinterpret_cast<std::uint64_t>(stream));
    const std::string expanded =
        stream_is_text(target)
            ? text_mode_expand(text, ::strlen(text))
            : std::string(text, ::strlen(text));
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

extern "C" __attribute__((ms_abi)) void* cr_realloc(
    void* block, std::uint64_t bytes) noexcept {
    // The realloc contract is the C one: grow or shrink in place when the
    // heap can, move when it cannot, and answer null for a zero-byte ask
    // only because the host's own realloc does. A guest that treats the
    // answer as "the block, possibly elsewhere" is the only caller this
    // spelling has.
    return ::realloc(block, static_cast<std::size_t>(bytes));
}

extern "C" __attribute__((ms_abi)) void* cr_memchr(const void* haystack,
                                                   std::int32_t needle,
                                                   std::uint64_t bytes) noexcept {
    // The byte searched for is the low byte of the int, which is what both
    // the C standard and the Microsoft spelling say, and the length is the
    // whole of the argument -- a count the guest believes it owns. The
    // answer loses the const the search came in with, which is the C
    // function's own signature and the guest's own view of its memory.
    if (haystack == nullptr || bytes == 0) {
        return nullptr;
    }
    return const_cast<void*>(::memchr(haystack, static_cast<int>(needle),
                                      static_cast<std::size_t>(bytes)));
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

// Windows' `,ccs=<encoding>` extension names the stream's encoding, and
// the host's fopen refuses a mode it cannot parse. The runtime's narrow
// streams are already UTF-8 -- the same text every path arrives in -- so
// the extension names exactly what the host would give, and stripping it
// changes nothing the guest could observe.
std::string strip_ccs(const char* mode) noexcept {
    std::string out;
    if (mode != nullptr) {
        for (const char* m = mode; *m != '\0'; ++m) {
            if (*m == ',') {
                break;
            }
            out += *m;
        }
    }
    return out;
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

// --------------------------------------------------------------------------
// The CRT's stdio: the buffer spellings and the file spellings
// --------------------------------------------------------------------------
//
// The buffer spellings run the same format the stream spellings run, with
// no text mode after it -- a buffer has no mode, and a newline in one
// stays a newline, exactly as Windows' sprintf delivers it. The file
// spellings take the DOS paths the guest spells and the text mode the
// Windows CRT reads and writes files through: writes expand on the way to
// the host's FILE, and reads press the pair back into one newline, the
// pending carriage return carried across a read boundary because a
// program reading one byte at a time sees the same text one that reads
// the whole file sees.

// --- the buffer spellings ---

extern "C" __attribute__((ms_abi)) std::int32_t cr_vsprintf(
    char* buffer, const char* fmt, void* ms_slots) noexcept {
    std::string text;
    const int written = host_vformat(text, fmt, ms_slots);
    if (written < 0) {
        return -1;
    }
    ::memcpy(buffer, text.data(), text.size() + 1);  // the terminator rides
    return written;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_sprintf(
    char* buffer, const char* fmt, ...) noexcept {
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, fmt);
    void* slots = nullptr;
    __builtin_memcpy(&slots, &ap, sizeof(slots));
    const std::int32_t result = cr_vsprintf(buffer, fmt, slots);
    __builtin_ms_va_end(ap);
    return result;
}

// C99's snprintf: at most `count - 1` bytes plus the terminator, and the
// answer is the length the *whole* text would have had -- truncation is
// part of the answer, not an error.
extern "C" __attribute__((ms_abi)) std::int32_t cr_vsnprintf(
    char* buffer, std::uint64_t count, const char* fmt,
    void* ms_slots) noexcept {
    std::string text;
    const int written = host_vformat(text, fmt, ms_slots);
    if (written < 0) {
        return -1;
    }
    if (count != 0) {
        const std::size_t stored =
            text.size() < count - 1 ? text.size() : count - 1;
        ::memcpy(buffer, text.data(), stored);
        buffer[stored] = '\0';
    }
    return static_cast<std::int32_t>(text.size());
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_snprintf(
    char* buffer, std::uint64_t count, const char* fmt, ...) noexcept {
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, fmt);
    void* slots = nullptr;
    __builtin_memcpy(&slots, &ap, sizeof(slots));
    const std::int32_t result = cr_vsnprintf(buffer, count, fmt, slots);
    __builtin_ms_va_end(ap);
    return result;
}

// The Microsoft spellings. `_snprintf` differs from C99's in the one place
// C99 improved it: a text that fills its count leaves *no* terminator --
// the dangerous contract a program written to it relies on.
extern "C" __attribute__((ms_abi)) std::int32_t cr__vsnprintf(
    char* buffer, std::uint64_t count, const char* fmt,
    void* ms_slots) noexcept {
    std::string text;
    const int written = host_vformat(text, fmt, ms_slots);
    if (written < 0) {
        return -1;
    }
    if (count != 0) {
        const std::size_t stored =
            text.size() < count ? text.size() : count;
        ::memcpy(buffer, text.data(), stored);
        if (text.size() < count) {
            buffer[stored] = '\0';
        }
    }
    return static_cast<std::int32_t>(text.size());
}

extern "C" __attribute__((ms_abi)) std::int32_t cr__snprintf(
    char* buffer, std::uint64_t count, const char* fmt, ...) noexcept {
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, fmt);
    void* slots = nullptr;
    __builtin_memcpy(&slots, &ap, sizeof(slots));
    const std::int32_t result = cr__vsnprintf(buffer, count, fmt, slots);
    __builtin_ms_va_end(ap);
    return result;
}

// --- user32's wsprintf ----------------------------------------------------
//
// The simplified printf the window layer carries: integers and text, no
// floating point, and a wide spelling whose `%s` reads a UTF-16 string
// from the slot. The conversion walk runs here rather than through the
// rebuilt-format bridge, because the slots a wide `%s` reads point at
// UTF-16 text the narrow bridge would misread.

namespace {

// The output accumulator wsprintfW writes through. The contract the guest
// accepted when it chose this call is sprintf's -- the buffer is big
// enough -- so the writing is unbounded, the way the real call is.
struct WideOut {
    char16_t* cursor;
    std::size_t count = 0;

    void put(char16_t unit) noexcept {
        *cursor++ = unit;
        ++count;
    }

    void put_narrow(const char* text) noexcept {
        for (; *text != '\0'; ++text) {
            put(static_cast<char16_t>(*text));
        }
    }
};

// One conversion's field assembly: the digits it produced, the padding
// the width asks for, and the two fill styles -- a zero fill that lands
// after the minus sign, and blanks that land either side depending on the
// left-align flag.
void pad_field(WideOut& out, const std::string& digits, bool negative,
               int width, bool left, bool zero) noexcept {
    std::size_t body = digits.size() + (negative ? 1U : 0U);
    if (left) {
        if (negative) {
            out.put(u'-');
        }
        out.put_narrow(digits.c_str());
        while (body < static_cast<std::size_t>(width)) {
            out.put(u' ');
            ++body;
        }
    } else if (zero && static_cast<std::size_t>(width) > body) {
        if (negative) {
            out.put(u'-');
        }
        for (std::size_t i = body; i < static_cast<std::size_t>(width);
             ++i) {
            out.put(u'0');
        }
        out.put_narrow(digits.c_str());
    } else {
        while (body < static_cast<std::size_t>(width)) {
            out.put(u' ');
            ++body;
        }
        if (negative) {
            out.put(u'-');
        }
        out.put_narrow(digits.c_str());
    }
}

} // namespace

extern "C" __attribute__((ms_abi)) std::int32_t cr_wsprintfW(
    char16_t* buffer, const char16_t* fmt, ...) noexcept {
    if (buffer == nullptr || fmt == nullptr) {
        return 0;
    }
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, fmt);
    const std::uint64_t* slots = nullptr;
    __builtin_memcpy(&slots, &ap, sizeof(slots));
    std::size_t slot = 0;

    WideOut out{buffer};
    for (std::size_t i = 0; fmt[i] != u'\0';) {
        if (fmt[i] != u'%') {
            out.put(fmt[i]);
            ++i;
            continue;
        }
        ++i;
        if (fmt[i] == u'%') {
            out.put(u'%');
            ++i;
            continue;
        }
        // The flags, the width, the precision, and the length prefixes the
        // simplified contract carries -- minus and zero, an optional digit
        // run or a star, and l or the l64 spelling of a 64-bit argument.
        bool left = false;
        bool zero = false;
        for (;;) {
            if (fmt[i] == u'-') {
                left = true;
            } else if (fmt[i] == u'0') {
                zero = true;
            } else {
                break;
            }
            ++i;
        }
        int width = 0;
        if (fmt[i] == u'*') {
            ++i;
            width = static_cast<int>(slots[slot++] & 0xFFFFFFFFU);
        } else {
            while (fmt[i] >= u'0' && fmt[i] <= u'9') {
                width = width * 10 + static_cast<int>(fmt[i] - u'0');
                ++i;
            }
        }
        int precision = -1;
        if (fmt[i] == u'.') {
            ++i;
            precision = 0;
            if (fmt[i] == u'*') {
                ++i;
                precision = static_cast<int>(slots[slot++] & 0xFFFFFFFFU);
            } else {
                while (fmt[i] >= u'0' && fmt[i] <= u'9') {
                    precision = precision * 10 + static_cast<int>(fmt[i] - u'0');
                    ++i;
                }
            }
        }
        bool sixty_four = false;
        for (;;) {
            if (fmt[i] == u'l') {
                if (fmt[i + 1] == u'6' && fmt[i + 2] == u'4') {
                    sixty_four = true;
                    i += 2;
                }
            } else {
                break;
            }
            ++i;
        }
        const char16_t conversion = fmt[i];

        std::string text;
        switch (conversion) {
        case u'd':
        case u'i': {
            if (sixty_four) {
                text = std::to_string(
                    static_cast<std::int64_t>(slots[slot++]));
            } else {
                const std::int32_t value =
                    static_cast<std::int32_t>(slots[slot] & 0xFFFFFFFFU);
                ++slot;
                text = std::to_string(value);
            }
            break;
        }
        case u'u': {
            if (sixty_four) {
                text = std::to_string(slots[slot++]);
            } else {
                text = std::to_string(slots[slot] & 0xFFFFFFFFU);
                ++slot;
            }
            break;
        }
        case u'x':
        case u'X': {
            char raw[24] = {};
            if (sixty_four) {
                write_unsigned_radix(slots[slot++], 16, raw);
            } else {
                write_unsigned_radix(slots[slot] & 0xFFFFFFFFU, 16, raw);
                ++slot;
            }
            text = raw;
            if (conversion == u'X') {
                for (char& c : text) {
                    c = static_cast<char>(::toupper(static_cast<unsigned char>(c)));
                }
            }
            break;
        }
        case u'p': {
            char raw[24] = {};
            write_unsigned_radix(slots[slot++], 16, raw);
            text = raw;
            break;
        }
        case u'c': {
            const std::uint32_t value =
                static_cast<std::uint32_t>(slots[slot++] & 0xFFFFFFFFU);
            // The wide spelling of a character conversion answers the
            // UTF-16 unit the slot carries.
            const std::size_t width_used = static_cast<std::size_t>(width);
            if (!left) {
                for (std::size_t w = 1; w < width_used; ++w) {
                    out.put(u' ');
                }
            }
            out.put(static_cast<char16_t>(value));
            if (left) {
                for (std::size_t w = 1; w < width_used; ++w) {
                    out.put(u' ');
                }
            }
            ++i;
            continue;
        }
        case u'C': {
            const std::uint32_t value =
                static_cast<std::uint32_t>(slots[slot++] & 0xFFFFFFFFU);
            const std::size_t width_used = static_cast<std::size_t>(width);
            if (!left) {
                for (std::size_t w = 1; w < width_used; ++w) {
                    out.put(u' ');
                }
            }
            out.put(static_cast<char16_t>(value & 0xFFU));
            if (left) {
                for (std::size_t w = 1; w < width_used; ++w) {
                    out.put(u' ');
                }
            }
            ++i;
            continue;
        }
        case u's': {
            const std::uint64_t pointer = slots[slot++];
            // In the wide spelling `%s` is a wide string: the slot points
            // at UTF-16 text, whether or not an `l` prefix named it.
            const auto* units = reinterpret_cast<const char16_t*>(pointer);
            std::size_t length = 0;
            if (units != nullptr) {
                while (units[length] != u'\0') {
                    ++length;
                }
            }
            if (precision >= 0 &&
                static_cast<std::size_t>(precision) < length) {
                length = static_cast<std::size_t>(precision);
            }
            const std::size_t width_used = static_cast<std::size_t>(width);
            if (!left) {
                for (std::size_t w = length; w < width_used; ++w) {
                    out.put(u' ');
                }
            }
            for (std::size_t c = 0; c < length; ++c) {
                out.put(units[c]);
            }
            if (left) {
                for (std::size_t w = length; w < width_used; ++w) {
                    out.put(u' ');
                }
            }
            ++i;
            continue;
        }
        case u'S': {
            const std::uint64_t pointer = slots[slot++];
            const char* narrow = reinterpret_cast<const char*>(pointer);
            text = narrow == nullptr ? "" : std::string(narrow);
            if (precision >= 0 &&
                static_cast<std::size_t>(precision) < text.size()) {
                text.resize(static_cast<std::size_t>(precision));
            }
            break;
        }
        default:
            // A conversion this simplified contract does not carry prints
            // as itself, the way the real one does.
            out.put(u'%');
            out.put(conversion);
            ++i;
            continue;
        }

        // The number conversions land here: sign, digits, padding.
        bool negative = false;
        if (!text.empty() && text.front() == '-') {
            negative = true;
            text.erase(text.begin());
        }
        pad_field(out, text, negative, width, left, zero);
        ++i;
    }
    buffer[out.count] = u'\0';
    __builtin_ms_va_end(ap);
    return static_cast<std::int32_t>(out.count);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_wsprintfA(
    char* buffer, const char* fmt, ...) noexcept {
    // The narrow spelling is the same contract cr_sprintf carries -- the
    // simplified conversions are a subset of what the bridge reads -- and
    // the answer is the character count in both.
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, fmt);
    void* slots = nullptr;
    __builtin_memcpy(&slots, &ap, sizeof(slots));
    const std::int32_t result = cr_vsprintf(buffer, fmt, slots);
    __builtin_ms_va_end(ap);
    return result;
}

// --- the file spellings ---

extern "C" __attribute__((ms_abi)) void* cr_fopen(
    const char* path, const char* mode) noexcept {
    if (path == nullptr || mode == nullptr) {
        return nullptr;
    }
    const std::string host_mode = strip_ccs(mode);
    std::FILE* file = ::fopen(from_dos_path(path).c_str(), host_mode.c_str());
    if (file != nullptr) {
        note_file_mode(file, mode);
    }
    return file;
}

extern "C" __attribute__((ms_abi)) void* cr__wfopen(
    const char16_t* path, const char16_t* mode) noexcept {
    if (path == nullptr || mode == nullptr) {
        return nullptr;
    }
    std::string narrow_path;
    std::string narrow_mode;
    if (!utf16_to_utf8(std::u16string_view(path), narrow_path) ||
        !utf16_to_utf8(std::u16string_view(mode), narrow_mode)) {
        return nullptr;
    }
    const std::string host_mode = strip_ccs(narrow_mode.c_str());
    std::FILE* file = ::fopen(from_dos_path(narrow_path).c_str(),
                              host_mode.c_str());
    if (file != nullptr) {
        note_file_mode(file, narrow_mode.c_str());
    }
    return file;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_fclose(
    void* stream) noexcept {
    if (stream == nullptr) {
        return -1;
    }
    std::FILE* target = resolve_stream(
        reinterpret_cast<std::uint64_t>(stream));
    forget_file_mode(target);
    return ::fclose(target);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr__read(
    std::int32_t fd, void* buffer, std::uint32_t count) noexcept {
    // The low-level read under the CRT's own name. The three standard
    // descriptors are the host's own -- the runtime never renumbers them --
    // so the call is the host's read narrowed to the int the CRT returns.
    // Anything else is a descriptor this file face never issued, and a
    // caller that reaches one is reading a table that does not exist.
    if (buffer == nullptr || fd < 0) {
        return -1;
    }
    if (fd > 2) {
        errno = EBADF;
        return -1;
    }
    const ::ssize_t got =
        ::read(fd, buffer, static_cast<std::size_t>(count));
    return static_cast<std::int32_t>(got);
}

extern "C" __attribute__((ms_abi)) std::uint64_t cr_fread(
    void* buffer, std::uint64_t size, std::uint64_t count,
    void* stream) noexcept {
    if (size == 0 || count == 0 || count > SIZE_MAX / size) {
        return 0;
    }
    auto* bytes = static_cast<char*>(buffer);
    const std::size_t requested = static_cast<std::size_t>(size * count);
    std::FILE* target = resolve_stream(
        reinterpret_cast<std::uint64_t>(stream));
    if (!stream_is_text(target)) {
        // A binary stream carries every byte it finds as it is, and the
        // host's own fread already speaks that contract.
        return static_cast<std::uint64_t>(
            ::fread(bytes, 1, requested, target) / size);
    }
    // The read side of the text mode: a pair the write side expanded
    // comes back as one newline when both of its halves arrived in the
    // one read. The source bytes are staged away from the guest's buffer
    // first -- fread writes the bytes it delivers and no others, so the
    // tail of the guest's buffer stays exactly what the caller left
    // there. A pair whose halves straddle two reads travels as the two
    // bytes it is: the read that ends on the return hands it over as
    // itself, and the read that follows brings its newline.
    std::vector<char> staged(requested);
    const std::size_t got = ::fread(staged.data(), 1, requested, target);
    std::size_t in = 0;
    std::size_t out = 0;
    while (in < got) {
        if (staged[in] == '\r' && in + 1 < got && staged[in + 1] == '\n') {
            bytes[out++] = '\n';
            ++in;
        } else {
            bytes[out++] = staged[in];
        }
        ++in;
    }
    return static_cast<std::uint64_t>(out / size);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_fseek(
    void* stream, std::int64_t offset, std::int32_t origin) noexcept {
    return ::fseeko(resolve_stream(reinterpret_cast<std::uint64_t>(stream)),
                    static_cast<off_t>(offset), origin);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_fseeki64(
    void* stream, std::int64_t offset, std::int32_t origin) noexcept {
    return cr_fseek(stream, offset, origin);
}

extern "C" __attribute__((ms_abi)) std::int64_t cr_ftell(
    void* stream) noexcept {
    return ::ftello(resolve_stream(reinterpret_cast<std::uint64_t>(stream)));
}

extern "C" __attribute__((ms_abi)) std::int64_t cr_ftelli64(
    void* stream) noexcept {
    return cr_ftell(stream);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_fflush(
    void* stream) noexcept {
    // A null stream means every open stream, and the host's own fflush
    // answers the same call the same way.
    return ::fflush(stream == nullptr
                        ? nullptr
                        : resolve_stream(
                              reinterpret_cast<std::uint64_t>(stream)));
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_feof(
    void* stream) noexcept {
    return ::feof(resolve_stream(reinterpret_cast<std::uint64_t>(stream)));
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_ferror(
    void* stream) noexcept {
    return ::ferror(resolve_stream(reinterpret_cast<std::uint64_t>(stream)));
}

extern "C" __attribute__((ms_abi)) void cr_clearerr(void* stream) noexcept {
    ::clearerr(resolve_stream(reinterpret_cast<std::uint64_t>(stream)));
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_setvbuf(
    void* stream, char* buffer, std::int32_t mode,
    std::uint64_t size) noexcept {
    return ::setvbuf(resolve_stream(reinterpret_cast<std::uint64_t>(stream)),
                     buffer, mode, static_cast<std::size_t>(size));
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_ungetc(
    std::int32_t c, void* stream) noexcept {
    return ::ungetc(c, resolve_stream(reinterpret_cast<std::uint64_t>(stream)));
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_rename(
    const char* from, const char* to) noexcept {
    if (from == nullptr || to == nullptr) {
        return -1;
    }
    return ::rename(from_dos_path(from).c_str(), from_dos_path(to).c_str());
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_remove(
    const char* path) noexcept {
    if (path == nullptr) {
        return -1;
    }
    return ::remove(from_dos_path(path).c_str());
}

extern "C" __attribute__((ms_abi)) void* cr_tmpfile() noexcept {
    // Windows' tmpfile opens `w+b`, binary, in the temp directory; the
    // host's own answers the same contract and names no path the guest
    // would have to know.
    return ::tmpfile();
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_fgetc(
    void* stream) noexcept {
    return ::fgetc(resolve_stream(reinterpret_cast<std::uint64_t>(stream)));
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_getc(
    void* stream) noexcept {
    return cr_fgetc(stream);
}

extern "C" __attribute__((ms_abi)) char* cr_fgets(
    char* buffer, std::int32_t count, void* stream) noexcept {
    if (count <= 0) {
        return nullptr;
    }
    std::FILE* target = resolve_stream(
        reinterpret_cast<std::uint64_t>(stream));
    char* line = ::fgets(buffer, count, target);
    if (line == nullptr) {
        return nullptr;
    }
    // The text mode the stream travels in presses the pair the write
    // side left into one newline. A line read in one fgets has both of
    // its halves, so the return the guest sees is the one Windows gives.
    if (stream_is_text(target)) {
        const std::size_t length = ::strlen(line);
        if (length >= 2 && line[length - 2] == '\r' &&
            line[length - 1] == '\n') {
            line[length - 2] = '\n';
            line[length - 1] = '\0';
        }
    }
    return line;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_putc(
    std::int32_t c, void* stream) noexcept {
    return cr_fputc(c, stream);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_getchar() noexcept {
    const GuestState* g = require_state();
    if (g == nullptr || g->iob_base == 0) {
        return -1;
    }
    // The guest's stdin is slot zero of its own file table.
    return ::fgetc(translate_stream(*g, g->iob_base));
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_putchar(
    std::int32_t c) noexcept {
    const GuestState* g = require_state();
    if (g == nullptr || g->iob_base == 0) {
        return -1;
    }
    // The guest's stdout is slot one, and the character leaves through
    // the stream's text mode like any CRT byte does.
    return cr_fputc(c, reinterpret_cast<void*>(g->iob_base + kGuestFileSlot));
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

// ---- exceptions ----------------------------------------------------------

// The body of `RaiseException`, reached from the assembly stub below. It
// builds the record the Windows call builds, runs the search pass over the
// guest's own frames, and ends the way Windows ends each outcome: a frame
// that resumes runs on, and an exception nobody caught ends the process
// with the exception's code.
extern "C" void k32_raise_dispatch(std::uint64_t code, std::uint64_t flags,
                                   std::uint64_t nargs,
                                   std::uint64_t args_address,
                                   std::uint8_t* context) noexcept {
    winabi::GuestState* guest = guest_state();
    if (guest == nullptr) {
        // No guest, no frames to walk and nowhere the exception could
        // land; the stub's own return is the only honest way back.
        return;
    }
    alignas(16) std::uint8_t record[seh::kRecordSize];
    std::memset(record, 0, sizeof(record));
    {
        const std::uint32_t narrow = static_cast<std::uint32_t>(code);
        std::memcpy(record + seh::kRecordCode, &narrow, sizeof(narrow));
        const std::uint32_t wide = static_cast<std::uint32_t>(flags);
        std::memcpy(record + seh::kRecordFlags, &wide, sizeof(wide));
        std::uint64_t address = 0;
        std::memcpy(&address, context + seh::kContextRip, sizeof(address));
        std::memcpy(record + 0x10, &address, sizeof(address));
        const std::uint32_t copied =
            nargs > 15 ? 15u : static_cast<std::uint32_t>(nargs);
        std::memcpy(record + 0x18, &copied, sizeof(copied));
        for (std::uint32_t i = 0; i < copied; ++i) {
            const void* slot = reinterpret_cast<const void*>(
                args_address + static_cast<std::size_t>(i) * 8);
            std::memcpy(record + 0x20 + static_cast<std::size_t>(i) * 8,
                        slot, sizeof(std::uint64_t));
        }
    }

    const bool resume = seh::dispatch(
        record, context,
        reinterpret_cast<const std::uint8_t*>(guest->pdata_va),
        static_cast<std::size_t>(guest->pdata_bytes),
        seh::UnwindRange{guest->xdata_va, guest->xdata_bytes},
        guest->image_base, guest->image_end, guest->stack_low,
        guest->stack_high);
    if (resume) {
        // A filter answered EXCEPTION_CONTINUE_EXECUTION: the guest
        // resolved the condition and the interrupted code runs on.
        seh::seh_restore_context(context);
    }

    // Windows gives the unhandled-exception filter its say before the
    // process ends; its verdicts both end the run, and the code the run
    // ends with is the exception's.
    if (guest->unhandled_filter != 0) {
        alignas(8) const void* pointers[2] = {record, context};
        const auto tell = reinterpret_cast<std::int32_t(
            __attribute__((ms_abi))*)(const void*)>(guest->unhandled_filter);
        (void)tell(pointers);
    }
    terminate(static_cast<std::uint32_t>(code));
}

// `RaiseException`, spelled as the stub the ABI needs: the guest's call
// arrives with its registers live -- the non-volatile ones still belong to
// the guest's caller, which a C prolog would destroy -- so the stub keeps
// no prolog, captures the caller's state, corrects the context to the
// call site the guest sees, and hands the rest to the body above.
extern "C" __attribute__((naked, ms_abi)) void k32_RaiseException(
    std::uint64_t, std::uint64_t, std::uint64_t,
    const std::uint64_t*) noexcept {
    __asm__(
        "subq $0x4f8, %rsp\n\t"           // keeps the calls below aligned
        "movq %rcx, 0x500(%rsp)\n\t"      // the caller's shadow slots,
        "movq %rdx, 0x508(%rsp)\n\t"      // which a callee may write
        "movq %r8, 0x510(%rsp)\n\t"
        "movq %r9, 0x518(%rsp)\n\t"
        "leaq 0x20(%rsp), %rcx\n\t"
        "call seh_capture_context\n\t"    // captures this stub's own state
        "leaq 0x500(%rsp), %rax\n\t"
        "movq %rax, 0xb8(%rsp)\n\t"       // context.Rsp: the caller's own,
                                          // pointing at the return address
        "movq 0x4f8(%rsp), %rax\n\t"
        "movq %rax, 0x118(%rsp)\n\t"      // context.Rip: the return address
        "movq 0x500(%rsp), %rax\n\t"
        "movq %rax, 0xa0(%rsp)\n\t"       // context.Rcx: the code, which
                                          // the capture overwrote
        "movq 0x500(%rsp), %rdi\n\t"      // the body runs on the host's own
        "movq 0x508(%rsp), %rsi\n\t"      // calling convention
        "movq 0x510(%rsp), %rdx\n\t"
        "movq 0x518(%rsp), %rcx\n\t"
        "leaq 0x20(%rsp), %r8\n\t"
        "call k32_raise_dispatch\n\t"
        "addq $0x4f8, %rsp\n\t"
        "ret\n\t");
}

// The lookup the guest's own unwind support reaches for: the table's own
// row for the control point, with the base it belongs to, or nothing --
// chains left for the walk to follow.
extern "C" __attribute__((ms_abi)) std::uint64_t k32_RtlLookupFunctionEntry(
    std::uint64_t control_pc, std::uint64_t* image_base_out,
    void* history_table) noexcept {
    (void)history_table;  // answered by search every time; the cache is
                          // the caller's to keep
    winabi::GuestState* guest = guest_state();
    if (guest == nullptr) {
        if (image_base_out != nullptr) {
            *image_base_out = 0;
        }
        return 0;
    }
    const seh::FunctionEntry* entry = seh::find_function_entry(
        guest->image_base,
        reinterpret_cast<const std::uint8_t*>(guest->pdata_va),
        static_cast<std::size_t>(guest->pdata_bytes), control_pc);
    if (image_base_out != nullptr) {
        *image_base_out = entry != nullptr ? guest->image_base : 0;
    }
    return reinterpret_cast<std::uint64_t>(entry);
}

// The one-frame reversal the guest's own unwind support reaches for: the
// same walk the search pass runs, one frame at a time, with the handler
// the frame carries -- or zero -- as the answer.
extern "C" __attribute__((ms_abi)) std::uint64_t k32_RtlVirtualUnwind(
    std::uint32_t handler_type, std::uint64_t image_base,
    std::uint64_t control_pc, const void* function_entry, void* context,
    void** handler_data_out, std::uint64_t* establisher_frame_out,
    void* history_table) noexcept {
    (void)history_table;
    std::uint64_t frame = 0;
    const void* handler_data = nullptr;
    std::uint64_t handler = 0;
    // The unwind data this call may read is the guest's own, so the range
    // comes from the state the runtime keeps rather than from an argument:
    // the guest's `RtlVirtualUnwind` has no way to name a section, and the
    // table its rows point into is the one the loader mapped.
    const winabi::GuestState* guest = winabi::guest_state();
    const seh::UnwindRange xdata =
        guest != nullptr ? seh::UnwindRange{guest->xdata_va, guest->xdata_bytes}
                         : seh::UnwindRange{};
    const bool ok = seh::virtual_unwind(
        handler_type, image_base, control_pc,
        static_cast<const seh::FunctionEntry*>(function_entry),
        static_cast<std::uint8_t*>(context), xdata,
        guest != nullptr ? guest->stack_low : 0,
        guest != nullptr ? guest->stack_high : 0, &handler_data, &frame,
        &handler);
    if (!ok) {
        // A table this runtime cannot read: the Windows call marks the
        // context with a zero rip and answers no handler.
        std::memset(static_cast<std::uint8_t*>(context) + seh::kContextRip, 0,
                    sizeof(std::uint64_t));
        if (handler_data_out != nullptr) {
            *handler_data_out = nullptr;
        }
        if (establisher_frame_out != nullptr) {
            *establisher_frame_out = frame;
        }
        return 0;
    }
    if (handler_data_out != nullptr) {
        *handler_data_out = const_cast<void*>(handler_data);
    }
    if (establisher_frame_out != nullptr) {
        *establisher_frame_out = frame;
    }
    return handler;
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
        e("ReadFile", reinterpret_cast<void*>(&k32_ReadFile)),
        e("CreateFileA", reinterpret_cast<void*>(&k32_CreateFileA)),
        e("GetFileSizeEx", reinterpret_cast<void*>(&k32_GetFileSizeEx)),
        e("DeleteFileA", reinterpret_cast<void*>(&k32_DeleteFileA)),
        e("CloseHandle", reinterpret_cast<void*>(&k32_CloseHandle)),
        e("CreateEventA", reinterpret_cast<void*>(&k32_CreateEventA)),
        e("CreateEventW", reinterpret_cast<void*>(&k32_CreateEventW)),
        e("SetEvent", reinterpret_cast<void*>(&k32_SetEvent)),
        e("ResetEvent", reinterpret_cast<void*>(&k32_ResetEvent)),
        e("WaitForSingleObject",
          reinterpret_cast<void*>(&k32_WaitForSingleObject)),
        e("WaitForSingleObjectEx",
          reinterpret_cast<void*>(&k32_WaitForSingleObjectEx)),
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
        e("GetProcAddress", reinterpret_cast<void*>(&k32_GetProcAddress)),
        e("LoadLibraryA", reinterpret_cast<void*>(&k32_LoadLibraryA)),
        e("LoadLibraryW", reinterpret_cast<void*>(&k32_LoadLibraryW)),
        e("LoadLibraryExW", reinterpret_cast<void*>(&k32_LoadLibraryExW)),
        e("GetThreadId", reinterpret_cast<void*>(&k32_GetThreadId)),
        e("GetStartupInfoA", reinterpret_cast<void*>(&k32_GetStartupInfoA)),
        e("GetStartupInfoW", reinterpret_cast<void*>(&k32_GetStartupInfoW)),
        e("GetCurrentProcessId",
          reinterpret_cast<void*>(&k32_GetCurrentProcessId)),
        e("GetCurrentThreadId",
          reinterpret_cast<void*>(&k32_GetCurrentThreadId)),
        e("GetCurrentProcess", reinterpret_cast<void*>(&k32_GetCurrentProcess)),
        e("GetCurrentThread", reinterpret_cast<void*>(&k32_GetCurrentThread)),
        e("IsDebuggerPresent", reinterpret_cast<void*>(&k32_IsDebuggerPresent)),
        e("GetEnvironmentVariableA",
          reinterpret_cast<void*>(&k32_GetEnvironmentVariableA)),
        e("GetEnvironmentVariableW",
          reinterpret_cast<void*>(&k32_GetEnvironmentVariableW)),
        e("GetLastError", reinterpret_cast<void*>(&k32_GetLastError)),
        e("SetEnvironmentVariableA",
          reinterpret_cast<void*>(&k32_SetEnvironmentVariableA)),
        e("SetEnvironmentVariableW",
          reinterpret_cast<void*>(&k32_SetEnvironmentVariableW)),
        e("SetLastError", reinterpret_cast<void*>(&k32_SetLastError)),
        e("InitializeCriticalSection",
          reinterpret_cast<void*>(&k32_InitializeCriticalSection)),
        e("EnterCriticalSection",
          reinterpret_cast<void*>(&k32_EnterCriticalSection)),
        e("LeaveCriticalSection",
          reinterpret_cast<void*>(&k32_LeaveCriticalSection)),
        e("DeleteCriticalSection",
          reinterpret_cast<void*>(&k32_DeleteCriticalSection)),
        e("TryEnterCriticalSection",
          reinterpret_cast<void*>(&k32_TryEnterCriticalSection)),
        e("SetUnhandledExceptionFilter",
          reinterpret_cast<void*>(&k32_SetUnhandledExceptionFilter)),
        e("Sleep", reinterpret_cast<void*>(&k32_Sleep)),
        e("TlsAlloc", reinterpret_cast<void*>(&k32_TlsAlloc)),
        e("TlsGetValue", reinterpret_cast<void*>(&k32_TlsGetValue)),
        e("TlsSetValue", reinterpret_cast<void*>(&k32_TlsSetValue)),
        e("TlsFree", reinterpret_cast<void*>(&k32_TlsFree)),
        // `VirtualProtect` and `VirtualQuery` are registered by the memory
        // domain, which owns the virtual-memory family.
        e("GetProcessHeap", reinterpret_cast<void*>(&k32_GetProcessHeap)),
        // The core heap family is registered by the memory domain, which
        // owns it and carries the tests for it; the entries here that the
        // domain does not have -- the compact and information queries --
        // stay with this table.
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
        // `GetSystemTimeAsFileTime` is registered by the time domain, which
        // owns the clock family for kernel32; registering it here too would
        // leave the export's answer depending on which table the index read
        // first.
        e("QueryPerformanceCounter",
          reinterpret_cast<void*>(&k32_QueryPerformanceCounter)),
        e("QueryPerformanceFrequency",
          reinterpret_cast<void*>(&k32_QueryPerformanceFrequency)),
        e("RaiseException", reinterpret_cast<void*>(&k32_RaiseException)),
        e("RtlCaptureContext",
          reinterpret_cast<void*>(&seh::seh_capture_context)),
        e("RtlLookupFunctionEntry",
          reinterpret_cast<void*>(&k32_RtlLookupFunctionEntry)),
        e("RtlUnwindEx", reinterpret_cast<void*>(&seh::seh_RtlUnwindEx)),
        e("RtlVirtualUnwind", reinterpret_cast<void*>(&k32_RtlVirtualUnwind)),
    };
    // The families that outgrew this list live in their own domains, and
    // their names are appended rather than typed here.
    add_file_kernel32(module.host_exports);
    add_time_kernel32(module.host_exports);
    add_memory_kernel32(module.host_exports);
    add_console_kernel32(module.host_exports);
    add_kernel32_extra(module.host_exports);
    add_kernel32_sync(module.host_exports);
    add_kernel32_proc(module.host_exports);
    add_kernel32_str(module.host_exports);
    add_kernel32_err(module.host_exports);
    add_kernel32_sys2(module.host_exports);
    add_kernel32_file2(module.host_exports);
    add_kernel32_state2(module.host_exports);
}

void add_user32(ExportModule& module) {
    module.name = "USER32.dll";
    const auto e = [](const char* n, void* fn) {
        HostExport out;
        out.name = n;
        out.address = reinterpret_cast<std::uint64_t>(fn);
        return out;
    };
    module.host_exports = {
        // The window layer's simplified printf. The narrow spelling and
        // cr_sprintf carry the same contract -- the simplified conversions
        // are a subset of what the bridge reads -- and the wide one runs
        // its own walk over the slots, because its `%s` reads UTF-16.
        e("wsprintfA", reinterpret_cast<void*>(&cr_wsprintfA)),
        e("wsprintfW", reinterpret_cast<void*>(&cr_wsprintfW)),
    };
    add_user32_extra(module.host_exports);
}

void add_kernelbase(ExportModule& module) {
    module.name = "KERNELBASE.dll";
    // Kernelbase is where the implementation of the kernel32 surface moved
    // to, and a guest that imports it directly expects the same answers.
    // This module holds the names that are exported *only* here: a name that
    // both modules export belongs to kernel32, because that is the one an
    // import table from a program written this century will name, and
    // registering it twice would be a duplicate the index silently resolves
    // to whichever came first.
    add_string_kernelbase(module.host_exports);
    add_kernelbase_extra(module.host_exports);
}

void add_shlwapi(ExportModule& module) {
    module.name = "SHLWAPI.dll";
    // This module is the first whose exports come from a domain rather than
    // from this file. `SHLWAPI` is where the shell's path and string
    // helpers live, and both are whole families whose rules are about text
    // rather than about this runtime, so they live beside each other in
    // `runtime/api/` and are appended here. The list above and the lists
    // there are the same list: an export is an export whether it was typed
    // in this file or contributed by a domain.
    add_path_shlwapi(module.host_exports);
    add_string_shlwapi(module.host_exports);
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
          reinterpret_cast<void*>(&seh::seh_C_specific_handler)),
        e("___lc_codepage_func",
          reinterpret_cast<void*>(&cr___lc_codepage_func)),
        e("___mb_cur_max_func",
          reinterpret_cast<void*>(&cr___mb_cur_max_func)),
        e("_amsg_exit", reinterpret_cast<void*>(&cr__amsg_exit)),
        e("_abs64", reinterpret_cast<void*>(&cr__abs64)),
        e("_atoi64", reinterpret_cast<void*>(&cr__atoi64)),
        e("_cexit", reinterpret_cast<void*>(&cr__cexit)),
        d("_commode", &g_commode),
        e("_ctime64", reinterpret_cast<void*>(&cr_ctime)),
        e("_errno", reinterpret_cast<void*>(&cr__errno)),
        d("_environ", &g_environ_ptr),
        e("_fmode", &g_fmode),
        e("_gmtime64", reinterpret_cast<void*>(&cr_gmtime)),
        e("_i64toa", reinterpret_cast<void*>(&cr__i64toa)),
        e("_initterm", reinterpret_cast<void*>(&cr__initterm)),
        e("_itoa", reinterpret_cast<void*>(&cr__itoa)),
        e("_lock", reinterpret_cast<void*>(&cr__lock)),
        e("_ltoa", reinterpret_cast<void*>(&cr__ltoa)),
        e("_localtime64", reinterpret_cast<void*>(&cr_localtime)),
        e("_mkgmtime", reinterpret_cast<void*>(&cr__mkgmtime)),
        e("_mkgmtime64", reinterpret_cast<void*>(&cr__mkgmtime)),
        e("_mktime64", reinterpret_cast<void*>(&cr_mktime)),
        e("_onexit", reinterpret_cast<void*>(&cr__onexit)),
        e("_putenv", reinterpret_cast<void*>(&cr__putenv)),
        e("_putenv_s", reinterpret_cast<void*>(&cr__putenv_s)),
        e("_stricmp", reinterpret_cast<void*>(&cr__stricmp)),
        e("_strlwr", reinterpret_cast<void*>(&cr__strlwr)),
        e("_strnicmp", reinterpret_cast<void*>(&cr__strnicmp)),
        e("_strupr", reinterpret_cast<void*>(&cr__strupr)),
        e("_snprintf", reinterpret_cast<void*>(&cr__snprintf)),
        e("_time64", reinterpret_cast<void*>(&cr_time)),
        e("_ui64toa", reinterpret_cast<void*>(&cr__ui64toa)),
        e("_ultoa", reinterpret_cast<void*>(&cr__ultoa)),
        e("_unlock", reinterpret_cast<void*>(&cr__unlock)),
        e("_vsnprintf", reinterpret_cast<void*>(&cr__vsnprintf)),
        e("_wfopen", reinterpret_cast<void*>(&cr__wfopen)),
        e("abs", reinterpret_cast<void*>(&cr_abs)),
        e("asctime", reinterpret_cast<void*>(&cr_asctime)),
        e("atexit", reinterpret_cast<void*>(&cr_atexit)),
        e("atof", reinterpret_cast<void*>(&cr_atof)),
        e("atoi", reinterpret_cast<void*>(&cr_atoi)),
        e("atol", reinterpret_cast<void*>(&cr_atol)),
        e("abort", reinterpret_cast<void*>(&cr_abort)),
        e("bsearch", reinterpret_cast<void*>(&cr_bsearch)),
        e("calloc", reinterpret_cast<void*>(&cr_calloc)),
        e("clock", reinterpret_cast<void*>(&cr_clock)),
        e("ctime", reinterpret_cast<void*>(&cr_ctime)),
        e("difftime", reinterpret_cast<void*>(&cr_difftime)),
        e("div", reinterpret_cast<void*>(&cr_div)),
        e("exit", reinterpret_cast<void*>(&cr_exit)),
        e("memchr", reinterpret_cast<void*>(&cr_memchr)),
        e("realloc", reinterpret_cast<void*>(&cr_realloc)),
        e("fclose", reinterpret_cast<void*>(&cr_fclose)),
        e("feof", reinterpret_cast<void*>(&cr_feof)),
        e("ferror", reinterpret_cast<void*>(&cr_ferror)),
        e("fflush", reinterpret_cast<void*>(&cr_fflush)),
        e("fgetc", reinterpret_cast<void*>(&cr_fgetc)),
        e("fgets", reinterpret_cast<void*>(&cr_fgets)),
        e("fopen", reinterpret_cast<void*>(&cr_fopen)),
        e("fprintf", reinterpret_cast<void*>(&cr_fprintf)),
        e("fputc", reinterpret_cast<void*>(&cr_fputc)),
        e("fputs", reinterpret_cast<void*>(&cr_fputs)),
        e("fread", reinterpret_cast<void*>(&cr_fread)),
        e("free", reinterpret_cast<void*>(&cr_free)),
        e("_read", reinterpret_cast<void*>(&cr__read)),
        e("fseek", reinterpret_cast<void*>(&cr_fseek)),
        e("fseeki64", reinterpret_cast<void*>(&cr_fseeki64)),
        e("ftell", reinterpret_cast<void*>(&cr_ftell)),
        e("ftelli64", reinterpret_cast<void*>(&cr_ftelli64)),
        e("fwrite", reinterpret_cast<void*>(&cr_fwrite)),
        e("getc", reinterpret_cast<void*>(&cr_getc)),
        e("getchar", reinterpret_cast<void*>(&cr_getchar)),
        e("getenv", reinterpret_cast<void*>(&cr_getenv)),
        e("gmtime", reinterpret_cast<void*>(&cr_gmtime)),
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
        e("localtime", reinterpret_cast<void*>(&cr_localtime)),
        e("localeconv", reinterpret_cast<void*>(&cr_localeconv)),
        e("malloc", reinterpret_cast<void*>(&cr_malloc)),
        e("mbstowcs", reinterpret_cast<void*>(&cr_mbstowcs)),
        e("memcmp", reinterpret_cast<void*>(&cr_memcmp)),
        e("memcpy", reinterpret_cast<void*>(&cr_memcpy)),
        e("memmove", reinterpret_cast<void*>(&cr_memmove)),
        e("memset", reinterpret_cast<void*>(&cr_memset)),
        e("mktime", reinterpret_cast<void*>(&cr_mktime)),
        e("putc", reinterpret_cast<void*>(&cr_putc)),
        e("putchar", reinterpret_cast<void*>(&cr_putchar)),
        e("putenv", reinterpret_cast<void*>(&cr__putenv)),
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
        e("strftime", reinterpret_cast<void*>(&cr_strftime)),
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
        e("time", reinterpret_cast<void*>(&cr_time)),
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
    // The C runtime this module is named for, appended from
    // the one table the whole family shares.
    add_crt(module.host_exports, "msvcrt.dll");
}

}  // namespace

void register_host_modules(ExportRegistry& registry) {
    // The one place a module is named. The registry and the handle lookup
    // are both built from this list, so a module cannot be reachable one
    // way and missing the other -- which is what the pair of hand-written
    // lists this replaces allowed, and what made adding a module a change
    // in three places that had to agree.
    struct ModuleSpec {
        const char* name;
        void (*add)(ExportModule&);
    };
    static const ModuleSpec kModules[] = {
        {"KERNEL32.dll", &add_kernel32},
        {"KERNELBASE.dll", &add_kernelbase},
        {"msvcrt.dll", &add_msvcrt},
        {"USER32.dll", &add_user32},
        {"SHLWAPI.dll", &add_shlwapi},
        {"NTDLL.dll", &add_module_ntdll},
        {"GDI32.dll", &add_module_gdi32},
        {"ADVAPI32.dll", &add_module_advapi32},
        {"RPCRT4.dll", &add_module_rpcrt4},
        {"SETUPAPI.dll", &add_module_setupapi},
        {"SHELL32.dll", &add_module_shell32},
        {"CRYPT32.dll", &add_module_crypt32},
        {"OLE32.dll", &add_module_ole32},
        {"UCRTBASE.dll", &add_module_ucrtbase},
        {"MSVCR70.dll", &add_module_msvcr70},
        {"MSVCR71.dll", &add_module_msvcr71},
        {"MSVCR80.dll", &add_module_msvcr80},
        {"MSVCR90.dll", &add_module_msvcr90},
        {"MSVCR100.dll", &add_module_msvcr100},
        {"MSVCR110.dll", &add_module_msvcr110},
        {"MSVCR120.dll", &add_module_msvcr120},
        {"MSVCR120_APP.dll", &add_module_msvcr120_app},
        {"MSVCRTD.dll", &add_module_msvcrtd},
        {"MSVCRT20.dll", &add_module_msvcrt20},
        {"MSVCRT40.dll", &add_module_msvcrt40},
        {"MSVCIRT.dll", &add_module_msvcirt},
    };

    auto& index = own_export_index();
    index.clear();
    for (const ModuleSpec& spec : kModules) {
        ExportModule module;
        spec.add(module);
        module.name = spec.name;
        // The index is keyed by the folded name. A module name is matched
        // without regard to case -- the registry's own `module_name_equal`
        // says so -- and a map key that kept the module's spelling would
        // make `LoadLibraryA("kernel32.dll")` miss a table filled under
        // `KERNEL32.dll`. The registry keeps the spelling the module
        // declares, because that is the name an import table is compared
        // against; only the lookup key is folded.
        auto& names = index[fold_module_name(module.name)];
        for (const HostExport& entry : module.host_exports) {
            names.emplace(entry.name, entry.address);
        }
        registry.add(std::move(module));
    }
}

// The error a guest reads back through `GetLastError`.
//
// It lives outside the anonymous namespace because the API domains, which
// are separate translation units, report failures through it. A second copy
// in one of them would be a second answer to the same question, and a guest
// that read one while the other was written would read a stale code. The
// thread-local store it writes belongs to this translation unit and is used
// from here only, which is why the definition can sit at the end of the file
// and still reach it.
void set_last_error(std::uint32_t error) noexcept {
    if (require_state() == nullptr) {
        g_host_last_error = error;
        return;
    }
    store_teb_u32(kTebLastError, error);
}

}  // namespace occ::runtime::winabi

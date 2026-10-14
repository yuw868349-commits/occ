#include "occ/runtime/vm_trace.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <string_view>
#include <vector>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace occ::runtime::vm_trace {

namespace {

constexpr std::uint64_t kPage = 4096;

// The dispatch idioms this runtime recognizes, as byte patterns. Each
// names the registers a handler table is read through and how the read
// is made, because the trace must know where the opcode index and the
// table base live at the moment of the jump. The first family is the one
// VMProtect 3.x emits for its main loop:
//   49 8b 0c c4   mov rcx, [r12+rax*8]
// followed by an indirect jump. Siblings cover the other register
// choices: r8 (`4c 8b 04 c4`), rax (`49 8b 04 c4`), and the plain
// `[r12+rax*8]` read into rcx without REX.B (`48 8b 0c c4`). The second
// family is a table-driven handler select with relative offsets -- the
// shape a hand-rolled interpreter keeps: the jump table holds the
// distance from its own base, and the dispatch adds the base back:
//   48 63 14 93        movslq (%rbx,%rdx,4),%rdx
//   48 01 da           add    %rbx,%rdx
//   ff e2              jmp    *%rdx
// The seven bytes up to the jump are the idiom; the jump byte follows.
struct DispatchIdiom {
    const char* bytes;
    std::size_t length;
    int index_reg;        // the register holding the opcode index
    int base_reg;         // the register holding the handler table base
    std::uint64_t scale;  // the index stride in the table
    bool relative;        // true: table cells hold offsets from the base
};

constexpr DispatchIdiom kIdioms[] = {
    {"\x49\x8b\x0c\xc4", 4, REG_RAX, REG_R12, 8, false},
    {"\x4c\x8b\x04\xc4", 4, REG_RAX, REG_R12, 8, false},
    {"\x49\x8b\x04\xc4", 4, REG_RAX, REG_R12, 8, false},
    {"\x48\x8b\x0c\xc4", 4, REG_RAX, REG_R12, 8, false},
    {"\x48\x63\x14\x93\x48\x01\xda", 7, REG_RDX, REG_RBX, 4, true},
};

// The ring buffer's depth: the tail the trace can show around a crash.
constexpr std::size_t kRingDepth = 512;

// The general registers, in the x86-64 encoding order, and their names.
// The trace carries all of them under their own names: a model can lean on
// any -- a bytecode buffer held in r8, a register file indexed by r11 --
// and a prediction that leans on one can only be checked if the trace has
// it. The names are the trace's, the order is the array's, and the two
// have to stay in step.
constexpr int kGprOrder[16] = {
    REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI,
    REG_R8,  REG_R9,  REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15,
};
constexpr const char* kGprNames[16] = {
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
};

// One value as the trace writes it: hex without a prefix, because every
// field of the line is one and the quotes carry the rest.
std::string hex_of(std::uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof(b), "%llx", static_cast<unsigned long long>(v));
    return b;
}

struct DispatchRecord {
    std::uint64_t t;      // CLOCK_MONOTONIC ns
    std::uint64_t rip;    // dispatch address
    std::uint64_t index;  // rax at dispatch
    std::uint64_t base;   // r12 at dispatch
    std::uint64_t target; // handler pointer read from the table
    std::uint64_t rsi;    // bytecode cursor (VM state)
    std::uint64_t rdi;
    std::uint64_t rsp;
    std::uint64_t rbp;    // virtual stack pointer (VM state)
    // The virtual stack, as the guest holds it: the top slots at the
    // dispatch are the operands the next handler consumes. Read from the
    // guest's own memory, which is the one source that cannot lie.
    std::uint64_t st0;
    std::uint64_t st1;
    std::uint64_t st2;
    // The same window around rsp. An engine that keeps its register file
    // at a register other than rbp has its cells read here too; which of
    // the two windows is the file is decided afterwards, by the model,
    // because the tracer's job is to record what the machine held and not
    // to decide what the machine meant.
    std::uint64_t rt[8];
    // Every general register, under its own name, so the checker can bind
    // any the model names.
    std::uint64_t gpr[16];
};

// The trace's switch and output, read once.
bool g_to_stderr = false;
std::string g_path;
std::FILE* g_file = nullptr;

// The dispatch sites, resolved at arm time. A packed image can carry
// more than one engine (VMProtect emits a separate VM per protected
// function), so every idiom site is a candidate; the trace records
// whichever ones the guest actually reaches. Each site keeps the
// register roles its idiom named, because a table-driven interpreter
// may index through any pair.
constexpr std::size_t kMaxCandidates = 16;
struct DispatchSite {
    std::uint64_t address = 0;
    int index_reg = REG_RAX;
    int base_reg = REG_R12;
    std::uint64_t scale = 8;
    bool relative = false;
};
DispatchSite g_sites[kMaxCandidates];
std::size_t g_dispatch_count = 0;
bool g_resolved = false;

// The image base the trace armed against, and its mapped size. The tracer
// needs both to tell a register that names guest memory from one that
// names this runtime's own mappings: the guest's mappings sit at and
// above the image, and everything below it belongs to the host.
std::uint64_t g_image_base = 0;

// The virtual clock's epoch (real tick at the first dispatch) and the
// clean dispatch rate the clock pretends. A thousand dispatches a
// millisecond is the order of magnitude a clean interpreter keeps.
constexpr std::uint64_t kDispatchesPerMs = 1000;
std::uint64_t g_tick_epoch_ms = 0;

// The trapped pages (dispatch pages without execute permission), and the
// single steps armed to re-trap them. A dispatch page holds ordinary code
// too -- the engine's own prologue and the jump network around it -- so
// every fetch into it faults, and only the fetch whose instruction
// pointer is a dispatch address becomes a record. The step state is
// thread-local, not a shared table: the trap flag is per-thread hardware
// state, and the SIGTRAP a step raises can only land on the thread that
// armed it. A shared owner table would race -- two threads fetching the
// same page at once would both write it, and one thread's step could be
// overwritten before its own trap arrived, leaving a trap flag with no
// owner and a guest that dies on the instrument's own signal.
std::uint64_t g_trapped_pages[kMaxCandidates] = {};
std::size_t g_trapped_count = 0;
thread_local bool g_step_pending = false;
thread_local std::uint64_t g_step_page = 0;

[[nodiscard]] std::uint64_t current_tid() noexcept {
    return static_cast<std::uint64_t>(::syscall(SYS_gettid));
}

// The ring buffer and its write position.
DispatchRecord g_ring[kRingDepth];
std::size_t g_ring_pos = 0;

// How many dispatches were recorded.
std::uint64_t g_recorded = 0;

// What the trace carries beyond the dispatch rows.
//
// The image dump carries the image. A page the engine allocated at run
// time -- the buffer it decrypted its bytecode into, the register file
// its handlers index -- is in no file, and the only source of its bytes
// is the run itself. The tracer therefore carries those pages: at a
// dispatch it reads the window around every register that names guest
// memory and writes the ones it has not written yet. The de-virtualizer
// then holds the bytes behind an address a handler read, so a prediction
// about a bytecode operand is checked instead of counted unverifiable.
//
// A window is written once, when a register first names it, and not once
// per dispatch: these are the engine's own bytes, they do not change from
// step to step, and a trace that repeated sixteen kilobytes three hundred
// times would be a file whose payload is noise. A window the engine moves
// into later -- a buffer it reallocates, a stack that grows -- is written
// when a register first names that one.
constexpr std::uint64_t kSnapshotWindow = 0x4000;  // 16 KiB per window
constexpr std::size_t kMaxSnapshots = 512;
std::uint64_t g_snapshot_windows[kMaxSnapshots];
std::size_t g_snapshot_count = 0;
bool g_snapshot_full_reported = false;

// The guest's own mappings, from /proc/self/maps. A window may only be
// read where the guest mapped it: a register can name an address the
// engine never touched -- a length that happens to look like a pointer, a
// register the packer left holding a constant -- and reading past the end
// of a mapping faults inside the signal handler the trace runs in, which
// is the one context where a fault cannot be delivered. The map answers
// "may this page be read", and it is read with the raw syscalls a handler
// is allowed to make.
constexpr std::size_t kMaxGuestRanges = 128;
struct GuestRange {
    std::uint64_t lo = 0;
    std::uint64_t hi = 0;
};
GuestRange g_guest_ranges[kMaxGuestRanges];
std::size_t g_guest_range_count = 0;
bool g_guest_ranges_ready = false;
constexpr std::size_t kMapsBuffer = 1 << 17;
char g_maps_buffer[kMapsBuffer];

// The highest address above the image a guest mapping may start at. The
// guest's own mappings sit at and above the image -- the image itself, the
// heap the engine allocated, its stack -- while this runtime's own
// mappings (the libc it is linked against, its heap, its thread stacks)
// are elsewhere in the address space. A gigabyte above the image is far
// past any heap a packed program allocates and far below where the host's
// own libraries land.
constexpr std::uint64_t kGuestCeiling = 0x40000000;

// One hexadecimal field of a maps line, stopping at the first byte that is
// not a hex digit. True when at least one digit was read.
[[nodiscard]] bool parse_hex_field(const char* p, const char* end,
                                   std::uint64_t* out) noexcept {
    std::uint64_t v = 0;
    std::size_t digits = 0;
    while (p < end) {
        const unsigned c = static_cast<unsigned>(*p);
        unsigned nibble = 0;
        if (c >= '0' && c <= '9') {
            nibble = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            nibble = c - 'a' + 10u;
        } else if (c >= 'A' && c <= 'F') {
            nibble = c - 'A' + 10u;
        } else {
            break;
        }
        v = (v << 4) | nibble;
        ++p;
        ++digits;
    }
    *out = v;
    return digits != 0;
}

void parse_guest_ranges() noexcept {
    g_guest_ranges_ready = true;
    const long fd = ::syscall(SYS_openat, AT_FDCWD, "/proc/self/maps",
                              O_RDONLY, 0);
    if (fd < 0) {
        return;
    }
    const long n = ::syscall(SYS_read, fd, g_maps_buffer, kMapsBuffer - 1);
    ::syscall(SYS_close, fd);
    if (n <= 0) {
        return;
    }
    g_maps_buffer[n] = '\0';
    const char* const base = g_maps_buffer;
    const char* const stop = base + n;
    for (const char* line = base; line < stop && g_guest_range_count < kMaxGuestRanges;) {
        const char* eol = line;
        while (eol < stop && *eol != '\n') {
            ++eol;
        }
        const char* dash = line;
        while (dash < eol && *dash != '-') {
            ++dash;
        }
        std::uint64_t lo = 0;
        std::uint64_t hi = 0;
        if (dash < eol && parse_hex_field(line, dash, &lo) &&
            parse_hex_field(dash + 1, eol, &hi)) {
            // The permission field follows the two addresses. Only a
            // readable mapping may be read; a guard page reports `---p`
            // and faulting on it would take the process down.
            const char* sp = dash;
            while (sp < eol && *sp != ' ') {
                ++sp;
            }
            const bool readable = sp + 1 < eol && sp[1] == 'r';
            // The image's own mapping is guest memory like any other.
            // Leaving it out would be a bet that the file view and the
            // runtime view agree -- true for code the program never
            // touches, false for a table it builds at start-up: the S box
            // of one engine is `0xff` on disk and a permutation in memory,
            // and the dispatcher that reads it from the file dispatches
            // every row to the same handler. The windows dedup by start,
            // so an image-resident register costs one record for the
            // window it names, not one per dispatch.
            if (readable && hi > lo && lo >= g_image_base &&
                lo < g_image_base + kGuestCeiling) {
                g_guest_ranges[g_guest_range_count].lo = lo;
                g_guest_ranges[g_guest_range_count].hi = hi;
                ++g_guest_range_count;
            }
        }
        line = eol + 1;
        if (eol == stop) {
            break;
        }
    }
}

// The window worth reading around a register value: the sixteen-kilobyte
// span that holds it, clamped to the mapping it lies in, so that a value
// near the end of a mapping yields a shorter window rather than a read
// past the end. False when the value names no guest mapping at all.
[[nodiscard]] bool guest_window(std::uint64_t value, std::uint64_t* lo,
                                std::uint64_t* hi) noexcept {
    if (value == 0) {
        return false;
    }
    for (std::size_t i = 0; i < g_guest_range_count; ++i) {
        const GuestRange& r = g_guest_ranges[i];
        if (value < r.lo || value >= r.hi) {
            continue;
        }
        const std::uint64_t start = value & ~(kSnapshotWindow - 1);
        const std::uint64_t from = start < r.lo ? r.lo : start;
        const std::uint64_t to =
            r.hi < start + kSnapshotWindow ? r.hi : start + kSnapshotWindow;
        if (to <= from) {
            return false;
        }
        *lo = from;
        *hi = to;
        return true;
    }
    return false;
}

// The trace's switch and output, opened on first use.
void ensure_sink() noexcept {
    if (g_file == nullptr && !g_to_stderr && !g_path.empty()) {
        g_file = std::fopen(g_path.c_str(), "w");
        if (g_file == nullptr) {
            std::fprintf(stderr, "occ vm: cannot open %s; tracing to stderr\n",
                         g_path.c_str());
            g_to_stderr = true;
        }
    }
}

void emit_line(const std::string& line) noexcept {
    if (g_to_stderr) {
        std::fputs(line.c_str(), stderr);
    } else if (g_file != nullptr) {
        std::fwrite(line.data(), 1, line.size(), g_file);
        std::fflush(g_file);
    }
}

// The window, as a `memory` record: the address it starts at, its length,
// and its bytes. The row that follows the record is the dispatch whose
// registers named it, so a reader that streams the trace has the bytes in
// hand before it reads the row that indexes them.
void emit_memory(std::uint64_t seq, std::uint64_t va,
                 std::uint64_t size) noexcept {
    static constexpr char kHex[] = "0123456789abcdef";
    const auto* p = reinterpret_cast<const std::uint8_t*>(va);
    std::string line;
    line.reserve(static_cast<std::size_t>(size) * 2 + 96);
    line += "{\"kind\":\"memory\",\"seq\":";
    line += std::to_string(seq);
    line += ",\"va\":\"0x" + hex_of(va);
    line += "\",\"size\":\"" + std::to_string(size);
    line += "\",\"bytes\":\"";
    for (std::uint64_t i = 0; i < size; ++i) {
        line.push_back(kHex[p[i] >> 4]);
        line.push_back(kHex[p[i] & 0x0fu]);
    }
    line += "\"}\n";
    emit_line(line);
}

// Writes the window around every register that names guest memory the
// trace has not carried yet. Called before the dispatch row is written,
// so the bytes precede the row that reads them.
void snapshot_windows(std::uint64_t seq, const std::uint64_t gpr[16]) noexcept {
    if (!g_guest_ranges_ready) {
        parse_guest_ranges();
    }
    if (g_guest_range_count == 0) {
        return;
    }
    for (std::size_t i = 0; i < 16; ++i) {
        std::uint64_t lo = 0;
        std::uint64_t hi = 0;
        if (!guest_window(gpr[i], &lo, &hi)) {
            continue;
        }
        bool known = false;
        for (std::size_t k = 0; k < g_snapshot_count; ++k) {
            if (g_snapshot_windows[k] == lo) {
                known = true;
                break;
            }
        }
        if (known) {
            continue;
        }
        if (g_snapshot_count == kMaxSnapshots) {
            if (!g_snapshot_full_reported) {
                g_snapshot_full_reported = true;
                std::fprintf(stderr,
                             "occ vm: the trace's memory windows are full; "
                             "pages the guest reaches later are not carried\n");
            }
            continue;
        }
        g_snapshot_windows[g_snapshot_count++] = lo;
        emit_memory(seq, lo, hi - lo);
    }
}

[[nodiscard]] bool read_once_enabled() noexcept {
    const char* value = ::getenv("OCC_VM_TRACE");
    if (value == nullptr || value[0] == '\0') {
        return false;
    }
    g_to_stderr = std::string_view{value} == "1";
    if (!g_to_stderr) {
        g_path = value;
    }
    return true;
}

[[nodiscard]] bool set_page_protection(std::uint64_t address, int prot) noexcept {
    const std::uint64_t page = address & ~(kPage - 1);
    return ::mprotect(reinterpret_cast<void*>(page), kPage, prot) == 0;
}

}  // namespace

bool enabled() noexcept {
    static const bool on = read_once_enabled();
    return on;
}

std::uint64_t recorded() noexcept {
    return g_recorded;
}

std::uint64_t image_base() noexcept {
    return g_image_base;
}

std::uint64_t virtual_tick_ms() noexcept {
    // The guest's clock, when the trace is driving it. A clean VM
    // dispatches roughly a thousand instructions a millisecond; the
    // instrumented one takes far longer per dispatch because of the page
    // fault and the step. The guest must see the clean speed, so the
    // clock is the epoch plus the dispatch count at the clean rate --
    // not the wall clock, which would leak the instrumentation. The
    // epoch is the first dispatch's wall time: absolute values the
    // packer compares against a remembered baseline stay consistent.
    if (!enabled() || g_recorded == 0) {
        return 0;
    }
    return g_tick_epoch_ms + g_recorded / kDispatchesPerMs;
}

std::size_t dispatch_count() noexcept {
    return g_dispatch_count;
}

std::uint64_t dispatch_at(std::size_t index) noexcept {
    return index < g_dispatch_count ? g_sites[index].address : 0;
}

bool active() noexcept {
    return enabled() && g_dispatch_count != 0;
}

void arm_trap(std::uint64_t image_base) noexcept {
    if (!enabled()) {
        return;
    }
    if (g_resolved) {
        return;
    }
    g_resolved = true;
    g_image_base = image_base;
    if (const char* named = ::getenv("OCC_VM_DISPATCH");
        named != nullptr && named[0] != '\0') {
        const std::uint64_t at =
            static_cast<std::uint64_t>(std::strtoull(named, nullptr, 0));
        if (at != 0) {
            g_sites[0].address = at;
            g_dispatch_count = 1;
        }
    } else {
        // Scan the mapped image. The size comes from the PE optional
        // header. The idiom plus its jump is distinctive, but encrypted
        // sections can produce the same five bytes by chance -- so every
        // site is kept and the ones the guest reaches are the ones that
        // matter.
        const auto* img = reinterpret_cast<const std::uint8_t*>(image_base);
        const std::uint32_t e_lfanew =
            *reinterpret_cast<const std::uint32_t*>(img + 0x3C);
        const std::uint32_t pe_at = e_lfanew;
        if (pe_at != 0 && std::memcmp(img + pe_at, "PE\0\0", 4) == 0) {
            const std::uint32_t image_size =
                *reinterpret_cast<const std::uint32_t*>(img + pe_at + 0x50);
            for (std::uint64_t off = 0;
                 off + 8 < image_size && g_dispatch_count < kMaxCandidates;
                 ++off) {
                for (const DispatchIdiom& idiom : kIdioms) {
                    if (std::memcmp(img + off, idiom.bytes, idiom.length) != 0) {
                        continue;
                    }
                    const std::uint8_t next = img[off + idiom.length];
                    if (next == 0xe9 || next == 0xff) {
                        g_sites[g_dispatch_count] = DispatchSite{
                            image_base + off, idiom.index_reg, idiom.base_reg,
                            idiom.scale, idiom.relative};
                        ++g_dispatch_count;
                        break;
                    }
                }
            }
        }
    }
    if (g_dispatch_count == 0) {
        std::fprintf(stderr, "occ vm: no dispatch idiom found in the image\n");
        return;
    }
    std::fprintf(stderr, "occ vm: %zu dispatch site(s):",
                 g_dispatch_count);
    for (std::size_t i = 0; i < g_dispatch_count; ++i) {
        std::fprintf(stderr, " 0x%llx",
                     static_cast<unsigned long long>(g_sites[i].address));
    }
    std::fprintf(stderr, "\n");

    // Take the execute permission away from every page holding a dispatch
    // site. The first fetch into each faults; service_fetch restores and
    // re-traps on the step, so the guest runs free between dispatches.
    for (std::size_t i = 0; i < g_dispatch_count; ++i) {
        const std::uint64_t page = g_sites[i].address & ~(kPage - 1);
        // A page already trapped is not trapped twice.
        bool known = false;
        for (std::size_t j = 0; j < g_trapped_count; ++j) {
            if (g_trapped_pages[j] == page) {
                known = true;
                break;
            }
        }
        if (known) {
            continue;
        }
        if (!set_page_protection(page, PROT_READ | PROT_WRITE)) {
            std::fprintf(stderr,
                         "occ vm: cannot trap page 0x%llx (mprotect); the "
                         "trace proceeds with it untrapped\n",
                         static_cast<unsigned long long>(page));
            continue;
        }
        g_trapped_pages[g_trapped_count++] = page;
        std::fprintf(stderr,
                     "occ vm: trapped page 0x%llx (dispatch 0x%llx)\n",
                     static_cast<unsigned long long>(page),
                     static_cast<unsigned long long>(g_sites[i].address));
    }
}

bool handles_fetch(std::uint64_t rip) noexcept {
    if (!active() || g_trapped_count == 0) {
        return false;
    }
    const std::uint64_t page = rip & ~(kPage - 1);
    for (std::size_t i = 0; i < g_trapped_count; ++i) {
        if (g_trapped_pages[i] == page) {
            return true;
        }
    }
    return false;
}

bool step_outstanding() noexcept {
    return g_step_pending;
}

bool handles_step(std::uint64_t rip) noexcept {
    static_cast<void>(rip);
    // The step's own thread decided: the trap flag is per-thread state,
    // and only the thread that armed it can raise its trace trap. The
    // page test is deliberately absent -- a dispatch that jumps across
    // pages raises its step with a rip on the destination page.
    return g_step_pending;
}

bool service_fetch(::ucontext_t* uc, std::uint64_t rip) noexcept {
    if (!active() || !handles_fetch(rip) || uc == nullptr) {
        return false;
    }
    const ::greg_t* g = uc->uc_mcontext.gregs;

    // A dispatch page holds ordinary code too -- the engine's prologue,
    // the jump network around it -- so most fetches into it are not
    // dispatches. They are still serviced (the page must run), but only a
    // fetch whose instruction pointer is a dispatch address is a virtual
    // instruction worth recording.
    bool is_dispatch = false;
    std::size_t site = 0;
    for (std::size_t i = 0; i < g_dispatch_count; ++i) {
        if (rip == g_sites[i].address) {
            is_dispatch = true;
            site = i;
            break;
        }
    }

    if (is_dispatch) {
        const DispatchSite& s = g_sites[site];
        const std::uint64_t index =
            static_cast<std::uint64_t>(g[s.index_reg]);
        const std::uint64_t base =
            static_cast<std::uint64_t>(g[s.base_reg]);

        DispatchRecord rec{};
        rec.t = static_cast<std::uint64_t>([] {
            struct ::timespec ts {};
            ::clock_gettime(CLOCK_MONOTONIC, &ts);
            return static_cast<std::uint64_t>(ts.tv_sec) * 1000000000ull +
                   static_cast<std::uint64_t>(ts.tv_nsec);
        }());
        rec.rip = rip;
        rec.index = index;
        rec.base = base;
        rec.rsi = static_cast<std::uint64_t>(g[REG_RSI]);
        rec.rdi = static_cast<std::uint64_t>(g[REG_RDI]);
        rec.rsp = static_cast<std::uint64_t>(g[REG_RSP]);
        rec.rbp = static_cast<std::uint64_t>(g[REG_RBP]);

        // The virtual stack, from the guest's own memory. The top slots
        // are the operands the next handler consumes; recording them
        // turns the trace into an operand-level record of the stream.
        rec.st0 = 0;
        rec.st1 = 0;
        rec.st2 = 0;
        if (rec.rbp >= 0x10000 && rec.rbp < 0x7ffffffff000ull) {
            const auto* stack = reinterpret_cast<const std::uint64_t*>(
                rec.rbp & ~7ull);
            rec.st0 = stack[0];
            rec.st1 = stack[1];
            rec.st2 = stack[2];
        }
        // The same window around rsp, and every general register. An
        // engine that indexes a file of its own needs both read, and
        // recording them is what lets the de-virtualizer check a
        // prediction about an indexed access instead of counting it
        // unverifiable.
        for (std::size_t i = 0; i < 8; ++i) {
            rec.rt[i] = 0;
        }
        if (rec.rsp >= 0x10000 && rec.rsp < 0x7ffffffff000ull) {
            const auto* file = reinterpret_cast<const std::uint64_t*>(
                rec.rsp & ~7ull);
            for (std::size_t i = 0; i < 8; ++i) {
                rec.rt[i] = file[i];
            }
        }
        for (std::size_t i = 0; i < 16; ++i) {
            rec.gpr[i] = static_cast<std::uint64_t>(g[kGprOrder[i]]);
        }

        // The handler pointer is in the table the guest indexes: this
        // process maps the guest, so the read is a plain load from the
        // guest's own memory, which is the one source that cannot lie.
        // No alignment is assumed: VMProtect runs its base pointer through
        // a constant first (r12 often ends one byte off a table entry),
        // and the read the guest itself makes is the one that decides. A
        // relative table stores the distance from its own base -- the
        // shape a hand-rolled interpreter keeps -- so the target adds
        // the base back instead of being read whole.
        rec.target = 0;
        if (base >= 0x10000 && base < 0x7ffffffff000ull) {
            const std::uint64_t cell = base + (index & 0xfffff) * s.scale;
            if (cell >= 0x10000 && cell < 0x7ffffffff000ull) {
                if (s.relative) {
                    const std::int32_t off =
                        *reinterpret_cast<const std::int32_t*>(cell);
                    rec.target = base + static_cast<std::uint64_t>(off);
                } else {
                    rec.target =
                        *reinterpret_cast<const std::uint64_t*>(cell);
                }
            }
        }

        g_ring[g_ring_pos] = rec;
        g_ring_pos = (g_ring_pos + 1) % kRingDepth;
        ++g_recorded;
        // The first dispatch anchors the virtual clock's epoch.
        if (g_tick_epoch_ms == 0) {
            struct ::timespec ts {};
            ::clock_gettime(CLOCK_MONOTONIC, &ts);
            g_tick_epoch_ms = static_cast<std::uint64_t>(ts.tv_sec) * 1000ull +
                              static_cast<std::uint64_t>(ts.tv_nsec) /
                                  1000000ull;
        }

        // The pages this dispatch's registers name come first, so a reader
        // that walks the trace in order holds the bytes before the row that
        // indexes them.
        ensure_sink();
        snapshot_windows(g_recorded, rec.gpr);
        // The line is built rather than formatted in one call: the record
        // carries a variable tail now -- eight cells and sixteen registers
        // -- and a format string with that many arguments is a place for
        // the arguments to drift out of step with the text.
        std::string line;
        line.reserve(1024);
        line += "{\"kind\":\"dispatch\",\"seq\":";
        line += std::to_string(g_recorded);
        line += ",\"va\":\"0x" + hex_of(rec.rip);
        line += "\",\"index\":\"0x" + hex_of(rec.index);
        line += "\",\"base\":\"0x" + hex_of(rec.base);
        line += "\",\"target\":\"0x" + hex_of(rec.target);
        line += "\",\"rsi\":\"0x" + hex_of(rec.rsi);
        line += "\",\"rdi\":\"0x" + hex_of(rec.rdi);
        line += "\",\"rsp\":\"0x" + hex_of(rec.rsp);
        line += "\",\"rbp\":\"0x" + hex_of(rec.rbp);
        line += "\",\"st0\":\"0x" + hex_of(rec.st0);
        line += "\",\"st1\":\"0x" + hex_of(rec.st1);
        line += "\",\"st2\":\"0x" + hex_of(rec.st2);
        line += "\"";
        char b[48];
        for (std::size_t i = 0; i < 8; ++i) {
            std::snprintf(b, sizeof(b), ",\"rt%zu\":\"0x%llx\"", i,
                          static_cast<unsigned long long>(rec.rt[i]));
            line += b;
        }
        for (std::size_t i = 0; i < 16; ++i) {
            std::snprintf(b, sizeof(b), ",\"%s\":\"0x%llx\"", kGprNames[i],
                          static_cast<unsigned long long>(rec.gpr[i]));
            line += b;
        }
        line += "}\n";
        emit_line(line);
    }

    // Whatever the fetch was, the instruction must now run: the page's
    // execute permission comes back, and the single step that follows
    // re-traps it, so the next fetch into the page faults again.
    const std::uint64_t page = rip & ~(kPage - 1);
    if (!set_page_protection(page, PROT_READ | PROT_EXEC)) {
        std::fprintf(stderr, "occ vm: cannot restore page 0x%llx\n",
                     static_cast<unsigned long long>(page));
        return true;
    }
    // Arm this thread's step: the page is executable again, and the trap
    // flag turns the next instruction into a SIGTRAP the trace owns. The
    // state is this thread's own -- a worker crossing the dispatch page
    // mid-step raises its own trap, which its own state answers and the
    // main thread's state ignores.
    g_step_page = page;
    g_step_pending = true;
    uc->uc_mcontext.gregs[REG_EFL] |= 0x100;
    return true;
}

bool service_step(::ucontext_t* uc, std::uint64_t rip) noexcept {
    static_cast<void>(uc);
    static_cast<void>(rip);
    if (!g_step_pending) {
        return false;
    }
    // The step is this thread's own: the trap flag is per-thread state,
    // so the trap that landed here was armed by this thread's own fetch.
    // Its page is the one to re-trap; a sibling thread's outstanding step
    // is untouched, and its trap will be answered by its own state.
    const std::uint64_t page = g_step_page;
    g_step_pending = false;
    // Re-trap: execute permission off again. The dispatch page's next
    // fetch -- the next dispatch -- faults, which is the instrument.
    if (!set_page_protection(page, PROT_READ | PROT_WRITE)) {
        std::fprintf(stderr, "occ vm: cannot re-trap page 0x%llx\n",
                     static_cast<unsigned long long>(page));
        return true;
    }
    return true;
}

void flush_on_fault() noexcept {
    if (!enabled() || g_recorded == 0) {
        return;
    }
    const std::size_t shown = g_recorded < kRingDepth ? g_recorded : kRingDepth;
    const std::size_t start = (g_ring_pos + kRingDepth - shown) % kRingDepth;
    std::fprintf(stderr,
                 "occ vm: %llu dispatches recorded; the last %zu before the "
                 "fault:\n",
                 static_cast<unsigned long long>(g_recorded), shown);
    for (std::size_t i = 0; i < shown; ++i) {
        const DispatchRecord& rec = g_ring[(start + i) % kRingDepth];
        std::fprintf(stderr,
                     "occ vm:   seq=%llu va=0x%llx index=0x%llx "
                     "target=0x%llx\n",
                     static_cast<unsigned long long>(rec.t),
                     static_cast<unsigned long long>(rec.rip),
                     static_cast<unsigned long long>(rec.index),
                     static_cast<unsigned long long>(rec.target));
    }
}

void debug_dump() noexcept {
    const std::uint64_t tid = current_tid();
    std::fprintf(stderr, "occ vm: debug tid=%llu trapped=%zu step_pending=%d\n",
                 static_cast<unsigned long long>(tid), g_trapped_count,
                 static_cast<int>(g_step_pending));
    for (std::size_t i = 0; i < g_trapped_count; ++i) {
        std::fprintf(stderr,
                     "occ vm:   trapped page 0x%llx\n",
                     static_cast<unsigned long long>(g_trapped_pages[i]));
    }
    if (g_step_pending) {
        std::fprintf(stderr, "occ vm:   pending step page 0x%llx\n",
                     static_cast<unsigned long long>(g_step_page));
    }
}

}  // namespace occ::runtime::vm_trace

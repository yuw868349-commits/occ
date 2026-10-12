#include "occ/runtime/vm_trace.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <string_view>
#include <vector>

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

// The image base the trace armed against.
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

        if (g_file == nullptr && !g_to_stderr && !g_path.empty()) {
            g_file = std::fopen(g_path.c_str(), "w");
            if (g_file == nullptr) {
                std::fprintf(stderr,
                             "occ vm: cannot open %s; tracing to stderr\n",
                             g_path.c_str());
                g_to_stderr = true;
            }
        }
        char line[400];
        const int n = std::snprintf(
            line, sizeof(line),
            "{\"kind\":\"dispatch\",\"seq\":%llu,\"va\":\"0x%llx\","
            "\"index\":\"0x%llx\",\"base\":\"0x%llx\",\"target\":\"0x%llx\","
            "\"rsi\":\"0x%llx\",\"rdi\":\"0x%llx\",\"rsp\":\"0x%llx\","
            "\"rbp\":\"0x%llx\",\"st0\":\"0x%llx\",\"st1\":\"0x%llx\","
            "\"st2\":\"0x%llx\"}\n",
            static_cast<unsigned long long>(g_recorded),
            static_cast<unsigned long long>(rec.rip),
            static_cast<unsigned long long>(rec.index),
            static_cast<unsigned long long>(rec.base),
            static_cast<unsigned long long>(rec.target),
            static_cast<unsigned long long>(rec.rsi),
            static_cast<unsigned long long>(rec.rdi),
            static_cast<unsigned long long>(rec.rsp),
            static_cast<unsigned long long>(rec.rbp),
            static_cast<unsigned long long>(rec.st0),
            static_cast<unsigned long long>(rec.st1),
            static_cast<unsigned long long>(rec.st2));
        if (g_to_stderr) {
            std::fprintf(stderr, "%s", line);
        } else if (g_file != nullptr) {
            std::fwrite(line, 1, static_cast<std::size_t>(n), g_file);
            std::fflush(g_file);
        }
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

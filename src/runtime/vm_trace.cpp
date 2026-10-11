#include "occ/runtime/vm_trace.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <string_view>
#include <vector>

#include <sys/mman.h>

namespace occ::runtime::vm_trace {

namespace {

constexpr std::uint64_t kPage = 4096;

// The dispatch idioms this runtime recognizes, as byte patterns. The
// first is the one VMProtect 3.x emits for its main loop:
//   49 8b 0c c4   mov rcx, [r12+rax*8]
// followed by an indirect jump. Siblings cover the other register
// choices: r8 (`4c 8b 04 c4`), rax (`49 8b 04 c4`), and the plain
// `[r12+rax*8]` read into rcx without REX.B (`48 8b 0c c4`).
struct DispatchIdiom {
    const char* bytes;
    std::size_t length;
};

constexpr DispatchIdiom kIdioms[] = {
    {"\x49\x8b\x0c\xc4", 4},  // mov rcx, [r12+rax*8]
    {"\x4c\x8b\x04\xc4", 4},  // mov r8,  [r12+rax*8]
    {"\x49\x8b\x04\xc4", 4},  // mov rax, [r12+rax*8]
    {"\x48\x8b\x0c\xc4", 4},  // mov rcx, [r12+rax*8] (no REX.B)
};

// The ring buffer's depth: the tail the trace can show around a crash.
constexpr std::size_t kRingDepth = 512;

struct DispatchRecord {
    std::uint64_t t;      // CLOCK_MONOTONIC ns
    std::uint64_t rip;    // dispatch address
    std::uint64_t index;  // rax at dispatch
    std::uint64_t base;   // r12 at dispatch
    std::uint64_t target; // handler pointer read from the table
    std::uint64_t rsi;
    std::uint64_t rdi;
    std::uint64_t rsp;
};

// The trace's switch and output, read once.
bool g_to_stderr = false;
std::string g_path;
std::FILE* g_file = nullptr;

// The dispatch addresses, resolved at arm time. A packed image can carry
// more than one engine (VMProtect emits a separate VM per protected
// function), so every idiom site is a candidate; the trace records
// whichever ones the guest actually reaches.
constexpr std::size_t kMaxCandidates = 16;
std::uint64_t g_dispatchs[kMaxCandidates] = {};
std::size_t g_dispatch_count = 0;
bool g_resolved = false;

// The image base the trace armed against.
std::uint64_t g_image_base = 0;

// The trapped pages (dispatch pages without execute permission), and the
// single step the last service_fetch armed to re-trap the page it
// restored. A dispatch page holds ordinary code too -- the engine's own
// prologue and the jump network around it -- so every fetch into it
// faults, and only the fetch whose instruction pointer is a dispatch
// address becomes a record.
std::uint64_t g_trapped_pages[kMaxCandidates] = {};
std::size_t g_trapped_count = 0;
std::uint64_t g_stepping_page = 0;

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

std::size_t dispatch_count() noexcept {
    return g_dispatch_count;
}

std::uint64_t dispatch_at(std::size_t index) noexcept {
    return index < g_dispatch_count ? g_dispatchs[index] : 0;
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
            g_dispatchs[0] = at;
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
                        g_dispatchs[g_dispatch_count++] = image_base + off;
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
                     static_cast<unsigned long long>(g_dispatchs[i]));
    }
    std::fprintf(stderr, "\n");

    // Take the execute permission away from every page holding a dispatch
    // site. The first fetch into each faults; service_fetch restores and
    // re-traps on the step, so the guest runs free between dispatches.
    for (std::size_t i = 0; i < g_dispatch_count; ++i) {
        const std::uint64_t page = g_dispatchs[i] & ~(kPage - 1);
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
                     static_cast<unsigned long long>(g_dispatchs[i]));
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
    return g_stepping_page != 0;
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
    for (std::size_t i = 0; i < g_dispatch_count; ++i) {
        if (rip == g_dispatchs[i]) {
            is_dispatch = true;
            break;
        }
    }

    if (is_dispatch) {
        const std::uint64_t rax = static_cast<std::uint64_t>(g[REG_RAX]);
        const std::uint64_t r12 = static_cast<std::uint64_t>(g[REG_R12]);

        DispatchRecord rec{};
        rec.t = static_cast<std::uint64_t>([] {
            struct ::timespec ts {};
            ::clock_gettime(CLOCK_MONOTONIC, &ts);
            return static_cast<std::uint64_t>(ts.tv_sec) * 1000000000ull +
                   static_cast<std::uint64_t>(ts.tv_nsec);
        }());
        rec.rip = rip;
        rec.index = rax;
        rec.base = r12;
        rec.rsi = static_cast<std::uint64_t>(g[REG_RSI]);
        rec.rdi = static_cast<std::uint64_t>(g[REG_RDI]);
        rec.rsp = static_cast<std::uint64_t>(g[REG_RSP]);

        // The handler pointer is in the table the guest indexes: this
        // process maps the guest, so the read is a plain load from the
        // guest's own memory, which is the one source that cannot lie.
        // No alignment is assumed: VMProtect runs its base pointer through
        // a constant first (r12 often ends one byte off a table entry),
        // and the read the guest itself makes is the one that decides.
        rec.target = 0;
        if (r12 >= 0x10000 && r12 < 0x7ffffffff000ull) {
            const std::uint64_t cell = r12 + (rax & 0xfffff) * 8;
            if (cell >= 0x10000 && cell < 0x7ffffffff000ull) {
                const auto* table =
                    reinterpret_cast<const std::uint64_t*>(cell);
                rec.target = *table;
            }
        }

        g_ring[g_ring_pos] = rec;
        g_ring_pos = (g_ring_pos + 1) % kRingDepth;
        ++g_recorded;

        if (g_file == nullptr && !g_to_stderr && !g_path.empty()) {
            g_file = std::fopen(g_path.c_str(), "w");
            if (g_file == nullptr) {
                std::fprintf(stderr,
                             "occ vm: cannot open %s; tracing to stderr\n",
                             g_path.c_str());
                g_to_stderr = true;
            }
        }
        char line[320];
        const int n = std::snprintf(
            line, sizeof(line),
            "{\"kind\":\"dispatch\",\"seq\":%llu,\"va\":\"0x%llx\","
            "\"index\":\"0x%llx\",\"base\":\"0x%llx\",\"target\":\"0x%llx\","
            "\"rsi\":\"0x%llx\",\"rdi\":\"0x%llx\",\"rsp\":\"0x%llx\"}\n",
            static_cast<unsigned long long>(g_recorded),
            static_cast<unsigned long long>(rec.rip),
            static_cast<unsigned long long>(rec.index),
            static_cast<unsigned long long>(rec.base),
            static_cast<unsigned long long>(rec.target),
            static_cast<unsigned long long>(rec.rsi),
            static_cast<unsigned long long>(rec.rdi),
            static_cast<unsigned long long>(rec.rsp));
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
    g_stepping_page = page;
    uc->uc_mcontext.gregs[REG_EFL] |= 0x100;
    return true;
}

bool service_step(::ucontext_t* uc, std::uint64_t rip) noexcept {
    static_cast<void>(uc);
    static_cast<void>(rip);
    if (g_stepping_page == 0) {
        return false;
    }
    const std::uint64_t page = g_stepping_page;
    g_stepping_page = 0;
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

}  // namespace occ::runtime::vm_trace

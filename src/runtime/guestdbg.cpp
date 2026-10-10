// The debugger's state machine, and the safe memory path it shares with
// the API trace. See the header for the shape of the thing; this file is
// the implementation of the two halves and the seam between them.

#include "occ/runtime/guestdbg.h"

#include <atomic>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <map>
#include <new>

#include <fcntl.h>
#include <sched.h>
#include <unistd.h>

namespace occ::runtime::guestdbg {
namespace {

// The parked states, as one atomic the two sides pass between them:
// `0` the guest is running; `1` the guest is parked and the driving
// thread may read the stop; `2` the driving thread has answered and the
// parked handler may rewrite its context and return.
constexpr int kRunning = 0;
constexpr int kStopped = 1;
constexpr int kReleased = 2;

std::atomic<int> g_state{kRunning};

// The stop the handler publishes and the driving thread reads. Written
// once by the handler before the state flips to `kStopped`, and written
// again only by the driving thread between `kStopped` and `kReleased` --
// the atomic is the fence that makes both orders safe.
Stop g_stop;

// The breakpoints. The displaced byte is what the INT3 replaced, kept so
// the hit can put it back and the re-arm can put the INT3 back again. An
// address the safe read could not read is not here -- a breakpoint over
// bytes nobody can read is not a breakpoint, it is a trap with no
// original to restore.
std::map<std::uint64_t, std::uint8_t> g_breakpoints;

// Set when a release asked for the single step that re-arms the
// breakpoint it resumed past: the trace trap that follows belongs to the
// debugger, and its job is to put the INT3 back rather than to stop.
bool g_rearm_pending = false;
std::uint64_t g_rearm_address = 0;

// Set when a release asked for the *next* instruction to stop -- the
// `step` command -- as opposed to the silent step a continue takes over
// the breakpoint it just resumed. A trace trap with this flag publishes a
// new stop instead of clearing the flag and running on, which is what
// makes `step` repeatable: every stop's release re-arms the flag.
bool g_step_pending = false;

[[nodiscard]] int guest_mem_fd() noexcept {
    static const int fd = ::open("/proc/self/mem", O_RDWR);
    return fd;
}

}  // namespace

bool active() noexcept {
    static const bool on = [] {
        const char* value = ::getenv("OCC_DEBUG_ACTIVE");
        return value != nullptr && value[0] != '\0';
    }();
    return on;
}

Stop& current_stop() noexcept {
    return g_stop;
}

bool guest_stopped() noexcept {
    return g_state.load(std::memory_order_seq_cst) == kStopped;
}

void release(bool step) noexcept {
    // The flags the handler reads on its way out of the park. A release
    // from a breakpoint hit always carries the silent step that re-arms
    // it; a release from a step stop carries only the visibility of the
    // next instruction.
    g_rearm_pending = g_stop.breakpoint != 0;
    g_rearm_address = g_stop.breakpoint;
    g_step_pending = step;
    g_state.store(kReleased, std::memory_order_seq_cst);
}

// ------------------------------------------------------- driving thread --

bool set_breakpoint(std::uint64_t address) noexcept {
    if (g_breakpoints.contains(address)) {
        return true;  // already set; idempotent is the useful answer
    }
    std::uint8_t original = 0;
    if (read_memory(address, &original, 1) != 1) {
        return false;
    }
    const std::uint8_t int3 = 0xCC;
    if (!write_memory(address, &int3, 1)) {
        return false;
    }
    g_breakpoints.emplace(address, original);
    return true;
}

bool clear_breakpoint(std::uint64_t address) noexcept {
    const auto it = g_breakpoints.find(address);
    if (it == g_breakpoints.end()) {
        return false;
    }
    static_cast<void>(write_memory(address, &it->second, 1));
    g_breakpoints.erase(it);
    return true;
}

std::size_t breakpoint_count() noexcept {
    return g_breakpoints.size();
}

BreakpointInfo breakpoint_at(std::size_t index) noexcept {
    BreakpointInfo info;
    auto it = g_breakpoints.begin();
    for (std::size_t i = 0; i < index && it != g_breakpoints.end(); ++i) {
        ++it;
    }
    if (it != g_breakpoints.end()) {
        info.address = it->first;
        info.displaced = it->second;
    }
    return info;
}

std::size_t read_memory(std::uint64_t address, void* out,
                        std::size_t bytes) noexcept {
    const int fd = guest_mem_fd();
    if (fd < 0 || bytes == 0) {
        return 0;
    }
    auto* dst = static_cast<std::uint8_t*>(out);
    std::size_t done = 0;
    while (done < bytes) {
        const ssize_t got = ::pread(fd, dst + done, bytes - done,
                                    static_cast<off_t>(address + done));
        if (got <= 0) {
            break;
        }
        done += static_cast<std::size_t>(got);
    }
    return done;
}

bool write_memory(std::uint64_t address, const void* in,
                  std::size_t bytes) noexcept {
    const int fd = guest_mem_fd();
    if (fd < 0 || bytes == 0) {
        return false;
    }
    const auto* src = static_cast<const std::uint8_t*>(in);
    std::size_t done = 0;
    while (done < bytes) {
        const ssize_t put = ::pwrite(fd, src + done, bytes - done,
                                     static_cast<off_t>(address + done));
        if (put <= 0) {
            return false;
        }
        done += static_cast<std::size_t>(put);
    }
    // A write that covered a breakpoint's displaced byte changes what the
    // re-arm would put back -- the record follows the memory, or the
    // re-arm would silently undo the caller's write the next time the
    // breakpoint resumed.
    for (auto& [bp, original] : g_breakpoints) {
        if (address <= bp && bp < address + bytes) {
            original = 0xCC;
        }
    }
    return true;
}

// ----------------------------------------------------- the handler's side --

bool is_breakpoint_hit(std::uint64_t rip) noexcept {
    if (g_breakpoints.empty()) {
        return false;
    }
    // The kernel reports the trap with rip already past the INT3, so the
    // breakpoint is the byte below -- but the saved rip is also exactly
    // what a debugger-modified context would resume to, and a hit on the
    // address itself is a hit all the same. Either naming the breakpoint
    // counts.
    return g_breakpoints.contains(rip - 1) || g_breakpoints.contains(rip);
}

void enter_stop(::ucontext_t* uc, std::uint64_t trap_address) noexcept {
    for (int i = 0; i < NGREG; ++i) {
        g_stop.regs[i] = static_cast<std::uint64_t>(uc->uc_mcontext.gregs[i]);
    }
    g_stop.rip = trap_address;
    g_stop.eflags = static_cast<std::uint64_t>(uc->uc_mcontext.gregs[REG_EFL]);
    g_stop.breakpoint = g_breakpoints.contains(trap_address) ? trap_address : 0;
    g_stop.stopped = true;
    g_state.store(kStopped, std::memory_order_seq_cst);

    // The park. The driving thread is in the same address space reading
    // this stop and the guest's memory; the only thing it cannot do is
    // run the guest, and the guest is the thread doing this waiting. A
    // yielding spin, because there is nothing to wait on but the answer.
    while (g_state.load(std::memory_order_seq_cst) != kReleased) {
        ::sched_yield();
    }

    // The release asked for one of: a plain resume past the breakpoint
    // (the re-arm flag is up, and the step over the restored instruction
    // is what re-arms it), a stop on the next instruction, or both at
    // once. The registers come back first, wholesale -- the driving
    // thread may have rewritten any of them -- and then the two
    // decisions that belong to the seam rather than to the guest.
    for (int i = 0; i < NGREG; ++i) {
        uc->uc_mcontext.gregs[i] =
            static_cast<::greg_t>(g_stop.regs[i]);
    }
    // The rip goes back over the INT3, whether or not the driving thread
    // moved it: the saved copy already carries whatever it wrote.
    if (g_stop.breakpoint != 0 && g_rearm_pending) {
        const auto it = g_breakpoints.find(g_stop.breakpoint);
        if (it != g_breakpoints.end()) {
            static_cast<void>(write_memory(g_stop.breakpoint, &it->second, 1));
        }
        uc->uc_mcontext.gregs[REG_RIP] =
            static_cast<::greg_t>(g_stop.breakpoint);
        uc->uc_mcontext.gregs[REG_EFL] =
            static_cast<::greg_t>(g_stop.eflags | 0x100);
    } else {
        uc->uc_mcontext.gregs[REG_RIP] = static_cast<::greg_t>(g_stop.rip);
        const std::uint64_t flags =
            g_step_pending ? (g_stop.eflags | 0x100) : g_stop.eflags;
        uc->uc_mcontext.gregs[REG_EFL] = static_cast<::greg_t>(flags);
    }
    g_state.store(kRunning, std::memory_order_seq_cst);
}

bool rearm_pending() noexcept {
    return g_rearm_pending;
}

void complete_rearm(::ucontext_t* uc) noexcept {
    // The instruction the breakpoint replaced has executed -- the trace
    // trap is one past it -- so the INT3 goes back over it and the flag
    // comes down. The rip the trap saved is where the guest is about to
    // run, untouched.
    const auto it = g_breakpoints.find(g_rearm_address);
    if (it != g_breakpoints.end()) {
        const std::uint8_t int3 = 0xCC;
        static_cast<void>(write_memory(g_rearm_address, &int3, 1));
    }
    g_rearm_pending = false;
    g_rearm_address = 0;
    if (!g_step_pending) {
        uc->uc_mcontext.gregs[REG_EFL] &=
            static_cast<::greg_t>(~0x100);
    }
}

bool step_requested() noexcept {
    return g_step_pending;
}

}  // namespace occ::runtime::guestdbg

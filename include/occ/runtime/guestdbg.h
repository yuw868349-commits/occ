// The debugger's half of the guest: breakpoints, stops, and the
// conversation between a stopped guest and the thread that drives it.
//
// The guest is native code on this process's main thread of execution, so
// a debugger for it has no process boundary to reach across -- which is
// why it needs no ptrace, and also why "stop the guest" cannot mean "wait
// for a process to sit still". A stop is the guest's own thread, parked
// inside the signal handler on a spin, holding its register state in a
// copy the driving thread can read and change. The driving thread lives
// in the same address space and reads the guest's memory directly; the
// only state worth copying is the registers, because those live in the
// kernel's frame and belong to the handler until it returns.
//
// Breakpoints are INT3 bytes patched over the guest's instructions, the
// way a classic debugger does it, with the displaced bytes kept here so
// the hit can restore them. A hit is recognized in the fault handler
// before the guest's own dispatch -- a breakpoint is the debugger's trap,
// not the guest's exception -- and the handler parks on `enter_stop`
// until the driving thread answers. Resuming single-steps over the
// instruction the breakpoint replaced, which is what lets the breakpoint
// be re-armed behind the guest's back: the step lands on the trace trap,
// the byte goes back, the flag comes down, and the guest runs on without
// ever seeing the seam.

#ifndef OCC_RUNTIME_GUESTDBG_H_
#define OCC_RUNTIME_GUESTDBG_H_

#include <cstdint>
#include <sys/ucontext.h>

namespace occ::runtime::guestdbg {

// Whether the run is a debugging session. Read from
// `OCC_DEBUG_ACTIVE`, set by the `occ dbg` command for the runner it
// starts; everything below answers false without it.
[[nodiscard]] bool active() noexcept;

// Registers at a stop, as the fault handler saw them. The driving thread
// reads this copy while the guest is parked and may rewrite `rip` and
// `eflags` before releasing; the release applies what it changed.
struct Stop {
    std::uint64_t rip = 0;
    std::uint64_t regs[NGREG] = {};  // the gregs order, as the handler read them
    std::uint64_t eflags = 0;
    // The breakpoint that was hit: the address the INT3 sits at, which is
    // one below the rip the kernel reported, and the reason the stop
    // happened rather than a step or a fault.
    std::uint64_t breakpoint = 0;
    bool stopped = false;
};

// The stop the guest is parked at, when it is parked. The driving thread
// may rewrite any field of it -- registers, rip, eflags -- before
// releasing; the release applies what it wrote. Valid only while
// `guest_stopped()` answers true.
[[nodiscard]] Stop& current_stop() noexcept;
[[nodiscard]] bool guest_stopped() noexcept;

// Releases the parked guest. `step` asks that the next instruction stop
// again; a release past a breakpoint always single-steps the instruction
// the breakpoint replaced, because that is how the breakpoint gets
// re-armed behind the guest's back, and a step is that same step made
// visible.
void release(bool step) noexcept;

// -- breakpoints, from the driving thread --------------------------------

// Sets a breakpoint at a guest virtual address. The byte there is saved
// and replaced with INT3; false means the address was unreadable, which
// the safe read answers rather than a fault, or a breakpoint already
// there.
[[nodiscard]] bool set_breakpoint(std::uint64_t address) noexcept;

// Removes one, putting the original byte back. False when there was no
// breakpoint at the address.
[[nodiscard]] bool clear_breakpoint(std::uint64_t address) noexcept;

// The breakpoints set, as (address, displaced byte) pairs -- what a
// `breaks` command lists.
struct BreakpointInfo {
    std::uint64_t address = 0;
    std::uint8_t displaced = 0;
};
[[nodiscard]] std::size_t breakpoint_count() noexcept;
[[nodiscard]] BreakpointInfo breakpoint_at(std::size_t index) noexcept;

// -- memory, from the driving thread --------------------------------------

// Reads guest memory through the same safe path the API trace uses:
// a bad address is a short read, not a fault, because the driving thread
// has a REPL to answer and no fault handler of its own to land in.
// Answers the number of bytes actually read.
[[nodiscard]] std::size_t read_memory(std::uint64_t address, void* out,
                                      std::size_t bytes) noexcept;

// Writes guest memory the same way, after clearing a breakpoint's INT3
// concern: the write goes through, and if it covered an armed
// breakpoint's displaced byte the record is updated so the re-arm does
// not undo the caller's write.
[[nodiscard]] bool write_memory(std::uint64_t address, const void* in,
                                std::size_t bytes) noexcept;

// -- the handler's side ----------------------------------------------------

// Whether this trap is a breakpoint hit. `rip` is what the kernel saved,
// which for an INT3 is the byte *after* the trap, so the test looks one
// below it as well.
[[nodiscard]] bool is_breakpoint_hit(std::uint64_t rip) noexcept;

// Parks the guest at a breakpoint hit. Copies the handler's register
// state out, publishes the stop, and spins until the driving thread
// releases -- which is when this returns, with `uc` rewritten to what the
// release asked for: the rip back over the INT3, the original byte in
// place of it, and the trap flag set if the release wants the next
// instruction to stop too.
void enter_stop(::ucontext_t* uc, std::uint64_t trap_address) noexcept;

// Whether a trace trap should be spent re-arming a breakpoint rather than
// shown to the guest. The driving thread's release decided this when it
// let the guest go.
[[nodiscard]] bool rearm_pending() noexcept;

// Completes the re-arm: the INT3 goes back over the (now executed)
// instruction, and the flag the step needed comes down. Called from the
// handler on the trace trap the release's single step produced.
void complete_rearm(::ucontext_t* uc) noexcept;

// Whether a trace trap should stop for the debugger -- the release asked
// for a step, and this is that step landing.
[[nodiscard]] bool step_requested() noexcept;

}  // namespace occ::runtime::guestdbg

#endif  // OCC_RUNTIME_GUESTDBG_H_

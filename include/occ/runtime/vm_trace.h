// Tracing a virtual-machine dispatcher.
//
// A code-virtualizing packer (VMProtect, Themida) does not decrypt a
// payload section and jump into it -- that would be a dumpable OEP. It
// translates the original instructions into bytecode for an interpreter
// (the VM engine) that the packer ships in the image. The engine is plain
// native code; what it consumes is not. The bytecode stays encrypted on
// disk and in memory; the engine decrypts one virtual instruction at a
// time, dispatches on its opcode through a handler table, and the
// handlers carry out the emulated operation. Nothing is ever written back
// to the code pages, which is why the page-protection watch -- the
// instrument for a decrypt-in-place packer -- sees nothing.
//
// The observable seam is the dispatch itself. The engine reads a handler
// pointer out of a table (`mov rcx, [r12+rax*8]` and its siblings) and
// jumps to it. Each trip through that read is one virtual instruction
// executed, and the index in `rax` names the opcode. Tracing the
// dispatcher is therefore tracing the virtual instruction stream: record
// the index and the handler address on every dispatch, and the stream is
// the program the packer hid -- enough to re-assemble the original
// instruction sequence offline (the `devirt` side of this runtime).
//
// The instrument is the page trap, the same one the OEP watch uses, not
// the trap flag: a guest that single-steps on purpose would see the flag
// and a timing-sensitive packer would notice the slowdown of a
// single-step-every-instruction trace. The dispatch page loses execute
// permission; the engine's fetch into it faults with the instruction
// pointer naming the dispatch, the record is taken from the faulting
// frame, the page is restored, the one instruction steps, and the page
// goes back to non-execute for the next dispatch. The guest runs free
// between dispatches, which keeps both the timing and the flag clean.
//
// Two knobs, both read once at arm time:
//   OCC_VM_TRACE      path of the JSON-lines trace file; the value `1`
//                     writes to stderr instead. Off unless set.
//   OCC_VM_DISPATCH   explicit dispatch address (guest VA); when absent,
//                     the image is scanned for the known dispatch idiom.
//
// On a fault that ends the guest, the trace appends the dispatches that
// led to it -- the last entries of the ring buffer -- so a crash site is
// always reachable from the virtual instruction stream that produced it.

#pragma once

#include <cstdint>

#include <signal.h>

namespace occ::runtime::vm_trace {

// Whether the run asked for a VM trace.
[[nodiscard]] bool enabled() noexcept;

// How many dispatches have been recorded so far.
[[nodiscard]] std::uint64_t recorded() noexcept;

// The image base the trace armed against; the dump that rides the first
// dispatch reads the decrypted image from it.
[[nodiscard]] std::uint64_t image_base() noexcept;

// The virtual clock, milliseconds: the time the guest is made to believe
// has passed. It is driven by the dispatch count at the rate a clean VM
// dispatches (no trap flag, no page faults), so a timing check that the
// packer runs -- GetTickCount between two dispatch points -- sees the
// speed it would have seen with no instrumentation at all. Zero when the
// trace is not running, in which case the real clock stands in.
[[nodiscard]] std::uint64_t virtual_tick_ms() noexcept;

// The dispatch addresses the trace will watch, resolved once. The first
// element is also the trap's page anchor. Empty when no dispatch idiom
// was found and none was named. `image_base` is the guest's image base,
// mapped in this process, scanned as native bytes.
[[nodiscard]] std::size_t dispatch_count() noexcept;
[[nodiscard]] std::uint64_t dispatch_at(std::size_t index) noexcept;

// Whether the trace is armed and the fault loop should service it.
[[nodiscard]] bool active() noexcept;

// Removes execute permission from the pages holding the dispatch sites.
// Called once, before the guest runs; the first fetch into a dispatch
// page faults with the dispatch address as the instruction pointer.
void arm_trap(std::uint64_t image_base) noexcept;

// Whether this SIGSEGV is a fetch into a trapped dispatch page -- the
// saved rip names the faulting byte, which is the discriminator against
// every data fault.
[[nodiscard]] bool handles_fetch(std::uint64_t rip) noexcept;

// Whether the last dispatch record left a single step outstanding.
[[nodiscard]] bool step_outstanding() noexcept;

// Services a dispatch fetch: records the virtual instruction from the
// faulting frame, restores the page's execute permission, and arms the
// single step that will re-trap it. Answers false when the fault was not
// the trace's after all.
[[nodiscard]] bool service_fetch(::ucontext_t* uc, std::uint64_t rip) noexcept;

// Completes the single step: re-traps the dispatch page (execute
// permission off again) and clears the outstanding step. Answers false
// when the trap was not the trace's.
[[nodiscard]] bool service_step(::ucontext_t* uc, std::uint64_t rip) noexcept;

// Appends the ring buffer's tail to the trace. Called by the fault
// handler when a guest-ending fault (one no guest handler accepted) is
// about to end the run: the dispatches immediately before the crash are
// the virtual instruction stream the crash came from.
void flush_on_fault() noexcept;

}  // namespace occ::runtime::vm_trace

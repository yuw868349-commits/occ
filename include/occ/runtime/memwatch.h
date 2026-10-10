// Watching a guest write to its own image.
//
// The guest is native code. When it decrypts a section or patches a
// function prologue, the write happens on the real CPU, through a real
// `mov`, and nothing in this runtime is consulted on the way -- which is
// exactly why a packed program can do those things without the runtime
// noticing. An observer built on `ptrace` would use hardware breakpoints
// to catch them; there is no `ptrace` here, because the guest is not a
// process of its own.
//
// What this process does have is its own page tables. The watch is a page
// protection: the watched pages lose their write permission, and the first
// store into one raises SIGSEGV -- the same signal a null dereference
// raises, and the same handler, which is why the watch integrates with the
// fault path rather than beside it. The handler recognizes a watched
// write, records the instruction and the address, re-admits writes to that
// one page, and single-steps the store so that the protection can be put
// back with the store's effect visible and no other write having slipped
// through.
//
// The single step is the part that has to be honest about its cost. While
// the watch is on, every store into the watched range costs a fault, a
// context record, a context restore and another fault; a decryption loop
// that touches a megabyte a byte at a time will take a very long time
// about it. That is not an implementation shortcoming to fix later -- it
// is what watching a write costs on an architecture whose only write
// trap is the page fault -- and it is the trade the analyst makes on
// purpose when they turn this on.
//
// One interaction is documented rather than solved. The single step is
// carried by `EFLAGS.TF`, and the guest can read that flag: a program
// that sets `TF` on itself to detect a tracer will see the watch's step.
// The x86 architecture has no hidden single-step bit, so no
// implementation on it can hide this one; what the code does instead is
// keep the watch's step and the guest's own step distinguishable, so a
// guest that steps on purpose keeps working while it is being watched.

#ifndef OCC_RUNTIME_MEMWATCH_H_
#define OCC_RUNTIME_MEMWATCH_H_

#include <cstdint>

namespace occ::runtime::memwatch {

// Whether the run asked to watch. `OCC_MEMWATCH` names the range: `image`
// watches every executable section of the guest's image, or an explicit
// `rva:size` pair watches one range. Off by default, for the cost above.
[[nodiscard]] bool enabled() noexcept;

// Arms the watch over the image at `image_base`.
//
// The watched ranges are read from the image's own headers -- the
// executable sections, or the range the environment named -- and the
// permission change happens here, before the guest runs. False means the
// headers did not parse or a protection change was refused; the watch is
// then simply off rather than half on, because a watch that covers part of
// a decryption loop reports a decryption that did not happen.
[[nodiscard]] bool arm(std::uint64_t image_base) noexcept;

// Whether this fault is a store into a watched page. Only meaningful for
// a write fault; the handler checks this before it decides the fault
// belongs to the guest.
[[nodiscard]] bool handles(std::uint64_t fault_address) noexcept;

// Services a watched store: records it, re-admits writes to the page it
// landed in, and arms the single step that will re-protect it. Called by
// the fault handler before any guest-visible dispatch, because a watch is
// not the guest's exception to handle.
void service_write(std::uint64_t fault_address, std::uint64_t rip) noexcept;

// Whether the last watched store left a single step outstanding.
[[nodiscard]] bool step_outstanding() noexcept;

// Completes the single step: re-protects the page, records the store's
// effect, and clears the outstanding step. Answers false when the trap
// was not the watch's -- a guest that single-steps on purpose traps too,
// and its step belongs to it.
[[nodiscard]] bool service_step() noexcept;

// Whether instruction tracing is on, and how it is bounded.
// `OCC_TRACE_STEPS` carries a count; the trace stops after that many.
[[nodiscard]] bool step_trace_active() noexcept;

// Records one traced instruction -- the address it sits at and the bytes
// it is -- and spends the trace's budget.
void record_step(std::uint64_t rip) noexcept;

}  // namespace occ::runtime::memwatch

#endif  // OCC_RUNTIME_MEMWATCH_H_

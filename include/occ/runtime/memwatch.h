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
// and its step belongs to it. `rip` is the instruction that stepped: the
// OEP trap uses it to leave the page without execute permission, except
// when the guest is already executing in that page, because a stub that
// patches itself in place would otherwise fault on its own next fetch and
// the trap would report the stub as its own entry point.
[[nodiscard]] bool service_step(std::uint64_t rip) noexcept;

// Whether instruction tracing is on, and how it is bounded.
// `OCC_TRACE_STEPS` carries a count; the trace stops after that many.
[[nodiscard]] bool step_trace_active() noexcept;

// Records one traced instruction -- the address it sits at and the bytes
// it is -- and spends the trace's budget.
void record_step(std::uint64_t rip) noexcept;

// The OEP trap, on top of the watch's machinery.
//
// An unpacker decrypts its payload into a page and then jumps into it, and
// the moment of that jump is the original entry point -- the one state a
// dump wants to be taken at, because from there on the program has begun
// and the pristine decrypted image is already being consumed. The trap
// makes the jump observable: when a watched page of an executable section
// takes a store, the step that follows leaves the page *without* execute
// permission rather than restoring it, and the first fetch that lands in
// the page faults -- a fault whose address is the instruction pointer,
// which is what distinguishes an execution from a data access. That fault
// is the OEP.
//
// `OCC_DUMP_AT_OEP` turns the trap on. It rides on the watch, because the
// watch's steps are what make the state changes safe: the store completed
// before the permission drops, so the page the guest jumps into is the
// page as written, whole.
[[nodiscard]] bool oep_trap_enabled() noexcept;

// Whether a fault is an execution into a page the trap holds. Answers
// false for anything else -- a data fault into the same page is the
// watch's write business, and a fetch into a page nobody wrote is the
// guest's own fault.
[[nodiscard]] bool service_fetch(std::uint64_t rip) noexcept;

// The first OEP the trap caught, and whether one was caught at all. Zero
// until then. A run whose guest never jumps into a page it wrote -- an
// unpacker that decrypts in place, or no unpacker at all -- reports no
// OEP, which is a finding and not a failure.
[[nodiscard]] bool oep_taken() noexcept;
[[nodiscard]] std::uint64_t oep_rip() noexcept;

// The image base the watch armed over, kept so the fault handler can dump
// at the OEP without the handler carrying state of its own.
[[nodiscard]] std::uint64_t image_base() noexcept;

// Re-asserts the watch over a range the guest itself re-protected.
//
// A packer makes its target page writable -- `VirtualProtect`, the same
// call the oracle uses -- and if that change stood, the stores into the
// page would not fault and the watch would go blind exactly on the
// program whose writes it exists to see. After the guest's change takes
// effect, the watched pages in the range go back to what the watch
// requires: write permission taken away again, and the OEP-trapped pages
// left without execute. The guest's request is recorded in what the page
// becomes when the watch finally lets go; until then the watch wins,
// because the watch's protection is not a permission, it is the
// instrument.
void note_protect(std::uint64_t address, std::uint64_t size) noexcept;

}  // namespace occ::runtime::memwatch

#endif  // OCC_RUNTIME_MEMWATCH_H_

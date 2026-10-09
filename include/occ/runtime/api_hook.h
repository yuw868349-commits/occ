// The hook that makes a guest's API calls visible.
//
// The observer layer watches a target through `ptrace`, which needs the
// target to be a process of its own. The guest of the PE runtime is not:
// it is native code this process runs in-process, so no tracer can see it,
// and the calls it makes arrive as ordinary host calls. What this file
// adds is the only vantage point that exists for that shape of target --
// the runtime's own export surface.
//
// The mechanism is the trampoline the module builder already writes. Every
// export of every module this runtime presents to a guest is reached
// through a small stub in the module's image, and that stub is built here.
// Left alone it is `movabs rax, <implementation>; jmp rax`, which is the
// whole of a call. With the trace on it becomes `mov r11, <slot>; movabs
// rax, <hook>; jmp rax`, where the hook records the slot and then jumps to
// the same implementation the plain stub would have reached. The guest
// sees one extra indirect jump; the implementation sees the same
// registers, the same stack and the same ABI, because the hook restores
// every register it touched before it jumps.
//
// The slot is what makes this general rather than a list of special cases:
// a slot is registered per export as the module is built, the name and the
// implementation address go into tables indexed by it, and nothing in the
// hook itself knows or cares which API it is looking at.
//
// The trace is off unless `OCC_API_TRACE` is set, because it changes the
// code a guest can read: a hardened image that hashes a prologue, or
// checks that an exported address falls where it expects, is entitled to
// an opinion about a stub that grew by sixteen bytes. Off is the honest
// default and on is the analyst's deliberate choice.

#ifndef OCC_RUNTIME_API_HOOK_H_
#define OCC_RUNTIME_API_HOOK_H_

#include <cstdint>
#include <span>
#include <string_view>

namespace occ::runtime::api_hook {

// Whether the run records the calls it makes. Read once, from the
// environment, for the same reason the guest trace is: a person who set
// the variable wants the trace and not a negotiation about it.
[[nodiscard]] bool enabled() noexcept;

// Registers one export and answers the slot its trampoline should carry.
//
// The name is kept for the report and the address is the implementation
// the hook jumps to -- the same value the plain trampoline would have
// loaded. With the trace off this answers a slot anyway: the tables are
// the hook's own business, and the caller decides what to write into its
// trampoline from `enabled()`, not from what this returns.
[[nodiscard]] std::uint32_t note(std::string_view module,
                                 std::string_view name,
                                 std::uint64_t address) noexcept;

// The hook's entry point, reached by the trampolines. Written in assembly
// because it is not a C function: the guest calls it with the Windows x64
// convention's registers still holding the arguments, it must leave them
// exactly as it found them, and it returns by jumping to the
// implementation rather than to its caller. `r11` carries the slot.
extern "C" void occ_api_hook() noexcept;

// What the hook calls: the slot and the first three argument registers as
// they were on entry -- `rcx`, `rdx` and `r8`. The values are passed raw
// and are not interpreted here: what an argument means depends on which
// API it belongs to, and a report that guessed would be worse than one
// that prints the number it was given.
extern "C" void occ_api_note(std::uint64_t index, std::uint64_t a0,
                             std::uint64_t a1, std::uint64_t a2) noexcept;

// The table the hook reads: slot to implementation address. Extern "C" and
// a pointer rather than the array itself, so the assembly names one
// symbol whose value the C++ side owns.
extern "C" std::uint64_t* occ_api_targets;

// The name an implementation address was registered under, or nullptr when
// the address was not registered.
//
// This is the reverse of the table the hook reads, and it is what makes a
// rebuilt import slot nameable: a packed image has no import directory to
// read, so the only record of "this address is KERNEL32!CreateFileW" is
// the one made when the module surface was built. The registration happens
// whether or not the trace is on -- the answer is wanted for a dump that
// traces nothing -- so this is available in either mode.
[[nodiscard]] const char* name_for_address(std::uint64_t address) noexcept;

// Registers an address that resolves to an already-claimed slot.
//
// A module's exports are reached through the trampolines in its image, and
// a guest that walks the loader list reads the export table and stores what
// it finds there -- so the address an image calls through, and the address
// a rebuilt import slot holds, are the trampoline's and not the
// implementation's. Both are registered so that either one names the same
// function: the implementation when the trace names what ran, the
// trampoline when a dump names what was stored.
void note_trampoline(std::uint64_t address, std::uint32_t slot) noexcept;

}  // namespace occ::runtime::api_hook

#endif  // OCC_RUNTIME_API_HOOK_H_

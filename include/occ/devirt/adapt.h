// Adaptation of the lift engine to a virtual machine that does not
// record its own conventions, and a purely static (trace-free) lifting
// of a handler CFG from a code image.
//
// Two jobs live here, and they answer the same question -- "which
// registers play the stack and cursor roles, and what does the handler
// graph look like?" -- from two different sources of evidence.
//
// == 1. infer_convention: roles from the trace alone ==
//
// The lift engine's own `Convention` is the register assignment this
// packer variant was built on. A variant that was built on a different
// assignment -- the virtual stack on rdi, the cursor on r12 -- produces
// a trace whose sampled fields move differently: the field that advances
// in small steps is a stack or cursor candidate, the field the
// dispatcher leaves alone is a table or engine base, and the field that
// occasionally jumps large is the handler-table base being switched.
//
// `infer_convention` measures, per sampled register field, the pattern of
// movement across adjacent dispatches: the fraction of transitions that
// leave it alone, the fraction that move it a little (<= 64 bytes), the
// fraction that jump it far, and -- among the small moves -- the fraction
// that are eight-aligned and the mean magnitude. Roles are then assigned
// by what a real VM's registers do, not by hard-coded register names:
//
//   stack/cursor   the (usually two) fields that move in small steps;
//                  the more eight-aligned, larger-stepping one is the
//                  stack (qword slots), the other the cursor (bytecode
//                  instruction sizes)
//   table           the static field with the large jumps
//   engine          the remaining most-static field
//
// Every assignment is gated on a measured margin -- aligned-vs-unaligned
// separation for stack/cursor, a positive jump share for the table, a
// unique most-static field for the engine. When the trace does not
// separate the roles (two movers that move alike, no static field with
// jumps, a tie for the engine), the inference refuses: it returns the
// default convention, `confident = false`, and notes why. It never
// guesses. All thresholds are named constants at the top of the
// implementation so the method is auditable.
//
// == 2. lift_static: a trace-free CFG lift ==
//
// The trace is how this de-virtualizer normally learns which handler
// runs when, and it is exactly what an unpacker has to do without. A
// purely static lift starts from the image alone: `entry_va` is the
// first handler, and the dispatcher's decrypt-and-jump pattern -- `mov
// rax,[rsi]; rol rax,n; add rsi,8; jmp rax` -- is what the lift engine
// already turns into a dispatch edge whose target is an expression over
// the bytecode. Bind the bytecode inputs to the actual image bytes at a
// known entry cursor and the expression evaluates to the next handler's
// address. That makes one handler's effect provably the next handler's
// entry, and a worklist over the handlers reaches a fixpoint: lift a
// handler, resolve its dispatch target against the image, follow it.
//
// The cursor is carried along the edges: a handler's `rsi_new` (the
// cursor expression) is evaluated under the same binding and becomes the
// successor's entry cursor, so a stream of decrypt handlers chains
// naturally. A dispatch target that depends on a value the image cannot
// supply -- the stack pointer, a host register, an unknown -- is
// reported as an indirect node and the lift is marked incomplete:
// honestly, never guessed. Budgets (`max_handlers`,
// `max_instructions_per_handler`) bound the worklist and the per-handler
// walk, and an exhausted budget is reported the same way -- incomplete
// with a note, not a silent truncation.
//
// The whole module is deliberately free of heuristics that cannot be
// tested: every claim is either measured statistics (with margins and
// refusal) or a fixpoint over resolvable edges (with honest failure).

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "occ/devirt/lift.h"

namespace occ::devirt::adapt {

// The outcome of inferring a VM's register convention from a trace.
// `confident` is true only when the trace separated every role with a
// margin. On any refusal the convention is the default and `notes`
// explains what could not be told apart.
struct InferResult {
    lift::Convention convention;  // the default when inference refused
    bool confident = false;
    std::vector<std::string> notes;
};

// Infers the convention a trace was recorded under, from the movement
// patterns of the sampled register fields across adjacent dispatches.
// See the file comment for the method. `rows` needs at least two
// dispatches; with fewer the inference refuses.
[[nodiscard]] InferResult infer_convention(const std::vector<lift::Row>& rows);

// One handler in the static CFG. `successors` are the dispatch targets
// that resolved to concrete image addresses; when the target could not
// be resolved `indirect` is true, the lift is incomplete, and `note`
// says why.
struct CfgNode {
    std::uint64_t va = 0;
    std::vector<std::uint64_t> successors;  // resolved dispatch targets
    bool indirect = false;
    std::string note;
};

// The static lift of the handler graph reachable from `entry_va`.
// `nodes[i]` is the handler at that address and `handlers[i]` is its
// model; the two arrays stay index-aligned even when the budget cut the
// walk short (a node that was discovered but never lifted has a default
// Handler).
struct StaticLift {
    std::vector<CfgNode> nodes;
    std::vector<lift::Handler> handlers;  // nodes[i] <-> handlers[i]
    std::vector<std::string> notes;
    bool complete = false;  // the worklist converged inside the budget
    std::uint64_t iterations = 0;  // handlers actually lifted
};

// Budgets and the known entry state for a static lift. `max_handlers`
// caps the number of handlers the worklist may lift (0 = no cap);
// `max_instructions_per_handler` is handed to the per-handler
// summarize walk. `cursor_known`/`entry_cursor` supply the bytecode
// cursor the entry handler was entered with -- without a known cursor
// the decrypt-dispatcher's target expression stays unbound and the
// lift reports an indirect entry (honestly incomplete).
struct StaticOptions {
    std::size_t max_handlers = 4096;
    std::size_t max_instructions_per_handler = 96;
    bool cursor_known = false;
    std::uint64_t entry_cursor = 0;
};

// Lifts the handler CFG reachable from `entry_va` statically. `image`
// is the mapped image at `image_base`; every resolved address must lie
// inside it. See the file comment for the method.
[[nodiscard]] StaticLift lift_static(const std::uint8_t* image,
                                     std::size_t image_size,
                                     std::uint64_t image_base,
                                     std::uint64_t entry_va,
                                     const lift::Convention& convention = {},
                                     const StaticOptions& options = {});

}  // namespace occ::devirt::adapt

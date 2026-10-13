// Opaque predicate elimination.
//
// An opaque predicate is a condition that is constant (always true or
// always false) but *looks* data-dependent, so that a human reader -- or
// a naive analysis -- cannot see the branch is dead. OLLVM emits a
// canonical family of them: `(x*x - x) & 1 == 0` (always true, because
// x*x-x is even), `x & ~x == 0` (always true), `x | ~x == 0xff` (always
// true at width 8), each usually wrapped as the condition of a branch
// whose other side is the "real" successor or junk code.
//
// The eliminator does not recognize shapes; it *proves* constants. For
// every 1-bit edge condition c it asks two questions of the equivalence
// layer:
//
//   prove c == 1   -> the edge always fires
//   prove c == 0   -> the edge never fires
//
// The word-level ring layer answers first (it decides constants and
// ring identities with no search), and when it answers Unknown the CDCL
// circuit path is asked. The answering method and its statistics
// (conflicts, propagations, or the ring witness) are recorded per step,
// so the report says *how* each predicate was proven, not only that it
// was.
//
// Structural rules, and the assumption they rest on:
//
//   R1. An edge whose condition proves constant-false is deleted. This
//       is sound for any block.
//   R2. In a block with exactly two edges, an edge whose condition
//       proves constant-true makes that edge unconditional and deletes
//       the other edge. This is the OLLVM branch shape
//       `if (opaque) A else B`.
//   R3. In a block with three or more edges (a switch-like block), an
//       edge whose condition proves constant-true is recorded with its
//       proof but *not* structurally forced: forcing it would delete the
//       other cases, which is only sound when the edges are mutually
//       exclusive and exactly one fires. That is a plausible reading of
//       a switch, but not one this pass is willing to commit to without
//       the caller opting in; the evidence is kept so the flattening
//       pass can use it. `force_multiway` opts into the aggressive
//       reading (constant-true edge wins, all other edges deleted).
//
// After any deletions, a block left with a single edge has that edge
// made unconditional (its condition is irrelevant once it is the only
// successor).
//
// Edge conditions that prove neither constant are left alone and
// counted; the pass never guesses.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "occ/devirt/bitblast.h"

#include "occ/deobf/ir.h"

namespace occ::deobf {

struct OpaqueOptions {
    // Ask the always-true / always-false questions at all. Turning both
    // off makes the pass a no-op; the two switches exist so a caller can
    // prove only the cheap direction.
    bool prove_always_true = true;
    bool prove_always_false = true;
    // Apply R3's aggressive reading to multi-way blocks (see the file
    // comment). Default off: evidence is recorded, structure is not
    // forced.
    bool force_multiway = false;
    // Request DRUP certificates for the SAT-answered cases. Costly (a
    // proof is generated per predicate) and only useful when the report
    // is being audited; default off.
    bool want_proof = false;
};

// One predicate verdict: which edge, what the condition was, what was
// proven, and by which layer.
struct OpaqueStep {
    std::uint32_t block = 0;
    std::uint32_t edge = 0;
    std::string cond;         // pretty() of the edge condition
    bool constant_true = false;
    bool constant_false = false;
    devirt::bb::Method method = devirt::bb::Method::Sat;  // which layer answered
    std::uint64_t conflicts = 0;
    std::uint64_t propagations = 0;
    std::string evidence;     // ring witness or SAT stats / proof lines
    std::string action;       // "deleted", "forced unconditional", ...
};

struct OpaqueResult {
    std::vector<OpaqueStep> steps;
    std::size_t edges_deleted = 0;
    std::size_t edges_forced = 0;
    std::size_t conditions_inspected = 0;  // incl. non-constant ones
    std::vector<std::string> notes;
    LiftedFunc func;          // the cleaned copy
};

// Eliminates opaque predicates from `func` and returns a new LiftedFunc
// with the dead edges removed and the surviving single-edge blocks made
// unconditional. `func` itself is not modified. Every verdict (constant
// or not) is recorded in `out.steps` with its method and statistics.
[[nodiscard]] LiftedFunc eliminate_opaque(const LiftedFunc& func,
                                          const OpaqueOptions& options,
                                          OpaqueResult& out);

}  // namespace occ::deobf

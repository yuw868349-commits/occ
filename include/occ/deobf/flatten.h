// Control-flow flattening recovery.
//
// OLLVM's flattening pass turns a structured CFG into a state machine:
// every original block ends by writing a fresh constant to a single
// `state` variable and jumping to one dispatcher block; the dispatcher
// is a chain (or switch) of tests `state == c` whose targets are the
// original blocks. Recovering the original CFG means (1) recognizing the
// dispatcher, (2) propagating the state constant through each ordinary
// block, and (3) resolving every edge that pointed at the dispatcher to
// the case target matching the block's state value.
//
// Dispatcher recognition is deliberately syntactic-but-normalized. Each
// edge condition is first normalized to a *case test*:
//
//   state == c                        direct form
//   (state ^ key) == c                xor form: equal to state == c^key
//   c == state / (c == state^key)     mirrored operand order
//
// where `state` is a DAG input and the other side is a constant, after
// the condition has already been simplified (constant folding happens at
// DAG construction; opaque predicates are eliminated before this pass --
// the orchestrator runs them first). A block is a dispatcher when it has
// at least `min_dispatcher_edges` edges and *every* edge normalizes to a
// case test of the *same* input with distinct constants. If any edge
// fails to normalize, the block is not claimed to be a dispatcher; that
// is the "do not guess" rule -- a partially recognized switch is
// reported unproven, not assumed.
//
// Resolution propagates the state variable's value through a block
// symbolically: assignments are applied in order to a per-name map of
// expressions (starting from the state input itself), and the value left
// in the state variable at the block's exit is the propagated constant.
// The DAG folds constant operations at construction, so `state = 5 ^
// 0x5a` propagates as 0x5f without any folding work here. An edge whose
// block's exit state is a known constant resolves to that constant's
// case target; an unknown exit state leaves the edge unresolved and the
// recovery is reported partial (the dispatcher is kept, and the
// unresolved edges are named) rather than guessed.
//
// On success the pass rebuilds a new LiftedFunc without the dispatcher,
// renumbering the surviving blocks and remapping every edge. Block ids
// therefore change; labels survive and are what the report addresses
// blocks by.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "occ/deobf/ir.h"

namespace occ::deobf {

struct FlattenOptions {
    // A dispatcher must have at least this many case-test edges.
    std::size_t min_dispatcher_edges = 3;
};

// One recognized case test: `state_ordinal` (a DAG input) tested against
// `value`. `key` is non-zero exactly for the xor form, where the
// original condition was `(state ^ key) == (value ^ key)`.
struct CaseTest {
    std::uint32_t state_ordinal = 0;
    std::uint64_t value = 0;
    std::uint64_t key = 0;
    bool xor_variant = false;
    std::string rendered;  // human-readable form of the test
};

// One step of the recovery, for the report.
struct FlattenStep {
    std::string what;             // e.g. "dispatcher identified",
                                  //      "edge retargeted"
    std::string detail;
    std::uint32_t block = 0;
    std::uint32_t old_target = 0;
    std::uint32_t new_target = 0;
    bool resolved = true;         // false for an unresolved edge
};

struct FlattenResult {
    bool recognized = false;      // full recovery completed
    std::uint32_t dispatcher = 0;
    std::string state_name;
    std::uint32_t state_ordinal = 0;
    // The dispatcher's case table, in input order: state value -> target
    // block id (in the *original* numbering).
    std::vector<std::pair<std::uint64_t, std::uint32_t>> cases;
    std::vector<FlattenStep> steps;
    std::vector<std::string> unresolved;  // what blocked full recovery
    LiftedFunc func;              // recovered function (renumbered) when
                                  // recognized, else an unmodified copy
};

// Normalizes one 1-bit edge condition into a case test. Returns false
// when the condition is not (directly or via xor with a constant) an
// equality test between one of the state inputs and a constant. This is
// the only place the pass commits to a syntactic form; everything else
// is propagation and proof.
[[nodiscard]] bool deobf_normalize_case(const LiftedFunc& func, devirt::expr::Id cond,
                                        CaseTest& out);

// Recovers the flattened CFG of `func`. `func` itself is not modified;
// the recovered function is returned through `out.func` (a renumbered
// copy) when `out.recognized` is true, else an unchanged copy. Run this
// after opaque-predicate elimination: a predicate edge grafted onto the
// dispatcher must be gone before the dispatcher's edges are required to
// all be case tests.
[[nodiscard]] LiftedFunc recover_flattening(const LiftedFunc& func,
                                            const FlattenOptions& options,
                                            FlattenResult& out);

}  // namespace occ::deobf

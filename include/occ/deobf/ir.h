// The deobfuscation IR: a lifted function, as the anti-obfuscation
// engine consumes it.
//
// This module does not run guest code. occ does not yet have a guest
// executor for the Windows PE functions it is interested in -- the
// runtime directory is being reworked in parallel -- so the deobfuscator
// cannot work from an instruction stream and an execution environment.
// It works from a *lifted* representation instead: the artifact a future
// x86 lifter feeds in, which is the same contract the devirt layers
// already reason in (`devirt::expr::DAG`).
//
// A lifted function is a set of named bit-vector state variables (each a
// DAG input) plus a control-flow graph over basic blocks. Every block is
// an ordered list of assignments (`dst <- value`, where `dst` names a
// state variable and `value` is an expression over the DAG) followed by
// a list of outgoing edges. An edge carries a 1-bit condition over the
// state variables (`kNoId` means unconditional) and a target block id.
//
// The boundary is stated honestly: whatever an OLLVM-style pass
// flattened, an opaque predicate wrapped, or a linear-MBA pass
// complicated shows up here as expressions and edges. The engine never
// guesses what a block "means" -- it proves what it claims (via the ring
// and SAT layers) and labels everything it cannot prove unproven.
//
// Block ids are the vector index and are *not* stable across
// transformations: recovery rebuilds a new LiftedFunc with renumbered
// blocks. `label` is the human-readable name that survives renumbering,
// which is what reports and tests address blocks by.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "occ/devirt/expr.h"

namespace occ::deobf {

// One state variable of the lifted machine: a name and the width (in
// bits) of its DAG input. A state variable that the dispatcher tests
// (the flattened switch state) is just a StateVar like any other; the
// flattening pass identifies it by looking at which input the
// dispatcher's conditions actually test.
struct StateVar {
    std::string name;
    unsigned width = 8;
};

// `dst <- value`: assigns the expression to the named state variable.
struct Assign {
    std::string dst;
    devirt::expr::Id value = devirt::expr::kNoId;
};

// One outgoing edge of a block. `cond` is a 1-bit expression over the
// state variables; `devirt::expr::kNoId` means the edge is unconditional. The
// conditions of a block's edges are assumed to partition the executions
// (branch / switch semantics: exactly one edge is taken). That
// assumption is what makes "this condition is constant true, therefore
// every other edge is dead" sound, and it is stated where it is used.
struct Edge {
    devirt::expr::Id cond = devirt::expr::kNoId;
    std::uint32_t target = 0;
};

// A basic block: assignments, then edges.
struct Block {
    std::uint32_t id = 0;      // == index into LiftedFunc::blocks
    std::string label;         // survives renumbering; "" when unnamed
    std::vector<Assign> assigns;
    std::vector<Edge> edges;
};

// A lifted function. `blocks` is indexed by block id. `state_vars[i]`
// corresponds to DAG input ordinal i; the mapping is positional so a
// report can say "st" where the DAG says "input #0".
struct LiftedFunc {
    devirt::expr::DAG dag;
    std::vector<StateVar> state_vars;
    std::vector<Block> blocks;
    std::uint32_t entry = 0;

    // The DAG input node for a state variable, deduplicated by the DAG
    // itself (same name and width is the same input). Creates the input
    // if it is not already present; not const because creating an input
    // grows the DAG.
    [[nodiscard]] devirt::expr::Id state_input(const StateVar& sv) {
        return dag.input(sv.name, sv.width);
    }
};

}  // namespace occ::deobf

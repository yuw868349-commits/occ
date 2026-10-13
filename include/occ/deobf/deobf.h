// The deobfuscation orchestrator and its report.
//
// The three passes of this module are deliberately separable -- each has
// its own header and entry point, and a caller that only wants opaque
// predicates or only wants MBA simplification can use it alone. This
// file ties them into the order the module's analysis depends on:
//
//   1. opaque-predicate elimination, because a predicate edge grafted
//      onto a dispatcher would make dispatcher recognition fail (the
//      dispatcher's edges must all be state tests);
//   2. control-flow flattening recovery, on the cleaned CFG;
//   3. MBA simplification of every assignment, on the recovered
//      function.
//
// The order is not arbitrary: step 1 removes edges, step 2 rewrites the
// CFG, and step 3 rewrites expressions inside the surviving blocks. The
// three transforms touch disjoint structure, so composition is a simple
// pipeline. The result carries the transformed function plus every
// evidence record the passes produced, and `deobf_report` renders all
// of it for a human reader.
//
// Everything the pipeline could not prove is collected in `notes` and
// the pass-specific "unresolved" lists; the report says what is
// unproven, never what it "probably" is.

#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "occ/deobf/flatten.h"
#include "occ/deobf/mba.h"
#include "occ/deobf/opaque.h"

namespace occ::deobf {

struct DeobfOptions {
    OpaqueOptions opaque;
    FlattenOptions flatten;
    MbaOptions mba;
};

struct DeobfResult {
    OpaqueResult opaque;      // step 1 evidence
    FlattenResult flatten;    // step 2 evidence (recognized or not)
    MbaPassResult mba;        // step 3 evidence
    std::vector<std::string> notes;
    LiftedFunc func;          // the final function
};

// Runs the pipeline. `func` itself is not modified; the transformed
// function is returned in `out.func`.
[[nodiscard]] DeobfResult deobfuscate(const LiftedFunc& func,
                                      const DeobfOptions& options);

// Renders a block's assignments and edges, one line per block, for the
// report's "before" and "after" CFG sections.
[[nodiscard]] std::string deobf_dump_cfg(const LiftedFunc& func,
                                         const std::string& title);

// The full human-readable report: original CFG, per-pass evidence, and
// the final CFG. `original` is the function as the caller handed it in;
// everything else comes from `result`.
[[nodiscard]] std::string deobf_report(const LiftedFunc& original,
                                       const DeobfResult& result);

}  // namespace occ::deobf

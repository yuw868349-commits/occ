#pragma once

// Asking the recovered program a question.
//
// De-virtualization ends with a model: every handler's effect as an
// expression, and a check that says the model agrees with the run. That
// answers "what does this engine do". It does not answer "what input does
// it accept", which is the question a crackme poses and the one an
// analyst eventually has to answer.
//
// The answer is a replay. The trace is a straight record of what ran, in
// order; the models say what each step did; so replaying the models over
// the trace's own path executes the recovered program a second time,
// with one difference -- the bytes the caller names as unknown are not
// the bytes the run had, but variables. What comes out is an expression
// over those variables, and satisfying it is a constraint problem the
// bit-blaster and the solver in this tree already answer.
//
// Nothing here is specific to an engine. The semantics are the models
// that the conformance check has already validated, the path is the one
// the trace took, the memory is the trace's own recorded bytes, and the
// unknown bytes are the caller's declaration. An engine whose handlers
// the lift can model at all can be asked this way.
//
// Three things the replay does not invent, and says so about:
//
//   * The path. A dispatch whose next handler depends on the input would
//     need exploring; the trace names one. A handler's *internal* branch
//     is not a problem -- the lifter merges the arms and the model
//     carries the condition, so the replay is exact for both -- but a
//     dispatch target that leans on an unknown is reported.
//   * The interpreter's own registers. The cursor, the operand index, the
//     input length are read from the trace row by row, so the replay is
//     the run's own path; an input of a different length walks a
//     different one. A solution is therefore a candidate until the
//     program has been run with it, which is the only proof that cannot
//     be argued with.
//   * The values no run observed. A register the trace did not carry, a
//     byte nothing recorded: each becomes a variable of its own and is
//     counted, so a solution that leans on one is reported as leaning on
//     it rather than presented as settled.

#include <cstdint>
#include <string>
#include <vector>

#include "occ/devirt/goal.h"
#include "occ/devirt/lift.h"

namespace occ::devirt::lift {

// A region of memory whose bytes the solve may choose, whatever the run
// put there. This is how a caller says "the input lives here": a crackme
// hands its virtual machine a buffer, and every byte of it is the
// question rather than an answer. Declaring the region is not a hint
// about the engine -- it is the shape of the problem.
struct UnknownRegion {
    std::uint64_t va = 0;
    std::uint64_t size = 0;
};

struct SolveOptions {
    std::vector<UnknownRegion> unknown;
    // The conditions the finished program must satisfy, in the language
    // goal.h documents. They are read once the replay has finished, in
    // the state the last dispatch left behind, and every one of them has
    // to hold at the same time.
    std::vector<GoalNode> goals;
    // The search budget. Zero means no cap, which is the honest setting
    // for a question whose answer is worth waiting for and the wrong one
    // for a wrapper script; a question that runs out is reported as
    // unproven, never as answered.
    std::uint64_t max_conflicts = 500000;
    double max_seconds = 30.0;
    // How many unmet constraints to spell out. A program that cannot be
    // satisfied usually has one region of trouble, and the first few
    // constraints say which faster than a count does.
    std::size_t failures_shown = 4;
    // Whether to work out what the control flow does beyond the path the
    // trace took. Reading a trace answers "what ran"; the dispatches'
    // own targets answer "what could have run", and for a machine whose
    // next handler depends on the input the two are not the same
    // question. Off by default because it costs a solver query per
    // candidate per dispatch, which is worth it when the machine
    // branches on its input and wasted when it cannot.
    bool explore = false;
};

// One step where the model's next handler is not the one the run took,
// or might not have been.
//
// The replay computes each handler's dispatch target the same way it
// computes everything else -- symbolically, over the unknown bytes. What
// it does with the answer is the point: a target that resolves to a
// number is the machine's own decision, and comparing it with the
// handler the trace saw is a check on the model that no other part of
// the analysis makes. A target that depends on the unknown is a branch,
// and the branches are what a single trace by construction cannot show.
struct BranchPoint {
    std::size_t seq = 0;               // the dispatch this came from
    std::uint64_t handler_va = 0;      // the handler whose target it is
    std::string condition;             // the target, rendered
    bool symbolic = false;             // does it depend on the unknown
    // What the trace saw next. For a symbolic target this is the path
    // the run happened to take; it is one of the successors and never the
    // whole set.
    std::uint64_t observed = 0;
    // What the model's own replay of the dispatcher computed for that
    // step, when it resolved to a number.
    std::uint64_t computed = 0;
    bool observed_matches_model = false;
    // The handlers a successor could be, and whether the unknown can
    // reach that edge at all. A candidate the model rules out is as much
    // an answer as one it allows: together they are the control flow
    // graph at dispatch granularity, which is more than any one run can
    // show.
    struct Edge {
        std::uint64_t target = 0;
        bool reachable = false;
    };
    std::vector<Edge> edges;
};

struct SolveResult {
    // True only when the goals are satisfied by the bytes in
    // `region_bytes`, and only under the assumptions `assumed` lists.
    bool solved = false;
    // One line saying why not, when not.
    std::string reason;

    // The bytes the solve chose, one vector per declared region, in the
    // order the regions were declared.
    std::vector<std::vector<std::uint8_t>> region_bytes;

    // The address each goal was read from, in the order the goals were
    // given. A caller that named a slot by displacement gets the address
    // the machine read, which is the only way to be sure the two agreed.
    // A goal that read no memory leaves its entry at zero.
    std::vector<std::uint64_t> goal_addresses;

    // The goals as the machine's own names render them, in the order they
    // were given, so a report shows the question in the vocabulary of its
    // answer.
    std::vector<std::string> goal_text;

    // Where the model's control flow was read off the run rather than
    // checked against it: every dispatch whose target came out as a
    // number gets compared with the handler the trace saw, and the ones
    // that disagree -- and the ones that came out symbolic -- are here.
    // Empty when every target resolved to the handler the run took.
    std::vector<BranchPoint> branches;
    // How many dispatches had a target the model could resolve to a
    // number. The rest are the ones a single trace cannot vouch for.
    std::size_t targets_resolved = 0;
    std::size_t targets_symbolic = 0;

    // Constraints no assignment satisfies, rendered. A constraint that
    // reaches no variable at all is the interesting one: it says the
    // state the run left behind cannot satisfy this step, whatever the
    // unknown bytes are -- which is what a trace whose input was too
    // short looks like from here.
    std::vector<std::string> unmet;

    // The replay's coverage, so a caller can see how much of the program
    // the answer rests on.
    std::size_t rows_played = 0;
    std::size_t rows_skipped = 0;
    // Values the model needed that no run recorded -- a register the
    // trace did not carry, a byte nothing read, a store through an
    // address no run fixed. Each became a variable; a solution that
    // depends on one is a candidate and not a fact.
    std::size_t unrecorded_variables = 0;
    std::size_t unrecorded_used = 0;
    // Stores whose address the replay could not fix to a number, so
    // nothing can be said about which cells they covered.
    std::size_t symbolic_stores = 0;

    // The constraint problem as it was actually put: how many variables
    // the goals reach, how many clauses the bit-blaster built, and what
    // the search cost. A solve that answers without searching (a goal
    // every assignment satisfies, or none does) is worth reading as such.
    std::size_t variables = 0;
    std::size_t clauses = 0;
    std::uint64_t conflicts = 0;
    std::uint64_t decisions = 0;
};

// Replays the handlers over the trace's rows and solves for the goals.
//
// `model` is the model the handlers were summarized under; the replay
// adds input nodes to its expression DAG for the unknown bytes, which is
// why the model is taken by reference and why a caller runs the
// conformance check first -- the check's answers describe the model as it
// was, and the nodes added here are not part of them.
//
// `dispatcher` is the shared code every handler jumps to, summarized
// under the same model, and it is what turns the replay's knowledge of
// control flow from "what ran" into "what it computed". Pass null and the
// replay follows the trace's own handler sequence without ever asking why
// it was that sequence; pass it and each dispatch's target is recomputed
// from the dispatcher's model and checked against the word the trace
// recorded. The second is what a caller wants when the machine might
// dispatch on its input.
[[nodiscard]] SolveResult solve(Model& model,
                                const std::vector<Handler>& handlers,
                                const std::vector<Row>& rows,
                                const std::vector<std::size_t>& handler_of_row,
                                CodeReader code_bytes, void* code_ctx,
                                const SolveOptions& options,
                                const Handler* dispatcher = nullptr);

}  // namespace occ::devirt::lift

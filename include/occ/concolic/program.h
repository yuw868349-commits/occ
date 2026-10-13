// The concolic program model, and the concrete interpreter over it.
//
// The concolic engine is built on a deliberately small, self-contained
// program model: a list of named state variables, a list of basic blocks,
// and straight-line assignments inside each block. There is no guest
// executor behind it -- the model *is* the program, and every value in it
// is an expression over the `expr::DAG`, so the same program is executed
// concretely (bind the DAG inputs, evaluate), tainted (ask which inputs a
// value reaches), and solved against (assert path conditions in the SAT
// layer) without translating anything twice.
//
// The state is a set of named variables. Each variable holds one value,
// expressed as a DAG expression; a statement `dst <- src` gives `dst` the
// value of `src`, and `src` is built over the DAG's inputs and constants.
// A state is therefore an alias for a DAG expression, which is why the
// model can stay small: the DAG carries the widths, the folding, and the
// evaluation, and the blocks carry only the dataflow.
//
// Inputs are declared by name and width; each declaration creates a DAG
// input node, so "x is symbolic" means "state x holds DAG input #0".
// Memory is modelled statically: each cell is a state variable named after
// its address (the tests use `mem[0x1000]`). Dynamically indexed memory --
// a load or store through a computed address, which would need an array
// theory -- is **unsupported** in this model: the DAG has no way to name
// an address's content as a function of the address, and pretending it
// could would make the taint and constraint answers wrong rather than
// approximate. Programs that need dynamic indexing are outside this
// module's capability and are reported as such in the reports, not
// silently mishandled.
//
// Control flow is a list of edges per block. Every edge carries a 1-bit
// condition (or kNoId for an unconditional fall-through); the interpreter
// walks the edges in order and takes the first whose condition evaluates
// to one. A block with no edges is terminal -- reaching it is the program
// halting. This is exactly the shape the path exploration needs: each
// conditioned edge is a decision point whose truth value becomes a path
// constraint, and flipping a decision is asserting the chosen edge's
// condition false (or a different edge's condition true).
//
// The interpreter (`conc::run`) is concrete: it binds the inputs, walks
// the blocks, evaluates every statement and every edge condition with
// `DAG::evaluate`, and returns the visited block sequence, the decisions
// taken (which edge was chosen at which block, and every condition's
// value), and the final state. It is also bounded: a program whose loop
// exit depends on an unconstrained input would not terminate, so a run
// that exceeds `kMaxRunSteps` stops and reports itself Pruned. Nothing
// here guesses: a block whose edges all evaluate false stops with
// NoEdge, which is a program shape the model declares rather than a
// silence.

#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "occ/devirt/expr.h"

namespace occ::concolic {

// The concolic module is a sibling of the devirt module, not a child of
// it, so `expr` is not in scope by nesting the way it is inside
// occ::devirt. This alias keeps the reads identical to the devirt code
// (`expr::Id`, `expr::kNoId`) without a using-directive's name pollution.
namespace expr = occ::devirt::expr;

// A single concrete run is bounded by this many block visits. A loop
// whose exit depends on a symbolic input is the standard concolic
// nuisance; 4096 visits bounds the run while leaving room for the small
// straight-line programs this module is for. A run that hits the cap is
// reported Pruned with the prefix it did visit.
inline constexpr std::size_t kMaxRunSteps = 4096;

// One declared state variable. `init` is the value the variable holds on
// entry (a DAG input for a symbolic input, a constant, or kNoId which
// reads as zero); `cell` marks the static-memory cells the taint engine
// collects as memory-write sinks.
struct StateVar {
    std::string name;
    unsigned width = 0;
    expr::Id init = expr::kNoId;
    bool cell = false;
};

// A declaration of a symbolic program input: state `state` holds the DAG
// input `sym` (width bits), whose ordinal is `ordinal`.
struct InputDecl {
    std::string state;
    std::string sym;
    unsigned width = 0;
    std::uint32_t ordinal = 0;
};

// One assignment: `dst <- src`. `src` is a DAG expression over the
// program's inputs; `dst` names a state variable (created implicitly on
// first write if it was not declared). Assignments are not resized: the
// expression's own width discipline applies, and the state stores the
// value at that width.
struct Stmt {
    std::string dst;
    expr::Id src = expr::kNoId;
};

// An outgoing edge: condition `cond` (1-bit; kNoId = unconditional) to
// block `target`. Edges are evaluated in order; the first true one wins.
struct Edge {
    expr::Id cond = expr::kNoId;
    std::uint32_t target = 0;
};

struct Block {
    std::uint32_t id = 0;
    std::vector<Stmt> stmts;
    std::vector<Edge> edges;
};

// The program. Construction is imperative (add blocks, statements, edges,
// inputs); misuse -- a duplicate input name, an edge to a nonexistent
// block, a condition that is not 1-bit -- records itself in `error` and
// the offending call becomes a no-op, so an invalid program is visible
// instead of undefined.
struct Program {
    expr::DAG dag;
    std::vector<StateVar> states;
    std::vector<InputDecl> inputs;
    std::vector<Block> blocks;
    std::uint32_t entry = 0;
    std::string error;

    [[nodiscard]] bool valid() const noexcept { return error.empty(); }

    // -- construction ----------------------------------------------------

    // Appends a block and returns its id.
    [[nodiscard]] std::uint32_t add_block();

    // `dst <- src`. Declares `dst` implicitly (width = src's width) if it
    // does not exist yet; otherwise only the assignment is recorded.
    void add_stmt(std::uint32_t block, const std::string& dst, expr::Id src);

    // Adds an edge from `block` to `target` guarded by `cond` (kNoId for
    // unconditional). `cond` must be 1-bit; `target` must already exist.
    void add_edge(std::uint32_t block, std::uint32_t target,
                  expr::Id cond = expr::kNoId);

    // Declares a symbolic input: state `state` (created if missing) holds
    // a width-bit DAG input named `sym`, appended to `inputs`. Both names
    // must be unused. Returns the input's DAG node id (kNoId on failure).
    [[nodiscard]] expr::Id add_input(const std::string& state,
                                     const std::string& sym, unsigned width);

    // Declares a state variable holding `init` from the start (kNoId
    // reads as zero). Cells (static memory) are declared through
    // `declare_cell` so the taint engine recognises writes to them.
    void declare_state(const std::string& name, unsigned width,
                       expr::Id init = expr::kNoId);

    // Declares a static memory cell: a state named after the address,
    // initially zero, written by statements like any other state.
    void declare_cell(const std::string& name, unsigned width);

    // -- queries ---------------------------------------------------------

    [[nodiscard]] std::size_t num_inputs() const noexcept {
        return inputs.size();
    }
    // The state index of `name`, or `states.size()` when unknown.
    [[nodiscard]] std::size_t state_index(const std::string& name) const;
};

// ------------------------------------------------------------ concrete run

// What one concrete run did. `decisions` records, at every block with
// edges, the chosen edge and every edge condition's concrete value -- the
// raw material the concolic driver turns into path constraints.
struct RunResult {
    enum class Status : std::uint8_t {
        // A terminal block (no edges) was reached: the program halted.
        Halt,
        // The step budget ran out; `blocks` is the visited prefix.
        Pruned,
        // Every edge condition evaluated false and no edge was taken;
        // the program shape does not cover this input.
        NoEdge,
    };

    // One edge's condition and its value under the run's inputs.
    struct EdgeEval {
        expr::Id cond = expr::kNoId;
        bool value = false;
    };

    // The decision at one block: `chosen` is the index into `edges` of
    // the edge taken (`taken` false means every edge evaluated false and
    // the run stopped with NoEdge); `edges` lists every outgoing edge in
    // order.
    struct Decision {
        std::uint32_t block = 0;
        std::uint32_t chosen = 0;
        bool taken = false;
        std::vector<EdgeEval> edges;
    };

    Status status = Status::Halt;
    std::vector<std::uint32_t> blocks;  // visited block ids, in order
    std::vector<Decision> decisions;
    // Final value of every state, in declaration order.
    std::vector<std::pair<std::string, std::uint64_t>> final_state;
    std::size_t steps = 0;
};

// Executes the program on concrete inputs, bound to the DAG inputs by
// ordinal. Inputs beyond `concrete_inputs`' length read as zero (the
// DAG's own evaluate semantics). `max_steps` bounds the run; a run that
// exceeds it reports Pruned.
[[nodiscard]] RunResult run(
    const Program& prog, const std::vector<std::uint64_t>& concrete_inputs,
    std::size_t max_steps = kMaxRunSteps);

}  // namespace occ::concolic

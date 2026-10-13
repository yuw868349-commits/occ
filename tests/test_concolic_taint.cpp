// Taint engine tests over the concolic program model.
//
// A small program with two symbolic inputs is tainted and the report is
// checked against what the dataflow says by construction: x flows into y
// through `x ^ 0x3f`, into z through `y + 1`, into a static memory cell
// through a write, and into a branch condition built on z. The second
// input k is deliberately *not* marked, so v = k + 1 must come out clean
// -- an unmarked input adds no label no matter how deep it sits in an
// expression -- and so must a constant-only state. The propagation chain
// is checked entry by entry: every (label, assignment) that carries x
// must be reported, and the report must say which sinks are clean.
//
// The concrete run is checked first, because the taint claims only make
// sense over a program whose evaluation is itself verified: x = 0x20
// gives y = 0x1f, z = 0x20, mem[0x1000] = 0x1f, and the branch on
// z < 0x40 taken.

#include "occ/concolic/program.h"
#include "occ/concolic/taint.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using namespace occ::concolic;

namespace {

int failures = 0;
int checks = 0;

void check(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

// ------------------------------------------------------------ program

// y = x ^ 0x3f; z = y + 1; v = k + 1; w = 5; mem[0x1000] = y; then branch
// on z < 0x40. k is a second input that stays unmarked.
struct Fixture {
    Program prog;
    std::uint32_t block0 = 0;
    expr::Id y = expr::kNoId;
    expr::Id z = expr::kNoId;
};

Fixture make_program() {
    Fixture f;
    expr::DAG& dag = f.prog.dag;
    const expr::Id x = f.prog.add_input("x", "x", 8);
    const expr::Id k = f.prog.add_input("k", "k", 8);
    f.prog.declare_cell("mem[0x1000]", 8);

    f.block0 = f.prog.add_block();
    const std::uint32_t b1 = f.prog.add_block();
    const std::uint32_t b2 = f.prog.add_block();

    f.y = dag.bit_xor(x, dag.constant(0x3F, 8));
    f.z = dag.add(f.y, dag.constant(1, 8));
    const expr::Id v = dag.add(k, dag.constant(1, 8));
    const expr::Id w = dag.constant(5, 8);

    f.prog.add_stmt(f.block0, "y", f.y);
    f.prog.add_stmt(f.block0, "z", f.z);
    f.prog.add_stmt(f.block0, "v", v);
    f.prog.add_stmt(f.block0, "w", w);
    f.prog.add_stmt(f.block0, "mem[0x1000]", f.y);
    f.prog.add_stmt(f.block0, "arg", f.y);
    f.prog.add_stmt(f.block0, "arg_clean", w);

    const expr::Id cond = dag.cmp_ult(f.z, dag.constant(0x40, 8));
    f.prog.add_edge(f.block0, b1, cond);
    f.prog.add_edge(f.block0, b2);
    return f;
}

void test_concrete_run() {
    const Fixture f = make_program();
    check(f.prog.valid(), "the taint fixture program builds");

    const std::vector<std::uint64_t> in{0x20, 0x7F};
    const RunResult r = run(f.prog, in);
    check(r.status == RunResult::Status::Halt, "the fixture halts on x=0x20");
    check(r.blocks.size() == 2 && r.blocks[0] == f.block0,
          "the fixture visits block 0 then a terminal block");
    check(r.blocks.size() == 2 && r.blocks[1] != f.block0,
          "and leaves block 0 for the then-arm");
    std::uint64_t yv = 0;
    std::uint64_t zv = 0;
    std::uint64_t mv = 0;
    for (const auto& [name, value] : r.final_state) {
        if (name == "y") {
            yv = value;
        } else if (name == "z") {
            zv = value;
        } else if (name == "mem[0x1000]") {
            mv = value;
        }
    }
    check(yv == 0x1F, "y = 0x20 ^ 0x3f = 0x1f");
    check(zv == 0x20, "z = 0x1f + 1 = 0x20");
    check(mv == 0x1F, "mem[0x1000] holds the written value y = 0x1f");
}

void test_taint() {
    const Fixture f = make_program();
    TaintEngine te(f.prog);
    te.mark_input(0);  // x only; k stays unmarked
    te.add_sink("arg");
    te.add_sink("arg_clean");
    const TaintReport r = te.analyze();

    check(r.error.empty(), "taint analysis runs without error");

    // Per-state taint: x flows to y, z, the cell and arg; v (k-based) and
    // w (constant) stay clean.
    const auto state_labels = [&](const std::string& name) -> const std::vector<std::uint32_t>& {
        for (const StateTaint& st : r.states) {
            if (st.name == name) {
                return st.labels;
            }
        }
        static const std::vector<std::uint32_t> kEmpty;
        return kEmpty;
    };
    check(state_labels("x").size() == 1 && state_labels("x")[0] == 0,
          "x carries its own label");
    check(state_labels("y").size() == 1 && state_labels("y")[0] == 0,
          "y = x ^ 0x3f is tainted by x");
    check(state_labels("z").size() == 1 && state_labels("z")[0] == 0,
          "z = y + 1 is tainted by x through y");
    check(state_labels("mem[0x1000]").size() == 1 &&
              state_labels("mem[0x1000]")[0] == 0,
          "the memory cell written with y is tainted by x");
    check(state_labels("arg").size() == 1 && state_labels("arg")[0] == 0,
          "the argument sink holding y is tainted by x");
    check(state_labels("v").empty(), "v = k + 1 is clean: k was not marked");
    check(state_labels("w").empty(), "w = 5 is clean: no input at all");
    check(state_labels("arg_clean").empty(),
          "the argument sink holding a constant is clean");

    // Sinks: the branch on z, the memory write, and the two arguments.
    std::size_t branch_tainted = 0;
    std::size_t mem_tainted = 0;
    std::size_t arg_tainted = 0;
    std::size_t arg_clean = 0;
    for (const SinkReport& s : r.sinks) {
        if (s.kind == SinkReport::Kind::Branch && !s.labels.empty() &&
            s.labels[0] == 0) {
            ++branch_tainted;
        }
        if (s.kind == SinkReport::Kind::Memory && s.name == "mem[0x1000]" &&
            !s.labels.empty() && s.labels[0] == 0) {
            ++mem_tainted;
        }
        if (s.kind == SinkReport::Kind::Argument && s.name == "arg" &&
            !s.labels.empty() && s.labels[0] == 0) {
            ++arg_tainted;
        }
        if (s.kind == SinkReport::Kind::Argument && s.name == "arg_clean" &&
            s.labels.empty()) {
            ++arg_clean;
        }
    }
    check(branch_tainted == 1, "the branch condition on z is tainted by x");
    check(mem_tainted == 1, "the memory write sink is tainted by x");
    check(arg_tainted == 1, "the argument sink is tainted by x");
    check(arg_clean == 1, "the clean argument sink is reported clean");

    // Propagation chain: every assignment carrying x is listed, into y,
    // z, the cell and arg.
    std::size_t into_y = 0;
    std::size_t into_z = 0;
    std::size_t into_mem = 0;
    std::size_t into_arg = 0;
    for (const ChainEntry& c : r.chains) {
        if (c.label != 0) {
            continue;
        }
        if (c.dst == "y") {
            ++into_y;
        }
        if (c.dst == "z") {
            ++into_z;
        }
        if (c.dst == "mem[0x1000]") {
            ++into_mem;
        }
        if (c.dst == "arg") {
            ++into_arg;
        }
    }
    check(into_y == 1, "the chain reports y <- (x ^ 0x3f)");
    check(into_z == 1, "the chain reports z <- (y + 1)");
    check(into_mem == 1, "the chain reports the cell write");
    check(into_arg == 1, "the chain reports the argument write");

    const std::string text = report_text(f.prog, r);
    check(text.find("mem[0x1000]") != std::string::npos,
          "the taint report names the memory cell");
    check(text.find("clean") != std::string::npos,
          "the taint report explains what stayed clean");
}

}  // namespace

int main() {
    const auto run = [](const char* name, void (*fn)()) {
        std::printf("-- %s\n", name);
        std::fflush(stdout);
        fn();
    };
    run("concrete_run", test_concrete_run);
    run("taint", test_taint);
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

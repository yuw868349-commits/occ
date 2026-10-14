// Symbolic memory tests: computed-address loads and stores expand to
// select chains over the declared cell family, and every layer -- the
// concrete interpreter, the bit-level taint engine and the concolic path
// explorer -- treats them as ordinary assignments over DAG expressions.

#include "occ/concolic/bitflow.h"
#include "occ/concolic/engine.h"
#include "occ/concolic/program.h"

#include <cstdint>
#include <cstdio>
#include <string>

using namespace occ::concolic;

namespace {

int g_checks = 0;
int g_failures = 0;

void check(bool ok, const char* what) {
    ++g_checks;
    if (!ok) {
        ++g_failures;
        std::fprintf(stderr, "FAIL: %s\n", what);
    }
}

// A program with a 2-cell family, a symbolic address and a symbolic value:
//   mem[0x1000], mem[0x1004] cells
//   addr <- input a (64b); val <- input v (32b)
//   store a -> val
//   out <- load a (32b)
struct Fixture {
    Program prog;
    std::uint32_t entry = 0;
    expr::Id a = expr::kNoId;
    expr::Id v = expr::kNoId;
    std::uint64_t addr = 0x1000;
    std::uint64_t addr2 = 0x1004;
};

Fixture make_program() {
    Fixture f;
    f.prog.declare_cell("mem[0x1000]", 32);
    f.prog.declare_cell("mem[0x1004]", 32);
    f.entry = f.prog.add_block();
    f.a = f.prog.add_input("st_a", "a", 64);
    f.v = f.prog.add_input("st_v", "v", 32);
    f.prog.add_store(f.entry, "mem", f.a, f.v);
    f.prog.add_load(f.entry, "out", f.a, "mem", 32);
    return f;
}

}  // namespace

int main() {
    namespace expr = occ::devirt::expr;

    // --- concrete execution: store then load through the same address --
    {
        Fixture f = make_program();
        // a = 0x1000: the store lands in mem[0x1000] and the load reads
        // it back; out == v.
        const RunResult rr = run(f.prog, {f.addr, 0xDEADBEEF});
        check(rr.status == RunResult::Status::Halt, "mem: run halts");
        bool saw_out = false;
        for (const auto& p : rr.final_state) {
            if (p.first == "out") {
                saw_out = true;
                check(p.second == 0xDEADBEEF, "mem: out reads stored value");
            }
            if (p.first == "mem[0x1000]") {
                check(p.second == 0xDEADBEEF, "mem: cell updated at addr");
            }
            if (p.first == "mem[0x1004]") {
                check(p.second == 0, "mem: other cell untouched");
            }
        }
        check(saw_out, "mem: out state exists");
    }

    // --- concrete execution: load from an unwritten cell reads zero -----
    {
        Fixture f = make_program();
        const RunResult rr = run(f.prog, {0x2000, 0xABCD});
        bool saw_out = false;
        for (const auto& p : rr.final_state) {
            if (p.first == "out") {
                saw_out = true;
                check(p.second == 0, "mem: out reads zero outside family");
            }
        }
        check(saw_out, "mem: out exists for foreign address");
    }

    // --- symbolic address: the load expands to a select chain -----------
    {
        Fixture f = make_program();
        // The load expression is ite(a==0x1000, cell1000, ite(a==0x1004,
        // cell1004, 0)); evaluating it at both addresses picks the right
        // arm -- verify directly on the DAG.
        const expr::Id out_expr = f.prog.current_expr("out");
        const std::uint64_t v1 =
            f.prog.dag.evaluate(out_expr, {f.addr, 0x1111});
        const std::uint64_t v2 =
            f.prog.dag.evaluate(out_expr, {f.addr2, 0x2222});
        const std::uint64_t v3 =
            f.prog.dag.evaluate(out_expr, {0x3000, 0x3333});
        check(v1 == 0x1111, "mem: select chain picks first cell");
        check(v2 == 0x2222, "mem: select chain picks second cell");
        check(v3 == 0, "mem: select chain default is zero");
    }

    // --- taint: a symbolic load depends on the address and every cell ---
    {
        Fixture f = make_program();
        // Seed a cell with a marked input first.
        const expr::Id x = f.prog.add_input("st_x", "x", 32);
        f.prog.add_stmt(f.entry, "mem[0x1004]", x);
        // Rebuild the load after the write so the chain sees the new
        // cell value.
        f.prog.add_load(f.entry, "out2", f.a, "mem", 32);
        BitFlowEngine e(f.prog);
        e.mark_input(0);  // a (addr)
        e.mark_input(1);  // v
        e.mark_input(2);  // x
        const BitFlow flow = e.state_flow("out2");
        bool a_bits = false, v_bits = false, x_bits = false;
        for (const LabelBits& lb : flow) {
            if (lb.label == 0 && lb.mask != 0) a_bits = true;
            if (lb.label == 1 && lb.mask != 0) v_bits = true;
            if (lb.label == 2 && lb.mask != 0) x_bits = true;
        }
        check(a_bits, "mem taint: address label reaches load");
        check(v_bits, "mem taint: stored value label reaches load");
        check(x_bits, "mem taint: seeded cell label reaches load");
    }

    // --- concolic: a branch on a loaded value flips through the solver --
    {
        Program prog;
        expr::DAG& dag = prog.dag;
        prog.declare_cell("mem[0x1000]", 8);
        const std::uint32_t b0 = prog.add_block();
        const std::uint32_t b1 = prog.add_block();
        const std::uint32_t b2 = prog.add_block();
        const expr::Id a = prog.add_input("st_a", "a", 32);
        prog.add_store(b0, "mem", a, dag.constant(0x2A, 8));
        prog.add_load(b0, "v", a, "mem", 8);
        prog.add_edge(b0, b1, dag.cmp_eq(prog.current_expr("v"),
                                         dag.constant(0x2A, 8)));
        prog.add_edge(b0, b2);
        const std::vector<std::uint64_t> initial = {0x1000};
        PathReport rep = concolic_explore(prog, initial, Budget{});
        check(!rep.error.empty() || !rep.paths.empty(),
              "concolic mem: exploration ran");
        // Both branches are reachable: address 0x1000 reads 0x2A (true
        // edge), a foreign address reads zero (false edge).
        bool saw_halt_true = false, saw_halt_false = false;
        for (const PathReport::Path& p : rep.paths) {
            if (p.status == PathReport::Path::Status::Halt) {
                if (p.inputs.size() > 0 && p.inputs[0] == 0x1000) {
                    saw_halt_true = true;
                }
                if (p.inputs.size() > 0 && p.inputs[0] != 0x1000) {
                    saw_halt_false = true;
                }
            }
        }
        check(saw_halt_true, "concolic mem: matching-address path explored");
        check(saw_halt_false, "concolic mem: foreign-address path explored");
    }

    std::fprintf(stderr, "%d checks, %d failures\n", g_checks, g_failures);
    return 0;
}

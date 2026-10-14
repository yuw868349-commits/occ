// Bit-precise taint flow tests: exact per-bit dependency masks across
// every operation class the flow engine must model.

#include <cstdint>
#include <cstdio>
#include <string>

#include "occ/concolic/bitflow.h"

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

occ::concolic::BitFlowEngine make_engine(
    occ::concolic::Program& prog, const std::vector<unsigned>& marks) {
    occ::concolic::BitFlowEngine e(prog);
    for (const unsigned m : marks) {
        e.mark_input(m);
    }
    return e;
}

bool mask_is(const occ::concolic::BitFlow& flow, std::uint32_t label,
             std::uint64_t mask) {
    for (const occ::concolic::LabelBits& lb : flow) {
        if (lb.label == label) {
            return lb.mask == mask;
        }
    }
    return false;
}

}  // namespace

int main() {
    using namespace occ::concolic;
    namespace expr = occ::devirt::expr;

    // --- direct assignment: full-width dependency ----------------------
    {
        Program prog;
        (void)prog.add_block();
        const expr::Id x = prog.add_input("st_x", "x", 64);
        prog.add_stmt(0, "out", x);
        BitFlowEngine e = make_engine(prog, {0});
        const BitFlow f = e.state_flow("out");
        check(f.size() == 1, "assign: one label");
        check(mask_is(f, 0, ~std::uint64_t{0}), "assign: full 64-bit mask");
    }

    // --- masking: low 8 bits only ---------------------------------------
    {
        Program prog;
        (void)prog.add_block();
        const expr::Id x = prog.add_input("st_x", "x", 64);
        prog.add_stmt(0, "out", prog.dag.bit_and(x, prog.dag.constant(0xFF, 64)));
        BitFlowEngine e = make_engine(prog, {0});
        check(mask_is(e.state_flow("out"), 0, 0xFF), "mask: low 8 bits");
    }

    // --- high 8 bits: x >> 56 ------------------------------------------
    {
        Program prog;
        (void)prog.add_block();
        const expr::Id x = prog.add_input("st_x", "x", 64);
        prog.add_stmt(0, "out", prog.dag.shr(x, prog.dag.constant(56, 64)));
        BitFlowEngine e = make_engine(prog, {0});
        check(mask_is(e.state_flow("out"), 0, 0xFF), "shr 56: bits 56-63");
    }

    // --- shl 8: low bits fall off --------------------------------------
    {
        Program prog;
        (void)prog.add_block();
        const expr::Id x = prog.add_input("st_x", "x", 64);
        prog.add_stmt(0, "out", prog.dag.shl(x, prog.dag.constant(8, 64)));
        BitFlowEngine e = make_engine(prog, {0});
        check(mask_is(e.state_flow("out"), 0, ~std::uint64_t{0} << 8),
              "shl 8: bits 8-63");
    }

    // --- add: prefix dependency (carry chain) --------------------------
    {
        Program prog;
        (void)prog.add_block();
        const expr::Id a = prog.add_input("st_a", "a", 64);
        const expr::Id b = prog.add_input("st_b", "b", 64);
        prog.add_stmt(0, "out", prog.dag.add(a, b));
        BitFlowEngine e = make_engine(prog, {0, 1});
        const BitFlow f = e.state_flow("out");
        check(mask_is(f, 0, ~std::uint64_t{0}), "add a: full (prefix of full)");
        check(mask_is(f, 1, ~std::uint64_t{0}), "add b: full (prefix of full)");
    }

    // --- add with masked mid byte: the carry chain is exact -------------
    {
        Program prog;
        (void)prog.add_block();
        const expr::Id a = prog.add_input("st_a", "a", 64);
        const expr::Id b = prog.add_input("st_b", "b", 64);
        // out = (a & 0xff00) + b. a's bits 8-15 can carry into every
        // result bit >= 8 (the prefix chain: bit i depends on operand
        // bits 0..i, and a's bits 8..15 sit inside 0..i for i >= 8);
        // result bits 0-7 depend on b's low bits only.
        prog.add_stmt(0, "out",
                      prog.dag.add(prog.dag.bit_and(a, prog.dag.constant(0xFF00, 64)),
                                   b));
        BitFlowEngine e = make_engine(prog, {0, 1});
        const BitFlow f = e.state_flow("out");
        check(mask_is(f, 0, ~std::uint64_t{0xFF}),
              "add masked a: bits 8-63 (carry chain)");
        check(mask_is(f, 1, ~std::uint64_t{0}), "add b: full");
    }

    // --- select: condition + both arms ---------------------------------
    {
        Program prog;
        (void)prog.add_block();
        const expr::Id c = prog.add_input("st_c", "c", 1);
        const expr::Id x = prog.add_input("st_x", "x", 8);
        const expr::Id y = prog.add_input("st_y", "y", 8);
        prog.add_stmt(0, "out", prog.dag.select(c, x, y));
        BitFlowEngine e = make_engine(prog, {0, 1, 2});
        const BitFlow f = e.state_flow("out");
        check(mask_is(f, 0, 0xFF), "select cond: full (1-bit flips all)");
        check(mask_is(f, 1, 0xFF), "select x arm: full");
        check(mask_is(f, 2, 0xFF), "select y arm: full");
    }

    // --- constant: clean -------------------------------------------------
    {
        Program prog;
        (void)prog.add_block();
        prog.add_stmt(0, "out", prog.dag.constant(0x42, 8));
        BitFlowEngine e = make_engine(prog, {0});
        check(e.state_flow("out").empty(), "constant: clean");
    }

    // --- resize truncation: high bits lose dependency -------------------
    {
        Program prog;
        (void)prog.add_block();
        const expr::Id x = prog.add_input("st_x", "x", 64);
        prog.add_stmt(0, "out", prog.dag.resize(x, 16));
        BitFlowEngine e = make_engine(prog, {0});
        check(mask_is(e.state_flow("out"), 0, 0xFFFF), "resize 16: low 16");
    }

    // --- xor of two inputs: both, full ----------------------------------
    {
        Program prog;
        (void)prog.add_block();
        const expr::Id a = prog.add_input("st_a", "a", 8);
        const expr::Id b = prog.add_input("st_b", "b", 8);
        prog.add_stmt(0, "out", prog.dag.bit_xor(a, b));
        BitFlowEngine e = make_engine(prog, {0, 1});
        const BitFlow f = e.state_flow("out");
        check(mask_is(f, 0, 0xFF), "xor a: full 8");
        check(mask_is(f, 1, 0xFF), "xor b: full 8");
    }

    // --- comparison sink: 1-bit result depends on all operand bits ------
    {
        Program prog;
        (void)prog.add_block();
        const std::uint32_t b0 = prog.add_block();
        const std::uint32_t b1 = prog.add_block();
        const expr::Id x = prog.add_input("st_x", "x", 32);
        const expr::Id y = prog.add_input("st_y", "y", 32);
        prog.add_stmt(0, "s", x);
        prog.add_stmt(0, "t", y);
        prog.add_edge(0, b1, prog.dag.cmp_ult(x, y));
        prog.add_edge(0, b0);
        BitFlowEngine e = make_engine(prog, {0, 1});
        const BitFlowReport r = e.analyze();
        check(!r.sinks.empty(), "branch sink exists");
        bool branch_found = false;
        for (const BitSink& s : r.sinks) {
            if (s.kind == BitSink::Kind::Branch && s.name.find("edge 0") !=
                                                       std::string::npos) {
                branch_found = true;
                check(mask_is(s.flow, 0, 1), "cmp x: bit 0 depends on all of x");
                check(mask_is(s.flow, 1, 1), "cmp y: bit 0 depends on all of y");
            }
        }
        check(branch_found, "branch edge 0 found");
    }

    // --- memory cell write sink -----------------------------------------
    {
        Program prog;
        (void)prog.add_block();
        const expr::Id y = prog.add_input("st_y", "y", 8);
        prog.declare_cell("mem[0x1000]", 8);
        prog.add_stmt(0, "mem[0x1000]", y);
        BitFlowEngine e = make_engine(prog, {0});
        const BitFlowReport r = e.analyze();
        bool mem_found = false;
        for (const BitSink& s : r.sinks) {
            if (s.kind == BitSink::Kind::Memory) {
                mem_found = true;
                check(mask_is(s.flow, 0, 0xFF), "mem write: full 8");
            }
        }
        check(mem_found, "memory sink found");
    }

    // --- bits_tainted_by / tainted_by queries ---------------------------
    {
        Program prog;
        (void)prog.add_block();
        const expr::Id x = prog.add_input("st_x", "x", 64);
        prog.add_stmt(0, "out", prog.dag.bit_and(x, prog.dag.constant(0xF0, 64)));
        BitFlowEngine e = make_engine(prog, {0});
        check(e.tainted_by("out", 0), "tainted_by true");
        check(e.bits_tainted_by("out", 0) == 0xF0, "bits_tainted_by 0xF0");
        check(!e.tainted_by("out", 1), "tainted_by false for unmarked");
    }

    // --- report text renders --------------------------------------------
    {
        Program prog;
        (void)prog.add_block();
        const expr::Id x = prog.add_input("st_x", "x", 8);
        prog.add_stmt(0, "out", x);
        BitFlowEngine e = make_engine(prog, {0});
        const BitFlowReport r = e.analyze();
        const std::string text = bit_report_text(prog, r);
        check(text.find("bit-taint report") != std::string::npos,
              "report header");
        check(text.find("bits 0-7") != std::string::npos, "report bits");
    }

    std::fprintf(stderr, "%d checks, %d failures\n", g_checks, g_failures);
    return 0;
}

// Solve tests: asking the recovered program a question.
//
// The handlers here are hand-assembled, and so are the traces: the point
// is not that a real engine was de-virtualized but that the replay is
// driven by the model and the trace and by nothing else -- no engine
// constants, no per-handler code, no knowledge of what the program is
// supposed to be. A handler that mixes a byte it read with a constant is
// enough to ask "which byte makes the slot zero", and the answer is
// checked against the arithmetic the test itself did.
//
// Three behaviours matter beyond the happy path. A goal nothing can
// satisfy must be reported with the step that caused it, because "the run
// whose input reached further" is the fix and a bare unsatisfiable does
// not say that. A goal that depends on no unknown byte at all must be
// decided without searching. And an answer must be checked before it is
// reported: a solver model that does not satisfy the expression it was
// built from is a bug in the encoder or the extraction, and this layer
// refuses to pass either off as a solution.

#include "occ/devirt/solve.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using namespace occ::devirt;

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

// A goal from the text the command line would take. The tests write the
// same language a caller does, so a change to the parser shows up here
// rather than only in a hand-built tree.
lift::GoalNode goal_of(const std::string& text) {
    lift::GoalNode g;
    std::string err;
    if (!lift::parse_goal(text, &g, &err)) {
        std::fprintf(stderr, "FAIL the test's own goal %s: %s\n",
                     text.c_str(), err.c_str());
        ++failures;
    }
    return g;
}

constexpr std::uint64_t kHandlerVa = 0x1000;

// A run that recorded zero at every address. A reader rather than null so
// the replay is told "the record says zero here" instead of "nothing was
// recorded", which is a different statement and would show up as a
// variable no run observed.
bool zero_bytes(void* ctx, std::uint64_t va, unsigned width,
                std::uint64_t* out) {
    static_cast<void>(ctx);
    static_cast<void>(va);
    static_cast<void>(width);
    *out = 0;
    return true;
}

// Sets the general register `name` in a row, presence mask included: a
// row that carries a register and a row that left the field zero are the
// same number, and the mask is what tells them apart.
void set_reg(lift::Row& r, const std::string& name, std::uint64_t value) {
    for (std::size_t i = 0; i < 16; ++i) {
        if (name == lift::kRowGprNames[i]) {
            r.gpr[i] = value;
            r.gpr_present |= std::uint32_t{1} << i;
            return;
        }
    }
}

// movzx eax, byte [rdx]; xor eax, 0x5a; mov [rbp+0], eax; jmp rcx.
const std::vector<std::uint8_t> kMix = {
    0x0F, 0xB6, 0x02, 0x83, 0xF0, 0x5A, 0x89, 0x45, 0x00, 0xFF, 0xE1,
};

// mov eax, 0x11; mov [rbp+0], eax; jmp rcx -- a store of a constant.
const std::vector<std::uint8_t> kStoreConstant = {
    0xB8, 0x11, 0x00, 0x00, 0x00, 0x89, 0x45, 0x00, 0xFF, 0xE1,
};

// movzx eax, byte [rdx]; movzx ecx, byte [rdx+1]; or eax, ecx;
// mov [rbp+0], eax; jmp rcx.
const std::vector<std::uint8_t> kOrPair = {
    0x0F, 0xB6, 0x02, 0x0F, 0xB6, 0x4A, 0x01,
    0x09, 0xC8, 0x89, 0x45, 0x00, 0xFF, 0xE1,
};

lift::Row row_of(std::uint64_t rbp, std::uint64_t rdx) {
    lift::Row r;
    r.seq = 1;
    r.rbp = rbp;
    r.rsi = 0x2000;
    set_reg(r, "rdx", rdx);
    return r;
}

void test_solve_reads_a_byte_out_of_the_unknown() {
    lift::Model model;
    const lift::Handler h = lift::summarize(
        model, kMix.data(), kMix.size(), kHandlerVa, kHandlerVa);
    check(h.modeled, "the mixing handler is modelled");

    const std::vector<lift::Row> rows{row_of(0x3000, 0x5000)};
    const std::vector<std::size_t> which{0};

    lift::SolveOptions opts;
    opts.unknown.push_back(lift::UnknownRegion{0x5000, 1});
    opts.goals.push_back(goal_of("vst[0] = 0"));

    const lift::SolveResult res = lift::solve(
        model, {h}, rows, which, zero_bytes, nullptr, opts);
    check(res.solved, "the byte that zeroes the slot is found");
    if (res.solved) {
        check(res.region_bytes.size() == 1 &&
                  res.region_bytes[0].size() == 1,
              "the answer is one byte of one region");
        check(res.region_bytes[0][0] == 0x5a,
              "and it is the constant the handler mixed in");
        check(res.variables == 1, "one unknown byte was in play");
        check(res.unrecorded_used == 0,
              "and the answer leans on no value the run never had");
    }
}

void test_solve_reports_a_goal_no_input_can_meet() {
    // The store is a constant, so the goal cannot depend on the unknown
    // byte at all. Searching would answer nothing; the honest reply is
    // that the run's own state fixes this step, which is what a trace
    // whose input was too short looks like from here.
    lift::Model model;
    const lift::Handler h = lift::summarize(model, kStoreConstant.data(),
                                            kStoreConstant.size(),
                                            kHandlerVa, kHandlerVa);
    check(h.modeled, "the constant-store handler is modelled");

    const std::vector<lift::Row> rows{row_of(0x3000, 0x5000)};
    const std::vector<std::size_t> which{0};

    lift::SolveOptions opts;
    opts.unknown.push_back(lift::UnknownRegion{0x5000, 1});
    opts.goals.push_back(goal_of("vst[0] = 0"));

    const lift::SolveResult res = lift::solve(
        model, {h}, rows, which, zero_bytes, nullptr, opts);
    check(!res.solved, "a goal nothing can meet is not reported as solved");
    check(!res.unmet.empty(), "the step that caused it is named");
    if (!res.unmet.empty()) {
        check(res.unmet[0].find("no unknown byte reaches it") !=
                  std::string::npos,
              "with the reason a caller can act on");
    }
    check(res.conflicts == 0,
          "and no search was run to learn what arithmetic already said");
}

void test_solve_splits_a_goal_that_a_bitwise_or_joins() {
    // The stored value is `a | b` of two independent bytes, and the goal
    // is that it be zero. A bitwise or is zero exactly when both halves
    // are, so the split is an equivalence: the solver is asked two
    // smaller questions with the same answers, not a weaker one.
    lift::Model model;
    const lift::Handler h = lift::summarize(
        model, kOrPair.data(), kOrPair.size(), kHandlerVa, kHandlerVa);
    check(h.modeled, "the or-of-two-bytes handler is modelled");

    const std::vector<lift::Row> rows{row_of(0x3000, 0x5000)};
    const std::vector<std::size_t> which{0};

    lift::SolveOptions opts;
    opts.unknown.push_back(lift::UnknownRegion{0x5000, 2});
    opts.goals.push_back(goal_of("vst[0] = 0"));

    const lift::SolveResult res = lift::solve(
        model, {h}, rows, which, zero_bytes, nullptr, opts);
    check(res.solved, "the pair that zeroes the slot is found");
    if (res.solved) {
        check(res.region_bytes.size() == 1 &&
                  res.region_bytes[0].size() == 2,
              "the answer is both bytes");
        check(res.region_bytes[0][0] == 0 && res.region_bytes[0][1] == 0,
              "and both are zero: the or forces each of them");
        check(res.variables == 2, "two unknown bytes were in play");
    }
}

void test_solve_says_what_it_was_not_told() {
    // A solve with no goal and no unknown region is a question with no
    // question in it. It must say which, rather than searching for an
    // answer to nothing.
    lift::Model model;
    const lift::Handler h = lift::summarize(
        model, kMix.data(), kMix.size(), kHandlerVa, kHandlerVa);
    const std::vector<lift::Row> rows{row_of(0x3000, 0x5000)};
    const std::vector<std::size_t> which{0};

    lift::SolveOptions none;
    none.goals.push_back(goal_of("vst[0] = 0"));
    const lift::SolveResult no_region = lift::solve(
        model, {h}, rows, which, zero_bytes, nullptr, none);
    check(!no_region.solved && !no_region.reason.empty(),
          "a solve with no unknown region says so");

    lift::SolveOptions no_goal;
    no_goal.unknown.push_back(lift::UnknownRegion{0x5000, 1});
    const lift::SolveResult no_ask = lift::solve(
        model, {h}, rows, which, zero_bytes, nullptr, no_goal);
    check(!no_ask.solved && !no_ask.reason.empty(),
          "a solve with no goal says so too");
}

void test_solve_looks_through_a_narrow_goal() {
    // The same one-byte question, asked at the width a register machine's
    // slots are: a thirty-two-bit goal, which the replay reads out of an
    // eight-byte cell through a narrowing and a mask. The split has to
    // look through both to reach the pieces, and the answer must be the
    // same one it gave at sixty-four bits.
    lift::Model model;
    model.convention.regfile = "rsp";
    model.convention.regfile_width = 32;
    const lift::Handler h = lift::summarize(
        model, kMix.data(), kMix.size(), kHandlerVa, kHandlerVa);
    check(h.modeled, "the handler is modelled under the register file");

    const std::vector<lift::Row> rows{row_of(0x3000, 0x5000)};
    const std::vector<std::size_t> which{0};

    lift::SolveOptions opts;
    opts.unknown.push_back(lift::UnknownRegion{0x5000, 1});
    opts.goals.push_back(goal_of("vst[0] = 0"));

    const lift::SolveResult res = lift::solve(
        model, {h}, rows, which, zero_bytes, nullptr, opts);
    check(res.solved, "the same byte is found through a thirty-two-bit goal");
    if (res.solved) {
        check(res.region_bytes[0][0] == 0x5a,
              "and it is still the constant the handler mixed in");
    }
}

void test_solve_reads_the_goal_at_the_last_row_s_pointer() {
    // The base a goal is read from is the stack pointer the trace carried
    // at the last dispatch -- the state the run observed. A model's own
    // prediction of where its handler left the pointer describes a next
    // step that, for the last row, never came: an engine whose epilogue
    // pops its frame would otherwise have its goals read from past its
    // own memory.
    lift::Model model;
    const lift::Handler h = lift::summarize(
        model, kMix.data(), kMix.size(), kHandlerVa, kHandlerVa);
    std::vector<lift::Row> rows(2);
    rows[0] = row_of(0x3000, 0x5000);
    rows[0].seq = 1;
    rows[1] = row_of(0x3008, 0x5000);
    rows[1].seq = 2;
    const std::vector<std::size_t> which{0, 0};

    lift::SolveOptions opts;
    opts.unknown.push_back(lift::UnknownRegion{0x5000, 1});
    opts.goals.push_back(goal_of("vst[0] = 0"));
    const lift::SolveResult res = lift::solve(
        model, {h}, rows, which, zero_bytes, nullptr, opts);
    check(!res.goal_addresses.empty(), "the goal's address is reported");
    if (!res.goal_addresses.empty()) {
        check(res.goal_addresses[0] == 0x3008,
              "and it is the last row's pointer, not the one the model "
              "would have left behind");
    }
}


// The goal language: what a caller can write down.
//
// The parser is the only place a person's question enters this layer, so
// it is tested on the things a person writes -- a comparison, a
// conjunction, an index, a register -- and on the things they get wrong.
// An error that says which offset and what was expected is worth more
// than a refusal, and a rendering that re-parses to the same tree is what
// keeps the report and the answer in one vocabulary.
void test_goal_language_parses_what_a_caller_writes() {
    const auto ok = [](const char* text) {
        lift::GoalNode g;
        std::string err;
        const bool parsed = lift::parse_goal(text, &g, &err);
        if (!parsed) {
            std::fprintf(stderr, "  (rejected: %s -- %s)\n", text,
                         err.c_str());
        }
        return parsed;
    };
    check(ok("vst[0] == 0"), "a slot compared with a number");
    check(ok("vst[0] = 0"), "a single '=' is the same comparison");
    check(ok("vst[1] <u 0x100"), "an unsigned bound");
    check(ok("vst[1] <s 0"), "a signed one");
    check(ok("vst[0] != 0xdeadbeef && mem64[0x1000] == 0x1122334455667788"),
          "a conjunction over two places");
    check(ok("code[rax] == 0x11"), "a bytecode byte against a constant");
    check(ok("mem8[rsp + 4] == 0"), "a narrow access at a register");
    check(ok("rax == 0 || rbx != 0"), "a disjunction over registers");
    check(ok("(vst[0] + vst[1]) * 2 == vst[2]"),
          "arithmetic with parentheses");
    check(ok("vst[vst[1]] == 0"), "an index that is itself a slot");
    check(ok("~vst[0] == 0xffffffff"), "a bitwise not");
    check(ok("!(vst[0] == 0)"), "a negated condition");
}

void test_goal_language_refuses_what_it_cannot_read() {
    lift::GoalNode g;
    std::string err;
    check(!lift::parse_goal("vst[0", &g, &err),
          "an unclosed index is refused");
    check(err.find("never closed") != std::string::npos,
          "and the refusal says which brace");
    err.clear();
    check(!lift::parse_goal("0x10", &g, &err),
          "a bare value asks no question");
    check(err.find("condition") != std::string::npos,
          "and the refusal says what a goal has to be");
    err.clear();
    check(!lift::parse_goal("mem7[0] == 0", &g, &err),
          "a width that is not a machine width is refused");
    err.clear();
    check(!lift::parse_goal("vst[0] == 0 extra", &g, &err),
          "trailing text is refused rather than ignored");
    err.clear();
    check(!lift::parse_goal("", &g, &err), "an empty goal is refused");
}

void test_goal_language_round_trips() {
    // A rendering re-parses to the same tree. The report shows a goal in
    // the machine's own vocabulary; if that text did not mean what the
    // tree means, the report would be describing a different question.
    const char* const texts[] = {
        "vst[0] == 0",
        "vst[1] <u 0x100 && mem64[0x1000] == 0xdeadbeef",
        "rax == 0 || rbx != 0",
        "(vst[0] + vst[1]) * 2 == vst[2]",
        "mem8[rsp + 4] == 0",
        "~(vst[0] & 0xff) == 0",
    };
    for (const char* text : texts) {
        lift::GoalNode a;
        std::string err;
        if (!lift::parse_goal(text, &a, &err)) {
            check(false, text);
            continue;
        }
        const std::string shown = lift::render_goal(a);
        lift::GoalNode b;
        if (!lift::parse_goal(shown, &b, &err)) {
            std::fprintf(stderr, "  (re-parse failed: %s -- %s)\n",
                         shown.c_str(), err.c_str());
            check(false, text);
            continue;
        }
        check(lift::render_goal(b) == shown, text);
    }
}

void test_goal_language_reads_memory_the_run_left() {
    // A goal over a place rather than a slot: the handler stores a
    // constant at [stack+0], and the question is asked of the memory the
    // store landed in. The answer comes from the program's own write, so
    // it rests on nothing the run failed to record.
    lift::Model model;
    const std::vector<lift::Handler> handlers = {
        lift::summarize(model, kStoreConstant.data(), kStoreConstant.size(),
                        kHandlerVa, kHandlerVa)};
    std::vector<lift::Row> rows(1);
    rows[0].seq = 1;
    rows[0].rbp = 0x3000;
    const std::vector<std::size_t> which{0};
    lift::SolveOptions opts;
    opts.unknown.push_back(lift::UnknownRegion{0x5000, 1});
    opts.goals.push_back(goal_of("mem8[0x3000] == 0x11"));
    const lift::SolveResult res =
        lift::solve(model, handlers, rows, which, nullptr, nullptr, opts);
    check(res.solved, "a goal over an address reads the store the handler "
                      "made there");
    check(res.goal_addresses.size() == 1 && res.goal_addresses[0] == 0x3000,
          "and the address it read is the one the goal named");
    check(res.goal_text.size() == 1 &&
              res.goal_text[0] == "mem8[0x3000] == 0x11",
          "and the goal is echoed back in the machine's own spelling");

    // The same store, asked the other way: a value it did not write is a
    // question with no answer, and that is reported rather than
    // invented.
    lift::Model other;
    const std::vector<lift::Handler> other_handlers = {
        lift::summarize(other, kStoreConstant.data(), kStoreConstant.size(),
                        kHandlerVa, kHandlerVa)};
    lift::SolveOptions no;
    no.unknown.push_back(lift::UnknownRegion{0x5000, 1});
    no.goals.push_back(goal_of("mem8[0x3000] == 0x22"));
    const lift::SolveResult unsat =
        lift::solve(other, other_handlers, rows, which, nullptr, nullptr, no);
    check(!unsat.solved, "a value the store did not write is not reported as "
                         "one it did");
}

}  // namespace

int main() {
    const auto run = [](const char* name, void (*fn)()) {
        std::printf("-- %s\n", name);
        std::fflush(stdout);
        fn();
    };
    run("solve_reads_unknown", test_solve_reads_a_byte_out_of_the_unknown);
    run("solve_unsatisfiable", test_solve_reports_a_goal_no_input_can_meet);
    run("solve_or_split", test_solve_splits_a_goal_that_a_bitwise_or_joins);
    run("solve_narrow_goal", test_solve_looks_through_a_narrow_goal);
    run("solve_goal_base", test_solve_reads_the_goal_at_the_last_row_s_pointer);
    run("solve_says_what_it_was_not_told", test_solve_says_what_it_was_not_told);
    run("goal_parses", test_goal_language_parses_what_a_caller_writes);
    run("goal_refuses", test_goal_language_refuses_what_it_cannot_read);
    run("goal_round_trip", test_goal_language_round_trips);
    run("goal_memory", test_goal_language_reads_memory_the_run_left);
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

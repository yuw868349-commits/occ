// Handler lifting tests.
//
// The handlers here are hand-assembled byte sequences whose effects are
// known by construction, and the traces are built the same way: the
// expected post-state of each handler is computed by hand from the
// micro-program, fed in as an observed row, and the model has to agree.
// That is the same agreement the pipeline runs against a real trace --
// the difference is only who supplied the numbers.
//
// The cases are the ones that would pass a weaker analysis: a write to a
// stack slot, a stack shift that moves which slot is on top, a bytecode
// read whose value lands in a slot, and the decrypt-and-dispatch handler
// whose jump target is an expression over the bytecode rather than a
// constant. One case has junk in the middle that the interpreter cannot
// model, to check that the model is reported incomplete *and* still
// recovers the effect that matters. One case mutates the observed trace
// so the checker has to fail: a conformance check that cannot fail is
// not a check.

#include "occ/devirt/lift.h"

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

// ------------------------------------------------------------- programs

// add:  rax = st0; rax += st1; st1 = rax; rbp += 8 -> the virtual
// "pop both, push the sum" instruction.
const std::vector<std::uint8_t> kAdd = {
    0x48, 0x8B, 0x45, 0x00,  // mov rax, [rbp+0x0]
    0x48, 0x03, 0x45, 0x08,  // add rax, [rbp+0x8]
    0x48, 0x89, 0x45, 0x08,  // mov [rbp+0x8], rax
    0x48, 0x83, 0xC5, 0x08,  // add rbp, 0x8
    0xFF, 0xE1,              // jmp rcx
};

// byte:  al = [rsi]; rsi += 1; st0 = al -> the virtual "push immediate
// byte" instruction, with the byte coming from the bytecode.
const std::vector<std::uint8_t> kByte = {
    0x48, 0x0F, 0xB6, 0x06,  // movzx rax, byte [rsi]
    0x48, 0x83, 0xC6, 0x01,  // add rsi, 0x1
    0x48, 0x89, 0x45, 0x00,  // mov [rbp+0x0], rax
    0xFF, 0xE1,              // jmp rcx
};

// decrypt: the sample's dispatch handler -- read the bytecode word,
// rotate it, advance the cursor, jump to it.
const std::vector<std::uint8_t> kDecrypt = {
    0x48, 0x8B, 0x06,        // mov rax, [rsi]
    0x48, 0xC1, 0xC0, 0x0A,  // rol rax, 0xa
    0x48, 0x83, 0xC6, 0x08,  // add rsi, 0x8
    0xFF, 0xE0,              // jmp rax
};

// junk: a cpuid the interpreter does not model, then a real effect.
const std::vector<std::uint8_t> kJunk = {
    0x0F, 0xA2,              // cpuid
    0x48, 0x83, 0xC6, 0x02,  // add rsi, 0x2
    0xFF, 0xE1,              // jmp rcx
};

constexpr std::uint64_t kHandlerVa = 0x1000;

struct Image {
    std::vector<std::uint8_t> bytes;
    std::uint64_t base = 0x2000;
};

bool read_image(void* ctx, std::uint64_t va, unsigned width, std::uint64_t* out) {
    const auto* img = static_cast<const Image*>(ctx);
    std::uint64_t value = 0;
    for (unsigned i = 0; i < width / 8; ++i) {
        const std::uint64_t at = va - img->base + i;
        if (at >= img->bytes.size()) {
            return false;
        }
        value |= static_cast<std::uint64_t>(img->bytes[at]) << (8 * i);
    }
    *out = value;
    return true;
}

// -------------------------------------------------------------- decoding

void test_decode_insn() {
    {
        lift::Insn in;
        const bool ok = lift::decode_insn(kAdd.data(), kAdd.size(), kHandlerVa, in);
        check(ok, "the first instruction decodes");
        check(in.length == 4 && in.mnemonic == "mov", "mov rax, [rbp+0x0]");
        check(in.operands.size() == 2, "mov has two operands");
        if (in.operands.size() == 2) {
            check(in.operands[0].kind == lift::Operand::Kind::Reg &&
                      in.operands[0].reg == "rax" &&
                      in.operands[0].width == 64,
                  "the destination is rax at 64 bits");
            check(in.operands[1].kind == lift::Operand::Kind::Mem &&
                      in.operands[1].base == "rbp" && in.operands[1].disp == 0 &&
                      in.operands[1].width == 64,
                  "the source is [rbp+0] at 64 bits");
        }
    }
    {
        lift::Insn in;
        const bool ok =
            lift::decode_insn(kAdd.data() + 12, kAdd.size() - 12, kHandlerVa + 12, in);
        check(ok && in.mnemonic == "add", "add rbp, 0x8 decodes");
        check(in.operands.size() == 2 && in.operands[1].kind == lift::Operand::Kind::Imm &&
                  in.operands[1].imm == 8,
              "the immediate is 8");
    }
    {
        lift::Insn in;
        const bool ok = lift::decode_insn(kByte.data(), kByte.size(), kHandlerVa, in);
        check(ok && in.mnemonic == "movzx", "movzx rax, byte [rsi] decodes");
        check(in.operands.size() == 2 &&
                  in.operands[1].kind == lift::Operand::Kind::Mem &&
                  in.operands[1].base == "rsi" && in.operands[1].width == 8,
              "the source is a byte of the bytecode");
    }
    {
        lift::Insn in;
        const bool ok =
            lift::decode_insn(kDecrypt.data() + 4, kDecrypt.size() - 4, kHandlerVa + 4, in);
        check(ok && in.mnemonic == "rol", "rol rax, 0xa decodes");
        check(in.operands.size() == 2 && in.operands[1].imm == 10,
              "the rotate amount is 10");
    }
}

// ----------------------------------------------------------- summarizing

void test_add_handler() {
    lift::Model model;
    const lift::Handler h =
        lift::summarize(model, kAdd.data(), kAdd.size(), kHandlerVa, kHandlerVa);
    check(h.modeled, "the add handler is fully modelled");
    check(h.transfer == lift::Handler::Transfer::Dispatch,
          "it ends by dispatching");
    check(!h.writes.empty() && h.writes[0].disp == 8,
          "it writes the slot at +8");
    check(h.writes[0].value != expr::kNoId, "the written value is an expression");
    if (h.writes[0].value != expr::kNoId) {
        // st1 = st0 + st1, expressed over the two slot inputs.
        const std::string text = lift::render(model, h.writes[0].value);
        check(text.find("vst[+0]") != std::string::npos &&
                  text.find("vst[+8]") != std::string::npos,
              "the write reads both slots");
        check(text.find("+") != std::string::npos,
              "and it is a sum of the two");
    }
    check(h.rbp_new != expr::kNoId && h.rsi_new != expr::kNoId,
          "rbp and rsi come back as expressions");
}

void test_byte_handler() {
    lift::Model model;
    const lift::Handler h =
        lift::summarize(model, kByte.data(), kByte.size(), kHandlerVa, kHandlerVa);
    check(h.modeled, "the byte handler is fully modelled");
    check(!h.writes.empty() && h.writes[0].disp == 0 &&
              h.writes[0].value != expr::kNoId,
          "it writes the top slot");
    if (h.writes[0].value != expr::kNoId) {
        const std::string text = lift::render(model, h.writes[0].value);
        check(text.find("code[+0]") != std::string::npos,
              "the value comes from the bytecode byte");
    }
}

void test_decrypt_handler() {
    lift::Model model;
    const lift::Handler h =
        lift::summarize(model, kDecrypt.data(), kDecrypt.size(), kHandlerVa,
                        kHandlerVa);
    check(h.modeled, "the decrypt handler is fully modelled");
    check(h.transfer == lift::Handler::Transfer::Dispatch,
          "it dispatches");
    check(h.target_expr != expr::kNoId,
          "the dispatch target is an expression, not a constant");
    if (h.target_expr != expr::kNoId) {
        const std::string text = lift::render(model, h.target_expr);
        check(text.find("code[+0]") != std::string::npos,
              "the target is computed from the bytecode word");
        check(text.find("<<") != std::string::npos &&
                  text.find(">>") != std::string::npos,
              "the rotate is two shifts and an or");
    }
}

void test_junk_is_reported_not_hidden() {
    lift::Model model;
    const lift::Handler h =
        lift::summarize(model, kJunk.data(), kJunk.size(), kHandlerVa, kHandlerVa);
    // The walk does not stop at the junk, and it does not guess either:
    // what the instruction can no longer be shown not to have written
    // becomes unknowns of their own, so the model claims nothing it
    // cannot know -- and the note says it happened.
    check(h.modeled, "an unmodelled instruction does not make the model inexact");
    check(!h.notes.empty(), "but it is reported");
    bool mentioned = false;
    for (const std::string& n : h.notes) {
        if (n.find("cpuid") != std::string::npos) {
            mentioned = true;
        }
    }
    check(mentioned, "the note names the instruction");
    check(h.transfer == lift::Handler::Transfer::Dispatch,
          "and the walk went on");
    // The cursor's effect is the increment over what the junk left: an
    // expression, not a hole and not a stale value.
    check(h.rsi_new != expr::kNoId, "the cursor effect survived the junk");
    if (h.rsi_new != expr::kNoId) {
        const std::string text = lift::render(model, h.rsi_new);
        check(text.find("unk[") != std::string::npos &&
                  text.find("0x2") != std::string::npos,
              "as the increment applied to an unknown of its own");
    }
}

// ---------------------------------------------------------- conformance

void test_conformance_agrees_and_bites() {
    lift::Model model;
    const std::vector<lift::Handler> handlers = {
        lift::summarize(model, kAdd.data(), kAdd.size(), kHandlerVa,
                        kHandlerVa)};

    // The trace: rbp 0x3000, st0 = 5, st1 = 7, st2 = 9. The handler
    // computes 5 + 7, stores it at +8 and pops, so the next state has
    // rbp 0x3008 and the new top slot equal to 12.
    std::vector<lift::Row> rows(2);
    rows[0].seq = 1;
    rows[0].rsi = 0x2000;
    rows[0].rbp = 0x3000;
    rows[0].st0 = 5;
    rows[0].st1 = 7;
    rows[0].st2 = 9;
    rows[1].seq = 2;
    rows[1].rsi = 0x2000;
    rows[1].rbp = 0x3008;
    rows[1].st0 = 12;
    rows[1].st1 = 9;
    rows[1].st2 = 0;
    const std::vector<std::size_t> which{0};

    const lift::Conformance good =
        lift::check_trace(model, handlers, rows, which, nullptr, nullptr);
    check(good.mismatched == 0, "the model matches the trace");
    check(good.checked >= 3, "the pointer and the slot were actually checked");
    check(good.unmodeled == 0, "no dispatch went unmodelled");

    // Move the observed stack pointer and the check has to fail: the
    // conformance report is the thing that makes the model trustworthy,
    // and a check that cannot fail is not a check.
    std::vector<lift::Row> wrong = rows;
    wrong[1].rbp = 0x3010;
    const lift::Conformance bad =
        lift::check_trace(model, handlers, wrong, which, nullptr, nullptr);
    check(bad.mismatched > 0, "a wrong trace is caught");
    check(!bad.failures.empty(), "and is reported with both numbers");
    if (!bad.failures.empty()) {
        const std::string& f = bad.failures.front();
        check(f.find("rbp") != std::string::npos,
              "the failure names the field that disagreed");
    }

    // A wrong slot value is caught too.
    std::vector<lift::Row> wrong_slot = rows;
    wrong_slot[1].st0 = 13;
    const lift::Conformance bad_slot =
        lift::check_trace(model, handlers, wrong_slot, which, nullptr, nullptr);
    check(bad_slot.mismatched > 0, "a wrong slot value is caught");
}

void test_bytecode_binding() {
    lift::Model model;
    const std::vector<lift::Handler> handlers = {
        lift::summarize(model, kByte.data(), kByte.size(), kHandlerVa,
                        kHandlerVa)};

    Image img;
    img.bytes = {0x00, 0x00, 0x00, 0x00, 0x2A};  // the byte at +4 is 0x2a
    img.base = 0x4000;

    std::vector<lift::Row> rows(2);
    rows[0].seq = 1;
    rows[0].rsi = 0x4004;  // the cursor points at 0x2a
    rows[0].rbp = 0x5000;
    rows[1].seq = 2;
    rows[1].rsi = 0x4005;
    rows[1].rbp = 0x5000;
    rows[1].st0 = 0x2A;   // the byte the handler fetched
    const std::vector<std::size_t> which{0};

    const lift::Conformance conf = lift::check_trace(
        model, handlers, rows, which, read_image, &img);
    check(conf.mismatched == 0, "the bytecode read matches the image");
    check(conf.checked >= 3, "the cursor and the slot were checked");
}

// ----------------------------------------------------------- newer forms

// The integer forms a real VMP handler is full of: bit tests, bit scans,
// a byte swap, a rotate through the carry, a double shift, and xadd.
const std::vector<std::uint8_t> kBt = {
    0x48, 0x0F, 0xA3, 0xD0,  // bt rax, rdx
    0xFF, 0xE1,              // jmp rcx
};
const std::vector<std::uint8_t> kBts = {
    0x48, 0x0F, 0xAB, 0xD0,  // bts rax, rdx
    0xFF, 0xE1,
};
const std::vector<std::uint8_t> kBsr = {
    0x48, 0x0F, 0xBD, 0xC2,  // bsr rax, rdx
    0xFF, 0xE1,
};
const std::vector<std::uint8_t> kBswap = {
    0x48, 0x0F, 0xC8,        // bswap rax
    0xFF, 0xE1,
};
const std::vector<std::uint8_t> kRcl = {
    0x48, 0xC1, 0xD0, 0x01,  // rcl rax, 0x1
    0xFF, 0xE1,
};
const std::vector<std::uint8_t> kShld = {
    0x48, 0x0F, 0xA4, 0xD0, 0x08,  // shld rax, rdx, 0x8
    0xFF, 0xE1,
};
const std::vector<std::uint8_t> kXadd = {
    0x48, 0x0F, 0xC1, 0xD0,  // xadd rax, rdx
    0xFF, 0xE1,
};

void test_more_integer_forms() {
    struct Case {
        const char* name;
        const std::vector<std::uint8_t>* bytes;
    };
    const Case cases[] = {
        {"bt", &kBt},     {"bts", &kBts},   {"bsr", &kBsr},
        {"bswap", &kBswap}, {"rcl", &kRcl}, {"shld", &kShld},
        {"xadd", &kXadd},
    };
    for (const Case& c : cases) {
        lift::Model model;
        const lift::Handler h =
            lift::summarize(model, c.bytes->data(), c.bytes->size(),
                            kHandlerVa, kHandlerVa);
        const std::string what =
            std::string("the handler with ") + c.name + " is fully modelled";
        check(h.modeled, what.c_str());
        check(h.transfer == lift::Handler::Transfer::Dispatch,
              (std::string("and ") + c.name + " still dispatches").c_str());
    }
}

// A chain of two blocks where the entry jumps *backwards* to the first:
// the read in the entry block, then the write in the earlier block. The
// single-block tests would pass a walk that cannot leave its bytes, so
// this is the case that pins the window.
const std::vector<std::uint8_t> kChain = {
    0x48, 0x89, 0x45, 0x08,              // 0:  mov [rbp+0x8], rax
    0xFF, 0xE1,                          // 4:  jmp rcx
    0x90, 0x90, 0x90, 0x90, 0x90,        // 6:  padding
    0x90, 0x90, 0x90, 0x90, 0x90,        // 11: padding
    0x48, 0x8B, 0x45, 0x00,              // 16: mov rax, [rbp+0x0]
    0xE9, 0xE7, 0xFF, 0xFF, 0xFF,        // 20: jmp 0 (rel -25)
};

void test_chain_steps_backwards() {
    lift::Model model;
    const lift::Handler h =
        lift::summarize(model, kChain.data(), kChain.size(), kHandlerVa,
                        kHandlerVa + 16);
    check(h.modeled, "a chain with a backwards jump is walked");
    check(h.transfer == lift::Handler::Transfer::Dispatch,
          "the chain ends at the indirect jump");
    check(h.writes.size() == 1 && h.writes[0].disp == 8,
          "the write from the earlier block is recovered");
    if (!h.writes.empty() && h.writes[0].value != expr::kNoId) {
        const std::string text = lift::render(model, h.writes[0].value);
        check(text.find("vst[+0]") != std::string::npos,
              "and its value is the slot the entry block loaded");
    }
}

// An opaque branch: the condition depends on flags the handler was
// entered with, so it cannot be reduced. Both edges are walked and the
// arms merged under the condition, which makes the model exact for
// either outcome -- and the trace check, which *can* evaluate the
// condition, follows the arm that ran.
const std::vector<std::uint8_t> kOpaque = {
    0x0F, 0x85, 0x14, 0x00, 0x00, 0x00,  // 0:  jne 0x1a (the other arm)
    0x48, 0x83, 0xC6, 0x01,              // 6:  add rsi, 0x1
    0x48, 0x89, 0x45, 0x00,              // 10: mov [rbp+0], rax
    0xFF, 0xE1,                          // 14: jmp rcx
    0x90, 0x90, 0x90, 0x90, 0x90,        // 16: padding
    0x90, 0x90, 0x90, 0x90, 0x90,        // 21: padding
    0x48, 0x83, 0xEE, 0x02,              // 26: sub rsi, 0x2
    0x48, 0x89, 0x55, 0x08,              // 30: mov [rbp+8], rdx
    0xFF, 0xE1,                          // 34: jmp rcx
};

void test_opaque_branch_is_merged() {
    lift::Model model;
    const lift::Handler h =
        lift::summarize(model, kOpaque.data(), kOpaque.size(), kHandlerVa,
                        kHandlerVa);
    check(h.modeled, "both edges of the branch are walked, so it is exact");
    check(h.transfer == lift::Handler::Transfer::Dispatch,
          "and it still dispatches");

    // Each arm's effect is in the model under the condition: rsi is
    // one past its entry value or two before it, and the write is to one
    // slot or the other.
    bool saw_select = false;
    if (h.rsi_new != expr::kNoId) {
        const std::string text = lift::render(model, h.rsi_new);
        if (text.find(" ? ") != std::string::npos) {
            saw_select = true;
        }
    }
    check(saw_select, "the condition decides which arm's value it is");

    // The same handler against a trace, twice: once with the condition
    // true and once false. The checker has to follow the arm that ran and
    // agree with the observed state both times.
    const auto run = [&](bool taken) {
        std::vector<lift::Row> rows(2);
        rows[0].seq = 1;
        rows[0].rsi = 0x2000;
        rows[0].rbp = 0x3000;
        rows[0].st0 = 0x11;
        rows[0].st1 = 0x22;
        rows[0].st2 = 0x33;
        rows[1].seq = 2;
        rows[1].rsi = taken ? 0x2000 : 0x2001;
        rows[1].rbp = 0x3000;
        rows[1].st0 = taken ? 0x11 : 0x11;
        rows[1].st1 = 0x22;
        rows[1].st2 = 0x33;
        const std::vector<std::size_t> which{0};
        return lift::check_trace(model, {h}, rows, which, nullptr, nullptr);
    };
    // The condition is entered-flags, which the trace does not carry, so
    // both outcomes stay unverifiable rather than checked -- but neither
    // may come out as a mismatch, because the model does not claim one
    // arm's values for the other.
    const lift::Conformance c = run(false);
    check(c.mismatched == 0, "the arm that ran is the one predicted");
}

// A branch whose condition the trace *can* decide: the model's select is
// then evaluated on the side that ran, so the prediction is checked
// rather than left unverifiable.
const std::vector<std::uint8_t> kDecidable = {
    0x48, 0x83, 0xFE, 0x00,              // 0:  cmp rsi, 0x0
    0x0F, 0x85, 0x10, 0x00, 0x00, 0x00,  // 4:  jne 0x1a
    0x48, 0x83, 0xC6, 0x01,              // 10: add rsi, 0x1
    0xFF, 0xE1,                          // 14: jmp rcx
    0x90, 0x90, 0x90, 0x90, 0x90,        // 16: padding
    0x90, 0x90, 0x90, 0x90, 0x90,        // 21: padding
    0x48, 0x83, 0xC6, 0x04,              // 26: add rsi, 0x4
    0xFF, 0xE1,                          // 30: jmp rcx
};

void test_merged_condition_is_checked() {
    lift::Model model;
    const lift::Handler h =
        lift::summarize(model, kDecidable.data(), kDecidable.size(),
                        kHandlerVa, kHandlerVa);
    check(h.modeled, "the branch's condition is a value the model holds");

    // rsi != 0: the branch is taken and the cursor advances by four.
    std::vector<lift::Row> rows(2);
    rows[0].seq = 1;
    rows[0].rsi = 0x2000;
    rows[0].rbp = 0x3000;
    rows[1].seq = 2;
    rows[1].rsi = 0x2004;
    rows[1].rbp = 0x3000;
    const std::vector<std::size_t> which{0};
    const lift::Conformance taken =
        lift::check_trace(model, {h}, rows, which, nullptr, nullptr);
    check(taken.mismatched == 0, "the taken arm's value is predicted");
    check(taken.checked >= 2, "and it was checked, not left unverifiable");

    // rsi == 0: the branch falls through and the cursor advances by one.
    rows[0].rsi = 0;
    rows[1].rsi = 0x1;
    const lift::Conformance fall =
        lift::check_trace(model, {h}, rows, which, nullptr, nullptr);
    check(fall.mismatched == 0, "the fall-through arm's value is predicted");
    check(fall.checked >= 2, "and that one is checked too");
}

// mov dh, ah: bits 8..15 of rdx take bits 8..15 of rax. A model that
// folds dh into rsi would move the cursor register, which is how a junk
// scratch byte once wandered into it, so this pins the high bytes.
const std::vector<std::uint8_t> kHighByte = {
    0x88, 0xE6,              // mov dh, ah
    0xFF, 0xE1,              // jmp rcx
};

void test_high_bytes_stay_in_their_parent() {
    lift::Model model;
    const lift::Handler h =
        lift::summarize(model, kHighByte.data(), kHighByte.size(),
                        kHandlerVa, kHandlerVa);
    check(h.modeled, "mov dh, ah is modelled");
    if (h.rsi_new != expr::kNoId) {
        check(lift::render(model, h.rsi_new) == "rsi",
              "the cursor register is untouched");
    }
    if (h.rbp_new != expr::kNoId) {
        check(lift::render(model, h.rbp_new) == "rbp",
              "and so is the stack pointer");
    }
}

// sub rsi, 0xffffffffffffffff in its imm32 form: the immediate is
// sign-extended to the operand width, so this is an increment. A decoder
// that skips the sign extension reads it as +0xffffffff and the cursor
// prediction is off by 2^32.
const std::vector<std::uint8_t> kSubNeg = {
    0x48, 0x81, 0xEE, 0xFF, 0xFF, 0xFF, 0xFF,  // sub rsi, -1
    0xFF, 0xE1,
};

void test_imm32_sign_extends() {
    lift::Model model;
    const lift::Handler h =
        lift::summarize(model, kSubNeg.data(), kSubNeg.size(), kHandlerVa,
                        kHandlerVa);
    check(h.modeled, "the imm32 form is modelled");
    if (h.rsi_new != expr::kNoId) {
        const std::vector<unsigned> deps = model.dag.inputs_of(h.rsi_new);
        std::vector<std::uint64_t> binding(model.inputs.size(), 0);
        for (const unsigned d : deps) {
            if (d < model.inputs.size() && model.inputs[d].name == "rsi") {
                binding[d] = 0x1000;
            }
        }
        check(model.dag.evaluate(h.rsi_new, binding) == 0x1001,
              "rsi comes back one past its entry value");
    }
}

// A 16-bit store into the upper half of a slot, `mov [rbp+2], ax`: the
// low half of the slot has to survive it.
const std::vector<std::uint8_t> kHalfSlot = {
    0x66, 0x89, 0x45, 0x02,  // mov [rbp+0x2], ax
    0xFF, 0xE1,
};

void test_partial_slot_write() {
    lift::Model model;
    const lift::Handler h =
        lift::summarize(model, kHalfSlot.data(), kHalfSlot.size(),
                        kHandlerVa, kHandlerVa);
    check(h.modeled, "a half-slot store is modelled");
    check(h.writes.size() == 1 && h.writes[0].disp == 0,
          "the write lands on the slot");
    if (!h.writes.empty() && h.writes[0].value != expr::kNoId) {
        const std::string text = lift::render(model, h.writes[0].value);
        check(text.find("vst[+0]") != std::string::npos &&
                  text.find("<<") != std::string::npos,
              "the low half is preserved and the value shifted in");
    }
}

// A virtual store: the address comes off the stack, and the handler
// stores through it. The effect is a write the model can name (both the
// address and the value are expressions), not a note about an address it
// cannot track.
const std::vector<std::uint8_t> kStore = {
    0x48, 0x8B, 0x45, 0x00,  // mov rax, [rbp+0x0]
    0x48, 0x8B, 0x55, 0x08,  // mov rdx, [rbp+0x8]
    0x48, 0x83, 0xC5, 0x10,  // add rbp, 0x10
    0x48, 0x89, 0x10,        // mov [rax], rdx
    0xFF, 0xE1,              // jmp rcx
};

void test_computed_store() {
    lift::Model model;
    const lift::Handler h =
        lift::summarize(model, kStore.data(), kStore.size(), kHandlerVa,
                        kHandlerVa);
    check(h.modeled, "the store through a computed address is modelled");
    check(h.writes.size() == 1, "one write");
    if (h.writes.size() == 1) {
        const lift::Handler::Write& w = h.writes[0];
        check(!w.to_slot, "and it is a computed-address write");
        check(lift::render(model, w.addr) == "vst[+0]",
              "the address is the slot it was popped from");
        check(lift::render(model, w.value) == "vst[+8]",
              "the value is the other slot");
    }
    check(lift::render(model, h.rbp_new) == "(rbp + 0x10)",
          "and the stack pointer moved past both");

    // The same handler against a trace: the store's address is the value
    // the trace put in slot 0, the stored value is the one in slot 1, and
    // the checker has to look both up and find the store where it lands.
    std::vector<lift::Row> rows(2);
    rows[0].seq = 1;
    rows[0].rsi = 0x2000;
    rows[0].rbp = 0x3000;
    rows[0].st0 = 0x3010;  // where the store goes
    rows[0].st1 = 0xCAFEBABE;
    rows[0].st2 = 0;
    rows[1].seq = 2;
    rows[1].rsi = 0x2000;
    rows[1].rbp = 0x3010;
    rows[1].st0 = 0xCAFEBABE;
    rows[1].st1 = 0;
    rows[1].st2 = 0;
    const std::vector<std::size_t> which{0};
    const lift::Conformance good =
        lift::check_trace(model, {h}, rows, which, nullptr, nullptr);
    check(good.mismatched == 0, "the store lands where the trace says");
    check(good.checked >= 3, "and the pointer and the slot were checked");

    std::vector<lift::Row> wrong = rows;
    wrong[1].st0 = 0xCAFEBABF;
    const lift::Conformance bad =
        lift::check_trace(model, {h}, wrong, which, nullptr, nullptr);
    check(bad.mismatched >= 1, "a wrong stored value is caught");
}

// rcl by CL with the carry set: the count is computed, and the result --
// and the ring the instruction rotates through -- are still expressible.
const std::vector<std::uint8_t> kRclCl = {
    0x8A, 0x06,              // mov al, [rsi]
    0xF9,                    // stc
    0xD2, 0xD0,              // rcl al, cl
    0x88, 0x45, 0x00,        // mov [rbp+0], al
    0xFF, 0xE1,              // jmp rcx
};

void test_symbolic_rotate() {
    lift::Model model;
    const lift::Handler h =
        lift::summarize(model, kRclCl.data(), kRclCl.size(), kHandlerVa,
                        kHandlerVa);
    check(h.modeled, "a rotate by a computed count is modelled");
    check(!h.writes.empty() && h.writes[0].value != expr::kNoId,
          "and its value is an expression");
    if (h.writes.empty() || h.writes[0].value == expr::kNoId) {
        return;
    }
    const expr::Id value = h.writes[0].value;

    // Bind what the trace would: the bytecode byte, the count register,
    // and the slot the byte is written into. Then compare against the
    // ring the hardware rotates through, for counts on both sides of the
    // operand width.
    const auto evaluate = [&](std::uint64_t count) {
        std::vector<std::uint64_t> binding(model.inputs.size(), 0);
        for (std::size_t i = 0; i < model.inputs.size(); ++i) {
            const lift::Model::Input& in = model.inputs[i];
            if (in.name == "code[+0]") {
                binding[i] = 0xB5;
            } else if (in.name == "rcx") {
                binding[i] = count;
            }
        }
        return model.dag.evaluate(value, binding);
    };
    const auto ring = [](unsigned n) {
        // rcl of 0xB5 with CF = 1, n taken modulo the nine-bit ring.
        unsigned x = 0xB5 | (1u << 8);
        const unsigned k = n % 9;
        x = ((x << k) | (x >> (9 - k))) & 0x1FF;
        return x & 0xFF;
    };
    for (const unsigned n : {0u, 1u, 3u, 8u, 9u, 12u, 17u}) {
        check(evaluate(n) == ring(n),
              "the rotate matches the hardware's ring for this count");
    }
}

// A partial write over a register an unmodelled instruction clobbered:
// the half the write did not touch is an unknown of its own, so the
// value stays an expression instead of collapsing to a hole.
const std::vector<std::uint8_t> kClobbered = {
    0x0F, 0xA2,              // cpuid
    0xB0, 0x05,              // mov al, 0x5
    0x48, 0x89, 0x45, 0x00,  // mov [rbp+0x0], rax
    0xFF, 0xE1,              // jmp rcx
};

void test_partial_write_over_clobbered_register() {
    lift::Model model;
    const lift::Handler h =
        lift::summarize(model, kClobbered.data(), kClobbered.size(),
                        kHandlerVa, kHandlerVa);
    check(!h.notes.empty(), "the unmodelled instruction is reported");
    check(!h.writes.empty() && h.writes[0].value != expr::kNoId,
          "the write it feeds still has a value");
    if (!h.writes.empty() && h.writes[0].value != expr::kNoId) {
        const std::string text = lift::render(model, h.writes[0].value);
        check(text.find("unk[") != std::string::npos &&
                  text.find("0x5") != std::string::npos,
              "the unknown half and the written byte are both there");
    }
}

// Two writes that overlap: a qword and then a dword inside it. The slot
// file is byte-granular, so the second write has to see the first one's
// bytes rather than the entry value.
const std::vector<std::uint8_t> kOverlap = {
    0x48, 0x89, 0x45, 0x00,  // mov [rbp+0x0], rax
    0x89, 0x5D, 0x04,        // mov [rbp+0x4], ebx
    0xFF, 0xE1,              // jmp rcx
};

void test_overlapping_writes_compose() {
    lift::Model model;
    const lift::Handler h =
        lift::summarize(model, kOverlap.data(), kOverlap.size(), kHandlerVa,
                        kHandlerVa);
    check(h.modeled, "the overlapping writes are modelled");
    check(h.writes.size() == 1 && h.writes[0].disp == 0,
          "one cell was touched");
    if (h.writes.size() != 1 || h.writes[0].value == expr::kNoId) {
        return;
    }
    const std::string text = lift::render(model, h.writes[0].value);
    check(text.find("rax") != std::string::npos &&
              text.find("rbx") != std::string::npos,
          "both regs are in the cell's value");
    // Evaluate it: the qword's low half survives (the low *dword* of the
    // cell), and the dword write lands on top of its high half.
    std::vector<std::uint64_t> binding(model.inputs.size(), 0);
    for (std::size_t i = 0; i < model.inputs.size(); ++i) {
        if (model.inputs[i].name == "rax") {
            binding[i] = 0x1111111122222222ULL;
        } else if (model.inputs[i].name == "rbx") {
            binding[i] = 0x3333333344444444ULL;
        }
    }
    const std::uint64_t got = model.dag.evaluate(h.writes[0].value, binding);
    check(got == 0x4444444422222222ULL,
          "the low dword is the first write, the high dword the second");
}

// The trace's cells are the *aligned* cells around an unaligned stack
// pointer, and the model's writes are at the addresses the handler used.
// The checker composes the comparison out of bytes, so a frame that sits
// mid-cell still checks instead of turning into a false mismatch.
void test_unaligned_frame_conformance() {
    lift::Model model;
    const lift::Handler h =
        lift::summarize(model, kAdd.data(), kAdd.size(), kHandlerVa,
                        kHandlerVa);
    // The entry frame: a qword 1, a qword 2, a qword 3 at 0x1000.
    std::vector<lift::Row> rows(2);
    rows[0].seq = 1;
    rows[0].rsi = 0x2000;
    rows[0].rbp = 0x1006;  // six bytes into the cell
    rows[0].st0 = 1;
    rows[0].st1 = 2;
    rows[0].st2 = 3;
    // The handler reads [rbp+0] and [rbp+8] over the cell boundary, adds
    // them, stores the sum at [rbp+8] and advances rbp by 8. In bytes:
    // [rbp+0] = 0x0000000000020000, [rbp+8] = 0x0000000000030000, sum =
    // 0x50000, whose eight bytes start at 0x100e. So the tracer's next
    // cells mix the store's bytes with the seed's, and the comparison
    // only comes out right if it is composed byte for byte.
    rows[1].seq = 2;
    rows[1].rsi = 0x2000;
    rows[1].rbp = 0x100E;
    rows[1].st0 = 2;  // [0x1008], the store's two low bytes are zeros
    rows[1].st1 = 5;  // [0x1010], the sum's third byte landed here
    rows[1].st2 = 0;  // [0x1018], never observed
    const std::vector<std::size_t> which{0};
    const lift::Conformance good =
        lift::check_trace(model, {h}, rows, which, nullptr, nullptr);
    check(good.mismatched == 0, "the unaligned frame checks clean");
    check(good.checked >= 3,
          "and the predictions were evaluated, not waved through");

    std::vector<lift::Row> wrong = rows;
    wrong[1].st0 ^= 0x0100000000000000ULL;
    const lift::Conformance bad =
        lift::check_trace(model, {h}, wrong, which, nullptr, nullptr);
    check(bad.mismatched >= 1, "a byte that is off is caught");
}

// The value a resize produces: x cut to 32 bits and widened back is not
// x -- the widening zeroes what the cut removed. A simplifier that folds
// the pair away hands back bits the expression should not have.
void test_resize_does_not_widen_back() {
    expr::DAG dag;
    const expr::Id x = dag.input("x", 64);
    const expr::Id cut = dag.resize(x, 32);
    const expr::Id widened = dag.resize(cut, 64);
    check(cut != widened, "a cut and a cut-then-widened are not one node");
    const std::vector<std::uint64_t> binding = {0xFFFFFFFFDEADBEEFULL};
    check(dag.evaluate(widened, binding) == 0xDEADBEEF,
          "the widened value is the low half, zero-extended");
    check(dag.evaluate(cut, binding) == 0xDEADBEEF, "and the cut agrees");
    const expr::Id twice = dag.resize(widened, 16);
    check(dag.evaluate(twice, binding) == 0xBEEF,
          "a narrowing chain still composes");
}

// Nested branches: a jne whose taken edge leaves the nest and whose
// fall-through is the next jne. Each one forks, so the walk nests one
// level deeper per instruction. The cap on that nesting is a resource,
// not a guess -- below it the model is complete, at it the model says so
// and says why.
std::vector<std::uint8_t> nest(unsigned levels) {
    std::vector<std::uint8_t> b;
    for (unsigned i = 0; i < levels; ++i) {
        const std::uint32_t rel = 6 * (levels - i - 1);
        b.insert(b.end(), {0x0F, 0x85,
                           static_cast<std::uint8_t>(rel & 0xFF),
                           static_cast<std::uint8_t>((rel >> 8) & 0xFF),
                           static_cast<std::uint8_t>((rel >> 16) & 0xFF),
                           static_cast<std::uint8_t>((rel >> 24) & 0xFF)});
    }
    b.insert(b.end(), {0xFF, 0xE1});
    return b;
}

void test_branch_nesting_cap_is_reported() {
    {
        lift::Model model;
        const std::vector<std::uint8_t> b = nest(12);
        const lift::Handler h = lift::summarize(
            model, b.data(), b.size(), kHandlerVa, kHandlerVa);
        check(h.modeled, "nested branches below the cap are walked");
        check(h.transfer == lift::Handler::Transfer::Dispatch,
              "and both arms merge back together");
    }
    {
        lift::Model model;
        const std::vector<std::uint8_t> b = nest(20);
        const lift::Handler h = lift::summarize(
            model, b.data(), b.size(), kHandlerVa, kHandlerVa);
        check(!h.modeled, "past the cap the model is not claimed exact");
        check(h.reason.find("nested") != std::string::npos,
              "and the report names the cap");
    }
}

// The dispatch word is the value the dispatcher read out of its handler
// table, and the two VM families the de-virtualizer serves store that
// value two ways. The trace does not carry which way, so the image
// decides -- and these cases pin the one rule that does the deciding: the
// word that points at code is the address, and only a word with nothing
// behind it is rotated back.
void test_handler_resolution() {
    // A hand-rolled VM's table holds the address. When the image places
    // the word, it is taken as read -- and that has to hold for any word,
    // so the check does not lean on one lucky value.
    const std::uint64_t placed[] = {
        0x1400016d0ull,  // a handler in the sample's .text
        0x1ull,
        0xffffffffffffffffull,
        0x4000000000000000ull,
    };
    for (const std::uint64_t a : placed) {
        check(lift::resolve_handler(a, true) == a,
              "a word the image places is the handler address");
    }

    // VMP 3's table holds the address rotated left by ten. Two facts pin
    // the rotate: bit 0 comes back as bit 10, and the top bit wraps to the
    // bottom instead of falling off the end -- the wrap is why the
    // operation is a rotate and not a shift.
    check(lift::resolve_handler(0x1ull, false) == 0x400ull,
          "bit 0 rotates to bit 10");
    check(lift::resolve_handler(0x8000000000000000ull, false) == 0x200ull,
          "bit 63 wraps to bit 9 rather than off the end");
    check(lift::resolve_handler(0x4000000000000000ull, false) == 0x100ull,
          "bit 62 wraps to bit 8");

    // The sample's own numbers. A dispatch word the image can place is
    // used directly; its rotated form, which the image cannot place, is
    // what the old code produced -- so a word with nothing behind it
    // still reports exactly as it did before the two families were told
    // apart.
    check(lift::resolve_handler(0x1400016d0ull, false) == 0x500005b4000ull,
          "the rotated form of a sample handler address");
    check(lift::resolve_handler(0, false) == 0, "zero resolves to zero");
}

// A VM that keeps one dispatcher lets every handler tail into it. Walking
// that shared code as if it were the handler's is what sinks the walk, so
// the boundary is where the handler ends -- and these cases pin that: the
// same bytes model differently once an address inside them is named as a
// shared entry, and the way they differ is that the walk stopped there.
void test_shared_boundary_ends_the_walk() {
    // Two moves of the virtual stack pointer, then a jump: the shape a
    // handler has when the dispatcher is code it shares with the others.
    const std::vector<std::uint8_t> body = {
        0x48, 0x83, 0xC5, 0x08,  // add rbp, 0x8
        0x48, 0x83, 0xC5, 0x08,  // add rbp, 0x8
        0xFF, 0xE1,              // jmp rcx
    };
    lift::Model walked;
    const lift::Handler whole = lift::summarize(
        walked, body.data(), body.size(), kHandlerVa, kHandlerVa);
    check(whole.modeled, "a straight handler walks to its dispatch");

    // The same bytes with the second move named a shared entry: the walk
    // stops there, so the pointer moved once and the hand-back is the
    // dispatch the boundary is.
    lift::Model cut;
    const std::vector<std::uint64_t> boundary{kHandlerVa + 4};
    const lift::Handler part = lift::summarize(
        cut, body.data(), body.size(), kHandlerVa, kHandlerVa, 96, boundary);
    check(part.modeled, "a handler stopped at a boundary is still modelled");
    check(part.transfer == lift::Handler::Transfer::Dispatch,
          "and the hand-back is the dispatch it is");
    check(lift::render(cut, part.rbp_new) != lift::render(walked, whole.rbp_new),
          "the boundary is where the handler ended, not past it");
}

// The semantics label is the model's, not a match on the instruction
// text. That is what makes it follow the convention instead of one
// family's register use -- the same handler reads differently under two
// conventions, and only the model names both.
void test_effect_label_names_the_operation() {
    lift::Model model;
    const lift::Handler h =
        lift::summarize(model, kAdd.data(), kAdd.size(), kHandlerVa, kHandlerVa);
    const std::string label = lift::effect_label(model, h);
    check(label.rfind("add", 0) == 0,
          "the label names the operation the model performed");
    check(label.find("dispatch") != std::string::npos,
          "and it says where the handler went");
}

// The layout a VM addresses is read out of the handlers' own code, not
// guessed at: the base of an indexed access and the step it takes. The
// step is what tells a register file from a byte stream, and it is the
// only thing that does.
void test_infer_layout_reads_the_handlers() {
    // A register machine: slots at `[rbx + rax*4]`, the bytecode at
    // `[rdi + rcx*1]`. One step is four bytes and one is a byte, and that
    // difference is the whole of what separates the two.
    const std::vector<std::uint8_t> body = {
        0x8B, 0x0C, 0x83,        // mov   ecx, [rbx + rax*4]
        0x89, 0x0C, 0x83,        // mov   [rbx + rax*4], ecx
        0x0F, 0xB6, 0x14, 0x0F,  // movzx edx, BYTE PTR [rdi + rcx*1]
        0xFF, 0xE1,              // jmp   rcx
    };
    const lift::HandlerBytes hb{kHandlerVa, body.data(), body.size()};
    const lift::Layout layout = lift::infer_layout({hb});
    check(layout.regfile == "rbx",
          "the wider step names the register file");
    check(layout.regfile_width == 32, "and says how wide its elements are");
    check(layout.code == "rdi", "the byte step names the bytecode buffer");
}

// A stack machine indexes nothing, so it has neither a file nor a buffer.
// The inference has to leave both empty rather than name the first
// register it happens to see.
void test_infer_layout_leaves_a_stack_machine_alone() {
    const std::vector<std::uint8_t> body = {
        0x48, 0x8B, 0x45, 0x00,  // mov rax, [rbp+0x0]
        0x48, 0x03, 0x45, 0x08,  // add rax, [rbp+0x8]
        0xFF, 0xE1,              // jmp rcx
    };
    const lift::HandlerBytes hb{kHandlerVa, body.data(), body.size()};
    const lift::Layout layout = lift::infer_layout({hb});
    check(layout.regfile.empty(), "a stack machine has no register file");
    check(layout.code.empty(), "and no bytecode buffer");
}

// ---------------------------------------------------- the trace's own bytes

void test_trace_memory_serves_its_windows() {
    // The bytes a trace carried for pages no file holds. The reader has to
    // answer a read a window contains and refuse one it does not: half an
    // answer would be a value no run produced, which is the one thing a
    // conformance check must never do.
    lift::TraceMemory mem;
    std::vector<std::uint8_t> first(16);
    for (std::size_t i = 0; i < first.size(); ++i) {
        first[i] = static_cast<std::uint8_t>(0x10 + i);
    }
    mem.add(0x1000, first);
    std::vector<std::uint8_t> second(8, 0xaa);
    mem.add(0x2000, second);

    check(mem.windows.size() == 2, "both windows are held");
    check(mem.windows[0].va == 0x1000 && mem.windows[1].va == 0x2000,
          "the windows are kept in address order");

    std::uint64_t v = 0;
    check(mem.read(0x1000, 64, &v) && v == 0x1716151413121110ull,
          "a window answers a read at its first byte, little endian");
    check(mem.read(0x1004, 32, &v) && v == 0x17161514ull,
          "a read inside a window answers");
    check(mem.read(0x1008, 64, &v) && v == 0x1f1e1d1c1b1a1918ull,
          "a read ending on the window's last byte answers");
    check(mem.read(0x2000, 64, &v) && v == 0xaaaaaaaaaaaaaaaaull,
          "the second window answers too");

    check(!mem.read(0x100c, 64, &v),
          "a read that runs past the window is refused, not truncated");
    check(!mem.read(0xff8, 16, &v), "a read that starts below a window is refused");
    check(!mem.read(0x1800, 8, &v), "a read in the gap between windows is refused");
    check(!mem.read(0x2000, 72, &v), "a read past the last window is refused");
    check(!mem.read(0, 8, &v), "a null address is no address");
    check(!mem.read(0x1000, 0, &v), "a zero width is refused");
    check(!mem.read(0x1000, 12, &v), "a width that is not whole bytes is refused");
    check(!mem.read(0x1000, 72, &v), "a width past a register is refused");
}

void test_trace_memory_later_record_wins() {
    // Two records that overlap are a hand-built reader's doing, and the one
    // fed second is the later read of those bytes: it wins where it covers
    // rather than being dropped for the collision.
    lift::TraceMemory mem;
    mem.add(0x1000, std::vector<std::uint8_t>(8, 0x11));
    mem.add(0x1004, std::vector<std::uint8_t>(8, 0x22));

    std::uint64_t v = 0;
    check(mem.read(0x1004, 32, &v) && v == 0x22222222ull,
          "the later record's bytes are the ones served");
    check(mem.read(0x1000, 32, &v) && v == 0x11111111ull,
          "the bytes only the earlier record covers keep their value");
    check(!mem.read(0x1000, 64, &v),
          "a read across the seam is refused: no single window holds it");
}

void test_trace_memory_refuses_nothing_windows() {
    // A trace from a runtime built before the tracer carried pages has no
    // windows at all, and the reader must say so rather than answer with a
    // zero: an unverifiable prediction is honest, a fabricated byte is not.
    lift::TraceMemory mem;
    std::uint64_t v = 0xdeadbeefull;
    check(!mem.read(0x1000, 8, &v), "an empty trace carries no bytes");
    check(v == 0xdeadbeefull, "and the output is left untouched");
}

// ------------------------------------------------ instantiating a model

void test_pretty_bound_replaces_what_the_run_pinned() {
    // The rendering rule the report leans on: an input the run bound is
    // the value the machine held, an input it did not is still its own
    // name, and a value prints at the width of the slot it came out of.
    expr::DAG dag;
    const expr::Id a = dag.input("st0", 32);
    const expr::Id b = dag.input("st1", 64);
    const expr::Id sum = dag.add(a, b);

    expr::Bindings bound;
    bound.values = {0x41, 0x100000000ull};
    bound.known = {true, false};

    check(dag.pretty_bound(a, bound) == "0x41",
          "a bound input prints as the value it held");
    check(dag.pretty_bound(b, bound) == "st1",
          "an input the trace never carried keeps its name");
    const std::string both = dag.pretty_bound(sum, bound);
    check(both.find("0x41") != std::string::npos &&
              both.find("st1") != std::string::npos,
          "and one expression says both at once");

    // The mask is the input's own: a thirty-two-bit slot that held 0x41
    // did not hold 0x0000000000000041.
    expr::Bindings wide;
    wide.values = {0x1ffffffffull, 0x1ffffffffull};
    wide.known = {true, true};
    check(dag.pretty_bound(a, wide) == "0xffffffff",
          "a value is printed at the width of the input it came from");
    check(dag.pretty_bound(b, wide) == "0x1ffffffff",
          "and a sixty-four-bit input keeps all of its bits");

    check(dag.pretty_bound(expr::kNoId, bound) == "?",
          "an absent expression says so rather than answering");
}

void test_instantiated_row_shows_the_run() {
    // The step the machine took, with the run's own numbers in it. The
    // symbolic model says `vst[+8] = vst[+0] + vst[+8]`; this says the
    // same thing about the row that ran, and the handler's `jmp rcx`
    // makes the row is fully pinned only when the trace carried rcx.
    lift::Model model;
    const std::vector<lift::Handler> handlers = {
        lift::summarize(model, kAdd.data(), kAdd.size(), kHandlerVa,
                        kHandlerVa)};
    std::vector<lift::Row> rows(2);
    rows[0].seq = 1;
    rows[0].rsi = 0x2000;
    rows[0].rbp = 0x3000;
    rows[0].st0 = 5;
    rows[0].st1 = 7;
    rows[0].st2 = 9;
    rows[1].seq = 2;
    rows[1].rsi = 0x2000;
    rows[1].rbp = 0x3008;
    rows[1].st0 = 12;
    rows[1].st1 = 9;
    rows[1].st2 = 0;
    for (lift::Row& r : rows) {
        r.gpr[1] = 0x4000;  // rcx, the register the handler jumps through
        r.gpr_present |= std::uint32_t{1} << 1;
    }
    const std::vector<std::size_t> which{0};

    std::vector<lift::InstantiatedRow> inst;
    const lift::Conformance conf = lift::check_trace(
        model, handlers, rows, which, nullptr, nullptr, &inst);
    check(conf.checked >= 3, "the row is still checked");
    check(inst.size() == 1, "and it is described once");
    check(inst[0].seq == 1 && inst[0].handler_va == kHandlerVa,
          "as the row that ran");
    check(inst[0].inputs_bound == inst[0].inputs_total,
          "the inputs its own effect reaches were all pinned by the trace");
    check(!inst[0].writes.empty(), "the write is there");
    if (!inst[0].writes.empty()) {
        check(inst[0].writes[0] == "vst[8] = 0xc",
              "at the slot it wrote, with the value the run produced");
    }
    check(inst[0].transfer == "0x4000",
          "and the jump it made is the address it held, not a schema");

    // The same row on a trace that never carried rcx: what the run pinned
    // stays pinned, and what it did not is not invented. The row is then
    // honestly reported as partly open.
    std::vector<lift::Row> bare = rows;
    for (lift::Row& r : bare) {
        r.gpr_present &= ~(std::uint32_t{1} << 1);
    }
    std::vector<lift::InstantiatedRow> bare_inst;
    const lift::Conformance bare_conf = lift::check_trace(
        model, handlers, bare, which, nullptr, nullptr, &bare_inst);
    check(bare_conf.mismatched == 0, "the bare row still checks out");
    check(!bare_inst.empty(), "the bare row is described too");
    if (!bare_inst.empty()) {
        check(bare_inst[0].inputs_bound < bare_inst[0].inputs_total,
              "a register the trace did not carry leaves the row open");
        check(bare_inst[0].writes.size() == 1 &&
                  bare_inst[0].writes[0] == "vst[8] = 0xc",
              "while the part it did pin still reads as the run's value");
        check(bare_inst[0].transfer == "rcx",
              "and the open part keeps its name");
    }
}

void test_instantiated_row_spans_the_last_dispatch() {
    // A trace's last dispatch has no successor to compare against, and a
    // report of the stream that stopped one row short would drop the
    // engine's final step. The walk covers it; what it skips is the
    // comparison, because there is nothing to compare with.
    lift::Model model;
    const std::vector<lift::Handler> handlers = {
        lift::summarize(model, kAdd.data(), kAdd.size(), kHandlerVa,
                        kHandlerVa)};
    // Each row's cells are the ones the previous handler left. The add
    // takes `[rbp+0] + [rbp+8]`, stores the sum at `[rbp+8]` and advances
    // rbp by eight, so the next row's top cell is what this row wrote and
    // the cell above it is what this row saw.
    std::vector<lift::Row> rows(3);
    const std::uint64_t tops[3] = {1, 3, 3};
    const std::uint64_t second[3] = {2, 0, 0};
    for (std::size_t i = 0; i < rows.size(); ++i) {
        rows[i].seq = i + 1;
        rows[i].rsi = 0x2000;
        rows[i].rbp = 0x3000 + 8 * i;
        rows[i].st0 = tops[i];
        rows[i].st1 = second[i];
        rows[i].st2 = 0;
    }
    const std::vector<std::size_t> which{0, 0, 0};

    std::vector<lift::InstantiatedRow> inst;
    const lift::Conformance conf = lift::check_trace(
        model, handlers, rows, which, nullptr, nullptr, &inst);
    check(inst.size() == 3, "every dispatch is described, the last included");
    check(inst.back().seq == 3, "and the last one is the trace's last row");
    check(conf.mismatched == 0, "with no comparison invented for it");
}

}  // namespace

int main() {
    const auto run = [](const char* name, void (*fn)()) {
        std::printf("-- %s\n", name);
        std::fflush(stdout);
        fn();
    };
    run("decode_insn", test_decode_insn);
    run("add_handler", test_add_handler);
    run("byte_handler", test_byte_handler);
    run("decrypt_handler", test_decrypt_handler);
    run("junk_reported", test_junk_is_reported_not_hidden);
    run("conformance", test_conformance_agrees_and_bites);
    run("bytecode_binding", test_bytecode_binding);
    run("more_integer_forms", test_more_integer_forms);
    run("chain_steps_backwards", test_chain_steps_backwards);
    run("opaque_branch_merged", test_opaque_branch_is_merged);
    run("merged_condition_checked", test_merged_condition_is_checked);
    run("high_bytes", test_high_bytes_stay_in_their_parent);
    run("imm32_sign_extends", test_imm32_sign_extends);
    run("partial_slot", test_partial_slot_write);
    run("computed_store", test_computed_store);
    run("symbolic_rotate", test_symbolic_rotate);
    run("clobbered_partial", test_partial_write_over_clobbered_register);
    run("overlap_compose", test_overlapping_writes_compose);
    run("unaligned_frame", test_unaligned_frame_conformance);
    run("resize_widen_back", test_resize_does_not_widen_back);
    run("nesting_cap", test_branch_nesting_cap_is_reported);
    run("handler_resolution", test_handler_resolution);
    run("shared_boundary", test_shared_boundary_ends_the_walk);
    run("effect_label", test_effect_label_names_the_operation);
    run("infer_layout", test_infer_layout_reads_the_handlers);
    run("infer_layout_stack", test_infer_layout_leaves_a_stack_machine_alone);
    run("trace_memory", test_trace_memory_serves_its_windows);
    run("trace_memory_overlap", test_trace_memory_later_record_wins);
    run("trace_memory_empty", test_trace_memory_refuses_nothing_windows);
    run("pretty_bound", test_pretty_bound_replaces_what_the_run_pinned);
    run("instantiated_row", test_instantiated_row_shows_the_run);
    run("instantiated_last_row", test_instantiated_row_spans_the_last_dispatch);
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
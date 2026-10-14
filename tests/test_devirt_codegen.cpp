// Rebuild-engine output stage tests: lift a handler, rebuild it as linear
// IR, and prove the rebuild equivalent with the same miter machinery the
// rest of the de-virtualizer trusts.
//
// Four levels of checking, all against real prove_equivalent runs:
//   - the four shared fixtures (add/byte/decrypt/junk) must rebuild to IR
//     whose simulated effects every miter proves equal to the model's, and
//     the assembly text must contain the semantics they are known for;
//   - negative cases -- a hand-tampered Function (Add replaced by Sub, a
//     store moved to the wrong slot) -- must be caught by the certificate
//     (ok false, failures non-empty), so the certificate can bite;
//   - common-subexpression elimination and dead-code elimination are
//     checked structurally in the emitted assembly;
//   - a branchy handler whose lift model carries a `select` (the lift walk
//     could not decide a branch and merged the arms) exercises a genuine
//     positive SAT miter: the branchless expansion the emitter produces is
//     structurally different from the model's select node, and only the
//     bit-blaster can prove them equal.

#include "occ/devirt/codegen.h"
#include "occ/devirt/expr.h"
#include "occ/devirt/lift.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
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

// ------------------------------------------------------------ fixtures

// add:  rax = st0; rax += st1; st1 = rax; rbp += 8
const std::vector<std::uint8_t> kAdd = {
    0x48, 0x8B, 0x45, 0x00, 0x48, 0x03, 0x45, 0x08, 0x48, 0x89, 0x45, 0x08,
    0x48, 0x83, 0xC5, 0x08, 0xFF, 0xE1};
// byte:  al = [rsi]; rsi += 1; st0 = al
const std::vector<std::uint8_t> kByte = {
    0x48, 0x0F, 0xB6, 0x06, 0x48, 0x83, 0xC6, 0x01, 0x48, 0x89, 0x45, 0x00,
    0xFF, 0xE1};
// decrypt: rax = [rsi]; rol rax, 0xa; rsi += 8; jmp rax
const std::vector<std::uint8_t> kDecrypt = {
    0x48, 0x8B, 0x06, 0x48, 0xC1, 0xC0, 0x0A, 0x48, 0x83, 0xC6, 0x08,
    0xFF, 0xE0};
// junk: cpuid; rsi += 2; jmp rcx
const std::vector<std::uint8_t> kJunk = {
    0x0F, 0xA2, 0x48, 0x83, 0xC6, 0x02, 0xFF, 0xE1};

constexpr std::uint64_t kHandlerVa = 0x1000;

// Two writes sharing one subexpression (rax = st0 + st1 stored twice).
const std::vector<std::uint8_t> kShared = {
    0x48, 0x8B, 0x45, 0x00,  // mov rax, [rbp+0x0]
    0x48, 0x03, 0x45, 0x08,  // add rax, [rbp+0x8]
    0x48, 0x89, 0x45, 0x10,  // mov [rbp+0x10], rax
    0x48, 0x89, 0x45, 0x18,  // mov [rbp+0x18], rax
    0xFF, 0xE1,              // jmp rcx
};

// A dead computation (rbx = rax - 3) no effect ever reads.
const std::vector<std::uint8_t> kDead = {
    0x48, 0x8B, 0x45, 0x00,  // mov rax, [rbp+0x0]
    0x48, 0x83, 0xC0, 0x05,  // add rax, 0x5
    0x48, 0x89, 0xC3,        // mov rbx, rax
    0x48, 0x83, 0xEB, 0x03,  // sub rbx, 0x3
    0x48, 0x89, 0x45, 0x08,  // mov [rbp+0x8], rax
    0xFF, 0xE1,              // jmp rcx
};

// A branch the lift walk cannot decide: rax is either the entry value
// (taken arm) or 7 (fall-through); the store value is a select, which the
// rebuild expands branchlessly and verify proves with a real SAT miter.
const std::vector<std::uint8_t> kBranch = {
    0x48, 0x8B, 0x45, 0x00,        // mov rax, [rbp+0x0]
    0x48, 0x83, 0xF8, 0x05,        // cmp rax, 0x5
    0x7E, 0x07,                    // jle +7 (to 0x11)
    0x48, 0xC7, 0xC0, 0x07, 0x00, 0x00, 0x00,  // mov rax, 0x7
    0x48, 0x89, 0x45, 0x08,        // mov [rbp+0x8], rax
    0xFF, 0xE1,                    // jmp rcx
};

lift::Handler summarize_one(lift::Model& model,
                            const std::vector<std::uint8_t>& bytes) {
    return lift::summarize(model, bytes.data(), bytes.size(), kHandlerVa,
                           kHandlerVa);
}

// Counts instruction lines whose mnemonic column equals `mnemonic` (the
// emitter indents every instruction with four spaces).
std::size_t count_op(const std::string& asm_text, const char* mnemonic) {
    const std::string needle = std::string("    ") + mnemonic + " ";
    std::size_t n = 0;
    std::size_t at = 0;
    while ((at = asm_text.find(needle, at)) != std::string::npos) {
        ++n;
        at += needle.size();
    }
    return n;
}

// ---------------------------------------------------------------- tests

void test_fixture_add() {
    lift::Model model;
    const lift::Handler h = summarize_one(model, kAdd);
    check(h.modeled, "add handler is modeled");
    check(h.transfer == lift::Handler::Transfer::Dispatch,
          "add handler dispatches");

    const codegen::Function f = codegen::rebuild(model, h);
    const codegen::Check c = codegen::verify(model, h, f);
    check(c.ok, "add rebuild verifies");
    check(c.failures.empty(), "add rebuild has no failures");
    check(c.miters > 0, "add rebuild produced miters");
    check(!f.insns.empty(), "add rebuild emitted instructions");

    const std::string asm_text = codegen::emit_asm(f);
    check(asm_text.find("0x1000") != std::string::npos,
          "add asm header names the handler VA");
    check(count_op(asm_text, "add") >= 1, "add asm contains an add");
    check(count_op(asm_text, "mov") >= 1, "add asm contains movs");
    check(count_op(asm_text, "jmp") == 1, "add asm ends with one jmp");
}

void test_fixture_byte() {
    lift::Model model;
    const lift::Handler h = summarize_one(model, kByte);
    check(h.modeled, "byte handler is modeled");

    const codegen::Function f = codegen::rebuild(model, h);
    const codegen::Check c = codegen::verify(model, h, f);
    check(c.ok, "byte rebuild verifies");
    check(c.failures.empty(), "byte rebuild has no failures");

    const std::string asm_text = codegen::emit_asm(f);
    check(asm_text.find("movzx") != std::string::npos,
          "byte asm loads the cursor byte with movzx");
    check(asm_text.find("[rsi]") != std::string::npos,
          "byte asm reads through the cursor");
    check(count_op(asm_text, "add") >= 1, "byte asm advances the cursor");
}

void test_fixture_decrypt() {
    lift::Model model;
    const lift::Handler h = summarize_one(model, kDecrypt);
    check(h.modeled, "decrypt handler is modeled");
    check(h.transfer == lift::Handler::Transfer::Dispatch &&
              h.target_expr != expr::kNoId,
          "decrypt handler has a dispatch target expression");

    const codegen::Function f = codegen::rebuild(model, h);
    const codegen::Check c = codegen::verify(model, h, f);
    check(c.ok, "decrypt rebuild verifies");
    check(c.failures.empty(), "decrypt rebuild has no failures");

    // The rol is expressed as (x << 10) | (x >> 54); the rebuilt code must
    // show the decryption, not a bare constant.
    const std::string asm_text = codegen::emit_asm(f);
    check(asm_text.find("shl") != std::string::npos,
          "decrypt asm shows the left shift of the rol");
    check(asm_text.find("shr") != std::string::npos,
          "decrypt asm shows the right shift of the rol");
    check(asm_text.find("or ") != std::string::npos ||
              asm_text.find("or\n") != std::string::npos,
          "decrypt asm combines the halves with or");
    check(asm_text.find("jmp") != std::string::npos,
          "decrypt asm jumps to the decrypted target");
}

void test_fixture_junk() {
    lift::Model model;
    const lift::Handler h = summarize_one(model, kJunk);
    // cpuid is not modelled: the handler carries a note disclosing it (the
    // walk still recovers the cursor advance and the dispatch).
    check(!h.notes.empty(), "junk handler carries notes");

    const codegen::Function f = codegen::rebuild(model, h);
    const codegen::Check c = codegen::verify(model, h, f);
    // The notes say cpuid was not modelled; the effects that *were*
    // recovered (cursor += 2, dispatch to rcx) must still verify.
    check(c.ok, "junk rebuild verifies despite notes");
    check(c.failures.empty(), "junk rebuild has no failures");

    const std::string asm_text = codegen::emit_asm(f);
    check(count_op(asm_text, "add") >= 1, "junk asm advances the cursor");
    check(asm_text.find("jmp rcx") != std::string::npos,
          "junk asm dispatches through rcx");
}

void test_negative_add_sub() {
    lift::Model model;
    const lift::Handler h = summarize_one(model, kAdd);
    codegen::Function f = codegen::rebuild(model, h);

    // Sabotage: turn the add into a sub. The certificate must bite.
    bool changed = false;
    for (codegen::Insn& in : f.insns) {
        if (in.op == codegen::Insn::Op::Add) {
            in.op = codegen::Insn::Op::Sub;
            changed = true;
            break;
        }
    }
    check(changed, "found the add instruction to sabotage");

    const codegen::Check c = codegen::verify(model, h, f);
    check(!c.ok, "sabotaged rebuild (Add->Sub) is not ok");
    check(!c.failures.empty(), "sabotaged rebuild reports failures");
    check(c.miters > 0, "sabotaged rebuild still ran miters");
}

void test_negative_wrong_slot() {
    lift::Model model;
    const lift::Handler h = summarize_one(model, kAdd);
    codegen::Function f = codegen::rebuild(model, h);

    // Sabotage: store the result to [rbp+0x10] instead of [rbp+0x8].
    bool changed = false;
    for (codegen::Insn& in : f.insns) {
        if (in.op == codegen::Insn::Op::Mov &&
            in.dst.kind == codegen::Operand::Kind::Slot &&
            in.dst.disp == 8) {
            in.dst.disp = 0x10;
            changed = true;
            break;
        }
    }
    check(changed, "found the slot store to sabotage");

    const codegen::Check c = codegen::verify(model, h, f);
    check(!c.ok, "sabotaged rebuild (wrong slot) is not ok");
    check(!c.failures.empty(), "sabotaged rebuild reports failures");
}

void test_cse_shared_subexpression() {
    lift::Model model;
    const lift::Handler h = summarize_one(model, kShared);
    check(h.modeled, "shared handler is modeled");
    check(h.writes.size() == 2, "shared handler performs two writes");

    const codegen::Function f = codegen::rebuild(model, h);
    const codegen::Check c = codegen::verify(model, h, f);
    check(c.ok, "shared rebuild verifies");

    const std::string asm_text = codegen::emit_asm(f);
    // The shared (st0 + st1) subexpression is materialized exactly once.
    check(count_op(asm_text, "add") == 1,
          "shared subexpression materialized once");
    check(asm_text.find("[rbp+0x10]") != std::string::npos &&
              asm_text.find("[rbp+0x18]") != std::string::npos,
          "both stores appear");
    // load + two stores (+ the fused add's memory operand needs no mov).
    check(count_op(asm_text, "mov") >= 3, "shared rebuild is straight-line");
}

void test_dead_code_eliminated() {
    lift::Model model;
    const lift::Handler h = summarize_one(model, kDead);
    check(h.modeled, "dead handler is modeled");

    const codegen::Function f = codegen::rebuild(model, h);
    const codegen::Check c = codegen::verify(model, h, f);
    check(c.ok, "dead-code rebuild verifies");

    const std::string asm_text = codegen::emit_asm(f);
    // rbx = rax - 3 feeds no effect; it must not be emitted.
    check(count_op(asm_text, "sub") == 0,
          "dead sub is not emitted");
    check(count_op(asm_text, "mov") >= 1, "the live store remains");
}

void test_branch_select_sat_miter() {
    lift::Model model;
    const lift::Handler h = summarize_one(model, kBranch);
    if (!h.modeled) {
        // The branch-merge machinery in lift is the dependency here; if it
        // declines to model this handler, the test cannot exercise what it
        // was written for -- report it loudly rather than skip.
        check(false, "branchy handler is modeled (lift merged the arms)");
        return;
    }
    check(!h.writes.empty() && h.writes[0].value != expr::kNoId,
          "branchy handler has a write value");

    const codegen::Function f = codegen::rebuild(model, h);
    const codegen::Check c = codegen::verify(model, h, f);
    // The select node is expanded branchlessly; only the SAT layer can
    // prove the expansion equal, so a real positive miter ran here.
    check(c.ok, "branchy rebuild verifies via a real miter");
    check(c.failures.empty(), "branchy rebuild has no failures");
}

void test_transfer_kind_mismatch() {
    lift::Model model;
    const lift::Handler h = summarize_one(model, kAdd);
    codegen::Function f = codegen::rebuild(model, h);

    // Sabotage: the model dispatches, but the IR returns.
    bool changed = false;
    for (codegen::Insn& in : f.insns) {
        if (in.op == codegen::Insn::Op::Jmp) {
            in.op = codegen::Insn::Op::Ret;
            changed = true;
            break;
        }
    }
    check(changed, "found the jmp to sabotage");
    const codegen::Check c = codegen::verify(model, h, f);
    check(!c.ok, "transfer-kind sabotage is not ok");
}

}  // namespace

int main() {
    test_fixture_add();
    test_fixture_byte();
    test_fixture_decrypt();
    test_fixture_junk();
    test_negative_add_sub();
    test_negative_wrong_slot();
    test_cse_shared_subexpression();
    test_dead_code_eliminated();
    test_branch_select_sat_miter();
    test_transfer_kind_mismatch();

    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

// Semantic recognition layer tests.
//
// The four handler fixtures of the contract are summarized with the lift
// and fed to `semlib::recover`, and the recovered stream is checked
// against the known effects: add -> one Add over two slots with the
// stack delta noted; byte -> one Push of the bytecode byte at cursor
// +0; decrypt -> one Jmp to a decrypted bytecode word (reported as the
// decryption expression, since no image bytes reach `recover`);
// junk -> one Unknown with a note naming the unmodellable instruction,
// never a guessed opcode. `fold_encrypted` is then exercised directly
// with known bytes: a 32-bit `0x11223344 rol 0xa` (and a rol+xor-mask
// variant) over a Code input folds to its plaintext constant, an Image
// input folds the same way, and anything with a non-bytecode leaf or a
// null reader refuses to fold.

#include "occ/devirt/expr.h"
#include "occ/devirt/lift.h"
#include "occ/devirt/semlib.h"

#include <cstdint>
#include <cstdio>
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

const std::vector<std::uint8_t> kAdd = {
    0x48, 0x8B, 0x45, 0x00, 0x48, 0x03, 0x45, 0x08, 0x48, 0x89, 0x45, 0x08,
    0x48, 0x83, 0xC5, 0x08, 0xFF, 0xE1};
const std::vector<std::uint8_t> kByte = {
    0x48, 0x0F, 0xB6, 0x06, 0x48, 0x83, 0xC6, 0x01, 0x48, 0x89, 0x45, 0x00,
    0xFF, 0xE1};
const std::vector<std::uint8_t> kDecrypt = {
    0x48, 0x8B, 0x06, 0x48, 0xC1, 0xC0, 0x0A, 0x48, 0x83, 0xC6, 0x08,
    0xFF, 0xE0};
const std::vector<std::uint8_t> kJunk = {
    0x0F, 0xA2, 0x48, 0x83, 0xC6, 0x02, 0xFF, 0xE1};
constexpr std::uint64_t kHandlerVa = 0x1000;

// ---------------------------------------------------------------- fold

// The bytecode bytes the Code inputs are bound from, little-endian.
// A reader for Code inputs: `fold_encrypted` passes the displacement
// relative to the cursor, so this reader adds its own cursor base. The
// image is a 0x5000-byte buffer; the word under test lives at 0x4000.
struct CodeCtx {
    std::vector<std::uint8_t> image;
    std::uint64_t cursor = 0x4000;
};
bool read_code(void* ctx, std::uint64_t va, unsigned width,
               std::uint64_t* out) {
    const auto* c = static_cast<const CodeCtx*>(ctx);
    const std::uint64_t addr = c->cursor + va;
    std::uint64_t v = 0;
    for (unsigned i = 0; i < width / 8 && i < 8; ++i) {
        if (addr + i >= c->image.size()) {
            return false;
        }
        v |= static_cast<std::uint64_t>(c->image[addr + i]) << (8 * i);
    }
    *out = v;
    return true;
}

CodeCtx make_code_ctx() {
    CodeCtx c;
    c.image.assign(0x5000, 0);
    c.image[0x4000] = 0x44;
    c.image[0x4001] = 0x33;
    c.image[0x4002] = 0x22;
    c.image[0x4003] = 0x11;  // the word at cursor+0 is 0x11223344
    return c;
}

// A reader for Image inputs: `fold_encrypted` passes the absolute image
// address, so this reader reads the image directly.
struct ImageCtx {
    const std::vector<std::uint8_t>* image;
    std::uint64_t base = 0x2000;
};
bool read_image(void* ctx, std::uint64_t va, unsigned width,
                std::uint64_t* out) {
    const auto* c = static_cast<const ImageCtx*>(ctx);
    std::uint64_t v = 0;
    for (unsigned i = 0; i < width / 8 && i < 8; ++i) {
        const std::uint64_t at = va - c->base + i;
        if (at >= c->image->size()) {
            return false;
        }
        v |= static_cast<std::uint64_t>((*c->image)[at]) << (8 * i);
    }
    *out = v;
    return true;
}

// A 32-bit rotate-left helper, matching the DAG's `(x << k) | (x >> (32-k))`.
expr::Id rol32(expr::DAG& dag, expr::Id x, unsigned k) {
    return dag.bit_or(dag.shl(x, dag.constant(k, 32)),
                      dag.shr(x, dag.constant(32 - k, 32)));
}

void test_fold_code_rol() {
    expr::DAG dag;
    const expr::Id c = dag.input("code[+0]", 32);
    const expr::Id t = rol32(dag, c, 10);
    CodeCtx ctx = make_code_ctx();
    const expr::Id folded = semlib::fold_encrypted(dag, t, read_code, &ctx);
    check(dag.is_const(folded), "rol of a code word folds to a constant");
    check(dag.const_value(folded) == 0x88CD1044ULL,
          "0x11223344 rol 0xa is 0x88CD1044");
    check(dag.evaluate(t, {0x11223344ULL}) == dag.const_value(folded),
          "the fold agrees with evaluating the expression");

    // A decrypt chain: rol then xor mask, as a packer's decryptor does.
    const expr::Id masked = dag.bit_xor(t, dag.constant(0x0F0F0F0F, 32));
    const expr::Id f2 = semlib::fold_encrypted(dag, masked, read_code, &ctx);
    check(dag.is_const(f2) && dag.const_value(f2) == 0x87C21F4BULL,
          "rol+xor-mask folds to the masked plaintext");
}

void test_fold_image() {
    expr::DAG dag;
    const expr::Id im = dag.input("img[0x2000]", 32);
    const expr::Id t = dag.bit_xor(im, dag.constant(0xFF, 32));
    ImageCtx ctx;
    const std::vector<std::uint8_t> bytes = {0x44, 0x33, 0x22, 0x11};
    ctx.image = &bytes;
    const expr::Id folded = semlib::fold_encrypted(dag, t, read_image, &ctx);
    check(dag.is_const(folded), "an image word folds to a constant");
    check(dag.const_value(folded) == 0x112233BBULL,
          "0x11223344 ^ 0xff is 0x112233bb");
}

void test_fold_refuses() {
    expr::DAG dag;
    const expr::Id c = dag.input("code[+0]", 32);
    const expr::Id s = dag.input("vst[+0]", 32);
    const expr::Id mixed = dag.add(c, s);
    CodeCtx ctx = make_code_ctx();
    check(semlib::fold_encrypted(dag, mixed, read_code, &ctx) == expr::kNoId,
          "an expression with a non-bytecode leaf refuses to fold");
    check(semlib::fold_encrypted(dag, c, nullptr, nullptr) == expr::kNoId,
          "a null reader binds nothing");
    check(semlib::fold_encrypted(dag, c, read_code, &ctx) != expr::kNoId,
          "a bare code read folds with a reader");
}

// -------------------------------------------------------------- recover

void test_add_recover() {
    lift::Model model;
    const std::vector<lift::Handler> handlers = {
        lift::summarize(model, kAdd.data(), kAdd.size(), kHandlerVa,
                        kHandlerVa)};
    const semlib::Stream s = semlib::recover(model, handlers);
    check(s.insns.size() == 1, "the add handler recovers one instruction");
    if (s.insns.size() == 1) {
        const semlib::VInsn& v = s.insns[0];
        check(v.op == semlib::VInsn::Op::Add, "it is an Add");
        check(v.src_va == kHandlerVa, "it carries the handler VA");
        bool slot_operand = false;
        for (const semlib::Operand& o : v.operands) {
            if (o.kind == semlib::Operand::Kind::Slot) {
                slot_operand = true;
            }
        }
        check(slot_operand, "its operands include a Slot");
        check(!v.decrypted, "it is not marked decrypted");
        check(v.note.find("vsp +8") != std::string::npos,
              "the stack delta is in the note");
    }
    check(s.unmodeled == 0 && s.unrecognized == 0,
          "the add handler is fully recognized");
}

void test_byte_recover() {
    lift::Model model;
    const std::vector<lift::Handler> handlers = {
        lift::summarize(model, kByte.data(), kByte.size(), kHandlerVa,
                        kHandlerVa)};
    const semlib::Stream s = semlib::recover(model, handlers);
    check(s.insns.size() == 1, "the byte handler recovers one instruction");
    if (s.insns.size() == 1) {
        const semlib::VInsn& v = s.insns[0];
        check(v.op == semlib::VInsn::Op::Push, "it is a Push");
        check(!v.operands.empty() &&
                  v.operands[0].kind == semlib::Operand::Kind::Code &&
                  v.operands[0].disp == 0,
              "its operand is the bytecode byte at cursor +0");
        check(!v.decrypted, "a raw byte read is not decrypted");
        check(v.note.find("cursor +1") != std::string::npos,
              "the cursor advance is noted");
    }
    check(s.unmodeled == 0 && s.unrecognized == 0,
          "the byte handler is fully recognized");
}

void test_decrypt_recover() {
    lift::Model model;
    const std::vector<lift::Handler> handlers = {
        lift::summarize(model, kDecrypt.data(), kDecrypt.size(), kHandlerVa,
                        kHandlerVa)};
    const semlib::Stream s = semlib::recover(model, handlers);
    check(s.insns.size() == 1, "the decrypt handler recovers one instruction");
    if (s.insns.size() == 1) {
        const semlib::VInsn& v = s.insns[0];
        check(v.op == semlib::VInsn::Op::Jmp, "it is a Jmp");
        check(v.decrypted, "the dispatch target is a decrypted word");
        check(!v.operands.empty() &&
                  v.operands[0].kind == semlib::Operand::Kind::Code,
              "the target is the bytecode word it decrypts");
        check(v.note.find("decrypted") != std::string::npos,
              "the note says the plaintext needs fold_encrypted");
    }
    check(s.unmodeled == 0 && s.unrecognized == 0,
          "the decrypt handler is fully recognized");
}

void test_junk_recover() {
    lift::Model model;
    const std::vector<lift::Handler> handlers = {
        lift::summarize(model, kJunk.data(), kJunk.size(), kHandlerVa,
                        kHandlerVa)};
    const semlib::Stream s = semlib::recover(model, handlers);
    check(s.insns.size() == 1, "the junk handler yields one instruction");
    if (s.insns.size() == 1) {
        const semlib::VInsn& v = s.insns[0];
        check(v.op == semlib::VInsn::Op::Unknown,
              "it is Unknown, never a guessed opcode");
        check(v.note.find("cpuid") != std::string::npos,
              "the note names the unmodellable instruction");
        check(v.note.find("cursor") != std::string::npos,
              "the approximated cursor effect is in the note");
    }
    check(s.unmodeled == 1, "the inexact model is counted unmodeled");
    check(s.unrecognized == 1, "the effect is counted unrecognized");
}

void test_stream_order_and_render() {
    lift::Model model;
    const std::vector<lift::Handler> handlers = {
        lift::summarize(model, kAdd.data(), kAdd.size(), kHandlerVa,
                        kHandlerVa),
        lift::summarize(model, kByte.data(), kByte.size(), kHandlerVa,
                        kHandlerVa),
        lift::summarize(model, kDecrypt.data(), kDecrypt.size(), kHandlerVa,
                        kHandlerVa),
        lift::summarize(model, kJunk.data(), kJunk.size(), kHandlerVa,
                        kHandlerVa)};
    const semlib::Stream s = semlib::recover(model, handlers);
    check(s.insns.size() == 4, "four handlers recover in order");
    if (s.insns.size() == 4) {
        check(s.insns[0].op == semlib::VInsn::Op::Add &&
                  s.insns[1].op == semlib::VInsn::Op::Push &&
                  s.insns[2].op == semlib::VInsn::Op::Jmp &&
                  s.insns[3].op == semlib::VInsn::Op::Unknown,
              "the stream keeps handler order and opcodes");
    }
    const std::string text = s.render();
    check(text.find("add") != std::string::npos &&
              text.find("jmp") != std::string::npos &&
              text.find("unknown") != std::string::npos,
          "render() spells the instructions out");
    check(text.find("unmodeled: 1, unrecognized: 1") != std::string::npos,
          "render() totals the honesty counters");
}

}  // namespace

int main() {
    const auto run = [](const char* name, void (*fn)()) {
        std::printf("-- %s\n", name);
        std::fflush(stdout);
        fn();
    };
    run("fold_code_rol", test_fold_code_rol);
    run("fold_image", test_fold_image);
    run("fold_refuses", test_fold_refuses);
    run("add_recover", test_add_recover);
    run("byte_recover", test_byte_recover);
    run("decrypt_recover", test_decrypt_recover);
    run("junk_recover", test_junk_recover);
    run("stream_order_and_render", test_stream_order_and_render);
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

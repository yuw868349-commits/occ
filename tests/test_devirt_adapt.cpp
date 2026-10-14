// adapt module tests: convention inference and the static CFG lift.
//
// Two layers of evidence are exercised. First, `infer_convention` is
// fed hand-built traces whose movement patterns separate the roles with
// wide margins -- the default engine convention, a fully permuted one
// (stack=rdi, cursor=r12, table=rsi, engine=rbp), and one deliberately
// ambiguous trace where the inference must refuse rather than guess.
//
// Second, `lift_static` is fed a small image: a chain of two decrypt
// handlers whose dispatch targets are encrypted bytecode words, so the
// fixpoint must decrypt word -> handler, carry the cursor along the
// edge, and close the loop -- then the failure modes: an unknown cursor
// (nothing resolvable), a host-register dispatch (jmp rcx), and a
// handler budget of one (discovery outlives the budget). Every failure
// must be reported as an indirect node or an incomplete lift, never a
// guessed edge.
//
// The permuted convention is also lifted through `summarize` itself, to
// show the parameterized engine classifies `[stack+d]`/`[cursor+d]`
// accesses under a non-default assignment, and that a trace built
// around the permuted stack register conforms.

#include "occ/devirt/adapt.h"
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

// ------------------------------------------------------------- fixtures

// Handler bytecode in the engine's own convention: rax=[rbp+0];
// rax+=[rbp+8]; [rbp+8]=rax; rbp+=8; jmp rcx.
const std::vector<std::uint8_t> kAdd = {
    0x48, 0x8B, 0x45, 0x00, 0x48, 0x03, 0x45, 0x08, 0x48, 0x89, 0x45, 0x08,
    0x48, 0x83, 0xC5, 0x08, 0xFF, 0xE1};

// movzx rax, byte [rsi]; add rsi, 1; mov [rbp+0], rax; jmp rcx.
const std::vector<std::uint8_t> kByte = {
    0x48, 0x0F, 0xB6, 0x06, 0x48, 0x83, 0xC6, 0x01, 0x48, 0x89, 0x45, 0x00,
    0xFF, 0xE1};

// rax=[rsi]; rol rax, 0xa; rsi+=8; jmp rax.
const std::vector<std::uint8_t> kDecrypt = {
    0x48, 0x8B, 0x06, 0x48, 0xC1, 0xC0, 0x0A, 0x48, 0x83, 0xC6, 0x08,
    0xFF, 0xE0};

// The same add handler written for a permuted convention
// (stack=rdi, cursor=r12): rax=[rdi+0]; rax+=[rdi+8]; [rdi+8]=rax;
// rdi+=8; jmp rcx.
const std::vector<std::uint8_t> kAddRdi = {
    0x48, 0x8B, 0x47, 0x00, 0x48, 0x03, 0x47, 0x08, 0x48, 0x89, 0x47, 0x08,
    0x48, 0x83, 0xC7, 0x08, 0xFF, 0xE1};

// movzx rax, byte [r12]; add r12, 1; mov [rdi+0], rax; jmp rcx.
const std::vector<std::uint8_t> kByteR12 = {
    0x49, 0x0F, 0xB6, 0x04, 0x24, 0x49, 0x83, 0xC4, 0x01, 0x48, 0x89, 0x47,
    0x00, 0xFF, 0xE1};

constexpr std::uint64_t kHandlerVa = 0x1000;

// A row with all six sampled fields set. st0/st1/st2 default to zero;
// the tests that use them overwrite the fields afterwards.
lift::Row row(std::uint64_t seq, std::uint64_t rsi, std::uint64_t rbp,
              std::uint64_t rdi, std::uint64_t rsp, std::uint64_t r12,
              std::uint64_t st0, std::uint64_t st1, std::uint64_t st2) {
    lift::Row r;
    r.seq = seq;
    r.rsi = rsi;
    r.rbp = rbp;
    r.rdi = rdi;
    r.rsp = rsp;
    r.r12 = r12;
    r.st0 = st0;
    r.st1 = st1;
    r.st2 = st2;
    return r;
}

// 64-bit rotate right, the inverse of the handler's rol-by-0xa.
std::uint64_t ror64(std::uint64_t x, unsigned k) {
    k &= 63;
    if (k == 0) {
        return x;
    }
    return (x >> k) | (x << (64 - k));
}

// A small image laid out at base 0x1000, written through virtual
// addresses.
struct TestImage {
    std::vector<std::uint8_t> bytes;
    std::uint64_t base = 0x1000;
    explicit TestImage(std::size_t size) : bytes(size, 0x90) {}
    void put(std::uint64_t va, const std::vector<std::uint8_t>& src) {
        const std::size_t off = static_cast<std::size_t>(va - base);
        for (std::size_t i = 0; i < src.size(); ++i) {
            bytes[off + i] = src[i];
        }
    }
    void put_u64(std::uint64_t va, std::uint64_t v) {
        const std::size_t off = static_cast<std::size_t>(va - base);
        for (unsigned i = 0; i < 8; ++i) {
            bytes[off + i] = static_cast<std::uint8_t>(v >> (8 * i));
        }
    }
};

// ------------------------------------------------------------- inference

void test_infer_default() {
    // Default convention trace: rbp steps +8 (stack), rsi steps +1/+2
    // (cursor), rdi never moves (engine), r12 jumps once (table), rsp
    // moves once (so it stays static but not the most static).
    std::vector<lift::Row> d;
    d.push_back(row(1, 0x2000, 0x3000, 0x4000, 0x7000, 0x5000, 0, 0, 0));
    d.push_back(row(2, 0x2001, 0x3008, 0x4000, 0x7008, 0x5000, 0, 0, 0));
    d.push_back(row(3, 0x2003, 0x3010, 0x4000, 0x7008, 0x5000, 0, 0, 0));
    d.push_back(row(4, 0x2004, 0x3018, 0x4000, 0x7008, 0x5000, 0, 0, 0));
    d.push_back(row(5, 0x2006, 0x3020, 0x4000, 0x7008, 0x5000, 0, 0, 0));
    d.push_back(row(6, 0x2008, 0x3028, 0x4000, 0x7008, 0x6000, 0, 0, 0));
    const adapt::InferResult ir = adapt::infer_convention(d);
    check(ir.confident, "the default trace separates every role");
    check(ir.convention == lift::kDefaultConvention,
          "the default trace infers the default convention");
}

void test_infer_permuted() {
    // Fully permuted roles: stack=rdi (+8), cursor=r12 (+1/+2),
    // table=rsi (one large jump), engine=rbp (never moves), rsp moves
    // once so it stays static without being the most static.
    std::vector<lift::Row> p;
    p.push_back(row(1, 0x5000, 0x4000, 0x3000, 0x7000, 0x2000, 0, 0, 0));
    p.push_back(row(2, 0x5000, 0x4000, 0x3008, 0x7008, 0x2001, 0, 0, 0));
    p.push_back(row(3, 0x5000, 0x4000, 0x3010, 0x7008, 0x2003, 0, 0, 0));
    p.push_back(row(4, 0x5000, 0x4000, 0x3018, 0x7008, 0x2004, 0, 0, 0));
    p.push_back(row(5, 0x5000, 0x4000, 0x3020, 0x7008, 0x2006, 0, 0, 0));
    p.push_back(row(6, 0x6000, 0x4000, 0x3028, 0x7008, 0x2008, 0, 0, 0));
    const adapt::InferResult pr = adapt::infer_convention(p);
    check(pr.confident, "the permuted trace separates every role");
    lift::Convention want;
    want.stack = "rdi";
    want.cursor = "r12";
    want.table = "rsi";
    want.engine = "rbp";
    check(pr.convention == want, "the permuted roles are inferred");
}

void test_infer_refuses_guess() {
    // Both small-stepping registers move by +8 every dispatch: no
    // alignment or magnitude margin separates stack from cursor. The
    // inference must refuse rather than pick.
    std::vector<lift::Row> amb;
    amb.push_back(row(1, 0x2000, 0x3000, 0x4000, 0x7000, 0x5000, 0, 0, 0));
    amb.push_back(row(2, 0x2008, 0x3008, 0x4000, 0x7000, 0x5000, 0, 0, 0));
    amb.push_back(row(3, 0x2010, 0x3010, 0x4000, 0x7000, 0x5000, 0, 0, 0));
    amb.push_back(row(4, 0x2018, 0x3018, 0x4000, 0x7000, 0x6000, 0, 0, 0));
    const adapt::InferResult ar = adapt::infer_convention(amb);
    check(!ar.confident, "indistinguishable movers are refused, not guessed");
    check(ar.convention == lift::kDefaultConvention,
          "a refused inference returns the default convention");
}

// ------------------------------------------------- lift under a convention

void test_lift_permuted_convention() {
    lift::Convention conv;
    conv.stack = "rdi";
    conv.cursor = "r12";
    conv.table = "rsi";
    conv.engine = "rbp";

    // The add handler written against rdi: slot reads, slot write at +8,
    // stack pointer advanced on rdi, cursor untouched.
    lift::Model m;
    m.convention = conv;
    const lift::Handler h =
        lift::summarize(m, kAddRdi.data(), kAddRdi.size(), kHandlerVa,
                        kHandlerVa);
    check(h.modeled, "the permuted add handler is modeled");
    check(h.transfer == lift::Handler::Transfer::Dispatch,
          "the permuted add handler ends in a dispatch");
    check(h.writes.size() == 1 && h.writes[0].to_slot &&
              h.writes[0].disp == 8,
          "the write is classified as a slot write at +8");
    const std::string wval = lift::render(m, h.writes[0].value);
    check(wval.find("vst[+0]") != std::string::npos &&
              wval.find("vst[+8]") != std::string::npos,
          "the write value sums slots 0 and 8");
    check(lift::render(m, h.rbp_new) == "(rdi + 0x8)",
          "the stack pointer role advances on rdi");
    check(lift::render(m, h.rsi_new) == "r12",
          "the cursor role is named r12 and does not move");

    // The byte handler written against r12: a byte read classified as
    // code, cursor advanced on r12, store to slot +0.
    lift::Model m2;
    m2.convention = conv;
    const lift::Handler hb =
        lift::summarize(m2, kByteR12.data(), kByteR12.size(), kHandlerVa,
                        kHandlerVa);
    check(hb.modeled, "the permuted byte handler is modeled");
    check(hb.writes.size() == 1 && hb.writes[0].to_slot &&
              hb.writes[0].disp == 0,
          "the byte store goes to slot +0");
    const std::string bval = lift::render(m2, hb.writes[0].value);
    check(bval.find("code[+0]") != std::string::npos,
          "the byte read is classified as bytecode");
    const std::string rsi_txt = lift::render(m2, hb.rsi_new);
    check(rsi_txt.find("r12") != std::string::npos &&
              rsi_txt.find("0x1") != std::string::npos,
          "the cursor role advances on r12");

    // A trace built around the permuted stack register (rdi) conforms to
    // the model: the cells are around rdi, the cursor is in r12.
    std::vector<lift::Row> rows;
    rows.push_back(row(1, 0x5000, 0x4000, 0x3000, 0x7000, 0x2000, 5, 7, 9));
    rows.push_back(row(2, 0x5000, 0x4000, 0x3008, 0x7000, 0x2000, 12, 9, 0));
    const std::vector<std::size_t> which = {0, 0};
    const lift::Conformance c =
        lift::check_trace(m, {h}, rows, which, nullptr, nullptr);
    check(c.mismatched == 0, "the permuted-convention trace conforms");
    check(c.checked >= 3, "the cells and pointers are checked");
}

// ------------------------------------------------------- the static lift

void test_lift_static_chain() {
    // Two decrypt handlers at 0x1100 and 0x1200. The bytecode stream at
    // 0x2000 holds encrypted words: word 0 decrypts to 0x1200, word 1
    // (read by the second handler, whose entry cursor is 0x2008)
    // decrypts back to 0x1100. The fixpoint must close the loop.
    TestImage img(0x1100);  // 0x1000 .. 0x20FF
    img.put(0x1100, kDecrypt);
    img.put(0x1200, kDecrypt);
    img.put_u64(0x2000, ror64(0x1200ULL, 10));
    img.put_u64(0x2008, ror64(0x1100ULL, 10));

    adapt::StaticOptions opts;
    opts.cursor_known = true;
    opts.entry_cursor = 0x2000;
    const adapt::StaticLift r =
        adapt::lift_static(img.bytes.data(), img.bytes.size(), 0x1000, 0x1100,
                           lift::kDefaultConvention, opts);
    check(r.complete, "the static fixpoint converged");
    check(r.nodes.size() == 2, "two reachable handlers");
    check(r.handlers.size() == 2, "two models, index-aligned");
    check(r.nodes[0].va == 0x1100 && !r.nodes[0].indirect &&
              r.nodes[0].successors.size() == 1 &&
              r.nodes[0].successors[0] == 0x1200,
          "the entry handler decrypts to the next handler");
    check(r.nodes[1].va == 0x1200 && !r.nodes[1].indirect &&
              r.nodes[1].successors.size() == 1 &&
              r.nodes[1].successors[0] == 0x1100,
          "the second handler decrypts back to the first");
    check(r.iterations == 2, "exactly two handlers were lifted");
}

void test_lift_static_unresolved() {
    // Without a known entry cursor the decrypt expression cannot be
    // bound: the entry node is honestly indirect and the lift is
    // incomplete.
    TestImage img(0x1100);
    img.put(0x1100, kDecrypt);
    img.put(0x1200, kDecrypt);
    img.put_u64(0x2000, ror64(0x1200ULL, 10));
    img.put_u64(0x2008, ror64(0x1100ULL, 10));

    adapt::StaticOptions opts;  // cursor_known = false
    const adapt::StaticLift r =
        adapt::lift_static(img.bytes.data(), img.bytes.size(), 0x1000, 0x1100,
                           {}, opts);
    check(!r.complete, "an unknown cursor makes the lift incomplete");
    check(r.nodes.size() == 1 && r.nodes[0].indirect &&
              r.nodes[0].successors.empty(),
          "the entry node is indirect with no edges");

    // A host-register dispatch (jmp rcx) is unresolvable even with a
    // known cursor: the target depends on a register the image cannot
    // supply, and that is reported, not guessed.
    TestImage img2(0x1100);
    img2.put(0x1100, {0xFF, 0xE1});
    adapt::StaticOptions opts2;
    opts2.cursor_known = true;
    opts2.entry_cursor = 0x2000;
    const adapt::StaticLift r2 =
        adapt::lift_static(img2.bytes.data(), img2.bytes.size(), 0x1000,
                           0x1100, {}, opts2);
    check(!r2.complete && r2.nodes.size() == 1 && r2.nodes[0].indirect,
          "a host-register dispatch is honestly indirect");
}

void test_lift_static_budget() {
    // A budget of one handler on the two-handler loop: the second
    // handler is discovered but never lifted, and the walk stops
    // incomplete.
    TestImage img(0x1100);
    img.put(0x1100, kDecrypt);
    img.put(0x1200, kDecrypt);
    img.put_u64(0x2000, ror64(0x1200ULL, 10));
    img.put_u64(0x2008, ror64(0x1100ULL, 10));

    adapt::StaticOptions opts;
    opts.cursor_known = true;
    opts.entry_cursor = 0x2000;
    opts.max_handlers = 1;
    const adapt::StaticLift r =
        adapt::lift_static(img.bytes.data(), img.bytes.size(), 0x1000, 0x1100,
                           {}, opts);
    check(!r.complete, "the handler budget stops the walk");
    check(r.nodes.size() == 2, "the second handler was discovered");
    check(r.handlers[1].va == 0, "the second handler was never lifted");
    check(r.iterations == 1, "exactly one handler was lifted");
}

}  // namespace

int main() {
    test_infer_default();
    test_infer_permuted();
    test_infer_refuses_guess();
    test_lift_permuted_convention();
    test_lift_static_chain();
    test_lift_static_unresolved();
    test_lift_static_budget();
    std::fprintf(stdout, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

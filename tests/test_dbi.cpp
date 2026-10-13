// Dynamic instrumentation tests.
//
// Four levels, weakest first. The decoder is asked instructions whose
// encodings are known by construction and its lengths and branch classes
// must match. The splitter is asked straight-line and branching code and
// the block boundaries must land where a human would put them. The
// rewriter is asked code with every relocation shape -- a fallthrough, a
// short jump that grows to a near jump, a RIP-relative operand, a call
// out of the region -- and its output is decoded again to check the
// relocations. Finally the instrumented copy is executed for real: the
// test mmaps an executable page, copies the rewrite in, calls its entry,
// and checks both the effect of the guest code and the sequence of
// blocks the probe saw. A rewriter whose output crashes or records the
// wrong blocks fails here even if its bytes look plausible.

#include "occ/dbi/dbi.h"

#include <sys/mman.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

using namespace occ::dbi;

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

// The lengths and branch classes of a hand-encoded instruction.
struct Expect {
    const char* what;
    std::vector<std::uint8_t> bytes;
    std::uint32_t len;
    BranchKind branch;
    bool rip;
};

void test_decoder() {
    const Expect kCases[] = {
        {"nop", {0x90}, 1, BranchKind::None, false},
        {"push rax", {0x50}, 1, BranchKind::None, false},
        {"pop r11", {0x41, 0x5B}, 2, BranchKind::None, false},
        {"mov rbp, rsp", {0x48, 0x89, 0xE5}, 3, BranchKind::None, false},
        {"add rsp, 0x20", {0x48, 0x83, 0xC4, 0x20}, 4, BranchKind::None, false},
        {"mov eax, 0x12345678", {0xB8, 0x78, 0x56, 0x34, 0x12}, 5,
         BranchKind::None, false},
        {"movabs rax, imm64", {0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0}, 10,
         BranchKind::None, false},
        {"jmp rel8", {0xEB, 0xF9}, 2, BranchKind::Rel8, false},
        {"je rel8", {0x74, 0x02}, 2, BranchKind::Rel8, false},
        {"jne rel32", {0x0F, 0x85, 0, 0, 0, 0}, 6, BranchKind::Rel32, false},
        {"call rel32", {0xE8, 0, 0, 0, 0}, 5, BranchKind::Rel32, false},
        {"jmp rel32", {0xE9, 0, 0, 0, 0}, 5, BranchKind::Rel32, false},
        {"ret", {0xC3}, 1, BranchKind::Ret, false},
        {"call rax", {0xFF, 0xD0}, 2, BranchKind::Indirect, false},
        {"jmp rax", {0xFF, 0xE0}, 2, BranchKind::Indirect, false},
        {"mov rax, [rip]", {0x48, 0x8B, 0x05, 0, 0, 0, 0}, 7, BranchKind::None,
         true},
        {"lea rax, [rip]", {0x48, 0x8D, 0x05, 0, 0, 0, 0}, 7,
         BranchKind::None, true},
        {"mov byte [rip], 1", {0xC6, 0x05, 0, 0, 0, 0, 0x01}, 7,
         BranchKind::None, true},
        {"mov rax, fs:[0]", {0x64, 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0}, 9,
         BranchKind::None, false},
        {"add eax, 1", {0x81, 0xC0, 0x01, 0, 0, 0}, 6, BranchKind::None, false},
        {"add ax, 1", {0x66, 0x81, 0xC0, 0x01, 0}, 5, BranchKind::None, false},
        {"popcnt rax, rax", {0xF2, 0x0F, 0xB8, 0xC0}, 4, BranchKind::None,
         false},
        {"bswap eax", {0x0F, 0xC8}, 2, BranchKind::None, false},
        {"xadd [r12], rax", {0x49, 0x0F, 0xC1, 0x04, 0x24}, 5,
         BranchKind::None, false},
        {"setz al", {0x0F, 0x94, 0xC0}, 3, BranchKind::None, false},
        {"movzx eax, byte [rax]", {0x0F, 0xB6, 0x00}, 3, BranchKind::None,
         false},
        {"syscall", {0x0F, 0x05}, 2, BranchKind::None, false},
    };
    for (const Expect& e : kCases) {
        DecodedInsn d;
        const bool ok = decode_insn(e.bytes.data(), e.bytes.size(), d);
        check(ok && d.len == e.len, e.what);
        if (ok) {
            check(d.branch == e.branch, e.what);
            check(d.rip_relative == e.rip, e.what);
        }
    }
    // The displacement of a rel8 must be signed and correct.
    DecodedInsn d;
    const std::uint8_t jmp[] = {0xEB, 0xF9};
    check(decode_insn(jmp, 2, d) && d.disp == -7, "jmp rel8 displacement");
    const std::uint8_t jcc[] = {0x74, 0x02};
    check(decode_insn(jcc, 2, d) && d.disp == 2, "jcc rel8 displacement");
    // A truncated instruction must refuse rather than guess.
    const std::uint8_t cut[] = {0x48, 0x8B};
    check(!decode_insn(cut, 2, d), "truncated instruction refused");
    // A vector-space opcode the table does not carry must refuse.
    const std::uint8_t sse[] = {0x0F, 0x28, 0xC0};
    check(!decode_insn(sse, 3, d), "vector instruction refused");
}

void test_split() {
    // mov eax, 1; jz +5 (skip to the ret); mov eax, 2; ret. The
    // conditional jump does not terminate its block, so the first three
    // instructions form one block; the jump's target (the ret) is the
    // second.
    const std::uint8_t code[] = {0xB8, 0x01, 0, 0, 0, 0x74, 0x05,
                                 0xB8, 0x02, 0, 0, 0, 0xC3};
    std::vector<Block> blocks;
    check(split_blocks(code, sizeof(code), 0x10000, blocks),
          "split branching code");
    check(blocks.size() == 2, "two blocks");
    if (blocks.size() == 2) {
        check(blocks[0].offset == 0 && blocks[0].size == 12, "block0 bounds");
        check(blocks[1].offset == 12 && blocks[1].size == 1, "block1 bounds");
        check(blocks[0].entry, "entry block");
        check(!blocks[0].ends_transfer, "jcc falls through");
        check(blocks[0].targets.size() == 1 && blocks[0].targets[0] == 12,
              "jcc target recorded");
        check(blocks[1].ends_transfer, "ret terminates");
    }
    // An unconditional jump terminates its block; the byte after it is a
    // fresh block even when the jump self-loops.
    const std::uint8_t jmp[] = {0xEB, 0xFE, 0x90};
    std::vector<Block> b2;
    check(split_blocks(jmp, sizeof(jmp), 0x10000, b2), "split jump code");
    check(b2.size() == 2, "jump block and fallthrough block");
    check(b2[0].ends_transfer, "jump terminates");
    // A region that contains an undecodable instruction refuses whole.
    const std::uint8_t bad[] = {0x90, 0x0F, 0x28, 0xC0};
    std::vector<Block> b3;
    check(!split_blocks(bad, sizeof(bad), 0x10000, b3),
          "undecodable region refused");
}

void test_rewrite() {
    // mov eax, 1; jmp +0 (to the ret); ret. The jump is rel8 and must
    // grow to rel32; the ret must survive. The first two instructions
    // form one block (no branch between them) and the ret is the second.
    const std::uint8_t code[] = {0xB8, 0x01, 0, 0, 0, 0xEB, 0x00, 0xC3};
    std::vector<Block> blocks;
    check(split_blocks(code, sizeof(code), 0x10000, blocks), "split");
    check(blocks.size() == 2, "two blocks");
    Instrumented ins;
    const char* why = nullptr;
    check(instrument(code, sizeof(code), 0x10000, blocks, ins, &why),
          "instrument basic code");
    if (why) {
        std::fprintf(stderr, "  why: %s\n", why);
    }
    check(ins.blocks.size() == 2, "two rewritten blocks");
    check(ins.block_count == 2, "block count");
    // The first block's stub calls the probe with block id 1; the entry
    // must be the start of the first block's stub.
    check(ins.entry == ins.blocks[0].new_offset, "entry is first block");
    // The first block's jump (after its stub and the five-byte mov) must
    // now be E9 rel32 and land on the second block's stub.
    if (ins.blocks.size() == 2) {
        const std::size_t jmp_pos =
            static_cast<std::size_t>(ins.blocks[0].new_offset) + kStubLen + 5;
        check(ins.code[jmp_pos] == 0xE9, "short jump grew to near jump");
        std::int32_t disp = 0;
        std::memcpy(&disp, ins.code.data() + jmp_pos + 1, 4);
        const std::int64_t target =
            static_cast<std::int64_t>(jmp_pos + 5) + disp;
        check(target == ins.blocks[1].new_offset, "jump retargeted to copy");
    }
    // A RIP-relative operand must be relocated to the same absolute
    // target. mov rax, [rip + 4] at base 0x10000: next instruction at
    // 0x10007, so the operand names 0x1000B. The trailing ret makes the
    // block end; both stay in one block.
    const std::uint8_t rip[] = {0x48, 0x8B, 0x05, 0x04, 0, 0, 0, 0xC3};
    std::vector<Block> rb;
    check(split_blocks(rip, sizeof(rip), 0x10000, rb), "split rip code");
    Instrumented ri;
    check(instrument(rip, sizeof(rip), 0x10000, rb, ri, &why),
          "instrument rip code");
    if (!ri.blocks.empty()) {
        const std::size_t mov_pos =
            static_cast<std::size_t>(ri.blocks[0].new_offset) + kStubLen;
        std::int32_t disp = 0;
        std::memcpy(&disp, ri.code.data() + mov_pos + 3, 4);
        // New next instruction is mov_pos + 7; the operand must still
        // name 0x1000B.
        const std::int64_t target =
            static_cast<std::int64_t>(mov_pos + 7) + disp;
        check(target == 0x1000B, "rip operand relocated to original target");
    }
    // A call out of the region must become movabs r11, target; call r11.
    // call rel32 = 0 at base 0x10000 calls 0x10005, beyond a 4-byte
    // region.
    const std::uint8_t out[] = {0xE8, 0, 0, 0, 0};
    std::vector<Block> ob;
    check(split_blocks(out, sizeof(out), 0x10000, ob), "split out call");
    Instrumented oi;
    check(instrument(out, sizeof(out), 0x10000, ob, oi, &why),
          "instrument out call");
    if (!oi.blocks.empty()) {
        const std::size_t call_pos =
            static_cast<std::size_t>(oi.blocks[0].new_offset) + kStubLen;
        check(oi.code[call_pos] == 0x49 && oi.code[call_pos + 1] == 0xBB,
              "out-of-region call made absolute");
        std::uint64_t target = 0;
        std::memcpy(&target, oi.code.data() + call_pos + 2, 8);
        check(target == 0x10005, "out-of-region call target preserved");
    }
    // The rewriter refuses a control transfer whose target is not a block
    // start. A hand-built block list that covers the jump but omits its
    // target triggers the refusal.
    const std::uint8_t mid[] = {0xB8, 0x01, 0, 0, 0, 0xEB, 0xFC, 0xC3};
    Block mb0;
    mb0.offset = 0;
    mb0.size = 7; // The mov and the jump, but not the ret it targets.
    mb0.entry = true;
    std::vector<Block> mb = {mb0};
    Instrumented mi;
    check(!instrument(mid, sizeof(mid), 0x10000, mb, mi, &why),
          "unlisted jump target refused");
    check(why != nullptr, "refusal names a reason");
}

// The probe used by the execution test: appends the block id it saw.
std::vector<std::uint32_t> g_probe_seen;
void test_probe(std::uint32_t block_id) noexcept { g_probe_seen.push_back(block_id); }

void test_execute() {
    // mov eax, 1; jmp +0; ret -- two blocks, executed for real.
    const std::uint8_t code[] = {0xB8, 0x01, 0, 0, 0, 0xEB, 0x00, 0xC3};
    std::vector<Block> blocks;
    check(split_blocks(code, sizeof(code), 0x10000, blocks), "split exec");
    g_probe_seen.clear();
    Instrumented ins;
    const char* why = nullptr;
    check(instrument(code, sizeof(code), 0x10000, blocks, ins, &why,
                     &test_probe),
          "instrument exec code");
    if (!ins.code.empty()) {
        const std::size_t page = static_cast<std::size_t>(getpagesize());
        const std::size_t n = (ins.code.size() + page - 1) & ~(page - 1);
        void* mem = mmap(nullptr, n, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        check(mem != MAP_FAILED, "mmap executable");
        if (mem != MAP_FAILED) {
            std::memcpy(mem, ins.code.data(), ins.code.size());
            auto fn = reinterpret_cast<void (*)()>(
                reinterpret_cast<std::uintptr_t>(mem) + ins.entry);
            fn(); // Enters the copy, runs the stub chain, returns via ret.
            munmap(mem, n);
            check(g_probe_seen.size() == 2, "probe saw two blocks");
            if (g_probe_seen.size() == 2) {
                check(g_probe_seen[0] == 1 && g_probe_seen[1] == 2,
                      "probe sequence follows control flow");
            }
        }
    }
    // The default probe records into the global map: the same code, with
    // the global coverage reset, must move the counters.
    std::memset(&global_coverage, 0, sizeof(global_coverage));
    Instrumented ins2;
    check(instrument(code, sizeof(code), 0x10000, blocks, ins2, &why),
          "instrument default probe");
    if (!ins2.code.empty()) {
        const std::size_t page = static_cast<std::size_t>(getpagesize());
        const std::size_t n = (ins2.code.size() + page - 1) & ~(page - 1);
        void* mem = mmap(nullptr, n, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem != MAP_FAILED) {
            std::memcpy(mem, ins2.code.data(), ins2.code.size());
            auto fn = reinterpret_cast<void (*)()>(
                reinterpret_cast<std::uintptr_t>(mem) + ins2.entry);
            fn();
            munmap(mem, n);
            check(global_coverage.hits == 2, "global probe counted hits");
            check(global_coverage.edges == 2, "global probe counted edges");
        }
    }
}

void test_coverage_hash() {
    // The slot is deterministic and respects direction: (1,2) and (2,1)
    // are different edges.
    check(Coverage::slot(1, 2) != Coverage::slot(2, 1),
          "directional edge hash");
    check(Coverage::slot(7, 9) == Coverage::slot(7, 9), "deterministic hash");
    check(Coverage::slot(1, 2) < kMapBytes, "slot in range");
}

} // namespace

int main() {
    const auto run = [](const char* name, void (*fn)()) {
        std::printf("-- %s\n", name);
        std::fflush(stdout);
        fn();
    };
    run("decoder", test_decoder);
    run("split", test_split);
    run("rewrite", test_rewrite);
    run("execute", test_execute);
    run("coverage_hash", test_coverage_hash);
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

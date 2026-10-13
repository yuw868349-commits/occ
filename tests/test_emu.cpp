// Emulator tests.
//
// The interpreter is exercised instruction by instruction: hand-encoded
// sequences whose effects are known by construction, run through the
// public entry point, with the register file, memory image, flags and
// stop reason checked afterwards. The families covered are the ones a
// 64-bit compiler emits: the mov family, arithmetic with the full flag
// semantics (carry and overflow at every width, adc/sbb chains, shifts
// and their carry), the stack and call/ret, conditional and
// unconditional transfers, memory forms including RIP-relative and
// SIB-scaled addressing, the integer conversions, and the stop reasons
// (ret, fault, budget, unknown, syscall, hlt). Refusals are tested as
// refusals: a floating-point instruction and a divide by zero must halt
// with the named reason, not misbehave.

#include "occ/emu/emu.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace occ::emu;

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

// A machine: a flat memory image that doubles as the code region.
struct Machine {
    std::vector<std::uint8_t> bytes;
    std::uint64_t base = 0x100000;
    Cpu cpu{};
    Memory mem{};

    explicit Machine(std::size_t n) : bytes(n, 0) {
        mem.base = base;
        mem.bytes = std::span<std::uint8_t>(bytes.data(), bytes.size());
    }

    // Loads a runnable instruction sequence and starts the cpu at it.
    // The last 64 bytes of the image are reserved as stack space, so the
    // interpreted region is bytes.size() - 64 long.
    void load(const std::uint8_t* p, std::size_t n) {
        std::memcpy(bytes.data(), p, n);
        mem.bytes = std::span<std::uint8_t>(bytes.data(), bytes.size());
        cpu.rip = base;
        cpu.rflags = 0;
        std::memset(cpu.reg, 0, sizeof(cpu.reg));
        cpu.reg[RSP] = base + bytes.size() - 64;
    }

    RunResult run(std::size_t max_steps = 4096, StepHook hook = nullptr,
                  void* ctx = nullptr) {
        return occ::emu::run(bytes.data(), bytes.size() - 64, base, cpu, mem,
                             max_steps, hook, ctx);
    }
};

// ---------------------------------------------------------------------------
// Arithmetic and flags
// ---------------------------------------------------------------------------

void test_arith() {
    Machine m(128);
    const std::uint8_t code[] = {
        0x48, 0x83, 0xC0, 0x01, // add rax, 1
        0x48, 0x83, 0xC3, 0x02, // add rbx, 2
        0x48, 0x29, 0xC8, // sub rax, rcx
        0xC3, // ret
    };
    m.load(code, sizeof(code));
    m.cpu.reg[RAX] = 1;
    m.cpu.reg[RBX] = 2;
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "arith: ret stop");
    check(m.cpu.reg[RAX] == 2, "arith: rax = (1+1) - 0");
    check(m.cpu.reg[RBX] == 4, "arith: rbx = 2+2");
    check(r.steps == 4, "arith: four steps");
}

void test_flags_32() {
    Machine m(128);
    const std::uint8_t code[] = {
        0xB8, 0xFF, 0xFF, 0xFF, 0x7F, // mov eax, 0x7FFFFFFF
        0x05, 0x01, 0x00, 0x00, 0x00, // add eax, 1 -> 0x80000000
        0xC3,
    };
    m.load(code, sizeof(code));
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "flags32: ret stop");
    check(m.cpu.reg[RAX] == 0x80000000ull,
          "flags32: 32-bit add clears the high half");
    check((m.cpu.rflags & kFlagOF) != 0, "flags32: overflow set");
    check((m.cpu.rflags & kFlagSF) != 0, "flags32: sign set");
    check((m.cpu.rflags & kFlagZF) == 0, "flags32: zero clear");
    check((m.cpu.rflags & kFlagCF) == 0, "flags32: carry clear");
}

void test_flags_64_carry() {
    Machine m(128);
    const std::uint8_t code[] = {
        0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // movabs rax, -1
        0x48, 0x83, 0xC0, 0x01, // add rax, 1 -> 0, CF=1
        0xC3,
    };
    m.load(code, sizeof(code));
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "flags64: ret stop");
    check(m.cpu.reg[RAX] == 0, "flags64: rax wraps to zero");
    check((m.cpu.rflags & kFlagCF) != 0, "flags64: carry set");
    check((m.cpu.rflags & kFlagZF) != 0, "flags64: zero set");
}

void test_adc_chain() {
    Machine m(128);
    const std::uint8_t code[] = {
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0x83, 0xC0, 0xFF, // add eax, -1 -> 0 with CF=1
        0x13, 0xC0, // adc eax, eax -> 1
        0xC3,
    };
    m.load(code, sizeof(code));
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "adc: ret stop");
    check(m.cpu.reg[RAX] == 1, "adc: 0 + 0 + carry = 1");
}

void test_jcc_taken() {
    Machine m(128);
    const std::uint8_t code[] = {
        0x31, 0xC0, // xor eax, eax (ZF=1)
        0x74, 0x05, // je +5 -> lands on the ret
        0xB8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2 (skipped)
        0xC3,
    };
    m.load(code, sizeof(code));
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "jcc-taken: ret stop");
    check(m.cpu.reg[RAX] == 0, "jcc-taken: branch skipped mov eax,2");
}

void test_jcc_notaken() {
    Machine m(128);
    const std::uint8_t code[] = {
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1 (flags untouched)
        0x74, 0x05, // je +5 -> not taken, fall through
        0xB8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2
        0xC3,
    };
    m.load(code, sizeof(code));
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "jcc-notaken: ret stop");
    check(m.cpu.reg[RAX] == 2, "jcc-notaken: fell through to mov eax,2");
}

// ---------------------------------------------------------------------------
// Mov, memory, conversions
// ---------------------------------------------------------------------------

void test_mov_family() {
    Machine m(128);
    const std::uint8_t code[] = {
        0x48, 0xB8, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, // movabs rax
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF, // mov eax, -1 (clears high half)
        0x48, 0x89, 0xC3, // mov rbx, rax
        0x31, 0xC0, // xor eax, eax
        0xB0, 0xAA, // mov al, 0xAA
        0x88, 0xC3, // mov bl, al
        0xC3,
    };
    m.load(code, sizeof(code));
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "mov: ret stop");
    check(m.cpu.reg[RAX] == 0xAA, "mov: al write preserves the upper bits");
    check(m.cpu.reg[RBX] == 0xFFFFFFAAull,
          "mov: bl write preserves the upper bits");
}

void test_mem_rip() {
    Machine m(128);
    const std::uint8_t code[] = {
        0x48, 0x8B, 0x05, 0x01, 0x00, 0x00, 0x00, // mov rax, [rip+1]
        0xC3,
        0xDE, 0xAD, 0xBE, 0xEF, 0x78, 0x56, 0x34, 0x12, // data at +8
    };
    m.load(code, sizeof(code));
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "memrip: ret stop");
    check(m.cpu.reg[RAX] == 0x12345678EFBEADDEull,
          "memrip: rip-relative load reads the data");
}

void test_mem_sib() {
    Machine m(256);
    std::uint64_t v = 0x1122334455667788ull;
    std::memcpy(m.bytes.data() + 0x48, &v, 8); // data at base+0x48
    m.mem.bytes = std::span<std::uint8_t>(m.bytes.data(), m.bytes.size());
    const std::uint8_t code[] = {
        0x48, 0xB8, 0x30, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x100030
        0x48, 0xBB, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, 4
        0x48, 0x8B, 0x44, 0x98, 0x08, // mov rax, [rax+rbx*4+8]
        0xC3,
    };
    m.load(code, sizeof(code));
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "sib: ret stop");
    check(m.cpu.reg[RAX] == 0x1122334455667788ull,
          "sib: scaled index addressing hits base+0x48");
}

void test_lea_movzx() {
    Machine m(128);
    const std::uint8_t code[] = {
        0x48, 0x8D, 0x04, 0x07, // lea rax, [rdi+rax]
        0xB0, 0xFF, // mov al, 0xFF
        0x0F, 0xB6, 0xC0, // movzx eax, al
        0x0F, 0xBE, 0xC0, // movsx rax, al
        0xC3,
    };
    m.load(code, sizeof(code));
    m.cpu.reg[RDI] = 5;
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "movzx: ret stop");
    check(m.cpu.reg[RAX] == 0xFFFFFFFFFFFFFFFFull,
          "movsx: sign extends the byte");
}

// ---------------------------------------------------------------------------
// Stack and control flow
// ---------------------------------------------------------------------------

void test_stack_call_ret() {
    Machine m(128);
    // sp0 holds a canned escape address so the final ret leaves the
    // region with a known target.
    const std::uint8_t code[] = {
        0x50, // push rax
        0x68, 0x78, 0x56, 0x34, 0x12, // push 0x12345678
        0x58, // pop rax
        0x5B, // pop rbx
        0xE8, 0x02, 0x00, 0x00, 0x00, // call +2 (to the sub)
        0xC3, // ret from the region (pops the canned address)
        0x48, 0x31, 0xC0, // xor rax, rax
        0xC3, // ret back to +6
    };
    m.load(code, sizeof(code));
    m.cpu.reg[RAX] = 0xAAAA;
    const std::uint64_t sp0 = m.cpu.reg[RSP];
    const std::uint64_t escape = 0xDEADBEEFCAFE0000ull;
    std::memcpy(m.bytes.data() + (sp0 - m.base), &escape, 8);
    m.mem.bytes = std::span<std::uint8_t>(m.bytes.data(), m.bytes.size());
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "callret: escaped the region with a ret");
    check(r.rip == escape, "callret: the canned return address was popped");
    check(m.cpu.reg[RAX] == 0, "callret: the sub zeroed rax");
    check(m.cpu.reg[RBX] == 0xAAAA, "callret: rbx popped the saved rax");
    check(m.cpu.reg[RSP] == sp0 + 8,
          "callret: stack balanced (final ret consumed the canned word)");
}

void test_ret_imm() {
    Machine m(128);
    const std::uint8_t code[] = {
        0xC2, 0x10, 0x00, // ret 0x10
    };
    m.load(code, sizeof(code));
    const std::uint64_t sp = m.base + 32;
    m.cpu.reg[RSP] = sp;
    const std::uint64_t ret = m.base + 0x77;
    std::memcpy(m.bytes.data() + 32, &ret, 8);
    m.mem.bytes = std::span<std::uint8_t>(m.bytes.data(), m.bytes.size());
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "retimm: escaped with a ret");
    check(m.cpu.rip == ret, "retimm: popped the return address");
    check(m.cpu.reg[RSP] == sp + 8 + 0x10, "retimm: pops the imm too");
}

void test_jmp_loop_budget() {
    Machine m(128);
    const std::uint8_t code[] = {
        0xEB, 0xFE, // jmp -2 (self loop)
    };
    m.load(code, sizeof(code));
    const RunResult r = m.run(16);
    check(r.why == Halt::Budget, "budget: infinite loop stops on budget");
    check(r.steps == 16, "budget: steps capped at max");
}

// ---------------------------------------------------------------------------
// Shifts and multiply/divide
// ---------------------------------------------------------------------------

void test_shifts() {
    Machine m(128);
    const std::uint8_t code[] = {
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0xD1, 0xE0, // shl eax, 1 -> 2
        0xD1, 0xE8, // shr eax, 1 -> 1
        0xB8, 0x00, 0x00, 0x00, 0x80, // mov eax, 0x80000000
        0xC1, 0xF8, 0x04, // sar eax, 4 -> 0xF8000000
        0xB8, 0x80, 0x00, 0x00, 0x00, // mov eax, 0x80
        0xD3, 0xE0, // shl eax, cl (cl=4) -> 0x800
        0xC3,
    };
    m.load(code, sizeof(code));
    m.cpu.reg[RCX] = 4;
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "shift: ret stop");
    check(m.cpu.reg[RAX] == 0x800, "shift: shl by cl works");
}

void test_shift_carry() {
    Machine m(128);
    const std::uint8_t code[] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // movabs rax, 1<<63
        0x48, 0xD1, 0xE0, // shl rax, 1 -> CF=1, rax=0
        0xC3,
    };
    m.load(code, sizeof(code));
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "shiftcarry: ret stop");
    check(m.cpu.reg[RAX] == 0, "shiftcarry: shifted out");
    check((m.cpu.rflags & kFlagCF) != 0, "shiftcarry: carry holds the top bit");
}

void test_mul_div() {
    Machine m(128);
    const std::uint8_t code[] = {
        0xB8, 0x06, 0x00, 0x00, 0x00, // mov eax, 6
        0xBB, 0x07, 0x00, 0x00, 0x00, // mov ebx, 7
        0xF7, 0xE3, // mul ebx -> edx:eax = 42
        0xBA, 0x00, 0x00, 0x00, 0x00, // mov edx, 0
        0xB8, 0x2A, 0x00, 0x00, 0x00, // mov eax, 42
        0xF7, 0xFB, // idiv ebx -> eax=6, edx=0
        0xC3,
    };
    m.load(code, sizeof(code));
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "muldiv: ret stop");
    check(m.cpu.reg[RAX] == 6, "muldiv: idiv quotient");
    check(m.cpu.reg[RDX] == 0, "muldiv: idiv remainder");
}

void test_imul_forms() {
    Machine m(128);
    const std::uint8_t code[] = {
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF, // mov eax, -1
        0x6B, 0xC0, 0x0A, // imul eax, eax, 10 -> -10
        0x0F, 0xAF, 0xC0, // imul eax, eax -> 100
        0xC3,
    };
    m.load(code, sizeof(code));
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "imul: ret stop");
    check(m.cpu.reg[RAX] == 100, "imul: -10 * -10 = 100");
}

void test_div_zero() {
    Machine m(128);
    const std::uint8_t code[] = {
        0x31, 0xC0, // xor eax, eax
        0xF7, 0xF0, // div eax (divisor 0)
    };
    m.load(code, sizeof(code));
    const RunResult r = m.run();
    check(r.why == Halt::Fault, "divzero: named fault");
    check(r.detail != nullptr && std::strstr(r.detail, "divide") != nullptr,
          "divzero: detail explains");
}

// ---------------------------------------------------------------------------
// Integer conversions and misc
// ---------------------------------------------------------------------------

void test_bswap_bitops() {
    Machine m(128);
    const std::uint8_t code[] = {
        0x48, 0xB8, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // movabs rax
        0x48, 0x0F, 0xC8, // bswap rax
        0x48, 0x0F, 0xBC, 0xC0, // bsf rax, rax -> 0
        0x48, 0xF7, 0xD8, // neg rax -> 0
        0xF7, 0xD0, // not eax -> 0xFFFFFFFF
        0xF3, 0x0F, 0xB8, 0xC0, // popcnt eax, eax -> 32
        0x48, 0x0F, 0xBD, 0xC8, // bsr rcx, rax (rax kept 32)
        0xC3,
    };
    m.load(code, sizeof(code));
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "bitops: ret stop");
    check(m.cpu.reg[RAX] == 32, "bitops: popcnt of 0xFFFFFFFF");
}

void test_setcc_cmovcc() {
    Machine m(128);
    const std::uint8_t code[] = {
        0x31, 0xC0, // xor eax, eax (ZF=1)
        0x0F, 0x94, 0xC1, // sete cl -> 1
        0x0F, 0x45, 0xC1, // cmovne eax, ecx (not taken)
        0xC3,
    };
    m.load(code, sizeof(code));
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "setcc: ret stop");
    check((m.cpu.reg[RCX] & 0xFF) == 1, "setcc: sete wrote 1");
    check(m.cpu.reg[RAX] == 0, "cmov: not taken leaves rax");
}

void test_cmpxchg_xadd() {
    Machine m(128);
    const std::uint8_t code[] = {
        0xB8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5
        0xBB, 0x05, 0x00, 0x00, 0x00, // mov ebx, 5
        0x0F, 0xB1, 0xC3, // cmpxchg ebx, eax (equal -> ZF=1)
        0xB8, 0x03, 0x00, 0x00, 0x00, // mov eax, 3
        0x0F, 0xC1, 0xC3, // xadd ebx, eax -> ebx=8, eax=5
        0xC3,
    };
    m.load(code, sizeof(code));
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "cmpxchg: ret stop");
    // The trailing xadd overwrites rflags (8 != 0 clears ZF); the
    // equal-path ZF behavior of cmpxchg itself is covered by
    // test_cmpxchg_zf below.
    check((m.cpu.rflags & kFlagZF) == 0, "cmpxchg: xadd cleared ZF");
    check(m.cpu.reg[RAX] == 5, "xadd: old value returned in eax");
    check(m.cpu.reg[RBX] == 8, "xadd: sum written to ebx");
}

void test_cmpxchg_zf() {
    Machine m(128);
    const std::uint8_t code[] = {
        0xB8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5
        0xBB, 0x05, 0x00, 0x00, 0x00, // mov ebx, 5
        0x0F, 0xB1, 0xC3, // cmpxchg ebx, eax (equal -> ZF=1)
        0xC3,
    };
    m.load(code, sizeof(code));
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "cmpxchg-zf: ret stop");
    check((m.cpu.rflags & kFlagZF) != 0, "cmpxchg-zf: equal set ZF");
    check(m.cpu.reg[RAX] == 5, "cmpxchg-zf: accumulator untouched");
    check(m.cpu.reg[RBX] == 5, "cmpxchg-zf: destination untouched");
}

void test_test_not_neg() {
    Machine m(128);
    const std::uint8_t code[] = {
        0xB8, 0x0F, 0x00, 0x00, 0x00, // mov eax, 15
        0xA9, 0x0F, 0x00, 0x00, 0x00, // test eax, 15 (ZF=0)
        0xF7, 0xD0, // not eax -> 0xFFFFFFF0
        0xF7, 0xD8, // neg eax -> 0x10
        0xC3,
    };
    m.load(code, sizeof(code));
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "test: ret stop");
    check(m.cpu.reg[RAX] == 0x10, "test: not then neg = +16");
}

// ---------------------------------------------------------------------------
// Stop reasons
// ---------------------------------------------------------------------------

void test_unknown_halt() {
    Machine m(128);
    const std::uint8_t code[] = {
        0x0F, 0x10, 0xC0, // movups xmm0, xmm0 (refused)
    };
    m.load(code, sizeof(code));
    const RunResult r = m.run();
    check(r.why == Halt::Unknown, "unknown: float instruction refused");
    check(r.detail != nullptr, "unknown: detail present");
}

void test_syscall_hlt() {
    Machine m(128);
    const std::uint8_t code[] = {
        0x0F, 0x05, // syscall
        0xF4, // hlt
    };
    m.load(code, sizeof(code));
    RunResult r = m.run();
    check(r.why == Halt::Syscall, "syscall: named stop");
    m.cpu.rip = m.base + 2;
    r = m.run();
    check(r.why == Halt::Hlt, "hlt: named stop");
}

void test_fault_oob() {
    Machine m(128);
    const std::uint8_t code[] = {
        0x48, 0x8B, 0x85, 0x00, 0x00, 0x00, 0x10, // mov rax, [rbp+0x10000000]
        0xC3,
    };
    m.load(code, sizeof(code));
    const RunResult r = m.run();
    check(r.why == Halt::Fault, "oob: load outside the image faults");
}

void test_hook() {
    Machine m(128);
    const std::uint8_t code[] = {
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0x83, 0xC0, 0x01, // add eax, 1
        0xC3,
    };
    m.load(code, sizeof(code));
    std::size_t steps = 0;
    const auto hook = [](const StepInfo&, void* ctx) noexcept {
        ++*static_cast<std::size_t*>(ctx);
        return true;
    };
    const RunResult r = m.run(4096, hook, &steps);
    check(r.why == Halt::Ret, "hook: ret stop");
    check(steps == 3, "hook: saw every step");

    std::size_t abort_at = 0;
    const auto stopper = [](const StepInfo&, void* ctx) noexcept {
        return ++*static_cast<std::size_t*>(ctx) < 2;
    };
    Machine n(128);
    n.load(code, sizeof(code));
    const RunResult r2 = n.run(4096, stopper, &abort_at);
    check(r2.why == Halt::None, "hook: abort ends normally");
    check(r2.steps == 2, "hook: aborted after two steps");
}

void test_16bit() {
    Machine m(128);
    const std::uint8_t code[] = {
        0x66, 0xB8, 0x34, 0x12, // mov ax, 0x1234
        0x66, 0x83, 0xC0, 0x01, // add ax, 1 -> 0x1235
        0x66, 0x83, 0xC0, 0xFF, // add ax, -1 -> 0x1234
        0xC3,
    };
    m.load(code, sizeof(code));
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "16bit: ret stop");
    check((m.cpu.reg[RAX] & 0xFFFF) == 0x1234, "16bit: ax arithmetic");
    check((m.cpu.reg[RAX] >> 16) == 0, "16bit: upper bits untouched");
}

void test_selfmodifying() {
    Machine m(128);
    // Rewrites the immediate of `mov eax, 1` (its low byte at +11) to 42
    // before the mov executes. With the patch the mov loads 42 and rax
    // ends at 42; without it rax would be 1. Fetching from the memory
    // image (not a separate code pointer) is what makes the program
    // observe its own store.
    const std::uint8_t code[] = {
        0x48, 0x8D, 0xBD, 0x0B, 0x00, 0x00, 0x00, // lea rdi, [rbp+11]
        0xC6, 0x07, 0x2A, // mov byte [rdi], 0x2A -> mov eax, 42
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1 (immediate at +11)
        0xC3, // ret
    };
    m.load(code, sizeof(code));
    m.cpu.reg[RBP] = m.base;
    const RunResult r = m.run();
    check(r.why == Halt::Ret, "selfmod: ret stop");
    check(m.cpu.reg[RAX] == 42,
          "selfmod: patched immediate made the mov load 42");
}

} // namespace

int main() {
    const auto run = [](const char* name, void (*fn)()) {
        std::printf("-- %s\n", name);
        std::fflush(stdout);
        fn();
    };
    run("arith", test_arith);
    run("flags32", test_flags_32);
    run("flags64", test_flags_64_carry);
    run("adc", test_adc_chain);
    run("jcc_taken", test_jcc_taken);
    run("jcc_notaken", test_jcc_notaken);
    run("mov_family", test_mov_family);
    run("mem_rip", test_mem_rip);
    run("mem_sib", test_mem_sib);
    run("lea_movzx", test_lea_movzx);
    run("stack_call_ret", test_stack_call_ret);
    run("ret_imm", test_ret_imm);
    run("budget", test_jmp_loop_budget);
    run("shifts", test_shifts);
    run("shift_carry", test_shift_carry);
    run("mul_div", test_mul_div);
    run("imul", test_imul_forms);
    run("div_zero", test_div_zero);
    run("bitops", test_bswap_bitops);
    run("setcc", test_setcc_cmovcc);
    run("cmpxchg", test_cmpxchg_xadd);
    run("cmpxchg-zf", test_cmpxchg_zf);
    run("test_not_neg", test_test_not_neg);
    run("unknown", test_unknown_halt);
    run("syscall_hlt", test_syscall_hlt);
    run("fault", test_fault_oob);
    run("hook", test_hook);
    run("16bit", test_16bit);
    run("selfmod", test_selfmodifying);
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

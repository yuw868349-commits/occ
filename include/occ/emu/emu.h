// A self-contained interpreter for x86-64 integer code.
// The guest of this runtime is native code, and native code runs on the
// CPU -- which is the whole problem a piece of packed or virtualized code
// is built to make hard. A packer decrypts a function and jumps into it;
// an anti-analysis stub reads the code it is about to execute; a virtual
// machine's handlers step one byte at a time. All of those want the
// answer to "what would this code do" without the code actually running
// where anything can observe it. That answer is an interpreter.
//
// This module interprets a region of x86-64 bytes on a private register
// file and a private flat memory image, so that analysis runs the code
// the way an emulator would: the guest's real process, its real page
// tables and its real timing are never touched. It shares the length
// decoder with the instrumentation module (`dbi`), which guarantees the
// two see the same instruction stream, and adds what an emulator needs
// on top: operand decoding, arithmetic with the x86 flags, memory access
// through a bounded flat space, and a step hook for coverage or tracing.
//
// Scope is deliberate and documented rather than hidden. The interpreted
// family is the integer instruction set a 64-bit compiler emits -- the
// same family `dbi` accepts -- with full flag semantics for the arithmetic
// members, push/pop/call/ret for stack code, and the memory forms that
// straight-line and small-loop code use. Floating point, the vector
// family, the x87 stack and privileged/system instructions are not
// interpreted: they halt the run with a named reason rather than being
// guessed at, because a wrong answer is worse than a stopped one. The
// system-call instruction is likewise halted, leaving the decision of
// what a syscall means to the caller (this runtime's own syscall layer,
// or a policy that says "no system calls in interpreted code").
//
// The memory model is one flat byte array mapped at a caller-chosen base,
// exactly the shape a decrypted region or a VM handler set needs. There
// is no segmentation, no paging and no protection: a load or store
// outside the array halts with a named fault. A caller that wants the
// code to see a Windows address space maps that space's bytes into the
// array and lets the interpreter touch them.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "occ/dbi/dbi.h"

namespace occ::emu {

// The general-purpose registers, in the order `reg[]` is indexed.
enum Reg : std::uint8_t {
    RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
    R8, R9, R10, R11, R12, R13, R14, R15,
    kRegCount,
};

// A register file and the machine state that travels with it.
struct Cpu {
    std::uint64_t reg[kRegCount]{};
    std::uint64_t rip = 0;
    // The arithmetic flags, kept in the low byte as a bit field
    // (bit 0 CF, bit 6 ZF, bit 7 SF, bit 11 OF, and the AF/PF bits at
    // their x86 positions). Only the flags the interpreter computes are
    // meaningful; the rest read as zero.
    std::uint32_t rflags = 0;
};

// The flags the interpreter computes and tests.
enum : std::uint32_t {
    kFlagCF = 1u << 0,
    kFlagPF = 1u << 2,
    kFlagAF = 1u << 4,
    kFlagZF = 1u << 6,
    kFlagSF = 1u << 7,
    kFlagOF = 1u << 11,
};

// A flat byte-addressable memory image.
class Memory {
public:
    // The address the first byte of `bytes` is mapped at. `bytes` is a
    // view over the caller's buffer; the emulator shares it with the code
    // image, so self-modifying code is observed as it patches itself. The
    // caller keeps the buffer alive and does not reallocate it while
    // emulating.
    std::uint64_t base = 0;
    std::span<std::uint8_t> bytes;

    // Loads `n` bytes at `addr` into `dst`. False when the range lies
    // outside the image, in which case nothing is written.
    [[nodiscard]] bool load(std::uint64_t addr, void* dst,
                            std::size_t n) const noexcept;
    // Stores `n` bytes from `src` at `addr`. False when the range lies
    // outside the image, in which case nothing is written.
    [[nodiscard]] bool store(std::uint64_t addr, const void* src,
                             std::size_t n) noexcept;

    template <typename T> [[nodiscard]] bool load(std::uint64_t addr,
                                                  T& v) noexcept {
        static_assert(sizeof(T) <= 8);
        return load(addr, &v, sizeof(T));
    }
    template <typename T> [[nodiscard]] bool store(std::uint64_t addr,
                                                   T v) noexcept {
        static_assert(sizeof(T) <= 8);
        return store(addr, &v, sizeof(T));
    }
};

// Why a run stopped.
enum class Halt : std::uint8_t {
    None, // Finished normally (hit the region end or a return).
    Ret, // Returned through ret; `cpu.rip` is the popped target.
    Fault, // A memory access outside the image, or a divide by zero.
    Budget, // Reached the step budget.
    Unknown, // An instruction outside the interpreted family.
    Syscall, // syscall/sysenter executed.
    Hlt, // hlt executed.
};

// One executed step, delivered to the hook.
struct StepInfo {
    std::uint64_t rip = 0;
    std::uint32_t len = 0;
};

// Called after every executed instruction when non-null. The hook may
// stop the run by returning false.
using StepHook = bool (*)(const StepInfo&, void* ctx) noexcept;

struct RunResult {
    Halt why = Halt::None;
    std::uint64_t steps = 0;
    // A sentence naming the fault or the unknown instruction, for a
    // report a person reads. Empty unless `why` says otherwise.
    const char* detail = nullptr;
    // The RIP at which the run stopped.
    std::uint64_t rip = 0;
};

// Interprets `code[0..size)` mapped at `base`, starting at `cpu.rip`
// (which the caller sets to an address within the region; any value is
// accepted, and execution proceeds from the byte at `rip - base`).
// `mem` is the memory image the code reads and writes. Stops at the
// region's end, on a ret, on a named halt, or after `max_steps`.
// Returns the reason and the number of steps taken.
[[nodiscard]] RunResult run(const std::uint8_t* code, std::size_t size,
                            std::uint64_t base, Cpu& cpu, Memory& mem,
                            std::size_t max_steps, StepHook hook = nullptr,
                            void* hook_ctx = nullptr) noexcept;

} // namespace occ::emu

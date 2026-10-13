// Dynamic binary instrumentation: block splitting, edge coverage and a
// load-time rewriter.
//
// The guest of this runtime is native code running in-process, so there is
// no emulator and no tracing layer between the guest and the CPU -- the
// same fact that makes the page-trap watches (memwatch, vm_trace) the only
// instruments that exist for a guest that writes to itself. Coverage is a
// different question: the analyst wants to know which code ran, at block
// granularity and cheaply enough to run for the whole of a run. That is
// what this module answers.
//
// The instrument is a load-time rewrite. The image's executable sections
// are copied into a fresh buffer before the guest runs, every basic block
// is given a small record stub at its head, and every control transfer is
// re-targeted from the original buffer to its copy. The guest never
// executes the original code pages again; it executes the copy, and the
// copy records an edge every time control crosses from one block to the
// next. A run that collects edges this way needs no debugger, no trap flag
// and no emulation, and the record is a single store into a fixed-size
// map -- the same shape the coverage-guided fuzzer (the `fuzz` module)
// consumes as its feedback signal.
//
// Two honest limits, documented rather than hidden:
//
//   * Rewriting is only sound for code whose control transfers land on
//     block boundaries. A jump into the middle of a block (hand-written
//     code, data mixed with instructions) is refused: the rewriter reports
//     the block and the caller decides what a refusal means for its
//     target. Compiler-produced code jumps between blocks, so this is not
//     the limit it sounds like.
//
//   * Instruction length decoding is table-driven for the common integer
//     instruction family (the same family a 64-bit compiler emits) and
//     refuses what the table does not know. A refusal is honest: a
//     wrong length would misalign everything after it, and a misaligned
//     rewrite is worse than no rewrite.
//
// The same decoder is the front end of the emulator (`emu`), which is why
// it lives here and answers a length and a branch classification rather
// than anything emulator-shaped.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace occ::dbi {

// ---------------------------------------------------------------------------
// Instruction decoding
// ---------------------------------------------------------------------------

// What the rewriter and the emulator need to know about one instruction:
// its length and whether it changes control flow. Everything else (the
// operation it performs) belongs to the emulator and is decoded there.
enum class BranchKind : std::uint8_t {
    None, // Falls through.
    Rel8, // Signed 8-bit relative: EB, 70-7F.
    Rel32, // Signed 32-bit relative: E9, E8, 0F 80-8F.
    Indirect, // Absolute through a register or memory: FF /2, FF /4.
    Ret, // C2, C3, CA, CB.
};

struct DecodedInsn {
    std::uint32_t len = 0; // Total length, prefixes included.
    BranchKind branch = BranchKind::None;
    // For Rel8/Rel32, the signed displacement (from the end of the
    // instruction). For the others, zero.
    std::int64_t disp = 0;
    // Whether the instruction addresses memory relative to RIP. The
    // rewriter must relocate the displacement of exactly these.
    bool rip_relative = false;
    // Byte offset of the 32-bit displacement to relocate, valid when
    // rip_relative is true.
    std::uint32_t disp_offset = 0;
};

// Decodes one instruction at `p` with `avail` bytes remaining. True when
// the instruction is known and `len` is trustworthy; false when the table
// does not know it (in which case nothing is written to `out`).
[[nodiscard]] bool decode_insn(const std::uint8_t* p, std::size_t avail,
                               DecodedInsn& out) noexcept;

// ---------------------------------------------------------------------------
// Basic-block splitting
// ---------------------------------------------------------------------------

struct Block {
    // Offset of the block's first byte within the analyzed region.
    std::uint32_t offset = 0;
    // Byte length of the block's original instruction sequence.
    std::uint32_t size = 0;
    // Whether the block is the region's entry point.
    bool entry = false;
    // Whether the block ends in a control transfer that does not fall
    // through (unconditional jump, return, or a call -- calls are treated
    // as both falling through and transferring, so a call does not end a
    // block unless the analyzer says otherwise; here calls do not end a
    // block, which matches how compilers lay out straight-line code).
    bool ends_transfer = false;
    // Edge targets: the offsets this block can transfer control to, in
    // order. Empty for a block that only falls through. A fallthrough
    // successor is the first entry when present (compiler convention).
    std::vector<std::uint32_t> targets;
};

// Splits a contiguous region into basic blocks. `code` is the region,
// `size` its length, `base` the address the region is mapped at (used only
// for diagnostics and for target arithmetic on relocations). True when the
// whole region decoded and split; false when an instruction refused to
// decode, in which case `out` holds the blocks found before the refusal.
[[nodiscard]] bool split_blocks(const std::uint8_t* code, std::size_t size,
                                std::uint64_t base,
                                std::vector<Block>& out) noexcept;

// ---------------------------------------------------------------------------
// Edge coverage
// ---------------------------------------------------------------------------

// The coverage map is a fixed bitmap, indexed by a hash of the source and
// destination block addresses -- the same compact shape AFL uses, because
// it is the shape that makes a coverage signal cheap enough to consult
// after every block. 64 KiB is enough that the hash collisions of a real
// run stay a rounding error and small enough that the map fits in a cache
// line or two per probe.
static constexpr std::size_t kMapBytes = 1u << 16;

// The probe the rewritten code calls with the edge id in `rax`. Written in
// C++ and reached through a small register-save stub in the rewritten
// buffer, so it may be any ordinary function; it must not throw (the
// runtime is built -fno-exceptions) and should stay short.
using CoverageFn = void (*)(std::uint32_t edge) noexcept;

struct Coverage {
    std::uint8_t map[kMapBytes]{};
    std::uint64_t edges = 0; // Distinct edges seen (counted by the probe).
    std::uint64_t hits = 0; // Total crossings (counted by the probe).

    // The block id of the previous block, read and written by the probe.
    // The edge a crossing records is the hash of (last, current), which is
    // the same state that makes AFL's edge map directional.
    std::uint64_t last = 0;

    // The map slot for a crossing from block ids `from` to `to`.
    [[nodiscard]] static std::uint32_t slot(std::uint64_t from,
                                            std::uint64_t to) noexcept {
        const std::uint64_t mix = (from >> 4) ^ (to << 1);
        return static_cast<std::uint32_t>(mix) & (kMapBytes - 1);
    }
};

// The default probe: records a crossing from the previous block into
// `global_coverage`. The rewriter emits calls to the address of this
// function when the caller supplies no probe of its own; the argument is
// the block's id in the rewritten region.
void default_probe(std::uint32_t block_id) noexcept;
extern Coverage global_coverage;

// ---------------------------------------------------------------------------
// Rewriting
// ---------------------------------------------------------------------------

// The length of the per-block instrumentation stub the rewriter emits
// before a block's own instructions:
//
//   9C            pushfq
//   57            push rdi
//   41 53         push r11
//   41 52         push r10
//   50            push rax
//   53            push rbx
//   51            push rcx
//   49 BB <imm64> movabs r11, probe
//   48 BF <imm64> movabs rdi, block_id
//   41 FF D3      call r11
//   59            pop rcx
//   5B            pop rbx
//   58            pop rax
//   41 5A         pop r10
//   41 5B         pop r11
//   5F            pop rdi
//   9D            popfq
//
// The stub preserves every register and the flags around the probe call
// and leaves the stack balanced. The block id travels in `rdi` because
// this runtime is compiled with the SysV convention and the probe's first
// argument is `rdi`; the stub saves and restores `rdi` itself because a
// Windows guest treats it as callee-saved. The seven pushes move rsp by
// 56 bytes, which aligns the probe's call when the block was entered with
// the Windows convention's rsp % 16 == 8 (see the implementation notes).
static constexpr std::size_t kStubLen = 41;

// The result of rewriting one region.
struct Instrumented {
    // The executable copy. Entry point is `entry`, which is an offset
    // into `code`.
    std::vector<std::uint8_t> code;
    std::uint32_t entry = 0;

    // The blocks, in the order the rewriter laid them out, with offsets
    // into `code` and the original region's offsets retained for the
    // caller's bookkeeping.
    struct RewrittenBlock {
        std::uint32_t orig_offset = 0;
        std::uint32_t new_offset = 0;
        std::uint32_t size = 0; // Length of the rewritten block in `code`.
    };
    std::vector<RewrittenBlock> blocks;

    // Count of blocks the rewrite instrumented. The probe sees a block id
    // in [1, block_count] -- ids start at 1 so that the probe's initial
    // `last == 0` records the entry crossing as (0, 1) -- and derives the
    // edge from (last, id).
    std::uint32_t block_count = 0;
};

// Rewrites one region into an instrumented copy. `probe` defaults to the
// global probe. True when the region rewrote completely; false when a
// control transfer could not be relocated (an out-of-range target, a jump
// into the middle of a block, a refused instruction), with `out` left
// partially built and `*why` (when non-null) holding the reason.
[[nodiscard]] bool instrument(const std::uint8_t* code, std::size_t size,
                              std::uint64_t base,
                              const std::vector<Block>& blocks,
                              Instrumented& out, const char** why = nullptr,
                              CoverageFn probe = default_probe) noexcept;

} // namespace occ::dbi

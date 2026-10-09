// The API hook, as the assembly and the tables behind it.
//
// The hook is not a C function and cannot be written as one: the guest
// arrives with the Windows x64 convention's registers holding its
// arguments, and it must leave the function with those registers unchanged
// and with control transferred to the real implementation rather than
// returned to the caller. What it does write in C is the pair of tables a
// slot indexes -- the implementation address and the name -- and the
// report one call produces.

#include "occ/runtime/api_hook.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace occ::runtime::api_hook {
namespace {

// The slots. One per export of every module this runtime presents, which
// for the full Windows surface is some thousands; the cap is well above
// what any run registers and small enough that the table is a static
// array rather than an allocation. An overflow is recorded rather than
// written past, because a trampoline's slot has to be stable and "no slot"
// is a state the report can name.
constexpr std::uint32_t kCapacity = 65536;

std::uint64_t g_targets[kCapacity] = {};
std::vector<std::string> g_names;
std::uint32_t g_count = 0;
bool g_overflowed = false;

[[nodiscard]] bool read_switch() noexcept {
    const char* value = ::getenv("OCC_API_TRACE");
    return value != nullptr && value[0] != '\0';
}

}  // namespace

bool enabled() noexcept {
    static const bool on = read_switch();
    return on;
}

std::uint32_t note(std::string_view module, std::string_view name,
                   std::uint64_t address) noexcept {
    if (g_count >= kCapacity) {
        if (!g_overflowed) {
            g_overflowed = true;
            std::fprintf(stderr,
                         "occ api: the slot table is full at %u entries; "
                         "later exports are not traced\n",
                         static_cast<unsigned>(kCapacity));
        }
        return 0;
    }
    const std::uint32_t slot = g_count++;
    g_targets[slot] = address;

    // The name is stored in slot order, so the report needs no lookup
    // structure: the slot is the index.
    std::string full;
    full.reserve(module.size() + name.size() + 1);
    full.append(module);
    full.push_back('!');
    full.append(name);
    g_names.push_back(std::move(full));
    return slot;
}

// What the hook calls. One line per call: the export the slot belongs to
// and the three argument registers, as numbers. The arguments are not
// decoded here on purpose -- a decoder would need to know each API's
// signature, and a report that guessed at a pointer would print a string
// that was never a string. The number it was handed is always true.
extern "C" void occ_api_note(std::uint64_t index, std::uint64_t a0,
                             std::uint64_t a1, std::uint64_t a2) noexcept {
    const std::size_t at = static_cast<std::size_t>(index);
    if (at < g_names.size()) {
        std::fprintf(stderr, "occ api: %s(0x%llx, 0x%llx, 0x%llx)\n",
                     g_names[at].c_str(),
                     static_cast<unsigned long long>(a0),
                     static_cast<unsigned long long>(a1),
                     static_cast<unsigned long long>(a2));
    } else {
        std::fprintf(stderr, "occ api: slot %llu is not registered\n",
                     static_cast<unsigned long long>(index));
    }
}

// The table the hook reads.
//
// The declaration and the definition are separate statements because the
// linkage attribute belongs on the declaration: a variable written as
// `extern "C" T x = init;` is one GCC refuses, since it reads the linkage
// block as an `extern` storage class on an initialized object. A
// definition written after a C-linkage declaration keeps that linkage, so
// the assembly's `occ_api_targets` names this object and nothing else.
//
// The assembly reaches it rip-relative rather than through the GOT, which
// is correct for a symbol defined in the main program and never
// preemptible.
extern "C" {
extern std::uint64_t* occ_api_targets;
}
std::uint64_t* occ_api_targets = g_targets;

// The hook itself.
//
// Entry state, as the trampoline leaves it: `r11` holds the slot, and the
// guest's arguments are where its own caller put them -- `rcx`, `rdx`,
// `r8` and `r9` for the first four integers or pointers, and the rest on
// the stack above the return address.
//
// Two conventions meet here and both have to be satisfied, which is what
// makes this longer than it looks like it should be.
//
// The trampoline arrives under the Windows x64 convention, which is the
// guest's. Its volatile registers are `rax`, `rcx`, `rdx`, `r8`, `r9`,
// `r10` and `r11`; everything else -- `rbx`, `rbp`, `rsi`, `rdi`, `r12`
// through `r15`, and the whole of `xmm6` through `xmm15` -- belongs to the
// caller and has to come back unchanged. A hook that clobbered one of
// those would not crash where it happened: it would corrupt the guest's
// loop counter or its saved value and the damage would surface later, as a
// hang or a wrong answer, in code that looks unrelated to the API call.
//
// The recording function is host code, compiled by the host's compiler,
// and takes its arguments under the host (System V) convention -- `rdi`,
// `rsi`, `rdx`, `rcx` -- and may clobber every `xmm` register, because the
// host convention says those are the caller's to save. So the arguments
// are read from where the guest convention put them, written to where the
// host convention looks for them, and the registers the host call is free
// to destroy are saved first.
//
// The stack is laid out by this code and the numbers are its own. Seven
// pushes take `rsp` from the guest's eight-mod-sixteen entry to a
// sixteen-byte boundary; the 192 bytes below are the ten saved `xmm`
// registers (160) plus the shadow space the guest convention requires at
// a call (32). The saved general registers then sit at fixed offsets and
// the arguments are loaded from exactly the slots they were pushed to. An
// offset written wrong here would not crash the hook either: it would
// report one API's argument in another's row, which reads as a finding.
__asm__(
    ".text\n"
    ".globl occ_api_hook\n"
    ".hidden occ_api_hook\n"
    ".type occ_api_hook, @function\n"
    ".p2align 4\n"
    "occ_api_hook:\n"
    // The guest's registers, saved. The five volatile ones above the
    // callee-saved pair, so the offsets below stay easy to read.
    "    pushq %rcx\n"
    "    pushq %rdx\n"
    "    pushq %r8\n"
    "    pushq %r9\n"
    "    pushq %r11\n"
    // The two callee-saved general registers the host call would destroy.
    "    pushq %rsi\n"
    "    pushq %rdi\n"
    "    subq  $192, %rsp\n"
    // The ten callee-saved vector registers, on a sixteen-byte boundary.
    "    movaps %xmm6,  0(%rsp)\n"
    "    movaps %xmm7,  16(%rsp)\n"
    "    movaps %xmm8,  32(%rsp)\n"
    "    movaps %xmm9,  48(%rsp)\n"
    "    movaps %xmm10, 64(%rsp)\n"
    "    movaps %xmm11, 80(%rsp)\n"
    "    movaps %xmm12, 96(%rsp)\n"
    "    movaps %xmm13, 112(%rsp)\n"
    "    movaps %xmm14, 128(%rsp)\n"
    "    movaps %xmm15, 144(%rsp)\n"
    // The host convention's arguments: the slot, then the guest's first
    // three argument registers.
    "    movq  208(%rsp), %rdi\n"
    "    movq  240(%rsp), %rsi\n"
    "    movq  232(%rsp), %rdx\n"
    "    movq  224(%rsp), %rcx\n"
    "    call  occ_api_note\n"
    "    movaps  0(%rsp), %xmm6\n"
    "    movaps  16(%rsp), %xmm7\n"
    "    movaps  32(%rsp), %xmm8\n"
    "    movaps  48(%rsp), %xmm9\n"
    "    movaps  64(%rsp), %xmm10\n"
    "    movaps  80(%rsp), %xmm11\n"
    "    movaps  96(%rsp), %xmm12\n"
    "    movaps  112(%rsp), %xmm13\n"
    "    movaps  128(%rsp), %xmm14\n"
    "    movaps  144(%rsp), %xmm15\n"
    "    addq  $192, %rsp\n"
    "    popq  %rdi\n"
    "    popq  %rsi\n"
    "    popq  %r11\n"
    "    popq  %r9\n"
    "    popq  %r8\n"
    "    popq  %rdx\n"
    "    popq  %rcx\n"
    // The implementation the plain trampoline would have reached, entered
    // with the guest's registers and stack exactly as they were.
    "    movq  occ_api_targets(%rip), %r10\n"
    "    movq  (%r10,%r11,8), %r10\n"
    "    jmp   *%r10\n"
    ".size occ_api_hook, .-occ_api_hook\n");

}  // namespace occ::runtime::api_hook

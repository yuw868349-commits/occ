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

#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <unordered_map>
#include <utility>
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
// Address to slot, so a rebuilt import slot can be named from the address
// it holds. Built as the surface is registered; a duplicate address keeps
// the first registration, which is the rule the name table uses too.
std::unordered_map<std::uint64_t, std::uint32_t> g_by_address;
std::uint32_t g_count = 0;
bool g_overflowed = false;

// How the report renders one slot's arguments. The table below maps the
// export's name to a kind at registration time, so the per-call cost is an
// index into this enum and nothing else.
enum class Kind : std::uint8_t {
    None,           // three numbers, the honest default
    Arg0Utf16,      // a0 -> wide string (LoadLibraryW, GetModuleHandleW)
    Arg0Ascii,      // a0 -> narrow string (LoadLibraryA)
    Arg1Ascii,      // a1 -> narrow string or ordinal (GetProcAddress)
    OpenProcess,    // a0 access, a2 pid
    MessageBoxW,    // a1 -> wide text, a2 -> wide caption
    Proc32W,        // a1 -> PROCESSENTRY32W, executable name at 0x2C
    WriteConsoleW,  // a1 -> wide buffer, a2 -> character count
    CreateFileW,    // a0 -> wide path, a1 -> access
};

[[nodiscard]] Kind kind_for_name(std::string_view name) noexcept {
    static const std::pair<std::string_view, Kind> kTable[] = {
        {"LoadLibraryW", Kind::Arg0Utf16},
        {"LoadLibraryExW", Kind::Arg0Utf16},
        {"GetModuleHandleW", Kind::Arg0Utf16},
        {"CreateEventW", Kind::Arg0Utf16},
        {"LoadLibraryA", Kind::Arg0Ascii},
        {"GetProcAddress", Kind::Arg1Ascii},
        {"OpenProcess", Kind::OpenProcess},
        {"MessageBoxW", Kind::MessageBoxW},
        {"Process32FirstW", Kind::Proc32W},
        {"Process32NextW", Kind::Proc32W},
        {"WriteConsoleW", Kind::WriteConsoleW},
        {"CreateFileW", Kind::CreateFileW},
    };
    for (const auto& [key, kind] : kTable) {
        if (key == name) {
            return kind;
        }
    }
    return Kind::None;
}

std::vector<Kind> g_kinds;

// Guest memory, read so that a wild pointer is a failed read and not a
// fault. The hook runs on the guest's own thread, so a plain dereference
// of a bad address would kill the run; `pread` on this process's own
// memory answers the same question -- is this address mapped -- through
// the kernel, which returns EFAULT instead of raising. The fd is opened
// once and stays open for the run.
[[nodiscard]] int guest_mem_fd() noexcept {
    static const int fd = [] {
        const int opened = ::open("/proc/self/mem", O_RDONLY);
        return opened;
    }();
    return fd;
}

// Reads a string of at most `max` units through the safe path, `wide`
// choosing the unit size. False when the first unit could not be read --
// which is the answer "this pointer does not name readable memory", and
// the report prints the number it was handed instead of a string that was
// never there.
template <typename Unit>
[[nodiscard]] bool read_guest_string(std::uint64_t address, bool wide,
                                     std::size_t max, std::string& out) noexcept {
    out.clear();
    if (address == 0) {
        out = "NULL";
        return true;
    }
    const int fd = guest_mem_fd();
    if (fd < 0) {
        return false;
    }
    const std::size_t unit = sizeof(Unit);
    std::size_t consumed = 0;
    while (consumed < max) {
        Unit buffer[32];
        const std::size_t want = sizeof(buffer);
        const ssize_t got = ::pread(fd, buffer, want,
                                    static_cast<off_t>(address + consumed));
        if (got < static_cast<ssize_t>(unit)) {
            return !out.empty();
        }
        const std::size_t units = static_cast<std::size_t>(got) / unit;
        for (std::size_t i = 0; i < units; ++i) {
            const unsigned long long v =
                wide ? static_cast<unsigned long long>(buffer[i])
                     : static_cast<unsigned char>(buffer[i]);
            if (v == 0) {
                return true;
            }
            if (v >= 0x20 && v < 0x7F) {
                out.push_back(static_cast<char>(v));
            } else {
                char escape[8];
                std::snprintf(escape, sizeof(escape), "\\x%llx", v);
                out.append(escape);
            }
        }
        consumed += units * unit;
    }
    out.append("...");
    return true;
}

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
    g_by_address.emplace(address, slot);

    // The name is stored in slot order, so the report needs no lookup
    // structure: the slot is the index. The decode kind is decided from
    // the name once, here, rather than per call.
    std::string full;
    full.reserve(module.size() + name.size() + 1);
    full.append(module);
    full.push_back('!');
    full.append(name);
    g_kinds.push_back(kind_for_name(name));
    g_names.push_back(std::move(full));
    return slot;
}

const char* name_for_address(std::uint64_t address) noexcept {
    const auto it = g_by_address.find(address);
    if (it == g_by_address.end()) {
        return nullptr;
    }
    return g_names[it->second].c_str();
}

void note_trampoline(std::uint64_t address, std::uint32_t slot) noexcept {
    if (slot >= g_count || address == 0) {
        return;
    }
    // A trampoline address that collides with an implementation's keeps
    // whichever was registered first, which is the implementation: the
    // module surface is built before its trampolines are placed, so the
    // entry can only already be there for a reason that matters.
    g_by_address.emplace(address, slot);
}

// What the hook calls. One line per call: the export the slot belongs to
// and its arguments. The numbers are always printed raw; where the export
// has a signature this runtime knows, the value behind the number is
// fetched through the safe read and shown beside it -- beside, not
// instead, because the number is the one thing that is true without a
// guess and a wrong string is worse than no string.
extern "C" void occ_api_note(std::uint64_t index, std::uint64_t a0,
                             std::uint64_t a1, std::uint64_t a2) noexcept {
    const std::size_t at = static_cast<std::size_t>(index);
    if (at >= g_names.size()) {
        std::fprintf(stderr, "occ api: slot %llu is not registered\n",
                     static_cast<unsigned long long>(index));
        return;
    }
    std::string args;
    const Kind kind = at < g_kinds.size() ? g_kinds[at] : Kind::None;
    std::string text;
    switch (kind) {
    case Kind::Arg0Utf16:
        if (read_guest_string<unsigned short>(a0, true, 260, text)) {
            args = "L\"" + text + "\"";
        }
        break;
    case Kind::Arg0Ascii:
        if (read_guest_string<char>(a0, false, 260, text)) {
            args = "\"" + text + "\"";
        }
        break;
    case Kind::Arg1Ascii:
        if ((a1 & ~0xFFFFULL) == 0 && a1 != 0) {
            args = "ordinal " + std::to_string(a1 & 0xFFFF);
        } else if (read_guest_string<char>(a1, false, 260, text)) {
            args = "\"" + text + "\"";
        }
        break;
    case Kind::OpenProcess:
        args = "access=0x" + ([a0] {
                   char b[24];
                   std::snprintf(b, sizeof(b), "%llx",
                                 static_cast<unsigned long long>(a0));
                   return std::string(b);
               })() +
               " pid=" + std::to_string(a2 & 0xFFFFFFFF);
        break;
    case Kind::MessageBoxW: {
        std::string caption;
        const bool ok_text =
            read_guest_string<unsigned short>(a1, true, 260, text);
        const bool ok_caption =
            read_guest_string<unsigned short>(a2, true, 260, caption);
        if (ok_text && ok_caption) {
            args = "text=L\"" + text + "\" caption=L\"" + caption + "\"";
        }
        break;
    }
    case Kind::Proc32W:
        // The executable name sits 0x2C into PROCESSENTRY32W on x64 --
        // after the counters, the two ULONG_PTRs and the flags.
        if (read_guest_string<unsigned short>(a1 + 0x2C, true, 260, text)) {
            args = "exe=\"" + text + "\"";
        }
        break;
    case Kind::WriteConsoleW:
        if (a2 != 0 && a2 < 4096 &&
            read_guest_string<unsigned short>(a1, true, a2, text)) {
            args = "chars=" + std::to_string(a2) + " L\"" + text + "\"";
        }
        break;
    case Kind::CreateFileW:
        if (read_guest_string<unsigned short>(a0, true, 260, text)) {
            args = "path=L\"" + text + "\" access=0x" + ([a1] {
                       char b[24];
                       std::snprintf(b, sizeof(b), "%llx",
                                     static_cast<unsigned long long>(a1));
                       return std::string(b);
                   })();
        }
        break;
    case Kind::None:
        break;
    }
    if (args.empty()) {
        std::fprintf(stderr, "occ api: %s(0x%llx, 0x%llx, 0x%llx)\n",
                     g_names[at].c_str(),
                     static_cast<unsigned long long>(a0),
                     static_cast<unsigned long long>(a1),
                     static_cast<unsigned long long>(a2));
    } else {
        std::fprintf(stderr, "occ api: %s(%s)\n", g_names[at].c_str(),
                     args.c_str());
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

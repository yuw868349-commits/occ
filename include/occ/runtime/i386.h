// The 32-bit interpreter: a CPU the runtime owns, for images the host
// CPU cannot run.
//
// A 64-bit process cannot execute 32-bit code by jumping into it -- the
// mode switch that would take is the operating system's business, not a
// runtime's. What this runtime can do instead is read the instructions
// and do what they say: an interpreter, with its own register file and
// its own flags, over a memory model that is the guest's alone. That is
// slower than the native path by orders of magnitude, and it is the only
// route a 32-bit image has; the honest engineering question was never
// interpreter versus native, it was interpreter versus refusal.
//
// The scope is deliberate and written down: the instruction set below is
// the integer core a compiler actually emits -- moves, arithmetic, stack,
// control flow, string operations with their repeat prefixes -- and each
// addition lands with a test that runs it. The point of this file is not
// to be the whole x86; it is to be true on every byte it does claim.

#ifndef OCC_RUNTIME_I386_H_
#define OCC_RUNTIME_I386_H_

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace occ::runtime::i386 {

// The machine. Eight 32-bit registers in the encoding order the ModRM
// byte uses (eax, ecx, edx, ebx, esp, ebp, esi, edi), the instruction
// pointer, and the flags that survive into the subset: CF, PF, AF, ZF,
// SF, OF, DF -- the set the compiler's integer code reads and writes.
struct Machine {
    std::uint32_t regs[8] = {};
    std::uint32_t eip = 0;
    std::uint32_t eflags = 0x2;  // bit 1 is always set
    bool halted = false;
    std::uint32_t exit_code = 0;
    // The fs segment base -- the 32-bit TEB, built by the loader and
    // named here so the prefix handler can serve `mov %fs:0x18` with the
    // answer Windows would: the TEB is where every thread-shaped question
    // a CRT asks is answered from.
    std::uint32_t fs_base = 0;
    // The nested-call state: a host callback that must run guest code --
    // the global-constructor walk, an atexit handler -- re-enters the
    // interpreter's loop with this flag up, and the loop ends that nested
    // run when the guest's return pops the sentinel the host pushed.
    bool nest_active = false;
    std::uint32_t nest_saved_eip = 0;
    // The bytes the host seam removed from the stack on a stdcall API's
    // behalf -- the arguments it consumed, not the return address, which
    // the interpreter's own return takes back.
    std::uint32_t esp_adjust = 0;

    static constexpr std::uint32_t kEax = 0, kEcx = 1, kEdx = 2, kEbx = 3,
                                    kEsp = 4, kEbp = 5, kEsi = 6, kEdi = 7;
    static constexpr std::uint32_t kCF = 1 << 0, kPF = 1 << 2, kAF = 1 << 4,
                                    kZF = 1 << 6, kSF = 1 << 7,
                                    kDF = 1 << 10, kOF = 1 << 11;
};

// The memory: a flat 32-bit space, paged sparsely. Pages are 4096 bytes,
// created on first touch, zero-filled -- which is the semantics a
// loader's zero-fill promise has, and the only one an interpreter needs.
struct Memory {
    std::vector<std::uint8_t> page(std::uint32_t address);
    std::uint8_t read8(std::uint32_t address);
    void write8(std::uint32_t address, std::uint8_t value);
    std::uint32_t read32(std::uint32_t address);
    void write32(std::uint32_t address, std::uint32_t value);
    // Bulk copy for the image load and the string instructions; the
    // crossing pages are handled page by page.
    void read(std::uint32_t address, void* out, std::size_t bytes);
    void write(std::uint32_t address, const void* in, std::size_t bytes);

  private:
    // The page table is private to the memory model; the interpreter
    // touches memory only through the accessors above.
    static constexpr std::uint32_t kPageBits = 12;
    static constexpr std::uint32_t kPageSize = 1u << kPageBits;
    // Friendship is narrower than a public field: the translation is what
    // the accessors run, and only they run it.
    friend std::vector<std::uint8_t>& page_for(Memory&, std::uint32_t);
    std::vector<std::vector<std::uint8_t>> pages_;
    std::vector<std::uint32_t> page_base_;
};

// The page translation, named at namespace scope so the memory model's
// friendship names something the implementation can define.
std::vector<std::uint8_t>& page_for(Memory& m, std::uint32_t address);

// The API a 32-bit guest calls. The loader resolves the import table into
// magic addresses -- one per (dll, name) -- and the interpreter, on a
// call to one, hands the pair and the machine to this callback. The
// callback answers in Windows terms: it sets eax (and edx for the few
// 64-bit returns), or marks the machine halted for ExitProcess. A false
// return means "this runtime cannot service that call", which becomes
// the guest's failure, not the interpreter's crash.
using HostCall = bool (*)(void* state, const char* dll, const char* name,
                          Machine& m, Memory& mem);

// Loads the image at `image_bytes` into `mem` at its preferred base,
// resolves its import table through `resolve` into magic addresses, and
// runs from the entry point until the guest halts or `step_budget`
// instructions pass -- a budget every interpreter needs, because a
// guest that loops forever is a hang, and a hang is not an answer.
//
// Returns the exit code the guest gave, with `*fault` set (and a one-line
// reason in `*fault_detail`) when the run ended on something the
// interpreter could not do -- an instruction outside the implemented set
// names itself, which is how the set grows honestly.
// A data import -- __argc, _iob, __initenv -- is a VARIABLE the guest
// reads through its IAT slot, not a function it calls: the slot must
// hold an address of guest memory the loader set aside, and the host
// fills the value. is_data names them; data_init builds each one at the
// address the loader reserved.
using IsData = bool (*)(void* state, const char* dll, const char* name);
using DataInit = void (*)(void* state, const char* dll, const char* name,
                          std::uint32_t addr, Memory& mem);

[[nodiscard]] bool run(const std::uint8_t* image_bytes, std::size_t bytes,
                       const std::string& image_path,
                       bool (*resolve)(void* state, const char* dll,
                                       const char* name),
                       void* resolve_state, HostCall host_call,
                       void* host_call_state, Machine& m,
                       std::uint64_t step_budget, std::string* fault_detail,
                       IsData is_data = nullptr, DataInit data_init = nullptr);

// The nested-call executor the run hands back: runs a guest function to
// completion -- arguments under the cdecl convention, the sentinel return
// the interpreter itself removes -- and answers with eax. This is how a
// host callback that the guest gave a function pointer to (the global
// constructor walk, atexit) runs that pointer without leaving the
// machine.
// Registers a magic address the host handed out -- GetProcAddress's
// answer -- so a call through it routes back to the host seam with the
// pair it names.
void note_magic(std::uint32_t address, const std::string& dll,
                const std::string& name);

// Runs a guest function to completion from inside a host call: the
// arguments are pushed cdecl, a sentinel return marks the end, and the
// answer is eax. The active run provides the machine; without one the
// call fails and says so.
[[nodiscard]] bool call_guest(Machine& m, Memory& mem, std::uint32_t func,
                              std::uint32_t a1, std::uint32_t a2,
                              std::uint64_t budget, std::string* fault_detail);

using GuestExecutor =
    bool (*)(void* ctx, Machine& m, Memory& mem, std::uint32_t func,
             std::uint32_t a1, std::uint32_t a2, std::uint64_t budget,
             std::string* fault_detail);

}  // namespace occ::runtime::i386

#endif  // OCC_RUNTIME_I386_H_

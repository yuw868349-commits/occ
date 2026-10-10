// The 32-bit interpreter. See the header for the shape; this file is the
// decoder, the flag arithmetic, and the host-call seam.

#include "occ/runtime/i386.h"

#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

#include <sys/ucontext.h>

namespace occ::runtime::i386 {

constexpr std::uint32_t kPageSize = 0x1000;

// The executor the run publishes, and the context it reads: the lambda
// lives at function scope because it outlives the host call that received
// it and dies with the run.
static void* s_exec_ctx = nullptr;
using i386_exec_fn = bool (*)(void*, Machine&, Memory&, std::uint32_t,
                              std::uint32_t, std::uint32_t, std::uint64_t,
                              std::string*);
static i386_exec_fn s_exec_fn = nullptr;

// ------------------------------------------------------------------ memory

std::vector<std::uint8_t>& page_for(Memory& m, std::uint32_t address) {
    const std::uint32_t base = address & ~(kPageSize - 1);
    for (std::size_t i = 0; i < m.page_base_.size(); ++i) {
        if (m.page_base_[i] == base) {
            return m.pages_[i];
        }
    }
    m.page_base_.push_back(base);
    m.pages_.emplace_back(kPageSize, 0);
    return m.pages_.back();
}

std::vector<std::uint8_t> Memory::page(std::uint32_t address) {
    return page_for(*this, address);
}

std::uint8_t Memory::read8(std::uint32_t address) {
    auto& p = page_for(*this, address);
    return p[address & (kPageSize - 1)];
}

void Memory::write8(std::uint32_t address, std::uint8_t value) {
    auto& p = page_for(*this, address);
    p[address & (kPageSize - 1)] = value;
}

std::uint32_t Memory::read32(std::uint32_t address) {
    std::uint32_t v = 0;
    this->read(address, &v, 4);
    return v;
}

void Memory::write32(std::uint32_t address, std::uint32_t value) {
    static const bool trace = [] {
        const char* v = ::getenv("OCC_I386_TRACE");
        return v != nullptr && v[0] != '\0';
    }();
    if (trace && (address & 0xFFFFF000u) == 0x406000u) {
        std::fprintf(stderr, "occ i386: write [0x%x] = 0x%x\n", address,
                     value);
    }
    this->write(address, &value, 4);
}

void Memory::read(std::uint32_t address, void* out, std::size_t bytes) {
    auto* dst = static_cast<std::uint8_t*>(out);
    while (bytes != 0) {
        const std::uint32_t offset = address & (kPageSize - 1);
        const auto chunk = static_cast<std::uint32_t>(
            std::min<std::size_t>(bytes, kPageSize - offset));
        auto& p = page_for(*this, address);
        std::memcpy(dst, p.data() + offset, chunk);
        dst += chunk;
        address += chunk;
        bytes -= chunk;
    }
}

void Memory::write(std::uint32_t address, const void* in, std::size_t bytes) {
    const auto* src = static_cast<const std::uint8_t*>(in);
    while (bytes != 0) {
        const std::uint32_t offset = address & (kPageSize - 1);
        const auto chunk = static_cast<std::uint32_t>(
            std::min<std::size_t>(bytes, kPageSize - offset));
        auto& p = page_for(*this, address);
        std::memcpy(p.data() + offset, src, chunk);
        src += chunk;
        address += chunk;
        bytes -= chunk;
    }
}

namespace {

// ------------------------------------------------------------ flag math --

// The flag rules are stated once each, on the operation's result and its
// operands -- the form the manuals give, and the form that reads back as
// the definition rather than as a trick.
void set_szp(Machine& m, std::uint32_t result, unsigned width) {
    const unsigned sign_bit = 1u << (width * 8 - 1);
    const std::uint32_t mask = width == 4 ? 0xFFFFFFFFu : (sign_bit << 1) - 1;
    m.eflags &= ~(Machine::kZF | Machine::kSF | Machine::kPF);
    if ((result & mask) == 0) {
        m.eflags |= Machine::kZF;
    }
    if ((result & sign_bit) != 0) {
        m.eflags |= Machine::kSF;
    }
    // PF is the parity of the low byte, even parity set.
    const std::uint8_t low = static_cast<std::uint8_t>(result);
    int bits = 0;
    for (int i = 0; i < 8; ++i) {
        bits += (low >> i) & 1;
    }
    if (bits % 2 == 0) {
        m.eflags |= Machine::kPF;
    }
}

void add_flags(Machine& m, std::uint32_t a, std::uint32_t b,
               std::uint32_t result, unsigned width) {
    const unsigned sign_bit = 1u << (width * 8 - 1);
    const std::uint32_t mask = width == 4 ? 0xFFFFFFFFu : (sign_bit << 1) - 1;
    const std::uint32_t aa = a & mask;
    const std::uint32_t bb = b & mask;
    const std::uint32_t rr = result & mask;
    m.eflags &= ~(Machine::kCF | Machine::kOF | Machine::kAF);
    if (rr < aa) {
        m.eflags |= Machine::kCF;
    }
    if (((aa ^ rr) & (bb ^ rr)) & sign_bit) {
        m.eflags |= Machine::kOF;
    }
    if (((aa ^ bb ^ rr) & 0x10) != 0) {
        m.eflags |= Machine::kAF;
    }
    set_szp(m, rr, width);
}

void sub_flags(Machine& m, std::uint32_t a, std::uint32_t b,
               std::uint32_t result, unsigned width) {
    const unsigned sign_bit = 1u << (width * 8 - 1);
    const std::uint32_t mask = width == 4 ? 0xFFFFFFFFu : (sign_bit << 1) - 1;
    const std::uint32_t aa = a & mask;
    const std::uint32_t bb = b & mask;
    const std::uint32_t rr = result & mask;
    m.eflags &= ~(Machine::kCF | Machine::kOF | Machine::kAF);
    if (aa < bb) {
        m.eflags |= Machine::kCF;
    }
    if (((aa ^ bb) & (aa ^ rr)) & sign_bit) {
        m.eflags |= Machine::kOF;
    }
    if (((aa ^ bb ^ rr) & 0x10) != 0) {
        m.eflags |= Machine::kAF;
    }
    set_szp(m, rr, width);
}

void logic_flags(Machine& m, std::uint32_t result, unsigned width) {
    set_szp(m, result, width);
}

// ---------------------------------------------------------------- decoding

struct ModRm {
    std::uint8_t mod = 0, reg = 0, rm = 0;
    std::uint32_t address = 0;  // valid when mod != 3
    bool is_register = false;
};

// Reads a ModRM and its displacement, the way the decoder has to: the
// addressing modes are a table, and writing the table as a table is the
// difference between a decoder and a pile of branches.
[[nodiscard]] ModRm decode_modrm(Machine& m, Memory& /*mem*/,
                                 const std::uint8_t* code,
                                 std::size_t& i) noexcept {
    const std::uint8_t byte = code[i++];
    ModRm r;
    r.mod = byte >> 6;
    r.reg = (byte >> 3) & 7;
    r.rm = byte & 7;
    r.is_register = r.mod == 3;
    if (r.is_register) {
        return r;
    }
    std::uint32_t effective = 0;
    // The 32-bit table: each rm is one register, full stop. The first
    // version here carried the 16-bit addressing table's partners -- [edx]
    // answering as [edx+esi] -- so every base-plus-displacement read a
    // register that never belonged, and GetSectionCount's [edx+0x400000]
    // read zero while the MZ check on the plain disp32 form read true.
    switch (r.rm) {
    case 0: effective = m.regs[Machine::kEax]; break;
    case 1: effective = m.regs[Machine::kEcx]; break;
    case 2: effective = m.regs[Machine::kEdx]; break;
    case 3: effective = m.regs[Machine::kEbx]; break;
    case 4: {  // SIB
        const std::uint8_t sib = code[i++];
        const std::uint32_t scale = 1u << (sib >> 6);
        const std::uint8_t index = (sib >> 3) & 7;
        const std::uint8_t base = sib & 7;
        // base 5 means ebp, except with mod 0 -- there it means "no
        // base, a disp32 follows", and that displacement is part of the
        // instruction. The first version skipped it: the four skipped
        // bytes then decoded as two harmless byte-adds, the stream
        // re-synchronized by luck, and the missing displacement turned
        // lea 0x4(,%esi,4) into lea (%esi,4) -- which shrank the CRT's
        // argv array by one slot and sent its copy loop past the end.
        if (base == 5 && r.mod == 0) {
            std::uint32_t disp = 0;
            std::memcpy(&disp, code + i, 4);
            i += 4;
            effective = disp;
        } else {
            effective = m.regs[base];
        }
        if (index != 4) {
            effective += m.regs[index] * scale;
        }
        break;
    }
    case 5:
        if (r.mod == 0) {  // absolute disp32
            std::memcpy(&effective, code + i, 4);
            i += 4;
        } else {
            effective = m.regs[Machine::kEbp];
        }
        break;
    case 6: effective = m.regs[Machine::kEsi]; break;
    case 7: effective = m.regs[Machine::kEdi]; break;
    }
    switch (r.mod) {
    case 1: {
        std::int8_t disp;
        std::memcpy(&disp, code + i, 1);
        ++i;
        effective += static_cast<std::uint32_t>(static_cast<std::int32_t>(disp));
        break;
    }
    case 2: {
        std::int32_t disp;
        std::memcpy(&disp, code + i, 4);
        i += 4;
        effective += static_cast<std::uint32_t>(disp);
        break;
    }
    default: break;
    }
    r.address = effective;
    return r;
}

[[nodiscard]] std::uint32_t rm_read(Machine& m, Memory& mem,
                                    const ModRm& r, unsigned width) {
    if (r.is_register) {
        if (width == 4) {
            return m.regs[r.rm];
        }
        if (width == 2) {
            return m.regs[r.rm] & 0xFFFF;
        }
        return (m.regs[r.rm] & 0xFF) | ((m.regs[r.rm] >> 8) & 0xFF00);
    }
    if (width == 4) {
        const std::uint32_t v = mem.read32(r.address);
        return v;
    }
    std::uint32_t v = 0;
    mem.read(r.address, &v, width);
    return v;
}

void rm_write(Machine& m, Memory& mem, const ModRm& r, std::uint32_t v,
              unsigned width) {
    if (r.is_register) {
        if (width == 4) {
            m.regs[r.rm] = v;
        } else if (width == 2) {
            m.regs[r.rm] = (m.regs[r.rm] & 0xFFFF0000) | (v & 0xFFFF);
        } else {
            const std::uint32_t byte = v & 0xFF;
            const std::uint32_t keep = r.rm < 4
                                           ? (m.regs[r.rm] & 0xFFFFFF00)
                                           : (m.regs[r.rm & 3] & 0xFFFF00FF);
            m.regs[r.rm < 4 ? r.rm : r.rm & 3] =
                r.rm < 4 ? (keep | byte)
                         : (keep | (byte << ((r.rm - 4) * 8)));
        }
        return;
    }
    if (width == 4) {
        mem.write32(r.address, v);
    } else if (width == 2) {
        const std::uint16_t half = static_cast<std::uint16_t>(v);
        mem.write(r.address, &half, 2);
    } else {
        mem.write8(r.address, static_cast<std::uint8_t>(v));
    }
}

[[nodiscard]] std::uint32_t reg_read(Machine& m, std::uint8_t reg,
                                     unsigned width) {
    if (width == 4) {
        return m.regs[reg];
    }
    if (width == 2) {
        return m.regs[reg] & 0xFFFF;
    }
    return reg < 4 ? ((m.regs[reg] & 0xFF) | ((m.regs[reg] >> 8) & 0xFF00))
                   : ((m.regs[reg & 3] >> ((reg - 4) * 8)) & 0xFF);
}

void reg_write(Machine& m, std::uint8_t reg, std::uint32_t v, unsigned width) {
    if (width == 4) {
        m.regs[reg] = v;
        return;
    }
    if (width == 2) {
        m.regs[reg] = (m.regs[reg] & 0xFFFF0000) | (v & 0xFFFF);
        return;
    }
    if (reg < 4) {
        m.regs[reg] = (m.regs[reg] & 0xFFFF0000) | ((v & 0xFF) | ((v & 0xFF) << 8));
    } else {
        const auto shift = static_cast<std::uint32_t>((reg - 4) * 8);
        m.regs[reg & 3] =
            (m.regs[reg & 3] & ~(0xFFu << shift)) | ((v & 0xFF) << shift);
    }
}

}  // namespace

// The magic -> api table, at file scope: the run fills it from the
// image's import table, and note_magic lets a host callback register a
// magic it handed out -- GetProcAddress's answers are exactly that.
std::unordered_map<std::uint32_t, std::pair<std::string, std::string>>
    magic_to_api;

// -------------------------------------------------------------------- run

bool run(const std::uint8_t* image_bytes, std::size_t bytes,
         const std::string& image_path,
         bool (*resolve)(void*, const char*, const char*), void* resolve_state,
         HostCall host_call, void* host_call_state, Machine& m,
         std::uint64_t step_budget, std::string* fault_detail,
         IsData is_data, DataInit data_init) {
    (void)image_path;
    static const bool trace = [] {
        const char* v = ::getenv("OCC_I386_TRACE");
        return v != nullptr && v[0] != '\0';
    }();

    // The image: headers, then each section at its virtual address. A
    // 16-byte scratch stack at 0x7fff0000 -- the loader would place a real
    // one; the interpreter places a page-range and points esp at its top.
    // TODO: TLS, the PEB/TEB pair, and the loader's other promises land
    // with the first guest that asks for them; the first guest this file
    // runs reads its imports and calls, which is the spine.
    Memory mem;
    const std::uint32_t image_base = [&] {
        std::uint32_t pe_at = 0;
        std::memcpy(&pe_at, image_bytes + 0x3C, 4);
        std::uint32_t base = 0;
        std::memcpy(&base, image_bytes + pe_at + 24 + 28, 4);
        return base;
    }();
    const std::uint32_t size_of_headers = [&] {
        std::uint32_t pe_at = 0;
        std::memcpy(&pe_at, image_bytes + 0x3C, 4);
        std::uint32_t v = 0;
        std::memcpy(&v, image_bytes + pe_at + 24 + 60, 4);
        return v;
    }();
    mem.write(image_base, image_bytes,
              size_of_headers < bytes ? size_of_headers : bytes);
    {
        const std::uint32_t pe_at = [&] {
            std::uint32_t v = 0;
            std::memcpy(&v, image_bytes + 0x3C, 4);
            return v;
        }();
        const std::uint16_t section_count = [&] {
            std::uint16_t v = 0;
            std::memcpy(&v, image_bytes + pe_at + 6, 2);
            return v;
        }();
        const std::uint16_t optional_size = [&] {
            std::uint16_t v = 0;
            std::memcpy(&v, image_bytes + pe_at + 20, 2);
            return v;
        }();
        const std::size_t table =
            static_cast<std::size_t>(pe_at) + 24 + optional_size;
        for (std::uint16_t s = 0; s < section_count; ++s) {
            const std::size_t e = table + static_cast<std::size_t>(s) * 40;
            std::uint32_t va = 0, raw = 0, raw_size = 0, vsize = 0;
            std::memcpy(&vsize, image_bytes + e + 8, 4);
            std::memcpy(&va, image_bytes + e + 12, 4);
            std::memcpy(&raw_size, image_bytes + e + 16, 4);
            std::memcpy(&raw, image_bytes + e + 20, 4);
            if (raw == 0 || raw_size == 0 || va == 0) {
                continue;
            }
            const std::size_t take = raw_size < bytes - raw ? raw_size
                                                            : bytes - raw;
            const std::size_t put = vsize < take ? vsize : take;
            mem.write(image_base + va, image_bytes + raw, put);
        }
        // The entry, and the stack.
        std::uint32_t entry = 0;
        std::memcpy(&entry, image_bytes + pe_at + 24 + 16, 4);
        if (trace) {
            std::fprintf(stderr,
                         "occ i386: load base 0x%08x entry 0x%08x "
                         "(pe at 0x%x)\n",
                         image_base, entry, pe_at);
        }
        m.eip = image_base + entry;
    }
    static constexpr std::uint32_t kStackTop = 0x7FFF0000;
    for (std::uint32_t p = kStackTop - 16 * kPageSize; p < kStackTop;
         p += kPageSize) {
        static_cast<void>(mem.page(p));
    }
    m.regs[Machine::kEsp] = kStackTop - 4;

    // The TEB, at the address Windows puts the first thread's on, and the
    // fields the CRT reads through fs: Self at 0x18, the client id at
    // 0x20, the TLS pointer array at 0x2C, and the PEB at 0x30. The PEB
    // itself is a page with nothing in it yet -- a guest that reads
    // deeper than the process id names what it needs, and the loader
    // grows the answer then.
    static constexpr std::uint32_t kTeb = 0x7FFDE000;
    static constexpr std::uint32_t kPeb = 0x7FFDF000;
    mem.write32(kTeb + 0x18, kTeb);
    mem.write32(kTeb + 0x20, 1);  // client id: process
    mem.write32(kTeb + 0x24, 1);  // client id: thread
    mem.write32(kTeb + 0x2C, 0);  // thread local storage: none yet
    mem.write32(kTeb + 0x30, kPeb);
    m.fs_base = kTeb;

    // The import table resolves to magic addresses -- one per (dll, name),
    // issued from a counter in the 0x70000000 range, which is a range the
    // image has no reason to touch and the interpreter can test in one
    // comparison. The map from address back to the pair lives for the run.
    std::unordered_map<std::string, std::uint32_t> api_to_magic;
    std::uint32_t next_magic = 0x70000000;
    static constexpr std::uint32_t kDataRegion = 0x71000000;
    std::uint32_t next_data = 0;
    {
        const std::uint32_t pe_at = [&] {
            std::uint32_t v = 0;
            std::memcpy(&v, image_bytes + 0x3C, 4);
            return v;
        }();
        std::uint32_t import_rva = 0, import_size = 0;
        std::memcpy(&import_rva, image_bytes + pe_at + 24 + 96 + 8, 4);
        std::memcpy(&import_size, image_bytes + pe_at + 24 + 96 + 12, 4);
        if (import_rva != 0 && import_size != 0) {
            std::uint32_t desc = import_rva;
            for (;;) {
                const std::uint32_t name_rva = mem.read32(image_base + desc + 12);
                const std::uint32_t first_thunk = mem.read32(image_base + desc + 16);
                const std::uint32_t original = mem.read32(image_base + desc);
                if (name_rva == 0 && first_thunk == 0) {
                    break;
                }
                char dll[64] = {};
                for (int i = 0; i < 63; ++i) {
                    dll[i] = static_cast<char>(
                        mem.read8(image_base + name_rva +
                                  static_cast<std::uint32_t>(i)));
                    if (dll[i] == '\0') {
                        break;
                    }
                }
                std::uint32_t thunk = first_thunk != 0 ? first_thunk : original;
                for (;;) {
                    const std::uint32_t field = mem.read32(image_base + thunk);
                    if (field == 0) {
                        break;
                    }
                    if ((field & 0x80000000) == 0) {  // by name
                        char name[128] = {};
                        for (int i = 0; i < 127; ++i) {
                            name[i] = static_cast<char>(
                                mem.read8(image_base + field + 2 +
                                          static_cast<std::uint32_t>(i)));
                            if (name[i] == '\0') {
                                break;
                            }
                        }
                        if (resolve(resolve_state, dll, name)) {
                            const std::string key =
                                std::string(dll) + "!" + name;
                            if (!api_to_magic.contains(key)) {
                                api_to_magic.emplace(key, next_magic);
                                magic_to_api.emplace(
                                    next_magic,
                                    std::make_pair(std::string(dll),
                                                   std::string(name)));
                                ++next_magic;
                            }
                            if (is_data != nullptr &&
                                data_init != nullptr &&
                                is_data(resolve_state, dll, name)) {
                                // A data import: the slot holds the
                                // address of a variable the host builds
                                // in guest memory, 64 KiB apart so each
                                // one has room for what it carries.
                                const std::uint32_t slot =
                                    kDataRegion + next_data * 0x10000;
                                ++next_data;
                                mem.write32(image_base + thunk, slot);
                                data_init(resolve_state, dll, name, slot,
                                          mem);
                            } else {
                                mem.write32(image_base + thunk,
                                            api_to_magic.at(key));
                            }
                            if (trace) {
                                std::fprintf(stderr,
                                             "occ i386: import %s!%s -> "
                                             "magic 0x%x at 0x%x\n",
                                             dll, name,
                                             api_to_magic.at(key),
                                             image_base + thunk);
                            }
                        }
                    }
                    thunk += 4;
                }
                desc += 20;
            }
        }
    }

    // The interpreter loop. The code bytes are fetched from guest memory
    // into a local copy each step: the fetch is where a self-modifying
    // guest is served, and the copy is what bounds a faulting decode.
    std::vector<std::uint8_t> code(16);
    constexpr std::uint32_t kNestReturn = 0x7FF00000;
    // A plain local: the captures are this run's parameters, alive as
    // long as the run is, and every host callback that re-enters lives
    // inside that span. A static here would capture the first run's
    // parameters and hand them to the second.
    std::function<bool(Machine&, Memory&, std::uint32_t, std::uint32_t,
                       std::uint32_t, std::uint64_t, std::string*)>
        exec_fn;
    exec_fn = [&](Machine& machine, Memory& memory, std::uint32_t func,
                  std::uint32_t a1, std::uint32_t a2,
                  std::uint64_t loop_budget,
                  std::string* loop_fault) -> bool {
        if (func != 0) {
            if (a2 != 0) {
                machine.regs[Machine::kEsp] -= 4;
                memory.write32(machine.regs[Machine::kEsp], a2);
            }
            if (a1 != 0) {
                machine.regs[Machine::kEsp] -= 4;
                memory.write32(machine.regs[Machine::kEsp], a1);
            }
            machine.regs[Machine::kEsp] -= 4;
            memory.write32(machine.regs[Machine::kEsp], kNestReturn);
            machine.eip = func;
        }
        if (trace && func != 0) {
            std::fprintf(stderr, "occ i386: nested run fn=0x%x esp=0x%x\n",
                         func, machine.regs[Machine::kEsp]);
        }
        machine.nest_active = func != 0;
        std::uint64_t steps = 0;
        while (!machine.halted) {
            if (machine.nest_active &&
                machine.eip == kNestReturn) {
                if (trace) {
                    std::fprintf(stderr,
                                 "occ i386: nested run done esp=0x%x\n",
                                 machine.regs[Machine::kEsp]);
                }
                machine.nest_active = false;
                machine.eip = machine.nest_saved_eip;
                return true;
            }
            if (steps++ >= loop_budget) {
                if (loop_fault != nullptr) {
                    *loop_fault = "the step budget ran out";
                }
                return false;
            }
        memory.read(machine.eip, code.data(), code.size());
        const std::uint8_t* c = code.data();
        std::size_t i = 0;
        bool op16 = true;      // operand size prefix: 66 clears it
        bool rep = false;
        std::uint32_t segment_base = 0;  // fs lands here, per instruction
        (void)rep;
        (void)segment_base;
        // Prefixes, before any opcode.
        for (;;) {
            if (c[i] == 0x66) {
                op16 = false;
                ++i;
            } else if (c[i] == 0x64) {
                segment_base = machine.fs_base;  // fs: the TEB, for real
                ++i;
            } else if (c[i] == 0xF0 || c[i] == 0x67 || c[i] == 0x2E ||
                       c[i] == 0x3E || c[i] == 0x65 || c[i] == 0x36) {
                ++i;
            } else if (c[i] == 0xF3 || c[i] == 0xF2) {
                rep = true;
                ++i;
            } else {
                break;
            }
        }
        const unsigned opsz = op16 ? 4u : 2u;  // the 66 prefix's answer
        const std::uint8_t op = c[i++];
        const std::uint32_t rip_after = machine.eip + static_cast<std::uint32_t>(i);
        if (trace) {
            std::fprintf(stderr, "occ i386: eip 0x%08x op %02x\n",
                         static_cast<unsigned>(machine.eip),
                         static_cast<unsigned>(op));
        }

        switch (op) {
        case 0x90:  // nop
            machine.eip = rip_after;
            break;
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57: {  // push r
            machine.regs[Machine::kEsp] -= opsz;
            const std::uint32_t val = reg_read(m, op - 0x50, opsz);
            if (opsz == 2) {
                const std::uint16_t half = static_cast<std::uint16_t>(val);
                memory.write(machine.regs[Machine::kEsp], &half, 2);
            } else {
                memory.write32(machine.regs[Machine::kEsp], val);
            }
            machine.eip = rip_after;
            break;
        }
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F: {  // pop r
            if (opsz == 2) {
                std::uint16_t half = 0;
                memory.read(machine.regs[Machine::kEsp], &half, 2);
                reg_write(m, op - 0x58, half, 2);
            } else {
                machine.regs[op - 0x58] =
                    memory.read32(machine.regs[Machine::kEsp]);
            }
            machine.regs[Machine::kEsp] += opsz;
            machine.eip = rip_after;
            break;
        }
        case 0x68: {  // push imm
            std::uint32_t imm = 0;
            std::memcpy(&imm, c + i, opsz);
            machine.regs[Machine::kEsp] -= opsz;
            if (opsz == 2) {
                const std::uint16_t half = static_cast<std::uint16_t>(imm);
                memory.write(machine.regs[Machine::kEsp], &half, 2);
            } else {
                memory.write32(machine.regs[Machine::kEsp], imm);
            }
            machine.eip = rip_after + opsz;
            break;
        }
        case 0x6A: {  // push imm8 sign-extended
            std::int8_t imm8 = 0;
            std::memcpy(&imm8, c + i, 1);
            machine.regs[Machine::kEsp] -= 4;
            memory.write32(machine.regs[Machine::kEsp],
                        static_cast<std::uint32_t>(
                            static_cast<std::int32_t>(imm8)));
            machine.eip = rip_after + 1;
            break;
        }
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF: {  // mov r, imm
            std::uint32_t imm = 0;
            std::memcpy(&imm, c + i, opsz);
            reg_write(m, op - 0xB8, imm, opsz);
            machine.eip = rip_after + opsz;
            break;
        }
        case 0x00: case 0x01: case 0x02: case 0x03:
        case 0x08: case 0x09: case 0x0A: case 0x0B:
        case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x18: case 0x19: case 0x1A: case 0x1B:
        case 0x20: case 0x21: case 0x22: case 0x23:
        case 0x28: case 0x29: case 0x2A: case 0x2B:
        case 0x30: case 0x31: case 0x32: case 0x33:
        case 0x38: case 0x39: case 0x3A: case 0x3B: {
            // The main table's arithmetic, as the pattern it is: op&7
            // picks the form (rm,r / r,rm / acc,imm), op>>3 picks the
            // operation. One body instead of eight copies that drift.
            const std::uint8_t form = op & 7;
            const std::uint8_t kind = op >> 3;
            const unsigned wide = (form & 1) != 0 ? opsz : 1u;
            const bool to_rm = (form & 2) == 0;
            const ModRm r = decode_modrm(m, mem, c, i);
            std::uint32_t a, b;
            if (to_rm) {
                a = rm_read(m, mem, r, wide);
                b = reg_read(m, r.reg, wide);
            } else {
                a = reg_read(m, r.reg, wide);
                b = rm_read(m, mem, r, wide);
            }
            std::uint32_t v = a;
            switch (kind) {
            case 0: v = a + b; add_flags(m, a, b, v, wide); break;
            case 1: v = a | b; logic_flags(m, v, wide); break;
            case 2: v = a + b + (machine.eflags & Machine::kCF ? 1 : 0);
                    add_flags(m, a, b, v, wide); break;
            case 3: v = a - b - (machine.eflags & Machine::kCF ? 1 : 0);
                    sub_flags(m, a, b, v, wide); break;
            case 4: v = a & b; logic_flags(m, v, wide); break;
            case 5: v = a - b; sub_flags(m, a, b, v, wide); break;
            case 6: v = a ^ b; logic_flags(m, v, wide); break;
            case 7: sub_flags(m, a, b, a - b, wide); break;
            }
            if (kind != 7) {
                if (to_rm) {
                    rm_write(m, mem, r, v, wide);
                } else {
                    reg_write(m, r.reg, v, wide);
                }
            }
            machine.eip = machine.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0x04: case 0x05: case 0x0C: case 0x0D:
        case 0x14: case 0x15: case 0x1C: case 0x1D:
        case 0x24: case 0x25: case 0x2C: case 0x2D:
        case 0x34: case 0x35: case 0x3C: case 0x3D: {  // acc, imm
            const std::uint8_t kind = op >> 3;
            const unsigned wide = (op & 1) != 0 ? opsz : 1u;
            std::uint32_t imm = 0;
            std::memcpy(&imm, c + i, wide);
            i += wide;
            const std::uint32_t a = reg_read(m, 0, wide);
            std::uint32_t v = a;
            switch (kind) {
            case 0: v = a + imm; add_flags(m, a, imm, v, wide); break;
            case 1: v = a | imm; logic_flags(m, v, wide); break;
            case 3: v = a - imm; sub_flags(m, a, imm, v, wide); break;
            case 4: v = a & imm; logic_flags(m, v, wide); break;
            case 5: v = a - imm; sub_flags(m, a, imm, v, wide); break;
            case 6: v = a ^ imm; logic_flags(m, v, wide); break;
            case 7: sub_flags(m, a, imm, a - imm, wide); break;
            default:
                if (loop_fault != nullptr) {
                    *loop_fault = "acc,imm op " + std::to_string(kind);
                }
                return false;
            }
            if (kind != 7) {
                reg_write(m, 0, v, wide);
            }
            machine.eip = machine.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0x40: case 0x41: case 0x42: case 0x43:
        case 0x44: case 0x45: case 0x46: case 0x47: {  // inc r
            const std::uint32_t a = reg_read(m, op - 0x40, opsz);
            add_flags(m, a, 1, a + 1, opsz);
            reg_write(m, op - 0x40, a + 1, opsz);
            break;
        }
        case 0x48: case 0x49: case 0x4A: case 0x4B:
        case 0x4C: case 0x4D: case 0x4E: case 0x4F: {  // dec r
            const std::uint32_t a = reg_read(m, op - 0x48, opsz);
            sub_flags(m, a, 1, a - 1, opsz);
            reg_write(m, op - 0x48, a - 1, opsz);
            break;
        }
        case 0x88: case 0x89: {  // mov rm, r8 / mov rm, r32
            const ModRm r = decode_modrm(m, mem, c, i);
            rm_write(m, mem, r, reg_read(m, r.reg, (op == 0x89) ? opsz : 1u), (op == 0x89) ? opsz : 1u);
            machine.eip = machine.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0x8A: case 0x8B: {  // mov r, rm
            const ModRm r = decode_modrm(m, mem, c, i);
            reg_write(m, r.reg, rm_read(m, mem, r, (op == 0x8B) ? opsz : 1u), (op == 0x8B) ? opsz : 1u);
            machine.eip = machine.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0x8D: {  // lea r, m
            const ModRm r = decode_modrm(m, mem, c, i);
            if (r.is_register) {
                if (loop_fault != nullptr) {
                    *loop_fault = "lea with a register operand";
                }
                return false;
            }
            reg_write(m, r.reg, r.address, opsz);
            machine.eip = machine.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0xC7: {  // mov rm, imm
            const ModRm r = decode_modrm(m, mem, c, i);
            std::uint32_t imm = 0;
            std::memcpy(&imm, c + i, opsz);
            i += opsz;
            rm_write(m, mem, r, imm, opsz);
            machine.eip = machine.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0x84: case 0x85: {  // test
            const ModRm r = decode_modrm(m, mem, c, i);
            const unsigned tw = (op == 0x85) ? opsz : 1u;
            logic_flags(m, rm_read(m, mem, r, tw) & reg_read(m, r.reg, tw),
                        tw);
            machine.eip = machine.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0x80: case 0x81: case 0x83: {  // group1 rm, imm
            const ModRm r = decode_modrm(m, mem, c, i);
            const std::uint8_t sub = r.reg;
            // 80 is the byte form; 83 is imm8 sign-extended to the
            // operand size; 81 is the immediate at the operand size --
            // which the 66 prefix makes 2, and the first version here
            // read 4 regardless, ate the next instruction's bytes as
            // immediate, and desynced the stream.
            const unsigned gw = op == 0x80 ? 1u : opsz;
            std::uint32_t imm = 0;
            if (op == 0x83) {
                std::int8_t imm8 = 0;
                std::memcpy(&imm8, c + i, 1);
                imm = static_cast<std::uint32_t>(
                    static_cast<std::int32_t>(imm8));
                i += 1;
            } else if (op == 0x81) {
                std::memcpy(&imm, c + i, gw);
                i += gw;
            } else {
                imm = c[i];
                i += 1;
            }
            const std::uint32_t a = rm_read(m, mem, r, gw);
            std::uint32_t v = a;
            switch (sub) {
            case 0: v = a + imm; add_flags(m, a, imm, v, gw); break;
            case 1: v = a | imm; logic_flags(m, v, gw); break;
            case 4: v = a & imm; logic_flags(m, v, gw); break;
            case 5: v = a - imm; sub_flags(m, a, imm, v, gw); break;
            case 6: v = a ^ imm; logic_flags(m, v, gw); break;
            case 7:
                sub_flags(m, a, imm, a - imm, gw);
                if (trace) {
                    std::fprintf(stderr,
                                 "occ i386:   cmp 0x%x-0x%x -> zf=%d\n",
                                 a, imm,
                                 (machine.eflags & Machine::kZF) != 0 ? 1 : 0);
                }
                break;
            default:
                if (loop_fault != nullptr) {
                    *loop_fault = "group1 op " + std::to_string(sub);
                }
                return false;
            }
            if (sub != 7) {
                rm_write(m, mem, r, v, gw);
            }
            machine.eip = machine.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0xE8: {  // call rel32
            std::int32_t rel = 0;
            std::memcpy(&rel, c + i, 4);
            const std::uint32_t target =
                rip_after + 4 + static_cast<std::uint32_t>(rel);
            machine.regs[Machine::kEsp] -= 4;
            memory.write32(machine.regs[Machine::kEsp], rip_after + 4);
            // The magic range: a call into an address the loader filled is
            // the host-call seam, entered the same way the guest entered
            // every call -- through this switch, with the machine as it is.
            if (target >= 0x70000000 && target < 0x71000000) {
                const auto api_it = magic_to_api.find(target);
                if (api_it == magic_to_api.end()) {
                    char mh[12];
                    std::snprintf(mh, sizeof(mh), "%x", target);
                    if (loop_fault != nullptr) {
                        *loop_fault = std::string("call through unknown "
                                                  "magic 0x") + mh;
                    }
                    return false;
                }
                const auto& api = api_it->second;
                if (!host_call(host_call_state, api.first.c_str(),
                               api.second.c_str(), m, mem)) {
                    if (loop_fault != nullptr) {
                        *loop_fault = "unhosted call " + api.first + "!" +
                                        api.second;
                    }
                    return false;
                }
                if (machine.halted) {
                    return true;
                }
                machine.eip = memory.read32(machine.regs[Machine::kEsp]);
                machine.regs[Machine::kEsp] += 4;
            } else {
                machine.eip = target;
            }
            break;
        }
        case 0xC3: {  // ret
            machine.eip = memory.read32(machine.regs[Machine::kEsp]);
            machine.regs[Machine::kEsp] += 4;
            break;
        }
        case 0xC2: {  // ret imm16: pop the return, then the caller's bytes
            std::uint16_t imm = 0;
            std::memcpy(&imm, c + i, 2);
            machine.eip = memory.read32(machine.regs[Machine::kEsp]);
            machine.regs[Machine::kEsp] += 4 + imm;
            break;
        }
        case 0xE9: {  // jmp rel32
            std::int32_t rel = 0;
            std::memcpy(&rel, c + i, 4);
            machine.eip = rip_after + 4 + static_cast<std::uint32_t>(rel);
            break;
        }
        case 0xEB: {  // jmp rel8
            std::int8_t rel = 0;
            std::memcpy(&rel, c + i, 1);
            machine.eip = rip_after + 1 + static_cast<std::uint32_t>(static_cast<std::int32_t>(rel));
            break;
        }
        case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7C: case 0x7D:
        case 0x7E: case 0x7F: {  // jcc rel8
            std::int8_t rel = 0;
            std::memcpy(&rel, c + i, 1);
            bool taken = false;
            switch (op) {
            case 0x72: taken = (machine.eflags & Machine::kCF) != 0; break;
            case 0x73: taken = (machine.eflags & Machine::kCF) == 0; break;
            case 0x74: taken = (machine.eflags & Machine::kZF) != 0; break;
            case 0x75: taken = (machine.eflags & Machine::kZF) == 0; break;
            case 0x76: taken = (machine.eflags & Machine::kCF) != 0 ||
                               (machine.eflags & Machine::kZF) != 0; break;
            case 0x77: taken = (machine.eflags & Machine::kCF) == 0 &&
                               (machine.eflags & Machine::kZF) == 0; break;
            case 0x78: taken = (machine.eflags & Machine::kSF) != 0; break;
            case 0x79: taken = (machine.eflags & Machine::kSF) == 0; break;
            case 0x7C: taken = (machine.eflags & Machine::kSF) !=
                               (machine.eflags & Machine::kOF); break;
            case 0x7D: taken = (machine.eflags & Machine::kSF) ==
                               (machine.eflags & Machine::kOF); break;
            case 0x7E: taken = (machine.eflags & Machine::kZF) != 0 ||
                               (machine.eflags & Machine::kSF) !=
                                   (machine.eflags & Machine::kOF); break;
            case 0x7F: taken = (machine.eflags & Machine::kZF) == 0 &&
                               (machine.eflags & Machine::kSF) ==
                                   (machine.eflags & Machine::kOF); break;
            }
            if (taken) {
                machine.eip = rip_after + 1 + static_cast<std::uint32_t>(static_cast<std::int32_t>(rel));
            } else {
                machine.eip = rip_after + 1;
            }
            break;
        }
        case 0xC9: {  // leave
            machine.regs[Machine::kEsp] = machine.regs[Machine::kEbp];
            machine.regs[Machine::kEbp] = memory.read32(machine.regs[Machine::kEsp]);
            machine.regs[Machine::kEsp] += 4;
            machine.eip = rip_after;
            break;
        }
        case 0xCC: {  // int3: the guest's own trap becomes a stop
            if (loop_fault != nullptr) {
                *loop_fault = "int3 at guest eip";
            }
            return false;
        }
        case 0xA1: {  // mov eax, moffs
            std::uint32_t addr = 0;
            std::memcpy(&addr, c + i, 4);
            if (opsz == 2) {
                std::uint16_t half = 0;
                memory.read(addr, &half, 2);
                reg_write(m, Machine::kEax, half, 2);
            } else {
                machine.regs[Machine::kEax] = memory.read32(addr);
            }
            if (trace) {
                std::fprintf(stderr,
                             "occ i386:   mov eax,[0x%x] = 0x%x\n", addr,
                             machine.regs[Machine::kEax]);
            }
            machine.eip = rip_after + 4;
            break;
        }
        case 0xA0: {  // mov al, moffs8
            std::uint32_t addr = 0;
            std::memcpy(&addr, c + i, 4);
            reg_write(m, 0, memory.read8(addr), 1);
            machine.eip = rip_after + 4;
            break;
        }
        case 0xA2: {  // mov moffs8, al
            std::uint32_t addr = 0;
            std::memcpy(&addr, c + i, 4);
            memory.write8(addr,
                          static_cast<std::uint8_t>(reg_read(m, 0, 1)));
            machine.eip = rip_after + 4;
            break;
        }
        case 0xA3: {  // mov moffs, eax
            std::uint32_t addr = 0;
            std::memcpy(&addr, c + i, 4);
            if (opsz == 2) {
                const std::uint16_t half =
                    static_cast<std::uint16_t>(
                        reg_read(m, Machine::kEax, 2));
                memory.write(addr, &half, 2);
            } else {
                memory.write32(addr, machine.regs[Machine::kEax]);
            }
            machine.eip = rip_after + 4;
            break;
        }
        case 0xFF: {  // group5: the indirect call and jump
            const ModRm r = decode_modrm(m, mem, c, i);
            const std::uint8_t sub = r.reg;
            const std::uint32_t target = rm_read(m, mem, r, 4);
            if (sub == 2) {  // call rm32
                const std::uint32_t return_to =
                    machine.eip + static_cast<std::uint32_t>(i);
                if (target >= 0x70000000 && target < 0x71000000) {
                    // The seam: an address the loader filled with a magic
                    // is the host's, entered exactly as a real call
                    // enters it -- the return address pushed, the
                    // arguments where the convention put them -- and
                    // left by the convention the host names in
                    // `esp_adjust`.
                    machine.regs[Machine::kEsp] -= 4;
                    memory.write32(machine.regs[Machine::kEsp], return_to);
                    const auto api_it = magic_to_api.find(target);
                if (api_it == magic_to_api.end()) {
                    char mh[12];
                    std::snprintf(mh, sizeof(mh), "%x", target);
                    if (loop_fault != nullptr) {
                        *loop_fault = std::string("call through unknown "
                                                  "magic 0x") + mh;
                    }
                    return false;
                }
                const auto& api = api_it->second;
                    machine.esp_adjust = 0;
                    if (!host_call(host_call_state, api.first.c_str(),
                                   api.second.c_str(), m, mem)) {
                        if (loop_fault != nullptr) {
                            *loop_fault = "unhosted call " + api.first +
                                            "!" + api.second;
                        }
                        return false;
                    }
                    if (machine.halted) {
                        return true;
                    }
                    // The return of a stdcall call: pop the return
                    // address first, then the bytes the callee removed
                    // -- in that order, because the other order turns
                    // the last argument into the return address, which
                    // is exactly what the first console run did.
                    machine.eip = memory.read32(machine.regs[Machine::kEsp]);
                    machine.regs[Machine::kEsp] +=
                        4 + machine.esp_adjust;
                } else {
                    machine.regs[Machine::kEsp] -= 4;
                    memory.write32(machine.regs[Machine::kEsp], return_to);
                    machine.eip = target;
                }
            } else if (sub == 6) {  // push rm32
                const std::uint32_t v = rm_read(m, mem, r, 4);
                machine.regs[Machine::kEsp] -= 4;
                memory.write32(machine.regs[Machine::kEsp], v);
                machine.eip = machine.eip + static_cast<std::uint32_t>(i);
            } else if (sub == 4) {  // jmp rm32
                if (target >= 0x70000000 && target < 0x71000000) {
                    // A tail call into an import: the guest has nothing
                    // left to do after the call, so the host answers it
                    // and the machine returns to whoever called the
                    // tail-caller -- which is [esp] here, not a return
                    // address this instruction pushed.
                    const auto api_it = magic_to_api.find(target);
                if (api_it == magic_to_api.end()) {
                    char mh[12];
                    std::snprintf(mh, sizeof(mh), "%x", target);
                    if (loop_fault != nullptr) {
                        *loop_fault = std::string("call through unknown "
                                                  "magic 0x") + mh;
                    }
                    return false;
                }
                const auto& api = api_it->second;
                    if (trace) {
                        std::fprintf(stderr,
                                     "occ i386: tail %s!%s esp=0x%x "
                                     "ret=0x%x\n",
                                     api.first.c_str(), api.second.c_str(),
                                     machine.regs[Machine::kEsp],
                                     memory.read32(machine.regs[Machine::kEsp]));
                    }
                    if (!host_call(host_call_state, api.first.c_str(),
                                   api.second.c_str(), m, mem)) {
                        if (loop_fault != nullptr) {
                            *loop_fault = "unhosted tail call " +
                                            api.first + "!" + api.second;
                        }
                        return false;
                    }
                    if (machine.halted) {
                        return true;
                    }
                    // The same return discipline the call seam uses:
                    // pop the return address first, then the arguments
                    // the callee removed. The old order here turned the
                    // last argument into the return address, and the
                    // guest executed its own __xi_z table as code.
                    machine.eip =
                        memory.read32(machine.regs[Machine::kEsp]);
                    machine.regs[Machine::kEsp] +=
                        4 + machine.esp_adjust;
                } else {
                    machine.eip = target;
                }
            } else {
                if (loop_fault != nullptr) {
                    *loop_fault = "group5 op " + std::to_string(sub);
                }
                return false;
            }
            break;
        }
        case 0xC0: case 0xC1: case 0xD0: case 0xD1:
        case 0xD2: case 0xD3: {  // group2: shifts
            const unsigned wide = (op & 1) != 0 ? opsz : 1u;
            const ModRm r = decode_modrm(m, mem, c, i);
            std::uint32_t count = 0;
            if (op == 0xC0 || op == 0xC1) {
                count = c[i];
                i += 1;
            } else if (op == 0xD0 || op == 0xD1) {
                count = 1;
            } else {
                count = machine.regs[Machine::kEcx] & 0xFF;
            }
            const std::uint32_t v0 = rm_read(m, mem, r, wide);
            count &= 0x1F;
            const unsigned bits = wide * 8;
            const std::uint32_t smask =
                wide == 4 ? 0xFFFFFFFFu : (1u << bits) - 1;
            std::uint32_t v = v0 & smask;
            machine.eflags &= ~(Machine::kCF | Machine::kOF | Machine::kSF |
                          Machine::kZF | Machine::kPF);
            switch (r.reg) {
            case 4: case 6:  // shl / sal
                if (count != 0) {
                    machine.eflags |=
                        ((v0 >> (bits - count)) & 1) != 0 ? Machine::kCF : 0;
                    v = (v0 << count) & smask;
                    if (((v >> (bits - 1)) & 1) !=
                        ((v0 >> (bits - 1 - count)) & 1)) {
                        machine.eflags |= Machine::kOF;
                    }
                    set_szp(m, v, wide);
                }
                break;
            case 5:  // shr
                if (count != 0) {
                    machine.eflags |=
                        ((v0 >> (count - 1)) & 1) != 0 ? Machine::kCF : 0;
                    v = (v0 & smask) >> count;
                    set_szp(m, v, wide);
                }
                break;
            case 7: {  // sar
                if (count != 0) {
                    // Sign-extend from the operand width, then shift: the
                    // 16-bit sar must fill from bit 15, not bit 31.
                    std::int32_t sv0 = static_cast<std::int32_t>(v0 & smask);
                    if ((static_cast<std::uint32_t>(sv0) &
                         (1u << (bits - 1))) != 0) {
                        sv0 = static_cast<std::int32_t>(
                            static_cast<std::uint32_t>(sv0) | ~smask);
                    }
                    machine.eflags |=
                        ((v0 >> (count - 1)) & 1) != 0 ? Machine::kCF : 0;
                    v = static_cast<std::uint32_t>(sv0 >> count) & smask;
                    set_szp(m, v, wide);
                }
                break;
            }
            default:
                if (loop_fault != nullptr) {
                    *loop_fault = "shift op " + std::to_string(r.reg);
                }
                return false;
            }
            rm_write(m, mem, r, v, wide);
            machine.eip = machine.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0xF6: {  // group3, byte: test/not/neg/mul/imul/div/idiv
            const ModRm r = decode_modrm(m, mem, c, i);
            const std::uint32_t a = rm_read(m, mem, r, 1);
            switch (r.reg) {
            case 0: case 1: {  // test rm8, imm8
                std::uint32_t imm = 0;
                imm = c[i];
                i += 1;
                logic_flags(m, a & imm, 1);
                break;
            }
            case 2:
                rm_write(m, mem, r, ~a, 1);
                break;
            case 3:
                sub_flags(m, 0, a, 0 - a, 1);
                rm_write(m, mem, r, 0 - a, 1);
                break;
            case 4: {  // mul: ax = al * rm8
                const std::uint32_t p =
                    (reg_read(m, Machine::kEax, 1) & 0xFF) * (a & 0xFF);
                reg_write(m, Machine::kEax, p, 2);
                machine.eflags &= ~(Machine::kCF | Machine::kOF);
                if ((p >> 8) != 0) {
                    machine.eflags |= Machine::kCF | Machine::kOF;
                }
                break;
            }
            case 5: {  // imul: ax = signed al * rm8
                const int sa = static_cast<std::int8_t>(
                    static_cast<std::uint8_t>(
                        reg_read(m, Machine::kEax, 1)));
                const int sb = static_cast<std::int8_t>(
                    static_cast<std::uint8_t>(a));
                const std::int32_t p = sa * sb;
                reg_write(m, Machine::kEax,
                          static_cast<std::uint32_t>(p), 2);
                machine.eflags &= ~(Machine::kCF | Machine::kOF);
                if (p != static_cast<std::int32_t>(
                             static_cast<std::int8_t>(p))) {
                    machine.eflags |= Machine::kCF | Machine::kOF;
                }
                break;
            }
            case 6: {  // div: al = ax / rm8, ah = remainder
                if ((a & 0xFF) == 0) {
                    if (loop_fault != nullptr) {
                        *loop_fault = "divide by zero";
                    }
                    return false;
                }
                const std::uint32_t dividend = reg_read(m, Machine::kEax, 2);
                const std::uint32_t q = dividend / (a & 0xFF);
                if (q > 0xFF) {
                    if (loop_fault != nullptr) {
                        *loop_fault = "divide overflow";
                    }
                    return false;
                }
                reg_write(m, Machine::kEax,
                          (q & 0xFF) |
                              ((dividend % (a & 0xFF)) << 8), 2);
                break;
            }
            case 7: {  // idiv
                if ((a & 0xFF) == 0) {
                    if (loop_fault != nullptr) {
                        *loop_fault = "integer divide by zero";
                    }
                    return false;
                }
                const int dividend = static_cast<std::int16_t>(
                    static_cast<std::uint16_t>(
                        reg_read(m, Machine::kEax, 2)));
                const int divisor = static_cast<std::int8_t>(
                    static_cast<std::uint8_t>(a));
                const int q = dividend / divisor;
                if (q > 0x7F || q < -0x80) {
                    if (loop_fault != nullptr) {
                        *loop_fault = "integer divide overflow";
                    }
                    return false;
                }
                reg_write(m, Machine::kEax,
                          static_cast<std::uint32_t>(
                              (q & 0xFF) |
                              ((dividend % divisor) << 8)), 2);
                break;
            }
            default: break;
            }
            machine.eip = machine.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0xF7: {  // group3, 32-bit: test/not/neg/mul/imul/div/idiv
            if (op16) {
                if (loop_fault != nullptr) {
                    *loop_fault = "66-prefixed group3 is not modeled";
                }
                return false;
            }
            const ModRm r = decode_modrm(m, mem, c, i);
            const std::uint32_t a = rm_read(m, mem, r, 4);
            std::uint32_t v = a;
            switch (r.reg) {
            case 0: case 1: {  // test
                std::uint32_t imm = 0;
                std::memcpy(&imm, c + i, 4);
                i += 4;
                logic_flags(m, a & imm, 4);
                break;
            }
            case 2:  // not
                v = ~a;
                rm_write(m, mem, r, v, 4);
                break;
            case 3:  // neg
                v = 0 - a;
                sub_flags(m, 0, a, v, 4);
                rm_write(m, mem, r, v, 4);
                break;
            case 4: {  // mul: edx:eax = eax * rm
                const std::uint64_t p =
                    static_cast<std::uint64_t>(machine.regs[Machine::kEax]) * a;
                machine.regs[Machine::kEax] = static_cast<std::uint32_t>(p);
                machine.regs[Machine::kEdx] = static_cast<std::uint32_t>(p >> 32);
                machine.eflags &= ~(Machine::kCF | Machine::kOF);
                if (machine.regs[Machine::kEdx] != 0) {
                    machine.eflags |= Machine::kCF | Machine::kOF;
                }
                break;
            }
            case 5: {  // imul: edx:eax = signed eax * rm
                const std::int64_t p =
                    static_cast<std::int64_t>(
                        static_cast<std::int32_t>(machine.regs[Machine::kEax])) *
                    static_cast<std::int64_t>(static_cast<std::int32_t>(a));
                machine.regs[Machine::kEax] = static_cast<std::uint32_t>(p);
                machine.regs[Machine::kEdx] = static_cast<std::uint32_t>(
                    static_cast<std::uint64_t>(p) >> 32);
                machine.eflags &= ~(Machine::kCF | Machine::kOF);
                if (p != static_cast<std::int64_t>(
                             static_cast<std::int32_t>(p))) {
                    machine.eflags |= Machine::kCF | Machine::kOF;
                }
                break;
            }
            case 6: {  // div
                const std::uint64_t dividend =
                    (static_cast<std::uint64_t>(machine.regs[Machine::kEdx]) << 32) |
                    machine.regs[Machine::kEax];
                if (a == 0) {
                    if (loop_fault != nullptr) {
                        *loop_fault = "divide by zero";
                    }
                    return false;
                }
                const std::uint64_t q = dividend / a;
                if (q > 0xFFFFFFFFULL) {
                    if (loop_fault != nullptr) {
                        *loop_fault = "divide overflow";
                    }
                    return false;
                }
                machine.regs[Machine::kEax] = static_cast<std::uint32_t>(q);
                machine.regs[Machine::kEdx] =
                    static_cast<std::uint32_t>(dividend % a);
                break;
            }
            case 7: {  // idiv
                const std::int64_t dividend =
                    (static_cast<std::int64_t>(
                         static_cast<std::uint32_t>(machine.regs[Machine::kEdx]))
                     << 32) |
                    machine.regs[Machine::kEax];
                const std::int32_t divisor = static_cast<std::int32_t>(a);
                if (divisor == 0) {
                    if (loop_fault != nullptr) {
                        *loop_fault = "integer divide by zero";
                    }
                    return false;
                }
                const std::int64_t q = dividend / divisor;
                if (q != static_cast<std::int64_t>(
                             static_cast<std::int32_t>(q))) {
                    if (loop_fault != nullptr) {
                        *loop_fault = "integer divide overflow";
                    }
                    return false;
                }
                machine.regs[Machine::kEax] = static_cast<std::uint32_t>(
                    static_cast<std::int32_t>(q));
                machine.regs[Machine::kEdx] = static_cast<std::uint32_t>(
                    static_cast<std::int32_t>(dividend % divisor));
                break;
            }
            default: break;
            }
            machine.eip = machine.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0x69: case 0x6B: {  // imul r, rm, imm
            const ModRm r = decode_modrm(m, mem, c, i);
            const unsigned wide = opsz;
            const std::uint32_t src = rm_read(m, mem, r, wide);
            std::uint32_t imm = 0;
            if (op == 0x6B) {
                std::int8_t imm8 = 0;
                std::memcpy(&imm8, c + i, 1);
                imm = static_cast<std::uint32_t>(
                    static_cast<std::int32_t>(imm8));
                i += 1;
            } else {
                std::memcpy(&imm, c + i, wide);
                i += wide;
            }
            const std::int64_t p =
                static_cast<std::int64_t>(static_cast<std::int32_t>(src)) *
                static_cast<std::int64_t>(static_cast<std::int32_t>(imm));
            reg_write(m, r.reg, static_cast<std::uint32_t>(p), wide);
            machine.eflags &= ~(Machine::kCF | Machine::kOF);
            const std::int64_t truncated =
                wide == 2
                    ? static_cast<std::int64_t>(
                          static_cast<std::int16_t>(
                              static_cast<std::uint16_t>(p)))
                    : static_cast<std::int64_t>(
                          static_cast<std::int32_t>(p));
            if (p != truncated) {
                machine.eflags |= Machine::kCF | Machine::kOF;
            }
            machine.eip = machine.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0x0F: {  // two-byte opcodes the subset carries
            const std::uint8_t op2 = c[i++];
            if (op2 == 0xAF) {  // imul r, rm
                const ModRm r = decode_modrm(m, mem, c, i);
                const unsigned wide = opsz;
                const std::int64_t p =
                    static_cast<std::int64_t>(static_cast<std::int32_t>(
                        reg_read(m, r.reg, wide))) *
                    static_cast<std::int64_t>(static_cast<std::int32_t>(
                        rm_read(m, mem, r, wide)));
                reg_write(m, r.reg, static_cast<std::uint32_t>(p), wide);
                machine.eflags &= ~(Machine::kCF | Machine::kOF);
                const std::int64_t truncated =
                    wide == 2
                        ? static_cast<std::int64_t>(
                              static_cast<std::int16_t>(
                                  static_cast<std::uint16_t>(p)))
                        : static_cast<std::int64_t>(
                              static_cast<std::int32_t>(p));
                if (p != truncated) {
                    machine.eflags |= Machine::kCF | Machine::kOF;
                }
                machine.eip = machine.eip + static_cast<std::uint32_t>(i);
            } else if (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE ||
                       op2 == 0xBF) {  // movzx / movsx
                const ModRm r = decode_modrm(m, mem, c, i);
                // The source width is the opcode's own choice: B6/BE
                // read a byte, B7/BF a word -- the 66 prefix narrows the
                // destination, never widens the source. Reading a dword
                // here fed GetSectionCount's movzwl past NumberOfSections
                // into the following bytes, and the garbage became a
                // chkstk allocation the probe would walk for gigabytes.
                const unsigned src_w = (op2 & 1) != 0 ? 2u : 1u;
                const bool sign = (op2 & 8) != 0;
                std::uint32_t v = 0;
                if (src_w == 4) {
                    v = rm_read(m, mem, r, 4);
                } else if (src_w == 2) {
                    const std::uint32_t half = rm_read(m, mem, r, 2) & 0xFFFF;
                    v = sign && (half & 0x8000) != 0 ? half | 0xFFFF0000
                                                     : half;
                } else {
                    const std::uint32_t byte = rm_read(m, mem, r, 1) & 0xFF;
                    v = sign && (byte & 0x80) != 0 ? byte | 0xFFFFFF00 : byte;
                }
                reg_write(m, r.reg, v, opsz);
                machine.eip = machine.eip + static_cast<std::uint32_t>(i);
            } else if (op2 == 0xB0 || op2 == 0xB1) {  // cmpxchg rm, r
                const unsigned wide = (op2 & 1) != 0 ? opsz : 1u;
                const ModRm r = decode_modrm(m, mem, c, i);
                const std::uint32_t dst = rm_read(m, mem, r, wide);
                const std::uint32_t src = reg_read(m, r.reg, wide);
                const std::uint32_t acc = reg_read(m, Machine::kEax, wide);
                sub_flags(m, acc, dst, acc - dst, wide);
                if ((machine.eflags & Machine::kZF) != 0) {
                    rm_write(m, mem, r, src, wide);
                } else {
                    reg_write(m, Machine::kEax, dst, wide);
                }
                machine.eip = machine.eip + static_cast<std::uint32_t>(i);
            } else if (op2 == 0xC0 || op2 == 0xC1) {  // xadd rm, r
                const unsigned wide = (op2 & 1) != 0 ? opsz : 1u;
                const ModRm r = decode_modrm(m, mem, c, i);
                const std::uint32_t dst = rm_read(m, mem, r, wide);
                const std::uint32_t src = reg_read(m, r.reg, wide);
                add_flags(m, dst, src, dst + src, wide);
                rm_write(m, mem, r, dst + src, wide);
                reg_write(m, r.reg, dst, wide);
                machine.eip = machine.eip + static_cast<std::uint32_t>(i);
            } else if ((op2 & 0xF0) == 0x80) {  // jcc rel32
                std::int32_t rel = 0;
                std::memcpy(&rel, c + i, 4);
                const std::uint32_t next = machine.eip + 2 + 4;
                const std::uint8_t cc = op2 & 0xF;
                const bool zf = (machine.eflags & Machine::kZF) != 0;
                const bool cf = (machine.eflags & Machine::kCF) != 0;
                const bool sf = (machine.eflags & Machine::kSF) != 0;
                const bool of = (machine.eflags & Machine::kOF) != 0;
                bool taken = false;
                // The condition codes, in the encoding every branch
                // family shares: 0 carry, 2 zero, 6 sign-equals-overflow
                // ... -- the table the setcc branch below uses too, which
                // is the table the first version here did not: its cc=4
                // answered carry-or-zero where the file asked for zero,
                // and the CRT's every long conditional jump went wherever
                // the wrong predicate pointed.
                const bool pf_flag = (machine.eflags & Machine::kPF) != 0;
                switch (cc) {
                case 0x0: taken = of; break;
                case 0x1: taken = !of; break;
                case 0x2: taken = cf; break;
                case 0x3: taken = !cf; break;
                case 0x4: taken = zf; break;
                case 0x5: taken = !zf; break;
                case 0x6: taken = cf || zf; break;
                case 0x7: taken = !cf && !zf; break;
                case 0x8: taken = sf; break;
                case 0x9: taken = !sf; break;
                case 0xA: taken = pf_flag; break;
                case 0xB: taken = !pf_flag; break;
                case 0xC: taken = sf != of; break;
                case 0xD: taken = sf == of; break;
                case 0xE: taken = zf || (sf != of); break;
                case 0xF: taken = !zf && (sf == of); break;
                }
                if (trace) {
                    std::fprintf(stderr,
                                 "occ i386:   jcc cc=%x zf=%d cf=%d "
                                 "taken=%d -> 0x%x\n",
                                 cc, zf ? 1 : 0, cf ? 1 : 0, taken ? 1 : 0,
                                 machine.eip);
                }
                machine.eip = taken ? next + static_cast<std::uint32_t>(rel) : next;
            } else if ((op2 & 0xF0) == 0x90) {  // setcc rm8
                const ModRm r = decode_modrm(m, mem, c, i);
                const std::uint8_t cc = op2 & 0xF;
                const bool zf = (machine.eflags & Machine::kZF) != 0;
                const bool cf = (machine.eflags & Machine::kCF) != 0;
                const bool sf = (machine.eflags & Machine::kSF) != 0;
                const bool of = (machine.eflags & Machine::kOF) != 0;
                bool taken = false;
                switch (cc) {
                case 0x4: taken = zf; break;
                case 0x5: taken = !zf; break;
                case 0x6: taken = cf || zf; break;
                case 0x7: taken = !cf && !zf; break;
                case 0x8: taken = sf; break;
                case 0x9: taken = !sf; break;
                case 0xC: taken = sf != of; break;
                case 0xD: taken = sf == of; break;
                case 0xE: taken = zf || (sf != of); break;
                case 0xF: taken = !zf && (sf == of); break;
                default: break;
                }
                rm_write(m, mem, r, taken ? 1 : 0, 1);
                machine.eip = machine.eip + static_cast<std::uint32_t>(i);
            } else if (op2 == 0x05 || op2 == 0x34 || op2 == 0x35) {
                // syscall / sysenter / sysexit: not part of the model
                if (loop_fault != nullptr) {
                    *loop_fault = "0f 0x" + std::to_string(op2);
                }
                return false;
            } else {
                if (loop_fault != nullptr) {
                    char hex[8];
                    std::snprintf(hex, sizeof(hex), "%02x", op2);
                    *loop_fault = std::string("unimplemented 0f ") + hex;
                }
                return false;
            }
            break;
        }
        case 0xF3: case 0xF2: {  // a repeat prefix with no string op: rep stos/movs
            if (loop_fault != nullptr) {
                *loop_fault = "string op without its prefix handled";
            }
            return false;
        }
        case 0x86: case 0x87: {  // xchg rm, r
            const unsigned wide = (op & 1) != 0 ? opsz : 1u;
            const ModRm r = decode_modrm(m, mem, c, i);
            const std::uint32_t a = rm_read(m, mem, r, wide);
            const std::uint32_t b = reg_read(m, r.reg, wide);
            rm_write(m, mem, r, b, wide);
            reg_write(m, r.reg, a, wide);
            machine.eip = machine.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0x91: case 0x92: case 0x93: case 0x94:
        case 0x95: case 0x96: case 0x97: {  // xchg eax, r
            const std::uint32_t t = reg_read(m, 0, opsz);
            reg_write(m, 0, reg_read(m, op - 0x90, opsz), opsz);
            reg_write(m, op - 0x90, t, opsz);
            break;
        }
        case 0xAA: case 0xAB: {  // stos
            const unsigned wide = (op & 1) != 0 ? opsz : 1u;
            std::uint32_t count = rep ? machine.regs[Machine::kEcx] : 1;
            const std::uint32_t step = wide;
            const std::uint32_t v = reg_read(m, Machine::kEax, wide);
            const bool up = (machine.eflags & Machine::kDF) == 0;
            while (count != 0) {
                if (wide == 4) {
                    memory.write32(machine.regs[Machine::kEdi], v);
                } else {
                    memory.write(machine.regs[Machine::kEdi], &v, wide);
                }
                machine.regs[Machine::kEdi] += up ? step : (0u - step);
                --count;
            }
            if (rep) {
                machine.regs[Machine::kEcx] = 0;
            }
            break;
        }
        case 0xA4: case 0xA5: {  // movs
            const unsigned wide = (op & 1) != 0 ? opsz : 1u;
            std::uint32_t count = rep ? machine.regs[Machine::kEcx] : 1;
            const std::uint32_t step = wide;
            const bool up = (machine.eflags & Machine::kDF) == 0;
            while (count != 0) {
                std::uint32_t val = 0;
                memory.read(machine.regs[Machine::kEsi], &val, wide);
                memory.write(machine.regs[Machine::kEdi], &val, wide);
                machine.regs[Machine::kEsi] += up ? step : (0u - step);
                machine.regs[Machine::kEdi] += up ? step : (0u - step);
                --count;
            }
            if (rep) {
                machine.regs[Machine::kEcx] = 0;
            }
            break;
        }
        case 0xDB: {  // FPU escape: fninit is the one the CRT runs
            if (i + 1 < code.size() && c[i] == 0xE3) {
                ++i;  // fninit: the integer model has no FPU state
                machine.eip = machine.eip + static_cast<std::uint32_t>(i);
                break;
            }
            if (loop_fault != nullptr) {
                *loop_fault = "fpu escape db";
            }
            return false;
        }
        case 0x9B:  // fwait: nothing to wait for
        case 0xF4: {  // hlt: treated as an orderly stop
            machine.halted = true;
            return true;
        }
        default:
            if (loop_fault != nullptr) {
                char hex[16];
                std::snprintf(hex, sizeof(hex), "%02x", op);
                char eip_hex[12];
                std::snprintf(eip_hex, sizeof(eip_hex), "%x",
                              machine.eip);
                *loop_fault = std::string("unimplemented opcode 0x") +
                              hex + " at eip 0x" + eip_hex;
            }
            return false;
        }
        }
        return true;
    };
    // The executor is published before the machine runs: the host calls
    // that arrive while it runs -- the global-constructor walk, atexit --
    // are exactly the callers, and a run that publishes only after it
    // returns publishes for nobody.
    s_exec_fn = [](void* ctx, Machine& machine, Memory& memory,
                   std::uint32_t func, std::uint32_t a1,
                   std::uint32_t a2, std::uint64_t budget,
                   std::string* loop_fault) -> bool {
        auto* fn = static_cast<std::function<bool(
            Machine&, Memory&, std::uint32_t, std::uint32_t,
            std::uint32_t, std::uint64_t, std::string*)>*>(ctx);
        return (*fn)(machine, memory, func, a1, a2, budget, loop_fault);
    };
    s_exec_ctx = &exec_fn;
    return exec_fn(m, mem, 0, 0, 0, step_budget, fault_detail);
}

void note_magic(std::uint32_t address, const std::string& dll,
                const std::string& name) {
    magic_to_api[address] = {dll, name};
}

bool call_guest(Machine& m, Memory& mem, std::uint32_t func,
                std::uint32_t a1, std::uint32_t a2, std::uint64_t budget,
                std::string* fault_detail) {
    if (s_exec_fn == nullptr) {
        if (fault_detail != nullptr) {
            *fault_detail = "no run is active to call the guest from";
        }
        return false;
    }
    return s_exec_fn(s_exec_ctx, m, mem, func, a1, a2, budget, fault_detail);
}

}  // namespace occ::runtime::i386

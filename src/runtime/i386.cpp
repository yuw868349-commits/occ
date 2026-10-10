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
void set_szp(Machine& m, std::uint32_t result) {
    m.eflags &= ~(Machine::kZF | Machine::kSF | Machine::kPF);
    if (result == 0) {
        m.eflags |= Machine::kZF;
    }
    if ((result & 0x80000000) != 0) {
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
               std::uint32_t result) {
    m.eflags &= ~(Machine::kCF | Machine::kOF | Machine::kAF);
    if (result < a) {
        m.eflags |= Machine::kCF;
    }
    if (((a ^ result) & (b ^ result)) & 0x80000000) {
        m.eflags |= Machine::kOF;
    }
    if (((a ^ b ^ result) & 0x10) != 0) {
        m.eflags |= Machine::kAF;
    }
    set_szp(m, result);
}

void sub_flags(Machine& m, std::uint32_t a, std::uint32_t b,
               std::uint32_t result) {
    m.eflags &= ~(Machine::kCF | Machine::kOF | Machine::kAF);
    if (a < b) {
        m.eflags |= Machine::kCF;
    }
    if (((a ^ b) & (a ^ result)) & 0x80000000) {
        m.eflags |= Machine::kOF;
    }
    if (((a ^ b ^ result) & 0x10) != 0) {
        m.eflags |= Machine::kAF;
    }
    set_szp(m, result);
}

void logic_flags(Machine& m, std::uint32_t result) {
    m.eflags &= ~(Machine::kCF | Machine::kOF | Machine::kAF);
    set_szp(m, result);
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
    switch (r.rm) {
    case 0: effective = m.regs[Machine::kEax] + m.regs[Machine::kEsi]; break;
    case 1: effective = m.regs[Machine::kEcx] + m.regs[Machine::kEdi]; break;
    case 2: effective = m.regs[Machine::kEdx] + m.regs[Machine::kEsi]; break;
    case 3: effective = m.regs[Machine::kEbx] + m.regs[Machine::kEdi]; break;
    case 4: {  // SIB
        const std::uint8_t sib = code[i++];
        const std::uint32_t scale = 1u << (sib >> 6);
        const std::uint8_t index = (sib >> 3) & 7;
        const std::uint8_t base = sib & 7;
        effective = base == 5 ? 0u : m.regs[base];
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
                                    const ModRm& r, bool wide) {
    if (r.is_register) {
        return wide ? m.regs[r.rm]
                    : (m.regs[r.rm] & 0xFF) | ((m.regs[r.rm] >> 8) & 0xFF00);
    }
    if (wide) {
        return mem.read32(r.address);
    }
    std::uint32_t v = 0;
    mem.read(r.address, &v, 1);
    return v;
}

void rm_write(Machine& m, Memory& mem, const ModRm& r, std::uint32_t v,
              bool wide) {
    if (r.is_register) {
        if (wide) {
            m.regs[r.rm] = v;
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
    if (wide) {
        mem.write32(r.address, v);
    } else {
        mem.write8(r.address, static_cast<std::uint8_t>(v));
    }
}

[[nodiscard]] std::uint32_t reg_read(Machine& m, std::uint8_t reg,
                                     bool wide) {
    if (wide) {
        return m.regs[reg];
    }
    return reg < 4 ? ((m.regs[reg] & 0xFF) | ((m.regs[reg] >> 8) & 0xFF00))
                   : ((m.regs[reg & 3] >> ((reg - 4) * 8)) & 0xFF);
}

void reg_write(Machine& m, std::uint8_t reg, std::uint32_t v, bool wide) {
    if (wide) {
        m.regs[reg] = v;
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

// -------------------------------------------------------------------- run

bool run(const std::uint8_t* image_bytes, std::size_t bytes,
         const std::string& image_path,
         bool (*resolve)(void*, const char*, const char*), void* resolve_state,
         HostCall host_call, void* host_call_state, Machine& m,
         std::uint64_t step_budget, std::string* fault_detail) {
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

    // The import table resolves to magic addresses -- one per (dll, name),
    // issued from a counter in the 0x70000000 range, which is a range the
    // image has no reason to touch and the interpreter can test in one
    // comparison. The map from address back to the pair lives for the run.
    std::unordered_map<std::uint32_t, std::pair<std::string, std::string>>
        magic_to_api;
    std::unordered_map<std::string, std::uint32_t> api_to_magic;
    std::uint32_t next_magic = 0x70000000;
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
                            mem.write32(image_base + thunk,
                                        api_to_magic.at(key));
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
    std::uint64_t steps = 0;
    while (!m.halted) {
        if (steps++ >= step_budget) {
            if (fault_detail != nullptr) {
                *fault_detail = "the step budget ran out";
            }
            return false;
        }
        mem.read(m.eip, code.data(), code.size());
        const std::uint8_t* c = code.data();
        std::size_t i = 0;
        bool wide = true;      // operand size prefix: 66 clears it
        bool rep = false;
        std::uint32_t segment_base = 0;  // fs/gs prefixes land here
        (void)wide;
        (void)rep;
        (void)segment_base;
        // Prefixes, before any opcode.
        for (;;) {
            if (c[i] == 0x66) {
                wide = false;
                ++i;
            } else if (c[i] == 0x67 || c[i] == 0x2E || c[i] == 0x3E ||
                       c[i] == 0x64 || c[i] == 0x65 || c[i] == 0x36) {
                ++i;  // accepted and, for fs/gs, ignored: the subset has
                      // no segment-carrying data structures yet
            } else if (c[i] == 0xF3 || c[i] == 0xF2) {
                rep = true;
                ++i;
            } else {
                break;
            }
        }
        const std::uint8_t op = c[i++];
        const std::uint32_t rip_after = m.eip + static_cast<std::uint32_t>(i);
        if (trace) {
            std::fprintf(stderr, "occ i386: eip 0x%08x op %02x\n",
                         static_cast<unsigned>(m.eip),
                         static_cast<unsigned>(op));
        }

        switch (op) {
        case 0x90:  // nop
            m.eip = rip_after;
            break;
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57: {  // push r32
            m.regs[Machine::kEsp] -= 4;
            mem.write32(m.regs[Machine::kEsp], m.regs[op - 0x50]);
            m.eip = rip_after;
            break;
        }
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F: {  // pop r32
            m.regs[op - 0x58] = mem.read32(m.regs[Machine::kEsp]);
            m.regs[Machine::kEsp] += 4;
            m.eip = rip_after;
            break;
        }
        case 0x68: {  // push imm32
            std::uint32_t imm = 0;
            std::memcpy(&imm, c + i, 4);
            i += 4;
            m.regs[Machine::kEsp] -= 4;
            mem.write32(m.regs[Machine::kEsp], imm);
            m.eip = rip_after + 4;
            break;
        }
        case 0x6A: {  // push imm8 sign-extended
            std::int8_t imm8 = 0;
            std::memcpy(&imm8, c + i, 1);
            m.regs[Machine::kEsp] -= 4;
            mem.write32(m.regs[Machine::kEsp],
                        static_cast<std::uint32_t>(
                            static_cast<std::int32_t>(imm8)));
            m.eip = rip_after + 1;
            break;
        }
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF: {  // mov r32, imm32
            std::uint32_t imm = 0;
            std::memcpy(&imm, c + i, 4);
            m.regs[op - 0xB8] = imm;
            m.eip = rip_after + 4;
            break;
        }
        case 0x88: case 0x89: {  // mov rm, r8 / mov rm, r32
            const ModRm r = decode_modrm(m, mem, c, i);
            rm_write(m, mem, r, reg_read(m, r.reg, op == 0x89), op == 0x89);
            m.eip = m.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0x8A: case 0x8B: {  // mov r, rm
            const ModRm r = decode_modrm(m, mem, c, i);
            reg_write(m, r.reg, rm_read(m, mem, r, op == 0x8B), op == 0x8B);
            m.eip = m.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0x8D: {  // lea r, m
            const ModRm r = decode_modrm(m, mem, c, i);
            if (r.is_register) {
                if (fault_detail != nullptr) {
                    *fault_detail = "lea with a register operand";
                }
                return false;
            }
            m.regs[r.reg] = r.address;
            m.eip = m.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0xC7: {  // mov rm, imm32
            const ModRm r = decode_modrm(m, mem, c, i);
            std::uint32_t imm = 0;
            std::memcpy(&imm, c + i, 4);
            i += 4;
            rm_write(m, mem, r, imm, true);
            m.eip = m.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0x00: case 0x01: {  // add rm, r
            const ModRm r = decode_modrm(m, mem, c, i);
            const std::uint32_t a = rm_read(m, mem, r, op == 0x01);
            const std::uint32_t b = reg_read(m, r.reg, op == 0x01);
            const std::uint32_t sum = a + b;
            add_flags(m, a, b, sum);
            rm_write(m, mem, r, sum, op == 0x01);
            m.eip = m.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0x28: case 0x29: {  // sub rm, r
            const ModRm r = decode_modrm(m, mem, c, i);
            const std::uint32_t a = rm_read(m, mem, r, op == 0x29);
            const std::uint32_t b = reg_read(m, r.reg, op == 0x29);
            const std::uint32_t diff = a - b;
            sub_flags(m, a, b, diff);
            rm_write(m, mem, r, diff, op == 0x29);
            m.eip = m.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0x30: case 0x31: {  // xor
            const ModRm r = decode_modrm(m, mem, c, i);
            const std::uint32_t v = rm_read(m, mem, r, op == 0x31) ^
                                    reg_read(m, r.reg, op == 0x31);
            logic_flags(m, v);
            rm_write(m, mem, r, v, op == 0x31);
            m.eip = m.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0x20: case 0x21: {  // and
            const ModRm r = decode_modrm(m, mem, c, i);
            const std::uint32_t v = rm_read(m, mem, r, op == 0x21) &
                                    reg_read(m, r.reg, op == 0x21);
            logic_flags(m, v);
            rm_write(m, mem, r, v, op == 0x21);
            m.eip = m.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0x08: case 0x09: {  // or
            const ModRm r = decode_modrm(m, mem, c, i);
            const std::uint32_t v = rm_read(m, mem, r, op == 0x09) |
                                    reg_read(m, r.reg, op == 0x09);
            logic_flags(m, v);
            rm_write(m, mem, r, v, op == 0x09);
            m.eip = m.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0x38: case 0x39: {  // cmp rm, r
            const ModRm r = decode_modrm(m, mem, c, i);
            const std::uint32_t a = rm_read(m, mem, r, op == 0x39);
            sub_flags(m, a, reg_read(m, r.reg, op == 0x39),
                      a - reg_read(m, r.reg, op == 0x39));
            m.eip = m.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0x84: case 0x85: {  // test
            const ModRm r = decode_modrm(m, mem, c, i);
            logic_flags(m, rm_read(m, mem, r, op == 0x85) &
                               reg_read(m, r.reg, op == 0x85));
            m.eip = m.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0x80: case 0x81: case 0x83: {  // group1 rm, imm
            const ModRm r = decode_modrm(m, mem, c, i);
            const std::uint8_t sub = r.reg;
            std::uint32_t imm = 0;
            if (op == 0x83) {
                std::int8_t imm8 = 0;
                std::memcpy(&imm8, c + i, 1);
                imm = static_cast<std::uint32_t>(
                    static_cast<std::int32_t>(imm8));
                i += 1;
            } else if (op == 0x81) {
                std::memcpy(&imm, c + i, 4);
                i += 4;
            } else {
                imm = c[i];
                i += 1;
            }
            const std::uint32_t a = rm_read(m, mem, r, true);
            std::uint32_t v = a;
            switch (sub) {
            case 0: v = a + imm; add_flags(m, a, imm, v); break;
            case 1: v = a | imm; logic_flags(m, v); break;
            case 4: v = a & imm; logic_flags(m, v); break;
            case 5: v = a - imm; sub_flags(m, a, imm, v); break;
            case 6: v = a ^ imm; logic_flags(m, v); break;
            case 7: sub_flags(m, a, imm, a - imm); break;
            default:
                if (fault_detail != nullptr) {
                    *fault_detail = "group1 op " + std::to_string(sub);
                }
                return false;
            }
            if (sub != 7) {
                rm_write(m, mem, r, v, true);
            }
            m.eip = m.eip + static_cast<std::uint32_t>(i);
            break;
        }
        case 0xE8: {  // call rel32
            std::int32_t rel = 0;
            std::memcpy(&rel, c + i, 4);
            const std::uint32_t target =
                rip_after + 4 + static_cast<std::uint32_t>(rel);
            m.regs[Machine::kEsp] -= 4;
            mem.write32(m.regs[Machine::kEsp], rip_after + 4);
            // The magic range: a call into an address the loader filled is
            // the host-call seam, entered the same way the guest entered
            // every call -- through this switch, with the machine as it is.
            if (target >= 0x70000000 && target < 0x71000000) {
                const auto& api = magic_to_api.at(target);
                if (!host_call(host_call_state, api.first.c_str(),
                               api.second.c_str(), m, mem)) {
                    if (fault_detail != nullptr) {
                        *fault_detail = "unhosted call " + api.first + "!" +
                                        api.second;
                    }
                    return false;
                }
                if (m.halted) {
                    return true;
                }
                m.eip = mem.read32(m.regs[Machine::kEsp]);
                m.regs[Machine::kEsp] += 4;
            } else {
                m.eip = target;
            }
            break;
        }
        case 0xC3: {  // ret
            m.eip = mem.read32(m.regs[Machine::kEsp]);
            m.regs[Machine::kEsp] += 4;
            break;
        }
        case 0xE9: {  // jmp rel32
            std::int32_t rel = 0;
            std::memcpy(&rel, c + i, 4);
            m.eip = rip_after + 4 + static_cast<std::uint32_t>(rel);
            break;
        }
        case 0xEB: {  // jmp rel8
            std::int8_t rel = 0;
            std::memcpy(&rel, c + i, 1);
            m.eip = rip_after + 1 + static_cast<std::uint32_t>(static_cast<std::int32_t>(rel));
            break;
        }
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7C: case 0x7D:
        case 0x7E: case 0x7F: {  // jcc rel8
            std::int8_t rel = 0;
            std::memcpy(&rel, c + i, 1);
            bool taken = false;
            switch (op) {
            case 0x74: taken = (m.eflags & Machine::kZF) != 0; break;
            case 0x75: taken = (m.eflags & Machine::kZF) == 0; break;
            case 0x76: taken = (m.eflags & Machine::kCF) != 0 ||
                               (m.eflags & Machine::kZF) != 0; break;
            case 0x77: taken = (m.eflags & Machine::kCF) == 0 &&
                               (m.eflags & Machine::kZF) == 0; break;
            case 0x78: taken = (m.eflags & Machine::kSF) != 0; break;
            case 0x79: taken = (m.eflags & Machine::kSF) == 0; break;
            case 0x7C: taken = (m.eflags & Machine::kSF) !=
                               (m.eflags & Machine::kOF); break;
            case 0x7D: taken = (m.eflags & Machine::kSF) ==
                               (m.eflags & Machine::kOF); break;
            case 0x7E: taken = (m.eflags & Machine::kZF) != 0 ||
                               (m.eflags & Machine::kSF) !=
                                   (m.eflags & Machine::kOF); break;
            case 0x7F: taken = (m.eflags & Machine::kZF) == 0 &&
                               (m.eflags & Machine::kSF) ==
                                   (m.eflags & Machine::kOF); break;
            }
            if (taken) {
                m.eip = rip_after + 1 + static_cast<std::uint32_t>(static_cast<std::int32_t>(rel));
            } else {
                m.eip = rip_after + 1;
            }
            break;
        }
        case 0xC9: {  // leave
            m.regs[Machine::kEsp] = m.regs[Machine::kEbp];
            m.regs[Machine::kEbp] = mem.read32(m.regs[Machine::kEsp]);
            m.regs[Machine::kEsp] += 4;
            break;
        }
        case 0xCC: {  // int3: the guest's own trap becomes a stop
            if (fault_detail != nullptr) {
                *fault_detail = "int3 at guest eip";
            }
            return false;
        }
        case 0xA1: {  // mov eax, moffs32
            std::uint32_t addr = 0;
            std::memcpy(&addr, c + i, 4);
            m.regs[Machine::kEax] = mem.read32(addr);
            if (trace) {
                std::fprintf(stderr,
                             "occ i386:   mov eax,[0x%x] = 0x%x\n", addr,
                             m.regs[Machine::kEax]);
            }
            m.eip = rip_after + 4;
            break;
        }
        case 0xA3: {  // mov moffs32, eax
            std::uint32_t addr = 0;
            std::memcpy(&addr, c + i, 4);
            mem.write32(addr, m.regs[Machine::kEax]);
            m.eip = rip_after + 4;
            break;
        }
        case 0xFF: {  // group5: the indirect call and jump
            const ModRm r = decode_modrm(m, mem, c, i);
            const std::uint8_t sub = r.reg;
            const std::uint32_t target = rm_read(m, mem, r, true);
            if (sub == 2) {  // call rm32
                const std::uint32_t return_to =
                    m.eip + static_cast<std::uint32_t>(i);
                if (target >= 0x70000000 && target < 0x71000000) {
                    // The seam: an address the loader filled with a magic
                    // is the host's, entered exactly as a real call
                    // enters it -- the return address pushed, the
                    // arguments where the convention put them -- and
                    // left by the convention the host names in
                    // `esp_adjust`.
                    m.regs[Machine::kEsp] -= 4;
                    mem.write32(m.regs[Machine::kEsp], return_to);
                    const auto& api = magic_to_api.at(target);
                    m.esp_adjust = 0;
                    if (!host_call(host_call_state, api.first.c_str(),
                                   api.second.c_str(), m, mem)) {
                        if (fault_detail != nullptr) {
                            *fault_detail = "unhosted call " + api.first +
                                            "!" + api.second;
                        }
                        return false;
                    }
                    if (m.halted) {
                        return true;
                    }
                    // The return of a stdcall call: pop the return
                    // address first, then the bytes the callee removed
                    // -- in that order, because the other order turns
                    // the last argument into the return address, which
                    // is exactly what the first console run did.
                    m.eip = mem.read32(m.regs[Machine::kEsp]);
                    m.regs[Machine::kEsp] +=
                        4 + m.esp_adjust;
                } else {
                    m.regs[Machine::kEsp] -= 4;
                    mem.write32(m.regs[Machine::kEsp], return_to);
                    m.eip = target;
                }
            } else if (sub == 4) {  // jmp rm32
                if (target >= 0x70000000 && target < 0x71000000) {
                    if (fault_detail != nullptr) {
                        *fault_detail = "a jump through an import";
                    }
                    return false;
                }
                m.eip = target;
            } else {
                if (fault_detail != nullptr) {
                    *fault_detail = "group5 op " + std::to_string(sub);
                }
                return false;
            }
            break;
        }
        case 0xF4: {  // hlt: treated as an orderly stop
            m.halted = true;
            return true;
        }
        default:
            if (fault_detail != nullptr) {
                char hex[16];
                std::snprintf(hex, sizeof(hex), "%02x", op);
                *fault_detail = std::string("unimplemented opcode 0x") +
                                hex + " at eip 0x" +
                                std::to_string(m.eip);
            }
            return false;
        }
    }
    return true;
}

}  // namespace occ::runtime::i386

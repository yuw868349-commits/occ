// occ devirt — the offline VM de-virtualizer, as a native command.
//
// Consumes the JSON-lines VM trace (`OCC_VM_TRACE`, kind=dispatch) and the
// decrypted image dump (`.vmf`), and reassembles the virtual instruction
// stream the VM engine executed: handler semantics (via objdump over the
// handler bytes), the API calls it makes (named from the `.api` map the
// runtime dumps next to the image), control flow, and an assembly-like
// listing.
//
// Each dispatch row carries the word the dispatcher read out of its
// handler table. Two VM families write that word two ways and the trace
// does not distinguish them, so the image decides (lift::resolve_handler):
//   * a hand-rolled VM stores the handler's address directly;
//   * VMP 3 stores it rotated left by ten and rotates it back before the
//     jump -- `dispatch: mov rcx,[r12+rax*8]` at 0x6b2a, then
//     `decrypt: cmc;cmc; rol rcx,0xa; jmp rcx` at 0x8851.
// A handler is a junk-wrapped micro-program on the virtual state:
// rbp = virtual stack pointer, rsi = bytecode cursor. The trace records
// the virtual stack at every dispatch (st0/st1/st2) and the cursor, so a
// call is visible as the guest's own API address in the stack slots.

#include "occ/commands.h"
#include "occ/devirt/lift.h"
#include "occ/devirt/solve.h"
#include "occ/inspect/disasm.h"
#include "occ/parser/pe.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace occ::devirt {

namespace {

// ---------------------------------------------------------------- trace

struct Row {
    std::uint64_t seq = 0;
    std::uint64_t rsi = 0;   // bytecode cursor
    std::uint64_t rbp = 0;   // virtual stack pointer
    std::uint64_t rdi = 0;   // the engine's stack base
    std::uint64_t rsp = 0;
    std::uint64_t r12 = 0;   // the handler table base the dispatcher indexes
    std::uint64_t st0 = 0;   // virtual stack top
    std::uint64_t st1 = 0;
    std::uint64_t st2 = 0;
    // The rsp window and every general register, as the trace carries
    // them: both are what lets a prediction about an indexed access be
    // checked rather than counted unverifiable. The presence flags say
    // which of them this trace actually named -- an absent field and a
    // field that held zero are the same number, and only the flag tells
    // the checker which it is looking at.
    std::array<std::uint64_t, 8> rt{};
    bool rt_present = false;
    std::array<std::uint64_t, 16> gpr{};
    std::uint32_t gpr_present = 0;
    std::uint64_t word = 0;  // the value the dispatcher read from the table
    // The handler address `word` resolves to. It is computed once, against
    // the image, right after the trace loads (see resolve_rows) so every
    // later step reads the same answer instead of each re-deciding how the
    // table encodes its entries.
    std::uint64_t handler = 0;
};

std::uint64_t json_hex(std::string_view s) {
    std::uint64_t v = 0;
    const char* p = s.data();
    const char* end = p + s.size();
    if (p + 2 <= end && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
    }
    for (; p < end; ++p) {
        const char c = *p;
        v <<= 4;
        if (c >= '0' && c <= '9') {
            v |= static_cast<std::uint64_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            v |= static_cast<std::uint64_t>(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            v |= static_cast<std::uint64_t>(c - 'A' + 10);
        }
    }
    return v;
}

// Pulls "key":"value" / "key":<number> pairs out of one JSON object.
void json_fields(std::string_view line,
                 std::map<std::string, std::string>& out) {
    std::size_t i = 0;
    const std::size_t n = line.size();
    while (i < n) {
        if (line[i] == '"') {
            const std::size_t ks = ++i;
            while (i < n && line[i] != '"') {
                ++i;
            }
            const std::string key(line.substr(ks, i - ks));
            if (i < n) {
                ++i;  // the key's closing quote
            }
            while (i < n && (line[i] == ':' || line[i] == ' ' ||
                             line[i] == '\t')) {
                ++i;
            }
            if (i < n && line[i] == '"') {
                const std::size_t vs = ++i;
                while (i < n && line[i] != '"') {
                    ++i;
                }
                out[key] = std::string(line.substr(vs, i - vs));
                if (i < n) {
                    ++i;
                }
            } else {
                const std::size_t vs = i;
                while (i < n && line[i] != ',' && line[i] != '}') {
                    ++i;
                }
                out[key] = std::string(line.substr(vs, i - vs));
            }
        } else {
            ++i;
        }
    }
}

// The bytes the trace carried for pages the image dump does not hold: the
// buffer the engine decrypted its bytecode into, the register file its
// handlers index. A trace from a runtime built before the tracer carried
// them has none, and every prediction that needed one stays unverifiable --
// which is the honest reading of a trace that does not have the bytes.
lift::TraceMemory g_memory;

bool load_trace(const std::string& path, std::vector<Row>& rows) {
    std::ifstream in(path);
    if (!in) {
        std::fprintf(stderr, "devirt: cannot open trace %s\n", path.c_str());
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) {
            continue;
        }
        std::map<std::string, std::string> f;
        json_fields(line, f);
        if (f["kind"] == "memory") {
            // The bytes the tracer carried for a page no file holds. The
            // record is the window's address, its length and its bytes as
            // one hexadecimal string, which is the shape that keeps a
            // sixteen-kilobyte window a single line.
            std::vector<std::uint8_t> bytes;
            const std::string& hex = f["bytes"];
            if (hex.size() % 2 == 0) {
                bytes.reserve(hex.size() / 2);
                for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
                    const auto pair = hex.substr(i, 2);
                    bytes.push_back(static_cast<std::uint8_t>(
                        std::strtoul(pair.c_str(), nullptr, 16) & 0xffu));
                }
            }
            g_memory.add(json_hex(f["va"]), std::move(bytes));
            continue;
        }
        if (f["kind"] != "dispatch") {
            continue;
        }
        Row r;
        // `seq` is the runtime's dispatch counter, written in decimal
        // (`%llu` in the tracer); every other field is %llx and is read
        // as hex.
        r.seq = std::strtoull(f["seq"].c_str(), nullptr, 10);
        r.word = json_hex(f["target"]);
        r.rsi = json_hex(f["rsi"]);
        r.rbp = json_hex(f["rbp"]);
        r.rdi = json_hex(f["rdi"]);
        r.rsp = json_hex(f["rsp"]);
        r.r12 = json_hex(f["base"]);
        r.st0 = json_hex(f["st0"]);
        r.st1 = json_hex(f["st1"]);
        r.st2 = json_hex(f["st2"]);
        // The rsp window and the general registers, by the names the
        // trace writes them under. A trace from before the tracer carried
        // them has none, and the presence flags are what record that: a
        // field left zero by absence and a field that really held zero are
        // the same number, so the row says which of them the trace named
        // and a model that leans on an absent one stays unverifiable
        // rather than being bound to a number the trace never recorded.
        for (std::size_t i = 0; i < r.rt.size(); ++i) {
            char key[8];
            std::snprintf(key, sizeof(key), "rt%zu", i);
            const auto it = f.find(key);
            if (it != f.end()) {
                r.rt[i] = json_hex(it->second);
                r.rt_present = true;
            }
        }
        // The five registers the trace has always carried name the same
        // ones the extension does, so they seed the table first: a trace
        // from before the extension keeps working and binds exactly what
        // it used to, and a model that leans on any of the others stays
        // unverifiable rather than being bound to a number this trace
        // never recorded.
        r.gpr[4] = r.rsp;
        r.gpr[5] = r.rbp;
        r.gpr[6] = r.rsi;
        r.gpr[7] = r.rdi;
        r.gpr[12] = r.r12;
        r.gpr_present = (std::uint32_t{1} << 4) | (std::uint32_t{1} << 5) |
                        (std::uint32_t{1} << 6) | (std::uint32_t{1} << 7) |
                        (std::uint32_t{1} << 12);
        for (std::size_t i = 0; i < r.gpr.size(); ++i) {
            const auto it = f.find(lift::kRowGprNames[i]);
            if (it != f.end()) {
                r.gpr[i] = json_hex(it->second);
                r.gpr_present |= std::uint32_t{1} << i;
            }
        }
        rows.push_back(r);
    }
    return !rows.empty();
}

// ------------------------------------------------------------ API names

// The host's ASLR moves every export between runs, so the authoritative
// name map is the `.api` file the runtime dumps next to the image.
std::map<std::uint64_t, std::string> g_api;

void load_api_map(const std::string& dump_path) {
    const std::string api_path =
        dump_path.substr(0, dump_path.find_last_of('.')) + ".api";
    std::ifstream in(api_path);
    if (!in) {
        return;
    }
    std::string line;
    while (std::getline(in, line)) {
        std::map<std::string, std::string> f;
        json_fields(line, f);
        const auto addr = f.find("addr");
        const auto name = f.find("name");
        if (addr != f.end() && name != f.end()) {
            // The map is written with %llu, so the address is decimal.
            g_api[std::strtoull(addr->second.c_str(), nullptr, 10)] =
                name->second;
        }
    }
}

std::string api_name(std::uint64_t v) {
    const auto it = g_api.find(v);
    if (it != g_api.end()) {
        return it->second;
    }
    // VMP tags call operands with a prefix; strip it and look again.
    if ((v >> 56) == 0x31) {
        const auto it2 = g_api.find(v & 0xFFFFFFFFFFULL);
        if (it2 != g_api.end()) {
            return it2->second + " (tagged)";
        }
    }
    return std::string();
}

// ----------------------------------------------------------- lifting image

// The .vmf as an addressable image: the file bytes plus the PE map that
// turns the virtual addresses the trace records into offsets into them.
// The lifter decodes handlers straight from these bytes -- it does not
// need objdump for its model, only the raw encoding -- and the
// conformance check reads the bytecode bytes through the same map.
struct ImageMap {
    std::vector<std::uint8_t> bytes;
    parser::PeImage pe;
    std::uint64_t base = 0;
    bool ok = false;

    bool load(const std::string& path) {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            return false;
        }
        bytes.assign(std::istreambuf_iterator<char>(in),
                     std::istreambuf_iterator<char>());
        pe = parser::PeImage::parse(ByteSpan(bytes.data(), bytes.size()));
        if (!pe.ok()) {
            return false;
        }
        base = pe.image_base();
        ok = true;
        return true;
    }

    // The whole section that holds `va`, as a window for the lifter: the
    // handler's blocks are chained by direct jumps scattered through the
    // section, so the walk needs the section, not the handler's bytes.
    // Null when `va` is in no file-backed section.
    const std::uint8_t* window(std::uint64_t va, std::uint64_t* window_va,
                               std::size_t* available) const {
        if (!ok || va < base) {
            return nullptr;
        }
        const std::uint64_t rva = va - base;
        for (const parser::PeSection& s : pe.sections()) {
            const std::uint64_t within = rva - s.virtual_address;
            if (rva < s.virtual_address || rva >= s.virtual_end()) {
                continue;
            }
            if (within >= s.raw_size || s.raw_offset >= bytes.size()) {
                return nullptr;
            }
            const std::size_t limit =
                std::min<std::size_t>(s.raw_size,
                                      bytes.size() - s.raw_offset);
            *window_va = base + s.virtual_address;
            *available = limit;
            return bytes.data() + s.raw_offset;
        }
        return nullptr;
    }

    // Whether `va` names file-backed bytes. It is the probe `resolve_rows`
    // hands to the handler resolver: an address with bytes behind it is
    // the one the dispatcher jumped to.
    bool code_at(std::uint64_t va) const {
        std::uint64_t window_va = 0;
        std::size_t available = 0;
        return window(va, &window_va, &available) != nullptr;
    }

    // The code reader the conformance check binds bytecode and image
    // inputs with: `width` bits from the image at `va`.
    static bool read(void* ctx, std::uint64_t va, unsigned width,
                     std::uint64_t* out) {
        const auto* self = static_cast<const ImageMap*>(ctx);
        if (!self->ok || va < self->base) {
            return false;
        }
        std::uint64_t value = 0;
        for (unsigned i = 0; i < width / 8; ++i) {
            std::uint64_t off = 0;
            bool zero = false;
            if (!self->pe.resolve_rva(va - self->base + i, off, zero)) {
                return false;
            }
            if (!zero) {
                value |= static_cast<std::uint64_t>(self->bytes[off])
                         << (8 * i);
            }
        }
        *out = value;
        return true;
    }
};

// The bytes behind an address, from whichever of the two sources holds
// them. The image dump answers for the image; the trace's own memory
// records answer for the pages the engine allocated while it ran. Which
// source holds an address is the address itself, so there is no order to
// prefer and no overlap to arbitrate: a read the image cannot place is
// asked of the trace, and one neither holds is a read nothing recorded.
struct ByteSources {
    const ImageMap* img = nullptr;
    const lift::TraceMemory* memory = nullptr;
};

bool read_bytes(void* ctx, std::uint64_t va, unsigned width,
                std::uint64_t* out) {
    const auto* s = static_cast<const ByteSources*>(ctx);
    // The run's own record first.
    //
    // A table a program decrypts at start-up has one value in the file
    // and another in memory, and it is the memory the program read. The
    // trace is the only thing here that holds what was in memory at the
    // time; the dump is what was on disk. Reading the file first answers
    // every question about a self-decrypting table with the
    // pre-decryption bytes -- not a wrong answer to a hard question, but
    // a confident answer to a different one.
    if (s->memory != nullptr && s->memory->read(va, width, out)) {
        return true;
    }
    return s->img != nullptr &&
           ImageMap::read(const_cast<ImageMap*>(s->img), va, width, out);
}


void resolve_rows(const ImageMap& img, bool have_img, std::vector<Row>& rows) {
    for (Row& r : rows) {
        r.handler =
            lift::resolve_handler(r.word, have_img && img.code_at(r.word));
    }
}

// Learns where the handlers hand control back. A VM that keeps one
// dispatcher lets every handler tail into it, and that shared entry is
// not any handler's own entry -- which is how it is told apart from a
// handler body. Each handler is linear-scanned to the instruction that
// leaves it and the targets are tallied: a target more than one handler
// jumps to is shared code, and the walk has to stop there rather than
// model the dispatcher as part of the handler.
//
// The scan follows the straight path only. A conditional branch's
// fall-through is still the handler, so the scan steps over it; only an
// unconditional jump, a return or a call ends the scan, because those
// are the instructions a handler leaves by. A shared entry that is a
// handler's own entry is not a boundary: it is a dispatch target the
// dispatcher computes, not a thing the handler tailed into.
std::vector<std::uint64_t> learn_boundary(
    const ImageMap& img, const std::vector<std::uint64_t>& handler_vas) {
    std::map<std::uint64_t, std::size_t> refs;     // target -> owning handlers
    std::map<std::uint64_t, std::uint64_t> owner;  // target -> last owner
    for (const std::uint64_t h : handler_vas) {
        std::uint64_t window_va = 0;
        std::size_t available = 0;
        const std::uint8_t* p = img.window(h, &window_va, &available);
        if (p == nullptr) {
            continue;
        }
        std::uint64_t at = h;
        for (std::size_t i = 0; i < 64; ++i) {
            if (at < window_va || at - window_va >= available) {
                break;
            }
            lift::Insn insn;
            if (!lift::decode_insn(p + (at - window_va),
                                   available - (at - window_va), at, insn)) {
                break;
            }
            if (insn.target != 0 && owner[insn.target] != h) {
                owner[insn.target] = h;
                ++refs[insn.target];
            }
            if (insn.kind == inspect::InsnKind::Jcc) {
                at += insn.length;  // the fall-through is still the handler
                continue;
            }
            if (insn.kind == inspect::InsnKind::Jmp ||
                insn.kind == inspect::InsnKind::Ret ||
                insn.kind == inspect::InsnKind::Call) {
                break;
            }
            at += insn.length;
        }
    }
    std::vector<std::uint64_t> out;
    for (const auto& [target, n] : refs) {
        if (n >= 2) {
            out.push_back(target);
        }
    }
    std::sort(out.begin(), out.end());
    return out;
}

// -------------------------------------------------------------- disasm

// objdump is the one external dependency the de-virtualizer keeps: the
// handler semantics are read from the real instruction text, and writing
// an x86 decoder into the tool would be a second decoder to keep in step
// with the one the inspector already has.
struct Insn {
    std::uint64_t addr = 0;
    std::string text;
};

void disasm(const std::string& dump, std::uint64_t start, std::uint64_t stop,
            std::vector<Insn>& out) {
    char cmd[640];
    std::snprintf(cmd, sizeof(cmd),
                  "objdump -d -M intel --start-address=0x%llx "
                  "--stop-address=0x%llx '%s' 2>/dev/null",
                  static_cast<unsigned long long>(start),
                  static_cast<unsigned long long>(stop), dump.c_str());
    FILE* p = ::popen(cmd, "r");
    if (p == nullptr) {
        return;
    }
    std::array<char, 4096> buf{};
    std::string all;
    while (std::fgets(buf.data(), static_cast<int>(buf.size()), p)) {
        all.append(buf.data());
    }
    ::pclose(p);
    std::istringstream ss(all);
    std::string line;
    while (std::getline(ss, line)) {
        // objdump line: "   140009240:\t8b 33 ...\tmov esi,..."
        const std::size_t addr_end = line.find(':');
        if (addr_end == std::string::npos) {
            continue;
        }
        std::string addr_s =
            line.substr(line.find_first_not_of(" \t"), addr_end - line.find_first_not_of(" \t"));
        if (addr_s.empty()) {
            continue;
        }
        const std::size_t tab = line.find('\t', addr_end);
        if (tab == std::string::npos) {
            continue;
        }
        std::string rest = line.substr(tab + 1);
        const std::size_t op_tab = rest.find('\t');
        std::string text = op_tab != std::string::npos ? rest.substr(op_tab + 1)
                                                       : rest;
        text.erase(text.find_last_not_of(" \t\r\n") + 1);
        if (text.empty() || text.find("(bad)") != std::string::npos) {
            continue;
        }
        Insn in;
        in.addr = json_hex(addr_s);
        in.text = std::move(text);
        out.push_back(std::move(in));
    }
}

std::string_view classify(const std::string& op) {
    std::string lo;
    lo.reserve(op.size());
    for (char c : op) {
        lo.push_back(static_cast<char>(::tolower(static_cast<unsigned char>(c))));
    }
    if (lo.find("call") != std::string::npos) {
        return "vCall";
    }
    if (lo.find("[rsi]") != std::string::npos) {
        return "vImm";
    }
    if (lo.find("[rbp") != std::string::npos) {
        if (lo.rfind("mov", 0) == 0) {
            const std::size_t comma = op.find(',');
            const std::string lhs =
                comma != std::string::npos ? op.substr(0, comma) : op;
            if (lhs.find("ptr [rbp") != std::string::npos) {
                return "vStore";
            }
            return "vLoad";
        }
        if (lo.find("ptr [rbp") != std::string::npos &&
            (lo.rfind("add", 0) == 0 || lo.rfind("sub", 0) == 0)) {
            return "vArithMem";
        }
        if (lo.rfind("add", 0) == 0 || lo.rfind("sub", 0) == 0 ||
            lo.rfind("xor", 0) == 0 || lo.rfind("and", 0) == 0 ||
            lo.rfind("or", 0) == 0) {
            return "vArith";
        }
        return "vStack";
    }
    // Anything else is the handler's junk filler: the real semantics are
    // the virtual-stack and bytecode operations above.
    return "";
}

struct Sem {
    std::string cls;
    std::string op;
};

std::map<std::uint64_t, std::vector<Sem>>
extract_handlers(const std::string& dump, const std::vector<Row>& rows) {
    std::map<std::uint64_t, std::vector<Sem>> handlers;
    for (const Row& r : rows) {
        const std::uint64_t h = r.handler;
        if (handlers.count(h)) {
            continue;
        }
        std::vector<Insn> code;
        disasm(dump, h, h + 0x80, code);
        std::vector<Sem> sem;
        for (const Insn& in : code) {
            if (in.text.rfind("jmp", 0) == 0 || in.text.rfind("ret", 0) == 0) {
                break;
            }
            const std::string_view cls = classify(in.text);
            if (cls.empty()) {
                continue;
            }
            sem.push_back(Sem{std::string(cls), in.text});
            if (sem.size() >= 6) {
                break;
            }
        }
        handlers[h] = std::move(sem);
    }
    return handlers;
}

// ---------------------------------------------------------------- asm

std::string asm_label(const std::vector<Sem>& sem) {
    std::string label;
    std::size_t used = 0;
    for (const Sem& s : sem) {
        if (used >= 3) {
            break;
        }
        if (!label.empty()) {
            label += ' ';
        }
        if (s.cls == "vImm") {
            label += "imm";
            ++used;
            continue;
        }
        if (s.cls == "vStack") {
            std::string lo;
            for (char c : s.op) {
                lo.push_back(static_cast<char>(
                    ::tolower(static_cast<unsigned char>(c))));
            }
            if (lo.find("pop") != std::string::npos) {
                label += "pop";
            } else if (lo.find("push") != std::string::npos) {
                label += "push";
            } else if (lo.find("call") != std::string::npos) {
                label += "call";
            } else if (lo.find("jmp") != std::string::npos) {
                label += "jmp";
            } else if (lo.rfind("mov", 0) == 0) {
                const std::size_t comma = s.op.find(',');
                const std::string dst = comma != std::string::npos
                                            ? s.op.substr(0, comma)
                                            : s.op;
                label += dst.find('[') != std::string::npos ? "store" : "load";
            } else if (lo.rfind("add", 0) == 0) {
                label += "add";
            } else if (lo.rfind("sub", 0) == 0) {
                label += "sub";
            } else if (lo.rfind("and", 0) == 0) {
                label += "and";
            } else if (lo.rfind("or", 0) == 0) {
                label += "or";
            } else if (lo.rfind("xor", 0) == 0) {
                label += "xor";
            } else if (lo.rfind("dec", 0) == 0) {
                label += "dec";
            } else if (lo.rfind("inc", 0) == 0) {
                label += "inc";
            } else if (lo.rfind("cmp", 0) == 0) {
                label += "cmp";
            } else if (lo.rfind("test", 0) == 0) {
                label += "test";
            } else {
                label += "op";
            }
            ++used;
            continue;
        }
        label += s.cls.substr(1);
        ++used;
    }
    return label.empty() ? "?" : label;
}

std::string fmt_slots(const Row& r) {
    std::string out;
    const std::array<std::uint64_t, 3> slots{r.st0, r.st1, r.st2};
    for (const std::uint64_t v : slots) {
        if (v == 0) {
            continue;
        }
        if (!out.empty()) {
            out += ", ";
        }
        const std::string name = api_name(v);
        if (!name.empty()) {
            out += name;
        } else {
            char b[32];
            std::snprintf(b, sizeof(b), "0x%llx",
                          static_cast<unsigned long long>(v));
            out += b;
        }
    }
    return out;
}

// -------------------------------------------------------------- report

// A handler's effect expressions can nest deeply -- the junk does a lot
// of arithmetic, and a merged branch wraps both arms in a select -- and a
// report line past a few hundred characters stops being read by anyone.
// The checked truth is the expression itself; what is printed is a
// summary of it, one clause per line.
std::string brief(const std::string& text, std::size_t limit = 110) {
    if (text.size() <= limit) {
        return text;
    }
    return text.substr(0, limit - 3) + "...";
}

class Report {
public:
    void emit(const std::string& line = "") {
        lines_.push_back(line);
        std::fputs(line.c_str(), stdout);
        std::fputc('\n', stdout);
    }
    void write(const std::string& path) const {
        if (path.empty()) {
            return;
        }
        std::ofstream out(path);
        if (!out) {
            return;
        }
        for (const std::string& l : lines_) {
            out << l << '\n';
        }
    }

private:
    std::vector<std::string> lines_;
};

}  // namespace

}  // namespace occ::devirt

// ------------------------------------------------------------ interface

namespace occ {

int cmd_devirt(int argc, char** argv) {
    using namespace devirt;

    if (argc < 2) {
        std::fprintf(stderr,
                     "usage: occ devirt TRACE.jsonl DUMP.vmf [N] "
                     "[--asm [N]] [-o REPORT] "
                     "[--unknown VA:SIZE] [--goal CONDITION] [--explore]\n"
                     "  --unknown VA:SIZE   bytes the solve may choose\n"
                     "  --goal CONDITION    what the finished program must "
                     "satisfy; a condition over\n"
                     "                      vst[i], code[i], mem64[a], "
                     "mem8/16/32/64[a], the\n"
                     "                      interpreter's registers, and the "
                     "usual operators\n"
                     "  --explore           recompute each dispatch's target "
                     "from the model and\n"
                     "                      enumerate where else it could "
                     "have gone\n");
        return 2;
    }
    // The dispatcher calls this with argv+2, so argv[0] is the trace and
    // argv[1] the dump.
    const std::string trace_path = argv[0];
    const std::string dump_path = argv[1];
    std::size_t limit = 0;
    std::size_t asm_limit = 0;
    bool want_asm = false;
    bool want_explore = false;
    std::string report_path;
    lift::SolveOptions solve_opts;
    bool want_solve = false;
    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--asm") {
            want_asm = true;
            if (i + 1 < argc && std::isdigit(static_cast<unsigned char>(argv[i + 1][0]))) {
                asm_limit = static_cast<std::size_t>(std::strtoull(argv[++i], nullptr, 10));
            }
        } else if (a == "--explore") {
            want_explore = true;
            want_solve = true;
        } else if (a == "-o") {
            if (i + 1 < argc) {
                report_path = argv[++i];
            }
        } else if (a == "--unknown" && i + 1 < argc) {
            // VA:SIZE, both hexadecimal or decimal.
            const std::string spec = argv[++i];
            const std::size_t colon = spec.find(':');
            if (colon == std::string::npos) {
                std::fprintf(stderr,
                             "devirt: --unknown wants VA:SIZE (got %s)\n",
                             spec.c_str());
                return 2;
            }
            const auto parse = [](const std::string& s) {
                return static_cast<std::uint64_t>(
                    std::strtoull(s.c_str(), nullptr, 0));
            };
            lift::UnknownRegion region;
            region.va = parse(spec.substr(0, colon));
            region.size = parse(spec.substr(colon + 1));
            if (region.size == 0) {
                std::fprintf(stderr,
                             "devirt: --unknown needs a non-empty region\n");
                return 2;
            }
            solve_opts.unknown.push_back(region);
            want_solve = true;
        } else if (a == "--goal" && i + 1 < argc) {
            const std::string spec = argv[++i];
            lift::GoalNode goal;
            std::string error;
            if (!lift::parse_goal(spec, &goal, &error)) {
                std::fprintf(stderr, "devirt: --goal %s\n  %s\n",
                             spec.c_str(), error.c_str());
                return 2;
            }
            solve_opts.goals.push_back(std::move(goal));
            want_solve = true;
        } else if (std::isdigit(static_cast<unsigned char>(a[0]))) {
            limit = static_cast<std::size_t>(std::strtoull(a.c_str(), nullptr, 10));
        }
    }
    solve_opts.explore = want_explore;

    load_api_map(dump_path);

    std::vector<Row> rows;
    if (!load_trace(trace_path, rows)) {
        std::fprintf(stderr, "devirt: no dispatch rows in %s\n",
                     trace_path.c_str());
        return 1;
    }
    if (limit) {
        rows.resize(limit);
    }

    // The handler table's encoding is settled here, once, against the
    // image. Every step below reads the resolved `handler` off the row and
    // none of them has to know which VM family wrote the trace.
    ImageMap img;
    const bool have_img = img.load(dump_path);
    resolve_rows(img, have_img, rows);

    // The entries the handlers hand control back through, learned from the
    // handlers themselves before they are lifted (see learn_boundary): the
    // lift stops at them, so each handler is modelled up to its own
    // boundary and not through the dispatcher it shares with the others.
    std::vector<std::uint64_t> handler_vas;
    for (const Row& r : rows) {
        handler_vas.push_back(r.handler);
    }
    std::sort(handler_vas.begin(), handler_vas.end());
    handler_vas.erase(std::unique(handler_vas.begin(), handler_vas.end()),
                      handler_vas.end());
    const std::vector<std::uint64_t> boundary =
        have_img ? learn_boundary(img, handler_vas)
                 : std::vector<std::uint64_t>{};

    Report rep;
    rep.emit("trace: " + std::to_string(rows.size()) + " dispatches");

    const auto handlers = extract_handlers(dump_path, rows);
    rep.emit("distinct handlers: " + std::to_string(handlers.size()) + "\n");

    std::map<std::uint64_t, std::vector<Row>> by_handler;
    for (const Row& r : rows) {
        by_handler[r.handler].push_back(r);
    }

    // Lift every handler before the tables print. The semantics column is
    // the model's now, not a match on the instruction text, so the models
    // have to exist first; the same ones are reported in full below.
    lift::Model model;
    std::vector<lift::Handler> lhandlers;
    std::map<std::uint64_t, std::size_t> index_of;
    if (have_img) {
        // The register file the handlers index, read out of their own code
        // before anything is lifted. A stack machine reaches its slots by
        // offset from a base and has none; a register machine reaches them
        // by an index and names its base here. Setting it first is what
        // makes the model read in slots instead of in addresses.
        std::vector<lift::HandlerBytes> handler_bytes;
        for (const auto& [h, rs] : by_handler) {
            (void)rs;
            std::uint64_t window_va = 0;
            std::size_t avail = 0;
            const std::uint8_t* p = img.window(h, &window_va, &avail);
            // The window is the whole section; the scan starts at the
            // handler, so the view handed over starts there too.
            if (p == nullptr || h < window_va || h - window_va >= avail) {
                handler_bytes.push_back(lift::HandlerBytes{h, nullptr, 0});
            } else {
                handler_bytes.push_back(lift::HandlerBytes{
                    h, p + (h - window_va), avail - (h - window_va)});
            }
        }
        const lift::Layout layout = lift::infer_layout(handler_bytes);
        model.convention.regfile = layout.regfile;
        model.convention.regfile_width = layout.regfile_width;
        model.convention.code = layout.code;
        // A register machine's slots hang off its file's base, so that is
        // the register the checker has to read its window around -- and
        // naming it as the stack is what makes the model's slots and the
        // trace's observed cells the same place. A stack machine has no
        // file and keeps the default.
        if (!layout.regfile.empty()) {
            model.convention.stack = layout.regfile;
        }

        for (const auto& [h, rs] : by_handler) {
            (void)rs;
            std::uint64_t window_va = 0;
            std::size_t avail = 0;
            const std::uint8_t* p = img.window(h, &window_va, &avail);
            lift::Handler handler;
            handler.va = h;
            if (p != nullptr && avail != 0) {
                // A handler is a chain of blocks scattered through the
                // section, and the budget has to cover the whole chain --
                // the sample's handlers run 70 to 150 instructions.
                handler = lift::summarize(model, p, avail, window_va, h, 1024,
                                          boundary);
            } else {
                handler.reason = "handler bytes are not file-backed";
            }
            index_of[h] = lhandlers.size();
            lhandlers.push_back(std::move(handler));
        }
    }

    // The shared code every handler jumps to -- the dispatcher -- as a
    // model of its own.
    //
    // The handlers stop at the boundary on purpose: the dispatcher is not
    // any one handler's business, and folding it into each of them would
    // give thirteen copies of the same code and thirteen chances to get
    // it wrong. But it is the code that decides what runs next, and
    // without a model of it the analysis can only report the sequence the
    // trace happened to take. Summarized once, here, and replayed with
    // the handlers, it turns "what ran" into "what the machine computed",
    // which is a check where there was none and the only way a dispatch
    // that depends on the input can be seen at all.
    lift::Handler dispatcher;
    bool have_dispatcher = false;
    if (have_img && !boundary.empty()) {
        std::uint64_t entry = boundary.front();
        // The boundary is where the handlers hand control back. The
        // dispatch itself may live a jump or two further along -- a key
        // roll, a bounds check, whatever the engine shares -- and the
        // model has to start where the trace's own registers mean what
        // the model's inputs say they mean. A state the trace never
        // carried would make every input a guess: an engine whose shared
        // tail rolls a key before re-entering the dispatch reads the
        // trace's key *after* that roll, so a model entered at the tail
        // would roll it a second time and index its own table with the
        // wrong byte. Following the chain of unconditional jumps lands on
        // the loop head the trace's sampling point sits inside, where
        // the recorded registers are the model's own inputs.
        std::vector<std::uint64_t> visited{entry};
        for (int hop = 0; hop < 8; ++hop) {
            std::uint64_t window_va = 0;
            std::size_t avail = 0;
            const std::uint8_t* p = img.window(entry, &window_va, &avail);
            if (p == nullptr || entry < window_va ||
                entry - window_va >= avail) {
                break;
            }
            // Walk the block from the entry to its terminator. Only an
            // unconditional direct jump moves the entry: a conditional
            // or an indirect one leaves the state the trace carried
            // behind a branch, and a call or a return leaves it in
            // someone else's frame.
            std::uint64_t pc = entry;
            std::uint64_t next = 0;
            while (pc - window_va < avail) {
                lift::Insn in;
                if (!lift::decode_insn(p + (pc - window_va),
                                       avail - (pc - window_va), pc, in)) {
                    break;
                }
                if (in.kind == inspect::InsnKind::Jmp && in.target != 0) {
                    next = in.target;
                    break;
                }
                if (in.kind != inspect::InsnKind::Other) {
                    break;
                }
                pc += in.length;
            }
            if (next == 0 || next == entry ||
                std::find(visited.begin(), visited.end(), next) !=
                    visited.end()) {
                break;
            }
            entry = next;
            visited.push_back(entry);
        }
        std::uint64_t window_va = 0;
        std::size_t avail = 0;
        const std::uint8_t* p = img.window(entry, &window_va, &avail);
        // The boundary list handed to the walk is empty: the dispatcher
        // *is* the shared code, and it does not stop at itself. What
        // stops it is its own indirect jump, which is where the next
        // handler's address comes out.
        if (p != nullptr && entry >= window_va && entry - window_va < avail) {
            // `summarize` takes the section's own view -- the pointer the
            // window returned and the address it starts at -- and finds
            // the entry inside it. The offset that `HandlerBytes` wants
            // is a different convention and is not applied here.
            dispatcher = lift::summarize(model, p, avail, window_va, entry,
                                         256);
            have_dispatcher = true;
        }
    }

    rep.emit("handler        count  semantics");
    rep.emit(std::string(96, '-'));
    for (const auto& [h, rs] : by_handler) {
        std::string label;
        if (have_img) {
            label = lift::effect_label(model, lhandlers[index_of[h]]);
        }
        char b[32];
        std::snprintf(b, sizeof(b), "0x%010llx  %6zu",
                      static_cast<unsigned long long>(h), rs.size());
        rep.emit(std::string(b) + "  " + label);
    }

    // The column is the model's, so it names the operation whatever
    // registers the VM chose: the label follows the convention the model
    // was lifted under, and a family whose register use a match on the
    // instruction text would miss is named all the same.

    // The bytecode cursor's range.
    if (!rows.empty()) {
        std::uint64_t lo = rows[0].rsi, hi = rows[0].rsi;
        for (const Row& r : rows) {
            lo = std::min(lo, r.rsi);
            hi = std::max(hi, r.rsi);
        }
        char b[64];
        std::snprintf(b, sizeof(b), "\nbytecode cursor range: 0x%llx .. 0x%llx",
                      static_cast<unsigned long long>(lo),
                      static_cast<unsigned long long>(hi));
        rep.emit(b);
    }

    // The reassembled stream, first N.
    const std::size_t shown = std::min<std::size_t>(50, rows.size());
    rep.emit("\nreassembled virtual stream (first " + std::to_string(shown) + "):");
    rep.emit("#    handler       word                  semantics");
    for (std::size_t i = 0; i < shown; ++i) {
        const Row& r = rows[i];
        std::string label;
        if (have_img) {
            label = lift::effect_label(model, lhandlers[index_of[r.handler]]);
        }
        char b[64];
        std::snprintf(b, sizeof(b), "%-5llu0x%010llx  0x%016llx",
                      static_cast<unsigned long long>(r.seq),
                      static_cast<unsigned long long>(r.handler),
                      static_cast<unsigned long long>(r.word));
        rep.emit(std::string(b) + "  " + (label.empty() ? "?" : label));
    }

    // API calls: an API address in a virtual stack slot is a call being
    // set up.
    rep.emit("\nAPI calls observed:");
    std::size_t api_shown = 0;
    for (const Row& r : rows) {
        std::string name;
        for (const std::uint64_t v : {r.st0, r.st1, r.st2}) {
            name = api_name(v);
            if (!name.empty()) {
                break;
            }
        }
        if (name.empty()) {
            continue;
        }
        if (api_shown++ < 40) {
            char b[128];
            std::snprintf(b, sizeof(b),
                          "  #%-5llu %-22s word=%016llx rsi=0x%llx rbp=0x%llx",
                          static_cast<unsigned long long>(r.seq), name.c_str(),
                          static_cast<unsigned long long>(r.word),
                          static_cast<unsigned long long>(r.rsi),
                          static_cast<unsigned long long>(r.rbp));
            rep.emit(b);
        }
    }
    if (api_shown == 0) {
        rep.emit("  (none)");
    }

    // Opcode histogram.
    std::map<std::string, std::size_t> counts;
    for (const Row& r : rows) {
        if (have_img) {
            counts[lift::effect_label(model, lhandlers[index_of[r.handler]])]++;
        } else {
            counts["(unknown)"]++;
        }
    }
    rep.emit("\nopcode histogram (all " + std::to_string(rows.size()) + "):");
    // Sort by count descending.
    std::vector<std::pair<std::string, std::size_t>> sorted(counts.begin(),
                                                            counts.end());
    std::sort(sorted.begin(), sorted.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    for (const auto& [op, c] : sorted) {
        // The label is the model's now, and its length is not bounded the
        // way the text-match labels were: `select -> dispatch` is longer
        // than the old three-letter classes. The pad is a floor, so the
        // subtraction stays in size_t.
        const std::size_t pad = op.size() < 14 ? 14 - op.size() : 1;
        rep.emit("  " + op + std::string(pad, ' ') + std::to_string(c));
    }

    // Control flow: the cursor advances by the virtual instruction length;
    // a jump beyond any footprint, or backwards at all, is an edge.
    rep.emit("\ncontrol flow (basic blocks from rsi continuity):");
    std::vector<std::tuple<std::size_t, std::size_t, std::uint64_t, std::uint64_t>> blocks;
    std::size_t block_start = 0;
    for (std::size_t i = 1; i < rows.size(); ++i) {
        const std::int64_t d =
            static_cast<std::int64_t>(rows[i].rsi - rows[i - 1].rsi);
        if (d > 0x40 || d < 0) {
            blocks.emplace_back(block_start + 1, i, rows[block_start].rsi,
                                rows[i - 1].rsi);
            block_start = i;
        }
    }
    blocks.emplace_back(block_start + 1, rows.size(), rows[block_start].rsi,
                        rows.back().rsi);
    rep.emit("  " + std::to_string(blocks.size()) + " basic blocks");
    std::size_t bi = 0;
    for (const auto& [lo, hi, rs, re] : blocks) {
        std::string edge;
        if (lo > 1) {
            const std::int64_t d =
                static_cast<std::int64_t>(rows[lo - 1].rsi - rows[lo - 2].rsi);
            if (d > 0x40 || d < 0) {
                const char* kind = d > 0 ? "vCall" : "vRet";
                char b[80];
                std::snprintf(b, sizeof(b),
                              "  <- %s from #%zu (target st0=0x%llx)", kind,
                              lo - 1,
                              static_cast<unsigned long long>(rows[lo - 1].st0));
                edge = b;
            }
        }
        char b[96];
        std::snprintf(b, sizeof(b), "  B%zu #%4zu-#%-4zu rsi 0x%llx..0x%llx %zu instr",
                      bi++, lo, hi, static_cast<unsigned long long>(rs),
                      static_cast<unsigned long long>(re), hi - lo + 1);
        rep.emit(std::string(b) + edge);
    }

    // The lift: every handler modelled as a micro-program over the
    // virtual state, and the model checked against the trace. This is
    // the part that makes the semantics above checkable rather than
    // plausible -- each dispatch's prediction is evaluated with the
    // previous row's values and compared with the next row's, field by
    // field.
    {
        if (!have_img) {
            rep.emit("");
            rep.emit("handler lifting: skipped (the dump does not parse as "
                     "a PE image)");
        } else {
            std::size_t incomplete = 0;
            for (const lift::Handler& lh : lhandlers) {
                if (!lh.modeled) {
                    ++incomplete;
                }
            }

            rep.emit("");
            if (!boundary.empty()) {
                std::string b =
                    "handler boundary (shared entries the walk stops at): ";
                for (std::size_t i = 0; i < boundary.size(); ++i) {
                    char buf[24];
                    std::snprintf(buf, sizeof(buf), "%s0x%llx", i ? ", " : "",
                                  static_cast<unsigned long long>(boundary[i]));
                    b += buf;
                }
                rep.emit(b);
            }
            if (!model.convention.regfile.empty() ||
                !model.convention.code.empty()) {
                std::string line = "layout read from the handlers:";
                if (!model.convention.regfile.empty()) {
                    line += " register file " + model.convention.regfile + " (" +
                            std::to_string(model.convention.regfile_width) +
                            "-bit elements, slots read as vst[...])";
                }
                if (!model.convention.code.empty()) {
                    line += "; bytecode " + model.convention.code +
                            " (read as code[...])";
                }
                rep.emit(line);
            }
            rep.emit("handler lifting: " + std::to_string(lhandlers.size()) +
                     " handlers, " +
                     std::to_string(lhandlers.size() - incomplete) +
                     " fully modelled, " + std::to_string(incomplete) +
                     " incomplete");
            for (const auto& [h, rs] : by_handler) {
                (void)rs;
                const lift::Handler& lh = lhandlers[index_of[h]];
                char b[24];
                std::snprintf(b, sizeof(b), "  0x%010llx  ",
                              static_cast<unsigned long long>(h));
                const std::string head = b;
                const std::string indent(head.size(), ' ');
                if (!lh.modeled) {
                    rep.emit(head + "(incomplete: " + lh.reason + ")");
                    continue;
                }
                rep.emit(head + "fully modelled");
                // The two virtual pointers, printed only when the handler
                // moved them: "<stack>' = <stack>" is the model saying the
                // handler left it alone, which the name already says.
                const std::string rbp_s = brief(lift::render(model, lh.rbp_new));
                if (rbp_s != model.convention.stack) {
                    rep.emit(indent + "rbp' = " + rbp_s);
                }
                const std::string rsi_s = brief(lift::render(model, lh.rsi_new));
                if (rsi_s != model.convention.cursor) {
                    rep.emit(indent + "rsi' = " + rsi_s);
                }
                for (const lift::Handler::Write& w : lh.writes) {
                    if (w.to_slot) {
                        rep.emit(indent + "vst[" + std::to_string(w.disp) +
                                 "] = " + brief(lift::render(model, w.value)));
                    } else {
                        rep.emit(indent + lift::address_label(model, w.addr,
                                                             w.width) +
                                 " = " + brief(lift::render(model, w.value)));
                    }
                }
                if (lh.transfer == lift::Handler::Transfer::Dispatch) {
                    // A dispatch whose target the model could not compute --
                    // the handler handed control back at a shared entry --
                    // still names the transfer; only the target is unknown.
                    rep.emit(indent + "-> " +
                             (lh.target_expr == expr::kNoId
                                  ? std::string("dispatch")
                                  : brief(lift::render(model, lh.target_expr))));
                } else if (lh.transfer == lift::Handler::Transfer::Call) {
                    rep.emit(indent + "-> call-out");
                } else if (lh.transfer == lift::Handler::Transfer::Return) {
                    rep.emit(indent + "-> return");
                }
                // What the walk met and handled: the model is exact, but
                // the analyst should know where it had to approximate.
                for (const std::string& n : lh.notes) {
                    rep.emit(indent + "note: " + n);
                }
            }

            std::vector<lift::Row> lrows;
            std::vector<std::size_t> which;
            lrows.reserve(rows.size());
            which.reserve(rows.size());
            for (const Row& r : rows) {
                lift::Row lr;
                lr.seq = r.seq;
                lr.rsi = r.rsi;
                lr.rbp = r.rbp;
                lr.rdi = r.rdi;
                lr.rsp = r.rsp;
                lr.r12 = r.r12;
                lr.st0 = r.st0;
                lr.st1 = r.st1;
                lr.st2 = r.st2;
                lr.rt = r.rt;
                lr.rt_present = r.rt_present;
                lr.gpr = r.gpr;
                lr.gpr_present = r.gpr_present;
                lr.target = r.word;
                lrows.push_back(lr);
                which.push_back(index_of[r.handler]);
            }
            ByteSources sources{have_img ? &img : nullptr, &g_memory};
            // The instantiation is asked of the check, not built beside it:
            // the binding it prints is the one the check itself used, so the
            // two cannot disagree about a row they both describe.
            std::vector<lift::InstantiatedRow> instantiated;
            const lift::Conformance conf = lift::check_trace(
                model, lhandlers, lrows, which, read_bytes, &sources,
                &instantiated);
            char b[224];
            std::snprintf(b, sizeof(b),
                          "  trace conformance: %llu checked, %llu mismatched, "
                          "%llu unverifiable, %llu to incomplete models "
                          "(agreement %.1f%%)",
                          static_cast<unsigned long long>(conf.checked),
                          static_cast<unsigned long long>(conf.mismatched),
                          static_cast<unsigned long long>(conf.unverifiable),
                          static_cast<unsigned long long>(conf.unmodeled),
                          conf.rate() * 100.0);
            rep.emit(b);
            if (!conf.worst_handlers.empty()) {
                std::string tally = "  mismatches by handler:";
                for (const lift::Conformance::PerHandler& ph :
                     conf.worst_handlers) {
                    char hb[40];
                    std::snprintf(hb, sizeof(hb), " 0x%llx x%llu",
                                  static_cast<unsigned long long>(ph.va),
                                  static_cast<unsigned long long>(ph.count));
                    tally += hb;
                }
                rep.emit(tally);
            }
            for (const std::string& f : conf.failures) {
                rep.emit("  ! " + f);
            }
            // The stream again, with the run's own values in it. The
            // symbolic listing above says what each handler is; this says
            // what the engine did with it, which is the difference between
            // `vst[i] ^= code[rax+2]` and `vst[3] ^= 0x5c` -- and it is the
            // difference between a schema and a program.
            if (!instantiated.empty()) {
                // The program listing is the point of this section, so it
                // gets a far wider cap than the schema above: a schema
                // truncated is one entry missing, a program truncated is a
                // tail nobody can read. What a trace longer than the cap
                // still hides is said rather than silently dropped.
                const std::size_t inst_shown =
                    std::min<std::size_t>(400, instantiated.size());
                std::size_t pinned = 0;
                for (const lift::InstantiatedRow& ir : instantiated) {
                    if (ir.inputs_bound == ir.inputs_total) {
                        ++pinned;
                    }
                }
                rep.emit("\ninstantiated stream (first " +
                         std::to_string(inst_shown) +
                         " of " + std::to_string(instantiated.size()) +
                         "), every value the trace supplied substituted in:");
                rep.emit("#    handler       effect");
                for (std::size_t i = 0; i < inst_shown; ++i) {
                    const lift::InstantiatedRow& ir = instantiated[i];
                    std::string text;
                    for (const std::string& w : ir.writes) {
                        if (!text.empty()) {
                            text += "; ";
                        }
                        text += w;
                    }
                    if (!ir.transfer.empty()) {
                        if (!text.empty()) {
                            text += "; ";
                        }
                        text += "-> " + ir.transfer;
                    }
                    char hb[80];
                    std::snprintf(hb, sizeof(hb), "%-5llu0x%010llx  ",
                                  static_cast<unsigned long long>(ir.seq),
                                  static_cast<unsigned long long>(
                                      ir.handler_va));
                    rep.emit(std::string(hb) + text);
                }
                if (inst_shown < instantiated.size()) {
                    rep.emit("  ... " +
                             std::to_string(instantiated.size() - inst_shown) +
                             " rows not shown");
                }
                char sb[128];
                std::snprintf(sb, sizeof(sb),
                              "  %llu of %llu rows pinned down completely "
                              "by the trace",
                              static_cast<unsigned long long>(pinned),
                              static_cast<unsigned long long>(
                                  instantiated.size()));
                rep.emit(sb);
            }

            // The question the caller asked, answered by replaying the
            // models the check just agreed with. It runs after the check
            // on purpose: the replay adds input nodes to the model's
            // expression DAG, and the check's answers describe the model
            // as it was.
            if (want_solve) {
                const lift::SolveResult sol = lift::solve(
                    model, lhandlers, lrows, which, read_bytes, &sources,
                    solve_opts, have_dispatcher ? &dispatcher : nullptr);
                rep.emit("\nsolve:");
                for (std::size_t i = 0; i < solve_opts.unknown.size(); ++i) {
                    char ub[96];
                    std::snprintf(ub, sizeof(ub),
                                  "  unknown[%zu]  0x%llx + %llu bytes", i,
                                  static_cast<unsigned long long>(
                                      solve_opts.unknown[i].va),
                                  static_cast<unsigned long long>(
                                      solve_opts.unknown[i].size));
                    rep.emit(ub);
                }
                for (std::size_t i = 0; i < sol.goal_text.size(); ++i) {
                    std::string line = "  goal " + sol.goal_text[i];
                    if (i < sol.goal_addresses.size() &&
                        sol.goal_addresses[i] != 0) {
                        char ab[64];
                        std::snprintf(ab, sizeof(ab), "   (read at 0x%llx)",
                                      static_cast<unsigned long long>(
                                          sol.goal_addresses[i]));
                        line += ab;
                    }
                    rep.emit(line);
                }
                {
                    char rb[192];
                    std::snprintf(rb, sizeof(rb),
                                  "  %llu of %llu rows replayed, %llu "
                                  "skipped; the goals reach %llu of the "
                                  "regions' bytes",
                                  static_cast<unsigned long long>(
                                      sol.rows_played),
                                  static_cast<unsigned long long>(
                                      lrows.size()),
                                  static_cast<unsigned long long>(
                                      sol.rows_skipped),
                                  static_cast<unsigned long long>(
                                      sol.variables));
                    rep.emit(rb);
                }
                if (sol.clauses != 0) {
                    char cb[192];
                    std::snprintf(cb, sizeof(cb),
                                  "  %llu clauses over %llu variables, "
                                  "%llu conflicts, %llu decisions",
                                  static_cast<unsigned long long>(
                                      sol.clauses),
                                  static_cast<unsigned long long>(
                                      sol.variables),
                                  static_cast<unsigned long long>(
                                      sol.conflicts),
                                  static_cast<unsigned long long>(
                                      sol.decisions));
                    rep.emit(cb);
                }
                if (sol.unrecorded_variables != 0) {
                    char nb[192];
                    std::snprintf(nb, sizeof(nb),
                                  "  %llu values the model needed that no "
                                  "run recorded%s",
                                  static_cast<unsigned long long>(
                                      sol.unrecorded_variables),
                                  sol.unrecorded_used
                                      ? ", and the answer depends on some "
                                        "of them"
                                      : "; the answer depends on none");
                    rep.emit(nb);
                }
                if (sol.symbolic_stores != 0) {
                    char wb[160];
                    std::snprintf(wb, sizeof(wb),
                                  "  %llu stores whose address no run "
                                  "fixed: which cells they covered is not "
                                  "known from here",
                                  static_cast<unsigned long long>(
                                      sol.symbolic_stores));
                    rep.emit(wb);
                }
                // What the model says about control flow, against what the
                // run did. Every dispatch's target is recomputed from the
                // dispatcher's model; the ones that agree are a check on
                // the model that nothing else in the analysis makes, and
                // the ones that do not are either a defect or a branch.
                if (have_dispatcher) {
                    char db[224];
                    std::snprintf(db, sizeof(db),
                                  "  dispatch: the shared code at 0x%llx "
                                  "was replayed over every row; %llu targets "
                                  "resolved to a number, %llu depend on the "
                                  "unknown",
                                  static_cast<unsigned long long>(
                                      dispatcher.va),
                                  static_cast<unsigned long long>(
                                      sol.targets_resolved),
                                  static_cast<unsigned long long>(
                                      sol.targets_symbolic));
                    rep.emit(db);
                    if (sol.targets_symbolic == 0 && sol.branches.empty() &&
                        sol.targets_resolved != 0) {
                        rep.emit("    and every one of them is the word the "
                                 "run read, so the model's control flow and "
                                 "the run's agree at all of them");
                    }
                    if (!dispatcher.modeled) {
                        rep.emit("  ! the dispatcher's own model is not "
                                 "claimed exact, and its targets are read "
                                 "with that in mind");
                    }
                    {
                        const char* ends = "nothing";
                        switch (dispatcher.transfer) {
                        case lift::Handler::Transfer::Dispatch:
                            ends = "a dispatch";
                            break;
                        case lift::Handler::Transfer::Return:
                            ends = "a return";
                            break;
                        case lift::Handler::Transfer::Call:
                            ends = "a call out";
                            break;
                        default:
                            break;
                        }
                        std::string line =
                            std::string("    its model ends in ") + ends;
                        if (dispatcher.target_expr != expr::kNoId) {
                            line += ", on " +
                                    lift::render(model,
                                                 dispatcher.target_expr);
                        } else {
                            line += ", and names no target";
                        }
                        rep.emit(line);
                        for (const std::string& n : dispatcher.notes) {
                            rep.emit("    note: " + n);
                        }
                    }
                } else if (want_solve) {
                    rep.emit("  dispatch: not replayed; no shared code was "
                             "modelled, so the handler sequence is the "
                             "trace's and not the model's");
                }
                for (const lift::BranchPoint& bp : sol.branches) {
                    char hb[192];
                    std::snprintf(hb, sizeof(hb),
                                  "  %s at seq %llu (handler 0x%llx): %s",
                                  bp.symbolic ? "branch" : "divergence",
                                  static_cast<unsigned long long>(bp.seq),
                                  static_cast<unsigned long long>(
                                      bp.handler_va),
                                  bp.condition.c_str());
                    rep.emit(hb);
                    char ob[224];
                    if (bp.symbolic) {
                        std::snprintf(ob, sizeof(ob),
                                      "    the run read 0x%llx there, which "
                                      "is one successor and not the whole set",
                                      static_cast<unsigned long long>(
                                          bp.observed));
                    } else {
                        std::snprintf(ob, sizeof(ob),
                                      "    the model made it 0x%llx and the "
                                      "run read 0x%llx",
                                      static_cast<unsigned long long>(
                                          bp.computed),
                                      static_cast<unsigned long long>(
                                          bp.observed));
                    }
                    rep.emit(ob);
                    for (const lift::BranchPoint::Edge& e : bp.edges) {
                        char eb[128];
                        std::snprintf(eb, sizeof(eb), "    -> 0x%llx  %s",
                                      static_cast<unsigned long long>(
                                          e.target),
                                      e.reachable ? "reachable"
                                                  : "ruled out by the path "
                                                    "the run took");
                        rep.emit(eb);
                    }
                }
                for (const std::string& u : sol.unmet) {
                    rep.emit("  ! " + u);
                }
                if (sol.solved) {
                    for (std::size_t i = 0; i < sol.region_bytes.size();
                         ++i) {
                        const std::vector<std::uint8_t>& bytes =
                            sol.region_bytes[i];
                        std::string hex;
                        std::string text;
                        for (const std::uint8_t byte : bytes) {
                            char hb[4];
                            std::snprintf(hb, sizeof(hb), "%02x", byte);
                            hex += hb;
                            text += (byte >= 0x20 && byte < 0x7f)
                                        ? static_cast<char>(byte)
                                        : '.';
                        }
                        rep.emit("  answer[" + std::to_string(i) + "] 0x" +
                                 hex + "  \"" + text + "\"");
                    }
                    rep.emit("  solved: the bytes above satisfy every "
                             "goal, checked by evaluating the expressions "
                             "the search was built from");
                    rep.emit("  a candidate, not a proof: run the program "
                             "with it, because the replay follows the "
                             "traced path and the traced input's length");
                } else {
                    rep.emit("  not solved: " + sol.reason);
                }
            }
        }
    }

    // The assembly-like listing.
    if (want_asm) {
        rep.emit("");
        rep.emit("assembly-like listing (first " +
                 (asm_limit ? std::to_string(asm_limit)
                            : std::to_string(rows.size())) +
                 " of " + std::to_string(rows.size()) + " dispatches):");
        rep.emit("#    @rsi         handler       instr                operands");
        rep.emit(std::string(78, '-'));
        const std::size_t n = asm_limit ? asm_limit : rows.size();
        for (std::size_t i = 0; i < n; ++i) {
            const Row& r = rows[i];
            const auto sem = handlers.find(r.handler);
            const std::string label =
                sem != handlers.end() ? asm_label(sem->second) : "?";
            char b[48];
            std::snprintf(b, sizeof(b), "%-5llu0x%010llx 0x%010llx",
                          static_cast<unsigned long long>(r.seq),
                          static_cast<unsigned long long>(r.rsi),
                          static_cast<unsigned long long>(r.handler));
            rep.emit(std::string(b) + "  " + label +
                     std::string(22 - std::min<std::size_t>(22, label.size()), ' ') +
                     "  " + fmt_slots(r));
        }
    }

    rep.write(report_path);
    if (!report_path.empty()) {
        rep.emit("\nreport written to " + report_path);
    }
    return 0;
}

}  // namespace occ

// occ devirt — the offline VM de-virtualizer, as a native command.
//
// Consumes the JSON-lines VM trace (`OCC_VM_TRACE`, kind=dispatch) and the
// decrypted image dump (`.vmf`), and reassembles the virtual instruction
// stream the VM engine executed: handler semantics (via objdump over the
// handler bytes), the API calls it makes (named from the `.api` map the
// runtime dumps next to the image), control flow, and an assembly-like
// listing.
//
// VMP 3 virtual instruction format (the bundled sample):
//   dispatch:  mov rcx,[r12+rax*8]          @ 0x6b2a
//   decrypt:   cmc;cmc; rol rcx,0xa; jmp rcx @ 0x8851
//   handler = rol(word, 10).  The handler is a junk-wrapped micro-program
//   on the virtual state: rbp = virtual stack pointer, rsi = bytecode
//   cursor.  The trace records the virtual stack at every dispatch
//   (st0/st1/st2) and the cursor, so a call is visible as the guest's own
//   API address in the stack slots.

#include "occ/commands.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace occ::devirt {

namespace {

constexpr std::uint64_t kMask = 0xFFFFFFFFFFFFFFFFULL;

std::uint64_t rol10(std::uint64_t v) {
    return ((v << 10) & kMask) | (v >> 54);
}

// ---------------------------------------------------------------- trace

struct Row {
    std::uint64_t seq = 0;
    std::uint64_t rsi = 0;   // bytecode cursor
    std::uint64_t rbp = 0;   // virtual stack pointer
    std::uint64_t st0 = 0;   // virtual stack top
    std::uint64_t st1 = 0;
    std::uint64_t st2 = 0;
    std::uint64_t word = 0;  // the encrypted virtual instruction word
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
        if (f["kind"] != "dispatch") {
            continue;
        }
        Row r;
        r.seq = json_hex(f["seq"]);
        r.word = json_hex(f["target"]);
        r.rsi = json_hex(f["rsi"]);
        r.rbp = json_hex(f["rbp"]);
        r.st0 = json_hex(f["st0"]);
        r.st1 = json_hex(f["st1"]);
        r.st2 = json_hex(f["st2"]);
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
        const std::uint64_t h = rol10(r.word);
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
                     "[--asm [N]] [-o REPORT]\n");
        return 2;
    }
    // The dispatcher calls this with argv+2, so argv[0] is the trace and
    // argv[1] the dump.
    const std::string trace_path = argv[0];
    const std::string dump_path = argv[1];
    std::size_t limit = 0;
    std::size_t asm_limit = 0;
    bool want_asm = false;
    std::string report_path;
    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--asm") {
            want_asm = true;
            if (i + 1 < argc && std::isdigit(static_cast<unsigned char>(argv[i + 1][0]))) {
                asm_limit = static_cast<std::size_t>(std::strtoull(argv[++i], nullptr, 10));
            }
        } else if (a == "-o") {
            if (i + 1 < argc) {
                report_path = argv[++i];
            }
        } else if (std::isdigit(static_cast<unsigned char>(a[0]))) {
            limit = static_cast<std::size_t>(std::strtoull(a.c_str(), nullptr, 10));
        }
    }

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

    Report rep;
    rep.emit("trace: " + std::to_string(rows.size()) + " dispatches");

    const auto handlers = extract_handlers(dump_path, rows);
    rep.emit("distinct handlers: " + std::to_string(handlers.size()) + "\n");

    std::map<std::uint64_t, std::vector<Row>> by_handler;
    for (const Row& r : rows) {
        by_handler[rol10(r.word)].push_back(r);
    }

    rep.emit("handler        count  semantics");
    rep.emit(std::string(96, '-'));
    for (const auto& [h, rs] : by_handler) {
        const auto sem = handlers.find(h);
        if (sem == handlers.end()) {
            rep.emit("(none)");
            continue;
        }
        std::string label;
        for (std::size_t i = 0; i < sem->second.size() && i < 2; ++i) {
            if (!label.empty()) {
                label += " ; ";
            }
            label += sem->second[i].cls + ":" + sem->second[i].op.substr(0, 38);
        }
        char b[32];
        std::snprintf(b, sizeof(b), "0x%010llx  %6zu",
                      static_cast<unsigned long long>(h), rs.size());
        rep.emit(std::string(b) + "  " + label.substr(0, 82));
    }

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
        const auto sem = handlers.find(rol10(r.word));
        std::string label;
        if (sem != handlers.end()) {
            for (std::size_t j = 0; j < sem->second.size() && j < 3; ++j) {
                if (!label.empty()) {
                    label += " ; ";
                }
                label += sem->second[j].cls;
            }
        }
        char b[64];
        std::snprintf(b, sizeof(b), "%-5llu0x%010llx  0x%016llx",
                      static_cast<unsigned long long>(r.seq),
                      static_cast<unsigned long long>(rol10(r.word)),
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
        const auto sem = handlers.find(rol10(r.word));
        if (sem != handlers.end() && !sem->second.empty()) {
            counts[sem->second[0].cls]++;
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
        rep.emit("  " + op + std::string(14 - op.size(), ' ') +
                 std::to_string(c));
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
            const auto sem = handlers.find(rol10(r.word));
            const std::string label =
                sem != handlers.end() ? asm_label(sem->second) : "?";
            char b[48];
            std::snprintf(b, sizeof(b), "%-5llu0x%010llx 0x%010llx",
                          static_cast<unsigned long long>(r.seq),
                          static_cast<unsigned long long>(r.rsi),
                          static_cast<unsigned long long>(rol10(r.word)));
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

#include "occ/inspect/analysis.h"

#include "occ/inspect/disasm.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace occ::inspect {
namespace {

// The file's little-endian readers. The parser has its own, private to it;
// the analysis reads raw header bytes for the data directories, so it
// carries the same two helpers -- and nothing else of the parser's
// internals.
[[nodiscard]] std::uint32_t read_u32(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

[[nodiscard]] std::uint64_t read_u64(const std::uint8_t* p) noexcept {
    return static_cast<std::uint64_t>(read_u32(p)) |
           (static_cast<std::uint64_t>(read_u32(p + 4)) << 32);
}

// The caps. Each exists because a packed or generated image can hold more
// of one thing than any reader wants to page through, and each is reported
// in the document next to the count it truncates, so a consumer knows an
// answer is bounded rather than complete.
constexpr std::uint32_t kMaxFunctionsWalked = 8192;
constexpr std::uint32_t kMaxInstructionsPerFunction = 32768;
constexpr std::uint32_t kMaxXrefOrigins = 32;
constexpr std::size_t kMaxStrings = 65536;
constexpr std::size_t kMinString = 5;

// A tiny JSON writer. The report file has one; this file's needs are a
// subset and carrying the dependency in would couple two formats that
// change for different reasons. Strings written through `value` are
// escaped, because import names and string literals come from the file.
struct Json {
    std::string out;
    bool first = true;

    void comma() {
        if (!first) {
            out += ',';
        }
        first = false;
    }
    void key(const char* k) {
        comma();
        out += '"';
        out += k;
        out += "\":";
        // The value that follows is not a new element: the comma between
        // elements was already written above, and a second one would sit
        // between the key and its value.
        first = true;
    }
    void begin_object() {
        comma();
        out += '{';
        first = true;
    }
    void end_object() {
        out += '}';
        first = false;
    }
    void begin_array() {
        comma();
        out += '[';
        first = true;
    }
    void end_array() {
        out += ']';
        first = false;
    }
    void raw(const std::string& text) {
        comma();
        out += text;
        first = false;
    }
    void value(std::uint64_t v) {
        comma();
        out += std::to_string(v);
        first = false;
    }
    void value(int v) {
        comma();
        out += std::to_string(v);
        first = false;
    }
    void hex(std::uint64_t v) {
        comma();
        char buf[24];
        std::snprintf(buf, sizeof(buf), "\"0x%llx\"",
                      static_cast<unsigned long long>(v));
        out += buf;
        first = false;
    }
    void value(const std::string& text) {
        comma();
        out += '"';
        for (const char c : text) {
            switch (c) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
            }
        }
        out += '"';
        first = false;
    }
};

[[nodiscard]] bool in_file(std::uint64_t file_size, std::uint64_t offset,
                           std::uint64_t bytes) noexcept {
    return offset <= file_size && bytes <= file_size - offset;
}

// One imported function, keyed by the IAT slot's RVA -- which is the
// address a rip-relative call or jump names.
struct ImportSite {
    std::string dll;
    std::string name;
};

// Walks the import directory and maps every IAT slot's RVA to the
// "dll!name" it holds. The walk is the file's own: descriptors until a
// zeroed one, thunks until a zeroed one, ordinal entries skipped.
[[nodiscard]] std::unordered_map<std::uint64_t, ImportSite> import_sites(
    const parser::PeImage& image, const std::uint8_t* file,
    std::uint64_t file_size, std::uint64_t import_dir_rva,
    std::uint64_t import_dir_size, bool plus) {
    std::unordered_map<std::uint64_t, ImportSite> out;
    if (import_dir_rva == 0 || import_dir_size == 0) {
        return out;
    }
    const std::uint32_t thunk_size = plus ? 8 : 4;
    for (std::uint64_t descriptor = import_dir_rva;
         descriptor + 20 <= import_dir_rva + import_dir_size;
         descriptor += 20) {
        std::uint64_t at = 0;
        if (!image.to_file_offset(descriptor, at) ||
            !in_file(file_size, at, 20)) {
            break;
        }
        const std::uint32_t original_thunk = read_u32(file + at);
        const std::uint32_t name_rva = read_u32(file + at + 12);
        const std::uint32_t first_thunk = read_u32(file + at + 16);
        if (original_thunk == 0 && first_thunk == 0) {
            break;
        }
        std::string dll;
        std::uint64_t dll_offset = 0;
        if (image.to_file_offset(name_rva, dll_offset) &&
            in_file(file_size, dll_offset, 2)) {
            const std::uint8_t* p = file + dll_offset;
            while (p < file + file_size && *p != 0) {
                dll += static_cast<char>(*p++);
            }
        }
        // Two walks in step: the names (original thunks, or first thunks
        // when bound) and the IAT slots (first thunks) advance together,
        // so slot k of the IAT holds the function name k of the name
        // table -- which is the pairing the loader itself performs.
        std::uint64_t name_walk =
            original_thunk != 0 ? original_thunk : first_thunk;
        std::uint64_t slot_walk = first_thunk;
        for (std::uint32_t i = 0; i < 65536; ++i) {
            std::uint64_t name_offset = 0;
            if (!image.to_file_offset(name_walk, name_offset) ||
                !in_file(file_size, name_offset, thunk_size)) {
                break;
            }
            const std::uint64_t entry =
                plus ? read_u64(file + name_offset)
                     : read_u32(file + name_offset);
            if (entry == 0) {
                break;
            }
            ImportSite site;
            site.dll = dll;
            if ((entry >> ((plus ? 64 : 32) - 1)) == 0) {
                std::uint64_t fn_offset = 0;
                if (image.to_file_offset(
                        static_cast<std::uint32_t>(entry), fn_offset) &&
                    in_file(file_size, fn_offset, 3)) {
                    // Two bytes of hint precede the name.
                    const std::uint8_t* p = file + fn_offset + 2;
                    while (p < file + file_size && *p != 0) {
                        site.name += static_cast<char>(*p++);
                    }
                }
            } else {
                site.name = "ordinal#" +
                            std::to_string(entry & 0xFFFFu);
            }
            // Keyed by the slot's virtual address: the targets a decoded
            // instruction names are VAs, and a lookup that had to remember
            // to subtract the base at every site is a lookup that one
            // caller eventually forgets.
            out[image.image_base() + slot_walk] = site;
            name_walk += thunk_size;
            slot_walk += thunk_size;
        }
    }
    return out;
}

// One printable string, at the RVA it lives at -- the target a rip-relative
// reference names.
struct StringSite {
    std::uint64_t rva = 0;
    std::string text;
};

// Collects the ASCII strings of the data sections, with their RVAs. The
// extraction is the report's own -- runs of printable bytes above the
// minimum length -- keyed by where they live rather than listed in order.
[[nodiscard]] std::unordered_map<std::uint64_t, std::string> string_sites(
    const parser::PeImage& image, const std::uint8_t* file,
    std::uint64_t file_size) {
    std::unordered_map<std::uint64_t, std::string> out;
    std::size_t found = 0;
    for (const parser::PeSection& s : image.sections()) {
        if (s.executable() || s.raw_size == 0 ||
            !in_file(file_size, s.raw_offset, s.raw_size)) {
            continue;
        }
        const std::uint8_t* p = file + s.raw_offset;
        std::size_t run = 0;
        for (std::size_t i = 0; i <= s.raw_size; ++i) {
            const bool printable =
                i < s.raw_size && p[i] >= 0x20 && p[i] < 0x7F;
            if (printable) {
                ++run;
                continue;
            }
            if (run >= kMinString && found < kMaxStrings) {
                std::string text(reinterpret_cast<const char*>(p + i - run),
                                 run);
                // Keyed by VA, for the same reason the imports are.
                out[image.image_base() + s.virtual_address + (i - run)] =
                    std::move(text);
                ++found;
            }
            run = 0;
        }
    }
    return out;
}

// One function, from the .pdata table's own row.
struct Function {
    std::uint64_t begin = 0;
    std::uint64_t end = 0;
    std::uint32_t unwind = 0;
};

// The .pdata table: the runtime function rows, in the order the file
// lists them, which the loader requires to be sorted by start address.
[[nodiscard]] std::vector<Function> pdata_functions(
    const parser::PeImage& image, const std::uint8_t* file,
    std::uint64_t file_size, std::uint64_t pdata_rva,
    std::uint64_t pdata_size) {
    std::vector<Function> out;
    if (pdata_rva == 0 || pdata_size < 12) {
        return out;
    }
    const std::uint64_t rows = pdata_size / 12;
    out.reserve(rows < 100000 ? rows : 100000);
    for (std::uint64_t i = 0; i < rows; ++i) {
        std::uint64_t at = 0;
        if (!image.to_file_offset(pdata_rva + i * 12, at) ||
            !in_file(file_size, at, 12)) {
            break;
        }
        Function f;
        f.begin = read_u32(file + at);
        f.end = read_u32(file + at + 4);
        f.unwind = read_u32(file + at + 8);
        if (f.begin == 0 && f.end == 0) {
            break;  // the terminating row
        }
        out.push_back(f);
    }
    return out;
}

// The xref one decoded instruction contributes. Branch targets are code
// references; rip-relative memory operands are data or import references.
struct Xref {
    std::uint64_t from = 0;
    std::uint64_t to = 0;
    InsnKind kind = InsnKind::Other;
};

// What a target is, is answered inline where the xref is printed: the
// import table, the function table and the string set are each consulted
// in turn, and the first that names the target labels it.

// The structural stamps: shapes whose meaning is local to the bytes that
// carry them, so naming them is a fact and not a guess.
[[nodiscard]] const char* stamp_of(const std::uint8_t* p,
                                   std::size_t available) noexcept {
    // endbr64: F3 0F 1E FA. Every MSVC and modern GCC function prologue
    // carries it under CET, and its presence at a function start is the
    // compiler fingerprint the analysis reports.
    if (available >= 4 && p[0] == 0xF3 && p[1] == 0x0F && p[2] == 0x1E &&
        p[3] == 0xFA) {
        return "endbr64_prologue";
    }
    // xor eax, eax; ret -- the zero-return the compilers emit for stubs
    // and for the failure paths of thin wrappers.
    if (available >= 4 && p[0] == 0x48 && p[1] == 0x31 && p[2] == 0xC0 &&
        p[3] == 0xC3) {
        return "xor_zero_return";
    }
    if (available >= 3 && p[0] == 0x31 && p[1] == 0xC0 && p[2] == 0xC3) {
        return "xor_zero_return";
    }
    // A tail-jump through the IAT -- the import thunk. Named by the
    // signature pass below, but stamped here so the count is visible.
    if (available >= 6 && p[0] == 0xFF && p[1] == 0x25) {
        return "iat_jump_thunk";
    }
    return nullptr;
}

}  // namespace

std::string analyze_pe_json(const parser::PeImage& image,
                            ByteSpan bytes) {
    // A parse that failed has no sections and no directories to walk; the
    // honest answer is no document, and the caller reports the parse's
    // own error -- the same contract inspect_pe_json states.
    if (!image.ok()) {
        return "";
    }
    const auto* file = static_cast<const std::uint8_t*>(bytes.data());
    const std::uint64_t file_size = bytes.size();
    const bool plus = image.is_pe32_plus();

    // The data directories the analysis reads: imports (1) and exceptions
    // (3). Read from the optional header the parse carried, at the offsets
    // the PE32/PE32+ layouts agree on for the first sixteen entries.
    std::uint64_t dir_rva[16] = {};
    std::uint32_t dir_size[16] = {};
    {
        // The directory table's file offset is anchored at the PE header
        // the DOS header names, not at RVA 0: the optional header starts
        // 24 bytes into the PE signature + COFF header, and the directory
        // table follows the fixed part of the optional header -- 112 bytes
        // for PE32+, 96 for PE32.
        const std::uint64_t pe_at = read_u32(file + 0x3C);
        const std::size_t opt_start = pe_at + 24;
        const std::size_t dir_table =
            opt_start + (plus ? 112 : 96);
        if (in_file(file_size, dir_table, 16 * 8)) {
            for (std::size_t i = 0; i < 16; ++i) {
                const std::uint64_t entry = dir_table + i * 8;
                dir_rva[i] = read_u32(file + entry);
                dir_size[i] = read_u32(file + entry + 4);
            }
        }
    }

    const auto imports = import_sites(image, file, file_size, dir_rva[1],
                                      dir_size[1], plus);
    const auto strings = string_sites(image, file, file_size);
    const auto functions =
        pdata_functions(image, file, file_size, dir_rva[3], dir_size[3]);

    std::unordered_map<std::uint64_t, std::uint64_t> function_begin;
    for (const Function& f : functions) {
        function_begin[image.image_base() + f.begin] = f.end;
    }

    // -- the sweep ----------------------------------------------------------
    //
    // Every executable section, linearly: decode, collect the xref the
    // instruction contributes, and note the stamps at function starts.
    struct TargetRefs {
        std::vector<std::uint64_t> from;
        bool call = false;
        bool jump = false;
        bool data = false;
        bool truncated = false;
    };
    std::unordered_map<std::uint64_t, TargetRefs> xrefs;
    std::vector<Xref> call_edges;
    std::uint32_t functions_walked = 0;
    std::uint32_t instructions_decoded = 0;
    bool functions_capped = false;

    // Import thunks and stamps, found during the same walk.
    struct Thunk {
        std::uint64_t va = 0;
        std::uint64_t iat_rva = 0;
    };
    std::vector<Thunk> thunks;
    std::vector<std::pair<std::uint64_t, const char*>> stamps;

    for (const parser::PeSection& s : image.sections()) {
        if (!s.executable() || s.raw_size == 0 ||
            !in_file(file_size, s.raw_offset, s.raw_size)) {
            continue;
        }
        const std::uint8_t* base = file + s.raw_offset;
        const std::uint64_t section_rva = s.virtual_address;
        std::size_t offset = 0;
        while (offset + 1 < s.raw_size) {
            Decoded insn;
            const std::uint32_t length =
                x64_decode(base + offset, s.raw_size - offset,
                           image.image_base() + section_rva + offset, insn);
            if (length == 0) {
                ++offset;
                continue;
            }
            ++instructions_decoded;
            const std::uint64_t va =
                image.image_base() + section_rva + offset;

            // The stamps only mean something at a function's first byte.
            if (function_begin.count(va) != 0) {
                if (functions_walked < kMaxFunctionsWalked) {
                    ++functions_walked;
                } else {
                    functions_capped = true;
                }
                if (const char* stamp =
                        stamp_of(base + offset, s.raw_size - offset)) {
                    stamps.emplace_back(va, stamp);
                }
            }

            // The import tail-thunk: jmp [rip+X] into the IAT. Named from
            // the IAT, which is the image naming its own functions.
            if (insn.kind == InsnKind::Jmp && insn.has_rip_target &&
                imports.count(insn.rip_target) != 0) {
                thunks.push_back({va, insn.rip_target});
            }

            if (insn.has_branch_target) {
                TargetRefs& refs = xrefs[insn.branch_target];
                if (refs.from.size() < kMaxXrefOrigins) {
                    refs.from.push_back(va);
                } else {
                    refs.truncated = true;
                }
                if (insn.kind == InsnKind::Call) {
                    refs.call = true;
                    call_edges.push_back({va, insn.branch_target,
                                          InsnKind::Call});
                } else if (insn.kind == InsnKind::Jmp ||
                           insn.kind == InsnKind::Jcc) {
                    refs.jump = true;
                }
            }
            if (insn.has_rip_target) {
                TargetRefs& refs = xrefs[insn.rip_target];
                if (refs.from.size() < kMaxXrefOrigins) {
                    refs.from.push_back(va);
                } else {
                    refs.truncated = true;
                }
                // An indirect call or jump through an IAT slot is a call
                // edge like a direct one, and the slot names the callee:
                // `call [rip+X]` is how every import is reached. A plain
                // rip-relative load is a data reference, and stays one.
                const auto import_it = imports.find(insn.rip_target);
                if (import_it != imports.end() &&
                    (insn.kind == InsnKind::Call ||
                     insn.kind == InsnKind::Jmp)) {
                    if (insn.kind == InsnKind::Call) {
                        refs.call = true;
                        call_edges.push_back({va, insn.rip_target,
                                              InsnKind::Call});
                    } else {
                        refs.jump = true;
                    }
                } else {
                    refs.data = true;
                }
            }

            offset += length;
        }
    }

    // -- the per-function walk ----------------------------------------------
    //
    // Blocks and calls, per .pdata function. The walk stops at the
    // function's own end, so a jump table's targets cannot pull the
    // sweep into another function's bytes.
    struct BlockEdge {
        std::uint64_t to = 0;
        bool conditional = false;
    };
    struct FunctionAnalysis {
        std::uint32_t instructions = 0;
        std::uint32_t blocks = 0;
        std::vector<std::uint64_t> leaders;
        std::vector<BlockEdge> edges;
        struct Call {
            std::uint64_t from = 0;
            std::uint64_t to = 0;
            const ImportSite* import = nullptr;
            bool in_function = false;
        };
        std::vector<Call> calls;
        bool truncated = false;
    };
    std::unordered_map<std::uint64_t, FunctionAnalysis> analysis;
    for (const Function& f : functions) {
        if (analysis.size() >= kMaxFunctionsWalked) {
            functions_capped = true;
            break;
        }
        FunctionAnalysis& fa = analysis[f.begin];
        if (f.end <= f.begin) {
            continue;
        }
        const std::uint64_t span = f.end - f.begin;
        // The function's bytes come from whichever section holds them; a
        // function the file does not back is skipped, not invented.
        std::uint64_t offset = 0;
        if (!image.to_file_offset(f.begin, offset)) {
            continue;
        }
        if (!in_file(file_size, offset, span)) {
            continue;
        }
        const std::uint8_t* base = file + offset;
        std::uint64_t at = 0;
        fa.leaders.push_back(image.image_base() + f.begin);
        while (at < span) {
            if (fa.instructions >= kMaxInstructionsPerFunction) {
                fa.truncated = true;
                break;
            }
            Decoded insn;
            const std::uint32_t length =
                x64_decode(base + at, static_cast<std::size_t>(span - at),
                           image.image_base() + f.begin + at, insn);
            if (length == 0) {
                ++at;
                continue;
            }
            ++fa.instructions;
            const std::uint64_t va = image.image_base() + f.begin + at;

            if (insn.has_branch_target) {
                // A target inside the function is a leader; the edge is
                // recorded either way, and labeled by where it lands.
                if (insn.branch_target >= image.image_base() + f.begin &&
                    insn.branch_target < image.image_base() + f.end) {
                    fa.leaders.push_back(insn.branch_target);
                }
                fa.edges.push_back(
                    {insn.branch_target, insn.kind == InsnKind::Jcc});
            }
            if (insn.kind == InsnKind::Call && insn.has_branch_target) {
                FunctionAnalysis::Call call;
                call.from = va;
                call.to = insn.branch_target;
                const auto it = imports.find(insn.branch_target);
                if (it != imports.end()) {
                    call.import = &it->second;
                }
                if (function_begin.count(insn.branch_target) != 0) {
                    call.in_function = true;
                }
                fa.calls.push_back(call);
            }
            // A rip-relative call or jump names an IAT slot: the import
            // the indirect call reaches.
            if (insn.kind == InsnKind::Call && insn.has_rip_target) {
                const auto it = imports.find(insn.rip_target);
                if (it != imports.end()) {
                    FunctionAnalysis::Call call;
                    call.from = va;
                    call.to = insn.rip_target;
                    call.import = &it->second;
                    fa.calls.push_back(call);
                }
            }
            at += length;
        }
        // The block count is the leader set's size, deduplicated by the
        // set the leaders were collected into.
        std::sort(fa.leaders.begin(), fa.leaders.end());
        fa.leaders.erase(std::unique(fa.leaders.begin(), fa.leaders.end()),
                         fa.leaders.end());
        fa.blocks = static_cast<std::uint32_t>(fa.leaders.size());
    }

    // -- the document -------------------------------------------------------
    Json json;
    json.begin_object();

    json.key("image_base");
    json.hex(image.image_base());

    // Functions.
    json.key("functions");
    json.begin_object();
    json.key("total");
    json.value(static_cast<std::uint64_t>(functions.size()));
    json.key("walked");
    json.value(static_cast<std::uint64_t>(functions_walked));
    json.key("capped");
    json.value(functions_capped);
    json.key("list");
    json.begin_array();
    for (const Function& f : functions) {
        if (functions_capped &&
            json.out.size() > 32u * 1024u * 1024u) {
            break;
        }
        json.begin_object();
        json.key("begin");
        json.hex(image.image_base() + f.begin);
        json.key("end");
        json.hex(image.image_base() + f.end);
        json.key("bytes");
        json.value(static_cast<std::uint64_t>(f.end - f.begin));
        const auto it = analysis.find(f.begin);
        if (it != analysis.end()) {
            json.key("instructions");
            json.value(static_cast<std::uint64_t>(it->second.instructions));
            json.key("blocks");
            json.value(static_cast<std::uint64_t>(it->second.blocks));
            json.key("cfg_truncated");
            json.value(it->second.truncated);
            if (it->second.blocks <= 64 && !it->second.truncated) {
                // The small functions carry their blocks: the graph a
                // reader can hold whole is the graph worth printing.
                json.key("block_starts");
                json.begin_array();
                for (const std::uint64_t leader : it->second.leaders) {
                    json.hex(leader);
                }
                json.end_array();
                json.key("edges");
                json.begin_array();
                for (const BlockEdge& e : it->second.edges) {
                    json.begin_object();
                    json.key("to");
                    json.hex(e.to);
                    json.key("conditional");
                    json.value(e.conditional);
                    json.end_object();
                }
                json.end_array();
            }
            json.key("calls");
            json.begin_array();
            for (const FunctionAnalysis::Call& c : it->second.calls) {
                json.begin_object();
                json.key("at");
                json.hex(c.from);
                json.key("to");
                json.hex(c.to);
                if (c.import != nullptr) {
                    json.key("import");
                    json.value(c.import->dll + "!" + c.import->name);
                } else if (c.in_function) {
                    json.key("function");
                    json.value(true);
                }
                json.end_object();
            }
            json.end_array();
        }
        json.end_object();
    }
    json.end_array();
    json.end_object();

    // Xrefs, grouped by target.
    json.key("xrefs");
    json.begin_object();
    json.key("instructions_decoded");
    json.value(static_cast<std::uint64_t>(instructions_decoded));
    json.key("targets");
    json.value(static_cast<std::uint64_t>(xrefs.size()));
    json.key("list");
    json.begin_array();
    for (const auto& [target, refs] : xrefs) {
        json.begin_object();
        json.key("target");
        json.hex(target);
        json.key("what");
        if (imports.count(target) != 0) {
            const ImportSite& site = imports.at(target);
            json.value(std::string("import ") + site.dll + "!" + site.name);
        } else if (function_begin.count(target) != 0) {
            json.value("function");
        } else {
            const auto it = strings.find(target);
            if (it != strings.end()) {
                json.value(std::string("string \"") + it->second + "\"");
            } else {
                json.value("data");
            }
        }
        json.key("is_call");
        json.value(refs.call);
        json.key("is_jump");
        json.value(refs.jump);
        json.key("is_data");
        json.value(refs.data);
        json.key("from_count");
        json.value(static_cast<std::uint64_t>(refs.from.size()));
        json.key("from");
        json.begin_array();
        for (const std::uint64_t origin : refs.from) {
            json.hex(origin);
        }
        json.end_array();
        json.key("origins_truncated");
        json.value(refs.truncated);
        json.end_object();
    }
    json.end_array();
    json.end_object();

    // The call graph, as edges with names where names exist.
    json.key("callgraph");
    json.begin_object();
    json.key("edges");
    json.value(static_cast<std::uint64_t>(call_edges.size()));
    json.key("capped");
    json.value(call_edges.size() > 100000);
    json.key("list");
    json.begin_array();
    std::size_t edge_written = 0;
    for (const Xref& e : call_edges) {
        if (edge_written >= 100000) {
            break;
        }
        ++edge_written;
        json.begin_object();
        json.key("from");
        json.hex(e.from);
        json.key("to");
        json.hex(e.to);
        const auto it = imports.find(e.to);
        if (it != imports.end()) {
            json.key("import");
            json.value(it->second.dll + "!" + it->second.name);
        } else if (function_begin.count(e.to) != 0) {
            json.key("function");
            json.value(true);
        }
        json.end_object();
    }
    json.end_array();
    json.end_object();

    // The names the image gives itself.
    json.key("signatures");
    json.begin_object();
    json.key("imports_resolved");
    json.value(static_cast<std::uint64_t>(imports.size()));
    json.key("thunks");
    json.begin_array();
    for (const Thunk& t : thunks) {
        const auto it = imports.find(t.iat_rva);
        if (it == imports.end()) {
            continue;
        }
        json.begin_object();
        json.key("at");
        json.hex(t.va);
        json.key("name");
        json.value(it->second.dll + "!" + it->second.name);
        json.end_object();
    }
    json.end_array();
    json.key("stamps");
    json.begin_array();
    for (const auto& [va, stamp] : stamps) {
        json.begin_object();
        json.key("at");
        json.hex(va);
        json.key("stamp");
        json.value(stamp);
        json.end_object();
    }
    json.end_array();
    json.key("strings_named");
    json.value(static_cast<std::uint64_t>(strings.size()));
    json.end_object();

    json.end_object();
    return json.out;
}

}  // namespace occ::inspect

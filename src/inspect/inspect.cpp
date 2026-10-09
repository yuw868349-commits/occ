// The static inspection of a PE image, written out structure by structure.
//
// Every section of the report answers a question an analyst asks with a
// second tool today: what the header flags promise, where the entry point
// is, which functions the image imports and by what hint, which it exports
// and which of those are forwarders, where the TLS template lives and which
// callbacks run on thread attach, how many unwind records the exception
// table carries and what each says, what the resource tree holds, where the
// debug directory points and which PDB it names, how the relocations are
// distributed by type, and how random each section's bytes are -- the
// entropy that separates compiled code from a packed payload.
//
// The parsing is deliberately skeptical. A malformed structure is reported
// as malformed -- `null`, or a count with a `"truncated"` marker -- rather
// than skipped, because the shape of the damage is evidence: an import
// directory that claims twenty DLLs but ends after three is a packed or
// damaged image, and the report says so rather than pretending the
// remaining seventeen were read.
//
// Nothing here runs the image. This file is the static half of the
// toolkit; the dynamic half is `occ run`'s event stream.

#include "occ/inspect/inspect.h"

#include <cmath>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace occ::inspect {
namespace {

// ---------------------------------------------------------------------------
// The JSON writer
// ---------------------------------------------------------------------------

// A tiny streaming JSON writer. It exists because the report is one nested
// document and building it out of string concatenation would escape every
// quote wrong exactly once. Every string that reaches it is escaped
// properly, including the control characters a PDB path can carry.
class Json {
public:
    explicit Json(std::string& out) : out_(out) {}

    void begin_object() {
        separator();
        out_ += '{';
        need_sep_ = false;
        stack_.push_back(false);
    }
    void end_object() {
        out_ += '}';
        stack_.pop_back();
        need_sep_ = true;
    }
    void begin_array() {
        separator();
        out_ += '[';
        need_sep_ = false;
        stack_.push_back(true);
    }
    void end_array() {
        out_ += ']';
        stack_.pop_back();
        need_sep_ = true;
    }

    void key(const char* k) {
        separator();
        write_string(k);
        out_ += ':';
        need_sep_ = false;
    }

    void value(const char* v) {
        separator();
        write_string(v);
        need_sep_ = true;
    }
    void value(const std::string& v) {
        separator();
        write_string(v);
        need_sep_ = true;
    }
    void value(std::uint64_t v) {
        separator();
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%llu",
                      static_cast<unsigned long long>(v));
        out_ += buf;
        need_sep_ = true;
    }
    void value(std::uint32_t v) { value(static_cast<std::uint64_t>(v)); }
    void value(int v) {
        separator();
        out_ += std::to_string(v);
        need_sep_ = true;
    }
    void value(bool v) {
        separator();
        out_ += v ? "true" : "false";
        need_sep_ = true;
    }
    // A hex number, for the addresses and masks an analyst reads in hex.
    void hex(std::uint64_t v) {
        separator();
        char buf[32];
        std::snprintf(buf, sizeof(buf), "\"0x%llx\"",
                      static_cast<unsigned long long>(v));
        out_ += buf;
        need_sep_ = true;
    }
    // A real number with two decimals -- the entropy's whole precision.
    void value(double v) {
        separator();
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%.2f", v);
        out_ += buf;
        need_sep_ = true;
    }
    void null() {
        separator();
        out_ += "null";
        need_sep_ = true;
    }

private:
    void separator() {
        if (need_sep_ && !stack_.empty()) {
            out_ += ',';
        }
    }
    void write_string(const std::string& v) {
        out_ += '"';
        for (const char c : v) {
            const auto uc = static_cast<unsigned char>(c);
            switch (c) {
            case '"':
                out_ += "\\\"";
                break;
            case '\\':
                out_ += "\\\\";
                break;
            case '\n':
                out_ += "\\n";
                break;
            case '\r':
                out_ += "\\r";
                break;
            case '\t':
                out_ += "\\t";
                break;
            default:
                if (uc < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", uc);
                    out_ += buf;
                } else {
                    out_ += c;
                }
            }
        }
        out_ += '"';
    }

    std::string& out_;
    std::vector<bool> stack_;
    bool need_sep_ = false;
};

// ---------------------------------------------------------------------------
// Reading helpers
// ---------------------------------------------------------------------------

// Whether [offset, offset+bytes) lies inside the file. Every read below is
// guarded by this first, because a truncated structure is evidence and a
// read past the end is a crash.
[[nodiscard]] bool in_file(std::uint64_t file_size, std::uint64_t offset,
                           std::uint64_t bytes) noexcept {
    return offset <= file_size && bytes <= file_size - offset;
}

[[nodiscard]] std::uint16_t read_u16(const std::uint8_t* p) noexcept {
    std::uint16_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

[[nodiscard]] std::uint32_t read_u32(const std::uint8_t* p) noexcept {
    std::uint32_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

[[nodiscard]] std::uint64_t read_u64(const std::uint8_t* p) noexcept {
    std::uint64_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

// Shannon entropy over one span of bytes, in bits per byte. Zero-length
// spans answer 0 rather than dividing by zero.
[[nodiscard]] double entropy_of(const std::uint8_t* data,
                                std::size_t bytes) noexcept {
    if (bytes == 0) {
        return 0.0;
    }
    std::uint64_t counts[256] = {};
    for (std::size_t i = 0; i < bytes; ++i) {
        ++counts[data[i]];
    }
    double entropy = 0.0;
    for (const std::uint64_t count : counts) {
        if (count == 0) {
            continue;
        }
        const double p = static_cast<double>(count) / static_cast<double>(bytes);
        entropy -= p * std::log2(p);
    }
    return entropy;
}

// The resource type a numeric first-level node names, or null for a custom
// type the tree names itself.
[[nodiscard]] const char* resource_type_name(std::uint32_t id) noexcept {
    switch (id) {
    case 1: return "CURSOR";
    case 2: return "BITMAP";
    case 3: return "ICON";
    case 4: return "MENU";
    case 5: return "DIALOG";
    case 6: return "STRINGTABLE";
    case 7: return "FONTDIR";
    case 8: return "FONT";
    case 9: return "ACCELERATOR";
    case 10: return "RCDATA";
    case 11: return "MESSAGETABLE";
    case 12: return "GROUP_CURSOR";
    case 14: return "GROUP_ICON";
    case 16: return "VERSION";
    case 23: return "MANIFEST";
    case 24: return "HTML";
    default: return nullptr;
    }
}

// The resource node's name or id. The high bit of the first word decides
// which: set, the word is an offset to a UTF-16 name string; clear, it is
// the id itself.
[[nodiscard]] std::string resource_node_name(const std::uint8_t* base,
                                             std::uint32_t field,
                                             std::size_t section_span,
                                             bool from_file) noexcept {
    if ((field & 0x80000000u) == 0) {
        return std::to_string(field);
    }
    const std::uint64_t offset =
        static_cast<std::uint64_t>(field & 0x7FFFFFFFu);
    if (offset + 2 > section_span) {
        return "?";
    }
    const std::uint16_t chars = static_cast<std::uint16_t>(
        read_u16(base + offset) / sizeof(char16_t));
    std::string out;
    for (std::uint16_t i = 0; i < chars && offset + 2 + i * 2 + 1 < section_span;
         ++i) {
        const std::uint16_t c =
            read_u16(base + offset + 2 + i * 2);
        out += (c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '?';
    }
    static_cast<void>(from_file);
    return out;
}

// The DLL characteristics, as the names an analyst reads rather than a mask.
void write_dll_characteristics(Json& json, std::uint32_t characteristics) {
    json.begin_array();
    struct Flag {
        std::uint32_t bit;
        const char* name;
    };
    static constexpr Flag flags[] = {
        {0x0020, "HIGH_ENTROPY_VA"},
        {0x0040, "DYNAMIC_BASE"},
        {0x0100, "NX_COMPAT"},
        {0x0200, "NO_SEH"},
        {0x0400, "NO_BIND"},
        {0x1000, "WDM_DRIVER"},
        {0x2000, "TERMINAL_SERVER_AWARE"},
        {0x8000, "CONTROL_FLOW_GUARD"},
    };
    for (const Flag& flag : flags) {
        if ((characteristics & flag.bit) != 0) {
            json.value(flag.name);
        }
    }
    json.end_array();
}

// The section characteristics, in the same style.
void write_section_characteristics(Json& json, std::uint32_t characteristics) {
    json.begin_array();
    struct Flag {
        std::uint32_t bit;
        const char* name;
    };
    static constexpr Flag flags[] = {
        {0x00000020, "CODE"},
        {0x00000040, "INITIALIZED_DATA"},
        {0x00000080, "UNINITIALIZED_DATA"},
        {0x02000000, "DISCARDABLE"},
        {0x04000000, "NOT_CACHED"},
        {0x08000000, "NOT_PAGED"},
        {0x10000000, "SHARED"},
        {0x20000000, "EXECUTE"},
        {0x40000000, "READ"},
        {0x80000000, "WRITE"},
    };
    for (const Flag& flag : flags) {
        if ((characteristics & flag.bit) != 0) {
            json.value(flag.name);
        }
    }
    json.end_array();
}

// The machine's byte order is the guest's; the strings it holds are wide
// characters in UTF-16LE.
[[nodiscard]] bool printable_ascii(char c) noexcept {
    const auto uc = static_cast<unsigned char>(c);
    return uc >= 0x20 && uc < 0x7F;
}

}  // namespace

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

std::string inspect_pe_json(const parser::PeImage& image, ByteSpan bytes,
                            const InspectOptions& options) {
    std::string out;
    out.reserve(64 * 1024);
    Json json(out);
    json.begin_object();

    const auto* file = static_cast<const std::uint8_t*>(bytes.data());
    const std::size_t file_size = bytes.size();
    const std::uint32_t lfanew = read_u32(file + 0x3C);
    const auto* nt = file + lfanew;
    const bool plus = image.is_pe32_plus();

    // -- the identification ------------------------------------------------
    json.key("path");
    json.null();
    json.key("size");
    json.value(static_cast<std::uint64_t>(file_size));
    json.key("format");
    json.value("pe");
    json.key("pe32_plus");
    json.value(plus);
    json.key("kind");
    json.value(image.is_dll() ? "dll" : "executable");
    json.key("machine");
    json.value(parser::pe_machine_name(image.machine()));
    json.key("timestamp");
    {
        // The COFF timestamp, in the two forms it is read: the Unix time and
        // the reproducible-build hash it has become when the high bit is set.
        const std::uint32_t stamp = read_u32(nt + 8);
        json.value(static_cast<std::uint64_t>(stamp));
        json.key("timestamp_is_hash");
        json.value((stamp & 0x80000000u) != 0);
    }
    json.key("image_base");
    json.hex(image.image_base());
    json.key("image_size");
    json.hex(image.image_size());
    json.key("entry_rva");
    json.hex(image.entry_rva());
    json.key("entry_va");
    json.hex(image.entry_va());
    json.key("subsystem");
    json.value(parser::pe_subsystem_name(image.subsystem()));
    json.key("headers_size");
    json.value(static_cast<std::uint64_t>(image.headers_size()));
    json.key("section_alignment");
    json.hex(image.section_alignment());
    json.key("file_alignment");
    json.hex(image.file_alignment());

    // -- the optional header's security posture ----------------------------
    json.key("dll_characteristics");
    {
        const std::uint32_t offset = lfanew + 24 + (plus ? 70 : 68);
        const std::uint32_t characteristics =
            (in_file(file_size, offset, 2)) ? read_u16(file + offset) : 0;
        write_dll_characteristics(json, characteristics);
        json.key("dll_characteristics_raw");
        json.hex(characteristics);
    }
    json.key("linker_version");
    {
        const std::uint32_t offset = lfanew + 24 + 2;
        if (in_file(file_size, offset, 2)) {
            std::string v = std::to_string(file[offset]);
            v += ".";
            v += std::to_string(file[offset + 1]);
            json.value(v);
        } else {
            json.null();
        }
    }

    // -- the data directory -------------------------------------------------
    //
    // Sixteen optional structures, most of which are absent. Each is
    // reported with its rva, its size, and its name, because the *absent*
    // ones are as informative as the present ones: an image with no
    // exception directory and a .pdata section is an image that unpacked
    // itself after load.
    json.key("data_directories");
    json.begin_array();
    static const char* const directory_names[16] = {
        "export", "import", "resource", "exception", "certificate",
        "relocation", "debug", "architecture", "global_ptr", "tls",
        "load_config", "bound_import", "iat", "delay_import", "com", "reserved",
    };
    std::uint64_t directory_rva[16] = {};
    std::uint32_t directory_size[16] = {};
    {
        const std::uint32_t dir_at =
            lfanew + 24 + (plus ? 112u : 96u);
        for (std::size_t i = 0; i < 16; ++i) {
            const std::uint32_t at = dir_at + static_cast<std::uint32_t>(i) * 8;
            json.begin_object();
            json.key("name");
            json.value(directory_names[i]);
            if (in_file(file_size, at, 8)) {
                directory_rva[i] = read_u32(file + at);
                directory_size[i] = read_u32(file + at + 4);
            }
            json.key("rva");
            json.hex(directory_rva[i]);
            json.key("size");
            json.value(directory_size[i]);
            json.key("present");
            json.value(directory_size[i] != 0);
            json.end_object();
        }
    }
    json.end_array();

    // -- the sections, each with its entropy --------------------------------
    json.key("sections");
    json.begin_array();
    double total_entropy_numerator = 0.0;
    std::uint64_t total_entropy_weight = 0;
    for (const parser::PeSection& section : image.sections()) {
        json.begin_object();
        json.key("name");
        json.value(section.name);
        json.key("virtual_address");
        json.hex(section.virtual_address);
        json.key("virtual_size");
        json.hex(section.virtual_size);
        json.key("raw_offset");
        json.hex(section.raw_offset);
        json.key("raw_size");
        json.hex(section.raw_size);
        json.key("mapped_size");
        json.hex(section.mapped_size());
        json.key("protection");
        {
            std::string prot;
            if (section.executable()) {
                prot += 'x';
            }
            if (section.writable()) {
                prot += 'w';
            }
            if (section.readable()) {
                prot += 'r';
            }
            json.value(prot.empty() ? "-" : prot);
        }
        json.key("characteristics");
        write_section_characteristics(json, section.characteristics);
        double entropy = 0.0;
        if (section.raw_size != 0 &&
            in_file(file_size, section.raw_offset, section.raw_size)) {
            entropy = entropy_of(file + section.raw_offset, section.raw_size);
        }
        json.key("entropy");
        json.value(entropy);
        json.key("zero_tail_bytes");
        json.value(static_cast<std::uint64_t>(
            section.raw_size > section.virtual_size
                ? section.raw_size - section.virtual_size
                : 0));
        json.end_object();
        total_entropy_numerator += entropy * static_cast<double>(section.raw_size);
        total_entropy_weight += section.raw_size;
    }
    json.end_array();
    json.key("entropy_overall");
    json.value(total_entropy_weight == 0
                   ? 0.0
                   : total_entropy_numerator /
                         static_cast<double>(total_entropy_weight));

    // -- the imports, function by function ----------------------------------
    //
    // The import directory is walked through the *original* thunk when the
    // image has one, because that is the table the hint and the name live
    // in; the IAT is where the loader writes and is reported beside them so
    // a hook can be seen as a difference between the two.
    json.key("imports");
    json.begin_array();
    std::size_t import_functions = 0;
    bool truncated = false;
    {
        const std::uint64_t dir_rva = directory_rva[1];
        const std::uint32_t dir_size = directory_size[1];
        if (dir_rva != 0 && dir_size != 0) {
            std::uint64_t descriptor_at = dir_rva;
            for (std::uint32_t index = 0; index < 8192; ++index, descriptor_at += 20) {
                std::uint8_t descriptor[20];
                std::uint64_t file_offset = 0;
                if (!image.to_file_offset(descriptor_at, file_offset) ||
                    !in_file(file_size, file_offset, 20)) {
                    truncated = index != 0;
                    break;
                }
                std::memcpy(descriptor, file + file_offset, 20);
                const std::uint32_t original_thunk = read_u32(descriptor);
                const std::uint32_t name_rva = read_u32(descriptor + 12);
                const std::uint32_t first_thunk = read_u32(descriptor + 16);
                if (original_thunk == 0 && name_rva == 0 && first_thunk == 0) {
                    break;
                }

                std::string dll;
                if (image.to_file_offset(name_rva, file_offset) &&
                    in_file(file_size, file_offset, 1)) {
                    const std::uint8_t* p = file + file_offset;
                    while (*p != 0 && p < file + file_size) {
                        dll += static_cast<char>(*p++);
                    }
                }

                json.begin_object();
                json.key("dll");
                json.value(dll);
                json.key("iat_rva");
                json.hex(first_thunk);
                json.key("functions");
                json.begin_array();

                // The thunks are 8 bytes on PE32+ and 4 on PE32.
                const std::uint32_t thunk_size = plus ? 8 : 4;
                std::uint32_t ordinal_index = 0;
                for (; ordinal_index < 65536; ++ordinal_index) {
                    const std::uint64_t thunk_rva =
                        (original_thunk != 0 ? original_thunk : first_thunk) +
                        static_cast<std::uint64_t>(ordinal_index) * thunk_size;
                    std::uint64_t thunk_offset = 0;
                    if (!image.to_file_offset(thunk_rva, thunk_offset) ||
                        !in_file(file_size, thunk_offset, thunk_size)) {
                        truncated = true;
                        break;
                    }
                    std::uint64_t entry = plus
                                              ? read_u64(file + thunk_offset)
                                              : read_u32(file + thunk_offset);
                    if (entry == 0) {
                        break;
                    }
                    json.begin_object();
                    json.key("iat");
                    json.hex(image.image_base() + first_thunk +
                             static_cast<std::uint64_t>(ordinal_index) *
                                 thunk_size);
                    const bool by_ordinal =
                        (entry >> ((plus ? 64 : 32) - 1)) != 0;
                    if (by_ordinal) {
                        const std::uint64_t mask = plus ? 0xFFFFu : 0xFFFFu;
                        json.key("ordinal");
                        json.value(static_cast<std::uint64_t>(entry & mask));
                    } else {
                        // The hint travels in the two bytes before the name.
                        const std::uint32_t name_rva2 =
                            plus
                                ? static_cast<std::uint32_t>(entry & 0xFFFFFFFFu)
                                : static_cast<std::uint32_t>(entry);
                        std::uint64_t name_offset = 0;
                        if (image.to_file_offset(name_rva2, name_offset) &&
                            in_file(file_size, name_offset, 3)) {
                            json.key("hint");
                            json.value(read_u16(file + name_offset));
                            std::string fn;
                            const std::uint8_t* p = file + name_offset + 2;
                            while (p < file + file_size && *p != 0) {
                                fn += static_cast<char>(*p++);
                            }
                            json.key("name");
                            json.value(fn);
                        } else {
                            json.key("name");
                            json.null();
                        }
                    }
                    json.end_object();
                    ++import_functions;
                }
                json.end_array();
                json.key("function_count");
                json.value(static_cast<std::uint64_t>(ordinal_index));
                json.end_object();
            }
        }
    }
    json.end_array();
    json.key("imports_truncated");
    json.value(truncated);
    json.key("import_function_count");
    json.value(static_cast<std::uint64_t>(import_functions));

    // -- the exports ---------------------------------------------------------
    json.key("exports");
    {
        json.begin_object();
        json.key("ordinal_base");
        json.value(static_cast<std::uint64_t>(image.export_ordinal_base()));
        json.key("count");
        json.value(static_cast<std::uint64_t>(image.exports().size()));
        json.key("forwarders");
        std::uint64_t forwarders = 0;
        for (const parser::PeExport& entry : image.exports()) {
            if (entry.is_forwarder) {
                ++forwarders;
            }
        }
        json.value(forwarders);
        json.key("entries");
        json.begin_array();
        for (const parser::PeExport& entry : image.exports()) {
            json.begin_object();
            json.key("ordinal");
            json.value(static_cast<std::uint64_t>(entry.ordinal));
            json.key("name");
            if (entry.name.empty()) {
                json.null();
            } else {
                json.value(entry.name);
            }
            json.key("rva");
            json.hex(entry.rva);
            if (entry.is_forwarder) {
                std::string forwarder = entry.forwarder_dll;
                forwarder += "!";
                if (entry.forwarder_by_ordinal) {
                    forwarder += "#" + std::to_string(entry.forwarder_ordinal);
                } else {
                    forwarder += entry.forwarder_name;
                }
                json.key("forwarder");
                json.value(forwarder);
            }
            json.end_object();
        }
        json.end_array();
        json.end_object();
    }

    // -- the TLS directory ----------------------------------------------------
    //
    // The callbacks are walked until the null terminator, which is how the
    // platform walks them; a list that runs off the image without one is
    // reported as unterminated rather than followed.
    json.key("tls");
    {
        json.begin_object();
        const std::uint64_t dir_rva = directory_rva[9];
        const std::uint32_t dir_size = directory_size[9];
        bool present = false;
        if (dir_rva != 0 && dir_size >= 40) {
            std::uint64_t at = 0;
            if (image.to_file_offset(dir_rva, at) &&
                in_file(file_size, at, 40)) {
                present = true;
                const std::uint8_t* tls = file + at;
                const std::uint64_t raw_start = read_u64(tls);
                const std::uint64_t raw_end = read_u64(tls + 8);
                const std::uint64_t index_va = read_u64(tls + 16);
                const std::uint64_t callbacks_va = read_u64(tls + 24);
                const std::uint32_t zero_fill = read_u32(tls + 32);
                const std::uint32_t characteristics = read_u32(tls + 36);

                json.key("present");
                json.value(true);
                json.key("template_start");
                json.hex(raw_start);
                json.key("template_end");
                json.hex(raw_end);
                json.key("template_bytes");
                json.value(raw_end >= raw_start ? raw_end - raw_start : 0);
                json.key("zero_fill");
                json.value(static_cast<std::uint64_t>(zero_fill));
                json.key("index_va");
                json.hex(index_va);
                json.key("callbacks");
                json.begin_array();
                // The callback array is a pointer chain in the image, walked
                // until null, bounded so a corrupted list cannot run away.
                if (callbacks_va != 0) {
                    std::uint64_t callback_rva =
                        callbacks_va >= image.image_base()
                            ? callbacks_va - image.image_base()
                            : callbacks_va;
                    for (std::uint32_t i = 0; i < 64; ++i) {
                        std::uint64_t entry_offset = 0;
                        if (!image.to_file_offset(
                                callback_rva +
                                    static_cast<std::uint64_t>(i) * 8,
                                entry_offset) ||
                            !in_file(file_size, entry_offset, 8)) {
                            json.value("unreachable");
                            break;
                        }
                        const std::uint64_t fn =
                            read_u64(file + entry_offset);
                        if (fn == 0) {
                            break;
                        }
                        json.hex(fn);
                    }
                }
                json.end_array();
                json.key("characteristics");
                json.hex(characteristics);
            }
        }
        if (!present) {
            json.key("present");
            json.value(false);
        }
        json.end_object();
    }

    // -- the exception table ---------------------------------------------------
    //
    // Every RUNTIME_FUNCTION is a triple of RVAs; the unwind header that
    // follows each one is decoded into its version, its flags and its frame
    // register, because the flags name the functions that hook exceptions --
    // which is where a packer's personality routine lives.
    json.key("exceptions");
    {
        json.begin_object();
        const std::uint64_t dir_rva = directory_rva[3];
        const std::uint32_t dir_size = directory_size[3];
        json.key("present");
        json.value(dir_rva != 0 && dir_size != 0);
        const std::uint32_t count = dir_size / 12;
        json.key("function_count");
        json.value(static_cast<std::uint64_t>(count));
        json.key("flags_histogram");
        {
            json.begin_object();
            // The two flag bits of each unwind header: 0 none, 1 epilogue,
            // 2 chain, 3 custom. A histogram over the image is the shape of
            // its exception handling at a glance.
            std::uint64_t histogram[4] = {};
            std::uint64_t counted = 0;
            for (std::uint32_t i = 0; i < count; ++i) {
                std::uint64_t at = 0;
                if (!image.to_file_offset(dir_rva + static_cast<std::uint64_t>(i) * 12 + 8,
                                          at) ||
                    !in_file(file_size, at, 4)) {
                    break;
                }
                const std::uint32_t unwind_rva = read_u32(file + at);
                std::uint64_t unwind_offset = 0;
                if (!image.to_file_offset(unwind_rva, unwind_offset) ||
                    !in_file(file_size, unwind_offset, 4)) {
                    continue;
                }
                const std::uint32_t header = read_u32(file + unwind_offset);
                const std::uint32_t flags = (header >> 20) & 0x3u;
                ++histogram[flags];
                ++counted;
            }
            json.key("none");
            json.value(histogram[0]);
            json.key("epilogue");
            json.value(histogram[1]);
            json.key("chain");
            json.value(histogram[2]);
            json.key("custom");
            json.value(histogram[3]);
            json.key("counted");
            json.value(counted);
            json.end_object();
        }
        json.end_object();
    }

    // -- the resource tree -------------------------------------------------------
    //
    // Three levels, each a directory: type, name, language. The leaves are
    // the data entries, and a leaf's rva is relative to the resource
    // section, not the image -- a difference every other tool gets wrong
    // once.
    json.key("resources");
    {
        json.begin_object();
        const std::uint64_t dir_rva = directory_rva[2];
        bool present = dir_rva != 0;
        json.key("present");
        json.value(present);
        if (present) {
            // The section that holds the tree, found by rva.
            const parser::PeSection* section = nullptr;
            for (const parser::PeSection& s : image.sections()) {
                if (dir_rva >= s.virtual_address &&
                    dir_rva < s.virtual_address + s.mapped_size()) {
                    section = &s;
                    break;
                }
            }
            if (section == nullptr || section->raw_size == 0 ||
                !in_file(file_size, section->raw_offset, section->raw_size)) {
                present = false;
                json.key("unreachable");
                json.value(true);
            } else {
                const std::uint8_t* base = file + section->raw_offset;
                const std::uint64_t section_rva = section->virtual_address;
                const std::size_t section_span = section->raw_size;

                json.key("tree");
                json.begin_array();
                std::uint32_t entries_total = 0;
                // Level 1: types.
                if (in_file(file_size, section->raw_offset, 16)) {
                    const std::uint16_t named = read_u16(base + 2);
                    const std::uint16_t ided = read_u16(base + 4);
                    const std::uint32_t type_count =
                        static_cast<std::uint32_t>(named) + ided;
                    for (std::uint32_t t = 0; t < type_count && t < 64; ++t) {
                        const std::size_t entry_at = 16 + static_cast<std::size_t>(t) * 8;
                        if (entry_at + 8 > section_span) {
                            break;
                        }
                        const std::uint32_t name_field =
                            read_u32(base + entry_at);
                        const std::uint32_t offset_field =
                            read_u32(base + entry_at + 4);
                        const std::string type_name =
                            resource_node_name(base, name_field, section_span, true);
                        const bool is_directory =
                            (offset_field & 0x80000000u) != 0;
                        const std::uint32_t sub_offset =
                            offset_field & 0x7FFFFFFFu;

                        json.begin_object();
                        json.key("type");
                        if (const char* standard =
                                resource_type_name(
                                    static_cast<std::uint32_t>(
                                        std::strtoul(type_name.c_str(),
                                                     nullptr, 10)))) {
                            json.value(standard);
                        } else {
                            json.value(type_name);
                        }
                        json.key("named");
                        json.value((name_field & 0x80000000u) != 0);

                        // Level 2: names.
                        json.key("entries");
                        json.begin_array();
                        if (is_directory && sub_offset + 16 <= section_span) {
                            const std::uint16_t named2 =
                                read_u16(base + sub_offset + 2);
                            const std::uint16_t ided2 =
                                read_u16(base + sub_offset + 4);
                            const std::uint32_t name_count =
                                static_cast<std::uint32_t>(named2) + ided2;
                            for (std::uint32_t n = 0;
                                 n < name_count && n < 256; ++n) {
                                const std::size_t name_at =
                                    sub_offset + 16 + static_cast<std::size_t>(n) * 8;
                                if (name_at + 8 > section_span) {
                                    break;
                                }
                                const std::uint32_t res_name =
                                    read_u32(base + name_at);
                                const std::uint32_t lang_field =
                                    read_u32(base + name_at + 4);
                                const bool lang_is_dir =
                                    (lang_field & 0x80000000u) != 0;

                                json.begin_object();
                                json.key("name");
                                json.value(resource_node_name(
                                    base, res_name, section_span, true));

                                // Level 3: languages, then the data leaf.
                                if (lang_is_dir &&
                                    (lang_field & 0x7FFFFFFFu) + 16 <=
                                        section_span) {
                                    const std::uint32_t lang_dir =
                                        lang_field & 0x7FFFFFFFu;
                                    const std::uint16_t langs =
                                        read_u16(base + lang_dir + 4);
                                    json.key("languages");
                                    json.begin_array();
                                    for (std::uint32_t l = 0;
                                         l < langs && l < 32; ++l) {
                                        const std::size_t lang_at =
                                            lang_dir + 16 +
                                            static_cast<std::size_t>(l) * 8;
                                        if (lang_at + 8 > section_span) {
                                            break;
                                        }
                                        const std::uint32_t lang_id =
                                            read_u32(base + lang_at);
                                        const std::uint32_t data_field =
                                            read_u32(base + lang_at + 4);
                                        if ((data_field & 0x80000000u) != 0) {
                                            continue;
                                        }
                                        const std::uint32_t data_at =
                                            data_field & 0x7FFFFFFFu;
                                        if (data_at + 16 > section_span) {
                                            continue;
                                        }
                                        json.begin_object();
                                        json.key("id");
                                        json.value(lang_id);
                                        json.key("data_rva");
                                        json.hex(section_rva +
                                                 read_u32(base + data_at));
                                        json.key("data_size");
                                        json.value(read_u32(base + data_at + 4));
                                        json.end_object();
                                        ++entries_total;
                                    }
                                    json.end_array();
                                } else {
                                    const std::uint32_t data_at =
                                        lang_field & 0x7FFFFFFFu;
                                    if (data_at + 16 <= section_span) {
                                        json.key("data_rva");
                                        json.hex(section_rva +
                                                 read_u32(base + data_at));
                                        json.key("data_size");
                                        json.value(
                                            read_u32(base + data_at + 4));
                                        ++entries_total;
                                    }
                                }
                                json.end_object();
                            }
                        }
                        json.end_array();
                        json.end_object();
                    }
                }
                json.end_array();
                json.key("entry_count");
                json.value(static_cast<std::uint64_t>(entries_total));
            }
        }
        json.end_object();
    }

    // -- the debug directory -----------------------------------------------------
    //
    // The codeview entry names the PDB, and the PDB path is the single most
    // useful string in a binary: it names the machine that built it.
    json.key("debug");
    {
        json.begin_object();
        const std::uint64_t dir_rva = directory_rva[6];
        const std::uint32_t dir_size = directory_size[6];
        const std::uint32_t count = dir_size / 28;
        json.key("entry_count");
        json.value(static_cast<std::uint64_t>(count));
        json.key("entries");
        json.begin_array();
        for (std::uint32_t i = 0; i < count && i < 64; ++i) {
            std::uint64_t at = 0;
            if (!image.to_file_offset(dir_rva + static_cast<std::uint64_t>(i) * 28,
                                      at) ||
                !in_file(file_size, at, 28)) {
                break;
            }
            const std::uint32_t type = read_u32(file + at + 12);
            const std::uint32_t data_rva = read_u32(file + at + 20);
            const std::uint32_t data_size = read_u32(file + at + 16);
            json.begin_object();
            json.key("type");
            json.value(type == 1    ? "COFF"
                       : type == 2  ? "CODEVIEW"
                       : type == 12 ? "REPRO"
                                    : std::to_string(type).c_str());
            std::uint64_t data_offset = 0;
            if (type == 2 && image.to_file_offset(data_rva, data_offset) &&
                in_file(file_size, data_offset, 24) &&
                std::memcmp(file + data_offset, "RSDS", 4) == 0) {
                // RSDS: 4 signature, 16 GUID, 4 age, then the path.
                const std::uint8_t* guid = file + data_offset + 4;
                char guid_text[40];
                std::snprintf(
                    guid_text, sizeof(guid_text),
                    "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-"
                    "%02X%02X%02X%02X%02X%02X",
                    guid[3], guid[2], guid[1], guid[0], guid[5], guid[4],
                    guid[7], guid[6], guid[8], guid[9], guid[10], guid[11],
                    guid[12], guid[13], guid[14], guid[15]);
                json.key("pdb_guid");
                json.value(guid_text);
                json.key("pdb_age");
                json.value(read_u32(file + data_offset + 20));
                std::string pdb;
                const std::uint8_t* p = file + data_offset + 24;
                while (p < file + file_size && *p != 0) {
                    pdb += static_cast<char>(*p++);
                }
                json.key("pdb_path");
                json.value(pdb);
            }
            static_cast<void>(data_size);
            json.end_object();
        }
        json.end_array();
        json.end_object();
    }

    // -- the relocations, by type ---------------------------------------------------
    //
    // The histogram is what matters: an image whose relocations are all
    // DIR64 is an ordinary x64 image; one with HIGHLOW on an x64 image is
    // 32-bit code wearing a 64-bit header, and one with none at all cannot
    // be relocated, which is a fact its load depends on.
    json.key("relocations");
    {
        json.begin_object();
        const std::uint64_t dir_rva = directory_rva[5];
        const std::uint32_t dir_size = directory_size[5];
        json.key("present");
        json.value(dir_rva != 0 && dir_size != 0);
        json.key("bytes");
        json.value(static_cast<std::uint64_t>(dir_size));
        std::uint64_t blocks = 0;
        std::uint64_t by_type[16] = {};
        std::uint64_t entries = 0;
        std::uint64_t walked = 0;
        for (std::uint64_t at = dir_rva;
             at + 8 <= dir_rva + dir_size && blocks < 4096;) {
            std::uint64_t offset = 0;
            if (!image.to_file_offset(at, offset) ||
                !in_file(file_size, offset, 8)) {
                break;
            }
            const std::uint32_t page_rva = read_u32(file + offset);
            const std::uint32_t block_size = read_u32(file + offset + 4);
            if (block_size < 8 || at + block_size > dir_rva + dir_size) {
                break;
            }
            ++blocks;
            const std::uint32_t pair_count = (block_size - 8) / 2;
            for (std::uint32_t i = 0; i < pair_count; ++i) {
                const std::uint16_t entry =
                    read_u16(file + offset + 8 + static_cast<std::uint64_t>(i) * 2);
                const std::uint32_t type = entry >> 12;
                if (type < 16) {
                    ++by_type[type];
                }
                ++entries;
            }
            static_cast<void>(page_rva);
            at += block_size;
        }
        walked = blocks;
        json.key("blocks");
        json.value(walked);
        json.key("entries");
        json.value(entries);
        json.key("by_type");
        {
            json.begin_object();
            static const char* const type_names[16] = {
                "ABSOLUTE", "HIGH", "LOW", "HIGHLOW", "HIGHADJ",
                "MIPS_JMPADDR", "SECTION", "REL32", "GPREL32",
                "MIPS_JMPADDR16", "DIR64", "HIGH3ADJ", "TOKEN", "PCREL24",
                "UNKNOWN_14", "UNKNOWN_15",
            };
            for (std::uint32_t t = 0; t < 16; ++t) {
                if (by_type[t] != 0) {
                    json.key(type_names[t]);
                    json.value(by_type[t]);
                }
            }
            json.end_object();
        }
        json.end_object();
    }

    // -- the certificate table (Authenticode) ---------------------------------------
    json.key("certificate");
    {
        json.begin_object();
        const std::uint64_t dir_rva = directory_rva[4];
        const std::uint32_t dir_size = directory_size[4];
        json.key("present");
        json.value(dir_rva != 0 && dir_size != 0);
        json.key("bytes");
        json.value(static_cast<std::uint64_t>(dir_size));
        // The certificate table lives in the file, not the image, and its
        // rva field is a file offset -- the one data directory where the
        // field means something else, and the one every reader forgets.
        json.key("file_offset");
        json.hex(dir_rva);
        json.end_object();
    }

    // -- .NET AOT markers -------------------------------------------------------------
    //
    // The export named DotNetRuntimeDebugHeader and the .managed/hydrated
    // sections are the three markers of a .NET Native AOT binary, which is
    // a program whose GC and type system are compiled in -- and whose
    // thread model, TLS and heap the runtime must carry exactly.
    json.key("dotnet_aot");
    {
        json.begin_object();
        bool has_debug_header = false;
        for (const parser::PeExport& entry : image.exports()) {
            if (entry.name == "DotNetRuntimeDebugHeader") {
                has_debug_header = true;
                break;
            }
        }
        bool has_managed = false;
        bool has_hydrated = false;
        for (const parser::PeSection& s : image.sections()) {
            if (s.name == ".managed") {
                has_managed = true;
            }
            if (s.name == "hydrated") {
                has_hydrated = true;
            }
        }
        json.key("debug_header_export");
        json.value(has_debug_header);
        json.key("managed_section");
        json.value(has_managed);
        json.key("hydrated_section");
        json.value(has_hydrated);
        json.key("detected");
        json.value(has_debug_header && has_managed);
        json.end_object();
    }

    // -- the observations -----------------------------------------------------------
    //
    // What the structures above *mean* together: the flags an analyst reads
    // ten tools to collect. Deliberately few and deliberately stated, so a
    // reader can check each one against the sections that justify it.
    json.key("observations");
    {
        json.begin_array();
        // Anti-debug imports, which are the ordinary first question.
        static const char* const anti_debug[] = {
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "NtSetInformationThread",
            "NtQuerySystemInformation", "OutputDebugStringA",
            "OutputDebugStringW",
        };
        // The import names this runtime has read, matched case-sensitively
        // against the list above. A match is reported with the name so the
        // report is checkable against the import section beside it.
        std::vector<std::string> seen;
        {
            // Re-walk the file's import names, cheaply: the thunks again.
            const std::uint64_t dir_rva = directory_rva[1];
            const std::uint32_t dir_size = directory_size[1];
            const std::uint32_t thunk_size = plus ? 8 : 4;
            if (dir_rva != 0 && dir_size != 0) {
                for (std::uint64_t descriptor_at = dir_rva; descriptor_at + 20 <= dir_rva + dir_size;
                     descriptor_at += 20) {
                    std::uint64_t offset = 0;
                    if (!image.to_file_offset(descriptor_at, offset) ||
                        !in_file(file_size, offset, 20)) {
                        break;
                    }
                    const std::uint32_t original_thunk = read_u32(file + offset);
                    const std::uint32_t first_thunk = read_u32(file + offset + 16);
                    if (original_thunk == 0 && first_thunk == 0) {
                        break;
                    }
                    for (std::uint32_t i = 0; i < 65536; ++i) {
                        const std::uint64_t thunk_rva =
                            (original_thunk != 0 ? original_thunk : first_thunk) +
                            static_cast<std::uint64_t>(i) * thunk_size;
                        std::uint64_t thunk_offset = 0;
                        if (!image.to_file_offset(thunk_rva, thunk_offset) ||
                            !in_file(file_size, thunk_offset, thunk_size)) {
                            break;
                        }
                        const std::uint64_t entry =
                            plus ? read_u64(file + thunk_offset)
                                 : read_u32(file + thunk_offset);
                        if (entry == 0) {
                            break;
                        }
                        if ((entry >> ((plus ? 64 : 32) - 1)) != 0) {
                            continue;
                        }
                        const std::uint32_t name_rva =
                            plus ? static_cast<std::uint32_t>(entry)
                                 : static_cast<std::uint32_t>(entry);
                        std::uint64_t name_offset = 0;
                        if (!image.to_file_offset(name_rva, name_offset) ||
                            !in_file(file_size, name_offset, 3)) {
                            break;
                        }
                        std::string fn;
                        const std::uint8_t* p = file + name_offset + 2;
                        while (p < file + file_size && *p != 0) {
                            fn += static_cast<char>(*p++);
                        }
                        for (const char* suspect : anti_debug) {
                            if (fn == suspect) {
                                seen.push_back(fn);
                            }
                        }
                    }
                }
            }
        }
        if (!seen.empty()) {
            json.begin_object();
            json.key("kind");
            json.value("anti_debug_imports");
            json.key("names");
            json.begin_array();
            for (const std::string& name : seen) {
                json.value(name);
            }
            json.end_array();
            json.end_object();
        }
        // High-entropy executable sections: packed code, or code the file
        // stores encrypted.
        for (const parser::PeSection& s : image.sections()) {
            if (!s.executable() || s.raw_size == 0 ||
                !in_file(file_size, s.raw_offset, s.raw_size)) {
                continue;
            }
            const double entropy =
                entropy_of(file + s.raw_offset, s.raw_size);
            if (entropy > 7.2) {
                json.begin_object();
                json.key("kind");
                json.value("high_entropy_executable_section");
                json.key("section");
                json.value(s.name);
                json.key("entropy");
                json.value(entropy);
                json.end_object();
            }
        }
        // An image with a .managed section and a hydrated one is an AOT
        // .NET binary: noted, because the analysis approach differs.
        json.end_array();
    }

    // -- the strings -------------------------------------------------------------------
    //
    // Runs of printable ASCII and of UTF-16LE, above the minimum length.
    // Capped, because a packed image's false positives run to the thousands;
    // the cap is reported, so a truncated list is known to be one.
    if (options.strings) {
        json.key("strings");
        {
            json.begin_object();
            json.key("min_length");
            json.value(static_cast<std::uint64_t>(5));
            json.key("limit");
            json.value(static_cast<std::uint64_t>(options.string_limit));
            json.key("ascii");
            json.begin_array();
            std::uint64_t ascii_count = 0;
            bool ascii_capped = false;
            std::size_t i = 0;
            while (i < file_size) {
                if (!printable_ascii(static_cast<char>(file[i]))) {
                    ++i;
                    continue;
                }
                std::size_t j = i;
                while (j < file_size && printable_ascii(static_cast<char>(file[j]))) {
                    ++j;
                }
                if (j - i >= 5) {
                    ++ascii_count;
                    if (ascii_count <= options.string_limit) {
                        json.value(std::string(
                            reinterpret_cast<const char*>(file + i), j - i));
                    } else {
                        ascii_capped = true;
                    }
                }
                i = j;
            }
            json.end_array();
            json.key("ascii_count");
            json.value(ascii_count);
            json.key("ascii_capped");
            json.value(ascii_capped);

            json.key("utf16");
            json.begin_array();
            std::uint64_t utf16_count = 0;
            bool utf16_capped = false;
            i = 0;
            while (i + 1 < file_size) {
                // A UTF-16 run: low byte printable, high byte zero, for at
                // least the minimum length in characters.
                if (file[i + 1] != 0 ||
                    !printable_ascii(static_cast<char>(file[i]))) {
                    ++i;
                    continue;
                }
                std::size_t j = i;
                std::string run;
                while (j + 1 < file_size && file[j + 1] == 0 &&
                       printable_ascii(static_cast<char>(file[j]))) {
                    run += static_cast<char>(file[j]);
                    j += 2;
                }
                if (run.size() >= 5) {
                    ++utf16_count;
                    if (utf16_count <= options.string_limit) {
                        json.value(run);
                    } else {
                        utf16_capped = true;
                    }
                }
                i = (j > i + 1) ? j : i + 2;
            }
            json.end_array();
            json.key("utf16_count");
            json.value(utf16_count);
            json.key("utf16_capped");
            json.value(utf16_capped);
            json.end_object();
        }
    }

    json.end_object();
    return out;
}

}  // namespace occ::inspect

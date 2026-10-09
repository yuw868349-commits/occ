// `occ inspect <path>` -- the static report.
//
// One command, every structure the image carries, one JSON document. The
// flags select the additions: `--strings` is on by default and the
// disassembly is requested by rva, because a linear sweep of a whole image
// is a decision an analyst makes deliberately rather than a default.
//
//   occ inspect <path>                          the full structural report
//   occ inspect <path> --no-strings             skip the string extraction
//   occ inspect <path> --disasm <rva>           disassemble at an rva
//   occ inspect <path> --disasm <rva>:<count>   ... at most count instructions
//   occ inspect <path> --disasm <rva>:<count>:<bytes>   ... a raw byte range
//
// The rva form reads from the mapped image (a section the file holds); the
// three-part form decodes literal bytes, which is how a hook's prologue is
// analyzed without a file at all.

#include "occ/inspect/disasm.h"
#include "occ/inspect/inspect.h"
#include "occ/parser/pe.h"
#include "occ/commands.h"
#include "occ/util/fs.h"


#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

[[nodiscard]] int inspect_failure(const char* what, const std::string& path) {
    std::fprintf(stderr, "occ inspect: %s: %s\n", what, path.c_str());
    return 2;
}

}  // namespace

int occ::cmd_inspect(int argc, char** argv) {
    if (argc < 1 || argv[0] == nullptr || argv[0][0] == '\0') {
        std::fprintf(stderr,
                     "usage: occ inspect <path> [--no-strings] "
                     "[--disasm <rva>[:<count>[:<bytes>]]] [--limit <n>]\n");
        return 2;
    }

    const std::string path = argv[0];
    occ::inspect::InspectOptions options;
    bool want_disasm = false;
    std::uint64_t disasm_rva = 0;
    std::uint32_t disasm_count = 64;
    std::vector<std::uint8_t> disasm_bytes;
    std::uint64_t disasm_base = 0;

    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];
        if (std::strcmp(arg, "--no-strings") == 0) {
            options.strings = false;
        } else if (std::strcmp(arg, "--strings") == 0) {
            options.strings = true;
        } else if (std::strcmp(arg, "--disasm") == 0 && i + 1 < argc) {
            want_disasm = true;
            ++i;
            // The value is <rva>[:<count>[:<hex bytes>]]. The byte form
            // carries the commas-free hex of a prologue with the separators
            // the caller likes; the parser accepts both.
            const std::string spec = argv[i];
            std::vector<std::string> parts;
            std::string current;
            for (const char c : spec) {
                if (c == ':' || c == ',') {
                    parts.push_back(current);
                    current.clear();
                } else {
                    current += c;
                }
            }
            parts.push_back(current);
            if (parts.empty() || parts[0].empty()) {
                std::fprintf(stderr, "occ inspect: --disasm needs an rva\n");
                return 2;
            }
            disasm_rva = std::strtoull(parts[0].c_str(), nullptr, 0);
            if (parts.size() > 1 && !parts[1].empty()) {
                disasm_count =
                    static_cast<std::uint32_t>(std::strtoul(parts[1].c_str(),
                                                            nullptr, 0));
            }
            if (parts.size() > 2 && !parts[2].empty()) {
                // The byte form: hex, whitespace or separator separated.
                std::string hex;
                for (const char c : parts[2]) {
                    if (std::strchr("0123456789abcdefABCDEF", c) != nullptr) {
                        hex += c;
                    }
                }
                if (hex.size() % 2 != 0) {
                    std::fprintf(stderr,
                                 "occ inspect: --disasm bytes must be pairs\n");
                    return 2;
                }
                for (std::size_t h = 0; h < hex.size(); h += 2) {
                    const char pair[3] = {hex[h], hex[h + 1], '\0'};
                    disasm_bytes.push_back(
                        static_cast<std::uint8_t>(std::strtoul(pair, nullptr,
                                                               16)));
                }
                disasm_base = disasm_rva;
            }
        } else if (std::strcmp(arg, "--limit") == 0 && i + 1 < argc) {
            ++i;
            options.string_limit = static_cast<std::size_t>(
                std::strtoul(argv[i], nullptr, 0));
        } else {
            std::fprintf(stderr, "occ inspect: unknown flag: %s\n", arg);
            return 2;
        }
    }

    auto bytes = occ::fs::read_file_bytes(path);
    if (!bytes || bytes->empty()) {
        return inspect_failure("the file could not be read", path);
    }
    const occ::ByteSpan span{bytes->data(), bytes->size()};
    const occ::parser::PeImage image = occ::parser::PeImage::parse(span);
    if (!image.ok()) {
        return inspect_failure("not a PE this inspector reads", path);
    }

    // The structural report, or -- with --disasm and no byte form -- the
    // disassembly of a range inside the image. Both are one JSON document
    // on stdout, because jq is the interface.
    if (want_disasm && !disasm_bytes.empty()) {
        std::fputs(occ::inspect::x64_disassemble_json(
                       occ::ByteSpan{disasm_bytes.data(),
                                           disasm_bytes.size()},
                       disasm_base, disasm_count)
                       .c_str(),
                   stdout);
        std::fputc('\n', stdout);
        return 0;
    }

    const std::string report =
        occ::inspect::inspect_pe_json(image, span, options);
    std::fputs(report.c_str(), stdout);
    std::fputc('\n', stdout);

    if (want_disasm) {
        // The disassembly rides in its own document, after the report: two
        // documents rather than one nested, because the disassembly can be
        // long enough to drown the structure it was asked beside.
        const std::uint64_t at = disasm_rva;
        std::uint64_t file_offset = 0;
        std::size_t available = 0;
        if (image.to_file_offset(at, file_offset) &&
            file_offset < bytes->size()) {
            available = bytes->size() - file_offset;
            // The span is bounded by the section the rva lands in, so a
            // sweep cannot run off the end of a section into the next one's
            // bytes and call them code.
            for (const occ::parser::PeSection& section : image.sections()) {
                if (at >= section.virtual_address &&
                    at < section.virtual_address + section.mapped_size()) {
                    const std::uint64_t in_section =
                        section.virtual_address + section.mapped_size() - at;
                    if (in_section < available) {
                        available = static_cast<std::size_t>(in_section);
                    }
                    break;
                }
            }
            const std::string disassembly =
                occ::inspect::x64_disassemble_json(
                    occ::ByteSpan{bytes->data() + file_offset, available},
                    image.image_base() + at, disasm_count);
            std::fputs(disassembly.c_str(), stdout);
            std::fputc('\n', stdout);
        } else {
            std::fprintf(stderr, "occ inspect: rva 0x%llx is not mapped\n",
                         static_cast<unsigned long long>(at));
            return 2;
        }
    }

    return 0;
}

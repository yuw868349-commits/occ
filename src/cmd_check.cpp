#include "occ/commands.h"

#include "occ/engine/engine.h"
#include "occ/parser/detect.h"
#include "occ/parser/pe.h"
#include "occ/runtime/address_space.h"
#include "occ/runtime/loader.h"
#include "occ/util/fs.h"
#include "occ/util/log.h"
#include "occ/util/string.h"

#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

#include <unistd.h>

namespace occ {

namespace {

using parser::Detection;
using parser::ElfClass;
using parser::ElfEndian;
using parser::Format;

struct Cli {
    std::string path;
    bool use_ndjson = false;
};

// A deliberately small parser. There is no getopt here because the grammar
// is three tokens wide and the standard library's version brings in global
// state and an error convention that would have to be documented.
bool parse(const int argc, char** argv, Cli& out) {
    for (int i = 0; i < argc; ++i) {
        const std::string_view a = argv[i];
        if (a == "--json") {
            out.use_ndjson = true;
        } else if (a == "--help" || a == "-h") {
            std::fprintf(
                stderr,
                "usage: occ check <path> [--json]\n"
                "\n"
                "Reports the format of a target, the engine occ would use "
                "for it, and\n"
                "whether the runtime for that engine can load it. The load "
                "is done against\n"
                "a throwaway address space, so no bytes are mapped and no "
                "import is\n"
                "resolved; the file is read and its headers, relocations, "
                "imports and TLS\n"
                "directory are walked, which is what a load would do before "
                "it touched\n"
                "memory.\n"
                "\n"
                "The exit status is 0 when the format is one an engine "
                "handles and the\n"
                "load succeeded, 3 when the format is recognised but not "
                "handled, 4 when\n"
                "it is not recognised at all, and 5 when the engine's "
                "runtime refused to\n"
                "load it.\n");
            return false;
        } else if (!a.empty() && a[0] == '-') {
            log::error("unknown option");
            return false;
        } else if (out.path.empty()) {
            out.path = a;
        } else {
            log::error("check takes one path");
            return false;
        }
    }
    if (out.path.empty()) {
        log::error("check requires a path");
        return false;
    }
    return true;
}

// Which engine would run this. Every ELF goes to the exe engine, including
// the ones it does not handle: an engine that receives a target it cannot
// run produces a named refusal, and routing such a target nowhere would
// turn a specific error into a generic one.
//
// This asks the engine layer rather than keeping a table here. Two tables
// of which format goes where is one more than the tree should have, and the
// one that is not the engine's is the one that goes stale.
const char* engine_for(const Detection& d) noexcept {
    const engine::Engine* e = engine::engine_for(d);
    return e != nullptr ? e->name() : nullptr;
}

// The reason a format is not runnable, in one line. Kept separate from the
// engine decision because a caller reading the exit status needs to know
// which of "no engine exists" and "the engine refuses this file" applies.
//
// The refusal comes from the engine, not from here, for the same reason the
// engine choice does. A refusal written in this file would be a second
// statement of what each engine accepts, and the two would disagree the
// first time an engine changed.
std::string refusal(const Detection& d) {
    const engine::Engine* e = engine::engine_for(d);
    if (e == nullptr) {
        switch (d.format) {
        case Format::Unknown:
            return "no signature matched";
        case Format::Zip:
            return "a zip archive of code has no engine; point occ at a "
                   "package or extract the native library from it";
        case Format::MachO:
            return "Mach-O images are not handled; occ runs Linux and Windows "
                   "targets";
        case Format::Elf:
        case Format::Apk:
        case Format::Pe:
            break;
        }
        return "this build has no engine for this format";
    }
    return e->preflight(d);
}

// The reason a target is not runnable, in one line, or an empty string.
//
// Two different questions are answered here and they are kept apart because
// they have different exit statuses. The first is whether an engine takes
// this format at all, which preflight answers. The second is whether the
// engine that takes it can actually run this file, which is a property of
// the runtime behind the engine and of the file's contents rather than of
// the format -- an APK needs an Android runtime, and that is not a fact
// `occ check` can read from a detection.
//
// The PE engine is not on this list, and its absence is the answer to the
// question rather than a gap in it. The runtime that executes a PE image is
// this binary, so what it accepts is a property of the image, and the loader
// reports it in the load section below together with the machine the image
// declares and the machine this build executes. The caveat it used to carry
// -- a Wine loader the host had to supply -- was true when the PE path
// borrowed a loader and stopped being true when that path was replaced. A
// caveat restating the runtime's own answer would be a second table of what
// each engine accepts, and the second table is the one that goes stale.
//
// So the second question is reported as a caveat rather than folded into
// the refusal. A caller that sees a caveat knows the engine will read the
// file and may still decline to run it, and a caller that sees neither
// knows the engine has no host-level objection.
std::string caveat(const Detection& d) {
    const engine::Engine* e = engine::engine_for(d);
    if (e == nullptr) {
        return {};
    }
    if (e->kind() == engine::EngineKind::Apk) {
        return "the apk engine reads a package and reports it, but occ has no "
               "Android runtime and will not run one; extract the native "
               "library under lib/ and point occ at that";
    }
    return {};
}

// What a load attempt found, for a format that has a loader.
//
// This is the second question `occ check` answers and it is a different one
// from the engine's. The engine answers "would I read this file"; this
// answers "would the runtime be able to put it in memory". A PE that parses
// and has an unrelocatable conflict with its preferred base is one the
// engine accepts and the loader refuses, and reporting only the first would
// tell a caller the file is fine when the run that follows will fail before
// reaching the target's first instruction.
//
// The load is done against a throwaway address space with a null resolver,
// so nothing is mapped and no import is resolved. That is the property the
// loader was built for -- `load_image` walks the headers, the relocations,
// the imports and the TLS directory without copying a byte, and the address
// space is bookkeeping rather than memory -- and it is what makes this
// affordable to run on any file a caller points at.
struct LoadCheck {
    // False when the format has no loader, or the file did not parse. In
    // that case the fields below are not meaningful and `reason` says why.
    bool attempted = false;
    bool loaded = false;
    std::string reason;
    std::uint64_t base = 0;
    std::uint64_t regions = 0;
    std::uint64_t resident_bytes = 0;
    std::uint64_t reserved_bytes = 0;
    bool entry_mapped = false;
    bool entry_executable = false;
};

LoadCheck load_check(const std::string& path, const Detection& d) {
    LoadCheck out;
    if (d.format != Format::Pe) {
        // Only the PE engine has a runtime here. Saying so is better than
        // returning a LoadCheck whose fields are all zero, which a reader
        // would take for a load that mapped nothing.
        return out;
    }

    auto bytes = fs::read_file_bytes(path);
    if (!bytes.has_value()) {
        out.attempted = true;
        out.reason = "the file could not be read";
        return out;
    }

    const ByteSpan span{bytes->data(), bytes->size()};
    parser::PeImage image = parser::PeImage::parse(span);
    if (!image.ok()) {
        out.attempted = true;
        // The parser's own sentence, not a translation of its code: the
        // detail names an offset or a field, and rewriting it here would
        // lose the part that tells a caller where to look.
        out.reason = std::string("the PE parser refused it: ") +
                     image.error_detail();
        return out;
    }

    runtime::AddressSpace space;
    runtime::LoadContext context;   // null resolver: record imports, resolve none
    const runtime::LoadResult result =
        runtime::load_image(image, span, 0, space, context);

    out.attempted = true;
    if (!result.ok) {
        out.reason = std::string(runtime::load_error_name(result.error));
        if (!result.detail.empty()) {
            out.reason += ": ";
            out.reason += result.detail;
        }
        return out;
    }

    out.loaded = true;
    out.base = result.module.base;
    out.regions = space.regions().size();

    // Two byte counts rather than one, and the pair is the point.
    //
    // "Resident" is the sum of the regions the loader recorded, which is the
    // memory the image actually takes. "Reserved" is what the image's own
    // declared size adds beyond that: the alignment between sections and any
    // part of the declared range no section covers. A caller asking how much
    // memory a load costs wants the first; a caller asking how much address
    // space has to be free before it can be placed wants the sum, and the
    // report gives both rather than deciding for them.
    for (const runtime::Region& r : space.regions()) {
        out.resident_bytes += r.size;
    }
    const std::uint64_t declared = image.image_size();
    out.reserved_bytes =
        declared > out.resident_bytes ? declared - out.resident_bytes : 0;

    if (image.entry_rva() != 0) {
        // entry_va already carries the image's own base, and the load above
        // used that base when preferred_base was zero, so the two agree.
        const runtime::Region* at_entry = space.find(image.entry_va());
        out.entry_mapped = at_entry != nullptr;
        out.entry_executable = out.entry_mapped && at_entry->executable;
    }

    return out;
}

int exit_status_for(const Detection& d) noexcept {
    if (d.format == Format::Unknown) {
        return 4;
    }
    if (engine_for(d) == nullptr || !refusal(d).empty()) {
        return 3;
    }
    return 0;
}

void print_text(const std::string& path, const Detection& d,
                const LoadCheck& load) {
    std::string out;
    out += path;
    out += ": ";
    out += parser::format_name(d.format);
    out += "\n";

    out += "  size         ";
    append_uint(out, d.file_size);
    out += "\n";

    if (d.format == Format::Elf) {
        if (d.bare_program_header) {
            out += "  layout       bare program header (Android OAT)\n";
        } else {
            out += "  class        ";
            out += parser::elf_class_name(d.elf_class);
            out += "\n";
            out += "  endianness   ";
            out += parser::elf_endian_name(d.elf_endian);
            out += "\n";
            out += "  type         ";
            out += parser::elf_type_name(d.elf_type);
            out += "\n";
            out += "  machine      ";
            out += parser::elf_machine_name(d.elf_machine);
            out += "\n";
        }
    }

    const char* engine = engine_for(d);
    out += "  engine       ";
    out += engine != nullptr ? engine : "(none)";
    out += "\n";

    const std::string why = refusal(d);
    if (!why.empty()) {
        out += "  reason       ";
        out += why;
        out += "\n";
    }

    const std::string note = caveat(d);
    if (!note.empty()) {
        out += "  note         ";
        out += note;
        out += "\n";
    }

    if (!d.evidence.empty()) {
        out += "  evidence\n";
        for (const auto& e : d.evidence) {
            out += "    - ";
            out += e;
            out += "\n";
        }
    }

    // The load, when there was one to attempt. The indent is the same as the
    // rest and the label is a sentence rather than a word, because this is
    // the answer to the question a caller runs `check` to ask and the lines
    // above are the preamble that decides whether it can be asked.
    if (load.attempted) {
        out += "  load\n";
        if (load.loaded) {
            out += "    result       loaded\n";
            out += "    base         0x";
            append_hex(out, load.base, 16);
            out += "\n";
            out += "    regions      ";
            append_uint(out, load.regions);
            out += "\n";
            out += "    image bytes  ";
            append_uint(out, load.resident_bytes);
            out += "\n";
            out += "    reserved     ";
            append_uint(out, load.reserved_bytes);
            out += " (zero-fill and alignment)\n";
            if (load.entry_mapped) {
                out += "    entry        mapped";
                out += load.entry_executable ? " and executable\n"
                                             : " but not executable\n";
            } else {
                out += "    entry        not present, so this is a library-like "
                       "image\n";
            }
        } else {
            out += "    result       refused\n";
            out += "    reason       ";
            out += load.reason;
            out += "\n";
        }
    }

    (void)std::fwrite(out.data(), 1, out.size(), stdout);
}

void print_ndjson(const std::string& path, const Detection& d,
                  const LoadCheck& load) {
    std::string out;
    out += "{\"path\":\"";
    append_json_escaped(out, path);
    out += "\",\"format\":\"";
    out += parser::format_name(d.format);
    out += "\",\"size\":";
    append_uint(out, d.file_size);

    if (d.format == Format::Elf) {
        out += ",\"elf_class\":\"";
        out += parser::elf_class_name(d.elf_class);
        out += "\",\"elf_endian\":\"";
        out += parser::elf_endian_name(d.elf_endian);
        out += "\",\"elf_type\":\"";
        out += parser::elf_type_name(d.elf_type);
        out += "\",\"elf_machine\":\"";
        out += parser::elf_machine_name(d.elf_machine);
        out += "\"";
    }

    const char* engine = engine_for(d);
    out += ",\"engine\":";
    if (engine == nullptr) {
        out += "null";
    } else {
        out += "\"";
        out += engine;
        out += "\"";
    }

    out += ",\"reason\":\"";
    append_json_escaped(out, refusal(d));
    out += "\"";

    out += ",\"note\":\"";
    append_json_escaped(out, caveat(d));
    out += "\"";

    out += ",\"evidence\":[";
    for (std::size_t i = 0; i < d.evidence.size(); ++i) {
        if (i != 0) {
            out += ",";
        }
        out += "\"";
        append_json_escaped(out, d.evidence[i]);
        out += "\"";
    }
    out += "]";

    // The load, as an object with an "attempted" flag rather than a null.
    //
    // The two absences are different and a null would merge them: a format
    // with no loader was never asked, and a format that has one was asked
    // and the answer was no. The first is an absence of a question and the
    // second is an answer, and a consumer that has to act on the result
    // needs to distinguish them without reading the format field.
    out += ",\"load\":{";
    out += "\"attempted\":";
    out += load.attempted ? "true" : "false";
    if (load.attempted) {
        out += ",\"loaded\":";
        out += load.loaded ? "true" : "false";
        if (load.loaded) {
            out += ",\"base\":\"0x";
            append_hex(out, load.base, 16);
            out += "\",\"base_dec\":";
            append_uint(out, load.base);
            out += ",\"regions\":";
            append_uint(out, load.regions);
            out += ",\"resident_bytes\":";
            append_uint(out, load.resident_bytes);
            out += ",\"reserved_bytes\":";
            append_uint(out, load.reserved_bytes);
            out += ",\"entry_mapped\":";
            out += load.entry_mapped ? "true" : "false";
            out += ",\"entry_executable\":";
            out += load.entry_executable ? "true" : "false";
        } else {
            out += ",\"reason\":\"";
            append_json_escaped(out, load.reason);
            out += "\"";
        }
    }
    out += "}}\n";

    (void)std::fwrite(out.data(), 1, out.size(), stdout);
}

} // namespace

int cmd_check(int argc, char** argv) {
    Cli cli;
    if (!parse(argc, argv, cli)) {
        return 2;
    }

    // The default follows the same rule as the other commands: NDJSON when
    // stdout is not a terminal, the readable form when it is.
    if (!cli.use_ndjson) {
        cli.use_ndjson = ::isatty(1) == 0;
    }

    const Detection d = parser::detect_file(cli.path);

    // The load is attempted only for a file an engine would take. Running it
    // for a zip or a Mach-O would produce a refusal whose text says "there
    // is no loader for this", which is the answer the engine section already
    // gave, in a second voice.
    LoadCheck load;
    if (engine_for(d) != nullptr && refusal(d).empty()) {
        load = load_check(cli.path, d);
    }

    if (cli.use_ndjson) {
        print_ndjson(cli.path, d, load);
    } else {
        print_text(cli.path, d, load);
    }

    // A file the loader refuses is a file the engine will not run, and the
    // exit status says so. It has its own value rather than sharing 3 with
    // the format-level refusals, because the two send a caller to different
    // places: 3 is "occ has no engine for this", 5 is "the engine has one
    // and this file cannot be put in memory".
    if (load.attempted && !load.loaded) {
        return 5;
    }

    return exit_status_for(d);
}

} // namespace occ

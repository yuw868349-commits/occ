// `occ dll`: load a library and drive its lifecycle.
//
// Three modes, and the three are the three questions a person has about an
// unknown DLL:
//
//   * `attach` -- what does it do when it loads? Load it, run its
//     dependencies' and its own entry points, and stop. The entry point is
//     where a module does its hiding: registers, hooks, decryption, the
//     detection of a debugger. Running it and nothing else, with the
//     observer's stream pointed at the run, is the whole of that question.
//
//   * `call` -- what does an export do? Load it, call the export the caller
//     named with the arguments the caller gave, and report what came back.
//
//   * `serve` -- the same, interactively: load once, then call exports one
//     after another from a prompt, where the state between calls is the
//     process's rather than rebuilt per call.
//
// The arguments on the command line are typed by their prefixes -- `i64:5`,
// `ptr:0x1000`, `str:hello`, `f64:1.5` -- because a DLL export has no type
// information in the file: the export directory carries a name and an
// address and nothing about a signature. The caller supplies what the loader
// cannot.

#include "occ/commands.h"
#include "occ/parser/pe.h"
#include "occ/runtime/dll_runtime.h"
#include "occ/util/fs.h"
#include "occ/util/span.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

namespace {

// The parsed form of one `--args` entry.
struct Argument {
    // Whether the value goes in a floating-point slot. The two sequences are
    // counted apart by the calling convention, so which one an argument
    // belongs to is a property of its type and not of its position.
    bool floating = false;
    double as_float = 0;
    std::uint64_t as_integer = 0;
    // A string argument's text. Empty for every other type. The text is
    // copied into the guest's memory before the call and the address of the
    // copy travels in the integer slot, which is what a caller passing a
    // `const char*` wants and what the file cannot know it is passing.
    std::string text;
    bool is_string = false;
};

void print_usage(const char* argv0) {
    std::fprintf(
        stderr,
        "usage: %s <dll> <mode> [options]\n"
        "\n"
        "modes:\n"
        "  attach                load the library, run its entry points, "
        "detach\n"
        "  call <export>         load the library and call one export\n"
        "  serve                 load the library and read calls from stdin\n"
        "\n"
        "options:\n"
        "  --args <spec>...      call's arguments, typed by prefix:\n"
        "                          i32:5 i64:0x10 ptr:0x1000 str:hello "
        "f32:1.5 f64:2.5\n"
        "                        a string is copied into the guest's memory "
        "and its\n"
        "                        address passed; the address is reported\n"
        "  --dir <path>          a directory to search for dependencies "
        "(repeatable);\n"
        "                        the library's own directory is always "
        "searched first\n"
        "  --dirs                print the search path and exit\n"
        "  --ret <type>          the export's return type: i64 (default) or "
        "f64;\n"
        "                        a file carries no signature, so the caller "
        "says\n"
        "  --quiet               report only the call's result\n"
        "  --help                print this text\n"
        "\n"
        "the entry points of the library and of every dependency run in the\n"
        "order a loader would run them, dependencies first. `attach` is that\n"
        "order and nothing else, which is what makes it the mode to watch a\n"
        "module's load-time behaviour in\n",
        argv0);
}

[[nodiscard]] bool read_file(const std::string& path,
                             std::vector<std::uint8_t>* out) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return false;
    }
    out->assign(std::istreambuf_iterator<char>(stream),
                std::istreambuf_iterator<char>());
    return true;
}

// The directory a path lives in, or empty. Used to put the library's own
// directory first in the search path, which is where the platform's loader
// looks first after the application directory.
[[nodiscard]] std::string directory_of(const std::string& path) {
    const std::size_t separator = path.find_last_of("/\\");
    if (separator == std::string::npos) {
        return std::string();
    }
    return path.substr(0, separator);
}

[[nodiscard]] bool parse_u64(std::string_view text, std::uint64_t* out) {
    if (text.empty()) {
        return false;
    }
    const std::string copy(text);
    char* end = nullptr;
    const unsigned long long value = std::strtoull(copy.c_str(), &end, 0);
    if (end == nullptr || *end != '\0') {
        return false;
    }
    *out = static_cast<std::uint64_t>(value);
    return true;
}

[[nodiscard]] bool parse_argument(std::string_view spec, Argument* out,
                                  std::string* error) {
    const std::size_t colon = spec.find(':');
    if (colon == std::string_view::npos) {
        *error = "an argument needs a type prefix: " + std::string(spec);
        return false;
    }
    const std::string_view type = spec.substr(0, colon);
    const std::string_view value = spec.substr(colon + 1);
    if (type == "f32" || type == "f64") {
        const std::string copy(value);
        char* end = nullptr;
        const double number = std::strtod(copy.c_str(), &end);
        if (end == nullptr || *end != '\0') {
            *error = "not a number: " + copy;
            return false;
        }
        out->floating = true;
        out->as_float = number;
        return true;
    }
    if (type == "str") {
        // The address is filled in later, when the guest's memory exists.
        // The string is kept in `as_integer` as a pointer the loader will
        // replace; the marker is the empty type.
        out->floating = false;
        out->as_integer = 0;
        out->text = std::string(value);
        out->is_string = true;
        return true;
    }
    if (type == "i32" || type == "i64" || type == "ptr" || type == "u64") {
        std::uint64_t parsed = 0;
        if (!parse_u64(value, &parsed)) {
            *error = "not a number: " + std::string(value);
            return false;
        }
        out->floating = false;
        out->as_integer = parsed;
        return true;
    }
    *error = "unknown argument type: " + std::string(type);
    return false;
}

void report_module(const occ::runtime::dll_runtime::ModuleInfo& info) {
    std::printf("  %-24s base 0x%012llx  size 0x%-8llx entry 0x%012llx\n",
                info.name.c_str(),
                static_cast<unsigned long long>(info.base),
                static_cast<unsigned long long>(info.size),
                static_cast<unsigned long long>(info.entry));
    std::printf("  %-24s exports %zu  refs %u  tls %s  %s\n", "",
                info.exports, info.refcount, info.has_tls ? "yes" : "no",
                info.initialized ? "initialized" : "not initialized");
    if (!info.path.empty()) {
        std::printf("  %-24s %s\n", "", info.path.c_str());
    }
    if (!info.dependencies.empty()) {
        std::printf("  %-24s depends on:", "");
        for (const std::string& dep : info.dependencies) {
            std::printf(" %s", dep.c_str());
        }
        std::printf("\n");
    }
}

void report_modules(const occ::runtime::dll_runtime::Runtime& runtime,
                    const char* heading) {
    std::printf("%s\n", heading);
    for (const auto& info : runtime.modules()) {
        report_module(info);
    }
}

// The call's result, in the two forms a person reads: the decimal the
// function's own type would print and the hexadecimal an address reads as.
void report_result(const occ::runtime::GuestCallOutcome& outcome,
                   std::uint64_t export_address, bool floating_result) {
    if (!outcome.ok) {
        std::printf("call failed: %s\n", outcome.detail.c_str());
        return;
    }
    // The answer in the forms it can be read as. An integer answer is what
    // most exports return; a floating-point one is read from the vector
    // register the type names, and the same eight bytes are shown as an
    // integer beside it so that a caller who guessed the type wrong can see
    // which reading looks like a value.
    std::printf("call returned %llu (0x%llx)\n",
                static_cast<unsigned long long>(outcome.result),
                static_cast<unsigned long long>(outcome.result));
    if (floating_result) {
        double as_float = 0;
        std::memcpy(&as_float, &outcome.result, sizeof(as_float));
        std::printf("as f64: %.17g\n", as_float);
    }
    std::printf("export address 0x%012llx\n",
                static_cast<unsigned long long>(export_address));
}

// Copies a C string into the guest's address space and answers its address.
//
// The copy goes above the highest region the process owns, which is where
// the loader puts a guest allocation and where nothing the image declared
// can collide with it. Zero from a placement that could not be made, which
// the caller reports as the argument it could not build.
[[nodiscard]] std::uint64_t place_guest_string(
    occ::runtime::dll_runtime::Runtime& runtime, std::string_view text) {
    using occ::runtime::AddressSpace;
    using occ::runtime::PageProtection;
    using occ::runtime::RegionKind;
    std::uint64_t floor = 0;
    for (const auto& region : runtime.process().image().regions) {
        const std::uint64_t end = region.base + region.size;
        if (end > floor) {
            floor = end;
        }
    }
    const std::uint64_t want = text.size() + 1;
    const auto mapped = runtime.process().mapper().map_above(
        AddressSpace::round_up(floor, AddressSpace::kGranularity),
        AddressSpace::round_up(want, AddressSpace::kPageSize),
        PageProtection::ReadWrite, RegionKind::Private);
    if (!mapped.ok()) {
        return 0;
    }
    std::memcpy(reinterpret_cast<void*>(mapped.value), text.data(),
                text.size());
    reinterpret_cast<char*>(mapped.value)[text.size()] = '\0';
    return mapped.value;
}

// One `call` line: the export's name and its arguments, as `serve` reads
// them and as the command line spells them.
struct CallRequest {
    std::string export_name;
    std::vector<Argument> arguments;
    // Whether the answer comes back in a vector register. Read from
    // `--ret` on the command line and fixed at `i64` in `serve`, where a
    // per-line type prefix would be the next thing to add.
    bool floating_result = false;
};

[[nodiscard]] bool parse_call_line(std::string_view line, CallRequest* out,
                                   std::string* error) {
    out->export_name.clear();
    out->arguments.clear();
    std::size_t at = 0;
    const auto skip = [&]() {
        while (at < line.size() &&
               std::isspace(static_cast<unsigned char>(line[at])) != 0) {
            ++at;
        }
    };
    skip();
    const std::size_t name_start = at;
    while (at < line.size() &&
           std::isspace(static_cast<unsigned char>(line[at])) == 0) {
        ++at;
    }
    if (at == name_start) {
        *error = "no export name";
        return false;
    }
    out->export_name = std::string(line.substr(name_start, at - name_start));
    for (;;) {
        skip();
        if (at >= line.size()) {
            break;
        }
        const std::size_t start = at;
        while (at < line.size() &&
               std::isspace(static_cast<unsigned char>(line[at])) == 0) {
            ++at;
        }
        Argument argument;
        if (!parse_argument(line.substr(start, at - start), &argument,
                            error)) {
            return false;
        }
        out->arguments.push_back(std::move(argument));
    }
    return true;
}

// Runs one call: resolves the export, lays the arguments out in the two
// sequences the convention counts apart, makes the call, and reports.
int run_call(occ::runtime::dll_runtime::Runtime& runtime, std::uint64_t module,
             const CallRequest& request, bool quiet) {
    const std::uint64_t address = runtime.find_export(module, request.export_name);
    if (address == 0) {
        std::fprintf(stderr, "no export named %s in the library\n",
                     request.export_name.c_str());
        return 1;
    }
    if (!quiet) {
        std::printf("calling %s at 0x%012llx\n", request.export_name.c_str(),
                    static_cast<unsigned long long>(address));
    }
    occ::runtime::GuestCallArgs args;
    if (request.arguments.size() > 4) {
        // The fifth argument of a call travels on the stack, past the
        // shadow space, and placing one means building the frame that
        // carries it. Rather than call with the argument silently missing,
        // the call is refused and the reason is this line.
        std::fprintf(stderr,
                     "%zu arguments: only the first four travel in "
                     "registers, and this call does not place stack "
                     "arguments\n",
                     request.arguments.size());
        return 2;
    }
    for (std::size_t i = 0; i < request.arguments.size(); ++i) {
        const Argument& argument = request.arguments[i];
        auto& slot = args.slots[i];
        if (argument.is_string) {
            const std::uint64_t placed =
                place_guest_string(runtime, argument.text);
            if (placed == 0) {
                std::fprintf(stderr,
                             "the string argument could not be placed in "
                             "the guest's memory\n");
                return 1;
            }
            if (!quiet) {
                std::printf("  string \"%s\" placed at 0x%012llx\n",
                            argument.text.c_str(),
                            static_cast<unsigned long long>(placed));
            }
            slot.floating = false;
            slot.as_integer = placed;
            continue;
        }
        slot.floating = argument.floating;
        slot.as_float = argument.as_float;
        slot.as_integer = argument.as_integer;
    }
    args.count = request.arguments.size();
    args.floating_result = request.floating_result;
    const occ::runtime::GuestCallOutcome outcome =
        runtime.call(address, args);
    report_result(outcome, address, request.floating_result);
    return outcome.ok ? 0 : 1;
}

}  // namespace

int occ::cmd_dll(int argc, char** argv) {
    using namespace occ::runtime;
    using namespace occ::runtime::dll_runtime;

    if (argc < 2) {
        print_usage("occ dll");
        return 2;
    }
    // The path as an absolute one: the search path is built from the
    // library's own directory, and a bare `helper.dll` has no directory to
    // take -- which would leave every sibling dependency unfindable.
    const std::string library_path = occ::fs::absolute_path(argv[0]);
    const std::string mode = argv[1];

    if (mode == "--help" || mode == "-h") {
        print_usage("occ dll");
        return 0;
    }

    std::vector<std::string> directories;
    std::string export_name;
    std::vector<Argument> arguments;
    bool quiet = false;
    bool print_dirs = false;
    bool floating_result = false;

    for (int i = 2; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--dir" && i + 1 < argc) {
            directories.emplace_back(argv[++i]);
        } else if (arg == "--args") {
            // Everything up to the next option is an argument to the call.
            while (i + 1 < argc && argv[i + 1][0] != '-') {
                Argument parsed;
                std::string error;
                if (!parse_argument(argv[++i], &parsed, &error)) {
                    std::fprintf(stderr, "occ dll: %s\n", error.c_str());
                    return 2;
                }
                arguments.push_back(std::move(parsed));
            }
        } else if (arg == "--ret" && i + 1 < argc) {
            const std::string_view type = argv[++i];
            if (type == "f64" || type == "f32" || type == "double") {
                floating_result = true;
            } else if (type == "i64" || type == "i32" || type == "ptr") {
                floating_result = false;
            } else {
                std::fprintf(stderr, "occ dll: unknown return type %s\n",
                             std::string(type).c_str());
                return 2;
            }
        } else if (arg == "--quiet") {
            quiet = true;
        } else if (arg == "--dirs") {
            print_dirs = true;
        } else if (mode == "call" && export_name.empty()) {
            export_name = arg;
        } else {
            std::fprintf(stderr, "occ dll: unknown option %s\n",
                         std::string(arg).c_str());
            print_usage("occ dll");
            return 2;
        }
    }

    // The search path: the library's own directory first, which is where a
    // module's siblings live and where the platform's loader looks first
    // after the application directory.
    const std::string own_directory = directory_of(library_path);
    if (!own_directory.empty()) {
        directories.insert(directories.begin(), own_directory);
    }
    if (print_dirs) {
        for (const std::string& directory : directories) {
            std::printf("%s\n", directory.c_str());
        }
        return 0;
    }

    std::vector<std::uint8_t> bytes;
    if (!read_file(library_path, &bytes)) {
        std::fprintf(stderr, "occ dll: cannot read %s\n", library_path.c_str());
        return 2;
    }
    const parser::PeImage image = parser::PeImage::parse(ByteSpan{
        bytes.data(), bytes.size()});
    if (!image.ok()) {
        std::fprintf(stderr, "occ dll: %s is not loadable: %s -- %s\n",
                     library_path.c_str(),
                     parser::pe_error_name(image.error()),
                     image.error_detail().c_str());
        return 2;
    }

    Options options;
    options.search_directories = directories;
    std::string error;
    std::unique_ptr<Runtime> runtime =
        Runtime::build(image, ByteSpan{bytes.data(), bytes.size()},
                       library_path, options, &error);
    if (runtime == nullptr) {
        std::fprintf(stderr, "occ dll: %s\n", error.c_str());
        return 1;
    }

    const std::uint64_t module = runtime->table().find_name(
        occ::runtime::module_table::fold_name(library_path)) != nullptr
                                    ? runtime->table()
                                          .find_name(occ::runtime::module_table::
                                                         fold_name(library_path))
                                          ->base
                                    : runtime->process().image().module.base;

    // The load: the dependencies and then the library, entry points in
    // post-order, which is what `attach` is.
    std::string initialize_error;
    if (!runtime->table().initialize(module, &initialize_error)) {
        std::fprintf(stderr, "occ dll: the load failed: %s\n",
                     initialize_error.c_str());
        return 1;
    }
    if (!quiet) {
        report_modules(*runtime, "loaded:");
    }

    int status = 0;
    if (mode == "attach") {
        // Nothing more: the entry points ran, which is the question.
        status = 0;
    } else if (mode == "call") {
        if (export_name.empty()) {
            std::fprintf(stderr, "occ dll: call needs an export name\n");
            return 2;
        }
        CallRequest request;
        request.export_name = export_name;
        request.arguments = std::move(arguments);
        request.floating_result = floating_result;
        status = run_call(*runtime, module, request, quiet);
    } else if (mode == "serve") {
        std::printf("occ dll: reading calls from stdin; one per line, "
                    "`export arg arg ...`\n");
        std::string line;
        while (std::getline(std::cin, line)) {
            if (line.empty() || line[0] == '#') {
                continue;
            }
            if (line == "modules") {
                report_modules(*runtime, "loaded:");
                continue;
            }
            if (line == "quit" || line == "exit") {
                break;
            }
            CallRequest request;
            std::string parse_error;
            if (!parse_call_line(line, &request, &parse_error)) {
                std::printf("  %s\n", parse_error.c_str());
                continue;
            }
            static_cast<void>(
                run_call(*runtime, module, request, quiet));
        }
    } else {
        std::fprintf(stderr, "occ dll: unknown mode %s\n", mode.c_str());
        print_usage("occ dll");
        return 2;
    }

    // The detach, in reverse load order, which is what the images are owed
    // whether the run called anything or not.
    std::string detach_error;
    if (!runtime->detach_all(&detach_error) && !quiet) {
        std::fprintf(stderr, "occ dll: the detach reported: %s\n",
                     detach_error.c_str());
    }
    return status;
}

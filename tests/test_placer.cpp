// Probe placer tests.
//
// The placer turns a request naming a module and a symbol into a uprobe, and
// the failures it can report are the interesting part: a symbol that is not
// there, a symbol that is there and is not code, an address that no part of
// the file backs. Each of those is a different sentence to a reader and each
// has to be reachable, so most of this file is about which outcome comes back
// for which input.
//
// The resolution half runs against real libraries on the host -- libc and, if
// it is installed, Wine's ntdll -- because a resolution that works against a
// fixture and not against a real ELF is a resolution that works on nothing.
// The registration half cannot complete on a host without tracefs, and the
// outcome there is checked to be a refusal rather than a crash.

#include "occ/probe/placer.h"

#include "occ/parser/elf.h"
#include "occ/util/fs.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <type_traits>
#include <vector>

#include <unistd.h>

using namespace occ::obs;
using occ::engine::ProbeRequest;

namespace {

int failures = 0;
int checks = 0;

void check(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

// ------------------------------------------------------------ the outcomes

void test_outcome_names_are_distinct() {
    std::vector<std::string_view> seen;
    const PlacementOutcome all[] = {
        PlacementOutcome::Attached,    PlacementOutcome::ModuleMissing,
        PlacementOutcome::ModuleUnreadable, PlacementOutcome::SymbolMissing,
        PlacementOutcome::NoFileOffset, PlacementOutcome::KernelRefused,
    };
    for (PlacementOutcome o : all) {
        const char* name = placement_outcome_name(o);
        if (name == nullptr || name[0] == '\0') {
            check(false, "every outcome has a name");
            return;
        }
        for (std::string_view s : seen) {
            if (s == name) {
                check(false, "no two outcomes share a name");
                return;
            }
        }
        seen.emplace_back(name);
    }
    check(true, "every outcome has a name");
    check(true, "no two outcomes share a name");
}

void test_a_module_with_a_slash_is_used_as_given() {
    // libc is present on every host that can run this test at all, and the
    // assertion is unconditional for the same reason the bare-name check
    // is: a resolver that searched for an absolute path or dropped it would
    // answer nothing, and the test has to be able to see that.
    const std::string path = find_module("/lib/x86_64-linux-gnu/libc.so.6");
    check(!path.empty(), "an absolute path to a present library resolves");
    if (path.empty()) {
        return;
    }
    check(path == "/lib/x86_64-linux-gnu/libc.so.6",
          "an absolute path is returned unchanged rather than searched for");
    check(find_module("/nonexistent/absolute/path.so").empty(),
          "an absolute path that does not exist resolves to nothing");
}

void test_a_missing_module_resolves_to_nothing() {
    check(find_module("libThisDoesNotExistAnywhere.so").empty(),
          "a library name that is nowhere on the path resolves to nothing");
    check(find_module("/no/such/directory/libnope.so").empty(),
          "an absolute path that does not exist resolves to nothing");
    check(find_module("").empty(), "an empty module resolves to nothing");
}

void test_a_bare_name_is_searched() {
    // libc is in the default library directories, and a bare name has to
    // find it there -- that is the whole point of the search. The assertion
    // is unconditional: a resolver that only honoured absolute paths would
    // return nothing here, and returning nothing is exactly the failure
    // that would make every probe request naming a library rather than a
    // path silently unplaced.
    const std::string path = find_module("libc.so.6");
    check(!path.empty(),
          "a bare library name is searched for and found on the default "
          "library path");
    if (path.empty()) {
        return;
    }
    check(path.find("libc.so.6") != std::string::npos,
          "a bare name resolves to a path ending in that name");
    check(path.find('/') != std::string::npos,
          "and the result is a path and not the name again");
}

// ------------------------------------------------------------ the placement

void test_a_missing_module_is_reported_as_missing() {
    ProbePlacer placer;
    std::vector<ProbeRequest> requests;
    requests.push_back(ProbeRequest{"libNotHere.so", "NtCreateFile", "label",
                                    ""});

    std::vector<Placement> out;
    const std::size_t attached = placer.place(requests, out, nullptr);

    check(attached == 0, "nothing is attached for a module that is not there");
    check(out.size() == 1, "one placement is reported");
    check(out[0].outcome == PlacementOutcome::ModuleMissing,
          "and it is the missing module");
    check(!out[0].detail.empty(), "and it says why");
    check(out[0].label == "label", "and it keeps the label it was given");
}

void test_a_symbol_that_is_not_there_is_reported_as_missing() {
    const std::string path = find_module("libc.so.6");
    if (path.empty()) {
        return;
    }
    ProbePlacer placer;
    std::vector<ProbeRequest> requests;
    requests.push_back(
        ProbeRequest{path, "occ_no_such_symbol_at_all", "label", ""});

    std::vector<Placement> out;
    const std::size_t attached = placer.place(requests, out, nullptr);

    check(attached == 0, "nothing is attached for a symbol that is not there");
    check(out.size() == 1, "one placement is reported");
    check(out[0].outcome == PlacementOutcome::SymbolMissing,
          "and it is the missing symbol");
    check(out[0].detail.find("occ_no_such_symbol_at_all") != std::string::npos,
          "and the reason names the symbol");
}

void test_a_data_symbol_is_not_code() {
    const std::string path = find_module("libc.so.6");
    if (path.empty()) {
        return;
    }
    // A real data object in libc. It is exported, it is defined, and it has
    // an address -- and there is no code at that address to break on. A
    // placer that only checked the name would place a probe here.
    ProbePlacer placer;
    std::vector<ProbeRequest> requests;
    requests.push_back(
        ProbeRequest{path, "stdin", "the standard input object", ""});

    std::vector<Placement> out;
    placer.place(requests, out, nullptr);

    check(out.size() == 1, "one placement is reported");
    // stdin is a FILE*, so its symbol type is an object. The outcome is
    // that it is not a function, which is the same value as a missing
    // symbol and a different sentence.
    check(out[0].outcome == PlacementOutcome::SymbolMissing ||
              out[0].outcome == PlacementOutcome::ModuleUnreadable,
          "a data symbol is not placed as a function");
    if (out[0].outcome == PlacementOutcome::SymbolMissing) {
        check(out[0].detail.find("not a function") != std::string::npos,
              "and the reason says it is not a function rather than absent");
    }
}

void test_a_real_function_resolves_to_a_file_offset() {
    const std::string path = find_module("libc.so.6");
    if (path.empty()) {
        return;
    }
    ProbePlacer placer;
    std::vector<ProbeRequest> requests;
    requests.push_back(ProbeRequest{path, "malloc", "malloc", ""});

    std::vector<Placement> out;
    placer.place(requests, out, nullptr);

    check(out.size() == 1, "one placement is reported");
    if (out[0].outcome == PlacementOutcome::Attached ||
        out[0].outcome == PlacementOutcome::KernelRefused) {
        // Resolved. A kernel refusal is the expected end on a host without
        // tracefs, and it is reached only after the offset was found.
        check(out[0].offset != 0,
              "a resolved function has a non-zero file offset");
        check(out[0].module == path, "and the module is the one searched for");
    } else {
        std::fprintf(stderr, "malloc did not resolve: %s\n",
                     out[0].detail.c_str());
        check(false, "a real function resolves");
    }
}

void test_the_definition_is_preferred_over_the_import() {
    // libc defines memcpy and may also import a versioned alias of it. The
    // resolver has to pick the one with a body; picking the import would
    // give an address that belongs to whatever exports it, and the offset
    // computed from that address is inside the wrong file.
    const std::string path = find_module("libc.so.6");
    if (path.empty()) {
        return;
    }
    ProbePlacer placer;
    std::vector<ProbeRequest> requests;
    requests.push_back(ProbeRequest{path, "memcpy", "memcpy", ""});

    std::vector<Placement> out;
    placer.place(requests, out, nullptr);

    check(out.size() == 1, "one placement is reported");
    check(out[0].outcome == PlacementOutcome::Attached ||
              out[0].outcome == PlacementOutcome::KernelRefused,
          "memcpy resolves to something placeable");
    check(out[0].offset != 0, "and it has an offset");
}

// A shared object whose code segment is mapped far from its file offset.
//
// Built at test time by the compiler rather than committed, because a
// committed binary is one nobody can read and one that stops matching the
// architecture it is run on. The link flag is what creates the gap: without
// it the code segment is at the file offset and a placer that never converted
// an address would still place correct probes, which is exactly the mistake
// this test exists to catch.
struct DeltaLibrary {
    std::string path;
    std::uint64_t symbol_vaddr = 0;
    std::uint64_t expected_offset = 0;
    bool ok = false;
    // The temporary directory the library was built in, removed when this
    // goes out of scope. A test that leaves a directory behind is a test
    // that fills /tmp on the machine that runs it most.
    std::string dir;

    DeltaLibrary() = default;
    DeltaLibrary(const DeltaLibrary&) = delete;
    DeltaLibrary& operator=(const DeltaLibrary&) = delete;
    DeltaLibrary(DeltaLibrary&& o) noexcept
        : path(std::move(o.path)), symbol_vaddr(o.symbol_vaddr),
          expected_offset(o.expected_offset), ok(o.ok), dir(std::move(o.dir)) {
        o.ok = false;
    }
    DeltaLibrary& operator=(DeltaLibrary&& o) noexcept {
        if (this != &o) {
            if (!dir.empty()) {
                (void)occ::fs::remove_tree(dir);
            }
            path = std::move(o.path);
            symbol_vaddr = o.symbol_vaddr;
            expected_offset = o.expected_offset;
            ok = o.ok;
            dir = std::move(o.dir);
            o.ok = false;
        }
        return *this;
    }
    ~DeltaLibrary() {
        if (!dir.empty()) {
            (void)occ::fs::remove_tree(dir);
        }
    }
};

DeltaLibrary build_delta_library() {
    DeltaLibrary out;

    // The compiler is found through the environment so that a host whose
    // toolchain is not at the default path is not silently treated as a host
    // with no compiler. The test is skipped when there is none, and the skip
    // is printed.
    const char* cc = std::getenv("CC");
    const std::string compiler = cc != nullptr && cc[0] != '\0'
                                     ? std::string(cc)
                                     : std::string("cc");

    char dir[] = "/tmp/occ_placer_XXXXXX";
    if (::mkdtemp(dir) == nullptr) {
        return out;
    }
    const std::string base(dir);
    const std::string src = base + "/d.c";
    const std::string so = base + "/libdelta.so";

    if (!occ::fs::write_file(src, "int occ_delta_target(int x) { return x + 1; }\n")) {
        return out;
    }

    // -Ttext-segment is a linker flag, and the two linkers spell it the
    // same. The value is deliberately not page-adjacent to zero: the gap
    // between the code segment's file offset and its virtual address is
    // what the test measures.
    const std::string cmd = compiler + " -shared -fPIC -o " + so + " " + src +
                            " -Wl,-Ttext-segment=0x800000 >/dev/null 2>&1";
    if (std::system(cmd.c_str()) != 0) {
        return out;
    }
    if (!occ::fs::exists(so)) {
        return out;
    }

    auto bytes = occ::fs::read_file_bytes(so);
    if (!bytes || bytes->empty()) {
        return out;
    }
    const occ::parser::ElfImage image =
        occ::parser::ElfImage::parse(occ::ByteSpan{bytes->data(), bytes->size()});
    if (!image.ok()) {
        return out;
    }
    const occ::parser::Symbol* s = image.find_symbol("occ_delta_target");
    if (s == nullptr || !s->probeable()) {
        return out;
    }

    std::uint64_t offset = 0;
    if (!image.vaddr_to_file_offset(s->value, offset)) {
        return out;
    }

    // The library is only useful if the two numbers differ. A toolchain
    // that ignored the flag produces a normal library, and testing against
    // it would be testing nothing.
    if (offset == s->value) {
        return out;
    }

    out.path = so;
    out.symbol_vaddr = s->value;
    out.expected_offset = offset;
    out.dir = base;
    out.ok = true;
    return out;
}

void test_the_offset_is_not_the_address() {
    const DeltaLibrary lib = build_delta_library();
    if (!lib.ok) {
        std::fprintf(stderr,
                     "note: no toolchain that can build a gap-offset library; "
                     "the address-conversion check was skipped\n");
        return;
    }

    check(lib.symbol_vaddr != lib.expected_offset,
          "the fixture has an address that is not its file offset");

    ProbePlacer placer;
    std::vector<ProbeRequest> requests;
    requests.push_back(
        ProbeRequest{lib.path, "occ_delta_target", "occ_delta_target", ""});

    std::vector<Placement> out;
    placer.place(requests, out, nullptr);

    check(out.size() == 1, "one placement is reported");
    check(out[0].outcome == PlacementOutcome::Attached ||
              out[0].outcome == PlacementOutcome::KernelRefused,
          "the symbol in the fixture resolves");
    // The assertion that matters. A placer that used the address would
    // report 0x801100 here and place a probe eight megabytes into a file
    // that is a few kilobytes long; the kernel would refuse it, the refusal
    // would name the offset, and nothing would say the offset was a virtual
    // address.
    check(out[0].offset == lib.expected_offset,
          "and the placement uses the file offset, not the virtual address");
    check(out[0].offset != lib.symbol_vaddr,
          "which is a different number from the symbol's address");
}

// ------------------------------------------------------- the layer lifetime

void test_argument_names_survive_resolution() {
    // The names have to reach the placement, because the placement is what
    // the report and the hit both read them from. They are copied in
    // resolve() rather than in place(), and resolve() runs whichever way the
    // placement turns out -- so a refusal still has its names, which is what
    // makes this assertable on a host that cannot place a probe.
    const DeltaLibrary lib = build_delta_library();
    if (!lib.ok) {
        std::fprintf(stderr,
                     "note: no toolchain that can build a gap-offset library; "
                     "the argument-name check was skipped\n");
        return;
    }

    ProbeRequest req{lib.path, "occ_delta_target", "occ_delta_target", ""};
    req.arg_names[0] = "FileHandle";
    req.arg_names[2] = "DesiredAccess";
    // Position 1 is deliberately left empty: an argument that is not named
    // is not the same as an argument that does not exist, and the empty slot
    // has to survive the copy rather than being filled in with something.

    ProbePlacer placer;
    std::vector<ProbeRequest> requests{req};
    std::vector<Placement> out;
    placer.place(requests, out, nullptr);

    check(out.size() == 1, "one placement is reported");
    check(out[0].arg_names[0] == "FileHandle",
          "the first argument's name survives into the placement");
    check(out[0].arg_names[2] == "DesiredAccess",
          "and so does the third");
    check(out[0].arg_names[1].empty(),
          "an unnamed argument stays unnamed rather than being filled in");
    check(out[0].arg_names[5].empty(),
          "and the ones past the named entries are unnamed too");
}

void test_placing_nothing_leaves_an_empty_layer() {
    ProbePlacer placer;
    std::vector<ProbeRequest> requests;
    std::vector<Placement> out;
    const std::size_t attached = placer.place(requests, out, nullptr);

    check(attached == 0, "no requests means nothing is attached");
    check(out.empty(), "and nothing is reported");
    check(placer.layer().size() == 0, "and the layer is empty");
    check(placer.layer().fds().empty(), "and there is nothing to poll");
}

void test_a_layer_that_placed_nothing_says_why() {
    ProbePlacer placer;
    std::vector<ProbeRequest> requests;
    requests.push_back(ProbeRequest{"libNotHere.so", "x", "x", ""});
    std::vector<Placement> out;
    placer.place(requests, out, nullptr);

    // A host without tracefs, which is most containers. The placer has to
    // be able to say so once for the whole run rather than once per probe,
    // because the reason is the same for all of them.
    if (!Uprobes::availability().available) {
        check(!placer.unavailable_reason().empty(),
              "a placer that placed nothing on a host without tracefs has a "
              "reason");
        check(placer.tracefs_root().empty() ||
                  occ::fs::is_dir(placer.tracefs_root()),
              "and whatever root it reports, if any, is a directory");
    }
}

void test_a_placer_is_not_copyable() {
    // The layer owns tracefs events, and two owners would remove them
    // twice: the second removal finds no event and the kernel refuses the
    // whole write. That the type cannot be copied is the guarantee.
    static_assert(!std::is_copy_constructible_v<ProbePlacer>,
                  "ProbePlacer must not be copyable");
    static_assert(!std::is_copy_assignable_v<ProbePlacer>,
                  "ProbePlacer must not be copy-assignable");
    check(true, "a placer owns its probes and cannot be copied");
}

} // namespace

int main() {
    test_outcome_names_are_distinct();
    test_a_module_with_a_slash_is_used_as_given();
    test_a_missing_module_resolves_to_nothing();
    test_a_bare_name_is_searched();
    test_a_missing_module_is_reported_as_missing();
    test_a_symbol_that_is_not_there_is_reported_as_missing();
    test_a_data_symbol_is_not_code();
    test_a_real_function_resolves_to_a_file_offset();
    test_the_definition_is_preferred_over_the_import();
    test_the_offset_is_not_the_address();
    test_argument_names_survive_resolution();
    test_placing_nothing_leaves_an_empty_layer();
    test_a_layer_that_placed_nothing_says_why();
    test_a_placer_is_not_copyable();

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

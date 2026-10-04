#include "occ/engine/engine.h"

#include "occ/observer/ntdll_probes.h"
#include "occ/parser/elf.h"
#include "occ/parser/pe.h"
#include "occ/util/fs.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include <unistd.h>

namespace occ::engine {

namespace {

// Reports one section. A PE section is not a mapping -- it is a range of
// the file and a range of the address space, and the loader is what turns
// one into the other -- so it is reported with its own numbers rather than
// forced into the mapping event's fields. The executable and writable bits
// are the reason anyone reads this event, so they are reported as booleans
// rather than as the characteristics word a consumer would have to know the
// bit positions of.
void report_section(obs::Writer& events, const parser::PeSection& s,
                    std::size_t index) {
    auto& e = events.begin(obs::EventKind::Section);
    e.add("index", static_cast<std::uint64_t>(index));
    e.add("name", s.name);
    e.add_hex("virtual_address", s.virtual_address);
    e.add_hex("virtual_size", s.virtual_size);
    e.add_hex("raw_offset", s.raw_offset);
    e.add_hex("raw_size", s.raw_size);
    e.add("readable", s.readable());
    e.add("writable", s.writable());
    e.add("executable", s.executable());
    e.add_hex("characteristics", s.characteristics);
    // The two sizes are different numbers and are routinely different in
    // one direction or the other. A section whose virtual size exceeds its
    // raw size has trailing zero-fill; the reverse means the tail of the
    // virtual range is not backed by the file at all. A consumer that
    // subtracts one from the other to find the zero region gets the right
    // answer in the first case and a meaningless number in the second, so
    // the answer is stated rather than left to be derived.
    e.add_hex("zero_fill",
              s.virtual_size > s.raw_size ? s.virtual_size - s.raw_size : 0);
    // The count is stated as a number rather than left as a difference for
    // the consumer to compute: it is zero in the ordinary case, and a
    // reader that has to notice the field is absent for the common case is
    // reading a schema with two shapes where one would do.
    e.add("tail_not_mapped",
          static_cast<std::uint64_t>(s.virtual_size < s.raw_size
                                         ? s.raw_size - s.virtual_size
                                         : 0));
    events.commit();
}

// The Wine loaders this host has.
//
// The two names are not the same program. wine64 loads 64-bit images and
// wine loads 32-bit ones, and a 32-bit image handed to a 64-bit-only loader
// fails in the loader with a message that does not mention bitness. So
// both are looked for and the plan picks by the image's own width.
struct WineSearch {
    std::string wine64;
    std::string wine;
};

// Records dir/name as a loader if it is one. Executability is tested
// rather than existence: a distribution can leave a wrapper script that is
// not executable next to the real binary, and exec'ing that produces an
// error naming the file rather than the missing capability.
//
// The slot is only filled once. A second wine64 earlier or later in PATH
// does not replace the first, because which one wins is a property of the
// host's configuration and either answer is defensible -- what is not
// defensible is a search whose result depends on directory order in a way
// nobody can see.
void consider(WineSearch* out, const std::string& dir, const char* name,
              bool is64) noexcept {
    if (out == nullptr) {
        return;
    }
    std::string& slot = is64 ? out->wine64 : out->wine;
    if (!slot.empty()) {
        return;
    }
    std::string candidate = dir;
    if (candidate.back() != '/') {
        candidate += '/';
    }
    candidate += name;
    if (!fs::exists(candidate)) {
        return;
    }
    if (::access(candidate.c_str(), X_OK) != 0) {
        return;
    }
    slot = candidate;
}

// Searches PATH for a loader. The search is a search rather than a fixed
// path because the path is a property of the host, and a hard-coded one
// would make this engine work on exactly the machine it was written on.
//
// Cached because the answer cannot change within a process and a run asks
// once. The function-local static is constructed on first use rather than
// at load time so that a program that never runs a PE never walks PATH.
WineSearch find_wine() noexcept {
    // An explicit loader, if the caller named one.
    //
    // This branch is read on every call rather than cached with the search,
    // and the difference is deliberate. The search's answer is a property of
    // the host and cannot change within a process; the named loader is a
    // property of the request, and a process that plans two runs against two
    // installations has two answers. Caching it would make the second plan
    // silently use the first one's Wine.
    //
    // The name is the loader itself and is used as given, including the
    // executable bit being checked: a path that is named and not executable
    // is a configuration mistake, and falling back to a search would run a
    // different Wine than the one that was asked for.
    if (const char* explicit_loader = ::getenv("OCC_WINE_LOADER")) {
        if (explicit_loader[0] != '\0') {
            WineSearch named_out;
            const std::string named(explicit_loader);
            if (fs::exists(named) && ::access(named.c_str(), X_OK) == 0) {
                // Both slots hold it. The plan picks by the image's width
                // rather than by which slot is filled, so a named loader has
                // to be reachable from both or a 32-bit image would be told
                // there is no 32-bit Wine when the caller said there is.
                named_out.wine64 = named;
                named_out.wine = named;
            }
            return named_out;
        }
    }

    static const WineSearch found = [] {
        WineSearch out;
        const char* path = ::getenv("PATH");
        if (path == nullptr || path[0] == '\0') {
            path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:"
                   "/sbin:/bin";
        }

        // Split on ':' inline rather than through a helper. There is no
        // path-splitting function in the tree, and adding one for a single
        // caller would be a larger change than the loop.
        std::string rest(path);
        std::size_t start = 0;
        for (;;) {
            const std::size_t colon = rest.find(':', start);
            const std::size_t end =
                colon == std::string::npos ? rest.size() : colon;
            if (end > start) {
                // An empty PATH element means the current directory, which
                // is what the shell does with one. It is skipped rather
                // than honoured: a loader is a program that runs with the
                // privileges occ was given, and the working directory is
                // the least trustworthy directory in the set.
                consider(&out, rest.substr(start, end - start), "wine64",
                         true);
                consider(&out, rest.substr(start, end - start), "wine",
                         false);
            }
            if (colon == std::string::npos) {
                break;
            }
            start = colon + 1;
        }
        return out;
    }();
    return found;
}

// The directory a Wine prefix is created in, and where the loader's
// libraries are found.
//
// A prefix is a directory tree Wine populates on first use: a registry
// hive, a drive_c, a set of DLLs it builds or copies. It has to be writable
// and it has to be per-run, because two runs sharing a prefix share a
// wineserver and a target's writes to its own drive_c.
//
// The location is derived from the loader's own path rather than
// hard-coded, because that is the only thing that identifies which
// installation this is. A Wine in /usr/lib/wine has its libraries in
// ../lib/wine; one in /opt/wine-stable has them beside it. Getting this
// wrong produces a loader that starts and then cannot load anything.
struct WineLayout {
    // The library directory, empty when it could not be located.
    std::string lib_dir;
};

WineLayout wine_layout(const std::string& loader) noexcept {
    WineLayout out;
    if (loader.empty()) {
        return out;
    }

    const std::size_t slash = loader.rfind('/');
    const std::string bin_dir =
        slash == std::string::npos ? std::string(".") : loader.substr(0, slash);
    const std::string prefix_dir =
        slash == std::string::npos ? bin_dir : bin_dir.substr(0, bin_dir.rfind('/'));

    // The layouts in use, most specific first. A layout is a candidate
    // directory that is accepted only if it actually exists, so listing one
    // that is absent costs a stat and never produces a wrong bind.
    for (const char* candidate : {"/lib/wine", "/lib64/wine", "/lib/x86_64-linux-gnu/wine"}) {
        const std::string path = prefix_dir + candidate;
        if (fs::is_dir(path)) {
            out.lib_dir = path;
            break;
        }
    }
    if (out.lib_dir.empty() && fs::is_dir("/usr/lib/wine")) {
        out.lib_dir = "/usr/lib/wine";
    }

    return out;
}

// Wine's Unix-side ntdll, which is the file the probes go into.
//
// It is the host-native ELF, not the PE ntdll.dll. A Windows program's
// NtCreateFile is a thunk into __wine_syscall_dispatcher, which indexes a
// table of Unix functions; the one with a body to place a probe on is the
// Unix function, and it lives in the .so.
//
// The search order is the layout Wine installs under on the distributions
// that ship it, most specific first. The host's uname machine is not
// consulted: the directory name is the target ISA Wine was built for, which
// is the image's ISA and not necessarily the running kernel's -- a 32-bit
// Wine on a 64-bit kernel lives under i386-unix and still runs.
struct NtdllLocation {
    // The file, empty when it could not be found.
    std::string path;
    // Why it could not be found, for the degradation note.
    std::string reason;
};

NtdllLocation find_ntdll(const std::string& lib_dir,
                         std::uint32_t address_bits) noexcept {
    NtdllLocation out;

    // The loader's own directory tree first, because that is the one
    // installation the plan is already committed to. A Wine in /opt has its
    // ntdll beside it, and a search that preferred /usr would place probes
    // in a different Wine than the one being run.
    //
    // lib_dir is already the Wine library directory -- wine_layout returns
    // .../lib/wine, not .../lib -- so the ISA directory goes directly under
    // it. A second "wine" component here would be a path that does not exist
    // on any installation, and the search would then fall through to the
    // packaged locations and probe a different Wine than the one planned.
    std::vector<std::string> dirs;
    if (!lib_dir.empty()) {
        const std::string isa = address_bits == 32 ? "i386" : "x86_64";
        dirs.push_back(lib_dir + "/" + isa + "-unix");
        dirs.push_back(lib_dir + "/" + isa + "-windows");
    }
    // The packaged locations, which are where a distribution puts it when
    // the loader is a shim in /usr/bin that exec's these.
    const std::string isa = address_bits == 32 ? "i386" : "x86_64";
    for (const char* root : {"/usr/lib/x86_64-linux-gnu/wine",
                             "/usr/lib64/wine",
                             "/usr/lib/wine",
                             "/usr/lib/i386-linux-gnu/wine"}) {
        dirs.push_back(std::string(root) + "/" + isa + "-unix");
    }

    for (const std::string& dir : dirs) {
        for (std::string_view name : obs::ntdll_sonames()) {
            const std::string candidate = dir + "/" + std::string(name);
            if (fs::exists(candidate)) {
                out.path = candidate;
                return out;
            }
        }
    }

    out.reason =
        "Wine's Unix-side ntdll was not found, so no function-level probes "
        "could be placed; the run continues with syscall-level observation, "
        "which sees Wine's own library traffic mixed with the target's";
    return out;
}

// Reads the probes out of the table and drops the ones whose symbols the
// ntdll on this host does not have.
//
// The table was checked against a real Wine when it was written, but a host
// may have a different Wine: a version that renamed a function, or a build
// configured without one. Placing a probe needs an address, and a symbol
// that is not in this file has none -- so the ones that are missing are
// counted and reported rather than attempted. Attempting them would make
// the kernel refuse a line the engine wrote, and the failure would be
// attributed to the run rather than to the version mismatch that caused it.
struct ProbePlan {
    std::vector<ProbeRequest> requests;
    std::size_t dropped = 0;
    std::size_t total = 0;
    std::string first_dropped;
};

ProbePlan build_probes(const std::string& ntdll_path) noexcept {
    ProbePlan out;
    out.total = obs::ntdll_probe_count();

    auto bytes = fs::read_file_bytes(ntdll_path);
    if (!bytes || bytes->empty()) {
        // The file exists and cannot be read. That is a different problem
        // from the symbol being absent and it costs every probe rather than
        // some, so everything is counted as dropped and the reason is not
        // about any one symbol.
        out.dropped = out.total;
        out.first_dropped = "the module could not be read";
        return out;
    }

    const parser::ElfImage image =
        parser::ElfImage::parse(ByteSpan{bytes->data(), bytes->size()});
    if (!image.ok()) {
        out.dropped = out.total;
        out.first_dropped = "the module is not an ELF this build can read";
        return out;
    }
    if (!image.has_symbols()) {
        // A stripped ntdll keeps its dynamic symbols or it could not be
        // loaded by the linker, so this means the symbol table is damaged
        // rather than absent. Either way there are no addresses.
        out.dropped = out.total;
        out.first_dropped =
            "the module has no readable dynamic symbol table";
        return out;
    }

    for (const obs::NtdllProbe& p : obs::ntdll_probes()) {
        const parser::Symbol* s = image.find_symbol(p.symbol);
        if (s == nullptr || !s->probeable()) {
            ++out.dropped;
            if (out.first_dropped.empty()) {
                out.first_dropped = std::string(p.symbol);
            }
            continue;
        }
        ProbeRequest req;
        req.module = ntdll_path;
        req.symbol = std::string(p.symbol);
        req.label = std::string(p.symbol);
        req.note = std::string(p.note);
        out.requests.push_back(std::move(req));
    }
    return out;
}

class PeEngine final : public Engine {
public:
    [[nodiscard]] EngineKind kind() const noexcept override {
        return EngineKind::Pe;
    }

    [[nodiscard]] const char* name() const noexcept override { return "pe"; }

    [[nodiscard]] std::string preflight(
        const parser::Detection& d) const override {
        // Nothing here refuses a PE, and that is a decision rather than an
        // oversight. The detection reads the MZ stub and the signature at
        // e_lfanew; everything that decides whether a PE can be run lives
        // in the COFF and optional headers, which means reading the file. A
        // preflight that guessed from the detection would either refuse
        // images that run or wave through images that do not, and both are
        // worse than reading the file and answering properly. So the PE
        // engine's answers all come from load() and plan(), where they are
        // based on the headers.
        (void)d;
        return {};
    }

    [[nodiscard]] LoadedImage load(const std::string& path,
                                   obs::Writer* events) const override {
        LoadedImage out;
        out.format = parser::Format::Pe;

        auto bytes = fs::read_file_bytes(path);
        if (!bytes) {
            out.error = "the file could not be read";
            out.detail = path;
            report_unreadable(events, path, out);
            return out;
        }

        const parser::PeImage image =
            parser::PeImage::parse(ByteSpan{bytes->data(), bytes->size()});

        out.ok = image.ok();
        if (!out.ok) {
            out.error = parser::pe_error_name(image.error());
            out.detail = image.error_detail();
        } else {
            // The entry is reported as a virtual address rather than as the
            // RVA the file stores, because an RVA means nothing without the
            // base it is added to and the base becomes a per-run value once
            // the loader has placed the image. The RVA is reported alongside
            // it in the event so a consumer that wants the file's own
            // number has it.
            out.entry = image.entry_va();
            out.region_count = image.section_count();
            out.address_bits = image.is_pe32_plus() ? 64u : 32u;
        }

        if (events != nullptr) {
            auto& e = events->begin(obs::EventKind::ImageLoaded);
            e.add("path", path);
            e.add("engine", name());
            e.add("size", static_cast<std::uint64_t>(bytes->size()));
            e.add("ok", image.ok());
            if (image.ok()) {
                e.add("format", image.is_pe32_plus() ? "pe32+" : "pe32");
                e.add("kind", image.is_dll() ? "dll" : "executable");
                e.add("machine", static_cast<std::uint64_t>(image.machine()));
                e.add("machine_raw",
                      static_cast<std::uint64_t>(image.machine_raw()));
                e.add("subsystem",
                      static_cast<std::uint64_t>(image.subsystem()));
                e.add_hex("entry", image.entry_va());
                e.add_hex("entry_rva", image.entry_rva());
                e.add_hex("image_base", image.image_base());
                e.add_hex("image_size", image.image_size());
                e.add_hex("headers_size", image.headers_size());
                e.add_hex("section_alignment", image.section_alignment());
                e.add_hex("file_alignment", image.file_alignment());
                e.add("sections",
                      static_cast<std::uint64_t>(image.section_count()));
                e.add("imports",
                      static_cast<std::uint64_t>(image.imports().size()));
                e.add("dynamic_base", image.dynamic_base());
                e.add("nx_compat", image.nx_compat());
                e.add("high_entropy_va", image.high_entropy_va());
                e.add("seh", image.has_seh());
            } else {
                e.add("error", out.error);
                e.add("detail", out.detail);
            }
            events->commit();

            if (image.ok()) {
                for (std::size_t i = 0; i < image.sections().size(); ++i) {
                    report_section(*events, image.sections()[i], i);
                }
                // The import list is one event per name rather than a field,
                // because it is a list of variable length and a field whose
                // length depends on the target is a field a consumer has to
                // guess the end of.
                for (const std::string& dll : image.imports()) {
                    auto& imp = events->begin(obs::EventKind::Import);
                    imp.add("dll", dll);
                    events->commit();
                }
            }
        }

        return out;
    }

    [[nodiscard]] LaunchPlan plan(const EngineRequest& request,
                                  const LoadedImage& image) const override;

private:
    static void report_unreadable(obs::Writer* events, const std::string& path,
                                  const LoadedImage& out) {
        if (events == nullptr) {
            return;
        }
        auto& e = events->begin(obs::EventKind::ImageLoaded);
        e.add("path", path);
        e.add("engine", "pe");
        e.add("size", static_cast<std::uint64_t>(0));
        e.add("ok", false);
        e.add("error", out.error);
        e.add("detail", out.detail);
        events->commit();
    }
};

LaunchPlan PeEngine::plan(const EngineRequest& request,
                          const LoadedImage& image) const {
    LaunchPlan out;
    if (!image.ok) {
        out.refusal =
            "the image is not one this build can run: " + image.error;
        return out;
    }

    // Wine supplies the loader and the Win32 API. Occ does not implement
    // either -- see docs/DESIGN.md for why the boundary falls there. So the
    // question this function answers is not "what does the API do" but
    // "which loader, with which arguments, in which prefix, seeing which
    // libraries", and every one of those is a host property rather than a
    // target property.
    const WineSearch wine = find_wine();

    // The loader is chosen by the image's width, and the widths are
    // exclusive because a host with only one loader can only run one of
    // them. A refusal here names both facts, because "no Wine" and "only
    // the 32-bit Wine" call for different installs and a user who is told
    // only the first will install the wrong one.
    const bool wants64 = image.address_bits == 64;
    std::string loader = wants64 ? wine.wine64 : wine.wine;
    if (loader.empty()) {
        // The other width is a fallback rather than a refusal. A 64-bit
        // loader running a 32-bit image is a supported configuration --
        // WoW64 is exactly that -- so using one is correct where it is the
        // only one there is. It is reported as a degradation because the
        // fidelity notes in DESIGN.md apply, and a run whose fidelity
        // differs should say so rather than look identical to one that does
        // not.
        loader = wants64 ? wine.wine : wine.wine64;
        if (loader.empty()) {
            out.refusal =
                wants64
                    ? "no Wine loader was found on PATH; a PE needs Wine to "
                      "supply the loader and the Win32 API, and occ "
                      "implements neither"
                    : "no 32-bit Wine loader was found on PATH and no 64-bit "
                      "one either; a 32-bit PE needs a loader that can run "
                      "it, and occ implements neither";
            return out;
        }
        out.degradations.emplace_back(
            std::string("no ") + (wants64 ? "64" : "32") +
            "-bit Wine loader was found; using the " +
            (wants64 ? "32" : "64") + "-bit one");
    }

    const WineLayout layout = wine_layout(loader);
    if (layout.lib_dir.empty()) {
        out.refusal =
            "the Wine loader at " + loader +
            " has no library directory beside it, so the loader would start "
            "and then fail to load anything; point occ at an installation "
            "that has one";
        return out;
    }

    // The prefix. It is a directory tree Wine writes on first use, so it
    // has to be writable and per-run. The run's own scratch directory is
    // the only location that satisfies both without the engine inventing a
    // path outside the run's lifetime.
    if (request.scratch_dir.empty()) {
        out.refusal =
            "running a PE needs a writable Wine prefix, and this run has no "
            "scratch directory to put one in";
        return out;
    }
    const std::string prefix = request.scratch_dir + "/wineprefix";
    if (!fs::mkdir_p(prefix, 0700)) {
        out.refusal = "the Wine prefix directory " + prefix +
                      " could not be created";
        return out;
    }
    out.scratch_dir = prefix;

    // argv[0] is the loader, then the target, then the caller's arguments
    // with the target removed from the front. The caller's argv[0] was the
    // target as it was named; keeping it would make the loader see the
    // target twice.
    out.program = loader;
    out.argv.push_back(loader);
    out.argv.push_back(fs::absolute_path(request.path));
    for (std::size_t i = 1; i < request.argv.size(); ++i) {
        out.argv.push_back(request.argv[i]);
    }

    // WINEPREFIX is set unconditionally rather than only when the caller
    // did not set it, because the run's scratch directory has to be where
    // the prefix is: a prefix in the caller's home would be a second
    // program's state, and a run that is supposed to leave nothing behind
    // would leave a wineserver's registry there.
    out.env.emplace_back("WINEPREFIX=" + prefix);

    // WINEDEBUG=-all because a loader that prints to stderr corrupts the
    // target's own output, and the diagnostics it would print are not
    // something occ can act on.
    out.env.emplace_back("WINEDEBUG=-all");

    // WINEDLLOVERRIDES=mscoree,mshtml= turns off the two libraries whose
    // only effect on a run this tool observes is to start a service that
    // outlives the target. Left alone they add processes to a session that
    // is supposed to be about one target.
    out.env.emplace_back("WINEDLLOVERRIDES=mscoree,mshtml=");

    // The loader's libraries, read-only. Without them the exec succeeds and
    // the target dies in the dynamic linker, which is a worse report than a
    // refusal: it looks like the target's problem and is not.
    isolation::ContainerConfig::BindMount libs;
    libs.source = layout.lib_dir;
    libs.target = layout.lib_dir;
    libs.writable = false;
    out.binds.push_back(libs);

    // Wine reads its loader configuration from /usr/lib/wine and its
    // registry from the prefix, and it writes nothing outside those two
    // except a socket under /tmp. The socket is the one that matters: a
    // wineserver that outlives the run holds the prefix open, and the next
    // run against the same prefix would find a server it did not start.
    // WINESERVER= disables the sharing outright, which costs some speed on
    // a run that starts several processes and buys a run that leaves
    // nothing running.
    out.env.emplace_back("WINESERVER=");

    // The probes.
    //
    // A syscall trace of a Wine run is a trace of the target and the loader
    // together, and the loader's file traffic is most of it. Placing probes
    // on the Nt* entry points of Wine's Unix-side ntdll is what separates
    // them: a hit at NtCreateFile is the Windows program asking for a file,
    // and it fires whether the request ends in a host open, in a wineserver
    // round trip, or nowhere at all.
    //
    // Failing to find the ntdll or the symbols is a degradation and not a
    // refusal. The run still happens and is still observed at the syscall
    // level; it is only coarser, and SECURITY.md says why that trade is made
    // rather than refusing a target that runs perfectly well without probes.
    const NtdllLocation ntdll = find_ntdll(layout.lib_dir, image.address_bits);
    if (ntdll.path.empty()) {
        out.degradations.push_back(ntdll.reason);
        return out;
    }

    const ProbePlan probes = build_probes(ntdll.path);
    if (probes.requests.empty()) {
        out.degradations.push_back(
            "no ntdll probe could be placed on " + ntdll.path +
            ": " + probes.first_dropped +
            "; the run continues with syscall-level observation");
        return out;
    }

    if (probes.dropped != 0) {
        // Named rather than counted, because the count says how many and the
        // name says which, and a run reporting "62 of 73" leaves a reader
        // wondering whether the missing ones were the ones they cared about.
        out.degradations.push_back(
            std::to_string(probes.requests.size()) + " of " +
            std::to_string(probes.total) + " ntdll probes were placed; the "
            "first symbol this Wine does not export is " +
            probes.first_dropped);
    }

    out.probes = probes.requests;

    return out;
}

const PeEngine& the_pe_engine() noexcept {
    static const PeEngine engine;
    return engine;
}

} // namespace

const Engine& pe_engine() noexcept {
    return the_pe_engine();
}

} // namespace occ::engine

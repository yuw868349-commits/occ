#include "occ/engine/engine.h"

#include "occ/parser/pe.h"
#include "occ/runner/pe_runner.h"
#include "occ/util/fs.h"

#include <cstdint>
#include <string>
#include <vector>

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
                // Not `kind`, which is the key every event in this stream
                // uses to say what it is. A second `kind` in the same object
                // collides with that one, and a consumer reading `kind` to
                // tell one record from another reads this field instead --
                // the image_loaded record then looks like an event named
                // `executable`. The name mirrors `type` on the ELF branch,
                // which is the same fact spelled for that format.
                e.add("image_kind", image.is_dll() ? "dll" : "executable");
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

    // The runtime this build carries executes PE32+ -- the x64 shape. A
    // 32-bit image is not a smaller problem the same code solves: every
    // thunk, every TEB offset and every register width in it is the 64-bit
    // one, and running a 32-bit image would mean carrying a second runtime
    // beside it. The refusal names the widths, because a user who sees one
    // should know which side of the split they are on.
    if (image.address_bits != 64) {
        out.refusal =
            "this build executes PE32+ (x64) images itself; a " +
            std::to_string(image.address_bits) +
            "-bit image needs a runtime this build does not carry";
        return out;
    }

    // The process is occ itself, re-exec'd.
    //
    // The plan names `/proc/self/exe` with `__pe-runner` after it, and the
    // container exec's that: the runner is this binary again, inside the
    // namespaces the container has entered, dispatching on the token to the
    // code in `runner/pe_runner.cpp`. The exec is the seam that makes both
    // halves of the design work -- the container can seal a process it
    // exec's, and a guest that corrupts its own state corrupts a process
    // that was started for it rather than the one the caller is sitting in.
    // Naming this binary through `/proc/self/exe` rather than a PATH search
    // is part of the same argument: the runner has to be the binary whose
    // registry this build audited, and a PATH search is a way to run
    // somebody else's.
    //
    // Everything the old plan arranged -- a Wine install, a prefix tree, a
    // writable /tmp, the loader's libraries -- is absent because nothing on
    // this side consumes any of it. The API the guest imports is the host's
    // own code, resolved through the registry the runner builds; the
    // filesystem the guest sees is the container's read-only bind of the
    // host's; and the scratch directory this run owns stays empty, because
    // the runtime is from this binary and the process keeps no state on
    // disk.
    out.program = runner::kPeRunnerProgram;
    out.argv.push_back(runner::kPeRunnerProgram);
    out.argv.push_back(runner::kPeRunnerCommand);

    // The image, as an absolute path, then the caller's arguments with the
    // target removed from the front -- the caller's argv[0] named the
    // target as it was typed, and the runner's own argv[0] slot is the
    // image path. The guest's command line is built from these by the
    // Microsoft rules, which is why the arguments travel as separate argv
    // entries and not as a pre-quoted string: the quoting is the runtime's
    // job, done once, where the split that reads it back can be tested
    // against it.
    out.argv.push_back(fs::absolute_path(request.path));
    for (std::size_t i = 1; i < request.argv.size(); ++i) {
        out.argv.push_back(request.argv[i]);
    }

    // No probes are requested, and that is a fact about the mechanism
    // rather than a gap in it. The probes this format once asked for went
    // into Wine's Unix-side ntdll, to separate the target's syscalls from
    // the loader's; the loader is gone, and every syscall a container sees
    // from a runner process is the target's own. The noise those probes
    // existed to separate no longer exists, and a request that asked for
    // them would be a memory of the thing this engine replaced.

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

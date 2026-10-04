#include "occ/engine/engine.h"

#include "occ/parser/elf.h"
#include "occ/util/fs.h"

namespace occ::engine {

namespace {

// Reports one loadable segment. Called once per PT_LOAD header, in address
// order, which is the order the kernel itself would map them.
void report_mapping(obs::Writer& events, const parser::DesiredMapping& m,
                    std::size_t index) {
    auto& e = events.begin(obs::EventKind::Mapping);
    e.add("index", static_cast<std::uint64_t>(index));
    e.add_hex("file_offset", m.file_offset);
    e.add_hex("vaddr", m.vaddr);
    e.add_hex("filesz", m.filesz);
    e.add_hex("memsz", m.memsz);
    e.add("readable", (m.flags & parser::kPfRead) != 0);
    e.add("writable", (m.flags & parser::kPfWrite) != 0);
    e.add("executable", (m.flags & parser::kPfExec) != 0);
    // The part of the segment that is not backed by the file has to be
    // zeroed rather than read. Reporting it separately means a consumer does
    // not have to subtract two fields to find the size of the zero region.
    e.add_hex("zero_fill", m.memsz > m.filesz ? m.memsz - m.filesz : 0);
    events.commit();
}

// The ELF engine.
//
// The only engine whose program is the target. Everything else about a run
// -- the container, the observer, the event stream -- is the runner's, and
// is the same code whatever this engine decides.
class ExeEngine final : public Engine {
public:
    [[nodiscard]] EngineKind kind() const noexcept override {
        return EngineKind::Elf;
    }

    [[nodiscard]] const char* name() const noexcept override { return "exe"; }

    [[nodiscard]] std::string preflight(
        const parser::Detection& d) const override {
        // The refusals live here rather than in a table in the runner
        // because each of them is a fact about this engine and not about
        // ELF in general. A big-endian ELF is not something occ cannot run;
        // it is something *this* engine does not run, and saying otherwise
        // would make the sentence wrong the day a second engine appears.
        if (d.bare_program_header) {
            return "the file is an Android OAT image, which the apk engine "
                   "reads rather than the exe engine";
        }
        if (d.elf_class == parser::ElfClass::Elf32) {
            return "32-bit ELF is not handled by the exe engine";
        }
        if (d.elf_endian == parser::ElfEndian::Big) {
            return "big-endian ELF is not handled by the exe engine";
        }
        if (d.elf_machine != parser::ElfMachine::X86_64) {
            return std::string("e_machine is ") +
                   parser::elf_machine_name(d.elf_machine) +
                   "; the exe engine handles x86-64 only";
        }
        if (d.elf_type == parser::ElfType::Rel) {
            return "a relocatable object is not a program; link it first";
        }
        if (d.elf_type == parser::ElfType::Core) {
            return "a core file is not a program";
        }
        return {};
    }

    [[nodiscard]] LoadedImage load(const std::string& path,
                                   obs::Writer* events) const override {
        LoadedImage out;
        out.format = parser::Format::Elf;

        auto bytes = fs::read_file_bytes(path);
        if (!bytes) {
            out.error = "the file could not be read";
            out.detail = path;
            report_unreadable(events, path, 0, out);
            return out;
        }

        const parser::ElfImage image =
            parser::ElfImage::parse(ByteSpan{bytes->data(), bytes->size()});

        out.ok = image.ok();
        if (!out.ok) {
            out.error = parser::load_error_name(image.error());
            out.detail = image.error_detail();
        } else {
            out.entry = image.entry();
            out.region_count = image.mappings().size();
            // 64 unconditionally, and the reason is that ok() implies it:
            // the reader refuses a 32-bit object, a big-endian one and
            // anything that is not x86-64 before it reports success, so an
            // image that got here is 64-bit. Deriving it from the class
            // would be reading a field the reader has already checked and
            // would have to be kept in step with that check.
            out.address_bits = 64;
        }

        if (events != nullptr) {
            auto& e = events->begin(obs::EventKind::ImageLoaded);
            e.add("path", path);
            e.add("engine", name());
            e.add("size", static_cast<std::uint64_t>(bytes->size()));
            e.add("ok", image.ok());
            if (image.ok()) {
                e.add("type", static_cast<std::uint64_t>(image.type()));
                e.add("machine", static_cast<std::uint64_t>(image.machine()));
                e.add_hex("entry", image.entry());
                e.add("phnum", static_cast<std::uint64_t>(image.phnum()));
                e.add("phentsize", static_cast<std::uint64_t>(image.phentsize()));
                e.add_hex("lowest_vaddr", image.lowest_vaddr());
                e.add_hex("highest_vaddr", image.highest_vaddr());
                e.add("interpreter", image.interpreter());
                e.add("executable_stack", image.wants_executable_stack());
                e.add("gnu_relro", image.has_gnu_relro());
            } else {
                e.add("error", out.error);
                e.add("detail", out.detail);
            }
            events->commit();

            if (image.ok()) {
                for (std::size_t i = 0; i < image.mappings().size(); ++i) {
                    report_mapping(*events, image.mappings()[i], i);
                }
            }
        }

        return out;
    }

    [[nodiscard]] LaunchPlan plan(const EngineRequest& request,
                                  const LoadedImage& image) const override {
        LaunchPlan out;
        if (!image.ok) {
            out.refusal =
                "the image is not one this build can run: " + image.error;
            return out;
        }

        // The target's path is made absolute before the container is built.
        //
        // The container pivots its root, and everything after the pivot is
        // resolved against the new root rather than against the directory
        // occ happened to be started in. A relative path is therefore a
        // different file inside the container than it was outside, and the
        // failure is an ENOENT from an execve that looks correct at the
        // call site.
        //
        // Resolving here rather than in the child is deliberate: the child
        // has already pivoted by the time it could do it, and the host's
        // view of where the file is no longer exists from inside. The path
        // recorded in the event stream is the resolved one too, so a reader
        // of the stream can tell what actually ran.
        out.program = fs::absolute_path(request.path);

        // The caller's argv, unchanged. argv[0] is the target as the caller
        // named it rather than the resolved path, because argv[0] is what
        // the target reads back out of /proc/self/cmdline and what a shell
        // would have put there. Rewriting it would change what the target
        // believes it was invoked as, which is not occ's decision to make.
        out.argv = request.argv;

        // No binds and no environment of its own. A Linux executable needs
        // the libraries it names in its interpreter line, and those live
        // under the caller's root, which is the same root an ELF run has
        // always had. Adding them here would mean an ELF run could see a
        // library an ordinary run could not, which is the kind of
        // difference between the two paths that nobody would find by
        // reading the code.
        return out;
    }

private:
    // A file that could not be read is still an image_loaded event with
    // ok false, not a silent absence. A consumer counting the targets in a
    // stream would otherwise be right by accident on a run whose target it
    // never saw, and wrong by one on a run that failed for a reason worth
    // knowing.
    static void report_unreadable(obs::Writer* events, const std::string& path,
                                  std::uint64_t size, const LoadedImage& out) {
        if (events == nullptr) {
            return;
        }
        auto& e = events->begin(obs::EventKind::ImageLoaded);
        e.add("path", path);
        e.add("engine", "exe");
        e.add("size", size);
        e.add("ok", false);
        e.add("error", out.error);
        e.add("detail", out.detail);
        events->commit();
    }
};

const ExeEngine& the_exe_engine() noexcept {
    static const ExeEngine engine;
    return engine;
}

} // namespace

const Engine& elf_engine() noexcept {
    return the_exe_engine();
}

} // namespace occ::engine

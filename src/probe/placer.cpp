#include "occ/probe/placer.h"

#include "occ/parser/elf.h"
#include "occ/util/fs.h"

#include <cstdlib>
#include <string>

namespace occ::obs {

namespace {

// The directories the dynamic linker searches when a name has no slash.
//
// The two are the packaged 64-bit multiarch directory and the plain
// /usr/lib, which is what a non-Debian host uses. The list is short on
// purpose: a longer one would be a guess at the host's configuration, and a
// probe placed in the wrong copy of a library is worse than a probe that was
// reported as unplaced.
constexpr const char* kDefaultLibDirs[] = {
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
    "/lib64",
    "/usr/lib64",
    "/lib",
    "/usr/lib",
};

std::vector<std::string> library_path_dirs() {
    std::vector<std::string> out;

    const auto append = [&out](const char* value) {
        if (value == nullptr || value[0] == '\0') {
            return;
        }
        std::string rest(value);
        std::size_t start = 0;
        for (;;) {
            const std::size_t colon = rest.find(':', start);
            const std::size_t end =
                colon == std::string::npos ? rest.size() : colon;
            if (end > start) {
                out.emplace_back(rest.substr(start, end - start));
            }
            if (colon == std::string::npos) {
                break;
            }
            start = colon + 1;
        }
    };

    append(::getenv("LD_LIBRARY_PATH"));
    for (const char* dir : kDefaultLibDirs) {
        out.emplace_back(dir);
    }
    return out;
}

} // namespace

const char* placement_outcome_name(PlacementOutcome o) noexcept {
    switch (o) {
    case PlacementOutcome::Attached: return "attached";
    case PlacementOutcome::ModuleMissing: return "module_missing";
    case PlacementOutcome::ModuleUnreadable: return "module_unreadable";
    case PlacementOutcome::SymbolMissing: return "symbol_missing";
    case PlacementOutcome::NoFileOffset: return "no_file_offset";
    case PlacementOutcome::KernelRefused: return "kernel_refused";
    }
    return "unknown";
}

std::string find_module(std::string_view module) noexcept {
    if (module.empty()) {
        return {};
    }
    if (module.find('/') != std::string_view::npos) {
        const std::string path(module);
        return fs::exists(path) ? path : std::string{};
    }

    for (const std::string& dir : library_path_dirs()) {
        if (dir.empty()) {
            continue;
        }
        std::string candidate = dir;
        if (candidate.back() != '/') {
            candidate += '/';
        }
        candidate += module;
        if (fs::exists(candidate)) {
            return candidate;
        }
    }
    return {};
}

Placement ProbePlacer::resolve(const engine::ProbeRequest& request) noexcept {
    Placement out;
    out.label = request.label;
    out.symbol = request.symbol;

    const std::string path = find_module(request.module);
    if (path.empty()) {
        out.module = std::string(request.module);
        out.outcome = PlacementOutcome::ModuleMissing;
        out.detail = "the module " + std::string(request.module) +
                     " is not on the loader's path";
        return out;
    }
    out.module = path;

    auto bytes = fs::read_file_bytes(path);
    if (!bytes || bytes->empty()) {
        out.outcome = PlacementOutcome::ModuleUnreadable;
        out.detail = "the module could not be read";
        return out;
    }

    const parser::ElfImage image =
        parser::ElfImage::parse(ByteSpan{bytes->data(), bytes->size()});
    if (!image.ok()) {
        out.outcome = PlacementOutcome::ModuleUnreadable;
        out.detail = std::string("the module is not an ELF this build can "
                                 "read: ") +
                     parser::load_error_name(image.error());
        return out;
    }

    const parser::Symbol* symbol = image.find_symbol(request.symbol);
    if (symbol == nullptr) {
        out.outcome = PlacementOutcome::SymbolMissing;
        out.detail = "the module has no symbol named " + request.symbol;
        return out;
    }
    if (!symbol->probeable()) {
        // Named separately from absent because they call for different
        // actions. An import with the right name means the function is
        // somewhere else -- in the module that exports it -- and a data
        // symbol with the right name means the name was reused.
        out.outcome = PlacementOutcome::SymbolMissing;
        out.detail = symbol->defined()
                         ? "the symbol " + request.symbol +
                               " is not a function, so there is no code to "
                               "probe"
                         : "the symbol " + request.symbol +
                               " is undefined in this module, which means it "
                               "is imported rather than defined here";
        return out;
    }

    std::uint64_t offset = 0;
    if (!image.vaddr_to_file_offset(symbol->value, offset)) {
        out.outcome = PlacementOutcome::NoFileOffset;
        out.detail = "the symbol " + request.symbol + " is at a virtual "
                     "address that no part of the file backs, so there is no "
                     "byte to place a probe on";
        return out;
    }

    out.offset = offset;
    out.outcome = PlacementOutcome::Attached;
    return out;
}

std::size_t ProbePlacer::place(
    const std::vector<engine::ProbeRequest>& requests,
    std::vector<Placement>& out, Writer* events) noexcept {
    std::size_t attached = 0;

    for (const engine::ProbeRequest& request : requests) {
        Placement p = resolve(request);

        // The resolution is reported before the registration attempt, so a
        // reader sees the offset that was chosen even when the kernel then
        // refuses it. A refusal that reports no offset cannot be compared
        // against readelf output, which is the first thing anyone does.
        if (p.outcome == PlacementOutcome::Attached) {
            std::string detail;
            const int err = probes_.add(p.label, p.module, p.offset,
                                        ProbeKind::Entry, detail);
            if (err != 0) {
                p.outcome = PlacementOutcome::KernelRefused;
                p.detail = detail;
            } else {
                ++attached;
            }
        }

        if (events != nullptr) {
            auto& e = events->begin(EventKind::ProbeAttached);
            e.add("label", p.label);
            e.add("symbol", p.symbol);
            e.add("module", p.module);
            e.add("outcome", placement_outcome_name(p.outcome));
            e.add("ok", p.outcome == PlacementOutcome::Attached);
            if (p.outcome == PlacementOutcome::Attached) {
                e.add_hex("offset", p.offset);
                e.add("kind", "entry");
            }
            if (!p.detail.empty()) {
                e.add("detail", p.detail);
            }
            if (!request.note.empty()) {
                e.add("note", request.note);
            }
            events->commit();
        }

        out.push_back(std::move(p));
    }

    // Where the probes went, or where they would have gone. A layer that
    // resolved a tracefs remembers it; one that placed nothing never
    // resolved one, and the reason is asked for here rather than per probe
    // because it is the same answer for all of them.
    root_ = probes_.tracefs_root();
    if (root_.empty()) {
        const ProbeAvailability avail =
            Uprobes::availability(probes_.tracefs_root());
        if (avail.available) {
            root_ = avail.tracefs_root;
        } else {
            unavailable_reason_ = avail.reason;
        }
    }

    return attached;
}

} // namespace occ::obs

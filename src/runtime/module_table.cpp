// The process's module table. See module_table.h for what this is and why.
//
// The load is two passes, and the two passes are what make the answer
// independent of the dependency graph's shape.
//
// The first pass walks the graph in post-order -- a module's dependencies
// before the module itself -- and maps every node with the loader's resolver
// unset. A load without a resolver maps, relocates and *records* the import
// table without resolving it: every import's slot address and the name it
// wants are kept in `LoadedModule::imports`, and nothing is written into the
// image. That is also why this pass cannot fail on a missing import, which
// matters more than it looks: the pass that could fail -- the one that
// resolves -- runs when every base in the process is already fixed, so
// resolving is a lookup rather than a load.
//
// The second pass walks the same order and resolves. For each recorded
// import it asks `resolve_import`, writes the answer into the IAT slot, and
// on the first name it cannot answer reports the module and the symbol that
// wanted it.
//
// The alternative -- resolving during the load, which is what the loader's
// resolver callback invites -- is one pass and is what a loader with no
// cycles to worry about does. It cannot survive a cycle: A imports B and B
// imports A makes A's load call B's load call A's load, and the second visit
// to A finds a module with no base because the first visit has not returned.
// The two passes turn the cycle into a shape of the graph rather than a
// failure of the load, which is what Windows' own loader does by the same
// means: it maps before it snapshots.
//
// What the passes cost is a second walk of each import table. Each walk is
// linear in the table and happens once per module per process.

#include "occ/runtime/module_table.h"

#include "occ/observer/event.h"
#include "occ/runtime/containment.h"
#include "occ/runtime/dos_path.h"

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <set>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

namespace occ::runtime::module_table {

namespace {

// The table the thunks reach. One per process, set by the layer that builds
// the process and cleared when it is done.
Table* g_table = nullptr;

// A node of the dependency graph: a file, its bytes, and its dependencies by
// name, before anything is mapped.
//
// The bytes are held from the parse to the mapping. A load that read the
// file again would be reading a file the caller may have replaced in
// between, and the image that ran would then not be the image that was
// checked -- which is the same argument the loader makes for loading from a
// span rather than from a path.
struct Node {
    std::string folded_name;
    std::string path;
    std::vector<std::uint8_t> bytes;
    parser::PeImage image;
    std::vector<std::string> dependencies;
    LoadedModule loaded;
    bool mapped = false;
};

[[nodiscard]] ByteSpan span_of(const std::vector<std::uint8_t>& bytes) noexcept {
    return ByteSpan{bytes.data(), bytes.size()};
}

// The host path for a path the caller spelled, in either the DOS form a
// guest uses or the host form a command line uses.
[[nodiscard]] std::string host_path_for(std::string_view named) noexcept {
    return from_dos_path(std::string(named));
}

// Reads a whole file, through the confined open every other file operation
// here goes through: a module load must not be the one path that escapes the
// runtime's root.
[[nodiscard]] bool read_file(const std::string& host_path,
                             std::vector<std::uint8_t>* out) {
    const int fd = contained_open(host_path.c_str(), O_RDONLY, 0);
    if (fd < 0) {
        return false;
    }
    out->clear();
    std::uint8_t buffer[64 * 1024];
    for (;;) {
        const ::ssize_t got = ::read(fd, buffer, sizeof(buffer));
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            ::close(fd);
            return false;
        }
        if (got == 0) {
            break;
        }
        out->insert(out->end(), buffer, buffer + got);
    }
    ::close(fd);
    return true;
}

}  // namespace

Table* current() noexcept { return g_table; }

void set_current(Table* table) noexcept { g_table = table; }

std::string fold_name(std::string_view path_or_name) {
    const std::size_t separator = path_or_name.find_last_of("/\\");
    const std::string_view base =
        separator == std::string_view::npos
            ? path_or_name
            : path_or_name.substr(separator + 1);
    std::string folded;
    folded.reserve(base.size() + 4);
    for (const char ch : base) {
        folded.push_back(ch >= 'A' && ch <= 'Z'
                             ? static_cast<char>(ch - 'A' + 'a')
                             : ch);
    }
    // A name with no extension is the name `LoadLibrary("foo")` spells, and
    // the search for it ends at `foo.dll`. Normalizing it here rather than at
    // the search keeps one spelling inside the table: a module loaded as
    // `foo` and one loaded as `foo.dll` are one module, and a table that held
    // both would initialize it twice and count its references twice.
    if (!folded.empty() && folded.find('.') == std::string::npos) {
        folded += ".dll";
    }
    return folded;
}

// -------------------------------------------------------------- the images

void Table::adopt_main_image(std::string folded_name, std::uint64_t base,
                             std::uint64_t size, std::uint64_t entry_va) {
    Entry entry;
    entry.name = std::move(folded_name);
    entry.kind = ModuleKind::MainImage;
    entry.base = base;
    entry.size = size;
    entry.entry_va = entry_va;
    entry.refcount = 1;
    // The running image cannot be unloaded, which is what `FreeLibrary` on
    // its handle answers `ERROR_INVALID_PARAMETER` for. Pinned rather than
    // counted, because a count can be decremented and this cannot.
    entry.pinned = true;
    entry.initialized = true;  // its entry is the program, which is running
    entries_.push_back(std::move(entry));
}

void Table::adopt_api_image(std::string folded_name, std::uint64_t base,
                            std::uint64_t size) {
    Entry entry;
    entry.name = std::move(folded_name);
    entry.kind = ModuleKind::ApiImage;
    entry.base = base;
    entry.size = size;
    entry.refcount = 1;
    // An API image is a view of this runtime's own code: there is no file to
    // unload and no entry point to run that is not the thunk behind a
    // trampoline. Its exports stay valid for the process's life.
    entry.pinned = true;
    entry.initialized = true;
    entries_.push_back(std::move(entry));
}

void Table::set_api_resolver(ApiResolver resolver, void* state) noexcept {
    api_resolver_ = resolver;
    api_state_ = state;
}

void Table::set_search_directories(std::vector<std::string> directories) {
    search_directories_ = std::move(directories);
}

Entry* Table::find(std::uint64_t base) noexcept {
    for (Entry& entry : entries_) {
        if (entry.base == base) {
            return &entry;
        }
    }
    return nullptr;
}

Entry* Table::find_name(std::string_view folded_name) noexcept {
    for (Entry& entry : entries_) {
        if (entry.name == folded_name) {
            return &entry;
        }
    }
    return nullptr;
}

std::vector<Entry*> Table::load_order() {
    std::vector<Entry*> order;
    order.reserve(entries_.size());
    for (Entry& entry : entries_) {
        order.push_back(&entry);
    }
    return order;
}

std::vector<Entry*> Table::disk_modules() {
    std::vector<Entry*> modules;
    for (Entry& entry : entries_) {
        if (entry.kind == ModuleKind::DiskImage) {
            modules.push_back(&entry);
        }
    }
    return modules;
}

std::uint32_t Table::add_ref(std::uint64_t base) noexcept {
    Entry* entry = find(base);
    if (entry == nullptr) {
        return 0;
    }
    ++entry->refcount;
    return entry->refcount;
}

// -------------------------------------------------------------- the search

std::string Table::resolve_path(std::string_view name) const {
    const std::string named(name);
    if (named.empty()) {
        return std::string();
    }
    // A name with a separator or a drive letter is a path the caller spelled,
    // and it is used as it stands. The drive check is what makes `C:foo.dll`
    // -- a drive-relative path -- a path rather than a name the search would
    // look for in a directory called `C:`.
    const bool has_separator = named.find_first_of("/\\") != std::string::npos;
    const bool has_drive =
        named.size() >= 2 && named[1] == ':' &&
        ((named[0] >= 'A' && named[0] <= 'Z') ||
         (named[0] >= 'a' && named[0] <= 'z'));
    if (has_separator || has_drive) {
        const std::string host = host_path_for(named);
        if (::access(host.c_str(), R_OK) == 0) {
            return host;
        }
        return std::string();
    }
    // A bare name: the directories the table was given, in order, and the two
    // spellings of each -- as it was written, and with `.dll` when it had no
    // extension. The order is the caller's, and the caller is the command
    // layer, which knows where the program's own directory is.
    std::vector<std::string> spellings;
    spellings.push_back(named);
    if (named.find('.') == std::string::npos) {
        spellings.push_back(named + ".dll");
    }
    for (const std::string& directory : search_directories_) {
        for (const std::string& spelling : spellings) {
            std::string candidate = directory;
            if (!candidate.empty() && candidate.back() != '/' &&
                candidate.back() != '\\') {
                candidate.push_back('/');
            }
            candidate += spelling;
            const std::string host = host_path_for(candidate);
            if (::access(host.c_str(), R_OK) == 0) {
                return host;
            }
        }
    }
    return std::string();
}

// ---------------------------------------------------------------- the load

LoadOutcome Table::load(std::string_view name_or_path) {
    const std::string folded = fold_name(name_or_path);
    if (Entry* existing = find_name(folded); existing != nullptr) {
        // A second ask for a loaded module is a reference, not a load. The
        // count moves and the same base answers, which is the contract
        // `LoadLibrary` has and the reason two loads balance two frees.
        ++existing->refcount;
        LoadOutcome outcome;
        outcome.ok = true;
        outcome.base = existing->base;
        return outcome;
    }
    const std::string path = resolve_path(name_or_path);
    if (path.empty()) {
        LoadOutcome outcome;
        outcome.detail = "no file named " + std::string(name_or_path) +
                         " was found in " +
                         std::to_string(search_directories_.size()) +
                         " search directories";
        return outcome;
    }
    return load_disk(path, folded);
}

void Table::index_exports(Entry& entry, const parser::PeImage& image) {
    for (const parser::PeExport& parsed : image.exports()) {
        Export record;
        record.name = parsed.name;
        record.ordinal = parsed.ordinal;
        if (parsed.is_forwarder) {
            // A forwarder has no address of its own: its `rva` names a string
            // inside the export directory, and answering it as an address
            // would hand the caller a pointer into the middle of a table.
            // What the caller wants is the target, and the target is resolved
            // when it is asked for rather than here -- a forwarder may name a
            // module that is not loaded yet, and a module that never loads
            // must not fail the load of the module that forwards.
            record.is_forwarder = true;
            record.forwarder_module = fold_name(parsed.forwarder_dll);
            record.forwarder_symbol = parsed.forwarder_name;
            record.forwarder_ordinal = parsed.forwarder_ordinal;
            record.forwarder_by_ordinal = parsed.forwarder_by_ordinal;
        } else if (parsed.rva != 0) {
            record.address = entry.base + parsed.rva;
        } else {
            // A slot the address table left empty, which the format uses for
            // a symbol that was removed while its slot was kept so the
            // ordinals after it did not move. Not an export, and not an
            // error: the entry is dropped.
            continue;
        }
        const std::size_t index = entry.exports.size();
        if (!record.name.empty()) {
            entry.by_name.emplace(record.name, index);
        }
        entry.by_ordinal.emplace(record.ordinal, index);
        entry.exports.push_back(std::move(record));
    }
}

bool Table::write_iat(std::uint64_t slot_va, std::uint64_t value,
                      std::string* error) {
    // The slot has to be inside an image this table mapped. The check is
    // against the image's own bounds rather than against the space, because
    // an import record's slot address is arithmetic on the file's table and a
    // malformed file is exactly the case that arithmetic gets wrong.
    bool inside = false;
    for (const Entry& entry : entries_) {
        if (entry.base != 0 && slot_va >= entry.base &&
            slot_va - entry.base <= entry.size &&
            entry.size - (slot_va - entry.base) >= sizeof(std::uint64_t)) {
            inside = true;
            break;
        }
    }
    if (!inside) {
        *error = "an import slot at 0x" +
                 std::to_string(static_cast<unsigned long long>(slot_va)) +
                 " is not inside any image this process mapped";
        return false;
    }
    // A slot the ledger does not cover is a slot no mapping reaches, and the
    // store below would fault rather than fail. The bound is written as a
    // difference for the reason `loader.cpp` writes its bounds that way: a
    // sum can wrap and a difference cannot.
    const Region* region = space_.find(slot_va);
    if (region == nullptr || region->size < sizeof(std::uint64_t) ||
        slot_va - region->base > region->size - sizeof(std::uint64_t)) {
        *error = "an import slot at 0x" +
                 std::to_string(static_cast<unsigned long long>(slot_va)) +
                 " has no eight writable bytes in a mapped region";
        return false;
    }
    const bool writable =
        (protection_to_prot(region->protection) & PROT_WRITE) != 0;
    if (!writable) {
        // An IAT that lands in a read-only section -- which is where a link
        // puts it -- is made writable for the store and put back, which is
        // the same two steps the platform's loader takes and the reason a
        // program that reads its own IAT at rest reads a page it cannot
        // write.
        const Result<std::uint32_t> changed = mapper_.protect_in_range(
            slot_va, sizeof(std::uint64_t), PageProtection::ReadWrite);
        if (!changed.ok()) {
            *error = "an import slot at 0x" +
                     std::to_string(static_cast<unsigned long long>(slot_va)) +
                     " could not be made writable";
            return false;
        }
    }
    std::memcpy(reinterpret_cast<void*>(slot_va), &value, sizeof(value));
    if (!writable) {
        static_cast<void>(mapper_.protect_in_range(
            slot_va, sizeof(std::uint64_t), region->protection));
    }
    return true;
}

void Table::rollback_all() {
    // Unmap every disk image the table holds, newest first -- which is the
    // order that keeps a dependency from being unmapped while a dependent's
    // remaining bytes still name it. The API images and the main image are
    // not this function's to unmap; they belong to the process.
    for (std::size_t i = entries_.size(); i > 0; --i) {
        Entry& entry = entries_[i - 1];
        if (entry.kind != ModuleKind::DiskImage) {
            continue;
        }
        if (entry.base != 0) {
            static_cast<void>(mapper_.unmap(entry.base));
        }
    }
    entries_.erase(std::remove_if(entries_.begin(), entries_.end(),
                                  [](const Entry& entry) {
                                      return entry.kind ==
                                             ModuleKind::DiskImage;
                                  }),
                   entries_.end());
}

void Table::write_load_event(const Entry& entry) {
    if (events_ == nullptr) {
        return;
    }
    auto& e = events_->begin(obs::EventKind::ImageLoaded);
    e.add("name", entry.name);
    if (!entry.path.empty()) {
        e.add("path", entry.path);
    }
    e.add_hex("base", entry.base);
    e.add_hex("size", entry.size);
    e.add_hex("entry", entry.entry_va);
    e.add("exports", static_cast<std::uint64_t>(entry.exports.size()));
    e.add("dependencies",
          static_cast<std::uint64_t>(entry.dependencies.size()));
    e.add("tls", entry.has_tls);
    e.add("refcount", static_cast<std::uint64_t>(entry.refcount));
    events_->commit();
}

LoadOutcome Table::load_disk(std::string path, std::string folded_name) {
    LoadOutcome outcome;

    // --- 1. the graph -----------------------------------------------------
    //
    // Every module the target needs, read and parsed, in post-order. Nothing
    // is mapped yet: a node is bytes, a parsed image and a list of names.
    //
    // The walk is iterative. A chain of a few hundred modules is a real
    // chain -- a program that loads a browser's worth of DLLs does it -- and
    // a recursive walk of it would consume host stack in proportion, which
    // is host stack the guest's own recursion has not asked for.
    std::vector<Node> nodes;
    std::vector<std::string> order;  // post-order, by folded name
    std::map<std::string, std::size_t> index_of;
    std::set<std::string> visiting;  // names on the walk's stack -- a cycle
    std::set<std::string> finished;

    const auto read_and_parse = [&](Node& node) -> std::string {
        if (!read_file(node.path, &node.bytes)) {
            return "the file could not be read: " + node.path;
        }
        node.image = parser::PeImage::parse(span_of(node.bytes));
        if (!node.image.ok()) {
            return "not an image this runtime can load: " +
                   std::string(parser::pe_error_name(node.image.error())) +
                   " -- " + node.image.error_detail();
        }
        for (const std::string& dll : node.image.imports()) {
            const std::string dep = fold_name(dll);
            if (std::find(node.dependencies.begin(), node.dependencies.end(),
                          dep) == node.dependencies.end()) {
                node.dependencies.push_back(dep);
            }
        }
        return std::string();
    };

    {
        Node root;
        root.folded_name = folded_name;
        root.path = std::move(path);
        const std::string failed = read_and_parse(root);
        if (!failed.empty()) {
            outcome.detail = failed;
            return outcome;
        }
        index_of[folded_name] = 0;
        nodes.push_back(std::move(root));
        visiting.insert(folded_name);
    }

    struct Frame {
        std::size_t node = 0;
        std::size_t next_dep = 0;
    };
    std::vector<Frame> stack;
    stack.push_back(Frame{0, 0});

    while (!stack.empty()) {
        Frame& frame = stack.back();
        Node& node = nodes[frame.node];
        if (frame.next_dep >= node.dependencies.size()) {
            order.push_back(node.folded_name);
            finished.insert(node.folded_name);
            visiting.erase(node.folded_name);
            stack.pop_back();
            continue;
        }
        const std::string dep = node.dependencies[frame.next_dep++];
        if (finished.count(dep) != 0) {
            continue;
        }
        if (visiting.count(dep) != 0) {
            // A cycle. Not an error, and not a re-walk: the module is on the
            // stack above this frame and its post-order position is already
            // decided by the frame that opened it. This is the branch the
            // two-pass load exists to make survivable.
            continue;
        }
        // A module the process already has is a node with a base and nothing
        // to read. Recorded as finished so the walk does not come back to it,
        // and skipped by the mapping pass.
        if (find_name(dep) != nullptr) {
            finished.insert(dep);
            continue;
        }
        const std::string dep_path = resolve_path(dep);
        if (dep_path.empty()) {
            // Not a file. It may be an API module the host implements, in
            // which case the resolution pass answers it from the API face,
            // and it may be nothing at all, in which case the resolution
            // pass fails on it and names the module that wanted it. Either
            // way the graph has nothing more to say about it.
            finished.insert(dep);
            continue;
        }
        Node child;
        child.folded_name = dep;
        child.path = dep_path;
        const std::string child_failed = read_and_parse(child);
        if (!child_failed.empty()) {
            outcome.detail = child_failed + " (wanted by " + node.folded_name +
                             ")";
            return outcome;
        }
        const std::size_t child_index = nodes.size();
        index_of[dep] = child_index;
        nodes.push_back(std::move(child));
        visiting.insert(dep);
        stack.push_back(Frame{child_index, 0});
    }

    // --- 2. map every node, in post-order ---------------------------------
    //
    // No resolver: the loader maps, relocates, records the import table and
    // writes nothing into the image. Every base that exists after this pass
    // is a base that exists before the first resolution.
    for (const std::string& name : order) {
        const auto it = index_of.find(name);
        if (it == index_of.end()) {
            continue;
        }
        Node& node = nodes[it->second];
        if (find_name(name) != nullptr) {
            continue;
        }

        // The entry goes in before the mapping, with a zero base, so that a
        // cycle's second visit -- which happens during this pass, because a
        // module's imports are resolved inside the loader only when there is
        // a resolver, and there is not -- finds the module present. The base
        // is filled in below, and a mapping that fails takes the entry back
        // out.
        Entry entry;
        entry.name = node.folded_name;
        entry.path = node.path;
        entry.kind = ModuleKind::DiskImage;
        entry.size = node.image.image_size();
        entry.refcount = 1;
        for (const std::string& dep : node.dependencies) {
            entry.dependencies.push_back(dep);
        }
        entries_.push_back(std::move(entry));
        const std::size_t entry_index = entries_.size() - 1;

        LoadContext context;
        context.events = nullptr;  // the load is reported once, by load()
        context.placement = &mapper_;
        context.resolve = nullptr;
        context.resolver_state = nullptr;
        // TLS slots are `guest_tls`'s to hand out, not the loader's table:
        // see the entry's own field comment for why there is one registry.
        context.tls = nullptr;

        BaseRetry retry{};
        const LoadResult loaded = load_image_retrying(
            node.image, span_of(node.bytes), 0, space_, context, &retry);
        if (!loaded.ok) {
            entries_.erase(entries_.begin() +
                           static_cast<std::ptrdiff_t>(entry_index));
            rollback_all();
            outcome.detail = "the image was refused: " + loaded.detail;
            return outcome;
        }
        node.loaded = loaded.module;
        node.mapped = true;
        Entry& placed = entries_[entry_index];
        placed.base = loaded.module.base;
        placed.size = loaded.module.size;
        placed.entry_va = loaded.module.entry_va;
        placed.has_tls = loaded.module.has_tls;
        placed.tls = loaded.module.tls;
        index_exports(placed, node.image);
    }

    // --- 3. resolve every node's imports ----------------------------------
    //
    // The second walk. Every base in the process is fixed, the modules that
    // were already loaded never moved, so this is a lookup per import and
    // never a load.
    for (const std::string& name : order) {
        const auto it = index_of.find(name);
        if (it == index_of.end()) {
            continue;
        }
        Node& node = nodes[it->second];
        if (!node.mapped) {
            continue;
        }
        Entry* entry = find_name(name);
        if (entry == nullptr) {
            continue;
        }
        std::string import_error;
        if (!resolve_imports_of(*entry, node.loaded, &import_error)) {
            outcome.detail = import_error;
            rollback_all();
            return outcome;
        }
    }

    Entry* root = find_name(folded_name);
    if (root == nullptr) {
        outcome.detail = "the load left no entry for " + folded_name;
        rollback_all();
        return outcome;
    }
    write_load_event(*root);
    outcome.ok = true;
    outcome.base = root->base;
    return outcome;
}

bool Table::resolve_imports_of(Entry& entry, const LoadedModule& loaded,
                               std::string* error) {
    {
        for (const ResolvedImport& import : loaded.imports) {
            if (import.iat_va == 0) {
                continue;
            }
            // An import by ordinal keeps its number in the name the loader
            // recorded -- `#27` -- because the import table's own record is
            // the ordinal flag plus sixteen bits, and the loader renders the
            // number once rather than carrying both spellings. Recovering it
            // here is that rendering in reverse.
            std::uint16_t ordinal = 0;
            if (import.by_ordinal && import.name.size() > 1) {
                ordinal = static_cast<std::uint16_t>(
                    std::strtoul(import.name.c_str() + 1, nullptr, 10));
            }
            std::string reason;
            const std::uint64_t target =
                resolve_import(import.dll, import.name, ordinal,
                               import.by_ordinal, &reason);
            if (target == 0) {
                *error = "an import could not be resolved: " + entry.name +
                         " wants " + fold_name(import.dll) + "!" +
                         import.name +
                         (reason.empty() ? std::string() : " -- " + reason);
                return false;
            }
            std::string write_error;
            if (!write_iat(import.iat_va, target, &write_error)) {
                *error = "an import could not be written: " + entry.name +
                         "!" + import.name + " -- " + write_error;
                return false;
            }
        }
    }
    return true;
}

bool Table::finish_main_image(Entry& entry, const LoadedModule& loaded,
                              const parser::PeImage& image,
                              std::string* error) {
    // The dependencies first. A name the disk search cannot find is left
    // alone: it is either an API module, which the resolution pass answers
    // from the API face, or a name nothing answers, which the resolution
    // pass reports against the module that wanted it.
    for (const std::string& dll : image.imports()) {
        const std::string dep = fold_name(dll);
        if (find_name(dep) != nullptr) {
            continue;
        }
        if (resolve_path(dep).empty()) {
            continue;
        }
        // The name, not the resolved path: `load` is the entry point that
        // understands a second reference to a module already loaded, and
        // calling it with the path would bypass that understanding.
        const LoadOutcome outcome = load(dep);
        if (!outcome.ok) {
            *error = outcome.detail;
            return false;
        }
    }
    if (!resolve_imports_of(entry, loaded, error)) {
        return false;
    }
    index_exports(entry, image);
    entry.initialized = false;
    return true;
}

// ------------------------------------------------------------- the resolver

std::uint64_t Table::resolve_import(const std::string& dll,
                                    const std::string& name,
                                    std::uint16_t ordinal, bool by_ordinal,
                                    std::string* error) {
    // The API face first, and the order is the one the platform uses: a
    // module this runtime implements is the answer Windows gives too, and the
    // api-set schema exists to make the contract name resolve to that module
    // before any file is consulted.
    if (api_resolver_ != nullptr) {
        std::uint64_t answer = 0;
        if (api_resolver_(api_state_, dll, name, ordinal, by_ordinal,
                          &answer) &&
            answer != 0) {
            return answer;
        }
    }
    // Then the module table. The module is loaded -- pass one put every file
    // in the process -- so this is a lookup, and a miss is a miss rather than
    // a reason to read a file the graph pass did not find.
    Entry* module = find_name(fold_name(dll));
    if (module == nullptr) {
        if (error != nullptr) {
            *error = "the module " + fold_name(dll) +
                     " is not in this process";
        }
        return 0;
    }
    const std::uint64_t target = proc_address(module->base,
                                              by_ordinal
                                                  ? reinterpret_cast<const char*>(
                                                        static_cast<std::uintptr_t>(
                                                            ordinal))
                                                  : name.c_str());
    if (target == 0 && error != nullptr) {
        *error = module->name + " does not export " +
                 (by_ordinal ? "#" + std::to_string(ordinal) : name);
    }
    return target;
}

std::uint64_t Table::proc_address(std::uint64_t base, const char* name) noexcept {
    Entry* entry = find(base);
    if (entry == nullptr || name == nullptr) {
        return 0;
    }
    // An ordinal ask travels as `MAKEINTRESOURCE`: the value is the ordinal
    // itself, and a real name is never that small.
    const bool by_ordinal =
        reinterpret_cast<std::uintptr_t>(name) <= 0xFFFFU;
    const Export* found = nullptr;
    if (by_ordinal) {
        const auto it = entry->by_ordinal.find(
            static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(name)));
        if (it != entry->by_ordinal.end()) {
            found = &entry->exports[it->second];
        }
    } else {
        const auto it = entry->by_name.find(name);
        if (it != entry->by_name.end()) {
            found = &entry->exports[it->second];
        }
    }
    if (found == nullptr) {
        return 0;
    }
    if (!found->is_forwarder) {
        return found->address;
    }
    // A forwarder answers with its target's export, resolved now rather than
    // at load time: a forwarder may name a module the image does not import,
    // and Windows resolves the string when `GetProcAddress` reads it, which
    // is why a forwarder to a missing module is a failed call and not a
    // failed load.
    Entry* target_module = find_name(found->forwarder_module);
    if (target_module == nullptr) {
        return 0;
    }
    if (found->forwarder_by_ordinal) {
        return proc_address(
            target_module->base,
            reinterpret_cast<const char*>(
                static_cast<std::uintptr_t>(found->forwarder_ordinal)));
    }
    return proc_address(target_module->base, found->forwarder_symbol.c_str());
}

// -------------------------------------------------------- the entry points

bool Table::call_entry(Entry& entry, std::uint64_t reason,
                       std::string* error) {
    if (entry.entry_va == 0) {
        // An image whose entry point is zero has nothing to run. The format
        // allows it -- a resource-only DLL is exactly this -- and a load of
        // one is a successful load, not a failure.
        return true;
    }
    if (call_ == nullptr) {
        *error = "no guest call mechanism was installed for " + entry.name;
        return false;
    }
    std::string call_error;
    const std::uint64_t result =
        call_(call_state_, entry.entry_va, entry.base, reason, 0, &call_error);
    if (!call_error.empty()) {
        *error = entry.name + "'s entry point failed: " + call_error;
        return false;
    }
    // `DllMain` answers a BOOL. False is the module refusing to load, which
    // the platform's loader turns into a failed `LoadLibrary`, and which
    // this reports as a failure with the module named.
    if (result == 0) {
        *error = entry.name + "'s entry point returned FALSE, which refuses "
                             "the load";
        return false;
    }
    return true;
}

bool Table::initialize_recursive(Entry& entry, std::string* error) {
    if (entry.initialized) {
        return true;
    }
    if (entry.initializing) {
        // A cycle in the dependency graph, reached while walking it. The
        // module is on the stack above this call; its own initializer will
        // run once the walk unwinds to it. Returning true here is what makes
        // a cycle initializable, and it is safe because the only thing the
        // caller is waiting for is the module's existence, which is already
        // true.
        return true;
    }
    entry.initializing = true;
    // The dependencies first, which is what makes a dependency's exported
    // data valid by the time its dependent's `DllMain` reads it. The order
    // is the load order for a lazily loaded module and post-order for the
    // graph, and both are the same rule: nothing runs before what it needs.
    for (const std::string& dep : entry.dependencies) {
        Entry* dependency = find_name(dep);
        if (dependency == nullptr) {
            continue;  // an API module, or a name nothing answered
        }
        if (!initialize_recursive(*dependency, error)) {
            entry.initializing = false;
            return false;
        }
    }
    // `DLL_PROCESS_ATTACH` is 1, which is the value the format and every
    // CRT in existence agree on.
    if (!call_entry(entry, 1, error)) {
        entry.initializing = false;
        entry.entry_failed = true;
        return false;
    }
    entry.initializing = false;
    entry.initialized = true;
    return true;
}

bool Table::initialize(std::uint64_t base, std::string* error) {
    Entry* entry = find(base);
    if (entry == nullptr) {
        *error = "no module has base 0x" +
                 std::to_string(static_cast<unsigned long long>(base));
        return false;
    }
    return initialize_recursive(*entry, error);
}

bool Table::detach_all(std::string* error) {
    std::vector<Entry*> order = disk_modules();
    std::reverse(order.begin(), order.end());
    bool ok = true;
    for (Entry* entry : order) {
        if (!entry->initialized || entry->pinned) {
            continue;
        }
        // `DLL_PROCESS_DETACH` is 0. A module whose entry point fails here
        // has already been told the process is going away; the platform
        // ignores the answer and so does this, but the failure is reported
        // rather than dropped.
        std::string detach_error;
        if (!call_entry(*entry, 0, &detach_error)) {
            if (ok) {
                *error = detach_error;
                ok = false;
            }
        }
        entry->initialized = false;
    }
    return ok;
}

bool Table::release(std::uint64_t base, std::string* error) {
    Entry* entry = find(base);
    if (entry == nullptr) {
        *error = "no module has base 0x" +
                 std::to_string(static_cast<unsigned long long>(base));
        return false;
    }
    if (entry->pinned) {
        *error = entry->name + " cannot be unloaded: it is " +
                 (entry->kind == ModuleKind::MainImage ? "the running image"
                                                       : "an API image");
        return false;
    }
    if (entry->refcount > 1) {
        --entry->refcount;
        return true;
    }
    // The last reference. The detach, then the unmapping, then the slot.
    if (entry->initialized) {
        std::string detach_error;
        if (!call_entry(*entry, 0, &detach_error)) {
            *error = detach_error;
            // The unload continues: the platform's own loader unmaps a
            // module whose detach failed, because leaving it mapped would
            // leak an image nothing has a handle to.
        }
    }
    const std::uint64_t image_base = entry->base;
    const std::string name = entry->name;
    // The entry is taken out before the unmapping, because the unmapping
    // invalidates the addresses the entry holds and a failure here must not
    // leave a table naming an image that is gone.
    entries_.erase(std::remove_if(entries_.begin(), entries_.end(),
                                  [&](const Entry& candidate) {
                                      return &candidate == entry;
                                  }),
                   entries_.end());
    const Result<std::uint64_t> unmapped = mapper_.unmap(image_base);
    if (!unmapped.ok()) {
        *error = name + " was detached but its image could not be unmapped";
        return false;
    }
    if (events_ != nullptr) {
        auto& e = events_->begin(obs::EventKind::Note);
        e.add("event", "module_unloaded");
        e.add("name", name);
        e.add_hex("base", image_base);
        events_->commit();
    }
    return true;
}

}  // namespace occ::runtime::module_table

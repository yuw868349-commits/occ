// The DLL runtime. See dll_runtime.h for what this is and why.
//
// The order of what happens in `build` is the only non-obvious part, and it
// is forced by a circular dependency between three layers that each need the
// one below:
//
//   * the module table needs the process's address space, because that is
//     where it maps;
//   * the process builder needs the import resolver, which is the table's;
//   * the table needs the process to exist before it can be constructed.
//
// The cycle is broken the way the two-pass load breaks the module cycle: the
// process is built *without* a resolver, which maps the image and records
// its imports without resolving any of them, and the table is constructed
// over the finished process and hands back the resolution. What that costs
// is one extra walk of the main image's import table, and what it buys is
// that the main image and every dependency loaded after it go through
// exactly one resolution path.

#include "occ/runtime/dll_runtime.h"

#include "occ/runtime/exports.h"
#include "occ/runtime/winabi.h"

#include <cstdlib>
#include <unistd.h>
#include <utility>

namespace occ::runtime::dll_runtime {

// The table's entry point for a guest call, in the shape the table's
// `GuestCall` takes. The session is the runtime's, so the state a call runs
// under is the process's rather than a fresh one per call.
struct CallContext {
    PeProcess* process = nullptr;
    GuestCallSession* session = nullptr;
};

namespace {

// The API face, one per running DLL runtime. The process's resolver points
// into it, so it has to outlive the process: a guest resolves an import
// whenever it reaches one, not only at load time.
//
// A unique pointer rather than a static object because the registry is
// expensive to build -- every module this runtime implements, every export
// of each -- and a process that ends should give it back.
std::unique_ptr<ExportRegistry> g_registry;

// The answer the API face gives, in the shape the module table's resolver
// takes.
[[nodiscard]] bool api_lookup(void* state, const std::string& dll,
                              const std::string& name, std::uint16_t ordinal,
                              bool by_ordinal,
                              std::uint64_t* out) noexcept {
    static_cast<void>(state);
    if (g_registry == nullptr) {
        return false;
    }
    // The hint travels as zero: the registry verifies any hint against the
    // name before it believes it, so zero is merely "no better guess".
    const ExportLookup found = by_ordinal
                                   ? g_registry->find_by_ordinal(dll, ordinal)
                                   : g_registry->find_by_name(dll, name, 0);
    if (found.address == 0) {
        return false;
    }
    *out = found.address;
    return true;
}

[[nodiscard]] std::uint64_t guest_call_thunk(void* state, std::uint64_t entry,
                                             std::uint64_t arg0,
                                             std::uint64_t arg1,
                                             std::uint64_t arg2,
                                             std::string* out_error) noexcept {
    auto* context = static_cast<CallContext*>(state);
    if (context == nullptr || context->session == nullptr) {
        *out_error = "the call session is not installed";
        return 0;
    }
    // A `DllMain` is three integer arguments -- the module's base, the
    // reason, and the reserved pointer -- so the three positions the loader
    // fills are the first three integer slots and nothing else.
    GuestCallArgs args;
    args.slots[0].floating = false;
    args.slots[0].as_integer = arg0;
    args.slots[1].floating = false;
    args.slots[1].as_integer = arg1;
    args.slots[2].floating = false;
    args.slots[2].as_integer = arg2;
    args.count = 3;
    const GuestCallOutcome outcome =
        call_guest_entry(*context->process, *context->session, entry, args);
    if (!outcome.ok) {
        *out_error = outcome.detail;
        return 0;
    }
    return outcome.result;
}

// The per-user directories a Windows program assumes exist. The same list
// the runner's own process uses, and for the same reason: a program that
// asks for its cache directory gets "not defined" from Windows when the
// variable is missing, and the container's environment names Linux paths
// and Linux variables.
constexpr const char* kWindowsStandardVariables[] = {
    "LOCALAPPDATA=C:\\Users\\User\\AppData\\Local",
    "APPDATA=C:\\Users\\User\\AppData\\Roaming",
    "USERPROFILE=C:\\Users\\User",
    "HOMEDRIVE=C:",
    "HOMEPATH=\\Users\\User",
    "SYSTEMROOT=C:\\Windows",
    "windir=C:\\Windows",
    "TEMP=C:\\Users\\User\\AppData\\Local\\Temp",
    "TMP=C:\\Users\\User\\AppData\\Local\\Temp",
    "PROGRAMFILES=C:\\Program Files",
    "COMMONPROGRAMFILES=C:\\Program Files\\Common Files",
    "NUMBER_OF_PROCESSORS=8",
    "PROCESSOR_ARCHITECTURE=AMD64",
    "OS=Windows_NT",
};

}  // namespace

Runtime::~Runtime() {
    // The table points into the process's address space, so it goes first:
    // a table destroyed after the space it describes would be a table whose
    // last act names an address nothing maps.
    module_table::set_current(nullptr);
    table_.reset();
    process_.reset();
}

std::unique_ptr<Runtime> Runtime::build(const parser::PeImage& image,
                                        ByteSpan bytes, std::string image_path,
                                        const Options& options,
                                        std::string* error) noexcept {
    if (!image.ok()) {
        *error = "the image is not loadable: " +
                 std::string(parser::pe_error_name(image.error())) + " -- " +
                 image.error_detail();
        return nullptr;
    }
    auto runtime = std::unique_ptr<Runtime>(new Runtime());
    runtime->image_ = &image;
    runtime->bytes_ = bytes;
    runtime->image_path_ = std::move(image_path);
    runtime->options_ = options;

    // --- the API face -----------------------------------------------------
    g_registry = std::make_unique<ExportRegistry>();
    winabi::register_host_modules(*g_registry);

    // --- the process ------------------------------------------------------
    //
    // No resolver: this pass maps the image, relocates it, and records its
    // imports without resolving them. The table below resolves them, and
    // between the two there is exactly one resolution path for the main
    // image and for every dependency.
    const std::string dos_path = winabi::to_dos_path(runtime->image_path_);
    ProcessOptions process_options;
    process_options.command_line =
        winabi::build_command_line(dos_path, std::vector<std::string>{});
    process_options.image_path = dos_path;
    for (char** entry = environ; *entry != nullptr; ++entry) {
        process_options.environment.emplace_back(*entry);
    }
    for (const char* variable : kWindowsStandardVariables) {
        process_options.environment.emplace_back(variable);
    }
    process_options.loading_library = true;
    process_options.resolver_state = nullptr;
    process_options.resolve = nullptr;

    ProcessImage failure;
    runtime->process_ = PeProcess::build(image, bytes, process_options,
                                         &failure);
    if (runtime->process_ == nullptr || !runtime->process_->ok()) {
        *error = failure.detail.empty()
                     ? std::string(process_error_name(failure.error))
                     : failure.detail;
        runtime->process_.reset();
        return nullptr;
    }

    // --- the table --------------------------------------------------------
    runtime->table_ = std::make_unique<module_table::Table>(
        runtime->process_->space(), runtime->process_->mapper());
    module_table::set_current(runtime->table_.get());
    runtime->table_->set_search_directories(options.search_directories);
    runtime->table_->set_events(options.events);
    runtime->table_->set_api_resolver(&api_lookup, nullptr);

    // --- the main image, finished ----------------------------------------
    const LoadedModule& main_module = runtime->process_->image().module;
    runtime->table_->adopt_main_image(module_table::fold_name(runtime->image_path_),
                                      main_module.base, main_module.size,
                                      main_module.entry_va);
    module_table::Entry* main_entry =
        runtime->table_->find_name(module_table::fold_name(runtime->image_path_));
    if (main_entry == nullptr) {
        *error = "the main image could not be entered into the module table";
        return nullptr;
    }
    main_entry->has_tls = main_module.has_tls;
    main_entry->tls = main_module.tls;
    std::string finish_error;
    if (!runtime->table_->finish_main_image(*main_entry, main_module, image,
                                            &finish_error)) {
        *error = finish_error;
        return nullptr;
    }

    // --- the call session -------------------------------------------------
    runtime->session_ = make_guest_call_session(*runtime->process_);
    if (!guest_call_session_ready(*runtime->session_)) {
        *error = guest_call_session_error(*runtime->session_);
        return nullptr;
    }
    runtime->call_context_ = std::make_unique<CallContext>();
    runtime->call_context_->process = runtime->process_.get();
    runtime->call_context_->session = runtime->session_.get();
    runtime->table_->set_guest_call(&guest_call_thunk,
                                    runtime->call_context_.get());
    return runtime;
}

module_table::LoadOutcome Runtime::load(std::string_view name_or_path) {
    return table_->load(name_or_path);
}

std::uint64_t Runtime::find_export(std::uint64_t base,
                                   std::string_view name) const {
    // The name is copied into a terminator the table's lookup can read: the
    // table speaks the C form, because that is the form `GetProcAddress`
    // takes and the form the table was written against.
    const std::string terminated(name);
    return table_->proc_address(base, terminated.c_str());
}

GuestCallOutcome Runtime::call(std::uint64_t function,
                               const GuestCallArgs& args) noexcept {
    return call_guest_entry(*process_, *session_, function, args);
}

bool Runtime::detach_all(std::string* error) noexcept {
    if (detached_) {
        return true;
    }
    detached_ = true;
    return table_->detach_all(error);
}

bool Runtime::unload(std::uint64_t base, std::string* error) noexcept {
    return table_->release(base, error);
}

std::vector<ModuleInfo> Runtime::modules() const {
    std::vector<ModuleInfo> report;
    for (module_table::Entry* entry : table_->load_order()) {
        ModuleInfo info;
        info.name = entry->name;
        info.path = entry->path;
        info.base = entry->base;
        info.size = entry->size;
        info.entry = entry->entry_va;
        info.refcount = entry->refcount;
        info.has_tls = entry->has_tls;
        info.initialized = entry->initialized;
        info.exports = entry->exports.size();
        info.dependencies = entry->dependencies;
        report.push_back(std::move(info));
    }
    return report;
}

}  // namespace occ::runtime::dll_runtime

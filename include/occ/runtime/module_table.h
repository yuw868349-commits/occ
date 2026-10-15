#pragma once

// The process's module table: every image this process has, as one ledger.
//
// Before this file there were two kinds of module and two places that knew
// about them. `guest_module.cpp` carried the API modules, as images it
// synthesises so that a hand-rolled PEB walk finds what it looks for; the
// process builder carried the image the process was built around, as a
// `LoadedModule` the loader had returned. Neither could name a file on
// disk: `LoadLibrary` answered "module not found" for anything that was not
// an API module this runtime implements, and `FreeLibrary` refused every
// handle but the image's own, because the image was the only module.
//
// This file is the third kind, and it is the kind that makes the other two
// one thing. A disk DLL is an image the loader maps the same way it maps
// the main image -- the parse, the placement, the relocation walk, the
// import resolution and the TLS directory read are the same code -- and
// what it needs beyond that is bookkeeping: who depends on whom, what order
// the DLL entry points run in, what an export's address is, and when a
// `FreeLibrary` may actually unload.
//
// The bookkeeping is this file. It owns:
//
//   * the entry per module: base, size, path, kind, reference count, and
//     the export index a `GetProcAddress` answers from;
//   * the load: name resolution against a search path, the loader call,
//     the recursive resolution of the loaded image's own imports, and the
//     TLS slot when the image declares one;
//   * the initialization order: the post-order walk that runs every
//     dependency's entry point before the module that needs it, which is
//     the order Windows runs them in and the order that makes a
//     dependency's exported data valid by the time its dependent reads it;
//   * the release order, which is the reverse, and the rule that an unload
//     only happens when the last reference goes.
//
// What it deliberately does not own is the act of calling a guest entry
// point. That is a jump into memory this runtime mapped for someone else's
// code, and the layer that knows how to make such a jump -- the segment
// base, the fault boundary, the guest state the thunks read -- is the
// process layer. The table asks it through a callback, the same shape of
// dependency the loader's import resolver has.

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "occ/parser/pe.h"
#include "occ/runtime/address_space.h"
#include "occ/runtime/loader.h"
#include "occ/runtime/mapper.h"

namespace occ::obs {
class Writer;
}

namespace occ::runtime::module_table {

// What a module is to this process.
//
// The distinction is not cosmetic: only a disk image has a file to read
// again, only a disk image can be freed, and only a disk image's entry
// point is a `DllMain` whose return value decides whether the load
// succeeded. An API image has a base and an export table and nothing else.
enum class ModuleKind : std::uint8_t {
    // The image the process was built around. It cannot be freed -- freeing
    // the running program is what `FreeLibrary` on the image answers
    // `ERROR_INVALID_PARAMETER` for -- and its entry point is a `main`, not
    // a `DllMain`.
    MainImage,
    // An image `guest_module.cpp` synthesised for an API module the host
    // implements. Its exports are trampolines into host thunks. It has no
    // file, cannot be freed, and has no entry point to run.
    ApiImage,
    // A file. Loaded by `load`, initialized by `initialize_all`, released by
    // `release`, and unloaded when its reference count reaches zero.
    DiskImage,
};

// One export of one module, as `GetProcAddress` reads it.
//
// An export is reached three ways and the three are recorded apart rather
// than folded into one address, because the three need different answers
// at different times. A named export's address is a guest address the
// caller can call. A by-ordinal export has the ordinal and may have no
// name at all -- the format permits it, and a file that gives no name to an
// export is not a damaged file. A forwarder is not an address at all: it is
// a string naming another module's export, and answering it as an address
// would hand the caller a pointer into the middle of the export directory.
//
// The forwarder's target is kept parsed rather than as the string. A string
// here would be a second thing to parse, and the parse is where a reader
// and a caller would come to disagree about which dot separates the module
// from the symbol -- the same reason `parser::PeExport` keeps it parsed.
struct Export {
    // The public name, or empty for an export reachable by ordinal alone.
    std::string name;
    std::uint32_t ordinal = 0;

    // Where the export lives in this process's address space, as a guest
    // address. Zero for a forwarder, which has no address of its own.
    std::uint64_t address = 0;

    // Whether this export forwards, and where to. `forwarder_module` is the
    // module name as the string spells it (without the `.dll` the string
    // does not carry), folded for the table's comparison.
    bool is_forwarder = false;
    std::string forwarder_module;
    std::string forwarder_symbol;
    std::uint32_t forwarder_ordinal = 0;
    bool forwarder_by_ordinal = false;
};

// One module.
//
// The fields are grouped by who reads them: the loader's answers first (what
// the image is and where it is), then the bookkeeping (who needs it and
// whether it has run), then the export index.
struct Entry {
    // The name the loader list and every comparison here use: the file's
    // base name, lower-case, with the extension. A path in the guest's hands
    // becomes this by taking everything after the last separator and folding
    // it, which is what Windows' own name matching does.
    std::string name;

    // The file this module was read from, as a host path. Empty for an API
    // image, which has no file.
    std::string path;

    ModuleKind kind = ModuleKind::DiskImage;

    // Where the image was placed. The base is `LoadedModule::base` -- the
    // placement the relocation pass produced, which may differ from what the
    // file asked for.
    std::uint64_t base = 0;
    std::uint64_t size = 0;

    // The image's entry point, as an address in this space. For a disk image
    // this is the DLL's entry: `_DllMainCRTStartup` in an image built with a
    // CRT, or the `DllMain` itself in one built without. Running it is what
    // initialises the module, and its return value is what says whether the
    // load succeeded.
    std::uint64_t entry_va = 0;

    // How many references exist. A disk image starts at one -- the caller
    // that loaded it -- and every `LoadLibrary` for a module already in the
    // table increments it. An API image and the main image are pinned: their
    // count never falls, because there is nothing to unload. Kept as a count
    // rather than a flag because `FreeLibrary` is required to unload only on
    // the last call, and a boolean cannot tell the last call from the first.
    std::uint32_t refcount = 0;
    bool pinned = false;

    // Whether the entry point has run with `DLL_PROCESS_ATTACH` and
    // returned success. A module whose entry point has not run is not
    // usable -- its exported data is uninitialised -- so every dependency
    // walk checks this rather than the load result.
    bool initialized = false;

    // Whether the image is in the process of initializing. A module that
    // asks for itself -- `LoadLibrary` of a module currently running its
    // own `DllMain` -- is answered from this state rather than recursively
    // initialized, which is what keeps a cycle from recursing without end.
    bool initializing = false;

    // The TLS directory, when the image declares one. The slot and the
    // per-thread blocks are `guest_tls`'s business: that layer owns the one
    // module registry this runtime has, and a second registry here would be
    // a second place a module's slot number lives. What is kept is the
    // directory as the loader read it, so a report can say what the module
    // declared.
    bool has_tls = false;
    TlsModule tls{};

    // The exports, in address-table order, with the two indexes a lookup
    // goes through. Indexes rather than a linear scan because a module with
    // four thousand exports -- and the CRT has more -- is scanned once per
    // `GetProcAddress`, and a program's startup is thousands of those.
    std::vector<Export> exports;
    std::map<std::string, std::size_t> by_name;
    std::map<std::uint32_t, std::size_t> by_ordinal;

    // The modules this one imports, in the order the import directory names
    // them, folded. Kept because the initialization order is derived from it
    // and because a report that cannot say what a module needs cannot
    // explain why it failed.
    std::vector<std::string> dependencies;

    // The entry point's verdict, kept so that a second `initialize_all`
    // call can report a module that failed rather than re-run it.
    bool entry_failed = false;
};

// What a load produced.
//
// A struct rather than a base plus an out-error because a load has three
// answers the caller wants together: the base on success, the reason on
// failure, and the module the reason is about -- a failure while resolving
// a dependency's import names the dependency and the import, which is the
// only part of a failed load a person can act on.
struct LoadOutcome {
    bool ok = false;
    std::uint64_t base = 0;
    std::string detail;
};

// How a guest entry point is called.
//
// The table knows *which* function to call and the layer above knows *how*:
// calling a guest function means setting the segment base, being ready for
// the guest to fault, and passing arguments in the guest's convention. That
// knowledge lives in the process layer with the rest of the jump machinery.
//
// The signature is the DLL entry point's. A callback that only runs
// `DllMain` needs no more, and an export call with a different arity is the
// command layer's problem, not the table's: the table's job is the order,
// and the order is the same whatever the function's arguments are.
//
// The return is the guest's own: a `DllMain` returns a BOOL, and false ends
// the load. Zero from a call that could not be made at all -- a fault, a
// bad address -- is reported through `out_error` rather than folded into
// the false a `DllMain` legitimately returns, because "the module refused
// to load" and "the module crashed while loading" are different answers to
// the person reading the report.
using GuestCall = std::uint64_t (*)(void* state, std::uint64_t entry,
                                    std::uint64_t arg0, std::uint64_t arg1,
                                    std::uint64_t arg2,
                                    std::string* out_error) noexcept;

// The process's modules.
//
// One instance per process, owned by whoever built the process. The thunks
// reach it through `current()`, which is the same shape `guest_state()` has
// and for the same reason: an API called from guest code has no parameter
// to find the process through, and a thread-local would be a second place
// the process's identity is recorded.
class Table {
public:
    Table(const Table&) = delete;
    Table& operator=(const Table&) = delete;

    Table(AddressSpace& space, Mapper& mapper) noexcept
        : space_(space), mapper_(mapper) {}

    // ---------------------------------------------------------- the images

    // Records the image the process was built around. Its name is what
    // `GetModuleHandle` answers for the running program -- both the file
    // name and, per the API, a null or empty ask.
    void adopt_main_image(std::string folded_name, std::uint64_t base,
                          std::uint64_t size, std::uint64_t entry_va);

    // Records an API module's synthesised image. Called once per module, in
    // the order the loader list names them.
    void adopt_api_image(std::string folded_name, std::uint64_t base,
                         std::uint64_t size);

    // The API face's import answer, or nullptr when the process has none.
    // Called before any disk search, because a module the host implements
    // is the answer Windows would give too -- the apiset schema resolves
    // `kernel32.dll!CreateFileW` to a host module before any file is
    // consulted. Returns true and writes the address on a hit.
    using ApiResolver = bool (*)(void* state, const std::string& module,
                                 const std::string& name,
                                 std::uint16_t ordinal, bool by_ordinal,
                                 std::uint64_t* out) noexcept;
    void set_api_resolver(ApiResolver resolver, void* state) noexcept;

    // Where a bare name is looked for, in order. A name with a separator and
    // a name with a drive letter are used as they are; anything else is
    // tried in each directory here.
    void set_search_directories(std::vector<std::string> directories);

    // The observer's stream, or nullptr. Loads, unloads and entry-point
    // results are written here as they happen.
    void set_events(obs::Writer* events) noexcept { events_ = events; }

    // How a guest entry point is called. Must be set before any
    // initialization.
    void set_guest_call(GuestCall call, void* state) noexcept {
        call_ = call;
        call_state_ = state;
    }

    // ------------------------------------------------------------ the load

    // Loads the module `name_or_path` names, or returns the existing entry
    // when it is already loaded -- a second `LoadLibrary` of a loaded module
    // increments the count and answers the same base, and that is this
    // function's contract too.
    //
    // The load is recursive: the image's own imports are resolved through
    // `resolve_import`, which loads a disk module for an import no API
    // module answers. A dependency that fails to load fails the load that
    // needed it, with the reason naming the dependency.
    [[nodiscard]] LoadOutcome load(std::string_view name_or_path);

    // Finishes a main image the process builder already mapped.
    //
    // The builder maps the image the process was built around before this
    // table exists -- the table needs the process's address space, and the
    // process needs the resolver the table answers -- so that image arrives
    // here placed rather than loaded by `load`. What is left is what `load`
    // does after its own mapping: the dependencies are loaded, every
    // recorded import is resolved and written, and the export index is
    // built. The order is the same one the two-pass load uses, because the
    // reasons are the same.
    [[nodiscard]] bool finish_main_image(Entry& entry,
                                         const LoadedModule& loaded,
                                         const parser::PeImage& image,
                                         std::string* error);

    // Runs every loaded module's entry point with `DLL_PROCESS_ATTACH`, in
    // post-order: a module's dependencies before the module itself.
    //
    // Idempotent per module. A module whose entry point already ran is not
    // run again, so the second caller -- and there is one: the command layer
    // initializes after each explicit load, and the module's own
    // dependencies were initialized by their own loads -- does not run a
    // module's initialiser twice.
    [[nodiscard]] bool initialize(std::uint64_t base, std::string* error);

    // Detaches every initialized module, in reverse load order, and clears
    // the flags. Called at process exit, after the last reference is gone.
    [[nodiscard]] bool detach_all(std::string* error);

    // -------------------------------------------------------- the lookups

    [[nodiscard]] Entry* find(std::uint64_t base) noexcept;
    [[nodiscard]] Entry* find_name(std::string_view folded_name) noexcept;

    // The address `GetProcAddress` answers: the export's own code for a disk
    // module, a trampoline for an API image, and -- for a forwarder -- the
    // target module's export, resolved recursively. Zero when the name or
    // ordinal is not there.
    [[nodiscard]] std::uint64_t proc_address(std::uint64_t base,
                                             const char* name) noexcept;

    // Decrements the count and unloads when it reaches zero: detach, unmap,
    // free the TLS slot, forget the entry. Returns false for a pinned
    // module, which is what `FreeLibrary` on the image answers.
    [[nodiscard]] bool release(std::uint64_t base, std::string* error);

    // The reference count after an increment, or zero for a base this table
    // does not have. `LoadLibrary` on a loaded module is this call.
    std::uint32_t add_ref(std::uint64_t base) noexcept;

    // ------------------------------------------------------- the resolver

    // The loader's import answer. The order is the one Windows uses and the
    // one the api-set schema exists to make workable: the API face first --
    // it answers for the modules this runtime *is* -- then the module table
    // for an already-loaded disk module, then a disk load of the named file.
    [[nodiscard]] std::uint64_t resolve_import(const std::string& dll,
                                               const std::string& name,
                                               std::uint16_t ordinal,
                                               bool by_ordinal,
                                               std::string* error);

    // ---------------------------------------------------------- the state

    [[nodiscard]] AddressSpace& space() noexcept { return space_; }
    [[nodiscard]] Mapper& mapper() noexcept { return mapper_; }

    // Every module, in load order: the main image, the API images, then the
    // disk modules in the order they were loaded.
    [[nodiscard]] std::vector<Entry*> load_order();

    // Every disk module, in load order. What the reports iterate: an API
    // image has no file, no entry point and no reference count to speak of,
    // so a report that listed them would be four fifths noise.
    [[nodiscard]] std::vector<Entry*> disk_modules();

private:
    // The per-module work the three public steps share.
    [[nodiscard]] LoadOutcome load_disk(std::string path,
                                        std::string folded_name);
    [[nodiscard]] bool initialize_recursive(Entry& entry, std::string* error);
    [[nodiscard]] bool call_entry(Entry& entry, std::uint64_t reason,
                                  std::string* error);
    void index_exports(Entry& entry, const parser::PeImage& image);

    // Resolves and writes every import the loader recorded for one module.
    // The second pass of the load, shared with the main image's finish.
    [[nodiscard]] bool resolve_imports_of(Entry& entry,
                                          const LoadedModule& loaded,
                                          std::string* error);
    [[nodiscard]] std::string resolve_path(std::string_view name) const;
    void write_load_event(const Entry& entry);

    // Writes one resolved import into its slot, making the slot writable for
    // the store when the section it lives in is read-only and putting the
    // protection back afterwards. Fails when the slot is not inside an image
    // this table mapped or has no eight writable bytes in a mapped region --
    // the two checks that keep a malformed import directory from turning an
    // import resolution into a store somewhere else.
    [[nodiscard]] bool write_iat(std::uint64_t slot_va, std::uint64_t value,
                                 std::string* error);

    // Unmaps every disk image and forgets it, newest first. What a load that
    // failed part-way through calls on itself, and what keeps the space from
    // holding images nothing can name.
    void rollback_all();

    AddressSpace& space_;
    Mapper& mapper_;

    // Load order, which is also the order the loader list names modules and
    // the order the PEB walk sees. A vector rather than a map because the
    // order is part of the contract and a map's order is not.
    std::vector<Entry> entries_;

    std::vector<std::string> search_directories_;

    ApiResolver api_resolver_ = nullptr;
    void* api_state_ = nullptr;

    GuestCall call_ = nullptr;
    void* call_state_ = nullptr;

    obs::Writer* events_ = nullptr;
};

// The process's table, for the thunks that have no parameter to find it
// through. Null before a process is built, which the thunks check.
[[nodiscard]] Table* current() noexcept;
void set_current(Table* table) noexcept;

// Folds a path or a name to the form every comparison here uses: everything
// after the last separator, lower-case. The one function both the loader
// list and the lookups spell names with, so that a name that matches in one
// place matches in the other.
[[nodiscard]] std::string fold_name(std::string_view path_or_name);

}  // namespace occ::runtime::module_table

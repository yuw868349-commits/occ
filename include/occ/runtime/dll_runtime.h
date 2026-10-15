#pragma once

// The DLL runtime: loading a library and driving its lifecycle.
//
// `occ run` runs a program. This runs a *library*: it loads the image, runs
// its dependencies' and its own entry points the way a loader would, and
// then, depending on what the caller asked for, either stops there -- a
// load and a detach, which is the whole of what a `DllMain` does -- or calls
// an export the caller named and reports what came back.
//
// The three things this layer owns, and why each needs a layer at all:
//
//   * **The process.** A DLL cannot be mapped into nothing. It needs an
//     address space, a PEB with a loader list in it, a TEB with a TLS array,
//     and a stack -- which is exactly what `PeProcess::build` produces, and
//     the image it was pointed at is what those structures describe. So the
//     library *is* the image the process was built around, and the only
//     difference from `occ run` is that the entry point is called as a
//     `DllMain` with a reason rather than jumped to as a `main`.
//
//   * **The module table.** Its own header explains this at length. The
//     short form: it is where a loaded library, its dependencies, its
//     reference count and its export index live.
//
//   * **The order.** A library's entry point runs after its dependencies';
//     a process detach runs in the reverse order. The table derives the
//     order from the graph, and this layer is what says when.
//
// What is deliberately *not* here is the call itself. Calling a guest
// function is the process layer's job -- the segment base, the fault
// boundary, the guest state -- and `runtime::call_guest_entry` is that call.
// This layer only decides what to call and what to make of the answer.

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "occ/parser/pe.h"
#include "occ/runtime/module_table.h"
#include "occ/runtime/pe_process.h"

namespace occ::obs {
class Writer;
}

namespace occ::runtime::dll_runtime {

// The shape of the call hook the table is given: the process and the session
// a guest call goes through. Defined in the implementation file, because what
// it holds is machinery rather than interface.
struct CallContext;

// What the caller decides before a library is loaded.
struct Options {
    // Where a bare module name is looked for, in order. The command layer
    // fills this with the image's own directory first -- which is where a
    // program's own DLLs live and the first place the platform's loader
    // looks after the application directory -- and then the directories the
    // caller named.
    std::vector<std::string> search_directories;

    // The observer's stream, or nullptr. Loads, entry-point results and
    // unloads are written here.
    obs::Writer* events = nullptr;

    // The kernel32 flags `LoadLibraryEx` accepts. Only the set that changes
    // what the loader does is honoured; the rest are recorded and have no
    // effect, which is what the platform does with the ones it does not
    // implement either.
    std::uint32_t load_flags = 0;
};

// One module, as a report reads it.
struct ModuleInfo {
    std::string name;
    std::string path;
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::uint64_t entry = 0;
    std::uint32_t refcount = 0;
    bool has_tls = false;
    bool initialized = false;
    std::size_t exports = 0;
    std::vector<std::string> dependencies;
};

// The loaded library, and the process it is loaded into.
//
// Owned by pointer for the reason `PeProcess` is: the process's identity is
// tied to the address of its own address space, so it cannot be moved and
// cannot be returned by value.
class Runtime {
public:
    Runtime(const Runtime&) = delete;
    Runtime& operator=(const Runtime&) = delete;

    ~Runtime();

    // Builds the process around `image` and prepares the table. The bytes
    // are the file's, held by the caller for the process's life.
    //
    // A null result leaves `error` set. Nothing is loaded yet: `load` is
    // what loads, and this only makes a process for something to be loaded
    // into.
    [[nodiscard]] static std::unique_ptr<Runtime> build(
        const parser::PeImage& image, ByteSpan bytes, std::string image_path,
        const Options& options, std::string* error) noexcept;

    // Loads `name_or_path`, its dependencies, and initializes every module
    // whose entry point has not run -- dependencies first, which the table
    // derives from the graph.
    //
    // A module that is already loaded is a second reference: the count
    // moves and the same base answers, as `LoadLibrary` has it.
    [[nodiscard]] module_table::LoadOutcome load(std::string_view name_or_path);

    // The address of an export, resolved through forwarders the way
    // `GetProcAddress` resolves them. Zero when the module or the name is
    // not there.
    [[nodiscard]] std::uint64_t find_export(std::uint64_t base,
                                            std::string_view name) const;

    // Calls a guest function the caller has an address for -- an export
    // this table resolved, or the library's own entry point.
    [[nodiscard]] GuestCallOutcome call(std::uint64_t function,
                                        const GuestCallArgs& args) noexcept;

    // Runs every initialized module's detach, in reverse load order. What
    // an `attach`-only run ends with, and what a run that loaded something
    // and is about to exit owes the images it loaded.
    [[nodiscard]] bool detach_all(std::string* error) noexcept;

    // Unloads one module: detach, unmap, forget. Fails for a pinned module,
    // which is the answer `FreeLibrary` gives for the image itself.
    [[nodiscard]] bool unload(std::uint64_t base, std::string* error) noexcept;

    // Every loaded module, in load order, as a report reads it.
    [[nodiscard]] std::vector<ModuleInfo> modules() const;

    [[nodiscard]] PeProcess& process() noexcept { return *process_; }
    [[nodiscard]] module_table::Table& table() noexcept { return *table_; }
    [[nodiscard]] const parser::PeImage& image() const noexcept {
        return *image_;
    }

private:
    Runtime() noexcept = default;

    std::unique_ptr<PeProcess> process_;
    std::unique_ptr<module_table::Table> table_;
    // The session every guest call goes through: one assembly of the state
    // the thunks read, shared by every call the runtime makes.
    GuestCallSessionPtr session_;
    std::unique_ptr<CallContext> call_context_;
    // The image the process was built around, held as a pointer into the
    // caller's parse: the table and the thunks read it, and a copy here
    // would be a second parse of the same bytes.
    const parser::PeImage* image_ = nullptr;
    ByteSpan bytes_{};
    std::string image_path_;
    Options options_{};
    bool detached_ = false;
};

// The import answer the process's own `DllMain` and exports reach: the API
// face first -- the modules this runtime implements -- then the module
// table. Installed by `Runtime::build` so that a library's import of
// `kernel32.dll!CreateFileW` is answered from this runtime and an import of
// a sibling `helper.dll` is answered from the table.
//
// Exposed because the process builder takes it as a pair and because a
// second process -- the observer's, the fuzzer's -- installs the same
// answer through the same function.
struct ImportAnswer {
    void* state = nullptr;
    bool (*resolve)(void* state, const std::string& dll,
                    const std::string& name, std::uint16_t ordinal,
                    bool by_ordinal, std::uint64_t* out) noexcept = nullptr;
};

// The resolver the process builder and the table both go through.
[[nodiscard]] std::uint64_t resolve_import(void* state, const std::string& dll,
                                           const std::string& name,
                                           std::uint16_t ordinal,
                                           bool by_ordinal) noexcept;

}  // namespace occ::runtime::dll_runtime

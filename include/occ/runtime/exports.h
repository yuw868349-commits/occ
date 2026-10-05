#pragma once

// Resolving an import to an address.
//
// `LoadContext::resolve` is a function pointer with no implementation anywhere
// in this tree, which makes the fourth step of loading -- "the import tables
// are resolved into the IAT" -- the one step that cannot run. The walk is
// complete and correct: it finds every descriptor, every thunk, every name,
// and it writes into the IAT slot when a resolver answered. What is missing is
// the thing that knows where `kernel32!CreateFileW` lives.
//
// This file is that thing, in the only shape that is honest about what occ
// is. Wine answers the question by loading the imported DLL and reading its
// export table (`import_dll` -> `find_named_export` -> `find_ordinal_export`).
// occ can read the export table -- `PeImage::exports()` is a full parse of it,
// including the forwarder strings that the ninth way of getting it wrong lives
// in -- but occ cannot *load* a Windows DLL yet, because loading one means
// executing its entry point and carrying its own imports, and that is the
// layer this project is building toward rather than something it has.
//
// So a resolver here is a registry: modules registered under the names a
// guest asks for, exports looked up by the rules Wine uses, and a refusal
// that names what was missing. It is a real implementation of the lookup half
// of Wine's `fixup_imports`, and it is honest about not being the loading
// half. When the module registry can load a DLL for real, this file grows a
// loader and nothing else changes shape.
//
// The rules that are copied from Wine, and each is a decision rather than a
// detail:
//
//   * A DLL name is matched without regard to case. Wine's
//     `find_basename_module` calls `RtlEqualUnicodeString(..., TRUE)` -- the
//     TRUE is the case-insensitive flag -- so a guest that imports
//     `KERNEL32.DLL` and a registry that registered `kernel32.dll` are looking
//     at the same module. A case-sensitive comparison here would refuse an
//     import that Windows resolves, and the failure would be attributed to the
//     guest rather than to the comparison.
//
//   * An export is found by name with a *hint* tried first, then a binary
//     search. The hint is not authoritative: Wine compares the name at the
//     hint's index and falls through to the search when it differs, because a
//     hint is a starting guess and the sorted name array is the truth.
//
//   * A forwarder is a *string*, not an address, and following it means
//     looking the symbol up in another module. Wine decides an export is a
//     forwarder by the RVA falling inside the export directory rather than by
//     any bit in the table, and the string is `DLL.symbol` or `DLL.#27`.
//
//   * A name that is not found resolves to nothing, and nothing is written.
//     Wine writes a stub that raises an exception with the DLL and symbol in
//     the message, so that the program faults with a diagnosis instead of
//     jumping to zero. occ has no guest call mechanism to raise anything, so
//     the address is left unwritten and the *caller* is told, in the module's
//     import record and in an event. A zero in the IAT would be a program
//     that calls address zero; an unwritten slot holding the image's own RVA
//     is a program that faults on a value it can be shown, and this loader
//     already goes out of its way to preserve that value for `occ check`.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "occ/parser/pe.h"
#include "occ/runtime/address_space.h"
#include "occ/util/span.h"

namespace occ::runtime {

// A module a guest may import from, as far as the resolver is concerned.
struct ExportModule {
    // The name to match an import against, spelled the way the guest spells
    // it. Compared case-insensitively and without regard to a path, because
    // both are what the operating system does: a guest that imports
    // "kernel32.dll" means the same module as one that imports
    // "KERNEL32.DLL", and neither means a file at a path.
    //
    // A name with a path in it is a request the loader layer resolves before
    // it gets here -- the format allows `OriginalFirstThunk` to name a path
    // and a guest does it deliberately -- so this is the base name and a
    // caller that has a path strips it the way Wine's `alloc_module` does
    // with `wcsrchr(buffer, '\\')`.
    std::string name;

    // Where the module's image is, so that an export's RVA becomes an address.
    // Zero for a module that is described but not placed, which is a real
    // state: the export table is known from the file and the addresses are
    // not yet real. `find` returns nothing for such a module rather than
    // returning an RVA, because an RVA handed to a caller as an address is
    // the exact confusion the TLS layer refuses to create.
    std::uint64_t base = 0;

    // Whether `base` is an address this module is actually at. A registry
    // entry built from a parsed file has no base until it is mapped, and
    // saying so is what keeps a lookup from inventing one.
    bool mapped = false;

    // The module's export table, as `PeImage` parsed it. This is the whole
    // table rather than a lookup structure built from it, because the table
    // is small, it is already parsed, and a second index would be a second
    // thing that can disagree with the first.
    std::vector<parser::PeExport> exports;

    // The export directory's RVA and size, which together decide whether an
    // RVA is a forwarder string. Kept because `PeImage` keeps them and a
    // module registered from a file has to answer the question without the
    // image, and because the answer is a range test against these two numbers
    // rather than against anything in the export itself.
    std::uint32_t export_rva = 0;
    std::uint32_t export_size = 0;

    // The ordinal the first entry of the address table is exported as. The
    // table's index is not the ordinal; the index plus this is, and getting
    // that wrong resolves every ordinal import to the wrong function.
    std::uint32_t ordinal_base = 0;
};

// What a lookup found, and what it looked for when it found nothing.
struct ExportLookup {
    // The address, or zero when nothing matched. Zero is not an address any
    // loaded module has, which is what makes it usable as "not found" here
    // and would make it a poor choice in a system that mapped page zero.
    std::uint64_t address = 0;

    // The export that produced it, or nullptr. Present so a caller can report
    // which ordinal answered, which is the difference between "resolved" and
    // "resolved to the right thing" when an image binds to a wrong export and
    // the only evidence is the report.
    const parser::PeExport* export_entry = nullptr;

    // The module the symbol was found in, which is not necessarily the module
    // that was asked: a forwarder answers with a different module's export.
    const ExportModule* module = nullptr;

    // How the name was matched, which is worth recording because "found by
    // the hint" and "found by the search" are different facts about an image
    // and an image whose hint is wrong is a thing worth being able to see.
    bool by_ordinal = false;
    bool by_hint = false;

    // The forwarder chain, from the module asked about to the module that
    // answered. One entry for a direct answer, more for a forwarder, and a
    // depth-bounded walk means the chain cannot be longer than the bound.
    std::vector<std::string> chain;
};

// Why a lookup could not produce an address, when it could not.
//
// A return code rather than a refusal: this is the resolver's answer to a
// question, and the loader's own contract is that an unresolvable import is
// recorded and skipped rather than fatal. The distinction between the reasons
// exists because they mean different things to whoever reads the report --
// "no such module" is a missing runtime, "no such export" is a guest asking
// for something that does not exist, and a cycle is a malformed image.
enum class ExportStatus {
    // The symbol was found and the address is real.
    Found,
    // No module by that name is registered.
    NoSuchModule,
    // The module is registered but has no export table.
    NoExports,
    // The module has an export table with no such name.
    NoSuchExport,
    // The ordinal is outside the address table.
    OrdinalOutOfRange,
    // The export's slot is empty. The format keeps a slot for a symbol that
    // was removed so the ordinals after it do not move, and an import naming
    // it is a name the guest believes in and the module does not provide.
    EmptySlot,
    // Following forwarders reached the depth bound. A real limit rather than
    // a suspected one, and stated in ExportLookup::chain.
    ForwarderTooDeep,
    // A forwarder named a module that is not registered, or a symbol in a
    // module that does not have it. Separate from NoSuchModule so a report
    // can say *which* module in the chain was missing.
    ForwarderUnresolved,
};

// A registry of modules and the rules for looking an export up in one.
//
// The lifetime is the caller's. There is no file-scope registry anywhere in
// this project, and the reason is the one the TLS layer already established:
// Wine's global `tls_dirs` is shared by every process in the address space,
// and a slot or a module that is shared across address spaces belongs to
// neither. A resolver is the same kind of state -- it names addresses, and
// addresses mean something only relative to the space they are in.
class ExportRegistry {
public:
    // A registry with nothing in it. A lookup on it answers `NoSuchModule`
    // for everything, which is the correct answer for a runtime that has no
    // Windows DLLs, and is why `occ check` needs none: it passes a null
    // resolver and gets the imports recorded unresolved on purpose.
    ExportRegistry() = default;

    // Registers a module under a name. A name already registered is
    // replaced, and that is a decision rather than an accident: a module
    // loaded twice at two addresses is a real state during a load, and the
    // later one is the one an import should reach. Returning false for a
    // duplicate would leave the older entry reachable and the two answers
    // would depend on registration order.
    void add(ExportModule module);

    // Registers a module from a parsed image, at a base if it is mapped.
    //
    // The exports are taken from `image` as parsed. A file whose export table
    // is malformed has none -- `PeImage` reports that as an error rather than
    // as an empty table, and this function does not second-guess it: a module
    // with an unreadable export table is a module with no exports, and the
    // distinction the caller needs is between "this module has nothing to
    // offer" and "this module is not here", which is `NoExports` and
    // `NoSuchModule` and is worth keeping apart in a report.
    void add_from_image(std::string name, const parser::PeImage& image,
                        std::uint64_t base, bool mapped);

    // The number of registered modules. `occ doctor` reports it, and a run
    // reports it beside the unresolved import count, because a runtime with
    // zero modules resolving imports successfully is a contradiction worth
    // seeing.
    [[nodiscard]] std::size_t size() const noexcept { return modules_.size(); }

    // The module registered under a name, or nullptr. Case-insensitive, and
    // path-free: the name is compared whole.
    [[nodiscard]] const ExportModule* find(std::string_view name) const noexcept;

    // Every module, in registration order. A copy of the pointers rather than
    // of the modules, so a caller cannot invalidate the registry's own
    // storage by holding what it is handed.
    [[nodiscard]] std::vector<const ExportModule*> modules() const noexcept;

    // Looks an export up by name.
    //
    // `hint` is the thunk's hint field, which is a 16-bit index the linker
    // wrote and is usually right. It is tried first and is believed only
    // after a name comparison, exactly as Wine's `find_named_export` does:
    // treating it as authoritative resolves a stale hint to the wrong export
    // silently, which is a corruption rather than a refusal.
    [[nodiscard]] ExportLookup find_by_name(std::string_view dll,
                                            std::string_view name,
                                            std::uint16_t hint) const;

    // Looks an export up by ordinal. The ordinal is the number the outside
    // world uses; the address table is indexed by the number less the
    // directory's base, and a caller that has already subtracted it is
    // reading the table rather than naming an export.
    [[nodiscard]] ExportLookup find_by_ordinal(std::string_view dll,
                                               std::uint16_t ordinal) const;

    // Looks an export up the way `LoadContext::resolve` is asked to: by name,
    // or by ordinal when `by_ordinal` is set.
    //
    // This is the function the loader calls, and the signature is
    // `LoadContext::resolve`'s exactly -- the `const std::string&` parameters
    // included, which is a detail rather than a preference. A member function
    // taking `string_view` cannot be assigned to that pointer, and a wrapper
    // lambda that converted would be a second signature to keep in step with
    // the first. The strings are the loader's own, already built, and a
    // `string_view` over them would be a view the registry then has to trust
    // not to outlive the call -- which it would, but only because the loader
    // holds them for the whole walk, and that is a fact about the caller
    // rather than a guarantee the callee can check.
    //
    // The return is the address and nothing else, because the loader reports
    // the rest itself.
    [[nodiscard]] std::uint64_t resolve(void* state, const std::string& dll,
                                        const std::string& name,
                                        std::uint16_t ordinal,
                                        bool by_ordinal) const noexcept;

    // The same thing as a plain function pointer, which is the type
    // `LoadContext::resolve` is.
    //
    // It is a separate function and not a convenience because a member
    // function pointer is not assignable to a free function pointer even when
    // the signatures match exactly -- the implicit object argument is part of
    // the type, and the conversion C++ offers is the reverse of the one that
    // is needed here. So the member is what a caller with a registry
    // expression in hand uses, and this is what a caller wiring up a
    // `LoadContext` uses:
    //
    //     ctx.resolver_state = &registry;
    //     ctx.resolve = &ExportRegistry::resolve_thunk;
    //
    // The state pointer is the registry, and a null one is answered rather
    // than dereferenced -- see the member for why.
    [[nodiscard]] static std::uint64_t resolve_thunk(
        void* state, const std::string& dll, const std::string& name,
        std::uint16_t ordinal, bool by_ordinal) noexcept;

    // How deep a forwarder chain may go before the walk gives up.
    //
    // Wine has no bound: `find_forwarded_export` recurses into
    // `load_dll` and back, and a cycle between two modules is a load that does
    // not terminate rather than a refusal. A chain in real images is one or
    // two deep -- ntdll's own exports forward to the Unix side, and
    // kernel32's forward to ntdll -- so four is generous to the point of
    // being a statement about what images do rather than a limit on them.
    static constexpr std::size_t kMaxForwarderDepth = 4;

private:
    // The one implementation both public resolve entry points share.
    //
    // They cannot call each other: `resolve` takes its state as a `void*` and
    // the thunk holds a `const ExportRegistry*`, so routing one through the
    // other needs a cast in one direction or the other. Rather than pay for
    // that and keep two bodies, both delegate here.
    //
    // A *reference*, and that is the load-bearing part. The first version took
    // a pointer, and the null checks in the two callers were dead code: the
    // pointer was passed straight through to a `static` whose parameter the
    // optimiser knew was dereferenced, so Clang deleted the branches and
    // emitted no compare at all. A mutation harness caught it -- removing the
    // check changed nothing, because there was nothing to remove. A reference
    // cannot be null, so the check has to happen before the call and the
    // compiler has to keep it.
    [[nodiscard]] static std::uint64_t answer(const ExportRegistry& self,
                                              const std::string& dll,
                                              const std::string& name,
                                              std::uint16_t ordinal,
                                              bool by_ordinal) noexcept;

    // One step of the walk, shared by the two public entry points: the
    // module, the index into its address table, and the chain so far.
    //
    // `depth` is the chain length so far, and the bound is tested against it
    // rather than against a recursion depth elsewhere, so a cycle is stopped
    // by a number that means something in the report.
    [[nodiscard]] ExportLookup walk(const ExportModule& module,
                                    std::size_t index, bool by_ordinal,
                                    bool by_hint, std::size_t depth,
                                    std::vector<std::string> chain) const;

    std::vector<ExportModule> modules_;
};

// The name a module is registered under, taken from a path the way Wine's
// `alloc_module` takes it: everything after the last separator, with no
// case folding and no extension stripping. A path is not part of the name a
// guest imports by, and a registry keyed on the whole path would answer
// `NoSuchModule` for a guest that asked correctly.
//
// The extension *is* kept, because a guest can import "foo" and mean
// "foo.dll", and a registry that guesses would resolve a name the guest
// never asked for. The mapping from a bare name to a file is the loader
// layer's job, and it is a search of a directory rather than a rewrite of a
// string.
[[nodiscard]] std::string module_basename(std::string_view path) noexcept;

// Whether two module names are the same module.
//
// The comparison is ASCII case-insensitive and nothing else. Not Unicode
// case folding -- Wine's `RtlEqualUnicodeString` does fold, but the names
// involved are DOS-era 8.3 ASCII and a Unicode fold would need tables this
// project has no reason to carry. Not a locale-sensitive compare either,
// because the guest's locale is not this process's, and a
// `strcasecmp` under a Turkish locale would fold `I` to a dotless `ı` and
// stop matching `KERNEL32`.
[[nodiscard]] bool module_name_equal(std::string_view a,
                                     std::string_view b) noexcept;

}  // namespace occ::runtime

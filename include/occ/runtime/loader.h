#pragma once

// Loading a PE image into an address space.
//
// This is the piece Wine supplies today and this project is taking over.
// The reference for its behaviour is Wine's map_image_into_view, read and
// not copied, and the differences are deliberate and are stated below.
//
// What loading an image means, in order:
//
//   1. the headers are placed at the image base
//   2. each section is placed at base + VirtualAddress, with the file's
//      bytes for the part the file covers and zeros for the part it does
//      not
//   3. the base relocations are applied, if the image did not get the base
//      it asked for
//   4. the import tables are resolved into the IAT
//   5. the TLS directory is recorded so thread entry can run its callbacks
//
// The order is not a convention. Step 3 must follow step 2 because a
// relocation writes into a mapped section, and step 4 must follow step 3
// because an import address that was relocated has to be relocated before
// it is read. Wine does the same things in the same order for the same
// reason, and the reason is worth writing down because a file that reorders
// them appears to work until it meets an image with a relocated IAT.
//
// Three differences from Wine, each of which is a decision:
//
//   * A malformed image is refused. Wine accommodates a list of specific
//     programs -- there is a comment in its loader naming a game whose
//     headers are mapped over by its own sections -- and the accommodation
//     is why its loader has the shape it has. The programs this runtime is
//     for are not those programs, and a refusal that names the field and
//     the constraint is worth more than a load that succeeds for reasons
//     the person reading the report cannot see.
//
//   * Every step produces events. Mapping a region, applying a batch of
//     relocations, resolving an import -- each is reported as it happens,
//     with the numbers that were used. Wine's loader reports nothing
//     because reporting is not its purpose.
//
//   * The address space is the loader's own structure. Wine asks its
//     server to map and then learns what happened; here the map is a value
//     the loader holds, so a question about the loaded image is a lookup
//     rather than a query.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "occ/observer/event.h"
#include "occ/parser/pe.h"
#include "occ/runtime/address_space.h"
#include "occ/util/span.h"

namespace occ::runtime {

// Why an image could not be loaded.
//
// Separate from parser::PeError because a file that parses can still be
// unloadable and the two produce different sentences. A parse failure says
// the file is not a PE; a load failure says it is a PE and cannot be placed.
enum class LoadError : std::uint8_t {
    None,
    // The parser refused the file. The parser's own error is carried in the
    // detail so that the reason is not translated twice.
    NotParsable,
    // The image is for a machine this runtime does not execute. Named
    // rather than folded into a generic refusal, because "this is an ARM64
    // image" and "this file is damaged" call for different actions.
    UnsupportedMachine,
    // A section's virtual range leaves the address window, or two sections
    // overlap. Overlapping sections are legal in the format and are not
    // loadable, so this is a refusal and not a repair.
    SectionOutOfRange,
    // The image asked for a base and got something else, and it has no
    // relocation table to fix itself up with. This is the failure that a
    // runtime must report and Wine must accommodate, because the program
    // that hits it cannot run and the person needs to know why.
    NoRelocations,
    // A relocation entry names an address outside the loaded image, or a
    // relocation type this runtime does not apply. The second is a
    // capability limit and is kept distinct from the first, which is a
    // damaged file.
    BadRelocation,
    // The import directory names a DLL that is not available. Carried as an
    // error rather than a degradation because a program whose imports do
    // not resolve cannot start at all.
    MissingImport,
    // The runtime has no implementation of a function the image imports.
    // This is the value the coverage table in docs/RUNTIME.md counts, and it
    // is reported per import so that a reader learns which functions are
    // missing rather than that some function is.
    UnimplementedImport,
    // The address space refused to record a region: an overlap, or an
    // address outside the window.
    AddressConflict,
};

[[nodiscard]] const char* load_error_name(LoadError e) noexcept;

// What an image asked to import, resolved or not.
//
// The name and the resolved address are both kept, and the address is zero
// when the import was not resolved. A record with a name and no address is
// the shape of a missing import and is more useful than an absent record,
// because it says which name was wanted.
struct ResolvedImport {
    std::string dll;
    std::string name;
    // The slot in the IAT this import was written to, and the address
    // written. Both zero when the import was not resolved.
    std::uint64_t iat_va = 0;
    std::uint64_t target_va = 0;
    bool resolved = false;
    // Set when the import is by ordinal. The name is then the ordinal
    // rendered as text, and this is true, so a reader can tell an export by
    // number from one by name.
    bool by_ordinal = false;
};

// A loaded image.
struct LoadedModule {
    std::string path;
    // Where the headers were placed, which is the image base in every case
    // this runtime produces. Kept as a field rather than read from the
    // parser because the whole point of the relocation pass is that it can
    // differ from what the file asked for.
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::uint64_t entry_va = 0;

    std::vector<ResolvedImport> imports;

    // The number of relocations applied, and the number of blocks they came
    // in. Counted rather than listed in full: a large image has tens of
    // thousands of relocations and a stream that carries them all is a
    // stream nobody reads. The blocks are reported because the block is the
    // unit the file stores them in.
    std::uint64_t relocations_applied = 0;
    std::uint32_t relocation_blocks = 0;

    // The TLS directory's virtual address and the size of the template, or
    // zero when the image has none.
    std::uint64_t tls_directory_va = 0;
    std::uint32_t tls_template_size = 0;
};

struct LoadResult {
    bool ok = false;
    LoadError error = LoadError::None;
    std::string detail;
    LoadedModule module;
};

// Everything the loader needs from outside itself.
//
// The import resolver is a function rather than a link against a table of
// this runtime's own exports, because the layer above owns the export table
// and the loader is a lower layer than it. The loader asks "where is
// kernel32!CreateFileW" and the answer comes from whoever knows, which is
// the same shape of dependency the dynamic linker has.
struct LoadContext {
    // The handle to resolve an import against, or nullptr when the image's
    // imports should be recorded but not resolved. A nullptr here is what
    // makes it possible to load an image for inspection -- which is what
    // `occ check` does -- without an implementation of the API existing.
    //
    // The signature is (dll, name, ordinal, ordinal_valid) -> address, with
    // zero meaning not found.
    void* resolver_state = nullptr;
    std::uint64_t (*resolve)(void* state, const std::string& dll,
                             const std::string& name, std::uint16_t ordinal,
                             bool by_ordinal) noexcept = nullptr;

    // The events to write to, or nullptr for a load that is not observed.
    obs::Writer* events = nullptr;
};

// Loads a parsed image at `preferred_base`, or at the image's own base when
// `preferred_base` is zero.
//
// Never throws and never partially succeeds: a LoadResult that is not ok
// leaves `space` unchanged, which is what lets the caller retry at another
// base without unwinding a half-populated map. That property is worth the
// cost of building the module in a local and moving it in at the end.
[[nodiscard]] LoadResult load_image(const parser::PeImage& image,
                                    ByteSpan bytes, std::uint64_t preferred_base,
                                    AddressSpace& space,
                                    const LoadContext& context) noexcept;

} // namespace occ::runtime

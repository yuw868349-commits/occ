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
#include "occ/runtime/mapper.h"
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
    // The kernel refused a mapping the plan had already accepted: a
    // placement at an address the plan covered and the kernel disagreed
    // with, or no memory. It is a different value from AddressConflict
    // because AddressConflict is a fact about the caller's space and this
    // is a fact about the system the runtime is on -- a container with a
    // low limit, a host out of memory, a hardened kernel that refused an
    // executable mapping. A reader of the two learns which one happened.
    MappingRefused,
    // A relocation named an address the placement did not cover.
    //
    // The plan checks that every relocation's RVA is inside the image, and
    // that is enough to place the image. It is not enough to write the
    // relocation: the image's own size is not the set of addresses that are
    // writable, because a relocation can name a read-only section and
    // because a section's virtual extent is rounded up while its writable
    // content is not. This is therefore discovered at the point of the
    // write, which is the only place that holds both the address and the
    // map, and it is the same reason the entry point and the IAT slots are
    // checked where they are.
    RelocationNotWritable,
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
    // True when this import's address was actually stored into the slot.
    //
    // Distinct from `resolved`, and the distinction is the useful one: an
    // import can be resolved and not written, which is what a load that
    // mapped no memory reports, and a caller asking "can this program call
    // that function" needs the second answer rather than the first. A
    // module whose imports are all resolved and none written is a shape, not
    // a loaded image, and the field is what tells the two apart.
    bool iat_written = false;
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

    // Where the image is put, or nullptr to decide without putting it
    // anywhere.
    //
    // This is the difference between the two things a caller can want from
    // this function, and it is a pointer rather than a flag because the two
    // are not a matter of degree. With a mapper, the image's bytes are
    // copied into memory, its relocations are written, its IAT is filled
    // and its sections are given their final protections, and the module
    // returned describes memory a program can execute. Without one, every
    // decision is still made and every refusal is still reported, and
    // nothing is mapped: the module describes the shape of an image rather
    // than a loaded one.
    //
    // `occ check` passes nullptr and is the reason this is optional. It
    // answers questions about a file -- is it a PE, what does it import,
    // would it load -- and answering them does not require an address space
    // or a syscall, and a checker that mapped every file it looked at would
    // be a runtime with a file browser attached.
    //
    // A mapper here changes what the function does, not whether it decides:
    // the placement plan, the relocation walk and the entry-point check all
    // run before anything is mapped, exactly as they do without one, so an
    // image that would be refused is refused before a byte is placed. What a
    // mapper adds is the part that can still fail afterwards -- the kernel
    // refusing a mapping, and a write to an address the plan covered turning
    // out to be possible or impossible.
    Mapper* placement = nullptr;
};

// Loads a parsed image at `preferred_base`, or at the image's own base when
// `preferred_base` is zero.
//
// Never throws and never partially succeeds: a LoadResult that is not ok
// leaves `space` unchanged, which is what lets the caller retry at another
// base without unwinding a half-populated map. That property is worth the
// cost of building the module in a local and moving it in at the end.
//
// The contract holds in both of the function's two modes, and holding it in
// the placing one is the harder half: a mapping that succeeded has to be
// unmapped before the function returns a failure, or the space is left
// holding memory the map does not describe.
//
// With `context.placement` set, the image is placed: the headers and each
// section are mapped, the file's bytes are copied in, the part of a section
// the file does not cover is zeroed, the base relocations are written, the
// IAT is filled with the resolved addresses, and each region is given its
// final protection. Without it, all of the decisions are made and none of
// the stores happen, and the returned module describes a shape rather than a
// loaded image. See LoadContext::placement.
[[nodiscard]] LoadResult load_image(const parser::PeImage& image,
                                    ByteSpan bytes, std::uint64_t preferred_base,
                                    AddressSpace& space,
                                    const LoadContext& context) noexcept;

} // namespace occ::runtime

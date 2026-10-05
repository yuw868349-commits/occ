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
    // The TLS directory is present and does not describe anything this
    // runtime can build: the template's end is before its start, or one of
    // its addresses is outside the image.
    //
    // Its own value rather than a reuse of BadRelocation, because the two
    // are found at different times by different code and the reader needs to
    // know which structure was wrong. A bad relocation is a good image with
    // one bad entry; a bad TLS directory means the whole structure is
    // unusable, and a caller who fixed the relocation would find the same
    // refusal waiting.
    TlsRefused,
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

// ------------------------------------------------------------------- TLS
//
// What a PE's TLS directory means, and what has to happen for it to work.
//
// The directory is nine four-byte fields (twenty-four on PE32), and three of
// them describe a block of bytes the file carries and every thread needs its
// own copy of:
//
//   StartAddressOfRawData   the template, as a virtual address
//   EndAddressOfRawData     one past its last byte
//   AddressOfIndex          a DWORD in the image the loader writes the
//                           module's slot number into
//   AddressOfCallBacks      a NULL-terminated array of function pointers
//   SizeOfZeroFill          zero bytes appended after the template
//
// The indirection is the whole design. An image cannot contain a thread's TLS
// block, because there are as many of those as there are threads and the
// image is mapped once. So the image contains a *template*, and the runtime
// copies it per thread; and because the copy has to be found by a variable
// the program indexes, the image contains the *address of a slot number*
// rather than the slot number, which is what lets a module loaded later still
// find its block through code that was compiled against an earlier one.
//
// **Every one of those addresses is read out of memory, never out of the
// file.** This is the one thing about TLS that has to be right and it is the
// thing that is easy to get wrong, because reading the directory out of the
// file looks like it works: the values are there, they are the right shape,
// and every bounds check passes. They are also the addresses the image was
// *linked* at. The four address fields are not in the relocation table --
// which is exactly why a file's copy of them is stale the moment the image
// moves -- so a module placed anywhere but its preferred base has a
// directory that names memory nothing is mapped at.
//
// Wine gets the reading right and is the reference for it: `alloc_tls_slot`
// in `dlls/ntdll/loader.c` calls `RtlImageDirectoryEntryToData(mod->DllBase,
// ...)`, on the *mapped* image, and `call_tls_callbacks` re-reads the
// directory from the module rather than from the copy it cached, for the
// same reason. So does occ read the directory from the space whenever there
// is one, and fall back to the file only when there is not -- which is the
// `occ check` case, where the answer is about the file's shape and no
// relocation will ever happen to it.
//
// **The fields are 32 bits and the image is not, and both encodings are in
// the wild.** A field read as a virtual address can only describe an image
// based below 4 GiB, which is what the specification means and what Wine
// assumes without checking: a DLL based at 0x7fa2a6e30000, which is where
// a real 64-bit process puts one, has a TLS directory Wine cannot use. A
// field read as an RVA works at any base, and that is what modern linkers
// emit for 64-bit images, because it is the only encoding that survives
// ASLR. This runtime accepts both, disambiguated by which one lands inside
// the image and resolved toward the VA reading when both could. Wine accepts
// only the first, which is a real limitation rather than a simplification.
//
// Three further things are done differently from Wine, each a decision
// rather than an accident:
//
//   * **A slot is a slot in a table the caller owns.** Wine keeps a global
//     `tls_dirs` array and a `tls_module_count`, and a process with twenty
//     DLLs has a twenty-four-slot array that grew by doubling and was never
//     shrunk -- and a test harness in the same address space silently shares
//     it. `TlsTable` is a value, so a caller can put two of them in two
//     processes and cannot accidentally share one.
//
//   * **The index is written even when there are no threads yet.** A module
//     loaded before the first thread still has to be findable by index from
//     that thread, so the write happens at load time rather than at first
//     thread creation.
//
//   * **A template of zero length with a zero fill is not "no TLS".** Wine
//     returns FALSE for a directory whose template, zero fill and callback
//     array are all empty, and that check is kept: a module with an all-zero
//     directory is a module with no TLS, and giving it a slot would make
//     `AddressOfIndex` meaningful where the file says nothing.
// A module's TLS, as the loader recorded it.
//
// `index` is the slot. `template_va` and `template_size` describe the bytes
// every thread copies; `zero_fill` is how many zeros follow them in each
// block; `callbacks_va` is where the callback array is, or zero.
//
// `index_va` is where the slot number was *written*, which is a different
// question from what the slot number is. It is kept because a reader
// debugging "the program read a garbage index" needs the address to look at,
// and because it is the one field a caller has to be able to check for
// itself: a module with a slot and no writable index field has a slot number
// that exists in the loader and not in the image, and every thread it starts
// will read whatever was in those four bytes before.
//
// `directory_va` is kept because a report that cannot name the structure it
// read is a report about a number.
struct TlsModule {
    std::uint32_t index = 0;
    std::uint64_t directory_va = 0;
    std::uint64_t template_va = 0;
    std::uint64_t index_va = 0;
    std::uint64_t callbacks_va = 0;
    std::uint32_t template_size = 0;
    std::uint32_t zero_fill = 0;
};

// The per-process table of modules with TLS.
//
// A value rather than a global, so that two processes in one address space --
// which is what the observer and the fuzz harness both do -- do not share a
// slot table, and so that a table's lifetime is the caller's to state.
struct TlsTable {
    // One entry per module, in the order slots were handed out. The order is
    // the slot order: an entry's index in this vector *is* its slot number,
    // which is what `AddressOfIndex` receives.
    //
    // A freed slot stays in this vector as a zeroed entry rather than being
    // erased, because erasing one would renumber every module after it and a
    // module's slot number is written into its own image where nothing
    // rewrites it. Wine's `free_tls_slot` memsets the entry for the same
    // reason.
    std::vector<TlsModule> modules;

    // The number of entries ever allocated, including ones freed. A freed
    // slot is reused, and this is the high-water mark the search for a free
    // slot stops at -- the same thing Wine's `tls_module_count` is, and named
    // for the same reason: it is a bound, not a length.
    std::uint32_t slots_allocated = 0;
};

// The three things a thread needs from TLS, gathered in one value.
//
// Gathered because the three are always wanted together and are always
// derived from the same two structures -- the image's directory and the
// process's slot table -- and deriving them separately is how a caller ends
// up with a block for slot 2 and a callback list for slot 3.
struct TlsBlock {
    // The thread's copy of the template plus its zero fill, or zero when the
    // module has neither. A module whose template and zero fill are both
    // empty legitimately has no block, and this is zero rather than a
    // one-byte allocation: an address the program never dereferences should
    // not be a heap block it has to keep alive.
    std::uint64_t address = 0;
    std::uint32_t size = 0;

    // The callbacks, in the order the array lists them. Empty when the
    // module has no callback array, and also empty when the array's first
    // entry is null -- which is the format's own terminator and not an
    // absence.
    std::vector<std::uint64_t> callbacks;
};

// Why a module's TLS could not be set up.
//
// Separate from LoadError rather than a value of it, and the separation is
// the point: a load that failed because the *base* was taken can be retried
// somewhere else, and a load that failed because the TLS directory is
// nonsense cannot be retried anywhere. Folding the second into the first
// would make the retry loop below try sixty-four bases against a file that
// was never going to load.
enum class TlsError : std::uint8_t {
    None = 0,
    // The directory is present but its fields do not describe anything: the
    // template's end is before its start, or an address in it is outside the
    // image. A file that says this is a file whose TLS nobody can build.
    MalformedDirectory,
    // The template plus its zero fill, or a callback array's entries, do not
    // fit in what this runtime can map for one thread.
    TooLarge,
    // A callback returned false, so the load it belongs to failed.
    CallbackFailed,
    // The thread's block could not be mapped.
    OutOfMemory,
};

[[nodiscard]] const char* tls_error_name(TlsError e) noexcept;

struct TlsResult {
    bool ok = false;
    TlsError error = TlsError::None;
    std::string detail;
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

    // The TLS directory as the loader read it, or a zeroed record when the
    // image has none. A record rather than two scalars because the directory
    // is a structure, and the useful question about it -- what will this
    // module's thread blocks contain -- cannot be answered from a size and
    // an address.
    //
    // Filled whether or not `LoadContext::tls` was set, because reading the
    // directory is a decision and every load makes it. What the table adds
    // is the slot, and a caller without a table has no slot to be given.
    TlsModule tls{};

    // Whether this image declares TLS at all, which is not the same as
    // `tls.template_size` being non-zero: a module may declare a template
    // with no zero fill, or a zero fill with no template, and both are TLS.
    bool has_tls = false;
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
// How the next base is chosen, given the one that just failed.
//
// Returning zero means "no more", which ends the loop. The state pointer is
// the chooser's own, so a caller can keep a count or a seed across
// attempts; `attempts` is one-based and is the attempt that just failed.
using BaseChooser = std::uint64_t (*)(void* state,
                                      const parser::PeImage& image,
                                      std::uint64_t failed_base,
                                      std::uint32_t attempts) noexcept;

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

    // How the next base is chosen when the one before it was taken, or
    // nullptr for the deterministic downward scan. Appended rather than
    // inserted, because callers construct this with a positional aggregate
    // and reordering the fields would silently change what four of them
    // mean.
    //
    // Only consulted by load_image_retrying. A plain load_image call names
    // its base and does not consult it, because a caller that named a base
    // and got a different one has a bug the retry loop would hide.
    BaseChooser base_chooser = nullptr;
    void* base_chooser_state = nullptr;

    // The per-process table of TLS modules, or nullptr to skip TLS
    // allocation. Appended last, and see the section on TLS below for why it
    // is a caller-owned table rather than something the loader keeps.
    TlsTable* tls = nullptr;
};


// Reads an image's TLS directory and records it in `table`.
//
// Returns ok with a zero `module` for an image with no TLS, which is not a
// failure: most images have none, and a caller that had to distinguish "no
// TLS" from "TLS refused" would be asking a question with two useless
// answers. `module->index` is the slot the image's `AddressOfIndex` was
// given, and it is the index into `table->modules`.
//
// **The directory is read out of `space` when there is one.** The four
// address fields in it are virtual addresses that the relocation pass has
// already rewritten, so the file's copy of them is the image's *linked*
// addresses and is wrong for every image that was placed anywhere else. The
// file is read only when `space` has nothing -- that is, when
// `context.placement` is null and no mapper was given, which is the
// `occ check` case, where the question is about the file's shape and no
// relocation is going to happen to it. See the section on TLS above.
//
// A mapper's absence is not a failure and the difference is not a special
// case in the code: with a mapper the slot number is *written* into the
// image's `AddressOfIndex`, and without one there is nowhere to write it.
// The slot is allocated and reported either way, because deciding is most of
// the work and a caller in the no-mapper path still wants to know what the
// directory says.
[[nodiscard]] TlsResult load_tls(const parser::PeImage& image, ByteSpan bytes,
                                 std::uint64_t base, AddressSpace& space,
                                 const LoadContext& context, TlsTable& table,
                                 TlsModule* module) noexcept;

// Builds a thread's TLS block for one module: copies the template, appends
// `zero_fill` zeros, and reads the callback array.
//
// The template is copied *out of the space* rather than out of the file, and
// that is not an optimisation. The template holds pointers into the image,
// and an image placed away from its linked base has had those pointers
// relocated; copying from the file would give every thread a block full of
// addresses that point at the image's preferred base, which is memory
// nothing is mapped at. For the same reason the callback array is read from
// the space: its entries are addresses in the image too.
//
// There is no `bytes` parameter, and the omission is the point stated as an
// interface: a caller holding the file cannot use it to build a block,
// because a block built from the file is wrong for every image that was
// placed anywhere but its linked base. The only source that is always
// correct is the mapped image.
//
// Returns a failure rather than a partial block, and unmaps whatever it had
// mapped: a thread whose TLS is half-built is a thread that faults later,
// somewhere else, and a caller that cannot tell a partial block from a whole
// one will treat the address it got as usable.
[[nodiscard]] TlsResult build_tls_block(const TlsTable& table,
                                        std::uint32_t slot,
                                        const AddressSpace& space,
                                        Mapper& mapper, TlsBlock* out) noexcept;

// Releases a thread's block for one module.
//
// Named rather than left to a destructor because the address came from a
// mapper the caller owns and the caller has to say which: a block freed
// through the wrong mapper is a block the ledger still describes, and the
// space and the ledger then disagree about what is mapped. A block with no
// address is a module with neither template nor zero fill, which is a real
// case rather than a degenerate one, and freeing it is not an error.
void free_tls_block(Mapper& mapper, const TlsBlock& block) noexcept;

// The reason DLL_THREAD_ATTACH exists, as the four values a callback is
// called with.
//
// Named here rather than as four integers because the values are a
// contract: a callback that does not recognise its reason must return
// immediately without initialising anything, because Windows will call it
// again for every module in the load order and a callback that runs its
// initialiser twice is a bug that shows up as a corrupted module rather
// than as a rejected one.
enum class TlsReason : std::uint32_t {
    ProcessDetach = 0,
    ThreadAttach = 1,
    ThreadDetach = 2,
    ProcessAttach = 3,
};

[[nodiscard]] const char* tls_reason_name(TlsReason r) noexcept;

// How a callback is reached.
//
// A callback is an address in the image, and calling it means calling into
// memory this runtime mapped for someone else's code -- which on a host that
// does not execute the guest's instructions cannot be done by dereferencing
// the address. So the address is handed to a caller-supplied invoker, which
// is the same shape of dependency the import resolver has: the loader knows
// *which* function to call and the layer above knows *how*.
//
// The bool is the callback's return: TRUE keeps the load going, FALSE fails
// it. Wine treats a callback that returns FALSE as a failed load (see
// `call_dll_entry_point` in its loader.c).
//
// `reserved` is passed through as null, as Wine passes it, and is named in
// the signature because a callback that declares three parameters and is
// called with four is a callback reading a register the caller happened to
// leave set.
using TlsCallback = bool (*)(void* state, std::uint64_t callback,
                             std::uint64_t module, TlsReason reason) noexcept;

// Calls one module's callbacks for `reason`, in the order the array lists
// them, stopping at the first one that returns false.
//
// `block` carries the callback addresses and `module` is the base they are
// relative to, which is a parameter rather than something read out of the
// table because the table is a value the caller owns and a module's base is
// a property of the mapping, not of the TLS slot.
//
// Stops at the first false, and says so in the result, rather than calling
// the rest: a callback that returned false has told the loader the load
// failed, and calling the remaining callbacks would run their initialisers
// for a module that is not going to be loaded. Wine stops too, though it
// stops by catching an exception rather than by reading a return value --
// its `call_tls_callbacks` wraps each call in `__TRY` and returns on
// `__EXCEPT_ALL`, which is a statement about structured exceptions rather
// than about the return value, and this runtime has no SEH to catch. What is
// kept is the shape: the first failure ends the walk, and the callbacks after
// it are not called.
[[nodiscard]] TlsResult call_tls_callbacks(const TlsBlock& block,
                                           TlsCallback callback, void* state,
                                           std::uint64_t module,
                                           TlsReason reason) noexcept;

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

// ------------------------------------------------------- placing with retry
//
// A load that fails because its base was taken is not a failure of the load.
// It is a fact about the caller's address space at one moment, and the same
// call one base over usually succeeds. This is the part that turns that fact
// into an action.
//
// What it does, and what it deliberately does not do.
//
// It retries. The loader's contract already says a failed load leaves the
// space unchanged, and `rollback_placement` already makes that true in the
// placing mode -- a mapping that succeeded is unmapped before a failure is
// reported, so the space is not left holding memory the map does not
// describe. That contract is what makes a retry possible at all, and it is
// why the retry loop below is this short: it does not undo anything, because
// the call it is looping over has already undone everything.
//
// What it does not do is guess. Two limits bound the search and both are
// reported in the returned error rather than left implicit:
//
//   * the granularity is 64 KiB, the allocation granularity of
//     NtAllocateVirtualMemory, because a base that is not a multiple of it
//     cannot be the base of a mapping a program will keep;
//   * the window is the user's, and a base is only tried where the whole
//     image fits inside it.
//
// A caller that wants Windows' random choice -- the `MiChooseImageBase`
// behaviour, a random 64 KiB-aligned point within 16 MiB of the preferred
// base -- supplies a different function; `BaseChooser` is a pointer, and
// this one is the deterministic policy, not the only one. Randomness is not
// provided here on purpose: it needs a source of entropy this runtime does
// not own, and a replay needs the sequence to come back, so a random policy
// belongs to the layer that has both. See LoadContext::base_chooser.
struct BaseRetry {
    // The error the first attempt produced, when the retry gave up. The
    // last one is kept rather than the first because the last is the one
    // that describes the space as it finally was, and a caller reading
    // "it ran out of room" wants that rather than "the first guess was
    // taken".
    LoadError error = LoadError::AddressConflict;
    std::string detail;

    // How many bases were tried, including the first. One means the first
    // attempt was the last one, which is the case where the image does not
    // fit anywhere and retrying was never going to help.
    std::uint32_t attempts = 0;

    // The bases that were tried, in order. Recorded because a caller that
    // cannot load an image needs to see where it looked: "it tried 200
    // addresses" is a fact, and the addresses are how a person decides
    // whether the space is too full or the image is too large.
    std::vector<std::uint64_t> tried;
};

// The deterministic policy: scan down from the failed base by the
// allocation granularity, to the bottom of the user's window.
//
// Down rather than up, and this is the one choice worth defending. The
// image's preferred base is where its linker assumed it would live, and
// everything in it that is not relocated is correct only there. Scanning
// down moves away from other images that were linked to coexist above; the
// addresses just above a taken base are the ones most likely to be the base
// of something else, because that is where a linker put it. Scanning up
// walks into the bases other images are competing for.
//
// It is also the direction that makes the scan terminate on the image's own
// terms. Below the preferred base there is only the rest of the image's
// reservation space and then the bottom of the window, so the loop ends
// when the image no longer fits rather than when it runs out of addresses.
//
// The signature is the chooser's, and the state and attempt count are
// ignored: a deterministic scan has no state to carry and no use for the
// count, since the only thing that stops it is running out of window. They
// are in the signature because the loop calls through a pointer and a
// function that cannot answer those questions cannot be told apart from one
// that is choosing badly.
[[nodiscard]] std::uint64_t choose_base_below(
    void* state, const parser::PeImage& image, std::uint64_t failed_base,
    std::uint32_t attempts) noexcept;

// Loads the image, retrying at another base when the address space says the
// one it tried is taken.
//
// The loop stops at the first attempt that is not a placement conflict, and
// the error from that attempt is what comes back. An image that is refused
// for a reason no other base would fix -- a bad relocation, a machine this
// runtime does not execute, an import that does not resolve -- fails once
// and is reported, because trying it elsewhere would turn a refusal that
// names the problem into a refusal that names the wrong problem.
//
// The space is unchanged unless the result is ok, and that holds across the
// whole loop rather than per attempt: a caller that gets a failure from this
// function has a space it can keep using, which is the property that makes
// the retry safe to expose at all.
[[nodiscard]] LoadResult load_image_retrying(
    const parser::PeImage& image, ByteSpan bytes, std::uint64_t preferred_base,
    AddressSpace& space, const LoadContext& context, BaseRetry* report = nullptr) noexcept;

} // namespace occ::runtime

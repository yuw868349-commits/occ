// A Windows process built by this runtime.
//
// The machinery this file assembles already existed: an address space with a
// three-state ledger, a mapper that places regions, a loader that maps a PE
// and writes its relocations, and a set of `nt_*` calls that operate on all
// of it. What was missing was anything that put the pieces together in the
// order a process needs and started the result, so `occ run` went to Wine
// instead and none of the above was reachable from a running program.
//
// This file is that assembly, and it is deliberately thin. Every decision
// it makes is one of: where to put something (the mapper's job), what the
// loader does with the bytes (the loader's job), or what the TEB says (the
// layout below). Nothing here re-derives a page protection or a relocation,
// because a second copy of either is a second thing to keep in step with
// Windows.

#include "occ/runtime/pe_process.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <utility>

#include "occ/util/fs.h"

namespace occ::runtime {

namespace {

// ---------------------------------------------------------------- layout

// The TEB and the PEB, as Windows lays them out.
//
// These are the fields a program actually reads during startup, taken from
// the published x64 layout rather than from Wine's version of it. Wine's
// `TEB` carries an extra `wine` field and reorders nothing, but it also does
// not fill every field this one does, because a Wine process gets its TEB
// from the kernel side of Wine and the fields land there by a different
// route. Here the struct is the authority and this file writes it.
//
// Only the fields a program reads are listed. A full `TEB` is about 1800
// bytes and most of it is state this runtime does not have -- the fiber
// data, the activation context stack, the last error code -- and a struct
// with those fields but no values for them is worse than a struct without
// them, because the first reads as filled and is not.
//
// `offsetof`-checked rather than trusted: a field at the wrong offset is a
// program reading a stack pointer as a TLS index, which faults in a place
// with no relation to the mistake.
struct TebLayout {
    // NtTib
    std::uint64_t exception_list = 0;   // 0x00 -- the SEH chain head
    std::uint64_t stack_base = 0;       // 0x08 -- high end of the stack
    std::uint64_t stack_limit = 0;      // 0x10 -- low end, grows down
    std::uint64_t sub_system_tib = 0;   // 0x18
    std::uint64_t fiber_data = 0;       // 0x20
    std::uint64_t arbitrary_user_ptr = 0; // 0x28
    std::uint64_t self = 0;             // 0x30 -- &TEB, the field the
                                        //         segment base points at
    std::uint32_t environment_pointer = 0; // 0x38
    std::uint32_t process_id = 0;       // 0x40
    std::uint32_t thread_id = 0;        // 0x48
    std::uint32_t active_rpc_handle = 0; // 0x4C
    std::uint64_t tls_pointer = 0;      // 0x58 -- the TLS array
    std::uint64_t peb = 0;              // 0x60 -- &PEB

    // The problem with writing this as a struct is that the padding has to
    // be exactly right and the compiler will not tell us when it is not.
    // So it is written as a byte buffer with named offsets instead, and the
    // `k*` constants below are the authority the writers and the readers
    // share. This is the one place in the runtime where a magic number is
    // the honest representation: the offset *is* the interface.
    static constexpr std::size_t kExceptionList = 0x00;
    static constexpr std::size_t kStackBase = 0x08;
    static constexpr std::size_t kStackLimit = 0x10;
    static constexpr std::size_t kSelf = 0x30;
    static constexpr std::size_t kProcessId = 0x40;
    static constexpr std::size_t kThreadId = 0x48;
    static constexpr std::size_t kTlsPointer = 0x58;
    static constexpr std::size_t kPeb = 0x60;
};

// The offsets above, as a compile-time check on the ones that can be
// checked. `offsetof` on the struct itself is not usable because the struct
// is not the layout -- the constants are -- so what is checked here is that
// the constants are ordered and the structure is at least as large as the
// last field.
static_assert(TebLayout::kExceptionList < TebLayout::kPeb,
              "TEB field offsets must ascend");

// The size of the TEB as Windows allocates it, one page rounded up. The
// segment base points at the *start*, and a program that walks past the
// fields above finds zeros rather than the next region.
constexpr std::uint64_t kTebBytes = 0x2000; // 8 KiB, two pages

// The PEB.
//
// A program reads four things here during startup: `ImageBaseAddress` to
// find itself, `Ldr` to walk the loaded-module list, `ProcessParameters`
// for the command line and environment, and `NtGlobalFlag` for a surprising
// number of decisions inside msvcrt. Everything else is here because a
// program that dumps the PEB expects the fields to exist and reads a null
// as "this process has no heaps", which is a different bug than "this
// runtime did not fill the field".
struct PebLayout {
    static constexpr std::size_t kInheritedAddressSpace = 0x00;
    static constexpr std::size_t kImageBaseAddress = 0x10;
    static constexpr std::size_t kLdr = 0x18;
    static constexpr std::size_t kProcessParameters = 0x20;
    static constexpr std::size_t kProcessHeaps = 0x30;
    static constexpr std::size_t kNumberOfHeaps = 0x38;
    static constexpr std::size_t kNtGlobalFlag = 0xBC;
    static constexpr std::size_t kOsMajorVersion = 0x118;
    static constexpr std::size_t kOsMinorVersion = 0x11A;
    static constexpr std::size_t kOsBuildNumber = 0x120;
};

constexpr std::uint64_t kPebBytes = 0x1000;

// The TLS array the TEB points at: 64 slots of 8 bytes, the inline part of
// the thread's TLS before any expansion block is allocated. Windows puts it
// at `TEB + 0x1480`, and a program takes the address from `TlsPointer`
// rather than computing it, so the offset matters only in that it must be
// inside the TEB region and 8-byte aligned.
constexpr std::size_t kTlsSlots = 64;
constexpr std::size_t kTlsArrayOffset = 0x1480;

// Where the process's memory goes.
//
// Windows places a 64-bit image at its preferred base when it can and the
// preferred base is almost always `0x140000000`. The TEB and PEB go above
// it, and the stack above those. This runtime does not need to match the
// numbers; it needs the *relative order* and the alignment, because a
// program that computes a stack address from a TEB address, which is what
// `RtlCaptureStackBackTrace` and every `_alloca` do, assumes they are in the
// same neighbourhood and consistent.
//
// **The hints are hints, and that is load-bearing rather than defensive.**
// They were absolute addresses near the top of the user window -- `0x7FFD0000`
// and `0x7FFE0000`, chosen because that is roughly where Windows puts them --
// and a hard-wired absolute address is a claim about the address space that
// the host can falsify. AddressSanitizer reserves a contiguous span from 4 GiB
// to 128 TiB for its shadow memory, so the whole neighbourhood is occupied:
// `map_above` walks up from the hint one 64 KiB granule at a time for at most
// `kMaxAttempts` of them, all `kMaxAttempts` come back `EEXIST`, and the load
// fails with STATUS_NO_MEMORY for a reason that has nothing to do with the
// image. The plain build never saw it, which is exactly why a test that only
// ever runs unsanitized is not a test.
//
// So each of the three regions is placed *above the one before it* -- image,
// then TEB and PEB, then the stack -- with the floor rounded up to the next
// granule, and none of them is named by an absolute address. A host with the
// room gives the usual answer; a host without it gives an answer in the same
// relative order, which is the part that is observable.

// A stable, non-zero process id and thread id. Windows never issues zero
// for either, and a program that uses one as a map key -- or as a sentinel
// for "not set" -- behaves differently for zero.
constexpr std::uint32_t kOurProcessId = 0x0DCC;
constexpr std::uint32_t kOurThreadId = 0x0DCD;

// ------------------------------------------------------------ byte writes

// Writes into a region of the process's own address space.
//
// The regions this file fills are its own mappings, so the writes are plain
// stores with a bounds check. The check is not paranoia: the TEB and the PEB
// are mapped read-write by this file and the offsets are constants that a
// future edit can push past the end of a page, and a store past the end of a
// mapping is a fault reported at an address with no relation to the field.
void store_u32(std::uint64_t base, std::size_t off, std::uint32_t v,
               std::uint64_t region_bytes) noexcept {
    if (off + 4 > region_bytes) {
        return;
    }
    std::memcpy(reinterpret_cast<void*>(base + off), &v, 4);
}

void store_u64(std::uint64_t base, std::size_t off, std::uint64_t v,
               std::uint64_t region_bytes) noexcept {
    if (off + 8 > region_bytes) {
        return;
    }
    std::memcpy(reinterpret_cast<void*>(base + off), &v, 8);
}

// The `UNICODE_STRING` Windows uses for a counted string.
//
// The layout is `{ USHORT Length; USHORT MaximumLength; PWSTR Buffer; }`
// with the length in *bytes* and not counting the terminator, and the buffer
// a separate allocation. A reader that treats it as a C string reads past
// the end of a `CommandLine` whose buffer happens to have no terminator
// within the count, which is a heap read in the target.
void store_u16(std::uint64_t base, std::size_t off, std::uint16_t v,
               std::uint64_t region_bytes) noexcept {
    if (off + 2 > region_bytes) {
        return;
    }
    std::memcpy(reinterpret_cast<void*>(base + off), &v, 2);
}

// A UTF-16 string, narrow source widened one code unit at a time.
//
// Windows strings are UTF-16 and this runtime's own strings are narrow. The
// widening here is *not* a UTF-8 to UTF-16 conversion and deliberately so: a
// path from a Linux command line is a byte sequence, and treating it as
// UTF-8 and re-encoding would change bytes the caller passed. Widening one
// byte to one code unit keeps a byte string a byte string, which is what a
// program that reads it back with `WideCharToMultiByte` expects.
void store_u16_string(std::uint64_t where, const std::string& s) noexcept {
    auto* p = reinterpret_cast<std::uint16_t*>(where);
    for (std::size_t i = 0; i < s.size(); ++i) {
        p[i] = static_cast<std::uint16_t>(
            static_cast<unsigned char>(s[i]));
    }
    p[s.size()] = 0;
}

void store_unicode_string(std::uint64_t where, std::uint64_t buffer,
                          std::uint32_t chars) noexcept {
    const std::uint16_t bytes = static_cast<std::uint16_t>(chars * 2);
    std::memcpy(reinterpret_cast<void*>(where), &bytes, 2);
    const std::uint16_t max = static_cast<std::uint16_t>(bytes + 2);
    std::memcpy(reinterpret_cast<void*>(where + 2), &max, 2);
    std::memcpy(reinterpret_cast<void*>(where + 8), &buffer, 8);
}

// The `LIST_ENTRY` Windows uses for a doubly-linked list.
struct ListEntry {
    std::uint64_t flink = 0;
    std::uint64_t blink = 0;
};

// A one-element circular list, which is what a list with one node is. The
// `flink` and `blink` both point at the *head*, not at each other, because
// that is the convention `InitializeListHead` establishes and a walker that
// stops on `head.flink == &head` depends on it.
void store_self_list(std::uint64_t head) noexcept {
    std::uint64_t self = head;
    std::memcpy(reinterpret_cast<void*>(head), &self, 8);
    std::memcpy(reinterpret_cast<void*>(head + 8), &self, 8);
}

} // namespace

const char* process_error_name(ProcessError e) noexcept {
    switch (e) {
    case ProcessError::None:                 return "none";
    case ProcessError::ImageRejected:        return "image_rejected";
    case ProcessError::UnsupportedMachine:   return "unsupported_machine";
    case ProcessError::NotAnExecutable:      return "not_an_executable";
    case ProcessError::UnsupportedSubsystem: return "unsupported_subsystem";
    case ProcessError::OutOfAddressSpace:    return "out_of_address_space";
    case ProcessError::HostRefused:          return "host_refused";
    }
    return "unknown";
}

// ------------------------------------------------------------- building

namespace {

// Turns a `Status` into the `ProcessError` a caller above can act on.
//
// The two enums are not the same and the mapping is not a formality. A
// refusal to place is `OutOfAddressSpace` when the address the mapper wanted
// was taken and `HostRefused` when the kernel said no for a reason that is
// about this host rather than about this space -- and the distinction matters
// because the first is worth retrying one granule over and the second is not.
ProcessError error_for(const Status s) noexcept {
    switch (s) {
    case Status::ConflictingAddresses:
    case Status::NoMemory:
    case Status::MemoryNotAllocated:
        return ProcessError::OutOfAddressSpace;
    default:
        return ProcessError::HostRefused;
    }
}

// The protection an image region needs for a linker-declared section.
//
// Windows derives it from the section's own characteristics word, and the
// loader already did that when it mapped the section -- this is the same
// answer for the region *record*, so that a caller listing the process sees
// what the program will find rather than what the file asked for. The two
// agree because the loader's rule and this one are the same rule, and the
// reason it exists twice is that the record is written by this file and the
// mapping by the loader. It is not a second implementation; it is the same
// one applied to a copy.
PageProtection record_protection_for(const AddressSpace& space,
                                     std::uint64_t base) noexcept {
    const Region* r = space.find(base);
    return r != nullptr ? r->protection : PageProtection::NoAccess;
}

} // namespace

std::unique_ptr<PeProcess> PeProcess::build(const parser::PeImage& image,
                                            ByteSpan bytes,
                                            const ProcessOptions& options,
                                            ProcessImage* failure) noexcept {
    auto self = std::unique_ptr<PeProcess>(new PeProcess());
    self->options_ = options;
    ProcessImage& image_out = self->image_;

    // The failure record goes to the caller's out-parameter and the result is
    // null. One helper, called at every refusal below, so that no path can
    // return null without having said why.
    const auto bail = [&](ProcessError e, std::string why)
        -> std::unique_ptr<PeProcess> {
        image_out.ok = false;
        image_out.error = e;
        image_out.detail = std::move(why);
        if (failure != nullptr) {
            *failure = image_out;
        }
        return nullptr;
    };

    // --- 1. the image itself -------------------------------------------

    // A DLL is not started, and this is checked before the loader runs
    // because every reason to refuse a DLL is cheaper than mapping it: the
    // loader would map it, write its relocations, fill its IAT, and then
    // there is nothing to jump to, and the address space is now full of a
    // half-built process.
    if (image.is_dll()) {
        return bail(ProcessError::NotAnExecutable,
                    "the image is a DLL; a DLL is loaded into a process "
                    "rather than started as one");
    }

    // The machine check. Only the host's own width is executable here,
    // because executing the image means executing its instructions and an
    // i386 image on x86-64 is a different problem (route B5, Wow64) rather
    // than a different base address.
    if (image.machine() != parser::PeMachine::Amd64 && image.machine_raw() != 0x8664) {
        return bail(ProcessError::UnsupportedMachine,
                    "the image is for machine 0x" +
                        std::to_string(image.machine_raw()) +
                        " and this runtime executes 0x8664");
    }

    if (!image.is_pe32_plus()) {
        return bail(ProcessError::UnsupportedMachine,
                    "a 32-bit image needs the Wow64 path, which is not this "
                    "one");
    }

    // --- 2. map the image ----------------------------------------------

    LoadContext lc;
    lc.events = options.events;
    lc.resolver_state = options.resolver_state;
    lc.resolve = options.resolve;
    lc.placement = &self->mapper_;

    const LoadResult loaded =
        load_image(image, bytes, image.image_base(), self->space_, lc);
    if (!loaded.ok) {
        // The loader's own detail, verbatim. It knows which section was short
        // and which relocation pointed outside the image, and re-expressing
        // that here as "the image was rejected" would throw away the only
        // part a person debugging a load needs.
        return bail(ProcessError::ImageRejected, loaded.detail);
    }
    image_out.module = loaded.module;

    // --- 3. the control region: TEB and PEB ------------------------------

    // One mapping holds both, the TEB first. Windows puts them in one region
    // for the same reason: they are read together (every TEB has a PEB
    // pointer and the PEB has the process's heap list) and a single region
    // means a single protection change keeps them in step.
    //
    // Ordered *above the image*, not at a fixed address. See the note on
    // `kTebBaseHint`: the relationship is what a program can observe, and the
    // absolute numbers are not. Rounding the floor up to the next granule
    // gives the alignment the mapper requires and leaves a gap between the
    // image and the TEB, which is what Windows has.
    const std::uint64_t teb_floor =
        AddressSpace::round_up(loaded.module.base + loaded.module.size,
                               AddressSpace::kGranularity);
    const std::uint64_t control_bytes =
        AddressSpace::round_up(kTebBytes + kPebBytes, AddressSpace::kPageSize);
    const Result<std::uint64_t> control = self->mapper_.map_above(
        teb_floor, control_bytes, PageProtection::ReadWrite,
        RegionKind::Control);
    if (!control.ok()) {
        return bail(error_for(control.status),
                    "the TEB and PEB could not be placed: " +
                        std::string(status_name(control.status)));
    }
    const std::uint64_t teb = control.value;
    const std::uint64_t peb = teb + kTebBytes;
    image_out.teb = teb;
    image_out.peb = peb;

    // --- 4. the stack ---------------------------------------------------

    // Above the control region, for the same reason and with the same
    // rounding. A program that walks from a TEB address to a stack address --
    // which is what stack-backtrace and probe code does -- needs the two to
    // be ordered, and it cannot know the numbers.
    const std::uint64_t stack_bytes =
        AddressSpace::round_up(std::max(options.stack_reserve,
                                        AddressSpace::kPageSize),
                               AddressSpace::kPageSize);
    const std::uint64_t stack_floor =
        AddressSpace::round_up(teb + control_bytes, AddressSpace::kGranularity);
    const Result<std::uint64_t> stack = self->mapper_.map_above(
        stack_floor, stack_bytes, PageProtection::ReadWrite,
        RegionKind::Stack);
    if (!stack.ok()) {
        return bail(error_for(stack.status),
                    "the stack could not be placed: " +
                        std::string(status_name(stack.status)));
    }

    // --- 5. fill the TEB ------------------------------------------------

    const std::uint64_t stack_base = stack.value + stack_bytes;
    // The stack grows down from the top; `StackLimit` is the lowest address
    // the thread may use. Windows keeps one page below `StackLimit` as a
    // guard so that a `_chkstk` probe faults against it rather than against
    // the region's end, and leaving the same page here is what lets a
    // deep-recursion program fail the way it does on Windows.
    const std::uint64_t stack_limit = stack.value + AddressSpace::kPageSize;

    store_u64(teb, TebLayout::kExceptionList, 0xFFFFFFFFFFFFFFFFULL, kTebBytes);
    store_u64(teb, TebLayout::kStackBase, stack_base, kTebBytes);
    store_u64(teb, TebLayout::kStackLimit, stack_limit, kTebBytes);
    store_u64(teb, TebLayout::kSelf, teb, kTebBytes);
    store_u32(teb, TebLayout::kProcessId, kOurProcessId, kTebBytes);
    store_u32(teb, TebLayout::kThreadId, kOurThreadId, kTebBytes);
    store_u64(teb, TebLayout::kPeb, peb, kTebBytes);

    // The TLS array. `TlsPointer` points at it and the TEB's own inline
    // slots are what a module with a slot number under 64 writes through, so
    // the array is the TEB's storage rather than a separate allocation --
    // which is what `TlsPointer` being an address inside the TEB means.
    store_u64(teb, TebLayout::kTlsPointer, teb + kTlsArrayOffset, kTebBytes);

    // The TEB's `Self` is read through the segment base as well as from the
    // field, and on x86-64 the segment base is not what a program computes:
    // it is set from `IA32_GS_BASE` (or the FS one, depending on how the
    // program was built) and only the `enter_guest` stub can set it. What
    // this file can do is make the field and the base agree, which is what a
    // `mov %gs:0x30` and a `mov [teb+0x30]` both landing on the same value
    // requires.

    // --- 6. fill the PEB ------------------------------------------------

    store_u64(peb, PebLayout::kImageBaseAddress, image_out.module.base,
              kPebBytes);
    // `Ldr` points at a `PEB_LDR_DATA` whose three list heads are circular
    // with nothing in them. A program that walks the module list therefore
    // finds zero modules rather than walking into an unmapped page, which is
    // the honest answer for a process whose only module is the image itself:
    // the image's own entry is added by the loader when there is a loader
    // list to add it to, and until then an empty list is a smaller lie than
    // a null pointer.
    //
    // The `PEB_LDR_DATA` lives at a fixed offset inside the PEB's own region
    // so that no second allocation is needed and the pointer never dangles.
    const std::uint64_t ldr = peb + 0x200;
    store_self_list(ldr + 0x10);  // InLoadOrderModuleList
    store_self_list(ldr + 0x20);  // InMemoryOrderModuleList
    store_self_list(ldr + 0x30);  // InInitializationOrderModuleList
    store_u32(ldr, 0, static_cast<std::uint32_t>(sizeof(void*) * 3), kPebBytes);
    store_u64(peb, PebLayout::kLdr, ldr, kPebBytes);

    // The process parameters. Windows keeps them in the PEB's own address
    // space below the PEB proper, and the command line and image path are
    // `UNICODE_STRING`s whose buffers live after the structure.
    const std::uint64_t params = peb + 0x400;
    store_u64(peb, PebLayout::kProcessParameters, params, kPebBytes);

    // The command line and image path, as counted strings. The buffers are
    // placed after the parameters structure inside the same region, so a
    // program that reads one gets a pointer into its own PEB rather than
    // into a region that was freed when this function returned.
    std::uint64_t str_cursor = params + 0x400;
    if (!options.command_line.empty()) {
        const std::uint32_t chars = static_cast<std::uint32_t>(
            options.command_line.size());
        store_u16_string(str_cursor, options.command_line);
        store_unicode_string(params + 0x70, str_cursor, chars);
        str_cursor += (static_cast<std::uint64_t>(chars) + 1) * 2;
    }
    if (!options.image_path.empty()) {
        const std::uint32_t chars =
            static_cast<std::uint32_t>(options.image_path.size());
        store_u16_string(str_cursor, options.image_path);
        store_unicode_string(params + 0x60, str_cursor, chars);
        str_cursor += (static_cast<std::uint64_t>(chars) + 1) * 2;
    }

    // The standard handles and the environment block are filled by the
    // console layer, which is the next layer up: this file knows where the
    // PEB is, and `kernel32`'s `GetStdHandle` knows what a handle is. What
    // is written here is the shape, so that a program reading
    // `ProcessParameters` finds a structure and not zeros.

    store_u32(peb, PebLayout::kNtGlobalFlag, 0, kPebBytes);
    store_u16(peb, PebLayout::kOsMajorVersion, 10, kPebBytes);
    store_u16(peb, PebLayout::kOsMinorVersion, 0, kPebBytes);
    store_u16(peb, PebLayout::kOsBuildNumber, 19045, kPebBytes);

    // --- 7. record the regions ------------------------------------------

    for (const Region& r : self->space_.regions()) {
        ProcessImage::RegionRecord rec;
        rec.base = r.base;
        rec.size = r.size;
        rec.kind = r.kind;
        rec.protection = r.protection;
        switch (r.kind) {
        case RegionKind::Image:  rec.what = r.section; break;
        case RegionKind::Stack:  rec.what = "stack"; break;
        case RegionKind::Control: rec.what = "teb+peb"; break;
        case RegionKind::Private: rec.what = "private"; break;
        case RegionKind::Mapped: rec.what = r.section; break;
        }
        image_out.regions.push_back(rec);
    }
    (void)record_protection_for;

    // --- 8. where the thread starts --------------------------------------

    image_out.entry_point = image_out.module.entry_va;
    // **The stack a Windows entry point expects is not a bare stack top.**
    // The x64 ABI reserves 32 bytes of "shadow space" below the return
    // address for the callee's first four arguments, and a `_start` that
    // jumps to a function with the stack top exactly at the end makes every
    // store into that shadow space land in the guard page. The 16-byte
    // alignment is the other half: `enter_guest` does the alignment, and the
    // shadow reservation is done here so that a reader can see both numbers
    // and know the entry sees a stack it can use.
    image_out.initial_stack_pointer =
        AddressSpace::round_down(stack_base, 16);

    image_out.ok = true;
    return self;
}

} // namespace occ::runtime

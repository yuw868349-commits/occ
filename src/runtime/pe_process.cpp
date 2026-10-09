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
#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>

#include <setjmp.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>
#include <unistd.h>

#include "occ/util/fs.h"
#include "occ/runtime/seh.h"

#include <sys/sysinfo.h>

#include <chrono>
#include <thread>
#include "occ/runtime/guest_module.h"
#include "occ/runtime/seh.h"

#include <sys/sysinfo.h>

#include <chrono>
#include <thread>
#include "occ/runtime/winabi.h"

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

// The array has to land inside the region the segment base points at. A
// slot count that outgrew the TEB would put the last slots past its end,
// where the mapping above begins, and a guest that wrote one would be
// writing into a region this file placed for something else. The two
// numbers are independent constants, so the relationship is asserted rather
// than trusted.
static_assert(kTlsArrayOffset + kTlsSlots * sizeof(std::uint64_t) <=
                  kTebBytes,
              "the TLS array must fit inside the TEB");
static_assert(kTlsArrayOffset % alignof(std::uint64_t) == 0,
              "the TLS array must be aligned for the slots it holds");

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
//
// The helpers are not inlined on purpose. With the callers' constant offsets
// folded in, GCC's store-overflow analysis concludes that the destination
// object -- an address computed from an integer, so an object of no known
// size -- must be empty, and reports the guarded store against it. The bound
// is checked here, where it is, and noinline keeps that decision in this
// function instead of in an analysis that cannot see it.
__attribute__((noinline)) void store_u32(std::uint64_t base, std::size_t off,
                                         std::uint32_t v,
                                         std::uint64_t region_bytes) noexcept {
    if (off + 4 > region_bytes) {
        return;
    }
    std::memcpy(reinterpret_cast<void*>(base + off), &v, 4);
}

__attribute__((noinline)) void store_u64(std::uint64_t base, std::size_t off,
                                         std::uint64_t v,
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
// A single byte, with the same bounds check the wider stores make. The PEB
// has byte-sized fields, and they are written for the same reason the wider
// ones are: the region arrives zeroed, and a run that wrote nothing would be
// relying on that rather than stating what the field holds.
void store_u8(std::uint64_t base, std::size_t off, std::uint8_t v,
              std::uint64_t region_bytes) noexcept {
    if (off + 1 > region_bytes) {
        return;
    }
    std::memcpy(reinterpret_cast<void*>(base + off), &v, 1);
}

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

    // The retrying spelling, not the plain one.
    //
    // An image whose preferred base is occupied still has to run -- this is
    // the case the relocation pass exists for, and an image that carries a
    // relocation table can be placed anywhere in the window. The plain load
    // hands the conflict back to its caller, which is the right answer for
    // a caller that named a base and the wrong one for a caller that named
    // an image; this is the second kind. The base passed here is zero, so
    // the loader starts at the image's own and steps down a granule at a
    // time while it is taken.
    //
    // The retry is consulted rather than ignored: when a placement took
    // more than one attempt, the bases that did not work are part of what a
    // person diagnosing the load wants to see.
    BaseRetry retry{};
    const LoadResult loaded =
        load_image_retrying(image, bytes, 0, self->space_, lc, &retry);
    if (!loaded.ok) {
        // The loader's own detail, verbatim. It knows which section was short
        // and which relocation pointed outside the image, and re-expressing
        // that here as "the image was rejected" would throw away the only
        // part a person debugging a load needs.
        return bail(ProcessError::ImageRejected, loaded.detail);
    }
    image_out.module = loaded.module;

    // --- 2b. the KUSER_SHARED_DATA page ----------------------------------
    //
    // Windows maps one page of the kernel's data into every process at a
    // fixed address, and programs read it as *memory*, not as a call: the
    // tick count, the interrupt time and the system time are fields a
    // compiled program loads directly -- Go's runtime opens with `mov
    // eax, [0x7ffe0008]` for its clock -- and a runtime that leaves the
    // page unmapped faults a program whose only fault was reading its
    // clock the way Windows taught it.
    //
    // The values a reader wants moving. A dedicated thread advances the
    // interrupt time on the host's clock and keeps the system time beside
    // it, which is what the kernel's own tick does; the granularity is
    // finer than the tick Windows halves at 15.6 ms, and a finer clock is
    // the kind of difference a caller measures as good news.
    {
        constexpr std::uint64_t kSharedData = 0x7FFE0000ULL;
        constexpr std::uint64_t kSharedDataBytes = 0x1000;
        const Result<std::uint64_t> shared = self->mapper_.map(
            kSharedData, kSharedDataBytes, PageProtection::ReadWrite,
            RegionKind::Control);
        if (!shared.ok()) {
            return bail(error_for(shared.status),
                        "the KUSER_SHARED_DATA page could not be placed: " +
                            std::string(status_name(shared.status)));
        }
        auto* page = reinterpret_cast<std::uint8_t*>(shared.value);

        // The fields a reader wants at the offsets Windows spells. The
        // times are `KSYSTEM_TIME` triplets -- low, high, high again --
        // whose second copy is what makes a reader's two loads consistent
        // against a tick that lands between them.
        constexpr std::size_t kInterruptTime = 0x008;
        constexpr std::size_t kSystemTime = 0x014;
        [[maybe_unused]] constexpr std::size_t kTimeZoneBias = 0x020;
        constexpr std::size_t kNtBuildNumber = 0x258;
        constexpr std::size_t kNtProductType = 0x25C;
        constexpr std::size_t kProductTypeIsValid = 0x260;
        constexpr std::size_t kNativeProcessorArchitecture = 0x268;
        constexpr std::size_t kSuiteMask = 0x2C8;
        constexpr std::size_t kKdDebuggerEnabled = 0x2CC;
        constexpr std::size_t kNumberOfPhysicalPages = 0x2E0;
        constexpr std::size_t kTickCount = 0x320;

        const auto put32 = [page](std::size_t off, std::uint32_t v) {
            std::memcpy(page + off, &v, 4);
        };

        // The build and the product, which a program reads once to know
        // what it is talking to. The suite mask names Terminal Server and
        // the single-user terminal services, which is what a plain
        // workstation reports.
        put32(kNtBuildNumber, 19045);
        put32(kNtProductType, 1);          // WinNT
        put32(kProductTypeIsValid, 1);
        put32(kNativeProcessorArchitecture, 9);  // PROCESSOR_ARCHITECTURE_AMD64
        put32(kSuiteMask, 0x0110);
        put32(kKdDebuggerEnabled, 0);

        struct ::sysinfo host_info;
        ::sysinfo(&host_info);
        put32(kNumberOfPhysicalPages,
              static_cast<std::uint32_t>(host_info.totalram));

        // The advancing times. The thread owns the page; a reader is a
        // load of the fields the thread writes, and the triplet's repeated
        // high half is what tells a reader whether its two loads straddled
        // an update.
        const auto write_system_time = [page](std::uint64_t hundreds) {
            // `hundreds` is the count of 100-nanosecond units since the
            // 1601 epoch, as FILETIME spells time.
            const std::uint32_t low = static_cast<std::uint32_t>(hundreds);
            const std::uint32_t high =
                static_cast<std::uint32_t>(hundreds >> 32);
            // The bias stays zero: this runtime reports UTC everywhere, so
            // the system time needs no offset subtracted.
            std::memcpy(page + kSystemTime, &low, 4);
            std::memcpy(page + kSystemTime + 4, &high, 4);
            std::memcpy(page + kSystemTime + 8, &high, 4);
        };
        // Boot-relative interrupt time and wall-clock system time, both
        // in the same units, written together so a reader of either sees
        // a consistent pair.
        const auto tick = []() -> std::uint64_t {
            struct ::timespec now;
            ::clock_gettime(CLOCK_REALTIME, &now);
            constexpr std::int64_t kEpochOffset = 11644473600;
            return (static_cast<std::uint64_t>(now.tv_sec) +
                    static_cast<std::uint64_t>(kEpochOffset)) *
                       10000000ULL +
                   static_cast<std::uint64_t>(now.tv_nsec) / 100ULL;
        };
        write_system_time(tick());
        const auto write_interrupt = [page](std::uint64_t hundreds) {
            const std::uint32_t low = static_cast<std::uint32_t>(hundreds);
            const std::uint32_t high =
                static_cast<std::uint32_t>(hundreds >> 32);
            std::memcpy(page + kInterruptTime, &low, 4);
            std::memcpy(page + kInterruptTime + 4, &high, 4);
            std::memcpy(page + kInterruptTime + 8, &high, 4);
            std::memcpy(page + kTickCount, &low, 4);
            std::memcpy(page + kTickCount + 4, &high, 4);
            std::memcpy(page + kTickCount + 8, &high, 4);
        };
        // The updater runs detached for the life of the process, which is
        // the life the page has: the page dies with the process and the
        // thread's last write dies with it.
        std::thread([write_interrupt, write_system_time, tick]() {
            std::uint64_t elapsed = 0;
            std::uint64_t last_real = tick();
            for (;;) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                const std::uint64_t now = tick();
                elapsed += now - last_real;
                last_real = now;
                write_interrupt(elapsed);
                write_system_time(now);
            }
        }).detach();
    }

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
    // `Ldr` points at a `PEB_LDR_DATA` whose three lists carry every
    // module this process can name: the image itself, then the API
    // modules, each with an image in the guest's own address space whose
    // headers parse and whose export table answers a hand-rolled walk.
    // The builder of the list is the guest-module layer, which owns the
    // image shapes; this call hands it the PEB and the placements' ground.
    // An install that failed leaves the empty circular lists -- the state
    // the code below writes first -- because a list naming images that
    // are not there is a walk that faults on the second hop, and the
    // caller of the run reports the failure through its own channel.
    const std::uint64_t ldr = peb + 0x200;
    store_self_list(ldr + 0x10);  // InLoadOrderModuleList
    store_self_list(ldr + 0x20);  // InMemoryOrderModuleList
    store_self_list(ldr + 0x30);  // InInitializationOrderModuleList
    store_u32(ldr, 0, static_cast<std::uint32_t>(sizeof(void*) * 3), kPebBytes);
    store_u64(peb, PebLayout::kLdr, ldr, kPebBytes);

    {
        guest_module::InstallRequest request;
        request.space = &self->space_;
        request.mapper = &self->mapper_;
        request.peb = peb;
        request.image_base = image_out.module.base;
        request.image_size = image_out.module.size;
        request.image_name =
            options.image_path.empty() ? "image.exe" : options.image_path;
        for (const guest_module::ModuleInput& module :
             winabi::guest_module_inputs()) {
            request.modules.push_back(module);
        }
        static_cast<void>(guest_module::install(request));
    }

    // The process parameters. Windows keeps them in the PEB's own address
    // space below the PEB proper, and the command line and image path are
    // `UNICODE_STRING`s whose buffers live after the structure.
    const std::uint64_t params = peb + 0x400;
    store_u64(peb, PebLayout::kProcessParameters, params, kPebBytes);

    // The parameter block's own header. The flags a live Windows process
    // carries are 0x6001 -- the compatibility bits and the reserved low
    // word -- and *not* the normalized bit: a block built in place, as
    // this one is, has no RVAs left to normalize away, and the programs
    // that read the flag read it to decide which parameter-copying path
    // their obfuscated loaders take.
    const std::uint32_t params_length = 0x400;
    constexpr std::uint32_t params_flags = 0x6001u;
    store_u32(params, 0x00, params_length, kPebBytes);   // MaximumLength
    store_u32(params, 0x04, params_length - 0x10, kPebBytes);  // Length
    store_u32(params, 0x08, params_flags, kPebBytes);    // Flags

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

    // The two fields a program reads to find the process's heaps, written as
    // a pair because that is how they are read. `ProcessHeaps` points at an
    // array of handles inside the PEB's own region -- handles, not
    // addresses, which is what Windows stores and what `GetProcessHeap`
    // answers with -- and `NumberOfHeaps` is its length. Leaving the pointer
    // null would not mean "no list here": a program that enumerates the
    // heaps reads null as "this process has no heaps", which is a statement
    // about the process rather than about where the runtime put the array.
    //
    // The run supplies the list, because the handles belong to the layer
    // that implements the heap functions. An empty list is a real answer
    // and leaves the field null, so a caller that wants the field filled
    // says so by naming the heaps.
    if (!options.process_heaps.empty()) {
        const std::uint64_t heaps = peb + 0x300;
        for (std::size_t i = 0; i < options.process_heaps.size(); ++i) {
            store_u64(heaps, i * sizeof(std::uint64_t),
                      options.process_heaps[i], kPebBytes);
        }
        store_u64(peb, PebLayout::kProcessHeaps, heaps, kPebBytes);
        store_u32(peb, PebLayout::kNumberOfHeaps,
                  static_cast<std::uint32_t>(options.process_heaps.size()),
                  kPebBytes);
    }

    // `InheritedAddressSpace` is FALSE: this process was not handed the
    // parent's address space, which is what every process the loader starts
    // for itself reports.
    store_u8(peb, PebLayout::kInheritedAddressSpace, 0, kPebBytes);

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

    // The exception directory, as the loaded image holds it. The section is
    // named `.pdata` by every x64 linker that emits one, and the table's
    // bytes are the file's own -- the RUNTIME_FUNCTIONs live in raw data,
    // so the table's length is the smaller of what the section declares
    // and what the file carries. `.xdata` is recorded the same way: it is
    // where the rows' `unwind_rva` values point, and the walk needs its
    // extent to tell a row that names unwind data from one that names
    // whatever byte happens to follow the section in this address space.
    for (const parser::PeSection& section : image.sections()) {
        if (section.name == ".pdata") {
            image_out.pdata_va =
                image_out.module.base + section.virtual_address;
            image_out.pdata_bytes =
                static_cast<std::uint64_t>(section.virtual_size <
                                                   section.raw_size
                                               ? section.virtual_size
                                               : section.raw_size);
        } else if (section.name == ".xdata") {
            image_out.xdata_va =
                image_out.module.base + section.virtual_address;
            image_out.xdata_bytes =
                static_cast<std::uint64_t>(section.virtual_size <
                                                   section.raw_size
                                               ? section.virtual_size
                                               : section.raw_size);
        }
    }

    // The image's own exports, at absolute addresses, for `GetProcAddress`
    // on the image's module. The parser has already walked the directory and
    // named the forwarders; this is the same walk, once, at the width the
    // process will answer from. An export whose RVA is zero is the empty
    // slot the format keeps, not an export at address zero.
    for (const parser::PeExport& entry : image.exports()) {
        if (entry.rva == 0) {
            continue;
        }
        ProcessImage::ExportRecord record;
        record.name = entry.name;
        record.ordinal = entry.ordinal;
        record.address = image_out.module.base + entry.rva;
        record.is_forwarder = entry.is_forwarder;
        record.forwarder_text = image_out.module.base + entry.rva;
        image_out.own_exports.push_back(std::move(record));
    }

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

// --------------------------------------------------------------------------
// Running the guest
// --------------------------------------------------------------------------

// Everything above builds a process; this section is the part that runs one,
// and it is the only place in the runtime where control passes from host code
// to guest code and back. The round trip has three legs:
//
//   1. `enter_guest` sets the segment base to the guest's TEB, switches to
//      the stack the builder prepared, and calls the entry point. The call
//      is the whole of the handoff -- the guest is native x86 code in this
//      address space, and there is nothing to "emulate".
//
//   2. The guest runs. Every API it imports is a thunk compiled `ms_abi`,
//      so its calls arrive as ordinary host calls on the guest's stack; the
//      thunks read the `GuestState` through the thread-local pointer and
//      answer. `ExitProcess`, `TerminateProcess`, `exit` and `abort` end by
//      calling the terminate path this section installed, which is a
//      `siglongjmp` -- not because anything failed, but because the guest's
//      exit is an unwind past frames that own no C++ objects: the CRT
//      startup, the thunks, the entry. A `longjmp` is exactly the right tool
//      for an unwind of code nobody wrote in this language.
//
//   3. A fault is a signal. The guest is native code, so its null
//      dereference is a real SIGSEGV, and the handler's job is to make the
//      fault look the way Windows makes faults look: an EXCEPTION_RECORD and
//      a CONTEXT on the stack of the filter the guest registered with
//      `SetUnhandledExceptionFilter`, and the filter's verdict honored. A
//      filter that declines, or none at all, dies by the signal -- which is
//      what the same program does under a Unix loader, and what a Windows
//      program does under a debugger-less loader too, once the last filter
//      has declined.
//
// The section is deliberately the only place that knows both layouts: the
// CONTEXT below is the Windows x64 shape, and the `ucontext_t` above it is
// the kernel's. The conversion between them is byte-offset arithmetic, and
// it is written as named constants because this is the one interface where
// the offsets themselves are the contract.

namespace {

// `arch_prctl` operations. The header that names them (`asm/prctl.h`) is a
// kernel header no portable program includes, and the numbers have not moved
// since they were introduced, so they are defined here with the values the
// kernel UAPI documents.
constexpr unsigned long kArchSetGs = 0x1001;
constexpr unsigned long kArchGetGs = 0x1004;

// ---------------------------------------------------------------- context

// The Windows x64 CONTEXT, as offsets into a 1232-byte buffer. The offsets
// are the seh layer's own constants, imported rather than repeated: the
// raise-and-unwind path reads the buffers this file builds, and one copy
// of the layout is the only thing keeping the two in step.
using occ::runtime::seh::kContextAmd64;
using occ::runtime::seh::kContextEFlags;
using occ::runtime::seh::kContextFlags;
using occ::runtime::seh::kContextFltSave;
using occ::runtime::seh::kContextFull;
using occ::runtime::seh::kContextMxCsr;
using occ::runtime::seh::kContextR10;
using occ::runtime::seh::kContextR11;
using occ::runtime::seh::kContextR12;
using occ::runtime::seh::kContextR13;
using occ::runtime::seh::kContextR14;
using occ::runtime::seh::kContextR15;
using occ::runtime::seh::kContextR8;
using occ::runtime::seh::kContextR9;
using occ::runtime::seh::kContextRax;
using occ::runtime::seh::kContextRbp;
using occ::runtime::seh::kContextRbx;
using occ::runtime::seh::kContextRcx;
using occ::runtime::seh::kContextRdi;
using occ::runtime::seh::kContextRdx;
using occ::runtime::seh::kContextRip;
using occ::runtime::seh::kContextRsi;
using occ::runtime::seh::kContextRsp;
using occ::runtime::seh::kContextSegCs;
using occ::runtime::seh::kContextSegDs;
using occ::runtime::seh::kContextSegEs;
using occ::runtime::seh::kContextSegFs;
using occ::runtime::seh::kContextSegGs;
using occ::runtime::seh::kContextSegSs;
using occ::runtime::seh::kContextSize;

// The floating-point save area's two layouts are the seh layer's constants,
// imported where they are used below: the CONTEXT is seh's structure, and a
// second copy of its layout here is the thing that goes stale.

constexpr std::uint32_t kMxCsrReset = 0x1F80u;  // all exceptions masked

// ------------------------------------------------------------ exceptions

// The NTSTATUS codes a fault maps to, and the record the filter reads.
constexpr std::uint32_t kStatusAccessViolation = 0xC0000005u;
constexpr std::uint32_t kStatusInPageError = 0xC0000006u;
constexpr std::uint32_t kStatusIllegalInstruction = 0xC000001Du;
constexpr std::uint32_t kStatusBreakpoint = 0x80000003u;
constexpr std::uint32_t kStatusSingleStep = 0x80000004u;
constexpr std::uint32_t kStatusFloatDivideByZero = 0xC000008Eu;
constexpr std::uint32_t kStatusFloatInexactResult = 0xC000008Fu;
constexpr std::uint32_t kStatusFloatInvalidOperation = 0xC0000090u;
constexpr std::uint32_t kStatusFloatOverflow = 0xC0000091u;
constexpr std::uint32_t kStatusFloatUnderflow = 0xC0000093u;
constexpr std::uint32_t kStatusIntegerDivideByZero = 0xC0000094u;
constexpr std::uint32_t kStatusIntegerOverflow = 0xC0000095u;
constexpr std::uint32_t kStatusPrivilegedInstruction = 0xC0000096u;
constexpr std::uint32_t kStatusStackOverflow = 0xC00000FDu;

constexpr std::uint32_t kExceptionNoncontinuable = 0x1u;
constexpr std::int32_t kExecuteHandler = 1;  // EXCEPTION_EXECUTE_HANDLER
constexpr std::uint64_t kExceptionInfoAccess = 0;  // read
constexpr std::uint64_t kExceptionInfoWrite = 1;
constexpr std::uint64_t kExceptionInfoExecute = 8;  // DEP

// The guest's EXCEPTION_RECORD. Field for field the Windows shape; the
// `static_assert`s are the proof, the way the TEB layout above is proven.
struct GuestExceptionRecord {
    std::uint32_t code = 0;
    std::uint32_t flags = 0;
    std::uint64_t inner = 0;  // nested ExceptionRecord*, none here
    std::uint64_t address = 0;
    std::uint32_t parameters = 0;
    std::uint32_t reserved = 0;
    std::uint64_t information[15] = {};
};
static_assert(sizeof(GuestExceptionRecord) == 152,
              "EXCEPTION_RECORD layout drifted");

// The guest's EXCEPTION_POINTERS: the pair the filter receives.
struct GuestExceptionPointers {
    const GuestExceptionRecord* record = nullptr;
    const void* context = nullptr;
};
static_assert(sizeof(GuestExceptionPointers) == 16,
              "EXCEPTION_POINTERS layout drifted");

// The filter is guest code: Microsoft ABI, called by address.
using UnhandledFilterFn = std::int32_t (__attribute__((ms_abi))*)(
    const GuestExceptionPointers* pointers);

// --------------------------------------------------------- the run frame

// What the fault handler needs to reach, carried beside the `GuestState`
// because the handler cannot take parameters. All thread-local for the same
// reason the state pointer is: the guest runs on one thread.
struct RunFrame {
    winabi::GuestState* state = nullptr;
    // The stack region the builder placed, low end first. A fault below the
    // low end is the stack overflow Windows names STATUS_STACK_OVERFLOW --
    // a distinct code with distinct meaning, and free to detect once the
    // region is known.
    std::uint64_t stack_low = 0;
    std::uint64_t stack_high = 0;
};
thread_local RunFrame g_run_frame;

// Where the exit longjmp lands, and the code it carries. The buffer lives
// here rather than on `run_pe_process`'s frame because the terminate path
// has no parameter to carry it in; the code travels beside it because
// `siglongjmp` treats a zero as a one, and exit code zero is the single most
// common code a correct program produces.
thread_local ::sigjmp_buf g_host_return;
thread_local volatile std::uint32_t g_guest_exit_code = 0;

// The exit path the thunks reach through `winabi::terminate`. The flush is
// the callers' duty -- `ExitProcess` and `exit` flush before they get here,
// and the fault handler flushes before it does -- so this is the jump and
// nothing else.
void guest_terminate(std::uint32_t code) noexcept {
    g_guest_exit_code = code;
    ::siglongjmp(g_host_return, 1);
}

// ------------------------------------------------------------------- jump

// The handoff. Eight instructions, none of them optional:
//
//   `mov`    -- the stack the builder placed, which is 16-byte aligned and
//               has the entry's shadow space subtracted first, because a
//               Windows caller reserves those 32 bytes *below* its own frame
//               and the callee writes them before it touches anything else;
//   `sub`    -- the shadow space itself;
//   `xor`    -- the frame pointer Windows' startup expects to start clean;
//   `call`   -- the entry point, which pushes this stub's own address as the
//               return address: an entry that returns lands on `ud2` and
//               faults the honest way, since no Windows entry returns;
//   `ud2`    -- the fence.
//
// The call destroys every caller-saved register and the guest destroys the
// callee-saved ones besides; that is why the return leg is a `siglongjmp`,
// which restores the register set `sigsetjmp` saved. Control "returns" from
// this function only through that jump, never through the epilogue.
void enter_guest_asm(std::uint64_t entry, std::uint64_t stack_top) noexcept {
    __asm__ volatile("movq %1, %%rsp\n\t"
                     "subq $32, %%rsp\n\t"
                     "xorl %%ebp, %%ebp\n\t"
                     "call *%0\n\t"
                     "ud2\n\t"
                     :
                     : "r"(entry), "r"(stack_top)
                     : "memory");
}

// ------------------------------------------------------------------ bytes

// The field writers the CONTEXT builder uses. `memcpy` into a byte buffer
// because the buffer is unaligned by design -- it is laid out the way
// Windows lays out memory, not the way C structures align.
//
// There is no reader here and no byte-wide writer: the floating-point half
// of the CONTEXT is filled by the seh layer, which owns both save-area
// layouts and the walk that copies one into the other, and what is left in
// this file only writes fields it names itself.
void put_u16(std::uint8_t* base, std::size_t offset,
             std::uint16_t value) noexcept {
    std::memcpy(base + offset, &value, sizeof(value));
}

void put_u32(std::uint8_t* base, std::size_t offset,
             std::uint32_t value) noexcept {
    std::memcpy(base + offset, &value, sizeof(value));
}

void put_u64(std::uint8_t* base, std::size_t offset,
             std::uint64_t value) noexcept {
    std::memcpy(base + offset, &value, sizeof(value));
}

// --------------------------------------------------------------- the maps

// The CONTEXT, from the signal context. Integer registers, segments, flags
// and the floating-point area are filled from the kernel's saved state; the
// debug registers are left zero and *not claimed* in `ContextFlags`, because
// a filter that reads `Dr0` of a process that has no hardware breakpoints
// should be told the field is absent, not that it is zero.
void fill_guest_context(std::uint8_t* context, const ::ucontext_t& uc) noexcept {
    std::memset(context, 0, kContextSize);
    const ::greg_t* g = uc.uc_mcontext.gregs;
    put_u32(context, kContextFlags, kContextFull);
    // The kernel packs the four segment registers into one slot, in the
    // order CS, GS, FS, SS, sixteen bits each.
    put_u16(context, kContextSegCs,
            static_cast<std::uint16_t>((g[REG_CSGSFS] >> 0) & 0xFFFF));
    put_u16(context, kContextSegGs,
            static_cast<std::uint16_t>((g[REG_CSGSFS] >> 16) & 0xFFFF));
    put_u16(context, kContextSegFs,
            static_cast<std::uint16_t>((g[REG_CSGSFS] >> 32) & 0xFFFF));
    put_u16(context, kContextSegSs,
            static_cast<std::uint16_t>((g[REG_CSGSFS] >> 48) & 0xFFFF));
    put_u32(context, kContextEFlags, static_cast<std::uint32_t>(g[REG_EFL]));
    put_u64(context, kContextRax, static_cast<std::uint64_t>(g[REG_RAX]));
    put_u64(context, kContextRcx, static_cast<std::uint64_t>(g[REG_RCX]));
    put_u64(context, kContextRdx, static_cast<std::uint64_t>(g[REG_RDX]));
    put_u64(context, kContextRbx, static_cast<std::uint64_t>(g[REG_RBX]));
    put_u64(context, kContextRsp, static_cast<std::uint64_t>(g[REG_RSP]));
    put_u64(context, kContextRbp, static_cast<std::uint64_t>(g[REG_RBP]));
    put_u64(context, kContextRsi, static_cast<std::uint64_t>(g[REG_RSI]));
    put_u64(context, kContextRdi, static_cast<std::uint64_t>(g[REG_RDI]));
    put_u64(context, kContextR8, static_cast<std::uint64_t>(g[REG_R8]));
    put_u64(context, kContextR9, static_cast<std::uint64_t>(g[REG_R9]));
    put_u64(context, kContextR10, static_cast<std::uint64_t>(g[REG_R10]));
    put_u64(context, kContextR11, static_cast<std::uint64_t>(g[REG_R11]));
    put_u64(context, kContextR12, static_cast<std::uint64_t>(g[REG_R12]));
    put_u64(context, kContextR13, static_cast<std::uint64_t>(g[REG_R13]));
    put_u64(context, kContextR14, static_cast<std::uint64_t>(g[REG_R14]));
    put_u64(context, kContextR15, static_cast<std::uint64_t>(g[REG_R15]));
    put_u64(context, kContextRip, static_cast<std::uint64_t>(g[REG_RIP]));

    const auto* fp =
        reinterpret_cast<const std::uint8_t*>(uc.uc_mcontext.fpregs);
    if (fp != nullptr) {
        // The floating-point half, by the layer that owns the CONTEXT's
        // layout. The walk of the two save areas lives there rather than
        // here because a copy of it here is a second list of fields to keep
        // in step with seh's, and the list is what went stale.
        seh::copy_fpregs_to_context(context, fp);
    } else {
        // No floating-point state was saved, which the kernel does not do
        // once any has been used; the reset MXCSR is the honest default.
        put_u32(context, kContextMxCsr, kMxCsrReset);
    }
}

// The NTSTATUS a signal and its cause name. The stack-overflow test is
// address arithmetic against the region the builder placed: a fault *below*
// the stack's low end, within a window, is the guard-page probe that Windows
// reports as STATUS_STACK_OVERFLOW, and a program whose recursion ran away
// deserves the code that says so rather than a generic access violation.
std::uint32_t exception_code_for(int sig, const ::siginfo_t& info,
                                 const RunFrame& frame,
                                 std::uint64_t address) noexcept {
    switch (sig) {
    case SIGSEGV:
    case SIGBUS:
        if (frame.stack_low != 0 && address < frame.stack_low &&
            frame.stack_low - address <= (std::uint64_t{64} << 10)) {
            return kStatusStackOverflow;
        }
        return sig == SIGBUS ? kStatusInPageError : kStatusAccessViolation;
    case SIGILL:
        return info.si_code == ILL_PRVOPC ? kStatusPrivilegedInstruction
                                          : kStatusIllegalInstruction;
    case SIGFPE:
        switch (info.si_code) {
        case FPE_INTDIV: return kStatusIntegerDivideByZero;
        case FPE_INTOVF: return kStatusIntegerOverflow;
        case FPE_FLTDIV: return kStatusFloatDivideByZero;
        case FPE_FLTOVF: return kStatusFloatOverflow;
        case FPE_FLTUND: return kStatusFloatUnderflow;
        case FPE_FLTRES: return kStatusFloatInexactResult;
        case FPE_FLTINV: return kStatusFloatInvalidOperation;
        default: return kStatusFloatInvalidOperation;
        }
    case SIGTRAP:
        return info.si_code == TRAP_TRACE ? kStatusSingleStep
                                          : kStatusBreakpoint;
    default:
        return kStatusAccessViolation;
    }
}

// The record the filter reads. The access-violation parameters are the
// operation and the address, with the operation decided by the page-fault
// error code the kernel saved: bit 1 is a write, bit 4 an instruction fetch.
// The in-page record carries a third parameter, the paging status the kernel
// would have named, which here has no source and is zero for that reason.
void fill_exception_record(GuestExceptionRecord& record, std::uint32_t code,
                           std::uint64_t address, int sig,
                           const ::ucontext_t& uc) noexcept {
    record.code = code;
    record.flags = kExceptionNoncontinuable;
    record.inner = 0;
    record.address = address;
    record.parameters = 0;
    record.reserved = 0;
    for (std::uint64_t& slot : record.information) {
        slot = 0;
    }
    if (code == kStatusAccessViolation) {
        record.parameters = 2;
        std::uint64_t operation = kExceptionInfoAccess;
        if (sig == SIGSEGV) {
            const ::greg_t err = uc.uc_mcontext.gregs[REG_ERR];
            if ((err & 0x10) != 0) {
                operation = kExceptionInfoExecute;
            } else if ((err & 0x2) != 0) {
                operation = kExceptionInfoWrite;
            }
        }
        record.information[0] = operation;
        record.information[1] = address;
    } else if (code == kStatusInPageError) {
        record.parameters = 3;
        record.information[0] = kExceptionInfoAccess;
        record.information[1] = address;
        record.information[2] = 0;
    }
}

// The vectored dispatch, from the ntdll layer that owns the list the
// registrations went into. Answering true means a handler repaired the
// state and the faulting instruction runs again.
extern "C" bool occ_vectored_dispatch(const void* record,
                                      const void* context) noexcept;

// ----------------------------------------------------------- the handler

// The fault, seen from the host's side. It records what happened in the
// state the run reports, gives the guest's filter its say in Windows' own
// terms, and otherwise kills the process with the signal -- which is what
// the same code does under a Unix loader, and what Windows does once every
// filter has declined.
//
// The handler runs on the alternate stack, which is what makes a fault in
// the guest's own stack survivable long enough to be reported.
// ---------------------------------------------------------------------------
// The guest trace
//
// `OCC_GUEST_TRACE` turns on a stderr trace of the run's mechanical events:
// the jump into the entry point and every fault the handler sees, with the
// dispatch verdict each fault earned. The trace exists because a guest that
// runs to a stop without ever reporting anything is the one state a person
// outside the process cannot diagnose from the observer's event stream --
// the observer sees a process that spawned and did not exit, and nothing
// between. The trace is opt-in, writes to stderr rather than the event
// stream (the stream belongs to the observer's schema; this belongs to the
// person debugging the run), and costs one `getenv` per run and one write
// per event.
// ---------------------------------------------------------------------------

namespace {

// The trace's switch, read once per run. The value is not graded -- any
// non-empty value turns the trace on -- because a person setting this wants
// the trace and not a negotiation about how much of it. The one refinement
// is `stop`: a value of `stop` also turns the trace on and asks the run to
// stop itself rather than die on the fault no filter accepted, which is
// how a person reaches the crash site with a debugger before the process
// is gone.
[[nodiscard]] bool guest_trace_enabled() noexcept {
    static const bool enabled = [] {
        const char* value = ::getenv("OCC_GUEST_TRACE");
        return value != nullptr && value[0] != '\0';
    }();
    return enabled;
}

// Whether the run asked to be stopped at the crash site rather than end by
// the signal. Separate from the trace's switch because the two are set for
// different reasons: the trace is for reading after the fact, the stop is
// for being there while it happens.
[[nodiscard]] bool guest_trace_stop() noexcept {
    static const bool stop = [] {
        const char* value = ::getenv("OCC_GUEST_TRACE");
        return value != nullptr && std::string_view{value} == "stop";
    }();
    return stop;
}

// The signal's name, for the trace line. A number is correct and a name is
// readable, and the trace is for a person.
[[nodiscard]] const char* signal_name(int sig) noexcept {
    switch (sig) {
    case SIGSEGV: return "SIGSEGV";
    case SIGILL: return "SIGILL";
    case SIGFPE: return "SIGFPE";
    case SIGBUS: return "SIGBUS";
    case SIGTRAP: return "SIGTRAP";
    default: return "SIG?";
    }
}

}  // namespace

void guest_fault_handler(int sig, ::siginfo_t* info, void* context_void) noexcept {
    auto* uc = static_cast<::ucontext_t*>(context_void);
    const ::greg_t* g = uc->uc_mcontext.gregs;
    const std::uint64_t rip = static_cast<std::uint64_t>(g[REG_RIP]);

    // A breakpoint trap is the one fault Windows reports against the
    // instruction itself: the CONTEXT an int3 handler reads names the
    // one-byte breakpoint, and the handler that resumes past it writes
    // Rip+1. The kernel here traps past it -- the rip the signal saved is
    // already the byte after -- so a context built from it unchanged would
    // land the guest one byte into the instruction that follows. Naming
    // the breakpoint is the fix: the saved rip steps back over the 0xCC,
    // in the saved state itself, so the context the handler sees, the
    // record's address and the resume all name the same instruction, the
    // way Windows names them. The judge is the byte itself rather than the
    // signal's cause code, because kernels disagree on the cause they name
    // a user int3 with -- some say TRAP_BRKPT and some say SI_KERNEL --
    // while none of them put anything but a breakpoint one byte before a
    // rip that traps onto a 0xCC. A trace trap stays where the kernel put
    // it, because single-step is a trap on both sides.
    if (sig == SIGTRAP && rip >= 1 &&
        (info == nullptr || info->si_code != TRAP_TRACE)) {
        const volatile std::uint8_t* breakpoint =
            reinterpret_cast<const volatile std::uint8_t*>(rip - 1);
        if (*breakpoint == 0xCC) {
            uc->uc_mcontext.gregs[REG_RIP] = static_cast<::greg_t>(rip - 1);
        }
    }

    const bool from_memory = (sig == SIGSEGV || sig == SIGBUS) && info != nullptr;
    const std::uint64_t address =
        from_memory ? reinterpret_cast<std::uint64_t>(info->si_addr)
                    : static_cast<std::uint64_t>(uc->uc_mcontext.gregs[REG_RIP]);

    winabi::GuestState* state = g_run_frame.state;
    if (state != nullptr) {
        state->faulted = true;
        state->fault_signal = sig;
        state->fault_address = address;
    }

    const std::uint32_t code =
        exception_code_for(sig, info != nullptr ? *info : ::siginfo_t{},
                           g_run_frame, address);

    if (guest_trace_enabled()) {
        std::fprintf(stderr,
                     "occ trace: %s at guest rip 0x%llx, fault address "
                     "0x%llx, status 0x%08x\n",
                     signal_name(sig),
                     static_cast<unsigned long long>(
                         uc->uc_mcontext.gregs[REG_RIP]),
                     static_cast<unsigned long long>(address),
                     code);
    }

    // The frame walk comes first, which is the order Windows keeps: the
    // exception dispatches through the frames whose language handlers ask
    // for it, and only an exception every frame declines reaches the
    // process filter below. A handler that decides to handle starts its
    // own unwind and never returns; a filter that answers
    // EXCEPTION_CONTINUE_EXECUTION lands on the restore below.
    // The vectored handlers come before every frame, in Windows' order and
    // for Windows' reason: a handler that registered first is the one the
    // process wanted deciding first, and a handler that repairs the state
    // -- which is what the runtimes that use vectored handlers do, their
    // stack grows and their faults on purpose -- needs the resume without
    // any scope table being walked at all.
    if (state != nullptr) {
        alignas(16) std::uint8_t context[kContextSize];
        fill_guest_context(context, *uc);
        GuestExceptionRecord record;
        fill_exception_record(record, code, address, sig, *uc);
        if (occ_vectored_dispatch(&record, context)) {
            if (guest_trace_enabled()) {
                std::fprintf(stderr,
                             "occ trace: a vectored handler resumed the "
                             "fault at guest rip 0x%llx\n",
                             static_cast<unsigned long long>(rip));
            }
            ::sigset_t mask;
            std::memcpy(&mask, &uc->uc_sigmask, sizeof(mask));
            ::sigprocmask(SIG_SETMASK, &mask, nullptr);
            seh::seh_restore_context(context);
        }
    }

    if (state != nullptr && state->pdata_va != 0) {
        static_assert(sizeof(::sigset_t) <=
                          winabi::GuestState::kSignalMaskBytes,
                      "the saved mask must fit the state's slot");
        alignas(16) std::uint8_t context[kContextSize];
        fill_guest_context(context, *uc);
        GuestExceptionRecord record;
        fill_exception_record(record, code, address, sig, *uc);
        std::memcpy(state->resume_mask, &uc->uc_sigmask, sizeof(::sigset_t));
        state->resume_mask_valid = true;
        const bool resume = seh::dispatch(
            reinterpret_cast<std::uint8_t*>(&record), context,
            reinterpret_cast<const std::uint8_t*>(state->pdata_va),
            static_cast<std::size_t>(state->pdata_bytes),
            seh::UnwindRange{state->xdata_va, state->xdata_bytes},
            state->image_base, state->image_end, state->stack_low,
            state->stack_high);
        if (resume) {
            // The guest resolved the condition. The mask the fault
            // blocked comes back before the state it interrupted does,
            // or the guest that caught the fault could not fault again.
            if (guest_trace_enabled()) {
                std::fprintf(stderr,
                             "occ trace: the frame walk resumed the fault "
                             "at guest rip 0x%llx\n",
                             static_cast<unsigned long long>(rip));
            }
            ::sigset_t mask;
            std::memcpy(&mask, state->resume_mask, sizeof(mask));
            ::sigprocmask(SIG_SETMASK, &mask, nullptr);
            seh::seh_restore_context(context);
        }
    }

    const std::uint64_t filter = state != nullptr ? state->unhandled_filter : 0;
    if (filter != 0) {
        alignas(16) std::uint8_t context[kContextSize];
        fill_guest_context(context, *uc);
        GuestExceptionRecord record;
        fill_exception_record(record, code, address, sig, *uc);
        const GuestExceptionPointers pointers{&record, context};
        const auto tell = reinterpret_cast<UnhandledFilterFn>(filter);
        if (tell(&pointers) == kExecuteHandler) {
            // The filter accepted the failure, which on Windows means the
            // process unwinds and ends with the exception's code. The flush
            // is here rather than in the exit path because nothing else on
            // this path was given the chance to flush.
            ::fflush(nullptr);
            guest_terminate(code);
        }
        // EXCEPTION_CONTINUE_SEARCH means the filter declined; EXCEPTION_
        // CONTINUE_EXECUTION from a top-level filter would resume into the
        // same faulting instruction, and Windows itself treats the combination
        // as a defect in the filter. Both end here, the way the loader ends
        // them: with the signal.
    }

    // A run that asked to stop at the crash site stops here, with the
    // faulting state still on the stack the debugger will find it on.
    if (guest_trace_stop()) {
        std::fprintf(stderr,
                     "occ trace: the fault at guest rip 0x%llx was not "
                     "accepted; the process stops itself for inspection\n",
                     static_cast<unsigned long long>(
                         uc->uc_mcontext.gregs[REG_RIP]));
        ::fflush(stderr);
        ::raise(SIGSTOP);
    }

    ::signal(sig, SIG_DFL);
    ::sigset_t unblock;
    ::sigemptyset(&unblock);
    ::sigaddset(&unblock, sig);
    ::sigprocmask(SIG_UNBLOCK, &unblock, nullptr);
    ::raise(sig);
    ::_exit(128 + sig);  // only if the raise could not deliver
}

}  // namespace

// Start the process and run it to completion.
//
// The state the thunks serve is built here, from the options the caller
// built the process with, so that the PEB's command line, `GetCommandLineA`
// and `__getmainargs` are three views of the one string rather than three
// strings that agree by luck. The exit codes and the fault reports come back
// through the terminate path and the handler above; the caller sees a
// `RunOutcome` and none of the plumbing.
[[nodiscard]] RunOutcome run_pe_process(PeProcess& process) noexcept {
    RunOutcome outcome;
    const ProcessImage& image = process.image();
    if (!image.ok) {
        outcome.detail =
            std::string(process_error_name(image.error)) + ": " + image.detail;
        return outcome;
    }
    const ProcessOptions& options = process.options();

    // --- the state the thunks serve --------------------------------------

    winabi::GuestState state;
    state.space = &process.space();
    state.mapper = &process.mapper();
    state.teb = image.teb;
    state.peb = image.peb;
    state.image_base = image.module.base;
    state.command_line = options.command_line;
    (void)winabi::utf8_to_utf16(options.command_line, state.command_line_u16);
    state.image_path_dos = winabi::to_dos_path(options.image_path);
    for (const ProcessImage::ExportRecord& entry : image.own_exports) {
        winabi::GuestState::GuestExport copy;
        copy.name = entry.name;
        copy.ordinal = entry.ordinal;
        copy.address = entry.address;
        copy.is_forwarder = entry.is_forwarder;
        copy.forwarder_text = entry.forwarder_text;
        state.own_exports.push_back(std::move(copy));
    }

    // The argv the C startup hands out, which is the command line parsed by
    // the Microsoft rules -- the same rules the guest would apply itself,
    // which is why the parse lives in `winabi` next to the builder it
    // inverts. `argv_table` ends in a null because a C `argv` does, and a
    // program that walks its own `argv` past `argc` is walking somewhere
    // real.
    state.arguments = winabi::split_command_line(options.command_line);
    state.argv_table.reserve(state.arguments.size() + 1);
    for (const std::string& argument : state.arguments) {
        state.argv_table.push_back(argument.c_str());
    }
    state.argv_table.push_back(nullptr);

    // The environment table, pointing into the options' own storage, which
    // lives as long as the process does. Null-terminated for the same reason
    // the argv is.
    state.env_table.reserve(options.environment.size() + 1);
    for (const std::string& entry : options.environment) {
        state.env_table.push_back(entry.c_str());
    }
    state.env_table.push_back(nullptr);

    for (const ProcessImage::RegionRecord& region : image.regions) {
        if (region.kind == RegionKind::Stack) {
            g_run_frame.stack_low = region.base;
            g_run_frame.stack_high = region.base + region.size;
        }
    }

    // The exception walk's facts. The table and the image end travel with
    // the state because the walk reads the guest's memory and a corrupt
    // table is trusted only inside these bounds; the stack bounds come
    // from the same regions the fault path uses.
    state.pdata_va = image.pdata_va;
    state.pdata_bytes = image.pdata_bytes;
    state.xdata_va = image.xdata_va;
    state.xdata_bytes = image.xdata_bytes;
    state.image_end = image.module.base + image.module.size;
    state.stack_low = g_run_frame.stack_low;
    state.stack_high = g_run_frame.stack_high;

    winabi::set_guest_state(&state);
    winabi::install_terminate_path(&guest_terminate);

    // The image's static TLS. The module is given its index -- written into
    // the image's own `_tls_index` -- and the thread that is about to run
    // gets the block that index names. Both have to be in place before the
    // entry point, because the first `__declspec(thread)` variable the
    // guest touches is reached through them.
    // An image that declares no TLS answers false to the first call and has
    // nothing to build in the second, so a false here is the ordinary case
    // rather than a failure. A block that could not be allocated is the
    // other way to get false, and it needs no report of its own: the guest
    // faults at the first `__declspec(thread)` access and the fault path
    // says where.
    static_cast<void>(winabi::register_module_tls(state, image.module.base));
    static_cast<void>(winabi::install_thread_tls(state));

    g_run_frame.state = &state;

    // --- the fault plumbing ----------------------------------------------

    // An alternate stack for the handler. A fault on the guest's own stack
    // -- the stack overflow above -- has nowhere to run a handler on the
    // stack it faulted on, and the alternate stack is the only reason the
    // fault can be reported rather than silently fatal.
    constexpr std::size_t kAltStackBytes = 64 * 1024;
    const std::unique_ptr<std::uint8_t[]> alt_storage(
        new std::uint8_t[kAltStackBytes]);
    ::stack_t alt_stack{};
    alt_stack.ss_sp = alt_storage.get();
    alt_stack.ss_size = kAltStackBytes;
    ::stack_t previous_alt{};
    ::sigaltstack(&alt_stack, &previous_alt);

    constexpr int kFaultSignals[] = {SIGSEGV, SIGILL, SIGFPE, SIGBUS, SIGTRAP};
    constexpr std::size_t kFaultSignalCount =
        sizeof(kFaultSignals) / sizeof(kFaultSignals[0]);
    struct ::sigaction action {};
    action.sa_sigaction = &guest_fault_handler;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    ::sigemptyset(&action.sa_mask);
    struct ::sigaction previous[kFaultSignalCount] = {};
    for (std::size_t i = 0; i < kFaultSignalCount; ++i) {
        ::sigaction(kFaultSignals[i], &action, &previous[i]);
    }

    // The host's GS base, kept so the process that continues after this run
    // -- the same thread, with its own TLS conventions -- finds the segment
    // base it left behind.
    std::uint64_t host_gs_base = 0;
    ::syscall(SYS_arch_prctl, kArchGetGs, &host_gs_base);

    // --- the run ---------------------------------------------------------
    //
    // The `sigsetjmp` is the return leg. The branch the guest enters does
    // not complete -- the entry point's only ways out are the terminate jump
    // (which lands on the `sigsetjmp` with a nonzero value) and a fault the
    // filter declined (which kills the process) -- so what is spelled as an
    // `if` is really a rendezvous: the guest leaves through the jump, and
    // the code below it runs with the host's registers exactly as they were
    // saved, GS base included.
    if (::sigsetjmp(g_host_return, 1) == 0) {
        if (guest_trace_enabled()) {
            std::fprintf(stderr,
                         "occ trace: entering the guest at rip 0x%llx, "
                         "rsp 0x%llx, teb 0x%llx, peb 0x%llx\n",
                         static_cast<unsigned long long>(image.entry_point),
                         static_cast<unsigned long long>(
                             image.initial_stack_pointer),
                         static_cast<unsigned long long>(image.teb),
                         static_cast<unsigned long long>(image.peb));
        }
        ::syscall(SYS_arch_prctl, kArchSetGs, state.teb);
        enter_guest_asm(image.entry_point, image.initial_stack_pointer);
        __builtin_unreachable();
    }

    // --- home again -------------------------------------------------------

    ::syscall(SYS_arch_prctl, kArchSetGs, host_gs_base);
    for (std::size_t i = 0; i < kFaultSignalCount; ++i) {
        ::sigaction(kFaultSignals[i], &previous[i], nullptr);
    }
    ::sigaltstack(&previous_alt, nullptr);
    winabi::install_terminate_path(nullptr);
    winabi::set_guest_state(nullptr);
    g_run_frame = RunFrame{};

    const std::uint32_t code = g_guest_exit_code;
    outcome.exit_code = code;
    if (state.faulted) {
        // The filter accepted the failure and the process ended with the
        // exception's code, the way Windows ends it. The fault fields say
        // where; the exit code is the NTSTATUS.
        outcome.exited = false;
        outcome.fault_address = state.fault_address;
        outcome.signal = state.fault_signal;
        outcome.detail = "the guest faulted (signal " +
                         std::to_string(state.fault_signal) +
                         ") and the unhandled-exception filter accepted it";
    } else {
        outcome.exited = true;
    }
    return outcome;
}

} // namespace occ::runtime

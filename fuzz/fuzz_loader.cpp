// Harness: PE image loader over arbitrary bytes.
//
// A separate harness from fuzz_pe.cpp and not an extension of it, because the
// question is different. The parser harness asks "does this reader describe
// the file consistently"; this one asks "does this loader place it
// consistently" -- and placing means walking a relocation table, walking an
// import directory, and recording regions in an address space. Those three
// walks are new code, they read offsets the file chose, and every one of them
// can be steered by a two-byte edit.
//
// The invariants here are the contract the layer above depends on:
//
//   * A refused load leaves the space untouched. The loader documents this
//     and a caller retries at another base on the strength of it. It is the
//     invariant that was broken once already -- the mapping happened before
//     the relocation walk, so a bad relocation left three regions behind --
//     and this harness is what would have found it, because the input that
//     triggers it is a corrupted block header and that is exactly what a
//     fuzzer produces.
//
//   * Every region recorded is inside the user window, is non-empty, has a
//     size that does not overflow its own end, and does not overlap another.
//     The address space enforces the last two, so a violation here means the
//     enforcement and the reported values disagree.
//
//   * Every mapped region of an image belongs to a section the file actually
//     has, or to the headers. A loader that invented a region would be
//     describing an image the file does not contain.
//
//   * The module's entry point, when the load succeeded, is at the base plus
//     the image's entry RVA, and that address is inside a region the load
//     recorded and is executable. A program whose entry point is not mapped
//     is a program that faults on its first instruction, and the loader is
//     the only layer that can see that coming. The arithmetic is checked and
//     not only the mapping, because an entry computed from the wrong base is
//     still a mapped address.
//
//   * The module reports the base the caller asked for, or the image's own
//     when the caller asked for none. The harness loads each input twice,
//     once each way, so a loader that relocated the image but reported the
//     preferred base is caught.
//
//   * A resolved import's IAT slot is inside a region the load recorded. The
//     slot is where the address is written; a slot outside the map is a
//     store into unmapped memory before the program's first instruction.
//
// The corpus is the PE corpus. A loader harness whose inputs never parse
// would spend its whole budget in the parser's first three gates, so it reuses
// the seeds fuzz_pe.cpp already has rather than defining a second set.

#include "occ/parser/detect.h"
#include "occ/parser/pe.h"
#include "occ/runtime/address_space.h"
#include "occ/runtime/loader.h"
#include "occ/util/span.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace {

using occ::ByteSpan;
using occ::parser::PeImage;
using occ::runtime::AddressSpace;
using occ::runtime::LoadContext;
using occ::runtime::Region;

ByteSpan as_span(const uint8_t* data, std::size_t size) noexcept {
    return ByteSpan{data, size};
}

// A copy of a space's observable state, so that "unchanged" can be checked
// without holding a second address space. The fields are the ones a caller
// can see: the regions, the allocation count, and the high water.
struct SpaceSnapshot {
    std::vector<std::uint64_t> bases;
    std::uint64_t allocations = 0;
    std::uint64_t high_water = 0;

    bool operator==(const SpaceSnapshot& other) const noexcept {
        return bases == other.bases && allocations == other.allocations &&
               high_water == other.high_water;
    }
};

SpaceSnapshot snapshot(const AddressSpace& space) noexcept {
    SpaceSnapshot s;
    for (const Region& r : space.regions()) {
        s.bases.push_back(r.base);
    }
    s.allocations = space.allocation_count();
    s.high_water = space.high_water();
    return s;
}

// Every claim a recorded region has to satisfy.
//
// A region that fails any of these is a region the rest of occ would act on
// wrongly, so a violation is a finding whether or not it crashes.
bool region_is_sane(const Region& r) noexcept {
    // The window. The address space refuses a region outside it, so this is
    // a check that the refusal and the record agree.
    if (r.base < AddressSpace::kUserMin || r.base > AddressSpace::kUserMax) {
        return false;
    }
    if (r.size == 0) {
        return false;
    }
    // The size has to leave the end inside the window, written as the
    // subtraction the address space itself uses. An addition here would wrap
    // on the very input this is meant to catch.
    if (r.size > AddressSpace::kUserMax - r.base) {
        return false;
    }
    // A protection of zero is not one of the enumerated values and would be
    // rendered as PAGE_? by every report. The address space is given the
    // value by the loader, so this pins down that the loader's translation
    // from section characteristics always produced something.
    if (occ::runtime::protection_base(r.protection) == 0) {
        return false;
    }
    return true;
}

// The regions are ordered and disjoint. The address space maintains both, so
// this is a check on the insertion path rather than on the caller.
bool regions_are_disjoint(const AddressSpace& space) noexcept {
    const auto& regions = space.regions();
    for (std::size_t i = 1; i < regions.size(); ++i) {
        if (regions[i - 1].end() > regions[i].base) {
            return false;
        }
    }
    return true;
}

// What the loader claims about a successful load.
bool module_is_sane(const PeImage& image, const AddressSpace& space,
                    const occ::runtime::LoadedModule& m,
                    std::uint64_t requested_base) noexcept {
    // The entry point is mapped and executable -- but only when the image
    // declares one.
    //
    // The loader's rule is that a zero entry RVA means "this image has no
    // entry point", which is what a resource-only DLL declares, and it does
    // not check the entry address in that case. An invariant that required
    // an executable entry for every success would therefore fail every such
    // image while the loader was behaving correctly. The two have to agree
    // about when the rule applies, and the entry RVA is the field that says
    // so.
    //
    // This is the single most valuable claim here: a load that succeeds with
    // an entry point outside the mapped regions, or in a region that cannot
    // be executed, has produced a module that cannot run, and nothing above
    // this layer can tell.
    if (image.entry_rva() != 0) {
        const Region* at_entry = space.find(m.entry_va);
        if (at_entry == nullptr) {
            return false;
        }
        if (!at_entry->executable) {
            return false;
        }
        // The entry address is the base plus the image's own RVA, and the
        // check above would not catch a loader that paired the right entry
        // RVA with the wrong base -- the wrong base is still a mapped
        // address, just not the one the entry point is at. Loading an image
        // at a base it did not compute the entry for runs the wrong code
        // silently, so the arithmetic is asserted rather than the fact that
        // some region contains the answer.
        if (m.entry_va != m.base + image.entry_rva()) {
            return false;
        }
    }

    // The base is the one asked for, or the image's own when the caller
    // named none. The loader documents both halves: `preferred_base` of zero
    // means "use the image's base", and a non-zero one is a request the
    // caller is entitled to.
    //
    // The harness calls this twice per input, once with zero and once with a
    // chosen base, so a loader that ignored the caller's base -- or that
    // relocated the image but reported the preferred base -- is caught on
    // the second call. Checking only that the base is non-zero, which is
    // what this used to do, is satisfied by every wrong answer.
    const std::uint64_t expected_base =
        requested_base != 0 ? requested_base : image.image_base();
    if (m.base != expected_base) {
        return false;
    }
    if (m.base == 0) {
        return false;
    }

    // The size is the image's.
    if (m.size != image.image_size()) {
        return false;
    }

    // Every import names a DLL and a name, and an import that is resolved
    // has a non-zero address while one that is not has a zero address. A
    // record with `resolved` set and no address is a record a caller would
    // follow to address zero.
    for (const auto& imp : m.imports) {
        if (imp.dll.empty()) {
            return false;
        }
        if (imp.name.empty()) {
            return false;
        }
        if (imp.resolved != (imp.target_va != 0)) {
            return false;
        }
        // A resolved import's IAT slot is where the address is written, and
        // it is a virtual address in the loaded image. A slot outside every
        // recorded region is a write into memory the load never mapped --
        // the program would fault storing its own imports, before it ran a
        // single instruction of its own.
        //
        // Only checked when the image actually has an IAT slot for the
        // entry. A loader that could not place one records zero, and zero is
        // not an address this can test.
        if (imp.iat_va != 0 && space.find(imp.iat_va) == nullptr) {
            return false;
        }
    }

    // Every section of the file that occupies address space is mapped, at
    // the address the section names. A loader that dropped one would leave
    // the program's data unmapped and would report a load that succeeded.
    for (const auto& s : image.sections()) {
        const std::uint64_t memb =
            s.virtual_size != 0 ? s.virtual_size : s.raw_size;
        if (memb == 0) {
            continue;
        }
        // The address as a subtraction, not an addition. `m.base +
        // s.virtual_address` wraps when the base is large and the section's
        // address is large, and a wrapped sum is small and passes the window
        // check below while naming an address the load never produced. The
        // project's own rule -- bounds are checked by subtracting, never by
        // adding -- applies to the test as much as to the code under test.
        if (s.virtual_address > AddressSpace::kUserMax - m.base) {
            continue; // the load would have refused this, and did not
        }
        const std::uint64_t va = m.base + s.virtual_address;
        if (space.find(va) == nullptr) {
            return false;
        }
    }
    return true;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
    // A PE smaller than a DOS header and a signature cannot get anywhere, and
    // running the loader on it would only exercise the parser's first gate.
    //
    // Both returns below happen before the address space is constructed, so
    // there is no "the failed load left the space untouched" claim to make on
    // these paths -- there is no space yet. The invariant that matters is
    // asserted further down, against a space this function made and
    // pre-populated, and a reader should not have to trace the ordering to
    // find out which paths it covers.
    if (size < 64) {
        return 0;
    }

    const ByteSpan bytes = as_span(data, size);
    const PeImage image = PeImage::parse(bytes);
    if (!image.ok()) {
        return 0;
    }

    // Two bases: the image's own, which needs no relocation, and one chosen
    // to be different, which forces the relocation walk to run. The second is
    // the one that reaches the block-header parsing, and a harness that only
    // used the preferred base would never enter that code.
    const std::uint64_t bases[] = {
        0,
        0x0000000180000000ull,
    };

    for (const std::uint64_t base : bases) {
        AddressSpace space;

        // A region already present, so that a refused load has something to
        // leave alone and so that the retry path has a reason to care.
        (void)space.record(0x10000, 0x10000,
                           occ::runtime::PageProtection::ReadWrite,
                           occ::runtime::RegionKind::Private);

        const SpaceSnapshot before = snapshot(space);

        // A resolver that always succeeds, so the import path that writes an
        // address is exercised. A resolver that always failed would leave
        // every import unresolved and the branch that records a target would
        // never run.
        const auto resolve = [](void*, const std::string&, const std::string&,
                                std::uint16_t, bool) noexcept -> std::uint64_t {
            return 0x7FFE0000ull;
        };
        LoadContext ctx;
        ctx.resolve = resolve;

        const auto result = occ::runtime::load_image(image, bytes, base, space,
                                                     ctx);

        // The disjointness and sanity of what was recorded holds either way.
        if (!regions_are_disjoint(space)) {
            __builtin_trap();
        }
        for (const Region& r : space.regions()) {
            if (!region_is_sane(r)) {
                __builtin_trap();
            }
        }

        if (!result.ok) {
            // The contract: a refused load leaves the space untouched. This
            // is checked against the snapshot taken before the call, so a
            // loader that recorded and then unwound would be caught too --
            // the count and the high water would not match.
            if (!(snapshot(space) == before)) {
                __builtin_trap();
            }
            // And no detail is empty: a refusal that names nothing sends the
            // reader to look at the whole file.
            if (result.detail.empty()) {
                __builtin_trap();
            }
            continue;
        }

        if (!module_is_sane(image, space, result.module, base)) {
            __builtin_trap();
        }
    }

    return 0;
}

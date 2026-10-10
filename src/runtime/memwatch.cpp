// The page-protection watch, and the instruction trace beside it.
//
// See the header for why the watch is page protection rather than
// breakpoints: the guest is native and nothing this runtime does is
// consulted when it stores. This file is the machinery on the runtime's
// side of that fact -- which pages are watched, what a fault into one
// records, and how the store is let through exactly once so that the
// protection can go back up.
//
// Two switches drive it, read once per run:
//
//   OCC_MEMWATCH    `image` watches every section of the guest's image;
//                   `rva:size` watches one range. Off unless set.
//   OCC_TRACE_STEPS a number of instructions to trace with the trap flag.
//                   Independent of the watch: a run can trace without
//                   watching, and watch without tracing.
//
// Both are passed to the runner by the command that starts it, like the
// other runtime switches, because the process that runs the guest is not
// the process that read the environment the user set.

#include "occ/runtime/memwatch.h"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <string>

#include <sys/mman.h>

namespace occ::runtime::memwatch {
namespace {

constexpr std::uint64_t kPage = 0x1000;

// The watched pages, by base address. A set rather than a map because the
// only question the fault path asks of it is "is this address watched",
// and the page the answer names is recovered from the address itself.
std::set<std::uint64_t> g_pages;

// The page a recorded store is waiting on -- the one whose write
// permission was re-admitted so the store could complete -- and the
// address the store was writing to, kept so the step can record what the
// store left there.
std::uint64_t g_pending_page = 0;
std::uint64_t g_pending_address = 0;

// The instruction trace's remaining budget. Negative is off; a trace with
// no number would run forever and be a hang rather than a trace.
long long g_steps_left = -1;

// The range the environment named, when it named one rather than the
// whole image. Kept beside the parsed headers so `arm` can intersect the
// two instead of the caller doing it.
struct NamedRange {
    std::uint64_t rva = 0;
    std::uint64_t size = 0;
    bool whole_image = true;
};

NamedRange g_range;

[[nodiscard]] bool set_protection(std::uint64_t address, int prot) noexcept {
    return ::mprotect(reinterpret_cast<void*>(address),
                      static_cast<std::size_t>(kPage), prot) == 0;
}

[[nodiscard]] std::uint16_t rd16(const std::uint8_t* p,
                                 std::size_t at) noexcept {
    return static_cast<std::uint16_t>(p[at]) |
           static_cast<std::uint16_t>(p[at + 1] << 8);
}

[[nodiscard]] std::uint32_t rd32(const std::uint8_t* p,
                                 std::size_t at) noexcept {
    return static_cast<std::uint32_t>(p[at]) |
           (static_cast<std::uint32_t>(p[at + 1]) << 8) |
           (static_cast<std::uint32_t>(p[at + 2]) << 16) |
           (static_cast<std::uint32_t>(p[at + 3]) << 24);
}

[[nodiscard]] std::uint64_t rd64(const std::uint8_t* p,
                                 std::size_t at) noexcept {
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
        v = (v << 8) | p[at + static_cast<std::size_t>(i)];
    }
    return v;
}

constexpr std::size_t kSectionSize = 40;
constexpr std::size_t kSectionVirtualSize = 0x08;
constexpr std::size_t kSectionVirtualAddress = 0x0C;
constexpr std::size_t kSectionCharacteristics = 0x24;

// Parses the switch's value. `image` -- the word, case as written -- asks
// for the whole mapping; anything else is read as `rva:size`, in
// hexadecimal either with or without the 0x, because the values a person
// copies out of a hex dump carry the prefix and the ones they compute do
// not. A value that parses as neither is a run without a watch, said out
// loud rather than silently ignored.
[[nodiscard]] NamedRange parse_range(const char* value) noexcept {
    NamedRange range;
    if (value == nullptr || value[0] == '\0') {
        return range;
    }
    if (std::strcmp(value, "image") == 0) {
        range.whole_image = true;
        return range;
    }
    const char* colon = std::strchr(value, ':');
    if (colon == nullptr) {
        std::fprintf(stderr,
                     "occ memwatch: cannot read '%s' as image or rva:size; "
                     "the watch is off\n",
                     value);
        return range;
    }
    const std::string rva_text(value, static_cast<std::size_t>(colon - value));
    const std::string size_text(colon + 1);
    char* end = nullptr;
    const unsigned long long rva = std::strtoull(rva_text.c_str(), &end, 0);
    if (end == nullptr || *end != '\0') {
        std::fprintf(stderr,
                     "occ memwatch: '%s' is not an rva; the watch is off\n",
                     rva_text.c_str());
        return range;
    }
    end = nullptr;
    const unsigned long long size = std::strtoull(size_text.c_str(), &end, 0);
    if (end == nullptr || *end != '\0') {
        std::fprintf(stderr,
                     "occ memwatch: '%s' is not a size; the watch is off\n",
                     size_text.c_str());
        return range;
    }
    range.rva = rva;
    range.size = size;
    range.whole_image = false;
    return range;
}

// Whether a section, named by its span, is inside the range the run asked
// for. A named range that only crosses part of a section watches the part
// -- the pages are the unit, so the section's pages that overlap the range
// are the ones that lose their write bit.
[[nodiscard]] bool in_range(std::uint64_t rva, std::uint64_t bytes) noexcept {
    if (g_range.whole_image) {
        return true;
    }
    return rva < g_range.rva + g_range.size &&
           g_range.rva < rva + bytes;
}

}  // namespace

bool enabled() noexcept {
    static const bool on = [] {
        const char* value = ::getenv("OCC_MEMWATCH");
        return value != nullptr && value[0] != '\0';
    }();
    return on;
}

bool arm(std::uint64_t image_base) noexcept {
    // The trace's budget is read here rather than at first use, so that a
    // trace and a watch start together and neither is left unread because
    // the other was not asked for.
    if (const char* value = ::getenv("OCC_TRACE_STEPS");
        value != nullptr && value[0] != '\0') {
        const long long parsed = std::atoll(value);
        g_steps_left = parsed > 0 ? parsed : -1;
    }
    if (!enabled()) {
        return true;  // no watch to arm; the trace above still stands
    }

    const auto* img = reinterpret_cast<const std::uint8_t*>(image_base);
    if (rd16(img, 0) != 0x5A4D) {
        std::fprintf(stderr, "occ memwatch: no MZ at the image base\n");
        return false;
    }
    const std::uint32_t pe_at = rd32(img, 0x3C);
    if (rd32(img, pe_at) != 0x00004550) {
        std::fprintf(stderr, "occ memwatch: no PE signature at e_lfanew\n");
        return false;
    }
    const std::uint16_t section_count = rd16(img, pe_at + 6);
    const std::uint16_t optional_size = rd16(img, pe_at + 20);
    const std::size_t optional = static_cast<std::size_t>(pe_at) + 24;
    const std::size_t section_table =
        optional + static_cast<std::size_t>(optional_size);

    g_range = parse_range(::getenv("OCC_MEMWATCH"));

    std::size_t armed = 0;
    std::size_t refused = 0;
    for (std::uint16_t i = 0; i < section_count; ++i) {
        const std::size_t entry =
            section_table + static_cast<std::size_t>(i) * kSectionSize;
        const std::uint32_t virtual_size = rd32(img, entry + kSectionVirtualSize);
        const std::uint32_t virtual_address =
            rd32(img, entry + kSectionVirtualAddress);
        if (virtual_size == 0 || !in_range(virtual_address, virtual_size)) {
            continue;
        }
        // Page by page, because a section whose size is not a multiple of
        // the page size shares its last page with whatever follows it, and
        // protecting past the section would watch bytes the section does
        // not own.
        const std::uint64_t pages =
            (virtual_size + kPage - 1) / kPage;
        for (std::uint64_t page = 0; page < pages; ++page) {
            const std::uint64_t address =
                image_base + virtual_address + page * kPage;
            if (set_protection(address, PROT_READ | PROT_EXEC)) {
                g_pages.insert(address);
                ++armed;
            } else {
                ++refused;
            }
        }
    }

    std::fprintf(stderr,
                 "occ memwatch: %zu pages watched (%zu refused)%s\n", armed,
                 refused,
                 g_range.whole_image ? "" : " -- range as named");
    if (armed == 0) {
        // A watch over nothing would silently report nothing, and a
        // decryption the analyst was promised would be visible would run
        // unwatched. This is the state the note exists to prevent.
        std::fprintf(stderr,
                     "occ memwatch: nothing was armed; there will be no "
                     "records\n");
        return false;
    }
    return true;
}

bool handles(std::uint64_t fault_address) noexcept {
    return g_pages.contains(fault_address & ~(kPage - 1));
}

void service_write(std::uint64_t fault_address, std::uint64_t rip) noexcept {
    const std::uint64_t page = fault_address & ~(kPage - 1);
    // The value the store is about to replace, read at eight-byte
    // alignment: the store's width is not known here -- the instruction
    // has not run -- and eight bytes with a note of the address is what
    // the reader can line up against the step's record of what replaced
    // them.
    const std::uint64_t old_value = rd64(
        reinterpret_cast<const std::uint8_t*>(fault_address & ~7ULL), 0);
    std::fprintf(stderr,
                 "occ memwatch: store rip=0x%llx addr=0x%llx "
                 "old=0x%016llx\n",
                 static_cast<unsigned long long>(rip),
                 static_cast<unsigned long long>(fault_address),
                 static_cast<unsigned long long>(old_value));
    // Writes re-admitted for this page only, and only until the step: the
    // store completes, the step lands, and the page goes back to
    // read-execute before any other instruction of the guest's runs.
    static_cast<void>(set_protection(page, PROT_READ | PROT_WRITE | PROT_EXEC));
    g_pending_page = page;
    g_pending_address = fault_address;
}

bool step_outstanding() noexcept {
    return g_pending_page != 0;
}

bool service_step() noexcept {
    if (g_pending_page == 0) {
        return false;
    }
    const std::uint64_t page = g_pending_page;
    const std::uint64_t address = g_pending_address;
    g_pending_page = 0;
    g_pending_address = 0;
    // The value the store left, read now that it has run -- the pair of
    // this and the `old` the fault recorded is the write, whole.
    const std::uint64_t new_value = rd64(
        reinterpret_cast<const std::uint8_t*>(address & ~7ULL), 0);
    std::fprintf(stderr,
                 "occ memwatch:        addr=0x%llx new=0x%016llx "
                 "(page re-protected)\n",
                 static_cast<unsigned long long>(address),
                 static_cast<unsigned long long>(new_value));
    static_cast<void>(set_protection(page, PROT_READ | PROT_EXEC));
    return true;
}

bool step_trace_active() noexcept {
    return g_steps_left > 0;
}

void record_step(std::uint64_t rip) noexcept {
    if (g_steps_left <= 0) {
        return;
    }
    --g_steps_left;
    const auto* p = reinterpret_cast<const std::uint8_t*>(rip);
    std::fprintf(stderr, "occ step: rip=0x%llx bytes=", 
                 static_cast<unsigned long long>(rip));
    // The instruction's first bytes, up to the longest x64 instruction.
    // The trace is a record rather than a listing: the address and the
    // bytes are what any disassembler consumes, and printing a decoded
    // form here would couple this file to a decoder it does not need to
    // own a opinion about.
    for (std::size_t i = 0; i < 15; ++i) {
        std::fprintf(stderr, "%02x ", p[i]);
    }
    std::fprintf(stderr, "\n");
    if (g_steps_left == 0) {
        std::fprintf(stderr,
                     "occ step: budget spent; the trace ends here and the "
                     "guest runs on\n");
    }
}

}  // namespace occ::runtime::memwatch

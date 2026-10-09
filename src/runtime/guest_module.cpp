// The API modules, as images the guest can see.
//
// See guest_module.h for what this is and why. The short form: a program
// that walks the PEB's loader list and parses the module's own export
// directory is not asking the runtime a question -- it is reading memory,
// and the only answer that works is bytes shaped the way Windows shapes
// them. This file writes those bytes.

#include "occ/runtime/guest_module.h"

#include "occ/runtime/address_space.h"
#include "occ/runtime/api_hook.h"
#include "occ/runtime/mapper.h"

#include <cstring>
#include <map>
#include <utility>

namespace occ::runtime::guest_module {

namespace {

// The image layout. One header page, then the export directory's page, then
// the trampoline page. Everything is page-aligned because the structures a
// walker checks are the ones the alignment lets it trust: a SizeOfImage that
// does not cover the sections, or a section RVA that is not aligned, is the
// kind of detail a careful walker reads as a forgery.
constexpr std::uint64_t kPage = 0x1000;
[[maybe_unused]] constexpr std::uint64_t kHeadersRva = 0;
constexpr std::uint64_t kExportRva = 0x1000;
[[maybe_unused]] constexpr std::uint64_t kTextRva = 0x2000;

// The trampoline, in the two shapes it takes.
//
// Plain, `movabs rax, imm64; jmp rax` -- twelve bytes that turn a pointer
// the guest holds into a call that arrives at the host thunk. Traced, the
// same call with one detour: `mov r11, imm64` loads the hook's slot and
// the jump goes to the hook instead, which records the call and then
// jumps to the implementation the plain shape would have reached. `r11` is
// the register the x64 convention leaves undefined at a call, so the slot
// costs the guest nothing and the implementation never sees it.
//
// Both are padded to thirty-two with `0xCC`, which is the wider shape's
// size. The stride is one value for both because the layout -- the page
// count, the RVAs and `SizeOfImage` -- is computed from it before a single
// trampoline is written, and a layout that depended on which shape was
// chosen would make the image two different images depending on an
// environment variable.
constexpr std::uint64_t kTrampolineStride = 32;

// The names the export directory itself carries. The module name is the
// string the directory's Name field points at, spelled the way the module
// declares itself; a walker that compares it against the loader entry's
// base name is comparing two strings this code wrote from the same source.
struct BuiltImage {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    // The name table, as the walker reads it: for each export, the RVA of
    // its trampoline. Kept beside the base so `proc_address` can answer
    // without re-parsing what it just wrote.
    std::vector<std::pair<std::string, std::uint32_t>> exports;
};

void put8(std::vector<std::uint8_t>& image, std::uint64_t off,
          std::uint8_t v) noexcept {
    if (off < image.size()) {
        image[static_cast<std::size_t>(off)] = v;
    }
}

void put16(std::vector<std::uint8_t>& image, std::uint64_t off,
           std::uint16_t v) noexcept {
    if (off + 2 <= image.size()) {
        std::memcpy(image.data() + static_cast<std::size_t>(off), &v, 2);
    }
}

void put32(std::vector<std::uint8_t>& image, std::uint64_t off,
           std::uint32_t v) noexcept {
    if (off + 4 <= image.size()) {
        std::memcpy(image.data() + static_cast<std::size_t>(off), &v, 4);
    }
}

void put64(std::vector<std::uint8_t>& image, std::uint64_t off,
           std::uint64_t v) noexcept {
    if (off + 8 <= image.size()) {
        std::memcpy(image.data() + static_cast<std::size_t>(off), &v, 8);
    }
}

__attribute__((noinline)) void put_bytes(std::vector<std::uint8_t>& image,
                                         std::uint64_t off, const void* data,
                                         std::size_t bytes) noexcept {
    if (off + bytes <= image.size()) {
        std::memcpy(image.data() + static_cast<std::size_t>(off), data, bytes);
    }
}

void put_string(std::vector<std::uint8_t>& image, std::uint64_t off,
                std::string_view text) noexcept {
    put_bytes(image, off, text.data(), text.size());
    put8(image, off + static_cast<std::uint64_t>(text.size()), 0);
}

// The entries the three lists hang off, written in place once the entries
// exist: a list head is a `LIST_ENTRY` whose Flink names the first entry
// and whose Blink names the last, and the circle closes through the
// entries' own links. An empty list is the head pointing at itself, which
// is what `IsListEmpty` tests and what a walker stops on.
constexpr std::uint16_t kListHeadLength = 0x38;

// The region that holds the loader entries and their name buffers. One
// page per four entries plus a page of strings is generous for the module
// count a guest actually loads, and a region this runtime owns outright is
// one nobody's heap can hand to someone else.
constexpr std::uint64_t kEntryStride = 0x100;
constexpr std::uint64_t kEntriesPerPage = kPage / kEntryStride;

// The offsets inside one `LDR_DATA_TABLE_ENTRY`, from the entry's own
// start -- which is `InLoadOrderLinks`, because that is the layout Windows
// builds and the layout every walker's arithmetic assumes.
struct LdrEntryLayout {
    static constexpr std::size_t kInLoad = 0x00;
    static constexpr std::size_t kInMemory = 0x10;
    static constexpr std::size_t kInInit = 0x20;
    static constexpr std::size_t kDllBase = 0x30;
    static constexpr std::size_t kEntryPoint = 0x38;
    static constexpr std::size_t kSizeOfImage = 0x40;
    static constexpr std::size_t kFullDllName = 0x48;
    static constexpr std::size_t kBaseDllName = 0x58;
};

// The buffer a `UNICODE_STRING` points into, from the entry's own start.
// Each name gets its own slot inside the strings area of the region, so a
// walker that follows `Buffer` lands in this region and not in some other
// module's name.
constexpr std::size_t kNameBufferStride = 0x80;

}  // namespace

// ---------------------------------------------------------------------------
// The installed state
// ---------------------------------------------------------------------------

namespace {

struct ModuleEntry {
    BuiltImage image;
    std::string folded_name;
};

// The modules this process has images of, keyed by folded name and by
// base. Both maps answer the same question from the two directions the
// guest asks it: a name (`GetModuleHandleW`) and a base
// (`GetProcAddress`).
std::map<std::string, ModuleEntry>& module_by_name() noexcept {
    static std::map<std::string, ModuleEntry> map;
    return map;
}

std::map<std::uint64_t, ModuleEntry>& module_by_base() noexcept {
    static std::map<std::uint64_t, ModuleEntry> map;
    return map;
}

[[nodiscard]] std::string fold(std::string_view name) noexcept {
    std::string folded(name);
    for (char& c : folded) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return folded;
}

}  // namespace

// ---------------------------------------------------------------------------
// Building one image
// ---------------------------------------------------------------------------

namespace {

// Writes the whole image: headers that parse, an export directory with the
// module's names in it, and one trampoline per export. The layout is fixed
// by what a walker verifies -- aligned sections, a SizeOfImage that covers
// them, a name table in sorted order -- and the counts are computed from
// the export list rather than assumed, which is what keeps a module with
// more names than the layout guessed from writing its arrays over the
// section that follows.
[[nodiscard]] bool build_and_place(const ModuleInput& module, Mapper& mapper,
                                   BuiltImage& out) noexcept {
    // The exports, ordered by name -- the order `AddressOfNames` must be
    // in, because a walker binary-searches it. Duplicates by name collapse
    // to the first: a module with two exports of one name has one that
    // wins, and which one wins is not a thing Windows defines, so the
    // first registered does.
    std::map<std::string, const Export*> ordered;
    for (const Export& entry : module.exports) {
        ordered.emplace(entry.name, &entry);
    }

    const std::size_t name_count = ordered.size();
    const std::size_t export_count = module.exports.size();

    // The trampoline page count, from the export count: the data page
    // carries the directory, the module name, the export name strings and
    // the three arrays, so it is sized from the names too. Both pages are
    // counted here and the total is what `SizeOfImage` says.
    std::size_t name_bytes = 0;
    for (const auto& [name, entry] : ordered) {
        static_cast<void>(entry);
        name_bytes += name.size() + 1;
    }
    const std::uint64_t export_data_bytes =
        0x40 +                                     // the directory
        (module.name.size() + 1) +                 // the module name
        name_bytes +                               // the export names
        (export_count + 1) * 4 +                   // AddressOfFunctions
        (name_count + 1) * 4 +                     // AddressOfNames
        (name_count + 1) * 2 +                     // AddressOfNameOrdinals
        16;                                        // alignment slack
    const std::uint64_t export_pages =
        (export_data_bytes + kPage - 1) / kPage;
    const std::uint64_t trampoline_bytes =
        (static_cast<std::uint64_t>(export_count) + 1) * kTrampolineStride;
    const std::uint64_t text_pages =
        (trampoline_bytes + kPage - 1) / kPage;
    const std::uint64_t size =
        kExportRva + export_pages * kPage + text_pages * kPage;
    const std::uint64_t text_rva = kExportRva + export_pages * kPage;

    std::vector<std::uint8_t> image(static_cast<std::size_t>(size), 0);

    // --- the DOS header: the stub is the mark and the pointer, which is
    // what an `MZ` test reads and what `e_lfanew` follows.
    put8(image, 0, 'M');
    put8(image, 1, 'Z');
    put32(image, 0x3c, 0x80);

    // --- the NT headers at 0x80. The offsets below are the PE32+ ones the
    // manual spells, and a walker parses them from the same table: the
    // file header's twenty bytes end at 0x98, the optional header runs to
    // 0x188, and the export directory is the first entry of the data
    // directory -- which is the field a walker's `0x88` load reads, and
    // the one that must not be zero.
    put32(image, 0x80, 0x00004550);  // "PE\0\0"
    put16(image, 0x84, 0x8664);      // FileHeader.Machine: AMD64
    put16(image, 0x86, 2);           // NumberOfSections
    put16(image, 0x94, 0xF0);        // SizeOfOptionalHeader (PE32+)
    put16(image, 0x96, 0x2022);      // DLL | LARGE_ADDRESS_AWARE | EXECUTABLE
    put16(image, 0x98, 0x020B);      // OptionalHeader.Magic: PE32+
    put32(image, 0x9c, 0);           // SizeOfCode -- the trampolines are data
                                     // to the loader that built them
    put32(image, 0xa0, 0);           // patched below: SizeOfInitializedData
    put32(image, 0xa8, 0);           // AddressOfEntryPoint: none
    put32(image, 0xac, static_cast<std::uint32_t>(text_rva));  // BaseOfCode
    put32(image, 0xb8, kPage);       // SectionAlignment
    put32(image, 0xbc, kPage);       // FileAlignment
    put16(image, 0xc0, 10);          // OS major
    put16(image, 0xc8, 6);           // Subsystem major
    put32(image, 0xd0, static_cast<std::uint32_t>(size));  // SizeOfImage
    put32(image, 0xd4, kPage);       // SizeOfHeaders
    put16(image, 0xdc, 3);           // Subsystem: console
    put16(image, 0xde, 0x0160);      // HIGH_ENTROPY_VA | DYNAMIC_BASE | NX
    put64(image, 0xe0, 0x100000);    // stack reserve
    put64(image, 0xe8, 0x1000);      // stack commit
    put64(image, 0xf0, 0x100000);    // heap reserve
    put64(image, 0xf8, 0x1000);      // heap commit
    put32(image, 0x104, 16);         // NumberOfRvaAndSizes
    // DataDirectory[0]: the export directory. Written after the page
    // layout is computed -- the two fields below are patched when the
    // directory's own extent is known, and the walker that reads them is
    // the one this file exists to serve.
    put32(image, 0x108, 0);          // patched below: export RVA
    put32(image, 0x10c, 0);          // patched below: export size

    // --- the export data's layout inside its pages. The directory sits at
    // the page's start, the module name follows it, then the export name
    // strings, then the three arrays -- each offset computed as the one
    // before it is placed.
    const std::uint64_t dir_rva = kExportRva;
    const std::uint64_t module_name_rva = dir_rva + 0x40;
    const std::uint64_t strings_rva = module_name_rva +
                                      module.name.size() + 2;

    std::uint64_t cursor = strings_rva;
    std::vector<std::uint64_t> name_rvas;
    name_rvas.reserve(name_count);
    for (const auto& [name, entry] : ordered) {
        static_cast<void>(entry);
        name_rvas.push_back(cursor);
        put_string(image, cursor, name);
        cursor += static_cast<std::uint64_t>(name.size()) + 1;
    }

    cursor = (cursor + 3) & ~3ULL;
    const std::uint64_t functions_rva = cursor;
    cursor += static_cast<std::uint64_t>(export_count) * 4;
    const std::uint64_t names_rva = cursor;
    cursor += static_cast<std::uint64_t>(name_count) * 4;
    const std::uint64_t ordinals_rva = cursor;
    cursor += static_cast<std::uint64_t>(name_count) * 2;
    const std::uint64_t export_size = cursor - dir_rva;

    // --- the trampolines, in registration order: the function table is
    // indexed by the ordinal-relative index, `Base` is one, and the i-th
    // entry's ordinal is `1 + i`. A duplicate name does not take a second
    // trampoline -- the first registration wins, as it does in the name
    // table.
    std::map<std::string, std::uint32_t> function_index;
    // The slot each trampoline carries, in trampoline order, so that the
    // addresses the guest will actually hold can be registered once the
    // image is placed and those addresses are known.
    std::vector<std::uint32_t> slot_of_index;
    const bool traced = api_hook::enabled();
    std::uint32_t index = 0;
    for (const Export& entry : module.exports) {
        if (function_index.count(entry.name) != 0) {
            continue;
        }
        const std::uint32_t rva = static_cast<std::uint32_t>(
            text_rva + static_cast<std::uint64_t>(index) * kTrampolineStride);
        const std::uint64_t at = rva;
        // The slot is claimed whether or not the calls are traced. The
        // table behind it is what lets a dump name the address a rebuilt
        // import slot holds, and that answer is wanted from a run that
        // traces nothing -- so the registration is not part of the trace.
        [[maybe_unused]] const std::uint32_t slot =
            api_hook::note(module.name, entry.name, entry.address);
        if (traced) {
            put8(image, at, 0x49);       // REX.WB
            put8(image, at + 1, 0xBB);   // mov r11, imm64
            put64(image, at + 2, slot);
            put8(image, at + 10, 0x48);  // REX.W
            put8(image, at + 11, 0xB8);  // movabs rax, imm64
            put64(image, at + 12,
                  reinterpret_cast<std::uint64_t>(&api_hook::occ_api_hook));
            put8(image, at + 20, 0xFF);  // jmp rax
            put8(image, at + 21, 0xE0);
            for (std::uint64_t pad = 22; pad < kTrampolineStride; ++pad) {
                put8(image, at + pad, 0xCC);
            }
        } else {
            put8(image, at, 0x48);       // REX.W
            put8(image, at + 1, 0xB8);   // movabs rax, imm64
            put64(image, at + 2, entry.address);
            put8(image, at + 10, 0xFF);  // jmp rax
            put8(image, at + 11, 0xE0);
            for (std::uint64_t pad = 12; pad < kTrampolineStride; ++pad) {
                put8(image, at + pad, 0xCC);
            }
        }
        put32(image, functions_rva + static_cast<std::uint64_t>(index) * 4, rva);
        function_index.emplace(entry.name, index);
        slot_of_index.push_back(slot);
        ++index;
    }

    // The name table, in sorted order, and the ordinal table beside it --
    // each name's ordinal is the function index its name resolves to,
    // which is the whole of what `AddressOfNameOrdinals` means.
    std::size_t name_index = 0;
    for (const auto& [name, entry] : ordered) {
        static_cast<void>(entry);
        put32(image, names_rva + static_cast<std::uint64_t>(name_index) * 4,
              static_cast<std::uint32_t>(name_rvas[name_index]));
        put16(image, ordinals_rva + static_cast<std::uint64_t>(name_index) * 2,
              static_cast<std::uint16_t>(function_index.at(name)));
        ++name_index;
    }

    // The export directory, written last because its fields name the
    // offsets above.
    put32(image, dir_rva + 0x10, 1);  // Base: the ordinal base
    put32(image, dir_rva + 0x14,
          static_cast<std::uint32_t>(export_count));  // NumberOfFunctions
    put32(image, dir_rva + 0x18,
          static_cast<std::uint32_t>(name_count));    // NumberOfNames
    put32(image, dir_rva + 0x1c,
          static_cast<std::uint32_t>(functions_rva));
    put32(image, dir_rva + 0x20, static_cast<std::uint32_t>(names_rva));
    put32(image, dir_rva + 0x24,
          static_cast<std::uint32_t>(ordinals_rva));

    // --- the section table, at 0x194 where the PE32+ optional header
    // ends. Raw offsets equal RVAs: the image is mapped, not read from a
    // file, and equal values are the honest spelling of that.
    const std::uint64_t section_table = 0x194;
    put_bytes(image, section_table, ".rdata", 6);
    put32(image, section_table + 8, static_cast<std::uint32_t>(kPage));       // VirtualSize
    put32(image, section_table + 12, kExportRva); // VirtualAddress
    put32(image, section_table + 16, kPage);      // SizeOfRawData
    put32(image, section_table + 20, kExportRva); // PointerToRawData
    put32(image, section_table + 36, 0x40000040); // INITIALIZED_DATA, READ

    put_bytes(image, section_table + 40, ".text", 5);
    put32(image, section_table + 48, kPage);      // VirtualSize
    put32(image, section_table + 52,
          static_cast<std::uint32_t>(text_rva));    // VirtualAddress
    put32(image, section_table + 56, kPage);      // SizeOfRawData
    put32(image, section_table + 60,
          static_cast<std::uint32_t>(text_rva));    // PointerToRawData
    put32(image, section_table + 76, 0x60000020); // CODE, EXECUTE, READ

    // --- place it. The floor keeps the images out of the image's own
    // window and out of the heap's: the module images are a fixture of the
    // process, and a `VirtualAlloc` that later landed on one would be a
    // corruption the program did not cause. `ExecuteReadWrite` because the
    // trampolines execute and the headers are read; a two-protection
    // split would be closer to Windows and is not worth a second
    // mapping's bookkeeping here.
    // The mapping is the placement: `map` commits what it maps, and the
    // ledger records it as an image region, which is what the guest's
    // `VirtualQuery` will answer from.
    const auto placed = mapper.map_above(0x04000000, size,
                                         PageProtection::ExecuteReadWrite,
                                         RegionKind::Image);
    if (!placed.ok()) {
        return false;
    }
    const std::uint64_t base = placed.value;

    // The two fields that are facts about the placement: the ImageBase
    // and the directory's module-name pointer, whose string is written
    // into the same buffer before the whole image is copied across.
    put64(image, 0xb0, base);

    // The addresses the guest will actually hold, now that they exist. A
    // walk of the loader list reads the export table and stores the
    // trampoline it finds there, so a trampoline -- and not the
    // implementation behind it -- is what a rebuilt import slot contains.
    // Registering both is what lets the same slot name the same function
    // whichever of the two it happens to hold.
    for (std::size_t i = 0; i < slot_of_index.size(); ++i) {
        api_hook::note_trampoline(
            base + text_rva + static_cast<std::uint64_t>(i) * kTrampolineStride,
            slot_of_index[i]);
    }
    put_string(image, module_name_rva, module.name);
    put32(image, dir_rva + 0x0c, static_cast<std::uint32_t>(module_name_rva));
    put32(image, 0x108, static_cast<std::uint32_t>(dir_rva));
    put32(image, 0x10c, static_cast<std::uint32_t>(export_size));
    put32(image, 0xa0, static_cast<std::uint32_t>(size - kExportRva));
    std::memcpy(reinterpret_cast<void*>(base), image.data(), image.size());

    out.base = base;
    out.size = size;
    // The lookup table: each export's name and its trampoline RVA, in
    // registration order -- which is the ordinal order `proc_address`
    // answers from.
    out.exports.clear();
    for (const Export& entry : module.exports) {
        const auto it = function_index.find(entry.name);
        if (it != function_index.end()) {
            out.exports.emplace_back(entry.name, static_cast<std::uint32_t>(
                text_rva + static_cast<std::uint64_t>(it->second) *
                               kTrampolineStride));
        }
    }
    return true;
}

}  // namespace

namespace {

// The store into a region whose base the runtime computed. See the call
// site for why this is a function and not a lambda.
__attribute__((noinline)) void store_region(std::uint64_t base,
                                            std::uint64_t off,
                                            const void* data,
                                            std::size_t bytes) noexcept {
    std::memcpy(reinterpret_cast<void*>(base + off), data, bytes);
}

}  // namespace

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

bool install(const InstallRequest& request) noexcept {
    if (request.space == nullptr || request.mapper == nullptr ||
        request.peb == 0) {
        return false;
    }
    auto& mapper = *static_cast<Mapper*>(request.mapper);

    // The modules, in the order the loader list names them. Windows builds
    // the memory-order list with the image first, `ntdll.dll` second and
    // `kernel32.dll` third, and a walker that follows the list counting on
    // that order -- the "second entry is ntdll" walk this file exists to
    // serve -- is reading a fact the order decides. The caller's order is
    // respected for the rest.
    struct Entry {
        std::uint64_t base = 0;
        std::uint64_t size = 0;
        std::string full_name;
        std::string base_name;
        bool is_image = false;
    };
    std::vector<Entry> entries;
    entries.reserve(request.modules.size() + 1);
    entries.push_back(Entry{request.image_base, request.image_size,
                            request.image_name, request.image_name, true});

    std::vector<ModuleInput> ordered_modules;
    ordered_modules.reserve(request.modules.size());
    for (const ModuleInput& module : request.modules) {
        const std::string folded = fold(module.name);
        if (folded == "ntdll.dll") {
            ordered_modules.insert(ordered_modules.begin(), module);
        } else if (folded == "kernel32.dll") {
            // After ntdll, wherever ntdll landed.
            ordered_modules.insert(
                ordered_modules.begin() +
                    (static_cast<std::size_t>(fold(
                         ordered_modules.front().name) == "ntdll.dll")
                         ? 1
                         : 0),
                module);
        } else {
            ordered_modules.push_back(module);
        }
    }

    std::vector<BuiltImage> built;
    built.reserve(ordered_modules.size());
    for (const ModuleInput& module : ordered_modules) {
        BuiltImage image;
        if (!build_and_place(module, mapper, image)) {
            return false;
        }
        Entry entry;
        entry.base = image.base;
        entry.size = image.size;
        entry.full_name = "C:\\Windows\\System32\\" + module.name;
        entry.base_name = module.name;
        entries.push_back(std::move(entry));
        built.push_back(std::move(image));

        ModuleEntry record;
        record.image = built.back();
        record.folded_name = fold(module.name);
        module_by_name().emplace(record.folded_name, record);
        module_by_base().emplace(image.base, std::move(record));
    }

    // --- the loader region: entries and their name strings. One region,
    // mapped once, and the entries written into it. The region needs to
    // hold every entry plus every name buffer, which the layout below
    // computes rather than assumes.
    const std::size_t entry_count = entries.size();
    const std::uint64_t entry_bytes =
        ((entry_count + kEntriesPerPage - 1) / kEntriesPerPage) * kPage;
    // Two buffers per entry -- the full name and the base name -- each in
    // its own stride. The stride bounds the buffer, so the region's size
    // is computed from the strides rather than from the names: a loop that
    // wrote by stride into a region sized from the name lengths would run
    // past the end the first time a stride was longer than the name it
    // held.
    const std::size_t name_bytes = entry_count * 2 * kNameBufferStride;
    const std::uint64_t region_bytes =
        entry_bytes + ((name_bytes + kPage - 1) / kPage) * kPage;
    const auto placed = mapper.map_above(0x04000000, region_bytes,
                                         PageProtection::ReadWrite,
                                         RegionKind::Control);
    if (!placed.ok()) {
        return false;
    }
    const std::uint64_t region = placed.value;
    // The store into the region. A lambda would inline into this function
    // and hand the analysis a `memcpy` against an object of no known size
    // -- an address computed from an integer -- which is the report the
    // `noinline` here exists to keep in one function instead of letting it
    // grey out every store the caller makes.
    const auto write = [region](std::uint64_t off, const void* data,
                                std::size_t bytes) noexcept {
        store_region(region, off, data, bytes);
    };

    // The entries, each in its stride.
    std::uint64_t string_cursor = entry_bytes;
    std::vector<std::uint64_t> entry_offsets;
    entry_offsets.reserve(entry_count);
    for (std::size_t i = 0; i < entry_count; ++i) {
        entry_offsets.push_back(static_cast<std::uint64_t>(i) * kEntryStride);
    }

    // The name buffers, one per entry, after the entries. A module name
    // is an ASCII spelling widened to UTF-16, which is what every name the
    // loader list carries is; the widening is done here, into the slot,
    // rather than through a temporary that would have to be bounded the
    // same way this loop already is.
    std::vector<std::uint64_t> full_name_offsets;
    std::vector<std::uint64_t> base_name_offsets;
    for (const Entry& entry : entries) {
        full_name_offsets.push_back(string_cursor);
        auto* buf = reinterpret_cast<std::uint8_t*>(region + string_cursor);
        for (std::size_t c = 0; c < entry.full_name.size(); ++c) {
            buf[c * 2] = static_cast<std::uint8_t>(entry.full_name[c]);
            buf[c * 2 + 1] = 0;
        }
        buf[entry.full_name.size() * 2] = 0;
        buf[entry.full_name.size() * 2 + 1] = 0;
        string_cursor += kNameBufferStride;

        base_name_offsets.push_back(string_cursor);
        auto* base_buf =
            reinterpret_cast<std::uint8_t*>(region + string_cursor);
        for (std::size_t c = 0; c < entry.base_name.size(); ++c) {
            base_buf[c * 2] = static_cast<std::uint8_t>(entry.base_name[c]);
            base_buf[c * 2 + 1] = 0;
        }
        base_buf[entry.base_name.size() * 2] = 0;
        base_buf[entry.base_name.size() * 2 + 1] = 0;
        string_cursor += kNameBufferStride;
    }

    // Each entry's fields.
    for (std::size_t i = 0; i < entry_count; ++i) {
        const Entry& entry = entries[i];
        const std::uint64_t at = entry_offsets[i];
        const std::uint64_t self = region + at;

        // The three links. The list is built as a circle below; here each
        // link is written with its own address as a placeholder that the
        // circle pass replaces.
        for (const std::size_t link_off :
             {LdrEntryLayout::kInLoad, LdrEntryLayout::kInMemory,
              LdrEntryLayout::kInInit}) {
            write(at + link_off, &self, 8);
            const std::uint64_t same = self;
            write(at + link_off + 8, &same, 8);
        }

        write(at + LdrEntryLayout::kDllBase, &entry.base, 8);
        // EntryPoint: zero for a DLL is what Windows records for a module
        // whose entry point was not run as an entry, and zero for the
        // image is what the loader leaves before running it.
        static const std::uint64_t kZero = 0;
        write(at + LdrEntryLayout::kEntryPoint, &kZero, 8);
        const std::uint32_t size32 = static_cast<std::uint32_t>(entry.size);
        write(at + LdrEntryLayout::kSizeOfImage, &size32, 4);

        const auto write_us = [&, at](std::size_t off,
                                          std::uint64_t buffer_off,
                                          std::string_view text) noexcept {
            const std::uint16_t bytes =
                static_cast<std::uint16_t>(text.size() * 2);
            write(at + off, &bytes, 2);
            const std::uint16_t max_bytes = bytes + 2;
            write(at + off + 2, &max_bytes, 2);
            const std::uint32_t pad = 0;
            write(at + off + 4, &pad, 4);
            const std::uint64_t buffer = region + buffer_off;
            write(at + off + 8, &buffer, 8);
        };
        write_us(LdrEntryLayout::kFullDllName, full_name_offsets[i],
                 entry.full_name);
        write_us(LdrEntryLayout::kBaseDllName, base_name_offsets[i],
                 entry.base_name);
    }

    // The three circles. Each list head is in the `PEB_LDR_DATA`, and the
    // order of the circles is the one Windows builds: the load-order list
    // runs image-first, and the memory-order and init-order lists run the
    // same way here, which is close enough to the truth for every walker
    // this file exists to serve -- the one thing a walker relies on is
    // that the *second* memory-order entry is `ntdll`, and it is.
    const std::uint64_t ldr = request.peb + 0x200;
    struct ListHead {
        std::uint64_t offset;  // in the PEB_LDR_DATA
        std::size_t link_off;  // in the entry
    };
    const ListHead heads[] = {
        {0x10, LdrEntryLayout::kInLoad},
        {0x20, LdrEntryLayout::kInMemory},
        {0x30, LdrEntryLayout::kInInit},
    };
    for (const ListHead& head : heads) {
        const std::uint64_t head_addr = ldr + head.offset;
        // head.Flink = first entry's link; head.Blink = last entry's link.
        // First entry: the image. Last: the final API module. The head
        // lives in the PEB, not in the entry region, so these two writes
        // go through the PEB pointer directly.
        const std::uint64_t first = region + entry_offsets.front() + head.link_off;
        const std::uint64_t last = region + entry_offsets.back() + head.link_off;
        std::memcpy(reinterpret_cast<void*>(head_addr), &first, 8);
        std::memcpy(reinterpret_cast<void*>(head_addr + 8), &last, 8);
        // first.Blink = head; last.Flink = head.
        write(entry_offsets.front() + head.link_off + 8, &head_addr, 8);
        write(entry_offsets.back() + head.link_off, &head_addr, 8);
        // The middle links: entry i.Flink = entry i+1's link, and entry
        // i+1.Blink = entry i's.
        for (std::size_t i = 0; i + 1 < entry_count; ++i) {
            const std::uint64_t a = region + entry_offsets[i] + head.link_off;
            const std::uint64_t b = region + entry_offsets[i + 1] + head.link_off;
            write(entry_offsets[i] + head.link_off, &b, 8);
            write(entry_offsets[i + 1] + head.link_off + 8, &a, 8);
        }
    }

    // The `PEB_LDR_DATA` header, in the PEB where the caller pointed at
    // it: the length the field declares, the flag that says the data is
    // initialized, and the handle field that is zero in every process that
    // has no reason for it not to be.
    const std::uint32_t ldr_length = kListHeadLength;
    std::memcpy(reinterpret_cast<void*>(ldr), &ldr_length, 4);
    const std::uint8_t initialized = 1;
    std::memcpy(reinterpret_cast<void*>(ldr + 4), &initialized, 1);
    static const std::uint64_t kSsHandle = 0;
    std::memcpy(reinterpret_cast<void*>(ldr + 8), &kSsHandle, 8);
    return true;
}

// ---------------------------------------------------------------------------
// The lookups
// ---------------------------------------------------------------------------

std::uint64_t module_base(std::string_view folded_name) noexcept {
    const auto& map = module_by_name();
    const auto it = map.find(std::string(folded_name));
    if (it == map.end()) {
        return 0;
    }
    return it->second.image.base;
}

std::uint64_t proc_address(std::uint64_t module_base, const char* name) noexcept {
    auto& by_base = module_by_base();
    const auto it = by_base.find(module_base);
    if (it == by_base.end()) {
        return 0;
    }
    // An ordinal ask travels as MAKEINTRESOURCE: the pointer's value is
    // the ordinal, and the ordinal names the function table's entry
    // directly -- `Base` is one, so the index is the ordinal minus one.
    const auto as_int = reinterpret_cast<std::uint64_t>(name);
    if (as_int <= 0xFFFFULL) {
        const std::uint32_t ordinal = static_cast<std::uint32_t>(as_int);
        if (ordinal == 0 || ordinal > it->second.image.exports.size()) {
            return 0;
        }
        // The exports vector is keyed by name; the ordinal's function is
        // the one at the same index the function table carries, which is
        // registration order minus duplicates. Rebuilt here as the index
        // walk the write path used.
        std::uint32_t index = 0;
        for (const auto& [fname, rva] : it->second.image.exports) {
            static_cast<void>(fname);
            if (index + 1 == ordinal) {
                return it->second.image.base + rva;
            }
            ++index;
        }
        return 0;
    }
    for (const auto& [fname, rva] : it->second.image.exports) {
        // Case-insensitive, the way every other export name is compared.
        std::string_view asked(name);
        if (asked.size() == fname.size()) {
            bool equal = true;
            for (std::size_t i = 0; i < asked.size(); ++i) {
                const char a = asked[i];
                const char b = fname[i];
                const char la =
                    (a >= 'A' && a <= 'Z') ? static_cast<char>(a - 'A' + 'a') : a;
                const char lb =
                    (b >= 'A' && b <= 'Z') ? static_cast<char>(b - 'A' + 'a') : b;
                if (la != lb) {
                    equal = false;
                    break;
                }
            }
            if (equal) {
                return it->second.image.base + rva;
            }
        }
    }
    return 0;
}

}  // namespace occ::runtime::guest_module

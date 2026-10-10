// Dumping the guest's image back out as a PE file.
//
// See the header for why the bytes are only here. This file is the
// mechanics: read the image's own headers, lay the sections out at their
// full virtual size, patch the section table to say where each landed,
// and write it out.

#include "occ/runtime/image_dump.h"

#include "occ/runtime/iat_rebuild.h"

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <vector>

namespace occ::runtime::image_dump {
namespace {

// The section table entry, as offsets. Named so the layout is stated once
// rather than spelled as numbers in three places, and placed here rather
// than beside the function that first used them -- the rebuild reads them
// too, and a constant belongs to its readers, not to its first user.
constexpr std::size_t kSectionSize = 40;
constexpr std::size_t kSectionVirtualSize = 0x08;
constexpr std::size_t kSectionVirtualAddress = 0x0C;
constexpr std::size_t kSectionRawSize = 0x10;
constexpr std::size_t kSectionRawPointer = 0x14;
constexpr std::size_t kSectionCharacteristics = 0x24;
// The data directory: eight bytes an entry, and the import table is the
// second -- the entry the rebuild writes and the entry it clears.
constexpr std::size_t kDirEntry = 8;
constexpr std::size_t kImportDirIndex = 1;

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

void wr16(std::uint8_t* p, std::size_t at, std::uint16_t v) noexcept {
    p[at] = static_cast<std::uint8_t>(v);
    p[at + 1] = static_cast<std::uint8_t>(v >> 8);
}

void wr32(std::uint8_t* p, std::size_t at, std::uint32_t v) noexcept {
    p[at] = static_cast<std::uint8_t>(v);
    p[at + 1] = static_cast<std::uint8_t>(v >> 8);
    p[at + 2] = static_cast<std::uint8_t>(v >> 16);
    p[at + 3] = static_cast<std::uint8_t>(v >> 24);
}

[[nodiscard]] std::uint64_t align_up(std::uint64_t value,
                                     std::uint64_t unit) noexcept {
    if (unit == 0) {
        return value;
    }
    return ((value + unit - 1) / unit) * unit;
}

// Rebuilds the import table inside the dump.
//
// A packed image has no import directory worth reading: it resolved its
// APIs at run time and called them through slots it filled itself. The
// scan answers which slots those are and what each holds; this turns that
// into the structure a PE loader reads.
//
// The layout is the standard one -- descriptors per DLL, an array of
// thunks per DLL for both the hints and the IAT, the hint/name entries,
// the DLL names -- placed in a new section appended past the image, and
// the data directory pointed at it. What makes it more than a table
// rewrite is the last step: the code's `call [rip+...]` sites are
// repointed at the rebuilt IAT, because the rebuilt table has no reason to
// keep the guest's own layout, and the code has to follow it. Without the
// repointing the file would load and the program would call its old slots,
// which a loader would not fill -- a dump that loads and then crashes,
// which is worse than one that does not load at all.
[[nodiscard]] bool rebuild_imports(
    std::vector<std::uint8_t>& out,
    const std::vector<occ::runtime::iat_rebuild::CallRef>& calls) noexcept {
    if (calls.empty()) {
        return true;
    }
    std::uint8_t* f = out.data();
    if (rd16(f, 0) != 0x5A4D) {
        return false;
    }
    const std::uint32_t pe_at = rd32(f, 0x3C);
    if (rd32(f, pe_at) != 0x00004550) {
        return false;
    }
    const std::uint16_t optional_size = rd16(f, pe_at + 20);
    const std::size_t optional = static_cast<std::size_t>(pe_at) + 24;
    const std::uint16_t magic = rd16(f, optional);
    if (magic != 0x20B && magic != 0x10B) {
        std::fprintf(stderr,
                     "occ dump: import rebuild is neither PE32 nor PE32+\n");
        return false;
    }
    const std::uint32_t section_align =
        rd32(f, optional + 0x20) == 0 ? 0x1000 : rd32(f, optional + 0x20);
    const std::uint32_t file_align =
        rd32(f, optional + 0x24) == 0 ? 0x200 : rd32(f, optional + 0x24);
    const std::uint32_t size_of_image = rd32(f, optional + 0x38);
    const std::uint32_t size_of_headers = rd32(f, optional + 0x3C);
    const std::uint16_t section_count = rd16(f, pe_at + 6);
    const std::size_t section_table =
        optional + static_cast<std::size_t>(optional_size);
    // 0x70 into the optional header is PE32+'s data directory; PE32's is
    // at 0x60, because its ImageBase is four bytes, not eight.
    const std::size_t directories =
        optional + (magic == 0x20B ? 0x70 : 0x60);

    // The slots, deduplicated and ordered; then grouped by the DLL each
    // name names. A descriptor speaks for one DLL, so the grouping is the
    // loader's, not ours.
    std::map<std::uint64_t, std::string> slot_name;
    for (const auto& call : calls) {
        slot_name.emplace(call.slot_rva, call.name);
    }
    struct Group {
        std::string dll;
        std::vector<std::pair<std::uint64_t, std::string>> funcs;
        std::uint64_t descriptor_off = 0;
        std::uint64_t int_off = 0;
        std::uint64_t iat_off = 0;
        std::uint64_t name_off = 0;
        std::vector<std::uint64_t> hint_offs;
    };
    std::vector<Group> groups;
    for (const auto& [slot_rva, full] : slot_name) {
        const std::size_t bang = full.find('!');
        if (bang == std::string::npos) {
            continue;
        }
        const std::string dll = full.substr(0, bang);
        const std::string func = full.substr(bang + 1);
        if (groups.empty() || groups.back().dll != dll) {
            // The slots come out of the scan in address order, so one test
            // against the previous group is the whole of the grouping: a
            // DLL whose slots interleave with another's opens a second
            // group, and the loader is fine with a DLL named twice.
            groups.push_back(Group{dll, {}, 0, 0, 0, 0, {}});
        }
        groups.back().funcs.emplace_back(slot_rva, func);
    }

    // Each group's descriptor owns twenty bytes of the array, at its own
    // offset. The aggregate that built these groups left every offset at
    // zero, and a rebuild that wrote them there would have all four groups
    // covering one another -- a reader would have seen the last group and
    // taken it for the whole table, which is exactly the wrong kind of
    // quiet: five functions where there are twenty-two, with no error to
    // notice.
    for (std::size_t gi = 0; gi < groups.size(); ++gi) {
        groups[gi].descriptor_off = gi * 20;
    }

    // The room the structures take, walked in the order they will be
    // written so the offsets answer twice from one walk.
    std::size_t cursor = (groups.size() + 1) * 20;  // descriptors + null
    for (Group& g : groups) {
        g.int_off = cursor;
        cursor += (g.funcs.size() + 1) * 8;
        g.iat_off = cursor;
        cursor += (g.funcs.size() + 1) * 8;
    }
    for (Group& g : groups) {
        g.name_off = cursor;
        cursor += g.dll.size() + 1;
        for (auto& [slot_rva, func] : g.funcs) {
            // IMAGE_IMPORT_BY_NAME: a two-byte hint, the name, the null.
            // Even alignment, because the entries pack two-byte fields.
            g.hint_offs.push_back(cursor);
            cursor += 2 + func.size() + 1;
            cursor = (cursor + 1) & ~static_cast<std::size_t>(1);
        }
    }
    cursor = (cursor + 15) & ~static_cast<std::size_t>(15);

    // Room for the section table's one more entry, inside the headers the
    // file already carries; a header block with no slack would need the
    // headers themselves moved, which is a different kind of rebuild.
    if (section_table +
            (static_cast<std::size_t>(section_count) + 1) * kSectionSize >
        size_of_headers) {
        std::fprintf(stderr,
                     "occ dump: no header room for a section entry; the "
                     "import table is left as the report\n");
        return false;
    }

    const std::uint64_t new_rva = align_up(size_of_image, section_align);
    const std::uint64_t new_virtual = align_up(cursor, section_align);
    const std::uint64_t raw_at = align_up(out.size(), file_align);
    const std::uint64_t raw_size = align_up(cursor, file_align);
    out.resize(static_cast<std::size_t>(raw_at + raw_size), 0);
    f = out.data();
    const std::uint8_t* base = f;  // for rva arithmetic below

    // The section table's new entry, and the counts that describe it.
    std::uint8_t* entry =
        f + section_table + static_cast<std::size_t>(section_count) * kSectionSize;
    std::memcpy(entry, ".occimp", 8);
    const std::size_t entry_off = static_cast<std::size_t>(entry - base);
    wr32(f, entry_off + kSectionVirtualSize, static_cast<std::uint32_t>(cursor));
    wr32(f, entry_off + kSectionVirtualAddress,
         static_cast<std::uint32_t>(new_rva));
    wr32(f, entry_off + kSectionRawSize, static_cast<std::uint32_t>(raw_size));
    wr32(f, entry_off + kSectionRawPointer, static_cast<std::uint32_t>(raw_at));
    wr32(f, entry_off + kSectionCharacteristics, 0x40000040);
    wr16(f, static_cast<std::size_t>(pe_at) + 6, section_count + 1);
    wr32(f, optional + 0x38,
         static_cast<std::uint32_t>(new_rva + new_virtual));

    // The descriptors, the thunk arrays, the hint/name entries and the
    // names, each at the offset the walk above assigned.
    const auto at = [&](std::uint64_t off) -> std::uint8_t* {
        return f + raw_at + off;
    };
    for (std::size_t g = 0; g < groups.size(); ++g) {
        Group& grp = groups[g];
        std::uint8_t* d = at(grp.descriptor_off);
        wr32(d, 0, static_cast<std::uint32_t>(new_rva + grp.int_off));
        wr32(d, 4, 0);
        wr32(d, 8, 0xFFFFFFFFu);
        wr32(d, 12, static_cast<std::uint32_t>(new_rva + grp.name_off));
        wr32(d, 16, static_cast<std::uint32_t>(new_rva + grp.iat_off));
        for (std::size_t i = 0; i < grp.funcs.size(); ++i) {
            const std::uint64_t name_rva = new_rva + grp.hint_offs[i];
            wr32(at(grp.int_off + i * 8), 0, static_cast<std::uint32_t>(name_rva));
            wr32(at(grp.iat_off + i * 8), 0, static_cast<std::uint32_t>(name_rva));
            std::uint8_t* hn = at(grp.hint_offs[i]);
            hn[0] = 0;
            hn[1] = 0;
            std::memcpy(hn + 2, grp.funcs[i].second.c_str(),
                        grp.funcs[i].second.size() + 1);
        }
        // The null terminators the arrays end with are already there: the
        // whole buffer was zeroed when it was grown.
        std::memcpy(at(grp.name_off), grp.dll.c_str(), grp.dll.size() + 1);
    }

    // The code follows the table. Every rip-relative reference the scan
    // found is repointed at its slot's new home, through the section table
    // of the file itself -- the RVAs the sites name are guest RVAs, and
    // the file's own layout is what says where those bytes are now.
    for (const auto& call : calls) {
        std::uint64_t iat_rva = 0;
        for (const Group& g : groups) {
            for (std::size_t i = 0; i < g.funcs.size(); ++i) {
                if (g.funcs[i].first == call.slot_rva) {
                    iat_rva = new_rva + g.iat_off + i * 8;
                    break;
                }
            }
        }
        if (iat_rva == 0) {
            continue;
        }
        // Site rva to file offset: the section whose virtual range holds
        // it, and that section's raw pointer.
        std::uint64_t file_off = 0;
        bool found = false;
        for (std::uint16_t s = 0; s < section_count && !found; ++s) {
            const std::uint8_t* se =
                f + section_table + static_cast<std::size_t>(s) * kSectionSize;
            const std::uint32_t va = rd32(se, kSectionVirtualAddress);
            const std::uint32_t vs = rd32(se, kSectionVirtualSize);
            if (call.site_rva >= va && call.site_rva < va + vs) {
                file_off = rd32(se, kSectionRawPointer) +
                           (call.site_rva - va);
                found = true;
            }
        }
        if (!found) {
            continue;
        }
        const std::int64_t disp =
            static_cast<std::int64_t>(iat_rva) -
            static_cast<std::int64_t>(call.site_rva + 6);
        wr32(f, static_cast<std::size_t>(file_off) + 2,
             static_cast<std::uint32_t>(disp));
    }

    // The import directory itself, and the old IAT directory cleared: it
    // described a table the file no longer has, and a loader that reads
    // both would be reading one of them wrong.
    wr32(f, directories + kImportDirIndex * kDirEntry,
         static_cast<std::uint32_t>(new_rva));
    wr32(f, directories + kImportDirIndex * kDirEntry + 4,
         static_cast<std::uint32_t>((groups.size() + 1) * 20));
    wr32(f, directories + 12 * kDirEntry, 0);
    wr32(f, directories + 12 * kDirEntry + 4, 0);

    std::fprintf(stderr,
                 "occ dump: import table rebuilt (%zu DLLs, %zu functions, "
                 "new section at rva 0x%llx)\n",
                 groups.size(), slot_name.size(),
                 static_cast<unsigned long long>(new_rva));
    return true;
}

}  // namespace

bool enabled() noexcept {
    static const bool on = [] {
        const char* value = ::getenv("OCC_DUMP_IMAGE");
        return value != nullptr && value[0] != '\0';
    }();
    return on;
}

std::string path() {
    const char* value = ::getenv("OCC_DUMP_IMAGE");
    return value != nullptr ? std::string(value) : std::string();
}

bool dump(std::uint64_t image_base, const std::string& out_path) noexcept {
    const auto* img = reinterpret_cast<const std::uint8_t*>(image_base);
    if (img == nullptr) {
        std::fprintf(stderr, "occ dump: no image to dump\n");
        return false;
    }
    if (rd16(img, 0) != 0x5A4D) {  // 'M'
        std::fprintf(stderr, "occ dump: no MZ at the image base\n");
        return false;
    }
    const std::uint32_t pe_at = rd32(img, 0x3C);
    if (rd32(img, pe_at) != 0x00004550) {  // "PE\0\0"
        std::fprintf(stderr, "occ dump: no PE signature at e_lfanew\n");
        return false;
    }

    const std::uint16_t section_count = rd16(img, pe_at + 6);
    const std::uint16_t optional_size = rd16(img, pe_at + 20);
    const std::size_t optional = static_cast<std::size_t>(pe_at) + 24;
    const std::uint16_t magic = rd16(img, optional);
    // Both optional-header layouts are dumped, and the whole difference
    // between them that this file cares about is where the data directory
    // sits: every other field it reads -- file alignment, size of headers,
    // the section table and its entries -- is at the same offset in both.
    // A PE32 dump was refused once on the grounds that the layouts differ;
    // they differ in one offset, and the refusal cost every 32-bit sample
    // -- which is most of the sample sets worth running -- its dump.
    if (magic != 0x20B && magic != 0x10B) {
        std::fprintf(stderr,
                     "occ dump: neither PE32 nor PE32+; this image says "
                     "0x%x\n",
                     static_cast<unsigned>(magic));
        return false;
    }
    const std::uint32_t file_align = rd32(img, optional + 0x24);
    const std::uint32_t size_of_headers = rd32(img, optional + 0x3C);
    const std::size_t section_table =
        optional + static_cast<std::size_t>(optional_size);

    // The header area has to hold the section table whatever the header
    // says: the size in the optional header is the linker's, and a file
    // whose table lands past it would lose the entries this code is about
    // to patch.
    const std::uint64_t headers_bytes =
        align_up(section_table + static_cast<std::size_t>(section_count) *
                                    kSectionSize > size_of_headers
                     ? section_table +
                           static_cast<std::size_t>(section_count) * kSectionSize
                     : size_of_headers,
                 file_align == 0 ? 0x200 : file_align);

    std::vector<std::uint8_t> out(static_cast<std::size_t>(headers_bytes), 0);
    std::memcpy(out.data(), img, static_cast<std::size_t>(headers_bytes));

    std::uint64_t cursor = headers_bytes;
    for (std::uint16_t i = 0; i < section_count; ++i) {
        const std::size_t entry =
            section_table + static_cast<std::size_t>(i) * kSectionSize;
        const std::uint32_t virtual_size = rd32(img, entry + kSectionVirtualSize);
        const std::uint32_t virtual_address =
            rd32(img, entry + kSectionVirtualAddress);
        if (virtual_size == 0) {
            // A section with no virtual size still takes an entry; it
            // simply carries no bytes, and its file fields say so.
            wr32(out.data(), entry + kSectionRawSize, 0);
            wr32(out.data(), entry + kSectionRawPointer, 0);
            continue;
        }

        // The bytes as the guest holds them -- this is the whole point of
        // the dump, since the file's copy is the encrypted one.
        const std::uint8_t* source = img + virtual_address;
        const std::uint64_t raw_size = align_up(virtual_size, file_align == 0
                                                                ? 0x200
                                                                : file_align);
        out.resize(static_cast<std::size_t>(cursor + raw_size), 0);
        std::memcpy(out.data() + cursor, source, virtual_size);
        wr32(out.data(), entry + kSectionRawSize,
             static_cast<std::uint32_t>(raw_size));
        wr32(out.data(), entry + kSectionRawPointer,
             static_cast<std::uint32_t>(cursor));
        cursor += raw_size;
    }

    // The imports, before the write: a rebuild appends a section and
    // repoints the code, and both have to be in the bytes the file gets.
    const auto calls = occ::runtime::iat_rebuild::collect(image_base);
    if (!calls.empty()) {
        static_cast<void>(rebuild_imports(out, calls));
    }

    std::FILE* file = std::fopen(out_path.c_str(), "wb");
    if (file == nullptr) {
        std::fprintf(stderr, "occ dump: cannot open %s for writing: %s\n",
                     out_path.c_str(), std::strerror(errno));
        return false;
    }
    const std::size_t written =
        std::fwrite(out.data(), 1, out.size(), file);
    std::fclose(file);
    if (written != out.size()) {
        std::fprintf(stderr, "occ dump: short write to %s\n", out_path.c_str());
        return false;
    }
    std::fprintf(stderr,
                 "occ dump: wrote %s (%zu bytes, %u sections mapped at their "
                 "virtual size)\n",
                 out_path.c_str(), out.size(),
                 static_cast<unsigned>(section_count));
    return true;
}

}  // namespace occ::runtime::image_dump

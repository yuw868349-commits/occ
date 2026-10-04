#include "occ/parser/elf.h"

#include "occ/util/string.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace occ::parser {

namespace {

// Field offsets in the ELF64 header, and the values the identification
// block has to hold for the 64-bit little-endian path. The reader is
// deliberately specific: it is the reader for the case the engine runs, and
// a general one would be a general one that is only tested on that case.
constexpr std::size_t kIdentSize = 16;
constexpr std::size_t kElf64HeaderSize = 64;
constexpr std::size_t kElf64PhdrSize = 56;
// The 64-bit section header. Sixty-four bytes, of which this reader uses
// nine fields; the two it does not use are still stepped over, which is why
// the record size is a constant here rather than a sum of the fields taken.
constexpr std::size_t kElf64ShdrSize = 64;
// One Elf64_Sym. st_name, st_info, st_other, st_shndx, st_value, st_size.
constexpr std::size_t kElf64SymSize = 24;

// Field offsets in the 64-bit header. The 32-bit layout puts e_phoff and
// e_phnum elsewhere, so these are named after the word size rather than
// shared with a reader for the other one.
constexpr std::size_t kOffType = 16;
constexpr std::size_t kOffMachine = 18;
constexpr std::size_t kOffEntry = 24;
constexpr std::size_t kOffPhoff = 32;
constexpr std::size_t kOffShoff = 40;
constexpr std::size_t kOffPhentsize = 54;
constexpr std::size_t kOffPhnum = 56;
constexpr std::size_t kOffShentsize = 58;
constexpr std::size_t kOffShnum = 60;
constexpr std::size_t kOffShstrndx = 62;

// Field offsets in the 64-bit section header.
constexpr std::size_t kOffShName = 0;
constexpr std::size_t kOffShType = 4;
constexpr std::size_t kOffShFlags = 8;
constexpr std::size_t kOffShAddr = 16;
constexpr std::size_t kOffShOffset = 24;
constexpr std::size_t kOffShSize = 32;
constexpr std::size_t kOffShLink = 40;
constexpr std::size_t kOffShInfo = 44;
constexpr std::size_t kOffShEntsize = 56;

// Field offsets in the 64-bit symbol.
constexpr std::size_t kOffStName = 0;
constexpr std::size_t kOffStInfo = 4;
constexpr std::size_t kOffStOther = 5;
constexpr std::size_t kOffStShndx = 6;
constexpr std::size_t kOffStValue = 8;
constexpr std::size_t kOffStSize = 16;

constexpr std::uint16_t kEmX86_64 = 62;
constexpr std::uint16_t kEtRel = 1;
constexpr std::uint16_t kEtExec = 2;
constexpr std::uint16_t kEtDyn = 3;
constexpr std::uint16_t kEtCore = 4;

// Rounds a value up to a power-of-two boundary without the arithmetic that
// overflows when the value is near the top of the address space. The
// expression (v + a - 1) & ~(a - 1) overflows for a v within a of
// UINT64_MAX, and a malformed file is exactly where such a value comes
// from.
std::uint64_t align_up_safe(std::uint64_t v, std::uint64_t a) noexcept {
    if (a <= 1) {
        return v;
    }
    const std::uint64_t rem = v & (a - 1);
    if (rem == 0) {
        return v;
    }
    const std::uint64_t delta = a - rem;
    if (v > UINT64_MAX - delta) {
        return UINT64_MAX;
    }
    return v + delta;
}

bool is_power_of_two(std::uint64_t v) noexcept {
    return v != 0 && (v & (v - 1)) == 0;
}

// The three readers below take an offset straight out of the file -- e_phoff,
// e_shoff, a section header's sh_offset -- so a malformed file chooses it,
// and the value can be any 64-bit number.
//
// The bound is therefore written as a subtraction rather than the more
// obvious "off + 4 > b.size()". Adding first wraps: an offset of
// 0xfffffffffffffffc makes off + 4 equal zero, the check passes, and the
// read that follows lands outside the buffer. Reading one byte before the
// start is not a crash and not a fault -- it is a value the parser then
// treats as a header field, which is the harder kind of wrong.
//
// Written the other way round, a huge offset fails the subtraction and the
// reader returns zero, which is what an absent field already returns. The
// two forms agree for every offset that does not wrap and disagree only for
// the offsets that would have been unsafe.
constexpr bool in_range(ByteSpan b, std::size_t off,
                        std::size_t width) noexcept {
    return off <= b.size() && b.size() - off >= width;
}

std::uint16_t rd16(ByteSpan b, std::size_t off) noexcept {
    if (!in_range(b, off, 2)) {
        return 0;
    }
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(b[off]) |
        (static_cast<std::uint16_t>(b[off + 1]) << 8));
}

std::uint32_t rd32(ByteSpan b, std::size_t off) noexcept {
    if (!in_range(b, off, 4)) {
        return 0;
    }
    return static_cast<std::uint32_t>(b[off]) |
           (static_cast<std::uint32_t>(b[off + 1]) << 8) |
           (static_cast<std::uint32_t>(b[off + 2]) << 16) |
           (static_cast<std::uint32_t>(b[off + 3]) << 24);
}

std::uint64_t rd64(ByteSpan b, std::size_t off) noexcept {
    if (!in_range(b, off, 8)) {
        return 0;
    }
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<std::uint64_t>(b[off + static_cast<std::size_t>(i)])
             << (8 * i);
    }
    return v;
}

std::string decimal(std::uint64_t v) {
    std::string out;
    append_uint(out, v);
    return out;
}

std::string hex_value(std::uint64_t v) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    if (v == 0) {
        return "0x0";
    }
    while (v != 0) {
        out.push_back(digits[v & 0xf]);
        v >>= 4;
    }
    out.push_back('x');
    out.push_back('0');
    std::reverse(out.begin(), out.end());
    return out;
}

} // namespace

const char* load_error_name(LoadError e) noexcept {
    switch (e) {
    case LoadError::None:
        return "none";
    case LoadError::NotElf:
        return "not an ELF object";
    case LoadError::UnsupportedClass:
        return "not a 64-bit object";
    case LoadError::UnsupportedEndian:
        return "not little-endian";
    case LoadError::UnsupportedMachine:
        return "not x86-64";
    case LoadError::TruncatedHeader:
        return "the header is truncated";
    case LoadError::TruncatedProgramHeaders:
        return "the program header table is truncated";
    case LoadError::NoLoadSegments:
        return "there is no loadable segment";
    case LoadError::BadAlignment:
        return "a segment has an alignment that is not a power of two";
    case LoadError::SegmentOutOfFile:
        return "a segment extends past the end of the file";
    case LoadError::TruncatedSectionHeaders:
        return "the section header table is truncated";
    }
    return "unknown";
}

const char* section_type_name(std::uint32_t type) noexcept {
    switch (static_cast<SectionType>(type)) {
    case SectionType::Null:
        return "SHT_NULL";
    case SectionType::ProgBits:
        return "SHT_PROGBITS";
    case SectionType::Symtab:
        return "SHT_SYMTAB";
    case SectionType::Strtab:
        return "SHT_STRTAB";
    case SectionType::Rela:
        return "SHT_RELA";
    case SectionType::Hash:
        return "SHT_HASH";
    case SectionType::Dynamic:
        return "SHT_DYNAMIC";
    case SectionType::Note:
        return "SHT_NOTE";
    case SectionType::Nobits:
        return "SHT_NOBITS";
    case SectionType::Rel:
        return "SHT_REL";
    case SectionType::Shlib:
        return "SHT_SHLIB";
    case SectionType::Dynsym:
        return "SHT_DYNSYM";
    case SectionType::InitArray:
        return "SHT_INIT_ARRAY";
    case SectionType::FiniArray:
        return "SHT_FINI_ARRAY";
    case SectionType::PreinitArray:
        return "SHT_PREINIT_ARRAY";
    case SectionType::Group:
        return "SHT_GROUP";
    case SectionType::SymtabShndx:
        return "SHT_SYMTAB_SHNDX";
    }
    // A type this reader does not name is still a type, and printing the
    // number is more use to a reader than printing "unknown" for every
    // vendor section a toolchain adds.
    return "a section type this reader does not name";
}

const char* symbol_visibility_name(std::uint8_t v) noexcept {
    // STV_*. The values are the ELF specification's, and 3 is STV_DEFAULT
    // rather than a reserved value: a symbol whose st_other says nothing
    // else is the ordinary exported one.
    switch (v) {
    case 0:
        return "STV_DEFAULT";
    case 1:
        return "STV_INTERNAL";
    case 2:
        return "STV_HIDDEN";
    case 3:
        return "STV_PROTECTED";
    }
    return "STV_DEFAULT";
}

const char* symbol_status_name(SymbolStatus s) noexcept {    switch (s) {
    case SymbolStatus::Found:
        return "found";
    case SymbolStatus::NoSectionTable:
        return "no section table";
    case SymbolStatus::NoDynamicSymbols:
        return "no dynamic symbols";
    case SymbolStatus::TruncatedTable:
        return "the symbol table is truncated";
    case SymbolStatus::NoStringTable:
        return "no string table for the symbols";
    }
    return "unknown";
}

const char* symbol_status_detail(SymbolStatus s) noexcept {
    switch (s) {
    case SymbolStatus::Found:
        return "";
    case SymbolStatus::NoSectionTable:
        return "the file has no section header table, so there is no "
               "dynamic symbol table to read and a function cannot be "
               "located by name; function-level observation is not "
               "available and syscall-level observation continues";
    case SymbolStatus::NoDynamicSymbols:
        return "the section header table holds no SHT_DYNSYM entry, so the "
               "file exports no dynamic symbols; function-level "
               "observation is not available and syscall-level "
               "observation continues";
    case SymbolStatus::TruncatedTable:
        return "the section header names a dynamic symbol table that is not "
               "inside the file; function-level observation is not "
               "available and syscall-level observation continues";
    case SymbolStatus::NoStringTable:
        return "the dynamic symbol table is present but its string table is "
               "not, so a symbol has an address and no name; "
               "function-level observation is not available and "
               "syscall-level observation continues";
    }
    return "";
}

ElfImage ElfImage::parse(ByteSpan bytes) noexcept {
    ElfImage out;

    if (bytes.size() < kIdentSize || bytes[0] != 0x7f || bytes[1] != 'E' ||
        bytes[2] != 'L' || bytes[3] != 'F') {
        out.error_ = LoadError::NotElf;
        out.detail_ = "the ELF magic is absent";
        return out;
    }

    if (bytes[4] != 2) {
        out.error_ = LoadError::UnsupportedClass;
        out.detail_ = "EI_CLASS is " + decimal(bytes[4]) +
                      "; only 2 (ELFCLASS64) is handled";
        return out;
    }
    if (bytes[5] != 1) {
        out.error_ = LoadError::UnsupportedEndian;
        out.detail_ = "EI_DATA is " + decimal(bytes[5]) +
                      "; only 1 (ELFDATA2LSB) is handled";
        return out;
    }
    if (bytes[6] != 1) {
        out.error_ = LoadError::NotElf;
        out.detail_ = "EI_VERSION is " + decimal(bytes[6]) +
                      "; the only defined value is 1";
        return out;
    }

    if (bytes.size() < kElf64HeaderSize) {
        out.error_ = LoadError::TruncatedHeader;
        out.detail_ = "the file is " + decimal(bytes.size()) +
                      " bytes and a 64-bit header needs " +
                      decimal(kElf64HeaderSize);
        return out;
    }

    out.type_ = rd16(bytes, kOffType);
    out.machine_ = rd16(bytes, kOffMachine);
    out.entry_ = rd64(bytes, kOffEntry);
    out.phoff_ = rd64(bytes, kOffPhoff);
    out.phentsize_ = rd16(bytes, kOffPhentsize);
    out.phnum_ = rd16(bytes, kOffPhnum);
    out.shoff_ = rd64(bytes, kOffShoff);
    out.shentsize_ = rd16(bytes, kOffShentsize);
    out.shnum_ = rd16(bytes, kOffShnum);
    out.shstrndx_ = rd16(bytes, kOffShstrndx);

    if (out.machine_ != kEmX86_64) {
        out.error_ = LoadError::UnsupportedMachine;
        out.detail_ = "e_machine is " + decimal(out.machine_) +
                      "; only 62 (EM_X86_64) is handled";
        return out;
    }

    switch (out.type_) {
    case kEtExec:
    case kEtDyn:
        break;
    case kEtRel:
        out.error_ = LoadError::NoLoadSegments;
        out.detail_ = "e_type is ET_REL; a relocatable object is not a "
                      "program and has no program header table";
        return out;
    case kEtCore:
        out.error_ = LoadError::NoLoadSegments;
        out.detail_ = "e_type is ET_CORE; a core file is not a program";
        return out;
    default:
        out.error_ = LoadError::NoLoadSegments;
        out.detail_ = "e_type is " + decimal(out.type_) + ", which is "
                      "neither ET_EXEC nor ET_DYN";
        return out;
    }

    if (out.phnum_ == 0) {
        out.error_ = LoadError::NoLoadSegments;
        out.detail_ = "e_phnum is 0";
        return out;
    }

    // The entry size has to be the size this reader steps by. A file that
    // declares a different one is either corrupt or for an ABI this reader
    // does not implement, and both are reasons to stop rather than to walk
    // the table with the wrong stride.
    if (out.phentsize_ != kElf64PhdrSize) {
        out.error_ = LoadError::TruncatedProgramHeaders;
        out.detail_ = "e_phentsize is " + decimal(out.phentsize_) +
                      " and this reader steps by " +
                      decimal(kElf64PhdrSize);
        return out;
    }

    // The table's end, computed so that it cannot wrap. phoff_ is a 64-bit
    // field from the file and phnum_ is up to 65535 entries of 56 bytes, so
    // phoff_ + phnum * 56 is an addition that a crafted file can push past
    // UINT64_MAX -- and a table_end that wrapped to a small number passes
    // the "is the table inside the file" test below while describing a
    // table that is not there at all.
    //
    // The subtraction form asks the question directly: is the file long
    // enough to hold phnum entries starting at phoff_? It cannot be made to
    // answer wrongly by choosing a large phoff_, because phoff_ is only
    // ever subtracted from a size it was already compared against.
    const std::size_t width =
        static_cast<std::size_t>(out.phnum_) * kElf64PhdrSize;
    if (out.phoff_ < kElf64HeaderSize ||
        out.phoff_ > bytes.size() ||
        bytes.size() - out.phoff_ < width) {
        const std::uint64_t end =
            out.phoff_ <= UINT64_MAX - width ? out.phoff_ + width
                                             : UINT64_MAX;
        out.error_ = LoadError::TruncatedProgramHeaders;
        out.detail_ = "the table runs from " + hex_value(out.phoff_) + " to " +
                      hex_value(end) + " and the file is " +
                      decimal(bytes.size()) + " bytes";
        return out;
    }

    out.headers_.reserve(out.phnum_);
    for (std::uint16_t i = 0; i < out.phnum_; ++i) {
        const std::size_t base =
            static_cast<std::size_t>(out.phoff_) +
            static_cast<std::size_t>(i) * kElf64PhdrSize;

        ProgramHeader h;
        // The 64-bit program header: p_type, p_flags, p_offset, p_vaddr,
        // p_paddr, p_filesz, p_memsz, p_align. Note that flags come second,
        // before the offsets, which is not the order the names suggest.
        h.type = static_cast<SegmentType>(rd32(bytes, base + 0));
        h.flags = rd32(bytes, base + 4);
        h.offset = rd64(bytes, base + 8);
        h.vaddr = rd64(bytes, base + 16);
        h.paddr = rd64(bytes, base + 24);
        h.filesz = rd64(bytes, base + 32);
        h.memsz = rd64(bytes, base + 40);
        h.align = rd64(bytes, base + 48);

        switch (h.type) {
        case SegmentType::Load:
            break;
        case SegmentType::Interp:
            out.has_interpreter_ = true;
            break;
        case SegmentType::GnuStack:
            out.stack_.present = true;
            out.stack_.executable = h.executable();
            out.stack_.size = h.memsz;
            break;
        case SegmentType::GnuRelro:
            out.has_relro_ = true;
            break;
        default:
            break;
        }

        out.headers_.push_back(h);
    }

    // A PT_INTERP names the dynamic loader. Its contents are read here so
    // that the engine can report which interpreter the target expects
    // without having to keep the file open.
    if (out.has_interpreter_) {
        for (const auto& h : out.headers_) {
            if (h.type != SegmentType::Interp) {
                continue;
            }
            // The bound is a subtraction for the reason given at the top of
            // the file: an offset and a size taken from the file can add to
            // more than SIZE_MAX, and a wrapped sum passes an "is it inside"
            // test while pointing nowhere near the file.
            if (h.filesz == 0 || h.offset > bytes.size() ||
                bytes.size() - h.offset <
                    static_cast<std::size_t>(h.filesz)) {
                out.error_ = LoadError::SegmentOutOfFile;
                out.detail_ = "PT_INTERP runs past the end of the file";
                return out;
            }
            const std::size_t len = static_cast<std::size_t>(h.filesz);
            const char* p =
                reinterpret_cast<const char*>(bytes.data() + h.offset);
            // The segment is a NUL-terminated path, and the terminator is
            // part of filesz.
            std::size_t n = 0;
            while (n < len && p[n] != '\0') {
                ++n;
            }
            out.interpreter_.assign(p, n);
            // A segment whose first byte is NUL names an empty path. That
            // is not a path, and reporting it as one is worse than reporting
            // nothing: the caller has been told there is an interpreter, so
            // it will execve whatever string is here -- and an empty string
            // is a valid argument to execve that fails at run time, in the
            // child, with an error that names the interpreter rather than
            // the file that had no path in it.
            //
            // The contradiction is refused here rather than papered over,
            // because has_interpreter() true with an empty interpreter() is
            // a state the rest of occ has no way to represent correctly.
            if (out.interpreter_.empty()) {
                out.has_interpreter_ = false;
                out.error_ = LoadError::SegmentOutOfFile;
                out.detail_ = "PT_INTERP names an empty path";
                return out;
            }
            break;
        }
    }

    // The mappings are derived from the PT_LOAD headers. The kernel's own
    // loader sorts them and merges what can be merged; this does the same,
    // because the alternative -- mapping each header separately -- produces
    // overlapping mappings whose permissions are whichever was mapped last.
    std::vector<ProgramHeader> loads;
    for (const auto& h : out.headers_) {
        if (h.type == SegmentType::Load) {
            loads.push_back(h);
        }
    }

    if (loads.empty()) {
        out.error_ = LoadError::NoLoadSegments;
        out.detail_ = "no program header has p_type PT_LOAD";
        return out;
    }

    std::sort(loads.begin(), loads.end(),
              [](const ProgramHeader& a, const ProgramHeader& b) {
                  return a.vaddr < b.vaddr;
              });

    for (const auto& h : loads) {
        if (h.align > 1 && !is_power_of_two(h.align)) {
            out.error_ = LoadError::BadAlignment;
            out.detail_ = "a PT_LOAD segment at " + hex_value(h.vaddr) +
                          " has p_align " + hex_value(h.align) +
                          ", which is not a power of two";
            return out;
        }
        // The congruent-offset rule from the ELF specification: a segment
        // whose filesz is non-zero has to satisfy offset = vaddr (mod
        // p_align), because the kernel maps whole pages and the file is
        // read from the rounded-down offset. A file that violates it would
        // be mapped with the wrong bytes at the start of the segment.
        if (h.filesz != 0 && h.align > 1 &&
            (h.offset % h.align) != (h.vaddr % h.align)) {
            out.error_ = LoadError::BadAlignment;
            out.detail_ = "a PT_LOAD segment at " + hex_value(h.vaddr) +
                          " has p_offset " + hex_value(h.offset) +
                          " and p_vaddr " + hex_value(h.vaddr) +
                          " that are not congruent modulo p_align " +
                          hex_value(h.align);
            return out;
        }
        // The file-backed extent, asked by subtraction. The header supplies
        // both numbers, so their sum is one a crafted file can push past
        // SIZE_MAX; a wrapped sum passes this test and describes a range
        // that is not in the file.
        if (h.filesz > 0 &&
            (h.offset > bytes.size() ||
             bytes.size() - h.offset < static_cast<std::size_t>(h.filesz))) {
            out.error_ = LoadError::SegmentOutOfFile;
            out.detail_ = "a PT_LOAD segment runs from " + hex_value(h.offset) +
                          " for " + hex_value(h.filesz) + " bytes and the "
                          "file is " + decimal(bytes.size()) + " bytes";
            return out;
        }
        if (h.memsz < h.filesz) {
            out.error_ = LoadError::SegmentOutOfFile;
            out.detail_ = "a PT_LOAD segment at " + hex_value(h.vaddr) +
                          " has p_memsz smaller than p_filesz";
            return out;
        }
        // The mapping a segment describes must exist in the address space.
        //
        // vaddr + memsz is what a caller adds to learn where the segment
        // ends, and it is the addition that decides whether the segment fits
        // at all. A vaddr of 0xfffffd0004000000 with a memsz of 0x7a0000000000
        // -- both entirely ordinary as numbers -- sums to a value below its
        // own start, and every consumer of that sum then reads a small number
        // as a length. The mmap would be made for a few bytes where the file
        // describes a petabyte.
        //
        // A memsz of zero is exempt for the same reason it is elsewhere: it
        // is a segment that maps nothing, and zero plus anything does not
        // wrap.
        if (h.memsz > 0 && h.memsz > UINT64_MAX - h.vaddr) {
            out.error_ = LoadError::SegmentOutOfFile;
            out.detail_ = "a PT_LOAD segment at " + hex_value(h.vaddr) +
                          " has p_memsz " + hex_value(h.memsz) +
                          ", which does not fit above it in the address space";
            return out;
        }
    }

    out.lowest_vaddr_ = loads.front().vaddr;
    std::uint64_t high = 0;
    for (const auto& h : loads) {
        // The span a segment occupies, rounded out to whole pages. Both
        // roundings saturate rather than wrap -- align_up_safe returns
        // UINT64_MAX for a value it cannot round up -- so the sum of the two
        // is what has to be watched: two saturated values add to a small
        // one, and highest_vaddr_ is a bound that a caller sizes a mapping
        // from.
        //
        // A pair that cannot be added is the address space's own end, which
        // is the honest answer for a segment that claims to run to it.
        const std::uint64_t start = align_up_safe(h.vaddr, kPageSize);
        const std::uint64_t len = align_up_safe(h.memsz, kPageSize);
        const std::uint64_t end =
            len > UINT64_MAX - start ? UINT64_MAX : start + len;
        if (end > high) {
            high = end;
        }
    }
    out.highest_vaddr_ = high;

    for (const auto& h : loads) {
        DesiredMapping m;
        m.file_offset = h.offset;
        m.vaddr = h.vaddr;
        m.filesz = h.filesz;
        m.memsz = h.memsz;
        m.flags = h.flags;
        out.mappings_.push_back(m);
    }

    // The section table is read after the program headers and cannot change
    // whether the image loaded. That ordering is the whole point: a kernel
    // loader never reads these, so a file whose sections are corrupt is a
    // file the kernel will map, and refusing to describe it would be
    // refusing a running program over metadata.
    //
    // The two tables are separate for a reason that shows up here. A
    // section header says where a file's own bookkeeping lives; a program
    // header says what to map. A file can be missing either one and still
    // be the other kind of thing, and an image that is both has told us
    // two independent facts.
    out.read_sections(bytes, out.sections_, out.shoff_, out.shentsize_,
                      out.shnum_);

    if (out.sections_.empty()) {
        out.symbol_status_ = SymbolStatus::NoSectionTable;
        out.symbol_detail_ = symbol_status_detail(SymbolStatus::NoSectionTable);
    } else {
        out.read_dynamic_symbols(bytes);
    }

    out.error_ = LoadError::None;
    return out;
}

std::string ElfImage::section_name(const SectionHeader& s,
                                   ByteSpan bytes) const {
    // sh_name indexes the section name string table, which e_shstrndx
    // names. It is not sh_link: for a symbol table sh_link points at the
    // table that names the *symbols*, and reading a section's own name out
    // of that one produces a name made of unrelated bytes -- which is a
    // plausible-looking string rather than an obvious failure, and is the
    // hardest kind of wrong to notice by reading the output.
    //
    // e_shstrndx is a section header table index and is used as the header
    // states it. It is a zero-based index, so the 30th entry is 30.
    // e_shstrndx names the section name table, and it is used here as the
    // index into this vector that it is. The section header table is
    // zero-based, and the value in the file is the index of the name table
    // within it: a file whose table holds 31 entries writes 30 for the last
    // one, and that 30 is the 30th element of this vector, not the 29th.
    //
    // Subtracting one selects the section before the name table -- a real
    // section, with a real sh_offset, whose bytes are whatever that
    // section holds. The failure mode is a plausible string rather than an
    // empty one, which is the kind of wrong that a test with only one
    // fixture cannot see, and is why the fixtures below cover the table's
    // own position explicitly.
    if (shstrndx_ == 0 || shstrndx_ >= sections_.size()) {
        return {};
    }
    const SectionHeader& names = sections_[shstrndx_];
    if (names.type != static_cast<std::uint32_t>(SectionType::Strtab) ||
        names.size == 0) {
        return {};
    }
    if (names.offset > bytes.size() ||
        bytes.size() - names.offset < s.name_offset) {
        return {};
    }
    const std::size_t base = static_cast<std::size_t>(names.offset);
    const std::size_t limit = base + static_cast<std::size_t>(names.size);
    if (limit > bytes.size()) {
        return {};
    }
    const char* p =
        reinterpret_cast<const char*>(bytes.data()) + base + s.name_offset;
    // A name runs to the NUL or to the end of the table, whichever comes
    // first. The bound matters: the last section in a file has a name
    // table that ends where the file's own data ends, and reading past the
    // limit would run into whatever follows.
    std::size_t n = 0;
    while (base + s.name_offset + n < limit && p[n] != '\0') {
        ++n;
    }
    if (n == 0) {
        return {};
    }
    return std::string(p, n);
}

void ElfImage::read_sections(ByteSpan bytes, std::vector<SectionHeader>& out,
                             std::uint64_t shoff, std::uint16_t shentsize,
                             std::uint16_t shnum) noexcept {
    out.clear();

    // A file with no section table says so with e_shoff zero and e_shnum
    // zero. Both, or either: a table at offset zero cannot be a real table
    // because the ELF header occupies the first bytes, so either being zero
    // is enough to conclude there is none and there is nothing to
    // second-guess.
    if (shoff == 0 || shnum == 0) {
        return;
    }

    // The stride has to be the record size. A file that declares another one
    // is either corrupt or for an ABI this reader does not implement, and
    // walking the table with the wrong stride produces entries that are
    // each individually well-formed and collectively nonsense.
    if (shentsize != kElf64ShdrSize) {
        return;
    }

    // The table's end, asked by subtraction for the reason given in parse():
    // shoff is a 64-bit field from the file and shnum is up to 65535 records
    // of 64 bytes, and their sum is an addition a crafted file can push
    // past the end of the address space. Subtracting from the size asks
    // whether the file is long enough to hold the table, and shoff is only
    // ever subtracted from a size it was already compared against.
    const std::size_t width =
        static_cast<std::size_t>(shnum) * kElf64ShdrSize;
    if (shoff > bytes.size() ||
        bytes.size() - static_cast<std::size_t>(shoff) < width) {
        return;
    }

    out.reserve(shnum);
    for (std::uint16_t i = 0; i < shnum; ++i) {
        const std::size_t base = static_cast<std::size_t>(shoff) +
                                 static_cast<std::size_t>(i) * kElf64ShdrSize;
        SectionHeader s;
        s.name_offset = rd32(bytes, base + kOffShName);
        s.type = rd32(bytes, base + kOffShType);
        s.flags = rd64(bytes, base + kOffShFlags);
        s.addr = rd64(bytes, base + kOffShAddr);
        s.offset = rd64(bytes, base + kOffShOffset);
        s.size = rd64(bytes, base + kOffShSize);
        s.link = rd32(bytes, base + kOffShLink);
        s.info = rd32(bytes, base + kOffShInfo);
        s.entsize = rd64(bytes, base + kOffShEntsize);
        out.push_back(s);
    }
}

void ElfImage::read_dynamic_symbols(ByteSpan bytes) noexcept {
    // Two places name the dynamic symbol table, and they are read in this
    // order for a reason.
    //
    // SHT_DYNSYM is the section header, and it is the direct one: it says
    // the size, the stride and where the strings are in a single record.
    //
    // PT_DYNAMIC's DT_SYMTAB and DT_STRTAB are the program headers, and
    // they are the fallback because they survive something the section
    // headers do not. A file processed by a tool that rewrites the section
    // table can end up with a .dynsym section header that names nothing,
    // while the dynamic segment -- which the dynamic linker itself reads,
    // and cannot do without -- still points at the table. Reading the
    // section header first and the dynamic segment second means a file that
    // still works gets its symbols, and a file that does not is reported
    // rather than guessed at.
    //
    // The one thing neither can supply is the count, because neither
    // DT_SYMTAB nor the section header says how many symbols there are. It
    // comes from the section header's size when there is one, and from
    // DT_SYMENT when the count has to be derived, and the derivation is
    // bounded below by the string table's own offset: a symbol table cannot
    // run past the strings that name it, because the linker put them
    // together.
    struct TableLocation {
        std::uint64_t offset = 0;
        std::uint64_t count = 0;
        std::uint64_t str_offset = 0;
        std::uint64_t str_size = 0;
        bool have_offset = false;
        bool have_str = false;
    } loc;

    for (const SectionHeader& s : sections_) {
        if (s.type != static_cast<std::uint32_t>(SectionType::Dynsym)) {
            continue;
        }
        loc.offset = s.offset;
        // sh_entsize is the stride. A zero means the record size, which is
        // what the specification says and what a linker that does not need
        // a non-default stride leaves behind. A stride that is neither zero
        // nor the record size is a table this reader would misread, so it
        // contributes no count rather than a wrong one.
        const std::uint64_t stride = s.entsize == 0 ? kElf64SymSize : s.entsize;
        if (stride == kElf64SymSize) {
            loc.count = s.size / stride;
        }
        loc.have_offset = true;
        if (s.link < sections_.size()) {
            const SectionHeader& strtab = sections_[s.link];
            if (strtab.type == static_cast<std::uint32_t>(SectionType::Strtab)) {
                loc.str_offset = strtab.offset;
                loc.str_size = strtab.size;
                loc.have_str = true;
            }
        }
        break;
    }

    if (!loc.have_offset || !loc.have_str) {
        // Try the dynamic segment. This is not a fallback for a file with no
        // sections at all -- read_sections returns early in that case and
        // the caller never gets here -- it is a fallback for a file whose
        // sections do not name the table.
        for (const ProgramHeader& h : headers_) {
            if (h.type != SegmentType::Dynamic) {
                continue;
            }
            if (h.offset > bytes.size() ||
                bytes.size() - static_cast<std::size_t>(h.offset) <
                    static_cast<std::size_t>(h.filesz)) {
                break;
            }
            // Elf64_Dyn is a 16-byte pair of a tag and a value. The tags
            // below are the ones that matter here.
            constexpr std::uint64_t kDtNull = 0;
            constexpr std::uint64_t kDtStrtab = 5;
            constexpr std::uint64_t kDtSyment = 11;
            constexpr std::uint64_t kDtSymtab = 6;
            constexpr std::uint64_t kDtStrsz = 10;

            std::uint64_t symtab = 0;
            std::uint64_t strtab_v = 0;
            std::uint64_t strsz = 0;
            std::uint64_t syment = kElf64SymSize;
            bool have_symtab = false;
            bool have_strtab = false;

            const std::size_t entries =
                static_cast<std::size_t>(h.filesz) / 16;
            for (std::size_t i = 0; i < entries; ++i) {
                const std::size_t base =
                    static_cast<std::size_t>(h.offset) + i * 16;
                const std::uint64_t tag = rd64(bytes, base);
                const std::uint64_t val = rd64(bytes, base + 8);
                if (tag == kDtNull) {
                    break;
                }
                if (tag == kDtSymtab) {
                    symtab = val;
                    have_symtab = true;
                } else if (tag == kDtStrtab) {
                    strtab_v = val;
                    have_strtab = true;
                } else if (tag == kDtStrsz) {
                    strsz = val;
                } else if (tag == kDtSyment && val != 0) {
                    syment = val;
                }
            }

            if (!have_symtab || !have_strtab) {
                break;
            }
            // DT_SYMTAB and DT_STRTAB are virtual addresses, not file
            // offsets, even though they sit in a program header. The
            // conversion is the same one a probe needs and the same one that
            // can fail, and it is done with the segment list rather than by
            // assuming a load bias, because the load bias is a property of
            // the process and the file does not know it.
            std::uint64_t sym_off = 0;
            std::uint64_t str_off = 0;
            if (!vaddr_to_file_offset(symtab, sym_off) ||
                !vaddr_to_file_offset(strtab_v, str_off)) {
                break;
            }
            loc.offset = sym_off;
            loc.str_offset = str_off;
            loc.str_size = strsz;
            loc.have_offset = true;
            loc.have_str = true;
            // The count. With no section header to say it, the table runs
            // from DT_SYMTAB to the start of the string table, which is the
            // next thing in the file that could follow it. Where the
            // dynamic segment's own view and the file's layout disagree,
            // the smaller count is the one that cannot be wrong: a symbol
            // read past a real end is a fabricated function, and a symbol
            // not read because the count was short is a missing name.
            if (syment == 0) {
                syment = kElf64SymSize;
            }
            const std::uint64_t span =
                str_off > sym_off ? str_off - sym_off : 0;
            loc.count = span / syment;
            break;
        }
    }

    if (!loc.have_offset) {
        symbol_status_ = SymbolStatus::NoDynamicSymbols;
        symbol_detail_ = symbol_status_detail(SymbolStatus::NoDynamicSymbols);
        return;
    }
    if (!loc.have_str) {
        symbol_status_ = SymbolStatus::NoStringTable;
        symbol_detail_ = symbol_status_detail(SymbolStatus::NoStringTable);
        return;
    }

    // The table's own extent, as a subtraction. loc.offset is a file offset
    // that came either from a section header or from a converted address,
    // and in both cases the file is the thing that decides whether it is
    // inside.
    if (loc.offset > bytes.size() ||
        loc.str_offset > bytes.size() ||
        loc.count > (UINT64_MAX / kElf64SymSize) ||
        bytes.size() - static_cast<std::size_t>(loc.offset) <
            static_cast<std::size_t>(loc.count * kElf64SymSize)) {
        symbol_status_ = SymbolStatus::TruncatedTable;
        symbol_detail_ = symbol_status_detail(SymbolStatus::TruncatedTable);
        return;
    }
    if (loc.str_size == 0) {
        // A string table of zero length is a table with no names in it,
        // which is the same uselessness as having no table: every name
        // lookup would return empty and a caller would conclude the file
        // exports nothing, which is a different claim from "this file's
        // names are not here to be read".
        symbol_status_ = SymbolStatus::NoStringTable;
        symbol_detail_ = symbol_status_detail(SymbolStatus::NoStringTable);
        return;
    }
    if (loc.str_offset > bytes.size() ||
        bytes.size() - static_cast<std::size_t>(loc.str_offset) <
            static_cast<std::size_t>(loc.str_size)) {
        symbol_status_ = SymbolStatus::NoStringTable;
        symbol_detail_ = symbol_status_detail(SymbolStatus::NoStringTable);
        return;
    }

    symbols_.clear();
    symbols_.reserve(static_cast<std::size_t>(loc.count));

    const char* str_base = reinterpret_cast<const char*>(bytes.data()) +
                           static_cast<std::size_t>(loc.str_offset);
    const std::size_t str_limit = static_cast<std::size_t>(loc.str_size);

    for (std::uint64_t i = 0; i < loc.count; ++i) {
        const std::size_t base =
            static_cast<std::size_t>(loc.offset) +
            static_cast<std::size_t>(i) * kElf64SymSize;

        Symbol sym;
        const std::uint32_t name_off = rd32(bytes, base + kOffStName);
        const std::uint8_t info =
            static_cast<std::uint8_t>(rd32(bytes, base + kOffStInfo) & 0xff);
        const std::uint8_t other =
            static_cast<std::uint8_t>(rd32(bytes, base + kOffStOther) & 0xff);
        sym.shndx = static_cast<std::uint16_t>(
            rd32(bytes, base + kOffStShndx) & 0xffff);
        sym.visibility = static_cast<std::uint8_t>(other & 0x03);
        sym.value = rd64(bytes, base + kOffStValue);
        sym.size = rd64(bytes, base + kOffStSize);
        // st_info is two nibbles: the binding in the high four bits and
        // the type in the low four. Both are read here rather than by the
        // caller so that a caller asking "is this a function" does not have
        // to know the packing, and so that a Symbol's answer cannot
        // disagree with its type.
        sym.bind = static_cast<SymbolBind>(info >> 4);
        sym.type = static_cast<SymbolType>(info & 0x0f);

        // A name offset past the string table is a table that has been
        // truncated in the middle of a name. The symbol is kept with an
        // empty name rather than dropped: its address is real and a caller
        // probing by address rather than by name would otherwise lose a
        // probe point that was there.
        if (name_off < str_limit) {
            const char* p = str_base + name_off;
            std::size_t n = 0;
            while (name_off + n < str_limit && p[n] != '\0') {
                ++n;
            }
            sym.name.assign(p, n);
        }

        // The first symbol of a table is all zeroes by definition and names
        // nothing. It is not an error and it is not a symbol, so it is not
        // stored; storing it would put an unnamed entry with a zero address
        // into a list a caller iterates looking for probe points.
        if (i == 0 && name_off == 0 && sym.value == 0) {
            continue;
        }

        symbols_.push_back(std::move(sym));
    }

    symbol_status_ = SymbolStatus::Found;
    symbol_detail_.clear();
}

const Symbol* ElfImage::find_symbol(std::string_view name) const {
    // The best match wins, and the ranking is by what a caller can do with
    // the answer.
    //
    // A probeable symbol is what a caller asking for a name almost always
    // wants: it is a defined function at a real address, which is the one
    // thing a probe can be attached to. A defined symbol that is not
    // probeable is second -- it exists in code or data and the caller can
    // be told what it is. An undefined symbol is last, and it is returned
    // rather than hidden: a name in the table with no code behind it is a
    // different answer from a name that is not in the table at all, and a
    // caller that received "not found" for the first would look for the
    // symbol where it is not.
    const Symbol* best = nullptr;
    int best_rank = -1;
    for (const Symbol& s : symbols_) {
        if (s.name != name) {
            continue;
        }
        const int rank = s.probeable() ? 2 : (s.defined() ? 1 : 0);
        if (rank > best_rank) {
            best = &s;
            best_rank = rank;
            if (rank == 2) {
                // Nothing can beat a probeable symbol, so the search can
                // stop at the first one.
                return best;
            }
        }
    }
    return best;
}

bool ElfImage::vaddr_to_file_offset(std::uint64_t vaddr,
                                    std::uint64_t& out) const {
    for (const auto& h : headers_) {
        if (h.type != SegmentType::Load) {
            continue;
        }
        // The segment is [vaddr, vaddr + memsz). Both ends come from the
        // file and the second is an addition that can wrap, so the
        // containment is asked as a subtraction from the start. A memsz of
        // zero makes the segment empty and it contains nothing, which is
        // what the check below says without a special case.
        if (vaddr < h.vaddr || vaddr - h.vaddr >= h.memsz) {
            continue;
        }
        // Past filesz the segment is memory that was never in the file: the
        // .bss tail, zeroed by the loader. There is no byte there and so no
        // byte to probe. Returning false rather than clamping to the end of
        // the file is the honest answer -- clamping would produce an offset
        // that is inside the file and belongs to a different byte, and a
        // probe there would fire on the wrong instruction with nothing to
        // say so.
        if (vaddr - h.vaddr >= h.filesz) {
            return false;
        }
        // The offset is p_offset + (vaddr - p_vaddr). p_offset is a file
        // offset that the parser has already checked lies inside the file,
        // and the delta is bounded by filesz, so the sum is bounded by the
        // end of the segment -- but the sum is still formed, and a segment
        // at the very top of the address space with a large p_offset could
        // in principle exceed the file. A load segment's file extent was
        // validated, so this cannot happen for a file that parsed; the
        // subtraction is kept so the reasoning holds if that ever changes.
        const std::uint64_t delta = vaddr - h.vaddr;
        if (delta > h.filesz || h.offset > UINT64_MAX - delta) {
            return false;
        }
        out = h.offset + delta;
        return true;
    }
    return false;
}

} // namespace occ::parser

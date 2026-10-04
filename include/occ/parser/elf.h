#pragma once

// ELF image reader.
//
// The loader reads an ELF file and turns it into a description of what has
// to be mapped where. It does not perform the mapping: that is the engine's
// job, and keeping the two apart means the parser can be tested against
// files without any of them being executed.
//
// The reader is complete for ELF64 little-endian x86-64, which is the case
// the exe engine runs, and it reports what it cannot handle rather than
// reading a file it only half understands. A partial parse of an ELF file
// is worse than no parse: the fields that were skipped are exactly the ones
// that would have changed the answer.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "occ/util/span.h"

namespace occ::parser {

// The ELF types this reader understands. They mirror the ident block and
// header fields but are scoped to this namespace so that a caller does not
// have to include the whole detection API to read a header.
enum class ElfClass : std::uint8_t;
enum class ElfEndian : std::uint8_t;
enum class ElfMachine : std::uint16_t;
enum class ElfType : std::uint16_t;

// p_type
enum class SegmentType : std::uint32_t {
    Null = 0,
    Load = 1,
    Dynamic = 2,
    Interp = 3,
    Note = 4,
    Shlib = 5,
    Phdr = 6,
    Tls = 7,
    GnuEhFrame = 0x6474e550,
    GnuStack = 0x6474e551,
    GnuRelro = 0x6474e552,
    GnuProperty = 0x6474e553,
};

// p_flags
inline constexpr std::uint32_t kPfExec = 1;
inline constexpr std::uint32_t kPfWrite = 2;
inline constexpr std::uint32_t kPfRead = 4;

// PT_GNU_STACK and PT_GNU_RELRO are the two program headers that carry
// security-relevant information rather than a loadable region.
struct StackRequest {
    bool present = false;
    bool executable = false;
    std::uint64_t size = 0;
};

struct ProgramHeader {
    SegmentType type = SegmentType::Null;
    std::uint32_t flags = 0;
    // Offsets are into the file; addresses are where the segment wants to
    // live in the process.
    std::uint64_t offset = 0;
    std::uint64_t vaddr = 0;
    std::uint64_t paddr = 0;
    std::uint64_t filesz = 0;
    std::uint64_t memsz = 0;
    std::uint64_t align = 0;

    [[nodiscard]] bool readable() const noexcept {
        return (flags & kPfRead) != 0;
    }
    [[nodiscard]] bool writable() const noexcept {
        return (flags & kPfWrite) != 0;
    }
    [[nodiscard]] bool executable() const noexcept { return (flags & kPfExec) != 0; }

    // The part of the segment that exists in the file but not in memory is
    // the tail of .bss, and it has to be zeroed rather than copied.
    [[nodiscard]] std::uint64_t zero_tail() const noexcept {
        return memsz > filesz ? memsz - filesz : 0;
    }
};

// Where a loadable segment has to be placed. One DesiredMapping is produced
// per PT_LOAD program header, after the headers have been sorted and the
// overlaps resolved.
struct DesiredMapping {
    std::uint64_t file_offset = 0;
    std::uint64_t vaddr = 0;
    std::uint64_t filesz = 0;
    // The region from vaddr + filesz to vaddr + memsz has to be zeroed. It
    // may span more than one page, and the page boundary that separates it
    // from the file-backed part is the one the kernel rounds to.
    std::uint64_t memsz = 0;
    std::uint32_t flags = 0;
};

enum class LoadError : std::uint8_t {
    None,
    NotElf,
    UnsupportedClass,
    UnsupportedEndian,
    UnsupportedMachine,
    TruncatedHeader,
    TruncatedProgramHeaders,
    NoLoadSegments,
    BadAlignment,
    SegmentOutOfFile,
    // The section header table is not where the header says it is. This is
    // a distinct error from TruncatedProgramHeaders because it costs
    // nothing the loader needs: a binary with no readable section table
    // still runs, and refusing to load it would be refusing a working
    // program over a table the kernel does not read either.
    TruncatedSectionHeaders,
};

[[nodiscard]] const char* load_error_name(LoadError e) noexcept;

// One entry of the section header table. The fields kept are the ones a
// caller acts on; sh_flags and sh_addralign are read and skipped because
// walking a 64-byte record needs their positions even when nothing wants
// their values.
struct SectionHeader {
    // The offset of the name in the section's string table, not the name.
    // Resolving it needs sh_link, so a caller that wants names goes through
    // ElfImage::section_name rather than reading this and stringifying it.
    std::uint32_t name_offset = 0;
    std::uint32_t type = 0;
    std::uint64_t flags = 0;
    std::uint64_t addr = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::uint32_t link = 0;
    std::uint32_t info = 0;
    std::uint64_t entsize = 0;
};

// The section types this reader acts on. SHT_DYNSYM is the one that matters:
// a function-level probe needs an address, an address comes from a symbol,
// and the symbols an executable exports are the dynamic ones.
enum class SectionType : std::uint32_t {
    Null = 0,
    ProgBits = 1,
    Symtab = 2,
    Strtab = 3,
    Rela = 4,
    Hash = 5,
    Dynamic = 6,
    Note = 7,
    Nobits = 8,
    Rel = 9,
    Shlib = 10,
    Dynsym = 11,
    InitArray = 14,
    FiniArray = 15,
    PreinitArray = 16,
    Group = 17,
    SymtabShndx = 18,
};

[[nodiscard]] const char* section_type_name(std::uint32_t type) noexcept;

// How a symbol is bound and typed. The two nibbles share one byte in
// st_info, and separating them here means a caller does not shift.
enum class SymbolBind : std::uint8_t { Local = 0, Global = 1, Weak = 2 };
enum class SymbolType : std::uint8_t {
    NoType = 0,
    Object = 1,
    Func = 2,
    Section = 3,
    File = 4,
};

struct Symbol {
    std::string name;
    // The address the symbol is at, as a virtual address in the image. For
    // a probe this is what has to be converted to a file offset, because
    // the kernel's uprobe request is stated in file offsets and not in
    // addresses.
    std::uint64_t value = 0;
    std::uint64_t size = 0;
    // The index of the section the symbol is defined in. Zero is
    // SHN_UNDEF, which is the one value here that is an answer rather than
    // an index: an undefined symbol has an address in a table and no code
    // behind it, and a probe on one fires on nothing.
    std::uint16_t shndx = 0;
    // st_other's low two bits, which are the symbol's visibility. It is
    // kept because a hidden or internal symbol is still in .dynsym and is
    // still a place a trap can be placed, and because a caller filtering
    // probes by visibility needs it to be told the difference rather than
    // having every local symbol look exported.
    std::uint8_t visibility = 0;
    SymbolBind bind = SymbolBind::Local;
    SymbolType type = SymbolType::NoType;

    [[nodiscard]] bool defined() const noexcept { return shndx != 0; }
    [[nodiscard]] bool is_function() const noexcept {
        return type == SymbolType::Func;
    }
    // STV_HIDDEN and STV_INTERNAL name symbols that are not in the
    // dynamic symbol table's normal sense -- a linker has already resolved
    // every reference to them. They are reported rather than filtered: the
    // table has them, and a caller that wants only exported ones asks.
    [[nodiscard]] bool hidden() const noexcept {
        return visibility == 2 || visibility == 1;
    }
    [[nodiscard]] bool visible() const noexcept { return !hidden(); }
    // A probe target has to be a defined function. An object, an
    // undefined name and a zero-size function are all things a symbol
    // table can contain and none of them is something to attach a probe to.
    [[nodiscard]] bool probeable() const noexcept {
        return defined() && is_function() && value != 0;
    }
};

[[nodiscard]] const char* symbol_visibility_name(std::uint8_t v) noexcept;

// What a symbol lookup found. A distinct answer for "the table is not
// there" rather than an empty vector, because the two mean different things
// to a caller: a name that is absent from a readable table is a question
// answered, and a table that could not be read is an observation that could
// not be made.
enum class SymbolStatus : std::uint8_t {
    // The dynamic symbol table was read.
    Found,
    // The file has no section header table at all, so there is nothing to
    // find a symbol table through. A stripped-to-nothing file.
    NoSectionTable,
    // The section headers are readable and none of them is SHT_DYNSYM. This
    // is what a file whose exports were made local looks like.
    NoDynamicSymbols,
    // The table is named by a section header that is not inside the file.
    TruncatedTable,
    // The table is inside the file but its string table is not, so a name
    // could be read as an offset into nothing.
    NoStringTable,
};

[[nodiscard]] const char* symbol_status_name(SymbolStatus s) noexcept;

// Why a symbol table could not be read, in a sentence. Empty when it could.
[[nodiscard]] const char* symbol_status_detail(SymbolStatus s) noexcept;

// The parsed image. Reading is done entirely from a byte range, so the
// caller decides where the bytes came from.
class ElfImage {
public:
    // Parses `bytes`. On failure the returned object is in the NotElf state
    // and `error()` names the reason.
    [[nodiscard]] static ElfImage parse(ByteSpan bytes) noexcept;

    [[nodiscard]] bool ok() const noexcept { return error_ == LoadError::None; }
    [[nodiscard]] LoadError error() const noexcept { return error_; }
    [[nodiscard]] const std::string& error_detail() const noexcept {
        return detail_;
    }

    [[nodiscard]] std::uint16_t machine() const noexcept { return machine_; }
    [[nodiscard]] std::uint16_t type() const noexcept { return type_; }
    [[nodiscard]] std::uint64_t entry() const noexcept { return entry_; }
    [[nodiscard]] std::uint64_t phoff() const noexcept { return phoff_; }
    [[nodiscard]] std::uint16_t phnum() const noexcept { return phnum_; }
    [[nodiscard]] std::uint16_t phentsize() const noexcept {
        return phentsize_;
    }

    [[nodiscard]] const std::vector<ProgramHeader>& headers() const noexcept {
        return headers_;
    }
    [[nodiscard]] const std::vector<DesiredMapping>& mappings() const noexcept {
        return mappings_;
    }
    [[nodiscard]] const StackRequest& stack() const noexcept { return stack_; }

    // The lowest virtual address any PT_LOAD segment occupies. The loader
    // uses this to decide whether the image is non-relocatable, which is
    // what distinguishes an ET_EXEC from a PIE.
    [[nodiscard]] std::uint64_t lowest_vaddr() const noexcept {
        return lowest_vaddr_;
    }
    [[nodiscard]] std::uint64_t highest_vaddr() const noexcept {
        return highest_vaddr_;
    }
    [[nodiscard]] bool has_interpreter() const noexcept {
        return has_interpreter_;
    }
    [[nodiscard]] const std::string& interpreter() const noexcept {
        return interpreter_;
    }
    [[nodiscard]] bool has_gnu_relro() const noexcept { return has_relro_; }

    // True when the image asks for an executable stack. Reported rather
    // than silently honoured, because a target that needs one is a fact the
    // caller has to decide about.
    [[nodiscard]] bool wants_executable_stack() const noexcept {
        return stack_.present && stack_.executable;
    }

    // -------------------------------------------------------------- symbols
    //
    // Everything below here is optional in a way the program headers are
    // not. A missing or unreadable section table costs a caller the ability
    // to resolve a symbol by name; it costs nothing about what the image
    // asks the kernel to map, so it does not make ok() false. A reader that
    // failed the whole image over it would refuse to describe a program the
    // kernel will happily run, and the refusal would name a table that has
    // no bearing on the question.

    [[nodiscard]] const std::vector<SectionHeader>& sections() const noexcept {
        return sections_;
    }

    // What the symbol lookup can and cannot do. Found is the only value
    // that means names resolve; the rest are the ways it can fail, and each
    // is a fact about the file rather than a single "no symbols" that a
    // caller cannot act on.
    [[nodiscard]] SymbolStatus symbol_status() const noexcept {
        return symbol_status_;
    }
    [[nodiscard]] const std::string& symbol_detail() const noexcept {
        return symbol_detail_;
    }
    [[nodiscard]] bool has_symbols() const noexcept {
        return symbol_status_ == SymbolStatus::Found;
    }

    // Every dynamic symbol, in table order. Empty unless has_symbols().
    [[nodiscard]] const std::vector<Symbol>& dynamic_symbols() const noexcept {
        return symbols_;
    }

    // The name of a section. sh_name is an offset into the *section name*
    // table -- the one e_shstrndx names -- and not into whatever table
    // sh_link happens to point at. sh_link means different things for
    // different section types: for a symbol table it is the strings that
    // name the symbols, and using it here would read a symbol's name out of
    // the wrong table and produce a section called whatever bytes sit at
    // that offset. e_shstrndx is stored rather than taken from the caller
    // because it is a property of the file and every section in the file
    // resolves its name through the same one.
    [[nodiscard]] std::string section_name(const SectionHeader& s,
                                           ByteSpan bytes) const;

    // The named dynamic symbol, or nullptr. Prefers a defined function over
    // an undefined one of the same name, because a caller asking for
    // "memcpy" wants the one with code behind it -- an undefined memcpy is
    // an import the loader has not satisfied yet, and probing its recorded
    // address would place a trap on nothing.
    [[nodiscard]] const Symbol* find_symbol(std::string_view name) const;

    // Converts a virtual address to the file offset a probe request needs.
    //
    // This exists because the two are not the same number and confusing
    // them is silent. The kernel's uprobe request names a byte in the file;
    // a symbol table names an address in the process. The conversion is
    // only defined inside a PT_LOAD segment's file-backed part, and a
    // virtual address in a segment's zero tail has no file offset at all --
    // it is memory that was never in the file, and there is no byte to
    // probe.
    //
    // Returns false for an address in no segment, in a segment's zero tail,
    // or in a segment with no file backing. On false, `out` is untouched.
    [[nodiscard]] bool vaddr_to_file_offset(std::uint64_t vaddr,
                                            std::uint64_t& out) const;

private:
    // Reads the section header table. Fills `out` with what is inside the
    // file and leaves it empty when the table is not there or is not
    // readable; a caller distinguishes those through symbol_status, because
    // "no table" and "a table that could not be read" are different facts
    // and a probe layer needs to say which.
    void read_sections(ByteSpan bytes, std::vector<SectionHeader>& out,
                       std::uint64_t shoff, std::uint16_t shentsize,
                       std::uint16_t shnum) noexcept;
    // Reads .dynsym and the string table it points at. Sets
    // symbol_status_ and symbol_detail_ to describe what happened, which is
    // why this is separate from read_sections: the sections can be fine and
    // the symbols still unavailable.
    void read_dynamic_symbols(ByteSpan bytes) noexcept;

    // The section header count and the file offset, kept from the header so
    // the section walk does not re-read them and so a caller can report
    // where the table claimed to be.
    std::uint64_t shoff_ = 0;
    std::uint16_t shentsize_ = 0;
    std::uint16_t shnum_ = 0;
    // e_shstrndx, which names the table every section's own name lives in.
    // It is an index into the section header table and is used as such:
    // zero is the specification's SHN_UNDEF and means there is no such
    // table, which is a file with section headers and no names for them.
    std::uint16_t shstrndx_ = 0;
    LoadError error_ = LoadError::NotElf;
    std::string detail_;

    std::uint16_t machine_ = 0;
    std::uint16_t type_ = 0;
    std::uint64_t entry_ = 0;
    std::uint64_t phoff_ = 0;
    std::uint16_t phnum_ = 0;
    std::uint16_t phentsize_ = 0;

    std::vector<ProgramHeader> headers_;
    std::vector<DesiredMapping> mappings_;
    StackRequest stack_;

    // The section table and what was read out of it. The sections are kept
    // whole because a caller resolving a section by type needs to see the
    // table rather than the answer, and the symbols are kept alongside them
    // because resolving one needs the string table, which is itself a
    // section.
    std::vector<SectionHeader> sections_;
    std::vector<Symbol> symbols_;
    SymbolStatus symbol_status_ = SymbolStatus::NoSectionTable;
    std::string symbol_detail_;

    std::uint64_t lowest_vaddr_ = 0;
    std::uint64_t highest_vaddr_ = 0;
    bool has_interpreter_ = false;
    std::string interpreter_;
    bool has_relro_ = false;
};

// Page helpers. The loader works in pages because the kernel does, and
// rounding in one place rather than at each call site is what keeps the
// mapping sizes consistent.
inline constexpr std::uint64_t kPageSize = 4096;
[[nodiscard]] inline std::uint64_t page_floor(std::uint64_t v) noexcept {
    return v & ~(kPageSize - 1);
}
[[nodiscard]] inline std::uint64_t page_ceil(std::uint64_t v) noexcept {
    return (v + kPageSize - 1) & ~(kPageSize - 1);
}

} // namespace occ::parser

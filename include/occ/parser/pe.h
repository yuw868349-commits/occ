#pragma once

// PE image reader.
//
// The companion to parser/elf.h, and deliberately the same shape: a static
// parse() over a byte range, an ok() that says whether the headers held
// together, an error() that names which part did not, and accessors for every
// field. A caller that has read one of these knows how to read the other.
//
// The format is read here, not executed. Everything in this file answers
// questions about the file: what machine it is for, whether it is a DLL, where
// its entry point is, which sections are writable, which DLLs it imports.
// Running one is a separate layer (engine/pe_engine.cpp), and the boundary is
// where the DESIGN.md L177ff division falls: Occ supplies the isolation and
// the observation, Wine supplies the loader.
//
// Two things about the format drive the shape of the reader.
//
// The first is that a PE file is not laid out the way it is addressed. The
// file is a sequence of sections, each with a file offset and a size, and the
// program addresses them by RVA -- a different coordinate system entirely.
// Nothing in the headers states the conversion; it is derived by finding the
// section whose VirtualAddress range contains the RVA. to_file_offset() is that
// derivation, and it is the single most misused piece of PE knowledge in
// practice, so it is a named function here rather than arithmetic at each
// call site.
//
// The second is that almost every field is an offset or a count chosen by the
// file, and the structures they locate are variable-length. e_lfanew points
// at the COFF header; the optional header's size is declared separately from
// its content; the data directories are counted by a field whose value need
// not match the space available. A reader written as though the format were
// trustworthy is a reader that can be walked off the end of the buffer by a
// file that is not.
//
// So every bound below is a subtraction. "off + 4 > size" is the obvious way
// to write it and it is wrong: both operands come from the file, their sum
// wraps, a wrapped check passes, and the read after it is out of bounds. The
// fuzz harness under fuzz/ exists to hold that line.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "occ/util/span.h"

namespace occ::parser {

// The machine values the reader names. Anything else is reported through
// PeImage::machine_raw() rather than being forced into one of these, because
// "some machine this build does not know" and "x86" are different facts and
// collapsing them produces a refusal that names the wrong reason.
enum class PeMachine : std::uint16_t {
    Unknown = 0x0000,
    I386 = 0x014c,
    Arm = 0x01c0,
    Amd64 = 0x8664,
    Arm64 = 0xaa64,
};

[[nodiscard]] const char* pe_machine_name(PeMachine m) noexcept;

// Whether this is an image or a library. The distinction decides whether the
// engine can exec it at all, so it is a separate answer rather than a flag on
// the machine.
enum class PeKind : std::uint8_t { None, Executable, Dll };

// The subsystem field from the optional header. A console program and a
// windowed one are both valid targets and an analysis rarely cares which, so
// this is reported rather than acted on.
enum class PeSubsystem : std::uint16_t {
    Unknown = 0,
    Native = 1,
    WindowsGui = 2,
    WindowsCui = 3,
    Os2Cui = 5,
    PosixCui = 7,
    NativeWindows = 8,
    WindowsCeGui = 9,
    EfiApplication = 10,
    EfiBootServiceDriver = 11,
    EfiRuntimeDriver = 12,
    EfiRom = 13,
    Xbox = 14,
    WindowsBootApplication = 16,
};

[[nodiscard]] const char* pe_subsystem_name(PeSubsystem s) noexcept;

enum class PeError : std::uint8_t {
    None,
    // No MZ signature, or the PE signature was not where e_lfanew said.
    NotPe,
    // The MZ header claims to be longer than the file is.
    TruncatedDosHeader,
    // e_lfanew is outside the file, or is odd. A PE header is
    // pointer-aligned, and an unaligned one is a file whose layout this
    // reader has no reason to guess at.
    BadHeaderOffset,
    TruncatedCoffHeader,
    // SizeOfOptionalHeader does not cover the fields the reader needs. A
    // truncated optional header is a distinct fact from a truncated COFF
    // header and names a different repair.
    TruncatedOptionalHeader,
    // The optional header's magic is neither PE32 (0x10b) nor PE32+ (0x20b).
    UnknownOptionalMagic,
    TruncatedSectionTable,
    NoSections,
    // A section's raw extent is outside the file. A PE can legitimately have
    // sections with no raw data at all -- uninitialized data, .bss -- so this
    // is about a section that claims data the file does not have.
    BadSectionTable,
    // A data directory's RVA does not resolve to anywhere in the file.
    DirectoryOutOfFile,
    TruncatedImportTable,
    // The export directory declares fewer bytes than one 40-byte directory
    // record needs. A distinct fact from a truncated import table, and naming
    // a different repair: a DLL with an unusable export directory still has an
    // import table a loader can walk, and treating the two the same would
    // refuse a file whose problem is confined to the half nobody imports by.
    TruncatedExportDirectory,
    // One of the export directory's three tables -- addresses, names, or name
    // ordinals -- resolves to somewhere the file does not cover, or an entry
    // inside one of them names a string that will not read.
    //
    // Refused rather than reported as "no exports". An export directory that
    // is present and unreadable is a different claim from one that is absent,
    // and a reader that conflates them turns a broken DLL into a DLL with no
    // exports -- which is a thing a program can act on.
    BadExportTable,
    // SizeOfHeaders claims more of the file than the file has. This is not
    // a wrong number, it is a reclassification: the value decides which of
    // the two coordinate systems an RVA belongs to, so a file that overstates
    // it has every address in its image reclassified as a file offset. The
    // file is refused rather than reported, because there is no correct answer
    // to give about a file whose headers cannot be where it says they are.
    BadHeaderSize,
};

[[nodiscard]] const char* pe_error_name(PeError e) noexcept;

// A section header, as the file states it. The names are the section names
// (.text, .rdata, ...) which are advisory: nothing in the format requires
// them and a packer will rewrite them, so nothing here depends on one.
struct PeSection {
    // Up to eight bytes, NUL-padded and not necessarily NUL-terminated. The
    // stored form is kept alongside the string because a name that used the
    // full eight bytes is a real case and truncating it silently would make
    // two different sections look alike.
    char raw_name[8] = {};
    std::string name;

    // The size in memory and the size in the file, which are different
    // numbers and are routinely different in one direction or the other. A
    // section with virtual_size greater than raw_size has trailing zero-fill;
    // the reverse means the tail is not mapped.
    std::uint32_t virtual_size = 0;
    std::uint32_t virtual_address = 0;
    std::uint32_t raw_size = 0;
    std::uint32_t raw_offset = 0;

    // How much of the address space this section occupies, which is not always
    // `virtual_size`.
    //
    // `VirtualSize` of zero is legal and means "as much as the file holds",
    // which is what every linker emits for a section whose contents are
    // entirely file-backed -- there is nothing to zero-fill, so there is no
    // size to state. A PE that says zero is not malformed and a parser that
    // treats it as an empty section is wrong: it makes the section's whole
    // address range unaddressable, so an RVA that the Windows loader maps
    // resolves to nothing here, and everything downstream -- an import
    // descriptor, a relocation, a string the image reads at run time -- is
    // reported as absent from a file that contains it.
    //
    // The fallback is to the raw size and not to a page, because the rule is
    // about how much *file* there is to map, and rounding up to a page here
    // would claim address space beyond what the file provides.
    [[nodiscard]] std::uint64_t mapped_size() const noexcept {
        return virtual_size != 0 ? virtual_size : raw_size;
    }

    // The characteristics bitfield. Reported as a raw value with three
    // accessors rather than as a struct, because the bits that matter for
    // analysis are a subset and a reader that models all of them invites
    // someone to depend on the rest.
    std::uint32_t characteristics = 0;

    // IMAGE_SCN_MEM_EXECUTE / WRITE / READ.
    [[nodiscard]] bool executable() const noexcept;
    [[nodiscard]] bool writable() const noexcept;
    [[nodiscard]] bool readable() const noexcept;

    // The highest address this section occupies, and the highest file offset
    // it reaches. Both computed once at parse so that a caller asking the
    // question does not repeat the comparison that could overflow.
    std::uint64_t virtual_end() const noexcept;
    std::uint64_t raw_end() const noexcept;
};

// One entry of a PE's export table, as the file states it.
//
// The three fields that make up an export are the name, the ordinal and the
// RVA, and they come from three different arrays in the file. The ordinal in
// particular is not stored in the file as the number a caller would call an
// ordinal: the name-ordinal table holds an *index* into the address table,
// and the number a program imports by is that index plus the directory's
// base. What is recorded here is the number as the outside world sees it,
// because a caller asking "what is exported as Sleep" wants the ordinal that
// an import would name, not the offset of its entry.
//
// A forwarder is a fourth thing, and it is the one place where "the RVA of an
// export" is not an address of anything in this image. A forwarder's RVA
// points at a string inside the export directory itself, and that string
// names a symbol in a different DLL. It is kept as the parsed target rather
// than as the string because a string here would be a second thing to
// re-parse, and a re-parse is where a reader and a caller would come to
// disagree about which of several dots separates the DLL from the symbol.
struct PeExport {
    // The public name, or empty for an export that has none. A PE is allowed
    // to give some, all or none of its exports a name, and an unnamed one is
    // reachable by ordinal alone. An empty name is therefore a fact about the
    // export and not a failure to read it.
    std::string name;

    // The ordinal as the outside world sees it: the address table's index
    // plus the directory's base. Two things follow from that arithmetic being
    // done here rather than by the caller. A base of zero is legal in the
    // format, and a file that states one gets it honored rather than being
    // treated as though ordinals must start at one. And the sum is taken in a
    // type that holds it, so a file claiming a base near the top of the 32-bit
    // range does not produce an ordinal that wrapped.
    std::uint32_t ordinal = 0;

    // The address of the export, relative to the image base. Zero means the
    // slot has no export in it, which the format uses for a symbol that was
    // removed but whose slot was kept so the ordinals after it do not move.
    // A zero here is not a forwarder to address zero and not a missing value;
    // it is an index that was deliberately left empty.
    std::uint32_t rva = 0;

    // Whether this export is a forwarder, which is decided by the address
    // falling inside the export directory rather than by any bit in the
    // table. The three fields below are then the parsed form of the string
    // at `rva`.
    bool is_forwarder = false;

    // The DLL a forwarder names and the symbol it names there. The DLL part
    // is kept as the file spells it, without case folding: the operating
    // system's loader does not fold it either, and a reader that normalized
    // it would resolve a name the operating system would not.
    std::string forwarder_dll;
    std::string forwarder_name;

    // Which of the two a forwarder names. By name is the common case;
    // "KERNEL32.#27" is the other and carries a number instead of a name.
    bool forwarder_by_ordinal = false;
    std::uint32_t forwarder_ordinal = 0;
};

class PeImage {
public:
    [[nodiscard]] static PeImage parse(ByteSpan bytes) noexcept;

    [[nodiscard]] bool ok() const noexcept { return error_ == PeError::None; }
    [[nodiscard]] PeError error() const noexcept { return error_; }
    [[nodiscard]] const std::string& error_detail() const noexcept {
        return detail_;
    }

    [[nodiscard]] PeKind kind() const noexcept { return kind_; }
    [[nodiscard]] bool is_dll() const noexcept {
        return kind_ == PeKind::Dll;
    }
    [[nodiscard]] PeMachine machine() const noexcept { return machine_; }
    // The raw machine word, for a machine this build does not name. Reported
    // so that a refusal can say what it saw instead of only that it saw
    // something unfamiliar.
    [[nodiscard]] std::uint16_t machine_raw() const noexcept {
        return machine_raw_;
    }
    [[nodiscard]] PeSubsystem subsystem() const noexcept { return subsystem_; }
    [[nodiscard]] std::uint16_t subsystem_raw() const noexcept {
        return subsystem_raw_;
    }

    // True for the 64-bit optional header, false for the 32-bit one. Almost
    // every field below differs in width between the two, so a caller that
    // formats an address needs to know which it is looking at.
    [[nodiscard]] bool is_pe32_plus() const noexcept { return plus_; }
    [[nodiscard]] std::size_t optional_header_size() const noexcept {
        return opt_size_;
    }

    [[nodiscard]] std::uint64_t entry_rva() const noexcept { return entry_; }
    [[nodiscard]] std::uint64_t image_base() const noexcept { return base_; }
    [[nodiscard]] std::uint32_t image_size() const noexcept { return image_size_; }
    [[nodiscard]] std::uint32_t headers_size() const noexcept {
        return headers_size_;
    }
    [[nodiscard]] std::uint32_t section_alignment() const noexcept {
        return section_align_;
    }
    [[nodiscard]] std::uint32_t file_alignment() const noexcept {
        return file_align_;
    }
    [[nodiscard]] std::uint64_t entry_va() const noexcept {
        return base_ + entry_;
    }

    [[nodiscard]] std::uint16_t section_count() const noexcept {
        return section_count_;
    }
    [[nodiscard]] const std::vector<PeSection>& sections() const noexcept {
        return sections_;
    }

    // The three hardening questions, kept apart because they come from
    // different words and a reader that folds them into one "is it safe"
    // answer is answering a question nobody asked.
    [[nodiscard]] bool dynamic_base() const noexcept { return aslr_; }
    [[nodiscard]] bool nx_compat() const noexcept { return nx_; }
    [[nodiscard]] bool high_entropy_va() const noexcept { return hev_; }
    [[nodiscard]] bool has_seh() const noexcept { return seh_; }

    // The RVA-to-file-offset conversion.
    //
    // Four regions, and they are not the same question in each:
    //
    //   rva < headers_size          the headers, which are at the front of
    //                               the file and need no section
    //   within virtual_address .. + virtual_size     the section, if the RVA
    //                               is below virtual_address + raw_size
    //   within virtual_address .. + virtual_size     zero fill, if above
    //   otherwise                    in no section
    //
    // Returns true only for the second and third, because a caller asking
    // where to read a byte of the file is asking about file-backed content:
    // handing back an offset into zero-fill would send it to a region that
    // was never read from the file and produces a zero where a byte was.
    // The mapping matters for the loader, and the loader builds it from the
    // sections directly.
    [[nodiscard]] bool to_file_offset(std::uint64_t rva,
                                      std::uint64_t& out) const noexcept;

    // The same conversion without the file-backed restriction, for a caller
    // reasoning about the loaded image rather than about the file. Returns
    // false only when the RVA is in no section at all.
    [[nodiscard]] bool resolve_rva(std::uint64_t rva,
                                   std::uint64_t& file_offset,
                                   bool& zero_filled) const noexcept;

    // The imported DLL names, in the order the import directory lists them.
    // A PE with no imports is normal; a PE whose import directory RVA is set
    // but resolves to nothing is reported through error(), not silently
    // turned into an empty list, because the two mean different things.
    [[nodiscard]] const std::vector<std::string>& imports() const noexcept {
        return imports_;
    }

    // The exports, in address-table order -- which is the order the ordinals
    // are assigned in, so `exports()[i].ordinal` is the ordinal of the export
    // at index i, biased by the directory's base. That order is not the order
    // of the names, and the two are not required to correspond: an export may
    // have no name, and two names may share one entry only through the
    // name-ordinal table's saying so.
    //
    // A slot the address table leaves at zero produces no entry here. That is
    // a real gap in the sequence -- the ordinals on either side of it are not
    // adjacent -- and a caller that indexes this vector by ordinal has to ask
    // rather than assume. `export_ordinal_base()` is provided for exactly
    // that, and it is the only way to recover the ordinal of an entry without
    // trusting the array's position.
    [[nodiscard]] const std::vector<PeExport>& exports() const noexcept {
        return exports_;
    }

    // The first ordinal this image uses, which is the directory's base field.
    // Ordinarily 1, but the format only says it is "usually" 1, and a file
    // that says otherwise is a file this reader reports rather than corrects.
    // A caller turning a name into an ordinal, or the reverse, needs this; the
    // arithmetic is done in the reader so that it is done the same way once.
    [[nodiscard]] std::uint32_t export_ordinal_base() const noexcept {
        return export_base_;
    }

    // The export directory, as an RVA and a size, reported the way the
    // relocations are. The size matters to a caller and not to this reader:
    // an export whose RVA falls inside the directory is a forwarder rather
    // than an address, and that test needs the extent, not just the start.
    [[nodiscard]] std::uint64_t export_rva() const noexcept {
        return export_rva_;
    }
    [[nodiscard]] std::uint32_t export_size() const noexcept {
        return export_size_;
    }

    // The base relocation directory, reported rather than parsed. A
    // relocation reader is a larger piece of work and nothing in the engine
    // needs its contents -- what matters for analysis is that a reloc table
    // exists and how big it is.
    [[nodiscard]] std::uint64_t reloc_rva() const noexcept { return reloc_rva_; }
    [[nodiscard]] std::uint32_t reloc_size() const noexcept { return reloc_size_; }

private:
    // The number of bytes the parse was given. Kept because the conversions
    // above have to ask whether an offset is inside the file, and the
    // alternative would be threading the span through every one of them.
    std::size_t bytes_size_ = 0;

    // A NUL-terminated string at an RVA, resolved through the same
    // conversion. A name with no terminator inside the file, or one longer
    // than any real name, is refused rather than returned as a fragment.
    [[nodiscard]] bool read_rva_string(ByteSpan bytes, std::uint64_t rva,
                                       std::string& out) const noexcept;
    // The same, from a file offset, for a caller that already resolved one.
    [[nodiscard]] static bool read_cstring(ByteSpan bytes, std::size_t off,
                                          std::string& out) noexcept;

    PeError error_ = PeError::NotPe;
    std::string detail_;

    PeKind kind_ = PeKind::None;
    PeMachine machine_ = PeMachine::Unknown;
    std::uint16_t machine_raw_ = 0;
    PeSubsystem subsystem_ = PeSubsystem::Unknown;
    std::uint16_t subsystem_raw_ = 0;
    bool plus_ = false;
    std::size_t opt_size_ = 0;

    std::uint64_t entry_ = 0;
    std::uint64_t base_ = 0;
    std::uint32_t image_size_ = 0;
    std::uint32_t headers_size_ = 0;
    std::uint32_t section_align_ = 0;
    std::uint32_t file_align_ = 0;
    std::uint16_t section_count_ = 0;
    std::uint32_t characteristics_ = 0;

    bool aslr_ = false;
    bool nx_ = false;
    bool hev_ = false;
    bool seh_ = false;

    std::uint64_t reloc_rva_ = 0;
    std::uint32_t reloc_size_ = 0;
    std::uint32_t import_rva_ = 0;
    std::uint32_t import_size_ = 0;
    std::uint64_t export_rva_ = 0;
    std::uint32_t export_size_ = 0;
    std::uint32_t export_base_ = 0;

    // Whether SizeOfHeaders actually reaches past the section table. A file
    // can declare a region smaller than the headers this reader parsed out of
    // it -- a linker with an unusual section ordering, or a file that has
    // been edited. It is recorded rather than refused, because the conversion
    // is bounded by the file's length either way and refusing would reject
    // files that load. Reported so a caller that cares can see it.
    bool headers_cover_table_ = true;

    std::vector<PeSection> sections_;
    std::vector<std::string> imports_;
    // The parsed export table. Declared after the imports because the two are
    // read in that order, and a reader that kept its state in reading order
    // would be easier to check against the file layout than one that did not.
    std::vector<PeExport> exports_;
};

} // namespace occ::parser

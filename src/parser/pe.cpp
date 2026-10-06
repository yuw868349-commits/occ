#include "occ/parser/pe.h"

#include "occ/util/string.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace occ::parser {

namespace {

// --------------------------------------------------------------- layout

// Every offset and size in this file is one of two things: a constant from
// the specification, or a value the file chose. The constants are collected
// here so that the reader reads as a walk over the structure rather than as
// arithmetic scattered through it -- and so that a field at the wrong offset
// is a change in one line rather than a hunt.

// The DOS header. Every PE begins with one, so it is also where detection
// happens, and the two fields the reader needs are the only two this format
// guarantees beyond the signature.
constexpr std::size_t kDosHeaderSize = 64;
constexpr std::size_t kOffDosMagic = 0;
constexpr std::size_t kOffELfanew = 0x3c; // the only field past the 0x40 stub

constexpr std::uint16_t kDosMagic = 0x5a4d; // "MZ", little-endian

// The PE signature, the four bytes at e_lfanew that say the COFF header
// follows. Checked separately from the COFF header because a file can have
// the right magic at the wrong place, and "not a PE" and "a PE with a broken
// header" are different answers.
constexpr std::size_t kPeSignatureSize = 4;
constexpr std::uint32_t kPeSignature = 0x00004550; // "PE\0\0"

constexpr std::size_t kCoffHeaderSize = 20;
constexpr std::size_t kOffCoffMachine = 0;
constexpr std::size_t kOffCoffSectionCount = 2;
constexpr std::size_t kOffCoffOptionalSize = 16;
constexpr std::size_t kOffCoffCharacteristics = 18;

// IMAGE_FILE_DLL. The one characteristic bit that changes what the image is
// rather than how it was built.
constexpr std::uint16_t kCharDll = 0x2000;

// The optional header's magic distinguishes the two layouts. Everything after
// the shared prefix differs in width, which is why the reader branches on
// this instead of parameterising.
constexpr std::size_t kMagicPe32 = 0x10b;
constexpr std::size_t kMagicPe32Plus = 0x20b;

// The optional header's shared prefix. These offsets are the same in both
// layouts; from kOff32Base below, the widths diverge.
constexpr std::size_t kOffOptMagic = 0;
constexpr std::size_t kOffOptEntry = 16;

// PE32 after the prefix. ImageBase is four bytes here and eight in PE32+,
// and SizeOfImage/SizeOfHeaders/SizeOfOptionalHeader stay 32-bit in both.
constexpr std::size_t kOff32Base = 28;
constexpr std::size_t kOff32SectionAlign = 32;
constexpr std::size_t kOff32FileAlign = 36;
constexpr std::size_t kOff32ImageSize = 56;
constexpr std::size_t kOff32HeadersSize = 60;
constexpr std::size_t kOffOptSubsystem = 68;   // same offset in both layouts
constexpr std::size_t kOffOptDllCharacteristics = 70; // same in both
constexpr std::size_t kOff32NumberOfRvaAndSizes = 92;

// PE32+ after the prefix. The 64-bit ImageBase pushes everything below it up
// by four bytes relative to PE32, which is exactly the kind of difference
// that makes a shared offset table wrong.
constexpr std::size_t kOff64Base = 24;
constexpr std::size_t kOff64SectionAlign = 32;
constexpr std::size_t kOff64FileAlign = 36;
constexpr std::size_t kOff64ImageSize = 56;
constexpr std::size_t kOff64HeadersSize = 60;
constexpr std::size_t kOff64NumberOfRvaAndSizes = 108;

// The data directories start after NumberOfRvaAndSizes and are sixteen
// RVA/size pairs. Only three are read: the export table, the import table and
// the base relocations. The rest are reported nowhere because nothing here
// uses them, and a reader that parses what it does not need is a reader with
// more ways to be wrong.
constexpr std::size_t kDirSize = 8;
constexpr std::size_t kDirExport = 0;
constexpr std::size_t kDirImport = 1;
constexpr std::size_t kDirReloc = 5;
constexpr std::size_t kOff32Directories = 96;
constexpr std::size_t kOff64Directories = 112;

// IMAGE_DLLCHARACTERISTICS. ASLR, DEP and the high-entropy bit are asked
// about often enough to be named; the SEH table is a directory rather than a
// bit and is handled with the directories.
constexpr std::uint16_t kDllCharacteristicsHighEntropyVa = 0x0020;
constexpr std::uint16_t kDllCharacteristicsDynamicBase = 0x0040;
constexpr std::uint16_t kDllCharacteristicsNxCompat = 0x0100;

// IMAGE_DIRECTORY_ENTRY_SECURITY is index 4 and holds a file offset rather
// than an RVA -- the Authenticode signature is the one directory addressed by
// file position. Nothing here reads it, and the reason is worth recording,
// because "the reloc directory is at RVA 0x1000" and "the security
// directory is at file offset 0x1000" are the same sixteen bytes apart and
// only one of them is true.
constexpr std::size_t kDirSecurity = 4;

// The section table follows the optional header, whose size the COFF header
// declares. This is why the reader cannot walk to the section table by
// assuming an optional header size: the file states it, and a file that
// states a size that does not match its own content is the normal case for a
// packer and the interesting case for a fuzzer.
constexpr std::size_t kSectionHeaderSize = 40;
constexpr std::size_t kOffSectionName = 0;
constexpr std::size_t kOffSectionVirtualSize = 8;
constexpr std::size_t kOffSectionVirtualAddress = 12;
constexpr std::size_t kOffSectionRawSize = 16;
constexpr std::size_t kOffSectionRawOffset = 20;
constexpr std::size_t kOffSectionCharacteristics = 36;

// IMAGE_SCN_* -- the three bits this reader names.
constexpr std::uint32_t kScnMemExecute = 0x20000000;
constexpr std::uint32_t kScnMemWrite = 0x80000000;
constexpr std::uint32_t kScnMemRead = 0x40000000;

// The import directory is an array of descriptors, each 20 bytes, terminated
// by an all-zero entry rather than by a count. The terminator is what bounds
// the walk: a file that omits it would otherwise be read until the walk
// leaves the file, so the bound here is a limit as well as a check.
constexpr std::size_t kImportDescriptorSize = 20;
constexpr std::size_t kOffImportName = 12;   // RVA of the name, not an offset
constexpr std::size_t kOffImportThunk = 0;   // original first thunk
constexpr std::size_t kOffImportForwarder = 16;
// The bound on the walk. A 64-bit image cannot have more directories than
// its own size allows, and 4096 is far above any real binary -- a binary
// with thousands of imported DLLs is a file trying to make the reader do
// work, and the limit is what makes that a bounded walk.
constexpr std::size_t kMaxImportDescriptors = 4096;
// The length of a name the reader will copy. A real DLL name is well under
// 260 characters; a longer one is not a name this reader should hold.
constexpr std::size_t kMaxNameLength = 512;

// IMAGE_EXPORT_DIRECTORY -- forty bytes, twelve fields, and eleven of them
// say something. Characteristics is reserved and must be zero; the two
// version fields are a linker's bookkeeping that nothing in this runtime has
// an opinion about; TimeDateStamp is one for reproducibility. They are named
// anyway, because a reader that skips a field silently and a reader that
// knows it is skipping are different readers six months apart.
constexpr std::size_t kExportDirectorySize = 40;
constexpr std::size_t kOffExportName = 12;        // RVA of the DLL's name
constexpr std::size_t kOffExportBase = 16;        // first ordinal
constexpr std::size_t kOffExportNumFunctions = 20;
constexpr std::size_t kOffExportNumNames = 24;
constexpr std::size_t kOffExportFunctions = 28;   // RVA of the address table
constexpr std::size_t kOffExportNames = 32;       // RVA of the name-pointer table
constexpr std::size_t kOffExportNameOrdinals = 36; // RVA of the ordinal table

// The Name field is not read, and kOffExportName is here only so the record
// is laid out in the file's order rather than in the order this reader needs.
//
// Name is an RVA to the module's own name, and there is nothing in this file
// it can be used for: a caller that wants the name already has it from
// wherever it opened the image, and the field exists for a linker writing the
// record rather than for a reader resolving one. Reading it would be a way
// to refuse a file for a reason that has nothing to do with what the caller
// came for -- a DLL whose export table is perfectly walkable and whose Name
// RVA happens to point at a zero would be rejected by a reader that checked
// it, and Windows would load it. That is the difference between refusing a
// file that cannot work and refusing a file that would have worked, and only
// one of those is a reader's job.

// The record's layout, checked at compile time rather than described in a
// comment. Every field this reader uses is inside the forty bytes, in the
// order it reads them, and none of them is the one it skips. A constant
// mistyped here would be a silent misread of every export in every file, and
// a comment cannot fail a build.
static_assert(kOffExportBase == 16 && kOffExportBase >= kOffExportName + 4,
              "the base field must follow the name field and be four bytes "
              "wide");
static_assert(kOffExportNumFunctions == kOffExportBase + 4,
              "NumberOfFunctions must follow the base");
static_assert(kOffExportNumNames == kOffExportNumFunctions + 4,
              "NumberOfNames must follow NumberOfFunctions");
static_assert(kOffExportFunctions == kOffExportNumNames + 4,
              "AddressOfFunctions must follow NumberOfNames");
static_assert(kOffExportNames == kOffExportFunctions + 4,
              "AddressOfNames must follow AddressOfFunctions");
static_assert(kOffExportNameOrdinals == kOffExportNames + 4,
              "AddressOfNameOrdinals must follow AddressOfNames");
static_assert(kOffExportNameOrdinals + 4 == kExportDirectorySize,
              "the record ends after the last field this reader reads");

// The widths of the three tables. All three are indexed by the same kind of
// thing and none of them is interchangeable with another: the address table
// is a list of 32-bit addresses, the name-pointer table a list of 32-bit
// addresses *to strings*, and the ordinal table a list of 16-bit indices.
// Reading the last as 32-bit would double every stride and walk into the
// middle of whatever follows, which is why each is named where it is used
// rather than factored into one "element size".
constexpr std::size_t kExportAddressWidth = 4;
constexpr std::size_t kExportNamePointerWidth = 4;
constexpr std::size_t kExportOrdinalWidth = 2;

// The bound on the export table's walk, in entries.
//
// A PE's export count is a 32-bit field, so without a cap a file claiming
// four billion names would have this reader walk four billion of them -- one
// per iteration, each resolving an RVA -- before the file ran out. The import
// walk has the same cap for the same reason and the same justification: a
// bound is what makes the walk bounded. 65536 is far above any real DLL.
// kernel32 exports around two thousand; the largest figure any real image is
// known to use is under ten thousand, and the cap is not a limit on what this
// reader will accept so much as a floor on how long it can be made to work.
constexpr std::size_t kMaxExportedSymbols = 65536;

// A forwarder names its target as "DLL.symbol" or "DLL.#27", and the split is
// the *last* dot -- a symbol name may itself contain one, and a DLL name
// legally may too on the systems that let it. Splitting at the first would
// read "kernel32.dll.Sleep" as a DLL called "kernel32" and a symbol called
// "dll.Sleep", which is neither thing.
constexpr char kForwarderOrdinalPrefix = '#';

// --------------------------------------------------------------- reading

// The bound, written as a subtraction.
//
// "off + width > size" is the obvious form and it is the one that was found
// broken in the ELF reader: off and width both come from the file, their sum
// wraps, a wrapped sum is small, and the check passes. The read that follows
// then lands outside the buffer.
//
// An honest note on how much this matters *here*, because the ELF bug was
// found by fuzzing and this reader has not been fuzzed yet: every field in a
// PE is 32 bits, so on a 64-bit target the sum of two of them cannot reach the
// top of a 64-bit size_t and the addition cannot wrap. The subtraction is
// kept anyway. It costs nothing, it is the form that stays correct if a field
// is ever widened to 64 bits or the reader is built for 32-bit, and it means
// the next person editing a bound here does not have to re-derive why this
// one was different. The ELF reader carries the same helper and there the
// values really did come close enough to wrap.
constexpr bool in_range(ByteSpan b, std::size_t off,
                        std::size_t width) noexcept {
    return off <= b.size() && b.size() - off >= width;
}

std::uint8_t rd8(ByteSpan b, std::size_t off) noexcept {
    return in_range(b, off, 1) ? b[off] : 0;
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

// A section name is eight bytes, NUL-padded, and not necessarily terminated.
// Reading it as a C string would run past the field into the next header for
// a name that uses all eight, so the length is found within the field and
// never beyond it.
std::string read_name(const char* p, std::size_t width) {
    std::size_t n = 0;
    while (n < width && p[n] != '\0') {
        ++n;
    }
    return std::string(p, n);
}

// Same rendering as the ELF parser uses: 0x-prefixed, lowercase, no leading
// zeros. A reader comparing two messages should not have to notice that one
// side spells it in hex and the other does not.
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

std::string decimal(std::uint64_t v) {
    std::string out;
    append_uint(out, v);
    return out;
}

// A machine word is reported by name when it is one this build names and by
// value otherwise. A refusal that says "unsupported machine" and one that says
// "unsupported machine 0x1c4" send the reader to different places.
PeMachine machine_from(std::uint16_t raw) noexcept {
    switch (raw) {
    case 0x014c:
        return PeMachine::I386;
    case 0x01c0:
        return PeMachine::Arm;
    case 0x8664:
        return PeMachine::Amd64;
    case 0xaa64:
        return PeMachine::Arm64;
    default:
        return PeMachine::Unknown;
    }
}

PeSubsystem subsystem_from(std::uint16_t raw) noexcept {
    switch (raw) {
    case 1:
        return PeSubsystem::Native;
    case 2:
        return PeSubsystem::WindowsGui;
    case 3:
        return PeSubsystem::WindowsCui;
    case 5:
        return PeSubsystem::Os2Cui;
    case 7:
        return PeSubsystem::PosixCui;
    case 8:
        return PeSubsystem::NativeWindows;
    case 9:
        return PeSubsystem::WindowsCeGui;
    case 10:
        return PeSubsystem::EfiApplication;
    case 11:
        return PeSubsystem::EfiBootServiceDriver;
    case 12:
        return PeSubsystem::EfiRuntimeDriver;
    case 13:
        return PeSubsystem::EfiRom;
    case 14:
        return PeSubsystem::Xbox;
    case 16:
        return PeSubsystem::WindowsBootApplication;
    default:
        return PeSubsystem::Unknown;
    }
}

// The image's title, for a detail string. Built by the caller because it
// needs the name the file was read under, which this layer does not know.
struct Failure {
    PeError error;
    std::string detail;
};

} // namespace

const char* pe_machine_name(PeMachine m) noexcept {
    switch (m) {
    case PeMachine::I386:
        return "i386";
    case PeMachine::Arm:
        return "arm";
    case PeMachine::Amd64:
        return "amd64";
    case PeMachine::Arm64:
        return "arm64";
    case PeMachine::Unknown:
        return "unknown";
    }
    return "unknown";
}

const char* pe_subsystem_name(PeSubsystem s) noexcept {
    switch (s) {
    case PeSubsystem::Native:
        return "native";
    case PeSubsystem::WindowsGui:
        return "windows gui";
    case PeSubsystem::WindowsCui:
        return "windows console";
    case PeSubsystem::Os2Cui:
        return "os/2 console";
    case PeSubsystem::PosixCui:
        return "posix console";
    case PeSubsystem::NativeWindows:
        return "native windows";
    case PeSubsystem::WindowsCeGui:
        return "windows ce gui";
    case PeSubsystem::EfiApplication:
        return "efi application";
    case PeSubsystem::EfiBootServiceDriver:
        return "efi boot service driver";
    case PeSubsystem::EfiRuntimeDriver:
        return "efi runtime driver";
    case PeSubsystem::EfiRom:
        return "efi rom";
    case PeSubsystem::Xbox:
        return "xbox";
    case PeSubsystem::WindowsBootApplication:
        return "windows boot application";
    case PeSubsystem::Unknown:
        return "unknown";
    }
    return "unknown";
}

const char* pe_error_name(PeError e) noexcept {
    switch (e) {
    case PeError::None:
        return "none";
    case PeError::NotPe:
        return "not a PE image";
    case PeError::TruncatedDosHeader:
        return "the DOS header is truncated";
    case PeError::BadHeaderOffset:
        return "e_lfanew does not point at a PE header";
    case PeError::TruncatedCoffHeader:
        return "the COFF header is truncated";
    case PeError::TruncatedOptionalHeader:
        return "the optional header is truncated";
    case PeError::UnknownOptionalMagic:
        return "the optional header magic is neither PE32 nor PE32+";
    case PeError::TruncatedSectionTable:
        return "the section table is truncated";
    case PeError::NoSections:
        return "the image has no sections";
    case PeError::BadSectionTable:
        return "a section's contents are outside the file";
    case PeError::DirectoryOutOfFile:
        return "a data directory points outside the file";
    case PeError::TruncatedImportTable:
        return "the import table is truncated";
    case PeError::TruncatedExportDirectory:
        return "the export directory is truncated";
    case PeError::BadExportTable:
        return "the export table is malformed";
    case PeError::BadHeaderSize:
        return "SizeOfHeaders is larger than the file";
    }
    return "unknown";
}

bool PeSection::executable() const noexcept {
    return (characteristics & kScnMemExecute) != 0;
}

bool PeSection::writable() const noexcept {
    return (characteristics & kScnMemWrite) != 0;
}

bool PeSection::readable() const noexcept {
    return (characteristics & kScnMemRead) != 0;
}

std::uint64_t PeSection::virtual_end() const noexcept {
    // The end of a section's address range. Written as a subtraction-bounded
    // question for the same reason as everywhere else: a virtual_address near
    // the top of the address space with a large virtual_size would wrap, and
    // a caller comparing against the wrapped end would believe a section
    // that is enormous is a section that ends early.
    //
    // The size is `mapped_size()` rather than `virtual_size` because an end
    // computed from a zero VirtualSize is the section's own start, which says
    // the section occupies no address space at all -- see the accessor for why
    // that is the wrong answer for a section whose contents are in the file.
    const std::uint64_t span = mapped_size();
    return virtual_address > UINT64_MAX - span
               ? UINT64_MAX
               : static_cast<std::uint64_t>(virtual_address) + span;
}

std::uint64_t PeSection::raw_end() const noexcept {
    return raw_offset > UINT64_MAX - raw_size
               ? UINT64_MAX
               : static_cast<std::uint64_t>(raw_offset) + raw_size;
}

PeImage PeImage::parse(ByteSpan bytes) noexcept {
    PeImage out;
    out.bytes_size_ = bytes.size();

    // The failure path is used from several places below, and each one knows
    // what it was reading. A local lambda keeps the error and its sentence
    // together, because an error without its sentence is the thing this file
    // exists to avoid.
    const auto fail = [&out](PeError e, std::string detail) {
        out.error_ = e;
        out.detail_ = std::move(detail);
        out.sections_.clear();
        out.imports_.clear();
        out.exports_.clear();
        return out;
    };

    // --- the DOS header
    //
    // The size is checked before the signature, because a file too short to
    // hold the signature has not failed it -- it has not offered it. The two
    // answers send a reader to different places: one says "this is not a PE",
    // the other says "this is too short to tell".
    if (bytes.size() < kDosHeaderSize) {
        return fail(PeError::TruncatedDosHeader,
                    "the DOS header is " + decimal(kDosHeaderSize) +
                        " bytes and the file is " + decimal(bytes.size()));
    }
    if (!in_range(bytes, kOffDosMagic, 2) ||
        rd16(bytes, kOffDosMagic) != kDosMagic) {
        return fail(PeError::NotPe,
                    "the file does not begin with the MZ signature");
    }

    const std::uint32_t lfanew = rd32(bytes, kOffELfanew);

    // e_lfanew is the one offset in the DOS header, and it is used to index
    // everything else, so it is checked before anything is read through it.
    // The alignment check is not pedantry: a PE header is a sequence of
    // structures that are read as words, and a file that places one at an
    // odd offset is either corrupt or is a format this reader has no reason
    // to guess at. Either way the honest answer is to refuse.
    if (lfanew < kDosHeaderSize) {
        return fail(PeError::BadHeaderOffset,
                    "e_lfanew is " + hex_value(lfanew) +
                        ", which is inside the DOS header");
    }
    if ((lfanew & 1u) != 0) {
        return fail(PeError::BadHeaderOffset,
                    "e_lfanew is " + hex_value(lfanew) + ", which is odd");
    }
    if (!in_range(bytes, lfanew, kPeSignatureSize)) {
        return fail(PeError::BadHeaderOffset,
                    "e_lfanew is " + hex_value(lfanew) +
                        " and the file is " + decimal(bytes.size()) + " bytes");
    }
    if (rd32(bytes, lfanew) != kPeSignature) {
        return fail(PeError::NotPe,
                    "there is no PE signature at e_lfanew (" +
                        hex_value(lfanew) + ")");
    }

    // --- the COFF header, which starts right after the signature
    const std::size_t coff = lfanew + kPeSignatureSize;
    if (!in_range(bytes, coff, kCoffHeaderSize)) {
        return fail(PeError::TruncatedCoffHeader,
                    "the COFF header is at " + hex_value(coff) +
                        " and the file is " + decimal(bytes.size()) + " bytes");
    }

    out.machine_raw_ = rd16(bytes, coff + kOffCoffMachine);
    out.machine_ = machine_from(out.machine_raw_);
    out.section_count_ = rd16(bytes, coff + kOffCoffSectionCount);
    out.characteristics_ = rd16(bytes, coff + kOffCoffCharacteristics);
    out.kind_ = (out.characteristics_ & kCharDll) != 0 ? PeKind::Dll
                                                        : PeKind::Executable;
    const std::uint16_t opt_size = rd16(bytes, coff + kOffCoffOptionalSize);

    // --- the optional header
    const std::size_t opt = coff + kCoffHeaderSize;
    if (opt_size == 0) {
        // A file with no optional header is a driver or a resource-only
        // object. It is a real thing, and it is not a program this engine can
        // run, but the reader can still describe it -- so the format is
        // accepted and the fields that come from the optional header keep
        // their defaults. Refusing here would make the reader unable to say
        // anything at all about a valid file.
        out.plus_ = false;
        out.opt_size_ = 0;
    } else {
        if (!in_range(bytes, opt, opt_size)) {
            return fail(PeError::TruncatedOptionalHeader,
                        "the optional header is at " + hex_value(opt) +
                            " for " + decimal(opt_size) +
                            " bytes and the file is " + decimal(bytes.size()) +
                            " bytes");
        }
        // The magic comes before the length check below, and it has to be
        // there: which of the two layouts the header is depends on it, and the
        // offsets everything else uses depend on that. So the question is
        // asked first -- and a header too short to hold the magic is reported
        // as short. Reading it anyway yields zero, and zero is not a magic
        // this reader does not recognise, it is the absence of one.
        if (opt_size < kOffOptMagic + 2) {
            return fail(PeError::TruncatedOptionalHeader,
                        "SizeOfOptionalHeader is " + decimal(opt_size) +
                            ", too short to hold the two-byte magic that says "
                            "which layout this is");
        }
        const std::size_t magic = rd16(bytes, opt + kOffOptMagic);
        if (magic == kMagicPe32) {
            out.plus_ = false;
        } else if (magic == kMagicPe32Plus) {
            out.plus_ = true;
        } else {
            return fail(PeError::UnknownOptionalMagic,
                        "the optional header magic is " + hex_value(magic) +
                            ", which is neither PE32 (" + hex_value(kMagicPe32) +
                            ") nor PE32+ (" + hex_value(kMagicPe32Plus) + ")");
        }
        out.opt_size_ = opt_size;

        // The fixed fields this reader reads -- entry point, image base, both
        // alignments, subsystem, DLL characteristics -- end at offset 72 in
        // both layouts. SizeOfOptionalHeader is the file's own statement of
        // how long the header is, and reading past it does not fail: the
        // bytes are in the file, they are just the section table's bytes.
        // A subsystem of 0 read out of a section name is a wrong answer, and
        // the reader cannot tell it from a right one, so the header is
        // required to be long enough to hold what it claims to describe.
        constexpr std::size_t kFixedFieldsEnd = 72;
        if (opt_size < kFixedFieldsEnd) {
            return fail(PeError::TruncatedOptionalHeader,
                        "SizeOfOptionalHeader is " + decimal(opt_size) +
                            ", too short to hold the fixed fields, which end "
                            "at offset " +
                            decimal(kFixedFieldsEnd));
        }

        // The entry point, image base and the two alignments are at different
        // offsets in the two layouts, so they are read through a branch
        // rather than through an offset table. The branch is on a value the
        // file chose, once, above.
        out.entry_ = rd32(bytes, opt + kOffOptEntry);
        if (out.plus_) {
            out.base_ = rd64(bytes, opt + kOff64Base);
            out.section_align_ = rd32(bytes, opt + kOff64SectionAlign);
            out.file_align_ = rd32(bytes, opt + kOff64FileAlign);
            out.image_size_ = rd32(bytes, opt + kOff64ImageSize);
            out.headers_size_ = rd32(bytes, opt + kOff64HeadersSize);
        } else {
            out.base_ = rd32(bytes, opt + kOff32Base);
            out.section_align_ = rd32(bytes, opt + kOff32SectionAlign);
            out.file_align_ = rd32(bytes, opt + kOff32FileAlign);
            out.image_size_ = rd32(bytes, opt + kOff32ImageSize);
            out.headers_size_ = rd32(bytes, opt + kOff32HeadersSize);
        }

        out.subsystem_raw_ = rd16(bytes, opt + kOffOptSubsystem);
        out.subsystem_ = subsystem_from(out.subsystem_raw_);
        const std::uint16_t dllc = rd16(bytes, opt + kOffOptDllCharacteristics);
        out.aslr_ = (dllc & kDllCharacteristicsDynamicBase) != 0;
        out.nx_ = (dllc & kDllCharacteristicsNxCompat) != 0;
        out.hev_ = (dllc & kDllCharacteristicsHighEntropyVa) != 0;
    }

    // --- the data directories
    //
    // Read only where the optional header actually reaches them. A PE32
    // header can declare NumberOfRvaAndSizes without carrying the directories
    // themselves, and reading them anyway would read the section table.
    if (out.opt_size_ != 0) {
        const std::size_t count_off =
            out.plus_ ? kOff64NumberOfRvaAndSizes : kOff32NumberOfRvaAndSizes;
        const std::size_t count_at = opt + count_off;
        const std::size_t dirs_at =
            opt + (out.plus_ ? kOff64Directories : kOff32Directories);
        // NumberOfRvaAndSizes sits between the fixed fields and the array it
        // counts, so a header can reach the array's offset without reaching
        // the count. Reading it anyway would read the array's first entry, or
        // the section table, as a count -- and the clamp below would then
        // discard it, which is the right answer reached by reading the wrong
        // bytes. Asked instead: does the header contain the field?
        const std::uint32_t count =
            in_range(bytes, count_at, 4) && out.opt_size_ > count_off
                ? rd32(bytes, count_at)
                : 0;
        // The declared count is not trusted on its own: a file may claim
        // sixteen directories and provide two, so the count is clamped to
        // what the optional header's own size can hold. Both numbers come
        // from the file and either one can exceed the buffer.
        const std::size_t available =
            out.opt_size_ > (dirs_at - opt)
                ? (out.opt_size_ - (dirs_at - opt)) / kDirSize
                : 0;
        const std::size_t usable = count < available ? count : available;
        for (std::size_t i = 0; i < usable; ++i) {
            const std::size_t at = dirs_at + i * kDirSize;
            if (i == kDirExport) {
                out.export_rva_ = rd32(bytes, at);
                out.export_size_ = rd32(bytes, at + 4);
            } else if (i == kDirImport) {
                out.import_rva_ = rd32(bytes, at);
                out.import_size_ = rd32(bytes, at + 4);
            } else if (i == kDirReloc) {
                out.reloc_rva_ = rd32(bytes, at);
                out.reloc_size_ = rd32(bytes, at + 4);
            } else if (i == kDirSecurity) {
                // Deliberately not read. This directory's RVA is a file
                // offset, not an RVA, and treating it as one is a bug this
                // reader does not have. The constant is kept so the comment
                // above can name it.
                (void)0;
            }
        }
        // An empty SEH table is a valid configuration, so its presence is
        // only asserted when the file states one.
        const std::size_t seh_at = dirs_at + 4 * kDirSize;
        if (usable > 4 && rd32(bytes, seh_at) != 0) {
            out.seh_ = true;
        }
    }

    // --- the section table
    //
    // Its position is declared rather than computed: the COFF header says how
    // long the optional header is, and the table starts after it. Assuming a
    // length here would be the classic mistake, and would work on every file
    // whose optional header is the expected size -- which is to say it would
    // work on the files that are already parsed correctly.
    const std::size_t table = opt + opt_size;
    if (out.section_count_ == 0) {
        return fail(PeError::NoSections,
                    "the COFF header declares no sections");
    }
    // The table's own extent, asked as a subtraction. section_count_ is a
    // 16-bit value from the file and the product is the kind that can wrap
    // if written as an addition.
    const std::size_t table_bytes =
        static_cast<std::size_t>(out.section_count_) * kSectionHeaderSize;
    if (!in_range(bytes, table, table_bytes)) {
        return fail(PeError::TruncatedSectionTable,
                    "the section table is at " + hex_value(table) + " for " +
                        decimal(table_bytes) + " bytes and the file is " +
                        decimal(bytes.size()) + " bytes");
    }

    out.sections_.reserve(out.section_count_);
    for (std::uint16_t i = 0; i < out.section_count_; ++i) {
        const std::size_t at = table + static_cast<std::size_t>(i) * kSectionHeaderSize;
        PeSection s;
        for (std::size_t k = 0; k < 8; ++k) {
            s.raw_name[k] = static_cast<char>(rd8(bytes, at + kOffSectionName + k));
        }
        s.name = read_name(s.raw_name, 8);
        s.virtual_size = rd32(bytes, at + kOffSectionVirtualSize);
        s.virtual_address = rd32(bytes, at + kOffSectionVirtualAddress);
        s.raw_size = rd32(bytes, at + kOffSectionRawSize);
        s.raw_offset = rd32(bytes, at + kOffSectionRawOffset);
        s.characteristics = rd32(bytes, at + kOffSectionCharacteristics);

        // A section's raw data has to be in the file. One case is exempt: a
        // section of zero raw size stores nothing at all, which is what .bss
        // and the padding a linker emits look like.
        //
        // A raw offset of zero with a non-zero size used to be exempt too,
        // on the reasoning that a packer might fill it in later. That
        // exemption was wrong, and the fuzz harness found it: it lets a
        // file declare a 32 MiB section at offset zero in a 1 KB file, and
        // every caller that maps or reads sections then believes it. "The
        // file says this" is not the test; the test is whether the bytes are
        // there, and they are not. A packer that wants the offset filled in
        // has to write the offset.
        if (s.raw_size != 0) {
            if (s.raw_offset > bytes.size() ||
                bytes.size() - s.raw_offset < s.raw_size) {
                return fail(PeError::BadSectionTable,
                            "section " + decimal(i) + " (" + s.name +
                                ") runs from " + hex_value(s.raw_offset) +
                                " for " + hex_value(s.raw_size) +
                                " bytes and the file is " +
                                decimal(bytes.size()) + " bytes");
            }
        }
        out.sections_.push_back(s);
    }

    // --- SizeOfHeaders, checked against the sections it has to cover
    //
    // The value says how much of the file the linker reserved for the
    // headers. It is also the threshold that decides which of the two
    // coordinate systems an RVA belongs to, so a file that overstates it
    // does not merely carry a wrong number -- it reclassifies every address
    // in the image.
    //
    // Found by fuzz/fuzz_pe.cpp, twice, in two forms. A file claiming four
    // gigabytes of headers in three hundred bytes made the header rule claim
    // every section's RVA before the section table was consulted, so a
    // section at RVA 0x1000 resolved to *file* offset 0x1000 instead of
    // 0x200. Nothing crashed, every offset was inside the file, and every
    // one of them was wrong -- which is worse than a crash, because a caller
    // has no way to notice. The same overstatement also let an RVA equal to
    // the file's length resolve to that length, one byte past the end.
    //
    // Both are the same defect and both are answered here rather than at the
    // conversion: the file has said something that cannot be true, so it is
    // refused before any address is classified by it. The bound is the file
    // rather than the sections, because the file is the thing that cannot
    // grow -- and a file whose headers claim more than its own length is
    // malformed whatever its sections say.
    if (out.headers_size_ != 0 &&
        out.headers_size_ > static_cast<std::uint64_t>(bytes.size())) {
        return fail(PeError::BadHeaderSize,
                    "SizeOfHeaders is " + hex_value(out.headers_size_) +
                        ", which is more than the file's " +
                        decimal(bytes.size()) + " bytes");
    }
    // The headers also have to be at least as large as the headers this
    // reader just parsed out of them -- the DOS header, the COFF header, the
    // optional header and the section table all live inside that region, so a
    // SizeOfHeaders below the section table's end would place section data
    // inside the headers and the two rules would overlap.
    const std::size_t headers_claimed =
        static_cast<std::size_t>(out.headers_size_);
    if (out.headers_size_ != 0 && headers_claimed < table_bytes + table) {
        // Not fatal: a linker can pad the section table with a section whose
        // header lies past the declared region, and refusing would reject
        // files that load. It is noted rather than enforced because the
        // conversion's own bound -- the file's length -- is what keeps the
        // overlap from producing an out-of-range offset.
        out.headers_cover_table_ = false;
    } else {
        out.headers_cover_table_ = true;
    }

    // --- the import table
    //
    // Walked only if one is declared. A PE with no imports is ordinary; a PE
    // whose import directory RVA is set but resolves to nothing is a claim
    // the file does not keep, and reporting it is the difference between "no
    // imports" and "the import table is broken".
    //
    // The condition tests the RVA alone, and the declared size is left to
    // the descriptor check below for the same reason the export walk does
    // the same thing: a size of zero alongside a non-zero RVA is a file
    // claiming a directory with nothing in it, which is a contradiction to
    // report rather than an absence to infer. Wine resolves the RVA without
    // consulting Size as well.
    if (out.import_rva_ != 0) {
        std::uint64_t dir_off = 0;
        bool zero_filled = false;
        if (!out.resolve_rva(out.import_rva_, dir_off, zero_filled) ||
            zero_filled) {
            // A directory that lands in zero fill is not a directory. The
            // RVA resolved, but there is nothing behind it, and treating
            // that as "no imports" would turn a file that claims an import
            // table and has none into a file with no imports -- two claims
            // that differ and that a reader should not conflate.
            return fail(PeError::DirectoryOutOfFile,
                        "the import directory is at RVA " +
                            hex_value(out.import_rva_) +
                            ", which is not backed by the file");
        }
        // dir_off is a file offset. Each name is an RVA and is resolved
        // separately, because the two coordinate systems are different and
        // using one where the other belongs is the standard mistake.
        //
        // resolve_rva has already established that dir_off is inside the
        // file. The check is repeated anyway: it is the difference between
        // the walk below being correct and the walk below being correct
        // because of something a function two hundred lines away happens to
        // guarantee today.
        if (dir_off > bytes.size()) {
            return fail(PeError::DirectoryOutOfFile,
                        "the import directory resolves to file offset " +
                            hex_value(dir_off) + ", past the end of a file " +
                            decimal(bytes.size()) + " bytes long");
        }
        const std::size_t room = bytes.size() - static_cast<std::size_t>(dir_off);

        // The directory's declared size bounds the walk, and the bound is
        // read as a count of whole descriptors. A directory that declares
        // fewer bytes than one descriptor needs is a claim the file cannot
        // keep: there is no arrangement of a 20-byte record inside 8 bytes,
        // so this is reported rather than reported as "no imports".
        if (out.import_size_ < kImportDescriptorSize) {
            return fail(PeError::TruncatedImportTable,
                        "the import directory declares " +
                            decimal(out.import_size_) +
                            " bytes, which cannot hold one " +
                            decimal(kImportDescriptorSize) +
                            "-byte descriptor");
        }
        const std::size_t declared = out.import_size_ / kImportDescriptorSize;

        // The cap is checked against the declared count, before the file's
        // room is considered. A directory claiming a hundred thousand
        // descriptors is refused for claiming that whether or not the file
        // could hold them, and the diagnostic says so -- a reader told "only
        // N fit in the file" when the file claims ten times that is being
        // sent to look at the wrong problem.
        if (declared > kMaxImportDescriptors) {
            // Either not an import table, or a resource exhaustion attempt.
            // The cap is reported rather than applied: silently stopping at
            // the cap would produce exactly the same output as a table that
            // genuinely ended, and those two files are not alike.
            return fail(PeError::TruncatedImportTable,
                        "the import directory declares " + decimal(declared) +
                            " descriptors, which is past the " +
                            decimal(kMaxImportDescriptors) +
                            " this reader will walk");
        }

        const std::size_t fitting = room / kImportDescriptorSize;
        if (fitting < declared) {
            // The file ran out before the declaration did. That is a
            // different failure from the cap: the table is not too large to
            // read, it is broken, and the message has to say which.
            return fail(PeError::TruncatedImportTable,
                        "the import directory declares " + decimal(declared) +
                            " descriptors but only " + decimal(fitting) +
                            " fit in the file");
        }
        // Every declared descriptor was established to fit above, by division
        // rather than by an addition that could wrap.
        const std::size_t limit = declared;

        for (std::size_t n = 0; n < limit; ++n) {
            // `limit` descriptors were established to fit above, by
            // division rather than by an addition that could wrap, so the
            // offset needs no check of its own here.
            const std::size_t at = static_cast<std::size_t>(dir_off) +
                                    n * kImportDescriptorSize;
            // The all-zero terminator. It is not the walk's only end -- the
            // declared size is -- but a well-formed table has one, and a
            // descriptor past it is not part of this table.
            if (rd32(bytes, at + kOffImportThunk) == 0 &&
                rd32(bytes, at + kOffImportName) == 0 &&
                rd32(bytes, at + kOffImportForwarder) == 0) {
                break;
            }
            std::string name;
            if (out.read_rva_string(bytes, rd32(bytes, at + kOffImportName),
                                    name)) {
                out.imports_.push_back(std::move(name));
            }
        }
    }

    // --- the export table
    //
    // Parsed, and that is a departure from how the import table is treated
    // here. Imports are a list of names and a DLL's name is the only thing
    // this reader has ever wanted from them, so the structure is walked past.
    // An export is three arrays that mean nothing separately: an address with
    // no name, a name with no address, and an index that ties them together.
    // A reader that reported the address table and left the rest to a caller
    // would be reporting a table with holes in it, and the caller would have
    // to walk the same three arrays again to fill them -- which is the shape
    // of the one semantic path this project refuses to have.
    //
    // The division of labour is deliberate: everything read here is a fact
    // *about the file*, and the one thing that is not -- where a forwarder
    // actually points, which needs another DLL's export table and therefore a
    // module table this runtime does not have -- is left to the layer above.
    // A forwarder is parsed into the DLL and symbol it names and stops there.
    if (out.export_rva_ != 0) {
        std::uint64_t dir_off = 0;
        bool zero_filled = false;
        if (!out.resolve_rva(out.export_rva_, dir_off, zero_filled) ||
            zero_filled) {
            // Zero fill is not a directory. The address resolved and there is
            // nothing behind it, and treating that as "this DLL exports
            // nothing" would turn a file that claims an export table and
            // cannot keep it into a DLL with no exports -- a claim a program
            // would act on.
            return fail(PeError::DirectoryOutOfFile,
                        "the export directory is at RVA " +
                            hex_value(out.export_rva_) +
                            ", which is not backed by the file");
        }
        if (dir_off > bytes.size()) {
            return fail(PeError::DirectoryOutOfFile,
                        "the export directory resolves to file offset " +
                            hex_value(dir_off) + ", past the end of a file " +
                            decimal(bytes.size()) + " bytes long");
        }
        const std::size_t dir_at = static_cast<std::size_t>(dir_off);

        // The directory record itself, before any field in it is read. A
        // declared size smaller than the record cannot hold the record, and
        // the twelve fields are laid out in the order they must be read: a
        // reader that checked the array counts first would be trusting a
        // number it has not established is readable.
        //
        // This also covers a declared size of zero, and that is the reason
        // the entry condition above tests the RVA alone. A file with an RVA
        // and a size of zero has said it has an export directory and also
        // said the directory holds nothing -- two claims, one of which the
        // other makes impossible, because the record lives in the directory
        // and the directory has no bytes. Skipping the walk on a zero size
        // would report that as a DLL with no exports, which is a thing a
        // program acts on. Wine resolves the RVA without consulting Size for
        // the same reason and reaches the same conclusion one check later:
        // find_named_export refuses anything under sizeof(*exports).
        if (out.export_size_ < kExportDirectorySize) {
            return fail(PeError::TruncatedExportDirectory,
                        "the export directory declares " +
                            decimal(out.export_size_) +
                            " bytes, which cannot hold one " +
                            decimal(kExportDirectorySize) +
                            "-byte directory record");
        }
        if (!in_range(bytes, dir_at, kExportDirectorySize)) {
            return fail(PeError::DirectoryOutOfFile,
                        "the export directory at file offset " +
                            hex_value(dir_off) + " is truncated by the end of "
                            "a file " + decimal(bytes.size()) + " bytes long");
        }

        out.export_base_ = rd32(bytes, dir_at + kOffExportBase);
        const std::uint32_t num_functions =
            rd32(bytes, dir_at + kOffExportNumFunctions);
        const std::uint32_t num_names =
            rd32(bytes, dir_at + kOffExportNumNames);
        const std::uint32_t functions_rva =
            rd32(bytes, dir_at + kOffExportFunctions);
        const std::uint32_t names_rva = rd32(bytes, dir_at + kOffExportNames);
        const std::uint32_t ordinals_rva =
            rd32(bytes, dir_at + kOffExportNameOrdinals);

        // The two counts are independent and the file is not required to make
        // them agree. NumberOfFunctions is the length of the address table
        // and therefore the number of ordinals the image uses; NumberOfNames
        // is how many of those ordinals are reachable by name. A DLL that
        // exports five thousand symbols by ordinal and names ten of them is
        // ordinary, and a reader that required the counts to match would
        // refuse it.
        //
        // NumberOfFunctions is capped because it drives the address-table
        // walk, and an uncapped 32-bit count is a file that has asked for
        // four billion iterations. NumberOfNames is capped for the same
        // reason and with the same value, though it is a smaller number in
        // every real image.
        //
        // The cap is reported rather than applied, exactly as the import walk
        // does it. A reader that stopped silently at the cap and returned a
        // short list would be telling the caller this DLL exports this many
        // symbols, which is a claim about the file. The diagnostic says what
        // the file claimed instead.
        if (num_functions > kMaxExportedSymbols) {
            return fail(PeError::BadExportTable,
                        "the export directory claims " +
                            decimal(num_functions) +
                            " addresses in its address table, which is past "
                            "the " + decimal(kMaxExportedSymbols) +
                            " this reader walks");
        }
        if (num_names > kMaxExportedSymbols) {
            return fail(PeError::BadExportTable,
                        "the export directory claims " + decimal(num_names) +
                            " names in its name pointer table, which is past "
                            "the " + decimal(kMaxExportedSymbols) +
                            " this reader walks");
        }

        // A DLL that exports nothing declares zero for both counts and an RVA
        // of zero for the address table. That is not an error and there is
        // nothing to walk, so the walk is skipped rather than attempted. The
        // order matters: the counts are read before the arrays are resolved,
        // because a file that claims no names must not be failed for naming
        // an array it does not need.
        if (num_functions == 0) {
            // A name with no address table to point into is a claim the file
            // cannot keep: the name-ordinal table's entries are indices into
            // the address table, so with no address table every one of them
            // is out of range. Refused rather than ignored, because the
            // alternative is a name with no address, which is a thing a
            // caller would have to detect.
            if (num_names != 0) {
                return fail(PeError::BadExportTable,
                            "the export directory names " + decimal(num_names) +
                                " exports but declares no address table for "
                                "them to point into");
            }
        } else {
            // The address table. Resolved once, and every entry read through
            // the same bound check rather than trusting the count, because the
            // count and the file's length are two different claims and the
            // walk has to be bounded by the one that is true.
            std::uint64_t functions_off = 0;
            bool functions_zero = false;
            if (!out.resolve_rva(functions_rva, functions_off,
                                 functions_zero) ||
                functions_zero) {
                return fail(PeError::BadExportTable,
                            "the export address table is at RVA " +
                                hex_value(functions_rva) +
                                ", which is not backed by the file");
            }
            // The multiplication is by a constant width and a count already
            // bounded by the cap, so it cannot overflow a 64-bit size_t; the
            // subtraction is what makes the comparison below safe rather than
            // a sum that would have wrapped.
            const std::size_t functions_at =
                static_cast<std::size_t>(functions_off);
            if (functions_at > bytes.size() ||
                bytes.size() - functions_at <
                    static_cast<std::size_t>(num_functions) *
                        kExportAddressWidth) {
                return fail(PeError::BadExportTable,
                            "the export address table declares " +
                                decimal(num_functions) + " entries, which do "
                                "not all fit in a file " +
                                decimal(bytes.size()) + " bytes long");
            }

            out.exports_.resize(num_functions);

            // The name tables, in one pass. They are read together because
            // they are only meaningful together: entry i of the name-pointer
            // table, entry i of the ordinal table, and the entry of the
            // address table that the ordinal names are one fact, and reading
            // any two of them without the third produces a name attached to an
            // address it does not belong to.
            if (num_names != 0) {
                std::uint64_t names_off = 0;
                std::uint64_t ordinals_off = 0;
                bool names_zero = false;
                bool ordinals_zero = false;
                if (!out.resolve_rva(names_rva, names_off, names_zero) ||
                    names_zero) {
                    return fail(PeError::BadExportTable,
                                "the export name pointer table is at RVA " +
                                    hex_value(names_rva) +
                                    ", which is not backed by the file");
                }
                if (!out.resolve_rva(ordinals_rva, ordinals_off,
                                     ordinals_zero) ||
                    ordinals_zero) {
                    return fail(PeError::BadExportTable,
                                "the export ordinal table is at RVA " +
                                    hex_value(ordinals_rva) +
                                    ", which is not backed by the file");
                }
                const std::size_t names_at =
                    static_cast<std::size_t>(names_off);
                const std::size_t ordinals_at =
                    static_cast<std::size_t>(ordinals_off);
                if (names_at > bytes.size() ||
                    bytes.size() - names_at <
                        static_cast<std::size_t>(num_names) *
                            kExportNamePointerWidth) {
                    return fail(PeError::BadExportTable,
                                "the export name pointer table declares " +
                                    decimal(num_names) +
                                    " entries, which do not all fit in a "
                                    "file " + decimal(bytes.size()) +
                                    " bytes long");
                }
                if (ordinals_at > bytes.size() ||
                    bytes.size() - ordinals_at <
                        static_cast<std::size_t>(num_names) *
                            kExportOrdinalWidth) {
                    return fail(PeError::BadExportTable,
                                "the export ordinal table declares " +
                                    decimal(num_names) +
                                    " entries, which do not all fit in a "
                                    "file " + decimal(bytes.size()) +
                                    " bytes long");
                }

                for (std::size_t i = 0; i < num_names; ++i) {
                    // The index, not the ordinal. This is the field the
                    // format is most often misread on: it is an offset into
                    // the address table, and the ordinal a program imports by
                    // is that index plus the base. Adding the base here
                    // instead would be a one-character difference between
                    // this reader and one that resolves the wrong function
                    // for every named export in a DLL whose base is not 1.
                    const std::uint16_t index = rd16(
                        bytes, ordinals_at + i * kExportOrdinalWidth);

                    // An index past the end of the address table is a claim
                    // the file cannot keep. It is checked rather than
                    // skipped: skipping would leave a name attached to
                    // nothing, and a caller resolving that name would get
                    // whatever the vector happens to have at that position.
                    if (index >= num_functions) {
                        return fail(PeError::BadExportTable,
                                    "name " + decimal(i) + " of " +
                                        decimal(num_names) +
                                        " names address-table entry " +
                                        decimal(index) +
                                        ", and the address table has only " +
                                        decimal(num_functions) + " entries");
                    }

                    std::string name;
                    if (!out.read_rva_string(
                            bytes, rd32(bytes, names_at +
                                                 i * kExportNamePointerWidth),
                            name)) {
                        // A name that will not read ends the association but
                        // not the table. The entries before it are real
                        // exports and dropping them would understate what the
                        // image provides; the entries after it are equally
                        // real and may well read. So the walk stops, exactly
                        // as the import walk stops at a name it cannot read,
                        // and what was collected is kept.
                        //
                        // The alternative -- refusing the file -- would be
                        // wrong in a way that is hard to see: a DLL whose
                        // export table has one unreadable name is a DLL that
                        // works for every other symbol, and refusing it
                        // removes a program that ran before.
                        break;
                    }
                    out.exports_[index].name = std::move(name);
                }
            }

            // The ordinals, and the forwarder test, for every address-table
            // entry. The vector has already been sized to the address table
            // and the names have already been attached by index, so this loop
            // only has to number each slot and decide what its address means.
            for (std::size_t i = 0; i < num_functions; ++i) {
                const std::uint32_t rva =
                    rd32(bytes, functions_at + i * kExportAddressWidth);
                PeExport& e = out.exports_[i];

                // A slot the file left at zero is not an export, and the
                // check is not here. It is at the end of this block, where
                // the entries are trimmed -- one check, after the walk, for
                // a fact about the whole table. Putting it here as well
                // would be a second statement of the same thing, and the two
                // would have to be kept in step: a reader with both would
                // have two places to forget, and a mutation that removed
                // only this one would be invisible because the other would
                // still hold.

                // The ordinal. The base is added in a 64-bit temporary and
                // then narrowed, which is what makes a file that claims a
                // base near the top of the 32-bit range produce a report
                // rather than a wrapped ordinal. A file may legitimately set
                // the base to zero, and this honors that: ordinals then start
                // at zero and the image is saying so.
                e.rva = rva;
                e.ordinal = static_cast<std::uint32_t>(
                    static_cast<std::uint64_t>(i) + out.export_base_);

                // The forwarder test, and it is an address comparison rather
                // than a bit in the table because the format has no bit for
                // it: an export whose address falls inside the export
                // directory is not an address at all but the location of a
                // string that names another DLL's symbol. The interval is the
                // directory's own RVA and size, and it is half-open -- an
                // export pointing exactly at the end of the directory is past
                // it, and reading a forwarder from there would read the
                // section that follows.
                //
                // The comparison is done in 64 bits and the end is computed
                // by addition, which is safe because both operands are
                // 32-bit and their sum cannot reach the top of a 64-bit
                // value. A file declaring a directory that runs to the top of
                // the address space therefore produces a test that is false
                // for every export rather than one that is true for all of
                // them.
                const std::uint64_t dir_start = out.export_rva_;
                const std::uint64_t dir_end =
                    dir_start + static_cast<std::uint64_t>(out.export_size_);
                if (static_cast<std::uint64_t>(rva) < dir_start ||
                    static_cast<std::uint64_t>(rva) >= dir_end) {
                    continue;
                }
                e.is_forwarder = true;

                // The string. Read through the same bounded reader as every
                // other name in this file, which is what keeps a forwarder
                // from being the one place a file can make this reader walk
                // to the end of a large section: read_rva_string stops at the
                // first NUL, refuses a string that has none inside the file,
                // and refuses one longer than any name.
                std::string target;
                if (!out.read_rva_string(bytes, rva, target)) {
                    // A forwarder we cannot read is a claim the file does
                    // not keep, and it is refused rather than recorded as a
                    // forwarder to nothing. The export is left in place with
                    // its address and its name, so a reader that only wanted
                    // the names still has them; what is refused is the file,
                    // because a DLL whose forwarder cannot be read is a DLL
                    // whose import will fail later and less clearly.
                    return fail(PeError::BadExportTable,
                                "a forwarder for the export at RVA " +
                                    hex_value(rva) + " is not a readable "
                                    "string in the file");
                }

                // The split, at the last dot. `NTDLL.RtlAllocateHeap` and
                // `KERNEL32.Sleep` are the ordinary forms; a module whose
                // name contains a dot -- which Windows permitted for 16-bit
                // compatibility and which files in the wild still carry --
                // makes the first dot the wrong one to split at, and the
                // resulting half-DLL would resolve to nothing.
                const std::size_t dot = target.rfind('.');
                if (dot == std::string::npos || dot == 0 ||
                    dot + 1 >= target.size()) {
                    // No dot at all, a leading dot, or a trailing one. Each
                    // names a string the format does not define, and each is
                    // a file making a claim this reader cannot keep.
                    return fail(PeError::BadExportTable,
                                "the forwarder \"" + target +
                                    "\" is not of the form DLL.symbol or "
                                    "DLL.#ordinal");
                }
                e.forwarder_dll = target.substr(0, dot);
                const std::string symbol = target.substr(dot + 1);
                if (symbol[0] == kForwarderOrdinalPrefix) {
                    // The ordinal form. The number is parsed by hand rather
                    // than with a library function because the format accepts
                    // only decimal digits here and a parser that accepted
                    // "+27", " 27" or "0x1b" would resolve a forwarder the
                    // operating system would not.
                    //
                    // An empty or non-numeric rest is refused. "#" alone is
                    // not a forwarder to ordinal zero; it is a string the
                    // format does not define.
                    std::uint32_t ordinal = 0;
                    bool digits = !symbol.empty();
                    for (std::size_t k = 1; k < symbol.size(); ++k) {
                        const char c = symbol[k];
                        if (c < '0' || c > '9') {
                            digits = false;
                            break;
                        }
                        // The multiply-add is done in 64 bits and the result
                        // is range-checked rather than truncated: a forwarder
                        // naming an ordinal with twenty digits is a file
                        // making a claim no address table can satisfy, and
                        // truncating it would name a different one.
                        const std::uint64_t next =
                            static_cast<std::uint64_t>(ordinal) * 10u +
                            static_cast<std::uint64_t>(c - '0');
                        if (next > 0xFFFFFFFFull) {
                            digits = false;
                            break;
                        }
                        ordinal = static_cast<std::uint32_t>(next);
                    }
                    if (!digits) {
                        return fail(PeError::BadExportTable,
                                    "the forwarder \"" + target +
                                        "\" names an ordinal that is not a "
                                        "number");
                    }
                    e.forwarder_by_ordinal = true;
                    // The ordinal is recorded as the file states it. Whether
                    // it is inside this DLL's own range is not this reader's
                    // question -- the number belongs to the *forwarded* DLL and
                    // is meaningless here -- but a value of zero is refused,
                    // because the format numbers exports from the base field
                    // up and a base of zero would have to be stated by the
                    // target, which is a fact this file does not carry.
                    if (ordinal == 0) {
                        return fail(PeError::BadExportTable,
                                    "the forwarder \"" + target +
                                        "\" names ordinal zero");
                    }
                    e.forwarder_ordinal = ordinal;
                } else {
                    e.forwarder_name = symbol;
                }
            }

            // The vector is trimmed to what was actually filled. The resize
            // above made it the address table's length so that the name loop
            // could index it, and the entries a file left at zero are still in
            // it -- each one an export with no name, no RVA and the ordinal it
            // would have had. They are removed here rather than reported as
            // exports of address zero, which is the base of every image and
            // therefore a claim that would resolve to the module's own header.
            //
            // This is the only place an empty slot is recognized, and it is
            // placed after the walk rather than inside it for a reason worth
            // stating: an address of zero is also what an unreadable forwarder
            // would look like if the read were allowed to fail into it, and a
            // check inside the loop would have to be written to tell the two
            // apart. Trimming once, at the end, cannot be fooled by either --
            // a slot the file left empty and a slot whose string would not
            // read are both absent from the result, and neither is reported as
            // an export of the image base.
            out.exports_.erase(
                std::remove_if(out.exports_.begin(), out.exports_.end(),
                               [](const PeExport& e) { return e.rva == 0; }),
                out.exports_.end());
        }
    }

    out.error_ = PeError::None;
    return out;
}

bool PeImage::resolve_rva(std::uint64_t rva, std::uint64_t& file_offset,
                          bool& zero_filled) const noexcept {
    zero_filled = false;
    file_offset = 0;

    // The headers. They are at the front of the file and belong to no
    // section, and the section table itself is in here -- so a reader that
    // only searched the section table could never find the section table.
    //
    // The bound is the file's, not the header's. SizeOfHeaders is a claim
    // about how much of the file the linker reserved, and a file can claim
    // four gigabytes of it in three hundred bytes; believing that would hand
    // a caller an offset past the end of the file, one byte at a time. The
    // comparison is against bytes_size_ so that an RVA equal to the file's
    // length -- one past the last byte -- resolves to nothing. That off-by-one
    // was found by fuzz/fuzz_pe.cpp.
    if (headers_size_ != 0 && rva < headers_size_) {
        if (rva >= bytes_size_) {
            return false;
        }
        file_offset = rva;
        return true;
    }

    for (const auto& s : sections_) {
        // The containment test, written as a subtraction for the same reason
        // as every other bound in this file: a section whose virtual_address
        // is near the top of the address space would make virtual_address +
        // virtual_size wrap, and a wrapped end makes a section that covers
        // most of the address space look like one that ends before it
        // starts.
        if (rva < s.virtual_address) {
            continue;
        }
        const std::uint64_t delta = rva - s.virtual_address;
        // `mapped_size()` and not `virtual_size`. A VirtualSize of zero means
        // "as much as the file holds" rather than "nothing", and comparing
        // against the field directly made such a section unreachable: every
        // delta is at or above zero, so the loop skipped the section and an
        // RVA the Windows loader maps resolved to nothing. Nothing crashed and
        // every answer was a refusal, which is the shape of this bug -- a
        // caller cannot tell a file that does not contain the address from a
        // parser that will not look.
        if (delta >= s.mapped_size()) {
            continue;
        }

        // Inside the section's address range. Whether it is backed by the
        // file is the separate question this function's out-parameter
        // answers.
        if (delta < s.raw_size) {
            // File-backed. The offset is the section's raw offset plus the
            // distance into it -- and both come from the file, so the sum is
            // a sum of two chosen numbers. The section table already checked
            // that raw_offset + raw_size is inside the file, and delta is
            // below raw_size, so the addition cannot leave the section; it is
            // still written as a subtraction below so that the guarantee is
            // visible rather than inherited.
            if (s.raw_offset > bytes_size_) {
                return false;
            }
            const std::uint64_t room = bytes_size_ - s.raw_offset;
            if (room <= delta) {
                // Exactly at the end: the offset is one past the file.
                return false;
            }
            file_offset = s.raw_offset + delta;
            zero_filled = false;
            return true;
        }

        // Past the raw data but inside the virtual size: this is the zero
        // fill, which exists in memory and not in the file. Reported as such
        // rather than as a failure, because it is a real region of the
        // loaded image and a caller reasoning about the image wants to know
        // it is there.
        zero_filled = true;
        file_offset = 0;
        return true;
    }
    return false;
}

bool PeImage::to_file_offset(std::uint64_t rva,
                             std::uint64_t& out) const noexcept {
    bool zero_filled = false;
    if (!resolve_rva(rva, out, zero_filled)) {
        return false;
    }
    // Zero fill is deliberately not accepted here. This function answers
    // "where in the file do I read this", and the answer for a zero-filled
    // RVA is nowhere: handing back an offset would send a reader to a region
    // the file never contained, and it would read a zero and believe it was
    // a byte the file specified. The loaded-image question is
    // resolve_rva's, which is why there are two functions.
    return !zero_filled;
}

bool PeImage::read_rva_string(ByteSpan bytes, std::uint64_t rva,
                              std::string& out) const noexcept {
    out.clear();
    // The header region first: an RVA below SizeOfHeaders is a file offset
    // and needs no section, and a string in the headers is how a small
    // import table often spells a name.
    if (headers_size_ != 0 && rva < headers_size_) {
        if (rva > bytes_size_) {
            return false;
        }
        return read_cstring(bytes, static_cast<std::size_t>(rva), out);
    }

    bool zero_filled = false;
    std::uint64_t off = 0;
    if (!resolve_rva(rva, off, zero_filled) || zero_filled) {
        return false;
    }
    return read_cstring(bytes, static_cast<std::size_t>(off), out);
}

bool PeImage::read_cstring(ByteSpan bytes, std::size_t off,
                           std::string& out) noexcept {
    out.clear();
    // Bounded by the file and by a length no real name reaches. A name is
    // NUL-terminated, and a file that omits the terminator would otherwise
    // be read to the end of the buffer -- which is a read, not a crash, and
    // it is how a 4 GB "DLL name" ends up in an event stream.
    std::size_t n = 0;
    while (n < kMaxNameLength) {
        // off <= bytes.size() is established once, here, and n only grows by
        // one per iteration against a constant bound. Computing off + n on
        // each pass would be the shape that wraps when off is near the top
        // of the address space; keeping the subtraction form means the
        // check cannot be defeated by the value it is checking.
        if (!in_range(bytes, off, n + 1)) {
            // Ran off the end without a terminator. What was read is
            // discarded: a name with no terminator is not a name, and
            // reporting the fragment would be reporting something the file
            // did not say.
            return false;
        }
        if (bytes[off + n] == '\0') {
            return !out.empty();
        }
        out.push_back(static_cast<char>(bytes[off + n]));
        ++n;
    }
    // Longer than any name this reader accepts. Discarded for the same
    // reason: an unbounded string in an event is worse than none.
    return false;
}

} // namespace occ::parser

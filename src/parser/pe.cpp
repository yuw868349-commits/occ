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
// RVA/size pairs. Only two are read: the import table and the base
// relocations. The rest are reported nowhere because nothing here uses them,
// and a reader that parses what it does not need is a reader with more ways
// to be wrong.
constexpr std::size_t kDirSize = 8;
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
    return virtual_address > UINT64_MAX - virtual_size
               ? UINT64_MAX
               : static_cast<std::uint64_t>(virtual_address) + virtual_size;
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
            if (i == kDirImport) {
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
    if (out.import_rva_ != 0 && out.import_size_ != 0) {
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
        if (delta >= s.virtual_size) {
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

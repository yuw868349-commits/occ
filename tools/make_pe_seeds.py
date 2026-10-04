#!/usr/bin/env python3
"""Generates the fuzzing seed corpus for the PE harness.

The seeds are written rather than checked in as binaries so that what they
are is readable: a fuzzer starts by broadening what its corpus already
reaches, and each of these gets past one of the PE reader's gates that an
input of zeros would not.

Run from the repository root:

    python3 tools/make_pe_seeds.py fuzz/seeds
"""

import struct
import sys
from pathlib import Path

# PE32 optional header, one section, no imports. The smallest file the reader
# accepts, laid out the way a linker lays one out: the DOS header, the PE
# signature at 0x80, the COFF header, a full 224-byte optional header, one
# section header, then one page of headers and one page of section data.
def minimal_pe(*, plus=False, dll=False, machine=0x014c, subsystem=3,
               sections=1, section_chars=0x60000020, rdata_size=0x200):
    opt_size = 240 if plus else 224
    headers_size = 0x200
    coff = 0x80
    opt = coff + 4 + 20
    sections_at = opt + opt_size
    data_at = headers_size

    # Each section gets one page of file data, except .rdata which is sized
    # by the caller: the import table's seed needs room for descriptors and
    # names, and shrinking the section instead would leave the table pointing
    # past the file.
    sizes = [0x200] * sections
    if sections >= 2:
        sizes[1] = rdata_size
    total = data_at + sum(sizes)

    buf = bytearray(total)

    # DOS header. e_lfanew points at the PE signature, which is the second
    # gate: an input that has MZ but no valid e_lfanew never reaches the
    # optional header at all.
    struct.pack_into("<H", buf, 0, 0x5A4D)
    struct.pack_into("<I", buf, 0x3C, coff)

    struct.pack_into("<I", buf, coff, 0x00004550)   # "PE\0\0"
    c = coff + 4
    struct.pack_into("<H", buf, c + 0, machine)
    struct.pack_into("<H", buf, c + 2, sections)
    struct.pack_into("<H", buf, c + 16, opt_size)
    struct.pack_into("<H", buf, c + 18, 0x2000 if dll else 0x0002)

    o = opt
    struct.pack_into("<H", buf, o + 0, 0x20B if plus else 0x10B)
    buf[o + 2] = 14                                  # MajorLinkerVersion
    struct.pack_into("<I", buf, o + 4, 0x200)        # SizeOfCode
    struct.pack_into("<I", buf, o + 16, 0x1000)      # AddressOfEntryPoint
    struct.pack_into("<I", buf, o + 20, 0x1000)      # BaseOfCode
    # ImageBase: four bytes at 28 in PE32, eight at 24 in PE32+. This is the
    # offset that differs between the layouts.
    if plus:
        struct.pack_into("<Q", buf, o + 24, 0x140000000)
    else:
        struct.pack_into("<I", buf, o + 28, 0x400000)
    struct.pack_into("<I", buf, o + 32, 0x1000)      # SectionAlignment
    struct.pack_into("<I", buf, o + 36, 0x200)       # FileAlignment
    struct.pack_into("<I", buf, o + 56, 0x2000)      # SizeOfImage
    struct.pack_into("<I", buf, o + 60, headers_size)
    struct.pack_into("<H", buf, o + 68, subsystem)
    struct.pack_into("<H", buf, o + 70, 0x0160)      # DYNAMIC_BASE|NX_COMPAT
    # NumberOfRvaAndSizes, sixteen directories, none of them populated.
    struct.pack_into("<I", buf, o + (108 if plus else 92), 16)

    for i in range(sections):
        sh = sections_at + i * 40
        name = b".text" if i == 0 else b".rdata"
        buf[sh:sh + len(name)] = name
        struct.pack_into("<I", buf, sh + 8, 0x200)            # VirtualSize
        struct.pack_into("<I", buf, sh + 12, 0x1000 + i * 0x1000)
        struct.pack_into("<I", buf, sh + 16, sizes[i])               # SizeOfRawData
        struct.pack_into("<I", buf, sh + 20, data_at + sum(sizes[:i]))
        struct.pack_into("<I", buf, sh + 36, section_chars)

    return bytes(buf)


def with_import_directory(pe, dll_name=b"KERNEL32.dll", func_name=b"CreateFileW"):
    """Adds an import directory naming one DLL, laid out the way a linker
    would: the descriptor array at the start of .rdata, the DLL name after it,
    and a single thunk entry pointing at a hint/name record."""
    buf = bytearray(pe)

    # .rdata is the second section: RVA 0x2000, file offset 0x400, and it has
    # to be large enough to hold the descriptor array, both names and the
    # thunk -- all of which a linker puts in .rdata, at the start, before
    # anything else the section holds.
    rdata_file = 0x400
    rdata_rva = 0x2000

    desc_at = rdata_file
    dll_off = rdata_file + 64
    func_off = dll_off + len(dll_name) + 1
    hint_off = func_off + 2 + len(func_name) + 1
    thunk_off = hint_off + 4

    buf[dll_off:dll_off + len(dll_name)] = dll_name
    buf[func_off + 2:func_off + 2 + len(func_name)] = func_name
    # The hint, two bytes, then the name. A hint is an index into the
    # export table and is not meaningful here; zero is a valid one.
    struct.pack_into("<I", buf, thunk_off, rdata_rva + hint_off - rdata_file)

    def rva_at(off):
        return rdata_rva + (off - rdata_file)

    # One descriptor: OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name,
    # FirstThunk. Only Name and FirstThunk are non-zero; the reader reads the
    # DLL name.
    struct.pack_into("<I", buf, desc_at + 0, rva_at(thunk_off))
    struct.pack_into("<I", buf, desc_at + 12, rva_at(dll_off))
    struct.pack_into("<I", buf, desc_at + 16, rva_at(thunk_off))
    # The null terminator, so the walk has an end the file declares.
    for i in range(20):
        buf[desc_at + 20 + i] = 0

    # The directories' offset depends on the layout, which is stated by the magic
    # at the start of the optional header -- not by the PE signature, which is
    # at the COFF header and is always "PE\0\0".
    opt = 0x80 + 4 + 20
    plus = struct.unpack_from("<H", buf, opt)[0] == 0x20B
    dirs = opt + (112 if plus else 96)
    struct.pack_into("<I", buf, dirs + 1 * 8, rdata_rva)
    struct.pack_into("<I", buf, dirs + 1 * 8 + 4, 40)  # two descriptors

    return bytes(buf)


def _short_optional_header(pe, declared_size):
    """Rewrites SizeOfOptionalHeader in the COFF header.

    Truncating the file is not the same thing, and the difference is the
    point: a truncated file fails the check that the declared length is
    inside the file, while a file that declares a short header and carries
    the bytes anyway passes that check and reaches the fields. Only the
    second one is the case where reading past the declaration reads the
    section table.

    The COFF header's SizeOfOptionalHeader also says where the section table
    starts, so shortening it moves the table -- and the fixture keeps its
    bytes where they were. That is exactly the confusion being tested: the
    section table is now somewhere the file does not say it is.
    """
    buf = bytearray(pe)
    struct.pack_into("<H", buf, 0x80 + 4 + 16, declared_size)
    return bytes(buf)


# The corpus. Each entry exists to get past a specific gate, and the comment
# says which one -- a seed whose purpose is unclear is a seed nobody
# regenerates when it stops being useful.
SEEDS = {
    # The smallest file that parses at all. Everything past the optional
    # header's magic is reachable from here.
    "pe32_min.bin": minimal_pe(),

    # The 64-bit layout. The image base is eight bytes at a different offset,
    # so a reader that used one table for both would take a different path
    # here rather than the same one.
    "pe32plus_min.bin": minimal_pe(plus=True, machine=0x8664),

    # A DLL. The characteristics bit is what tells the two apart, and the
    # engine branches on it.
    "pe_dll.bin": minimal_pe(dll=True, subsystem=2),

    # Two sections, so the RVA-to-offset conversion has a choice of section to
    # make and can make the wrong one.
    "pe_two_sections.bin": minimal_pe(sections=2),

    # An import table, so the descriptor walk and the name resolution are
    # reachable. This is the path where a file offset and an RVA get confused.
    "pe_imports.bin": with_import_directory(minimal_pe(sections=2,
                                                       rdata_size=0x400)),

    # MZ with nothing else. Reaches the signature check and stops, which is
    # the branch that has to say "too short" rather than read past the end.
    "mz_only.bin": b"MZ",

    # A DOS header whose e_lfanew points at bytes that are not a signature.
    # The reader must distinguish "not a PE" from "a PE with a bad header",
    # and only an input that gets that far exercises the difference.
    "mz_no_signature.bin": (
        b"MZ" + bytes(0x3A) + struct.pack("<I", 0x80) + bytes(0x80 - 0x3E)
        + b"XXXX" + bytes(0x100)
    ),

    # A PE whose optional header declares itself shorter than the fields the
    # reader takes from it. Truncating the file is not enough -- the header
    # would still claim 224 bytes -- so the length in the COFF header is
    # rewritten to sixteen, and the bytes after it are kept. Reading the
    # subsystem anyway reads the section table and believes it; that is the
    # case this seed exists to reach.
    "pe_short_optional.bin": _short_optional_header(minimal_pe(), 16),

    # The same file with a length that cannot even hold the two-byte magic
    # that says which layout it is.
    "pe_tiny_optional.bin": _short_optional_header(minimal_pe(), 1),
}


def main():
    if len(sys.argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)

    for name, data in SEEDS.items():
        path = out / name
        path.write_bytes(bytes(data))
        print(f"{path}  {len(data)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
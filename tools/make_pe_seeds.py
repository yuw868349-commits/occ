#!/usr/bin/env python3
"""Generates the fuzzing seed corpus.

The seeds are written rather than checked in as binaries so that what they
are is readable: a fuzzer starts by broadening what its corpus already
reaches, and each of these gets past one of the reader's gates that an
input of zeros would not.

Three harnesses have seeds. They are generated here for the same reason
rather than two of them by hand: a binary checked in without the program
that makes it says only what it is, and the ELF and RSP seeds were both
written that way before. A reader who opens this file can see that one of
them declares thirteen program headers in a file that cannot hold them,
which is the entire point of it.

Run from the repository root:

    python3 tools/make_pe_seeds.py fuzz/seeds

The output is byte-for-byte reproducible and tests/test_seeds.cpp checks it
against what is checked in, so a seed cannot drift away from the generator
without a test failing. Python is not part of the build: it is only needed
to change a seed, never to compile or to run one.
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


def _loader_regressions(pe):
    """Shapes the loader harness is required to refuse.

    Each of these is a file the loader accepted before its entry-point and
    layout checks existed, and each one loads, reports success, and hands the
    layer above a module that faults on its first instruction. They are seeds
    rather than checked-in crash bytes for the same reason the other seeds
    are: a binary in a diff says nothing about what it is, and the point of
    every one of these is a specific field with a specific value.

    The loader harness traps on a violated invariant rather than returning,
    so a seed here is a permanent guard: the fuzzer starts next to the
    boundary instead of having to find it again.
    """
    opt = 0x80 + 4 + 20
    plus = struct.unpack_from("<H", pe, opt)[0] == 0x20B
    # The section table starts right after the optional header, whose length
    # the COFF header states.
    opt_size = struct.unpack_from("<H", pe, 0x80 + 4 + 16)[0]
    sections_at = opt + opt_size

    def override_entry(buf, rva):
        # AddressOfEntryPoint is at 16 in both layouts.
        struct.pack_into("<I", buf, opt + 16, rva)

    def override_section(buf, index, *, va=None, vsize=None, chars=None,
                         raw_size=None):
        sh = sections_at + index * 40
        if va is not None:
            struct.pack_into("<I", buf, sh + 12, va)
        if vsize is not None:
            struct.pack_into("<I", buf, sh + 8, vsize)
        if raw_size is not None:
            struct.pack_into("<I", buf, sh + 16, raw_size)
        if chars is not None:
            struct.pack_into("<I", buf, sh + 36, chars)

    results = {}

    # (1) The entry point is past every section. The image declares 0x2000
    #     bytes and the one section occupies [0x1000, 0x2000), but the entry
    #     RVA is 0x3000, outside both. Before the check existed this loaded
    #     and produced a module whose entry address was never mapped.
    buf = bytearray(pe)
    override_entry(buf, 0x3000)
    results["pe_bad_entry_rva.bin"] = bytes(buf)

    # (2) The entry point is inside a section that is not executable. The
    #     section characteristics are read-only, so the entry lands in a
    #     PAGE_READONLY region -- mapped, and impossible to begin executing
    #     in. This is the shape the fuzzer produced twice.
    buf = bytearray(pe)
    override_entry(buf, 0x1000)
    override_section(buf, 0, chars=0x40000040)  # MEM_READ only, no execute
    results["pe_entry_not_executable.bin"] = bytes(buf)

    # (3) A section whose VirtualAddress is zero, so it overlaps the headers.
    #     The address is legal in the format and unusable: the headers are
    #     at the image base, and a section there is a section placed over
    #     them. Before the layout check this recorded the headers and then
    #     failed, leaving the headers in the map.
    buf = bytearray(pe)
    override_entry(buf, 0x1000)
    override_section(buf, 0, va=0x0, vsize=0x2000)
    results["pe_section_over_headers.bin"] = bytes(buf)

    return results


# The corpus. Each entry exists to get past a specific gate, and the comment
# says which one -- a seed whose purpose is unclear is a seed nobody
# regenerates when it stops being useful.
PE_SEEDS = {
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

# The loader's own regressions, kept separate because they are about the
# loader's contract rather than about the parser's gates, and merged in here
# so that the PE corpus is one place.
#
# The base is the 64-bit image, not the 32-bit one. The loader refuses a
# non-amd64 image before it reads any layout field, so a regression seed
# built on the i386 base would be rejected by the machine check and would
# reach none of the checks it exists to exercise -- which is exactly what
# happened the first time this was written.
PE_SEEDS.update(_loader_regressions(minimal_pe(plus=True, machine=0x8664)))


# ---------------------------------------------------------------- ELF

# Field offsets in the 64-bit header, named as in include/occ/parser/elf.h
# and matching the constants in src/parser/elf.cpp. Stated here rather than
# shared with the reader because the reader is C++ and this is Python, and
# because a generator that imported the reader's offsets would be a second
# thing to keep in step rather than a description of the format.
_ELF_OFF_TYPE = 16
_ELF_OFF_MACHINE = 18
_ELF_OFF_ENTRY = 24
_ELF_OFF_PHOFF = 32
_ELF_OFF_SHOFF = 40
_ELF_OFF_EHSIZE = 52
_ELF_OFF_PHENTSIZE = 54
_ELF_OFF_PHNUM = 56
_ELF_OFF_SHENTSIZE = 58
_ELF_OFF_SHNUM = 60
_ELF_OFF_SHSTRNDX = 62

# The 64-bit header is 64 bytes and the 64-bit program header is 56. The
# reader checks e_phentsize against the second number rather than assuming
# it, so a seed that wants to reach the segment table has to state it.
_ELF64_HEADER_SIZE = 64
_ELF64_PHDR_SIZE = 56


def truncated_elf(*, machine=0x3E, elf_type=3, phoff=0x40, phnum=13, shoff=0x9218):
    """A 64-bit ELF header whose program header table does not fit.

    The name this seed carries says "minimal", and it is worth saying why
    that is misleading rather than renaming the file: what the file is, is
    the shape where the header parses completely, every field in it is
    plausible, and the table it points at runs past the end of the file.
    Reading it with ElfImage::parse gives, verbatim:

        error 6, "the table runs from 0x40 to 0x318 and the file is 256 bytes"

    That is the point. Everything up to and including the phdr-count check
    is reachable from this file, so the fuzzer starts next to the boundary
    rather than having to find its way there through 256 bytes of nothing.
    An input of zeros stops at the magic; this one stops four fields later.

    The numbers are chosen so that nothing else refuses the file first. The
    type is ET_DYN and the machine is x86-64, which are the two the reader
    accepts, and e_phentsize is the size it steps by, so the check that
    fires is the one about the table's extent and not one of the two easier
    ones above it. phnum is 13 because 13 * 56 is a table that clearly
    overruns a 256-byte file rather than one that lands just past the end,
    where the two mistakes are easy to confuse.
    """
    buf = bytearray(_ELF64_HEADER_SIZE)

    # e_ident. The class, the encoding and the version are the three the
    # reader checks; the rest is the padding the format specifies.
    buf[0:4] = b"\x7fELF"
    buf[4] = 2                                          # EI_CLASS: ELFCLASS64
    buf[5] = 1                                          # EI_DATA: ELFDATA2LSB
    buf[6] = 1                                          # EI_VERSION: EV_CURRENT

    struct.pack_into("<H", buf, _ELF_OFF_TYPE, elf_type)
    struct.pack_into("<H", buf, _ELF_OFF_MACHINE, machine)
    # e_version, the 32-bit field after the three 16-bit ones above. The
    # reader does not take it from here -- it uses e_ident[EI_VERSION] -- so
    # this one is set to the current value rather than left at zero, which is
    # what makes it a field a reader could get wrong.
    struct.pack_into("<I", buf, 20, 1)
    struct.pack_into("<Q", buf, _ELF_OFF_ENTRY, 0x3AC0)
    struct.pack_into("<Q", buf, _ELF_OFF_PHOFF, phoff)
    # e_shoff points into the middle of nowhere: 0x9218 is well past the end
    # of a 256-byte file, and it is not a value the program header count
    # produces, so a reader that checked the segment table's extent and then
    # went on to the section table's would find a second overrun rather than
    # the one it had already refused.
    struct.pack_into("<Q", buf, _ELF_OFF_SHOFF, shoff)
    struct.pack_into("<H", buf, _ELF_OFF_EHSIZE, _ELF64_HEADER_SIZE)
    struct.pack_into("<H", buf, _ELF_OFF_PHENTSIZE, _ELF64_PHDR_SIZE)
    struct.pack_into("<H", buf, _ELF_OFF_PHNUM, phnum)
    struct.pack_into("<H", buf, _ELF_OFF_SHENTSIZE, 64)  # Elf64_Shdr size
    struct.pack_into("<H", buf, _ELF_OFF_SHNUM, 31)
    struct.pack_into("<H", buf, _ELF_OFF_SHSTRNDX, 30)

    # Four program headers, the last one cut off after its first four fields.
    #
    # The point of writing them at all is that a fuzzer mutating this file
    # starts from a table with plausible contents rather than from 200 bytes
    # of zero, and the headers give it segment types, flags, offsets and
    # virtual addresses to move. They are never read -- the count above
    # refuses the file first -- so what they say does not matter, and the
    # fourth is truncated because a file that ended on a header boundary
    # would not be the shape where the table runs off the end. Its four
    # surviving fields are the ones a reader would take first, which makes
    # it the shape where a reader that checked the count but not the file
    # length would read a header and believe it.
    phdrs = bytearray()
    # PT_PHDR, then PT_INTERP, then a PT_LOAD at zero and one at 0x2000 --
    # the four types a real dynamic executable has, in the order it has them.
    phdrs += struct.pack("<IIQQQQQQ", 6, 4, 0x40, 0x40, 0x40, 0x2D8, 0x2D8, 8)
    phdrs += struct.pack("<IIQQQQQQ", 3, 4, 0x318, 0x318, 0x318, 0x1C, 0x1C, 1)
    phdrs += struct.pack("<IIQQQQQQ", 1, 4, 0, 0, 0, 0x1640, 0x1640, 0x1000)
    phdrs += struct.pack("<IIQQ", 1, 5, 0x2000, 0x2000)
    buf += phdrs

    return bytes(buf)


# ---------------------------------------------------------------- RSP

def rsp_query(payload=b"g"):
    """One framed GDB remote-serial-protocol packet, plus trailing noise.

    The packet is the "read registers" request a debugger sends first, and
    the framing is what the decoder has to see before it will look at any of
    it: a dollar, the payload, a hash, and two hex digits whose value is the
    payload's bytes summed mod 256. For "g" that sum is 0x67, which is what
    the two characters after the hash are.

    The newline at the end is not part of the packet and is not an accident
    of how the file was written. It is there because a byte outside a packet
    is a case the decoder has to get right: the protocol says to ignore it,
    and a decoder that treated an unexpected byte as the start of a checksum
    would leave this file waiting for two more digits that never come. The
    packet and the noise are one input because they are one thing a real peer
    does -- a line-oriented terminal, or a debugger whose output is captured
    with its echo.

    Feeding this to the decoder yields one packet with data "g" and
    checksum_ok set, and asks for a '+' back. Feeding it without the
    newline yields the same packet, which is the check that the newline
    changed nothing.
    """
    body = bytes(payload)
    cksum = sum(body) & 0xFF
    return b"$" + body + b"#" + ("%02x" % cksum).encode("ascii") + b"\n"


# The seeds for the harnesses that are not the PE one. Kept beside the PE
# seeds rather than in a second generator because the reason they are
# generated is the same reason, and a reader looking for "what does this
# harness start from" should find the answer in one place.
OTHER_SEEDS = {
    # Reaches the program header table's extent check and is refused there.
    # See truncated_elf for why it is shaped this way and what it reports.
    "elf_min.bin": truncated_elf(),

    # A well-formed packet the decoder accepts, followed by a byte it has to
    # ignore. See rsp_query.
    "rsp_g.gdb": rsp_query(),
}

SEEDS = dict(PE_SEEDS)
SEEDS.update(OTHER_SEEDS)


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
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

Four harnesses have seeds now, and the fourth is a different kind of thing
from the other three. The parsers are handed a file; the seccomp emitter is
handed a *policy*, which is a typed struct rather than a byte stream, so
there is no file format here to describe. The seeds below are therefore the
harness's own input encoding -- the fields fuzz_seccomp.cpp reads, in the
order it reads them -- and each one is written to reach a particular branch
of the emitter. They are generated for the reason the others are, which is
that a seed nobody can read is a seed nobody can regenerate, and the reading
is what says which branch a given seed is for.

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
#
# image_base defaults to None, which means "the base a linker would have
# chosen for this layout": 0x400000 for PE32 and 0x140000000 for PE32+.
# Passing 0 asks for an image that names no base at all, which is a legal
# field value and a shape the loader has to answer rather than assume -- see
# pe_base_zero.bin.
def minimal_pe(*, plus=False, dll=False, machine=0x014c, subsystem=3,
               sections=1, section_chars=0x60000020, rdata_size=0x200,
               image_base=None):
    opt_size = 240 if plus else 224
    headers_size = 0x200
    coff = 0x80
    opt = coff + 4 + 20
    sections_at = opt + opt_size
    data_at = headers_size
    if image_base is None:
        image_base = 0x140000000 if plus else 0x400000

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
        struct.pack_into("<Q", buf, o + 24, image_base)
    else:
        struct.pack_into("<I", buf, o + 28, image_base)
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

    # (4) A data directory array that stops before the TLS entry. The
    #     directory array is the last thing in the optional header and its
    #     length is a count, not a size, so an image can declare eight
    #     directories -- indexes 0 through 7, stopping one short of the TLS
    #     entry at index 9 -- and still be a well-formed optional header.
    #
    #     This one is the only seed here that the fuzzer found rather than a
    #     person, and it found it through a stage the other three cannot
    #     reach. Every one of those is refused by a check that runs *before*
    #     the image is recorded in the address space, so the refusal costs
    #     nothing. The TLS directory is read after the record, and the
    #     loader rolled that record back only when a mapper was supplied --
    #     a load with no mapper left the space describing an image whose
    #     bytes were never placed, which a caller cannot tell from a
    #     successful load.
    #
    #     It needs two sections so that the array has room to be short
    #     without shortening the file, and a TLS entry at an RVA inside the
    #     second one so that the only thing wrong with it is the count.
    buf = bytearray(pe)
    override_entry(buf, 0x1000)
    # NumberOfRvaAndSizes is at 108 in the PE32+ layout: 24 bytes of Windows
    # fields and standard fields, then 8 for the three timestamp and symbol
    # counts, plus 68 for the versions, then the two 4-byte size fields.
    struct.pack_into("<I", buf, opt + 108, 8)
    # And the TLS entry, which the short array no longer covers, still points
    # at something inside the image -- so an implementation that read it
    # anyway would find a directory rather than nothing, and the refusal
    # would have to come from the count.
    struct.pack_into("<II", buf, opt + 112 + 9 * 8, 0x2000, 0x28)
    results["pe_short_data_directory.bin"] = bytes(buf)

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


def _corpus_regressions():
    """Shapes the accumulated corpus reached and no seed did.

    Every one of these was found by running the PE harness over a few thousand
    inputs and then asking which verdict each one got -- not by reading the
    loader for a way to make it fail. That distinction is the reason they are
    here: a shape invented from the source is a shape the author already
    believed reachable, so it tests the belief rather than the code. These
    three came out of the corpus as hash-named files, and what is checked in
    is the generator call that produces the same verdict from a field anyone
    can read.

    The rest of the corpus's verdicts are not here, and the reason is worth
    stating because it is the rule rather than an omission. Most of what the
    fuzzer found is a field damaged past the point of naming: section 19 at
    0xffffffff for 0xffffffff bytes, an import directory at RVA 0xe8e8e8e8,
    a SizeOfHeaders of 0x40189f89. Each reaches a real check, and none of them
    is a shape a person would write, so a seed built from one would document
    nothing a reader did not already know from the message. Three that name
    something are worth the bytes.
    """
    results = {}

    # An image that names no base, with no relocation table to fall back on.
    #
    # The loader's answer is "no_relocations: the image names no base and the
    # caller named none", and it is reached by two fields agreeing: ImageBase
    # zero, and no reloc_rva. Both are legal on their own -- a PIE linked for
    # zero is not a malformed file -- so the only way to see this is to ask
    # for it, and every seed that named a base made it unreachable.
    #
    # It is the shape that decides where an image lands, which is the first
    # thing the loader does after agreeing the machine is right, so a change
    # to the base rule that stopped consulting the caller's preference would
    # still pass every other seed here.
    results["pe_base_zero.bin"] = minimal_pe(plus=True, machine=0x8664,
                                             image_base=0)

    # Two architectures this runtime does not execute.
    #
    # The seeds are all i386 or amd64, which between them cover the machine
    # check agreeing and the machine check refusing. They do not cover the
    # refusal naming a machine no reader thought to try, and the name comes
    # from the file rather than from a table in occ -- so a fuzzer that never
    # saw 0xaa64 had never seen the name it would print for 0xaa64.
    results["pe_machine_arm.bin"] = minimal_pe(machine=0x01C0)
    results["pe_machine_arm64.bin"] = minimal_pe(plus=True, machine=0xAA64)

    return results


PE_SEEDS.update(_corpus_regressions())


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


# ---------------------------------------------------------------- zip

# Offsets inside the three records, named so that the packing below reads as
# the layout rather than as a row of numbers. A central directory record is
# the one place where a mistake is invisible in the output: pack the fields in
# the wrong order and the record still has the right length, so the reader
# walks straight through it and finds a name of four bytes where there should
# be nineteen. These were checked against a zip produced by Info-ZIP 3.0,
# field by field, rather than against the specification alone.
_ZIP_LOCAL_SIG = 0x04034B50
_ZIP_CENTRAL_SIG = 0x02014B50
_ZIP_EOCD_SIG = 0x06054B50

_ZIP_LOCAL_NAME_LEN = 26
_ZIP_LOCAL_EXTRA_LEN = 28

_ZIP_CENTRAL_METHOD = 10
_ZIP_CENTRAL_COMP_SIZE = 20
_ZIP_CENTRAL_UNCOMP_SIZE = 24
_ZIP_CENTRAL_NAME_LEN = 28
_ZIP_CENTRAL_EXTRA_LEN = 30
_ZIP_CENTRAL_COMMENT_LEN = 32
_ZIP_CENTRAL_HEADER_SIZE = 46

_ZIP_EOCD_ENTRIES = 10
_ZIP_EOCD_CD_SIZE = 12
_ZIP_EOCD_CD_OFFSET = 16
_ZIP_EOCD_SIZE = 22

# A stored member: no compression, so the two sizes are equal and the bytes
# on disk are the bytes in the member.
_ZIP_STORED = 0
# Method 8 is deflate. The member's contents are not deflated here, because
# nothing ever reads them -- the directory records the sizes and occ does not
# inflate anything. A seed whose payload was not really compressed is still
# a valid directory record, and the field under test is the method number.
_ZIP_DEFLATED = 8


def _zip_local(name, method, payload):
    """A local file header followed by the member's data."""
    raw = name if isinstance(name, bytes) else name.encode("utf-8")
    head = bytearray(30)
    struct.pack_into("<I", head, 0, _ZIP_LOCAL_SIG)
    struct.pack_into("<H", head, 4, 20)        # version needed to extract
    struct.pack_into("<H", head, 6, 0)         # flags
    struct.pack_into("<H", head, 8, method)
    struct.pack_into("<I", head, 18, len(payload))   # compressed size
    struct.pack_into("<I", head, 22, len(payload))   # uncompressed size
    struct.pack_into("<H", head, _ZIP_LOCAL_NAME_LEN, len(raw))
    struct.pack_into("<H", head, _ZIP_LOCAL_EXTRA_LEN, 0)
    return bytes(head) + raw + bytes(payload)


def _zip_central(name, method, comp_size, uncomp_size, *,
                 name_len=None, extra_len=0, comment_len=0,
                 comment=b"", extra=b""):
    """A central directory record.

    The three lengths are what this reader checks against the directory's
    extent, and they are settable apart from the bytes actually written --
    which is how the malformed seeds below are built. `comment_len` says what
    the header claims; `comment` is what follows. Writing a claim larger than
    the bytes is the shape a truncated archive has.
    """
    raw = name if isinstance(name, bytes) else name.encode("utf-8")
    rec = bytearray(_ZIP_CENTRAL_HEADER_SIZE)
    struct.pack_into("<I", rec, 0, _ZIP_CENTRAL_SIG)
    struct.pack_into("<H", rec, 4, 20)         # version made by
    struct.pack_into("<H", rec, 6, 20)         # version needed
    struct.pack_into("<H", rec, 8, 0)          # flags
    struct.pack_into("<H", rec, _ZIP_CENTRAL_METHOD, method)
    struct.pack_into("<I", rec, _ZIP_CENTRAL_COMP_SIZE, comp_size)
    struct.pack_into("<I", rec, _ZIP_CENTRAL_UNCOMP_SIZE, uncomp_size)
    struct.pack_into("<H", rec, _ZIP_CENTRAL_NAME_LEN,
                     len(raw) if name_len is None else name_len)
    struct.pack_into("<H", rec, _ZIP_CENTRAL_EXTRA_LEN, extra_len)
    struct.pack_into("<H", rec, _ZIP_CENTRAL_COMMENT_LEN, comment_len)
    return bytes(rec) + raw + bytes(extra) + bytes(comment)


def _zip_eocd(entries, cd_size, cd_offset, comment=b""):
    """The end-of-central-directory record, with an optional archive comment."""
    rec = bytearray(_ZIP_EOCD_SIZE)
    struct.pack_into("<I", rec, 0, _ZIP_EOCD_SIG)
    struct.pack_into("<H", rec, 4, 0)          # this disk
    struct.pack_into("<H", rec, 6, 0)          # disk with the directory
    struct.pack_into("<H", rec, 8, entries)    # entries on this disk
    struct.pack_into("<H", rec, _ZIP_EOCD_ENTRIES, entries)
    struct.pack_into("<I", rec, _ZIP_EOCD_CD_SIZE, cd_size)
    struct.pack_into("<I", rec, _ZIP_EOCD_CD_OFFSET, cd_offset)
    struct.pack_into("<H", rec, 20, len(comment))
    return bytes(rec) + bytes(comment)


def zip_archive(members, *, comment=b"", entries=None, cd_size=None,
                cd_offset=None):
    """A whole archive: local headers, a central directory, and an EOCD.

    `members` is a list of (name, method, payload, compressed_size,
    uncompressed_size). The two sizes are passed rather than derived from the
    payload because a directory record's sizes are the claim under test: a
    real deflated member's compressed size is smaller than its bytes, and a
    seed that recorded the payload's length in both fields would never reach
    the code that has to tell them apart.

    The three overrides on the EOCD are the fields a malformed file lies
    about, and each produces a different refusal.

    Raises ValueError on a record that cannot exist. A stored member's two
    sizes are the same claim stated twice, so a seed giving them different
    values describes an archive no writer could produce -- and the harness
    would reject it as a broken invariant rather than as the malformed input
    it was meant to be. Catching it here means the mistake is a stack trace
    naming the call rather than a fuzzer artifact found forty seconds later.
    """
    for name, method, _payload, comp, uncomp in members:
        if method == _ZIP_STORED and comp != uncomp:
            raise ValueError(
                f"stored member {name!r} declares two sizes ({comp} and "
                f"{uncomp}); a stored member's sizes are equal by definition")

    body = bytearray()
    directory = bytearray()
    for name, method, payload, comp, uncomp in members:
        body += _zip_local(name, method, payload)
        directory += _zip_central(name, method, comp, uncomp)

    offset = len(body)
    body += directory
    tail = _zip_eocd(
        len(members) if entries is None else entries,
        len(directory) if cd_size is None else cd_size,
        offset if cd_offset is None else cd_offset,
        comment)
    return bytes(body) + tail


# The manifest is what makes a zip a package, so it is the first member in
# every archive below that is meant to be detected as one.
_MANIFEST = b"AndroidManifest.xml"
# A real manifest is a compiled binary XML blob. The first bytes matter to a
# real reader and not to this one, so this is the actual AXML magic followed
# by padding: it makes the seed look like what it is to anything that sniffs
# the member, which a fuzzer will do by accident.
_MANIFEST_BYTES = b"\x03\x00\x08\x00" + b"\x00" * 14
# An ELF header, so the member under lib/ is the shape occ could be pointed
# at instead of the package. The refusal says to extract exactly this file.
_SO_BYTES = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00\x3e\x00"


def _zip_seeds():
    """The archives the detection harness starts from.

    Each one gets past a different gate. The reader is the zip central
    directory, and its gates are: find the end-of-central-directory record,
    believe the directory's offset and size, then believe each record's
    name, extra and comment lengths. A seed that stops at the first gate
    teaches the fuzzer about the first gate only.
    """
    seeds = {}

    # The whole reader, reached and passed: two members, one of them a native
    # library, so the report list has a manifest and a lib/ entry and the
    # omitted-count path is not taken. This is the seed that makes the rest
    # reachable -- without an archive that reads, the later gates are only
    # ever reached by mutation.
    seeds["zip_package.zip"] = zip_archive([
        (_MANIFEST, _ZIP_STORED, _MANIFEST_BYTES,
         len(_MANIFEST_BYTES), len(_MANIFEST_BYTES)),
        (b"lib/arm64-v8a/libfoo.so", _ZIP_STORED, _SO_BYTES,
         len(_SO_BYTES), len(_SO_BYTES)),
    ])

    # The same archive with a deflated library, so the two sizes in a record
    # are different. The stored/deflated branch and the "print the size on
    # disk as well" branch are both here and nowhere else.
    seeds["zip_deflated.zip"] = zip_archive([
        (_MANIFEST, _ZIP_STORED, _MANIFEST_BYTES,
         len(_MANIFEST_BYTES), len(_MANIFEST_BYTES)),
        (b"lib/x86_64/libfoo.so", _ZIP_DEFLATED, _SO_BYTES,
         30, len(_SO_BYTES)),
    ])

    # More members than the report lists, so the cap and the line saying what
    # it left out are both reached. A real package has thousands of entries
    # and a real one has some libraries; the report's bound is only
    # meaningful when something hits it.
    many = [(_MANIFEST, _ZIP_STORED, _MANIFEST_BYTES,
             len(_MANIFEST_BYTES), len(_MANIFEST_BYTES))]
    for abi in (b"arm64-v8a", b"armeabi-v7a", b"x86", b"x86_64"):
        for lib in (b"libfoo.so", b"libbar.so", b"libbaz.so"):
            many.append((b"lib/" + abi + b"/" + lib, _ZIP_STORED, _SO_BYTES,
                         len(_SO_BYTES), len(_SO_BYTES)))
    many.append((b"classes.dex", _ZIP_DEFLATED, b"dex\n035\x00",
                 12, 40000))
    # Stored, so the two sizes have to be equal: a record claiming method 0
    # with two different sizes describes a file that cannot exist, and a
    # reader that believed it would be believing an archive nobody wrote.
    # The uncompressed size here is the member's real length.
    many.append((b"resources.arsc", _ZIP_STORED, b"\x02\x00\x0c\x00",
                 4, 4))
    seeds["zip_many_members.zip"] = zip_archive(many)

    # An archive comment, which is the reason the end record is searched for
    # rather than assumed to be the last 22 bytes. A build stamps its own
    # name there, so this is not a shape a producer has to go out of its way
    # to write.
    seeds["zip_commented.zip"] = zip_archive([
        (_MANIFEST, _ZIP_STORED, _MANIFEST_BYTES,
         len(_MANIFEST_BYTES), len(_MANIFEST_BYTES)),
    ], comment=b"built by occ's seed generator, 2026")

    # A member count larger than the directory holds. The walk stops when the
    # records run out, so the answer is the members that exist -- and the
    # count field being wrong is the case that separates a reader which
    # bounds its walk by the count from one which bounds it by the directory.
    seeds["zip_count_lies.zip"] = zip_archive([
        (_MANIFEST, _ZIP_STORED, _MANIFEST_BYTES,
         len(_MANIFEST_BYTES), len(_MANIFEST_BYTES)),
        (b"lib/arm64-v8a/libfoo.so", _ZIP_STORED, _SO_BYTES,
         len(_SO_BYTES), len(_SO_BYTES)),
    ], entries=30000)

    # A directory offset past the end of the file. The offset is 32 bits and
    # comes straight from the file, so this is the case the subtraction in the
    # bounds check exists for.
    seeds["zip_offset_past_end.zip"] = zip_archive([
        (_MANIFEST, _ZIP_STORED, _MANIFEST_BYTES,
         len(_MANIFEST_BYTES), len(_MANIFEST_BYTES)),
    ], cd_offset=0xFFFFFF00)

    # A directory size larger than what is there, from an offset that is
    # correct. The magic at the offset matches, so the walk starts; the size
    # is the only thing saying how far it may go.
    seeds["zip_size_lies.zip"] = zip_archive([
        (_MANIFEST, _ZIP_STORED, _MANIFEST_BYTES,
         len(_MANIFEST_BYTES), len(_MANIFEST_BYTES)),
    ], cd_size=0x7FFFFFFF)

    # A record whose name fits and whose comment does not. The record claims
    # 200 bytes of comment inside a directory that has 40, and the record
    # after it is a real one. A reader that adds the three lengths before
    # comparing stops here and reports one member; a reader that checks the
    # name alone accepts the record, starts the next one 200 bytes late,
    # finds no magic and stops -- with the same answer for the wrong reason.
    # The seed is here so that the difference is reachable, and the unit
    # tests in tests/test_detect.cpp are what tell the two apart.
    body = _zip_local(_MANIFEST, _ZIP_STORED, _MANIFEST_BYTES)
    directory = _zip_central(_MANIFEST, _ZIP_STORED,
                             len(_MANIFEST_BYTES), len(_MANIFEST_BYTES))
    directory += _zip_central(_MANIFEST, _ZIP_STORED, 18, 18,
                              comment_len=200, comment=b" " * 40)
    offset = len(body)
    seeds["zip_comment_overruns.zip"] = body + directory + _zip_eocd(
        2, len(directory), offset)

    # A streamed archive: local headers and no central directory at all. The
    # first member is still the manifest, so this is detected as a package
    # with no member list -- which is a different answer from a package with
    # an empty one, and both are real.
    seeds["zip_streamed.apk"] = (
        _zip_local(_MANIFEST, _ZIP_STORED, _MANIFEST_BYTES)
        + _zip_local(b"classes.dex", _ZIP_DEFLATED, b"dex\n035\x00", )
    )

    return seeds


# ---------------------------------------------------------------- seccomp

# The seccomp harness is not handed a file, so there is no format to describe
# here. What it is handed is the policy encoding fuzz_seccomp.cpp reads, and
# these are its fields in the order it reads them:
#
#     u8    fallback          % 4 -> Allow / Errno / Trap / KillProcess
#     u32   fallback_error    % 4096 + 1, so never zero
#     u32   ceiling           % 4 == 0 -> 0 (the default), else % 4096
#     u8    rule_count        % 25
#     per rule:
#       u32   nr
#       u8    action          % 5 -> Errno / Allow / Trap / KillThread /
#                                 KillProcess
#       u32   error           % 4096 + 1, so never zero
#       u8    test_count      % 7
#       per test:
#         u8  index           % 6
#         u8  cmp             % 7, and % 7 == 6 selects Masked
#         u32 value
#
# Every modulus is stated here because a seed is only useful if it lands where
# its comment says it does, and "it happens to" is not a property a
# regenerated seed may keep. The encodings below are therefore computed from
# these same constants rather than typed as literals, so a change to the
# harness's decoding is a change to these too.

_SEC_FALLBACK_ERRNO = 0        # % 4 -> 0
_SEC_FALLBACK_ALLOW = 1         # % 4 -> 1
_SEC_FALLBACK_TRAP = 2          # % 4 -> 2
_SEC_FALLBACK_KILL = 3          # % 4 -> 3

_SEC_ACTION_ERRNO = 0           # % 5 -> 0
_SEC_ACTION_ALLOW = 1           # % 5 -> 1
_SEC_ACTION_TRAP = 2            # % 5 -> 2
_SEC_ACTION_KILL_THREAD = 3     # % 5 -> 3
_SEC_ACTION_KILL_PROCESS = 4    # % 5 -> 4

_SEC_CMP_EQUAL = 0
_SEC_CMP_NOT_EQUAL = 1
_SEC_CMP_GREATER = 2
_SEC_CMP_GREATER_OR_EQUAL = 3
_SEC_CMP_LESS = 4
_SEC_CMP_LESS_OR_EQUAL = 5
_SEC_CMP_MASKED = 6             # % 7 == 6, and the only masked value

# A ceiling of zero means "use the builder's own default", and the default is
# the value the x32 defence rests on, so the seed that uses it is the one that
# reaches the range test with the number the header talks about.
#
# The harness reads a ceiling as `raw % 4 == 0 ? 0 : raw % 4096`, which is
# worth stating because it has a consequence that is easy to get wrong from the
# outside: one raw byte reaches every ceiling, and a byte that is a multiple of
# four is spent on the default. So three of every four raw bytes pick a
# concrete ceiling and one picks the default, and a *named* ceiling has to be
# not a multiple of four to arrive. `seccomp_policy` asserts that, which is why
# the first version of `seccomp_low_ceiling.pol` said 4 and arrived as the
# default it was trying not to be.
_SEC_CEILING_DEFAULT = 0


def _sec_ceiling(value):
    """The raw u32 that decodes to `value` in the harness's ceiling encoding.

    Not every ceiling is nameable, and the reason is arithmetic rather than a
    choice. The harness reads `raw % 4 == 0 ? 0 : raw % 4096`, so a raw byte
    reaching a given ceiling is `value + 4096k` -- and since 4096 is itself a
    multiple of four, every one of those is a multiple of four whenever
    `value` is, and every one of them decodes to the default instead. So the
    ceilings this can name are exactly the ones that are not multiples of four,
    three quarters of the range below 4096, and a request for a multiple of
    four is refused here rather than silently written out as a seed that means
    the default.

    That limit is the harness's, not this function's, and it is deliberate
    enough to keep: the alternative encoding would spend a second bit of
    entropy deciding default-or-not, and one byte in four choosing the default
    is a better ratio than one in two. A fuzzer still reaches the multiples of
    four by mutating a raw byte into them and getting the default, which is the
    branch those bytes exist for.

    Zero is the exception that proves the rule rather than one. It is a
    multiple of four, and it is reachable, because every raw byte that decodes
    to it decodes to *it* -- the default is what all of them mean, so asking
    for the default by name is exact rather than approximate.
    """
    assert 0 <= value < 4096, value
    assert value % 4 != 0 or value == 0, (value, "unreachable in the encoding")
    return value


def _sec_field(value, modulus):
    """The byte(s) that decode back to `value % modulus`.

    Written as a division and a multiplication rather than as the remainder
    alone because a seed generator that emits a value and asserts it decodes
    correctly is a seed that cannot silently stop meaning what its comment
    says. The assertion is the point; the arithmetic is how it is satisfied.
    """
    remainder = value % modulus
    encoded = remainder + (modulus * ((value - remainder) // modulus))
    assert encoded % modulus == remainder, (value, modulus)
    return encoded


def seccomp_policy(*, fallback=_SEC_FALLBACK_ERRNO, fallback_error=38,
                   ceiling=_SEC_CEILING_DEFAULT, rules=()):
    """One policy in the encoding the seccomp harness reads.

    `rules` is a sequence of (nr, action, error, tests) where `tests` is a
    sequence of (index, cmp, value). The result is the byte string a fuzzer
    would have to produce to make the harness build exactly this policy,
    which is the only honest way to state a seed for an emitter: the input is
    a policy, so the seed has to name the policy.
    """
    out = bytearray()
    out.append(_sec_field(fallback, 4))
    out += struct.pack(">I", _sec_field(fallback_error, 4096))
    out += struct.pack(">I", _sec_ceiling(ceiling))
    out.append(_sec_field(len(rules), 25))

    for nr, action, error, tests in rules:
        out += struct.pack(">I", _sec_field(nr, 4096))
        out.append(_sec_field(action, 5))
        out += struct.pack(">I", _sec_field(error, 4096))
        out.append(_sec_field(len(tests), 7))
        for index, cmp, value in tests:
            out.append(_sec_field(index, 6))
            out.append(_sec_field(cmp, 7))
            out += struct.pack(">I", _sec_field(value, 4096))
    return bytes(out)


def _seccomp_seeds():
    """The policies the emitter harness starts from.

    One per branch of the emitter rather than one per action, because the
    branches are what the bytecode geometry depends on. A policy with one rule
    and no argument tests is a three-instruction block; a policy with six
    tests is a thirty-one-instruction block, and the entry's not-taken offset
    is the difference between the two. The emitter's arithmetic is exercised
    by the width of a rule, so the corpus has to contain rules at both ends of
    it or the arithmetic is only ever checked at one width.
    """
    seeds = {}

    # The empty policy: a filter that denies everything by the fallback and
    # dispatches nothing. It is the smallest program the builder can emit and
    # the one whose instruction count is easiest to get wrong, because there
    # is no rule to make the count depend on. Everything else is a widening of
    # this, so it is the seed that has to be right.
    seeds["seccomp_empty.pol"] = seccomp_policy()

    # One rule, no argument tests. The block is one instruction, which is the
    # case the layout comment calls out: without the landing pad, the entry's
    # taken and not-taken offsets would both be one and the two branches
    # would be the same number.
    seeds["seccomp_one_rule.pol"] = seccomp_policy(rules=[
        (39, _SEC_ACTION_ERRNO, 13, ()),      # getpid, denied
    ])

    # Two rules, the first of which falls through to the second. This is the
    # case the whole block layout exists for: a rule whose argument test fails
    # has to resume at the next rule rather than at the fallback, so a policy
    # with one rule cannot tell a correct emitter from one that jumps straight
    # to the fallback.
    seeds["seccomp_two_rules.pol"] = seccomp_policy(rules=[
        (257, _SEC_ACTION_ERRNO, 13,          # openat
         ((2, _SEC_CMP_MASKED, 0o100),)),     # denied when O_CREAT is set
        (39, _SEC_ACTION_ALLOW, 0, ()),        # getpid, allowed
    ])

    # A rule with all six argument tests: the widest block the API can
    # describe, and therefore the entry offset closest to the eight-bit jump
    # field's limit. The builder's own range check cannot fire for any policy
    # this API can express -- six tests give an offset of 32, against a limit
    # of 255 -- so the harness asserts the invariant that makes it unreachable
    # rather than the check itself. If a future change raised the argument
    # limit, this is the seed that reaches the new geometry.
    seeds["seccomp_widest_rule.pol"] = seccomp_policy(rules=[
        (99, _SEC_ACTION_ERRNO, 13,
         tuple((i, _SEC_CMP_EQUAL, 0) for i in range(6))),
    ])

    # Every comparison, one rule each. Six of the seven are emitted as an
    # inverted operator rather than as a distinct opcode, so this is the seed
    # that reaches the inversion logic -- and a fuzzer that never varies the
    # comparison would never notice a change to which of jt and jf carries the
    # match. They are in one policy rather than seven because the harness
    # installs a filter per input and a corpus of seven single-rule policies
    # would spend its budget in the fork.
    seeds["seccomp_every_comparison.pol"] = seccomp_policy(rules=[
        (28, _SEC_ACTION_ERRNO, 13, ((2, _SEC_CMP_EQUAL, 10),)),
        (29, _SEC_ACTION_ERRNO, 14, ((2, _SEC_CMP_NOT_EQUAL, 10),)),
        (30, _SEC_ACTION_ERRNO, 15, ((2, _SEC_CMP_GREATER, 10),)),
        (31, _SEC_ACTION_ERRNO, 16, ((2, _SEC_CMP_GREATER_OR_EQUAL, 10),)),
        (32, _SEC_ACTION_ERRNO, 17, ((2, _SEC_CMP_LESS, 10),)),
        (33, _SEC_ACTION_ERRNO, 18, ((2, _SEC_CMP_LESS_OR_EQUAL, 10),)),
        (34, _SEC_ACTION_ERRNO, 19, ((2, _SEC_CMP_MASKED, 0o100),)),
    ])

    # An argument index of 5, the last one seccomp_data has. Index 5 accepted
    # and index 6 refused is the boundary, and a check written as "index > 5"
    # passes a test of the refusal alone and is wrong here. The harness makes
    # both assertions itself on every input, so this seed is here to make sure
    # the accepted side is reached by the fuzzer rather than only by the
    # harness's own fixed policy.
    seeds["seccomp_last_arg.pol"] = seccomp_policy(rules=[
        (39, _SEC_ACTION_ERRNO, 13, ((5, _SEC_CMP_EQUAL, 0),)),
    ])

    # Every action, including the two that kill. The harness rewrites a
    # killing action to a denial before installing, because a child that dies
    # of SIGSYS cannot report the install -- so the bytecode for KILL_THREAD
    # and KILL_PROCESS is generated and checked and never installed, which is
    # stated here because "the seed exercises the kill action" would
    # otherwise read as more than it is.
    seeds["seccomp_every_action.pol"] = seccomp_policy(
        fallback=_SEC_FALLBACK_KILL, rules=[
            (39, _SEC_ACTION_ALLOW, 0, ()),
            (40, _SEC_ACTION_TRAP, 0, ()),
            (41, _SEC_ACTION_KILL_THREAD, 0, ()),
            (42, _SEC_ACTION_KILL_PROCESS, 0, ()),
            (43, _SEC_ACTION_ERRNO, 13, ()),
        ])

    # A fallback that allows, with rules that deny. The interesting shape
    # because the two disagree: a policy whose default is to let everything
    # through is only safe because of the rules, so this is the seed that
    # would catch a rule block emitted with the wrong action.
    seeds["seccomp_permissive_fallback.pol"] = seccomp_policy(
        fallback=_SEC_FALLBACK_ALLOW, rules=[
            (39, _SEC_ACTION_ERRNO, 13, ()),
            (40, _SEC_ACTION_ERRNO, 14, ()),
        ])

    # An explicit ceiling, with one rule below it and one above. The builder
    # emits a JGT against the ceiling, so this is the only seed that reaches
    # the range test with a number a caller chose rather than the default --
    # and the two rules straddle it deliberately: 39 is dispatched, 257 is
    # refused to the fallback before any rule block runs. A policy that
    # compiles, installs, and denies one number while allowing another is a
    # fact about the policy rather than a defect, and it is here because the
    # range test's operand is the one field a caller can set to any number.
    #
    # 65 and not 64, because 64 is a multiple of four and the encoding spends
    # every multiple of four on the default; _sec_ceiling refuses it rather
    # than writing out a seed that does not mean what this comment says.
    seeds["seccomp_low_ceiling.pol"] = seccomp_policy(ceiling=65, rules=[
        (39, _SEC_ACTION_ERRNO, 13, ()),
        (257, _SEC_ACTION_ERRNO, 14, ()),
    ])

    return seeds


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

OTHER_SEEDS.update(_zip_seeds())
OTHER_SEEDS.update(_seccomp_seeds())

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
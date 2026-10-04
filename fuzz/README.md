# Fuzz harnesses

Four libFuzzer targets over the places untrusted bytes enter occ. Each one is
an `LLVMFuzzerTestOneInput` over a parser, and each asserts the parser's own
invariants rather than only surviving: a parser that does not crash but
reports a mapping past the end of the file has still produced a lie, and a
fuzzer watching only for crashes will not notice.

## Building and running

The harnesses need Clang. libFuzzer's runtime is linked against libstdc++,
so `OCC_ENABLE_FUZZ=ON` forces `OCC_USE_LIBCXX=OFF` in the cache -- asking
for both does not fail, it quietly builds against libstdc++ instead, which
is the right answer and worth knowing happened. Pointing a GCC build at
`-DOCC_ENABLE_FUZZ=ON` does fail, because GCC does not know
`-fsanitize=fuzzer-no-link`.

    cmake -S . -B build-fuzz -G Ninja \
      -DOCC_ENABLE_FUZZ=ON \
      -DCMAKE_CXX_COMPILER=/usr/lib/llvm-23/bin/clang++ \
      -DCMAKE_C_COMPILER=/usr/lib/llvm-23/bin/clang \
      -DCMAKE_CXX_FLAGS="-fsanitize=fuzzer,address,undefined"
    cmake --build build-fuzz

`occ_fuzz_smoke` runs each one briefly. Each is also a bounded ctest:

    ctest --test-dir build-fuzz -R occ_fuzz_run

which is `-max_total_time=30` per harness, with `OCC_FUZZ_CTEST_SECONDS` to
change it. The ctest `TIMEOUT` is not decoration: libFuzzer handed a
malformed `-max_total_time` does not fail, it runs forever, so a test whose
only limit is libFuzzer's has no limit at all.

For a longer run, point a harness at the corpus directly:

    ./build-fuzz/fuzz/occ_fuzz_pe build-fuzz/fuzz/corpus/pe fuzz/seeds

## What each harness covers

| Harness | Input | Claim under test |
|---|---|---|
| `occ_fuzz_elf` | any bytes | ELF parse, and format detection over the same bytes |
| `occ_fuzz_zip` | any bytes | the zip central directory, and the member report drawn from it |
| `occ_fuzz_pe` | any bytes | PE section extents and RVA-to-offset conversion |
| `occ_fuzz_loader` | any bytes | what the loader decides about an image, and where it puts it |
| `occ_fuzz_rsp` | any bytes | GDB RSP framing, checksums, escapes, and the queue between them |

`occ_fuzz_elf` also drives detection, because detection is what decides
which parser runs at all: a file's first eight bytes choose the reader, and
those bytes come from wherever the user pointed occ. It is called for the
sanitizers to watch rather than for an assertion -- detection has no
invariant of its own checked here, and `tests/test_detect.cpp` is where its
answers are pinned down. Running both readers on the same bytes is the point:
a corpus entry that reaches one is a starting point for the other, which is
most of the value of a corpus.

`occ_fuzz_zip` is the one reader whose offsets are relative to the *end* of
the file rather than the start. The end-of-central-directory record is found
by scanning backwards, and the directory's position, its size and the member
count all come from that record -- so a file controlling bytes near its end
controls every offset the walk uses. That is a different shape from the
other three inputs, which is why it is a separate binary against a separate
corpus rather than a case folded into the ELF one. What the report of a
package costs is downstream of this: `occ check` prints the member list, and
`occ run` writes one event per member, so a member read from the wrong offset
is a lie in both places at once.

`occ_fuzz_loader` shares the PE corpus deliberately. A loader harness whose
inputs never parsed would exercise the refusal paths and none of the
placement ones.

Every harness touches every accessor even when the parse failed. An accessor
that reads uninitialised state is a finding in itself, and a fuzzer that only
calls accessors on success never reaches one.

## Invariants, and why each is there

Each harness asserts claims the rest of occ depends on. `occ run` maps what
these report, `occ check` prints it, and the W^X tracker watches the regions
they name -- so a mapping that runs past the end of the file is not a
cosmetic defect, it is a length the rest of the program hands to `mmap`.

**ELF.** Every mapping's range does not wrap, and its file-backed part is
inside the file -- asked by subtraction, because `file_offset` and `filesz`
come straight out of a crafted table and an addition would wrap for the same
input that made the reader's own bound overflow. The zero-fill derived from
`memsz - filesz` never exceeds the memory size, which is what makes it a
count rather than a difference that could have been computed wrongly. An
interpreter, when present, is a path: a parsed one that is empty has said
there is no interpreter while also saying there is one, which is the kind of
contradiction that becomes a null deref somewhere else entirely. A failed
parse has no mappings at all: reporting some anyway would be the worst
outcome, because a caller checks `ok()` and then trusts the rest.

**PE.** Each section's virtual and raw extents do not wrap. Both ends are the
reader's own saturating additions, and a saturating addition that saturates
has still produced a range nobody can map. A parsed image has at least one
section -- a reader that reported none for a file it accepted would leave the
caller with nothing to map. Every RVA converts consistently, and the header
region is the interesting case: an RVA below `SizeOfHeaders` is already a
file offset, so it resolves without consulting any section and a reader that
forgot that would report it as unmapped. Every import name is a name the file
stated, so none is empty and none is longer than any real one.

**Loader.** A refused load leaves the address space untouched. Every recorded
region is inside the user window, non-empty, has an end inside the window, and
carries a protection that is one of the enumerated values -- a protection of
zero would be rendered `PAGE_?` by every report, so this pins down that the
loader's translation from section characteristics always produced something.
Regions stay ordered and disjoint. Every mapped region belongs to a section
the file actually declares. The entry point, when the load succeeded, is at
the base plus the image's entry RVA -- checked arithmetically and not only as
"lands in some region", because an entry computed from the wrong base is still
a mapped address. The module reports the base the caller asked for, or the
image's own when the caller asked for none; the harness loads each input
twice, once each way, so a loader that relocated the image but reported the
preferred base is caught. A resolved import's IAT slot is inside a region the
load recorded, because the slot is where the address is written and a slot
outside the map is a store into unmapped memory before the first instruction.

Each input is loaded at two bases: the image's own, which needs no relocation,
and one chosen to be different, which forces the relocation walk to run. The
second is what reaches the block-header parsing, so a harness that only used
the preferred base would never enter that code. A region is already present in
the space before each load, so a refused load has something to leave alone and
the retry path has a reason to care.

**RSP.** Every packet the decoder hands back is counted against what `feed()`
reported, and the queue may not hold one more -- an empty payload of `"$#00"`
has size zero, so what that catches is a packet with bytes `feed()` never
announced. Every packet's checksum matches the bytes it carries.

The escape helpers are checked on their own as well as through the codec:
`unescape(escape(x))` returns `x`. A trailing lone escape is passed through
rather than dropped, which is why the round trip is asserted on arbitrary
bytes rather than only on ones a real debugger would send.

The round trip is checked in both directions. `encode_packet` on any input
produces a frame of at least four bytes, because the framing characters and
the two checksum digits are unconditional and an encoder that returned less
would be a peer that went silent. One frame in is exactly one packet out --
zero would mean the encoder produced something the decoder does not recognise,
which for `"$#00"` is the same contradiction as the other direction -- the
decoded data equals the input, and nothing is left waiting.

The two-call shape is load-bearing: `feed()` appends to an internal queue and
`take()` pops from it, so a harness that only fed would never exercise the
queue's own bookkeeping, which is where an off-by-one would live.

**Zip.** Two invariants, and both are about where a name came from rather than
about what the archive says.

A reported member's name has to be bytes the file actually contains. This is
the one a walk from a wrong offset breaks, and the reader cannot check it: it
copies a name and hands back a string, and a copy of the wrong bytes is still
a string. The harness checks it against the input instead. The check is that
the name appears *somewhere* in the file rather than at a computed offset,
because the reader does not report where it read from -- reconstructing the
offset here would mean reimplementing the walk under test, and a second
implementation agreeing with the first would prove nothing.

`stored` is derived from the compression method rather than read, so it has to
equal `method == 0` on every member. That is the reader's own promise rather
than a fact about the archive, which is the distinction the next paragraph is
about.

And the member report has to be drawn from what was read: no member reported
that was not read, and none reported more often than it was read. Counted per
name rather than compared as a subsequence, because a directory may name the
same member twice -- two records with one name is a malformed archive, but it
is a well-formed list -- and a subsequence walk loses its place at the
duplicate and then fails to match a name that is genuinely present. That false
report was found by running this harness, not by reading it.

Detection and the reader are called separately and compared, but only where
the two are supposed to agree. Detection reads the central directory *after*
the first local file header has identified the file as a zip, so a file whose
first local header has been damaged is not a zip to detection -- it reports no
members -- while a direct call to the reader, which starts from the end of the
file, still finds the directory. Both answers are right; they answer different
questions. Asserting they agree unconditionally was the first version, and the
fuzzer found the contradiction on its first mutated input.

## What is deliberately not asserted

An invariant that is wrong is worse than a missing one, because it reports a
fault that does not exist and trains people to ignore the harness. These have
been left out on purpose, and the reasons are recorded so they are not
re-added by someone who thinks they found a gap.

**Not: that a member's uncompressed size fits in the file.** Asserted first,
and the fuzzer found the contradiction immediately on a seed that was a real
archive: a deflated member's uncompressed size is *supposed* to be able to
exceed the whole file, since the file holds the compressed bytes. That is
what compression is for. A size that exceeds the file is not a broken reader;
it is a member that would have to be inflated to be read, which is a fact a
caller needs in order to decide whether to bother.

**Not: that a stored member's two sizes are equal.** Also asserted first, also
found by the fuzzer, also wrong. They are equal in every archive a writer
produces, so a difference means the record is inconsistent -- but inconsistent
is a fact about the file, and this reader's contract is to report what the
directory said rather than to rule that the directory is lying. A caller who
sees a stored member whose sizes differ has learned something true and
important about the archive in front of them, and the harness that refused to
report it would have been the defect.

Both of those were the same mistake in different clothes: treating a property
of *well-formed archives* as a promise the *reader* makes. The distinction is
worth keeping. An invariant is about the code -- about what it promises
regardless of input. A fact about the input is what the code exists to report,
and asserting it inside the reader would mean a file could not be reported at
all.

**Not: that a packet with a good checksum carries a non-empty payload.**
`"$#00"` is `vMustReplyEmpty` -- a well-formed packet whose payload is empty.
The encoder produces it for an empty payload and the decoder accepts it with
a good checksum. This was asserted once, and the fuzzer found the
contradiction the first time it was handed either the empty string or
`"$#00"`.

**Not: that the decoder asked for an acknowledgment.** The decoder's
`needs_ack` and `pending_ack` are part of its contract and are covered by
`tests/test_observer.cpp` against a live decoder; asserting them here would
have added a second place to update without adding a second kind of coverage,
since the byte that reaches the wire is produced by the caller.

**Not: that a resolved import's address is the one the resolver returned.**
The loader harness installs a stub resolver that hands back a fixed value per
DLL. Asserting the address would check that the stub was called, which the
IAT-slot invariant already establishes by requiring the slot to be mapped.

**Not: relocation counts.** The loader counts them; the layer that applies
them does not exist yet. Asserting the count against the code that computes it
would restate the implementation rather than test it.

**Not: event flow.** `LoadContext::events` defaults to null and the loader
harness never sets it, so a load here writes no events. Event writing is not
part of the loader's contract -- `occ check` loads with a null resolver and a
null writer for exactly this reason -- and a harness that asserted on it would
be testing a mock.

## Seeds

Twenty-six seeds, all generated by `tools/make_pe_seeds.py` and checked
against it by `occ_test_seeds`. They are written rather than checked in by
hand so that what each one is can be read: a seed whose purpose is unclear is
a seed nobody regenerates when it stops being useful. Python is not part of
the build; it is needed to change a seed, never to compile or run one.

| Seed | Reaches |
|---|---|
| `pe32_min.bin` | the smallest file that parses at all |
| `pe32plus_min.bin` | the 64-bit layout, where ImageBase sits elsewhere |
| `pe_dll.bin` | the characteristics bit the engine branches on |
| `pe_two_sections.bin` | an RVA with a choice of section to convert into |
| `pe_imports.bin` | the descriptor walk and name resolution |
| `mz_only.bin` | "too short" rather than a read past the end |
| `mz_no_signature.bin` | "not a PE" distinguished from "a PE with a bad header" |
| `pe_short_optional.bin` | a header shorter than the fields read from it |
| `pe_tiny_optional.bin` | a header too short to hold the layout magic |
| `pe_base_zero.bin` | an image naming no base, with no relocations to fall back on |
| `pe_machine_arm.bin` | 0x01c0: a machine occ was never asked about before |
| `pe_machine_arm64.bin` | 0xaa64, and the name printed for it |
| `pe_bad_entry_rva.bin` | an entry point past every section |
| `pe_entry_not_executable.bin` | an entry in a mapped, non-executable region |
| `pe_section_over_headers.bin` | a section placed at RVA zero |
| `elf_min.bin` | the program header table's extent check |
| `rsp_g.gdb` | a valid packet followed by a byte outside a packet |
| `zip_package.zip` | the whole directory walk, and a member under `lib/` |
| `zip_deflated.zip` | a record whose two sizes differ, and the "on disk" half of the report |
| `zip_many_members.zip` | more libraries than the report lists, and the line saying so |
| `zip_commented.zip` | an archive comment, so the end record is searched for |
| `zip_count_lies.zip` | a count larger than the directory holds |
| `zip_offset_past_end.zip` | a directory offset past the end of the file |
| `zip_size_lies.zip` | a directory size larger than what is there, from a valid offset |
| `zip_comment_overruns.zip` | a record whose comment runs past the directory |
| `zip_streamed.apk` | a package with no central directory at all |

The last three of the loader group and `elf_min.bin` are permanent guards
rather than starting points: the loader harness traps on a violated invariant
rather than returning, so a seed here is a boundary the fuzzer no longer has
to find again.

`elf_min.bin` is named for what it is not. The header parses completely and
every field in it is plausible; the table it points at runs past the end of
the file, and `ElfImage::parse` refuses it with "the table runs from 0x40 to
0x318 and the file is 256 bytes".

The zip seeds are one per gate rather than one per format, because the reader
has four gates in sequence and a seed that stops at the first teaches the
fuzzer about the first. `zip_package.zip` is the only one that reads to the
end; the rest each stop at a different refusal, and three of them (the lying
count, the offset past the end, the lying size) are the shapes that separate a
reader which bounds its walk by the directory from one which trusts the file.

`zip_archive()` in the generator refuses to build a record that cannot exist
-- a stored member whose two sizes differ -- with a `ValueError` naming the
member. That check is there because of what it replaced: the first version of
`zip_many_members.zip` had such a record, and the harness rejected it as a
broken invariant rather than as the malformed input it was meant to be. The
mistake then reached the fuzz corpus as a crash artifact and cost three rounds
of "is occ wrong or is the harness wrong". Catching it at generation time
turns a forty-second investigation into a stack trace.


## Not reached

**Anything needing a process.** The `run` path and everything under it needs
a real process, a namespace, and a kernel, and a fuzzer that forks per input
spends all its time in setup. The parser is where untrusted bytes enter, so
that is where the budget goes. What this costs is stated rather than left
implicit: the container, the seccomp emitter, the probe plumbing and the
uprobe path are all unexercised here.

**The BPF emitter.** `src/isolation/seccomp.cpp` builds filters from a typed
`SeccompPolicy` rather than from bytes, so there is no untrusted-byte surface
to hand a fuzzer. Its failure mode is a filter the kernel rejects at install
time, which is not something a harness in this directory can observe.

**The seccomp and container tests are skipped in a fuzz build.** They install
filters and unshare namespaces, and the sanitizer runtimes do not compose
with that. The five harnesses here do none of it: no fork per input, no filter
installed, no ptrace, which is why they run sanitized without trouble.

**Non-determinism.** Nothing here records what a run depended on. Two runs of
`occ run` are not expected to produce the same event stream yet; making them
do so is a milestone of its own.

## Coverage, and what it converges to

Measured on the checked-in seeds: 430 edges for `occ_fuzz_pe`, 606 for
`occ_fuzz_loader`. A minute of `occ_fuzz_pe` over an accumulated corpus moves
the edge count by two, so "run it longer" is not where the value is at this
point. What moves it is a new shape -- see `pe_base_zero.bin`, which came out
of a 3409-input corpus and is worth five edges in the loader harness and two
in the PE one.

Most of what a corpus accumulates is not worth keeping, and the rule for
deciding is worth stating because it is what makes the corpus reviewable: a
seed earns its place when its verdict can be named. `section 19 at 0xffffffff
for 0xffffffff bytes` reaches a real check and documents nothing a reader
did not already have from the message; "the image names no base and the caller
named none" documents a decision.

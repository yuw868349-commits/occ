# Fuzz harnesses

Six libFuzzer targets over the places untrusted bytes enter occ. Each one is
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

**The two directories are different directories, and the order is the
argument order.** libFuzzer treats its first argument as the corpus it *writes*
and the rest as corpora it *reads*, so `occ_fuzz_corpus_dir fuzz/seeds` does
what it looks like: it reads the seeds, and then adds an entry to
`fuzz/seeds` for every input it reaches, named by the SHA-1 of its contents. A
run of half a minute across six harnesses leaves about two thousand of them, and
they are not seeds — a seed is an input somebody chose on purpose, and none of
those were chosen. Pointing the corpus at the seed directory is the mistake
this paragraph exists to prevent, because it is the mistake that makes the
repository accumulate files nobody chose, and because it does not fail: the run
passes, the tests pass, and the two thousand files are simply there afterwards.

`fuzz/corpus/` is in `.gitignore` and `fuzz/seeds/` is not, and the two are
told apart by where they are rather than by what they are called. Every seed is
hand-written with a name that says what it is for — `pe_dll.bin`,
`seccomp_two_rules.pol`, `rsp_g.gdb` — so a rule that recognised corpus entries
by name would have to be loose enough to catch `pe_dll.bin` as well. A
directory is the only distinction that survives a new seed.

## What each harness covers

| Harness | Input | Claim under test |
|---|---|---|
| `occ_fuzz_elf` | any bytes | ELF parse, and format detection over the same bytes |
| `occ_fuzz_zip` | any bytes | the zip central directory, and the member report drawn from it |
| `occ_fuzz_pe` | any bytes | PE section extents and RVA-to-offset conversion |
| `occ_fuzz_loader` | any bytes | what the loader decides about an image, and where it puts it |
| `occ_fuzz_rsp` | any bytes | GDB RSP framing, checksums, escapes, and the queue between them |
| `occ_fuzz_seccomp` | fixed-width record | that the bytecode is the program the policy described |

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

`occ_fuzz_seccomp` is the odd one out twice over, and both are worth stating
because the input column already says the first. It has no untrusted bytes to
parse: `src/isolation/seccomp.cpp` builds a filter from a typed
`SeccompPolicy`, so the harness has to invent its own surface before there is
anything to fuzz. The surface is a fixed-width record -- a fuzzer's bytes read
as a stream of fields that become a policy's fallback, ceiling, rules, actions,
errnos, argument indices and comparisons. Every field is therefore reachable
and none is out of reach, which is the property a generated surface needs and
the reason the encoding is written down in the harness header rather than left
implicit. The obvious alternative was worse: a fuzzer handed the enum values
alone would never build a policy with two rules and a fall-through between them,
and that fall-through is the only place the emitter's geometry gets interesting.

The second difference is that this harness does not install anything, and the
reason is a measurement rather than a preference. The first version did: it
installed the program in a child process and treated the install's return value
as the oracle, which is the right oracle -- only the kernel can say whether it
will execute a filter. It also deadlocked, intermittently, under libFuzzer.
Six campaigns over the same corpus and the same binary:

| runs | 106 | 130 | 150 | 170 | 185 | 195 |
|---|---|---|---|---|---|---|
| exit | 0 | 0 | 0 | **124** | 0 | 0 |

124 is the timeout's own code. The hang is not a function of the input -- all
54 corpus files fed one run each produced zero hangs -- and not a function of
the run count. What it is a function of is how fast libFuzzer calls the
harness. The cost was measured rather than guessed: fork, install and collect
runs at 6839 a second unsanitized and 1048 a second under AddressSanitizer, six
and a half times slower, because forking a sanitized process runs the runtime's
atfork handlers and re-accounts shadow memory. A twenty-second budget was
still going after three and a half minutes, which is what 1048 a second buys
you. Deduplicating the shapes the harness had already installed did not fix it
either, and neither did driving the same logic outside libFuzzer: 51 installs
over the same corpus, 51 successes, three clean ASan child runs. The mechanism
is sound. The interaction with a driver that manages its own children is not,
and neither side owns what they contend for.

So the kernel oracle is a test. `tests/test_seccomp.cpp` really installs
forty-nine filters, covering all seven comparisons and all five actions, in a
build without a sanitizer -- bounded, reproducible, and it names the failure
when it happens. What it cannot do is walk the emitter's geometry, because
there are only so many policies a person writes. That is what stayed here, and
the division loses nothing: the test answers "does the kernel take this filter",
once per shape someone thought of, and this file answers "is the program the
emitter built the program it meant to build", for every policy a fuzzer can
describe, at full speed.

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

**Seccomp.** The emitter lays a filter out as a preamble -- load the
architecture, reject anything that is not x86-64, load the syscall number,
range-test it against a ceiling -- then one block per rule, then a trailing
fallback return. The blocks are where the arithmetic lives, so that is where
the assertions are.

Every branch lands inside the program. A jump offset is relative to the
instruction *after* the branch, and classic BPF has no implicit end: a branch
whose target is the program length or beyond runs off the end, and the kernel
rejects the whole filter. This is the property a changed constant breaks first
and the one reading the source does not catch, because the offsets are computed
in three places and have to agree in all of them.

The program ends in a return, and every instruction a program can arrive at
without branching is accounted for. Both halves matter and the honest form of
the check is the pair: the last instruction returns *and* no branch targets past
it, and the second is what makes the first sufficient.

The reported count is the emitted count. `insn_count()` is what
`seccomp_install` hands the kernel as `sock_fprog::len`, and the kernel refuses
a program longer than 65535 instructions, so a count that disagreed with the
vector would make the install's own check and the kernel's wrong in opposite
directions with nothing in between to report it.

And the one that ties the bytecode back to the input: **every rule's number is
in the dispatch table.** The program is scanned for the comparisons it makes,
and each policy rule's syscall number has to be among them, with the
architecture guard subtracted by value rather than by position. This is the
invariant a fuzzer can actually break, and what breaking it looks like is not a
crash -- it is a filter that installs cleanly, answers every question it is
asked, and silently protects less than the policy said. A rule dropped from the
table is a rule that does not run.

Three properties are about the builder rather than about one program, and are
checked on every input because a fuzzer that only reached them on its first few
inputs would not notice a change that broke them later. An argument index the
header calls out of range is refused *and* the last legal one is accepted, both
halves, because a check written as "index > 5" passes both of a pair of tests
that only test the refusal and is wrong at the boundary -- and the boundary is
5, because `seccomp_data` has six slots. A zero errno is refused on both the
rule path and the fallback path, because `SECCOMP_RET_ERRNO` with a zero
payload makes the syscall return zero: a caller of `read` sees end of file and a
caller flushing a stdio buffer loops forever. And the ceiling keeps the x32 bit
out of the rule table, read back out of the emitted `JGT` rather than
recomputed, because the kernel presents a number carrying bit 30 to the filter
as carrying it -- verified on 6.6.117 by a filter matching `0x27`, which
matches a native `getpid` and does not match the same call issued as
`0x40000027`.

Two of those were written once, wrongly, and the way they were wrong is why
they read the way they do now. The argument bound refused index 6 and never
confirmed that 5 still worked, and the x32 ceiling was asserted against
`highest_known_syscall()` directly rather than against the number the builder
actually compares -- so a change to the emitter's range test would have
satisfied the assertion while defeating the defence. A check that reads the
constant under test rather than the implementation of it is the difference
between a test and a restatement, and both of these were restatements until
they were not.

A third was found by this harness, which is the argument for having it, and it
is recorded here because the shape recurs. Telling the architecture guard from
a rule's entry comparison was done by value -- collect every `JEQ`, erase
`AUDIT_ARCH_X86_64` -- and the fuzzer produced a policy naming `0xc000003e` as
a syscall number, which nothing forbids. Its rule was then reported missing,
because the only entry carrying that number was the guard and the guard had
just been erased. The harness trapped on a correct program. The comment called
that "the conservative direction", which is exactly backwards: an invariant
that reports a fault that does not exist is worse than a missing one, because
it trains people to ignore the harness, and one that fires on a legal input
also means the next real finding gets read as noise.

The fix was to stop guessing and start knowing. The preamble's five
instructions are now checked against the header's documented layout -- the
architecture guard's position, its two outcomes, the unconditional kill beside
it, and the range test's operand read back as the ceiling the policy asked for
-- and the rule scan starts after the preamble instead of subtracting from a
set. Which is also the stronger check: subtracting by value could not tell a
rule that happened to share the guard's number from one that did not, and it
reported both as missing.

The general form is worth keeping: *a check that has to guess which of two
things it is looking at is a check that will eventually be wrong about both*.
Position, once established, is information; a value comparison is a guess with
the numbers in it. And a new invariant is not evidence until something has
tried to get past it -- so the three assertions in the preamble were each
checked by breaking them on purpose (moving the guard's taken offset, pointing
the number load at the architecture's field, and neutering the ceiling
comparison, which the `-Wtautological-compare` in the warning set refused to
compile). Two trapped and the third did not build, which is the outcome the
warning suite is for.

Reading the file for the first time since writing it turned up a third one,
and it is the mirror image: an assertion that could not fail. There was a
function called `both_outcomes_are_offsets` whose body was a loop containing
two `continue`s, a comment and a closing brace. It was going to check that a
conditional branch's taken and not-taken offsets differ, which is not a
property any correct program here has -- a rule with no argument tests has a
one-instruction block, so both offsets are 1 and both branches land on the
same instruction, which is the entire reason the layout has a pad. Written as
"the outcomes must differ" it would have trapped on every such policy, so it
was going to be deleted rather than fixed; the property that does hold, that
both outcomes land inside the program, is already checked.

An assertion that cannot fail is the same defect as one that fails wrongly,
and quieter: it costs a reader who trusts it, and it makes the count of
invariants in a file a number that means nothing. The two of them together are
why the harness asserts six things about a program rather than nine, and why
the number is six rather than a larger one that would read as more thorough.

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

**Not: that the kernel will execute the program.** This is the one that
earlier read as a gap and is not. It is `tests/test_seccomp.cpp`, which
installs forty-nine filters for real, and it is a test rather than a fuzz
target for a measured reason given above: a harness that forks per input and
is called thousands of times a second deadlocks against libFuzzer's own
process management often enough to make a suite unreliable. The cost of the
split is that neither half sees the other's failures -- a filter the kernel
rejects for a reason the geometry does not predict is found by the test only
if someone writes that policy by hand -- and the benefit is that the geometry
is walked exhaustively here, which no hand-written policy list does. That
trade is the right way round, because a miscounted offset is the failure that
actually happens and it is the one a fuzzer finds.

**Not: that a filter answers a syscall the way the policy says.** The harness
builds programs and reads their geometry; it does not execute them, so nothing
here says a `Less` comparison means what the documentation says it means. That
is `tests/test_seccomp.cpp` too, which issues real syscalls and checks the
answers. Splitting it this way means the two halves cannot both be wrong in a
way that cancels out, which is the failure a single combined harness would
have.

## Seeds

Thirty-five seeds, all generated by `tools/make_pe_seeds.py` and checked
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
| `seccomp_empty.pol` | no rules at all: the preamble and the trailing fallback alone |
| `seccomp_one_rule.pol` | a rule with no argument tests, which is the only case where the layout's pad instruction is load-bearing |
| `seccomp_two_rules.pol` | a fall-through from one rule's failed test into the next rule's entry |
| `seccomp_widest_rule.pol` | six argument tests, the largest block the layout allows |
| `seccomp_every_comparison.pol` | all seven comparisons, one rule each |
| `seccomp_last_arg.pol` | argument index 5, the last one the header permits |
| `seccomp_every_action.pol` | all five actions, and a `KillProcess` fallback behind them |
| `seccomp_permissive_fallback.pol` | an `Allow` fallback with denying rules: the policy is safe only because of the rules |
| `seccomp_low_ceiling.pol` | an explicit ceiling of 65 with a rule below it and a rule above it |

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

The seccomp seeds are the same idea applied to something that is not a file. A
`.pol` seed is a policy's numbers in a fixed-width record, so the generator
does not merely emit bytes -- it asserts that the bytes it wrote decode back to
the fallback, the ceiling, each rule's number, action and errno, and each test's
index and comparison, through the same reduction the harness applies. A
generator that could write a seed meaning something other than what its comment
says would be a silent hole, and the assertion is what closes it. Every
`_sec_field` call carries the check inside it rather than in a test elsewhere,
because a check in a test is a check somebody can forget to extend.

Two of those assertions earned their place immediately, and both are worth
naming because a seed that lies is worse than no seed.

`_SEC_ACTION_KILL_THREAD` was unreachable. The harness's action rotation was
`% 4` against an enum with five values, so no byte produced `KillThread`: its
emitter branch was never generated, never checked, and the harness passed,
because four of five actions is not a failure by any assertion in it. It was
found by generating the seeds and printing what each one decoded to, where a
seed that named `KillThread` came back as something else. The lesson is the
one the encoding table exists to enforce: a rotation's modulus has to be
checked against the enum rather than chosen, and `% 7` against seven
comparisons being correct does not make `% 4` against five correct.

`seccomp_low_ceiling.pol` asked for a ceiling of 4 and got the default. The
harness reads a ceiling as `raw % 4 == 0 ? 0 : raw % 4096`, so a raw byte that
is a multiple of four is spent on the default -- and since 4096 is itself a
multiple of four, *no* multiple of four below 4096 is reachable, ever. The
generator now refuses one with an assertion rather than writing out a seed that
does not mean what it says, and the seed uses 65. The limit itself is kept: it
narrows nothing that matters, because a fuzzer still reaches those bytes by
mutation and gets the default, which is the branch they exist for.


## Not reached

**Anything needing a process.** The `run` path and everything under it needs
a real process, a namespace, and a kernel, and a fuzzer that forks per input
spends all its time in setup -- worse than that, under a sanitizer, where a
fork runs the runtime's atfork handlers and re-accounts shadow memory, six and
a half times slower than an unsanitized fork on this machine. The parser is
where untrusted bytes enter, so that is where the budget goes. What this costs
is stated rather than left implicit: the container, the probe plumbing and the
uprobe path are unexercised here.

**The seccomp and container tests are skipped in a fuzz build.** They install
filters and unshare namespaces, and the sanitizer runtimes do not compose with
that -- `occ_test_seccomp`'s policy denies `write(2)`, and ASan places its
shadow memory with `mmap` on the way out of `fork()`. The six harnesses here do
none of it: no fork per input, no filter installed, no namespace, no ptrace,
which is why they run sanitized without trouble. The seccomp emitter is no
longer on that list of unexercised things -- it is fuzzed here, statically --
but the kernel's opinion of what it emits is still the skipped test's job, and
that half is honestly absent from a fuzz build.

**Non-determinism.** Nothing here records what a run depended on. Two runs of
`occ run` are not expected to produce the same event stream yet; making them
do so is a milestone of its own.

## Coverage, and what it converges to

Measured on the checked-in seeds: 430 edges for `occ_fuzz_pe`, 606 for
`occ_fuzz_loader`, 359 for `occ_fuzz_seccomp`. A minute of `occ_fuzz_pe` over
an accumulated corpus moves the edge count by two, so "run it longer" is not
where the value is at this point. What moves it is a new shape -- see
`pe_base_zero.bin`, which came out of a 3409-input corpus and is worth five
edges in the loader harness and two in the PE one.

The seccomp harness is the one whose rate is worth a number, because the rate
is the argument. 3,091,554 inputs in 121 seconds, 25,550 a second, with
no crash, no timeout and no leak. The first version of it managed 1,048 a
second under the same sanitizer and deadlocked when it did. Nothing about the
work got cheaper -- the same builder runs and the same program is read back --
so the whole difference is that it no longer forks, and that is what the split
bought: an oracle is worth exactly as much as the rate at which you can ask
the question, and a question that deadlocks is worth nothing at any rate.

Most of what a corpus accumulates is not worth keeping, and the rule for
deciding is worth stating because it is what makes the corpus reviewable: a
seed earns its place when its verdict can be named. `section 19 at 0xffffffff
for 0xffffffff bytes` reaches a real check and documents nothing a reader
did not already have from the message; "the image names no base and the caller
named none" documents a decision.

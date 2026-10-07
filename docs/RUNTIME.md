# The Windows runtime

This document is the plan for running Windows images without Wine, and the
reasoning behind each structural decision. It is written before the code
exists so that the code can be measured against it.

## What this replaces, and why it is being replaced

Until now a PE was run by handing it to Wine and placing probes on Wine's
Unix-side ntdll. That worked, and it was the right first step: it proved the
loader-independent parts of the run — the container, the observer, the event
stream, the probe placer — against a real Windows process.

It is also a ceiling, and the ceiling is not about the number of APIs Wine
implements. Wine implements more Windows APIs than this project ever will.
The ceiling is that Wine's architecture is built for a different goal than
this project's, and three of its decisions are load-bearing for
compatibility and fatal for observability.

### Wine's first problem: one API, two implementations

`NtAllocateVirtualMemory` in Wine has a branch at the top:

```c
if (process != NtCurrentProcess())
{
    /* marshal the request to the server and wait for an APC */
    status = server_queue_process_apc( process, &call, &result );
    ...
}
/* otherwise do it here */
return allocate_virtual_memory( ... );
```

The same Windows entry point has two implementations, and which one runs
depends on whether the target process is the calling process. The two
paths share a signature and almost nothing else. Any behaviour that
differs between them — and over 30 years of changes, some will — is a
behaviour that depends on a fact the program cannot see. This is a class
of bug that cannot be fixed by testing, because the test surface is the
product of the two paths.

### Wine's second problem: the state is in another process

Wine's `server/` is 48,910 lines of a separate process that holds the
object table, the handle table, the thread registry, and the synchronization
state. It is reached over a Unix socket.

For a launcher that is fine. For an observer it is disqualifying. The
question this project exists to answer is "what did the program do, and
why", and with the answer split across three address spaces and a socket,
the question has no single answer. A handle's creation time, its owner, and
the sequence of operations that reached it are not recoverable from one
place, because they are not in one place.

### Wine's third problem: compatibility is grown, not specified

From Wine's `virtual.c`, in `map_image_into_view`:

```c
/* Some applications (e.g. the Steam version of Borderlands) map over the
 * top of the section headers, copying the headers into local memory is
 * necessary to properly load such applications. */
```

This is not a criticism of the people who wrote it. It is a description of
what compatibility work is: a growing list of specific programs that needed
a specific accommodation. The list has no end, and membership is decided by
whether someone reported the program.

An API whose behaviour is defined by the set of programs that have been
tried against it has a completeness that cannot be measured. This document
proposes something that can be.

## The shape of the replacement

The replacement is not "Wine but ours". It is a runtime whose invariants
are chosen so that the three problems above cannot occur.

### Invariant 1: one semantic path per API

Every `Nt*` entry point has exactly one implementation. Cross-process
operations are not a second path; they are the same path with a different
address space, resolved by the object table.

Concretely, the address space is a value:

```
NtAllocateVirtualMemory(process, base, size, type, protect)
    resolve process -> AddressSpace&
    AddressSpace::allocate(base, size, type, protect)
        -> this is the only implementation
```

When the process is not the caller, the address space is reached through
the object table instead of through a thread-local current-process
pointer. The difference between the two cases is one lookup and it lives in
one function. Everything below that function is shared, so there is no pair
of behaviours that can drift.

### Invariant 2: all state is in the observing process

There is no server. The object table, the handle table, the thread table,
the TEB and PEB, the allocated-memory map, and the registry model are
values in the process that is running the target and writing the events.

This is what makes the questions answerable:

| Question | With a server | Here |
|---|---|---|
| Who created this handle? | Not recorded | A field on the handle |
| What was the process state at time T? | Not recoverable | Replay the object log to T |
| Why did this call fail? | The status, if it propagated | The status and the syscall errno and the path through the code that chose between them |
| Is this program deterministic? | Unknowable | Every non-deterministic input is a recorded event, so a re-run with the same inputs is comparable |

The last row is the one that matters most. A runtime that records its own
non-determinism can be replayed, and a replayed run can be compared against
the original. Nothing in Wine can do this, not because it was overlooked,
but because the state needed to do it is not in one place.

### Invariant 3: behaviour is specified, then implemented, then verified

Each API has a **semantics card**: a written statement of what the call
does, in the order it does it.

```
NtCreateFile
  validates: FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
             in that order
  on failure: no handle is created, and no entry is added to the handle table
  on success: the handle is inserted before the call returns
  status: the value is derived from the failed syscall's errno by table,
          not by a chain of conditionals
```

Cards are not executable here. An earlier version of this file claimed that
`occ doctor` runs the card suite against the runtime and reports which cards
pass, and that the count of passing cards is a number two builds can be
compared on. None of that is implemented: `occ doctor` reports thirteen
checks about the host — identity, kernel, procfs, namespaces, mounts,
cgroup v2, seccomp, bpf, perf_event, tracefs, binderfs, kernel config — and
nothing about the runtime. The cards are prose in this document, and a card
is checked by the assertions in the test that covers the call, not by a
runner.

That is a weaker guarantee than an executable card and it is the reason the
idea is written down: the ordering claims above are the ones a test asserts
one at a time, and nothing in the tree collects them into a single number.

## What is built, in order

Each milestone ends with something that can be run and looked at. There is
no milestone whose only evidence is that the code compiles.

### M1 — the image loader

Map a PE into an address space and report what was mapped.

This is `map_image_into_view` without the accommodations. The loader
refuses an image that violates the format instead of guessing, because the
programs this runtime is for are not games that need to be rescued. A
refusal that names the field and the constraint is worth more here than a
load that succeeds for reasons the reader cannot see.

Events: the image's shape is reported through the `image_loaded`,
`mapping`, `section` and `import` kinds. There is no per-relocation or
per-TLS event: `docs/EVENTS.md` has the seventeen kinds that exist, and
neither `relocation_applied` nor `tls_initialized` nor `image_mapped` is
one of them. What the loader decides is observable through `occ check`,
which prints the placement plan rather than emitting records for it.

Depends on: `parser::PeImage`, which already parses the headers and
sections. The loader adds the mapping, the relocation pass, and the TLS
initialization.

**Landed.** `include/occ/runtime/address_space.h` and `loader.h`, with the
implementations beside them and `tests/test_runtime_loader.cpp` over a
fixture that writes a real PE byte by byte. What the loader refuses, and
why each refusal is load-bearing:

  * an image that is not amd64, by name, because "this is an ARM64 image"
    and "this file is damaged" call for different actions;
  * an image that asks for a base it cannot have and has no relocation
    table to fix itself up with;
  * a section whose virtual range leaves the user window;
  * a relocation block whose size is smaller than its own header, whose
    DIR64 entry points outside the image, or whose type is one this
    runtime does not apply;
  * two sections that overlap, or a section that starts inside the
    headers -- reported as a fact about the file, not as a conflict with
    the caller's space;
  * an entry point that is past every section, in a gap between two
    sections, or in a section that is not executable. A zero entry RVA is
    not an error: a resource-only DLL declares one.

The last two were found by the loader's own fuzz harness rather than by
reading, and each one was an image that loaded, reported success, and
handed the layer above a module that faults on its first instruction.
That is the class of failure this layer exists to catch and the reason
the harness runs the same corpus as the parser.

The contract that a load which is not ok leaves the address space
unchanged is checked by the tests and by the harness, and it is what
lets a caller retry at another base. It has three parts: the placement
plan, the relocation walk and the entry-point check all happen before
the first region is recorded, and the recording itself goes through
`record_batch`, which is all-or-nothing.

**What the loader does not do yet, stated plainly.** It reports an
image's shape; it does not run it. Without a mapper, nothing is mapped
from the file, no relocation is written, and no IAT slot is filled -- the
loader computes every one of those values and stops before the first store.
That is `occ check`'s mode and it is a contract rather than a fallback: a
checker that mapped every file it looked at would be a runtime with a file
browser attached. With a mapper -- `LoadContext::placement` -- the same
decisions produce memory, and the milestone is "M1 decides, and the stores
that follow the decisions are made and checked".

### The export table

`PeImage` parses the export directory; nothing consumes it yet. That is
deliberate, and the reason is worth more than the feature: the export table
is the first structure in this reader that **cannot** be walked correctly by
extending the import walk, because its three arrays are joined by indices and
every index is a place a file can disagree with itself.

Wine's implementation is a fair target for comparison here, because it is the
thing to beat. `dlls/ntdll/loader.c` resolves exports through
`find_named_export` and `find_ordinal_export`, and every one of the following
is a real difference rather than a stylistic one:

| | Wine | occ |
|---|---|---|
| name lookup | binary search over `AddressOfNames` | the name is attached to its entry during the walk, so there is no lookup to get wrong |
| name array order | assumed sorted, never checked | order is irrelevant; the file's order is honoured |
| counts | not cross-checked against the file's length | each array is bounded by the file before it is walked |
| `Base` | used in an unsigned subtraction that only works because the result "must" be in range | added in 64 bits and narrowed, so a base near the top of the range reports rather than wraps |
| forwarder cycle | recurses with no cycle detection (Wine Bug 60130; the fix, MR11701, is still unmerged) | not resolved in this layer at all — see below |
| forwarder string | no length bound, no termination check | read through the same bounded reader as every other name in the file |
| `AddressOfFunctions == 0` | dereferences the module base | refused |
| `Name` field | ignored | ignored, and the reason is written down |

The binary search is the substantive one, and the test that proves it is
worth reading. `find_name_in_exports` probes the middle of the name table and
narrows by `strcmp`. The format *requires* the pointers to be sorted so that
a reader may do this. Nothing enforces it. `test_export_names_out_of_order`
builds a table in the order `{Gamma, Alpha, Beta}` — a rotation of the sorted
order, which is the arrangement most likely to produce a wrong answer rather
than an outright failure. A search for `Alpha` there probes the middle,
compares equal, and is correct by luck. A search for `Beta` probes the
middle, goes left, finds `Gamma`, concludes it is greater, and reports
not-found. occ attaches each name to `AddressOfNameOrdinals[i]` as it walks,
so the table's order never enters into it: the cost is that names are read in
the file's order rather than searched for, and the benefit is that a file
which violates the specification still resolves.

**What the parser stops at, and why.** A forwarder is parsed into the module
and symbol it names — `KERNEL32.Sleep`, `MYDLL.#27` — and left there.
Resolving one means finding that module's own export table, which means a
module table, and this runtime does not have one yet; it is M2's asset.
Implementing the recursion now would mean writing a temporary module table
and deleting it, and the deletion would leave the parser different from what
the loader needs. The division of labour is therefore: **everything that is a
fact about the file is parsed here, and the one thing that is not — where a
forwarder actually points — is left to the layer that can answer it.** Wine
resolves forwarders by calling `load_dll` (`loader.c:963-974`), which changes
the process's module graph as a side effect of resolving a name; a reader
that answers "what does this DLL export" should not have that effect.

**Nine defects in Wine's export handling, and what each one costs.** Read from
`wine-mirror/wine` master and checked against the specification:

| # | defect | consequence |
|---|---|---|
| D1 | forwarder cycle, no detection | stack overflow (Bug 60130; fix unmerged) |
| D2 | counts not cross-checked against file length | reads past the image |
| D3 | table RVAs not range-checked | `get_rva` is bare pointer arithmetic (`ntdll_misc.h:109`) |
| D4 | name termination not checked | `strcmp` reads past the buffer |
| D5 | name array order assumed, never checked | wrong answer, silently |
| D6 | `Base` not validated; `ord - Base` relies on unsigned wraparound happening to fail | a TRACE line prints garbage |
| D7 | forwarder string unbounded | one export can be a 4 GB read |
| D8 | `AddressOfFunctions == 0` dereferences the PE header | resolves to the module's own DOS header |
| D9 | resolving a forwarder loads a module | the process's module graph changes |

D3 is the reason occ parses from a `ByteSpan` rather than from a mapped
image: `get_rva` is only correct for memory that is already there, and this
reader is given bytes.

**Two decisions that look like omissions and are not.**

The directory record's `Name` field is not read. It is an RVA to the module's
own name, and there is nothing in this file to use it for: a caller that
wants the name has it from wherever it opened the image. Reading it would
give occ a refusal Wine does not have — a DLL whose export table is perfectly
walkable and whose `Name` RVA happens to be zero would be rejected, and
Windows loads it. That is the difference between refusing a file that cannot
work and refusing a file that would have worked, and only one of those is a
reader's job.

The entry condition tests the RVA alone and leaves the declared size to the
record check. A file with an RVA and a size of zero has said it has an export
directory and also said the directory holds nothing, and the second claim
makes the first impossible: the record lives in the directory. Skipping the
walk on a zero size would report that as a DLL with no exports, which is a
thing a program acts on. Wine resolves the RVA without consulting `Size`
either — `RtlImageDirectoryEntryToData` returns on `!VirtualAddress` alone —
and reaches the same conclusion one check later, at
`exp_size < sizeof(*exports)`. The same condition was removed from the import
walk, where it had the same defect and had never been tested.

**What the tests are.** `tests/test_pe.cpp` grew from 278 to 466 assertions;
the export section is 130 of them. Seven mutations were run against the
production code, and the table below is the result. Every one is a mistake
this reader is known to have been protected against, and the point of running
them is that the second one is not protected against by anything except the
first:

| # | mutation | result |
|---|---|---|
| 1 | ordinal is the index, without the base | CAUGHT — 11 failures |
| 2 | forwarder interval closed on the right (`>`) | CAUGHT — 1 failure |
| 3 | forwarder DLL split at the *first* dot | CAUGHT — 4 failures |
| 4 | name written at the name table's position, not at the index | CAUGHT — 8 failures |
| 5 | out-of-range index clamped instead of refused | CAUGHT — 2 failures |
| 6 | empty slots not trimmed | CAUGHT — 1 failure |
| 7 | forwarder ordinal parsed with `strtoul` | CAUGHT — 8 failures |

Mutation 6 is the one worth explaining, because it found a redundant check
rather than a missing one. The address-table walk had `if (rva == 0) continue`
*and* a trim at the end; the trim made the first unreachable, so removing the
first changed nothing and the mutation escaped. Two statements of the same
fact is not a belt and braces, it is two places to forget. The check now
exists once, after the walk, and the comment at each site says where the other
one went.

The fixture is `build_export_image` in `tests/test_pe.cpp`, and it writes
every byte at a fixed offset: `.text` at RVA 0x1000, `.rdata` at RVA 0x2000,
the record at 40 bytes, then the address table, the name-pointer table, the
ordinal table, and the strings. A test that wants a name which will not read
says `unterminated` on that name; a test that wants a forwarder which will not
read says it on the forwarder; a test that wants a file cut short says
`truncate_to`. One builder, because a shared builder that grew a flag per test
would be a builder whose flags interact in ways no single test exercises.

### The placement layer

`LoadContext::placement` is the difference between the two things a caller can
want from `load_image`, and it is a pointer rather than a flag because the two
are not a matter of degree. With a mapper, the image's bytes are copied into
memory, its relocations are written, its IAT is filled and its sections are
given their final protections; the module returned describes memory a program
can execute. Without one, every decision is still made and every refusal is
still reported, and nothing is mapped.

The order is the contract, and it is the order Windows uses:

1. **Plan.** The window check, the section overlap check, the relocation walk
   and the entry-point check all run before anything is mapped. A file that
   cannot be placed is refused without having been placed, which is what lets
   a caller retry at another base without unwinding a half-populated map.
2. **Map, all read-write.** Every region goes in writable whatever the
   section's flags say, and the flags are applied afterwards. The alternative
   cannot work: a relocation routinely names an address in a read-only
   section, because a read-only section is full of pointers to the image's own
   functions and those pointers are exactly what a relocation rewrites.
3. **Copy the file's bytes** — headers and sections, with the section data
   bounded by both the file and the region.
4. **Apply the relocations.**
5. **Write the IAT** — after the relocations, because the IAT of a relocated
   image holds RVAs until the relocation pass has run, and an IAT written
   first would be rewritten by the relocations into an address plus a delta.
6. **Set the final protections**, section by section.

Steps 4 through 6 are the only ones that touch memory, and a failure in any of
them rolls back every mapping step 2 made. The rollback is by base address
from the batch rather than from the space, in reverse order, and it is not
reported over the failure that caused it.

`tests/test_placement.cpp` holds this layer to the rule `test_mapper.cpp` is
held to, applied one level up: a claim that a byte was placed is proved by
reading that byte back out of the mapped address and comparing it with the
file. The bytes in the file are the independent witness -- comparing the
loader's output against itself would agree with a loader that misplaced
everything as long as it misplaced it consistently.

**The relocation types, and three of them were wrong.** Writing the
placement layer's tests is what found this, and it is worth recording
because the errors were not subtle in the code -- they were confident.
`IMAGE_REL_BASED_HIGH`, `IMAGE_REL_BASED_LOW` and `IMAGE_REL_BASED_HIGHADJ`
are **16-bit** types, invented for machines whose instructions held half an
address each. This runtime implemented HIGH as a 32-bit add, LOW as a no-op,
and HIGHADJ as a 32-bit add whose adjustment was read from the bytes *after*
the field in the image. Each of those is a plausible-looking implementation,
and together they passed every test in `test_runtime_loader.cpp`.

The authority is the Windows Research Kernel's `LdrProcessRelocationBlock`
(`dlls/ntdll/ldr/ldrreloc.c`), which is the only place the arithmetic is
written down. Quoted here for the algorithm, in the kernel's own shape:

```c
case IMAGE_REL_BASED_HIGHADJ:
    if (Offset & LDRP_RELOCATION_FINAL) { ++NextOffset; --SizeOfBlock; break; }
    Temp = *(PUSHORT)FixupVA << 16;
    ++NextOffset;
    --SizeOfBlock;
    Temp += (LONG)(*(PSHORT)NextOffset);
    Temp += (ULONG)Diff;
    Temp += 0x8000;
    *(PUSHORT)FixupVA = (USHORT)(Temp >> 16);
    break;
```

Three parts of that are load-bearing and none is decoration:

- The adjustment is the **next relocation entry's own 16 bits**, not bytes in
  the image. An entry is a 4-bit type and a 12-bit offset with no room for a
  value, so the linker spends a whole second entry on the number. On the
  machines that emit HIGHADJ the bytes after the field are the *low half* of
  the immediate pair -- a different number entirely. HIGHADJ therefore
  consumes two slots, and the entry walk has to know that: a walker that
  treats the adjustment as a relocation of its own applies the delta twice.
- The adjustment is **signed**. A linker emits a negative carry when the low
  half was negative, and reading it as unsigned turns a subtraction of 8 into
  an addition of 65528.
- The `0x8000` is a **rounding term**, not an offset. An implementation that
  omits it is off by one on every field whose low half is below `0x8000` --
  a third of them -- and only on those, which is the worst possible way to be
  wrong.

Wine skips all three of the 16-bit types on win64 (`#ifndef _WIN64`), so there
was no Wine behaviour to copy and no test that could have disagreed with this
one. LOW in particular is applied here rather than skipped: "no amd64 linker
emits it" is a claim about linkers, and a loader that refuses a file it could
place is not more faithful than one that places it wrong.

**A test that agreed with a wrong implementation.** The fixture that caught
the three had to be built twice. The first version left the 16 bits after
HIGHADJ's field at zero and gave the entry an adjustment of -8; a mutation
that moved the adjustment's source from the entry to the image passed every
assertion in the file. The reason is arithmetic rather than a missing check:
both the preferred base and the placement base are page aligned, so the
delta's low 16 bits are zero, and two 16-bit adjustments can differ by at
most 65535 -- which cannot change the *high* half of a 32-bit sum unless it
crosses a 16-bit boundary. `-8 + 0x8000` carries nothing and so did the zero
that replaced it, so both sources computed the same field. The fixture now
uses `-32768`, whose sum with the rounding term is exactly `0x10000` and
carries, and a neighbouring half of `0x0100`, which does not.

There was a second failure in the same place, and it was the test's fault
rather than the loader's: the expected value was computed with the same
arithmetic from the same constants and compared against a load from the
mapped address, which the optimizer is entitled to fold into reading its own
answer. It did. The expectations now go through `volatile`, which says an
expectation is a value and not an alias for the thing under test.

**Measuring that, rather than assuming it.** The two fixes above arrived
together, which means neither was ever shown to be the one that worked, and a
fix nobody can attribute is a fix nobody can rely on. The mutation was HIGHADJ's
adjustment read from the image instead of the second entry -- the runtime's
own original code, and wrong here by a wide margin. Four runs, one variable at
a time:

| expectations | diagnostic in the loader | LTO | result |
|---|---|---|---|
| plain local | none | off | **passed all 74 checks** |
| plain local | one `fprintf` | off | 2 failed |
| `volatile` | none | off | **2 failed** |
| `volatile` | none | on | (not run; not needed) |

The first row is the finding: the suite was blind to a real bug in the code it
was written for. The second row is why the natural first guess about the fix
was wrong -- adding a print to the loader did stop the mutation, and it is
tempting to conclude the print fixed the test. It did not. The print was the
second and weaker half of the effect, and the third row separates them: with
`volatile` and no print anywhere, the mutation is caught. The loader ships
without a diagnostic in it.

**Six mutations, and the sixth is why the file is shaped this way.** Each of
these is a change that makes the loader wrong; none is a typo-shaped change
that a reviewer would reject, because each is the mistake someone would ship.
The runtime's own original code was three of them at once.

| mutation | what a runtime that made it would do | caught |
|---|---|---|
| HIGHADJ does not consume its second slot | applies the delta to the adjustment's own type nibble | 1 failure |
| HIGHADJ drops the `0x8000` | wrong on a third of fields, right on the rest | 1 failure |
| HIGH writes a 32-bit field | overwrites the low half of the immediate pair | 2 failures |
| LOW is a no-op | leaves the low half at the old base | 1 failure |
| HIGHADJ zero-extends the adjustment | a sign error of one carry | 2 failures |
| HIGHADJ takes the adjustment from the image | adds the low half instead of the carry | 2 failures |

The fourth row caught the code that shipped, and the fifth caught a fixture
that had been fixed for the sixth and left itself open to a fifth. That is
worth stating plainly because it is the part that generalises: **one constant
covers one failure mode, and a fixture fixed against a mutation is still
unmeasured against every other one.** `-32768` was chosen because a 15-bit
mask turns it into zero, whose sum with the rounding term is the same
`0x8000` that the correct value produces -- the two agree on the high half
and the mutation passes. The second HIGHADJ field, with an adjustment of
`-1`, closes that: masked it becomes `0x7FFF`, half the range away, on the
other side of the same boundary. Between the two fields the three wrong
readings of the adjustment -- signed as unsigned, with the sign bit cleared,
and taken from the image -- are each separated from the right answer, and the
count assertion says the module saw five relocations in seven entries.

The lesson generalises past this file, and the reason it does is structural
rather than a matter of discipline. The fold needs an assertion that reads a
field out of mapped memory and compares it against the same field re-derived
from constants. In this repository the helpers that dereference an address --
`load_u16`, `load_u32`, `load_u64` -- exist in exactly one file,
`tests/test_placement.cpp`, so the shape that can be folded exists in exactly
one file. `test_mapper.cpp` observes through a forked child and a pipe, and
`test_observer.cpp` through a socketpair, which no optimizer can follow. The
rest assert on parse results over a `std::vector` the test itself filled, where
the expected value is a literal. A future test that adds an address-dereferencing
read to one of those files is the first thing that would reintroduce the blind
spot, and the rule for it is already written down at
`tests/test_placement.cpp`'s `expected_field`: an expected value derived from
the same arithmetic as the code under test is a *value*, and `volatile` is how
it says so.

### Placing with retry

A caller that names a base gets it or gets a refusal. `load_image` says so
and does not pretend otherwise, because a caller which asked for an address
and silently received a different one has a bug, and a retry loop wrapped
around it would *hide* that bug rather than fix it — the failure mode, not
the remedy. So the loop is a separate entry point, `load_image_retrying`,
and the fact that it exists at all is the statement that a conflict and a
refusal are different things.

The loop retries exactly one error: `AddressConflict`. That is not the only
error a placement can produce, and the distinction is the whole content of
the policy. `AddressConflict` is a fact about the **caller's space** — this
address is spoken for, and another address may not be. Everything else is a
fact about the file or about this machine: a relocation naming a gap in the
image is bad at every base, and an image this runtime does not execute is
not going to be executed by moving it. Retrying those would replace a
refusal that names the problem with one that names the wrong problem, and a
reader of the second message would go looking for space that was never the
problem. Wine's `LdrAllocateDllSlot` retries on a broader set of statuses
and reports the last one, which is a defensible choice for a loader nobody
is debugging; here the report is the product, so the two cases get two
sentences.

Four things end a search, and each says which one it was, because "it tried
64 addresses" and "there was nowhere to put it" call for opposite responses
from whoever reads the report:

| End | `attempts` | The detail says |
|---|---|---|
| success | n | nothing; a success reports no reason |
| a refusal | 1 | what the attempt said, verbatim |
| the search ran out | n | "no base was free", followed by what the last attempt said |
| the cap | 64 | "still in the way after 64 bases" |
| a repeated base | n | which base, in hexadecimal, and that it had been tried |

The last two exist because the policy is a function pointer and a function
pointer can be wrong. A chooser that answered with the same address forever
would spin until the cap and then report 64 attempts, which is a sentence
about the policy wearing the loop's clothes.

The default policy is a **deterministic downward scan**, and calling it that
is a statement about what it is not. Windows picks a random base from a
16 MB window with ASLR, which needs an entropy source (`SystemFunction036`)
and a replay that hands back the same addresses — and this runtime has
neither yet, so a random policy here would produce runs that differ from each
other in a way nothing could reproduce. A scan that is verifiable beats a
randomiser that is not, until the layer that can carry one exists. It steps
*down* rather than up because a linker assumes the module is at its linked
base, and scanning up walks into the base-competition region where every
other image's preferred base already is.

Three measured facts about the address space shaped this, and all three are
the kind that are cheap to get wrong and expensive to debug:

  * **`mmap` guarantees page alignment and nothing more.** Measured here, an
    `mmap` of 192 KiB came back at `0x7febd0d407000`, which is `0x7000` past
    a 64 KiB boundary. An early fixture asked for twice the size, took the
    midpoint as one address and the whole as the other, and gave up whenever
    the answer was not granularity-aligned — which is **15 times out of 16**.
    Every case below it printed a `SKIP`, and the file still reported zero
    failures. The fix is to ask for one granularity more than the two
    addresses need and take the aligned pair out of the middle, so the
    alignment is arithmetic rather than a hope. This is the project's
    recurring failure mode in its sharpest form: **a test that measures
    nothing prints like a test that passed**, because `SKIP` prints a line
    and `PASS` prints nothing.

  * **The window is 128 TiB, so "occupy the window" is not a test
    operation.** From the `mmap` region at `0x7febd0d407000` down to a small
    image's floor at `0x30000` is about 33 million steps of 64 KiB. A case
    that wanted to watch a scan run out of room by reaching the floor would
    need 33 million attempts, or a cap low enough to stop it first — and a
    cap that low would stop every real search. So the floor cases name a low
    address and *check it against the kernel with real mappings* before
    relying on it. Naming an address is otherwise the thing these tests never
    do; it is allowed here for one reason, which is that the floor is a fact
    about the image and a base chosen without reference to it puts the bound
    under test out of reach.

  * **`space.find()` answers about interiors.** A region one granularity tall
    contains every address inside it, so a check for "was anything placed
    here" that looks *inside* an occupier answers yes whether or not the
    retry did anything. An early version of the retry case checked one
    address into the occupier and failed against a correct loader. The
    addresses checked are one granularity *above* it.

The floor itself is the window's floor and does not move with the image's
size, which is worth stating because an earlier version had it as
`kUserMin + round_up(size - 1, granularity)` — the image's own size added to
the window's bottom. That put the floor at least one granularity too high
for every image smaller than a granularity, and it did so silently, because a
scan that stops one step early still returns a plausible-looking answer. The
cost was a policy that reported *no base was free* about a space with a free
base in it. What the size decides is not where the floor is but whether
there is a base at all, and since PE32+ carries `SizeOfImage` in 32 bits
while the window is 47, that check is unreachable — asserted as such rather
than left as a branch nothing can enter.

The `BaseChooser` seam is where a caller installs ASLR later, and it is
documented as a seam rather than as a policy: a null chooser is the
deterministic scan, not "no policy". The contract it has to honour is that
it may answer with **any** legal base, and the test that enforces this uses
a chooser whose answers are one *page* apart rather than one granularity
apart — a case that only ever used granularity-spaced answers could not tell
a loop that honoured the chooser's spacing from one that overrode it with a
scan of its own.

`tests/test_placement.cpp` grew from 76 assertions to 193 with this section,
and the mutation harness in `tools/mutate-retry.sh` reports 12 of 12 caught.
That number is worth less than what it cost to get there. Three of the
mutants survived the first run, and each named a way the tests were lying:

  * a mutant that rounded the image's size differently survived because the
    test computed its expected floor with **the policy's own formula**. Every
    assertion was stated relative to a number derived from the expression
    under test. The test now finds the floor by asking what fits and what
    does not, in arithmetic that never mentions the policy.
  * a mutant that rewrote the underflow guard to inspect the result rather
    than the base survived because the test only asserted *why the guard is
    needed* — that the unguarded subtraction wraps — which is a statement
    about subtraction. It never called the policy with a base **below** the
    window, which is the only place the two forms disagree. That call is
    there now.
  * a mutant that made the syscall counter skip failed `mmap`s survived
    because the test's bound was `>= one per attempt`, which is exactly what
    a counter that skips failures produces when every attempt is refused on
    its first candidate. The check that distinguishes them is now in the
    retry case, where one attempt succeeds and the exact count of six is
    accounted for: the refused `mmap`, two mappings, two protections.

The counter itself was wrong before that, and finding out why is the more
useful half. `syscalls_made()` moved only on a **successful** mapping, on
the reasoning that a failure left nothing to be accountable for — which is
true of the space and false of a counter, whose job is to say what the
process asked the kernel for. A loop that spent three attempts discovering
three conflicts reported that it had made no syscalls at all, and a reader
checking that number against the attempt count had no way to tell a loop
that never tried from one whose every try the kernel refused. The same
comment in `record_batch`'s rollback path already said "the counter still
moves, because a syscall was made", so the two paths disagreed about what
the counter counted.

The harness itself has one rule learned the hard way: it copies the pristine
sources at **run time** into a temporary directory and verifies the restore
with `cmp` at the end. An earlier version restored from a path written down
when it was written, and the floor and upper-guard repairs — both made later
in the same session — were silently discarded by the final restore. The
suite still reported green, because it was measuring the older behaviour.

### The mapping layer — `include/occ/runtime/mapper.h`

`AddressSpace` is a ledger. It was deliberately built as one: every rule
in `record()` and `record_batch()` is reachable without a syscall, which is
what makes the overlap and window rules testable against spaces that were
never mapped. It also means the ledger cannot create memory.

`Mapper` is the hand that moves the kernel and the ledger in one step, and
it exists because the two cannot be allowed to disagree. Between "the kernel
mapped it" and "the ledger recorded it" there is a window in which a region
exists in memory and no operation can find it, or exists in the map and
nothing will ever free it. So the operations that create and destroy memory
come in pairs — `map`/`unmap`, `map_batch`/`remove`, `protect`/
`set_protection` — and there is deliberately no public way to map memory
into an address space that does not know about it.

Three decisions in it are the ones that matter, and each is a place where
the obvious implementation is wrong:

  * **`MAP_FIXED_NOREPLACE`, conditionally.** Without it, a mapping at an
    address that is already mapped does not fail — it silently replaces what
    was there, and the ledger still describes the old region, and the
    process's map is now a lie about its own memory. With a check-then-map
    instead, the check and the act are two syscalls and two threads both
    find the address free. The flag makes the kernel do the check as part of
    the mapping, which is the only place the answer cannot change in
    between.

    The flag is passed only when the caller named an address, and that
    condition is a kernel behaviour rather than a preference: asked with a
    null address the kernel does not search for a hole, it fails with EPERM,
    because the search starts at zero and zero is below `mmap_min_addr`.
    A null address is the one case where the flag has nothing to say, since
    the kernel's own search already finds a hole and a hole is not something
    that can be silently replaced.

  * **`PAGE_WRITECOPY` translates to `PROT_READ`.** Linux's private mapping
    is already copy-on-write, so the copy is the mapping's own semantics
    and the page must not be writable. Translating it to `PROT_READ|PROT_WRITE`
    would let a program write to a page whose entire purpose is that it must
    not, and the ledger would say `PAGE_WRITECOPY` while the kernel said
    otherwise. The two write-copy protections and the four executable ones
    are translated by enumeration rather than by bit test, because the
    Windows constants are powers of two that do not compose into the
    protection they name — `PAGE_EXECUTE` is 0x10 and `PAGE_EXECUTE_READ` is
    0x20, so neither shares a bit with the other, and `PAGE_READWRITE` is
    0x04, so a mask that included 0x04 would mark every writable region
    executable.

  * **A modifier is refused, not stripped.** `protect` returns
    `NotImplemented` for `PAGE_GUARD`, `PAGE_NOCACHE` and
    `PAGE_WRITECOMBINE` rather than applying the base protection. A guard
    page that arrives as ordinary read-write memory is a buffer overflow that
    does not fault, and the reason the modifier bits are separate from the
    protections in the type at all is that a reader who treats them as
    protections would accept `PAGE_GUARD` alone and map something with no
    access. Linux's closest equivalent is `PROT_NONE` plus a signal handler,
    which is a mechanism this runtime does not have a place for yet.

`Mapper::unmap` addresses a whole region and refuses an address in the middle
of one. `Mapper::protect` does the same, for the callers for which a whole
region is the right answer. This is stricter than `NtUnmapViewOfSection`, and
it is strict on purpose: a split makes "the region covering this address" a
different answer before and after a call a reader would call the same call.

`NtProtectVirtualMemory` is **not** limited that way, because Windows is not.
It takes a range and changes exactly the pages in it (`virtual.c:2039`,
`set_protection( view, base, size, new_prot )`), so a program that makes one
page read-only keeps its neighbour writable. The ledger is cut to match — the
same three-way split a `MEM_DECOMMIT` makes — so the region the ledger reports
covers the range that changed and nothing more. Two rules come with it:

  * **Every page in the range must be committed**, or the whole call is
    `STATUS_NOT_COMMITTED` and nothing changes. A protection is not a commit;
    a caller that protected half a reservation would believe it had memory it
    does not. This is Wine's check at `virtual.c:5629` and it is Windows'.
  * **The range may span more than one region.** Wine refuses this —
    `find_view` returns a single view — but on Windows the protection of a
    page is a property of the page, not of the kernel's bookkeeping, and two
    contiguous committed ranges are one range to a caller. This runtime walks
    the regions the range spans and gives the Windows answer, which is one of
    the places it is deliberately more correct than Wine.

`Mapper::protect_in_range` is the primitive behind it: it checks the range,
calls `mprotect` on the range, and only then cuts the ledger, so a refused
`mprotect` leaves the ledger exactly as it was. `Mapper::protect` remains the
whole-region operation, and keeping the two separate under two names is what
lets `Region::protection_changes` keep the meaning its comment claims.

`tests/test_mapper.cpp` holds every mapping case to one rule: a case that
claims a mapping works must prove it by writing to the bytes and reading
them back, and a case that claims a protection was applied must prove it by
failing to touch them. The read-only region of a batch is checked three ways
— the child faults on write, the ledger says `ReadOnly`, and
`/proc/self/maps` says `r--p` — because a mapper that translated every
protection to `PROT_READ|PROT_WRITE` would return success for all of them
and only the kernel's own map distinguishes them.

The accesses that must fault run in a forked child, and the first version of
that was wrong in a way only a sanitized build found. It had the child die and
the parent read `WTERMSIG(status) == SIGSEGV`. Under AddressSanitizer the
child does not die of `SIGSEGV`: the runtime installs its own handler, prints
a report, and aborts, so the parent sees `SIGABRT` and eleven cases fail for a
reason that has nothing to do with the mapper. A test whose result depends on
which sanitizer is linked is a test of the sanitizer.

Worse, the wait status cannot say *where* the fault was. A child that
segfaulted because the protection worked and a child that segfaulted because
the address was never mapped are the same observation to the parent, and
telling them apart is the entire question. So the child now installs its own
`SIGSEGV`/`SIGBUS` handler with `sigaction` and `SA_SIGINFO`, and reports the
signal and the kernel's `si_addr` back through a pipe. The child is
instrumented and the handler is the same on every build, so the observation
does not change with the build; and the parent can now assert *the fault was
at the address I named*, which a wait status could never support.

The same run turned up a second defect of the same kind, in the addresses
rather than the mechanism. The batch cases asked for `0x200000000` and two
other fixed addresses, on the reasoning that they were far enough above the
window floor to be out of the way. A fixed address is an assumption about
what else is in the process, and a sanitized build invalidates it by putting
its shadow memory exactly there. They are now found by asking the kernel for
a range and giving it straight back — and the first version of *that* reported
the address it had just taken without releasing it, so every caller received
an address already occupied, and then failed with `EEXIST` at an address the
finder had certified as free. A probe that cannot release what it took has
not found a free range; it has moved one.

92 checks. Three mutations were tried against it and each is caught by the
case written for it: removing `MAP_FIXED_NOREPLACE` (11 failures), removing
the batch's rollback (1 failure, the case that exists for exactly that), and
stripping modifiers instead of refusing them (6 failures).

### Thread-local storage — `include/occ/runtime/loader.h`

A module with a TLS directory owns a slot, every thread owns a block, and
the two are joined by a DWORD the loader writes once and never writes again.
That is the whole mechanism, and the reason it is worth its own section is
that every one of those four steps has a way to be wrong that does not crash.

Wine's implementation is `alloc_tls_slot`, `free_tls_slot` and
`call_tls_callbacks` in `dlls/ntdll/loader.c`, and reading them settles three
questions that a specification would leave open.

**The directory is read from the mapping, not the file.** Wine calls
`RtlImageDirectoryEntryToData(mod->DllBase, TRUE, IMAGE_DIRECTORY_ENTRY_TLS,
&size)` — the mapped image, not the file. This is not a preference. The
directory's four pointer fields hold *virtual addresses*, and a file's copy
holds the **linked** ones: `hello.exe` says `0x14000a000`, and once the image
is placed anywhere else that number names nothing. A loader that read the file
would hand every thread a template full of pointers into whatever the process
has at the *linked* base — which for a relocated image is nothing, and the
fault lands somewhere with no relationship to TLS. (An earlier version of this
document claimed the fields are 32-bit and absent from the relocation table,
so that reading either copy gives the same bytes. Both halves of that are
wrong — the fields are 64-bit on PE32+, and the relocation table *does* cover
them, `hello.exe` fixing up RVA 0x4040-0x405f — but the conclusion was right
by luck and is now right by the argument above.)

The directory's width matters as much as its source, and getting it wrong is
not a misparse of one field: `IMAGE_TLS_DIRECTORY64` is 40 bytes with 64-bit
pointers and `IMAGE_TLS_DIRECTORY32` is 24 with 32-bit ones. A reader that
steps four bytes per field reads the low half of `StartAddressOfRawData` as
the start and its **high half as the end**, so the template "ends before it
starts" and every real 64-bit module is refused. That is what happened: the
whole TLS suite passed, because the test builder wrote the four-DWORD layout
the loader expected — a structure Windows does not define. See
`tests/test_runtime_loader.cpp`'s real-compiler case, which exists to hold the
door shut on that class of bug.

`.tls` here declares four bytes of raw data and a full page of virtual size,
and the directory's RVA points 0x40 past the section's start — into the zero
fill. The file has no offset for that RVA at all, so a file reader *must*
refuse, and refusing is a different outcome from the one the test asserts. The
mapped reader finds six zero DWORDs, concludes the module has no TLS, and the
load succeeds. Reading the file cannot produce that outcome, and neither can a
mirror of the loader's own arithmetic, because the property being tested is
which memory the bytes came from.

**The pointer fields are relocated, and a null one is not.** The relocation
table covers the directory, so a VA-encoded directory stays correct when the
image moves — that is what a real linker emits, and mingw's `hello.exe` has
all four fields as VAs with entries for each. A linker only emits an entry
where it wrote an address, and a fixture that emits one for a null field gets
a field holding the *delta* after relocation: an address inside the image that
nothing meant to name, which the loader then walks as a callback array. That
is a fixture trap rather than a loader bug, and the loader's answer to it --
refusing a callback array outside the image -- is the correct one.

**A VA-encoded directory is only meaningful where the image landed.** The two
readings are both in real use. A field that falls inside the current image is
a virtual address; a field that does not is read as an RVA from the image base.
This is explicit rather than silent, which is the point: a reader of a
refusal needs to know which reading was chosen and what it resolved to, not to
be handed an address into nothing.

**A freed slot is zeroed, not erased.** `free_tls_slot` `memset`s the entry.
Erasing it would renumber every slot after it, and the slot numbers are
already written into module memory as `AddressOfIndex` — the table would stop
agreeing with the images that read it. The reuse search here is the same
search over the same all-zero records, and a test frees the middle of three
slots and asserts that the next load takes the hole, that the high-water mark
does not move, and that the two live modules still read the slots they had.

**What occ does not do, and why it is not a simplification.** Wine's
`call_tls_callbacks` calls the addresses in the array inside `__TRY` and stops
at the first exception. occ has no structured exception handling and cannot
execute guest code, so it does not call the addresses at all: `TlsCallback` is
an invoker supplied by the caller, returning `bool`, and the first `false`
stops the walk. What is left is the part that is actually about the format —
the walk, the terminator, the ordering, and the three inputs every callback
receives (`reason`, `module`, `callback`) — and the part that would be a
fiction is gone rather than stubbed.

**The order of operations is load-bearing, twice.**

The index DWORD is written after the final section protections are applied,
not before. Every section is mapped `ReadWrite` while the image is being
built, so a writability check made during `load_tls` is a check that cannot
fail. The sequence is: read the directory, validate it, take a slot; apply the
real protections; then `commit_tls_index`, which is the first point at which
"is this DWORD writable?" is a question with two answers. A refusal there
gives the slot back.

And `build_tls_block` checks that the template is readable *before* it asks
the kernel for a page. This one was a real defect, found by a test that was
itself making the same mistake the code was. The original order was: allocate
a block, then read the template out of the space. The kernel chooses the
block's address, and it is free to choose the template's own. When it does,
the new mapping covers the template, `find` reports it present, the copy
succeeds — and what it copied is a page of zeroes out of the block that was
just allocated. The call reports success. Every thread of that program then
has a TLS template full of zeroes where the module's pointers should be, and
nothing in any report says why.

The version with the defect passed every other test in the file, including one
that appears to cover exactly this ground. It was caught by a test that
unmapped the template's section and expected a refusal; the refusal did not
come, because the kernel had put the block back on top of what the test had
just removed. The fix is the order, and the case that pins it down asserts
that a `build_tls_block` whose template is not mapped is refused *and leaves
no region behind* — the mapping it would have made is not made.

**The suite's own address allocator, because a test that cannot be trusted
cannot test anything.** Fifteen fixtures need a base that nothing is mapped
at. A constant is an assumption about what else is in the process, and an
ASan build invalidates it by putting 4 GiB to 1 TiB of shadow exactly where
every 64-bit PE's preferred base lives — which is how this section's first
version failed, in three different fixtures, on the sanitizer build only.
Asking the kernel for a range and giving it straight back is the right answer
and is not sufficient alone: the kernel's search is deterministic about where
a mapping of a given size lands, so every caller asking the same size is
handed the same address, and the second load fails with
`STATUS_CONFLICTING_ADDRESSES` at an address the first one had certified as
free.

The stride that makes the answers distinct was the second version, and it was
wrong in a way that only a different compiler exposed. The stride separates
the claims from *each other*; it says nothing about the rest of the process.
On the Clang build the kernel's first answer came back outside the
shared-library range and every step after it was free by luck. On the GCC
build the kernel answered *inside* that range — `0x7f44...`, which is where
libc and libstdc++ live — and the same code stopped working. Each candidate
is now probed at its own address with `MAP_FIXED_NOREPLACE`, which refuses an
occupied address rather than replacing what is there, and the walk steps over
it. The case that pins this down parks a mapping inside the walk and asserts
that the claims on either side of it are neither that address nor a refusal.

**The defect the fuzzer found, which no unit test did.** The loader records
the image in the space before it walks the relocations, the IAT and the TLS
directory, and each of those three can refuse. The rollback undid the kernel
mapping and, when there was no mapper, nothing at all — so a refused
`occ check` left the space describing an image whose bytes were never placed,
which is a state a caller cannot tell from a successful load and which the
loader's own contract says cannot happen.

It survived every unit test in the file because every one of them that reaches
a post-record refusal supplies a mapper, and a mapper's rollback worked. The
path with no mapper is `occ check`, and it had no case of its own. What found
it was the loader harness's invariant — a refused load leaves the space as it
was — over a corpus seed whose optional header declares 0x60 bytes and whose
file stops 0x120 bytes in, so the data directory array is claimed and absent.
The parser handles that correctly: it reads only where the optional header
reaches and clamps the count to what fits. The loader on the no-mapper path
does not, because it goes to the file for the directory rather than to a
mapping that does not exist, and the offset it computes from the fixed layout
lands past the end.

The comment that kept it there was right about its subject and wrong about
its consequence. "A refusal with no mapper has nothing to roll back — nothing
was mapped" is true of the kernel and false of the ledger. The undo is now a
choice between two kinds rather than a guard on one of them, and the case
that pins it down asserts on the ledger's own contents rather than on a
count, because a rollback that forgot one section of four would satisfy a
count.

The harness's invariant was wrong too, and in the direction that matters: it
compared the allocation count, which `AddressSpace::remove` deliberately does
not move on a forget, because the count is a replay sequence number and a
region that was allocated and then forgotten still consumed one. Comparing it
demanded that an undone load lie about having happened. It is now `same_map`,
which compares the regions and the high water — and the loosening was checked
by re-tightening it and confirming the seeds still fail, so that a weaker
assertion is not doing the work of a missing fix.

**463 checks, 29 mutations.** The 29 are the ones a plausible mistake would
make, and the report is written to be worth what they were worth: three are
rejected by the compiler and counted separately rather than as coverage. One
is in the test file rather than the runtime, and one is the rollback above —
the two places where what is being checked is the suite's own honesty rather
than the loader's behaviour.

Two of them exist because of the width bug above, and neither could have been
written before it: reading a PE32+ directory at four bytes per field, and
reading a PE32 directory at eight. The first is caught by
`test_loads_a_real_compiler_pe` and the second by
`test_tls_pe32_fields_are_read_at_their_own_width`, so the pair is what keeps
the two widths honest from both sides.

**The harness restores the tree, and getting that right took a bug of its
own.** `restore()` copies three pristine files back over the working tree, and
its third line had the two paths the wrong way round — `cp "$TESTFILE"
"$WORK/test.pristine"`, which copies the file *under test* onto the backup
instead of the backup onto the file. The first mutant applied therefore
replaced the pristine copy with the mutated one, `restore` put the mutant
back, and every later mutant was reported "caught" because the tree was
already broken. The symptom is a report that looks perfect and measures
nothing, which is the failure mode this harness exists to detect — committed
here because the same three lines are in every mutation script in this
directory, and in three of the four the trap does not restore at all.

**A refactor that changes spelling invalidates a mutant, and that is a fact
about the harness rather than about the code.** One mutant's anchor named an
`if (m.template_size != 0)` wrapper and a `home` local that a later cleanup
folded into a short-circuited condition. The anchor matched nothing, the
mutant was never applied, and the run reported it as *survived* — which reads
as a hole in the suite and is nothing of the kind. The harness counts that
case separately, and the fix is to re-point the anchor, not to add a test.

### Import resolution — `include/occ/runtime/exports.h`

The fourth step of loading an image was the step that had no implementation.
`LoadContext::resolve` is a function pointer the loader calls once per import,
and nothing in the tree assigned it: the IAT walk found every descriptor,
parsed every thunk, honoured the ordinal flag and checked the target's
writability, and then had no way to learn that `kernel32!CreateFileW` lives at
an address. A registry of modules and the rules for looking a symbol up in one
is that missing half.

It is a registry and not a loader, and the distinction is the honest part of
the design rather than a way of making the work smaller. Loading a Windows DLL
means executing its entry point and recursively resolving *its* imports, which
is the layer above this one and is not built yet. What is built here is the
lookup half of Wine's `fixup_imports`: given a set of placed modules, find the
address a name names. When the loader can really load a DLL this file gains a
loader; the shape of everything below it does not change.

The four rules are Wine's, read out of `dlls/ntdll/loader.c` rather than
guessed at.

**A module name is matched without regard to case.** `find_basename_module`
passes `TRUE` to `RtlEqualUnicodeString`, and the `TRUE` is the
case-insensitive flag. An import spelled `KERNEL32.DLL` and a host that
registered `kernel32.dll` are the same module to the operating system, and a
case-sensitive comparison here would refuse an import Windows resolves — with
the refusal attributed to the guest.

**An export name is matched exactly.** This is the same loader and the other
direction, and the pair is the single most useful thing this file records.
`find_name_in_exports` does a binary search over the *sorted name array* with
`strcmp`, so Win32 export names are case-sensitive: a DLL exporting only
`Sleep` does not answer to `sleep`, and a program importing `sleep` fails to
link on real Windows. The first version of this file used one comparison for
both and the mutation harness caught it — folding the case of an export name
resolves an import Windows refuses, which is the same class of corruption as
believing a stale hint, in the other direction: a real address for a name
nobody exported. Two rules that differ, two functions that say so.

The search is a linear scan, and saying that is better than sorting a copy per
lookup and calling the result a binary search: `PeImage::exports()` is in
*address-table* order, not the sorted name-table order, so a binary search over
it would be a search for nothing. The table is a few hundred entries at most,
and a resolver that is O(n) on a table that fits in a cache line or two is not
what makes an import slow.

**A hint is tried first and believed only after a name comparison.** Wine's
order and Wine's reason (`find_named_export` compares `strcmp(ename, name)`
before returning `ordinals[hint]`). A hint is an index the linker wrote; the
sorted name table is the truth. A stale hint believed resolves a real import
to the wrong function with no report at all, which is a corruption rather than
a mistake.

**A forwarder is followed, and following one is bounded.** An export whose RVA
lands inside the export directory is a string naming a symbol in a *different*
module, so following it is a second lookup and the address that comes back
belongs to the module that answered. `find_forwarded_export` recurses through
`load_dll` with no depth bound, so two modules forwarding to each other is a
load that never returns; the bound of four is the reason this one terminates,
and a cycle is stopped rather than survived.

Two things this layer refuses that a loader is allowed to do. A module
described but not placed answers nothing rather than handing back an RVA as an
address — a caller that stored it would store base-zero and jump to the start
of the address space, and `occ check` relies on this: it has no resolver by
design, and imports are recorded and left alone. And an import that cannot be
resolved writes *nothing* to the IAT rather than a stub address, because the
loader reports the unresolved import as an event and a caller that can read the
record can say what was missing.

Two cases run the whole path rather than calling `resolve` directly: a real PE32+
image with an import table naming `kernel32.dll!CreateFileW` by name and
`kernel32.dll!Sleep` by ordinal, loaded through `load_image_retrying` with the
registry wired in as `LoadContext::resolve`, and the same image with no resolver
at all. The named import lands in the IAT at the registry's answer and the
ordinal — 0x37, past the end of a three-entry table — leaves its slot holding the
thunk the file described. So the second case's claim is that the slot is
*unchanged*, asserted against a named constant rather than a literal so the
reader can tell "unchanged" from "zero".

Reading the IAT is the part worth describing, because it is why these cases
cannot be faked. The loader's writes land in real memory at the module's base —
`AddressSpace` is the ledger of what is mapped, not the memory itself — so the
assertion reads the process's address space directly at
`LoadResult::imports[i].iat_va`. That distinction is the whole point:
`target_va` is the loader's *account* of what it wrote, and the slot is where a
program jumps. A loader that recorded the right address and stored the wrong one
satisfies every assertion that reads the record.

Three things about the fixture are worth recording because each cost a debugging
session, and each failed in the way that looks like a *different* bug:

- **The relocation directory's RVA was written as a tail-relative offset.** The
  directory named RVA `0xFC0`, below the section's own start, so `resolve_rva`
  failed and the loader refused the image as `BadRelocation` — from the
  *relocation* walk, for a field in the import area. Every other offset in the
  fixture is named the same way (`dll_at`, `thunk_at`, `iat_at`, `desc_at` are
  all tail-relative), so this one silently not being so was the point of naming
  them.
- **A base-relocation table with a terminator block.** The format is right to
  have one — a real table ends with an eight-byte block whose page RVA is zero.
  occ's loader does not walk that far: it stops on `cursor + 8 <= reloc_end`, so
  a terminator *inside* the declared size is read as a block whose size field is
  zero, and the image is refused as malformed with no detail string to explain
  it. The terminator is the version of this fixture that looks more correct and
  fails.
- **`0x140000000` is not a free base under AddressSanitizer.** A probe found the
  whole four megabytes from `0x140000000` to `0x141000000` occupied, and the
  retry policy's downward scan is sixty-four attempts of sixty-four kilobytes —
  exactly four megabytes, so it reported "the image was still in the way after
  64 bases" about a range that was never going to open. Both cases now ask the
  kernel for a base with a zero-base probe map and give it straight back, the
  same way `test_placement.cpp` finds one, and for the same reason: a written-down
  address is a claim about the process that stops being true when the process is
  different.

The first case is placed away from the base its own header names, on purpose.
The header says `0x140000000` and the placed base is whatever the process had
free, so the load delta is nonzero and the fixture's single `HIGHLOW`
relocation is *applied* rather than skipped. A fixture that happened to land on
its own base would pass with the relocation path never entered.

**121 checks, 19 mutations, none surviving.** Three of the 19 are rejected by
the compiler and counted separately rather than as coverage, because a change
the type system refuses is a stronger guarantee than any test and a report that
folded them in would be claiming credit it did not earn.

The harness runs every mutant under **two** builds and requires both to fail,
which is not redundancy. A hint bound one too generous reads past the end of
the table, and the plain run then reads whatever the allocator left there —
usually an empty string, so the hint is skipped anyway and the answer is right.
That mutant survived the first run of this harness, and the reason is the more
useful finding: every hint the suite supplied was either inside the table (0, 1,
2) or far outside it (0xFFFF), and `hint < size` and `hint <= size` agree about
every one of those. A table of three entries has no hint that lands between
"the last index" and "far away". The fixture that separates them is
`hint == size`, and it only separates them under AddressSanitizer, which
reports the heap-buffer-overflow at the mutated line and names the allocation.
A boundary test that passes for the wrong reason is the kind that lets the next
mistake through, so the suite now has one that cannot.

One check is documented rather than mutated. `walk`'s own
`index >= module.exports.size()` cannot be reached with a bad index by any
input: four paths reach `walk` and all four establish the bound first, and
`walk` is private with all four callers in the same file. An earlier version of
the harness carried that mutation and reported it surviving, correctly. The
check stays because it is the one place in the file that indexes the table, so
it is the one place that has to be right about the bound no matter what the
callers do — including the fifth one somebody adds later and forgets. Deleting
it turns a safe refactor into a heap read. The harness says it is untested
rather than leaving a "survived" that somebody eventually deletes out of the
script.

The harness restores the source and then rebuilds both trees on its way out, in
an `EXIT` trap rather than a line at the end of the script. Restoring the source
is not enough: the last mutant compiled is still in the build directories, it
compiles, and the next `ctest` runs it and reports a failure that has nothing to
do with any code under test. That happened here, and it is worse than a harness
that crashes — a crash is honest about what happened, while a stale mutant is a
green build that lies. The trap covers `SIGINT` for the same reason: a harness
interrupted halfway through nineteen mutants has one of them built, and whoever
interrupted it left believing the tree was clean.

### The ntdll memory layer — `include/occ/runtime/ntdll.h`

Eighteen exports, all of `dlls/ntdll/unix/virtual.c`, read rather than
remembered. Wine's file is about 6,100 lines and the eighteen are the whole of
its memory surface minus `NtCurrentTeb` and the two `NtWow*` shims; the rules
below are transcribed from it, with the line numbers in the comments so a
reader can check a claim without a checkout of Wine.

**What `zero_bits` actually means.** It is the half of an allocation request
that says *where* rather than *how much*, and the only thing surprising about
it is that it is not a bound on the address the caller passed.
`virtual.c:4618-4623`:

```c
if (!*ret) limit = get_zero_bits_limit( zero_bits );
else        limit = 0;
```

A caller that names an address has said where, and `zero_bits` is ignored
entirely. This runtime had a check that compared the two and refused — which
meant every call passing an address with the default window failed, and passing
an address with the default window is what a program that does not care does.
`NtMapViewOfSection` *does* compare them (`virtual.c:5450-5455`), the two
functions disagree in Wine, and the disagreement is transcribed rather than
smoothed over: a program that works on Windows relies on each function's own
rule, and harmonising them here would break one of the two.

**`zero_bits` changes kind at 32, and the two functions agree here.** Below 32
the value is a *count* of high-order address bits that must be zero, and both
the accept test and the search ceiling read it as one: `zero_bits == 21` means
"below 2^53", and the ceiling is `2^(32 - zero_bits) - 1`. At or above 32 the
documentation says the value "is a bitmask", and both halves read it as one:
`zero_bits_accepts` accepts an address exactly when `addr & ~zero_bits == 0`,
whose largest solution is `zero_bits` itself, so the search ceiling is the mask
plus one. The mask is `zero_bits` *as a number* and not a run of that many low
ones; the two spellings agree at exactly one value, 32, which is why a test of
only 32 cannot tell them apart.

**Wine's two halves disagree, and this runtime does not copy that.** Wine's
`NtMapViewOfSection` uses the mask reading (`virtual.c:5453-5455`), and its
`get_zero_bits_limit` (`unix_private.h:456-476`) reads the same value as a
*shift amount* instead, so for `zero_bits == 32` the accept test admits
addresses up to `0x20` while the ceiling the search uses is `0x3F` — a 64-byte
window, below the 64 KiB allocation granularity. Every request for memory under
4 GiB therefore fails with `STATUS_NO_MEMORY` on a machine with the whole low
4 GiB free. The mask reading is the documented one, so the mask reading is what
both halves do here. This is a deliberate divergence from Wine and the one place
in this layer where the transcription stops: a program that works on Windows has
to work here, and copying Wine's arithmetic would refuse an allocation Windows
places. A boundary walk in the suite asserts the property directly — for every
mask value, the last address the ceiling admits is one the accept test takes,
and the first address past it is one the accept test refuses.

**The `zero_bits` window has to be placed by this process.** Wine hands the
limit to wineserver, which places the mapping with the whole address space in
view. There is no server here, so `Mapper::map_below` does the search: descend
from the ceiling in granularity steps, `MAP_FIXED_NOREPLACE` at each candidate,
and let the kernel's refusal be the answer. The ledger lookup before each
attempt is a cheap skip and *not* the safety check — only the kernel knows what
anything has mapped, and a pre-check is the TOCTOU shape.

**A view with no address asked for comes from the bottom, and that is the
opposite direction.** A `zero_bits` request has a ceiling and so is searched
downward; a view that names no address at all has none, and Windows places it
low, above the image and below everything a program has mapped for itself. The
first version of this runtime asked for it the way a `mmap(NULL, ...)` asks —
`map(0, ...)`, let the kernel choose — and that is wrong twice over. Windows
places unconstrained views from the bottom of the user window *upward*, so a
program that maps a file and then asks for `plain` memory at a fixed offset
above it depends on the view being low; and `mmap(NULL, size, ...)` promises
page alignment and nothing more, where a view that must be reported by
`NtQueryVirtualMemory` as an allocation-granularity base has to actually be one.
`map_above(kUserMin, ...)` is the search, ascending in granularity steps, the
mirror of `map_below` and for the same reason: only the kernel's refusal is
evidence that a candidate is free.

**The 22-to-31 hole is copied, including the clause that cannot fire.**
`virtual.c:4581-4582` refuses `zero_bits` between 22 and 31 and accepts 21 and
32, and the second clause compares against a constant that makes it unreachable.
Both stay. The hole looks like an off-by-one and "fixing" it refuses a value
Windows accepts, in a program that was never wrong — the direction of divergence
nobody tests for. The dead clause stays for the same reason: removing a clause
that does nothing is safe today and wrong the day the constant's value changes.

**`MEM_DECOMMIT` is not a release.** Windows has three page states — free,
reserved and committed — and only the first two are address-space facts. A
release gives the addresses back; a decommit keeps them and only makes the pages
fault until something commits them again. The ledger models the third state with
`Region::committed`, a decommit of a range inside a region cuts that region into
up to three pieces (only the middle one loses its commit), and the pages are
`mprotect`ed away rather than unmapped, so a `MEM_COMMIT` into the same range
brings them back at the same addresses. Every accepted free type used to fall
through to one `unmap()`, which took the whole reservation away and returned
success — the addresses went back to the system, a later commit failed with
`MEMORY_NOT_ALLOCATED`, and a pointer the program had kept dangled. Nothing in
the return value said so.

**`MEM_COMMIT` takes a range, not a reservation.** A program reserves an arena
and commits it a page at a time as it needs it, and an implementation that only
accepted a whole reservation from its base would make every caller commit memory
it is not going to use. The commit is the exact inverse of the decommit: the
same `split` cuts the range out of its region, the same outward page rounding
applies, and the only difference is which way the `committed` flag is flipped.
Two roundings in this path are easy to swap and both are Windows':

  * **The address rounds to a page, not to the granularity.** The 64 KiB
    granularity is a rule about where a *reservation* starts; a commit names
    pages inside one. Rounding a commit to the granularity would move it to the
    start of the reservation, committing pages the caller did not name. The
    reserve path rounds down to the granularity and the commit path rounds down
    to a page, and the `base` computation branches on `MEM_RESERVE` for exactly
    that reason.
  * **The size is `ROUND_SIZE(addr, size, page_mask)`**, not the
    granularity-rounded size the reservation was made with. Using the
    granularity-rounded size makes a commit of the last page of a reservation
    whose length is not a multiple of 64 KiB reach past the region and fail as
    if it were extending the reservation.

A commit of a range that is already committed is a success and not an error —
Windows lets a program commit twice — and it changes nothing, so the ledger is
not cut and the change counter does not move. A commit is not a protection
change.

**`AddressSpace::split` is the cut, and it is written once.** A decommit, a
commit and a partial `NtProtectVirtualMemory` all need the same thing: the range
they act on must stop sharing a ledger entry with its neighbours, or the change
they make cannot be recorded as belonging to the range rather than to the whole
region. `split(base, size)` cuts the containing region into up to three pieces —
a head, the range, a tail — copies every field across, and returns the index of
the middle piece. The caller then flips the one field it came to flip and touches
nothing else, which is what keeps a decommit from changing a protection and a
protection change from committing a reservation.

**The index it returns is into the ledger, not into its own piece list, and
that distinction was a real bug.** The pieces are built in a local vector and
spliced in at the position the original region occupied, so the middle piece's
index *within the pieces* equals its index in the ledger only when the cut
happened at the front of the ledger. Reporting the pieces index addresses a
region the caller never named, and the symptom is silent: a decommit of the
second half of a reservation cleared the commit of the *first* half, so memory
the caller never touched faulted while the memory it had decommitted did not.
The fix is `insert_at - regions_.begin() + middle_index`, computed before the
insert invalidates the iterator, and the test that catches it is
`not committed: the page the commit did not name is still reserved` — which
exists because the mutant `a-commit-commits-the-whole-region` survived a suite
that only ever looked at the page that changed.

**`ROUND_SIZE` is not `round_up(size)`.** `virtual.c:189` adds the address's
offset *within its page* to the size before rounding:

```c
#define ROUND_SIZE(addr,size) (((SIZE_T)(size) + ((UINT_PTR)(addr) & page_mask) + page_mask) & ~page_mask)
```

Two consequences. A size that starts partway into a page is widened to cover the
whole page it ends on, so a range is never left with a live byte past its end.
And the term added before the mask is `page_mask`, which is one *less* than a
page — that single bit is what leaves an already-aligned size untouched
(`aligned + mask` rounds back down to `aligned`). Writing `page_size` there is
the bug this file shipped for a while: every request from a program that had
read the alignment rules is aligned, and each one then covered one page *more*
than the caller named, so a free or a protect reached into memory the program
did not ask about. The correct formula was written in the comment above the
wrong code the whole time, which is how it survived reading.

**A zero size in `NtProtectVirtualMemory` is a clause of its own.** The macro
above cannot express it — a range of length zero touches no pages, so
`ROUND_SIZE(addr, 0)` is zero, and Wine asks the kernel to protect nothing and
returns success having changed nothing. Windows protects the page the address is
in, and a program passing zero is asking for exactly that page; the call is
written out rather than left to the macro for that reason.

**Zero means opposite things in two functions.** `nt_free_virtual_memory`: zero
is "the size must be at the base", which is what `MEM_RELEASE` requires.
`nt_flush_virtual_memory`: zero is "the whole region" (`virtual.c:5793`). One
is a constraint and the other is a default, and a helper that normalised them
would break one caller each way.

**The read and write paths disagree on purpose.** An unusable destination
buffer is `STATUS_ACCESS_VIOLATION` in `NtReadVirtualMemory`
(`virtual.c:5902`) and an unusable source buffer is `STATUS_PARTIAL_COPY` in
`NtWriteVirtualMemory` (`virtual.c:5932`). The format is the reason: a write
can genuinely be partial — some of the source readable, some not — so the status
says so, while a read either copies all of a range or none of it and has no
partial case. A runtime with one code for both sends a program that branches on
it down a path Windows never takes. The two mutations of that pair are in
`tools/mutate-ntdll.sh` as one mutant each, in opposite directions, because a
suite that tested only one of the two would pass either.

**Three situations get three different status codes, and the inconsistency is
Wine's.** An address with nothing mapped is `MEMORY_NOT_ALLOCATED` from
`NtFreeVirtualMemory` and `INVALID_PARAMETER` from `NtProtectVirtualMemory`. An
unknown information class is `INVALID_INFO_CLASS` from `NtQueryVirtualMemory`,
`NOT_IMPLEMENTED` from `NtQuerySection`, and `INVALID_PARAMETER_2` from
`NtSetInformationVirtualMemory`. Harmonising any of them breaks a program that
branches on which it got.

### Where this goes past Wine

Four things Wine stubs are implemented, and the first two are the ones worth
naming because a stub that returns success is a bug the program cannot detect.

**`NtCreatePagingFile` reserves and reports its size.** `virtual.c:6079` is
`FIXME( "(%s %p %p %p) stub\n", ... ); return STATUS_SUCCESS;` — it returns
success and never writes `*actual_size`. A program that sizes its working set
from that answer reads whatever was in the variable, which on the first call is
uninitialised stack memory, and gets a page file of an arbitrary size. This
writes it.

**`NtFlushProcessWriteBuffers` actually flushes.** `virtual.c:6069-6073` is a
`FIXME` behind a `static int once` and returns success. Every writable region
here goes through `msync(MS_SYNC)` and the first failure is reported. A program
that calls this before telling the kernel its data is safe has a data-loss bug
that no return value will ever report, which is the worst kind to have: it
cannot be found by the program, only by the data it loses.

**The handle table is per-table and self-identifying.** A handle is a
per-table cookie in the high half and a slot index in the low half, with the
low bit forced so a handle is never zero and never reads as a null pointer.
An earlier version made a handle the *address* of its entry, on the reasoning
that an address is unforgeable and an index has to be trusted. That reasoning
was wrong three ways, and each is worth recording because the argument sounds
strong:

- the container had to become a `deque`, because `vector::push_back` moves every
  element and the handle was only valid while its entry stayed put — so making
  the handle unforgeable made it fragile;
- with a deque the entries are not contiguous, so the range check that made it
  safe could not be written as one;
- and worst, an entry's address plus `sizeof(entry)` *is* the next entry's
  address whenever the two are adjacent, so a forged interior pointer was
  indistinguishable from a real handle. The test caught it by accident: the
  forgery is only caught when the two entries are *not* adjacent, so the check
  passed or failed according to how the allocator felt that run.

An index has none of the three problems, and the cookie buys back what the
address seemed to give — two tables in one address space, which is the normal
case for the observer and the fuzz harness, cannot resolve each other's handles
even at the same index.

**Two information classes Wine cannot answer.** `MemoryRegionLedger`
(`0x1000`) reports a region's `initial_protection` alongside its current one,
plus how many times it changed, its kind, its section and whether it is
executable. Wine's `MEMORY_BASIC_INFORMATION` has only the *current*
protection, so "was this memory ever writable" has no answer there — and that
is exactly the question a write-then-execute exploit asks.
`MemoryRegionHistory` (`0x1001`) reports the allocation sequence number, the
region count and the high-water mark; Wine's regions live in a wineserver that
keeps no per-process counter, so a replay has nothing to align against.
`MemoryUnixFunctions` and its Wow64 twin are `FIXME` in Wine — they fall
through to a `default:` that returns `INVALID_INFO_CLASS` — and are answered
here from a real handle table.

**One class added where Wine says `NOT_IMPLEMENTED`.** `NtQuerySection` with
`SectionSectionInformation` reports the section's own extents, which is a
question about the object rather than about a view of it.

### What the tests are actually asserting

`tests/test_ntdll.cpp` is 298 checks in twenty functions, and the shape of
it is that each one is named after a rule rather than after a function. Six of
them exist because the first version asserted something Windows does not do, and
in each case the runtime was right and the test was wrong:

- `0x1001` bytes does **not** come back as `0x20000`. It comes back as
  `0x10000`, because `0x1001` is one byte over a *page* and the granularity is
  64 KiB. The test now asks for `0x10001` — one byte over the *granularity* —
  which is the only size that distinguishes the two roundings.
- a zero size in `NtProtectVirtualMemory` succeeds and protects one page.
- the rounded size for a one-page request is *two* pages, and the extra one is
  Wine's `+ page_mask`.
- a failed protect leaves `*old_protect` and the address and size untouched,
  which needs an address with *nothing* on it to be a failure at all — the
  earlier version shared an address with the success case above it.
- a forged handle is now three forgeries rather than one, because there are
  three distinct mistakes: an index moved by a slot, an index with the low bit
  clear, and an index from this table under another table's cookie.
- the flush-buffers case asserted that making a page read-only did **not** change
  the number of `msync` calls, which was true only while a protect changed the
  whole region. The old assertion described the old bug: with the whole region
  read-only there was no writable page left to reach. A range protect leaves the
  rest of the region writable, so the count now moves by exactly the regions
  that are writable, and the test computes that number from the ledger rather
  than hard-coding it.

Three more exist for the range-protect work itself, and each asserts the page
the caller did **not** name:

- `test_a_protect_acts_on_its_range_and_not_on_the_region` — the head and tail
  keep their protection and their change count, the range gets the new one, and
  the untouched page is written through to prove the kernel agrees. A runtime
  that only edited the ledger would pass the ledger assertions and fail this one.
- `test_a_protect_over_a_reserved_page_is_not_committed` — a range that includes
  a decommitted page is refused with `STATUS_NOT_COMMITTED`, *and nothing moved*:
  the committed page before it is still read-only and the region is not cut. A
  per-page check would have changed the head and then failed on the tail.
- `test_a_protect_may_span_two_regions` — a protect that crosses a seam between
  two committed regions succeeds, which is the Windows answer and not Wine's.

The other thing the tests assert is that the layer *refuses* rather than
faulting, and that is where the two most valuable findings came from.

**`memcpy` from address zero.** `nt_read_virtual_memory` had an `addr != 0`
guard around its mapping check — written to mean "a null address names no
region" — and address zero is exactly the address a program passes by accident,
so the guard skipped the check and the copy went to a null pointer. The
segfault is inside the runtime, so a program probing for a mapping by reading it
crashes the emulator rather than getting a status. `nt_write_virtual_memory` had
no destination check at all, and `nt_flush_instruction_cache` had the same
`addr != 0` shape. All three now check the whole range, and the status follows
Wine's far side rather than this layer's own: a `pread` on the target's
`/proc/pid/mem` that comes back short sets `STATUS_ACCESS_VIOLATION`
(`server/procfs.c:130-149`), so an unmapped source is an access violation on a
read and a partial copy on a write.

**Mapping the same range twice.** Three functions each made a probe mapping
with `mmap(nullptr, ...)` to learn an address and then handed that address to
`Mapper::map`, which mapped it *again* — and the second mapping always failed
with `EEXIST`, because the first was still there. `NtMapViewOfSection` and
`NtCreatePagingFile` therefore never succeeded at all, and
`NtAllocateVirtualMemoryEx`'s top-down search reported "no memory" on a machine
with terabytes of it. The detail string said "could not be recorded" and named
an address that had been free a moment before, which is the shape of a bug that
costs an afternoon.

**A `std::string` in a `memcpy`'d structure.** `MemoryRegionLedger` had a
`std::string` for the section name, and the whole struct is written into the
caller's buffer with `memcpy` — because that is what a byte-array ABI wants and
what the other info classes do. Under libc++ that works: the pointers come
along, nothing reads them, and the copy is never destroyed. Under libstdc++ the
caller's own variable *is* destroyed at the end of scope, its destructor calls
`free()` on a pointer that was copied rather than allocated, and the process
aborts. The name is a fixed 64-byte array with a reported length now, and the
comment on the struct says why — a byte array with a `std::string` in it is a
trap for the next person who adds a field and assumes the write is uniform.

**A use-after-free that a plain run cannot see.** `nt_unmap_view_of_section`
read `region->size` *after* the unmap that removed the region, and the ledger
is a `std::vector<Region>` — so the pointer was into an allocation the removal
had just freed or moved. AddressSanitizer found it; a plain run reports the
right answer, because the freed bytes still hold the size they had. Two of the
three similar cases in this layer are safe today and neither is safe *by
construction*: `set_protection` rewrites a field without reallocating, and
`erase` does not shrink capacity. That is now written down on
`AddressSpace::find` rather than left as two coincidences, because the failure
when it stops holding is a use-after-free that usually passes.

**Two memory constants that were the same number.** `MEM_REPLACE_PLACEHOLDER`
was `0x00080000`, which is `MEM_RESET` — the value written from memory, and the
kind of value that is written from memory. Two names for one bit meant the
`allocation_type_is_known_ex` mask had silently lost a bit it was meant to be
enforcing, and the plain `NtAllocateVirtualMemory` accepted
`MEM_RESERVE | MEM_REPLACE_PLACEHOLDER`, a request Windows refuses. The true
values are `MEM_RESERVE_PLACEHOLDER 0x00040000` and
`MEM_REPLACE_PLACEHOLDER 0x00004000` — not adjacent, with nine bits of gap
between them, which is exactly why the guess landed on a neighbour. The test
that caught it is a numeric assertion on the constants themselves, not a
behavioural one, because a behavioural test can only catch the collision once
some other bit happens to make the two distinguishable.

**A ceiling checked once, where it needed checking every step.** `map_below`
computed its candidate against the caller's ceiling and then looped *down*,
which means the first candidate respected the ceiling by construction and every
later one did too — for a loop that descends. The check was in the wrong place
to be evidence of anything: `in_the_user_window` bounds the *process's* window,
which is thousands of times larger than the `zero_bits` one, so nothing in the
loop would have stopped a search that walked the other way from handing back an
address above the window it was asked for. The comparison now runs every
iteration, written as a difference (`ceiling - size`) for the reason
`in_the_user_window` writes its own: `candidate + size` wraps near the top, and
a wrapped sum compares as small enough to pass.

**A flush that could not be observed, three times over.**
`NtFlushProcessWriteBuffers` called `::msync` directly, and `msync` on an
anonymous mapping succeeds whether or not it flushed anything — so a test could
only check the *return value*, which a stub can fabricate. The first version
recorded an event after the call, which the mutant matched by skipping the call
and taking the same path; the second recorded the return value, which the
mutant matched by reporting `0`. The version that works calls through
`Mapper::sync` and asserts the syscall counter advanced: the counter records
the *act*, and a fabricated return value cannot move it. This is now the
general rule for the runtime — **an event that describes a decision instead of
an action cannot tell a real flush from a stub, and an observability hook that
cannot is worse than no hook at all, because it reports work that was never
done.**

**A check that silently duplicated another one, which hid it.**
`HandleTable::find` verifies a handle in two steps: the cookie, then the low
half. The low half check was written as `make_handle(index) != handle` — a
round trip through the *whole* handle — and `make_handle` mixes **this table's**
cookie into its high half. So the round trip re-ran the cookie comparison, and
the two checks were indistinguishable: deleting the cookie check changed nothing
observable, because the round trip refused every foreign handle anyway. The
mutant survived several rounds of a harness that was otherwise catching
everything else. The fix is the low half on its own —
`(make_handle(index) & 0xFFFFFFFF) == parts.index` — after which each check
answers for one half and neither can stand in for the other. Redundant
validation is normally cheap; redundant validation that makes a check
*unobservable* is not, because a suite that cannot detect a check being removed
is not evidence the check was ever there.

**300 checks, 46 mutations, none surviving.** Five of the 46 are rejected by
the compiler and counted separately rather than as coverage. The harness runs
every mutant under two builds and requires both to fail, and the second build
is not redundancy: three of the findings above are memory faults that a plain
run gets away with. It runs the mapper and placement suites alongside ntdll's
for each mutant, for the reason the `SURVIVED` below records: a mutant that
lives in `mapper.cpp` is not observable from a binary that only reaches the
calls, and a survivor from the wrong binary reads exactly like a survivor from
a blind suite.

**And the harness counts its own failures, which is the part worth copying.**
An earlier version reported a mutant as un-caught when its anchor did not match
the source — the mutant was never applied, so nothing had been measured at all,
and the summary printed it in the same column as a genuine survivor. One such
anchor had been pointing at `kMaxAttempts = 16384` while the source said `64`,
so the run spent several rounds reporting a live survivor that was in fact a
symptom of the production code carrying the very bug the mutant was written to
detect: the placement search gave up after 4 MiB, and the mutant that would
have caught it never ran. Anchor failures are now a separate list with a
separate exit code, because a broken anchor is not a weaker result — it is not
a result, and it invalidates the numbers printed beside it.

**An anchor is not just text that matched once; it is text that matches
*once*.** The harness's apply step counts the occurrences and refuses at two,
and that guard earned itself the moment the range work landed. `map_above` was
added beside `map_below` and both carry a `kMaxAttempts = 16384` with an
identical three-line loop header under it; `commit()` was written as a range
and its empty-range guard came out byte-identical to `decommit`'s. Two mutants
whose anchors had been unique for as long as they existed stopped being unique
in one commit, without either mutant being touched. The report caught both as
`ANCHOR-FAIL count=2`, and the fix is the one the guard forces: widen the
anchor until it names the branch and not the shape — the loop header's own
`if (candidate < floor_ || ...)` for `map_below`, the trailing
`// A decommit of a range that is already reserved` for the decommit. A
narrower anchor would have silently mutated the first match, which for
`kMaxAttempts` is `map_below` and not the function the mutant is named after —
a mutant that measures the wrong function and reports `caught` is worse than a
survivor, because nothing about the output says to look.

**The suite a mutant is run against is part of the mutant.** The `SURVIVED` on
`a-protect-recommits-a-reservation` was not a gap in the assertions; it was a
gap in the reach. The mutant flips `updated.committed = at->committed;` — the
line that keeps a protection change from *committing* a reserved range — and
the only tests that call `Mapper::protect` are in `occ_test_mapper`, while the
harness ran `occ_test_ntdll`. The binary that owns the semantics had never been
asked. The assertion it needed did not exist either, and both halves were
fixed: the harness now runs the mapper and placement suites alongside ntdll's
for every mutant, and `test_a_protect_does_not_commit_a_reserved_range` pins
the field in both directions. A survivor has to mean the suite is blind, not
that the wrong suite was reading.

### M3 — mini-CRT and imports

The import tables of a real MSVC-compiled image point at `ucrtbase.dll` and
`msvcrt.dll`. Without an implementation of the subset those images
actually call, the smallest program a compiler produces will not start.

The subset is chosen by reading what the images need, not by reading the
CRT's documentation: `_initterm`, `__security_init_cookie`, the `_except_`
family, `malloc`/`free` over the runtime's own heap, `memcpy` and friends,
the integer and floating-point formatting the `printf` family reaches.

The CRT's allocator is the runtime's allocator. That is deliberate: a
program that allocates through the CRT and a program that allocates through
`NtAllocateVirtualMemory` produce the same kind of event, because they are
the same allocator.

Success condition: a program compiled with a normal toolchain prints a line
and exits zero, and the event stream shows which imports were resolved to
which addresses.

### M4 — threads and synchronization

`clone` with the thread flags, a TEB per thread, `futex`-based
implementations of the waitable objects, and `NtCreateThreadEx`.

The synchronization objects are the place where the "no server" decision
pays the most. A mutex's owner and its wait queue are fields in the object
table, so a deadlock is not something to be inferred from thread stacks —
it is a cycle in a graph the runtime is holding.

### M5 — Wine removed

The PE engine stops looking for a loader. `plan` produces argv whose first
element is the runtime, the container binds the runtime's own files instead
of a Wine installation, and the probe table points at the runtime's ntdll
rather than Wine's.

The loader half of this is in the tree. `plan` names `/proc/self/exe` with a
runner token after it, `PeProcess` builds the process out of this runtime's
pieces, and a guest's imports resolve to handlers in this tree; there is no
host requirement left for a PE, and `occ check` no longer reports one.

The probe half is not done. The table in `src/observer/ntdll_probes.cpp`
still names symbols in Wine's Unix-side `ntdll`, no engine asks for a probe,
and the pair of function-level events therefore belongs to no run. Pointing
that table at this runtime's own `nt_*` functions is what remains of this
milestone.

The move of the Wine-comparing tests into `tests/local/` is also only partly
done. The directory is ignored and absent, and one test still reaches for
Wine from inside `tests/`: `test_ntdll_probes` verifies its symbols against a
real Wine `ntdll` when the host has one, and skips that check when it does
not. That check is the reason no other test depends on Wine, and it belongs
where the milestone says once the table has been re-pointed.

### M6 — replay

Every non-deterministic input becomes an event: the return value of a
syscall that can vary, the clock, the random source, the order of an
unordered iteration that affects observable output.

With those recorded, a run can be repeated with the recorded values
substituted for the real ones, and the two event streams compared. A
difference is either a bug in the runtime or a source of non-determinism
that was not recorded, and both are worth knowing.

### M7 — coverage, grown by programs rather than by wish

A table of every entry point in the images this runtime claims to
implement, each with one of four states:

- `implemented`, with the count of semantics cards it passes
- `stubbed`, with the value it returns and why that value
- `absent`, meaning a call to it is reported and fails
- `refused`, with the reason

`occ doctor` prints the table's summary and `occ check` prints the coverage
for a specific image by walking its imports. A reader can then know, before
running anything, which of the functions their program imports will work.

That is the number this whole document is aimed at. It is not a claim that
the runtime is better than Wine. It is a claim that the runtime can tell
you what it does, and Wine cannot.

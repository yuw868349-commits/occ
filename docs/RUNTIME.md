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

Cards are executable. `occ doctor` runs the card suite against the runtime
and reports which cards pass. This is the measurable completeness that a
patch list cannot provide: a card either passes or it does not, and the
count of passing cards is a number that can be compared between builds.

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

Events: `image_mapped` (base, size, protection, per section),
`relocation_applied` (address, type, delta), `tls_initialized`.

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

`unmap` and `protect` address a whole region and refuse an address in the
middle of one. This is stricter than `NtUnmapViewOfSection` and
`NtProtectVirtualMemory`, which both take a range and split, and it is
strict on purpose: a split makes "the region covering this address" a
different answer before and after a call a reader would call the same call.
It is also the limit that lets `Region::protection_changes` mean what its
comment says — a per-region count is only a per-region count.

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

87 checks. Three mutations were tried against it and each is caught by the
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
directory's four address fields are 32-bit virtual addresses, and they are
**not in the base relocation table**: a file's copy and its mapped copy are
byte-identical no matter where the image lands, because nothing rewrites
them. A loader that read the file would produce the same answers as one that
read the mapping on every image that has ever existed, which is why the case
written for this had to be built out of a property no real image has.

`.tls` here declares four bytes of raw data and a full page of virtual size,
and the directory's RVA points 0x40 past the section's start — into the zero
fill. The file has no offset for that RVA at all, so a file reader *must*
refuse, and refusing is a different outcome from the one the test asserts. The
mapped reader finds six zero DWORDs, concludes the module has no TLS, and the
load succeeds. Reading the file cannot produce that outcome, and neither can a
mirror of the loader's own arithmetic, because the property being tested is
which memory the bytes came from.

**A VA-encoded directory is stale the moment the image moves.** The fields
are 32-bit; the image is not. A DLL linked at `0x7fa2a6e30000` writes
addresses that are 32-bit numbers, and after an ASLR move every one of them
points at nothing. Wine reads the field, believes it, and hands each thread a
template full of pointers into whatever the process has mapped at the *linked*
base — which for an ASLR image is nothing, and the first thread to touch its
TLS faults somewhere with no relationship to TLS.

This runtime accepts two encodings and says which it used. A field that falls
inside the current image is a virtual address. A field that does not is read
as an RVA from the image base. Both are in real use and neither is
Wine-compatible, which is the point: Wine's reading is only correct for images
based below 4 GiB, and this loader is explicit about the case rather than
silently producing addresses into nothing. A VA-encoded image placed away from
its linked base is refused, and the refusal names the address the loader
*resolved* rather than the field it read — a reader needs the decision, not the
file.

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

**412 checks, 28 mutations, none surviving.** The 28 are the ones a
plausible mistake would make, and the report is written to be worth what they
were worth: four are rejected by the compiler and counted separately rather
than as coverage, and two more are documented in the harness as
reachable-but-untested rather than listed as caught or as dead. Two of the 28
are paired edits, because this code has a *doubled* guard on the PE32
callback field and each half alone is an equivalent change that no single-edit
harness can distinguish from a no-op. One is in the test file rather than the
runtime, and one is the rollback above — the two places where what is being
checked is the suite's own honesty rather than the loader's behaviour.

### M2 — ntdll, memory and handles

`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtFreeVirtualMemory`,
`NtReadVirtualMemory`, `NtWriteVirtualMemory`, `NtClose`, and the handle
table they insert into.

The address space keeps a map of every region it handed out, so a
protection change on a region it did not allocate is an error rather than
a silent success. Wine cannot make that distinction cheaply; here it is a
lookup in a map the runtime owns.

Events: `memory_allocated`, `memory_protected`, `handle_created`,
`handle_closed`, each carrying the syscall that was made and its result.

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

The tests that compare against Wine move to `tests/local/`, which is in
`.gitignore`. They are useful — a reference implementation is the only
oracle available for some questions — and they are not part of the tree.
A test that requires Wine to pass is a test that makes Wine a dependency,
and the point of this milestone is that Wine is not one.

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

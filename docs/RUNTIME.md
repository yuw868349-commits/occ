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
image's shape; it does not run it. Nothing is mapped from the file,
no relocation is written, and no IAT slot is filled -- the loader
computes every one of those values and stops before the first store. So
the milestone is not "M1 is done" but "M1's decisions are made and
checked, and the stores that follow them are not". The layer that will
perform the stores is below.

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

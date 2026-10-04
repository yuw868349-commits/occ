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

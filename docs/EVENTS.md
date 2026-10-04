# Events

The event schema, field by field.

The sample stream below is verbatim from a real `occ run /bin/true`. The field
lists are not: they were read off the emitters in `src/observer/` and
`src/runner/`, because a sample only shows the fields one particular run
happened to produce, and a consumer needs to know which fields are always there
and which are conditional. Where the two disagree, the emitters are right.

One emitter is not in the sample and is documented here anyway, because
knowing a kind exists but never arrives is a fact a consumer needs. See
`file_opened`, `section`, `import`, `probe_attached` and `probe_hit` below.

## Shape

One JSON object per line, no array wrapper, no commas between records. The
stream is line-delimited so that a reader can process it without buffering the
whole session, and so that a truncated stream is still readable up to the
truncation.

Every record carries three fields, present on every event without exception:

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | One of the seventeen names below, or `"unknown"` |
| `session` | integer | Session id. Distinguishes concurrent sessions on one socket |
| `t` | integer | `CLOCK_MONOTONIC` in nanoseconds |

`t` is monotonic rather than wall-clock on purpose. A trace whose timestamps
can go backwards cannot be sorted, and a target that changes the system clock
would otherwise reorder its own history. To correlate with wall-clock, record
both ends and offset.

Addresses, sizes and offsets are **hex strings** (`"0x7f3e46875540"`). They are
addresses, and addresses are read as hex; a decimal address in a trace is read
wrong. Counts, indices, pids, errno and exit codes are **integers**, because
they are quantities rather than locations.

Booleans are `true`/`false`, unquoted.

## The kinds

`session_start`, `session_end`, `process_spawn`, `process_exit`,
`image_loaded`, `mapping`, `section`, `import`, `file_opened`,
`syscall_blocked`, `breakpoint_hit`, `signal`, `memory_write`, `exec`,
`probe_attached`, `probe_hit`, `note`.

`section` and `import` are PE-only. A `section` is one section of a PE image,
reported with its own numbers rather than as a mapping: a section is a range of
the file and a range of the address space, and the loader is what turns one
into the other, so reporting it as a mapping would claim a correspondence the
file does not make. An `import` is one DLL the image imports, in the order the
import directory lists them.

`probe_attached` and `probe_hit` are the function-level observation pair. A
probe is a uprobe placed on an entry point inside a library the target loads --
for a PE run, an `Nt*` function of Wine's Unix-side `ntdll`. `probe_attached`
is a fact about the run's setup and is emitted once per probe;
`probe_hit` is a fact about the target and is emitted as often as the target
enters the function. Attaching is reported even when it fails, because a run
that placed nine of ten probes and did not say which one it missed has a
silent hole in its output.

`note` carries diagnostics from occ itself — a target that could not be
exec'd, a capability that could not be acquired. Its `text` field is a
sentence, not a code. Anything occ wants to say about its own behaviour goes
here rather than to stderr, so that it lands in the same stream and in order.

Its other fields depend on the `text`; there is no fixed set. A consumer should
read `text` and treat the rest as context for that particular sentence. The
field names that do appear, and where they come from:

| `text` | Additional fields |
|---|---|
| the container could not be started | `stage`, `errno`, `detail` |
| no first stop | `pid`, `errno`, `status` |
| a breakpoint could not be installed | `address` (the detail string, not a number) |
| write tracking is off | — |
| write tracking armed | `regions`, `watches`, `bytes_covered`, `bytes_total`, `unwatched_regions` |
| a region could not be watched | `base` (hex), `length` |
| a debugger attached | `port` |
| the debugger resumed the target | `pc` (hex), `sp` (hex), if the registers could be read |
| chased a new mapping | `base` (hex), `length`, `watches`, `bytes_covered` |
| syscall entry | `pid`, `nr`, `arg0`, `arg1`, `arg2` (hex) |
| syscall exit | `pid`, `ret` |

`syscall entry` and `syscall exit` are not the same kind as the rest. They are
emitted per syscall stop whenever the observer is tracing, which `occ run
--observe` always does, and they are the only kind that arrives in volume. A
consumer that reads a run with observation on gets a syscall-level log as well
as the session structure; the two are interleaved in one stream, ordered by
`t`. There is no flag that turns them off.

## A real run

`occ run /bin/true`, verbatim and unedited:

```json
{"kind":"session_start","session":0,"t":3211955085839025,"target":"/bin/true","argv_count":1}
{"kind":"image_loaded","session":0,"t":3211955085888751,"path":"/bin/true","size":26936,"ok":true,"type":3,"machine":62,"entry":"0x19f0","phnum":13,"phentsize":56,"lowest_vaddr":"0x0","highest_vaddr":"0x7000","interpreter":"/lib64/ld-linux-x86-64.so.2","executable_stack":false,"gnu_relro":true}
{"kind":"mapping","session":0,"t":3211955085892410,"index":0,"file_offset":"0x0","vaddr":"0x0","filesz":"0xfa8","memsz":"0xfa8","readable":true,"writable":false,"executable":false,"zero_fill":"0x0"}
{"kind":"mapping","session":0,"t":3211955085898520,"index":3,"file_offset":"0x5c90","vaddr":"0x5c90","filesz":"0x384","memsz":"0x398","readable":true,"writable":true,"executable":false,"zero_fill":"0x14"}
{"kind":"process_spawn","session":0,"t":3211955099073266,"pid":148906,"entry":6640}
{"kind":"process_exit","session":0,"t":3211955099582717,"pid":148906,"exit_code":0,"signaled":false,"term_signal":0}
{"kind":"session_end","session":0,"t":3211955099585347,"started":true,"exit_code":0,"signaled":false,"term_signal":0}
```

Without `--observe` that is the whole stream: seven records, and nothing about
the target's execution beyond its exit.

## A real observed run

`occ run --observe /bin/true`, abridged — the first four records, the first
syscall pair, and the last three, with the middle of the syscall log cut:

```json
{"kind":"session_start","session":0,"t":3212420579797798,"target":"/bin/true","argv_count":1}
{"kind":"image_loaded","session":0,"t":3212420579845383,"path":"/bin/true","size":26936,"ok":true,"type":3,"machine":62,"entry":"0x19f0","phnum":13,"phentsize":56,"lowest_vaddr":"0x0","highest_vaddr":"0x7000","interpreter":"/lib64/ld-linux-x86-64.so.2","executable_stack":false,"gnu_relro":true}
{"kind":"mapping","session":0,"t":3212420579848643,"index":0,"file_offset":"0x0","vaddr":"0x0","filesz":"0xfa8","memsz":"0xfa8","readable":true,"writable":false,"executable":false,"zero_fill":"0x0"}
{"kind":"mapping","session":0,"t":3212420579850413,"index":1,"file_offset":"0x1000","vaddr":"0x1000","filesz":"0x2eb1","memsz":"0x2eb1","readable":true,"writable":false,"executable":true,"zero_fill":"0x0"}
{"kind":"process_spawn","session":0,"t":3212420591480366,"pid":164138,"entry":6640}
{"kind":"note","session":0,"t":3212420591606944,"text":"syscall entry","nr":12,"arg0":"0x0","arg1":"0x7fa24ed30a18","arg2":"0x0","pid":164138}
{"kind":"note","session":0,"t":3212420591617343,"text":"syscall exit","ret":93833319542784,"pid":164138}
...
{"kind":"note","session":0,"t":3212425858596813,"text":"syscall entry","nr":231,"arg0":"0x0","arg1":"0xffffffffffffff88","arg2":"0xe7","pid":164312}
{"kind":"process_exit","session":0,"t":3212425858754088,"pid":164312,"exit_code":0,"signaled":false,"term_signal":0}
{"kind":"session_end","session":0,"t":3212425858759188,"started":true,"observed":true,"stops":58,"exit_code":0,"signaled":false,"term_signal":0}
```

66 records in total, and the composition is the thing to notice:

| Kind | Count |
|---|---|
| `note` — `syscall entry` | 29 |
| `note` — `syscall exit` | 28 |
| `mapping` | 4 |
| `session_start`, `image_loaded`, `process_spawn`, `process_exit`, `session_end` | 1 each |

**Observation is mostly syscalls.** Five kinds carry the session's structure
and the rest is a syscall log, so a consumer that wants the structure filters
the other eleven kinds out.

Two details are visible in the sample and are not obvious from the schema.
**Entry and exit do not pair up**: 29 entries against 28 exits, because the
last one is `exit_group` (nr 231) and never returns. A consumer that pairs
them up and waits for a partner will hang on exactly the syscall that ended the
program. And **`stops: 58` in `session_end` is not a record count** — it
increments once per `waitpid`, so it counts waits, including any that reported
a `PTRACE_EVENT_STOP` and produced no record at all. 58 waits produced these
66 records; the two numbers are not comparable and neither is a subset of the
other.

The 29 syscalls a trivial static binary makes, by number: `read`, `close` ×2,
`fstat` ×2, `mmap` ×8, `mprotect` ×3, `munmap`, `brk`, `pread64` ×2, `access`,
`arch_prctl`, `set_tid_address`, `exit_group`, `openat` ×2, `set_robust_list`,
`prlimit64`, `rseq`.

`--observe` produced no `signal`, no `breakpoint_hit`, no `memory_write` and
no `syscall_blocked` here. Those need a target that faults, a debugger
attached, `--track-wx`, and a seccomp denial respectively; `/bin/true` does
none of them. Their absence from a real stream is expected and is not evidence
that they are unreachable — but neither is it evidence that they work. See
`docs/ROADMAP.md`.

## A real file_opened

`occ run --observe /bin/cat /etc/hostname`, filtered to the three file
events, verbatim:

```json
{"kind":"file_opened","session":0,"t":3214523203917680,"pid":238626,"path":"/etc/ld.so.cache","ret":3,"flags":524288,"flags_known":true}
{"kind":"file_opened","session":0,"t":3214523203964065,"pid":238626,"path":"/lib/x86_64-linux-gnu/libc.so.6","ret":3,"flags":524288,"flags_known":true}
{"kind":"file_opened","session":0,"t":3214523204350228,"pid":238626,"path":"/etc/hostname","ret":3,"flags":0,"flags_known":true}
```

Three files, and the first two are the dynamic loader doing its own work
before `main` exists. `ret` is the file descriptor the kernel returned, so
`3` for the first two and `3` again for the target's own open — the earlier
ones were closed after mapping. `flags` is `0x80000`, which is `O_CLOEXEC`,
on exactly the two the loader opens and absent on the one `cat` opens itself:
a program that does not want its library descriptors leaking into an exec
sets it, and a program that intends to pass them on does not.

A run that fails to open the file reports the attempt anyway, with the
kernel's error as `ret`:

```json
{"kind":"file_opened","session":0,"t":3214490070298931,"pid":237085,"path":"/nonexistent-xyz","ret":-2,"flags":0,"flags_known":true}
```

## Fields by kind

`session_start` — `target`, `argv_count`

`session_end` — `started`, and then `exit_code`, `signaled`, `term_signal`.
`started: false` means the target never ran; the stream still ends, so a reader
does not have to treat a short stream as a broken one. An observed run adds
`observed` and `stops`. **The field set is not the same on every path**: a
container that could not start emits only `started`, with no exit fields at
all, because there was no process to have an exit.

`process_spawn` — `pid`, and then either `entry` or `parent`. The first
process of a session is spawned by occ itself and carries the target's entry
point as a decimal number, not a hex string, because it is an offset into the
image and is compared against `image_loaded`'s `entry` as a number. A process
that appears because the target forked or cloned carries `parent` instead, and
has no entry point: it is running whatever the image already contained.

`process_exit` — `pid`, `exit_code`, `signaled`, `term_signal`. When
`signaled` is true, `exit_code` is meaningless and `term_signal` is the signal
that killed it.

`image_loaded` — `path`, `size`, `ok`, then either the ELF header fields
(`type`, `machine`, `entry` (hex here, unlike `process_spawn`), `phnum`,
`phentsize`, `lowest_vaddr`, `highest_vaddr`, `interpreter`,
`executable_stack`, `gnu_relro`) or, when `ok` is false, `error` and `detail`.
The two branches are exclusive. `ok: false` means the file was not a readable
ELF, and the header fields are absent rather than zero — absent and zero mean
different things.

`mapping` — `index`, `file_offset`, `vaddr`, `filesz`, `memsz`, `readable`,
`writable`, `executable`, `zero_fill`. `memsz` exceeding `filesz` is the BSS,
and `zero_fill` is how much of it is zero rather than file-backed. `index` is
the program header order, which is the order a loader sees. One event per
`PT_LOAD`, so `index` is sparse: a typical small binary reports 0, 3, 6.

`section` — `index`, `name`, `virtual_address`, `virtual_size`, `raw_offset`,
`raw_size`, `readable`, `writable`, `executable`, `characteristics`,
`zero_fill`, `tail_not_mapped`. PE only. A section is not a mapping: it is a
range of the file and a range of the address space, and the loader is what
turns one into the other, so the two sizes are reported as the file wrote them
rather than as a mapping. `virtual_size` exceeding `raw_size` gives `zero_fill`;
the reverse gives `tail_not_mapped`, whose virtual range is not backed by the
file at all. Both are stated as values because a consumer that subtracts one
from the other gets the right answer in the first case and a meaningless number
in the second.

`import` — `dll`. PE only, one event per imported DLL in the order the import
directory lists them. The list is variable-length, so it is one event per name
rather than a field: a field whose length depends on the target is a field a
consumer has to guess the end of.

`file_opened` — `pid`, `path`, `ret`, `flags`, `flags_known`. Emitted when a
path syscall returns, not when it is called, because only the return says
whether the file was opened at all: a path that was tried and failed is
reported with a negative `ret`, and a consumer counting the files a program
touched would otherwise be wrong by one per failed attempt.

`path` is read on the way in, while the register that holds it still points
where the target meant it to. On the way out that register has been reused
for the return value and the string may have been freed — an unlink followed
by an open of the same name is the common case — so a path read at the exit
would name whatever now occupies that memory. A trace reporting the wrong
file is worse than one reporting none, so an entry whose path could not be
read produces no event at all rather than an event with a guessed name.

`flags` is the flags word as the caller passed it; `0x80000` is `O_CLOEXEC`,
which is what a dynamically linked target sets on every library it loads.
`flags_known` is false only for `openat2`, whose flags live in a `how`
structure this does not read: the field is reported as zero and marked
unknown rather than filled with the structure's first word, which happens to
be `how.flags` on this kernel and is not something a uapi header guarantees.
`open`, `openat` and `openat2` are all recognised; `open` is unreachable from
a dynamically linked target, where `open()` is a wrapper around `openat`.

A path longer than 512 bytes is truncated, because the alternative is a
record whose size is set by the target.

`syscall_blocked` — `pid`, `nr`. Emitted when the seccomp filter denies a
call, and the process is resumed with the denial standing: occ does not
substitute a result. `nr` is a hex string. There is no `name` and no `errno`;
a consumer that wants a name maps `nr` itself, against the kernel's table for
the architecture, because a name occ guessed from a number it may not
recognise is a name that can be wrong.

`breakpoint_hit` — `pid`, `address` (hex). **There is no register block on the
event.** The address is `rip - 1`, because the breakpoint byte is still in
place when the trap is reported and the trap lands after the instruction that
fetched it. When a debugger is attached it has already read the registers over
the RSP connection and has them; the event exists to say that a trap was
classified as a breakpoint rather than a stray signal, which is a fact the
consumer cannot get any other way.

`signal` — `pid`, `signal`. There is no `core_dumped` and no `term_signal`
here: a `signal` event is a signal *delivered to* the target, not the signal
that killed it. The killing signal is on `process_exit`, as `term_signal` with
`signaled` true. A target that installs a SIGSEGV handler and recovers
produces a `signal` event and then exits normally, which is the case that
distinguishes the two.

`memory_write` — **two different field sets, from two different emitters.**
This is the one place in the schema where the kind alone does not tell a
consumer what is in the record.

| Emitter | Fields | Meaning |
|---|---|---|
| a hardware watch firing | `pid`, `address` (hex), `rip` (hex), `bytes`, `kind` | One store instruction, at the moment it happened |
| the W^X tracker | `pid`, `address` (hex), `bytes_written`, `write_count`, `was_writable`, `was_executable`, `became_executable` | A region that was written while not executable and is executable now |

`kind` is `"watch"` on the first and absent on the second, so the field's
presence distinguishes them. The first is a raw event and carries `rip`,
because knowing *which instruction* wrote is what makes the address mean
something. The second is a conclusion, and `became_executable` is always true
on it: a region that was already executable when written is not a transition
and is not reported as one. `bytes` on the first is decoded from the
instruction at `rip`, not from the watch record, because the kernel reports
which address matched and not how much was touched.

`exec` — `pid`. The target's own `execve`, reported because after it every
cached address, breakpoint and watch is stale and has been dropped. There is
no `path` and no `ret`: occ reports that an exec happened, and the new image
if it is an ELF is reported separately by `image_loaded`. An exec that failed
does not produce this event; it appears as a `syscall exit` whose `ret` is
negative.

`probe_attached` — `label`, `symbol`, `module`, `outcome`, `ok`, then `offset`
and `kind` when `ok`, and `detail` when not, and `note` when the request
carried one. Emitted once per probe the engine asked for, including the ones
that could not be placed.

`outcome` is one of six names, and each is a different thing to do about it:

| `outcome` | What happened |
|---|---|
| `attached` | The probe is registered and subscribed |
| `module_missing` | The library the symbol lives in is not on the loader's path |
| `module_unreadable` | The library was found and is not an ELF this build reads |
| `symbol_missing` | The symbol is not in the module, or is there and is not a defined function at a non-zero address |
| `no_file_offset` | The symbol's address is in a part of a segment the file does not back |
| `kernel_refused` | The address resolved and the kernel refused the registration or the subscription; `detail` says which |

`symbol_missing` covers two cases deliberately, and `detail` distinguishes
them: a name that is absent and a name that is present but is an import or a
data object call for different actions, and only the sentence can say which.
`offset` is a hex string and is the **file offset**, not the symbol's virtual
address -- the two differ whenever the segment's file offset differs from its
virtual address, which is the normal case for a multi-segment library.

`ok: false` is not a failed run. A host without tracefs places no probes at
all and the run continues at syscall-level observation; the events are how a
consumer learns that its own trace is coarser than it wanted, rather than
concluding from empty output that the target never made those calls.

`probe_hit` — `pid`, `tid`, `label`, `ip`. Emitted when the target enters a
probed function. `label` is the name the request gave the probe, which is what
ties a hit back to the `probe_attached` record that placed it; `ip` is the
address inside the function, which is the probed address because an entry
probe fires at its first byte.

Hits are attributed by which probe's ring buffer produced them, not by
anything in the record: each probe has its own buffer, so a hit cannot be
misattributed to another probe even if two probes share a module.

What is **not** on this event yet: the argument registers. A uprobe can read
up to six argument registers at the entry point, and the argument names are in
the probe table, but nothing reads them yet -- so this event carries no
`args` and a consumer that needs the arguments does not have them. A field
that is absent is a field a consumer can detect; one filled with zeroes would
look like a call with six zero arguments.

**The emitter for this kind is not wired up.** The kind is defined and the
decoder exists, but the observation loop does not yet emit it -- so a consumer
sees `probe_attached` records and no hits. That is the honest state of it, and
it is written here rather than left for a consumer to discover.

## What is not in the stream

**The target's output.** stdout and stderr belong to the target. Interleaving
them into the event stream would corrupt both: a prompt with no newline would
merge with the next record. Use a separate file descriptor, or run the target
under a pty.

**The register block, on any event.** No event in the schema carries GDB's
forty registers, and `breakpoint_hit` does not either. Dumping all of them on
every stop makes a stream that is expensive to read and expensive to store, and
the registers that did not change are the ones nobody looks at. When a
debugger is attached, the RSP server serves the full block on request, and that
is where the full block belongs. A consumer that wants registers without a
debugger attached gets none from this stream; that is the trade, and it is a
deliberate one.

**Anything from a run that failed before the session opened.** If occ cannot
isolate, it reports on stderr and emits no events. A stream that existed would
imply an observation happened.

**Function-level detail on a host that cannot place probes.** A uprobe needs a
mounted tracefs and a `perf_event_open` the security policy allows, and a
container frequently has neither. When that is the case the stream carries
`probe_attached` records with `ok: false` and a reason, and no `probe_hit`
records at all. The target's work inside a library function is then invisible,
and the syscall stream it produces is a mixture of the target's requests and
the loader's. The `probe_attached` records are how that is detectable rather
than inferable: a consumer that needs function-level observation should check
that at least one probe attached before trusting an absence.

**Argument values on a hit.** As noted under `probe_hit`, nothing reads the
argument registers yet. This tool would rather say so than report six zeroes
that read as arguments.

## Reading the stream

```
occ run ./target > events.ndjson
```

stdout carries the stream when it is not a terminal, and a session summary when
it is. When it is a TTY, the stream is on the socket and the summary is for a
human; the two are never mixed, so a reader never has to strip anything.

The stream is never multiplexed onto the target's output, and a dropped event
is reported rather than skipped — see the `note` kind, and
`docs/ROADMAP.md` for why that matters more than it sounds.

To follow a session live, read the socket. The path is printed as a single
NDJSON line when stdout is not a terminal:

```
socat - UNIX-CONNECT:/run/occ/<session>.sock
```

`jq` handles the format as-is:

```
occ run --observe ./target | jq -r 'select(.kind=="mapping" and .executable) | .vaddr'
```

## Adding a kind

`EventKind` in `include/occ/observer/event.h`, the name in
`event_kind_name`, the fields in whichever observer emits it, and a test in
`tests/test_event.cpp`. The enum and the name function are the two places
that have to agree; a kind added to one and not the other arrives as
`"unknown"`, which is the intended behaviour for a name occ does not know and
the reason that case is reachable at all.

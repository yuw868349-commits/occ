# Design notes

This document records decisions that are not obvious from the code, and
the reasons behind them. If you are reading the source and something looks
strange, the answer is probably here.

## Why everything is hand-written

Occ links against libc++ and the kernel. Nothing else.

That rule has a cost and it is paid deliberately. The components that
matter — the isolation setup, the seccomp emitter, the parsers, the RSP
server — are where the project's correctness lives, and they are small
enough to own outright. A security boundary that delegates to a dependency
is a boundary whose behavior you cannot fully describe.

The rule does not extend to reinventing tools that are not part of the
boundary. Occ does not contain a disassembler or an emulator. Those belong
to the tools that attach to it.

## No version numbers

There is no version string anywhere. Not in the build, not in the CLI, not
in this document.

Version numbers create an implication that this tree has releases with
defined compatibility ranges. It does not. What matters is which host it
was verified on, and that is recorded as fact in `docs/COMPAT.md` rather than
encoded as a number that has to be interpreted.

## Timestamps in output, not in source

Source, comments, and documentation carry no dates. Observation data
carries timing fields, because timing is the observation. A syscall event
without a timestamp is not an event, it is a rumor.

The rule is about authorship metadata, not about data.

## The isolation layer

### Namespaces

`clone3` with all seven namespaces in one call. Doing this in one call
rather than a chain of `unshare` calls removes a window where the process
is partially isolated and a signal could be delivered into an inconsistent
state.

The user namespace maps to the invoking user. Root outside, root inside,
but a different root — the containment is the point, not the privilege
change. Occ itself already runs with the capabilities it needs; the user
namespace is for the target.

`/proc/<pid>/setgroups` is written `deny` before `gid_map`. Skipping this
fails the `gid_map` write on any kernel where an unprivileged mapping is
attempted, and the failure mode is a confusing `EPERM` far from the cause.

### Root filesystem

`pivot_root`, not `chroot`. `chroot` is escapable by a process with
`CAP_SYS_CHROOT` and leaves the old root reachable through open directory
descriptors. `pivot_root` does not.

The sequence is: bind-mount the new root onto itself (because `pivot_root`
requires the new root to be a mount point), set `MS_PRIVATE` on the whole
tree (so nothing propagates back to the host), `chdir` into the new root,
`pivot_root`, then `umount2(MNT_DETACH)` the old root.

`MS_PRIVATE` is applied to the root of the propagation tree at mount time,
before any submounts exist. Applying it later leaves windows where a
propagation event can escape.

### Overlayfs

Lower layer is read-only and shared between runs. Upper and work layers are
per-session and destroyed with the session. A run never writes to the base.

The upper layer is on the same filesystem as the work layer. Overlayfs
requires this and the error when it is violated does not say so clearly.

### cgroup v2

Written directly. No systemd delegation dance, because Occ already requires
root or the equivalent capability set.

Files written, in order: `cgroup.max.descendants` and
`cgroup.max.depth` on the parent to bound runaway creation, then the leaf
`cgroup.procs` for placement, then the limit files. Writing limits before
placing the process means the process may run briefly unbounded.

### seccomp

Generated as raw `struct sock_filter` arrays. The emitter is in
`src/isolation/seccomp.cpp` and produces a jump table of the classic form:
load architecture, load syscall number, binary search over the allowed
set, return `SECCOMP_RET_ERRNO` with `EPERM` for anything unmatched.

The filter is installed after the mount setup and immediately before
`execve`. Installing it earlier would filter Occ's own setup syscalls.
Installing it later would leave a window where the target runs unfiltered.

`SECCOMP_RET_KILL_PROCESS` is not the default. A sandboxed target that
makes a disallowed syscall should learn that it failed, not die silently,
because silent death is indistinguishable from a crash and wastes the
analyst's time. The default is `EPERM`; kill-on-violation is opt-in.

### Network

Default-deny, always. `CLONE_NEWNET` is among the namespaces the container
is created with, so "deny" is the absence of a path rather than a rule that
could be misconfigured.

There is no opt-in path. Setting up a veth pair and writing nftables rules
through netlink is not implemented, so a run gets an empty network namespace
and stays there. A target that needs to reach a package manager does not get
a route. This is stated rather than deferred because the capability and the
absence of it look the same from outside: the run is silent either way.

## The observer layer

The consequence is that the filter is described by a typed policy rather than
by bytes, which is the boundary that matters: the emitter's input is a
`SeccompPolicy` the caller assembles, so a caller cannot hand it an
arbitrary program. That is also why the emitter is not fuzzed from bytes --
`fuzz/README.md` explains what the seccomp harness does instead.

### Ring buffer and backpressure

The perf ring used for watchpoints and uprobes has a fixed capacity. When it
fills, the kernel drops records and reports `PERF_RECORD_LOST`. Occ reads
that count and reports it: a lost watchpoint sample or uprobe hit appears in
the session summary as a degradation rather than as an absence.

Losing records silently would make every downstream conclusion suspect.
Reporting the loss makes it a fact the analyst can weigh.

Syscall records do not go through a ring at all. They are read from the
register block at a `PTRACE_SYSCALL` stop, so there is no buffer to overrun
and no loss to report; the cost is a stop per syscall, which is the trade
this design makes for not needing an eBPF program attached to the host.

### Hardware breakpoints

`perf_event_open(PERF_TYPE_BREAKPOINT)`. Four slots per core is a hardware
limit, not an Occ limit.

When a debugger asks for a fifth breakpoint, Occ does not silently
substitute a software breakpoint. It replies with an error and lets the
debugger decide. A software breakpoint writes `0xCC` into the target,
which changes what the target observes, which changes what it does. That
is a decision for the person driving the debugger, not for the tool.

There is no software-breakpoint mode to opt into. `Watchpoints` is hardware
only, and `int3.cpp` does not exist: an implementation that wrote `0xCC`
into target text would contradict the "target unmodified" claim that
`docs/SECURITY.md` makes, and there is no flag that turns a claim off.

### ptrace

Used for stop, continue, single-step, signal delivery, and register
get/set. Not used for breakpoints and not used to write code bytes.

This is what makes the "target unmodified" claim meaningful. It is a claim
about code, not about the absence of a debugger.

### Write-then-execute tracking

`mprotect` and `mmap` calls that change a page from writable to executable
are emitted as events with a snapshot of the page attached. The page is
read with `process_vm_readv` at the moment of the transition.

Occ does not classify the page. It does not say "this is packed" or "this
is shellcode". It reports that a page became executable and here are its
bytes. Naming things is analysis and analysis is the other tool's job.

## The PE engine

### Why the runtime is in this tree

Running a PE natively means implementing the Win32 and NT API surface the
binary uses. That surface is the work, and it is why this engine was once a
launcher: an earlier revision looked for a Wine loader on the host, built a
prefix, and handed the file over, on the grounds that Wine already
implements a large fraction of that surface and is maintained by people who
care about it.

What that arrangement could not do is answer for its own behaviour. A guest
that faulted inside Wine produced a process that exited, and the engine had
no way to tell a run that worked from one Wine rescued. The runtime in
`src/runtime/` replaced it. The loader, the address space, the mapper, the
export registry and the `nt_*` family are this tree's, the guest's imports
resolve to handlers in this tree, and what a run does is a fact this project
states rather than inherits.

### Why the seam is the import table

A guest calls `WriteFile` because its import table has an entry for it. That
entry holds a string, and the string has to resolve to an address in the
guest's process. The runtime owns everything up to that question and
nothing past it: resolving an import asks "where is kernel32!WriteFile" and
the export registry answers. That split is why the surface can grow one
handler at a time without reopening the loader, and why a missing API is a
named refusal at load rather than a fault at the call site.

### Probes, and where they are not pointed

The observer can place a uprobe on a symbol in a library a target loads, and
the event schema has the pair of events for it. Nothing in the PE path asks
for one today. The table of probes this format once requested named symbols
in Wine's Unix-side `ntdll`, and the loader it hooked is no longer in the
path; pointing that table at this runtime's own `nt_*` functions is open
work, and until it is done the function-level events belong to no run.

The uprobe mechanics outlive any particular target and are worth stating
precisely. A uprobe is the kernel inserting a trap into the target's text.
Occ does not write those bytes; the kernel does, on Occ's request. The
"target unmodified" claim is about what Occ writes, and a uprobe is not Occ
writing. `docs/SECURITY.md` states this without hedging, because a reader who
assumes otherwise will draw the wrong conclusion about what Occ guarantees.

### Fidelity

This runtime is not Windows. Stated here so it is not a surprise later:

- TLS callback ordering follows this loader's reading of the format.
- SEH unwinding is implemented from the structures, and the details are this
  tree's rather than Microsoft's.
- `NtQuerySystemInformation` classes are answered where a handler exists and
  refuse by name otherwise.
- Anti-debug checks that read the PEB, that hide threads from debuggers, or
  that time instructions will produce answers that differ from Windows.
- Structures that are undocumented on Windows may be approximations here.

Some targets will not run far enough to be worth analyzing. That is a
property of how much of the surface is implemented rather than of the
target, and the honest thing is to say so rather than to imply that every PE
works.

## The event schema

One struct-to-JSON mapping, defined in `docs/EVENTS.md`. Every observer
source produces one of a fixed set of event types. There is no free-form
field bag.

A schema that admits arbitrary keys cannot be parsed without guessing. The
fixed set is smaller and is worth the constraint.

## The runner

### Why GDB RSP

It is the one debugging protocol that gdb, gdb-multiarch, pwndbg, GEF, and
IDA's remote debugger already speak. Implementing it means the front end
is whatever the analyst already has open, not a new TUI to learn.

### Where reads and writes come from

Reads are served from observer data, which is collected without stopping
the target.

Writes are different. Changing a register or a memory location breaks the
"unmodified" property, and that is fine — it is what the analyst asked
for. Writes go through `process_vm_writev` and `PTRACE_SETREGSET`, and
they are applied at a stop point so the target is not running while its
state is being rewritten.

### Session state

A session is a directory under `/run/occ/<id>`, mode 0700. It holds a lock
file, the target's pid together with the start time from
`/proc/<pid>/stat`, the socket paths, and the overlay paths.

The pid alone is not enough to identify a process. Pids are reused. The
start time makes the pair unique.

`occ attach` and `occ run` both sweep `/run/occ` on startup. A session
whose pid and start time no longer describe a live process is treated as
crashed: its mounts are detached, its cgroup is removed, and its directory
is deleted. Leaving stale mounts around eventually fills the mount table
with entries that cannot be cleared without a reboot.

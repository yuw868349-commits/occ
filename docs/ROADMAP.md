# Roadmap

What is built, what is not, and what is known to be wrong. Written from the
tree rather than from intent, so that it can be checked.

The rule this file follows: a gap that is written down is a task, and a gap
that is not is a trap. Everything below was read off the source on the commit
that added this file.

## Where the code is

About 14,300 lines across 49 files. The distribution is uneven on purpose —
the observation layer is the product, and it is the deepest part.

| Area | Files | State |
|---|---|---|
| `src/observer/` | 8 | The deepest part. Event schema, ptrace control, RSP server, transport, watchpoints, W^X tracking |
| `src/util/` | 4 | Strings, spans, filesystem, logging |
| `src/isolation/` | 2 | Namespaces, overlay root, cgroup v2, seccomp BPF, capabilities |
| `src/syscall/` | 2 | Syscall numbers, errno, kernel ABI |
| `src/parser/` | 2 | ELF parsing, format detection |
| `src/runner/` | 1 | Spawns a target under the isolation and observation layers |
| `src/probe/` | 1 | `occ doctor` |
| `src/engine/` | 0 | Empty. See below |

The test suite is 441 assertions across six binaries. The counts are what the
binaries print, not what the sources appear to contain — the two differ,
because a check written across several lines is one assertion to a reader and
none to a grep:

| Test | Assertions |
|---|---|
| `test_observer` | 253 |
| `test_elf` | 80 |
| `test_event` | 36 |
| `test_detect` | 36 |
| `test_container` | 25 |
| `test_seccomp` | 11 |

## What works

**GDB Remote Serial Protocol.** `qSupported`, `g`, `G`, `m`, `M`, `c`, `s`,
`Z`, `z`, `vCont`, `qfThreadInfo`, `qsThreadInfo`, `qXfer`, implemented
in-tree. Verified against GDB 15.1 with no warnings: registers, the target
description, and disassembly of the target's first instructions all come back
correct.

**The event stream.** Thirteen event kinds on a Unix domain socket, one JSON
object per line. Dropped events are reported as their own kind rather than
lost, which is the property that makes a trace worth reading.

`file_opened` was one of the thirteen with a name and an enum value and no
producer — `src/observer/event.cpp` mapped it to a string and
`tests/test_event.cpp` built one to exercise the writer, and nothing in `src/`
created one. It is implemented now: the path is read at the syscall's entry,
where the register still points where the target meant it to, and reported at
its exit, where the result is known. `docs/EVENTS.md` has the fields.

**W^X tracking.** Hardware breakpoints via `perf_event_open`, so the target is
not modified to watch it. Four debug registers against whole-page candidate
regions is a real limit, and the stream reports how many bytes were actually
covered rather than implying the region was watched.

**Isolation.** User, PID, network, mount, UTS, IPC and cgroup namespaces; an
overlay root over `pivot_root`; a cgroup v2 subtree; a default-deny seccomp
filter from a bytecode emitter in the tree.

**Isolation without the target knowing.** Syscalls come from eBPF attached to
raw tracepoints, with field offsets read from tracefs at runtime — no libbpf,
no BTF, no CO-RE. Memory is read with `process_vm_readv` from outside. The
`ptrace` in the tree is for process control only, and `docs/SECURITY.md`
draws that line explicitly.

## What does not work

**No engine dispatch.** This is the largest gap and the README is wrong about
it. `src/parser/detect.cpp` recognises ELF, PE and APK, and `occ check` reports
them. But `occ run` never calls it: `runner::run` executes the target without
consulting the format at all. There is no PE engine, no APK engine and no SYS
engine — `src/engine/` and `include/occ/engine/` are empty directories that no
code refers to.

What that means in practice: `occ run` is a general-purpose executor. Against
an ELF target on Linux it has the full observation surface. Against a PE
target it will exec the file, which on a Linux host means the kernel's binfmt
handler rather than a loader under this project's control — so the uprobe
machinery the README describes for Wine is not in the tree either. An APK is a
zip, and running one as a process is not the same as running its native code.

**Three documents the README promised did not exist.** `docs/ROADMAP.md`,
`docs/RSP.md` and `docs/COMPAT.md` were all referenced from the README — two of
them in the document index — and none of them were in the tree. All three are
written now. A reference to a document that is not there is worse than no
reference: it tells a reader the question has been answered.

**Fuzz harnesses are not built.** `fuzz/` is an empty directory, and
`docs/BUILD.md` has a section describing how to build with
`-DOCC_ENABLE_FUZZ=ON`. That option is wired to `add_subdirectory(fuzz)`, so
turning it on fails configuration rather than producing harnesses. The build
option, the documentation and the tree disagree, and the tree is the one that
is right.

**Syscall tracing needs a tracepoint that exists.** The eBPF programs attach
to raw tracepoints whose field offsets are read at runtime. A kernel without
the expected tracepoint produces no syscall events rather than an error, and
the run continues. `occ doctor` reports what the host has.

**Hardware watchpoints are four.** W^X tracking over a region larger than the
debug registers can express is partial by construction.

## Known rough edges

**PE fidelity is bounded by the loader.** The README describes Wine as the PE
loader with hooks on its Unix side. That design is not implemented, so this is
a statement of intent rather than a description. When it is built, the
boundary is worth stating again: timing-sensitive, SEH-detail-sensitive and
undocumented-structure-sensitive checks will diverge from genuine Windows, and
some PE targets will never reach a state with analytical value. Saying so up
front is cheaper than a user discovering it.

**`seccomp` and `capabilities` are the thinnest tests.** 11 and no dedicated
file respectively, against a seccomp BPF emitter that is 338 lines of
arithmetic on a structure the kernel will reject without explanation. The
security boundary is the part with the least test coverage, which is the wrong
way round and is stated here rather than left to be discovered.

**Container error reporting lost its stage for a long time.** A setup failure
was reconstructed from a sentinel exit code with a zero errno, which the error
type reads as success — a container that never started reported as a clean run.
Fixed, and the reason is in the commit that fixed it. It is listed because the
class of bug is worth watching for, not because it is still there.

**`git push` from a network that cannot reach GitHub returns success.** A push
that timed out reported exit code 0 while nothing had been uploaded. Verify a
push by reading the remote back, not by its status.

## Deliberately not planned

- **A hypervisor.** Isolation here is namespace, cgroup and seccomp based —
  the same class as a container runtime. There is no hardware virtualization
  in this codebase and adding it would be a different project.
- **A general-purpose malware sandbox.** `docs/SECURITY.md` states the threat
  model and what weakens it. A target that is not trying to escape still gets
  host state it can read, and no amount of namespaging changes that.
- **Static analysis or disassembly.** Occ executes and reports. Analysis
  belongs to the tools a reader already uses; the value here is that they run
  against a target that is isolated and whose behaviour is already recorded.
- **Third-party dependencies.** Zero, and staying that way is what makes the
  static link, the reproducible build and the ability to read every line of
  the isolation layer possible.

## Verifying any of this

```
occ doctor                      # what this host actually grants
cmake -S . -B build && cmake --build build && ctest --test-dir build
```

The test suite is 441 assertions and needs no network and no target binary.
A claim in this file that can be checked should be checked that way before it
is believed.

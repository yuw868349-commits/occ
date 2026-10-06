# Roadmap

What is built, what is not, and what is known to be wrong. Written from the
tree rather than from intent, so that it can be checked.

The rule this file follows: a gap that is written down is a task, and a gap
that is not is a trap. Everything below was read off the source on the commit
that added this file.

## Where the code is

About 33,600 lines across 72 files under `src/` and `include/`. The
distribution is uneven on purpose — the observation layer is the product,
and it is the deepest part.

| Area | Files | State |
|---|---|---|
| `src/observer/` | 10 | The deepest part. Event schema, ptrace control, RSP server, transport, watchpoints, W^X tracking, uprobes, the Wine ntdll probe table |
| `src/runtime/` | 5 | The PE-facing runtime: address space, image loader, mapper, export resolution, the `ntdll` surface |
| `src/` (top level) | 6 | `main.cpp` and the five subcommand files |
| `src/engine/` | 4 | The dispatch table and one engine per format: ELF, PE, APK |
| `src/util/` | 4 | Strings, spans, filesystem, logging |
| `src/parser/` | 3 | ELF parsing including the dynamic symbols, PE parsing, format detection |
| `src/isolation/` | 2 | Namespaces, overlay root, cgroup v2, seccomp BPF, capabilities |
| `src/syscall/` | 2 | Syscall numbers, errno, kernel ABI |
| `src/probe/` | 2 | Turning a requested symbol into a placed uprobe |
| `src/runner/` | 1 | Spawns a target under the isolation and observation layers |

The test suite is 2,725 assertions across twenty binaries. The counts are
what the binaries print, not what the sources appear to contain — the two
differ, because a check written across several lines is one assertion to a
reader and none to a grep:

| Test | Assertions |
|---|---|
| `test_pe` | 466 |
| `test_runtime_loader` | 382 |
| `test_observer` | 345 |
| `test_ntdll` | 208 |
| `test_placement` | 193 |
| `test_elf` | 150 |
| `test_engine` | 134 |
| `test_runtime_exports` | 121 |
| `test_uprobe` | 128 |
| `test_ntdll_probes` | 99 |
| `test_mapper` | 92 |
| `test_seccomp` | 91 |
| `test_detect` | 65 |
| `test_placer` | 46 |
| `test_event` | 43 |
| `test_seeds` | 41 |
| `test_probe_wiring` | 36 |
| `test_container` | 32 |
| `test_gdb_interop` | 29 |
| `test_check` | 24 |

Three of those counts are lower here than a build without a Wine
installation would report. `test_engine` skips the probe-planning check, and
`test_ntdll_probes` skips the symbol check, when no Wine `ntdll` is present
on the host; both print the skip in a note rather than passing silently. The
figures above are from a host with no Wine.

`test_gdb_interop` is the one that does not run without a peer. It forks the
host's gdb and drives a real attach, register read and detach through a
listener this process serves, so the assertions are about what gdb does with
the answers rather than about what this project thinks it sent. When gdb is
absent it reports a skip and exits zero, and the count above is from a host
that has one.

## What works

**GDB Remote Serial Protocol.** `qSupported`, `g`, `G`, `m`, `M`, `c`, `s`,
`Z`, `z`, `vCont`, `qfThreadInfo`, `qsThreadInfo`, `qXfer`, implemented
in-tree. Verified against GDB 15.1 with no warnings: registers, the target
description, and disassembly of the target's first instructions all come back
correct.

The verification is a test rather than a claim. `tests/test_gdb_interop.cpp`
forks the host's gdb, serves it a connection, and asserts that it attaches,
reads a register and detaches with exit status zero — so the assertions are
about the peer's behaviour and not this project's own codec agreeing with
itself.

That test exists because of a defect it now covers. `vMustReplyEmpty` is a
protocol packet whose entire purpose is to confirm a stub answers an unknown
request with an empty packet; this stub answered it with silence, and GDB
refused the connection with `Remote replied unexpectedly to
'vMustReplyEmpty'`. Every self-test passed throughout, because the two ways
of having nothing to say — "not implemented" and "not yet" — were both
spelled as an empty `std::string`, and the encoder resolved the ambiguity by
refusing to frame an empty payload at all. They are now different types
(`Reply::unsupported()` against `Reply::nothing()`), the encoder frames
`$#00` as the packet it is, and the decoder accepts one instead of reporting
a checksum failure that the sender can never correct.

**The event stream.** Seventeen event kinds on a Unix domain socket, one
JSON object per line. Dropped events are reported rather than lost, which is
the property that makes a trace worth reading: a lost uprobe hit is counted
and reported as a degradation in the session summary, so a consumer can tell
a function that was not called from a hit the kernel dropped.

`file_opened` was one of the seventeen with a name and an enum value and no
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

**Isolation without the target knowing.** Syscalls come from `PTRACE_SYSCALL`
stops, with the register block read at the stop. Memory is read with
`process_vm_readv` from outside. There is no eBPF program in this codebase:
the filter is seccomp-BPF, which is a different thing that shares the `bpf`
syscall. The `ptrace` in the tree is for process control and register access
only, and `docs/SECURITY.md` draws that line explicitly.

## What does not work

**The PE engine runs until it needs a loader, and then it needs one this
host often does not have.** The dispatch exists: `runner::run` detects the
format, asks `engine_for` which engine takes it, and every format it
recognises has one. `src/engine/` holds `exe_engine.cpp` for ELF,
`pe_engine.cpp` for PE, and `apk_engine.cpp` for APK, and `engine.cpp` is the
table that names them.

What remains bounded is the PE path, and it is bounded by a fact about the
host rather than a gap in the code. A Windows image needs a Wine loader, and
a container usually has Wine's runtime libraries without the loader binary. The
engine says so by name and refuses the run rather than exec'ing the file and
letting the kernel's binfmt handler produce a process nobody configured. On a
host with a Wine installation the engine assembles the run -- the loader, a
per-run prefix under the run's scratch directory, the library directory bound
read-only, the `.so`-side `Nt*` probes planned and placed -- and on a host
without one it reports which of those it could not find.

The APK engine is the shallowest of the three. An APK is a zip and its native
code is a `lib/*/lib*.so` inside it; what the engine does is the part that has
a definite answer, which is to name the DEX and the native libraries rather
than to run the archive as a process.

**Three documents the README promised did not exist.** `docs/ROADMAP.md`,
`docs/RSP.md` and `docs/COMPAT.md` were all referenced from the README -- two
of them in the document index -- and none of them were in the tree. All three
are written now. A reference to a document that is not there is worse than no
reference: it tells a reader the question has been answered.

**The fuzz harnesses are built, and only in a build that asks for them.**
`fuzz/` holds six of them -- the ELF reader, the zip reader, the PE reader,
the PE loader, the GDB RSP codec and the seccomp-BPF emitter -- each a
`LLVMFuzzerTestOneInput` over the parser it names, plus a `seeds/` directory of
thirty-six seeds. `docs/BUILD.md` describes
`-DOCC_ENABLE_FUZZ=ON`, which is what `add_subdirectory(fuzz)` is conditioned
on, and `fuzz/README.md` records what each harness asserts. They are off by
default because the sanitizer link flags they need are per-consumer, so an
ordinary build does not pay for them.

What they are not is continuous. There is no fuzzing service, so they are a
thing a person runs rather than a thing that runs -- though a bounded run of
each is a ctest, so an ordinary `ctest` in a fuzz build does reach them. What
the accumulated corpus holds is not checked in: it is untracked, and a clean
build throws it away.

**They have already paid for themselves, which is the argument for keeping
them.** The loader harness asserts one thing above all others: a refused load
leaves the address space exactly as it was. A seed whose optional header
declares 0x60 bytes in a file that stops 0x120 bytes in -- so the data
directory array is claimed by the layout and absent from the file -- broke
it, and the defect was real: the loader rolled back a refused load's kernel
mapping and, with no mapper to unmap, rolled back nothing, leaving a ledger
that described an image whose bytes were never placed. Every unit test missed
it, because every unit test that reaches a refusal after the record supplies
a mapper. The fix is in, the case is in, and the seed is
`pe_short_data_directory.bin` so the fuzzer starts next to the boundary again.

The harness's own invariant was wrong in the same run, in the direction that
matters: it compared the allocation count, which `AddressSpace::remove`
deliberately does not move when a region is forgotten, because the count is a
replay sequence number. A harness that traps on correct behaviour is as much a
finding as one that misses a defect, and fixing it is only honest if the fix
is checked -- so `same_map` compares the regions and the high water instead,
and the loosening was verified by re-tightening it and confirming the seeds
still fail.

**Nothing that needs a process is fuzzed.** The `run` path and everything
under it needs a real namespace and a real kernel, and a fuzzer that forks per
input spends its time in setup -- and deadlocks against the driver's own
process management, which is a measured result rather than an assumption. The
parsers are where untrusted bytes enter, so that is where the budget went, and
the consequence is worth stating: the container, the probe plumbing and the
uprobe path are unexercised by any harness. `fuzz/README.md` says so in the
same terms.

The seccomp emitter is the exception, and it is the exception because it does
not need a process. It builds a filter from a typed policy rather than from
bytes, so the harness reads the fuzzer's bytes as that policy and then reads
the emitted bytecode back for the emitter's own promises: every branch lands
inside the program, the program ends in a return, the reported count is the
emitted one, the preamble is the five instructions the layout documents, and
every rule's number is in the dispatch table. The one thing a fuzzer would
reach for and cannot have is the kernel's verdict on the result, and that is
`occ_test_seccomp`'s -- 91 assertions, of which 37 install a real filter in a
forked child and make a call it has an opinion about, in a build without a
sanitizer. Building it already found a real hole in the harness
itself, which is in `fuzz/README.md` under the heading about invariants that
were wrong.

**Syscall tracing needs a host that lets occ attach.** The syscall path is
`PTRACE_SYSCALL` on the tracee, which needs `CAP_SYS_PTRACE` or root. A host
that refuses the attach produces no syscall events rather than an error, and
the run continues. `occ doctor` reports what the host has.

**Function-level observation needs a tracefs.** A uprobe is registered by
writing a line into tracefs and subscribed to with a `perf_event_open` on the
tracepoint id the kernel assigns. A host without tracefs mounted, or with
`perf_event_paranoid` set so the open is refused, places no probes at all --
the run continues at syscall level and every `probe_attached` record says
`ok: false` with a reason. Placing the probes is implemented; reaching the
kernel that has to accept them is the part that depends on the host.

**Hardware watchpoints are four.** W^X tracking over a region larger than the
debug registers can express is partial by construction.

## Known rough edges

**PE fidelity is bounded by the loader.** The engine runs the image under a
Wine loader it found on the host, with the loader's own library directory
bound read-only and a per-run prefix. How faithful that is follows from which
Wine is installed, and the engine has no way to tell a Wine that runs an image
from one that starts and then faults inside it: both produce a process that
exits, and the exit code comes from Wine rather than from the image. That
boundary is worth stating again: timing-sensitive, SEH-detail-sensitive and
undocumented-structure-sensitive checks will diverge from genuine Windows,
and some PE targets will never reach a state with analytical value. Saying so
up front is cheaper than a user discovering it.

**`capabilities` has no dedicated test file.** Zero, against a pair of
wrappers in `src/syscall/syscall.cpp` that a container setup calls to drop what
it should not keep. The seccomp half has grown to 91 assertions covering a BPF
emitter that is 467 lines of arithmetic on a structure the kernel rejects
without explanation; the capability half has a syscall wrapper and no test that
it is reached with the right arguments. The security boundary is the part with
the least test coverage, which is the wrong way round and is stated here rather
than left to be discovered.

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

The test suite is 2,725 assertions and needs no network. Six of the twenty
binaries can skip: two need a host that permits namespaces and seccomp
(`test_seccomp`, `test_container`), two need a Wine installation to find an
`ntdll` in (`test_engine`, `test_ntdll_probes`), one needs a handwritten PE
fixture on disk (`test_runtime_loader`), one needs a gdb on `PATH`, and one
needs a `python3` to re-run the seed generator. Those are skipped rather than
failed where the host does not have them, and the skip says so in a note. The
last one is worth naming here: it
is the only test whose skip weakens a guarantee rather than a measurement,
because nothing else would notice a seed drifting away from the generator
that describes it. A claim in this file that can be checked should be checked
that way before it is believed.

**A sanitizer is a host like any other, and one test is worse under it.** Two
assertions are conditional on the absence of AddressSanitizer, and both
because the sanitizer replaces the thing being measured rather than because
it found anything:

- `test_container`'s signal-reporting case runs a child that provokes
  SIGSEGV and inspects how the container reported it. ASan installs its own
  SIGSEGV handler in that child and its handler does not return — it prints
  and terminates — so the child dies of the sanitizer's abort rather than of
  the signal the test raised. Passing `handle_segv=0` restores the signal and
  also blinds the sanitizer to every real fault in the run, which is the worse
  trade. The case is skipped under ASan and runs in the build without one.
- `test_seccomp`'s "the child exited with status zero" is a supporting claim
  about a child that has finished its syscalls and is on its way out. Under
  ASan the exit path makes syscalls the filter has not been told about and
  refuses, so the status is nonzero. Every syscall observation in that case
  passes, and the check is made conditional rather than skipping the case,
  because the observations are the real assertions.

Neither skip hides a defect: the plain build reports `0 skipped` for
`test_container` and the seccomp exit-status check passes there. What they
establish is the rule this repository has been arguing for all along — a skip
is a claim, and a claim gets written down and checked.

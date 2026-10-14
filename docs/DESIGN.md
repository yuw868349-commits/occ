# DESIGN

This document describes the architecture: what each module owns, why the boundaries fall where they do, and what the invariants are. Facts here come from the source, not from any earlier revision of this document.

Repository shape: 21 module directories, 163 source files, 83 headers, roughly 180,000 lines of product code, 90 test files adding another 60,000.

---

## Contents

- [The core decision](#the-core-decision)
- [Module map](#module-map)
- [Dependency direction](#dependency-direction)
- [Parser](#parser)
- [Engine](#engine)
- [Runner](#runner)
- [Runtime](#runtime)
- [Syscall](#syscall)
- [Isolation](#isolation)
- [Observer](#observer)
- [Devirt](#devirt)
- [Concolic](#concolic)
- [Deobf](#deobf)
- [Inspect](#inspect)
- [Packer](#packer)
- [DBI](#dbi)
- [Emu](#emu)
- [Behave](#behave)
- [Probe](#probe)
- [Replay](#replay)
- [Hostile](#hostile)
- [Fuzz](#fuzz)
- [Util](#util)
- [Cross-cutting conventions](#cross-cutting-conventions)
- [Known gaps](#known-gaps)

---

## The core decision

A Windows PE is mapped into this process's address space and its own instructions execute on this process's own thread, on the host CPU, untranslated. Everything else in the architecture follows from that.

Because there is no boundary, the usual machinery disappears. No ptrace, because the debugger and the target share an address space and a thread. No QEMU, because no instruction is translated. No virtual machine, because the guest is native code here.

What must be built instead is the environment: a ntdll subset, loader behavior, SEH dispatch, TLS, the process environment blocks, the ABI that carries calls, and the API surface. The guest notices when loading is done differently, when `GetModuleHandle` returns something unusable, when `IsDebuggerPresent` is inconsistent across three different code paths.

The split is therefore not "simulated versus native" but "environment versus machine". The machine is real. The environment is built.

## Module map

| Directory | Owns |
|---|---|
| `parser` | Format detection and parsing: PE, ELF |
| `engine` | Format engines that drive a run |
| `runner` | The run and debug drivers |
| `runtime` | The guest runtime: loader, ntdll, SEH, TLS, API simulations, guest threads, memwatch, debugger, VM tracing, 32-bit interpreter |
| `syscall` | Kernel ABI: syscall numbers, capabilities, errno |
| `isolation` | seccomp and container |
| `observer` | The event stream: probes, watchpoints, registry, RSP, transport, sessions |
| `devirt` | De-virtualization: lift, bit-blast, SAT, solve, codegen, certify |
| `concolic` | Concolic execution: taint, bitflow, path constraints, engine |
| `deobf` | Deobfuscation: control-flow flattening, MBA, opaque predicates |
| `inspect` | Static analysis reports |
| `packer` | Packer identification, SMC detection, unpacking pipeline |
| `dbi` | Dynamic binary instrumentation |
| `emu` | x64 interpreter with the decode/split/rewrite/execute pipeline |
| `behave` | Behavior reporting |
| `probe` | Host capability probing |
| `replay` | Trace replay |
| `hostile` | Hostile sample detection |
| `fuzz` | Fuzz targets |
| `util` | Logging, filesystem, strings, spans |

## Dependency direction

Strictly downward. `util` depends on nothing. `parser`, `syscall`, `util` are leaves. `runtime` depends on `parser`, `syscall`, `util`. `engine` depends on `parser`, `runtime`, `isolation`. `runner` depends on `engine`, `runtime`, `observer`. `devirt` depends on `parser`, `runtime`, `util` and nothing above it.

`observer` is deliberately outside that chain: it is an observation layer, not a driver, so both `runner` and `engine` can subscribe to it without depending on each other.

The build enforces the bottom four layers as the `occ_core` static library, with `-fno-exceptions -fno-rtti` applied privately to that target only.

---

## Parser

`parser/pe.h`, `parser/pe.cpp`, `parser/elf.h`, `parser/elf.cpp`, `parser/detect.h`, `parser/detect.cpp`

### The tolerance split

The design decision that matters here is that **format recognition and structural loadability are two separate questions**.

`is_pe()` answers "did the code parse this as PE at all". `loadable()` answers "would this run". A file can be recognized as PE and still be unloadable, and that is the common case for real-world samples: truncated headers, overlapping sections, a directory pointing outside the image, a corrupt relocation table.

`recognized_` is a single bit carried on `PeFile`, so the answer survives to the caller. Content parsing is per-directory and never fails the whole file; each directory yields its own `PeDiagnostic`, and a caller that wants the diagnosis asks for it.

`loadable()` is the real criterion. `ok()` is an alias that exists only for callers predating the rename; the comment states plainly that it is `loadable()` and not `is_pe()` on purpose, because the two answers differ exactly when a file is recognizable but broken.

This is what lets the same parser serve three different callers with different requirements: `occ run` wants `loadable()`, `occ inspect` wants everything that was parsed, and the fuzzers want to know the parser survived.

### Structures

`DosHeader` (mz_header_off_=0, e_lfanew_=0x3C), `CoffFileHeader` 20 bytes, `OptionalHeader` with `dll_characteristics`/`subsystem`, `DataDirectory`, `PeSection`, `PeImport`, `PeExport`, `PeTls`, `PeFunctionEntry`, `PeResource`, `PeDebug`, `PeClr`, `PeLoadConfig`, `PeDelayImport`, `PeTls64`.

`PeResource` supports the classic three-level tree with id, string, and id-or-string entry variants. `PeDelayImport` is the delay-load table, which the loader does not yet consume but the parser does.

`SIGNATURE_BYTES = 4`; an empty optional header means NT64. `class ResourceTree` is a convenience wrapper.

### ELF

`ElfFile`, `ElfSymbol`, `ElfDynamic`, `ElfProgramHeader`, `ElfSectionHeader`, `ElfNote`, `ElfExceptionIndex`. The exception index is what the observer uses to map addresses onto symbol names.

### Detection

`Format{Unknown, Pe, Elf, MachO, Script, Raw}` with `sniff()` and `detect()`. `sniff()` decides from the first bytes alone; `detect()` additionally consults the filesystem. `Magic{Pe=0x5A4D, Elf=0x457F, MachO32=0xFEEDFACE, MachO64=0xFEEDFACF, MachOFat=0xCAFEBABE}`.

`MachO` is recognized but not parsed. The gap is explicit in the enum rather than hidden.

---

## Engine

`engine/engine.h`, `engine/engine.cpp`, `engine/pe_engine.h/.cpp`, `engine/exe_engine.h/.cpp`, `engine/apk_engine.h/.cpp`

`FormatEngine` is the interface a format plugs into. Each engine owns detection-to-execution for one family.

- `pe_engine` drives PE runs
- `exe_engine` handles the `.exe` container conventions
- `apk_engine` handles APK packaging

`engine.cpp` holds the dispatch: given a path, pick the engine, hand it the options, collect the result. The engines are interchangeable, which is what keeps the CLI from growing a branch per format.

---

## Runner

`runner/run.h`, `runner/run.cpp`, `runner/pe_runner.h`, `runner/pe_runner.cpp`

The top of the stack for actually executing something.

`pe_runner.cpp` holds `run_pe_process` and `run_pe_32`. `run_pe_process` is the 64-bit entry: it does the `sigaltstack`, installs the five signal handlers, arms memwatch and vm_trace, sets up GS base through `SYS_arch_prctl`, and uses `sigsetjmp` as the convergence point.

`run_pe_32` is the 32-bit counterpart and runs the `i386` interpreter. The container is deliberately absent there, because the interpreter is itself the isolation.

`run.cpp` decides which of the two to call based on the machine type from the parser.

---

## Runtime

See [RUNTIME.md](RUNTIME.md). In brief, it owns the guest environment: address space ledger, mapper, loader, TLS, TEB/PEB, SEH, the Windows ABI bridge, the guest heap and stdio, the export registry, API set resolution, synthetic guest module images, guest threads, write watching, VM dispatch tracing, image dump and minidump, IAT reconstruction, the 32-bit interpreter, containment, kernel objects, the guest debugger, the API hook, and 69 API simulation files covering 2733 registered exports.

---

## Syscall

`syscall/kabi.h`, `syscall/syscall.h`, `syscall/syscall.cpp`, `syscall/capability.h`, `syscall/capability.cpp`, `syscall/errno.h`

The kernel ABI layer.

`kabi.h` holds syscall numbers as constants, so a kernel upgrade does not silently change behavior.

`capability.h` is a static capability table: what this host kernel can do. Probing happens once at startup, and everything downstream asks the table rather than probing again. This is what makes `doctor` able to answer "what can this host do" without running anything.

`syscall.cpp` issues the calls. `errno.h` translates Linux errno to Windows error codes in one place, because the mapping is not symmetric and getting it wrong per call site is how inconsistency creeps in.

---

## Isolation

`isolation/seccomp.h`, `isolation/seccomp.cpp`, `isolation/container.h`, `isolation/container.cpp`

Two independent mechanisms.

### seccomp

`build_filter` takes an `AllowedSyscallList`, an `AllowedOpenFlagsList`, and a `SeccompPolicy` bitfield, and compiles them into one `sock_filter` program through the SBF macros in `seccomp.h`.

```
kActionAllow  = 0x7FFF0000
kActionErrno  = 0x00050005
kActionTrace  = 0x7FF00000
kActionKill   = 0x00000000
```

The compiled program is written in one `write()` to the filter fd, so no partially-installed filter can be observed. The kill action is only allowed when `policy.allow_kill_process` is set.

### Container

Runs the guest under a `chroot`-style confined process.

The containment module (`runtime/containment.cpp`) is the path-level half: `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`, atomic in one syscall, with an `openat`/`readlinkat` fallback capped at 40 symlinks and an explicit `confinement_unsupported` marker when neither works.

The container is the default. `--no-container` and `OCC_PLAIN_SPAWN=1` are the escape hatches for guests that need the host, and they are documented as such rather than hidden.

---

## Observer

`observer/session.h`, `observer/session.cpp`, `observer/transport.h`, `observer/transport.cpp`, `observer/event.h`, `observer/event.cpp`, `observer/ptrace.h`, `observer/ptrace.cpp`, `observer/uprobe.h`, `observer/uprobe.cpp`, `observer/watchpoint.h`, `observer/watchpoint.cpp`, `observer/registry.h`, `observer/registry.cpp`, `observer/rsp.h`, `observer/rsp.cpp`, `observer/wx.h`, `observer/wx.cpp`, `observer/ntdll_probes.h`, `observer/ntdll_probes.cpp`

The event stream. It records what a run did without the run needing to know it is being observed.

### Events

`EventKind` enumerates 26 kinds:

```
Syscall, ApiCall, MemoryWrite, RegisterChange, PageFault, ExecEntry,
ExecExit, ThreadCreate, ThreadExit, ModuleLoad, ModuleUnload, Breakpoint,
Watchpoint, WatchpointMiss, SectionChange, ApiHook, Hostile, ApiGap,
IatHook, MemoryProtectChange, Mutex, Snapshot, Trace, Coverage, Fatal,
Internal
```

Every event carries: `kind`, `t` (monotonic ns), `pid`, `tid`, `thread`, `address`, `arg0`/`arg1`/`arg2`, `a`/`b` (64-bit ints), `name` (32 chars), `text` (60 chars), `args`.

### The 128-byte record

One event is exactly `kRecordBytes = 128`, made of `kHeaderBytes = 40` plus `kPayloadBytes = 88`.

```
kNameBytes   = 32
kTextBytes   = 60
kArgsBytes   = 40
kArgsPerEvent = 8
```

This is a wire format, and the size is load-bearing: it makes the record cache-line-friendly, lets the ring buffer be a fixed block of memory rather than a growable structure, and means a reader can seek to event *n* by arithmetic instead of scanning.

### Sessions and transport

`ObserverSession` is the owner. Its magic is `kSessionMagic = 0x53454F42` ("SEO B"), its version is `kSessionVersion = 1`, and its stream magic is `kStreamMagic = 0x4F435354`.

The transport is a Unix datagram socket at a fixed path, named after the session with the PID appended. Records are fixed-size `EventRecord`s; a write that would not fit in one datagram is truncated to a multiple of 128 bytes, so a partial record can never be read as a whole one.

Reconnecting is what `attach` does: the CLI finds the socket, subscribes, and receives the stream. A long run can be inspected without babysitting it.

Ring depth is `kRingDepth = 256`.

### Probes

`ptrace.cpp` is the ptrace-based probe, `uprobe.cpp` the uprobes-based probe. `watchpoint.cpp` watches memory through the debug registers. `registry.cpp` records registry access. `rsp.cpp` is the RSP transport (see [RSP.md](RSP.md)). `wx.cpp` records the write/execute state of pages.

### ntdll probes

`ntdll_probes.cpp` holds `kProbes[]`, 73 entries, each an `NtdllProbe`:

```cpp
struct NtdllProbe {
    const char* symbol;
    ProbeCategory category;
    const char* arg0; ... arg3;   // parameter names, NULL when fewer
};
```

`ProbeCategory` covers File, Memory, Registry, Process, Thread, Sync, Security, SystemInfo, Debug, Object, Network, Token, Section, Key, Misc.

The categories are used to group syscall events without the observer needing to know anything about the kernel. An unlisted ntdll symbol falls into `Misc` via `kUnknownCategory`, so nothing is silently dropped.

---

## Devirt

`devirt/expr.h`, `devirt/expr.cpp`, `devirt/lift.h`, `devirt/lift.cpp`, `devirt/bitblast.h`, `devirt/bitblast.cpp`, `devirt/sat.h`, `devirt/sat.cpp`, `devirt/solve.h`, `devirt/solve.cpp`, `devirt/goal.h`, `devirt/goal.cpp`, `devirt/codegen.h`, `devirt/codegen.cpp`, `devirt/cert.h`, `devirt/cert.cpp`, `devirt/ring.h`, `devirt/ring.cpp`, `devirt/mba.h`, `devirt/mba.cpp`, `devirt/adapt.h`, `devirt/adapt.cpp`, `devirt/semlib.h`, `devirt/semlib.cpp`

Offline de-virtualization. Inputs are a dispatch trace and a decrypted image dump. Nothing here touches a running process.

### The IR

`expr::DAG` is a hash-consed SSA expression graph and the common IR for the whole module.

`Op` is `Const, Input, Add, Sub, Mul, And, Or, Xor, Shl, Shr, Sar, Not, Neg, Resize, Select, CmpEQ, CmpULT, CmpSLT`. `Id` is a `uint32_t` index into `nodes_`, `kNoId = 0xFFFFFFFF`.

Hash-consing works by canonicalizing each node into a key string of the form `op:width:imm:a:b:c` and interning it in `pool_`. Two structurally identical subexpressions are the same `Id`, which is what makes sharing possible and what keeps the SAT input small.

`Bindings{values, known}` binds inputs to concrete values. `evaluate` memoizes per call, which matters because a shared DAG is a graph, not a tree: without memoization a long chain of shared nodes is re-evaluated once per reference and the cost explodes.

`pretty` has a node budget of 4096. Expanding a shared DAG as text can grow exponentially, and an unbounded renderer is a hang waiting for the right input.

`adopt_input()` exists because `input()` returns the DAG's ordinal, and the ordinal is the only authoritative identity. Push-order identity is not, because the DAG deduplicates by `(name, width)`.

### Lift

`lift.cpp` turns the VM's native x86-64 handler code into DAG expressions.

- `Handler` models one handler: its preconditions, its effects, and its exits
- Symbolic lifting of x86-64 instructions, so an `add` inside a handler becomes an `Add` node rather than a black box
- Shared boundary recognition: a handler that ends by jumping into the dispatcher is recognized as such, and the lift stops at that boundary rather than walking into shared code it does not own
- Semantic labels are produced by the lift model itself, not bolted on by the CLI
- Layout inference: the register file at `rsp` is displayed as `vst[...]` and the bytecode at `r8` as `code[...]`, inferred from how the handler actually indexes, not hardcoded
- Conformance checking: the model is replayed against the trace and every register and memory effect is compared, with the count of checked and mismatched rows reported
- `Handler::exits` is a list, not a single target, because a handler with multiple exits was being discarded whole before the list existed

`adapt.cpp` and `semlib.cpp` are the no-trace static path: infer from the image alone.

### Bit-blast and SAT

`bitblast.cpp` encodes each DAG node as a vector of CNF clauses, one Boolean per bit.

`sat.cpp` is a CDCL solver: unit propagation, VSIDS decision heuristic, first-UIP conflict analysis with learned clauses, and Luby restarts.

The budget type `bb::Budget` bounds work so a pathological instance cannot run forever; "unproven" is a legitimate answer and is reported as such.

### Solve

`solve.cpp` is the replay solver. Given the handler models, the trace rows, a mapping from row to handler, a code reader, and a context, it replays the traced path through the verified models. Where the trace's bytes are unknown, they become symbolic input bytes.

The public surface:

```cpp
struct UnknownRegion { ... };
struct GoalNode { ... };
struct SolveOptions { std::vector<UnknownRegion> unknown; ... };
struct SolveResult { ... };

SolveResult solve(Model& model, const std::vector<Handler>& handlers,
                  const std::vector<Row>& rows,
                  const std::vector<std::size_t>& handler_of_row,
                  CodeReader code, SolveContext& ctx,
                  const SolveOptions& options);
```

This is general machinery. It has no knowledge of any particular sample.

### Goal language

`goal.cpp` parses an arbitrary condition into a `GoalNode` tree.

```cpp
enum class Kind : std::uint8_t { ... };
bool parse_goal(const std::string& text, GoalNode* out, std::string* error);
```

The grammar supports, among others: `vst[i]` (the register file), `code[i]` (the bytecode stream), `mem8|16|32|64[a]` (guest memory at a width), named registers, arithmetic, comparisons, and logical connectives. A goal is a tree rather than a DAG because it is written once by a human and read once by the solver.

### Codegen and certification

`codegen.cpp` rebuilds a handler as linear IR and checks that the IR reproduces the model's claimed effects: every write the model claims, every store the IR performs, `rbp_new`, `rsi_new`, and the dispatch target. Failures are named and specific, so a mismatch says which invariant broke.

`compare()` normalizes both sides to 64 bits before comparing, so an equivalence never depends on the width the expressions happened to be built at.

`cert.cpp` issues the certificate. `ring.cpp` is a cheap algebraic equivalence layer used before the expensive bit-blaster.

---

## Concolic

`concolic/engine.h`, `concolic/engine.cpp`, `concolic/taint.h`, `concolic/taint.cpp`, `concolic/bitflow.h`, `concolic/bitflow.cpp`, `concolic/program.h`, `concolic/program.cpp`

Symbolic execution over the runtime's own execution.

`PathReport::SolverStats` counts `calls`, `sat`, `unsat`, `limited`, `conflicts`, and `unsat_prefix_hits`. That last one counts unsatisfiability answers served from a prefix cache without a solver call: if a set is a superset of a proved-unsatisfiable set, it is unsatisfiable, and the solver does not need to be invoked.

`PathReport` carries `Budget budget`, `std::vector<Path> paths`, `std::vector<UnsatBranch> unsat_branches`, `Coverage coverage`, `SolverStats solver`, and `std::string error`.

`taint.cpp` tracks which bytes are symbolic. `bitflow.cpp` propagates values bit by bit. `program.cpp` models the program under analysis. `engine.cpp` explores paths, with the hot/cold worklist ordering and the unsat prefix cache described above.

---

## Deobf

`deobf/deobf.h`, `deobf/deobf.cpp`, `deobf/ir.h`, `deobf/flatten.h`, `deobf/flatten.cpp`, `deobf/mba.h`, `deobf/mba.cpp`, `deobf/opaque.h`, `deobf/opaque.cpp`

- `deobf.cpp` is the pipeline orchestrator and the reporter
- `flatten.cpp` identifies control-flow flattening: a switch-based dispatcher replacing structured control flow
- `mba.cpp` simplifies mixed boolean-arithmetic identities
- `opaque.cpp` identifies opaque predicates, conditions whose outcome is constant but not obviously so

`ir.h` is the IR they share.

---

## Inspect

`inspect/inspect.h`, `inspect/inspect.cpp`, `inspect/analysis.h`, `inspect/analysis.cpp`, `inspect/disasm.h`, `inspect/disasm.cpp`

The static report. `analysis.cpp` extracts headers, sections, imports, exports, TLS, exceptions, resources, and strings. `disasm.cpp` disassembles.

The point of `inspect` is that it never requires the file to be loadable. It reports what was parsed, alongside the diagnostics explaining what was not. That is the direct consumer of the parser's tolerance split.

---

## Packer

`packer/packer.h`, `packer/pe_view.h`, `packer/pe_view.cpp`, `packer/identify.cpp`, `packer/smc.cpp`, `packer/pipeline.cpp`, `packer/esp_law.h`, `packer/esp_law.cpp`

### Identify

`identify.cpp` scores candidate packers on shape. Four hard blockers cancel a candidate outright:

- `extra_section_penalty`: unusual section layout
- `very_high_entropy`: data that looks encrypted
- `bad_ep_section`: the entry point is outside any section
- `tiny_code`: no room for the unpacker to have run

The UPX family is identified by a triple: the section name `UPX!`, `PackedVersion` in the overlay, and `InfoVersion` in the overlay, all required. That is why a "name-shape contradiction" is a strong signal: a section named `UPX!` without the version fields is either a stripped packer or a decoy, and the code says which.

Candidates are rank-ordered, not asserted.

### SMC

`smc.cpp` statically detects self-modifying code, needed because the unpacker writes into its own `.text`.

### Pipeline

`pipeline.cpp` orchestrates: identify, view, unpack, dump.

### The gap

`esp_law.cpp` is not in the `occ_core` source list in `CMakeLists.txt`. It compiles nowhere in the normal build, which makes it dead code. Its own test is the only consumer. Treat the ESP-law unpacking as unfinished, not as a feature.

`packer` has no CLI command. `main.cpp` does not reference it. Its output is consumed by `inspect` and the tests.

---

## DBI

`dbi/dbi.h`, `dbi/dbi.cpp`

Dynamic binary instrumentation. The pipeline is decode, split, rewrite, execute.

`dbi.cpp` is the only file. `Coverage` is a fixed `uint8_t[32]`, not a `std::array`, deliberately.

Coverage is a hash rather than a set: a basic block executed ten times contributes one bit, so coverage measures reach, not frequency.

Like `packer`, `dbi` has no CLI command and no `main.cpp` reference. It is a library.

---

## Emu

`emu/emu.h`, `emu/emu.cpp`

An x64 interpreter with its own decode/split/rewrite/execute pipeline.

`emu` and `runtime/i386.cpp` are two different things and both exist. `i386.cpp` is a 32-bit CPU, present because a 64-bit process cannot execute 32-bit code natively. `emu` is an x64 interpreter with a rewrite pipeline that `i386` does not have. `i386` has `HostCall`; `emu` does not, and halts on a system call instead.

`emu` also has no CLI command and no `main.cpp` reference.

---

## Behave

`behave/behave.h`, `behave/behave.cpp`

Behavior reporting: what the sample did, summarized.

---

## Probe

`probe/placer.h`, `probe/placer.cpp`, `probe/doctor.cpp`

`placer.cpp` places probes on host symbols.

`doctor.cpp` is what `occ doctor` runs. It reports what this host can and cannot do, drawing on the `syscall` capability table and the container state. This is the honest answer to "what works here", and it is the reason the project does not need to pretend its API coverage is complete.

---

## Replay

`replay/replay.h`, `replay/replay.cpp`

Replays a recorded trace.

---

## Hostile

`hostile/hostile.h`, `hostile/hostile.cpp`

Detects anti-analysis measures in a sample: debugger checks, timing checks, integrity scans, VM detection.

---

## Fuzz

`fuzz/fuzz.h`, `fuzz/fuzz.cpp`

Fuzz targets for the parsers. Built with `-fsanitize=fuzzer,address,undefined` when `OCC_ENABLE_FUZZ` is on, which also forces `OCC_STATIC_LINK=OFF`.

---

## Util

`util/log.h`, `util/fs.h`, `util/string.h`, `util/span.h`, `util/errno.cpp`, `util/log.cpp`, `util/fs.cpp`, `util/string.cpp`

Logging, filesystem helpers, string helpers, spans. `span.h` is header-only.

---

## Cross-cutting conventions

**No exceptions, no RTTI.** `occ_core` is built with `-fno-exceptions -fno-rtti`. Failures travel as `Result<T>` or out-parameters. This is why `Result<T>` exists at all.

**Warnings are errors.** `-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wcast-qual -Wdouble-promotion -Wformat=2 -Wundef -Wnull-dereference -Wimplicit-fallthrough` plus `-Werror`, controlled by `OCC_WERROR`. `-Wconversion` and `-Wsign-conversion` are on, which is why the relocation code computes `delta` unsigned and why the capacity checks exist.

**Fixed sizes for wire structures.** Event records are 128 bytes, TEB is 8 KiB, PEB is 4 KiB, `MemoryBasicInformation` is 48 bytes, `DispatcherContext` is 0x50. Each has a `static_assert` where the compiler can see it. These are not preferences; they are the shapes the guest reads.

**No third-party runtime dependencies.** The build needs a C++23 compiler and CMake. Nothing else.

**Determinism where it is observable.** Base placement is a deterministic downward scan. Given the same input, the same base comes out. Reproducible analysis depends on it.

---

## Known gaps

Stated plainly, because a document that does not list them is marketing.

- `esp_law.cpp` is not built. Dead code.
- `packer`, `dbi`, and `emu` have no CLI entry points. They are libraries with tests.
- MachO is detected but not parsed.
- `modules.cpp`'s `kCrtForwarders[]` lists roughly 50 names with no corresponding registration.
- The API surface is large but not complete. Guests that lean on undocumented behavior or deep driver assumptions can still find a hole.
- Coverage instrumentation is not supported in the build.

`occ doctor` reports the host-specific half of this list at runtime.

---

Related: [RUNTIME.md](RUNTIME.md) for the runtime in detail, [BUILD.md](BUILD.md) for build options, [COMPAT.md](COMPAT.md) for the API surface, [EVENTS.md](EVENTS.md) for the event stream, [RSP.md](RSP.md) for the debug protocol, [ROADMAP.md](ROADMAP.md) for what is planned, [SECURITY.md](SECURITY.md) for the threat model.
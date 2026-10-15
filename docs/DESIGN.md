# DESIGN

This document describes the architecture: what each module owns, why the boundaries fall where they do, and what the invariants are. Facts here come from the source, not from any earlier revision of this document.

Repository shape: 20 module directories, 163 source files, 83 headers, roughly 180,000 lines of product code, 90 test files adding another 60,000.

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

Mostly downward, with three exceptions that are load-bearing:

- `util` depends on `syscall` for the errno constants, so `syscall` and `util` are not both leaves -- `syscall` is, and `util` sits on it.
- `runtime` depends on `observer`, which is the opposite of the direction the name suggests. The runtime emits events; the observer owns the sink they go to.
- `probe` depends on `observer` and `engine`. It is not a leaf, and it once was very nearly not a module at all: `observer/session.h` held a `ProbePlacer*` while `probe/placer.h` held a `Uprobes` by value and an event `Writer`, which is a cycle two headers wide that compiled only because the include guards happened to break it in the order the two were reached. `SessionConfig` now names the layer (`Uprobes*`) instead of the placer that owns it -- the session needs three things from the layer and all three are the layer's own -- so the edge is one-way and the accident is gone.

The rest holds: `parser` sits on `util`; `isolation` on `syscall` and `util`; `engine` on `parser`, `isolation`, `observer`, `runner`, `util`; `runner` on almost everything above it. `devirt` depends on `inspect` (for the disassembler) and nothing else outside itself; `concolic` and `deobf` depend on `devirt`'s expression DAG. `packer` depends on `runtime` for the dump and IAT rebuild; `emu` depends on `dbi`.

The build enforces the bottom layers as the `occ_core` static library, with `-fno-exceptions -fno-rtti` applied privately to that target only.

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

`PeImage` is the whole reader: one class, `parse(ByteSpan)`, and a set of accessors. The enums around it are `PeMachine`, `PeKind{None, Executable, Dll}`, `PeSubsystem`, `PeError`, `PeSeverity`; the structs are `PeDiagnostic`, `PeSection`, `PeExport`.

`PeSection` keeps the raw eight-byte name alongside the string, because a name that used all eight bytes is a real case and truncating it would make two sections look alike. `mapped_size()` falls back to the raw size when `VirtualSize` is zero -- the legal linker-emitted form meaning "as much as the file holds" -- because treating it as empty makes the section's whole address range unaddressable.

`PeExport` records the ordinal as the outside world sees it: the name-ordinal table holds an index into the address table, and the importable number is that index plus the directory's base. A forwarder is kept as its parsed target rather than as the string it points at, so a reader and a caller cannot disagree about which dot separates the DLL from the symbol.

Two RVA conversions, deliberately not one: `to_file_offset` answers "where do I read this byte" and returns false for zero-fill, because handing back an offset into zero-fill sends a reader to a region that was never in the file. `resolve_rva` answers the loaded-image question and reports zero-fill as such. The relocation directory is reported as an RVA and a size rather than parsed -- nothing in the engine needs its contents, and a relocation reader is a larger piece of work than the question asked.

### ELF

`elf.h` is the other half of the parser, and it answers a different question than `pe.h` does. `ElfImage` reads the headers and hands the engine a `DesiredMapping` -- the segments, the entry point, and a `StackRequest` for the auxiliary vector -- because an ELF is exec'd by the kernel here, so what the engine needs is what to map, not a structure to walk. `ProgramHeader`, `SectionHeader`, `Symbol`, `SymbolStatus`, and the `SymbolBind`/`SymbolType`/`SectionType`/`SegmentType` enums are the pieces; `LoadError` is the refusal vocabulary. A 64-bit little-endian x86-64 executable is the case handled natively; everything else is a refusal with a reason rather than a crash.

### Detection

`Format{Unknown, Elf, Apk, Zip, MachO, Pe}` with `format_name()`. Each format is identified by a signature at a fixed offset plus structural constraints a coincidence would have to satisfy as well, and the `Detection` struct carries the evidence that produced the verdict -- because a user who disagrees with the detection needs to see which bytes it was based on.

Two entry points, one analysis: `detect_file(path)` and `detect_bytes(ByteSpan)`. Neither fails; a path that cannot be read is `Format::Unknown` with the reason in the evidence. `Detection` also carries the ELF class/endianness/machine/type, a `bare_program_header` flag for Android OAT output, and the zip member list -- which lives there rather than on the engine's loaded image because the reader already walked the central directory to decide whether the file was a package, so an engine that wanted the names would otherwise re-read the file and could disagree with itself.

`MachO` is recognized so the refusal can name the format instead of reporting a corrupt ELF. The gap is explicit in the enum rather than hidden.

---

## Engine

`engine/engine.h`, `engine/engine.cpp`, `engine/pe_engine.cpp`, `engine/exe_engine.cpp`, `engine/apk_engine.cpp`

`Engine` is the interface a format plugs into: `kind()`, `name()`, `preflight()`, `load()`, `plan()`. One header, four implementations, no per-engine header -- the interface is the only thing a caller needs, and a derived class is reached through `engine_for()` rather than by name.

`EngineKind` has three members: `Elf` (a Linux executable or shared object, exec'd by the kernel), `Pe` (a Windows image, executed by occ's own runtime), `Apk` (an Android package). `engine_for()` routes a `Detection` to one; `engines()` lists them. A format this build recognizes but has no engine for is refused by name rather than exec'd, because a run whose isolation nobody designed is not a run worth having.

`engine.cpp` holds the dispatch. `LoadedImage` is what an engine learned, in the terms the runner uses, and it is a struct rather than three parameters so that a failure is reportable without changing the interface. `EngineRequest` is what an engine is asked to plan; `LaunchPlan` is what it answers -- the command line, the environment, the descriptors, the isolation -- which the runner executes without knowing which format produced it.

---

## Runner

`runner/run.h`, `runner/run.cpp`, `runner/pe_runner.h`, `runner/pe_runner.cpp`

The top of the stack for actually executing something.

`run.cpp` is the front half: `detect_file` the path, `engine_for` the format, `preflight`, `load`, `plan`, and then execute the plan. It owns the environment a target gets -- a caller who did not supply one gets three variables (`PATH`, `TERM=dumb`, `OCC_SANDBOX=1`) rather than the whole host environment, because `LD_PRELOAD` in the host environment changes what the binary does. The caller's named engine is an assertion the run checks rather than a second routing table: a caller who asked for one engine and got a detection that chose another is told the two disagree.

`pe_runner.cpp` is the back half and holds three entries. `run_pe_runner` is what occ exec's itself with under `__pe-runner`; `dbg_pe_runner` is the debug driver; `run_pe_32` runs the `i386` interpreter. The container is deliberately absent from the 32-bit path, because the interpreter is itself the isolation.

`runtime::run_pe_process` -- in `runtime/pe_process.cpp`, not here -- is where a 64-bit guest actually starts: it does the `sigaltstack`, installs the five fault handlers (`SIGSEGV`, `SIGILL`, `SIGFPE`, `SIGBUS`, `SIGTRAP`) with `SA_SIGINFO | SA_ONSTACK`, arms memwatch and vm_trace, saves the host GS base through `SYS_arch_prctl`, and uses `sigsetjmp` as the convergence point the guest's exit leg jumps back to.

---

## Runtime

See [RUNTIME.md](RUNTIME.md). In brief, it owns the guest environment: address space ledger, mapper, loader, TLS, TEB/PEB, SEH, the Windows ABI bridge, the guest heap and stdio, the export registry, API set resolution, synthetic guest module images, guest threads, write watching, VM dispatch tracing, image dump and minidump, IAT reconstruction, the 32-bit interpreter, containment, kernel objects, the guest debugger, the API hook, and 70 API simulation files covering 6351 registered exports.

---

## Syscall

`syscall/kabi.h`, `syscall/syscall.h`, `syscall/syscall.cpp`, `syscall/capability.h`, `syscall/capability.cpp`, `syscall/errno.h`

The kernel ABI layer.

`kabi.h` holds syscall numbers as constants, so a kernel upgrade does not silently change behavior.

`capability.h` is a static capability table: what this host kernel can do. Probing happens once at startup, and everything downstream asks the table rather than probing again. This is what makes `doctor` able to answer "what can this host do" without running anything.

`syscall.cpp` issues the calls. `errno.h` is where the errno numbers live, written out as constants rather than included from `<errno.h>`, because that header declares the thread-local errno variable and the syscall layer must not drag it in. `kEparse` is deliberately not an errno: it is a failure code distinct from every kernel value, so a caller can tell "the kernel said no" from "the input was malformed before the call". `util::strerror` reproduces the kernel's own descriptions rather than depending on the C library's locale files or its spelling of the message.

---

## Isolation

`isolation/seccomp.h`, `isolation/seccomp.cpp`, `isolation/container.h`, `isolation/container.cpp`

Two independent mechanisms.

### seccomp

`seccomp.h` emits the filter bytecode itself rather than delegating to libseccomp, because the kernel only ever executes bytecode: a library adds a policy compiler and a syscall-name table pinned to the library release rather than to the kernel the filter runs on, and both are things this project would then have to trust.

The shape of a generated program:

```
load arch
if arch != AUDIT_ARCH_X86_64 -> reject every call
load nr
if nr > max_nr -> reject
jump to the block for nr, else fall through
each block returns its action, or tests argument conditions first
fallthrough -> the policy's fallback action
```

`SeccompPolicy` is a fallback (`SeccompDefault::Allow | Errno | Trap | KillProcess`, defaulting to `Errno` with `ENOSYS`), a `max_nr` above which nothing is dispatched, and a list of `SeccompRule`s -- one per syscall number, each with an action, an errno payload for the `Errno` action, and zero or more `SeccompArgTest`s. The comparisons are the four the classic BPF instruction set actually has (`Equal`, `Greater`, `GreaterOrEqual`, `Masked`), with the other three expressed by exchanging a comparison's jump targets. An earlier version of this header reached for `BPF_JNE`, `BPF_JLT` and `BPF_JLE`, which are eBPF opcodes: the kernel rejects the whole filter at install time, so a policy using one protected nothing.

The `nr > max_nr` test is not an optimisation. On x86-64 the kernel sets bit 30 of the syscall number for x32 callers, so a number seen at the seccomp boundary has to be rejected on the full value; a filter that dispatched on the low bits would let an x32 caller reach the native entry point under a different number.

`build_seccomp` compiles and never installs; the installer sets `PR_SET_NO_NEW_PRIVS` itself, before the filter, because the kernel refuses an unprivileged install without it and a bit the caller had to remember was a bit that was forgotten.

`guest_default_policy()` is a refusal list rather than an allow list, and that choice is stated in the header: the runtime's own thunks reach the kernel on the target's behalf, so a target that needs a syscall the list forgot keeps running rather than stopping for a reason nobody can see from inside the container. The list takes away the calls a Windows target has no business making -- the mount family, the module family, kernel debugging and tracing, namespace changes, and the io_uring, keyring and cross-process memory interfaces. A caller that wants the stricter allow list sets `fallback = Errno` on its own policy and installs that instead.

### Container

`container.h` composes a container from kernel primitives, in an order that is not arbitrary:

1. `clone3` with the namespace flags. The new process is created stopped behind a pipe so it cannot run one instruction before the rest of the setup has happened.
2. Write the uid and gid maps. A user namespace starts with no mapping, so the process inside has no valid credentials until this completes.
3. In the child: make the mount table private, so nothing that happens next can propagate back to the host.
4. Assemble the new root. Overlayfs where a writable layer was asked for, a plain bind otherwise, then `pivot_root`.
5. Attach to a cgroup, so the resource limits a caller asked for are in place before any real work starts.
6. Install the seccomp filter last. It applies to the process that installs it, so everything above has to finish first.

No hypervisor and no kernel module. `NamespaceSet` is which namespaces to create, and a partial set is a valid and sometimes useful thing -- sharing the network namespace is how a target gets real network access, and sharing the pid namespace is how a tracer outside the container still sees it by pid. Each step reports a failure where it happened, because a container that half-exists is worse than one that never started.

The containment module (`runtime/containment.cpp`) is the path-level half: `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`, atomic in one syscall, with an `openat`/`readlinkat` fallback capped at 40 symlinks and an explicit `confinement_unsupported` marker when neither works.

The container is the default. `--no-container` and `OCC_PLAIN_SPAWN=1` are the escape hatches for guests that need the host, and they are documented as such rather than hidden.

---

## Observer

`observer/session.h`, `observer/session.cpp`, `observer/transport.h`, `observer/transport.cpp`, `observer/event.h`, `observer/event.cpp`, `observer/ptrace.h`, `observer/ptrace.cpp`, `observer/uprobe.h`, `observer/uprobe.cpp`, `observer/watchpoint.h`, `observer/watchpoint.cpp`, `observer/registry.h`, `observer/registry.cpp`, `observer/rsp.h`, `observer/rsp.cpp`, `observer/wx.h`, `observer/wx.cpp`, `observer/ntdll_probes.h`, `observer/ntdll_probes.cpp`

The event stream. It records what a run did without the run needing to know it is being observed.

### Events

`EventKind` enumerates 17 kinds:

```
SessionStart, SessionEnd, ProcessSpawn, ProcessExit, ImageLoaded, Mapping,
Section, Import, FileOpened, SyscallBlocked, BreakpointHit, Signal,
MemoryWrite, Exec, ProbeAttached, ProbeHit, Note
```

`Section` is separate from `Mapping` on purpose: a section is a range of the file and a range of the address space, and the loader is what turns one into the other, so reporting a section as a mapping would claim a correspondence the file does not make. `ProbeAttached` is separate from `ProbeHit` for the same reason -- attaching is a fact about the run's setup and happens once, and a hit is a fact about the target and happens as often as the target calls the function. A run that placed nine of ten probes and did not say which one it missed is a run whose output has a silent hole in it.

There is no event record struct. An `Event` *is* its already-encoded JSON body, built at the point the fact is observed, which keeps the encoder free of any state beyond the output sink and keeps a struct per event kind from being needed. `add()` is overloaded on the value type so a caller never quotes a string by hand; the `const char*` overload exists because a bare pointer would otherwise convert to `bool` and turn a name into a truth value.

### Sinks and sessions

`Sink` is an fd, not a `FILE*`, because the stream has to survive the process replacement the run performs and a buffer would be duplicated or lost across it. A partial write is retried; anything else is a stop.

`SessionConfig` and `SessionResult` bracket a session. `DebugServer` owns the debugger-facing half, which is where `attach` lands.

### Transport

`transport.h` holds `Connection` and `Listener`, and they are for the debugger protocol, not for the event stream. `Listener::open` takes a port as a number so that zero can be assigned by the kernel and read back -- that is how a caller learns which port it got when it asked for any free one. `Connection` owns the buffering that turns the byte stream back into packets and knows when the peer went away; a packet whose checksum failed does not count as complete, because there is nothing to handle until the debugger has been asked to send it again.

### Probes

`ptrace.cpp` is the ptrace-based probe, `uprobe.cpp` the uprobes-based probe. `watchpoint.cpp` watches memory through the debug registers. `registry.cpp` records registry access. `rsp.cpp` is the RSP transport (see [RSP.md](RSP.md)). `wx.cpp` records the write/execute state of pages.

### ntdll probes

`ntdll_probes.cpp` holds `kProbes[]`, 73 entries, each an `NtdllProbe`:

```cpp
struct NtdllProbe {
    std::string_view symbol;            // the Unix-side entry point
    ProbeCategory category;
    std::string_view arg0; ... arg5;    // parameter names, empty when fewer
    std::string_view note;              // why this call is worth a probe
};
```

The symbol is the Unix-side ntdll entry point rather than the Windows export: the PE-side `NtCreateFile` is a thunk into `__wine_syscall_dispatcher`, and the dispatcher is not a body a uprobe can be placed on. Six argument slots because a uprobe can read six argument registers.

`ProbeCategory` is eight values -- `File`, `Process`, `Memory`, `Registry`, `Sync`, `Module`, `Info`, `Other` -- and they are the ones a reader would sort events into, not the ones a kernel would. Two calls in the same category are reported together because a person asking about a program's file access wants both of them, even though the kernel implements one as a file lookup and the other as a handle close.

The categories group syscall events without the observer needing to know anything about the kernel. A symbol outside the table has no entry at all rather than a defaulted one, so nothing is silently dropped and nothing is silently added.

`occ doctor` reports the table's size next to whether this host can place any of it, which is what separates "no probes were placed" from "there were none to place".

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

The static report, one JSON document per image. `inspect.cpp` is the structural half: the headers, the data directories with presence flags, the sections with entropy and zero-tail counts, imports (per DLL, with the IAT and hint/name resolution), exports with forwarders, the TLS directory with its callbacks, the exception table with a flags histogram, the resource tree, and the debug directory. `strings` and `version` are options rather than defaults of the code -- both are on unless `--no-strings` says otherwise.

`analysis.cpp` is the code half and is requested with `--analyze`: it walks the instruction stream to find functions, builds a CFG per function with a cap on instructions walked, collects cross-references, and emits a call graph. Every cap is reported next to the count it truncates, so a consumer knows an answer is bounded rather than complete.

The point of `inspect` is that it never requires the file to be loadable. It reports what was parsed, alongside the diagnostics explaining what was not. That is the direct consumer of the parser's tolerance split.

---

## Packer

`packer/packer.h`, `packer/pe_view.h`, `packer/pe_view.cpp`, `packer/identify.cpp`, `packer/smc.cpp`, `packer/pipeline.cpp`, `packer/esp_law.h`, `packer/esp_law.cpp`

### Identify

`identify.cpp` answers "is this PE wrapped, and in what" from the file's own bytes. Six observations feed one weighted score per candidate:

| Observation | Weight | Why that number |
|---|---|---|
| Section name in the known table | 0.18 / 0.28 / 0.35 | Cheapest thing to fake; enough to notice, not to convict. Varies with how distinctive the name is. |
| Entropy >= 7.0 bits/byte | 0.30 | Compiled x86 measures 4.5..6.5. 7.0 sits above the code band with margin. |
| Virtual size >= 4x file bytes | 0.15 | A section that reserves more than it ships is reserving room for what the stub writes. |
| `LoadLibrary*` and `GetProcAddress` both imported | 0.15 | The strongest of the cheap signals: a clean program has no reason to resolve everything by hand. |
| Import count <= 3 | 0.10 | A packed image's import density is a fraction of a normal program's. |
| Stub idiom at the entry | 0.10 each, capped at 0.20 | `pushad`, `pushf`, a leading `jmp rel32` (bare or straight after `pushad`), `push imm32; ret`, `call rel32; pop`. None occurs in a compiler-emitted prologue. |

The UPX family is named by section name, and both spellings are in the table: `.upx0`/`.upx1`/`.upx2`, which is what UPX's writer emits, and `UPX0`/`UPX1`/`UPX2`, which survive from tools that strip the leading dot. Every other packer family is listed by the name it actually writes.

Consistency is scored in both directions. A section that claims a packer's name while measuring below 5.0 bits/byte contributes a negative weight, because the name and the bytes disagree; a zero-byte section (`.upx0`) is exempt, since it says nothing about its packer's entropy either way. `low_confidence` is set below 0.40 or on any contradictory candidate. The verdict bands are 0.60 (high) and 0.40 (medium); "unpacked (low-confidence signals only)" is a distinct string, not a soft "packed".

What cannot be measured is withheld, not guessed: an unreadable section reports entropy 0 with a note, and an import directory that cannot be walked contributes no import evidence at all rather than being read as "imports nothing".

### SMC

`smc.cpp` classifies a write stream against the section layout: a write into an executable section is a write-to-exec finding, repeated writes into one section are the shape a decryption loop leaves, a write into a data section is recorded and not alarmed. `static_smc_hints` adds the offline form -- an RWX section is a reason to arm the watch, not a finding on its own.

### Pipeline

`pipeline.cpp` orchestrates: identify, view, unpack, dump.

### ESP law

`esp_law.cpp` is the offline unpacker, and it is the reason this module does not need a running guest to produce a decrypted image. It carries its own small x86-64 machine -- registers, flags, a flat 32 MiB space -- and decodes and executes the entry-point stream directly, watching for the regularity the OllyDbg "ESP law" names: the wrapper saves the register state, runs its decryption loop, restores the state, and transfers out, so the stack pointer returns to its entry-time value exactly when the wrapper's work is done. The OEP is the first control transfer taken at a balanced stack that lands on an address nothing has executed before.

The decoder covers the subset a decryption loop uses -- moves, `lea`, the ALU group with register, memory and immediate forms, shifts, group 3, `inc`/`dec`, `jcc`/`jmp`/`call`/`ret`, `xchg`, `movzx`/`movsx`, `not`/`neg`, `pushad`/`popad`, `pushf`/`popf` -- and stops with the instruction's RVA and the reason when it meets anything else. A decoder that silently skipped an instruction would fabricate a successful unpack. Calls that leave the image are stubbed and recorded with a zero return, because resolving imports is the loader's job, not this loop's. Every write into the image is recorded as an `SMCWrite`, so the module feeds `analyze_smc` the same shape of evidence a runtime watch produces.

`offline_unpack` composes the two offline analyses in the order an unpacker asks them: `identify` first, then the loop, gated on the verdict. The gate is a refusal to guess. An image identified as unpacked has no wrapper, and running the loop anyway would report a step cap as a finding rather than as the absence of one; so the loop runs only on a "packed" verdict, at either confidence. `offline_unpack_file` is the same over a path. Neither upgrades a low-confidence signal into a verdict, which is the rule `identify` itself follows.

### The gap

`packer` has no CLI command. `main.cpp` does not reference it. Its output is consumed by `inspect` and the tests.

---

## DBI

`dbi/dbi.h`, `dbi/dbi.cpp`

Dynamic binary instrumentation. The pipeline is decode, split, rewrite, execute: a guest region is decoded, split at basic-block boundaries, rewritten with instrumentation calls, and executed from the rewritten buffer.

`dbi.cpp` is the only file. `Coverage` is `std::uint8_t map[1 << 16]` plus an edge counter and a hit counter, and the map is indexed by a hash of `(from, to)` rather than by a block id -- the same directional-edge state that makes AFL's coverage map useful. `edges` counts distinct edges and `hits` counts total crossings, so the type measures both reach and frequency and a consumer picks the one it means.

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

`doctor.cpp` is what `occ doctor` runs. It reports what this host can and cannot do, drawing on the `syscall` capability table, the container state, and the observer's probe table -- the last one next to whether this host can place any of it, so that "no probes were placed" is never read as "there were none to place". This is the honest answer to "what works here", and it is the reason the project does not need to pretend its API coverage is complete.

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

Fuzz targets for the parsers. `OCC_ENABLE_FUZZ` compiles them with `-fsanitize=fuzzer-no-link,address,undefined` and links each harness with `-fsanitize=fuzzer,address,undefined` from `fuzz/CMakeLists.txt`; the split exists because libFuzzer's archive contributes a `main()` and the `occ` binary has one of its own. Turning the option on also forces `OCC_STATIC_LINK` off -- a sanitized fully static binary is not something the linkers produce -- and so does any build whose flags carry `-fsanitize`, whether or not this option is what put them there.

---

## Util

`util/log.h`, `util/fs.h`, `util/string.h`, `util/span.h`, `util/errno.cpp`, `util/log.cpp`, `util/fs.cpp`, `util/string.cpp`

Logging, filesystem helpers, string helpers, spans. `span.h` is header-only.

---

## Cross-cutting conventions

**No exceptions, no RTTI.** `occ_core` is built with `-fno-exceptions -fno-rtti`. Failures travel as `Result<T>` or out-parameters. This is why `Result<T>` exists at all.

**Warnings are errors.** `-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wcast-qual -Wdouble-promotion -Wformat=2 -Wundef -Wnull-dereference -Wimplicit-fallthrough` plus `-Werror`, controlled by `OCC_WERROR`. `-Wconversion` and `-Wsign-conversion` are on, which is why the relocation code computes `delta` unsigned and why the capacity checks exist.

**Fixed sizes for wire structures.** TEB is 8 KiB, PEB is 4 KiB, `MemoryBasicInformation` is 48 bytes, `DispatcherContext` is 0x50 with a `static_assert` on each field offset the SEH dispatcher reads. These are not preferences; they are the shapes the guest reads. The event stream is the exception that proves the rule: it has no fixed record at all, because the body is built as JSON where the fact is observed, and there is nothing to `static_assert`.

**No third-party runtime dependencies.** The build needs a C++23 compiler and CMake. Nothing else.

**Determinism where it is observable.** Base placement is a deterministic downward scan. Given the same input, the same base comes out. Reproducible analysis depends on it.

---

## Known gaps

Stated plainly, because a document that does not list them is marketing.

- `packer`, `dbi`, and `emu` have no CLI entry points. They are libraries with tests.
- MachO is detected but not parsed.
- `modules.cpp`'s `kCrtForwarders[]` lists roughly 50 names with no corresponding registration.
- The API surface is large but not complete. Guests that lean on undocumented behavior or deep driver assumptions can still find a hole.
- Coverage instrumentation is not supported in the build.

`occ doctor` reports the host-specific half of this list at runtime.

---

Related: [RUNTIME.md](RUNTIME.md) for the runtime in detail, [BUILD.md](BUILD.md) for build options, [COMPAT.md](COMPAT.md) for the API surface, [EVENTS.md](EVENTS.md) for the event stream, [RSP.md](RSP.md) for the debug protocol, [ROADMAP.md](ROADMAP.md) for what is planned, [SECURITY.md](SECURITY.md) for the threat model.
# occ

[![C++23](https://img.shields.io/badge/C%2B%2B-23-00599C?style=flat-square&logo=cplusplus&logoColor=white)](https://en.cppreference.com/w/cpp/23)
[![Platform](https://img.shields.io/badge/platform-Linux_x86--64-1793D1?style=flat-square&logo=linux&logoColor=white)](#building)
[![Dependencies](https://img.shields.io/badge/dependencies-none-2ea44f?style=flat-square)](#building)
[![Link](https://img.shields.io/badge/link-static-6e7681?style=flat-square)](#building)
[![Build](https://img.shields.io/badge/build-CMake-064F8C?style=flat-square&logo=cmake&logoColor=white)](#building)
[![Issues](https://img.shields.io/badge/issues-welcome-6f42c1?style=flat-square)](../../issues)

A Windows PE runtime for Linux. It maps the image into its own address space, builds the Windows structures the guest expects, and runs the guest's own instructions on the host CPU. No hypervisor. No instruction translation on the fast path. No Wine underneath.

The guest is native code on a thread of this process. There is no boundary to reach across, so there is nothing to pay for one: no context switch per observation, no page-table shadow, no stop-the-world rendezvous. The debugger and the guest share one address space and one register file, and the parts of this project that look unusual are unusual because of that one fact.

```
src/parser/     format detection and parsing (PE, ELF)
src/engine/     one engine per format family, each driving a run
src/runtime/    the guest runtime: loader, ntdll, SEH, TLS, the ABI bridge,
                the API surface, guest threads, the debugger, memwatch
src/runner/     the run and debug drivers
src/isolation/  seccomp and container
src/observer/   the event stream, the session registry, the GDB protocol
src/devirt/     lift, normalize, bit-blast, solve, rebuild, certify
src/concolic/   taint, bit-precise flow, path exploration
src/deobf/      control-flow flattening, MBA, opaque predicates
src/packer/     identification, SMC, the ESP law
src/dbi/        block splitting, edge coverage, a load-time rewriter
src/emu/        an x86-64 interpreter for code that must not run
src/behave/     API behaviour sandbox
src/inspect/    static reports
src/syscall/    typed syscall wrappers, capabilities, errno
tests/          one file per area
fuzz/           libFuzzer harnesses for the parsers and the protocol
tools/apiwork/  the generator for the generated API surface
```

194,008 lines of hand-written product code, 89,753 lines of generated API surface, 65,588 lines of tests. C++23, no third-party runtime dependencies, statically linked.

---

## Contents

- [Not Wine. Not an emulator. Not a tracer.](#not-wine-not-an-emulator-not-a-tracer)
- [The runtime](#the-runtime)
- [The debugger](#the-debugger)
- [Isolation](#isolation)
- [Anti-analysis](#anti-analysis)
- [De-virtualization](#de-virtualization)
- [The analysis libraries](#the-analysis-libraries)
- [Commands](#commands)
- [Environment](#environment)
- [Building](#building)
- [Reading the source](#reading-the-source)

---

## Not Wine. Not an emulator. Not a tracer.

The three things this is usually mistaken for, and what is actually true instead.

**Wine** re-implements the Windows API on top of a real Linux process model and lets a PE call into it. That works, and it is a different project with a different goal. This one re-implements the *runtime*: the loader's behaviour, the TLS and exception machinery, the process environment, the ABI that carries a call from guest code into a simulation and back. There is no PE-side loader calling a Unix-side dlopen. The guest is a thread that *is* the guest.

**An emulator** translates or interprets instructions. Nothing here does on the PE path. The CPU executes the guest's instructions as its compiler emitted them, at native speed, because they are native. What is simulated is the environment, not the machine.

**A ptrace debugger** sits outside its target and pays a syscall for every observation. The PE path never calls ptrace, and not as a policy choice: there is no separate process to attach to. `procfs` is still how guest memory is read -- `pread` on `/proc/self/mem` -- but a breakpoint is a conversation between two sides of an atomic, not a wait on a stopped process. The observer layer does use ptrace, for the case it exists for: a host process that needs watching, which is a different thing from a guest that needs running.

The consequence worth stating plainly, because it is the reason any of this is shaped the way it is: **a hardware breakpoint never writes a byte of the guest's code.** An INT3 breakpoint displaces the original byte, hides the displacement from the guest's exception handler, and puts it back -- and a program that checksums its own `.text` finds the seam no matter how carefully it is covered. Hardware breakpoints use a debug register, single-step, and compare. For that class of guest the difference is not an optimization.

---

## The runtime

### Parsing and mapping

Format detection reads the bytes and not the name: an `app.apk` that is an ELF binary and a file called `image` that is an Android package are both real, and a decision taken from the extension is a confident wrong answer. `occ check` prints the decision, the evidence it was taken from, and -- since recognising a format and being able to act on it are different questions -- whether the loader could actually take the file.

Its own PE parser: DOS and NT headers, sections, imports, exports, relocations, and the data directory table, with a diagnostic for every fact it could not decide rather than one error that stops at the first. `src/parser/` is a static reader -- it turns a byte range into a description of what has to be mapped where, and executes nothing, which is what makes it testable against a corpus of hostile files.

The two judgements it makes are separate on purpose. `is_pe()` says whether the file is a PE at all; `loadable()` says whether its layout can be trusted. A file that is a PE with an untrustworthy layout is a real case, and the diagnostics say what was lost instead of collapsing the two into one refusal. Every bound is a subtraction, because `off + n > size` wraps, and a check that wraps passes and the read after it is out of bounds.

The mapper places the image at a chosen base, applies the relocation types the format defines -- `HIGH`, `LOW`, `HIGHLOW`, `HIGHADJ` and `DIR64`, with `ABSOLUTE` recognised and skipped because it is padding between blocks rather than a fixup, and applying it would write zeros through a section -- and rebuilds the import address table. Base selection prefers a suggested address when it is free, falls back to scanning, and reports which it took, because a guest that reads its own load address notices.

### Loading

Header validation before anything is mapped: alignment, section bounds, entry point, directory ranges. The loader then runs TLS initializers and the image's own entry callback the way a Windows loader does, because guests check. The order is not incidental -- a dependency's `DLL_PROCESS_ATTACH` has to have run before a dependent's, and every DETACH has to run in exactly the reverse order, and a runtime that got that wrong would be correct until the moment a guest relied on it.

### The Windows environment

Guest TLS with the real x64 layout. A TEB and a PEB the guest can walk with the field offsets its compiler baked in, reached through `GS` set by `arch_prctl`. SEH: unwind tables parsed from the image, dispatcher walk, a frame chain the guest can traverse, and the `__except` filter contract honoured rather than approximated.

### The API surface

`src/runtime/api/` is the hand-written surface: kernel32 across contexts, files and I/O, strings and code pages; ntdll's `Rtl*`, its memory and string functions, its debug and file entry points; the C runtime across the MSVC generations from 2.0 through the 140 toolset, and the UCRT; advapi32's registry, security descriptors, tokens and access checks; gdi32; user32; shell32; shlwapi; crypt32; rpcrt4; ws2_32; wininet; ole32; dbghelp; setupapi; iphlpapi; psapi; version; and the winmm console.

`src/runtime/api/generated/` is the rest. Every name the platform's own import libraries list that the hand-written surface did not answer, each carrying the signature the platform's headers declare. The signatures are read through the preprocessor rather than scanned out of the text, because a declaration is spelled `WINBASEAPI BOOL WINAPI f(...)` and a scan that takes the last word of the prefix answers `WINAPI` -- a calling convention read as a return type, which is a call whose answer the caller reads out of a register nobody wrote.

A generated entry point is one of two things, and each says which in the file that holds it. Where the behaviour is a property of a format or of arithmetic -- the path grammar, the bounded string helpers, the interlocked and bit-test families, the profile files, the DOS time conversions, the shell's size and interval formatters -- it is implemented. Where the subsystem is simply not here, it refuses through `ERROR_CALL_NOT_IMPLEMENTED`, with a comment naming the subsystem that would have to exist.

The refusal is the honest answer and not a placeholder. A guest handed a window handle for a window that was never created will use that handle four more times and then free it, and the failure surfaces somewhere else entirely, in code with no reason to suspect what went wrong. A guest told the call is unavailable takes the branch it already has for that answer. `tools/apiwork/` is the generator; it is checked in, and so are the files it writes, because a file nobody reads is a file nobody has audited.

### API set resolution

Windows ships an indirection layer: a binary imports `api-ms-win-core-file-l1-2-0`, and a table in the host decides which real module that names. The table is reproduced here, matched on the contract's own name -- lowercased, with the `.dll` the import table appends stripped off -- rather than on the file name. A contract the table does not carry resolves to nothing, and the loader turns that into a load failure naming the contract, which is more useful than a guess at a module that might have it. The `ext-ms-win-` extension contracts go through the same table.

### Libraries

`occ dll` treats a DLL as what the loader would: a module with entry points, dependencies, and a lifecycle. Dependencies load first, recursively, and every `DLL_PROCESS_ATTACH` runs before the library's own code is reached. Loading is two passes over the dependency graph -- map everything, then resolve -- which is what makes a circular dependency a property of the graph rather than a deadlock, and it is also what Windows does. The library's own directory is searched for its dependencies before anywhere else, as it would be with a loader that has no search path configured.

### Guest threads

Real threads. Each gets its own TEB and its own stack, with `arch_prctl` setting the GS base, so guest code reaches its TEB at the offset it was compiled against. Creation, exit, the start routine, and `WaitForSingleObject` on a thread handle all go through the same path whether the thread was created by the guest or by the runtime on its behalf.

### 32-bit images

A 64-bit process cannot execute 32-bit code by jumping into it; the mode switch is the kernel's business. `occ run32` reads the instructions and does what they say -- an interpreter with its own register file, its own flags, and a memory model that is the guest's alone. It is slower than the native path by orders of magnitude, and it is the only route a 32-bit image has. The engineering question was never interpreter versus native. It was interpreter versus refusal.

---

## The debugger

Because the guest is native code in this address space, a stop is not a stopped process. It is the guest's own thread parked inside the signal handler, on a spin, holding its register state in a copy the driving thread can read and change. The driving thread lives in the same address space; it reads guest memory directly and resumes the guest by writing the atomic the parked thread is watching. That is the entire protocol between them.

Software breakpoints (`b`) and hardware breakpoints (`hb`) are both there and are not interchangeable. `del` and `hbd` disarm. `breaks` lists both. `r` runs, `s` steps, `regs` dumps the register file, `x` examines memory, `disas` disassembles, `mdmp` writes a minidump of the stopped guest, `q` quits. The whole thing runs from the command line, with `--script` to drive it from a file.

`memwatch` is the other instrument, and it works the way the address space allows: a watched page loses its write permission, and the first store into it raises `SIGSEGV` -- the same signal a null dereference raises, and the same handler, which is why the watch integrates with fault handling rather than sitting beside it. `OCC_MEMWATCH` names the pages. For a program that decrypts itself in place, catching the decryption write at the moment it happens is the difference between reading a packed image and understanding it.

A stock debugger can attach too. The runtime serves the GDB Remote Serial Protocol over a loopback socket (`--gdb-port`, `--gdb-wait`), so gdb, lldb, or any editor that drives them attaches without a plugin. The port is printed before the target starts, and `--gdb-wait` holds the target at its first stop until a debugger connects -- which is what makes `break main` work instead of racing the program's first instructions.

### Observation without a debugger

`run` writes one JSON object per line to stdout when stdout is not a terminal, and suppresses the stream when it is, so an interactive run shows only the target's own output. The line-oriented format is chosen because the stream is readable while the run is going: a consumer tails it, parses one object at a time, and never holds the run in memory. A session outlives the process that started it -- the observation stream stays open, the registry holds it -- and `occ attach` reconnects to one by id or by pid, which is what makes a long run inspectable without babysitting it.

### Watching a program that is not this runtime's guest

`--observe` traces a target that is a host process, whoever runs it. For a PE program running under Wine, that is the case the ntdll probe table exists for. Wine's own syscalls are not distinguishable from the target's -- `NtCreateFile` becomes an `open`, `NtWriteFile` becomes a `write`, and the loader opening its own libraries looks the same -- but the call site is unambiguous. Wine's Unix-side ntdll is host-native ELF with real exported addresses, so a uprobe at one of them fires exactly when the Windows program asked for that service and never when Wine asked for something of its own. Each entry in the table carries the symbol to find, the category it belongs to, and the parameter names to print, because a report that says `r1=3 r2=0x7ffe1234` is a report nobody reads.

---

## Isolation

`seccomp` filter bytecode is emitted by this project rather than delegated to a library. The reason is that the kernel only ever executes bytecode: a library adds a policy compiler and a syscall-name table pinned to the library's release rather than to the kernel the filter runs on, and both of those are things this project would then have to trust. The filter is default-closed, and it closes the x32 bit-30 hole, which is the one a naive whitelist leaves open on a kernel that accepts the x32 ABI.

The container is a process tree with its own mount table, its own pid space, and its own root. No hypervisor, no kernel module -- composed from primitives the kernel already exposes, which is why the setup path reads as a sequence of small steps rather than one call. `--root`, `--overlay`, `--upper`, `--work`, `--bind`, `--rw-bind` shape the filesystem. cgroup v2 limits cover memory, pids and cpu bandwidth when the host has the controllers.

Path containment uses `openat2` where the kernel has it: a single atomic syscall that resolves a path and checks it stays inside the root, with no window between the resolution and the check. The escape hatches -- `--no-seccomp` and `--no-container` on `run`, and their environment twins -- exist and are documented, because a host whose kernel lacks a feature needs a way through, and a hidden one is worse than a stated one.

---

## Anti-analysis

A guest that was written to defend itself looks at the debugger-shaped objects a normal Windows process would have. `src/hostile/` makes those objects answer the way an undebugged process would, and the important property is consistency rather than any single answer: the same process queried through different namespaces has to report the same thing, because the guest is usually comparing two answers, not reading one.

The clock model is the clearest case. A guest that reads a monotonic clock and a system clock and compares them will find a lie if the two are simulated independently. There is one clock model, and both readers go through it. The debug registers in a guest's `CONTEXT` stay zero and, just as importantly, their bits are not claimed in `ContextFlags` -- a guest reading `Dr0` of a process that has no hardware breakpoints expects a zero and a flag saying the field means nothing, and a runtime that filled the field without setting the flag would be answering a question the guest did not ask. The fingerprint table spans the namespaces a guest is likely to probe, and the surface is `NtQueryInformationProcess`, `CheckRemoteDebuggerPresent`, `IsWow64Process`, `NtQuerySystemInformation`, the PEB's own fields, and the timing checks that follow from them.

---

## De-virtualization

`occ devirt` takes two files -- a dispatch trace and a decrypted image dump -- and answers what a code-virtualizing packer's interpreter actually computes. Everything about it is offline. It never touches a running process, which is a design constraint and not a convenience: the alternative is a tool whose result depends on the machine it was observed on.

**Lift.** Each handler is lifted into a model: how it moves the virtual stack pointer, how it advances the bytecode cursor, what it writes into the stack slots, where it dispatches. The junk the packer wraps around it is discarded because the model is built from effect, not from instruction text.

**Convention inference.** A packer variant that was built on a different register assignment cannot be lifted by assuming the known one. `adapt` infers the stack and cursor roles from how the handlers index, and it does so from the trace alone -- no assumption about which registers the variant chose.

**The expression DAG.** A hash-consed SSA representation over bit-vectors. Nodes are constants, inputs, and operations; identical operations on identical inputs are one node, which is what keeps the growth of a long handler chain linear rather than exponential.

**Normalization before the solver.** A bit-vector expression built from constants, addition, subtraction, negation and multiplication is a polynomial over `Z/2^w`, and polynomials have a normal form. `ring` computes it, which is the difference between a SAT query that answers in milliseconds and one that answers in the lifetime of the process: multiplier equivalence is the textbook hard instance for a CDCL solver, and `(x + 3) * (y - 3)` is ordinary virtual-machine code.

**Bit-blast and solve.** What is left is translated to CNF by Tseitin encoding and handed to a CDCL solver built for this purpose. The solver is real and not an evaluator: the inputs are 64-bit, and `2^64` is not a table.

**Naming.** The semantic recognition layer turns handler models back into virtual instructions -- a handler that does `slot 0 += slot 1; rbp += 8` is an `add`, one that pulls a bytecode byte into the top slot and advances the cursor is a push of an immediate, one that reads a word, decrypts it and jumps there is the dispatch. Recovered semantics are the answer to "what does this engine do".

**Rebuild and certify.** `codegen` emits linear x86-64-shaped IR that recomputes the model's effects from the entry state, and `cert` attaches the evidence to every claim: which handlers are covered, which CFG edges stay inside the reachable set, whether the rebuilt code is equivalent to the virtual stream, each with the check that produced it so the claim can be audited without re-running the pipeline.

**Ask it a question.** A goal is written in a small language over the machine's own state -- the recovered register file, the bytecode buffer, the virtual stack, memory at a width you choose -- with the usual operators. That is what turns "what does it do" into "what input does it accept", which is the question a crackme poses. `--explore` goes further and enumerates where a dispatch could have gone instead.

---

## The analysis libraries

These are the analysis libraries. They are linked into the build, they are driven by the layers above them, and each has tests of its own.

**`packer`** answers the three questions an unpacker asks in order. Identification is deliberately offline and every answer is a weighted sum of independent observations -- section names, the entry point's shape, the import table, the entropy profile -- so the answer comes with its reasons. SMC detection finds where an image decrypts itself. The ESP law recovers the original entry point from the stack balance: the wrapper pushes a register state, runs its loop, pops it back, and transfers -- so the OEP is the first control transfer that happens with the stack balanced and outside the wrapper.

**`concolic`** carries a taint engine and a bit-precise one. The first answers which inputs can influence a value; the second answers which *bits* of which inputs can influence which *bits* of this value, the way a production bit-level tracker does. On top of that sits path exploration, which turns a symbolic constraint into a concrete input.

**`deobf`** is three passes that are deliberately separable. Control-flow flattening recovery recognizes OLLVM's dispatcher, propagates the state constant through each block, and rewrites every edge that pointed at the dispatcher to the case target its state value names. MBA simplification reverses the arithmetic identity rewrites (`x + y` spelled `(x | y) + (x & y)`) in two fragments, a polynomial one and a boolean one, over the same `Z/2^w` ring the de-virtualizer uses. Opaque-predicate elimination proves the canonical constant conditions -- `(x*x - x) & 1 == 0`, `x & ~x == 0`, `x | ~x == 0xff` -- and removes the branches behind them. The order matters and is enforced: a predicate edge grafted onto a dispatcher would make dispatcher recognition fail.

**`dbi`** splits blocks, records edge coverage into a bitmap with count buckets, and rewrites an image at load time. Coverage is a different question from tracing: the analyst wants to know which code ran, at block granularity, cheaply enough to run for the whole of a run.

**`emu`** interprets a region of x86-64 bytes on a private register file and a private memory model. A packer decrypts a function and jumps into it; an anti-analysis stub reads the code it is about to execute; a VM steps through its handlers one byte at a time. All of those want the answer to "what would this code do" without the code running where anything can watch it.

**`behave`** is the API behaviour sandbox: calls happen under observation, the ones the analyst does not want reaching a real resource are denied or simulated, and everything that did happen leaves a structured record. The split into five pieces keeps the integration point small enough to read in one sitting.

**`probe`** places the probes an engine asked for. A request names a module and a symbol; a uprobe needs a path and a file offset, and the step between them is where the interesting failure lives -- the module may not be the one the engine expected, because what is on disk is whatever the dynamic linker found. A placement the host cannot honour is reported in the stream and the run continues with syscall-level observation, so a stream carrying no probe hits is distinguishable from one whose probes were never placed.

**`replay`** owns the determinism contract, in the `rr` lineage: every external input -- API return values, asynchronous writes, randomness -- is recorded as an event and replayed identically, so a run that took an hour can be re-created from its log.

**`fuzz`** is coverage-guided fuzzing in the AFL lineage: a fixed-size edge bitmap with count buckets as the interestingness signal, mutation over the same inputs, and the crashing inputs reported. The harnesses in `fuzz/` drive the parser, the loader, the ELF reader, the RSP server, the seccomp compiler and the zip reader.

**`inspect`** is the static side: headers, sections, imports, exports, TLS, exceptions, resources, strings, and disassembly at a chosen RVA, all from a file that is never executed. `occ inspect` is its command.

---

## Commands

```
occ check <path> [--json]         detect the format, print the routing decision
occ run [options] <path> [args...]  run under isolation, start the observer
occ dbg <path> [--script <file>] [--break <rva>]... [args...]
                                  interactive debugger
occ attach [-p] <session-id|pid>  reconnect to a running session
occ stop [-p] <session-id|pid>    tear a session down
occ inspect <path> [--no-strings] [--disasm <rva>[:<count>[:<bytes>]]] [--limit <n>]
                                  static report
occ devirt <trace> <dump> [N] [--asm [N]] [-o <report>] [--unknown <va>:<size>]
                                  [--goal <condition>] [--explore]
                                  offline de-virtualization report
occ dll <file> <mode> [options]   load a library and drive its lifecycle
occ run32 <image>                 run a 32-bit image on the in-process interpreter
occ mdmp <file>                   summarize a minidump
occ doctor                        report what this host can and cannot do
```

`occ run` with no target prints its own option list, and it is long, because the isolation and observation knobs are the command. `occ devirt` and `occ dll` do the same for theirs.

`occ dll` has three modes. `attach` loads the library, runs its entry points in loader order, and detaches -- which is the mode to watch a module's load-time behaviour in. `call <export>` loads it and calls one export. `serve` loads it and reads calls from stdin. Arguments are typed on the command line because a file carries no signature: `i32:5`, `i64:0x10`, `ptr:0x1000`, `str:hello`, `f32:1.5`, `f64:2.5`. A string is copied into guest memory and its address passed, and the address is reported, because the caller may need it.

`occ run` under the `occ` engine is the PE path. `--observe` traces the target with ptrace as it runs -- the observer layer, for a target that is a host process. `--probe` places the probes the engine asks for. `--track-wx` watches for a page that is written and then executed. `--engine` names the engine explicitly, and the detection's own choice has to agree.

### A first run

```
occ check app.exe       what the file is, and whether this host can run it
occ run app.exe         run it, isolated, one JSON object per line on stdout
occ dbg app.exe         run it under the debugger
occ inspect app.exe     read it without running it
occ doctor              what this host can and cannot do
```

---

## Environment

A guest's behaviour is sometimes only reproducible with an instrument on, so the instruments are environment variables as well as flags.

| Variable | Effect |
|---|---|
| `OCC_MEMWATCH` | pages whose first write stops the guest |
| `OCC_VM_TRACE`, `OCC_VM_DISPATCH` | record a VM's dispatch trace for `occ devirt` |
| `OCC_DUMP_AT_OEP`, `OCC_DUMP_IMAGE` | dump the image when the wrapper hands over |
| `OCC_API_TRACE`, `OCC_GUEST_TRACE`, `OCC_TRACE_STEPS` | call and step records |
| `OCC_MINIDUMP` | write a minidump at a chosen point |
| `OCC_RNG` | seed the guest's randomness, so a run repeats |
| `OCC_PROBE` | force probe placement on or off |
| `OCC_NO_SECCOMP`, `OCC_NO_CONTAINER`, `OCC_PLAIN_SPAWN` | the isolation escape hatches |
| `OCC_SCRATCH_DIR`, `OCC_SESSION_REGISTRY` | where scratch state and sessions live |
| `OCC_EVENT_STREAM` | whether the event stream is written |

---

## Building

A C++23 compiler and CMake. Nothing to install.

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build -j8
```

The build is configured with `-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wcast-qual -Wdouble-promotion -Wformat=2 -Wundef -Wnull-dereference -Wimplicit-fallthrough`, all of them errors. If the warnings are on, the code has to be worth them. `-DOCC_ENABLE_FUZZ=ON` builds the libFuzzer harnesses; `-DOCC_USE_LIBCXX` and `-DOCC_LIBCXX_ROOT` select libc++ instead of libstdc++; `-DOCC_STATIC_LINK=OFF` leaves the binary dynamic. [docs/BUILD.md](docs/BUILD.md) has the rest.

---

## Reading the source

Start with [docs/DESIGN.md](docs/DESIGN.md) for the model before the code, or `src/runtime/pe_process.cpp` to see the guest fault handler that everything else hangs off. The runtime is the part with the most in it, and [docs/RUNTIME.md](docs/RUNTIME.md) is long because the runtime is.

Two things are worth knowing before reading anything in `src/`: the syscall layer deliberately does not include `<errno.h>` (its values are written out, because the whole point of returning a `Result` is that no thread-local error state exists), and the API simulations are grouped by domain with one file per domain and one registration function each, so a name can be found by knowing what it does rather than by searching for it.

| Document | What it covers |
|---|---|
| [docs/DESIGN.md](docs/DESIGN.md) | the model, the module map, the dependency direction |
| [docs/RUNTIME.md](docs/RUNTIME.md) | the loader, the environment, the API surface, the debugger |
| [docs/COMPAT.md](docs/COMPAT.md) | what is answered, what is refused, and how the surface is organized |
| [docs/SECURITY.md](docs/SECURITY.md) | the threat model and the isolation boundary |
| [docs/EVENTS.md](docs/EVENTS.md) | the event stream: kinds, sinks, sessions, probes |
| [docs/RSP.md](docs/RSP.md) | the remote debug protocol |
| [docs/ROADMAP.md](docs/ROADMAP.md) | what comes next |
| [docs/BUILD.md](docs/BUILD.md) | build options and the toolchain probes |
| [CONTRIBUTING.md](CONTRIBUTING.md) | how to work on it |

---

Everything here follows from one decision, and the decision is in the first line: the guest runs on a thread of this process. Where that makes something possible that a separate-process design cannot do -- a breakpoint that never writes a byte of guest code, a watch that catches a decryption store at the moment it happens, a call observed with no boundary to cross -- it is done. Where it makes something impossible, the code says so and the documents say so. A limit stated is one you can plan around; a limit hidden is one you find out about at the worst possible moment.

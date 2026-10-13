# occ

A Windows PE runner that does not install Windows, does not emulate a
CPU, does not call ptrace, and does not ask Wine for anything. It maps
the image into its own address space, builds the Windows structures the
guest expects, and runs the guest's own code directly on the host CPU,
trapping the exceptions and intercepting the API calls itself.

The guest is native code on this process's main thread. There is no
boundary to reach across, which is why none of the usual machinery is
here: no ptrace, no QEMU, no virtual memory tricks. A "stop" is the
guest's own thread parked inside a signal handler, holding its register
state in a copy the debugger can read and change.

C++23. Zero third-party runtime dependencies. Statically linked. About
146k lines including tests.

## What this is not

- **Not Wine.** Wine re-implements the Windows API on top of a real
  Linux process model and lets the PE call into it. This project
  re-implements the *runtime*: a subset of ntdll, the loader behavior,
  SEH, TLS, the process environment, the API surface that matters, and
  the Windows ABI that carries calls through it. The guest runs in a
  thread that *is* the guest, not a process pretending to be one.
- **Not an emulator.** The CPU executes the guest's instructions
  directly. No translation, no interpretation, no JIT. What is
  simulated is the environment, not the machine.
- **Not ptrace-based.** A ptrace debugger sits outside the target and
  pays a syscall for every observation. Here the debugger and the
  target share one address space and one thread of execution; reading
  guest memory is a pread on /proc/self/mem, and a breakpoint is a
  conversation between two sides of an atomic, not a wait on a
  stopped process.

## What it does

- **PE parsing and mapping.** Its own parser (not libbfd, not
  llvm-objdump) for headers, sections, imports, exports, TLS, and
  exceptions, and its own loader that maps the image, rebuilds the
  import address table, applies relocations, and runs TLS
  initializers -- the way a Windows loader would, because guests
  notice when the loading is done differently.
- **A Windows runtime on a Linux thread.** Guest TLS, TEB/PEB, SEH
  dispatch, stack switching, a ntdll subset, apiset resolution, and a
  growing library of API simulations from kernel32 and the UCRT out
  to advapi32, crypt32, gdi32, shell32, user32, and friends. Each one
  is a deliberate re-implementation with real semantics, not a stub
  that returns zero.
- **Isolation.** A seccomp filter and a container layer when you want
  them, and a plain spawn when you do not. The sandbox is the default;
  `--no-container` and `OCC_PLAIN_SPAWN=1` are the escape hatches for
  guests that need the host.
- **A debugger that does not patch.** Normal breakpoints are INT3
  bytes with displaced originals kept so a hit can restore and re-arm
  behind the guest's back. Hardware breakpoints (`hb`) single-step the
  guest with the trap flag and compare the address about to run against
  the list -- no byte of the guest's code is ever touched, which is the
  point for programs that integrity-scan their own .text. `step`,
  `regs`, and `x` (memory examine) round it out, and `OCC_MEMWATCH`
  watch pages catch decryption writes at the moment they happen.
- **De-virtualization.** `devirt` takes a dispatch trace and a decrypted
  image dump and lifts the VM dispatch loop to expressions, bit-blasts
  them, and answers the underlying computation with a SAT solver.
  Offline, from files, not from a running process.
- **Observation without the debugger.** An event stream (syscalls,
  uprobes, watchpoints, registry access, the WX state of pages) that a
  session records and `attach` can reconnect to, so a long run can be
  inspected without babysitting it.

## Commands

```
occ check <path>      detect the format and print the routing decision
occ run <path>        run under isolation and start the observer
occ dbg <path>        interactive debugger (script with --script)
occ attach <session>  reconnect to a running session
occ stop <session>    tear a session down
occ inspect <path>    static report: headers, sections, imports, exports,
                      tls, exceptions, resources, strings
occ devirt <trace> <dump>  offline VM de-virtualization report
occ doctor            report what this host can and cannot do
```

The debugger's REPL: `b`/`break` and `hb` arm breakpoints (INT3 and
hardware), `del`/`hbd` disarm them, `breaks` lists both, `r` runs,
`s` steps, `regs` shows the register file, `x` examines memory,
`mdmp` writes a minidump of the stopped guest, `q` quits.

Environment knobs a run understands: `OCC_GUEST_TRACE`, `OCC_API_TRACE`,
`OCC_MEMWATCH`, `OCC_TRACE_STEPS`, `OCC_DUMP_IMAGE`, `OCC_DUMP_AT_OEP`,
`OCC_MINIDUMP`, `OCC_VM_TRACE`, `OCC_VM_DISPATCH`.

## Building

A C++23 compiler (clang recommended) and CMake. No third-party
libraries. The build is one command:

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## Status, honestly

The loader and the common API surface are solid enough that the test
suite covers kernel32, the UCRT, ntdll, advapi32, crypt32, shell32,
user32, and friends, with fuzzers for the PE/ELF/RSP/seccomp parsers
and mutation tools that flip bytes and re-run. Real guests this has
seen: a seven-layer packed crackme whose layers it unpacked to a
working image, and an 8/8 crackme it evaluates correctly.

What is honest about the limits: not every Windows API is simulated,
and the API family grows one test at a time. Guests that lean on
undocumented behavior or deep driver assumptions can still find a gap.
The project does not pretend otherwise -- the `doctor` command prints
the capabilities and the gaps of the host it runs on.

## Reading the source

```
src/parser/     PE/ELF detection and parsing
src/engine/     format engines that drive a run
src/runtime/    the guest runtime: loader, ntdll, SEH, TLS, API sims,
                guest threads, memwatch, the debugger, vm tracing
src/runner/     run and dbg drivers
src/isolation/  seccomp and container
src/observer/   the event stream: probes, watchpoints, registry, rsp
src/devirt/     lift -> bit-blast -> SAT de-virtualization
src/inspect/    static analysis reports
tests/          API simulations and runtime behavior, one file per area
docs/           BUILD, COMPAT, DESIGN, EVENTS, ROADMAP, RSP, RUNTIME,
                SECURITY
```

Start with `docs/DESIGN.md` if you want the model before the code, or
`src/runtime/pe_process.cpp` if you want to see the guest fault handler
that everything else hangs off.

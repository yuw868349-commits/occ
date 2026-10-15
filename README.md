# occ

A Windows PE runner for Linux that does not install Windows, does not emulate a CPU, does not call ptrace, and does not ask Wine for anything.

It maps the image into its own address space, builds the Windows structures the guest expects, and runs the guest's own code directly on the host CPU. Exceptions are trapped. API calls are intercepted. That is the whole trick, and there is not much more to it than that.

The guest is native code on this process's main thread. There is no boundary to reach across, which is why none of the usual machinery is here: no ptrace, no QEMU, no virtual memory games. A "stop" is the guest's own thread parked inside a signal handler, holding its register state in a copy the debugger can read and change.

C++23. Zero third-party runtime dependencies. Statically linked. Roughly 180,000 lines of product code and 60,000 more of tests.

---

## This is not Wine, and it is not an emulator

**Wine** re-implements the Windows API on top of a real Linux process model and lets the PE call into it. This project re-implements the *runtime*: a subset of ntdll, the loader's behavior, SEH dispatch, TLS, the process environment, the API surface that matters, and the Windows ABI that carries calls through all of it. The guest runs in a thread that *is* the guest, not a process pretending to be one.

**An emulator** translates or interprets instructions. Nothing here does. The CPU executes the guest's instructions as they were compiled. What is simulated is the environment, not the machine.

**A ptrace debugger** sits outside the target and pays a syscall for every observation. Here the debugger and the target share one address space and one thread of execution. Reading guest memory is a `pread` on `/proc/self/mem`. A breakpoint is a conversation between two sides of an atomic, not a wait on a stopped process.

The consequence of that last one is worth stating plainly, because it is the thing this project is actually about: **a hardware breakpoint never writes a byte of the guest's code.** INT3 breakpoints displace the original byte and put it back behind the guest's back. Hardware breakpoints single-step and compare. For a program that integrity-scans its own `.text`, the difference is not a detail.

---

## What it does

**PE parsing and mapping.** Its own parser for headers, sections, imports, exports, TLS, exceptions, resources, and delay imports, and its own loader that maps the image, applies the full relocation type set, rebuilds the import address table, and runs TLS initializers the way a Windows loader would, because guests notice when loading is done differently.

**A Windows runtime on a Linux thread.** Guest TLS, TEB and PEB with the real x64 layouts, SEH dispatch and stack unwinding, a ntdll subset, API set resolution, and 12181 registered exports across 76 modules: kernel32, the UCRT and the classic C runtime across eleven MSVC versions, a large `Rtl*` surface, GDI, USER32, Winsock, crypt32, advapi32 including the whole registry family, rpcrt4, dbghelp, and the rest.

Of those exports, 6389 are hand-written re-implementations with real semantics, and 5792 are the generated surface: one entry point per name the platform's import libraries list that this runtime does not answer, each with the signature the platform's own headers declare. 200 of the generated names are implemented -- the path grammar, the bounded string helpers, the interlocked family, the profile files, the formatters -- and the other 5592 refuse, through `ERROR_CALL_NOT_IMPLEMENTED` and a comment naming the subsystem that would have to exist.

A refusal is not a stub returning zero for a call that worked. It is the answer Windows gives for an entry point whose subsystem is not present, and the distinction matters: a guest told that a window was created holds a handle it will use four more times, and the failure that follows lands in code with no reason to suspect what went wrong. A guest told the call is unavailable takes the branch it already has for that answer.

**Guest threads.** Real threads, each with its own TEB and stack, with `SYS_arch_prctl` setting GS base so guest code can reach its TEB the way it was compiled to.

**Isolation.** `openat2` containment that resolves and checks in one atomic syscall, a seccomp filter compiler that is default-closed and closes the x32 bit-30 hole, and a container that is on by default. The escape hatches are documented rather than hidden.

**Anti-analysis.** Consistent answers across `NtQueryInformationProcess`, `CheckRemoteDebuggerPresent`, and `IsWow64Process`. One monotonic clock model, so a guest that reads two clocks and compares them finds no lie. A curated fingerprint table across eight namespaces. Debug registers that read as clean.

**De-virtualization.** `devirt` takes a dispatch trace and a decrypted image dump, lifts the VM's dispatch loop to a hash-consed expression DAG, bit-blasts it, and answers the underlying computation with a built-in CDCL SAT solver. The VM's register file and bytecode layout are inferred from how the handlers index, not hardcoded. A goal language lets you ask an arbitrary condition, not a pre-baked question. Offline, from files, never from a running process.

**Observation without the debugger.** An event stream a session records and `attach` can reconnect to, so a long run can be inspected without babysitting it. And a GDB-compatible remote serial protocol, so a stock GDB can attach and debug the guest.

---

## Commands

```
occ check <path> [--json]     detect the format, print the routing decision
occ run [options] <path> [args...]
                              run under isolation, start the observer;
                              'occ run' with no target prints the option list
occ dbg <path> [--script <file>] [--break <rva>]... [args...]
                              interactive debugger
occ attach <session-id|pid>   reconnect to a running session
occ stop <session-id|pid>     tear a session down
occ inspect <path> [--no-strings] [--disasm <rva>[:<count>[:<bytes>]]]
                              [--limit <n>]
                              static report: headers, sections, imports,
                              exports, tls, exceptions, resources, strings
occ devirt <trace> <dump> [N] [--asm [N]] [-o <report>]
                              [--unknown <va>:<size>] [--goal <condition>]
                              [--explore]
                              offline VM de-virtualization report
occ dll <file> <mode> [options]
                              load a library and drive its lifecycle:
                              attach, call an export, or read calls from
                              stdin
occ run32 <image>             run a 32-bit PE image on the in-process
                              interpreter
occ mdmp <file>               summarize a minidump
occ doctor                    report what this host can and cannot do
```

`occ dll` loads a library rather than starting a program: the entry points
of the library and of every dependency it needs run in the order a loader
runs them, dependencies first, and then one of three things happens --
nothing (`attach`, which is the mode to watch a module's load-time
behaviour in), a call to one export (`call`), or a prompt (`serve`). The
arguments are typed on the command line (`i32:5`, `str:hello`, `f64:1.5`)
because a file carries no signature, and the library's own directory is
searched for its dependencies before anywhere else.

The debugger: `b` and `hb` arm breakpoints, software and hardware. `del` and `hbd` disarm. `breaks` lists both. `r` runs, `s` steps, `regs` shows the register file, `x` examines memory, `mdmp` writes a minidump of the stopped guest, `q` quits.

`OCC_MEMWATCH` watch pages catch a decryption write at the moment it happens, which is the difference between reading a packed image and understanding it.

---

## Building

A C++23 compiler and CMake. No third-party libraries, nothing to install.

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build -j8
```

86 tests. `-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wcast-qual -Wdouble-promotion -Wformat=2 -Wundef -Wimplicit-fallthrough`, all of them errors. If the warnings are on, the code has to be worth them.

---

## Status, honestly

The loader and the common API surface are solid. Real guests this has run: a seven-layer packed crackme whose layers it unpacked to a working image, and a crackme it evaluates correctly and solves.

What is honest about the limits:

- Not every Windows API is simulated. The surface grows one test at a time.
- `packer`, `dbi`, and `emu` are libraries with tests and no command. They are not features you can invoke.
- MachO is detected and not parsed.
- Coverage instrumentation does not exist in the build.
- The container contains paths and filters syscalls. It is not a hardened sandbox and does not claim to be.

`occ doctor` prints the capabilities and the gaps of the host it runs on. That command exists so the project does not have to pretend.

---

## Reading the source

```
src/parser/     PE and ELF detection and parsing
src/engine/     format engines that drive a run
src/runtime/    the guest runtime: loader, ntdll, SEH, TLS, ABI bridge,
                API simulations, guest threads, memwatch, the debugger,
                VM tracing, the 32-bit interpreter
src/runner/     the run and debug drivers
src/isolation/  seccomp and container
src/observer/   the event stream: probes, watchpoints, registry, RSP
src/devirt/     lift, bit-blast, SAT, solve, certify
src/concolic/   taint, bit-level propagation, path exploration
src/deobf/      control-flow flattening, MBA, opaque predicates
src/inspect/    static analysis reports
src/syscall/    kernel ABI, capabilities, errno translation
tests/          one file per area, 86 of them
docs/           BUILD, COMPAT, DESIGN, EVENTS, ROADMAP, RSP, RUNTIME,
                SECURITY
```

Start with `docs/DESIGN.md` for the model before the code, or `src/runtime/pe_process.cpp` to see the guest fault handler that everything else hangs off.

`docs/RUNTIME.md` is the long one. It is long because the runtime is.
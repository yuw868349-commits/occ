# Occ

A dynamic execution runtime for reverse engineering.

Occ runs a target binary and reports what it actually does — syscalls,
memory events, register state — without analyzing it. Analysis is left to
the tools you already use: gdb, pwndbg, GEF, Frida, Ghidra, radare2.

Occ does not disassemble. It does not unpack. It does not diff traces. It
executes under isolation and emits facts.

## Status

`occ run` executes a target and observes it. It does not dispatch on the
target's format: it will exec an ELF, and it will also exec a PE or an APK,
but the kernel's binfmt handler decides what that means, not this project.
`src/engine/` holds one engine per format — `exe_engine.cpp` for ELF,
`pe_engine.cpp` for PE, `apk_engine.cpp` for APK — and `engine.cpp` is the
table that names them. What each engine does with the format differs, and
the difference is stated where it applies rather than here: the ELF engine
runs the image, the PE engine runs it in the runtime this binary carries,
and the APK engine reads the package and refuses. See
`docs/ROADMAP.md` for the state of each part, including what is known to be
missing.

## What this is not

- Not a VM. There is no hardware virtualization anywhere in this codebase.
- Not a sandbox for hostile code in the general case. See `docs/SECURITY.md`.
- Not a debugger. It speaks the GDB Remote Serial Protocol so your debugger
  can attach; it is not one.

## Isolation model

Occ shares the host kernel. Isolation is namespace-, cgroup-, and
seccomp-based. This is the same class of isolation as a container runtime,
not the same class as a hypervisor. The distinction matters and is stated
plainly rather than papered over.

Every run gets:

- A user, PID, network, mount, UTS, IPC, and cgroup namespace.
- A new root built with `pivot_root` over an overlayfs whose upper layer is
  disposable and whose lower layer is never written.
- A cgroup v2 subtree with explicit limits.
- A seccomp-BPF filter, default-deny, built from an in-tree bytecode
  emitter.

The isolation layer is the security boundary of this project. Its seccomp
emitter is tested against filters the kernel actually installs — 91
assertions, and 37 of them are a forked child that installs a real filter
and makes a call the filter has an opinion about — and its container setup
is tested for the things that have to be refused, such as an overlay mount
with no upper directory, which must fail and say at which stage it failed.

It is not fuzzed. The emitter's input is a typed policy rather than bytes,
so there is nothing to hand a fuzzer that a caller controls; `fuzz/README.md`
explains what the six harnesses do cover and, at more length, what none of
them reaches.

## Privilege model

Occ requires root, or `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_BPF`,
`CAP_PERFMON`, `CAP_SYS_PTRACE`, and `CAP_SYS_RESOURCE`. It states this as
a requirement rather than working around it. `occ doctor` reports what the
current host actually grants.

Occ does not attempt to run as an unprivileged user. Container and CI
environments that withhold these capabilities are reported as unsupported
by `occ doctor` rather than silently degraded.

## Observation model

The target is not instrumented by Occ.

- Syscall tracing uses `PTRACE_SYSCALL`, with `PTRACE_O_TRACESYSGOOD` so a
  syscall stop is distinguishable from a real `SIGTRAP`. The register block
  is read at the stop.
- The isolation layer's filter is seccomp-BPF, assembled as an instruction
  array by an emitter in the tree. There is no libbpf, no BTF, no CO-RE,
  and no eBPF program anywhere in this codebase.
- Function-level monitoring uses uprobes through
  `perf_event_open(PERF_TYPE_BREAKPOINT)`, registered by writing a line into
  tracefs.
- Memory reads use `process_vm_readv` from outside the target.
- `ptrace` is used for process control only: stop, continue, single-step,
  and signal delivery. It is not used to patch target memory.

`ptrace` being present while "target unmodified" is claimed is not a
contradiction, and `docs/DESIGN.md` explains exactly where the line is.

## Event stream

All observation output is normalized into one event schema and written as
line-delimited JSON to a Unix domain socket. One JSON object per line, no
array wrapper. Dropped events are reported as their own event type rather
than silently lost.

The stream is never multiplexed onto stdout. When stdout is a TTY, `occ run`
prints a session summary table; when it is not, `occ run` prints the socket
path and the session id as a single NDJSON line. The event stream is always
read from the socket.

## Debugger interface

A GDB Remote Serial Protocol server, implemented in-tree, speaks the packet
set listed in `docs/RSP.md`: `qSupported`, `g`, `G`, `m`, `M`, `c`, `s`,
`Z`, `z`, `vCont`, `qfThreadInfo`, `qsThreadInfo`, and `qXfer`. Reads are
served from observer data. Writes go through `process_vm_writev` and
`PTRACE_SETREGSET` at a stop point.

## PE engine

The PE engine runs a PE32+ image itself, in the runtime this binary carries.
It asks the host for nothing. `plan` names this binary through
`/proc/self/exe` with a runner token after it, the container exec's that
pair, and the runner builds a Windows process out of the pieces in
`src/runtime/` — an address space, the image mapped into it, a stack, a TEB,
a PEB — and starts it at the image's entry point. There is no loader to
find, no prefix to build, and no library directory to bind.

What the image imports is answered from this binary. `KERNEL32.dll` and
`msvcrt.dll` resolve through the runtime's own export registry, so the API
a guest calls is code in this tree. `docs/RUNTIME.md` describes that surface
and the plan for growing it.

A 32-bit image is refused by name. The runtime carries amd64 and nothing
else, and a second runtime is not something this one grows into; the refusal
names the machine the image declares and the machine this build executes.

Fidelity is bounded by this runtime rather than by a Wine build. Timing-
sensitive, SEH-detail-sensitive, and undocumented-structure-sensitive
anti-analysis checks will diverge from genuine Windows, and some PE targets
will not reach a state with analytical value. The documentation says so
instead of implying universal coverage.

Function-level probes are not placed for a PE today. The table of probes
this format once asked for named symbols in Wine's Unix-side `ntdll`, which
is the loader that used to be in the path; nothing requests it now, and
pointing it at this runtime's own `Nt*` functions is open work.

The APK engine reads a package and refuses to run it. An APK is a zip whose
native code is a `lib/*/lib*.so` inside it; occ has no Android runtime, so
the engine names the manifest, the dex and the native libraries and reports
that they were not run. `docs/ROADMAP.md` has the current state.

## Build

Requirements:

- Clang 20 or newer, or GCC 16 or newer. Those are the versions verified
  against the test suite with warnings treated as errors;
  `docs/BUILD.md` has the full matrix, including which pairings of compiler
  and standard library work and what an unusable libc++ looks like.
- CMake 3.20 or newer.
- A C++23 standard library. libc++ is recommended; see `docs/BUILD.md` for
  the exact flags used to produce a fully static binary against the LLVM
  tree, which is what this project ships.

A libc++ that is installed but that the compiler cannot use is detected at
configure time and reported, and the build falls back to libstdc++ rather
than failing partway through. GCC currently builds against libstdc++; Clang
builds against libc++.

```
cmake -S . -B build -G Ninja
cmake --build build
```

The build produces one statically linked executable.

Tests:

```
OCC_ENABLE_TESTS=ON cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build
```

Fuzz harnesses are a separate, non-static build because sanitizers and
libFuzzer cannot be combined with a fully static link:

```
OCC_ENABLE_FUZZ=ON cmake -S . -B build-fuzz -G Ninja
```

## Layout

```
include/occ/     public headers
  syscall/       typed syscall wrappers, one per syscall
  isolation/     namespaces, rootfs, cgroup, seccomp
  observer/      event encoding, ptrace control, rsp server, transport,
                 watchpoints, W^X tracking, uprobes, the ntdll probe
                 table
  parser/        elf, pe, format detection
  engine/        one engine per format: elf, pe, apk
  runtime/       the PE-facing runtime: address space, loader, mapper,
                 export resolution, ntdll
  probe/         turning a requested symbol into a placed uprobe
  runner/        spawning a target under the isolation and observation
                 layers
  util/          logging, filesystem, strings, spans
src/             implementation, mirrors include/occ
  main.cpp, cmd_*.cpp   the subcommands
tests/           unit tests
fuzz/            libFuzzer harnesses
docs/            design notes
tools/           development helpers, not shipped
```

## Documentation

- `docs/DESIGN.md` — architecture, and why each piece is shaped the way it is
- `docs/SECURITY.md` — threat model, what isolation does and does not give you
- `docs/RSP.md` — the packet set, and the exact semantics of each reply
- `docs/EVENTS.md` — the event schema, field by field
- `docs/BUILD.md` — toolchain details, static linking, reproducible flags
- `docs/ROADMAP.md` — what is implemented, what is not, in plain terms
- `docs/COMPAT.md` — hosts this has actually been built and run on
- `docs/RUNTIME.md` — the PE-facing runtime: loader, address space,
  relocations, export resolution, and the `ntdll` surface

## License

No license has been declared for this repository. There is no `LICENSE`
file, and nothing in the build, the CMake configuration, or the history so
far states one. Until a license is added, the default copyright rules
apply and the code is not licensed for reuse by anyone.

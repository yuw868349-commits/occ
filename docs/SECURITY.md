# SECURITY

Two subjects, and they are opposites:

1. **What a hostile guest can do to this runtime.** The guest is untrusted code executing in-process. Everything in `runtime/`, `isolation/`, and `containment.cpp` is written on the assumption that the guest is adversarial.
2. **What a hostile guest can detect about being observed.** A sample written to defend itself probes the environment. `hostile/` exists so those probes get the answers an undebugged process would give.

---

## Contents

- [The threat model](#the-threat-model)
- [In-process execution](#in-process-execution)
- [Path containment](#path-containment)
- [seccomp](#seccomp)
- [The x32 hole](#the-x32-hole)
- [Handles are not pointers](#handles-are-not-pointers)
- [Exception path safety](#exception-path-safety)
- [Untrusted input surfaces](#untrusted-input-surfaces)
- [Anti-analysis](#anti-analysis)
- [What is not defended](#what-is-not-defended)

---

## The threat model

The guest is untrusted code running on this process's own thread, with this process's privileges. There is no boundary. A successful attack against the runtime is not a sandbox escape; it is arbitrary code execution in the host, because the guest already has it.

This is why the containment is layered and why each layer is narrow:

| Layer | Mechanism | Stops |
|---|---|---|
| Filesystem | `openat2` with `RESOLVE_BENEATH` | Path escape via `..` or symlink |
| Syscalls | seccomp filter | Mount, module load, kernel debugging, io_uring, keyring, cross-process memory |
| Process | Container, chroot-style | Host filesystem visibility |
| Default posture | Container on by default | The guest needing the host is opt-out |

The escape hatches are `--no-container`, `--no-seccomp`, and `OCC_PLAIN_SPAWN=1`. They are documented as escape hatches, not hidden, because a guest that needs the host is a legitimate case and silently breaking it helps nobody.

## In-process execution

The guest is native code here. There is no tracer, no VM, and no address space separation. The security boundary is therefore not around the guest; it is around what the guest can reach.

The guest can reach:

- Any host file the process can open, unless containment blocks it
- Any syscall the filter allows
- The runtime's own memory, including the guest's own TEB and PEB, which it is supposed to reach

The guest cannot reach, by construction:

- Another process's memory, unless the filter allows it
- The kernel's module interface
- Debug and trace interfaces that would expose the host

## Path containment

`runtime/containment.cpp`

Primary path: `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`.

Atomic in one syscall. No TOCTOU window, because the resolution and the check are the same operation. `RESOLVE_NO_MAGICLINKS` blocks `/proc/self/fd`-style magic links, which would otherwise let a guest reach a descriptor it does not own.

Fallback path, for kernels without `openat2`: walk components with `openat` plus `readlinkat`, symlink expansion capped at `kMaxSymlinks = 40`.

That path is **not atomic**, and the code says so. It is a stated downgrade, and `confinement_unsupported` exists to mark the state where neither mechanism is available, so a caller can refuse to run rather than assume confinement it does not have.

Two entry points: the implicit one using the internal root fd, and `_under` for an explicit anchor fd, so a caller can confine a subtree it chose.

## seccomp

`isolation/seccomp.cpp`

`build_seccomp(policy)` compiles a policy into one `sock_filter` program:

```
load nr
if nr > max_nr -> reject
jump to the block for nr, else fall through
...
each block returns its action, or tests argument conditions first
fallthrough -> the policy's fallback action
```

Default-closed. A syscall the policy does not mention is rejected, because a syscall added by a future kernel is not silently permitted. That is the only default that can be reasoned about.

`guest_default_policy()` is the policy the container installs when the caller names none. It is a **refusal list, not an allow list**, and the reasoning is stated in the header: the runtime's thunks reach the kernel on the target's behalf for everything the target asks through the Windows API, so a target that needs a syscall the list forgot keeps running rather than stopping for a reason nobody can see from inside the container.

It takes away what a Windows target has no business making: the mount family, the module family, kernel debugging and tracing, namespace changes, and the io_uring, keyring and cross-process memory interfaces.

A caller wanting the stricter allow list sets `fallback = Errno` on its own policy. The container installs the policy it is given.

The compiled program is written in one `write()` to the filter fd, so a partially installed filter is never observable.

`SeccompDefault` is `Allow`, `Errno`, `Trap`, `KillProcess`. The kill action is permitted only when `allow_kill_process` is set on the policy; killing a process is not something a filter compiler decides on its own.

The installer sets `PR_SET_NO_NEW_PRIVS` itself, before the filter, because the kernel refuses an unprivileged install without it. A bit the caller had to remember was a bit that got forgotten. The bit is one-way, which is stated in the header so nobody tries to clear it.

## The x32 hole

On x86-64, the kernel sets **bit 30** of the syscall number for x32 callers. A number arriving at the seccomp boundary therefore has to be rejected on its full value.

A filter that dispatched on the low bits would let an x32 caller reach the native entry point under a different number. The `nr > max_nr` test at the top of the program is not an optimization; it closes this.

`max_nr = 0` in the default policy means every number above zero is rejected before dispatch, which is the strictest setting and is what `guest_default_policy` uses when the caller does not override it.

## Handles are not pointers

`runtime/objects.cpp`, `runtime/ntdll.cpp`

A handle is an index plus a cookie, not a pointer. The cookie is a SplitMix-style 64-bit hash: multiply by `0x9E3779B97F4A7C15ULL`, xor-shift, multiply by `0xBF58476D1CE4E5B9ULL`, forced non-zero.

A guest cannot derive a host address from a handle value, because the mapping is not arithmetic. This matters because the guest is adversarial and handle values are guest-controlled input to every API that takes one.

Handle spaces are disjoint by construction: files at `0x2000`, objects at `0x200000`, threads at `0x800000`. Adjacent ranges would let an off-by-one in one API reach another's object.

## Exception path safety

The guest controls the stack pointer, and the stack pointer is input to the exception path. Every read there is bounded.

`seh.cpp`:

- `lookup_function_entry` follows chained entries and detects cycles, so a malformed `.pdata` cannot hang the walk
- `virtual_unwind` and `dispatch` read xdata and stack under `StackRange` bounds
- `dispatch` works on a copy of the CONTEXT, so a hostile language handler cannot corrupt the state the walk depends on

`loader.cpp`:

- Section ranges are validated against the image
- Overlapping sections are rejected
- HIGHADJ at a block boundary is rejected rather than reading past the end
- Relocation runs in two passes, validate then write, so a failure never leaves a half-migrated image

`vm_trace.cpp`:

- Ring buffer is fixed at 512 entries
- Guest ranges capped at 128
- Snapshot window fixed at 16 KiB
- A guest that floods the dispatcher cannot grow the trace without bound

`objects.cpp`:

- `EventRecorder` is a bounded ring at 800 entries, so a guest hammering system calls cannot grow the event stream

`memwatch.cpp`:

- Section headers are parsed from the image at runtime rather than hardcoded, so a malformed section table produces a bounded watch set

## Untrusted input surfaces

| Surface | Guard |
|---|---|
| PE parser | Tolerance split: `is_pe()` and `loadable()` are separate, per-directory diagnostics, no whole-file failure |
| ELF parser | Same structure |
| RSP decoder | Checksum failure requires retransmission; a corrupt packet is never handled |
| seccomp compiler | Build never throws, never installs, reports `valid()` and a description |
| Fuzz targets | Cover PE, ELF, RSP, and the seccomp compiler |

The parser's tolerance split is a security property, not only an analysis convenience. A file that claims to be PE and then lies about a directory does not take the whole run down; it produces a diagnostic and a routing decision.

The RSP decoder's refusal to handle a corrupt packet is what keeps a malformed packet from becoming a command.

## Anti-analysis

`hostile/hostile.cpp`

The guest is native code in this process, so there is no tracer between an analyst and the guest. The only vantage point is the guest's own view. A sample written to defend itself looks at the debugger-shaped objects a normal Windows process would have, and this module makes those objects answer the way an undebugged process would.

Five surfaces:

**PEB fields.** `BeingDebugged` at `+0x02`, `NtGlobalFlag` at `+0x68`, and the process heap's `Flags` at `+0x70` and `ForceFlags` at `+0x74`. `compute_peb_patches()` returns offsets, widths, and masks as data; the caller applies them to the PEB image it owns. Offsets and widths are structure facts. The masks are the anti-detection constants, asserted in the tests.

**Debug queries.** `answer_process_info()` answers `NtQueryInformationProcess` classes 7, 8, and 30. `answer_system_info()` answers class 34 (`KernelDebuggerInformation`). A class this module does not model returns `modeled = false` and is passed through untouched. Refusing to guess is part of the contract, because a wrong answer is a fingerprint.

Modeled classes:

```
ProcessInfoClass: kHandleCount=4, kDebugPort=7, kDebugObjectHandle=8,
                  kWow64Information=26, kDebugFlags=30, kIoCounters=36
ThreadInfoClass:  kHideFromDebugger=0x11
```

**Time.** `GetTickCount` and `QueryPerformanceCounter` must agree with each other and with the wall clock, or a guest that reads two clocks and compares them detects the lie. `ClockModel` is one monotonic linear model, `wall_ms(qpc) = ms0 + (qpc - qpc0) * slope`, calibrated from two samples. Every time API reads from the same model, so no two clocks can disagree. `calibrate()` refuses a zero elapsed-qpc and leaves the model invalid, which `valid()` reports.

`clock_reads()` derives every time-visible answer from one model: `tick_count_ms`, `tick_count64_ms`, `qpc`, `system_time_ft` (100 ns ticks since 1601-01-01), and the `rdtsc` low dword.

**Environment fingerprints.** Debugger window classes, mutexes, pipes, drivers, registry keys, process names, module names, file paths, probed by name. `environment_hidden()` answers "not found" for any of them. The table is data, deliberately short, and each entry carries a comment naming the tool it belongs to, so growth stays reviewable.

`FingerprintKind` covers all eight namespaces, and answering "not found" in the wrong namespace is itself a fingerprint, which is why each entry carries its kind.

**The trap surface.** `TrapPolicy` names what the runtime should do per trap kind:

```
kInt3, kSingleStep, kBreakpointFault, kInt2D, kIllegalInstruction,
kPrivilegedInstruction
```

`kDeliverToGuest` is the honest undebugged behavior. `kSwallow` is what a debugger does. The module states the policy; the integration acts on it.

`undebugged_dr()` is the canonical no-debugger debug-register image: DR6 zero, no pending debug exception; DR7 zero, no enabled breakpoints.

`scan_breakpoints()` finds int3 bytes in a range, and when a pristine image is supplied, reports what the debugger overwrote.

`probe_host()` parses `/proc/self/status`, `/proc/self/stat`, and `/proc/self/maps` and reports whether this process is itself traced, who the parent is, and whether an analyst's image is mapped. Parsing is pure, so the tests exercise every field without a real procfs.

**Extended coverage.** `answer_thread_info()` answers the hide-from-debugger class the way an undebugged thread reports: not hidden. `answer_set_thread_info()` lets the hide request succeed, because a packer that sets the flag on its own thread expects success.

The module does not execute exceptions and does not poke memory it does not own. Everything is a computation with a testable input and output. `build_plan()` assembles the result, and wiring it into the API surface and the PEB image is the integration's job.

`Config` makes every surface independently selectable, so an integration hardens exactly what its scenario exposes.

## What is not defended

- **The container is not a security boundary against a determined guest.** It is containment against accident and against samples that escape a directory. A guest that finds a host vulnerability has already won, because it is running in-process with the host's privileges.
- **MachO is detected, not parsed.**
- **The API surface is not complete.** A guest calling an unimplemented export gets a failed `GetProcAddress`, which is a different observable than a working call. A sample that checks for specific APIs can tell.
- **`OCC_PLAIN_SPAWN=1` removes the container entirely.** It exists for guests that need the host, and it is exactly as safe as running the guest on the host directly.

`occ doctor` reports the host-specific state of these at runtime.

---

Related: [RUNTIME.md](RUNTIME.md) for the runtime, [COMPAT.md](COMPAT.md) for the API surface, [DESIGN.md](DESIGN.md) for the module map, [EVENTS.md](EVENTS.md) for observation.
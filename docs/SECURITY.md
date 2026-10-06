# Security

## Threat model

Occ is designed to run software that you do not trust, in an environment
where you control the machine and the kernel.

It is not designed to run software that can attack the kernel. A kernel
exploit from inside the target is outside what this project can prevent.
Namespace, cgroup, and seccomp isolation are kernel features; a bug in the
kernel is not contained by them.

The distinction:

| Threat | Contained |
|---|---|
| Target reads or writes files outside its root | yes, via `pivot_root` and the mount namespace |
| Target sees or signals other processes | yes, via the PID namespace |
| Target opens a network connection | yes, default-deny network namespace |
| Target exhausts host memory, CPU, or pids | yes, via cgroup v2 limits |
| Target makes a syscall it was not granted | yes, via seccomp-BPF |
| Target exploits a kernel bug | no |
| Target attacks the hardware | no |

If your requirement is to contain a kernel exploit, you need a hypervisor.
This project deliberately does not use one. Use a VM in addition to Occ, or
instead of it, depending on what you are doing.

## The "target unmodified" claim

Occ does not write to the target's memory. Concretely:

- Breakpoints are hardware breakpoints, through
  `perf_event_open(PERF_TYPE_BREAKPOINT)`. No `0xCC` is written into target
  text, and there is no software-breakpoint mode: `Watchpoints` in
  `src/observer/watchpoint.cpp` has no int3 path at all.
- Memory is read with `process_vm_readv`, which does not stop or alter the
  target.
- `ptrace` is used for stop, continue, single-step, signal delivery, and
  register access.

Two things sit outside this claim. Both are stated here rather than left
for the reader to discover:

1. **uprobes.** The PE engine hooks Wine's `ntdll` with a uprobe. A uprobe
   works by the kernel inserting a trap instruction into the probed
   function. Occ asks for it; the kernel performs the write. Occ itself
   does not write the byte. This is a real modification of target memory,
   the mechanism is the kernel's, and it is on by default for the PE
   engine because function-level observability is the point of the engine.

The claim is "Occ does not write to the target unless you ask it to", not
"nothing is ever written". The first is true. The second is not, and any
tool claiming it would be wrong.

An earlier version of this file described a software-breakpoint fallback
enabled by `--allow-int3-fallback`. No such flag exists in `src/cmd_*.cpp`
and no such code path exists in the tree.

## Privileges

Occ requires root or:

```
CAP_SYS_ADMIN    namespaces, mounts, pivot_root, cgroup
CAP_NET_ADMIN    network namespace manipulation
CAP_BPF          loading the seccomp filter program
CAP_PERFMON      perf_event_open for breakpoints and uprobes
CAP_SYS_PTRACE   ptrace and process_vm_readv
CAP_SYS_RESOURCE rlimit changes
```

This is the same requirement class as Docker and strace. It
is not a gap to be worked around. A tracing tool that cannot trace is not
useful, and pretending otherwise would mean shipping something that fails
in ways the user cannot diagnose.

`occ doctor` reports the effective capability set, so the reason for a
failure is visible before the failure happens.

## Host state that weakens isolation

`occ doctor` checks and reports each of these. None of them stop Occ. All
of them are worth knowing about.

| Setting | Effect when wrong |
|---|---|
| `kernel.unprivileged_bpf_disabled` | Does not apply to Occ, which runs with `CAP_BPF`. Reported for completeness. |
| `kernel.perf_event_paranoid` | Above 2 blocks non-root perf use. Occ runs as root, so this is informational. |
| `binderfs` not available | Nothing occ runs today depends on it. Reported for completeness. |
| cgroup v2 not mounted or not writable | Limits cannot be applied. Occ reports it rather than running without limits and saying nothing. |
| `CONFIG_*` unavailable | `/proc/config.gz` and `/boot/config-$(uname -r)` are both commonly absent on cloud images. `occ doctor` reports `unavailable` and continues; a missing config file is not an error. |
| AppArmor or SELinux in enforcing mode | May deny mounts, ptrace, or the seccomp filter. Reported when a profile is enforcing. |

## Untrusted input

These components parse data from the target and are the primary attack
surface besides the kernel itself:

- The ELF reader.
- The PE reader.
- The GDB RSP packet decoder, which accepts bytes from a socket.
- The zip reader in the format detector. It reads a local file header to
  tell an Android package from any other archive, and then walks the central
  directory to name the members -- the only reader here whose offsets are
  relative to the end of the file rather than the start, since the
  end-of-central-directory record is found by scanning backwards and every
  other offset comes from it.

Six libFuzzer harnesses exist under `fuzz/`, one per parser above, plus the PE
loader and the seccomp-BPF emitter. They are written to validate before
allocating, to bound every length against the buffer actually received, and to
never trust a field that describes the size of another field.
`fuzz/README.md` records what each one asserts and, at more length, what each
deliberately does not.

Two things on the earlier version of this list do not exist and never did: an
AXML parser and an adb client. They are named here as absent rather than
quietly dropped, because a reader who finds them later should know they were
not covered rather than assume they were and find them gone.

The seccomp-BPF emitter is the sixth, and it is split across two places on
purpose. Its geometry is fuzzed: a fuzzer's bytes are read as a policy's
fallback, ceiling, rules, actions, errnos and argument comparisons, and the
emitted bytecode is then read back for the promises the emitter makes about
it -- every branch lands inside the program, the program ends in a return, the
reported instruction count is the emitted one, the preamble is the five
instructions the layout documents, and every rule's number is in the dispatch
table. That last one is the invariant worth naming here, because a filter
missing a rule installs cleanly, answers every question it is asked, and
silently protects less than the policy said.

Its acceptance by the kernel is not fuzzed, and the reason is measured rather
than preferred. The first version installed each program in a child and
treated the install's return value as the oracle; it deadlocked intermittently
under libFuzzer, which calls a harness thousands of times a second and manages
its own processes while this one was forking underneath it. Six campaigns over
one corpus, five clean and one hung, with the hang a function of neither the
input nor the run count. So the kernel oracle stayed where it already was, in
`tests/test_seccomp.cpp`, which makes 91 assertions, 37 of them a forked
child that installs a real filter and makes a call it has an opinion about,
covering all
seven comparisons and all five actions in a build without a sanitizer -- a
stronger oracle than an assertion, and a bounded one. The division loses
nothing: the test answers whether the kernel will take a filter, and the
harness answers whether the emitter built the filter it meant to.

The parsers are the part of this codebase most likely to be handed
adversarial input on purpose, because that is what a reverse engineering
target is.

## Reporting

Do not open a public issue for a memory safety bug in a parser or a
privilege escalation in the isolation layer.

There is no private contact path. No `SECURITY.md` exists at the repository
root, no security contact address is configured anywhere in the tree, and
this file is the whole of the policy. A maintainer who wants a private
channel has to add one; until then, a report about a parser or the
isolation layer has nowhere private to go, and that is worth stating
rather than implying otherwise.

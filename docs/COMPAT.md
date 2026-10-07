# Compatibility

What occ has actually been built and run on, and what a host has to provide
before it can work at all.

The list below is short because it is honest. A compatibility table that
covers twelve hosts means the project was tested on one and guessed about
eleven.

## Verified hosts

| Host | Kernel | libc | Compiler | Result |
|---|---|---|---|---|
| Ubuntu 24.04.3 LTS | 6.6.117 x86-64 | glibc 2.39 | Clang 23.1.2 + libc++ 23 | clean, tests 20/20 |
| Ubuntu 24.04.3 LTS | 6.6.117 x86-64 | glibc 2.39 | Clang 20.1.2 + libc++ 20 | clean, tests 20/20 |
| Ubuntu 24.04.3 LTS | 6.6.117 x86-64 | glibc 2.39 | GCC 16.0.1 + libstdc++ | clean, tests 20/20 |
| Tencent Cloud Linux, x86-64 | 5.15 | glibc 2.32 | Clang 23.1.2 + libc++ | clean, tests 20/20, GDB 15.1 attaches |

The fraction is the test binaries. `docs/ROADMAP.md` has the assertion count
behind them.

Every row was built from a clean configure with warnings as errors, and the
test suite run. `docs/BUILD.md` has the compiler and standard library matrix in
full, including the pairings that fall back to libstdc++ and why.

The last row is a remote machine reached over the network, and it is the row
that caught the toolchain bug this project had for weeks: a tarball Clang whose
headers did not match its own `libc++`, which builds fine locally and fails
only where the include path is longer. It is recorded because a host that is
not the developer's is the only one that finds that class of problem.

**Architecture: x86-64 only.** Not a policy decision — the register layout,
the `user_regs_struct` field offsets, the target description and the syscall
table are all x86-64. There is no `#ifdef` guarding an alternative, so an
aarch64 build would compile and then be wrong. Adding a second architecture
means an abstraction over the register block, not a flag.

**Not tested on:** any distribution other than Ubuntu 24.04 and Tencent Cloud
Linux 4; any kernel below 5.15; any kernel without cgroup v2; musl or
static glibc; a host where occ is not root; a host with SELinux or AppArmor
enforcing.

## What a host must provide

`occ doctor` checks all of this and prints the result as a stream, one object
per line, so the answer is machine-readable rather than a sentence to parse:

```
occ doctor
```

It is the same code path the isolation layer uses to decide what it can do,
not a separate diagnostic that can disagree with it.

The checks, and what failing means:

| Check | Needed for | If it fails |
|---|---|---|
| `identity` | everything | Must be root, or have the right capabilities |
| `kernel` | everything | Linux only |
| `procfs` | everything | Must be mounted |
| `user namespaces` | process isolation | Isolation is impossible without them |
| `mount` | private tmpfs | Cannot build a root without it |
| `overlayfs` | the root layer | **The root filesystem layer cannot be built** |
| `cgroup v2` | resource limits | No limits; the run proceeds without them |
| `seccomp` | syscall filtering | No default-deny filter; the target is not restricted |
| `bpf` | the seccomp filter path | The filter cannot be loaded; the target is not restricted |
| `perf_event` | W^X tracking and uprobes | Hardware breakpoints unavailable; `--track-wx` reports it and stops |
| `tracefs` | uprobe registration | Function-level probes cannot be placed |
| `binderfs` | nothing occ runs today | Reported for completeness; see below |
| `kernel config` | `CONFIG_*` assertions | Cloud images ship neither `/boot/config-*` nor `/proc/config.gz` |

Two of these are worth expanding, because they are the ones that decide
whether occ runs at all.

**`overlayfs` is the one hard requirement beyond root.** The root filesystem
layer is an overlay over `pivot_root`, and without overlayfs registered — or
at least mountable in a private namespace — there is no way to give the target
a root that is not the host's. A container that shares `/` is not a container.
A failed overlay mount aborts container setup and the run fails: there is no
fallback to a bind-mount root, because a bind mount would leave the target
able to write the host's filesystem, which is the thing the overlay exists to
prevent. The error names all three directories, because the most common cause
by far is the work directory landing on a different filesystem from the upper
directory, which the kernel reports as `EINVAL` with no detail.

**`perf_event` gates W^X tracking and uprobes.** `paranoid 2` allows
hardware breakpoints for the owning user, which is what the tracker uses, so
no privilege is needed beyond occ's own. A host at `paranoid 3` or higher
loses `--track-wx` and the stream says so with a `note` rather than silently
watching nothing. The same check covers the uprobe subscription path, which
also goes through `perf_event_open`.

## Failing soft, and what it looks like

The `bpf` and `seccomp` checks are the ones that degrade rather than block: a
host that refuses the `bpf` syscall loses the filter, and a host without
seccomp support cannot have one at all. Either way the target still runs and
the stream carries a `note` saying which capability was not acquired — the
`note` kind exists so that a missing capability is visible in the record
rather than inferred from an absence.

The `binderfs` check is the one whose subject occ does not currently need. The
APK engine is in the tree, and it reads a package and refuses to run it
rather than needing an Android runtime, so nothing in occ opens binderfs. The
check is real and would matter to an engine that did.

## Kernel configuration

`doctor` reports `kernel config` as unavailable whenever neither
`/boot/config-$(uname -r)` nor `/proc/config.gz` is present, which is the
normal state on a cloud image. That means the `CONFIG_*` assertions cannot be
checked there, and the checks that matter are the behavioural ones above rather
than a config grep: a kernel can have the options and not have them enabled,
and only a mount attempt tells the truth.

To make it checkable:

```
mount -t tracefs nodev /sys/kernel/tracing   # for the tracefs check
zcat /proc/config.gz > /tmp/kconfig          # for the config check
```

## Root, and what replaces it

occ is built to run as root and says so. That is a deliberate consequence of
what it does: `pivot_root`, cgroup subtree creation, and namespace
manipulation are all privileged, and a version that dropped the requirement
would have dropped the isolation with it.

Unprivileged operation is possible in principle — user namespaces provide most
of it, and the `user namespaces` check exists to confirm they are available —
but it has not been verified and is not claimed. `docs/ROADMAP.md` lists it.

## Nested container runtimes, and MS_BIND

occ already runs inside a container in at least one deployment, and that is a
case worth writing down because it fails in a way that looks like anything
but the cause.

A runtime that virtualises the mount namespace — Sysbox is the one this was
found on — intercepts `mount(2)` and serves it from its own overlay rather
than from the kernel's mount tree. A bind mount issued by occ is accepted,
returns success, and does not produce a bind mount. The check is
`/proc/self/mounts` from inside the target, and it is unambiguous: every
mount point occ created, writable or read-only, reports as the same `overlay`
entry as `/`, with the host's `lowerdir` and `upperdir`. The evidence that
the runtime is the cause rather than occ is `sysboxfs` appearing in the same
table.

What breaks is any target that passes a path to another process. The
observation that produced this section came from a PE run, back when the
engine handed the image to a Wine loader: the `wineserver` and the loader
that talks to it both `chdir` into
`$TMPDIR/wine-<random>/server-<dev>-<ino>` and then talk over a socket named
by a *relative* path. That works only if the two see the same directory. They
do not — one sees its bind of the run's scratch, the other sees the overflow
layer — so the client's six `connect` attempts get `ECONNREFUSED` and the run
ends with

```
wine: for some mysterious reason, the wine server failed to run.
```

which names neither the mount that did not happen nor the runtime that
skipped it. The PE engine no longer borrows that loader and this particular
pair is gone with it; the shape of the failure is not, which is why it stays
written down.

Nothing about this is specific to Wine. Any engine whose target and its
helper process have to agree on a path will fail the same way, and the
failure will be as far from the cause. Two things follow:

- When a run inside a nested runtime fails at a point that involves two
  processes and a path, read `/proc/self/mounts` from inside the container
  before reading anything else. `OCC_DEBUG_CONTAINER=1` makes the container
  print it, along with the environment it was handed, immediately before the
  exec.
- A target that starts a helper process and passes it a path needs a runtime
  that does not virtualise mounts — a plain namespace-based one, or no
  container at all. There is no configuration of occ that works around it,
  because the missing piece is kernel semantics rather than a setting.

## Why no version matrix for kernels

occ depends on kernel behaviour, not kernel API stability: `PTRACE_*` and
`perf_event_open` are stable, but the *semantics* occ depends on — a seccomp
`TRAP` producing a stop the trace loop can classify, a `PTRACE_SYSCALL` stop
arriving with the register block the observer expects — are the parts that
vary.

That is why the honest statement is a minimum, not a range: **Linux 5.15 or
newer, with cgroup v2.** A host older than 5.15 is missing `PTRACE_EVENT_STOP`
on `seccomp` and the syscall-name path; one older than 5.8 is missing cgroup
v2 entirely. Above that, the variation is in the details, and the details are
what `occ doctor` reports.

## What to run on a new host

```
occ doctor                       # capabilities, machine-readable
occ run /bin/true               # isolation works
occ run --observe /bin/true     # observation works
occ run --gdb-port 9000 --gdb-wait ./target
                                 # then, from gdb: target remote localhost:9000
ctest --test-dir build          # the suite
```

The first three are the ones that fail informatively. A host that passes
`doctor` and fails `run --observe` is telling you something the checks do not
cover, and that is the case worth reporting.

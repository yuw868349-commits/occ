# EVENTS

The observation layer. It records what a run did, without the run needing to know it was being observed, and it lets a debugger or an analyst reconnect to a run that is already in progress.

The design rule that shapes the whole module: **an event is a fact, encoded where the fact is observed.** There is no struct per event kind, no visitor, no visitor table. An event is a JSON body plus a kind, and the body is built at the point of observation.

---

## Contents

- [Event kinds](#event-kinds)
- [The Event type](#the-event-type)
- [Sinks and writers](#sinks-and-writers)
- [Sessions](#sessions)
- [Transport](#transport)
- [Probes](#probes)
- [ntdll probes](#ntdll-probes)
- [Watchpoints, registry, and WX](#watchpoints-registry-and-wx)
- [Attaching](#attaching)

---

## Event kinds

`observer/event.h`

Seventeen kinds. The separations in the list are deliberate: `Section` is separate from `Mapping`, and `ProbeAttached` is separate from `ProbeHit`, and both exist because merging them would lose information a consumer cannot recover.

```
SessionStart, SessionEnd,
ProcessSpawn, ProcessExit,
ImageLoaded, Mapping, Section, Import,
FileOpened, SyscallBlocked,
BreakpointHit, Signal,
MemoryWrite, Exec,
ProbeAttached, ProbeHit,
Note
```

`Section` versus `Mapping`: a section is a range of the file and a range of the address space, and the loader is what turns one into the other. Reporting a section as a mapping claims a correspondence the file does not make.

`ProbeAttached` versus `ProbeHit`: attaching is a fact about the run's setup and happens once; a hit is a fact about the target and happens as often as the target calls the function. A run that placed nine of ten probes and did not say which one it missed has a silent hole in its output.

`Note` is the free-form kind, for facts that fit none of the above and are worth recording anyway.

`event_kind_name()` maps each to its wire name (`"session_start"`, `"process_spawn"`, `"image_loaded"`, `"memory_write"`, `"probe_hit"`, and so on). Anything unrecognized maps to `"unknown"`, so an unrecognized kind is visible rather than silently dropped.

## The Event type

```cpp
class Event {
    void add(std::string_view key, std::uint64_t value) noexcept;
    void add(std::string_view key, std::int64_t value) noexcept;
    void add(std::string_view key, std::string_view value) noexcept;
    void add(std::string_view key, bool value) noexcept;
    void add(std::string_view key, const char* value) noexcept;
    void add_hex(std::string_view key, std::uint64_t value) noexcept;

    const std::string& body() const noexcept;
    bool empty() const noexcept;
};
```

An event holds its already-encoded JSON body. The body is built where the fact is observed, which keeps the encoder free of state beyond the output sink and keeps a struct per event kind from being needed for the seventeen kinds that exist, or for the eighteenth when one is added.

The overload set is the quoting safety. `add(key, std::string_view)` quotes and escapes; `add(key, uint64_t)` does not. A caller cannot accidentally emit an unquoted string, and the `const char*` overload exists specifically so a bare pointer does not convert to `bool` and turn a name into a truth value. The hazard is closed at the type rather than at each call site.

`add_hex` emits a hexadecimal value, for addresses and pointers where hex is what a reader wants.

## Sinks and writers

```cpp
class Sink {
    explicit Sink(int fd) noexcept;
    bool write_line(std::string_view line) noexcept;
    int fd() const noexcept;
};

class Writer {
    // one per run; owns the stream's identity
};
```

A sink is an fd, not a `FILE*`, because the stream has to survive the process replacement a run performs. A `FILE*` buffer would be duplicated or lost across it.

`write_line` retries a partial write and reports anything else as failure. It never blocks indefinitely on a dead reader: a broken pipe is a disconnection, not a reason to spin.

The writer owns the stream's identity, so a consumer can tell two interleaved runs apart.

## Sessions

`observer/session.h`, `observer/session.cpp` (2443 lines)

`SessionConfig` configures a session. The notable field is a listening socket to accept a debugger on, with a port reported in the event stream when the session starts. That is what makes a session attachable rather than merely recordable.

`SessionResult` is the outcome.

A session is what `occ run` creates and `occ attach` reconnects to. It owns the observer for the life of the run and survives the run's own process replacement.

## Transport

`observer/transport.h`, `observer/transport.cpp` (360 lines)

`Connection` and `Listener`.

`Connection::adopt(int fd)` takes an already-accepted descriptor. It is moved in rather than connected, so a caller can set options on the raw descriptor before anything is read from it.

`Connection::pump()` reads whatever is available and appends it to the packet decoder. It returns false when the peer closed or the descriptor failed, which is the signal to stop serving. A read that would block returns true with nothing added, so a caller can wait for readiness first.

`has_packet()` is true only for a complete packet. A packet whose checksum failed does not count, because there is nothing to handle until the peer has been asked to retransmit.

This is the transport the RSP server rides on. See [RSP.md](RSP.md).

## Probes

`observer/ptrace.cpp`, `observer/uprobe.cpp`, `observer/watchpoint.cpp`, `observer/registry.cpp`, `observer/wx.cpp`

| Probe | Mechanism |
|---|---|
| `ptrace.cpp` | ptrace-based observation of syscalls and signals |
| `uprobe.cpp` | uprobes on host symbols |
| `watchpoint.cpp` | hardware watchpoints through the debug registers |
| `registry.cpp` | Registry access recording |
| `wx.cpp` | Write/execute state of pages |

`uprobe.cpp` emits `ProbeAttached` once per probe, including failures. A probe that could not be placed is a fact worth recording, because a missing probe is a hole in the coverage and a consumer that does not know about it will read the hole as absence of activity.

`wx.cpp` is what answers "was this page ever executable", which is the question SMC and unpacking raise.

## ntdll probes

`observer/ntdll_probes.cpp`

A static table of 73 `NtdllProbe` entries.

```cpp
struct NtdllProbe {
    const char* symbol;
    ProbeCategory category;
    const char* arg0, *arg1, *arg2, *arg3;  // parameter names, NULL when fewer
};
```

`kProbeCount` is derived from the array, so the table cannot drift from its own size. `ntdll_probe_count()` exposes it.

`ProbeCategory`:

```
File, Memory, Registry, Process, Thread, Sync, Security,
SystemInfo, Debug, Object, Network, Token, Section, Key, Misc
```

Each entry names the function and up to four parameter names, so a syscall event can carry `FileHandle`, `DesiredAccess`, `ObjectAttributes`, `IoStatusBlock` as names rather than as four anonymous integers. That is the difference between a trace an analyst can read and one they have to look up.

An ntdll symbol that is not in the table falls into `Misc` via `kUnknownCategory`. Nothing is dropped; it is merely uncategorized.

## Watchpoints, registry, and WX

`watchpoint.cpp` arms hardware watchpoints and reports hits. `registry.cpp` records registry access. `wx.cpp` records page protection transitions, which is how a run detects that a page became writable and then executable, the signature of an unpacker writing its output.

These are independent of the debugger. A run can be observed without anything stopping.

## Attaching

`occ attach <session>` finds the session's socket and subscribes. The stream arrives as events, in order, with the session's identity attached.

The point: a long run does not need babysitting. Start it, walk away, attach later, and read what it did. The event stream is the interface, not a log file that may or may not have been configured.

---

Related: [DESIGN.md](DESIGN.md) for where the observer sits, [RSP.md](RSP.md) for the debug protocol, [RUNTIME.md](RUNTIME.md) for the guest debugger.
# The GDB Remote Serial Protocol

What occ implements, packet by packet, and what it deliberately does not.

This is a stub server, not a debugger. It answers what GDB needs to attach,
read and single-step a target, and it declines the rest rather than
answering it approximately. A packet that gets an empty reply is one occ does
not implement — the protocol's own convention for "unsupported" — and a
debugger falls back to a path it already knows. That fallback is why the
server can be this small and still be usable: the parts that are missing are
the parts GDB has defaults for.

The implementation is `src/observer/rsp.cpp` for framing and hex, and the
dispatcher in `src/observer/session.cpp` for the packets themselves.

## Using it

```
occ run --gdb-port 9000 --gdb-wait ./target
```

Then attach from another terminal:

```
gdb -ex 'target remote localhost:9000'
```

`--gdb-wait` holds the target at its first stop until a debugger connects, so
the debugger's initial breakpoint does not land after the program's interesting
part. Without it, occ serves GDB and runs the target at the same time, and a
program that finishes quickly is gone before the debugger arrives. Port 0 asks
the kernel for any free port, and the chosen port is printed before the target
starts, so a debugger can attach at any point during the run.

These three are the only GDB flags: `--gdb-port`, `--gdb` (a synonym), and
`--gdb-wait`. There is no flag for an inherited file descriptor — occ always
listens on loopback, and the `gdb_read_fd`/`gdb_listen_fd` fields in
`RunOptions` are how the test suite drives the same server without a socket.

## Framing

Standard: `$<payload>#<two hex checksum digits>`, checksummed over the escaped
payload. `}`, `$` and `#` are escaped as `}` XOR 0x20. A `+` acknowledges, a
`-` asks for a retransmit, and both are parsed as well as emitted.

Three details in `PacketDecoder` are worth naming because a decoder that gets
them wrong interoperates with nothing:

**A damaged packet is acknowledged too.** A bad checksum produces `-`, not
silence, because silence is the one answer a sender cannot act on — it would
resend until it gave up. A packet that arrives framed but corrupt is a fact
about the wire, and the protocol has a way to report it.

**A `$` inside a payload restarts framing.** The earlier packet was cut short,
and restarting is what the protocol asks of a receiver that sees framing it
cannot complete. Discarding the partial payload rather than appending it is
what keeps the two packets from merging into one longer wrong one.

**A truncated escape is passed through.** A payload ending in a lone `}` is
returned as-is rather than shortened, so the caller sees a payload that is
wrong instead of one that is silently short. Those fail differently and only
one of them is a mystery.

## The packets

### `qSupported` → features

```
qXfer:features:read+;swbreak+;hwbreak+;vContSupported+;xmlRegisters=i386
```

The list is a contract and it is kept honest in both directions. Claiming a
feature that is not implemented sends the debugger down a path that then fails
in a way that looks like the debugger's bug; omitting one that is implemented
makes it take a slower path it did not have to.

`xmlRegisters=i386` is the load-bearing one. Without it GDB keeps its built-in
default, which describes a 32-bit i386 target with 17 registers, and every
register read is then the wrong width at the wrong offset: the `g` reply is
rejected as truncated and no register is shown at all. The name is `i386`
even for an x86-64 target — it names the register *description format*, not
the processor.

`qAttached` → `1`. The session was created from a process occ already owns,
rather than by asking a target to spawn one, so there is nothing to attach to.

`qC` → `QC<pid>`, `qfThreadInfo` → `m<pid>`, `qsThreadInfo` → `l`,
`qTStatus` → `T0`. One process, one thread, always that process.

`qSymbol` and every other query fall through to an empty reply.

### `qXfer:features:read:target.xml:OFFSET,LENGTH`

Serves the target description, which is a literal string in
`src/observer/session.cpp`. Chunking works, and a request past the end answers
`l` so the debugger stops asking rather than treating the end as an error. Any
annex other than `target.xml` also answers `l`.

The description declares three features: the core integer registers, the x87
block, then `org.gnu.gdb.i386.segments` (`fs_base`, `gs_base`) and
`org.gnu.gdb.i386.syscall` (`orig_rax`).

### `g` / `G` — all registers

The block is **300 bytes**, and that number is not a round figure. GDB packs a
target description end to end with no padding, so the layout is the sum of the
declared widths:

| Registers | Width | Bytes |
|---|---|---|
| 17 general + `rip` | 64 bits | 136 |
| `eflags` + 6 segment selectors | 32 bits | 28 |
| 8 x87 stack (`st0`–`st7`) | 80 bits | 80 |
| 8 x87 control | 32 bits | 32 |
| `fs_base`, `gs_base`, `orig_rax` | 64 bits | 24 |
| | | **300** |

A field is 8 or 20 hex characters depending on which register it is. Parsing
the block as a fixed-stride array reads `st0` out of the middle of `fop`; that
mistake is invisible from either side alone — each path is self-consistent —
and it does not corrupt one register, it shifts every register after the gap,
so a backtrace names the wrong frame.

`G` writes only the first seventeen. `eflags` and the segment selectors are
named because the description has to name them, and the kernel's `SETREGS`
rejects them on this architecture; the x87 block is not accepted at all; and
the last three belong to the syscall entry path. Writing any of them would be
either refused or silently undone, which is worse than ignoring the request.
The current values are read rather than zeroed, so the ignored registers stay
what the kernel last had.

### `p` / `P` — one register

`p<num>` reads by **register number**, not by position in the `g` block. The
two agree across the forty core registers and part company past that, because
GDB reserves 40–51 for the SSE and AVX banks this description does not
declare. `fs_base` is position 40 in the block and register **152** to GDB;
`gs_base` is 153; `orig_rax`, which has no number in GDB's enum at all, is
reported at 154. Reading by a different index than the description gives is
how a debugger ends up displaying one register's value under another's name.

The bound is 154 — the highest number this server answers for — rather than
the register count. `p0` asks for the first register and `p1a` for the
twenty-sixth; the number is variable-width hex and is read as a protocol
number, not as a register block, which would want eight digits and refuse
both.

`P` is **not implemented** and answers empty. GDB falls back to `G`.

### `m` / `M` — memory

`m<addr>,<len>` reads, `M<addr>,<len>:<bytes>` writes, both little-endian hex.
A read is capped at 4096 bytes: the protocol's reply has to fit in one packet,
and a debugger asking for more is asking for a transfer the framing cannot
carry, so the cap is what keeps the answer well-formed. A zero length or one
past the cap returns `E01`, as does a read that failed or returned nothing.

A read that succeeded partway returns what it managed, and its length is
shorter than requested. That is the protocol's own convention for a short
read, and it is what lets a debugger read up to a page boundary without first
asking where the mapping ends.

### `Z` / `z` — breakpoints

`Z0,<addr>,<kind>` sets and `z0,<addr>,<kind>` clears, where kind 0 is a
software breakpoint and kind 1 is a hardware one. Software breakpoints are
`int3`: the byte is written, the original is saved, and stepping over it puts
the original back for one instruction. A failure to install answers `E01`.

### `?` — why we stopped

Returns the `T` form carrying the signal and `rip` as register 16:

```
T05:7f3e46875540;
```

`rip` is read, not zero-filled. A debugger that resumes from address zero
because this returned zero is looking at a target that has already faulted.

### `c` / `s` — resume

`c[<signal>]` continues, `s` single-steps, and the optional signal is
variable-width hex. Neither resumes inside the handler: the trace loop owns
the process and decides when it runs, so these set a flag the loop reads. That
is why the reply comes back immediately, and why `c` has no reply body at all
— the next thing on the wire is a stop reply when the target stops.

`s` does not take a signal. The protocol allows one; occ ignores it, because a
single step that delivers a signal is a different operation from a single step
and answering `OK` would claim the one that was not requested happened.

### `vCont` — multi-threaded resume

`vCont?` reports the supported actions. `vCont;c` and `vCont;s` resume. As with
`c`, the reply is returned whether or not a resume was requested, because
`vCont?` produces an answer with no resume behind it.

Only `c` and `s` are answered. `C`, `S`, `r`, and `t` are not.

### `D` / `k` — detach and kill

`D` replies `OK` and detaches. `k` detaches too, and this is a deliberate
choice rather than an omission: killing a process the user did not ask to kill
is not something a debugger stub does on its own. The session reports it and
lets the caller decide.

### `#` — deprecated

Answers empty. Extended-remote mode is not implemented, and this packet is
what a stub that does not want extended mode uses to say so.

## What is not implemented

`qXfer:memory-map:read` and `qXfer:threads:read` — occ's memory map is in the
event stream instead, and it is not available to the debugger. `qRcmd` — no
monitor command channel. `P` — one-register write; use `G`. `vAttach`,
`vRun` — occ starts the process itself and attaches to what it started.
Multiprocess and multi-thread `vCont`. Non-stop mode. Reverse execution.

None of these are silent. Each answers empty, which is the protocol's own
"unsupported", and each is a thing GDB has a working fallback for.

## Interoperability

Verified against **GDB 15.1** (`GNU gdb (Ubuntu 15.1-1ubuntu1~24.04.1)`) on
x86-64 Linux. Attached to a live `occ run --gdb-wait --observe /bin/sleep`,
`info all-registers` returned all 51 declared registers, and `x/4i` gave
correct disassembly:

```
0x00007f0cd35d1540 in ?? ()
rip            0x7f0cd35d1540      0x7f0cd35d1540
eflags         0x200               [ IF ]
   0x7f0cd35d1538:	jmp    0x7f0cd35d13d2
   0x7f0cd35d153d:	nopl   (%rax)
=> 0x7f0cd35d1540:	mov    %rsp,%rdi
   0x7f0cd35d1543:	call   0x7f0cd35d21d0
orig_rax       0x3b                59
st0            0                   (raw 0x00000000000000000000)
...
```

`orig_rax` reading 59 (`0x3b`, `SYS_exit`) at a stop in `_start` is the check
that matters most: it confirms the register number 154 lines up with GDB's own
numbering, since a mismatch here would answer a question about the exit
syscall with the value of `gs_base` and look entirely plausible.

**No warnings from GDB's side.** The one message a bare `target remote`
produces — "No executable has been specified and target does not support
determining executable automatically" — is about GDB not knowing the
executable, not about the protocol, and passing the binary as an argument to
GDB removes it.

The x86-64 register layout passes GDB's own `i386_validate_tdesc_p()`, which
is a stricter check than looking correct: it verifies the description against
the numbering GDB will actually use, and it runs before any register is read.
A block that was 300 bytes and correct-looking but declared a width GDB
disagrees with is rejected there rather than showing up later as a wrong
value.

Every feature announced in `qSupported` is exercised by the test suite;
`include/occ/observer/session.h` notes this as an invariant, because a
feature announced and not implemented is the failure mode this protocol hides
best.

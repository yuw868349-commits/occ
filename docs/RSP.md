# RSP

The remote serial protocol. This is a GDB-compatible stub: the wire format, the packet framing, the checksum, the escapes, and the command set are GDB's, not this project's. A stock GDB can attach to an occ session and debug a guest.

This is the most delicate code in the observer, because the protocol has two ways of saying "no" and encoding one as the other breaks a debugger in a way that looks like the debugger's fault.

---

## Contents

- [Packet framing](#packet-framing)
- [The two kinds of nothing](#the-two-kinds-of-nothing)
- [Decoder state machine](#decoder-state-machine)
- [Hex and byte order](#hex-and-byte-order)
- [Command set](#command-set)
- [Register description](#register-description)
- [vCont](#vcont)
- [Stop replies](#stop-replies)
- [What is not implemented](#what-is-not-implemented)

---

## Packet framing

A packet on the wire is:

```
$<payload>#<checksum-hi><checksum-lo>
```

`encode_packet` escapes the payload, computes the checksum over the escaped bytes, and frames. `unescape` reverses it. The escape byte is `}` and the byte after it has `0x20` exclusive-or'd into it.

An empty payload frames as `$#00`, and that is a valid packet, not a failure. It is the protocol's "not implemented" answer.

`PacketDecoder::feed(data, length)` consumes bytes and `PacketDecoder::take()` returns the next complete packet.

## The two kinds of nothing

This is the central design point of the module.

The protocol has exactly two ways to be unhelpful, and they are not interchangeable:

**"Nothing to send."** The request was acted on and the answer, if any, comes from somewhere else. Continue is the case that matters: the resume is the answer, and the stop reply follows when the target stops again. A stub that framed an empty packet here would tell the debugger "unsupported", and the debugger would conclude the target cannot be resumed.

**"An empty packet."** The request was understood and is not implemented. This is `$#00` on the wire, and it is a real packet: it has framing and a checksum, and the peer reads it as an answer. `vMustReplyEmpty` exists precisely to test this, because a stub that cannot produce it is one that goes silent on every packet it does not know, which reads as a hung connection.

Encoding either as the other is the bug `Reply` exists to prevent:

```cpp
struct Reply {
    bool send = true;      // false: nothing is written; the session loop answers
    std::string payload;   // ignored when send is false

    static Reply packet(std::string body) noexcept;   // an answer the peer reads
    static Reply unsupported() noexcept;              // "$#00"
    static Reply nothing() noexcept;                  // send = false
};
```

`Reply::nothing()` sends nothing at all. `Reply::unsupported()` sends a well-formed empty packet. They are different functions because they mean different things.

The `'c'` and `'s'` handlers return `Reply::nothing()`: a continue is not a question, so there is nothing to answer now. The `'v'` handler for an unimplemented subcommand returns `Reply::unsupported()`, so the debugger falls back to the single-threaded packets it knows.

`vMustReplyEmpty` is the test named for this. A stub that stays silent on it fails, and that failure is the only way this bug class is observable from outside.

## Decoder state machine

```cpp
enum class State : std::uint8_t {
    Idle, Payload, FirstChecksum, SecondChecksum, Ack,
};
```

The `Ack` state exists because after a `+`, the next byte decides whether it is an acknowledgment or the start of a three-byte packet. Skipping that state means misreading one as the other.

`want_retransmit_` is set on checksum failure, and `has_packet()` refuses to report a packet until a retransmission has been asked for. A corrupt packet is not handled; it is requested again.

`needs_ack_` and `pending_ack_` carry the acknowledgment to send after the next packet.

## Hex and byte order

GDB's wire format is hexadecimal for every binary quantity, and the byte order is the target's, not the protocol's.

```
hex_u64_le / hex_u64_be
hex_u32_le
hex_u8
hex_number          // variable width, no padding
parse_hex_u64_le / parse_hex_u32_le / parse_hex_number / parse_hex_bytes
```

A register value is sent in the target's byte order. For a little-endian target that is least significant byte first, which is why these are not the same as a general hex read and why they live in the protocol layer rather than in a utility.

`hex_number` is variable-width because protocol numbers arrive that way: `p0` asks for the first register and `p1a` for the twenty-sixth. Reading a register number as a fixed-width field would refuse both.

`parse_hex_bytes` decodes a byte string, used for memory reads and writes.

## Command set

`DebugServer::handle(packet)` dispatches on the first byte of the payload.

| Packet | Meaning |
|---|---|
| `?` | Why did we stop |
| `vCont...` | Multiplexed continue/step |
| `q...` | Query |
| `g` | Read all registers |
| `G` | Write all registers |
| `p<n>` | Read one register by number |
| `m<addr>,<len>` | Read memory |
| `M<addr>,<len>:<data>` | Write memory |
| `Z`/`z` | Insert/remove breakpoint |
| `H` | Set thread |
| `c` | Continue |
| `s` | Step |
| `D` | Detach |
| `k` | Kill |

### `?`

The stop reply carries the program counter, because that is the register a debugger needs to decide what the stop was, and it should not have to ask separately. Answering with zero is the bug this avoids: a debugger that resumes from address zero because the stub returned zero is looking at a target that has already faulted.

### `p<n>`

The number is the one GDB assigned in its own register enum, not the position in the `g` block. The two agree only across the forty core registers, because GDB reserves 40 through 51 for the SSE and AVX banks this description does not declare.

Three distinct answers, and they are not the same:

- `which > kOrigRaxRegnum`: the register does not exist. Not "unsupported". An empty packet would send the debugger looking for a different way to ask.
- `bits == 0`: inside the range but outside the description, one of the SSE or AVX banks. There is no width to send it at, and zero bytes would read as "unsupported" rather than as a zero of some width.
- Otherwise: the register at the width the description declares.

That last point matters. GDB reads exactly as many bytes as the description says the register is wide, so a `%eflags` answered with sixteen hex digits is four bytes of the register followed by four bytes of whatever the debugger then reads as the next register.

### `c` and `s`

The session does not resume inside the handler. The loop owns the tracee and has to be the one that decides when it runs. So the handler sets `resume_requested_`, `step_`, and `resume_signal_`, and returns nothing.

`c` takes an optional signal to deliver, as a variable-width hexadecimal value.

### `k`

A kill request is reported as a detach and the caller decides. Killing a process the user did not ask to kill is not something a debugger stub does on its own. The detach is the answer, and it is carried by the session ending, so nothing is sent on the wire.

### `#`

A payload beginning with `#` never reaches a command byte, because the decoder has already consumed the checksum. Reaching this case means a malformed packet, and it is answered as unsupported.

## Register description

`qSupported` answers:

```
qXfer:features:read+;swbreak+;hwbreak+;vContSupported+;xmlRegisters=i386
```

The list is a contract and is kept honest in both directions. Claiming a feature that is not implemented makes the debugger take a code path that then fails in a way that looks like a bug in the debugger. Omitting one that is implemented makes the debugger fall back to a slower or less precise path it did not have to take. Every entry names the packet that implements it.

`xmlRegisters=i386` is what makes the debugger fetch the target description at all. Without it GDB keeps its built-in default, which describes a 32-bit i386 target with 17 registers, and every register read is then the wrong width at the wrong offset: the `g` reply is rejected as truncated and no register is shown. The name is `i386` even for an x86-64 target because it names the register description format, not the processor.

`qXfer:features:read:` serves the target description itself, through `handle_qxfer_features()`.

`qAttached` answers `1`, because the session was created from a process it owns rather than by asking the target to spawn one.

`qC` answers `QC<pid>`: this stub observes one process, so the answer is always that process.

## vCont

`vCont` is the multiplexed form of `c`, `s`, `C`, and `S`. The packet is `vCont[;action[:thread-id]]...` where an action is a letter.

Implementing `vCont` does not replace the single-threaded packets, because a debugger that does not use `vCont` still needs `c` and `s` to work.

`vCont?` asks which actions are supported. The answer is the list, and it is answered with a real packet so a stub's reply is recognizable as a `vCont` answer rather than as an empty one. A debugger that cannot tell the difference will not choose `vCont` at all, so the answer has to be a packet.

`handle_vcont()` implements the actions. A `vCont` naming no action this stub can perform is "unsupported" and gets the empty packet. One that named a resume gets silence, because the resume is the answer.

The capability query and the resume are told apart by the query itself, not by the emptiness of the returned string, because "no reply" and "an empty packet" are the same string and mean opposite things.

## Stop replies

`encode_stop_reply(signal, rip)` builds the stop notification. The signal comes from `gdb_signal_for_trap()`, and the PC is carried alongside so the debugger does not have to ask for it.

The distinction between `Reply::nothing()` and a stop reply is the same distinction as everywhere else: the stop reply is sent by the session loop when the target actually stops, never by the command handler.

## What is not implemented

Only `vCont` among the `v` packets. Every other `v` packet answers with an empty packet, and the debugger falls back.

Single-register reads outside the described range, SSE and AVX banks, and any packet not in the table are answered with an empty packet, which is the protocol's "not implemented".

That is the whole surface. It is small on purpose: a stub that claims more than it implements produces failures that look like debugger bugs, and the cost of an honest empty packet is a debugger taking a slower path.

---

Related: [EVENTS.md](EVENTS.md) for the event stream, [DESIGN.md](DESIGN.md) for the module map, [RUNTIME.md](RUNTIME.md) for the guest debugger that this protocol fronts.
#!/usr/bin/env python3
"""occ devirt — offline VMP de-virtualizer.

Consumes the JSON-lines VM trace (`OCC_VM_TRACE`) and the decrypted image
dump (`.vmf`), and reassembles the virtual instruction stream that the VM
engine executed, down to the API calls it makes.

VMP 3 virtual instruction format (this sample):
  dispatch:  mov rcx,[r12+rax*8]          @ 0x6b2a
  decrypt:   cmc;cmc; rol rcx,0xa; jmp rcx @ 0x8851
  handler = rol(word, 10).  The handler is a junk-wrapped micro-program on
  the virtual state: rbp = virtual stack pointer, rsi = bytecode cursor.
  API calls are indirect: a handler loads the target from the virtual
  stack and `call rdx`.  The trace records the virtual stack at every
  dispatch (st0/st1/st2) and the bytecode cursor (rsi), so a call is
  visible as the guest's own API address appearing in the stack slots.
"""
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict

def rol(v: int, n: int) -> int:
    return ((v << n) & 0xFFFFFFFFFFFFFFFF) | (v >> (64 - n))

# Guest API addresses observed in this run's IAT, from OCC_API_TRACE.
# The host-side semantic addresses the loader resolved for the sample.
API_TABLE = {
    0x7fdb7da42e04: "IsDebuggerPresent",
    0x7fdb7da3f790: "TerminateProcess",
    0x7fdb7da3b360: "RtlCaptureContext",
    0x7fdb7da51700: "RtlLookupFunctionEntry",
}

def api_name(addr: int) -> str:
    if addr in API_TABLE:
        return API_TABLE[addr]
    # A tag prefix (VMP marks call operands, e.g. 0x31...).
    if (addr >> 56) == 0x31 and (addr & 0xFFFFFFFFFF) in API_TABLE:
        return API_TABLE[addr & 0xFFFFFFFFFF] + " (tagged)"
    return None

def load_trace(path: str) -> list:
    rows = []
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        if o.get("kind") != "dispatch":
            continue
        rows.append({"seq": o["seq"], "va": int(o["va"], 16),
                     "index": int(o["index"], 16),
                     "base": int(o["base"], 16),
                     "word": int(o["target"], 16),
                     "rsi": int(o.get("rsi", "0"), 16),
                     "rbp": int(o.get("rbp", "0"), 16),
                     "st0": int(o.get("st0", "0"), 16),
                     "st1": int(o.get("st1", "0"), 16),
                     "st2": int(o.get("st2", "0"), 16)})
    return rows

def disasm(dump: str, start: int, stop: int) -> list:
    try:
        out = subprocess.run(
            ["objdump", "-d", "-M", "intel", "--start-address=0x%x" % start,
             "--stop-address=0x%x" % stop, dump],
            capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return []
    lines = []
    for ln in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s*(.*)", ln)
        if m:
            lines.append((int(m.group(1), 16), m.group(2).strip()))
    return lines

def classify(op: str):
    o = op.lower()
    if "call" in o:
        return "vCall"
    if "[rsi]" in o:
        return "vImm"
    if "[rbp" in o:
        if o.startswith("mov"):
            lhs = o.split(",", 1)[0] if "," in o else o
            return "vStore" if "ptr [rbp" in lhs else "vLoad"
        if o.startswith(("add", "sub")) and "ptr [rbp" in o:
            return "vArithMem"
        if o.startswith(("add", "sub", "xor", "and", "or")):
            return "vArith"
        return "vStack"
    if re.match(r"mov[a-z]*\s+(rax|eax|ax|al|rcx|ecx|cx|cl|rdx|edx|dx|dl"
                r"|rbx|ebx|bx|bl|rsi|rdi|r8|r9|r10|r11|r12|r13|r14|r15),", o):
        return "vMov"
    return None

def extract_handlers(dump: str, rows: list) -> dict:
    handlers = {}
    for r in rows:
        h = rol(r["word"], 10)
        if h in handlers:
            continue
        code = disasm(dump, h, h + 0x80)
        sem = []
        for addr, op in code:
            if op.startswith("jmp") or op.startswith("ret"):
                break
            c = classify(op)
            if c:
                sem.append((c, op))
        handlers[h] = sem
    return handlers

def main() -> None:
    if len(sys.argv) < 3:
        print("usage: devirt.py TRACE.jsonl DUMP.vmf [N] [-o REPORT]",
              file=sys.stderr)
        sys.exit(2)
    trace_path, dump_path = sys.argv[1], sys.argv[2]
    limit = 0
    report_path = None
    args = sys.argv[3:]
    while args:
        a = args.pop(0)
        if a == "-o":
            report_path = args.pop(0)
        else:
            limit = int(a)

    lines = []          # the report, echoed to stdout and written to -o
    def emit(s: str = "") -> None:
        lines.append(s)
        print(s)

    rows = load_trace(trace_path)
    if limit:
        rows = rows[:limit]
    emit(f"trace: {len(rows)} dispatches")

    handlers = extract_handlers(dump_path, rows)
    emit(f"distinct handlers: {len(handlers)}\n")

    by_handler = defaultdict(list)
    for r in rows:
        by_handler[rol(r["word"], 10)].append(r)

    emit(f"{'handler':<14}{'count':>6}  semantics")
    emit("-" * 96)
    for h, rs in sorted(by_handler.items(), key=lambda kv: -len(kv[1])):
        sem = handlers.get(h, [])
        label = " ; ".join(f"{c}:{op[:38]}" for c, op in sem[:2]) or "(none)"
        emit(f"0x{h:010x}  {len(rs):>6}  {label[:82]}")

    # The bytecode cursor's range: the region of .vmp0 the virtual program
    # actually executes.
    if rows:
        rsis = sorted(r["rsi"] for r in rows)
        emit(f"\nbytecode cursor range: 0x{rsis[0]:x} .. 0x{rsis[-1]:x}")

    emit(f"\nreassembled virtual stream (first {min(50, len(rows))}):")
    emit(f"{'#':<5}{'handler':<14}{'word':<20}  semantics")
    for r in rows[:min(50, len(rows))]:
        h = rol(r["word"], 10)
        sem = handlers.get(h, [])
        label = " ; ".join(f"{c}" for c, _ in sem[:3]) or "?"
        emit(f"{r['seq']:<5}0x{h:010x}  0x{r['word']:016x}  {label}")

    # API calls: the guest's own API address in a stack slot is a call
    # being set up. Report every dispatch where one of the slots is a
    # known API address (tagged or plain).
    emit(f"\nAPI calls observed:")
    api_rows = []
    for r in rows:
        for slot, v in (("st0", r["st0"]), ("st1", r["st1"]), ("st2", r["st2"])):
            name = api_name(v)
            if name:
                api_rows.append((r["seq"], slot, v, name, r["word"],
                                 r["rsi"], r["rbp"]))
                break
    if not api_rows:
        emit("  (none)")
    for seq, slot, v, name, word, rsi, rbp in api_rows[:40]:
        emit(f"  #{seq:<5} {slot}={v:016x} {name:<24} word={word:016x} "
             f"rsi=0x{rsi:x} rbp=0x{rbp:x}")

    counts = Counter()
    for r in rows:
        h = rol(r["word"], 10)
        sem = handlers.get(h, [])
        counts[sem[0][0] if sem else "(unknown)"] += 1
    emit(f"\nopcode histogram (all {len(rows)}):")
    for op, c in counts.most_common():
        emit(f"  {op:<14}{c}")

    if report_path:
        with open(report_path, "w") as f:
            f.write("\n".join(lines) + "\n")
        emit(f"\nreport written to {report_path}")

if __name__ == "__main__":
    main()

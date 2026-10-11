#!/usr/bin/env python3
"""occ devirt — offline VMP de-virtualizer.

Consumes the JSON-lines VM trace (`OCC_VM_TRACE`) and the decrypted image
dump (`.vmf`), and reassembles the virtual instruction stream that the VM
engine executed.

VMP 3 virtual instruction format (this sample):
  dispatch:  mov rcx,[r12+rax*8]          @ 0x6b2a
  decrypt:   cmc;cmc; rol rcx,0xa; jmp rcx @ 0x8851
  handler = rol(word, 10).  The handler is a junk-wrapped micro-program on
  the virtual state: rbp = virtual stack pointer, rsi = bytecode cursor.
  The junk (shld/shrd/bsf/bt/rol/rcr... on garbage registers) is
  interspersed with the real operation, which this tool recognises by the
  registers it touches.

Semantic recognition rules:
  - load/store touching [rsi] and advancing rsi        -> read bytecode imm
  - load/store/add/sub/xor touching [rbp+off]          -> virtual stack op
  - call through a guest address or IAT slot           -> vCall
  - anything else                                       -> junk
"""
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict

def rol(v: int, n: int) -> int:
    return ((v << n) & 0xFFFFFFFFFFFFFFFF) | (v >> (64 - n))

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
                     "word": int(o["target"], 16)})
    return rows

def disasm(dump: str, start: int, stop: int) -> str:
    try:
        out = subprocess.run(
            ["objdump", "-d", "-M", "intel", "--start-address=0x%x" % start,
             "--stop-address=0x%x" % stop, dump],
            capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return ""
    lines = []
    for ln in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s*(.*)", ln)
        if m:
            lines.append((int(m.group(1), 16), m.group(2).strip()))
    return lines

JUNK_RE = re.compile(
    r"^(shld|shrd|bsf|bsr|bt|bts|btr|btc|rol|ror|rcl|rcr|bswap|"
    r"cmc|clc|stc|set[a-z]+|sbb|xor|and|or|not|neg|test|add|sub|"
    r"dec|inc|mov[a-z]*\s+(r|e|a)[a-z0-9]+,(r|e|a)[a-z0-9]+)")

def classify(op: str):
    """Return the VM semantic of one instruction, or None for junk.

    The rules are deliberately loose: VMP's junk generator never touches
    the VM state registers (rsi = bytecode cursor, rbp = vstack), so any
    instruction that does is a real operation, and its shape tells the
    semantic."""
    o = op.lower()
    if "call" in o:
        return "vCall"
    if "[rsi]" in o:
        return "vImm"          # reading the bytecode stream
    if "[rbp" in o:
        # mov reg, QWORD PTR [rbp+..]   -> load from vstack
        # mov QWORD PTR [rbp+..], reg   -> store to vstack
        if o.startswith("mov"):
            lhs = o.split(",", 1)[0] if "," in o else o
            return "vStore" if "ptr [rbp" in lhs else "vLoad"
        if o.startswith(("add", "sub")) and "ptr [rbp" in o:
            return "vArithMem"   # e.g. add QWORD PTR [rbp+8],rax
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
        print("usage: devirt.py TRACE.jsonl DUMP.vmf [N]", file=sys.stderr)
        sys.exit(2)
    trace_path, dump_path = sys.argv[1], sys.argv[2]
    limit = int(sys.argv[3]) if len(sys.argv) > 3 else 0

    rows = load_trace(trace_path)
    if limit:
        rows = rows[:limit]
    print(f"trace: {len(rows)} dispatches")

    handlers = extract_handlers(dump_path, rows)
    print(f"distinct handlers: {len(handlers)}\n")

    by_handler = defaultdict(list)
    for r in rows:
        by_handler[rol(r["word"], 10)].append(r)

    print(f"{'handler':<14}{'count':>6}  semantics")
    print("-" * 78)
    for h, rs in sorted(by_handler.items(), key=lambda kv: -len(kv[1])):
        sem = handlers.get(h, [])
        label = " ; ".join(f"{c}" for c, _ in sem[:4]) or "(none)"
        print(f"0x{h:010x}  {len(rs):>6}  {label[:60]}")

    print(f"\nreassembled virtual stream (first {min(60, len(rows))}):")
    print(f"{'#':<5}{'handler':<14}{'word':<20} semantics")
    for r in rows[:min(60, len(rows))]:
        h = rol(r["word"], 10)
        sem = handlers.get(h, [])
        label = " ; ".join(f"{c}" for c, _ in sem[:3]) or "?"
        print(f"{r['seq']:<5}0x{h:010x}  0x{r['word']:016x}  {label}")

    # Histogram of the reassembled opcodes.
    counts = Counter()
    for r in rows:
        h = rol(r["word"], 10)
        sem = handlers.get(h, [])
        if sem:
            counts[sem[0][0]] += 1
        else:
            counts["(unknown)"] += 1
    print(f"\nopcode histogram (all {len(rows)}):")
    for op, c in counts.most_common():
        print(f"  {op:<14}{c}")

if __name__ == "__main__":
    main()

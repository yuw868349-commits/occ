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
import os
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

def asm_label(handlers: dict, h: int) -> str:
    """A short instruction name for a handler, inferred from its real
    instruction text: vImm -> imm, vStack -> push/pop/load/store/op by
    the actual mnemonic, vCall -> call, vRet -> ret."""
    sem = handlers.get(h, [])
    names: list[str] = []
    for c, op in sem[:3]:
        opn = op.lower().strip()
        if c == "vImm":
            names.append("imm")
            continue
        if c == "vStack":
            if "pop" in opn:
                names.append("pop")
            elif "push" in opn:
                names.append("push")
            elif "call" in opn:
                names.append("call")
            elif "jmp" in opn:
                names.append("jmp")
            elif opn.startswith("j") and len(opn) > 1:
                names.append("jcc")
            elif "mov" in opn:
                dst = opn.split("mov", 1)[1].strip().split(",")[0].strip()
                names.append("store" if "[" in dst else "load")
            elif "add" in opn:
                names.append("add")
            elif "sub" in opn:
                names.append("sub")
            elif "and" in opn:
                names.append("and")
            elif "or" in opn:
                names.append("or")
            elif "xor" in opn:
                names.append("xor")
            elif "dec" in opn:
                names.append("dec")
            elif "inc" in opn:
                names.append("inc")
            elif "cmp" in opn:
                names.append("cmp")
            elif "test" in opn:
                names.append("test")
            elif "shl" in opn or "shr" in opn or "sar" in opn:
                names.append("shift")
            elif "imul" in opn or "mul" in opn:
                names.append("mul")
            elif "neg" in opn:
                names.append("neg")
            elif "not" in opn:
                names.append("not")
            else:
                names.append("op")
            continue
        names.append(c.lower())
    return " ".join(names) or "?"


def asm_mode(handlers: dict, rows: list, out: list, limit: int) -> None:
    """Emit the trace as an assembly-like listing: per dispatch the
    bytecode address, the handler's instruction name, and the operand
    values observed in the virtual stack slots."""
    out.append("")
    out.append(f"assembly-like listing (first {limit or len(rows)} of "
               f"{len(rows)} dispatches):")
    out.append(f"{'#':<5}{'@rsi':<13}{'handler':<14}{'instr':<22}  operands")
    out.append("-" * 78)
    for r in rows[:limit if limit else len(rows)]:
        h = rol(r["word"], 10)
        label = asm_label(handlers, h)
        ops = []
        for slot in ("st0", "st1", "st2"):
            v = r[slot]
            if v:
                name = api_name(v)
                ops.append(name or f"0x{v:x}")
        op_str = ", ".join(ops)
        out.append(f"{r['seq']:<5}0x{r['rsi']:010x} 0x{h:010x}  {label:<22}  {op_str}")

def load_api_map(path: str) -> dict:
    """Read the address-to-name map the runtime dumps next to the image
    (`.api`, JSON lines). The map moves with the host's ASLR, so a
    baked-in table would not survive from one run to the next."""
    table: dict[int, str] = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if "addr" in rec and "name" in rec:
                    table[int(rec["addr"])] = str(rec["name"])
    except OSError:
        return {}
    return table


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
    api_path = os.path.splitext(dump_path)[0] + ".api"
    if os.path.exists(api_path):
        API_TABLE.update(load_api_map(api_path))
    limit = 0
    report_path = None
    asm_limit = 0
    args = sys.argv[3:]
    while args:
        a = args.pop(0)
        if a == "-o":
            report_path = args.pop(0)
        elif a == "--asm":
            asm_limit = int(args.pop(0)) if args and args[0].isdigit() else 0
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

    if asm_limit != 0 or "--asm" in sys.argv:
        asm_mode(handlers, rows, lines, asm_limit)

    # Control flow: the bytecode cursor (rsi) advances by the length of
    # each virtual instruction; a jump larger than any instruction's
    # footprint -- or backwards at all -- is a control-flow edge. The
    # edge's handler is the branch (vCall forward, vRet back), and its
    # virtual stack top names the target the branch took.
    emit(f"\ncontrol flow (basic blocks from rsi continuity):")
    blocks = []      # (start_seq, end_seq, start_rsi, end_rsi)
    block_start = 0
    for i in range(1, len(rows)):
        d = rows[i]["rsi"] - rows[i - 1]["rsi"]
        if d > 0x40 or d < 0:
            blocks.append((block_start + 1, i, rows[block_start]["rsi"],
                           rows[i - 1]["rsi"]))
            block_start = i
    blocks.append((block_start + 1, len(rows), rows[block_start]["rsi"],
                   rows[-1]["rsi"]))
    emit(f"  {len(blocks)} basic blocks")
    for bi, (lo, hi, rs, re) in enumerate(blocks):
        h = rol(rows[lo - 1]["word"], 10)
        sem = handlers.get(h, [])
        label = " ; ".join(f"{c}" for c, _ in sem[:2]) or "?"
        edge = ""
        if lo > 1:
            d = rows[lo - 1]["rsi"] - rows[lo - 2]["rsi"]
            if d > 0x40 or d < 0:
                tgt = rows[lo - 1]["st0"]
                kind = "vCall" if d > 0 else "vRet"
                edge = f"  <- {kind} from #{lo-1} (target st0=0x{tgt:x})"
        emit(f"  B{bi} #{lo:>4}-#{hi:<4} rsi 0x{rs:x}..0x{re:x} "
             f"{len(range(lo, hi+1))} instr{edge}")

    if report_path:
        with open(report_path, "w") as f:
            f.write("\n".join(lines) + "\n")
        emit(f"\nreport written to {report_path}")

if __name__ == "__main__":
    main()

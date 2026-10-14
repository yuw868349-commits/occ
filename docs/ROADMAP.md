# ROADMAP

What exists, what is unfinished, and what is next. Every claim here is checked against the source. Where a gap is real, it is named rather than smoothed over.

---

## Contents

- [Where the project stands](#where-the-project-stands)
- [Finished](#finished)
- [Unfinished, in the tree](#unfinished-in-the-tree)
- [Known gaps](#known-gaps)
- [Next](#next)
- [Not planned](#not-planned)

---

## Where the project stands

The runtime runs Windows PE images natively, in-process, on Linux, with a Windows environment built around them. The loader, the ABI bridge, SEH, TLS, and a broad API surface are complete enough that 86 tests cover them and real samples run.

The de-virtualization path works end to end: trace, lift, bit-blast, solve, and certify, with a goal language expressive enough to ask arbitrary questions of a recovered VM.

What is not finished is named below, and most of it is small.

## Finished

**PE loading.** Header validation, section mapping, the full relocation type set including HIGHADJ with its two-slot consumption, IAT resolution ordered after relocation, TLS directory handling with VA/RVA disambiguation, deterministic base placement, two-pass relocation with rollback.

**Windows ABI.** The `ms_abi` bridge for all guest-facing thunks, hand-built `SysvVaList` for variadics, struct returns through the hidden return pointer, path translation between host and `Z:` drive form, command line construction.

**The guest environment.** TEB and PEB with the real Windows x64 layouts, a clean `NtGlobalFlag` and heap flags, guest threads with their own TEB and stack, TLS slots, a guest heap and stdio table.

**Exception handling.** UNWIND_INFO parsing, cycle detection on chained entries, bounded stack walks, the C-specific handler with correct search and unwind phases, `RtlUnwindEx` with signal mask restoration.

**The API surface.** 2733 registered exports across 60 module entries and 69 files. kernel32, the UCRT and classic C runtime across eleven MSVC versions, a large `Rtl*` subset, GDI, USER32, Winsock, crypt32, advapi32 including the full registry family, rpcrt4, dbghelp, and the rest.

**Anti-detection.** Consistent answers across `NtQueryInformationProcess`, `CheckRemoteDebugerPresent`, and `IsWow64Process`. A single monotonic clock model so no two time APIs disagree. A curated fingerprint table across eight namespaces.

**Observation.** 18 event kinds, JSON bodies built where the fact is observed, sessions that survive process replacement, and a GDB-compatible RSP stub that a stock debugger can attach to.

**De-virtualization.** Lift with symbolic x86-64 promotion, shared boundary recognition, automatic layout inference, multi-exit handlers, conformance checking. A hash-consed expression DAG with memoized evaluation. Bit-blasting to CNF and a CDCL solver. A general replay solver. A goal language covering the register file, the bytecode stream, guest memory, registers, arithmetic, comparison, and logic.

**Isolation.** `openat2` containment with an atomic primary path, a seccomp compiler that is default-closed and closes the x32 hole, and a container that is on by default.

**The debugger.** INT3 breakpoints with displaced originals, hardware breakpoints that never write guest memory, `step`, `regs`, `x`, minidump, and watch pages that catch decryption writes as they happen.

## Unfinished, in the tree

These are files that exist and do not participate in the build. They are not features.

**`src/packer/esp_law.cpp`.** Not in the `occ_core` source list. `grep -c esp_law CMakeLists.txt` returns zero. Its test is the only consumer. The ESP-law unpacker is dead code.

**`packer`, `dbi`, and `emu` have no CLI entry points.** `main.cpp` does not reference them. They are libraries with tests. `identify.cpp`, `smc.cpp`, `pipeline.cpp`, `pe_view.cpp`, `dbi.cpp`, and `emu.cpp` are all built into `occ_core`, so they are reachable from code, but no command exposes them.

## Known gaps

**The apiset forwarder table is larger than the implementation.** `kCrtForwarders[]` in `modules.cpp` lists roughly 50 names with no corresponding registration in `crt.cpp` or `ucrt_extra.cpp`: `_strrev`, `strtok_s`, `_fullpath`, `_getcwd`, `_chdir`, `_mkdir`, `_access`, `_spawnv`, the `_mbs*` family, `_findfirst`, `_stat`, `_chmod`, `_execv`, and others. A guest calling one of these through an `api-ms-win-crt-*` contract module gets a failed `GetProcAddress`. The failure is safe, but it is a gap.

**MachO is detected, not parsed.** The parser recognizes the magic and stops. `Format::MachO` exists in the enum and nothing fills it.

**Coverage instrumentation is not in the build.** No `--coverage`, no `llvm-cov`, no `gcov`. Sanitizers are supported; coverage is not.

**Three empty placeholder files contribute zero exports.** `kernel32_extra.cpp`, `advapi32.cpp`, and `ntdll_rtl.cpp` are 35 lines each. They exist so a domain has somewhere to grow, and they are honest about being empty.

**The API surface is large but not complete.** Guests leaning on undocumented behavior or deep driver assumptions can find a hole. `occ doctor` reports the host-specific half of that at runtime.

**The container is not a hardened sandbox.** It contains paths and filters syscalls. It is not a defense against a determined guest, and it does not claim to be.

## Next

In order of how much they unblock:

**Wire `packer` into a command.** The identify, SMC, and pipeline code is written and tested. It needs a CLI surface, which is a thin layer over what exists.

**Close the forwarder gap.** Register the missing CRT names, or trim `kCrtForwarders[]` to what is implemented. Either is correct; the current state, where the table claims more than the code delivers, is not.

**Decide `esp_law.cpp`.** Build it or delete it. A file that is not compiled and not deleted costs a reader time to discover that it is neither.

**Give `dbi` and `emu` a surface, or state that they are internal.** Both are complete enough to be useful. Neither is reachable from the CLI.

**Coverage instrumentation.** It is the one build feature with no path at all, and it is the feature that makes the other work verifiable.

**MachO parsing, if it is wanted.** The detection is there. The parser is not.

## Not planned

- **A GUI.** The interfaces are a CLI, an event stream, and a debugger protocol.
- **Running non-x86-64 guests.** `winabi.cpp` uses `ms_abi`, `pe_process.cpp` has inline asm, `mapper.cpp` names the ASan shadow range, and `i386.cpp` exists precisely because a 64-bit process cannot run 32-bit code natively. A different architecture is a different project.
- **A CLR host.** `mscoree.cpp` says so plainly.
- **A general-purpose sandbox.** The containment is specific to what a Windows guest needs, and widening it would mean defending against a threat this project does not model.

---

Related: [DESIGN.md](DESIGN.md) for the architecture, [COMPAT.md](COMPAT.md) for the API surface, [SECURITY.md](SECURITY.md) for the threat model, [BUILD.md](BUILD.md) for build options.
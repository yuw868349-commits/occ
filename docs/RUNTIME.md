# RUNTIME

The runtime is the bulk of the project. It does one thing: put a Windows PE image into this process's address space, run the image's own instructions on the host CPU, and supply the Windows environment the image expects to find around them.

Not an emulator. Instructions are not translated, not interpreted, not recompiled. They execute. What is simulated is the environment, not the machine.

Not Wine. Wine re-implements the Win32 API layer and lets the PE call into it. This re-implements the runtime itself: a subset of ntdll, loader behavior, SEH dispatch, TLS, the process environment, and the Windows ABI that carries calls through it.

That choice drives everything downstream. Guest code is native code on this process's own thread. There is no boundary to reach across, so there is no ptrace, no QEMU, no virtual machine tricks. "Stopping the guest" is the guest's own thread parked inside a signal handler, holding its register state in a copy the debugger can read and change.

Scale: 163 source files, 83 headers, roughly 180,000 lines of product code, plus 90 test files adding another 60,000.

---

## Contents

- [Address space](#address-space)
- [Mapper](#mapper)
- [Loader](#loader)
- [TLS](#tls)
- [PE process environment](#pe-process-environment)
- [Exception path](#exception-path)
- [Windows ABI](#windows-abi)
- [Guest heap and stdio](#guest-heap-and-stdio)
- [Export registry](#export-registry)
- [API sets](#api-sets)
- [Guest module images](#guest-module-images)
- [Guest threads](#guest-threads)
- [Write watching and the OEP trap](#write-watching-and-the-oep-trap)
- [VM dispatch tracing](#vm-dispatch-tracing)
- [Image dump and minidump](#image-dump-and-minidump)
- [Import slot reconstruction](#import-slot-reconstruction)
- [32-bit interpreter](#32-bit-interpreter)
- [Containment and kernel objects](#containment-and-kernel-objects)
- [API simulation layer](#api-simulation-layer)

---

## Address space

`runtime/address_space.h`, `runtime/address_space.cpp`

The address space is a ledger. It records which address ranges are occupied and with what page protection. It makes no system calls.

Three page states: free, reserved, committed. `Region::committed` distinguishes reserve from commit. `MEM_DECOMMIT` keeps the address range and drops only the commit state.

Page protection reuses the Windows `PAGE_*` values directly rather than inventing a parallel enum. `protection_base` masks off the low 8 modifier bits, which are `Guard=0x100`, `NoCache=0x200`, `WriteCombine=0x400`.

Allocation granularity and page size are deliberately separate:

```
kGranularity = 0x10000    // 64 KiB, the ledger's unit
kPageSize    = 0x1000     //  4 KiB
kUserMin     = 0x10000    //  user window floor, clears the NULL page
kUserMax     = 0x7FFFFFFEFFFF
```

Regions are stored sorted by base to support binary search. `set_protection` splits into three parts when it covers only part of a range. `high_water` and `bytes_of_kind` report committed bytes to the guest.

`Result<T>` carries a `Status`. Failures are not expressed with exceptions; the whole library is built with `-fno-exceptions -fno-rtti`.

## Mapper

`runtime/mapper.h`, `runtime/mapper.cpp`

The mapper is the only bridge between the ledger and the kernel. It issues the real `mmap`/`munmap`/`mprotect`/`msync` and keeps them paired with the ledger.

It exists for rollback. When the ledger records a region but `mmap` fails, or `mprotect` fails, the ledger must be undone in step. The forbidden state is a ledger that claims an address is occupied when it is not, or the reverse.

`protection_to_prot()` is the single conversion point from `PageProtection` to `PROT_*`.

`map_below` and `map_above` are deterministic scans, not `MAP_FIXED` guess-and-retry. They place within a given range and dodge AddressSanitizer's reserved 4 GiB-128 TiB shadow region.

`map_batch` makes a batch of mappings all-or-nothing. `syscalls_made` and `last_failure` are observability counters.

## Loader

`runtime/loader.h`, `runtime/loader.cpp`

Maps a PE32+ file into a memory image. About three thousand lines, one of the longest single implementations in the runtime.

### Pipeline

The order is not negotiable:

1. Validate the PE header
2. Map sections
3. Apply base relocations (**writes into the mapped sections**)
4. Resolve the IAT (**depends on relocated addresses**)
5. Record the TLS directory

IAT resolution must follow relocation, because import addresses are wrong until relocation has run.

### Load validation

Rejection conditions:

- The machine must be `Amd64`. `PeProcess::build` additionally rejects DLLs, non-AMD64, and non-PE32+
- Every section's `[VirtualAddress, VirtualAddress+VirtualSize)` must fall inside the image
- Sections must not overlap
- The entry point must fall inside an executable section, or the OEP jump lands on non-executable memory
- `delta = base - image_base` is computed unsigned. Wrapping is meaningful; treating it as negative is wrong

### Relocations

The full type set and the width each one writes:

| Constant | Value | Width |
|---|---|---|
| `kRelBasedAbsolute` | 0 | 0 (skipped) |
| `kRelBasedHigh` | 1 | 2 |
| `kRelBasedLow` | 2 | 2 |
| `kRelBasedHighLow` | 3 | 4 |
| `kRelBasedHighAdj` | 4 | special |
| `kRelBasedDir64` | 10 | 8 |

`relocation_width()` centralizes the field width per type so the parsing loop advances uniformly.

**HIGHADJ**:

```
Temp = field << 16;
Temp += adjustment;
Temp += Diff;
Temp += 0x8000;
field = Temp >> 16;
```

Four things matter here:

1. All arithmetic is unsigned 32-bit. Signed arithmetic overflows and that is undefined behavior.
2. `adjustment` comes from the **next** relocation entry, so one HIGHADJ consumes two slots.
3. `adjustment` is signed.
4. A HIGHADJ at the end of a block, with no adjustment slot after it, is rejected. Reading past the end is not an option.

**Two passes**: the first pass validates and writes nothing; the second writes. Any failure leaves no half-migrated image, which is why `rollback()` never has to reverse repairs.

Rollback comes in three pieces: `rollback_placement` undoes base selection, `rollback_record` undoes the ledger entry, `rollback` calls both.

### Base selection

`choose_base_below()` is a deterministic 64 KiB downward linear scan. The same input yields the same base every time, which matters for reproducible analysis.

`load_image_retrying()` and `BaseChooser` make the placement policy replaceable. `BaseRetry` handles the case where the preferred base is taken.

### IAT resolution

Names come from the hint/name table. An API set name (`api-ms-win-*`, `ext-ms-win-*`) is resolved to a real DLL first, then looked up.

### Disambiguating the TLS directory's VA from its RVA

The TLS directory address may be an already-relocated VA or an un-relocated RVA. `resolve_tls_address(field, base, is_rva)` decides by asking whether the value falls inside the image; if it does, it is read as a VA. The TLS directory is read from mapped memory. Only when there is no mapper, in the `occ check` path, is it read from the file.

`commit_tls_index` runs after final protections take effect and needs a temporary permission raise to write the slot number, or the write violates the protection just installed.

## TLS

`runtime/guest_tls.cpp`

Byte-level parsing of the TLS directory, installation of per-thread TLS slots, dispatch of TLS callbacks.

The data directory index is fixed at `9`; the directory structure is `kTlsDirectoryBytes = 40`, the size of PE32+'s `_IMAGE_TLS_DIRECTORY64`. Both PE32 and PE32+ magics are accepted because the field offsets differ between them.

DLL reason values: `ProcessAttach=1`, `ThreadAttach=2`, `ThreadDetach=3`. The loader-side `TlsReason` is a separate enum, each matching the Windows definition it serves.

The TEB's index array is `kTlsDirectoryIndex = 9` wide; the guest reads its own slot number with `__readfsdword(9)`.

## PE process environment

`runtime/pe_process.h`, `runtime/pe_process.cpp`

Builds the TEB, PEB, heap, and stack, jumps to the OEP, installs the signal chain, and translates host signals into guest NTSTATUS exceptions.

### TEB layout

`kTebBytes = 0x2000` (8 KiB):

```
kExceptionList  = 0x00
kStackBase      = 0x08
kStackLimit     = 0x10
kSelf           = 0x30
kProcessId      = 0x40
kThreadId       = 0x48
kTlsPointer     = 0x58
kPeb            = 0x60
kTlsSlots       = 64
kTlsArrayOffset = 0x1480
```

### PEB layout

`kPebBytes = 0x1000`:

```
kBeingDebugged     = 0x02
kImageBaseAddress  = 0x10
kLdr               = 0x18
kProcessParameters = 0x20
kProcessHeap       = 0x30
kNtGlobalFlag      = 0xBC
kNumberOfHeaps     = 0xF0
kProcessHeaps      = 0xF8
kOsMajorVersion    = 0x118
```

The process heap sits inside the PEB region at `kProcessHeapOffset = 0x130`. Heap header fields: `kHeapFlagsOffset = 0x70`, `kHeapForceFlagsOffset = 0x74`, clean values `kHeapFlagsClean = 0x00000002` (`HEAP_GROWABLE`) and `kHeapForceFlagsClean = 0`. `NtGlobalFlag` is also written clean; it is a target of anti-debug checks.

Pseudo PID/TID are `kOurProcessId = 0x0DCC` and `kOurThreadId = 0x0DCD`, deliberately non-zero so they are not mistaken for a "no PID" sentinel.

### Relative placement

TEB, PEB, and stack are placed upward with `map_above` in the order image, then TEB/PEB, then stack. Placing upward keeps them clear of AddressSanitizer's reserved region.

### Entering the guest

`enter_guest_asm` is an inline asm sequence: set `rsp`, subtract 32 for stack alignment, `xor ebp,ebp`, then, if the image carries a `.occregs` section, restore registers from it in a fixed order (`rdx, rcx, r8..r15, rbx, rbp, rsi, rdi, r12`, with `r12` last because it is used as a pointer), `call *entry`, `ud2`.

`ud2` is the "this must not return" sentinel.

### Signal handler chain

`guest_fault_handler` runs in strict order:

1. memwatch single-step
2. instruction trace
3. vm_trace trap / OEP fetch
4. guestdbg breakpoint re-arm / hardware breakpoint scan / INT3
5. memwatch write
6. INT3: back `rip` up one byte
7. signal to NTSTATUS
8. vectored dispatch
9. `seh::dispatch` frame walk
10. top-level unhandled filter

This is the single entry point for every exception.

### Exception code mapping

`exception_code_for`:

- `SIGSEGV`/`SIGBUS` to stack overflow (fault address within 64 KiB below `stack_low`) / `InPageError` / `AccessViolation`
- `SIGILL` to `Privileged` / `Illegal`
- `SIGFPE` to `IntegerDivideByZero` / `IntegerOverflow` / `FloatDivideByZero` / `FloatOverflow` / `FloatUnderflow` / `FloatInexactResult` / `FloatInvalidOperation`
- `SIGTRAP` to `SingleStep` / `Breakpoint`

### Runtime setup

`run_pe_process` installs a 64 KiB `sigaltstack`, registers five signal handlers, arms memwatch and vm_trace, reads and writes GS base through `SYS_arch_prctl`, and uses `sigsetjmp` as the convergence point, restoring the prior state on the way out.

## Exception path

`runtime/seh.h`, `runtime/seh.cpp`

x64 Windows exception handling: UNWIND_INFO parsing, frame walking, CONTEXT construction, language-specific handler dispatch.

### Constants

```
kContextSize   = 0x4D0                    // 1232 bytes
kContextAmd64  = 0x100000
kContextFull   = Amd64 | 0x1 | 0x2 | 0x4 | 0x8
kRecordSize    = 152                      // EXCEPTION_RECORD
```

Real Windows x64 CONTEXT layout, register offsets `kContextRax = 0x78` through `kContextR15 = 0xF0`, `kContextRip = 0xF8`, `kContextFltSave = 0x100` (the 512-byte XSAVE area).

`FunctionEntry` is 12 bytes: `begin_rva` / `end_rva` / `unwind_rva`, which is the shape of a `.pdata` entry itself.

`DispatcherContext` is exactly 0x50 bytes, with the fields that matter at `target_ip = 0x20`, `context_record = 0x28`, `scope_index = 0x48`.

UNWIND flags: `kUnwFlagNHandler=0` / `EHandler=1` / `UHandler=2` / `ChainInfo=4`.

Exception record flags: `kExceptionNoncontinuable=0x1` / `Unwinding=0x2` / `ExitUnwind=0x4` / `TargetUnwind=0x20`.

Filter return values: `ContinueSearch=0` / `ExecuteHandler=1` / `ContinueExecution=-1`.

### Safety

`lookup_function_entry` follows chained entries (`kUnwFlagChainInfo`) and detects cycles, so a malformed or hostile `.pdata` cannot hang the walk.

`virtual_unwind` and `dispatch` read xdata and the stack under bounds, because the stack pointer is guest-controlled. `StackRange` supplies the limits.

`dispatch` copies a CONTEXT and walks frames with that copy, calling the language handler; on `EXCEPTION_CONTINUE_EXECUTION` (that is, -1) it resumes from the copied context.

`seh_C_specific_handler` runs filters in the search phase and finallys in the unwind phase, advancing `scope_index` and skipping the scope that contains the target address, because an exception thrown inside a try does not run that try's own finally.

`seh_RtlUnwindEx` restores the signal mask before unwinding, since unwinding code can raise further signals.

## Windows ABI

`runtime/winabi.h`, `runtime/winabi.cpp`

About six thousand lines, the longest single file in the runtime. It defines the ABI conversion for every guest-visible thunk, the guest heap, the stdio slots, and the module table that drives the export registry.

### The bridge

Every guest-facing thunk carries `__attribute__((ms_abi))`. The host is SysV (`rdi/rsi/rdx/rcx/r8/r9` plus XMM); the guest is MS (`rcx/rdx/r8/r9` plus XMM).

**Variadics are the hard part.** MS ABI varargs do not travel in registers, so a va_list has to be built by hand. `SysvVaList` is exactly 24 bytes holding `gp_offset`, `fp_offset`, `overflow_arg_area`, `reg_save_area`, checked by `static_assert`. The register save area is `kRegSaveBytes = 48 + 8*16`, integers starting at `kGpStart=24`, floats at `kFpStart=48`.

**Struct returns** travel through the hidden return-buffer pointer passed in `rcx`; `cr_llabs`, `cr_div`, `cr_ldiv`, `cr_lldiv` take that route.

### TEB offset constants

winabi keeps its own copy, consistent with `pe_process.cpp`:

```
kTebLastError   = 0x68
kTebProcessId   = 0x40
kTebThreadId    = 0x48
kTebTlsArray    = 0x1480
kTlsSlotCount   = 64
kTlsOutOfRange  = 0xFFFFFFFF
```

Standard handles: `kStdInputHandle = 0x1001`, `kStdOutputHandle = 0x1002`, `kStdErrorHandle = 0x1003`; `kFileHandleBase = 0x2000`; `kCurrentProcessHandle = 0xFFFFFFFFFFFFFFFF`.

### Paths and command lines

`to_dos_path` translates host paths into `Z:` drive form (`/tmp/x` to `Z:\tmp\x`); `from_dos_path` goes the other way (`Z:\` to `/`). Paths without a drive letter, and unmounted drive letters, pass through unchanged. No guessing.

`build_command_line` and `split_command_line` handle the command line the guest sees. `utf8_to_utf16` and `utf16_to_utf8` convert encodings.

## Guest heap and stdio

The guest heap reserves `kGuestHeapReserve = 512 << 20` (512 MiB) in one shot, with floor `kGuestHeapFloor = 0x01000000`. The heap header magic is `kHeapMagic = 0x4F43434845415031`, ASCII `"OCCHEAP1"`. Free blocks go on the `GuestHeapFree` free list.

Relevant entry points: `heap_lock`, `heap_blocks`, `heap_forget`, `heap_size`, `heap_live_blocks`, `heap_owns`, `heap_user_info`, `heap_set_user_info`, `heap_free`.

Guest stdio uses `kGuestFileSlot = 48`; from slot 48 onward the stdio table holds the mapping between guest FILE objects and host descriptors. `translate_stream` goes both ways. `init_stdio` initializes it.

## Export registry

`runtime/exports.h`, `runtime/exports.cpp`

The registry of exports this runtime implements, and the lookup machinery for them. It doubles as the DLL name resolver.

`ExportRegistry` is a value type with no global singleton, so several can exist at once, one per `run_pe_process`. DLL name comparison is ASCII case-insensitive.

Lookup tries the hint index first, then binary search, because the hint a guest supplies is frequently wrong.

Forwarder detection: a target RVA inside the export directory range is a forwarder. Depth is capped at `kMaxForwarderDepth = 4`.

`module_basename` takes everything after the last path separator and keeps the extension.

`add_from_image` reads an export table out of a real guest PE image, so a guest's own DLL exports can join the same table.

`HostExport` is consumed in three places: `ExportRegistry` (host-side `GetProcAddress`), `own_export_index` (indexed by folded name), and `guest_module_inputs` (the synthetic PE images built for the guest side).

## API sets

`runtime/apiset.h`, `runtime/apiset.cpp`

A static table mapping API set contract names to implementing DLLs.

`kApiSets[]` holds **364 entries**, sorted by name so `std::lower_bound` can be used. The order is a hard constraint; any change requires a re-sort.

Matching lowercases the query and strips the `.dll` suffix before the binary search. Both sides are normalized, so `API-MS-WIN-CORE-X.DLL` and `api-ms-win-core-x` are the same query.

The `ext-ms-win-` prefix is handled the same way, so third-party extension contracts travel the same path.

## Guest module images

`runtime/guest_module.h`, `runtime/guest_module.cpp`

For each API module the runtime implements, it synthesizes a parseable PE image in the guest address space, complete with an export table and executable trampolines, and wires up PEB's three Ldr lists.

### Image layout

```
kExportRva        = 0x1000
kTextRva          = 0x2000
kTrampolineStride = 32
```

### Trampolines

Two shapes:

1. Plain: `movabs rax, imm64; jmp rax` (12 bytes)
2. Intercepted by an API hook: `mov r11, slot; movabs rax, hook; jmp rax`

Both use a uniform 32-byte stride, with unused bytes filled with `0xCC` (INT3). The address can therefore serve directly as a slot index, and stray execution traps instead of wandering into data.

### LDR lists

`LdrEntryLayout` measures from the start of the entry itself:

```
kInLoadOrder   = 0x00
kInMemoryOrder = 0x10
kInInitOrder   = 0x20
kDllBase       = 0x30
kEntryPoint    = 0x38
kSizeOfImage   = 0x40
kFullDllName   = 0x48
kBaseDllName   = 0x58
```

`PEB_LDR_DATA` sits at PEB offset `0x200`, with its three list heads at `0x10`/`0x20`/`0x30`. List head length `kListHeadLength = 0x38`, entry stride `kEntryStride = 0x100`, name buffer stride `kNameBufferStride = 0x80`.

Two index maps, `module_by_name` and `module_by_base`, serve `GetModuleHandle(name)` and `GetModuleHandle(base)` respectively.

The effect that matters: after the guest calls `LoadLibrary("KERNEL32.dll")`, `GetProcAddress` returns a genuinely executable trampoline address, not an invalid handle. This is what having no guest/host boundary buys.

## Guest threads

`runtime/guest_thread.h`, `runtime/guest_thread.cpp`

Handle space is `kThreadHandleBase = 0x800000` with span `kThreadHandleSpan = 0x100000`, disjoint from file handles (`kFileHandleBase = 0x2000`) and object handles (`objects::kHandleBase = 0x200000`).

Per-thread TEB is `kTebBytes = 0x2000`, default stack `kDefaultStackBytes = 1 MiB`.

`ThreadRecord` fields: `id`, `handle`, `teb`, `stack_base`, `stack_limit`, `state` (a `unique_ptr<GuestState>`), `host` (`pthread_t`), `start`/`parameter`, `gate`/`done`/`resumed` (three condition variables), `suspend_count`, `running`, `finished`, `exit_code`, `handle_open`.

`create_guest_thread` places TEB plus stack with `map_above`, upward like the main thread, copies a `GuestState`, and rebuilds argv_table, because the argv array must be reachable from the new TEB. GS base is set with `SYS_arch_prctl`, since guest code may reach the TEB through the GS segment register.

Wait results: `kWaitObject0=0`, `kWaitTimeout=0x102`, `kWaitFailed=0xFFFFFFFF`, `kStillActive=259`.

Entry points: `create_guest_thread`, `is_guest_thread_handle`, `guest_thread_exit_code`, `wait_guest_thread`, `close_guest_thread`, `resume_guest_thread`, `suspend_guest_thread`, `open_guest_thread`, `guest_thread_count`, `guest_thread_at`, `guest_thread_exit_code_at`, `fill_teb`, `thread_terminate`.

## Write watching and the OEP trap

`runtime/memwatch.h`, `runtime/memwatch.cpp`

Watches guest writes to image memory by withdrawing write permission and restoring it inside `SIGSEGV`, and catches first instruction fetch at the OEP by withdrawing execute permission.

### Write-watch protocol

1. Withdraw write permission from the watched page, **keeping read and execute**
2. The guest's write raises `SIGSEGV`
3. `service_write` records the write (address, value, page)
4. **Temporarily grant write permission on that page**
5. Single-step the writing instruction with `EFLAGS.TF` (`0x100`)
6. `service_step` **re-protects** the page at the next instruction

The single-step is mandatory; without it there is no way to know the write has landed.

### OEP trap

A marked executable page is walked, execute permission is withdrawn on fetch, and a hit sets `oep_taken`.

### Environment knobs

`OCC_MEMWATCH` takes `image` (the whole image) or `rva:size` (a range); `OCC_DUMP_AT_OEP` turns on disk output; `OCC_TRACE_STEPS` bounds the instruction trace.

Section headers are parsed from the image at runtime (`kSectionSize = 40`) rather than hardcoded, so the watched range is never a guess.

## VM dispatch tracing

`runtime/vm_trace.h`, `runtime/vm_trace.cpp`

Traces every indirect jump of a virtual machine's dispatcher using page traps, not the TF flag, and writes registers, floats, and memory windows as JSON lines.

**Page traps rather than the TF flag is the design point.** The TF flag can only mark "the next instruction"; it cannot locate "this page is executed over and over". So the page holding the candidate address is made non-executable, and the hit both records and restores.

### Dispatcher identification

Byte-sequence matching, with five built-in `DispatchIdiom`s. Two are confirmed:

```
49 8b 0c c4              mov rcx, [r12+rax*8]
                          index=RAX base=R12 scale=8
48 63 14 93 48 01 da      relative offset table form
                          index=RDX base=RBX scale=4
```

Candidate addresses come from `kMaxCandidates = 16` `DispatchSite`s, inferred by observing execution patterns.

### Constants

```
kRingDepth            = 512
kSnapshotWindow       = 0x4000      // 16 KiB
kMaxSnapshots         = 512
kMaxGuestRanges       = 128
kGuestCeiling         = 0x40000000  // 1 GiB
kDispatchesPerMs      = 1000
kMapsBuffer           = 1 << 17     // 128 KiB
```

### What a record holds

Each `DispatchRecord` carries `t` (virtual time), `rip`, `index`, `base`, `target`, plus captured `rsi`/`rdi`/`rsp`/`rbp`, `st0..st2`, `rt[8]` (XMM 0-7), and `gpr[16]` (all sixteen general registers, in the fixed `kGprOrder`/`kGprNames` order).

The ring buffer is `kRingDepth = 512`.

Virtual clock: each dispatch advances 1 ms at `kDispatchesPerMs = 1000`, so a guest running under acceleration still observes monotonically increasing time.

Memory snapshot window contents are resolved through `read()` against `/proc/self/maps`, which is how a guest address is mapped onto a host mapping.

### Output

JSON lines to the path in `OCC_VM_TRACE`, or to stderr when the value is `1`. `OCC_VM_DISPATCH` names the dispatcher address directly and skips inference. `flush_on_fault` guarantees buffered lines survive a fault.

## Image dump and minidump

`runtime/image_dump.h`, `runtime/image_dump.cpp`

Dumps section by section using virtual sizes, **preserving original RVAs**, so the dumped file has the same layout as the original image and RVAs can be mapped straight back for analysis.

It appends one extra section, `.occregs`, holding `EntryRegs` (fourteen registers) so `enter_guest_asm` can restore entry register state on the next run. That section is a private convention of this runtime, not a PE standard.

`kImportDirIndex = 1`; the dump fixes up the import directory pointer, because the in-memory IAT has already been resolved to absolute addresses.

`runtime/minidump.h`, `runtime/minidump.cpp` writes MDMP by hand, with no Windows SDK structures involved.

```
kSignature                   = 0x504D444D   // ASCII "MDMP"
kVersion                     = 42899
stream types               ThreadList=3 ModuleList=4 MemoryList=5
                             Exception=6 SystemInfo=7
kProcessorArchitectureAmd64 = 9
kContextAmd64                = 0x100000
kContextFull                 = 0x10003F
kStackBytes                  = 0x10000      // 64 KiB of stack
```

`build_context` reorders registers into minidump's greg index order. `summarize` gives a plain-text summary for when no file is wanted.

## Import slot reconstruction

`runtime/iat_rebuild.h`, `runtime/iat_rebuild.cpp`

Scans executable sections for indirect references to infer what a given image imports and which exports are data exports.

- Call/jmp indirect: `FF 15` (call [rip+disp32]) and `FF 25` (jmp [rip+disp32]), 6-byte instructions, disp32 at offset +2
- Mov indirect: `mov reg,[rip+disp32]`, 7-byte instruction, disp32 at offset +3

Only candidates whose computed target lands inside the image, and whose 8-byte value points at a registered export, are reported. "Does the value point at something we know" is the filter that keeps the false-positive rate down.

`DataExport` handles the "shifted left by one byte" correction; MSVC encodes data export pointers differently from ordinary exports.

`RefForm{Call, Jump, Mov}` distinguishes the three reference forms.

## 32-bit interpreter

`runtime/i386.h`, `runtime/i386.cpp`

This is a **software 32-bit x86 CPU**, not a mirror of host x64 state. It exists because a 64-bit process cannot directly execute 32-bit code.

`Machine` holds eight 32-bit general registers, `eip`, `eflags`, `halted`, `exit_code`, `fs_base`, `nest_active`, `nest_saved_eip`, `esp_adjust`. The presence of `fs_base` says it runs 16/32-bit guest code and needs TEB semantics.

### Sparse paged memory

`kPageBits = 12`, `kPageSize = 4096`, with `pages_` and `page_base_` as the two-level structure. Pages are created and zeroed **on first touch**, so there is no preallocated-hole semantics to worry about.

`eflags` starts at `0x2` (bit 1 is always set) and stores eight arithmetic and direction flags: `kCF`, `kPF`, `kAF`, `kZF`, `kSF`, `kDF`, `kOF`.

### Flag computation

Four independent paths:

- `set_szp` sets S/Z/P
- `add_flags` affects CF/OF/AF/PF/SF/ZF on addition
- `sub_flags` the same on subtraction
- `logic_flags` affects CF/PF/SF/ZF and clears OF on logic operations

### HostCall mechanism

The import table is resolved into "one magic address per `(dll, name)`": `api_to_magic` and `magic_to_api` are the two directions, with magics counting up from `0x70000000`. IAT slots hold magic values, not real addresses.

`call`, `jmp`, and `ret` each consult `magic_to_api.find(target)`; a hit calls `host_call(state, dll, name, m, mem)`. Returning false means "this runtime cannot service that call", which becomes the guest's failure rather than an interpreter crash.

`note_magic(addr, dll, name)` lets a host callback register a magic it issued itself.

`call_guest` adds `GuestExecutor`: once a host callback holds a guest function pointer (global constructor traversal, atexit), it pushes arguments in cdecl order, pushes a sentinel return address, and re-enters the interpreter loop on the **same Machine**. `nest_active`/`nest_saved_eip` end the nested run when the guest returns by popping the sentinel.

Data imports: `IsData`/`DataInit` handle `__argc`, `_iob`, `__initenv` and similar variables that the guest **reads out of an IAT slot**, where the slot must point at guest memory reserved by the loader.

`run()` is one large switch covering opcodes `0x00` through `0xFF`. Static `s_exec_ctx`/`s_exec_fn` avoid recursing into the interpreter. `OCC_I386_TRACE` turns on instruction tracing.

`step_budget` is a `uint64_t`. An interpreter needs a budget, because a guest that loops forever is a hang, and a hang is not an answer.

## Containment and kernel objects

`runtime/containment.h`, `runtime/containment.cpp`

Keeps guest paths from escaping a designated root.

The primary path uses `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`, done **atomically in one system call**, so there is no TOCTOU window.

The fallback, for kernels without `openat2`, walks components with `openat` plus `readlinkat`, with symlink expansion capped at `kMaxSymlinks = 40`. That path is not atomic, and it is a stated downgrade; `confinement_unsupported` marks the state where confinement is unavailable.

`RESOLVE_NO_MAGICLINKS` blocks `/proc/self/fd`-style magic links.

Two entry points are offered: the implicit one using the internal root fd, and `_under` for an explicit anchor fd.

`RESOLVE_BENEATH = 0x01`, `RESOLVE_NO_MAGICLINKS = 0x02`.

`runtime/objects.h`, `runtime/objects.cpp` is the host-side kernel object manager, modeling exactly three kinds: Event, Mutex, Semaphore.

Handle base is `kHandleBase = 0x200000`, chosen above the file-handle range. `kInfinite = 0xFFFFFFFF`.

`WaitOutcome{Signalled, TimedOut, NoSuchObject}` is three-state on purpose: "no such object" and "timed out" must be distinguishable. An auto-reset event consumes its signal on a successful `wait_one`.

## API simulation layer

`runtime/api/` holds 108 files, about 189,000 lines. Total registered exports: 12181, of which 5792 are generated and 6389 hand-written.

### Registration path

Every `add_*` domain function pushes `HostExport{name, address}` entries into the same `ExportList`:

```cpp
const auto e = [](const char* n, void* fn) { HostExport entry;
    entry.name = n; entry.address = reinterpret_cast<std::uint64_t>(fn); return entry; };
out.push_back(e("Name", reinterpret_cast<void*>(&handler)));
```

The same data is consumed in three places, so registering a name in one file makes it visible to both `LoadLibrary` and `GetProcAddress`.

### Module table

`winabi.cpp`'s static `kModules[]` has **77 entries**, consumed by `register_host_modules`:

```
KERNEL32.dll        KERNELBASE.dll      msvcrt.dll          USER32.dll
PSAPI.dll           PSAPI.DLL           VERSION.dll         DBGHELP.dll
SECUR32.dll         SSPICLI.dll         SHLWAPI.dll         NTDLL.dll
GDI32.dll           ADVAPI32.dll        RPCRT4.dll          SETUPAPI.dll
SHELL32.dll         CRYPT32.dll         BCRYPT.dll          bcryptprimitives.dll
winmm.dll           MSCOREE.dll         WS2_32.dll          WININET.dll
URLMON.dll          IPHLPAPI.dll        OLE32.dll           UCRTBASE.dll
VCRUNTIME140.dll    VCRUNTIME140_1.dll  MSVCP140.dll
the 15 api-ms-win-crt-*.dll modules Windows ships (runtime / stdio /
  string / math / locale / time / convert / heap / environment /
  filesystem / process / conio / utility / multibyte / private, all
  l1-1-0; the -stdlib and -ctype names are not modules Windows builds)
MSVCR70/71/80/90/100/110/120/120_APP/MSVCRTD.dll
MSVCIRT.dll        MSVCRT20.dll        MSVCRT40.dll
```

`PSAPI.dll` and `PSAPI.DLL` point at the same constructor, differing only in case; likewise `SSPICLI.dll` and `SECUR32.dll`. DLL name comparison is case-insensitive, so this is not a bug; it exercises the comparison logic.

Module constructor locations: `add_kernel32` (winabi.cpp:5644), `add_module_psapi` (5808), `add_module_secur32` (5815), `add_module_dbghelp` (5820), `add_module_version` (5828), `add_module_vcruntime140` (5833), `add_module_vcruntime140_1` (5838), `add_module_msvcp140` (5843), `add_user32` (5848), `add_kernelbase` (5873), `add_shlwapi` (5886), `add_msvcrt` (5901). The rest live in `api/modules.cpp`.

### File-by-file coverage

| File | Lines | Coverage |
|---|---|---|
| `crt_families.cpp` | 9773 | The family surfaces the apiset split parcels out: the math family in all three widths plus the SSE2 spellings, the string and ctype families narrow and wide, the filesystem family (stat in four layouts, the find family over the kernel32 walks, the directory and path spellings), the environment, process, heap, locale, conio, convert and time families, the low-level descriptor family over the confined open, and the family table the forwarder modules are built from |
| `module_table.cpp` | The process's module ledger: the load (two passes, so a dependency cycle is a shape of the graph rather than a failure), the entry-point order, the export index, and the reference counts a `FreeLibrary` moves |
| `dll_runtime.cpp` | The library lifecycle: the process built around a DLL, the load, the entry points in post-order, and the call path |
| `crt.cpp` | 827 | Classic C runtime, 176 exports. Process and exit, memory, narrow strings, wide strings, mem functions, stdio, conversion, math, time, integer division, sort/search, random, environment, locale, thread-local locks, argv accessors. Shared by all 11 msvcr*/msvcrt* modules, with the module name as the only parameter |
| `ucrt_extra.cpp` | 4258 | Modern UCRT, 176 exports. `_s` safe series, wide stdio, printf/scanf variadic families, the `__stdio_common_*` formatting core, locale-aware `_l` suffixes, locale objects, path splitting, threads, aligned allocation, error handling, console |
| `ntdll_rtl_str.cpp` | 5669 | 130 `Rtl*` exports. ANSI/Unicode interconversion, string construction and concatenation, compare/find, case, memory operations, code page conversion core, UTF-16 normalization, numeric conversion, IP address text, IDN, SID strings, environment variable expansion, GUID, messages, function tables, context, the `IMemoryStream` family, atomics |
| `ntdll_rtl_mem1.cpp` | 3449 | 156 `Rtl*` exports. Heap, ACE/ACL, security descriptors, SIDs, security objects, Resource Manager, SRW locks, critical sections, atom tables, registry, attribute sets, activation context, RXact transactions, bit operations, pointer encoding and barriers, handle tables, compression, large integers, diagnostics, PE images, event wait, DOS/NT path conversion, process and thread creation, vector exceptions |
| `ntdll_rtl_mem2.cpp` | 4263 | 167 `Rtl*` exports. Version and product, time, SLIST, exceptions, stack unwind context, environment and directories, Generic Table, red-black tree, security descriptor field access, access masks, error conversion, error mode and filters, language and locale, transactions and callbacks, package identity, the `NtUser*` pfn indirection layer, condition variables, FLS, RunOnce, CRC32, PE reverse lookup |
| `ntdll_rtl_mem3.cpp` | 4301 | 156 `Rtl*` exports. Private `Rtlp*`, the Wow64 family, query classes, set classes, large-integer arithmetic, identity and path, checksum, version, startup |
| `gdi32.cpp` | 5348 | 191 exports. DCs, drawing, bitmaps, DC state, viewport/window/world transforms, clipping, objects, regions, paths, palettes, text |
| `user32_windows.cpp` | 3106 | 128 exports. Window creation and destruction, window properties, window queries, window state, class registration, messages, menus, dialogs, window enumeration, clipboard, cursor and icon timers, keyboard, system metrics |
| `kernel32_proc.cpp` | 2397 | 64 exports. Process and thread creation, status, priority and affinity, system information, cache and code page, Toolhelp snapshots, opening handles, thread pool I/O |
| `kernel32_sync.cpp` | 1874 | 76 exports. Events, mutexes, semaphores, waitable timers, timer queues, thread pool timers and waits, waits and condition variables, debug sessions, console events, named pipes and serial, event log |
| `kernel32_str.cpp` | 1374 | 40 exports. `CompareString*`, `FoldString*`, `GetStringType*`, `IsDBCSLeadByte`, `LCMapString*`, the whole `lstr*` family |
| `kernel32_file3.cpp` | 1206 | 22 exports. `CopyFileEx*`, `CreateHardLink*`, `FindFirstFile*`, `GetCompressedFileSize*`, `GetFileTime`, `GetLongPathNameA`, `GetShortPathName*`, `GetVolumePathName*`, `LockFile*`, `SetFilePointer`, `SetFileTime`, `UnlockFile*` |
| `memory.cpp` | 1072 | 36 exports. `Global*`, `Local*`, `Heap*`, `Virtual*`, `GetProcessHeaps`, `Read/WriteProcessMemory` |
| `advapi32_reg.cpp` | 2373 | 90 exports. The registry family: key open/create, key enumeration and query, value writing, delete, save/restore/replace, rename and remap, transactions and notification, reflection, security, copy, event log and tracing |
| `advapi32_sec.cpp` | 2530 | 132 exports. SIDs, ACLs, security descriptors, tokens, logon and lookup, privilege names, the service control manager |
| `ws2_32.cpp` | 4262 | 136 exports. Berkeley sockets, name resolution, wide-char resolution, address conversion, byte order, WSA extensions, WSC service provider configuration |
| `crypt32.cpp` | 5509 | 73 exports. Certificate stores, certificate contexts, names and key usage, CAPI, PKCS#7 messages, memory, DPAPI |
| `secur32.cpp` | 2249 | 45 exports. SSPI contexts, LSA, user and computer name, SASL |
| `shell_mem.cpp` | 1406 | 29 exports. Language preference, locale names, mitigation policy, heap walking. One file registering `Rtl*` spellings to NTDLL and Win32 spellings to KERNEL32 |
| `file.cpp` | 907 | 24 exports. `CopyFile*`, `CreateDirectory*`, `GetCurrentDirectory*`, `GetFileAttributes*`, `GetFullPathName*`, `GetTempPath*`, `MoveFile*`, `RemoveDirectory*`, `SetCurrentDirectory*`, `SetFileAttributes*` |
| `msvcp140.cpp` | 907 | MSVC-mangled exports. Allocation operators, six stream objects (`cout`/`cin`/`cerr`/`wcout`/`wcin`/`wcerr`) as data exports, insertion operator overloads, manipulators, ostream/istream members, the full `streambuf` vtable, `ios_base` state, member template versions |
| `antidebug2.cpp` | 2295 | 64 exports. Debug architecture detection, time and affinity, topology, version and firmware, locale, path search and drive letters, code pages and input devices, session and window station |
| `iphlpapi.cpp` | 967 | 56 exports. Adapters and interfaces, IP address tables, routing tables, statistics, connection-level statistics, network parameters, notifications. One of the few modules that actually queries the host network stack |
| `ntdll_antidebug.cpp` | 1451 | 13 `Nt*`/`Zw*` name pairs, 26 exports. `NtQueryInformationProcess`, `NtQuerySystemInformation`, `NtQueryObject`, `NtQueryVirtualMemory`, and the rest |
| `kernel32_file2.cpp` | 563 | 8 exports. `CreateFileW`, `DeleteFileW`, `FindClose`, `FindFirstFileExW`, `FindNextFileW`, `FlushFileBuffers`, `GetLongPathNameW`, `SetFilePointerEx` |
| `kernel32_sys2.cpp` | 887 | 28 exports. `DebugBreak`, environment block, code page, NUMA/topology, job objects, memory status |
| `kernel32_io2.cpp` | 672 | 8 exports. Completion ports, overlapped I/O, `DeviceIoControl`, `SetFileInformationByHandle` |
| `kernel32_ctx2.cpp` | 542 | 17 exports. Vectored exception handlers, `FreeLibrary`, `Get/SetThreadContext`, condition variable initialization, XState, `UnhandledExceptionFilter` |
| `kernel32_err.cpp` | 715 | 5 exports. `Beep`, `FormatMessageA/W`, `Get/SetErrorMode` |
| `kernel32_debug.cpp` | 154 | 5 exports. `CheckRemoteDebuggerPresent`, `OutputDebugStringA/W`, `DebugActiveProcess`, `DebugActiveProcessStop` |
| `kernel32_state2.cpp` | 382 | 11 exports. FLS, `EncodePointer`, file information, critical sections, `InitializeSListHead`, `RtlPcToFileHeader` |
| `sysinfo_ext.cpp` | 283 | 13 exports. Firmware tables, version numbers, OEM code page conversion |
| `selfcheck_ext.cpp` | 513 | 20 exports. `FatalAppExit*`, `FreeLibraryAndExitThread`, firmware environment variables, I/O counters, the `IsBad*Ptr` family |
| `strcase_ext.cpp` | 264 | 11 exports. ANSI/OEM and case conversion, `AnsiNext`/`AnsiPrev`, which are DBCS-aware single-character steps rather than +1/-1 |
| `rpcrt4.cpp` | 1216 | 65 exports. RPC binding, registration, impersonation and exceptions, async, memory, NDR, UUID |
| `path.cpp` | 983 | 30 exports. The `Path*` family, pure string-level path arithmetic with no filesystem contact |
| `string.cpp` | 1000 | 58 exports. The `Str*` series, registered to both KERNELBASE and SHLWAPI |
| `dbghelp.cpp` | 1466 | 49 exports. Symbol API, `StackWalk*`, imagehlp spellings, minidump, file tree |
| `vcruntime.cpp` | 360 | 38 exports. EH (`__CxxFrameHandler3/4`, `__CxxThrowException`, and the rest), `__vcrt_*` initialization, standard library support, entropy, overwrite-string memory |
| `ldr_ext2.cpp` | 1020 | 20 exports. Loader lock, notifications, resource lookup, `LoadLibraryExA` |
| `kernel32_extra.cpp` | 35 | Empty placeholder, contributing 0 exports. A mounting point for later work |
| `advapi32_token2.cpp` | 400 | 4 exports. `AdjustTokenGroups`, `DuplicateToken`, `DuplicateTokenEx`, `SetThreadToken` |
| `ntdll_debug.cpp` | 803 | 35 exports. DbgUi debug sessions, the CSR family, ALPC, A_SHA |
| `ntdll_file2.cpp` | 1201 | 12 exports. `RtlGenRandom`, `RtlGetCurrentTeb`, and a set of file existence helpers |
| `advapi32.cpp` | 35 | Empty placeholder, 0 exports |
| `ntdll_rtl.cpp` | 35 | Empty placeholder, 0 exports |
| `filemap.cpp` | 464 | 7 exports. `CreateFileMapping*`, `OpenFileMapping*`, `MapViewOfFile*`, `UnmapViewOfFile` |
| `version.cpp` | 733 | 16 exports. Version resources and installation validation |
| `ole32.cpp` | 187 | 4 exports. `CoInitializeEx`, `CoUninitialize`, `CoGetApartmentType`, `CoWaitForMultipleHandles` |
| `bcrypt.cpp` | 866 | 9 exports. `add_bcrypt` 8 (`BCryptOpenAlgorithmProvider` and the rest), `add_bcryptprimitives` 1 (`ProcessPrng`) |
| `wininet.cpp` | 462 | 6 exports. `InternetOpenA`, `InternetConnectA`, `InternetOpenUrlA`, `HttpSendRequestA`, `InternetReadFile`, `InternetCloseHandle`. Carries the shared download engine `wininet_http_get` |
| `urlmon.cpp` | 87 | 1 export. `URLDownloadToFileA`, reusing `wininet_http_get` |
| `setupapi.cpp` | 174 | 4 exports. `SetupDiGetClassDevsA/W`, `SetupDiEnumDeviceInfo`, `SetupDiDestroyDeviceInfoList` |
| `shell32.cpp` | 188 | 4 exports. `SHGetFolderPathA/W`, `SHGetSpecialFolderPathA/W` |
| `shell_exec.cpp` | 140 | 2 exports. `ShellExecuteA/W` |
| `imagehlp.cpp` | 178 | 2 exports. `CheckSumMappedFile`, `MapFileAndCheckSumA` |
| `dbg_ext.cpp` | 50 | 1 export. `DebugSetProcessKillOnExit` |
| `mscoree.cpp` | 102 | 4 exports. `CorExitProcess` supplies an exit path; the other three return `-1` (`CLR_E_SHIM_RUNTIME`) with `kErrorNotFound` set, telling the guest plainly that there is no CLR here |
| `winmm.cpp` | 99 | 4 exports. `timeBeginPeriod`, `timeEndPeriod`, `timeGetDevCaps`, `timeGetTime` |
| `kernelbase_extra.cpp` | 173 | 9 exports. The `AppPolicyGet*` family |
| `threads_ext.cpp` | 149 | 2 exports. `CreateRemoteThread`, `QueueUserAPC` |
| `proc_ext.cpp` | 168 | 3 exports. `WinExec`, `GetTempFileNameA` |
| `ldr_ext.cpp` | 208 | 4 exports. `LdrLoadDll`, `LdrGetProcedureAddress`, `NtGetContextThread`, `NtSetContextThread` |
| `ntdll_nt.cpp` | 137 | 4 exports. `Nt/Zw QueryInformationThread`, `Nt/Zw SetInformationThread` |
| `modules.cpp` | tables | The 15 `api-ms-win-crt-*` forwarder stub name tables and the MSVCR* alias tables |
| `api_common.cpp` | 133 | ANSI/wide-string capacity computation and narrowing, fixed-width guest memory access primitives |

### The api_common contract

Error code constants, HRESULT constants, ANSI/wide-string conversion, guest struct layouts, and guest memory primitives shared by every API domain.

Structures are defined as byte layouts, never converted:

```
SystemTimeLayout  16 bytes
FileTimeLayout     8 bytes
OverlappedLayout  40 bytes
```

`read_u8/u16/u32/u64` and `write_u8/u16/u32/u64` are the only path across the boundary, so bounds checking exists in exactly one implementation.

`required_capacity` and `fits` are the safety preconditions for wide-to-narrow conversion: compute the bytes needed, then check the destination buffer can hold them. Never write past `nBufferSize`.

Error constants run from `kErrorSuccess=0` to `kErrorBusy=170`, plus `kInvalidHandleValue` and `kInvalidHandle`. HRESULT constants run from `kSOk` to `kEDataError`.

### Loading a library

`occ dll` loads a library and drives its lifecycle, and three files are the
whole of it.

**`module_table.cpp` is the ledger.** One entry per module -- the image the
process was built around, the images `guest_module.cpp` synthesises for the
API modules, and every file loaded from disk -- carrying the base, the size,
the entry point, the reference count, the export index and the dependencies.
It is the first place in this runtime where a module is a thing rather than
a shape: before it, `LoadLibrary` answered "module not found" for anything
that was not an API module this runtime implements, and `FreeLibrary`
refused every handle but the image's own.

**The load is two passes, and that is what makes the order independent of
the dependency graph's shape.** The first pass walks the graph in post-order
and maps every node with the loader's resolver *unset* -- which maps,
relocates and records the import table without resolving it, because the
loader writes the IAT only when there is a resolver to ask. The second pass
walks the same order and resolves, writing each recorded import into its
slot. The alternative -- resolving during the load, which is what the
loader's resolver callback invites -- cannot survive a cycle: A importing B
and B importing A makes A's load call B's load call A's load, and the second
visit finds a module with no base because the first has not returned. It is
also what the platform's own loader does, by the same means: it maps before
it snapshots.

**`dll_runtime.cpp` is the lifecycle.** The process is built around the
library itself -- an address space, a PEB with a loader list, a TEB with a
TLS array, a stack -- and the only difference from `occ run` is that the
entry point is *called* with a reason rather than jumped to. The order is
post-order: a module's dependencies' entry points run before its own, which
is what makes a dependency's exported data valid by the time its dependent's
`DllMain` reads it. The detach runs in the reverse order.

**The entry points are called through `call_guest_entry`, and the call is
where the convention lives.** `run_pe_process` never needs a return leg --
a program leaves by `ExitProcess` or by faulting -- so this is the other
shape: a `call` that comes back. Its arguments are positional, which is the
whole of the x64 convention's argument rule and the one thing about it that
is easy to get wrong: the first four arguments go in registers, one register
per *position*, and the register is chosen by the argument's type rather
than by how many arguments of that type came before it. `f(int, double)`
puts the integer in `rcx` and the double in `xmm1`; a caller that counted
the two classes apart puts the double in `xmm0` and the integer on the
stack, which is a call with both arguments wrong. The dispatch is therefore
a switch over the sixteen shapes four positions and two classes produce,
one signature each, and the same switch appears twice because the answer can
come back in `rax` or in `xmm0` depending on the function's declared return
type -- which a file does not carry, so the caller says.

**The state is assembled once per process, not once per call.** Building it
registers every module's TLS and runs the process-attach callbacks, so a
session that rebuilt it per call would run every module's initializer once
per call. One `GuestCallSession` is one process's worth of setup, and the
calls made through it share it.

**A dependency that is a third-party runtime is an API-coverage question
rather than a loading question.** The loader walks a real dependency chain
correctly -- loading `helper.dll` from the mingw toolchain pulls in
`libgcc_s_seh-1.dll`, and that pulls in `libwinpthread-1.dll`, with each
module's imports resolved against the one below it -- and the chain then
stops at the first API this runtime does not implement, with the failure
naming the module and the symbol: `libwinpthread-1.dll wants
msvcrt.dll!_setjmp`. That is the honest boundary: what the runtime loads is
every DLL whose imports the API surface answers, which is the library and
its dependencies as long as those dependencies are the Windows system DLLs
rather than a compiler's own runtime.

**What it does not do.** A fifth argument travels on the stack, past the
shadow space, and this call does not place it: `occ dll` refuses a call with
one rather than making a call with an argument missing. `DllMain` is called
for `DLL_PROCESS_ATTACH` and `DLL_PROCESS_DETACH`; the thread reasons exist
in the same machinery and no path here produces them, because this runtime
does not start guest threads. A forwarder resolves at `GetProcAddress` time
rather than at load time, which is what the platform does: a forwarder to a
module that is not loaded is a failed call, not a failed load.

### The apiset forwarder surface

`modules.cpp`'s `kCrtForwarders[]` states the name set each of the 15
`api-ms-win-crt-*` contract modules carries, and the table lives in
`api.h` so the tests can iterate it. The implementation loads the
complete export face -- `add_crt_exports`, `add_ucrt_extra`, and the
family domain `add_crt_families` -- into a temporary `ExportList full`,
then filters that down to the subset each module should hold.

**Every name in the table resolves, to the implementation the base face
holds.** `tests/test_crt_forwarders.cpp` walks the table and asserts it
per name: the registry resolves it through the contract module, the
address is the one the full face answers, and the module carries exactly
the set and nothing more. The two module names the older table carried
that Windows does not ship (`-stdlib`, `-ctype`) are gone, and the
classic names that are header inlines on the UCRT (`printf`, `time`,
`mktime`, and the rest) are absent from every family, which is the
answer the real modules give.

**The families whose remainder is machinery rather than spelling are
narrower than their real counterparts.** Six families -- environment,
filesystem, heap, process, conio and utility -- are complete. The
residuals: private is missing the 1177 names that are the C++ exception
machinery, the demangler and the `_o_` detour spellings; multibyte is
missing the 199 multi-byte string functions, whose code pages this
single-byte runtime does not configure; math is missing the 166 names
that are the complex-arithmetic family and the vendor's internal float
helpers; convert, string, stdio, runtime, locale and time are missing
45, 23, 9, 8, 3 and 4 names. A guest calling one of the missing names
through a contract module gets a failed `GetProcAddress`, the same
refusal the real loader gives.

### The msvcp140 tradeoff

The six stream objects are 64-byte **static byte arrays**, not real `basic_ostream` instances. A real `basic_ostream` lives in the guest's own static initialization; these objects only need to be large enough that any call answered against them stays in bounds.

The insertion core, `msvcp_render(ostream, text, len)`, returns the object address unchanged and `fwrite`s the rendered text to host stdout. So `a << b << std::endl` keeps chaining on the guest side.

This is a deliberate good-enough tradeoff, and the file header says so.

### Consistency of the anti-detection answers

Three files give mutually consistent answers:

- `ntdll_antidebug.cpp`: `ProcessDebugPort` returns 0, `ProcessDebugFlags` returns 1 (the "no inherit debug" bit), `ProcessDebugObjectHandle` **fails with `STATUS_PORT_NOT_SET`**
- `kernel32_debug.cpp`: `CheckRemoteDebuggerPresent` always reports no debugger
- `antidebug2.cpp`: `IsWow64Process` is always false, because the guest really is running native x64

`ProcessDebugObjectHandle` deliberately uses an error rather than "success, returns 0", because the two are distinguishable and anti-debug checks know which one they asked for.

Unmodeled classes return the error the kernel would return, not a zeroed buffer.

### The ntdll subset's host-side machinery

`runtime/ntdll.h`, `runtime/ntdll.cpp`

`NtContext`, `EventSink`, and `EventRecorder` (`kCapacity = 800`, a bounded ring so a guest hammering system calls cannot grow it without limit).

`handle_cookie_for` and `handle_parts`: a handle is **an index plus a cookie**, not a pointer. The cookie is a SplitMix-style 64-bit hash (multiply by `0x9E3779B97F4A7C15ULL`, xor-shift, multiply by `0xBF58476D1CE4E5B9ULL`, forced non-zero), so a guest cannot derive a host address from a handle value.

`MemoryBasicInformation` is 48 bytes, with a `static_assert`.

`MemoryInformationClass` includes two occ-specific classes: `RegionLedger = 0x1000` and `RegionHistory = 0x1001`, exposing the address space ledger to the guest through NT semantics. `MemoryRegionLedger`'s section name is a fixed 64-byte array rather than a `std::string`, because it is a wire structure the guest reads.

`zero_bits_accepts` implements NT's zero-bit acceptance rule.

### Guest debugger

`runtime/guestdbg.h`, `runtime/guestdbg.cpp`

A three-state machine: `kRunning=0`, `kStopped=1`, `kReleased=2`.

**Software breakpoints** overwrite the target byte with `0xCC` (INT3), keeping the displaced **original byte** in the `g_breakpoints` map. Re-arming (`complete_rearm`) writes the original byte back, and `enter_stop` writes `0xCC` in again. `g_rearm_pending` and `g_rearm_address` are the state for that pair of operations.

**Hardware breakpoints never write guest memory**: `g_hard_breakpoints` single-steps and compares the RIP about to execute against the target list. Performance is traded for the guarantee that no byte of guest code is ever modified, which is the property that matters for code that integrity-scans itself.

`Stop` records both `breakpoint` and `hardware` as separate booleans.

### API hook

`runtime/api_hook.h`, `runtime/api_hook.cpp`

Records which host API a guest called. `note` is the recording entry point; `occ_api_hook` and `occ_api_note` are the C-linkage symbols; `dump_map` emits the mapping, `name_for_address` looks a name up by address, and `note_trampoline` records interception at the trampoline layer.

### The 32-bit runner

`runner/pe_runner.cpp`'s `run_pe_32` is the 32-bit counterpart, and the container is deliberately absent there: the interpreter is itself the isolation.

---

Related: [DESIGN](DESIGN.md) for the overall structure, [EVENTS](EVENTS.md) for the event stream and observation layer, [RSP](RSP.md) for the debug protocol.
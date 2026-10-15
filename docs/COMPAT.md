# COMPAT

What this runtime answers, what it does not, and how the API surface is organized. All figures come from the source: `src/runtime/api/`, `src/runtime/winabi.cpp`, `src/runtime/apiset.cpp`, `src/runtime/exports.cpp`.

Totals: **77 module entries** (**76 registered**; one pair differs only in case), **12181 registered exports**, **364 API set entries**, across **205 source files** and roughly 288,000 lines. Of those exports, **5792** are the generated surface described below, and **6389** are hand-written.

---

## Contents

- [How the surface is built](#how-the-surface-is-built)
- [Module table](#module-table)
- [Coverage by DLL](#coverage-by-dll)
- [The generated surface](#the-generated-surface)
- [API set resolution](#api-set-resolution)
- [The forwarder gap](#the-forwarder-gap)
- [Loading a library](#loading-a-library)
- [What is deliberately not answered](#what-is-deliberately-not-answered)
- [Guest-visible objects](#guest-visible-objects)
- [Consistency rules](#consistency-rules)

---

## How the surface is built

One registration path. Every `add_*` domain function pushes `HostExport{name, address}` into the same `ExportList`:

```cpp
const auto e = [](const char* n, void* fn) { HostExport entry;
    entry.name = n; entry.address = reinterpret_cast<std::uint64_t>(fn); return entry; };
out.push_back(e("Name", reinterpret_cast<void*>(&handler)));
```

The same list is consumed in three places:

1. `ExportRegistry`, which backs the host-side `GetProcAddress`
2. `own_export_index`, indexed by folded name
3. `guest_module_inputs`, which builds the synthetic PE images the guest parses

So registering a name in one file makes it visible to both `LoadLibrary` and `GetProcAddress`, and the guest sees a real, executable trampoline for it rather than an invalid handle.

DLL name comparison is ASCII case-insensitive. `PSAPI.dll` and `PSAPI.DLL` are two entries in the module table pointing at one constructor; that is a deliberate exercise of the comparison logic, not a duplicate.

Lookup tries the hint index first, then binary search, because a guest's hint is frequently wrong.

Forwarder detection: a target RVA inside the export directory range is a forwarder, resolved to depth `kMaxForwarderDepth = 4`.

## Module table

`winabi.cpp`'s static `kModules[]`, 77 entries, consumed by `register_host_modules`:

| Group | Modules |
|---|---|
| Core | `KERNEL32.dll`, `KERNELBASE.dll`, `ntdll.dll`, `SHLWAPI.dll` |
| C runtime | `msvcrt.dll`, `UCRTBASE.dll`, `MSVCR70/71/80/90/100/110/120/120_APP/MSVCRTD.dll`, `MSVCIRT.dll`, `MSVCRT20.dll`, `MSVCRT40.dll` |
| C++ runtime | `MSVCP140.dll`, `VCRUNTIME140.dll`, `VCRUNTIME140_1.dll` |
| Contract modules | the 15 `api-ms-win-crt-*.dll` modules Windows ships, all `l1-1-0`: runtime, stdio, string, math, locale, time, convert, heap, environment, filesystem, process, conio, utility, multibyte, private. The `-stdlib` and `-ctype` names the older table carried are not modules Windows builds, and a guest that imports one is refused the way the loader refuses any module it cannot find |
| UI | `USER32.dll`, `GDI32.dll` |
| Security | `ADVAPI32.dll`, `CRYPT32.dll`, `BCRYPT.dll`, `bcryptprimitives.dll`, `SECUR32.dll`, `SSPICLI.dll` |
| Network | `WS2_32.dll`, `WININET.dll`, `URLMON.dll`, `IPHLPAPI.dll` |
| Shell and COM | `SHELL32.dll`, `OLE32.dll` |
| System | `VERSION.dll`, `DBGHELP.dll`, `PSAPI.dll`, `PSAPI.DLL`, `RPCRT4.dll`, `SETUPAPI.dll`, `winmm.dll`, `MSCOREE.dll` |
| Generated, whole surface | `AVIFIL32.dll`, `COMCTL32.dll`, `COMDLG32.dll`, `DHCPCSVC.dll`, `DNSAPI.dll`, `IMM32.dll`, `MPR.dll`, `MSACM32.dll`, `MSWSOCK.dll`, `NETAPI32.dll`, `OLEAUT32.dll`, `OPENGL32.dll`, `USERENV.dll`, `UXTHEME.dll`, `WINHTTP.dll`, `WINSPOOL.DRV`, `WINTRUST.dll`, `WLDAP32.dll`, `WTSAPI32.dll` |

Module constructor locations in `winabi.cpp`: `add_kernel32` (5710), `add_module_psapi` (5875), `add_module_secur32` (5882), `add_module_dbghelp` (5888), `add_module_version` (5897), `add_module_vcruntime140` (5902), `add_module_msvcp140` (5912), `add_user32` (5917), `add_kernelbase` (5943), `add_shlwapi` (5956), `add_msvcrt` (5972). The rest are in `api/modules.cpp`.

## Coverage by DLL

### kernel32

| File | Exports | Covers |
|---|---|---|
| `kernel32_proc.cpp` | 64 | Process and thread creation, status, priority and affinity, system information, cache and code page, Toolhelp snapshots, opening handles, thread pool I/O |
| `kernel32_sync.cpp` | 76 | Events, mutexes, semaphores, waitable timers, timer queues, thread pool timers and waits, waits and condition variables, debug sessions, console events, named pipes and serial, event log |
| `kernel32_str.cpp` | 40 | `CompareString*`, `FoldString*`, `GetStringType*`, `IsDBCSLeadByte`, `LCMapString*`, `lstr*` |
| `kernel32_file3.cpp` | 22 | `CopyFileEx*`, `CreateHardLink*`, `FindFirstFile*`, `GetCompressedFileSize*`, `GetFileTime`, `GetLongPathNameA`, `GetShortPathName*`, `GetVolumePathName*`, `LockFile*`, `SetFilePointer`, `SetFileTime`, `UnlockFile*` |
| `kernel32_sys2.cpp` | 28 | `DebugBreak`, environment block, code page, NUMA/topology, job objects, memory status |
| `kernel32_io2.cpp` | 8 | Completion ports, overlapped I/O, `DeviceIoControl`, `SetFileInformationByHandle` |
| `kernel32_ctx2.cpp` | 17 | Vectored exception handlers, `FreeLibrary`, `Get/SetThreadContext`, condition variable initialization, XState, `UnhandledExceptionFilter` |
| `kernel32_err.cpp` | 5 | `Beep`, `FormatMessageA/W`, `Get/SetErrorMode` |
| `kernel32_debug.cpp` | 5 | `CheckRemoteDebuggerPresent`, `OutputDebugStringA/W`, `DebugActiveProcess`, `DebugActiveProcessStop` |
| `kernel32_state2.cpp` | 11 | FLS, `EncodePointer`, file information, critical sections, `InitializeSListHead`, `RtlPcToFileHeader` |
| `kernel32_file2.cpp` | 8 | `CreateFileW`, `DeleteFileW`, `FindClose`, `FindFirstFileExW`, `FindNextFileW`, `FlushFileBuffers`, `GetLongPathNameW`, `SetFilePointerEx` |
| `file.cpp` | 24 | `CopyFile*`, `CreateDirectory*`, `GetCurrentDirectory*`, `GetFileAttributes*`, `GetFullPathName*`, `GetTempPath*`, `MoveFile*`, `RemoveDirectory*`, `SetCurrentDirectory*`, `SetFileAttributes*` |
| `filemap.cpp` | 7 | `CreateFileMapping*`, `OpenFileMapping*`, `MapViewOfFile*`, `UnmapViewOfFile` |
| `memory.cpp` | 36 | `Global*`, `Local*`, `Heap*`, `Virtual*`, `GetProcessHeaps`, `Read/WriteProcessMemory` |
| `proc_ext.cpp` | 3 | `WinExec`, `GetTempFileNameA` |
| `threads_ext.cpp` | 2 | `CreateRemoteThread`, `QueueUserAPC` |
| `kernelbase_extra.cpp` | 9 | `AppPolicyGet*` |
| `kernel32_extra.cpp` | 0 | Empty placeholder, a mounting point |

### C and C++ runtime

| File | Exports | Covers |
|---|---|---|
| `crt.cpp` | 176 | Classic C runtime. Process and exit, memory, narrow and wide strings, mem functions, stdio, conversion, math, time, integer division, sort/search, random, environment, locale, thread-local locks, argv accessors. Shared by all 11 msvcr*/msvcrt* modules with the module name as the only parameter |
| `ucrt_extra.cpp` | 169 | Modern UCRT. `_s` safe series, wide stdio, printf/scanf variadic families, the `__stdio_common_*` formatting core, locale-aware `_l` suffixes, locale objects, path splitting, threads, aligned allocation, error handling, console |
| `msvcp140.cpp` | mangled | Allocation operators, six stream objects as data exports, insertion operator overloads, manipulators, ostream/istream members, the full `streambuf` vtable, `ios_base` state, member template versions |
| `vcruntime.cpp` | 38 | EH (`__CxxFrameHandler3/4`, `__CxxThrowException`), `__vcrt_*` initialization, standard library support, entropy, overwrite-string memory |
| `modules.cpp` | tables | The 15 `api-ms-win-crt-*` forwarder stub name tables and the MSVCR* alias tables |

### ntdll

| File | Exports | Covers |
|---|---|---|
| `ntdll_rtl_str.cpp` | 130 | ANSI/Unicode interconversion, string construction and concatenation, compare/find, case, memory operations, code page conversion core, UTF-16 normalization, numeric conversion, IP address text, IDN, SID strings, environment variable expansion, GUID, messages, function tables, context, the `IMemoryStream` family, atomics |
| `ntdll_rtl_mem1.cpp` | 156 | Heap, ACE/ACL, security descriptors, SIDs, security objects, Resource Manager, SRW locks, critical sections, atom tables, registry, attribute sets, activation context, RXact, bit operations, pointer encoding and barriers, handle tables, compression, large integers, diagnostics, PE images, event wait, DOS/NT path conversion, process and thread creation, vector exceptions |
| `ntdll_rtl_mem2.cpp` | 167 | Version and product, time, SLIST, exceptions, stack unwind context, environment and directories, Generic Table, red-black tree, security descriptor field access, access masks, error conversion, error mode and filters, language and locale, transactions and callbacks, package identity, the `NtUser*` pfn indirection layer, condition variables, FLS, RunOnce, CRC32, PE reverse lookup |
| `ntdll_rtl_mem3.cpp` | 156 | Private `Rtlp*`, the Wow64 family, query classes, set classes, large-integer arithmetic, identity and path, checksum, version, startup |
| `ntdll_antidebug.cpp` | 26 | 13 `Nt*`/`Zw*` name pairs: `NtQueryInformationProcess`, `NtQuerySystemInformation`, `NtQueryObject`, `NtQueryVirtualMemory`, and the rest |
| `ntdll_nt.cpp` | 4 | `Nt/Zw QueryInformationThread`, `Nt/Zw SetInformationThread` |
| `ntdll_debug.cpp` | 35 | DbgUi debug sessions, the CSR family, ALPC, A_SHA |
| `ntdll_file2.cpp` | 12 | `RtlGenRandom`, `RtlGetCurrentTeb`, file existence helpers |
| `ntdll_rtl.cpp` | 0 | Empty placeholder |

### Everything else

| File | Exports | Covers |
|---|---|---|
| `gdi32.cpp` | 191 | DCs, drawing, bitmaps, DC state, viewport/window/world transforms, clipping, objects, regions, paths, palettes, text |
| `user32_windows.cpp` | 128 | Window creation and destruction, window properties and queries, window state, class registration, messages, menus, dialogs, window enumeration, clipboard, cursor and icon timers, keyboard, system metrics |
| `ws2_32.cpp` | 136 | Berkeley sockets, name resolution, wide-char resolution, address conversion, byte order, WSA extensions, WSC service provider configuration |
| `crypt32.cpp` | 73 | Certificate stores, certificate contexts, names and key usage, CAPI, PKCS#7 messages, memory, DPAPI |
| `advapi32_reg.cpp` | 90 | The registry family: key open/create, key enumeration and query, value writing, delete, save/restore/replace, rename and remap, transactions and notification, reflection, security, copy, event log and tracing |
| `advapi32_sec.cpp` | 132 | SIDs, ACLs, security descriptors, tokens, logon and lookup, privilege names, the service control manager |
| `secur32.cpp` | 45 | SSPI contexts, LSA, user and computer name, SASL |
| `rpcrt4.cpp` | 65 | RPC binding, registration, impersonation and exceptions, async, memory, NDR, UUID |
| `dbghelp.cpp` | 49 | Symbol API, `StackWalk*`, imagehlp spellings, minidump, file tree |
| `string.cpp` | 58 | The `Str*` series, registered to both KERNELBASE and SHLWAPI |
| `path.cpp` | 30 | The `Path*` family, pure string-level path arithmetic with no filesystem contact |
| `shell32.cpp` | 4 | `SHGetFolderPathA/W`, `SHGetSpecialFolderPathA/W` |
| `shell_exec.cpp` | 2 | `ShellExecuteA/W` |
| `shell_mem.cpp` | 29 | Language preference, locale names, mitigation policy, heap walking. One file registering `Rtl*` spellings to NTDLL and Win32 spellings to KERNEL32 |
| `ole32.cpp` | 4 | `CoInitializeEx`, `CoUninitialize`, `CoGetApartmentType`, `CoWaitForMultipleHandles` |
| `bcrypt.cpp` | 9 | `add_bcrypt` 8 (`BCryptOpenAlgorithmProvider` and the rest), `add_bcryptprimitives` 1 (`ProcessPrng`) |
| `wininet.cpp` | 6 | `InternetOpenA`, `InternetConnectA`, `InternetOpenUrlA`, `HttpSendRequestA`, `InternetReadFile`, `InternetCloseHandle`. Carries the shared download engine `wininet_http_get` |
| `urlmon.cpp` | 1 | `URLDownloadToFileA`, reusing `wininet_http_get` |
| `iphlpapi.cpp` | 56 | Adapters and interfaces, IP address tables, routing tables, statistics, connection-level statistics, network parameters, notifications. One of the few modules that queries the host network stack |
| `setupapi.cpp` | 4 | `SetupDiGetClassDevsA/W`, `SetupDiEnumDeviceInfo`, `SetupDiDestroyDeviceInfoList` |
| `version.cpp` | 16 | Version resources and installation validation |
| `imagehlp.cpp` | 2 | `CheckSumMappedFile`, `MapFileAndCheckSumA` |
| `winmm.cpp` | 4 | `timeBeginPeriod`, `timeEndPeriod`, `timeGetDevCaps`, `timeGetTime` |
| `mscoree.cpp` | 4 | `CorExitProcess` supplies an exit path; the other three return `-1` (`CLR_E_SHIM_RUNTIME`) with `kErrorNotFound` set |
| `dbg_ext.cpp` | 1 | `DebugSetProcessKillOnExit` |
| `antidebug2.cpp` | 64 | Debug architecture detection, time and affinity, topology, version and firmware, locale, path search and drive letters, code pages and input devices, session and window station |
| `selfcheck_ext.cpp` | 20 | `FatalAppExit*`, `FreeLibraryAndExitThread`, firmware environment variables, I/O counters, the `IsBad*Ptr` family |
| `strcase_ext.cpp` | 11 | ANSI/OEM and case conversion, `AnsiNext`/`AnsiPrev`, which are DBCS-aware single-character steps rather than +1/-1 |
| `sysinfo_ext.cpp` | 13 | Firmware tables, version numbers, OEM code page conversion |
| `ldr_ext.cpp` | 4 | `LdrLoadDll`, `LdrGetProcedureAddress`, `NtGetContextThread`, `NtSetContextThread` |
| `ldr_ext2.cpp` | 20 | Loader lock, notifications, resource lookup, `LoadLibraryExA` |
| `advapi32_token2.cpp` | 4 | `AdjustTokenGroups`, `DuplicateToken`, `DuplicateTokenEx`, `SetThreadToken` |
| `advapi32.cpp` | 0 | Empty placeholder |

## The generated surface

`src/runtime/api/generated/` holds one C++ file per module: **37 files**, **89753 lines**, **5792 entry points**. They are the exports the mingw import libraries list and this runtime did not already answer, and every one of them has the signature the platform's own headers declare.

The names come from `nm` over the import libraries, which are the real DLLs' export tables. The signatures come from the headers, preprocessed by `x86_64-w64-mingw32-gcc -E` and read by `tools/apiwork/extract_prototypes.py`. The preprocessor is not optional: the declarations are macro-decorated, and a text scan of the raw headers reads `WINAPI` as a return type -- a signature whose answer the caller then reads out of a register the callee never wrote.

### Three kinds of entry point

| Kind | Count | What it does |
|---|---|---|
| Implementation | 200 | does the thing |
| Refusal | 5583 | `ERROR_CALL_NOT_IMPLEMENTED` through `SetLastError`, plus a comment naming the subsystem that would have to exist |
| Refusal, no declared signature | 9 | the headers do not declare the name, so the thunk names no parameters at all |

The signatureless case is safe rather than convenient, and the reason is the ABI: on the 64-bit Microsoft convention the caller allocates and releases the shadow space, so a callee that names no parameter reads neither it nor the registers the arguments arrived in. A guessed arity would not be safe, which is why the headers' silence is answered with no parameters rather than with a plausible-looking list.

What none of the three does is answer success for work that did not happen. A guest handed a window handle for a window that was never created will use that handle four more times and free it; a guest told the call is unavailable takes the branch it already has for that answer. The first failure surfaces somewhere else entirely, in code with no reason to suspect what went wrong.

### The refusals, by subsystem

The reasons are grouped by what would have to exist, not by function. `refuse.py` holds the table and the generated comments quote it.

| Subsystem | Families |
|---|---|
| the window manager | windows, menus, dialogs, messages, input, the desktop, the common controls, the common dialogs, themes, the IME |
| the graphics device layer | device contexts, bitmaps, brushes, fonts, palettes, regions, and the OpenGL client library |
| the device layer | the device tree, the print spooler, the audio and video device layers, serial ports, tape, volumes |
| the system services | the service control manager, the event log and audit, the network redirector, DHCP, DNS, LDAP, the security packages, the terminal services |
| the NT system call surface | `Nt*` and `Zw*` |
| the security subsystem | tokens, descriptors, access checks, the LSA |
| the COM and shell layers | interface calls by vtable, the shell namespace, the file-type database |
| the protocol clients | WinINet, WinHTTP, RPC, LDAP, the trust providers |
| the transactional file system | the `*Transacted` families and the kernel transaction manager |
| the locale and NLS data | calendar, collation, formatting and the code-page tables |

### What is implemented

Two hundred names, and they are the ones whose behaviour is a property of a format or of arithmetic rather than of a capability this machine lacks.

| Module | Implemented | What |
|---|---|---|
| `shlwapi` | 100 | the `Path*` grammar, the bounded `Str*` helpers, the shell's size and interval formatters, the narrow/wide conversions |
| `kernel32` | 100 | the interlocked and bit-test family, the S-list depth query, the one-shot and barrier objects, the pointer encoder, the DOS time conversions, the profile files, `MulDiv`, the wide multiply, `GetVersion`, `GetSystemWindowsDirectory`, and the calls the API documents as having no effect |

### The type table, and its last resort

`wintypes.py` names every type the headers use, and the names matter in exactly one respect: which register an argument travels in. A `FLOAT`, a `DATE` and a `GLclampf` are not integers that happen to be small, and a runtime that passed one in a general-purpose register would have the callee read a bit pattern out of an XMM register that was never written.

An unknown non-floating type of at most eight bytes travels in a general-purpose register whatever it is, so an unknown name maps to a 64-bit integer and the call is still correct. 700 distinct names reach that path; each is a handle, a status word or a pointer this table does not name, and each is checked by the rule that no floating-point name is among them.

### The generator

`tools/apiwork/` holds it, and the generated files are checked in. They are read, and a reader is owed the same review of them as of anything else here. The tool's own README states what it reads, what it writes and how to run it.

## API set resolution

`apiset.cpp` holds `kApiSets[]`, **364 entries**, sorted by name for `std::lower_bound`.

Matching lowercases the query and strips the `.dll` suffix, then binary searches. Both sides are normalized, so `API-MS-WIN-CORE-X.DLL` and `api-ms-win-core-x` are the same query. The `ext-ms-win-` prefix travels the same path, so third-party extension contracts resolve too.

The table order is a hard constraint. Any edit requires a re-sort, and a mis-sorted table fails silently, because binary search on an unsorted array returns whatever it finds first.

## Loading a library

`LoadLibrary` answers from three places, in this order, and the order is the
one the platform uses:

1. the API modules this runtime implements -- a real image is synthesised
   for each, so the handle is the base of something the guest can walk;
2. the modules already loaded into this process, by folded base name;
3. a file, searched in the directories the caller named, then loaded with
   its dependencies.

`GetProcAddress` answers a name, an ordinal, or a forwarder. A forwarder --
an export whose RVA lands inside the export directory -- is resolved when it
is asked for rather than when the module is loaded, because a forwarder may
name a module the image does not import and Windows resolves the string at
`GetProcAddress` time: a forwarder to a missing module is a failed call, not
a failed load.

`FreeLibrary` moves a reference count. A module whose count reaches zero is
detached, unmapped and forgotten. The image the process was built around,
and every API image, are pinned: there is nothing to unload, which is the
same answer the platform gives for the running module.

A dependency that cannot be resolved fails the load, and the failure names
the module that wanted it and the symbol it wanted -- `helper.dll wants
libgcc_s_seh-1.dll!__emutls_get_address`, which is the only form of that
message a person can act on. Nothing is mapped on a failed load: the images
the load had placed are unmapped and forgotten before the failure is
returned.

The library runtime's design -- the two-pass load, the entry-point order,
the call convention -- is in `docs/RUNTIME.md`, under "Loading a library".

## The forwarder gap

`modules.cpp`'s `kCrtForwarders[]` is an 18-entry table listing the names each contract module genuinely forwards. The implementation loads the complete `add_crt_exports` and `add_ucrt_extra` faces into a temporary `ExportList full`, then filters down to the subset each module should hold.

**A name in the table with no counterpart in the full face is silently skipped.** Roughly 50 names are affected, including `_strrev`, `strtok_s`, `_fullpath`, `_getcwd`, `_chdir`, `_mkdir`, `_access`, `_spawnv`, `_getche`, `_cgets`, `_cprintf`, `_cputs`, `_cscanf`, `_rotl`, `_rotr`, `_byteswap_*`, `_mbslen`, `_mbschr`, `_mbsrchr`, `_mbsstr`, `_mbsdup`, `_mbccpy`, `_mbclen`, `_ismbblead`, `_ismbbtrail`, `_wgetenv`, `_wputenv`, `_dupenv_s`, `_searchenv`, `_wsearchenv`, `_findfirst`, `_findnext`, `_stat`, `_fstat`, `_chsize`, `_chmod`, `_rmdir`, `_remove`, `_unlink`, `_execv`, `_execve`, `_spawnve`, `_wspawnv`, `_getmbcp`, `_setmbcp`, `_isctype`, `_tolower`, `_toupper`, `isblank`, `isleadbyte`, `btowc`, `wctob`, `_wcstombs_s`, `_mbstowcs_s`.

A guest calling one of these through an `api-ms-win-crt-*` contract module gets a failed `GetProcAddress`, not a wrong answer. That is the safer failure, but it is a gap.

## What is deliberately not answered

**No CLR.** `mscoree.cpp` answers `CorExitProcess` and returns `-1` (`CLR_E_SHIM_RUNTIME`) with `kErrorNotFound` for the rest. A .NET guest is told plainly that this is not a CLR host.

**Not every API.** The surface is large and grows one test at a time. Guests leaning on undocumented behavior or deep driver assumptions can still find a hole.

**MachO is detected but not parsed.** The parser recognizes the magic and stops.

## Guest-visible objects

| Object | Mechanism |
|---|---|
| Threads | `guest_thread.cpp`, handles from `0x800000`, span `0x100000` |
| Files | `kFileHandleBase = 0x2000`, stdio slots from `kGuestFileSlot = 48` |
| Kernel objects | `objects.cpp`, handles from `0x200000`, three kinds: Event, Mutex, Semaphore |
| Modules | `guest_module.cpp`, synthetic PE images with executable trampolines |
| Registry | `advapi32_reg.cpp`, backed by the observer's registry recording |

Handle spaces are disjoint by construction. A thread handle can never be mistaken for a file handle or an object handle, and the constants are chosen with gaps rather than adjacent ranges.

## Consistency rules

These are invariants the API layer maintains across files. Breaking one produces a guest-visible inconsistency, and anti-analysis code is written to find exactly these.

**Anti-debug answers agree.** `ProcessDebugPort` returns 0, `ProcessDebugFlags` returns 1, `ProcessDebugObjectHandle` fails with `STATUS_PORT_NOT_SET`, `CheckRemoteDebugerPresent` reports no debugger, and `IsWow64Process` is false. The last is true rather than a lie: the guest really is running native x64.

`ProcessDebugObjectHandle` uses an error rather than "success, returns 0" because the two are distinguishable and anti-debug checks know which one they asked for.

**Unmodeled classes return errors, not zeroes.** A query this runtime does not model returns the error the kernel would return. A zeroed buffer reads as "the answer is zero", which is a different and wrong statement.

**`NtGlobalFlag`, `BeingDebugged`, and the heap flags are clean.** `kHeapFlagsClean = 0x00000002` (`HEAP_GROWABLE`), `kHeapForceFlagsClean = 0`. These are the first things an anti-debug check reads.

**Capacity is checked before every wide-to-narrow conversion.** `required_capacity` computes the bytes needed, `fits` checks the destination. Never write past `nBufferSize`.

**One memory access path.** `read_u8/u16/u32/u64` and `write_u8/u16/u32/u64` are the only way across the guest boundary, so bounds checking exists in one implementation rather than in sixty-nine.

**Struct layouts are byte layouts, never converted.** `SystemTimeLayout` is 16 bytes, `FileTimeLayout` is 8, `OverlappedLayout` is 40, `MemoryBasicInformation` is 48. Where the compiler can see it, a `static_assert` pins the size.

---

Related: [RUNTIME.md](RUNTIME.md) for the runtime in detail, [DESIGN.md](DESIGN.md) for the module map, [SECURITY.md](SECURITY.md) for the threat model.
# BUILD

Requirements, options, and what each one costs. Everything here comes from `CMakeLists.txt` and the source, not from any earlier revision of this document.

---

## Contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Options](#options)
- [Sanitizers](#sanitizers)
- [Fuzzing](#fuzzing)
- [Static linking](#static-linking)
- [Warnings](#warnings)
- [Build targets](#build-targets)
- [Tests](#tests)
- [Cross-compilation notes](#cross-compilation-notes)
- [Troubleshooting](#troubleshooting)

---

## Requirements

- A C++23 compiler. Clang is what the code is written against; the build detects clang and applies clang-specific paths.
- CMake 3.16 or later.
- Ninja or Make.
- No third-party libraries. There is nothing to install.

Optional:

- libc++ rather than libstdc++, on by default when a clang root can be found.
- libFuzzer, only for `OCC_ENABLE_FUZZ`.

## Quick start

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build -j8
```

One static library, one binary, 86 tests.

## Options

| Option | Default | Effect |
|---|---|---|
| `OCC_USE_LIBCXX` | `ON` | Build against libc++ instead of libstdc++ |
| `OCC_LIBCXX_ROOT` | detected | libc++ root, searched through `OCC_LIBCXX_CANDIDATES` |
| `OCC_STATIC_LINK` | `ON` | Link the main binary statically, as a static PIE |
| `OCC_ENABLE_TESTS` | `ON` | Build the test suite |
| `OCC_WERROR` | `ON` | Treat warnings as errors |
| `OCC_ENABLE_FUZZ` | `OFF` | Build libFuzzer harnesses |
| `OCC_GCC_LIB_DIR` | detected | GCC library directory, used for the libc++ link |

`OCC_COMPILER_IS_CLANG` and `OCC_SANITIZED_BUILD` are internal, set by the build rather than by a user.

`OCC_LIBCXX_CANDIDATES` is the list of libc++ roots probed. It is not a cache variable; it is the search order.

Turning `OCC_USE_LIBCXX` off selects libstdc++. That combination compiles, and it is the path to take when a toolchain's libc++ is incomplete.

## Sanitizers

Supported. Two triggers:

- `-fsanitize` appearing in `CMAKE_CXX_FLAGS` or `CMAKE_CXX_FLAGS_<CONFIG>`
- `OCC_ENABLE_FUZZ=ON`

Both force `OCC_STATIC_LINK=OFF`, because a static PIE and a sanitizer runtime do not combine.

Under fuzzing, the flags are `-fsanitize=fuzzer-no-link,address,undefined` for compilation and `-fsanitize=fuzzer,address,undefined` for linking, plus `-fno-omit-frame-pointer`.

For the binary and tests, `-fsanitize=address,undefined`.

Three tests install real kernel state and are excluded from sanitized builds: `occ_test_seccomp`, which installs a real seccomp filter and denies a syscall; `occ_test_container`, which ptrace-attaches to a child and depends on ASan's shadow; and `occ_test_seh`, the third of that family. The exclusion is stated in `tests/CMakeLists.txt` with the reason, so it is a documented decision rather than a silently skipped test.

## Fuzzing

```
cmake -S . -B build-fuzz -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DOCC_ENABLE_FUZZ=ON -DOCC_STATIC_LINK=OFF
cmake --build build-fuzz -j
```

Harnesses live in `fuzz/`. Each runs under `ctest` with a per-harness time budget of `OCC_FUZZ_CTEST_SECONDS`, default 30.

`occ_test_seeds` guards the corpus against the generator that writes it, so a corrupted corpus is caught by the suite rather than by a fuzzer that stops finding anything.

The targets cover the parsers that take untrusted input: PE, ELF, the RSP decoder, and the seccomp filter compiler.

## Static linking

`-static-pie`, on by default. The binary has no runtime library dependency.

Two warnings are expected and benign, from glibc's NSS:

```
warning: Using 'getservbyname' in statically linked applications requires at
runtime the shared libraries from the glibc version used for linking
warning: Using 'getservbyport' in statically linked applications requires at
runtime the shared libraries from the glibc version used for linking
```

They come from `ws2_32.cpp`'s `getservbyname` and `getservbyport` paths. They do not affect a run unless a guest calls those two functions, and the alternative is a dynamically linked binary.

## Warnings

```
-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
-Wcast-qual -Wdouble-promotion -Wformat=2 -Wundef
-Wnull-dereference -Wimplicit-fallthrough
```

plus `-Werror` when `OCC_WERROR` is on.

On a non-clang compiler, `-Wno-error=null-dereference` is added, because GCC's null-dereference analysis produces different results than clang's and turning it into an error would block the build on a different compiler's opinion.

`-Wconversion` and `-Wsign-conversion` are on deliberately. They are why the relocation code computes `delta` unsigned, why the capacity checks exist before every wide-to-narrow conversion, and why the hex helpers specify widths. Those are not stylistic choices; they are what the warnings force.

`occ_core` additionally gets `-fno-exceptions -fno-rtti`, applied privately to that target only.

## Build targets

| Target | Kind |
|---|---|
| `occ_core` | Static library, the bottom four layers |
| `occ` | The executable |
| `occ_test_*` | 86 test executables |
| fuzz harnesses | One per `fuzz/` entry, only under `OCC_ENABLE_FUZZ` |

`occ_core` is built with the private `-fno-exceptions -fno-rtti`, so a translation unit that needs exceptions does not belong in that library.

## Tests

86 tests, registered through `occ_add_test` in `tests/CMakeLists.txt`.

```
ctest --test-dir build -j8
```

Two tests drive the built binary rather than the library: `occ_test_check` depends on the `occ` target and takes its path through a compile definition. `occ_test_seeds` likewise.

The API simulation tests are one file per area: `test_api_crt`, `test_api_ucrt`, `test_api_gdi32`, `test_api_advapi32`, `test_api_advapi32_reg`, `test_api_advapi32_sec`, `test_api_crypt32`, `test_api_crypt32_full`, `test_api_secur32`, `test_api_ole32`, `test_api_rpcrt4`, `test_api_setupapi`, `test_api_shell32`, `test_api_kernel32_sync`, `test_api_kernel32_proc`, `test_api_kernel32_str`, `test_api_kernel32_err`, `test_api_kernel32_extra`, `test_api_kernelbase_extra`, `test_api_user32_extra`, `test_api_user32_windows`, `test_api_ntdll_rtl`, `test_api_ntdll_rtl_str`, `test_api_ntdll_rtl_mem1`, `test_api_ntdll_rtl_mem2`, `test_api_ntdll_nt`, `test_api_ntdll_debug`, `test_api_psapi_version`, `test_api_dbghelp`, `test_api_ext`, `test_api_ext2`, `test_api_antidebug`, `test_api_shlwapi`, `test_api_file`, `test_api_time`, `test_api_memory`, `test_api_common`.

The runtime tests cover loader, exports, winabi, mapper, placement, ntdll, containment, SEH, seccomp, container, plain spawn.

The devirt tests cover each stage separately: `test_devirt_lift`, `test_devirt_sat`, `test_devirt_solve`, `test_devirt_cert`, `test_devirt_codegen`, `test_devirt_semlib`, `test_devirt_adapt`.

The observer tests cover events, sessions, registry, wx, uprobe, ntdll probes, placer, probe wiring, and gdb interop.

The remaining tests cover detect, inspect analysis, elf, engine, export duplicates, dbi, emu, hostile, behave, fuzz, replay, the three deobf areas, the three packer areas, and the two concolic areas.

## Cross-compilation notes

The code is x86-64 specific in places, and the places are deliberate:

- `runtime/winabi.cpp` uses `__attribute__((ms_abi))`, a GCC and clang extension available on x86-64 targets
- `runtime/pe_process.cpp` has inline asm for entering the guest
- `runtime/i386.cpp` interprets 32-bit code, which is what makes 32-bit guests possible on a 64-bit host
- `runtime/mapper.cpp` names AddressSanitizer's shadow range, which is an x86-64 layout property

A non-x86-64 target is not a supported configuration.

## Troubleshooting

**`could not read Username for 'https://github.com'`** when fetching: the repository is private and the credential helper is not populated. Use a token in the remote URL.

**`Using 'getservbyname' in statically linked applications`** at link time: expected, from `ws2_32.cpp`. Harmless unless a guest calls those two functions.

**`libc++` not found**: set `OCC_LIBCXX_ROOT` explicitly, or turn `OCC_USE_LIBCXX` off.

**`no member named 'unsat_prefix_hits'`**: that field was missing from `PathReport::SolverStats` while `concolic/engine.cpp` incremented it. It is declared now. If the error reappears, the tree predates that fix.

**Tests that install kernel state are skipped under sanitizers**: by design, listed above.

---

Related: [DESIGN.md](DESIGN.md) for the module structure, [CONTRIBUTING.md](../CONTRIBUTING.md) for how to change the code, [SECURITY.md](SECURITY.md) for the threat model.
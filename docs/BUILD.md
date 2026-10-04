# Build

## Toolchain

Occ requires C++23.

The compiler and the standard library are chosen separately, and the pair has
to be one that works. A compiler that is new enough for the language is not
automatically able to use a libc++ that happens to be installed, and the two
failures look nothing alike.

### Verified combinations

Every row below was built from a clean configure with warnings as errors on,
and the full test suite run. "Clean" means zero errors and zero warnings.

| Compiler | Standard library | Result |
|---|---|---|
| Clang 23.1.2 | libc++ 23 | clean, 16/16 |
| Clang 20.1.2 | libc++ 20 | not re-verified since the suite grew |
| GCC 16.0.1 | libstdc++ | clean, 16/16 |
| GCC 16.0.1 | libc++ 23 | falls back to libstdc++ |
| GCC 14.2 | libc++ 20 | falls back to libstdc++ |
| GCC 13.3 | libc++ 23 | falls back to libstdc++ |

The two rows marked clean were re-run most recently; the older Clang row is
left as it was rather than restated as current, because a number nobody has
re-measured is not a result. It was true when it was written and the suite
has grown since, so treat it as history.

The reference build is Clang with libc++ from the LLVM release tree. The
reason is the static link: libc++'s static archives are self-contained and are
what the shipped binary is built against.

GCC is supported and reaches the same clean result, on libstdc++. It is not
able to use libc++ 23 at all — the two standard libraries' headers are
mutually exclusive here, and libc++ asks for GCC 15 or newer regardless. That
is a property of the two implementations coexisting on one machine, not
something a flag resolves, and the build says so rather than failing later.

### Warnings the two compilers do not share

The build is warning-clean under both, and getting there is not automatic:
`-Wall` does not mean the same set of diagnostics on each. A construct that
Clang accepts silently can be an error under GCC with `-Werror` on, and the
reverse.

The one that has bitten this tree is a trailing backslash at the end of a
`//` comment. The preprocessor splices the following line onto it, so the
comment swallows a line the author meant to be a new one. GCC reports this
under `-Wcomment`; Clang does not. A shell example wrapped with a `\`
continuation inside a comment is the usual way to write it by accident:

```c++
    //     $ env -i PATH=/usr/bin:/bin TMPDIR=/tmp wine64 cmd.exe /c \
    //           --some-long-flag
    //                            ^ the backslash above is the bug
```

Written without the backslash the same example is clean under both:

```c++
    //     $ env -i PATH=/usr/bin:/bin TMPDIR=/tmp wine64 cmd.exe /c
    //           --some-long-flag
```

Since a Clang-only build would never show this, the GCC row in the table above
is worth running before a release, and the reference build being Clang is not
a reason to skip it.

### When a libc++ cannot be used

A libc++ is not usable merely because it is installed. The build compiles a
small probe with the include path it would really use, covering the headers
this project actually opens, and links it against the library directory it
would really use. If that fails, the build falls back to libstdc++ and reports
why, naming the compiler, its version, and the diagnostic it produced:

```
occ: GNU 16.0.1 cannot use the libc++ at /usr/lib/llvm-23
(error: 'abort' has not been declared in 'std'); falling back to libstdc++.
```

To use a libc++ the compiler cannot find for itself, name it:

```
cmake -S . -B build -DOCC_LIBCXX_ROOT=/opt/LLVM-23.1.2-Linux-X64
```

The GCC installation Clang is told to use is read from the compiler itself, so
that the version named is the version running. Override it when that answer is
right but the path is not — a sysroot, or a cross setup:

```
cmake -S . -B build -DOCC_GCC_LIB_DIR=/usr/lib/gcc/x86_64-linux-gnu/15
```

`-DOCC_USE_LIBCXX=OFF` forces libstdc++ and skips the probe.

CMake 3.20 or newer. Ninja is recommended but not required.

## Configure and build

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Output is `build/occ`, a single statically linked executable.

## Pointing at a libc++ tree

The installed libc++ is located automatically for the common cases. When
it is installed somewhere non-standard — a release tarball under `/opt`,
for instance — pass the root:

```
cmake -S . -B build -G Ninja \
  -DOCC_LIBCXX_ROOT=/opt/LLVM-23.1.2-Linux-X64 \
  -DOCC_GCC_LIB_DIR=/usr/lib/gcc/x86_64-linux-gnu/16
```

`occ doctor` prints both paths so a build can be reproduced from a working
binary.

## Static linking

Fully static, including libc++. The flags, in the order they matter:

```
-stdlib=libc++
-static
--unwindlib=libgcc
-I${OCC_LIBCXX_ROOT}/include/x86_64-unknown-linux-gnu/c++/v1
-L${OCC_LIBCXX_ROOT}/lib/x86_64-unknown-linux-gnu
-lc++ -lc++abi
```

Three things about this are worth writing down because each failed first:

**`--unwindlib=libgcc` is required.** libc++abi needs `_Unwind_*` symbols.
Both LLVM's libunwind and GCC's libgcc_eh provide them, and linking both
produces a wall of duplicate symbol errors that does not name the cause.
Picking one is the fix. libgcc is chosen because it is already present
where the toolchain is.

**`__gcc_personality_v0` is referenced from static libc.** It lives in
`libgcc_eh`. With `--unwindlib=libgcc` the link resolves it without an
explicit `-lgcc_eh`.

**Do not add `-lc++experimental`.** It pulls in a second definition of
several facilities that overlap with libc++ proper.

Verify the result:

```
file build/occ
# build/occ: ELF 64-bit LSB executable, x86-64, statically linked, ...
ldd build/occ
# not a dynamic executable
```

## Tests

```
cmake -S . -B build -G Ninja -DOCC_ENABLE_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Tests are built into the static configuration. They run against the same
isolation code the binary ships, which is the point.

## Fuzz harnesses

**Built, and only in a build that asks for them.** `fuzz/` holds six
`LLVMFuzzerTestOneInput` targets -- the ELF reader, the zip reader, the PE
reader, the PE loader, the GDB RSP codec and the seccomp-BPF emitter -- plus a
`seeds/` directory of thirty-five seeds that `tools/make_pe_seeds.py` writes
and `occ_test_seeds` checks against it.
`fuzz/README.md` records what each harness asserts and, at more length, what
each one deliberately does not.

They need Clang, because libFuzzer's runtime is linked against libstdc++ and a
GCC build rejects `-fsanitize=fuzzer-no-link` outright. `OCC_ENABLE_FUZZ=ON`
therefore forces `OCC_USE_LIBCXX=OFF` in the cache; asking for both does not
fail, it quietly builds against libstdc++ instead. Sanitizers and libFuzzer
cannot be combined with a fully static link, so the fuzz build is separate and
dynamic:

```
cmake -S . -B build-fuzz -G Ninja \
  -DOCC_ENABLE_FUZZ=ON \
  -DOCC_ENABLE_TESTS=OFF \
  -DCMAKE_CXX_COMPILER=/usr/lib/llvm-23/bin/clang++ \
  -DCMAKE_C_COMPILER=/usr/lib/llvm-23/bin/clang \
  -DCMAKE_CXX_FLAGS="-fsanitize=fuzzer,address,undefined"
cmake --build build-fuzz
```

`occ_fuzz_smoke` runs each harness briefly. Each is also a bounded ctest, so
an ordinary `ctest` in this build really does reach them:

```
ctest --test-dir build-fuzz -R occ_fuzz_run
```

`OCC_FUZZ_CTEST_SECONDS` sets how long each runs, 30 by default. The ctest
`TIMEOUT` is not decoration -- libFuzzer handed a malformed `-max_total_time`
does not fail, it runs forever -- so a test whose only limit is libFuzzer's
has no limit at all.

What the harnesses do not cover is stated in `fuzz/README.md` rather than
left to be discovered. It is worth knowing before reading a green run as more
than it was: nothing needing a real process is exercised, so the container, the
probe plumbing and the uprobe path are unverified by anything in that
directory.

The seccomp emitter is the interesting one, because it is 402 lines of
arithmetic producing a structure the kernel either executes or refuses without
explaining why, and because its input is a typed `SeccompPolicy` rather than
bytes -- so the harness has to invent a surface before there is anything to
fuzz. It does: the bytes are read as a fixed-width record of the policy's
fields, and the emitted bytecode is read back for the emitter's own promises
about it. What it does not do is install the program, which is where the
kernel's opinion would come in. That was the first design and it does not
survive libFuzzer: a harness that forks per input deadlocks against the
driver's process management often enough to make a suite unreliable, and not
as a function of the input. `occ_test_seccomp` is where the kernel is asked,
in a build without a sanitizer, and it really installs forty-nine filters.
`fuzz/README.md` has the measurements.

## Sanitizer build of the test suite

```
cmake -S . -B build-asan -G Ninja \
  -DOCC_ENABLE_TESTS=ON \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
cmake --build build-asan
ctest --test-dir build-asan --output-on-failure
```

## Memory

A full build of a C++23 tree with sanitizers is not small. On a host with
2 GiB and a swap file, limit parallelism:

```
cmake --build build -j2
```

Without a swap file the linker will be killed on a 2 GiB host. This is
recorded because it happened.

## Reproducing a reported environment

`docs/COMPAT.md` lists hosts this has been built and run on, with the kernel
release string, the toolchain paths, and the `occ doctor` output for each.
A build that differs from every entry there is not wrong, it is just not
one of the verified cases.

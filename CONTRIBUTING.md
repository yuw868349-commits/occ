# CONTRIBUTING

Rules for changing this codebase. They exist because the code has a shape, and a contribution that does not match it costs more to review than it is worth.

Everything here is enforced by the build or by the tests where it can be, and by review where it cannot.

---

## Contents

- [Language and build](#language-and-build)
- [Warnings are errors](#warnings-are-errors)
- [No exceptions, no RTTI](#no-exceptions-no-rtti)
- [Style](#style)
- [Naming](#naming)
- [Comments](#comments)
- [Constants](#constants)
- [Tests](#tests)
- [Adding an API export](#adding-an-api-export)
- [Adding a devirt capability](#adding-a-devirt-capability)
- [Commits](#commits)
- [What will be rejected](#what-will-be-rejected)

---

## Language and build

C++23. Clang is what the code is written against.

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build -j8
```

No third-party libraries. If a change needs one, it does not go in.

## Warnings are errors

```
-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
-Wcast-qual -Wdouble-promotion -Wformat=2 -Wundef
-Wnull-dereference -Wimplicit-fallthrough
```

plus `-Werror`, on by default via `OCC_WERROR`.

`-Wconversion` and `-Wsign-conversion` are the ones that change how you write code. They are why relocation deltas are computed unsigned, why every wide-to-narrow conversion checks capacity first, and why the hex helpers name their widths. Do not silence them with a cast. Fix the width.

## No exceptions, no RTTI

`occ_core` is built with `-fno-exceptions -fno-rtti`. Failures travel as `Result<T>` or out-parameters.

A translation unit that needs exceptions does not belong in `occ_core`. That is not a preference; it is the target's flags.

## Style

Four-space indentation. Braces on their own line. No tabs.

Column width: the code mostly stays under 100, with 204 lines over it and a maximum of 195. Treat 100 as the target, not as a wall. If a line has to go over, let it.

ASCII in source. No non-ASCII characters in identifiers, strings, or comments.

`constexpr` for compile-time constants, `[[nodiscard]]` on anything whose return value being dropped is a bug, `noexcept` on anything that cannot throw, which under `-fno-exceptions` is everything.

## Naming

Types and functions are `snake_case`. Constants are `kCamelCase`. Members are `snake_case_` with a trailing underscore. Enum values are `kCamelCase` in a scoped `enum class`.

The prefix matters. `kGranularity`, `kTebBytes`, `kMaxSymlinks`, `kRelBasedDir64`: the `k` says "compile-time constant" without a reader having to check.

Names describe what a thing is, not what it is for. `service_write` rather than `handle_the_write`. `rollback_placement` rather than `undo_base_stuff`.

## Comments

Comments explain **why**, and only when the why is not obvious from the code. A comment that restates the code is noise, and noise in a file this size is expensive.

The comments worth writing are the ones that record a non-obvious constraint:

```cpp
// HIGHADJ's adjustment comes from the NEXT relocation entry, so one
// HIGHADJ consumes two slots. A HIGHADJ at the end of a block, with no
// adjustment slot after it, is rejected: reading past the end is not an
// option.
```

```cpp
// A syscall the policy does not mention is handled by the fallback, which
// is rejection unless the caller says otherwise. Default-closed is the only
// default that can be reasoned about: a syscall added by a future kernel is
// not silently permitted.
```

Both record a decision and the reason for it. A reader who disagrees can find the place to argue.

Do not write a comment that says what the next three lines do. Do not write `// loop over the sections` above a loop over the sections.

## Constants

Wire structure sizes are named constants with a `static_assert` where the compiler can see them:

```cpp
static_assert(sizeof(SysvVaList) == 24);
static_assert(sizeof(MemoryBasicInformation) == 48);
```

This is not style. The guest reads these structures byte by byte, and a layout that drifts by four bytes produces a guest-visible failure that is miserable to diagnose.

Magic values get their name from their content where possible:

```cpp
kHeapMagic   = 0x4F43434845415031   // ASCII "OCCHEAP1"
kSignature   = 0x504D444D           // ASCII "MDMP"
kSessionMagic = 0x53454F42          // "SEO B"
```

## Tests

One test file per area. 86 of them. A change to a module adds or updates the test for that module.

```
ctest --test-dir build -j8
```

Tests that install real kernel state (`occ_test_seccomp`, `occ_test_container`, `occ_test_seh`) are excluded from sanitized builds. That exclusion is documented in `tests/CMakeLists.txt` with the reason.

`occ_test_check` and `occ_test_seeds` drive the built binary rather than the library and declare a dependency on the `occ` target.

A bug fix comes with a test that fails before the fix. A feature comes with a test that covers the path a guest will actually take.

## Adding an API export

The registration path is one function call into one `ExportList`:

```cpp
const auto e = [](const char* n, void* fn) { HostExport entry;
    entry.name = n; entry.address = reinterpret_cast<std::uint64_t>(fn); return entry; };
out.push_back(e("Name", reinterpret_cast<void*>(&handler)));
```

Four things a new export owes:

1. **Real semantics.** A stub that returns zero is not an implementation. If the semantics are not known, say so in the file and return the error the kernel would return, not a zeroed buffer.
2. **Capacity checks before every wide-to-narrow conversion.** `required_capacity` then `fits`. Never write past `nBufferSize`.
3. **Memory access through the primitives.** `read_u8/u16/u32/u64` and `write_u8/u16/u32/u64` are the only path across the guest boundary, so bounds checking exists once.
4. **Consistency with the other answers.** If it answers a debug-shaped query, it agrees with `ntdll_antidebug.cpp`, `kernel32_debug.cpp`, and `antidebug2.cpp`. A guest that reads the same fact through two paths and gets two answers has found you.

If the export is in the `kCrtForwarders[]` table, register it in `crt.cpp` or `ucrt_extra.cpp` too. The table currently names about fifty functions that are not registered, and each one added makes that gap smaller.

## Adding a devirt capability

The module is a pipeline, and each stage has its own test:

```
expr     hash-consed DAG, the IR everything shares
lift     handler models from native x86-64
bitblast DAG to CNF
sat      CDCL
solve    replay solving
goal     the goal language
codegen  rebuilt IR checked against the model
cert     the certificate
```

Two rules that are not negotiable:

**Generality.** A capability that works on one sample and not another is a bug. The lift infers layout from how the handlers index. The solver replays the traced path. The goal language parses any condition. Nothing in this module may know what sample it is looking at.

**Budgets.** `bb::Budget` bounds the work. "Unproven" is a legitimate answer and must be reported as one. An unbounded search on a hostile input is a hang, and a hang is worse than no answer.

If a new capability needs a new opcode in `expr::Op`, it needs a case in `bitblast`, in `simplify`, and in `pretty`. All three, or the DAG produces nodes the pipeline cannot lower.

## Commits

One logical change per commit. The subject line says what changed; the body says why.

```
devirt: replay the dispatcher from the loop head, and carry the
image's runtime bytes
```

Subjects are lowercase after the prefix, imperative, no trailing period. Prefixes seen in this repository: `devirt:`, `fix(concolic):`.

A body is expected when the change is not self-evident. The dispatcher commit's body explains that modeling from the wrong boundary re-executes key rolling, which is the reason the loop head is found by following unconditional jumps rather than by taking the first boundary.

Do not commit a change that breaks the build. `-Werror` and 86 tests mean you know before you push.

## What will be rejected

- A stub that returns zero where a real implementation is possible
- A `reinterpret_cast` that silences `-Wconversion` instead of fixing the width
- A hardcoded offset, table, or byte pattern that encodes one sample
- An unbounded loop or search over guest-controlled input
- A comment that restates the code
- A new third-party dependency
- A test that only exercises the happy path
- A commit that mixes two changes

---

Related: [BUILD.md](docs/BUILD.md) for build options, [DESIGN.md](docs/DESIGN.md) for the architecture, [SECURITY.md](docs/SECURITY.md) for the threat model.
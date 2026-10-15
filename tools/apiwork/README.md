# apiwork

The tool that writes `src/runtime/api/generated/`: one C++ file per module,
one entry point per name the mingw import libraries list that this runtime
did not already export.

## What it reads

| Input | Where from | What it is |
|---|---|---|
| `/tmp/target_api.json` | `nm` over the mingw import libraries, minus this runtime's own exports | the export names, by module |
| `/tmp/mingw_prototypes.json` | `extract_prototypes.py` | each name's declared signature |
| `/tmp/occ_names.txt` | this runtime's registry | what is already answered, so that nothing is registered twice |

Run `python3 extract_prototypes.py` first: it preprocesses the mingw headers
with `x86_64-w64-mingw32-gcc -E` and reads the declarations out. The
preprocessor is not optional -- the declarations are macro-decorated, and a
text scan of the raw headers reads a calling convention as a return type,
which is a signature whose answer arrives in the wrong register.

## What it writes

`../../src/runtime/api/generated/<module>.cpp`, one entry point per name:

* an implementation, where the behaviour is defined by a format, a
  structure layout or an arithmetic rule;
* a refusal, where the subsystem the call belongs to is not in this
  runtime. The refusal is `ERROR_CALL_NOT_IMPLEMENTED` through
  `SetLastError`, which is the answer Windows gives for an entry point whose
  subsystem is absent, and a comment above it names the subsystem.

A third case exists and is stated in the file: an export the headers do not
declare gets a thunk with no parameters. That is safe on this ABI -- the
caller allocates and releases the shadow space, and a callee that names no
parameter reads neither it nor the argument registers -- and it is the only
honest option, because a guessed arity is a call that reads its arguments out
of the wrong registers.

## Files

| File | What it holds |
|---|---|
| `extract_prototypes.py` | the header pass: signatures, with the return type read from the right token |
| `wintypes.py` | the type table, and the record of what it could not name |
| `emit.py` | symbol names, parameter names, the shapes a body is emitted in |
| `build.py` | the driver: reads the three inputs, applies the rules, writes the files |
| `semantic.py` | the dispatch over the domain modules |
| `sem_common.py` | the helpers every domain shares: text walks, the two widths, little-endian readers |
| `sem_shlwapi.py` | the path grammar, the bounded string helpers, the shell's formatters |
| `sem_kernel.py` | the interlocked family, the profile files, the small answers |
| `sem_profile.py` | the INI format and the calls that read and write it |
| `refuse.py` | why a family is refused, grouped by the subsystem that would have to exist |

## Running it

```
python3 extract_prototypes.py
python3 build.py
```

The generated files are checked in. They are read, and a reader is owed the
same review of them as of anything else in this repository; a file that is
only ever produced by a tool is a file nobody has looked at.

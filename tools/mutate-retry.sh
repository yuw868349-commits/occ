#!/usr/bin/env bash
# Mutation harness for the retry loop and the syscall counter.
#
# Each mutant is a one-line change to production code that should be caught by
# a test. A mutant that survives is a hole in the suite, and this script exists
# to find those rather than to reassure anyone that the tests are thorough.
#
# The report is per-mutant, not a pass/fail for the run: a run where three of
# eight mutants survived is a different thing from one where all eight were
# caught, and only the first tells you what to write next.
set -u

BUILD=/workspace/Occ/build
TEST="$BUILD/tests/occ_test_placement"
LOADER=/workspace/Occ/src/runtime/loader.cpp
MAPPER=/workspace/Occ/src/runtime/mapper.cpp

# The pristine copies are taken *now*, at run time, rather than from a path
# written down when this script was written. A fixed path is a claim about
# what the files contained, and this script restores them at the end of every
# mutant -- so a stale path does not merely fail to restore, it restores a
# version of the source from before the fixes made in the same session, and
# the next build then measures that older code. That happened: the floor and
# upper-guard repairs were both written after the backup was taken and both
# were silently discarded by the final restore, and the suite still reported
# green because it was testing the older behaviour.
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cp "$LOADER" "$WORK/loader.pristine"
cp "$MAPPER" "$WORK/mapper.pristine"

caught=0
survived=0
failed_names=()

restore() {
    cp "$WORK/loader.pristine" "$LOADER"
    cp "$WORK/mapper.pristine" "$MAPPER"
}

# Mutate, build, run, report. The mutant's name is $1; the file and the
# python replacement are $2 and $3.
mutate() {
    local name="$1" file="$2" old="$3" new="$4"
    restore
    python3 - "$file" "$old" "$new" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path).read()
n = s.count(old)
if n != 1:
    print("ANCHOR-FAIL count=%d" % n)
    sys.exit(3)
open(path, "w").write(s.replace(old, new))
PY
    if [ $? -ne 0 ]; then
        echo "  [$name] ANCHOR NOT UNIQUE -- the mutant was never applied"
        survived=$((survived + 1))
        failed_names+=("$name")
        return
    fi
    if ! cmake --build "$BUILD" --target occ_test_placement \
            -j"$(nproc)" >/tmp/mut_build.log 2>&1; then
        # A mutant the compiler rejects is not a surviving mutant, but it is
        # also not a caught one -- it means the line was not covered by a
        # build. Reported separately so it cannot be mistaken for either.
        echo "  [$name] DID NOT COMPILE"
        survived=$((survived + 1))
        failed_names+=("$name")
        return
    fi
    local out
    out=$("$TEST" 2>&1 | tail -1)
    if echo "$out" | grep -q " 0 failures"; then
        echo "  [$name] SURVIVED  <-- hole in the suite"
        survived=$((survived + 1))
        failed_names+=("$name")
    else
        echo "  [$name] caught: $out"
        caught=$((caught + 1))
    fi
}

echo "=== retry-loop and counter mutants ==="

mutate "retry-every-error" "$LOADER" \
    'if (out.error != LoadError::AddressConflict) {' \
    'if (false) {'

mutate "floor-adds-the-size" "$LOADER" \
    '    const std::uint64_t lowest =
        AddressSpace::round_up(AddressSpace::kUserMin, AddressSpace::kGranularity);' \
    '    const std::uint64_t lowest =
        AddressSpace::kUserMin +
        AddressSpace::round_up(size - 1, AddressSpace::kGranularity);'

mutate "floor-off-by-one-granularity" "$LOADER" \
    '    const std::uint64_t lowest =
        AddressSpace::round_up(AddressSpace::kUserMin, AddressSpace::kGranularity);' \
    '    const std::uint64_t lowest =
        AddressSpace::round_up(AddressSpace::kUserMin, AddressSpace::kGranularity) +
        AddressSpace::kGranularity;'

mutate "no-upper-guard" "$LOADER" \
    'if (failed_base < AddressSpace::kUserMin + AddressSpace::kGranularity ||
        failed_base > AddressSpace::kUserMax) {' \
    'if (failed_base < AddressSpace::kUserMin + AddressSpace::kGranularity) {'

# NOT a mutant: recorded as unreachable, and the reason is asserted in the
# suite rather than argued here.
#
# `if (size > kUserMax - lowest) return 0;` -- the check that refuses to offer
# a base to an image too big for the window. Deleting it changes nothing
# observable, because PE32+ carries SizeOfImage in 32 bits and the user
# window is 47, so no file can produce an image that does not fit. A harness
# that reported this as a hole would be wrong: no input reaches the line. The
# big-size case asserts the unreachability directly (kUserMax - kUserMin >
# 0xFFFFFFF0), so if a future change widened the declared-size field past the
# window, that assertion would fail and this would become a real mutant worth
# keeping -- which is the right way to handle a branch nothing can reach.
#
# mutate "no-fit-check" "$LOADER" \
#     '    if (size > AddressSpace::kUserMax - lowest) {
#         return 0;
#     }' \
#     '    if (false) {
#         return 0;
#     }'

mutate "no-repeat-check" "$LOADER" \
    '        bool already = false;
        for (const std::uint64_t b : local.tried) {' \
    '        bool already = false;
        for (const std::uint64_t b : std::vector<std::uint64_t>{}) {'

mutate "cap-off-by-one" "$LOADER" \
    'if (attempts >= kMaxAttempts) {' \
    'if (attempts > kMaxAttempts) {'

mutate "guard-on-result-not-base" "$LOADER" \
    'if (failed_base < AddressSpace::kUserMin + AddressSpace::kGranularity ||
        failed_base > AddressSpace::kUserMax) {' \
    'if ((failed_base < AddressSpace::kUserMin + AddressSpace::kGranularity
             ? 0
             : failed_base - AddressSpace::kGranularity) >= lowest) {'

mutate "step-is-a-page" "$LOADER" \
    'const std::uint64_t next = failed_base - AddressSpace::kGranularity;' \
    'const std::uint64_t next = failed_base - 0x1000;'

mutate "search-end-hides-the-conflict" "$LOADER" \
    'local.detail = "no base was free for the image";
            if (!out.detail.empty()) {
                local.detail += ": ";
                local.detail += out.detail;
            }' \
    'local.detail = out.detail;'

mutate "cap-says-it-ran-out" "$LOADER" \
    '"the image was still in the way after "' \
    '"no base was free for the image after "'

mutate "repeat-names-it-in-decimal" "$LOADER" \
    'local.detail = "the base chooser returned " +
                           hex_of(next) +' \
    'local.detail = "the base chooser returned " +
                           std::to_string(next) +'

mutate "counter-skips-failed-mmaps" "$MAPPER" \
    '    ++syscalls_made_;
    if (at == 0) {
        // The errno is translated' \
    '    if (at == 0) {
        // The errno is translated'

echo
echo "caught: $caught   survived: $survived"
if [ "$survived" -ne 0 ]; then
    echo "unproven mutants:"
    for n in "${failed_names[@]}"; do echo "  - $n"; done
fi

# The restore is verified rather than assumed. This script edits production
# files in place and puts them back, and a restore that quietly failed would
# leave the tree holding a mutant -- which the next build would then treat as
# the code. `cmp` says whether the bytes came back; a diff summary says what
# changed if they did not.
restore
for f in "$LOADER" "$MAPPER"; do
    case "$f" in
        *loader.cpp) pristine="$WORK/loader.pristine" ;;
        *mapper.cpp) pristine="$WORK/mapper.pristine" ;;
    esac
    if ! cmp -s "$f" "$pristine"; then
        echo "RESTORE FAILED for $f -- the tree is not what it was:"
        diff -u "$pristine" "$f" | head -30
    fi
done
cmake --build "$BUILD" --target occ_test_placement -j"$(nproc)" >/dev/null 2>&1
"$TEST" 2>&1 | tail -1

#!/usr/bin/env bash
# Mutation harness for the export registry: the name rules, the ordinal
# arithmetic, the forwarder walk.
#
# Same contract as mutate-tls.sh, and for the same reason: a mutant that
# survives is a hole in the suite, and a harness that reports "all caught" is
# only worth what the mutants were worth. Every mutant below is a change a
# plausible mistake would make -- not a sabotage, a mistake.
#
# Every mutant is run under two builds and has to fail both, and that is not
# redundancy. A bound that is one too generous reads past the end of a table,
# and the plain run then reads whatever the allocator left there -- usually an
# empty string, so the hint is skipped anyway and the answer is right. The
# sanitizer build reports the overflow at the mutated line instead, which is
# the difference between "this suite caught it" and "this suite happened not
# to be looking".
#
# The four that earned their place by surviving a first run are marked below.
# Two of them are the same mistake in opposite directions, which is the point:
# the module name is compared without regard to case and the export name is
# compared exactly, and a reader that uses one comparison for both is wrong
# about one of them in a way no test of the other would notice.
set -u

BUILD=/workspace/Occ/build
BUILD_SAN=/workspace/Occ/build-asan
TEST="$BUILD/tests/occ_test_runtime_exports"
TEST_SAN="$BUILD_SAN/tests/occ_test_runtime_exports"
EXPORTS=/workspace/Occ/src/runtime/exports.cpp
HEADER=/workspace/Occ/include/occ/runtime/exports.h

# Taken now, at run time, for the reason mutate-tls.sh's comment gives at
# length: a fixed path is a claim about what the file contained, and this
# script restores from it after every mutant.
WORK=$(mktemp -d)

# The rebuild on the way out, and it is a trap rather than a line at the end of
# the script because a harness that leaves a mutated binary behind is worse
# than one that crashes. Restoring the *source* is not enough: the last mutant
# compiled is still in `$BUILD` and `$BUILD_SAN`, it compiles, and the next
# `ctest` runs it and reports a failure that has nothing to do with any code
# under test. The confusion it causes is worse than the confusion a crashed
# harness causes, because the crash is honest about what happened.
#
# Which means this also runs on SIGINT. A harness interrupted halfway through
# nineteen mutants has one of them built, and the person who interrupted it
# went away believing the tree was clean.
cleanup() {
    # The restore first: rebuilding before the source is back would rebuild the
    # mutant a second time and leave *that* behind instead.
    cp "$WORK/exports.pristine" "$EXPORTS" 2>/dev/null || true
    cp "$WORK/exports.h.pristine" "$HEADER" 2>/dev/null || true
    cmake --build "$BUILD" -j"$(nproc)" >/dev/null 2>&1 || true
    cmake --build "$BUILD_SAN" -j"$(nproc)" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cp "$EXPORTS" "$WORK/exports.pristine"
cp "$HEADER" "$WORK/exports.h.pristine"

caught=0
survived=0
failed_names=()

restore() {
    cp "$WORK/exports.pristine" "$EXPORTS"
    cp "$WORK/exports.h.pristine" "$HEADER"
}

# mutate NAME FILE OLD NEW [OLD NEW ...]
#
# The extra pairs are for the mutants that need two edits at once, applied as a
# single mutant rather than as two runs. The reason is the same one
# mutate-tls.sh gives: this code has a *doubled* guard in more than one place
# -- the null-state check in `resolve` and in `resolve_thunk` are the same
# check written twice because the two entry points cannot call each other --
# and each half on its own is an equivalent change, which a harness that ran
# them separately would report as two surviving mutants. Neither report would
# be a fact about the suite.
mutate() {
    local name="$1" file="$2" old="$3" new="$4"
    shift 4
    restore
    python3 - "$file" "$@" "$old" "$new" <<'PYEOF'
import sys
args = sys.argv[1:]
path, rest = args[0], args[1:]
pairs = [(rest[i], rest[i + 1]) for i in range(0, len(rest), 2)]
s = open(path).read()
for old, new in pairs:
    n = s.count(old)
    if n != 1:
        print("ANCHOR-FAIL count=%d for %r" % (n, old[:40]))
        sys.exit(3)
    s = s.replace(old, new)
open(path, "w").write(s)
PYEOF
    if [ $? -ne 0 ]; then
        echo "  [$name] ANCHOR NOT UNIQUE -- the mutant was never applied"
        survived=$((survived + 1))
        failed_names+=("$name")
        return
    fi
    if ! cmake --build "$BUILD" -j"$(nproc)" >"$WORK/build.log" 2>&1; then
        # A mutant that does not compile is not a surviving mutant: it is a
        # change the type system rejects, which is a stronger guarantee than
        # any test. Counted separately so the report does not claim a
        # coverage it does not have.
        echo "  [$name] rejected by the compiler"
        caught=$((caught + 1))
        restore
        return
    fi
    # Every mutant is run under the sanitizer build as well as the plain one,
    # and it has to fail both. That is not belt-and-braces; it is the only way
    # one class of mistake is visible at all.
    #
    # A bound that is one too generous reads past the end of a table, and
    # whether the suite notices depends on what the allocator left there. In
    # practice it finds an empty string, the lookup skips the entry it should
    # not have read, and the answer is right -- the wrong answer only arrives
    # under a heap layout chosen by someone else. AddressSanitizer does not
    # have that luck: it reports the overflow at the mutated line and names
    # the allocation, so "the test passed" stops being a statement about the
    # read and starts being a statement about the run.
    #
    # So the plain run stays first, because a mutant that segfaults or fails
    # an assertion is caught by the fastest signal available, and the
    # sanitizer run is the second opinion that catches the ones a passing run
    # was hiding.
    if ! "$TEST" >"$WORK/run.log" 2>&1; then
        echo "  [$name] caught"
        caught=$((caught + 1))
        restore
        return
    fi
    if ! cmake --build "$BUILD_SAN" -j"$(nproc)" >"$WORK/build-san.log" 2>&1; then
        echo "  [$name] rejected by the compiler (sanitizer build)"
        caught=$((caught + 1))
        restore
        return
    fi
    if "$TEST_SAN" >"$WORK/run-san.log" 2>&1; then
        echo "  [$name] SURVIVED"
        survived=$((survived + 1))
        failed_names+=("$name")
        # A surviving mutant that the plain run *did* fail would mean the
        # build is stale rather than that the suite is weak, which is a
        # different bug entirely and one that a harness reporting "weak tests"
        # would misdiagnose.
        echo "      (passed under the sanitizer too -- a real gap, not a "
        echo "stale binary)"
    else
        if grep -q "AddressSanitizer" "$WORK/run-san.log"; then
            echo "  [$name] caught (AddressSanitizer -- the plain run passed it)"
        else
            echo "  [$name] caught (sanitizer build)"
        fi
        caught=$((caught + 1))
    fi
    restore
}

echo "Export registry mutants"

# -------------------------------------------------- module name comparison

# Wine's `find_basename_module` passes TRUE to `RtlEqualUnicodeString` and the
# TRUE is the case-insensitive flag. Making the comparison case-sensitive is
# the mistake every C++ programmer makes once, because a `std::string` compare
# is case-sensitive by default and it *looks* like the obvious spelling of
# "same name". It refuses every import a real program spells in a different
# case, which is most of them.
mutate "module-name-becomes-case-sensitive" "$EXPORTS" \
"    return internal::compare_ascii(a, b, true) == 0;" \
"    return internal::compare_ascii(a, b, false) == 0;"

# The other direction, and the one that is harder to see. Folding the case of
# a *module* name is right; folding the case of an *export* name resolves an
# import Windows refuses, because Win32 export names are case-sensitive and
# `find_name_in_exports` uses `strcmp`. This survived the first run of this
# harness, which is why the two comparisons are now separate functions with
# the difference spelled out at both.
mutate "export-name-becomes-case-insensitive" "$EXPORTS" \
"    return compare_ascii(a, b, false) == 0;" \
"    return compare_ascii(a, b, true) == 0;"

# -------------------------------------------------------- the name's path

# A registry is filled in by the host as well as by the guest, so a name in it
# may carry a path the guest never wrote. Splitting on `\\` alone is what Wine
# does because a path reaching its loader is always a Windows path; here it
# would mean a Unix path never matches.
#
# The replacement is spelled as a character literal rather than as a string
# containing a backslash. Quoting a backslash through two levels of shell --
# the script's own quoting and then Python's, which does the substitution --
# is a way to spend an afternoon, and `path.find_last_of('\\')` says exactly
# what `path.find_last_of("/\\")` means while containing no backslash at all.
mutate "basename-only-splits-windows-paths" "$EXPORTS" \
'    const std::size_t cut = path.find_last_of("/\\");' \
"    const std::size_t cut = path.find_last_of('\\\\');"

# Stripping the extension is the other direction of guessing: a guest importing
# `foo` may mean `foo.dll`, but that is a search of a directory, and a
# registry that guesses resolves a name nobody asked for.
mutate "basename-strips-the-extension" "$EXPORTS" \
"    if (cut == std::string_view::npos) {
        return std::string(path);
    }
    return std::string(path.substr(cut + 1));" \
"    if (cut == std::string_view::npos) {
        std::string bare(path);
        const std::size_t dot = bare.rfind('.');
        return dot == std::string::npos ? bare : bare.substr(0, dot);
    }
    return std::string(path.substr(cut + 1));"

# ---------------------------------------------------------------- the hint

# The mutant that is the whole reason the hint path has a test. Believing the
# linker's hint without comparing the name resolves a stale hint to a real,
# wrong address -- a corruption rather than a refusal, so nothing downstream
# can notice it. This survived the first run: the suite had a test for "the
# hint is right" and none for "the hint is wrong", which is the direction that
# breaks.
mutate "a-stale-hint-is-believed" "$EXPORTS" \
"    if (hint < table.size() && !table[hint].name.empty() &&
        internal::export_name_equal(table[hint].name, name)) {
        return walk(*module, hint, false, true, 0, {});
    }" \
"    if (hint < table.size() && !table[hint].name.empty()) {
        return walk(*module, hint, false, true, 0, {});
    }"

# The scan refusing an unnamed entry. This is what stops a lookup for the
# empty name from answering with whatever the module left in slot 0: an
# unnamed entry's name is "", so a comparison without the emptiness guard
# matches an import of "" to the first unnamed slot in the table.
#
# The hint path's own empty-name check is redundant, and finding that out
# cost two runs of this harness reporting it as surviving. An empty name
# never compares equal to a non-empty one, so removing that check changes no
# input's answer. A mutation that cannot change behaviour is not a weak test,
# it is not a mutation, and the honest thing is to say so in a comment rather
# than leave a permanent "survived" in the report.
mutate "the-scan-matches-an-unnamed-entry" "$EXPORTS" \
"        if (!table[i].name.empty() && internal::export_name_equal(table[i].name, name)) {" \
"        if (internal::export_name_equal(table[i].name, name)) {"

# -------------------------------------------------------------- the ordinal

# The base forgotten. Every ordinal import then resolves to the function
# base slots below the one asked for, and a module whose base is 1 -- which is
# most of them -- is the case where the mistake is nearly invisible because
# the arithmetic almost works out.
mutate "the-ordinal-base-is-ignored" "$EXPORTS" \
"    const std::int64_t shifted = static_cast<std::int64_t>(ordinal) -
                                 static_cast<std::int64_t>(base);" \
"    const std::int64_t shifted = static_cast<std::int64_t>(ordinal);"

# The hint bound. Three mutations of one comparison, and each of them is a
# mistake rather than a sabotage, so each is in the harness even though two
# of them are the same off-by-one read from opposite ends.
#
# The first drops the bound entirely. A hint of 0xFFFF is then an index into
# a three-entry table, and the read is past the end of the allocation --
# `a_library` reserves exactly as many entries as it fills, so there is no
# spare capacity for the read to land in harmlessly. The run segfaults rather
# than failing an assertion, which is why the harness counts a crash as caught
# and why the sanitizer build matters for the two below.
mutate "the-hint-bound-is-removed" "$EXPORTS" \
"    if (hint < table.size() && !table[hint].name.empty() &&" \
"    if (!table[hint].name.empty() &&"

# The bound widened by one: `hint <= size` reads one `PeExport` past the end
# when the hint names the first slot past the table. This one is the reason the
# harness has a boundary fixture at all.
#
# It survived the first run that carried it, which is the most interesting
# result this harness has produced. Every other hint in the suite is either
# inside the table (0, 1, 2) or far outside it (0xFFFF), and `hint < size` and
# `hint <= size` agree about every one of those -- a table of three entries
# has no hint that lands between "the last index" and "far away". The suite had
# a test named after the hint and none of them used the value that separates
# the two comparisons.
#
# The fixture that catches it is `hint == size`, and it only catches it under
# a sanitizer: a plain run reads one `PeExport` past a three-element
# allocation, finds whatever the allocator left there, and in practice finds
# an empty name -- so the hint is skipped anyway and the scan answers, which is
# the right answer. The answer was right by luck, and a boundary test that
# passes for the wrong reason is the kind that lets the next mistake through.
# AddressSanitizer reports the heap-buffer-overflow at the mutated line and
# names the allocation, which is what turns this from luck into a fact.
#
# The second one is the same off-by-one from the other end: `hint < size - 1`
# refuses a hint that names the *last* entry. It has no memory-safety
# consequence -- it reads nothing -- so it is caught by the answer rather than
# by the allocator, and it is here because a comparison that is right at one
# end and wrong at the other is one boundary, not two checks.
mutate "the-hint-bound-is-one-too-generous" "$EXPORTS" \
"    if (hint < table.size() && !table[hint].name.empty() &&" \
"    if (hint <= table.size() && !table[hint].name.empty() &&"

mutate "the-hint-bound-is-one-too-tight" "$EXPORTS" \
"    if (hint < table.size() && !table[hint].name.empty() &&" \
"    if (hint + 1 < table.size() && !table[hint].name.empty() &&"

# ------------------------------------------------------------- empty slots

# A zero RVA answered as an address. The format keeps a slot for a symbol that
# was removed so the ordinals after it do not move, and answering with the
# base plus zero is a real address pointing at the image's headers.
mutate "an-empty-slot-answers-with-base-plus-zero" "$EXPORTS" \
"    if (entry.rva == 0) {" \
"    if (false) {"

# ------------------------------------------------------------ the forwarder

# The bound removed. A cycle between two modules is then a walk that does not
# terminate, which is the defect Wine has -- `find_forwarded_export` recurses
# through `load_dll` with nothing to stop it -- and the bound is the only
# reason occ does not have it too.
mutate "the-forwarder-depth-bound-is-removed" "$EXPORTS" \
"    if (depth > kMaxForwarderDepth) {" \
"    if (false) {"

# The bound moved off by one, which is the version that survives a cycle of
# the same length as the bound and fails a longer one. A bound that is one too
# generous is a bound that has never been tested at its edge.
mutate "the-forwarder-bound-is-one-too-generous" "$EXPORTS" \
"    if (depth > kMaxForwarderDepth) {" \
"    if (depth > kMaxForwarderDepth + 1) {"

# A forwarder answered out of the forwarding module's own table. This is the
# fallback that looks like robustness and is a corruption: a guest importing
# `Sleep` from kernel32 would get whatever kernel32 happens to have at that
# index.
mutate "an-unresolved-forwarder-falls-back" "$EXPORTS" \
"    const ExportModule* target = find(entry.forwarder_dll);
    if (target == nullptr) {
        return out;
    }" \
"    const ExportModule* target = find(entry.forwarder_dll);
    if (target == nullptr) {
        target = &module;
    }"

# A forwarder chain that forgets to record where it has been, so the report
# cannot show that kernel32!Sleep is answered by ntdll. Nothing about the
# *answer* changes, which is the point: this is a mutant a suite that only
# checks addresses cannot catch at all.
mutate "the-forwarder-chain-is-not-recorded" "$EXPORTS" \
"    chain.push_back(module.name);" \
"    chain.push_back(std::string());"

# An unmapped module handing back an RVA as an address. A caller that stored
# it would store base-zero and jump to the start of the address space, which
# is the confusion the TLS layer refuses to create and this one inherits.
mutate "an-unplaced-module-hands-back-an-rva" "$EXPORTS" \
"        if (!module.mapped) {" \
"        if (false) {"

# ------------------------------------------------------- the registry's own

# Registering a name twice keeping the first. A module registered once per
# image during a load reaches the registry twice -- a forwarder that names a
# module the image also imports directly -- and which entry answers would then
# depend on the order the walk happened to use.
mutate "a-second-registration-is-ignored" "$EXPORTS" \
"            existing = std::move(module);
            existing.name = key;
            return;" \
"            return;"

# -------------------------------------------------------- the null contract

# A null state dereferenced rather than answered. `occ check` is the path that
# has no resolver by design, and a wiring mistake there should be a load with
# unresolved imports rather than a crash in the middle of one. Two edits,
# because the check is written twice: the two entry points cannot call each
# other, so the check is necessarily duplicated and a mutant of one half alone
# is an equivalent change.
mutate "a-null-state-is-dereferenced" "$EXPORTS" \
"    const auto* self = static_cast<const ExportRegistry*>(state);
    if (self == nullptr) {
        // A null state with a non-null function pointer is a wiring mistake,
        // and it is answered rather than dereferenced. The loader's contract
        // for a resolver that cannot answer is \"nothing is written\", and
        // honouring it here means the mistake is a load with unresolved
        // imports rather than a crash in the middle of one.
        return 0;
    }
    return answer(*self, dll, name, ordinal, by_ordinal);" \
"    const auto* self = static_cast<const ExportRegistry*>(state);
    return answer(*self, dll, name, ordinal, by_ordinal);"

# The `by_ordinal` flag ignored, so an import by ordinal is looked up as a
# name. A guest that imports `KERNEL32.#27` would get a lookup for the empty
# name and every ordinal import in the image would silently fail to resolve.
mutate "the-by-ordinal-flag-is-ignored" "$EXPORTS" \
"    if (by_ordinal) {
        return self.find_by_ordinal(dll, ordinal).address;
    }" \
"    if (false) {
        return self.find_by_ordinal(dll, ordinal).address;
    }"

# ------------------------------------------------------- gaps left open

# Gaps rather than unreachable branches, recorded here because a harness that
# reports "all caught" without saying what it did not try is claiming more than
# it checked.
#
#   * `walk`'s own `index >= module.exports.size()` is not mutated, and this
#     one is the interesting absence.
#
#     An earlier version of this harness carried that mutation and reported
#     it surviving, and it was right, for a reason that is a property of the
#     call graph rather than of the suite. Four paths reach `walk` and all
#     four establish the bound before they call it: the hint path checks
#     `hint < table.size()`, the scan path's `i` is a loop counter below
#     `table.size()`, and both ordinal paths -- a guest's ordinal and a
#     forwarder's -- go through `index_of`, which refuses anything outside the
#     table. So there is no input, through the public API or any other, that
#     hands `walk` an index it has to catch, and a mutation of the check
#     changes no answer. `walk` is private and its callers are in this file.
#
#     The check stays anyway, and the reason it stays is worth more than the
#     mutation would have been. It is the one place in this file that indexes
#     `module.exports`, so it is the one place that has to be right about the
#     bound no matter what the four callers do -- including the fifth one
#     somebody adds later and forgets. A check whose callers all happen to
#     make it redundant today is a precondition stated where the dereference
#     is, and deleting it converts a safe refactor into a heap read. The
#     harness cannot test that, and the honest report is that it is untested
#     rather than a "survived" that someone eventually deletes out of the
#     script.
#
#   * `add_from_image` is not mutated above. It is three lines of copying from
#     a `PeImage` whose accessors are tested in test_pe.cpp, and a mutant
#     here would be a mutant of a copy loop. It is listed so that the absence
#     is a decision rather than an oversight.
#
#   * `modules()` is not mutated above. Nothing in the runtime calls it; it
#     exists for `occ doctor` and for a report, and a mutant would be caught
#     by the test that reads the pointers back rather than by anything about
#     the registry.
#
#   * The scan in `find_by_name` is not mutated into a binary search over
#     `exports()`. That change would be *wrong* -- `PeImage::exports()` is in
#     address-table order and the name table is the sorted one -- and it is
#     the one a future reader is most likely to attempt, so the comment at the
#     scan says why not rather than the harness saying it.

echo
echo "----------------------------------------------------------------"
echo "caught:   $caught"
echo "survived: $survived"
if [ "$survived" -gt 0 ]; then
    echo "surviving mutants:"
    for n in "${failed_names[@]}"; do
        echo "  - $n"
    done
    exit 1
fi
exit 0

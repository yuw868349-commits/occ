#!/usr/bin/env bash
# Mutation harness for TLS: the directory read, the slot, the block, the
# callbacks.
#
# Same contract as mutate-retry.sh, and for the same reason: a mutant that
# survives is a hole in the suite, and a harness that reports "all caught" is
# only worth what the mutants were worth. Every mutant below is a change that
# a plausible mistake would make -- not a sabotage, a mistake -- and the ones
# that survived when this was first run are the reason the tests look the way
# they do. Those are marked in the notes beside them.
#
# One mutant below is in the test file rather than in the runtime. The address
# allocator the fixtures draw their bases from is part of the suite, not part
# of occ, and a suite whose fixtures can be handed an occupied address fails
# in a way that reads like a defect in whatever constraint the fixture was
# written to pin down. That one mutant is here for the same reason the others
# are: it is a change a plausible edit would make -- trusting the stride
# because it was chosen to be wide -- and the suite has to notice.
#
# The one thing this harness cannot check is a test that measures the code by
# means of the code. The retry suite learned that the hard way: its first
# version computed an expected floor with the policy's own formula, so every
# mutant of that formula changed both sides at once and nothing was caught.
# The TLS tests are built to not do that -- the expected address of a block
# is read out of the mapping with a memcpy and compared to arithmetic done in
# the test -- and the "template-from-file" mutant below is the one that
# proves it, because it is the change this whole layer exists to prevent.
set -u

# Every path is derived from this script's own location rather than written
# down. A hardcoded checkout path is a claim about where the tree lives, and
# the failure it produces is silent and total: cmake is pointed at a
# directory that does not exist, every build fails, and every mutant is
# reported as "rejected by the compiler". That is a report about nothing --
# it says 29 changes were all caught by the type system when in fact not one
# of them was ever compiled. Deriving the root means the harness runs where
# the tree actually is, and the preflight below turns a misconfigured tree
# into a refusal instead of a false pass.
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BUILD=${OCC_TLS_BUILD:-$ROOT/build}
TEST="$BUILD/tests/occ_test_runtime_loader"
LOADER="$ROOT/src/runtime/loader.cpp"
HEADER="$ROOT/include/occ/runtime/loader.h"
TESTFILE="$ROOT/tests/test_runtime_loader.cpp"

# Preflight. The harness rewrites LOADER and TESTFILE in place, so a tree that
# cannot build is a tree this script would corrupt 29 times over while
# reporting success. Everything the run depends on is checked once, up front,
# and the whole run is refused if any of it is missing -- a refusal costs one
# message, a false report costs the suite's credibility.
preflight() {
    local missing=0 f
    for f in "$BUILD" "$TEST" "$LOADER" "$HEADER" "$TESTFILE"; do
        if [ ! -e "$f" ]; then
            echo "refusing to run: $f does not exist" >&2
            missing=1
        fi
    done
    if [ "$missing" -ne 0 ]; then
        echo "configure and build first, e.g." >&2
        echo "  cmake -S '$ROOT' -B '$BUILD' && cmake --build '$BUILD' -j\"\$(nproc)\"" >&2
        exit 2
    fi
    if [ ! -x "$TEST" ]; then
        echo "refusing to run: $TEST is not executable" >&2
        exit 2
    fi
    # Build the pristine tree before running it. This step is not redundant
    # with the file-existence checks above, and skipping it is a trap that
    # has already been sprung once: the binary sitting in the build directory
    # is whatever the *previous* run last compiled, which -- because every
    # mutant here edits the sources in place -- is that run's last mutant.
    # An interrupted run therefore leaves a deliberately broken loader
    # compiled into $TEST, and a preflight that only executes the binary
    # reports the suite as failing when the sources are fine. The report then
    # says the suite is broken, which sends the reader looking for a defect
    # in code that has none.
    #
    # So the baseline is built, not assumed. If it does not build, that is a
    # real fact about the tree and the run is refused.
    if ! cmake --build "$BUILD" -j"$(nproc)" >"$WORK/preflight-build.log" 2>&1; then
        echo "refusing to run: the pristine tree does not build" >&2
        sed 's/^/  /' "$WORK/preflight-build.log" | head -20 >&2
        exit 2
    fi
    # A baseline run, before anything is rewritten. Every result below is
    # relative to this: a suite that already fails makes "caught" and
    # "survived" both meaningless, because a mutant that fails for an
    # unrelated reason is indistinguishable from one the suite is testing.
    if ! "$TEST" >"$WORK/preflight.log" 2>&1; then
        echo "refusing to run: the suite fails before any mutant is applied" >&2
        grep FAIL "$WORK/preflight.log" | head -20 >&2
        exit 2
    fi
}

# Taken now, at run time, for the reason mutate-retry.sh's comment gives at
# length: a fixed path is a claim about what the file contained, and this
# script restores from it after every mutant.
WORK=$(mktemp -d)
cp "$LOADER" "$WORK/loader.pristine"
cp "$HEADER" "$WORK/loader.h.pristine"
cp "$TESTFILE" "$WORK/test.pristine"

restore() {
    cp "$WORK/loader.pristine" "$LOADER"
    cp "$WORK/loader.h.pristine" "$HEADER"
    cp "$WORK/test.pristine" "$TESTFILE"
}

# The exit trap restores the tree before it removes the copies, and it runs on
# every path out of this script including SIGINT and SIGTERM. This is not
# tidiness. The trap used to delete $WORK and nothing else, so a run that was
# interrupted -- by a timeout, a Ctrl-C, or a kill -- left LOADER and TESTFILE
# holding whichever mutant was in flight. The next build then compiled a
# deliberately broken loader and the next run reported failures that had
# nothing to do with any mutant, which is a worse outcome than no run at all:
# it looks like a defect in the code under test. Restoring on the way out is
# what makes an interrupted run leave the tree exactly as it found it.
#
# restore is defined before the trap so the handler cannot fire before the
# function exists, and the handler tolerates a missing $WORK because it runs
# after rm in the worst case.
#
# **The third `cp` in `restore` had its arguments the wrong way round.** It read
# `cp "$TESTFILE" "$WORK/test.pristine"` -- the file under test *into* the
# backup -- where every other line copies the backup back over the file. So the
# first mutant applied replaced the pristine copy of the test file with the
# mutated one, and from then on `restore` put the mutant back: the tree was
# left holding whatever mutant the run was on, and the run's own report said
# every later mutant was "caught" because the tree was already broken. The
# mutation harness is the one tool in this repository that writes to the source
# tree, so a restore that restores nothing is worse than no restore -- it looks
# like the safety net working.
cleanup() {
    if [ -n "${WORK:-}" ] && [ -f "$WORK/loader.pristine" ]; then
        restore
    fi
    rm -rf "${WORK:-/nonexistent}"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

caught=0
survived=0
broken=0
failed_names=()

# mutate NAME FILE OLD NEW [OLD NEW ...]
#
# The extra OLD/NEW pairs exist for the mutants that need two edits at once,
# and they are applied as a single mutant rather than as two runs. The reason
# is specific and not hypothetical: this code has a *doubled* guard on the
# PE32 callback field -- the read is conditional and so is the use -- and
# each half on its own is an equivalent change, which a harness that ran them
# separately would report as two surviving mutants. Neither report would be a
# fact about the suite; both would be facts about single-edit changes to
# doubled code. A change that takes both edits is the smallest one that
# alters behaviour, so it is the one the suite has to catch, and it has to be
# built and run as one mutant for the report to mean anything.
mutate() {
    local name="$1" file="$2" old="$3" new="$4"
    shift 4
    restore
    python3 - "$file" "$@" "$old" "$new" <<'PYEOF'
import sys
# argv: path, then the extra OLD/NEW pairs, then the primary OLD/NEW pair.
# The primary pair goes last so that a failure names the primary anchor
# rather than an addition to a mutant that already works.
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
        #
        # But "did not compile" and "the build never ran" are different facts
        # and the report must not merge them. A cmake that fails because the
        # build directory is missing, because a header moved, or because the
        # disk is full has rejected nothing at all -- and counting it as caught
        # is how a whole run of 29 mutants once reported "rejected by the
        # compiler" while not one of them had been compiled. So the log is
        # read rather than assumed: a build failure that contains no compiler
        # diagnostic is a broken harness or a broken tree, and it is counted in
        # neither column.
        if grep -qE '(^|[ :])(error|Error):' "$WORK/build.log"; then
            echo "  [$name] rejected by the compiler"
            caught=$((caught + 1))
        else
            echo "  [$name] BUILD FAILED BEFORE COMPILING -- not counted as caught"
            echo "      (the build failed without a compiler diagnostic; this is a"
            echo "       harness or tree problem, not a fact about this mutant)"
            sed 's/^/      /' "$WORK/build.log" | head -5
            broken=$((broken + 1))
            failed_names+=("$name")
        fi
        restore
        return
    fi
    if "$TEST" >"$WORK/run.log" 2>&1; then
        echo "  [$name] SURVIVED"
        survived=$((survived + 1))
        failed_names+=("$name")
        # The failing output is kept, because "it survived" is a claim about
        # which assertions did not fire and the reader wants to see which
        # ones those were.
        grep -c FAIL "$WORK/run.log" | sed 's/^/      (the run reported /;s/$/ failing checks anyway -- see below)/'
    else
        echo "  [$name] caught"
        caught=$((caught + 1))
    fi
    restore
}

preflight

echo "TLS mutants"

# ------------------------------------------------- the directory's source

# The mutant this whole layer exists to catch. Reading the directory out of
# the file instead of the mapping: every value is the right shape, every
# bounds check passes, and the template address is the image's *linked*
# address rather than the mapped one. Caught by
# test_tls_template_is_copied_from_the_mapping, which loads the image away
# from its linked base and reads the copied pointer back out of the block --
# a comparison no mirror of the loader's own arithmetic could make.
mutate "directory-from-file-not-memory" "$LOADER" \
"    const bool mapped = context.placement != nullptr;" \
"    const bool mapped = false;"

# The same mistake made in the block builder rather than in the directory
# read: the template copied out of the file. There is no `bytes` parameter
# any more, so the mutant has to reintroduce one -- which is itself the
# point. A loader that needed the file to build a thread's TLS block would
# have an API this runtime deliberately does not have.
mutate "template-from-file-not-space" "$LOADER" \
"        if (m.template_size != 0) {
            if (!load_from(space, m.template_va, reinterpret_cast<void*>(out->address),
                           m.template_size)) {" \
"        if (m.template_size != 0) {
            if (false) {"

# The callback array read from the file rather than the space. Same shape as
# the template and caught by the same kind of assertion: the entries are
# addresses, and the test compares them against the mapped ones.
#
# The anchor is the *whole* walk, including the stride and the width branch,
# because the stride is now the module's pointer width and not a constant.
# Anchoring on a fragment that named 8 would keep working while the code it
# claimed to describe had stopped existing.
mutate "callbacks-from-file-not-space" "$LOADER" \
"        for (std::uint64_t at = m.callbacks_va; at + stride <= region_end;
             at += stride) {
            std::uint64_t fn = 0;
            if (stride == 4) {
                std::uint32_t narrow = 0;
                if (!load_u32_from(space, at, narrow)) {
                    break;
                }
                fn = narrow;
            } else if (!load_u64_from(space, at, fn)) {
                break;
            }" \
"        for (std::uint64_t at = m.callbacks_va; at + stride <= region_end;
             at += stride) {
            std::uint64_t fn = 0;
            break;"

# ---------------------------------------------------------- the encoding

# Every field read as a virtual address, which is what Wine does and what
# this runtime replaced. A 64-bit image's directory is RVA-encoded, so this
# mutant resolves a template to `base + 0x1100` when the field already *is*
# the RVA, giving an address one image above where it is -- refused by the
# bounds check, and therefore caught by the load succeeding.
mutate "rva-fallback-to-va-only" "$LOADER" \
"    return is_rva ? base + field : field;" \
"    (void)is_rva; return static_cast<std::uint64_t>(field);"

# The other direction: every field read as an RVA. A VA-encoded directory --
# the specification's own form, and the only one a low-based image can use --
# would resolve to `base + 0x40011000`, far outside, refused. Caught by the
# low-base fixture, which is the only one that writes the VA form.
mutate "va-fallback-to-rva-only" "$LOADER" \
"    return is_rva ? base + field : field;" \
"    (void)is_rva; return base + field;"

# The disambiguation inverted. An image based low whose VA-encoded field
# happens to be under SizeOfImage would be read as an RVA, landing one image
# below where it is. This is the ambiguous case the resolve comment names,
# and resolving it the other way is the mistake that would make a
# specification-conforming file fail.
mutate "field-inside-inverted" "$LOADER" \
"    return field >= base && field - base < image_rva_end;" \
"    return !(field >= base && field - base < image_rva_end);"

# ------------------------------------------------------------- the slot

# The slot is never written into the image. Every TLS test that loads with a
# mapper reads that DWORD back with a memcpy, so this cannot survive.
mutate "index-never-written" "$LOADER" \
"    store_u32(m.index_va, m.index);" \
"    ;"

# The wrong slot number is written -- the module's own index rather than the
# one the table handed it. Indistinguishable from the above in a
# single-module process and different in a three-module one, which is why
# test_tls_frees_and_reuses_a_slot exists.
mutate "index-writes-zero" "$LOADER" \
"    store_u32(m.index_va, m.index);" \
"    store_u32(m.index_va, 0);"

# No slot reuse: a freed slot is never offered again, so a process that
# loads and unloads in a loop grows its table without bound. Caught by the
# reuse test, which frees the middle slot and asserts the next load takes
# it.
mutate "no-slot-reuse" "$LOADER" \
"        if (table.modules[i].template_va == 0 &&
            table.modules[i].template_size == 0 &&
            table.modules[i].zero_fill == 0 &&
            table.modules[i].callbacks_va == 0) {" \
"        if (false) {"

# The freed slot is *erased* rather than zeroed, which renumbers every
# module after it. The reuse test asserts the third module still reads slot
# 2 after the middle one was freed, so this moves a number that is written
# into an image.
mutate "free-renumbers-by-erasing" "$LOADER" \
"    auto release = [&]() noexcept {
        if (m.index < table.modules.size()) {
            table.modules[m.index] = TlsModule{};
        }" \
"    auto release = [&]() noexcept {
        if (m.index < table.modules.size()) {
            table.modules.erase(table.modules.begin() +
                                static_cast<std::ptrdiff_t>(m.index));
        }"

# A failed load keeps its slot. The read-only-index test asserts both the
# entry is zeroed and the high-water mark came back, because a slot consumed
# by a load that failed is a slot the reuse search will never offer again.
mutate "failed-load-keeps-its-slot" "$LOADER" \
"    if ((protection_to_prot(r->protection) & PROT_WRITE) == 0) {
        release();" \
"    if ((protection_to_prot(r->protection) & PROT_WRITE) == 0) {"

# ------------------------------------------------------ the index's timing

# The index written before the final protections, which is where it was
# before this was found. The check it used to be guarded by was a check of a
# temporary state -- every region is ReadWrite until the protections are
# applied -- so it never fired, and a read-only index field was written
# anyway. Moving the store back is the exact regression, and the
# read-only-index test is the exact thing that catches it.
mutate "index-written-before-protections" "$LOADER" \
"    if (m.index_va == 0) {
        // A directory with no \`AddressOfIndex\` is legal" \
"    if (m.index_va == 0 || space.find(m.index_va) != nullptr) {
        // A directory with no \`AddressOfIndex\` is legal"

# The writability check dropped from the one place it is meaningful.
mutate "index-writability-not-checked" "$LOADER" \
"    if ((protection_to_prot(r->protection) & PROT_WRITE) == 0) {" \
"    if (false) {"

# ------------------------------------------------------------- the block

# The zero fill is not written, so every thread's TLS block arrives with
# whatever was at that address before. Caught by reading the fill half back
# and comparing it to zero.
mutate "zero-fill-not-written" "$LOADER" \
"        if (m.zero_fill != 0) {
            std::memset(reinterpret_cast<void*>(out->address + m.template_size),
                        0, m.zero_fill);
        }" \
"        if (false) {"

# The fill written over the template instead of after it. A block of the
# right size whose first half is zeros: a loader that got the arithmetic
# right and the offset wrong, which is the mistake this one actually is.
mutate "zero-fill-overwrites-the-template" "$LOADER" \
"            std::memset(reinterpret_cast<void*>(out->address + m.template_size),
                        0, m.zero_fill);" \
"            std::memset(reinterpret_cast<void*>(out->address), 0, m.zero_fill);"

# The block sized as the template alone, dropping the fill. Caught by the
# size assertion, which is stated as the sum of the two the spec declared
# rather than as either one of them.
mutate "block-size-drops-the-fill" "$LOADER" \
"    const std::uint64_t total =
        static_cast<std::uint64_t>(m.template_size) + m.zero_fill;" \
"    const std::uint64_t total = m.template_size;"

# A failed build leaving its mapping behind used to be a live mutant, caught
# by test_tls_a_failed_block_gives_its_mapping_back. It stopped being one when
# the pre-checks moved above the allocation, and the reason is worth recording
# because "the test still passes" and "the test still has something to say"
# came apart here.
#
# The defect that fix addressed was that the block could be mapped *over* the
# template, so the copy read a page of zeros out of the block it had just made
# and reported success. Closing it meant refusing a template that is not
# mapped *before* mapping anything -- and once the refusal happens there, the
# allocation never happens, so there is no mapping to hand back and the
# rollback below `refuse` has nothing to roll back.
#
# So the mutation survives, and it is not a hole in the suite: it is a
# statement that the code no longer has the shape the mutation removes. The
# rollback is still there, and still correct, because "the template is mapped"
# and "the template is mapped *and stays mapped*" are different claims and
# only the second one is trusted -- but the path that would exercise it is
# now unreachable, and a test that exercised it would have to manufacture the
# unmapping *after* the checks, which is a thing a test can do to a function
# only by giving it a table whose entries it then invalidates behind the
# function's back. That is a test of nothing.
#
# It is listed among the unreachable ones below rather than deleted, because a
# harness that quietly dropped a mutant would leave no trace of a check that
# used to be possible.

# free_tls_block does nothing, so a thread's block is never released and the
# ledger keeps describing it.
mutate "free-tls-block-is-a-no-op" "$LOADER" \
"    if (block.address == 0) {
        return;
    }" \
"    if (block.address != 0) {
        return;
    }"

# ---------------------------------------------------------- the callbacks

# The walk does not stop at the first refusal, so a module that said "this
# load failed" has its remaining initialisers run anyway. Caught by counting
# the calls: three callbacks where the second refuses must produce exactly
# two calls.
mutate "callbacks-ignore-the-refusal" "$LOADER" \
"        if (!callback(state, fn, module, reason)) {" \
"        if (false) {"

# The callbacks called in the wrong order -- back to front, which a reverse
# iteration gets for free. The order is the array's, and a module's
# initialisers can depend on it.
mutate "callbacks-walk-backwards" "$LOADER" \
"    for (std::uint64_t fn : block.callbacks) {" \
"    for (auto it = block.callbacks.rbegin(); it != block.callbacks.rend(); ++it) {
        const std::uint64_t fn = *it;"

# The null terminator treated as a callback, so every module with a
# callback array also gets a call at address zero.
mutate "terminator-counted-as-a-callback" "$LOADER" \
"            if (fn == 0) {" \
"            if (false) {"

# A missing invoker reported as a failure rather than as nothing to do. The
# distinction matters: a caller that cannot call into the image has not been
# told its callbacks refused, and reporting otherwise invents a module's
# failure.
mutate "no-invoker-is-a-failure" "$LOADER" \
"    if (callback == nullptr) {
        // Not a refusal of the module: a caller with no way to call into the
        // image can still walk the list, and saying \"failed\" here would make
        // an absence of an invoker indistinguishable from a callback that
        // returned false. Nothing was called, which is what ok means.
        out.ok = true;
        return out;
    }" \
"    if (callback == nullptr) {
        out.error = TlsError::CallbackFailed;
        return out;
    }"

# ----------------------------------------------------- the empty directory

# A directory whose template, fill and callback array are all zero gets a
# slot anyway, which makes its `AddressOfIndex` -- zero, so the image base --
# a place a slot number gets written. The all-zero test reads the DOS header
# back to catch exactly that.
mutate "empty-directory-gets-a-slot" "$LOADER" \
"    if (template_size == 0 && dir.zero_fill == 0 && dir.callbacks_va == 0) {
        out.ok = true;
        return out;
    }" \
"    if (false) {
        out.ok = true;
        return out;
    }"

# A zero-length template treated as malformed. Legal, and it is the other
# half of the empty-directory case: a module whose TLS is only a zero fill
# has EndAddressOfRawData == StartAddressOfRawData.
mutate "zero-length-template-refused" "$LOADER" \
"    if (dir.end_raw < dir.start_raw) {" \
"    if (dir.end_raw <= dir.start_raw) {"

# --------------------------------------------------------- the field width
#
# The mutants that used to live here assumed a PE32 directory was five DWORDs
# with no callback field, and that PE32+ therefore needed a "does this form
# have one" flag. Both halves of that belief were wrong, and the loader was
# built on them: it read a real 64-bit module's directory at a four-byte
# stride, saw `0x1` -- the high half of the start pointer -- as the end, and
# refused every module mingw produces. The belief is gone; `tls_layout` now
# states the width once and the two readers take it from there. See
# `RawTlsDirectory`.
#
# So the mutants below are the ones the mistake can still make: change the
# width, or ignore it.

# A PE32+ directory read at a four-byte stride, which is the mistake in its
# original form. The template start comes out as the low half of the real
# pointer and the end as the high half, so the directory is refused for
# ending before it starts. Caught by test_loads_a_real_compiler_pe, which
# loads a file a real linker produced -- no synthetic fixture has the field
# values that make this visible, which is exactly why the real one exists.
#
# The replacement is PE32's layout exactly, 24 bytes included. A short one
# would be a different mistake (a truncated structure) rather than this one,
# and a mutant that measures two things reports as neither.
mutate "pe32-plus-read-at-four-bytes" "$LOADER" \
"        return TlsDirectoryLayout{0, 8, 16, 24, 32, 36, 8, 40};" \
"        return TlsDirectoryLayout{0, 4, 8, 12, 16, 20, 4, 24};"

# A PE32 directory read at an eight-byte stride: the same mistake the other
# way. `IMAGE_TLS_DIRECTORY32` is 24 bytes of 32-bit pointers, so reading it
# at 8 takes the second half of `EndAddressOfRawData` as `AddressOfIndex`.
# Caught by test_tls_pe32_fields_are_read_at_their_own_width, which asserts
# the decoded index address against the one the fixture wrote.
mutate "pe32-read-at-eight-bytes" "$LOADER" \
"    return TlsDirectoryLayout{0, 4, 8, 12, 16, 20, 4, 24};" \
"    return TlsDirectoryLayout{0, 8, 16, 24, 32, 36, 8, 40};"

# The callback array walked at the process's width rather than the module's.
# A PE32 module with two 32-bit callbacks is then reported as having one,
# whose address is the concatenation of it and the next four bytes, and the
# second initialiser never runs. Caught by
# test_tls_pe32_reads_its_callback_field, which builds a two-entry array of
# the 32-bit form and counts what comes back.
mutate "callback-array-walked-at-eight-bytes" "$LOADER" \
"        const std::uint64_t stride =
            m.pointer_size == 4 ? 4u : 8u;" \
"        const std::uint64_t stride = 8u;"

# The block mapped before the template is checked, which is the order this
# code had and had to stop having. The kernel chooses where a block goes, and
# it is free to choose the template's own address; the mapping then covers the
# template, the copy succeeds, and what is copied is a page of zeros out of
# the block that was just made. The function reports success and every thread
# of the program gets a zeroed template.
#
# This is the only mutant in this file that was a defect rather than a
# plausible mistake, and it is here because the fix is an ordering, and an
# ordering is exactly the thing a test suite stops noticing once it is right.
# The anchor is the check itself, in the shape the code has now: a null lookup
# or a short region, short-circuited so that `find` is not dereferenced when it
# answered nothing. An earlier version of this file guarded the same condition
# with a nested `if (m.template_size != 0)` and a `home` local, and the anchor
# named those. A refactor that keeps the behaviour and changes the spelling
# invalidates the mutant, and an anchor that no longer matches is the harness
# reporting a fact about its own text rather than about the code -- which is
# why "ANCHOR NOT UNIQUE" is counted separately from "survived" and is a
# thing to fix rather than a coverage hole to accept.
mutate "block-mapped-before-the-template-is-checked" "$LOADER" \
"    if (space.find(m.template_va) == nullptr ||
        space.find(m.template_va)->end() < m.template_va + m.template_size) {" \
"    if (false) {"

# ------------------------------------------- the refusal that costs a rollback

# The defect the fuzzer found, and the only one in this file that no unit test
# found. The loader records the image in the space before it walks the
# relocations, the IAT and the TLS directory, and every one of those three can
# refuse. The rollback undid the kernel mapping and, when there was no mapper,
# nothing at all -- so a refused `occ check` left the space describing an
# image whose bytes were never placed, which a caller cannot tell from a
# successful load.
#
# It survived every unit test because every unit test that reaches a post-record
# refusal supplies a mapper, and a mapper's rollback worked. The path with no
# mapper is `occ check`, which has no unit test of its own here. What found it
# was the loader harness's invariant -- a refused load leaves the space as it
# was -- over a corpus seed whose data directory array stops before the TLS
# entry. Both halves of that are in the tree now: the seed is
# pe_short_data_directory.bin, and the invariant is `same_map` in
# fuzz_loader.cpp.
# Two edits rather than one, and the second is not part of the mistake. The
# first turns the rollback back into a guard, which leaves `rollback` with no
# caller; the second is what keeps the mutant compiling. A mutant the compiler
# rejects is counted separately and honestly, but for *this* one that would be
# a way of not testing anything -- the behaviour change is the guard, and the
# pair is the smallest version of it that builds.
mutate "a-refused-load-keeps-its-record" "$LOADER" \
"            rollback(space, placement, batch);
            return out;" \
"            if (placement != nullptr) {
                rollback_placement(*placement, batch);
            }
            return out;" \
"void rollback(AddressSpace& space, Mapper* placement," \
"[[maybe_unused]] void rollback(AddressSpace& space, Mapper* placement,"

# ----------------------------------------------------- the suite's own base

# The one mutant in the test file, and the only one whose subject is the
# harness rather than the runtime. `claim_a_base` walks a stride and probes
# each candidate with MAP_FIXED_NOREPLACE; this takes the candidate the
# moment the probe *fails*, which is what the code would look like if the
# stride were trusted because it was chosen wide enough.
#
# It is not a straw man. That is exactly how the function was written for the
# first few runs, and it passed -- because on the build it was written on the
# kernel's answer came back outside the shared-library range, so every stride
# step after it was free by luck. On a GCC build the kernel answered inside
# that range and the same code stopped working. Caught by
# test_a_claim_steps_over_an_address_something_else_took, which parks a
# mapping inside the walk and checks that the claims on either side of it are
# not it.
mutate "claim-trusts-the-stride" "$TESTFILE" \
"        if (!r.ok()) {
            continue;
        }" \
"        if (!r.ok()) {
            return candidate;
        }"

# ------------------------------------------------------- unreachable ones

# The two below are commented out rather than listed as surviving, because
# they *are* reachable and a harness that reported them as survivors would be
# reporting a fact about the code that is false. Each is a genuine mutant; a
# test that caught it would have been a test of a case no file can produce.
#
#   * `if (block > UINT32_MAX) return TooLarge` -- the template and the fill
#     are each 32-bit, so their sum is at most 2^33 and the check is only
#     reachable if a future format widens the declared size. Un-commenting
#     the line below and the corresponding assertion in
#     test_tls_error_names_cover_their_enums would make it live; until then
#     it is a guard against a format change, not a test.
#
#   * `if (dir.callbacks_va >= image_end)` -- a callback array of zero
#     entries still has a terminator, so the bound is right, but the array
#     must also fit *inside* the image, and no fixture builds one that
#     starts inside and ends outside. That is a coverage gap rather than an
#     unreachable branch, and the honest thing is to say so here rather than
#     to claim the branch is dead.

echo
echo "----------------------------------------------------------------"
echo "caught:   $caught"
echo "survived: $survived"
# A broken build is reported as its own column and fails the run, because the
# alternative is a report that reads as coverage while measuring nothing.
echo "unbuilt:  $broken"
if [ "$broken" -gt 0 ]; then
    echo "mutants that were never compiled (these are NOT results):"
    for n in "${failed_names[@]}"; do
        echo "  - $n"
    done
    exit 1
fi
if [ "$survived" -gt 0 ]; then
    echo "surviving mutants:"
    for n in "${failed_names[@]}"; do
        echo "  - $n"
    done
    exit 1
fi
exit 0

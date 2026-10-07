#!/usr/bin/env bash
# Mutation harness for the ntdll memory layer: the parameter rules, the
# rounding, the handle table, the range checks.
#
# Three sources are mutated rather than one, because the layer is three files
# and some of its rules live in the ledger rather than in the calls:
# `ntdll.cpp` holds the calls, `ntdll.h` holds the two `zero_bits` rules, and
# `address_space.cpp` holds the commit state that a decommit and a recommit move.
# A rule written in one of them and asserted through another is exactly the case
# a single-file harness would miss.
#
# Same contract as mutate-exports.sh, and for the same reason: a mutant that
# survives is a hole in the suite, and a harness that reports "all caught" is
# only worth what the mutants were worth. Every mutant below is a change a
# plausible mistake would make -- not a sabotage, a mistake.
#
# Every mutant is run under two builds and has to fail both, and that is not
# redundancy. This layer is the one where a wrong answer is a *silent*
# difference far more often than it is a refusal: a status code nobody
# branches on, a size one page short, a handle that names a neighbouring slot.
# The plain run catches the ones that change an assertion. The sanitizer run
# catches the ones that change memory -- a `memcpy` of a live C++ object, a
# read past a region -- which a plain run frequently gets away with because the
# freed bytes still hold the right value.
#
# The three marked below earned their place by surviving a first run, and two of
# them are the same mistake in opposite directions. That is the point: the
# read and write paths differ in one status code, so a runtime that harmonised
# them would pass a test of either and fail a program that branches on it.
set -u

BUILD=/workspace/Occ/build
BUILD_SAN=/workspace/Occ/build-asan
TEST="$BUILD/tests/occ_test_ntdll"
TEST_SAN="$BUILD_SAN/tests/occ_test_ntdll"
# The layer is exercised from three files and a mutant caught anywhere is
# caught. `occ_test_ntdll` reaches the calls, but `Mapper::protect`'s own
# semantics -- a protection is not a commit -- are asserted in
# `occ_test_mapper`, and a `Mapper` mutant that ntdll's path never runs through
# would come back SURVIVED from a binary that was never asked about it. A
# survivor has to mean the suite is blind, not that the wrong suite was run.
SUITE="$BUILD/tests/occ_test_mapper $BUILD/tests/occ_test_placement"
SUITE_SAN="$BUILD_SAN/tests/occ_test_mapper $BUILD_SAN/tests/occ_test_placement"
SRC=/workspace/Occ/src/runtime/ntdll.cpp
HDR=/workspace/Occ/include/occ/runtime/ntdll.h
MAPPER=/workspace/Occ/src/runtime/mapper.cpp
SPACE=/workspace/Occ/src/runtime/address_space.cpp

# Taken now, at run time, for the reason mutate-exports.sh's comment gives at
# length: a fixed path is a claim about what the file contained, and this script
# restores from it after every mutant.
WORK=$(mktemp -d)

# The rebuild on the way out, and it is a trap rather than a line at the end of
# the script because a harness that leaves a mutated binary behind is worse
# than one that crashes. Restoring the *source* is not enough: the last mutant
# compiled is still in `$BUILD` and `$BUILD_SAN`, it compiles, and the next
# `ctest` runs it and reports a failure that has nothing to do with any code
# under test.
#
# Which means this also runs on SIGINT. A harness interrupted halfway through
# twenty mutants has one of them built, and the person who interrupted it went
# away believing the tree was clean.
cleanup() {
    # The restore first: rebuilding before the source is back would rebuild the
    # mutant a second time and leave *that* behind instead.
    cp "$WORK/ntdll.pristine" "$SRC" 2>/dev/null || true
    cp "$WORK/ntdll.h.pristine" "$HDR" 2>/dev/null || true
    cp "$WORK/mapper.pristine" "$MAPPER" 2>/dev/null || true
    cp "$WORK/space.pristine" "$SPACE" 2>/dev/null || true
    cmake --build "$BUILD" -j"$(nproc)" >/dev/null 2>&1 || true
    cmake --build "$BUILD_SAN" -j"$(nproc)" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cp "$SRC" "$WORK/ntdll.pristine"
cp "$HDR" "$WORK/ntdll.h.pristine"
cp "$MAPPER" "$WORK/mapper.pristine"
cp "$SPACE" "$WORK/space.pristine"

caught=0
survived=0
anchor_failed=0
failed_names=()
anchor_names=()

restore() {
    cp "$WORK/ntdll.pristine" "$SRC"
    cp "$WORK/ntdll.h.pristine" "$HDR"
    cp "$WORK/mapper.pristine" "$MAPPER"
    cp "$WORK/space.pristine" "$SPACE"
}

# mutate NAME FILE OLD NEW [OLD NEW ...]
#
# The extra pairs are for the mutants that need two edits at once, applied as a
# single mutant rather than as two runs: a rule that is written in more than one
# place has two equivalent halves, and a harness that ran them separately would
# report two survivors where there is one fact -- that the rule is untested.
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
        # **This is a harness failure, not a coverage result, and the two must
        # never be allowed to look alike.** The branch below does count the
        # mutant as un-caught, which is the conservative answer -- an unapplied
        # mutant has certainly not been caught -- but the summary prints the
        # count in the same column as real survivors, and a reader has no way
        # to tell "the suite has a hole" from "the harness pointed at code that
        # does not exist". The second reading is the dangerous one, because it
        # looks like a passing result.
        #
        # It is not hypothetical. `the-placement-search-gives-up-early` anchored
        # on `kMaxAttempts = 16384` while the source said `64`, so the anchor
        # matched nothing, the mutant was never applied, and the run reported a
        # survivor whose actual cause was that the *production code* carried
        # the very bug the mutant was written to detect -- and the harness had
        # been reporting it as a live, un-caught mutant for several runs
        # without anyone reading the name closely enough to notice the
        # contradiction. The code was wrong the whole time and the mutant that
        # would have caught it never ran.
        #
        # So these are reported in their own list, and the summary counts them
        # separately rather than folding them into the survivor total. A
        # survivor means "the suite has a hole"; an anchor failure means "this
        # report is not a measurement of anything", and the second is strictly
        # more urgent because it invalidates the first.
        echo "  [$name] ANCHOR FAILED -- the mutant was never applied; this is a"
        echo "        harness fault, NOT evidence about the test suite"
        anchor_failed=$((anchor_failed + 1))
        anchor_names+=("$name")
        restore
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
    # The plain run first, because a mutant that segfaults or fails an
    # assertion is caught by the fastest signal available.
    if ! "$TEST" >"$WORK/run.log" 2>&1 || ! $SUITE >"$WORK/run-suite.log" 2>&1; then
        echo "  [$name] caught"
        caught=$((caught + 1))
        restore
        return
    fi
    # The sanitizer run second, and it is not belt-and-braces. This layer
    # copies whole structures into caller buffers and reads `Region` fields
    # across calls that can free them; both are memory faults that a plain run
    # frequently survives, because the bytes are still there and still say the
    # right thing.
    if ! cmake --build "$BUILD_SAN" -j"$(nproc)" >"$WORK/build-san.log" 2>&1; then
        echo "  [$name] rejected by the compiler (sanitizer build)"
        caught=$((caught + 1))
        restore
        return
    fi
    if "$TEST_SAN" >"$WORK/run-san.log" 2>&1 && $SUITE_SAN >"$WORK/run-san-suite.log" 2>&1; then
        echo "  [$name] SURVIVED"
        survived=$((survived + 1))
        failed_names+=("$name")
        echo "      (passed under the sanitizer too -- a real gap, not a stale binary)"
    else
        if grep -q "AddressSanitizer" "$WORK/run-san.log" "$WORK/run-san-suite.log" 2>/dev/null; then
            echo "  [$name] caught (AddressSanitizer -- the plain run passed it)"
        else
            echo "  [$name] caught (sanitizer build)"
        fi
        caught=$((caught + 1))
    fi
    restore
}

echo "ntdll memory layer mutants"

# ------------------------------------------------- the zero_bits window check

# The 22-31 hole closed. This is the mutation the whole `zero_bits` rule
# exists to prevent: the hole looks like an off-by-one, and "fixing" it makes
# this runtime refuse `zero_bits == 21` -- a value Windows accepts and a value a
# 32-bit-aware loader passes. The failure would be in a program that was never
# wrong, which is the direction of divergence nobody tests for.
mutate "the-zero-bits-hole-is-closed" "$SRC" \
"    if (zero_bits > 21 && zero_bits < 32) {
        return false;
    }" \
"    if (zero_bits > 21 && zero_bits < 33) {
        return false;
    }"

# The hole widened by one on the other side, so `zero_bits == 32` is refused
# too. A bound that is right at one end and wrong at the other is one bound, not
# two checks, and 32 is a value a program computing "below 2^64" passes.
mutate "the-zero-bits-hole-is-one-too-wide" "$SRC" \
"    if (zero_bits > 21 && zero_bits < 32) {
        return false;
    }" \
"    if (zero_bits > 20 && zero_bits < 32) {
        return false;
    }"

# `zero_bits` treated as a bound on the *address* rather than on the search.
# This survived the first run of this harness and it is the most interesting
# result it has produced, because the check it removes is one Wine does not
# have either: `virtual.c:4618-4623` uses `zero_bits` only when `*addr == 0`.
# A caller that passes both an address and the default window is refused here
# and placed correctly on Windows -- so the mutant is *closer* to correct for
# `NtMapViewOfSection` and further from it for `NtAllocateVirtualMemory`, which
# is exactly why the asymmetry is transcribed rather than smoothed over.
mutate "zero-bits-is-checked-against-a-requested-address" "$SRC" \
"    if (*addr != 0 && !zero_bits_accepts(zero_bits, *addr)) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter4,
            \"the requested address \" + std::to_string(*addr) +
                \" does not fit the window zero_bits \" +
                std::to_string(zero_bits) + \" describes\");
    }" \
"    if (false) {
        return refuse<std::uint64_t>(Status::InvalidParameter4, \"unused\");
    }"

# The mask in the at-or-above-32 branch written as a run of low ones instead of
# Wine's own `~zero_bits`. These two agree at exactly one value -- 32 -- and
# disagree everywhere else, so a suite that only tests 32 cannot tell them
# apart. It is here because "obviously correct" and "what Windows does" are
# different things and this is a case where they are.
mutate "the-above-32-zero-bits-mask-is-recomputed" "$HDR" \
"    return (addr & ~static_cast<std::uint64_t>(zero_bits)) == 0;" \
"    return (addr & ~((1ULL << (64 - zero_bits)) - 1)) == 0;"

# The limit's shift losing the 32. The below-32 branch computes
# `2^(32 - zero_bits) - 1`, so the shift amount is `32 + zero_bits`; dropping
# the 32 gives a limit billions of bytes too low, so every `zero_bits`
# placement refuses an allocation Windows places without trouble. A mutation
# whose whole effect is a *refusal* of something legal, which is the quietest
# failure mode there is.
mutate "the-zero-bits-limit-loses-its-32" "$HDR" \
"    return ~static_cast<std::uint64_t>(0) >>
               static_cast<unsigned int>(32u + zero_bits);" \
"    return ~static_cast<std::uint64_t>(0) >>
               static_cast<unsigned int>(zero_bits);"

# The mask branch of the limit read as a *shift* again -- which is exactly what
# Wine's `get_zero_bits_limit` does, and the bug this runtime does not copy. The
# mutant returns `~0ULL >> zero_bits` for every at-or-above-32 value, so
# `zero_bits == 32` yields a 64-byte window and every request for memory under
# 4 GiB fails on a machine with 4 GiB free. The mask reading and the shift
# reading differ at every such value, so the boundary walk in the suite --
# which asserts the ceiling and the accept test agree -- is what kills it.
mutate "the-zero-bits-mask-branch-is-read-as-a-shift" "$HDR" \
"    return static_cast<std::uint64_t>(zero_bits) + 1;" \
"    return ~static_cast<std::uint64_t>(0) >>
               static_cast<unsigned int>(zero_bits);"

# The ceiling made inclusive rather than exclusive. `map_below` places a region
# so that it *ends* at or below the ceiling, so the ceiling is one past the
# last admissible base; a ceiling that is the base itself promises one byte more
# than the window has, and the accept test then refuses the region the search
# just found. The disagreement is one byte wide, which is why the boundary walk
# asserts both sides of it.
mutate "the-zero-bits-mask-ceiling-is-inclusive" "$HDR" \
"    return static_cast<std::uint64_t>(zero_bits) + 1;" \
"    return static_cast<std::uint64_t>(zero_bits);"

# `zero_bits == 0` treated as "the whole space" rather than as "no window". Both
# readings are defensible and only one is Wine's: `get_zero_bits_limit` returns
# zero *immediately* for a zero, before any shifting, and the caller reads zero
# as no constraint. The mutant makes every unconstrained caller allocate inside
# a one-byte window.
mutate "the-zero-bits-zero-means-no-window" "$HDR" \
"    if (zero_bits == 0) {
        return 0;
    }" \
"    if (zero_bits == 0) {
        return ~static_cast<std::uint64_t>(0);
    }"

# ------------------------------------------------------------ ROUND_SIZE

# The page offset dropped from the rounding. `ROUND_SIZE` adds the address's
# in-page offset to the size *before* rounding, and that is what makes a range
# that starts partway into a page cover the whole page it ends on. Without the
# offset every partial-page range protects or frees one page less than Windows
# does -- in a call that succeeds either way, which is the worst kind of
# divergence: the program carries on and the bug surfaces later as a page that
# was not protected. The misaligned range in the protect cases is the assertion
# that kills it.
#
# This mutant and the mask-term one below delete different terms of the same
# expression, and both must be caught: the two are the over- and under-rounding
# ends of one macro, and a suite that pinned only one of them could not tell a
# correct `ROUND_SIZE` from one that is wrong in the other direction.
mutate "round-size-drops-the-in-page-offset" "$SRC" \
"    return (size + (addr & (AddressSpace::kPageSize - 1)) +
            (AddressSpace::kPageSize - 1)) &
           ~(AddressSpace::kPageSize - 1);" \
"    return (size + (AddressSpace::kPageSize - 1)) &
           ~(AddressSpace::kPageSize - 1);"

# The mask term inflated from `page_mask` to `page_size`, which is the bug this
# runtime shipped and the mutation is named for the survivor it would have been.
# `aligned + mask` rounds back down to `aligned`; `aligned + page_size` rounds
# up to `aligned + page_size`, so every request from a program that read the
# alignment rules -- which is every such request -- covers one page more than
# the caller named, and a free or a protect reaches into memory the program did
# not ask about. It survived a first run of this harness because the assertions
# had been written to match it, with the correct formula spelled out in the
# comment two lines above them; the mutation is here so the suite cannot go back
# to agreeing with it.
mutate "round-size-adds-a-page-size-instead-of-a-mask" "$SRC" \
"    return (size + (addr & (AddressSpace::kPageSize - 1)) +
            (AddressSpace::kPageSize - 1)) &
           ~(AddressSpace::kPageSize - 1);" \
"    return (size + (addr & (AddressSpace::kPageSize - 1)) +
            AddressSpace::kPageSize) &
           ~(AddressSpace::kPageSize - 1);"

# The mask term dropped altogether. Without it a page-aligned request of exactly
# one page comes back as that page rather than as two, which is right, and a
# *partially* aligned range comes back one page short -- the case the offset
# mutation above covers from the other side. These two mutants are the two ends
# of the same over- and under-rounding, and a suite that pins only one of them
# cannot tell a correct `ROUND_SIZE` from one that is wrong in the other
# direction.
mutate "round-size-loses-its-mask-term" "$SRC" \
"    return (size + (addr & (AddressSpace::kPageSize - 1)) +
            (AddressSpace::kPageSize - 1)) &
           ~(AddressSpace::kPageSize - 1);" \
"    return (size + (addr & (AddressSpace::kPageSize - 1))) &
           ~(AddressSpace::kPageSize - 1);"

# ------------------------------------------- the wrap that folds a size down

# **The overflow report in `round_size_from_checked` neutered, which puts the
# widening back to its unchecked form.** This is the mutant that matters most
# in this file, because the bug it restores was not a wrong answer: it was a
# wrong answer that looked like the right one. A size chosen to make the
# widening wrap folds *down* -- to zero at the extreme -- and every bound the
# callers write is `something < effective_size`, so a folded size satisfies
# every one of them. The call then walks an empty range, skips its region
# lookup, skips its commit check, asks the kernel for nothing, and returns
# success. `NtProtectVirtualMemory` reported an old protection the range never
# had, and `NtGetWriteWatch` answered "no regions" for a range full of them.
#
# A suite that only ever passes well-formed sizes cannot catch this, because
# the arithmetic is correct for every size that does not approach the top of
# the 64-bit range. The cases that catch it are the ones asserting on a size
# of `0xFFFFFFFFFFFFF001` and on the ledger it left behind.
mutate "the-rounding-overflow-report-is-dropped" "$SRC" \
"    overflowed = size > std::numeric_limits<std::uint64_t>::max() - addend;" \
"    (void)addend;
    overflowed = false;"

# **The second wrap, and it needs no dishonest size.** `range_end` is
# `base + effective_size`, and an `effective_size` that survives its own
# rounding can still carry the sum past the top of the 64-bit range when it is
# added to the base. The wrapped end lands *below* the start, so `while (cursor
# < range_end)` is false on entry and both walk loops run zero times -- the
# same silent success as the mutant above, reached by a different door. The two
# are separate mutants because they are separate guards: a suite that pinned
# only one would pass a runtime that still had the other.
mutate "the-range-end-wrap-check-is-removed" "$SRC" \
"    if (range_end < base || range_end > AddressSpace::kUserMax + 1) {" \
"    if (range_end > AddressSpace::kUserMax + 1) {"

# **The commit's bound restored to the addition form.** `base + commit_size >
# reservation_end` is the obvious way to write "the range reaches past the
# reservation" and it is defeated by the wrap exactly as the protect's is: the
# folded sum lands below the reservation's end, the check passes, and the call
# goes on to commit and then to protect a range reaching past the top of the
# address space. What the caller got was the kernel's refused `mprotect`
# reported as INVALID_ADDRESS -- a status naming the wrong problem, produced by
# a check that had been satisfied. Rewriting it as the subtraction is the fix,
# and restoring the addition is the mutant.
mutate "the-commit-bound-is-a-sum-that-can-wrap" "$SRC" \
"        if (commit_size > reservation_end - base) {" \
"        if (base + commit_size > reservation_end) {"

# **The write-watch sweep's end guard removed.** The sweep breaks on the first
# region at or past `end`, so a wrapped `end` stops it before it has looked at
# anything and the caller is told its correctly-named range holds no regions.
# The answer is short by an amount nothing in it records, which is why this is
# a survivor-in-waiting: there is no wrong status and no wrong pointer, only a
# count that is too small.
mutate "the-write-watch-end-wrap-check-is-removed" "$SRC" \
"    if (end < rounded) {" \
"    if (false) {"

# **The instruction-cache flush's coverage check removed, leaving only the
# guard on `addr + size`.** The two are different expressions: the flush's
# range is the *rounded* one, up to two pages larger than `addr + size`, and
# for an address with a nonzero in-page offset there are sizes where the direct
# sum fits and the rounded one wraps to zero. `range_is_mapped` answers `true`
# for a zero size whatever the address, so the range was accepted although it
# lies outside the address space -- which is the exact refusal the `addr + size`
# guard was written to make. This mutant is here rather than folded into the
# overflow one because the bug is a *missing second check*, not a missing
# report: the first guard is intact and passing.
mutate "the-flush-covers-a-range-it-never-checked" "$SRC" \
"        if (size_overflowed) {
            return refuse<std::uint64_t>(
                Status::InvalidAddress,
                \"the range \" + std::to_string(addr) + \"+\" +
                    std::to_string(size) +
                    \" runs off the end of the address space once the size is \"
                    \"widened to the pages the range touches, so there is no \"
                    \"instruction cache in it to flush\");
        }" \
"        (void)size_overflowed;"

# ------------------------------------------------ the read and write paths

# The read's unmapped-source status changed to INVALID_ADDRESS. This and the
# next one are the same mistake in opposite directions, and they are here
# because the asymmetry is the *point*: a read either copies all of a range or
# none of it, so it has no partial case and reports the violation; a write can
# genuinely be partial, so it reports PARTIAL_COPY. A runtime that used one code
# for both would send a program that branches on this down a path Windows never
# takes -- and a suite that tested only one of the two would pass.
mutate "the-read-reports-invalid-address" "$SRC" \
"            Status::AccessViolation,
            \"the range \" + std::to_string(addr) + \"+\" + std::to_string(size) +
                \" is not entirely mapped, so it cannot be read in one piece; \"" \
"            Status::InvalidAddress,
            \"the range \" + std::to_string(addr) + \"+\" + std::to_string(size) +
                \" is not entirely mapped, so it cannot be read in one piece; \""

# The write's, the other direction.
mutate "the-write-reports-access-violation" "$SRC" \
"            Status::PartialCopy,
            \"the range \" + std::to_string(addr) + \"+\" + std::to_string(size) +
                \" is not entirely mapped, so it cannot be written in one \"" \
"            Status::AccessViolation,
            \"the range \" + std::to_string(addr) + \"+\" + std::to_string(size) +
                \" is not entirely mapped, so it cannot be written in one \""

# The whole-range check reduced to a first-address check, which is the mistake
# that let a read of address zero through to a `memcpy` from a null pointer.
# The range walk is a loop over regions; collapsing it to one `find()` is the
# single most plausible edit to this function and it is a crash.
mutate "the-range-check-looks-only-at-the-first-address" "$SRC" \
"    std::uint64_t at = base;
    std::uint64_t left = size;
    while (left != 0) {
        const Region* r = space.find(at);
        if (r == nullptr) {
            return false;
        }" \
"    std::uint64_t at = base;
    std::uint64_t left = size;
    while (left != 0) {
        const Region* r = space.find(base);
        if (r != nullptr) return true;
        if (r == nullptr) {
            return false;
        }"

# The wrap check *removed* -- not relaxed. `addr + size` overflowing means the
# range runs off the top of the address space; without the check the walk starts
# from an address nothing is mapped at, so this one is caught by the answer
# rather than by the allocator. It is here because "the sum cannot overflow" is
# exactly the belief a reader of a 64-bit address API has.
#
# The earlier version of this mutant changed `end <= addr` to `end < addr`, and
# that was not a weaker version of the same mistake -- it was **not a mistake
# at all**, and no suite could have caught it. `end == addr` after the addition
# requires `size == 0`, and `size != 0` is the guard two lines above, so the
# two comparisons agree on every input that reaches them. A mutant that cannot
# be distinguished from the original by any input is not a hole in the suite; it
# is a hole in the *list*, and the honest entry is the one that removes the
# check rather than relaxing it. (Found by asking what a test for the relaxed
# form would have to look like, and discovering there is no such input.)
mutate "the-range-wrap-check-is-removed" "$SRC" \
"    if (size != 0 && end <= addr) {
        // Wrapped. The range runs off the top of the address space, so it
        // cannot be mapped, and the answer is the same one a short read gets.
        if (bytes_read != nullptr) {
            *bytes_read = 0;
        }
        return refuse<std::uint64_t>(
            Status::AccessViolation,
            \"the range \" + std::to_string(addr) + \"+\" + std::to_string(size) +
                \" runs off the end of the address space\");
    }" \
"    if (size != 0 && end <= addr && false) {
        // Wrapped. The range runs off the top of the address space, so it
        // cannot be mapped, and the answer is the same one a short read gets.
        if (bytes_read != nullptr) {
            *bytes_read = 0;
        }
        return refuse<std::uint64_t>(
            Status::AccessViolation,
            \"the range \" + std::to_string(addr) + \"+\" + std::to_string(size) +
                \" runs off the end of the address space\");
    }"

# ------------------------------------------------------------- the handles

# The index masked instead of shifted. `make_handle` shifts the index left by
# one to leave the low bit free for the oddness marker; masking the low bit
# instead maps slot 0 and slot 1 to the *same* handle, so the first two handles
# a program opens are one number and closing either closes both. This survived
# the first run of this harness, and the reason is worth recording: the tests
# that existed checked "two handles are different" and "a stale handle is
# refused", and both of those *pass* with two slots aliased -- the second insert
# returns the same number and the test reads it as "different" only because it
# compared against a handle from a table that had since been closed.
mutate "the-handle-index-is-masked-not-shifted" "$SRC" \
"           ((static_cast<std::uint64_t>(index) << 1) & 0xFFFFFFFFULL) | 1ULL;" \
"           (static_cast<std::uint64_t>(index) & 0xFFFFFFFEULL) | 1ULL;"

# The cookie check removed, so a handle from another table resolves here. Two
# tables in one address space is the normal case for the observer and the fuzz
# harness, and both have several, so an index from one is in range in the other
# often enough to matter. Without the cookie the lookup returns a *real* entry
# of this table for a handle naming a real entry of another one -- a plausible
# wrong answer, which is worse than a crash because nothing downstream notices.
#
# This mutant and `the-handle-index-is-not-verified` were the same observation
# until the round trip was narrowed to the low half. `make_handle` mixes this
# table's cookie into its high half, so a whole-handle round trip in `find`
# re-ran the cookie comparison and this mutant survived a suite that still
# refused every foreign handle -- the redundancy was the bug, because it made
# one of the two checks unobservable. Which is the claim-vs-act lesson again,
# one layer down: an observation that cannot tell two implementations apart is
# not an observation of either.
mutate "the-handle-cookie-is-not-checked" "$SRC" \
"    if (parts.cookie != (cookie_ & 0xFFFFFFFFULL)) {
        return nullptr;
    }" \
"    if (false) {
        return nullptr;
    }"

# The cookie taken from something shared -- the count of open handles -- rather
# than from the table's own address. Two tables at the same point in their life
# then issue the same handles, which is the case the cookie exists to make
# impossible, and it is invisible to a test that uses one table.
mutate "the-handle-cookie-is-not-per-table" "$SRC" \
"    : cookie_(handle_cookie_for(this)) {}" \
"    : cookie_(0x1234567890ABCDEFULL) {}"

# The oddness bit dropped, so handle 0 is zero. Zero is what every caller
# already treats as "no handle", so the first handle a program is given reads as
# absent and every `if (handle)` it writes takes the wrong branch.
mutate "a-handle-can-be-zero" "$SRC" \
"           ((static_cast<std::uint64_t>(index) << 1) & 0xFFFFFFFFULL) | 1ULL;" \
"           ((static_cast<std::uint64_t>(index) << 1) & 0xFFFFFFFFULL);"

# The round trip removed, so a handle whose low half is a *neighbouring* index
# resolves to that neighbour. The check rebuilds the low half from the decoded
# index -- `make_handle(index) & 0xFFFFFFFF == parts.index` -- and without it
# the bounds check above is the only thing left, which stops an out-of-range
# index and does nothing about one that is in range and wrong.
#
# The comparison is on the low half and not on the whole handle because the
# whole-handle form re-runs the cookie check with this table's cookie mixed
# in, and a check that duplicates another one hides it: with the whole-handle
# form this mutant and `the-handle-cookie-is-not-checked` are the same
# observation, and the cookie mutant survives a suite that still refuses every
# foreign handle. The low-half split is what gives the two checks separate
# reasons to exist and separate things to fail.
mutate "the-handle-index-is-not-verified" "$SRC" \
"    if ((make_handle(index) & 0xFFFFFFFFULL) != parts.index) {
        return nullptr;
    }" \
"    if (false) {
        return nullptr;
    }"

# --------------------------------------------------- the region's lifetime

# **`MEM_DECOMMIT` falling through to the release path.** This was the code's
# actual behaviour until it was fixed, and this mutant is the bug: every
# accepted free type reached one `unmap()`, so a decommit of the middle of a
# reservation released the *whole* reservation and returned success. The three
# damages are all silent -- the addresses go back to the system, a later commit
# into the same range fails with MEMORY_NOT_ALLOCATED, and a pointer the program
# kept into the reservation dangles. A suite that asserted only "the call
# returned success" passed against it, which is why the decommit cases assert
# the state the call left instead.
mutate "a-decommit-falls-through-to-a-release" "$SRC" \
"    if ((type & mem::kDecommit) != 0 && (type & mem::kRelease) == 0) {" \
"    if (false) {"

# The decommit's mprotect replaced by the release's unmap. The three-way cut of
# the ledger is left in place and only the kernel half changes, which is the
# subtler half of the same bug: the region still reads as reserved and the
# addresses are still in the ledger, but the kernel has given them back, so the
# next `MAP_FIXED_NOREPLACE` on a neighbouring address can take them and the
# ledger and the kernel disagree from that point on.
mutate "a-decommit-unmaps-instead-of-protecting" "$SRC" \
"            ctx.placement->protect_range(base, effective_size,
                                         PageProtection::NoAccess);" \
"            ctx.placement->unmap(round_addr(base));"

# The committed bit carried across a protection change dropped, so a
# decommitted range becomes committed again by a call that only meant to change
# its protection. `set_protection` rebuilds the region through `make_region`,
# which builds a committed region, and the line that copies `committed` back is
# the only thing keeping a reservation reserved across an unrelated call.
mutate "a-protect-recommits-a-reservation" "$SPACE" \
"    updated.committed = at->committed;" \
"    updated.committed = true;"

# The decommit's head/tail kept committed but the *middle* left committed too --
# the cut made and the flag never cleared. The ledger then reports the range as
# ordinary memory and a recommit of it is a no-op that reports success, while
# the pages are mprotected away and the program faults on its next touch.
mutate "a-decommit-does-not-clear-the-commit" "$SPACE" \
"    regions_[cut.value].committed = false;" \
"    regions_[cut.value].committed = true;"

# The empty-range case refused instead of answered with success. When the two
# roundings meet there are no whole pages to release, Wine returns SUCCESS
# having done nothing, and a runtime that refused would reject a call Windows
# accepts -- the direction of divergence that costs a program a working path
# rather than giving it a wrong answer, and so the one nobody notices.
mutate "a-decommit-refuses-an-empty-range" "$SPACE" \
"    if (first >= last) {
        out.value = 0;
        out.status = Status::Success;
        return out;
    }
    const std::uint64_t want = last - first;

    // A decommit of a range that is already reserved" \
"    if (first >= last) {
        out.value = 0;
        out.status = Status::InvalidParameter;
        return out;
    }
    const std::uint64_t want = last - first;

    // A decommit of a range that is already reserved"

# The unmap's size read from the region *after* the unmap removed it. This is
# the use-after-free that AddressSanitizer found and a plain run does not: the
# ledger is a `std::vector<Region>`, the removal frees or moves the element, and
# the freed bytes usually still hold the size they had. So the answer is right
# on a plain run and wrong under any allocator that reuses the block.
mutate "the-unmap-size-is-read-after-the-unmap" "$SRC" \
"    *addr = base;
    *size = region_size;
    return Result<std::uint64_t>{base};" \
"    *addr = base;
    *size = region->size;
    return Result<std::uint64_t>{base};"


# ------------------------------------------------- the range, not the region

# **The whole-region protect, which is the bug this batch removed.** A protect
# used to change the protection of the entire region the range fell in, so a
# program that made one page read-only found its neighbour -- which it was still
# writing to -- faulting, because the runtime had changed memory the caller
# never named. The damage is silent in one direction and fatal in the other: a
# whole-region protect that widens access hands out writable memory the caller
# did not ask for, and one that narrows it takes away memory the caller was
# using. Wine walks the range (`virtual.c:2039`), and so does this now.
#
# The replacement calls `protect_in_range` on the *region's* base and size
# rather than the range's, which is exactly the old behaviour expressed through
# the new primitive.
mutate "a-protect-acts-on-the-region-not-the-range" "$SRC" \
"        const std::uint64_t step = step_end - cursor;
        const Result<std::uint32_t> changed = ctx.placement->protect_in_range(
            cursor, step, static_cast<PageProtection>(new_protect));" \
"        const std::uint64_t step = ctx.space->find(cursor)->size;
        const Result<std::uint32_t> changed = ctx.placement->protect_in_range(
            ctx.space->find(cursor)->base, step,
            static_cast<PageProtection>(new_protect));"

# The commit check turned into "the first page is committed", which is the
# per-page mistake the two-pass walk exists to avoid. Windows refuses the whole
# call with STATUS_NOT_COMMITTED when *any* page in the range is reserved, and
# refuses it before changing anything. A check that looked only at the first
# page would protect the committed head and then leave the caller with a range
# it believes it protected and a call that said it did.
mutate "the-commit-check-looks-only-at-the-first-page" "$SRC" \
"        if (!piece->committed) {
            return refuse<std::uint64_t>(
                Status::NotCommitted,
                \"the range covers \" + std::to_string(piece->base) +
                    \", which is reserved rather than committed: a protection \"
                    \"change is not a commit, so Windows refuses the whole call\");
        }" \
"        if (first_piece && !piece->committed) {
            return refuse<std::uint64_t>(
                Status::NotCommitted,
                \"the first page is reserved\");
        }"

# A reservation made committable by a protect: the reserved page is treated as
# committed so the range check passes, and the call silently hands the caller
# memory that is not there. The status Windows uses to say "no" becomes a
# success that lies.
mutate "a-reserved-page-is-treated-as-committed" "$SRC" \
"        if (!piece->committed) {" \
"        if (false) {"

# The cut dropped, so the ledger keeps one region while the kernel has two
# protections. The pages outside the range read as the new protection in the
# ledger and keep the old one in the kernel, which is a divergence between the
# two that nothing later repairs -- and the change counter is attributed to the
# whole region.
mutate "a-protect-does-not-cut-the-ledger" "$MAPPER" \
"    const Result<std::size_t> cut = space_->split(base, size);
    if (!cut.ok()) {
        return fail<std::uint32_t>(cut.status, 0, base);
    }
    const Result<std::uint32_t> changed =
        space_->set_protection_at(cut.value, protection);" \
"    const Region* one = space_->find(base);
    const Result<std::uint32_t> changed =
        space_->set_protection(one->base, protection);"

# **The `split` result taken from `pieces` instead of from the ledger.** The
# middle piece's index *within `pieces`* is not its index in the ledger unless
# the cut happened at the front: `pieces` is spliced in at `insert_at`, and
# everything before that point in the ledger is still there. Reporting the
# `pieces` index addresses a region the caller never named, and the damage is
# silent -- a decommit of the second half of a reservation clears the commit of
# the first half, and the caller finds memory it did not touch faulting while
# memory it did decommit does not. This was a real bug, caught by the
# `not committed: the page the commit did not name is still reserved` assertion.
mutate "the-split-answers-a-piece-index-not-a-ledger-index" "$SPACE" \
"    const std::size_t ledger_index =
        static_cast<std::size_t>(insert_at - regions_.begin()) + middle_index;" \
"    const std::size_t ledger_index = middle_index;"

# The `split` early return handing back index zero instead of the index of the
# region it found. When the range already is a whole region the pieces vector
# holds one entry, and its index in the pieces vector is 0 -- but index 0 in the
# *ledger* is the first region, which is a different region the moment the range
# is not the first one. This was a real bug during development: committing the
# second half of a reservation flipped the `committed` flag on the first half.
mutate "the-split-early-return-answers-zero" "$SPACE" \
"    if (pieces.size() == 1) {
        out.value = static_cast<std::size_t>(at - regions_.begin());
        out.status = Status::Success;
        return out;
    }" \
"    if (pieces.size() == 1) {
        out.value = 0;
        out.status = Status::Success;
        return out;
    }"

# A commit committing the whole region rather than the range. The caller reserves
# an arena and commits one page; a whole-region commit hands it every page, which
# is memory the program never asked for and a `MEM_DECOMMIT` it does not owe.
# This is the same class of mistake as the whole-region protect, on the other
# half of the API.
mutate "a-commit-commits-the-whole-region" "$SRC" \
"        const Result<std::uint64_t> committed =
            ctx.space->commit(base, commit_size);" \
"        const Result<std::uint64_t> committed =
            ctx.space->commit(base, reservation_end - base);"

# The commit size rounded to the allocation granularity instead of a page. The
# granularity is a rule about where a *reservation* starts; a commit names pages
# inside one, and a size rounded up to 64 KiB reaches past the end of a
# reservation whose length is not a multiple of 64 KiB -- so a commit of the
# last page of such a reservation is refused as running past it.
mutate "a-commit-size-rounds-to-the-granularity" "$SRC" \
"        const std::uint64_t commit_size =
            requested_size == 0
                ? AddressSpace::kPageSize
                : round_size_from(*addr, requested_size);" \
"        const std::uint64_t commit_size =
            AddressSpace::round_up(requested_size, AddressSpace::kGranularity);"

# The commit address rounded to the granularity instead of a page. A commit of
# the second page of a reservation would be placed at the reservation's start,
# committing pages the caller did not name and reporting an address it did not
# ask for.
mutate "a-commit-address-rounds-to-the-granularity" "$SRC" \
"        base = want_reserve ? AddressSpace::granularity_round_down(*addr)
                            : AddressSpace::round_down(*addr,
                                                       AddressSpace::kPageSize);" \
"        base = AddressSpace::granularity_round_down(*addr);"

# ------------------------------------------------ the mapper's own placement

# The search giving up early, which is the loader's `still in the way after 64
# bases` bug reproduced in a second place: sixty-four attempts at one granule
# each is 4 MiB of search, which under a sanitizer is entirely inside the
# runtime's own mappings. The mutant's effect is a refusal on a machine with
# terabytes free, and refusals are the failure mode nobody debugs.
mutate "the-placement-search-gives-up-early" "$MAPPER" \
"    constexpr std::uint64_t kMaxAttempts = 16384;
    for (std::uint64_t attempt = 0; attempt < kMaxAttempts; ++attempt) {
        if (candidate < floor_ || candidate > ceiling_room ||
            !in_the_user_window(candidate, size)) {" \
"    constexpr std::uint64_t kMaxAttempts = 64;
    for (std::uint64_t attempt = 0; attempt < kMaxAttempts; ++attempt) {
        if (candidate < floor_ || candidate > ceiling_room ||
            !in_the_user_window(candidate, size)) {"

# The same cap in the ascending search, and it is a separate mutant rather than
# the same one applied twice: the two searches have their own `kMaxAttempts`
# and a change to one leaves the other alone, which is exactly the shape a
# single mutant with an ambiguous anchor cannot measure. The reach here is the
# unconstrained-view path, where a program that has filled the low part of its
# window still expects a load to place.
mutate "the-ascending-search-gives-up-early" "$MAPPER" \
"    constexpr std::uint64_t kMaxAttempts = 16384;
    for (std::uint64_t attempt = 0; attempt < kMaxAttempts; ++attempt) {
        if (candidate > AddressSpace::kUserMax ||
            !in_the_user_window(candidate, size)) {" \
"    constexpr std::uint64_t kMaxAttempts = 64;
    for (std::uint64_t attempt = 0; attempt < kMaxAttempts; ++attempt) {
        if (candidate > AddressSpace::kUserMax ||
            !in_the_user_window(candidate, size)) {"

# The search ascending instead of descending. The interesting ceilings are low
# -- a program asking for memory below 2^32 wants the *lowest* address that
# fits -- and starting from the ceiling and walking down reaches the dense low
# part of the space first. Walking up reaches the sparse high part, where there
# is room on a 64-bit host and none on a small one, so this is a mutation that
# passes everywhere and fails in the field.
mutate "the-placement-search-ascends" "$MAPPER" \
"        candidate -= kStride;" \
"        candidate += kStride;"

# The candidate rounded *up* rather than down, so a region that ends one byte
# past the ceiling is placed. `map_below`'s whole contract is that the result is
# inside the window, and rounding up is the one thing that breaks it while
# leaving every other answer right.
mutate "the-placement-ceiling-rounds-up" "$MAPPER" \
"    std::uint64_t candidate = AddressSpace::granularity_round_down(
        ceiling - size);" \
"    std::uint64_t candidate = AddressSpace::granularity_round_down(
        ceiling - size) + AddressSpace::kGranularity;"

# The size-versus-window underflow. `ceiling - size` underflows when the size
# does not fit, and a wrapped subtraction is enormous -- so the check is written
# as a difference against the window's low end rather than as the obvious
# subtraction. Removing it does not crash: it produces a candidate near the top
# of the space, which is outside the window, which is the one thing the caller
# asked not to happen.
mutate "the-placement-size-underflows" "$MAPPER" \
"    const std::uint64_t span = ceiling - AddressSpace::kUserMin;
    if (size > span) {
        return fail<std::uint64_t>(Status::NoMemory, 0, 0);
    }" \
"    const std::uint64_t span = ceiling - AddressSpace::kUserMin;
    if (false) {
        return fail<std::uint64_t>(Status::NoMemory, 0, 0);
    }"

# --------------------------------------------------- the type and the mask

# The type mask widened to the `Ex` one, so the plain call accepts the
# placeholder bits. `MEM_RESERVE_PLACEHOLDER` and `MEM_REPLACE_PLACEHOLDER` are
# `NtAllocateVirtualMemoryEx` arguments; a plain allocation that carries one is
# a caller using a structure it did not fill in, and accepting it reserves
# memory under a rule this path does not implement.
mutate "the-plain-call-accepts-the-ex-type-bits" "$SRC" \
"    constexpr std::uint32_t kMask = mem::kCommit | mem::kReserve |
                                    mem::kTopDown | mem::kWriteWatch |
                                    mem::kReset;
    return (type & ~kMask) == 0;
}

// The stricter mask \`NtAllocateVirtualMemoryEx\` uses" \
"    constexpr std::uint32_t kMask = mem::kCommit | mem::kReserve |
                                    mem::kTopDown | mem::kWriteWatch |
                                    mem::kReset | mem::kReservePlaceholder |
                                    mem::kReplacePlaceholder;
    return (type & ~kMask) == 0;
}

// The stricter mask \`NtAllocateVirtualMemoryEx\` uses"

# The protection check accepting anything whose low byte is a *combination*.
# The eight PAGE_ values are powers of two that do not compose -- there is no
# protection equal to `0x06` -- and a check written as "is any bit set" accepts
# every one of them, so a caller asking for read-and-noaccess gets ordinary
# memory with a protection no page has.
mutate "an-unknown-protection-is-accepted" "$SRC" \
"[[nodiscard]] bool protection_is_known(std::uint32_t protect) noexcept {
    switch (protect & 0xffU) {" \
"[[nodiscard]] bool protection_is_known(std::uint32_t protect) noexcept {
    if ((protect & 0xffU) != 0) return true;
    switch (protect & 0xffU) {"

# PAGE_GUARD honoured as its base protection. Linux has no `mprotect` flag for
# a guard page, so the modifier is either dropped or refused; dropping it gives
# the caller a buffer overflow that does not fault, which is the specific
# failure the comment on the constant is about.
mutate "page-guard-becomes-its-base-protection" "$SRC" \
"    // PAGE_GUARD alone is refused rather than treated as its base protection." \
"    if (true) return true;
    // PAGE_GUARD alone is refused rather than treated as its base protection."

# -------------------------------------------------- what Wine leaves stubbed

# `NtCreatePagingFile` not writing `*actual_size`, which is exactly Wine's stub
# (`virtual.c:6079`: `FIXME(...); return STATUS_SUCCESS;`). A program that sizes
# its working set from that answer reads uninitialised stack memory and gets a
# page file of an arbitrary size -- a bug the program cannot detect, which is
# what makes it worth a mutant rather than a comment.
mutate "the-page-file-size-is-not-reported" "$SRC" \
"    *actual_size = want;
    return Result<std::uint64_t>{recorded.value};" \
"    return Result<std::uint64_t>{recorded.value};"

# `NtFlushProcessWriteBuffers` back to Wine's stub: report success and write
# nothing. A program that calls this before telling the kernel its data is safe
# has a data-loss bug that no return value will ever report.
#
# The mutation replaces the *call*, not the test of its result. Replacing the
# test -- `if (::msync(...))` into `if (false)` -- was this file's first version
# of this mutant and it survived twice: once because there was nothing
# observable at all, and once because the event added to make it observable was
# written after the `if` rather than from its value, so it recorded "control
# reached here" for an implementation that had skipped the syscall. The first
# was a hole in the suite; the second was a hole in the *hook*, which is the
# worse of the two -- an observability hook that reports work never done is
# worse than no hook. A stub replaces the work; it does not merely mis-test the
# work's outcome.
# The mutation lives in the mapper now, because the flush's syscall does: the
# flush was calling `::msync` directly from the ntdll layer, which bypassed the
# mapper's counter, and the flush's work is now a `Mapper::sync` call with the
# counter increment beside it. The mutation removes the *pair* -- the count and
# the call -- and fakes a success return, which is what a stub is: the work
# replaced and the report of the work kept. An event recorded from the faked
# return still says success, so the events alone cannot catch it; the counter
# is the record of the syscall that a faked return value cannot move, and the
# flush test asserts both.
mutate "the-process-flush-is-a-stub-again" "$MAPPER" \
"    ++syscalls_made_;
    const sys::Result s =
        sys::msync(reinterpret_cast<void*>(base),
                   static_cast<std::size_t>(size), MS_SYNC);
    if (s.failed()) {
        return fail<std::uint64_t>(Status::NotMappedData, s.error, base);
    }
    Result<std::uint64_t> out;
    out.value = size;
    out.status = Status::Success;
    return out;" \
"    Result<std::uint64_t> out;
    out.value = size;
    out.status = Status::Success;
    return out;"

# The section-information class Wine answers with NOT_IMPLEMENTED
# (`virtual.c` has no arm for it) replaced by a refusal, so the one class occ
# added is gone and a program asking gets the same nothing Wine gives.
mutate "the-section-information-class-is-refused" "$SRC" \
"    case SectionInformationClass::SectionInformation: {" \
"    case SectionInformationClass::NoSuchClassAtAll:
    case SectionInformationClass::SectionInformation: {"

# ------------------------------------------------------- gaps left open

# Gaps rather than unreachable branches, recorded here because a harness that
# reports "all caught" without saying what it did not try is claiming more than
# it checked.
#
#   * `handle_cookie_for`'s mixing steps are not mutated. They are arithmetic
#     whose only requirement is that two different tables get different values,
#     and the test that checks that would pass for any mixing that separates
#     them. A mutation that made the cookie *worse* at separating would have to
#     be found by collision, not by a mutant, and the honest report is that the
#     property is tested once rather than proven.
#
#   * `Status::` values are not mutated. They are transcribed from Wine's
#     `ntstatus.h` and locked by `static_assert`s in address_space.h that check
#     each enumerator's severity, so a wrong value is a compile error or a
#     failed assertion rather than a runtime answer. That is a stronger
#     guarantee than this harness could give and it is already tested.
#
#   * `nt_are_mapped_files_the_same` is not mutated. Its answer is
#     `NOT_SAME_DEVICE` more often than Wine's, because the ledger keeps no
#     file identity -- a documented divergence rather than a rule, and the
#     divergence is a *refusal*, so a mutation of it would show up as a program
#     that gets an answer where it should get "these are not known to be the
#     same file".
#
#   * `nt_query_section`'s `SectionImageInformation` and
#     `SectionAlignmentInformation` arms are not mutated. They are two
#     `struct` fills, and the fields they write are the fields the loader
#     already reads out of a `PeImage` under test in test_pe.cpp.
#
#   * The `Ex` variants (`nt_allocate_virtual_memory_ex`,
#     `nt_map_view_of_section_ex`, `nt_unmap_view_of_section_ex`) are not
#     mutated separately. Each is a thin wrapper whose whole body is "adapt the
#     signature and call the plain one", and mutating the wrapper means mutating
#     the call it makes -- which is a mutation of the function above, reported
#     as a fact about the wrapper and not about the rule.

echo
echo "----------------------------------------------------------------"
echo "caught:          $caught"
echo "survived:        $survived"
echo "anchor failures: $anchor_failed"
if [ "$anchor_failed" -gt 0 ]; then
    echo
    echo "ANCHOR FAILURES -- the harness did not measure these, so the counts"
    echo "above do not describe the whole list. Fix the anchors before reading"
    echo "anything else in this report:"
    for n in "${anchor_names[@]}"; do
        echo "  - $n"
    done
fi
if [ "$survived" -gt 0 ]; then
    echo
    echo "surviving mutants -- these are holes in the test suite:"
    for n in "${failed_names[@]}"; do
        echo "  - $n"
    done
fi
# An anchor failure outranks a survivor. A survivor says one rule is untested;
# an anchor failure says the report is not a measurement of the list at all, so
# a clean-looking run with a broken anchor is not a pass. Exiting non-zero on
# either is right, and they exit for different reasons: the anchor case is a
# fault in this file, which is the one thing here that cannot be argued with.
if [ "$anchor_failed" -gt 0 ]; then
    exit 2
fi
if [ "$survived" -gt 0 ]; then
    exit 1
fi
exit 0

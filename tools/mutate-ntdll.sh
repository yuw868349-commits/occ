#!/usr/bin/env bash
# Mutation harness for the ntdll memory layer: the parameter rules, the
# rounding, the handle table, the range checks.
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
SRC=/workspace/Occ/src/runtime/ntdll.cpp
HDR=/workspace/Occ/include/occ/runtime/ntdll.h
MAPPER=/workspace/Occ/src/runtime/mapper.cpp

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

caught=0
survived=0
anchor_failed=0
failed_names=()
anchor_names=()

restore() {
    cp "$WORK/ntdll.pristine" "$SRC"
    cp "$WORK/ntdll.h.pristine" "$HDR"
    cp "$WORK/mapper.pristine" "$MAPPER"
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
    if ! "$TEST" >"$WORK/run.log" 2>&1; then
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
    if "$TEST_SAN" >"$WORK/run-san.log" 2>&1; then
        echo "  [$name] SURVIVED"
        survived=$((survived + 1))
        failed_names+=("$name")
        echo "      (passed under the sanitizer too -- a real gap, not a stale binary)"
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

# The limit's shift losing the 32. `get_zero_bits_limit` computes
# `32 + zero_bits` below 32 and `0` means "no window at all"; dropping the 32
# gives a limit billions of bytes too low, so every `zero_bits` placement
# refuses an allocation Windows places without trouble. A mutation whose whole
# effect is a *refusal* of something legal, which is the quietest failure mode
# there is.
mutate "the-zero-bits-limit-loses-its-32" "$HDR" \
"    if (zero_bits < 32) {
        shift = 32 + zero_bits;
    } else {" \
"    if (zero_bits < 32) {
        shift = zero_bits;
    } else {"

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
# in-page offset to the size *before* rounding, and that is what makes a size of
# zero at a page-aligned address cover one page rather than none. Without the
# offset every partial-page range protects or frees one page less than Windows
# does -- in a call that succeeds either way, which is the worst kind of
# divergence: the program carries on and the bug surfaces later as a page that
# was not protected.
mutate "round-size-drops-the-in-page-offset" "$SRC" \
"    return (size + (addr & (AddressSpace::kPageSize - 1)) +
            AddressSpace::kPageSize) &
           ~(AddressSpace::kPageSize - 1);" \
"    return (size + AddressSpace::kPageSize) & ~(AddressSpace::kPageSize - 1);"

# The `+ page_mask` dropped, which is the other half of the same macro. This one
# is the off-by-one every reader's eye offers to fix: without it a page-aligned
# request of exactly one page comes back as zero, and a protect call that
# reports zero changed nothing while having changed a page.
mutate "round-size-loses-its-extra-page" "$SRC" \
"    return (size + (addr & (AddressSpace::kPageSize - 1)) +
            AddressSpace::kPageSize) &
           ~(AddressSpace::kPageSize - 1);" \
"    return (size + (addr & (AddressSpace::kPageSize - 1))) &
           ~(AddressSpace::kPageSize - 1);"

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

# ------------------------------------------------ the mapper's own placement

# The search giving up early, which is the loader's `still in the way after 64
# bases` bug reproduced in a second place: sixty-four attempts at one granule
# each is 4 MiB of search, which under a sanitizer is entirely inside the
# runtime's own mappings. The mutant's effect is a refusal on a machine with
# terabytes free, and refusals are the failure mode nobody debugs.
mutate "the-placement-search-gives-up-early" "$MAPPER" \
"    constexpr std::uint64_t kMaxAttempts = 16384;" \
"    constexpr std::uint64_t kMaxAttempts = 64;"

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

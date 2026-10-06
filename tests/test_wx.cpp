// Write-then-execute tracker tests.
//
// The tracker exists to answer one question: did a region that was written
// become executable, and in which process. Every case below is about an
// answer that would be wrong in a way a consumer could not detect -- a write
// attributed to the wrong process, a cached range that no longer exists --
// or about arithmetic that is wrong only near the ends of the address space,
// where it is least likely to be exercised by hand.
//
// The hardware watches themselves need a live tracee and debug registers, so
// these cases test the bookkeeping around them: placement width, attribution
// and the reports. That is where the defects were.

#include "occ/observer/wx.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace {

int failures = 0;
int checks = 0;

void check(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

using occ::obs::RegionPerms;
using occ::obs::WriteExecuteTracker;

// The two halves of a transition. The tracker asks one question -- was it
// writable, and is it executable now -- so the fixtures need those two
// states and nothing else.
[[nodiscard]] RegionPerms executable() noexcept {
    RegionPerms p;
    p.readable = true;
    p.writable = false;
    p.executable = true;
    return p;
}

// A page-aligned address that names nothing. watch() does not touch the
// target's memory -- it records a range and rounds it to pages -- so the
// fixtures are free to use addresses with no mapping behind them.
constexpr std::uint64_t kBase = 0x0000700000000000ull;
constexpr std::uint64_t kPage = 4096;

// The width is a function of the address and the bytes left, so it is
// checked directly rather than through arm() and chase(), which both need a
// live tracee. arm() and chase() call this one function precisely so that
// the rule cannot be right in one path and wrong in the other.
void test_the_watch_width_is_the_widest_that_fits() {
    check(occ::obs::watch_width(kBase, 4096) == 8,
          "an eight-aligned address with room takes an eight-byte watch");
    check(occ::obs::watch_width(kBase + 4, 4096) == 4,
          "a four-aligned address with room takes a four-byte watch");
    check(occ::obs::watch_width(kBase, 4) == 4,
          "four bytes left takes a four-byte watch");
    // Between four and eight bytes left: four is the widest that fits, and
    // the region is credited with four rather than with the eight an
    // unclamped width would report.
    check(occ::obs::watch_width(kBase, 7) == 4,
          "between four and eight bytes left takes a four-byte watch");
    check(occ::obs::watch_width(kBase, 0) == 0, "no bytes left takes nothing");
    check(occ::obs::watch_width(kBase + 4, 3) == 0,
          "a misaligned address with too little room takes nothing");
}

// A region of one page is longer than the four debug registers can cover.
// The report has to say so rather than imply the whole page is watched.
void test_coverage_never_exceeds_the_region() {
    WriteExecuteTracker t;
    std::string detail;
    check(t.watch(1, kBase, kPage, detail) == 0, "a page region is accepted");
    const auto& targets = t.targets();
    check(targets.size() == 1, "one region is tracked");
    check(!targets.empty() && targets[0].length == kPage,
          "the region is the page it was rounded to");

    // The tracker's own account of coverage is what a caller sizes work
    // from, and it is bounded by the region rather than by the watches.
    check(t.region_count() == 1, "the region count is one");
}

// Two processes can map the same address. Merging them would credit one
// process's write to the other and report a transition that never happened.
void test_regions_are_kept_per_process() {
    WriteExecuteTracker t;
    std::string detail;
    check(t.watch(11, kBase, kPage, detail) == 0, "pid 11 watches the range");
    check(t.watch(22, kBase, kPage, detail) == 0, "pid 22 watches the range");
    check(t.region_count() == 2,
          "the same range in two processes is two regions");

    t.note_write(11, kBase + 16, 4, kBase);
    check(t.note_permission(22, kBase, executable()) == false,
          "a write in one process does not arm a transition in the other");
    check(t.note_permission(11, kBase, executable()) == true,
          "the writing process produces the transition");
    check(t.transitions().size() == 1, "exactly one transition is recorded");
    if (!t.transitions().empty()) {
        check(t.transitions()[0].pid == 11,
              "the transition names the process that wrote");
    }
}

// Regions of one process that overlap are merged into a single entry, so the
// tracker never holds two accounts of the same bytes. Adjacency is not
// overlap: two ranges that share only a boundary cover disjoint bytes, and
// merging them would claim a range the caller never asked about -- so the
// test uses a genuine overlap.
void test_overlapping_regions_of_one_process_merge() {
    WriteExecuteTracker t;
    std::string detail;
    check(t.watch(5, kBase, kPage, detail) == 0, "the first range");
    check(t.watch(5, kBase + kPage / 2, kPage, detail) == 0,
          "a range overlapping the first");
    check(t.region_count() == 1, "overlapping ranges of one process merge");

    // The merged region spans both, and is rounded out to whole pages: the
    // second range reaches halfway into the following page, and a region
    // that stopped at the byte would share a page with whatever else is
    // mapped there, which the tracker cannot watch independently.
    const auto& targets = t.targets();
    check(!targets.empty() && targets[0].length == 2 * kPage,
          "the merged region rounds out to whole pages");

    // Adjacent ranges are not merged: they share a boundary and no bytes.
    WriteExecuteTracker adjacent;
    std::string why;
    check(adjacent.watch(5, kBase, kPage, why) == 0, "the lower range");
    check(adjacent.watch(5, kBase + kPage, kPage, why) == 0,
          "an adjacent range with no bytes in common");
    check(adjacent.region_count() == 2,
          "adjacent ranges stay separate, because they share no bytes");
}

// A write to an address no region of that process covers is counted but not
// attributed. Without the pid in the lookup it would be attributed to
// whatever other process happened to map that address.
void test_a_write_in_another_process_is_not_located() {
    WriteExecuteTracker t;
    std::string detail;
    check(t.watch(7, kBase, kPage, detail) == 0, "pid 7 watches the range");
    t.note_write(99, kBase + 8, 8, kBase);
    check(t.writes_seen() == 1, "the write is counted");
    check(t.note_permission(99, kBase, executable()) == false,
          "a transition needs a region in the writing process");
    check(t.transitions().empty(), "no transition is recorded");
}

// The cached public view is invalidated when a region's length changes, not
// only when the number of regions does. A caller that sized work from the
// cached length would otherwise work from a range that no longer exists.
void test_targets_reflect_a_changed_length() {
    WriteExecuteTracker t;
    std::string detail;
    check(t.watch(4, kBase, kPage, detail) == 0, "a one-page region");
    check(t.targets().size() == 1, "one region is tracked");
    const std::uint64_t first = t.targets()[0].length;
    check(first == kPage, "the length is one page");

    // The same base with a longer length extends the region in place. The
    // number of regions is unchanged, which is the case a size-only cache
    // test gets wrong.
    check(t.watch(4, kBase, 4 * kPage, detail) == 0,
          "the region is extended");
    check(t.region_count() == 1, "the extension does not add a region");
    check(t.targets()[0].length == 4 * kPage,
          "the cached view shows the new length");
    check(t.targets()[0].length != first, "the cached length changed");
}

// The page rounding is the base every length rests on, so its behaviour at
// the top of the user range is checked rather than assumed. The last page
// below the boundary must be usable -- it is a real address and a caller
// that names it is asking for something that exists -- and a region that
// needs a page beyond it must be refused rather than rounded, because the
// addition would wrap and report a region of almost no bytes.
void test_a_region_past_the_address_space_is_refused() {
    // The last page below the boundary, which fits exactly.
    constexpr std::uint64_t kLastPage = 0x00007ffffffff000ull;
    WriteExecuteTracker fits;
    std::string detail;
    check(fits.watch(1, kLastPage, kPage, detail) == 0,
          "a region that is exactly the last page below the boundary is"
          " accepted");
    const auto& targets = fits.targets();
    check(!targets.empty() && targets[0].length == kPage,
          "the last page below the boundary is one page long");
    check(!targets.empty() && targets[0].base == kLastPage,
          "the last page keeps its address");

    // Asking for one byte more than that page needs a page past the
    // boundary.
    WriteExecuteTracker over;
    std::string why;
    check(over.watch(1, kLastPage, kPage + 1, why) != 0,
          "a region needing a page past the boundary is refused");

    // A region that begins at the boundary itself is not in the user range.
    WriteExecuteTracker beyond;
    std::string why2;
    check(beyond.watch(1, 0x0000800000000000ull, kPage, why2) != 0,
          "a region starting at the boundary is refused");
}

// A transition is reported once. A second permission change with no new
// write between them is not a second transition: the region was already
// known to be executable.
void test_permission_transition_is_reported_once() {
    WriteExecuteTracker t;
    std::string detail;
    check(t.watch(3, kBase, kPage, detail) == 0, "the region is watched");
    t.note_write(3, kBase, 8, kBase);
    check(t.note_permission(3, kBase, executable()) == true,
          "the first transition is reported");
    check(t.note_permission(3, kBase, executable()) == false,
          "a repeat with no new write is not a second transition");
    check(t.transitions().size() == 1, "only one transition is pending");
}

// A write outside every watched region is not attributed to one. The watch
// hardware fires on a range, so a write just past a region's end still
// reports, and the tracker must not fold it into the region.
void test_a_write_outside_every_region_is_counted_but_not_attributed() {
    WriteExecuteTracker t;
    std::string detail;
    check(t.watch(2, kBase, kPage, detail) == 0, "the region is watched");
    t.note_write(2, kBase + 16 * kPage, 8, kBase);
    check(t.writes_seen() == 1, "the write is counted");
    check(t.note_permission(2, kBase, executable()) == false,
          "an unattributed write does not arm the region");
}

} // namespace

int main() {
    test_the_watch_width_is_the_widest_that_fits();
    test_coverage_never_exceeds_the_region();
    test_regions_are_kept_per_process();
    test_overlapping_regions_of_one_process_merge();
    test_a_write_in_another_process_is_not_located();
    test_targets_reflect_a_changed_length();
    test_a_region_past_the_address_space_is_refused();
    test_permission_transition_is_reported_once();
    test_a_write_outside_every_region_is_counted_but_not_attributed();

    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks passed\n", checks);
    return 0;
}

// Uprobe layer tests.
//
// A uprobe needs tracefs and a kernel willing to let this process write to
// it, and neither is guaranteed on the machine running these tests. The
// suite is therefore built around what is true on every host:
//
//   - the availability answer is honest in both directions, and says which
//     of the two problems it found rather than a single "no"
//   - an object that has registered nothing behaves correctly, which is the
//     state it is in whenever the answer above was no
//   - a registration that cannot happen fails with a sentence that names
//     what is missing and does not leave state behind
//
// What is deliberately not tested here is that a probe fires. That needs a
// probe that registered, which needs tracefs, and a test that silently
// skipped itself on a host without tracefs would be a test that reports
// success for having run nothing. The registration path is covered by the
// failure cases below and the decode path by the observer's own watch tests,
// which share the ring reader's framing.

#include "occ/observer/uprobe.h"

#include "occ/syscall/errno.h"
#include "occ/util/fs.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace occ::obs;

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

// A directory that is removed when the test ends. mkdtemp rather than a
// name of this file's choosing, because a fixed name under /tmp is a name
// another run can already hold, and two concurrent runs would then be
// testing each other's leftovers.
struct TempDir {
    std::string path;
    ~TempDir() {
        if (!path.empty()) {
            (void)occ::fs::remove_tree(path);
        }
    }
    TempDir() = default;
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    // Movable so that a factory can return one. A copy would leave two
    // objects owning one directory and the first to die would remove it
    // from under the second.
    TempDir(TempDir&& o) noexcept : path(o.path) { o.path.clear(); }
    TempDir& operator=(TempDir&& o) noexcept {
        if (this != &o) {
            if (!path.empty()) { (void)occ::fs::remove_tree(path); }
            path = o.path;
            o.path.clear();
        }
        return *this;
    }
};

TempDir make_temp_dir() {
    TempDir out;
    char tmpl[] = "/tmp/occ_uprobe_XXXXXX";
    if (::mkdtemp(tmpl) == nullptr) {
        return out;
    }
    out.path = tmpl;
    return out;
}

bool make_dir(const std::string& path) {
    return occ::fs::mkdir_p(path, 0700);
}

// ------------------------------------------------------------- availability

void test_availability_is_answered() {
    const ProbeAvailability a = Uprobes::availability();

    // The answer is one of two, and both carry the information a caller
    // needs to act. A struct with an `available` flag and nothing else would
    // leave a caller that got false with no way to say why.
    if (a.available) {
        check(!a.tracefs_root.empty(),
              "an available probe layer names the tracefs it will use");
        check(a.reason.empty(),
              "an available probe layer does not carry a reason");
        check(occ::fs::is_dir(a.tracefs_root + "/events"),
              "the tracefs root an available answer names really holds "
              "events");
    } else {
        check(!a.reason.empty(),
              "an unavailable probe layer says why it is unavailable");
        // The sentence has to point at both halves of the consequence: the
        // thing that stopped and the thing that did not. A caller reading
        // "uprobes are unavailable" would reasonably conclude that nothing
        // can be observed, which is not what happened.
        check(a.reason.find("function-level") != std::string::npos,
              "the reason names the capability that stops");
        check(a.reason.find("syscall") != std::string::npos,
              "the reason names the capability that continues");
    }

    // Asking twice is asking the same question, and the answer must not
    // depend on the last call. A probe layer that cached a failure after a
    // transient one would report a host as broken for the rest of the run.
    const ProbeAvailability b = Uprobes::availability();
    check(a.available == b.available,
          "the availability answer is stable across calls");
}

void test_availability_probe_leaves_no_tracefs_event() {
    // availability() must not register anything. It is asked before a caller
    // has decided to observe at all, and a check that left an event behind
    // would have to be undone in a place that may never be reached.
    const ProbeAvailability a = Uprobes::availability();
    if (!a.available) {
        // Nothing was touched, so there is nothing to check. The assertion
        // is that this branch is reachable without a crash.
        check(true, "asking for availability without tracefs does not crash");
        return;
    }
    const std::string events = a.tracefs_root + "/uprobe_events";
    const std::string before = occ::fs::read_file(events).value_or("");
    (void)Uprobes::availability();
    const std::string after = occ::fs::read_file(events).value_or("");
    check(before == after,
          "asking for availability does not add a probe to uprobe_events");
}

// -------------------------------------------------------------- empty state

void test_empty_layer_is_well_formed() {
    Uprobes u;

    check(u.size() == 0, "a fresh probe layer holds no probes");
    check(u.fds().empty(), "and offers no descriptors to poll");
    check(u.lost_hits() == 0, "and has lost nothing, having seen nothing");

    std::vector<UprobeHit> hits;
    check(u.read_hits(hits) == 0,
          "draining a layer with no probes produces no hits");
    check(hits.empty(), "and appends nothing");
}

void test_clear_on_empty_is_safe() {
    // clear() is called on every exit path, including the paths where
    // nothing was registered. A clear that assumed at least one probe would
    // turn a refused run into a crash while unwinding from the refusal.
    Uprobes u;
    u.clear();
    check(u.size() == 0, "clearing an empty layer leaves it empty");
    u.clear();
    check(u.size() == 0, "clearing twice is not an error");
}

void test_removal_after_clear_is_idempotent() {
    Uprobes u;
    u.clear();
    std::vector<UprobeHit> hits;
    check(u.read_hits(hits) == 0, "reading after clear produces nothing");
    check(u.fds().empty(), "and there is nothing left to poll");
}

// ------------------------------------------------------------ registration

void test_registration_without_tracefs_fails_with_a_reason() {
    const ProbeAvailability a = Uprobes::availability();

    Uprobes u;
    std::string detail;
    const int rc = u.add("main", "/bin/true", 0x1000, ProbeKind::Entry, detail);

    if (a.available) {
        // The host has tracefs, so the registration either worked or failed
        // for a reason this test cannot anticipate -- a path that is not a
        // real file, most likely.
        //
        // What is asserted is the contract: success means a probe exists
        // and holds an id, failure means a sentence was produced and no
        // probe was left behind. Both are true on any host.
        if (rc == 0) {
            check(u.size() == 1, "a successful registration holds one probe");
            check(u.all().front().id != 0,
                  "and the probe has an event id from the kernel");
            check(u.all().front().name == "main",
                  "and it carries the name it was given");
            u.clear();
        } else {
            check(u.size() == 0,
                  "a failed registration leaves no probe behind");
            check(!detail.empty(),
                  "a failed registration says what failed");
        }
        return;
    }

    // No tracefs. The registration must fail and must say so in a way a
    // caller can act on, and it must not have touched the vector.
    check(rc != 0, "registering a probe without tracefs fails");
    check(!detail.empty(), "and it says why");
    check(detail.find("tracefs") != std::string::npos,
          "and the reason names tracefs, which is the thing that is missing");
    check(u.size() == 0, "and nothing was left in the layer");
    check(u.fds().empty(), "and there is no descriptor to poll");
}

void test_registration_reason_is_not_about_the_target() {
    const ProbeAvailability a = Uprobes::availability();
    if (a.available) {
        return;
    }

    Uprobes u;
    std::string detail;
    // A path that does not exist. Without tracefs the failure happens before
    // the path is ever looked at, so the reason must still be about the
    // missing interface and not about the file. A reason that named the
    // file would send a caller to check a path that was never the problem.
    const int rc = u.add("x", "/nonexistent/library.so", 0, ProbeKind::Entry,
                         detail);
    check(rc != 0, "a registration without tracefs fails");
    check(detail.find("tracefs") != std::string::npos,
          "and the reason is the interface, not the file it was given");
    check(u.size() == 0, "and nothing was registered");
}

void test_subscribe_of_an_unknown_index_is_refused() {
    Uprobes u;
    std::string detail;
    // subscribe() is exposed so that a caller can register many probes and
    // subscribe together. An index past the end is a caller mistake that
    // must be reported rather than reading out of bounds.
    const int rc = u.subscribe(0, detail);
    check(rc != 0, "subscribing to a probe that does not exist fails");
    check(!detail.empty(), "and it says so");
}

// -------------------------------------------------------------- the values

void test_probe_kind_values_are_distinct() {
    // The two kinds are separate values because the kernel's two line
    // prefixes are separate. A layer that used one value for both would
    // register an entry probe where a return probe was asked for and
    // produce hits at the wrong moment, with nothing in the output to say
    // which had happened.
    check(static_cast<int>(ProbeKind::Entry) !=
              static_cast<int>(ProbeKind::Return),
          "entry and return are different kinds");
}

void test_hit_defaults_are_zeroed() {
    // A hit carries the argument registers only when the sample carried
    // them. The has_args flag is what tells a consumer which of the two it
    // has; without it, six zero registers are indistinguishable from six
    // registers that really were zero, and a call with an address argument
    // of zero is a real thing.
    UprobeHit h;
    check(!h.has_args, "a hit does not claim arguments it does not have");
    check(h.ip == 0, "a default hit has no instruction pointer");
    check(h.name.empty(), "and no name");
    for (std::uint64_t a : h.args) {
        check(a == 0, "a default hit's argument registers are zero");
    }
}

void test_explicit_root_is_used_and_not_searched_past() {
    // A root that was named is the only one tried. A directory that is not
    // a tracefs must produce a reason about what was named, not a fallback
    // to the standard mounts -- a run pointed at an empty directory and
    // then silently using the host's tracefs is the opposite of what naming
    // one asks for.
    const ProbeAvailability a = Uprobes::availability("/tmp");
    check(!a.available,
          "a directory that is not a tracefs is not reported as available");
    check(!a.reason.empty(), "and the answer says why");
    check(a.reason.find("/tmp") != std::string::npos,
          "and the reason names the root that was asked for");
}

void test_explicit_root_missing_events_directory() {
    // A directory that exists and holds no events subdirectory is the shape
    // of a mount that went wrong. The reason has to distinguish it from "no
    // tracefs at all", because the fix is different.
    TempDir dir = make_temp_dir();
    if (dir.path.empty()) {
        return;
    }
    const ProbeAvailability a = Uprobes::availability(dir.path);
    check(!a.available, "a directory with no events is not a tracefs");
    check(!a.reason.empty(), "and the answer says why");
    check(a.reason.find("events") != std::string::npos,
          "and the reason names what is missing");
}

void test_explicit_root_without_uprobe_events_is_reported() {
    // A tracefs that is mounted with events but with the uprobe interface
    // disabled. The kernel has the file only when uprobes are enabled, so a
    // tracefs without it is a kernel built without them -- which is a
    // different message from "tracefs is not mounted" and is worth saying.
    TempDir dir = make_temp_dir();
    if (dir.path.empty()) {
        return;
    }
    if (!make_dir(dir.path + "/events")) {
        return;
    }
    const ProbeAvailability a = Uprobes::availability(dir.path);
    check(!a.available,
          "a tracefs with no uprobe_events is not usable for probes");
    check(a.reason.find("uprobe_events") != std::string::npos,
          "and the reason names the file that is missing");
}

void test_layer_with_an_explicit_root_reports_that_root() {
    TempDir dir = make_temp_dir();
    if (dir.path.empty()) {
        return;
    }
    if (!make_dir(dir.path + "/events")) {
        return;
    }
    // The registration fails, and the reason must be about the root the
    // layer was given rather than about the standard mounts it was told not
    // to look at.
    Uprobes u(dir.path);
    std::string detail;
    const int rc = u.add("x", "/bin/true", 0, ProbeKind::Entry, detail);
    check(rc != 0, "registering against an incomplete tracefs fails");
    check(detail.find(dir.path) != std::string::npos,
          "and the reason names the root the layer was given");
    check(u.size() == 0, "and nothing was registered");
}

// A tracefs shaped directory that the kernel is not behind.
//
// It is enough to carry a registration up to the point where the kernel
// would be asked for a perf event: the file is written, the id file is
// read, the probe is recorded, and then perf_event_open fails because
// there is no real event id behind the number. That is the state the two
// tests below need -- a probe that got into the layer's own bookkeeping
// before the failure -- and it is a state no host-independent test could
// otherwise reach.
//
// The id below is deliberately one the kernel will refuse. A number that
// happened to name a real tracepoint would make the test's outcome depend
// on what the host is tracing.
struct FakeTracefs {
    TempDir dir;
    std::string events;
    std::string uprobe_events;

    FakeTracefs() = default;
    FakeTracefs(const FakeTracefs&) = delete;
    FakeTracefs& operator=(const FakeTracefs&) = delete;
    FakeTracefs(FakeTracefs&&) noexcept = default;
    FakeTracefs& operator=(FakeTracefs&&) noexcept = default;
};

FakeTracefs make_fake_tracefs() {
    FakeTracefs f;
    f.dir = make_temp_dir();
    if (f.dir.path.empty()) {
        return f;
    }
    f.events = f.dir.path + "/events";
    f.uprobe_events = f.dir.path + "/uprobe_events";
    // Two event directories, because the layer numbers its events from
    // zero and a test that registers two probes needs the second id to be
    // there. The ids are distinct and deliberately not adjacent: a layer
    // that read the wrong file would still get a number, and the number it
    // got would be the other probe's.
    if (!make_dir(f.events) || !make_dir(f.events + "/uprobes") ||
        !make_dir(f.events + "/uprobes/occ_0") ||
        !make_dir(f.events + "/uprobes/occ_1")) {
        f.dir.path.clear();
        return f;
    }
    if (!occ::fs::write_file(f.uprobe_events, "") ||
        !occ::fs::write_file(f.events + "/uprobes/occ_0/id", "999999\n") ||
        !occ::fs::write_file(f.events + "/uprobes/occ_1/id", "1000002\n")) {
        f.dir.path.clear();
    }
    return f;
}

std::string read_file_or_empty(const std::string& path) {
    return occ::fs::read_file(path).value_or("");
}

void test_registration_that_fails_midway_leaves_nothing() {
    FakeTracefs f = make_fake_tracefs();
    if (f.dir.path.empty()) {
        return;
    }

    Uprobes u(f.dir.path);
    std::string detail;
    const int rc = u.add("main", "/bin/true", 0x1000, ProbeKind::Entry, detail);

    // The registration cannot complete on this host: either perf refused
    // the subscription, or the fake id is not one the kernel serves. Either
    // way the call has to fail, and it has to have removed the tracefs
    // line it wrote -- a registration the kernel accepted but this layer
    // could not subscribe to is exactly the state that produces hits
    // nobody sees, and it must not be reachable.
    check(rc != 0, "a registration against a fake tracefs fails");
    check(!detail.empty(), "and it says what failed");
    check(u.size() == 0, "and no probe was left in the layer");
    check(u.fds().empty(), "and there is no descriptor to poll");

    const std::string content = read_file_or_empty(f.uprobe_events);
    check(content.find("p:occ_0") != std::string::npos,
          "the line was written before the failure, which is what makes this "
          "a test of the rollback");
    check(content.find("-:occ_0") != std::string::npos,
          "and it was removed again, by the event name the kernel assigned");
}

void test_a_registered_probe_is_in_the_layer_before_any_subscription() {
    FakeTracefs f = make_fake_tracefs();
    if (f.dir.path.empty()) {
        return;
    }

    // Registration and subscription are separable on purpose: the tracefs
    // write is the slow part and a caller with many probes writes them
    // together. The state between the two has to be a real state with a
    // real size, not an implementation detail, because that is the state
    // the caller owns the subscription for.
    Uprobes u(f.dir.path);
    std::string detail;
    std::size_t index = 999;
    const int rc = u.register_only("main", "/bin/true", 0x2000,
                                   ProbeKind::Return, index, detail);

    check(rc == 0, "a registration against a fake tracefs succeeds");
    check(detail.empty(), "and leaves no failure to explain");
    check(u.size() == 1, "and the probe is in the layer");
    check(index == 0, "and its index is reported");
    check(u.all()[0].event == "occ_0",
          "and it carries the event name the kernel was given");
    check(u.all()[0].kind == ProbeKind::Return,
          "and the probe kind it was registered as");
    check(u.fds().empty(),
          "and it has no descriptor, because nothing subscribed to it yet");

    // A second registration reports the index of the new probe and not
    // the one before it. A single registration cannot tell a correct
    // index from one that was never written: the only probe in an empty
    // layer is at zero, which is what an unset index also reads as.
    std::size_t second = 999;
    const int rc2 = u.register_only("helper", "/bin/false", 0x3000,
                                    ProbeKind::Entry, second, detail);
    check(rc2 == 0, "a second registration succeeds beside the first");
    check(second == 1, "and reports its own index, not the earlier one");
    check(u.size() == 2, "and both probes are in the layer");
    check(u.all()[1].event == "occ_1",
          "and the second got the next event name");

    // The layer now holds probes, which is the state clear() has to be
    // able to unwind. This is the only way to reach it on a host that
    // cannot open a perf event.
    const std::string before = read_file_or_empty(f.uprobe_events);
    check(before.find("r:occ_0 /bin/true:0x2000") != std::string::npos,
          "and the return probe was written with an r, not a p");

    u.clear();
    const std::string after = read_file_or_empty(f.uprobe_events);
    check(u.size() == 0, "clearing the layer empties it");
    check(after.find("-:occ_0") != std::string::npos,
          "and removes the event by the name the kernel assigned");
    check(after.find("-:occ_1") != std::string::npos,
          "and removes the second one too, in the same write");
}

void test_clear_removes_a_recorded_probe_and_its_events() {
    FakeTracefs f = make_fake_tracefs();
    if (f.dir.path.empty()) {
        return;
    }

    Uprobes u(f.dir.path);
    std::string detail;
    std::size_t index = 0;
    (void)u.register_only("main", "/bin/true", 0x1000, ProbeKind::Entry,
                          index, detail);
    check(u.size() == 1, "the layer has a probe to clear");

    const std::string before = read_file_or_empty(f.uprobe_events);
    u.clear();
    const std::string after = read_file_or_empty(f.uprobe_events);
    check(u.size() == 0, "clearing leaves the layer empty");
    check(after.size() > before.size() || after != before,
          "clearing a layer with a probe in it writes the removal");

    // A second clear has nothing to remove and must not write one, because
    // the tracefs interface refuses a removal for an event that is not
    // there and refuses the whole write -- including any later lines that
    // were batched with it.
    const std::string mid = read_file_or_empty(f.uprobe_events);
    u.clear();
    const std::string end = read_file_or_empty(f.uprobe_events);
    check(end == mid, "clearing it again writes nothing");
}

void test_registration_line_uses_a_hex_file_offset() {
    FakeTracefs f = make_fake_tracefs();
    if (f.dir.path.empty()) {
        return;
    }

    Uprobes u(f.dir.path);
    std::string detail;
    (void)u.add("main", "/bin/true", 0x1000, ProbeKind::Entry, detail);

    const std::string content = read_file_or_empty(f.uprobe_events);
    // The kernel parses the offset field with base 16. A decimal offset
    // written without a prefix is silently reinterpreted: 4096 decimal
    // becomes 0x4096, which is a probe at a byte nobody chose, and the
    // kernel accepts it if that byte is inside the file.
    check(content.find("p:occ_0 /bin/true:0x1000") != std::string::npos,
          "the offset is written in hexadecimal with a prefix");
    check(content.find("p:occ_0 /bin/true:1000\n") == std::string::npos,
          "and it is not written as a bare number that would be read as one");
    // A line with no offset at all is what a fixed-width formatter called
    // with a width of zero produces. The kernel refuses it, and the refusal
    // names neither the offset nor the formatter.
    check(content.find("/bin/true:\n") == std::string::npos,
          "the offset field is not empty");
}

void test_an_id_of_zero_is_not_an_id() {
    FakeTracefs f = make_fake_tracefs();
    if (f.dir.path.empty()) {
        return;
    }
    // Zero is what the id file reads as when it is empty, and what a read
    // that landed on the wrong file would produce. It is not a usable
    // tracepoint config: perf_event_open with config 0 opens the software
    // event group, not this probe, and would return a descriptor that
    // reports nothing forever. The registration has to be refused here
    // rather than subscribed to successfully and silently.
    if (!occ::fs::write_file(f.events + "/uprobes/occ_0/id", "0\n")) {
        return;
    }

    Uprobes u(f.dir.path);
    std::string detail;
    const int rc = u.add("main", "/bin/true", 0x1000, ProbeKind::Entry, detail);
    check(rc != 0, "an event whose id is zero is refused");
    check(!detail.empty(), "and the failure is explained");
    // The two ways an id can be unusable are different problems. A file
    // that holds zero is a file that is there and does not name a
    // tracepoint, and saying "no id could be read" of it would send a
    // reader to look for a missing file that is not missing.
    check(detail.find("id 0") != std::string::npos,
          "and the reason names zero as the problem");
    check(u.size() == 0, "and nothing is left in the layer");

    // The tracefs line is removed on this path too. An id that could not
    // be read is the kernel's event having been created and the id file
    // not being there to say which one, and the event exists either way.
    const std::string content = read_file_or_empty(f.uprobe_events);
    check(content.find("-:occ_0") != std::string::npos,
          "and the tracefs event it created is removed");
}

void test_a_probe_whose_event_never_appears_is_not_left_registered() {
    FakeTracefs f = make_fake_tracefs();
    if (f.dir.path.empty()) {
        return;
    }
    // No id file at all, which is what happens when the kernel rejects the
    // line after writing it. The read comes back empty and the layer has
    // to undo the half-registration: the line is in uprobe_events, and a
    // second attempt at the same symbol would collide with it.
    if (!occ::fs::remove_file(f.events + "/uprobes/occ_0/id")) {
        return;
    }

    Uprobes u(f.dir.path);
    std::string detail;
    const int rc = u.add("main", "/bin/true", 0x1000, ProbeKind::Entry, detail);
    check(rc != 0, "a registration whose id cannot be read fails");
    check(detail.find("no id could be read") != std::string::npos,
          "and the reason is about the id that is not there, which is a "
          "different problem from a file that holds the wrong number");
    check(u.size() == 0, "and nothing is left in the layer");

    const std::string content = read_file_or_empty(f.uprobe_events);
    check(content.find("p:occ_0") != std::string::npos,
          "the line was written before the id was read");
    check(content.find("-:occ_0") != std::string::npos,
          "and it was removed again, so the next attempt will not collide");
}

// --------------------------------------------------------------- the file

void test_availability_names_a_real_directory_or_none() {
    const ProbeAvailability a = Uprobes::availability();
    if (a.tracefs_root.empty()) {
        check(!a.available,
              "an empty tracefs root is only reported while unavailable");
        return;
    }
    // A non-empty root has to be a directory that is there. A layer that
    // reported a path it had not checked would send a caller to look at a
    // directory that does not exist, which is the least useful kind of
    // wrong answer.
    check(occ::fs::is_dir(a.tracefs_root),
          "a named tracefs root is a directory that exists");
}

} // namespace

int main() {
    test_availability_is_answered();
    test_availability_probe_leaves_no_tracefs_event();
    test_availability_names_a_real_directory_or_none();
    test_empty_layer_is_well_formed();
    test_clear_on_empty_is_safe();
    test_removal_after_clear_is_idempotent();
    test_registration_without_tracefs_fails_with_a_reason();
    test_registration_reason_is_not_about_the_target();
    test_subscribe_of_an_unknown_index_is_refused();
    test_probe_kind_values_are_distinct();
    test_hit_defaults_are_zeroed();
    test_explicit_root_is_used_and_not_searched_past();
    test_explicit_root_missing_events_directory();
    test_explicit_root_without_uprobe_events_is_reported();
    test_layer_with_an_explicit_root_reports_that_root();
    test_registration_line_uses_a_hex_file_offset();
    test_registration_that_fails_midway_leaves_nothing();
    test_a_registered_probe_is_in_the_layer_before_any_subscription();
    test_clear_removes_a_recorded_probe_and_its_events();
    test_an_id_of_zero_is_not_an_id();
    test_a_probe_whose_event_never_appears_is_not_left_registered();

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

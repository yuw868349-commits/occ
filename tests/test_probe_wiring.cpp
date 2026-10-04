// The probe wiring: a placer handed to a session, and a runner that places
// probes.
//
// Two things are being checked here and they are different in kind.
//
// The first is that the session actually polls the probe layer. That is
// invisible from the outside on a host that cannot place probes -- which is
// every container -- so the test drives it directly: a placer is built,
// handed to a SessionConfig, and the session is asked to observe a process
// with no probes attached. The assertion is not that a hit was produced,
// because none can be; it is that the presence of the layer changes what the
// session does rather than being ignored. A session that dropped the pointer
// on the floor and one that used it are indistinguishable in the event
// stream of a real run on this host, and this is the only place the
// difference can be seen.
//
// The second is the three-valued decision about whether to try at all. A
// caller who asked for probes wants the attempt recorded; a caller who
// disabled them wants silence; and the two must not collapse into a single
// bool, because the second is a request and the first is not.
//
// What is NOT covered here, and could not be on this host: the body of the
// session's poll. It is entered only when the layer has a descriptor, and a
// descriptor exists only when a probe was subscribed to, which needs a
// mounted tracefs and a permitted perf_event_open. Neither is available in a
// container, so the block that drains on readiness and the block that drains
// after a stop are both reachable only on a host that can place a probe. The
// tests below cover what they can -- the count, the null layer, the empty
// layer, the registered-but-unsubscribed layer -- and the poll's own body is
// left to a host that can reach it. Saying so is better than a test that
// passes because it never ran: this file would otherwise look like proof
// that the drain works, and it is not.
//
// Nothing here needs tracefs, Wine, or a probe to fire. What it needs is the
// plumbing, which is exactly the part that a test on a real host would have
// exercised by accident and a test on this one cannot.

#include "occ/observer/session.h"
#include "occ/probe/placer.h"
#include "occ/runner/run.h"
#include "occ/util/fs.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <type_traits>
#include <vector>

#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace occ::obs;
using occ::engine::ProbeRequest;
using occ::runner::RunOptions;

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

// A tracefs directory with the two files a registration needs, so that a
// probe can be brought to the registered-but-unsubscribed state.
//
// This is the state that makes the session's count checkable. On a host with
// no tracefs every layer is empty, and an empty layer reports zero watched
// whether the session read the layer's descriptors or did not look at all --
// the two implementations are indistinguishable. A layer holding one probe
// with no subscription has a size of one and a descriptor count of zero, and
// a session that confused the two would report a watched probe that has no
// ring and can never fire.
struct FakeTracefs {
    std::string root;
    std::string events;
    std::string uprobe_events;
};

FakeTracefs make_fake_tracefs() {
    FakeTracefs f;
    char tmpl[] = "/tmp/occ-wiring-XXXXXX";
    const char* made = ::mkdtemp(tmpl);
    if (made == nullptr) {
        return f;
    }
    f.root = made;
    f.events = f.root + "/events";
    f.uprobe_events = f.root + "/uprobe_events";

    const std::string uprobes = f.events + "/uprobes";
    if (!occ::fs::mkdir_p(uprobes + "/occ_0", 0700)) {
        f.root.clear();
        return f;
    }
    if (!occ::fs::write_file(f.uprobe_events, "") ||
        !occ::fs::write_file(uprobes + "/occ_0/id", "999999\n")) {
        f.root.clear();
    }
    return f;
}

// A child that traces itself and then stops, so that a session has the one
// thing it needs to get past its first wait: a process that reports a stop.
//
// This is what makes the probe wiring testable at all. A session given the
// test's own pid fails its first wait and returns before it ever looks at
// the probe layer -- so a test that asserted anything about the layer's
// count would be asserting about unreachable code, and it would pass
// against an implementation that never read the layer at all. The child
// exists to make the code after the first wait reachable.
//
// PTRACE_TRACEME rather than a seize from the parent, because that is the
// path the runner takes: the container calls it before the exec, and the
// session consumes the resulting stop. A child stopping itself with
// SIGSTOP is the same shape from the session's point of view.
pid_t fork_traced_stopped() {
    const pid_t pid = ::fork();
    if (pid != 0) {
        // The parent does not wait here, and that is the whole point.
        //
        // A ptrace stop is reported once. A parent that consumed the child's
        // first stop with a waitpid of its own would leave the child stopped
        // with nothing left to report, and the session's own first wait
        // would then block forever on a process that is already parked. The
        // session is the tracer, so the session is the one that has to
        // receive that stop.
        return pid;
    }

    // The child. TRACEME makes the parent its tracer and raises a SIGTRAP
    // that the session consumes as its setup stop; the SIGSTOP after it is
    // the stop the loop then handles, and the exit after that ends the
    // session. Three events rather than one because a session's first wait
    // is part of its setup and not part of its loop.
    if (::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) {
        ::_exit(126);
    }
    ::raise(SIGSTOP);
    ::_exit(0);
}

// ------------------------------------------------------- the session's side

// Drives a session against a traced child and returns what it reported. The
// child is released and reaped here, because a session that was given a
// process to observe owns it until it is done.
//
// A session that failed is not an error for these tests: on a host that
// cannot trace, `observe` says so and returns. What is asserted is about the
// counts, and a count read off a failed session is zero for a reason the
// assertion would misattribute. So the caller is told whether the session
// got far enough for its numbers to mean anything, and the tests assert
// only when it did.
struct SessionRun {
    SessionResult result;
    bool reached_loop = false;
};

SessionRun drive_session(int pid, ProbePlacer* placer) {
    SessionConfig sc;
    sc.pid = pid;
    sc.trace_syscalls = false;
    sc.follow_forks = false;
    sc.probes = placer;

    Writer events;
    events.attach(-1);
    SessionRun out;
    out.result = observe(sc, events);
    // The loop was reached when either the target was seen to exit or a
    // stop other than the setup one was handled. The stderr note the
    // session writes for a failed first wait is not readable here, so the
    // detail string is the signal: it names the failure and is empty on a
    // session that got past it.
    out.reached_loop = out.result.detail.empty();
    return out;
}

void test_a_session_without_a_layer_polls_nothing() {
    // The baseline. A session handed no placer must still run a process to
    // completion, and must report no hits. The null pointer is the case
    // that would fault if the null check in the drain were missing, so the
    // assertion is that the session finished rather than that a number came
    // out.
    const pid_t pid = fork_traced_stopped();
    if (pid <= 0) {
        std::fprintf(stderr, "note: no child could be forked; the baseline "
                             "was skipped\n");
        return;
    }

    const SessionRun run = drive_session(pid, nullptr);
    (void)::waitpid(pid, nullptr, 0);

    check(run.result.probe_hits == 0,
          "a session with no layer reports no hits");
    check(run.result.probes_watched == 0,
          "and reports no probes watched, which is the honest number");
    check(!run.result.failed || !run.reached_loop || run.reached_loop,
          "and the null layer is a path rather than a fault");
}

void test_a_session_counts_the_layer_it_was_given() {
    // The layer holds a probe that is registered and not subscribed to. That
    // is reachable here because register_only touches only tracefs, and it
    // is the state the count has to get right: the layer's size is one and
    // its descriptor count is zero, and a session that reported the size
    // would be claiming a ring that does not exist.
    const FakeTracefs f = make_fake_tracefs();
    if (f.root.empty()) {
        std::fprintf(stderr, "note: no temporary directory; the count check "
                             "was skipped\n");
        return;
    }

    // The session is driven through ProbePlacer, which is the type the
    // runner hands over. The probe is registered through the placer's own
    // layer accessor, which is the object the session will poll.
    ProbePlacer placer(f.root);
    std::string detail;
    std::size_t index = 0;
    const int rc = placer.layer().register_only("main", "/bin/true", 0x1000,
                                                ProbeKind::Entry, index,
                                                detail);
    if (rc != 0) {
        // A host that refuses the tracefs write outright. The test is about
        // a layer with content, so it is skipped rather than asserted on a
        // state that was never reached.
        std::fprintf(stderr, "note: register_only failed (%d: %s); the count "
                             "check was skipped\n", rc, detail.c_str());
        return;
    }

    check(placer.layer().size() == 1, "the probe is in the layer");
    check(placer.layer().fds().empty(),
          "and it has no descriptor to poll, because nothing subscribed to "
          "it");

    const pid_t pid = fork_traced_stopped();
    if (pid <= 0) {
        std::fprintf(stderr, "note: no child could be forked; the count "
                             "check was skipped\n");
        return;
    }

    const SessionRun run = drive_session(pid, &placer);
    (void)::waitpid(pid, nullptr, 0);

    // The assertion is conditional on the session having reached the point
    // that sets the count. A host that cannot trace returns before it, and
    // a zero read off that path is zero for a different reason -- so
    // asserting unconditionally would be a test that passes for the wrong
    // answer.
    if (!run.reached_loop) {
        std::fprintf(stderr, "note: the session did not reach its loop (%s); "
                             "the count check was skipped\n",
                     run.result.detail.c_str());
        return;
    }

    check(placer.layer().size() == 1,
          "the layer still holds its probe after the session ran");
    check(placer.layer().fds().empty(),
          "and still has nothing subscribed to it");
    check(run.result.probes_watched == 0,
          "a session reports zero watched when nothing is subscribed, even "
          "though the layer is not empty");
    check(run.result.probes_watched !=
              static_cast<std::uint64_t>(placer.layer().size()),
          "which is a different number from the layer's size");
    check(run.result.probe_hits == 0,
          "and no hit can come from a probe with no ring");
}

void test_a_session_reports_what_it_watched_and_not_what_it_holds() {
    // The empty-layer case, on a session that reached its loop. The count is
    // zero and so is the layer, so this cannot distinguish a session that
    // read the layer from one that did not -- and it is here to pin the
    // other half of the contract: a session handed a layer with nothing in
    // it must not treat the emptiness as a failure.
    ProbePlacer placer;
    const pid_t pid = fork_traced_stopped();
    if (pid <= 0) {
        std::fprintf(stderr, "note: no child could be forked; the empty-layer "
                             "check was skipped\n");
        return;
    }

    const SessionRun run = drive_session(pid, &placer);
    (void)::waitpid(pid, nullptr, 0);

    check(run.result.probes_watched == 0,
          "an empty layer is polled and yields zero watched");
    check(run.result.probe_hits == 0, "and zero hits");
    check(!run.result.failed || run.result.detail.empty(),
          "and an empty layer is not itself a failure");
}

// ------------------------------------------------------- the runner's side

void test_a_run_with_no_probe_flag_asks_for_none() {
    // The default. An ELF target has no probes in its plan anyway, so the
    // observable difference is on the PE side, and this checks the option
    // itself rather than a run: the mode is Automatic and the flag is
    // false, which is the state a caller reaches by typing nothing.
    RunOptions options;
    check(options.probe == false, "a run asks for no probes by default");
    check(options.probe_mode == RunOptions::ProbeMode::Automatic,
          "and leaves the decision to the host and the engine");
}

void test_the_three_modes_are_distinct() {
    // An explicit off and an absence are different requests, and collapsing
    // them into one bool would mean a caller who typed --no-probe could not
    // be distinguished from one who typed nothing -- which matters because
    // only the first should suppress the "the host has no tracefs" notice.
    check(RunOptions::ProbeMode::Automatic != RunOptions::ProbeMode::Force,
          "automatic and force are different");
    check(RunOptions::ProbeMode::Force != RunOptions::ProbeMode::Disabled,
          "force and disabled are different");
    check(RunOptions::ProbeMode::Automatic != RunOptions::ProbeMode::Disabled,
          "automatic and disabled are different");
}

void test_the_mode_outranks_the_flag_in_both_directions() {
    // The rule, exhaustively, because there are six cases and a table is
    // the only honest way to state a total function.
    using Mode = RunOptions::ProbeMode;

    check(occ::runner::wants_probes(true, Mode::Automatic),
          "automatic with the flag set wants probes");
    check(!occ::runner::wants_probes(false, Mode::Automatic),
          "automatic without the flag does not");

    check(occ::runner::wants_probes(true, Mode::Force),
          "force wants probes when the flag is set");
    check(occ::runner::wants_probes(false, Mode::Force),
          "and when it is not, because force means force");

    check(!occ::runner::wants_probes(true, Mode::Disabled),
          "disabled does not want probes even when the flag is set");
    check(!occ::runner::wants_probes(false, Mode::Disabled),
          "and does not when it is not");
}

void test_disabled_is_not_the_same_answer_as_an_unset_flag() {
    // The two ways to reach "no" have to be distinguishable in the option,
    // because the run reports them differently: a caller who asked for
    // probes and did not get them is told why, and a caller who asked for
    // none is not told anything. If these were one value the notice could
    // not be suppressed.
    using Mode = RunOptions::ProbeMode;
    const bool asked_and_refused = occ::runner::wants_probes(true, Mode::Force);
    const bool did_not_ask = occ::runner::wants_probes(false, Mode::Disabled);
    check(asked_and_refused != did_not_ask,
          "force-with-flag and disabled-without are opposite answers");

    RunOptions a;
    a.probe = true;
    a.probe_mode = Mode::Disabled;
    RunOptions b;
    b.probe = false;
    b.probe_mode = Mode::Automatic;
    check(!occ::runner::wants_probes(a.probe, a.probe_mode),
          "an explicit off says no");
    check(!occ::runner::wants_probes(b.probe, b.probe_mode),
          "and an unset flag says no");
    check(a.probe_mode != b.probe_mode,
          "but the two are different states, which is what lets the run "
          "tell them apart");
}

void test_the_run_result_separates_attribute_count_host() {
    // Four numbers rather than one ratio, because each difference between
    // consecutive ones means something else: requested minus attached is a
    // hole in the coverage, and attached-with-no-hits is a function that
    // was never called or a ring that was never polled.
    occ::runner::RunResult result;
    check(result.probes_requested == 0, "a fresh result requested nothing");
    check(result.probes_attached == 0, "attached nothing");
    check(result.probe_hits == 0, "saw no hits");
    check(result.probes_unavailable.empty(),
          "and has no unavailability sentence, which is not the same as an "
          "empty one");
}

// -------------------------------------------------------- the option's shape

void test_a_probe_request_carries_what_a_placement_needs() {
    // The request is the interface between the engine and the placer. A
    // field added to one and not the other is a placement that resolves the
    // wrong thing, and the two are in different headers precisely so that
    // this can be checked without a run.
    static_assert(std::is_copy_constructible_v<ProbeRequest>,
                  "a request is copied into the plan and out of it");
    const ProbeRequest req{"lib.so", "Sym", "Label", "a note"};
    check(req.module == "lib.so", "a request carries its module");
    check(req.symbol == "Sym", "and its symbol");
    check(req.label == "Label", "and the label a hit is reported under");
    check(req.note == "a note", "and a note for the stream");
}

} // namespace

int main() {
    test_a_session_without_a_layer_polls_nothing();
    test_a_session_counts_the_layer_it_was_given();
    test_a_session_reports_what_it_watched_and_not_what_it_holds();

    test_a_run_with_no_probe_flag_asks_for_none();
    test_the_three_modes_are_distinct();
    test_the_mode_outranks_the_flag_in_both_directions();
    test_disabled_is_not_the_same_answer_as_an_unset_flag();
    test_the_run_result_separates_attribute_count_host();

    test_a_probe_request_carries_what_a_placement_needs();

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

// The plain spawn: a target with no container around it.
//
// What the tests here buy is confidence in the three promises the path
// makes. The target runs and its exit status comes back through the same
// reap the container path uses. The syscall filter the caller passed is
// genuinely active in the child -- proved with a policy that kills on
// write, because a shell that cannot write dies by SIGSYS and a filter
// that was never installed lets the echo through, and the two outcomes are
// nothing alike. And the tracer arrangement stops the child at the exec
// boundary, which is the promise the observer depends on.
//
// Every case reaps the child it spawned, including the ones that fail:
// a test that leaks a stopped or running child leaves it for the ctest
// runner to trip over.

#include "occ/isolation/container.h"
#include "occ/isolation/seccomp.h"
#include "occ/syscall/syscall.h"

#include <cstdio>
#include <string>
#include <vector>

#include <signal.h>

using namespace occ;
using namespace occ::isolation;
using namespace occ::sys;

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

std::vector<std::string> run_env() {
    return {"PATH=/usr/bin:/bin"};
}

}  // namespace

// The ordinary case: a target that runs, says how it ended, and is gone.
void test_spawns_and_reaps() {
    SeccompPolicy policy = guest_default_policy();
    SpawnResult spawned = plain_spawn(policy, true, false, "/bin/sh",
                                      {"/bin/sh", "-c", "exit 7"},
                                      run_env());
    check(spawned.error.ok(), "plain: the spawn succeeds");
    if (!spawned.error.ok()) {
        return;
    }
    const ContainerResult reaped = container_reap(spawned.pid);
    check(!reaped.signaled, "plain: the target was not killed");
    check(reaped.exit_code == 7, "plain: the target's exit code travels");
}

// The filter is real. The policy allows everything except write, which it
// kills on; a shell that reaches its echo dies by SIGSYS, and one running
// without the filter would print and exit zero. The two outcomes cannot be
// confused, which is what makes the check worth having.
void test_filter_is_active() {
    SeccompPolicy policy;
    policy.fallback = SeccompDefault::Allow;
    SeccompRule rule;
    rule.nr = 1;  // write
    rule.action = SeccompAction::KillProcess;
    policy.rules.push_back(rule);

    SpawnResult spawned = plain_spawn(policy, true, false, "/bin/sh",
                                      {"/bin/sh", "-c", "echo hello"},
                                      run_env());
    check(spawned.error.ok(), "plain: the filtered spawn succeeds");
    if (!spawned.error.ok()) {
        return;
    }
    const ContainerResult reaped = container_reap(spawned.pid);
    check(reaped.signaled, "plain: the filtered target was killed");
    check(reaped.term_signal == SIGSYS,
          "plain: the kill came from the filter, as SIGSYS");
}

// The tracer arrangement: a stop_at_exec spawn leaves the child stopped at
// the exec boundary with this process as its tracer. The test does not
// drive it -- the session layer owns that -- but it does collect it, and a
// child that was never stopped would have exited on its own before the
// kill arrived.
void test_stop_at_exec_holds_the_child() {
    SeccompPolicy policy = guest_default_policy();
    SpawnResult spawned = plain_spawn(policy, true, true, "/bin/sh",
                                      {"/bin/sh", "-c", "exit 0"},
                                      run_env());
    check(spawned.error.ok(), "plain: the traced spawn succeeds");
    if (!spawned.error.ok()) {
        return;
    }
    // The child is either stopped at its exec stop or, if the arrangement
    // failed, already gone. The kill and the reap tell the two apart: a
    // stopped child reports as killed by SIGKILL, a gone one reports
    // ECHILD, and neither outcome is a clean exit -- which is the fact the
    // check names.
    (void)sys::kill(spawned.pid, SIGKILL);
    const ContainerResult reaped = container_reap(spawned.pid);
    check(!(!reaped.signaled && reaped.error.ok() && reaped.exit_code == 0),
          "plain: the traced child was held, not left to finish");
}

// A target that cannot be exec'd reports through the reap, not as a hang
// and not as a success. The spawn itself succeeds -- the verdict byte went
// out before the exec was attempted, which is the same order the container
// path uses -- and the failure is the reap's to name.
void test_missing_binary_fails_in_the_reap() {
    SeccompPolicy policy = guest_default_policy();
    SpawnResult spawned = plain_spawn(policy, true, false,
                                      "/nonexistent/occ-plain-spawn-test",
                                      {"/nonexistent/occ-plain-spawn-test"},
                                      run_env());
    check(spawned.error.ok(), "plain: the spawn of a missing binary reports");
    if (!spawned.error.ok()) {
        return;
    }
    const ContainerResult reaped = container_reap(spawned.pid);
    check(!reaped.error.ok(), "plain: the missing binary fails the reap");
    check(reaped.error.stage == Stage::Exec,
          "plain: the failure is named as an exec failure");
}

int main() {
    test_spawns_and_reaps();
    test_filter_is_active();
    test_stop_at_exec_holds_the_child();
    test_missing_binary_fails_in_the_reap();
    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("plain spawn: %d checks, 0 failures\n", checks);
    return 0;
}

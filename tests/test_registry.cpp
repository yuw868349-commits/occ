// Session registry tests.
//
// The registry is how one occ process finds another: a record written when a
// session starts, read back by a later attach to learn which pid to follow.
// The failure it has to avoid is not "the record is missing" but "the record
// points at the wrong process" -- a pid outlives the process that owned it,
// and an attach that believes a recycled pid is attaching to an unrelated
// program while reporting the name of the one that is gone.
//
// Every case here therefore turns on identity rather than on existence, and
// the fixtures run against a private directory so that a case cannot see a
// session left behind by an earlier run.

#include "occ/observer/registry.h"

#include "occ/util/fs.h"

#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

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

// Points the registry at a directory of this test's own. The variable is
// read on every registry operation rather than captured once, so setting it
// before the first call is enough and the process does not have to be
// re-launched. Set through setenv because the value has to be in the
// environment the runtime reads, not in a local the test keeps.
struct PrivateRegistry {
    std::string dir;

    explicit PrivateRegistry(const char* label) {
        dir = std::string{"/tmp/occ-registry-test-"} +
              std::to_string(static_cast<long>(::getpid())) + "-" + label;
        ::setenv("OCC_SESSION_REGISTRY", dir.c_str(), 1);
    }

    ~PrivateRegistry() {
        ::unsetenv("OCC_SESSION_REGISTRY");
        // The records are files this test created; leaving them would make
        // the next run of a differently-named case see them.
        (void)occ::fs::remove_tree(dir);
    }
};

using occ::obs::SessionRecord;

// A process that stays alive for the length of a case, so that a record
// naming it reads back as live. fork() with nothing to do is the cheapest
// way to have a real pid with a real start time.
//
// The child blocks forever rather than returning. fork() here is inside a
// constructor, so the child resumes in the middle of the test's main() and
// would otherwise run every case a second time and write a second set of
// records into the same directory -- which is a failure that looks like a
// registry bug and is not one. A pause is what makes the child a process
// and nothing else.
struct LiveChild {
    pid_t pid = -1;

    LiveChild() {
        pid = ::fork();
        if (pid == 0) {
            for (;;) {
                ::pause();
            }
        }
    }

    ~LiveChild() {
        if (pid > 0) {
            ::kill(pid, 9);
            int status = 0;
            (void)::waitpid(pid, &status, 0);
        }
    }

    [[nodiscard]] bool started() const noexcept { return pid > 0; }
};

// A dead process's pid is the interesting one: the record still names it,
// and the registry must not report it as live.
struct DeadChild {
    pid_t pid = -1;

    DeadChild() {
        pid = ::fork();
        if (pid == 0) {
            ::_exit(0);
        }
        if (pid > 0) {
            int status = 0;
            (void)::waitpid(pid, &status, 0);
        }
    }
};

void test_a_registered_session_reads_back() {
    PrivateRegistry reg{"readback"};
    LiveChild child;
    check(child.started(), "the fixture forked a live process");
    if (!child.started()) {
        return;
    }

    std::string error;
    const std::string id = occ::obs::register_session(
        "/bin/true", static_cast<int>(child.pid), "/tmp/stream.ndjson", error);
    check(!id.empty(), "a session registers");
    if (id.empty()) {
        std::fprintf(stderr, "  register_session said: %s\n", error.c_str());
        return;
    }

    SessionRecord rec;
    check(occ::obs::find_session(id, false, rec), "the session is found by id");
    check(rec.pid == static_cast<int>(child.pid),
          "the record names the process it was given");
    check(rec.start_ticks != 0,
          "the record carries the process start time, not zero");

    // The registry root is the private one, so this did not touch /run.
    std::string root;
    std::string why;
    check(occ::obs::registry_root(root, why), "the registry root is usable");
    check(root == reg.dir, "the registry used the private directory");

    occ::obs::unregister_session(id);
    check(!occ::obs::find_session(id, false, rec),
          "the session is gone after it is unregistered");
}

// The point of storing the start time: a record whose process has exited
// must not be reported. Registering one is refused outright, because the
// start time cannot be read from a process that has gone and a record
// without one cannot be identified later -- and a record that cannot be
// identified is exactly the one that would send a later attach to a
// recycled pid.
void test_a_dead_process_is_not_a_live_session() {
    PrivateRegistry reg{"dead"};
    DeadChild child;
    if (child.pid <= 0) {
        check(false, "the fixture forked a process");
        return;
    }

    std::string error;
    const std::string id = occ::obs::register_session(
        "/bin/true", static_cast<int>(child.pid), "", error);
    check(id.empty(),
          "a session for a process that has exited is refused");
    check(!error.empty(), "the refusal says why");

    // And nothing was left behind that a later read would pick up.
    check(occ::obs::live_sessions().empty(),
          "a refused registration leaves no record");
}

// A record that names a live process reads back as live, which is the
// positive half of the case above: without it, a registry that reported
// nothing at all would pass.
void test_a_live_process_is_a_live_session() {
    PrivateRegistry reg{"live"};
    LiveChild child;
    if (!child.started()) {
        check(false, "the fixture forked a live process");
        return;
    }

    std::string error;
    const std::string id = occ::obs::register_session(
        "/bin/true", static_cast<int>(child.pid), "", error);
    if (id.empty()) {
        check(false, "the record is written");
        return;
    }

    bool found = false;
    for (const auto& r : occ::obs::live_sessions()) {
        if (r.id == id) {
            found = true;
            check(r.pid == static_cast<int>(child.pid),
                  "the live record names the right pid");
        }
    }
    check(found, "a session whose process is alive is live");
    occ::obs::unregister_session(id);
}

// find_session by pid has to apply the same identity test as the id lookup:
// a caller that asks "what session is watching pid N" must not be answered
// with the record of a process that used to have that pid.
void test_find_by_pid_uses_the_start_time() {
    PrivateRegistry reg{"bypid"};
    LiveChild child;
    if (!child.started()) {
        check(false, "the fixture forked a live process");
        return;
    }

    std::string error;
    const std::string id = occ::obs::register_session(
        "/bin/true", static_cast<int>(child.pid), "", error);
    if (id.empty()) {
        check(false, "the record is written");
        return;
    }

    SessionRecord rec;
    check(occ::obs::find_session(std::to_string(child.pid), true, rec),
          "a live process's record is found by pid");
    check(rec.id == id, "the record found by pid is the one registered");
    occ::obs::unregister_session(id);
}

// The start time is field 22 of /proc/<pid>/stat, and it has to be read from
// the process named and not from the caller. A registry that recorded its
// own clock would compare two values that never agree, and every record
// would read as stale.
void test_the_start_time_is_the_targets_own() {
    PrivateRegistry reg{"ticks"};
    LiveChild child;
    if (!child.started()) {
        check(false, "the fixture forked a live process");
        return;
    }

    std::uint64_t child_ticks = 0;
    std::uint64_t self_ticks = 0;
    check(occ::obs::process_start_ticks(child.pid, child_ticks),
          "the child's start time is readable");
    check(occ::obs::process_start_ticks(::getpid(), self_ticks),
          "this process's start time is readable");
    check(child_ticks != 0, "the child's start time is not zero");
    check(child_ticks <= self_ticks,
          "the child started after the process that forked it");

    // A pid that does not exist has no start time, which is a different
    // answer from a start time of zero and has to be reported as one.
    std::uint64_t unused = 0;
    check(!occ::obs::process_start_ticks(-1, unused),
          "a negative pid has no start time");
}

// An unusable registry root is reported rather than treated as an empty
// registry: "no sessions" is an answer a caller acts on by starting one, and
// "the registry is broken" is an answer it acts on by fixing it.
void test_an_unusable_root_is_reported() {
    // A regular file where the directory should be. mkdir_p fails on it,
    // and exists() says the path is occupied.
    const std::string path =
        std::string{"/tmp/occ-registry-blocked-"} +
        std::to_string(static_cast<long>(::getpid()));
    (void)occ::fs::remove_tree(path);
    {
        std::FILE* f = std::fopen(path.c_str(), "w");
        if (f != nullptr) {
            std::fclose(f);
        }
    }
    ::setenv("OCC_SESSION_REGISTRY", path.c_str(), 1);

    std::string root;
    std::string error;
    const bool ok = occ::obs::registry_root(root, error);
    check(!ok, "a file where the registry belongs is not a usable root");
    check(!error.empty(), "the refusal says what is wrong");

    ::unsetenv("OCC_SESSION_REGISTRY");
    (void)occ::fs::remove_tree(path);
}

} // namespace

int main() {
    test_a_registered_session_reads_back();
    test_a_dead_process_is_not_a_live_session();
    test_a_live_process_is_a_live_session();
    test_find_by_pid_uses_the_start_time();
    test_the_start_time_is_the_targets_own();
    test_an_unusable_root_is_reported();

    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks passed\n", checks);
    return 0;
}

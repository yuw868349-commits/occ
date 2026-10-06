// Container layer tests.
//
// The container cannot be tested the way the seccomp builder is. Building a
// filter is a pure function and every property of it can be asserted in
// process; building a container performs privileged operations whose
// availability depends on the host, and a test that fails because the host
// refuses a mount would be reporting on the host and not on this code.
//
// What is asserted here is therefore the part that is a property of the code
// and not of the host:
//
//   * a configuration that cannot work is rejected before anything is
//     created, with the stage named
//   * the namespace flag translation produces the right bits
//   * a real run either completes, or fails at a stage that is reported
//     with an errno -- never hangs, never returns a silent success
//   * the target's own exit code survives the round trip, and a target
//     killed by a signal is reported as signaled rather than as an exit
//
// The end-to-end cases are skipped where the host has no usable user
// namespace, because that is a property of the host and not a defect.

#include "occ/isolation/container.h"
#include "occ/syscall/errno.h"
#include "occ/util/fs.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace occ::isolation;
using occ::fs::exists;
using occ::fs::read_link;

namespace {

int failures = 0;
int checks = 0;
int skipped = 0;

void check(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

void skip(const char* what) {
    ++skipped;
    std::fprintf(stderr, "SKIP %s\n", what);
}

// Describes the namespace flag translation without needing to create
// anything. Each flag is checked on its own so a wrong bit names itself.
//
// A fresh NamespaceSet has every namespace on except the network, so a
// single-flag case is built by clearing the set first. Asserting against a
// default-constructed value would test the defaults and not the bit.
NamespaceSet only(bool user, bool mount, bool pid, bool ipc, bool uts,
                  bool net, bool cgroup) {
    NamespaceSet ns;
    ns.user = user;
    ns.mount = mount;
    ns.pid = pid;
    ns.ipc = ipc;
    ns.uts = uts;
    ns.net = net;
    ns.cgroup = cgroup;
    return ns;
}

void test_namespace_flags() {
    check(only(false, false, false, false, false, false, false).flags() == 0,
          "an empty namespace set has no flags");

    // CLONE_NEWUSER is 0x10000000.
    check(only(true, false, false, false, false, false, false).flags() ==
              0x10000000ULL,
          "user namespace bit");
    check(only(false, true, false, false, false, false, false).flags() ==
              0x00020000ULL,
          "mount namespace bit");
    check(only(false, false, true, false, false, false, false).flags() ==
              0x20000000ULL,
          "pid namespace bit");
    check(only(false, false, false, true, false, false, false).flags() ==
              0x08000000ULL,
          "ipc namespace bit");
    check(only(false, false, false, false, true, false, false).flags() ==
              0x04000000ULL,
          "uts namespace bit");
    check(only(false, false, false, false, false, true, false).flags() ==
              0x40000000ULL,
          "net namespace bit");
    check(only(false, false, false, false, false, false, true).flags() ==
              0x02000000ULL,
          "cgroup namespace bit");

    // Every flag set has to produce a value that carries every bit.
    const std::uint64_t all =
        only(true, true, true, true, true, true, true).flags();
    check((all & 0x10000000ULL) != 0, "all: user");
    check((all & 0x00020000ULL) != 0, "all: mount");
    check((all & 0x20000000ULL) != 0, "all: pid");
    check((all & 0x08000000ULL) != 0, "all: ipc");
    check((all & 0x04000000ULL) != 0, "all: uts");
    check((all & 0x40000000ULL) != 0, "all: net");
    check((all & 0x02000000ULL) != 0, "all: cgroup");

    // The network namespace default is off, which is a deliberate choice:
    // sharing the host's network is how a target is given real access.
    check((NamespaceSet{}.flags() & 0x40000000ULL) == 0,
          "the network namespace is off by default");

    // A configuration with no user namespace is legal and has to be
    // distinguishable, because the uid map write is conditional on it.
    check(only(false, true, false, false, false, false, false).flags() != 0,
          "namespaces without user are still a set");
}

// An overlay root without an upper directory cannot be built. The failure
// has to name the stage rather than producing a half-built container.
void test_overlay_needs_dirs() {
    ContainerConfig config;
    config.root_kind = RootKind::Overlay;
    config.root_dir = "/nonexistent-lower";
    config.upper_dir.clear();
    config.work_dir.clear();

    const ContainerResult r =
        run_container(config, "/bin/true", {"/bin/true"}, {});

    if (r.error.ok()) {
        // The host let a directory that does not exist be used as a lower
        // layer, which cannot happen; treat it as a failure of the test's
        // premise rather than of the code.
        check(false, "an overlay with no upper directory was accepted");
        return;
    }
    check(r.error.error != 0, "the overlay failure carries an errno");
    check(r.error.stage == Stage::RootAssembly ||
              r.error.stage == Stage::Clone,
          "the overlay failure is reported at root assembly or earlier");
}

// container_spawn must not report success for a container that failed to come
// up. This is the property the report pipe exists to provide, and it is the
// one the old protocol got wrong: the child's readiness byte and its failure
// report went into one pipe, so a report that reached the parent before the
// readiness read was consumed byte by byte in the wrong order and the verdict
// was read out of the middle of a failure message.
//
// The case is built to fail inside the child rather than in the parent, which
// is what puts a report on the pipe at all. A missing upper directory is
// refused by assemble_root, which runs after the gate is released, so the
// child is the one that discovers the failure and the parent is the one that
// has to read it.
//
// container_spawn is called directly rather than run_container, because the
// property under test is the return value of the spawn itself. run_container
// would also report the failure, but through container_reap and the exit
// status, which is the fallback path and not the one being asserted.
//
// It runs twice, with and without a user namespace, and the second run is the
// one that catches the old defect. With a user namespace the parent had a
// reason to read the pipe before releasing the child -- it had to write the
// uid map first -- and that read happened to consume the byte that was in
// front, which masked the misordering. With no user namespace there is
// nothing to wait for, so the parent's first and only read was the failure
// report with the readiness byte still sitting in front of it, and the
// readiness byte was read as the verdict. That is not a rarer schedule of the
// same bug; it is the bug, with nothing to hide it.
void spawn_reports_child_failure(bool with_user_namespace) {
    ContainerConfig config;
    config.root_kind = RootKind::Overlay;
    config.root_dir = "/nonexistent-lower";
    config.upper_dir.clear();
    config.work_dir.clear();
    config.namespaces.cgroup = false;
    config.namespaces.net = false;
    config.namespaces.user = with_user_namespace;

    const SpawnResult spawned =
        container_spawn(config, "/bin/true", {"/bin/true"}, {});

    if (spawned.error.ok()) {
        // The container came up on a host that accepted an overlay with no
        // writable layer, which cannot happen. The test's premise failed, not
        // the code.
        if (spawned.pid > 0) {
            (void)container_reap(spawned.pid);
        }
        check(false, with_user_namespace
                        ? "a spawn with no writable overlay layer reported ok"
                        : "a spawn without a user namespace reported ok for a "
                          "container that failed");
        (void)container_cleanup(config);
        return;
    }

    check(spawned.error.error != 0,
          "a spawn whose child failed carries an errno");
    // The stage is the child's, not a default. A spawn that fails with
    // neither of these would mean the parent gave up before the child said
    // anything, which is a different defect from the one being asserted -- and
    // the stage the child named is RootAssembly, because that is where the
    // missing upper directory is refused.
    check(spawned.error.stage == Stage::RootAssembly ||
              spawned.error.stage == Stage::Clone,
          "the child's failure is reported at the stage the child named");

    // A spawn that reports a failure must not leave the child behind. The
    // child exits on its own after writing the report, so this reaps it; a
    // failure here means the child is unreaped, which is a leak a caller
    // cannot see.
    if (spawned.pid > 0) {
        const ContainerResult reaped = container_reap(spawned.pid);
        check(!reaped.error.ok() || reaped.exit_code != 0,
              "a child that reported a failure did not exit successfully");
    }
    (void)container_cleanup(config);
}

void test_spawn_reports_child_failure() {
    spawn_reports_child_failure(true);
    spawn_reports_child_failure(false);
}

// The pid namespace has to be one the target can see. A container that asked
// for a pid namespace and got a process carrying a host pid has created the
// namespace and not used it: /proc inside the container shows the host's
// process list, and a target that inspects its own pid sees a number that
// means something outside.
//
// This is why the assertion is on the pid the target observes rather than on
// anything occ can see from outside: from outside, a container whose pid
// namespace was never entered looks exactly like one that was, because the
// process is a direct child either way and its pid is the same number either
// way. The difference is only visible from inside.
//
// The helper re-executes this binary, reads its own pid, and writes it to a
// descriptor the test passed down. A descriptor rather than a path, because a
// container with a read-only root cannot create a file: the root is sealed
// before the target runs, so a helper asked to write to /tmp fails for a
// reason that has nothing to do with the pid it was asked to report.
void test_target_is_pid_one() {
    const auto linked = read_link("/proc/self/exe");
    if (!linked || linked->empty() || linked->front() != '/') {
        skip("pid namespace: the executable path is not readable");
        return;
    }
    const std::string self = *linked;

    const std::string path =
        "/tmp/occ-test-pidns-" +
        std::to_string(static_cast<long>(::getpid())) + ".txt";

    // No O_CLOEXEC: the descriptor has to survive the exec, which is the only
    // way the target can hand a number back to a root it cannot write to.
    const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        skip("pid namespace: no writable temporary file");
        return;
    }

    ContainerConfig config;
    config.root_dir = "/";
    config.root_kind = RootKind::ReadOnlyBind;
    config.namespaces.cgroup = false;
    config.namespaces.net = false;

    const std::string marker = "--fd-helper";
    const std::string fd_arg = std::to_string(fd);
    const ContainerResult r =
        run_container(config, self, {self, marker, fd_arg}, {});

    (void)::close(fd);

    // The file is read whatever the run reported. A run that failed still
    // produced a number if the target got far enough to write one, and that
    // is information the test wants rather than a reason to skip.
    std::string content;
    if (auto text = occ::fs::read_file(path)) {
        content = *text;
    }
    (void)::unlink(path.c_str());

    if (r.error.ok() && !content.empty()) {
        const long observed = std::strtol(content.c_str(), nullptr, 10);
        check(observed == 1,
              "the target runs as pid 1 inside its pid namespace");
    } else if (r.error.ok()) {
        // The run succeeded but nothing was written, which means the helper
        // did not get to write. Reported rather than skipped: the target ran,
        // so this is not a host that refuses containers.
        check(false, "the target did not report its pid");
    } else {
        skip("pid namespace: this host refuses a container");
    }
}

// The target's exit status has to survive. This is the one end-to-end
// property that matters to every caller.
void test_exit_code_round_trip() {
    if (!exists("/bin/true") || !exists("/bin/false")) {
        skip("exit code round trip: /bin/true and /bin/false are needed");
        return;
    }

    ContainerConfig config;
    config.root_dir = "/";
    config.root_kind = RootKind::ReadOnlyBind;
    config.namespaces.cgroup = false;
    config.namespaces.net = false;

    const ContainerResult ok =
        run_container(config, "/bin/true", {"/bin/true"}, {});
    if (!ok.error.ok()) {
        skip("exit code round trip: this host refuses a container");
        return;
    }
    check(ok.exit_code == 0, "a target that exits 0 is reported as 0");
    check(!ok.signaled, "a target that exits is not reported as signaled");

    const ContainerResult bad =
        run_container(config, "/bin/false", {"/bin/false"}, {});
    if (bad.error.ok()) {
        check(bad.exit_code == 1, "a target that exits 1 is reported as 1");
    }
}

// A target killed by a signal is not an exit status. Conflating the two is
// the classic way a crash is reported as a clean exit.
void test_signal_reporting() {
    // Not under a sanitizer, and the reason is that the property under test is
    // a *signal*.
    //
    // This case works by running a child that provokes SIGSEGV and then
    // inspecting how the container reported it. AddressSanitizer installs its
    // own SIGSEGV handler in every process it is linked into, including that
    // child, and its handler does not return: it prints a report and then
    // terminates the process. So the child dies of the sanitizer's abort
    // rather than of the signal the test raised, and the container correctly
    // reports whatever actually happened -- which is not a signal, and is
    // therefore not what this case is about.
    //
    // The alternative would be to pass ASAN_OPTIONS=handle_segv=0 or
    // allow_user_segv_handler=1, and both were measured: the first lets the
    // child's own null write fault without a report and does restore the
    // signal, but it also disables the sanitizer's ability to see a real fault
    // anywhere else in the run, which is a worse trade than skipping one case
    // in one build. The second is what handle_segv=1 does anyway and does not
    // restore the signal either.
    //
    // So the case is skipped, and the build without a sanitizer still runs
    // it -- which is the build that has to prove this, because a signal is a
    // property of the program and not of the instrumentation.
#if defined(__SANITIZE_ADDRESS__) || defined(OCC_TEST_ASAN)
    skip("signal reporting: a sanitizer replaces the child's SIGSEGV path");
    return;
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
    skip("signal reporting: a sanitizer replaces the child's SIGSEGV path");
    return;
#endif
#endif

    const auto linked = read_link("/proc/self/exe");
    if (!linked || linked->empty() || linked->front() != '/') {
        skip("signal reporting: the executable path is not readable");
        return;
    }
    const std::string self = *linked;

    // Only the stages that do not need a writable root are exercised here.
    ContainerConfig config;
    config.root_dir = "/";
    config.root_kind = RootKind::ReadOnlyBind;
    config.namespaces.cgroup = false;
    config.namespaces.net = false;

    // The helper re-executes this binary with an argument that makes it
    // raise SIGSEGV. If the container cannot be built the case is skipped,
    // because the property under test is the reporting and not the setup.
    const std::string marker = "--sigsegv-helper";
    for (int i = 0; i < 1; ++i) {
        const ContainerResult r =
            run_container(config, self, {self, marker}, {});
        if (!r.error.ok()) {
            skip("signal reporting: this host refuses a container");
            return;
        }
        check(r.signaled, "a target killed by a signal is reported as signaled");
        check(r.term_signal == 11, "the signal number is reported");
        check(r.exit_code == 0, "a signaled target reports no exit code");
    }
}

} // namespace

// The helper entry points used by the tests that need a target to do
// something. They live outside the anonymous namespace so that main can find
// them.
namespace occ_test {
[[noreturn]] void raise_segv();
}

// Writes this process's pid to the descriptor whose number is the second
// argument.
//
// The write is through a descriptor rather than stdout because the
// container's stdout is the test's stdout: a line on it would be
// indistinguishable from the test's own output, and interleaving the two is
// exactly the sort of thing that makes a passing test unreadable.
void write_own_pid(const char* fd_arg) {
    const int fd = static_cast<int>(std::strtol(fd_arg, nullptr, 10));
    const std::string line = std::to_string(::getpid()) + "\n";
    const ssize_t written = ::write(fd, line.data(), line.size());
    const int rc = written == static_cast<ssize_t>(line.size()) ? 0 : 1;
    _exit(rc);
}

int main(int argc, char** argv) {
    if (argc > 1 && std::strcmp(argv[1], "--sigsegv-helper") == 0) {
        // A raw null write produces SIGSEGV without any library support.
        //
        // The address is taken from argc rather than written as a literal
        // null, so the compiler cannot prove the store is unreachable and
        // fold it away. The write is still unconditional: this path must
        // fault, and a check in front of it would be a check that could be
        // optimized away, leaving a test that passes without ever raising a
        // signal.
        auto* p = reinterpret_cast<volatile int*>(argc);
        *p = 1;
        _exit(0);
    }

    if (argc > 2 && std::strcmp(argv[1], "--fd-helper") == 0) {
        write_own_pid(argv[2]);
    }

    test_namespace_flags();
    test_overlay_needs_dirs();
    test_spawn_reports_child_failure();
    test_target_is_pid_one();
    test_exit_code_round_trip();
    test_signal_reporting();

    std::fprintf(stderr, "%d checks, %d failures, %d skipped\n", checks,
                 failures, skipped);
    return failures == 0 ? 0 : 1;
}

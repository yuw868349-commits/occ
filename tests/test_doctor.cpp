// The host capability report.
//
// `occ doctor` answers "what will work on this machine", and the answer is
// only worth as much as its shape: a report that skips a check because an
// earlier one failed is a report with a hole in it, and a check whose detail
// is empty is a check a reader cannot act on. Those are the properties tested
// here, and they are tested against the real host rather than against a
// fixture, because the report's whole subject is the host.
//
// The one check with a number in it is the observer's probe table, and it is
// the one whose number can be wrong without anything failing: the table is
// hand-written, and a report that said "73 probes" when the table held
// seventy-two would be a report nobody could catch by reading it. So the
// count is asserted against the table itself.

#include "occ/doctor.h"

#include "occ/observer/ntdll_probes.h"
#include "occ/observer/uprobe.h"

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

// The checks a report is expected to carry, by name. A new probe is a new
// line here, which is the point: the list is what stops a check from being
// dropped without anyone noticing.
const char* kExpected[] = {
    "identity",
    "kernel",
    "procfs",
    "user namespaces",
    "mount",
    "overlayfs",
    "cgroup v2",
    "seccomp",
    "bpf",
    "perf_event",
    "tracefs",
    "binderfs",
    "kernel config",
    "observer probes",
};

void test_the_report_is_complete() {
    const occ::DoctorReport report = occ::run_doctor();

    check(!report.checks.empty(), "the report has checks");

    std::size_t matched = 0;
    for (const char* name : kExpected) {
        bool found = false;
        for (const occ::Check& c : report.checks) {
            if (c.name == name) {
                found = true;
                break;
            }
        }
        if (found) {
            ++matched;
        } else {
            std::fprintf(stderr, "FAIL the report is missing the \"%s\" check\n",
                         name);
            ++failures;
        }
    }
    check(matched == sizeof(kExpected) / sizeof(kExpected[0]),
          "every expected check is present");

    check(report.checks.size() == matched,
          "and the report carries nothing beyond them");
}

void test_every_check_says_something() {
    const occ::DoctorReport report = occ::run_doctor();

    for (const occ::Check& c : report.checks) {
        if (c.name.empty()) {
            check(false, "a check has no name");
            continue;
        }
        if (c.detail.empty()) {
            std::fprintf(stderr, "FAIL the \"%s\" check has no detail\n",
                         c.name.c_str());
            ++failures;
            continue;
        }
        ++checks;
    }
    check(true, "every check carries a name and a detail");
}

void test_no_check_is_named_twice() {
    const occ::DoctorReport report = occ::run_doctor();

    for (std::size_t i = 0; i < report.checks.size(); ++i) {
        for (std::size_t j = i + 1; j < report.checks.size(); ++j) {
            if (report.checks[i].name == report.checks[j].name) {
                std::fprintf(stderr, "FAIL two checks are named \"%s\"\n",
                             report.checks[i].name.c_str());
                ++failures;
            }
        }
    }
    check(true, "no two checks share a name");
}

// The probe-table check, against the table itself.
//
// The check reports the table's size next to whether this host can place
// any of it. Both halves are asserted: the count has to be the table's real
// size, and the sentence has to say which of the two situations this host is
// in -- a host without tracefs says so, and a host with it names the root.
void test_the_probe_check_names_the_real_table() {
    const occ::DoctorReport report = occ::run_doctor();

    const occ::Check* probe = nullptr;
    for (const occ::Check& c : report.checks) {
        if (c.name == "observer probes") {
            probe = &c;
            break;
        }
    }
    if (probe == nullptr) {
        check(false, "the report has an observer probes check");
        return;
    }

    const std::size_t count = occ::obs::ntdll_probe_count();
    check(count > 0, "the probe table is not empty");

    const std::string want = std::to_string(count) + " probes in the table";
    check(probe->detail.rfind(want, 0) == 0,
          "the check opens with the table's real size");

    // One of the two endings, and the one that is there has to be the true
    // one. A host that can place probes names the tracefs root it found; a
    // host that cannot says why. Which is which is the host's business, so
    // the test asks the layer directly and requires the report to agree.
    const occ::obs::ProbeAvailability avail = occ::obs::Uprobes::availability();
    if (avail.available) {
        check(probe->detail.find("uprobes available at " + avail.tracefs_root) !=
                  std::string::npos,
              "a host that can place probes names the tracefs it found");
        check(probe->status == occ::CheckStatus::Ok,
              "and the check reports ok");
    } else {
        check(probe->detail.find("none of them can be placed here") !=
                  std::string::npos,
              "a host that cannot place probes says so");
        check(probe->status == occ::CheckStatus::Warn,
              "and the check reports warn rather than fail, because "
              "syscall-level observation continues");
    }
}

void test_the_exit_code_follows_the_failures() {
    const occ::DoctorReport report = occ::run_doctor();

    bool any_fail = false;
    for (const occ::Check& c : report.checks) {
        if (c.status == occ::CheckStatus::Fail) {
            any_fail = true;
        }
    }
    check(report.exit_code() == (any_fail ? 1 : 0),
          "the exit code is non-zero exactly when a check failed");
    check(report.has_failure() == any_fail,
          "and has_failure agrees with the checks it summarises");
}

} // namespace

int main() {
    test_the_report_is_complete();
    test_every_check_says_something();
    test_no_check_is_named_twice();
    test_the_probe_check_names_the_real_table();
    test_the_exit_code_follows_the_failures();

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

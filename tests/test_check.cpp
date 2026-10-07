// `occ check` end to end.
//
// This is the only test in the tree that runs the built binary rather than
// linking the library, and it is deliberate. `check` is a command: what a
// caller depends on is its exit status and the shape of the line it prints,
// and neither of those exists below `main`. A test that called the helper
// functions directly would pass while `check` returned the wrong status for
// a file the helpers refused, which is the failure mode worth catching.
//
// The binary's path arrives from CMake as OCC_BINARY, which is the generator
// expression for the `occ` target. Hard-coding build/occ would break the
// moment anyone built out of tree, which is exactly the kind of breakage a
// test is supposed to survive.
//
// The grammar is "occ check <path> [--json]", with the subcommand first.
// That is not a detail the test may assume away: a test that spelled the
// command wrong would exercise the usage message and pass the assertions
// below for the wrong reason, which is what an earlier revision of this
// file did. Every call here goes through the subcommand.
//
// The readable form is selected when stdout is a terminal and the JSON form
// when it is not, so the two cannot be reached by the same redirection. The
// tests that read JSON connect the child's stdout to a pipe; the one that
// reads the readable form gives the child a pseudo-terminal, which is the
// only way to ask for it from a process that has no terminal of its own.

#include <pty.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
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

struct Run {
    int status = -1;
    std::string out;
};

// The argument vector for one invocation, with the subcommand in front.
//
// Building it in one place is the fix for the bug that shipped in the first
// draft of this file: the path was passed where the subcommand belongs, so
// every case ran the usage message and the assertions were measuring
// nothing.
std::vector<std::string> argv_for(const std::vector<std::string>& args) {
    std::vector<std::string> v;
    v.push_back(OCC_BINARY);
    v.push_back("check");
    for (const std::string& a : args) {
        v.push_back(a);
    }
    return v;
}

void exec_child(const std::vector<std::string>& args, int out_fd) {
    if (::dup2(out_fd, 1) < 0) {
        ::_exit(126);
    }
    std::vector<std::string> storage = argv_for(args);
    std::vector<char*> argv;
    for (std::string& a : storage) {
        argv.push_back(a.data());
    }
    argv.push_back(nullptr);
    ::execv(OCC_BINARY, argv.data());
    ::_exit(127);
}

// Runs `occ check ...` with stdout on a pipe, and collects the output.
//
// A pipe is not a terminal, so this is the path that selects the JSON form.
// stderr is left inherited so that a diagnostic from the binary reaches the
// person running the test; a crash on the way to the assertion is worth
// seeing, and redirecting it would hide the only explanation there is.
Run run_occ(const std::vector<std::string>& args) {
    int fds[2];
    if (::pipe(fds) != 0) {
        return {};
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        ::close(fds[0]);
        ::close(fds[1]);
        return {};
    }

    if (pid == 0) {
        ::close(fds[0]);
        exec_child(args, fds[1]);
    }

    ::close(fds[1]);
    Run r;
    char buf[4096];
    for (;;) {
        const ssize_t n = ::read(fds[0], buf, sizeof buf);
        if (n <= 0) {
            break;
        }
        r.out.append(buf, static_cast<std::size_t>(n));
    }
    ::close(fds[0]);
    int status = 0;
    if (::waitpid(pid, &status, 0) == pid && WIFEXITED(status)) {
        r.status = WEXITSTATUS(status);
    }
    return r;
}

// Runs `occ check ...` with stdout on a pseudo-terminal, which is the only
// way to reach the readable form from a test runner whose stdout is a pipe
// or a file.
//
// The child becomes a session leader with the pty as its controlling
// terminal, which is what a real interactive invocation looks like. The
// master side is read until the child exits; a pty turns "\n" into "\r\n" on
// the way out, so the assertions that compare a whole line normalise it
// rather than depending on the termios settings an inherited terminal might
// or might not have.
Run run_occ_tty(const std::vector<std::string>& args) {
    int master = -1;
    const pid_t pid = ::forkpty(&master, nullptr, nullptr, nullptr);
    if (pid < 0) {
        return {};
    }

    if (pid == 0) {
        exec_child(args, 1);
    }

    Run r;
    char buf[4096];
    for (;;) {
        const ssize_t n = ::read(master, buf, sizeof buf);
        if (n <= 0) {
            break;
        }
        r.out.append(buf, static_cast<std::size_t>(n));
    }
    ::close(master);
    int status = 0;
    if (::waitpid(pid, &status, 0) == pid && WIFEXITED(status)) {
        r.status = WEXITSTATUS(status);
    }
    return r;
}

// The seeds the loader's own tests use, named here rather than rebuilt so
// that a change to one of them has to be made in one place. CMake passes the
// directory, so the path does not depend on where CTest happens to run from.
std::string seed(const char* name) {
    return std::string(OCC_SEED_DIR) + "/" + name + ".bin";
}

// A tiny substring test, so that the assertions below can name a field
// without depending on the order of the keys.
bool has(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

// A file that is not an image at all.
//
// /dev/null is empty, which is the case every format sniffer has to survive
// and the one a caller is most likely to hit by accident.
void test_check_refuses_a_non_image() {
    const Run r = run_occ({"/dev/null"});
    check(r.status == 4, "check: an empty file is not a recognised format");
    check(has(r.out, "\"format\":\"unknown\""),
          "check: the format is reported as unknown");
}

// The load section is filled in, and a refusal carries a sentence as well as
// a code.
//
// The subject is a fuzz seed rather than a real-world PE, because the tree
// does not carry one and a test that downloaded one would be testing the
// network. The seed has an entry point outside any executable section, which
// is the loader's refusal path.
void test_check_reports_a_loader_refusal() {
    const Run r = run_occ({seed("pe_entry_not_executable")});
    check(r.status == 5, "check: a bad entry point exits 5, not 0");
    check(has(r.out, "\"attempted\":true"),
          "check: the load was attempted for a PE");
    check(has(r.out, "\"loaded\":false"),
          "check: the load is reported as refused");
    check(has(r.out, "not in an executable section"),
          "check: the refusal names the reason and not only the code");
}

// Every loader refusal the fuzz corpus turned up is visible through `check`
// as itself, with its own sentence.
//
// This is the point of wiring the loader into the command: the same three
// files that crash a fuzz harness now produce a diagnosis a person can read,
// and the status tells a script which of them to act on.
void test_check_reports_each_loader_refusal() {
    struct Case {
        const char* name;
        const char* needle;
    };
    const Case cases[] = {
        {"pe_bad_entry_rva", "outside the image"},
        {"pe_entry_not_executable", "not in an executable section"},
        {"pe_section_over_headers", "overlaps the headers"},
    };
    for (const Case& c : cases) {
        const Run r = run_occ({seed(c.name)});
        check(r.status == 5, c.name);
        check(has(r.out, c.needle), c.name);
    }
}

// A format with no loader gets no load section, and the two absences stay
// distinguishable.
//
// The distinction is the reason the field is an object with "attempted"
// rather than a null: a caller that cannot tell "occ has no loader for this"
// from "the loader said no" would have to read the format field to decide
// what the result means.
void test_check_does_not_attempt_a_load_without_a_loader() {
    const Run r = run_occ({"/bin/sh"});
    check(r.status == 0, "check: an ELF is a format an engine handles");
    check(has(r.out, "\"load\":{\"attempted\":false}"),
          "check: no load is attempted for a format without a loader");
}

// A PE the loader accepts reports the numbers a successful load produces.
//
// The base, the region count and the entry flags are what a caller reads to
// confirm the image went where it said it would. A load that succeeded but
// reported zero regions would be a load that mapped nothing.
void test_check_reports_a_successful_load() {
    const Run r = run_occ({seed("pe32plus_min")});
    check(r.status == 0, "check: a loadable image exits 0");
    check(has(r.out, "\"attempted\":true,\"loaded\":true"),
          "check: the load is reported as loaded");
    check(has(r.out, "\"regions\":") && !has(r.out, "\"regions\":0"),
          "check: a loaded image has at least one region");
    check(has(r.out, "\"entry_mapped\":true"),
          "check: the entry point is reported as mapped");
    check(has(r.out, "\"entry_executable\":true"),
          "check: the entry point is reported as executable");
}

// The PE engine reports no host requirement, because it has none.
//
// It used to carry a caveat saying it needed a Wine loader from the host.
// That was true while the PE path borrowed a loader; it stopped being true
// when the runtime that executes the image moved into this binary, and the
// caveat was left behind. The note is asserted empty rather than asserted
// to hold other words, because the absence is the claim: `check` has no
// host-level objection to raise about a PE, and a caller that reads an
// empty note knows the engine's answer will come from the load below it.
void test_check_names_no_host_requirement_for_a_pe() {
    const Run r = run_occ({seed("pe32plus_min")});
    check(r.status == 0, "check: a loadable PE exits 0");
    check(has(r.out, "\"note\":\"\""),
          "check: the pe engine reports no host requirement");
    check(!has(r.out, "Wine"),
          "check: no engine claims a Wine loader is needed");
}

// A PE this build cannot execute says so from the loader, not from a note.
//
// Which machine a runtime executes is a property of that runtime, and the
// runtime is the one answering here: the load section names the machine the
// image declares and the machine this build carries. A note that guessed
// the answer from the format would be a second statement of the same fact,
// and the two would disagree the first time either changed.
void test_check_reports_the_machine_a_pe_needs() {
    const Run r = run_occ({seed("pe32_min")});
    check(r.status == 5, "check: a 32-bit image is refused by the loader");
    check(has(r.out, "\"note\":\"\""),
          "check: the refusal is not restated as a host caveat");
    check(has(r.out, "this runtime executes only amd64"),
          "check: the loader names the machine this build executes");
}

// The readable form says the same things as the JSON.
//
// Both are printed from the same LoadCheck and a change that updated one and
// not the other would be invisible to a test that only read the other. This
// is also the only test here that proves the terminal branch of the format
// choice is reachable at all.
//
// The newline normalisation is why the needles below are fragments rather
// than complete lines: a pty is in cooked mode, so every "\n" the program
// writes leaves the master side as "\r\n" and comparing a whole line would
// be comparing the terminal driver's behaviour instead of the program's.
void test_check_text_form_names_the_load() {
    const Run r = run_occ_tty({seed("pe_bad_entry_rva")});
    check(r.status == 5, "check: text form exits 5 on a refused load");
    check(has(r.out, "  load\r\n"), "check: text form has a load section");
    check(has(r.out, "    result       refused\r\n"),
          "check: text form says the load was refused");
    check(has(r.out, "    reason       section_out_of_range: the entry point "
                     "RVA 0x3000 is outside the image"),
          "check: text form carries the reason on the reason line");
    check(!has(r.out, "\""),
          "check: text form is not the JSON form, which was not asked for");
}

} // namespace

int main() {
    test_check_refuses_a_non_image();
    test_check_reports_a_loader_refusal();
    test_check_reports_each_loader_refusal();
    test_check_does_not_attempt_a_load_without_a_loader();
    test_check_reports_a_successful_load();
    test_check_names_no_host_requirement_for_a_pe();
    test_check_reports_the_machine_a_pe_needs();
    test_check_text_form_names_the_load();

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

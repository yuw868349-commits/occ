// Verifies the seccomp program builder against the running kernel.
//
// Two things make this harder than it looks, and both are properties of the
// system under test rather than of the test.
//
// The first is reporting. A filter that denies write(2) also denies the
// child's own diagnostics, so no amount of care with a file descriptor makes
// the observations visible. The results are written to a shared anonymous
// mapping instead: storing to memory needs no syscall, so every observation
// survives the child, and the parent reads them after a wait.
//
// The second is that the filter applies to the process that installed it,
// including the call that returns from installing it. Everything the child
// needs in order to terminate is therefore part of the policy, and the
// policy is what the test is checking.
//
// The comparison operators are the reason this file is long. Five of the six
// are encoded as hand-written constants rather than macros -- the uapi header
// exports BPF_JEQ, BPF_JGT, BPF_JGE and BPF_JSET but not JNE, JLT or JLE --
// and a wrong constant in that list is not a compile error. It is a filter
// that the kernel accepts and that compares with the wrong operator, which
// turns a rule that denies into a rule that permits. Nothing about installing
// it would say so. So each operator is exercised by installing a real filter
// and issuing a real syscall whose argument is chosen to distinguish the
// right comparison from its neighbours, and the observation is the syscall's
// actual return value.

#include "occ/isolation/seccomp.h"
#include "occ/syscall/syscall.h"

#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

using occ::sys::build_seccomp;
using occ::sys::SeccompAction;
using occ::sys::SeccompArgTest;
using occ::sys::SeccompCmp;
using occ::sys::SeccompDefault;
using occ::sys::SeccompPolicy;
using occ::sys::SeccompRule;
using occ::sys::highest_known_syscall;

int g_failures = 0;

void check(const char* label, long got, long want) {
    const bool pass = (got == want);
    std::printf("%s  %-52s got %4ld  want %4ld\n", pass ? "PASS" : "FAIL",
                label, got, want);
    if (!pass) {
        ++g_failures;
    }
}

void check_true(const char* label, bool value) {
    std::printf("%s  %s\n", value ? "PASS" : "FAIL", label);
    if (!value) {
        ++g_failures;
    }
}

// What the child observes. Plain data, so filling it needs no syscall.
struct Observations {
    long build_ok;
    long insn_count;
    long no_new_privs;
    long install;
    long write_ret;
    long getpid_ret;
    long openat_plain_ret;
    long openat_create_ret;
    long unlisted_ret;
    long allowed_ret;
};

// One child's report of a single filtered syscall. Kept in a shared mapping
// so it survives the filter that would otherwise block the reporting.
struct Probe {
    long built;
    long installed;
    long ret;
};

// A syscall chosen as a probe subject. madvise(2) takes an integer advice
// that reaches the filter as argument 0 and has no side effect the test
// depends on: the filter is installed before the call, and either the call is
// denied and never runs or the filter allowed it and the test does not care
// what a successful madvise returns. What the test cares about is which of
// the two happened, and the return value says so.
constexpr std::uint32_t kNrMadvise = 28;

constexpr std::uint32_t kNrWrite = 1;
constexpr std::uint32_t kNrGetpid = 39;
constexpr std::uint32_t kNrOpenat = 257;
constexpr std::uint32_t kNrGetuid = 102;
constexpr std::uint32_t kNrExitGroup = 231;
constexpr std::uint32_t kNrRtSigreturn = 15;

// errno values chosen to be distinguishable in a return value. A denied
// syscall returns -errno, so each branch of a policy needs its own.
constexpr int kErrDenied = 13;  // EACCES
constexpr int kErrFallback = 38; // ENOSYS

void run_child(Observations* out) {
    SeccompPolicy policy;
    policy.fallback = SeccompDefault::Errno;
    policy.fallback_error = 38; // ENOSYS
    policy.max_nr = highest_known_syscall();

    // Deny outright, with a number that distinguishes this rule from the
    // others in the policy.
    policy.rules.push_back(SeccompRule{kNrWrite, SeccompAction::Errno, 22, {}});
    policy.rules.push_back(SeccompRule{kNrGetpid, SeccompAction::Errno, 30, {}});

    // Deny only when O_CREAT is among the flags. Every other flag set falls
    // through to the next rule and then to the fallback, which is what makes
    // the argument test observable.
    policy.rules.push_back(SeccompRule{
        kNrOpenat, SeccompAction::Errno, 1,
        {SeccompArgTest{2, SeccompCmp::Masked, 0100}}});

    // Allow with no argument test, to confirm a rule can permit as well as
    // deny.
    policy.rules.push_back(
        SeccompRule{kNrGetuid, SeccompAction::Allow, 0, {}});

    // What a process needs in order to finish cleanly. The filter applies to
    // the exit path, so leaving these out would make the child die on a
    // denied exit_group and report nothing.
    policy.rules.push_back(
        SeccompRule{kNrExitGroup, SeccompAction::Allow, 0, {}});
    policy.rules.push_back(
        SeccompRule{kNrRtSigreturn, SeccompAction::Allow, 0, {}});

    const auto program = build_seccomp(policy);
    out->build_ok = program.valid() ? 1 : 0;
    out->insn_count = static_cast<long>(program.insn_count());
    if (!program.valid()) {
        _exit(1);
    }

    out->no_new_privs = occ::sys::prctl(38 /* PR_SET_NO_NEW_PRIVS */, 1, 0, 0, 0)
                            .value;
    out->install = occ::sys::seccomp_install(program);

    out->write_ret = occ::sys::write(1, "x", 1).value;
    out->getpid_ret = occ::sys::getpid().value;
    out->openat_plain_ret =
        occ::sys::openat(-100, "/nonexistent-occ-xyz", 0, 0).value;
    out->openat_create_ret =
        occ::sys::openat(-100, "/nonexistent-occ-xyz", 0100, 0644).value;
    out->unlisted_ret = occ::sys::nanosleep(nullptr, nullptr).value;
    out->allowed_ret = occ::sys::getuid_syscall().value;

    _exit(0);
}

// Builds a one-rule policy that denies its probe syscall exactly when the
// comparison holds, forks a child, installs the filter there and has the
// child make the call. Returns the syscall's return value, or the negative
// errno if the child could not be set up at all.
//
// A return of -kErrDenied means the comparison matched and the rule fired. A
// return of -kErrFallback means the comparison did not match and the call
// reached the fallback. Those are the two answers that distinguish one
// operator from another; the caller supplies an argument value for which the
// correct operator and each of its neighbours would answer differently.
long probe(SeccompCmp cmp, std::uint32_t value, long argument) {
    auto* p = static_cast<Probe*>(
        ::mmap(nullptr, sizeof(Probe), PROT_READ | PROT_WRITE,
               MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    if (p == MAP_FAILED) {
        return -1;
    }
    p->built = 0;
    p->installed = -1;
    p->ret = -1;

    const pid_t pid = ::fork();
    if (pid < 0) {
        (void)::munmap(p, sizeof(Probe));
        return -1;
    }
    if (pid == 0) {
        SeccompPolicy policy;
        policy.fallback = SeccompDefault::Errno;
        policy.fallback_error = kErrFallback;
        policy.max_nr = highest_known_syscall();

        // The rule denies when the comparison holds and says nothing when it
        // does not, so a non-match falls to the fallback. The two errnos are
        // different, so the return value alone identifies the branch.
        //
        // The test keys on argument 2, which is madvise's advice. Arguments 0
        // and 1 are the address and the length, and a rule on those would be
        // comparing values the test does not control: keying on argument 0
        // would compare the address, which is zero in every call here, and
        // every operator would then agree.
        policy.rules.push_back(SeccompRule{
            kNrMadvise, SeccompAction::Errno, kErrDenied,
            {SeccompArgTest{2, cmp, value}}});

        // The exit path, for the reason given in run_child.
        policy.rules.push_back(
            SeccompRule{kNrExitGroup, SeccompAction::Allow, 0, {}});
        policy.rules.push_back(
            SeccompRule{kNrRtSigreturn, SeccompAction::Allow, 0, {}});

        const auto program = build_seccomp(policy);
        p->built = program.valid() ? 1 : 0;
        if (!program.valid()) {
            _exit(1);
        }
        if (occ::sys::prctl(38 /* PR_SET_NO_NEW_PRIVS */, 1, 0, 0, 0).failed()) {
            _exit(1);
        }
        p->installed = occ::sys::seccomp_install(program);

        // madvise(addr, length, advice): the advice is argument 2 and is the
        // only argument the test both controls and can vary without a side
        // effect, so the rule above keys on it and the call passes the value
        // under test there.
        p->ret = occ::sys::detail::call6(
                     static_cast<long>(kNrMadvise), 0, 0, argument, 0, 0, 0)
                     .value;
        _exit(0);
    }

    int status = 0;
    (void)::waitpid(pid, &status, 0);
    const long result =
        (p->built == 1 && p->installed == 0) ? p->ret : -1;
    (void)::munmap(p, sizeof(Probe));
    return result;
}

} // namespace

int main() {
    // A rule that would make a syscall appear to succeed without running.
    // The kernel reads SECCOMP_RET_ERRNO with a zero payload as "return
    // zero", which is neither an error nor a success and which sends a
    // caller of read into an end-of-file loop. The builder refuses it.
    {
        SeccompPolicy policy;
        policy.fallback_error = 38;
        policy.rules.push_back(
            SeccompRule{kNrWrite, SeccompAction::Errno, 0, {}});
        const auto program = build_seccomp(policy);
        check_true("a zero errno is refused", !program.valid());
    }

    // The same refusal on the fallback, which is a separate code path: a
    // policy whose every rule is valid and whose fallback errno is zero is
    // still a policy that would turn a denied syscall into a success.
    {
        SeccompPolicy policy;
        policy.fallback = SeccompDefault::Errno;
        policy.fallback_error = 0;
        const auto program = build_seccomp(policy);
        check_true("a zero fallback errno is refused", !program.valid());
    }

    // An argument index past the sixth cannot be expressed in seccomp_data
    // and would silently read an adjacent field.
    {
        SeccompPolicy policy;
        policy.fallback_error = 38;
        policy.rules.push_back(SeccompRule{
            kNrWrite, SeccompAction::Errno, 22,
            {SeccompArgTest{9, SeccompCmp::Equal, 0}}});
        const auto program = build_seccomp(policy);
        check_true("an argument index above 5 is refused", !program.valid());
    }

    // The boundary case: index 5 is the last argument seccomp_data has, so it
    // must be accepted where 6 is refused. A check written as index > 5
    // would pass both of the tests above and still be wrong here.
    {
        SeccompPolicy policy;
        policy.fallback_error = 38;
        policy.rules.push_back(SeccompRule{
            kNrWrite, SeccompAction::Errno, 22,
            {SeccompArgTest{5, SeccompCmp::Equal, 0}}});
        const auto program = build_seccomp(policy);
        check_true("argument index 5 is accepted", program.valid());
    }

    auto* out = static_cast<Observations*>(
        ::mmap(nullptr, sizeof(Observations), PROT_READ | PROT_WRITE,
               MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    if (out == MAP_FAILED) {
        std::printf("FAIL  mmap\n");
        return 1;
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        std::printf("FAIL  fork\n");
        return 1;
    }
    if (pid == 0) {
        run_child(out);
    }

    int status = 0;
    (void)::waitpid(pid, &status, 0);

    check_true("the policy compiles", out->build_ok == 1);
    check("instruction count is positive", out->insn_count > 0 ? 1 : 0, 1);
    check("PR_SET_NO_NEW_PRIVS succeeds", out->no_new_privs, 0);
    check("the filter installs", out->install, 0);

    check("write(2) returns the rule's errno", out->write_ret, -22);
    check("getpid(2) returns the rule's errno", out->getpid_ret, -30);
    check("openat(2) without O_CREAT reaches the fallback",
          out->openat_plain_ret, -38);
    check("openat(2) with O_CREAT matches the argument test",
          out->openat_create_ret, -1);
    check("a syscall no rule mentions reaches the fallback",
          out->unlisted_ret, -38);
    check("a rule that allows runs the syscall", out->allowed_ret, 0);

    check_true("the child exited normally", WIFEXITED(status) == 1);
    // The exit status is only worth asserting when nothing else is between the
    // child's last observation and its exit.
    //
    // Under a sanitizer the child does more work on the way out -- the
    // runtime's own atexit handlers run, the sanitizer flushes its own state,
    // and each of those makes syscalls this filter has not been told about and
    // refuses. The child therefore leaves with a nonzero status, and the
    // assertion below fails on a build where the filter itself behaved
    // perfectly: every syscall observation above it passed, which is the whole
    // of what this case is about.
    //
    // So the check is made conditional rather than the case being skipped. The
    // syscall results are what prove the policy; the exit status is a
    // supporting claim that a sanitizer build cannot make, and dropping the
    // whole case would drop the real assertions with it.
#if !defined(__SANITIZE_ADDRESS__) && !defined(OCC_TEST_ASAN) && \
    !(defined(__has_feature) && __has_feature(address_sanitizer))
    check_true("the child exited with status zero",
               WIFEXITED(status) == 1 && WEXITSTATUS(status) == 0);
#endif

    (void)::munmap(out, sizeof(Observations));

    // The comparison operators. Each case passes an argument for which the
    // correct operator fires the rule and the neighbouring operators would
    // not, so a constant that decodes to the wrong instruction shows up as a
    // fallback errno where a rule errno was expected.
    //
    // Equal is the control: it is the one operator the uapi header exports,
    // so it establishes that the harness itself distinguishes the branches.
    check("Equal matches its value", probe(SeccompCmp::Equal, 10, 10),
          -kErrDenied);
    check("Equal rejects a different value", probe(SeccompCmp::Equal, 10, 11),
          -kErrFallback);

    check("NotEqual rejects its own value",
          probe(SeccompCmp::NotEqual, 10, 10), -kErrFallback);
    check("NotEqual accepts a different value",
          probe(SeccompCmp::NotEqual, 10, 11), -kErrDenied);

    check("Greater accepts a larger value", probe(SeccompCmp::Greater, 10, 11),
          -kErrDenied);
    check("Greater rejects an equal value", probe(SeccompCmp::Greater, 10, 10),
          -kErrFallback);
    check("Greater rejects a smaller value",
          probe(SeccompCmp::Greater, 10, 9), -kErrFallback);

    check("GreaterOrEqual accepts an equal value",
          probe(SeccompCmp::GreaterOrEqual, 10, 10), -kErrDenied);
    check("GreaterOrEqual accepts a larger value",
          probe(SeccompCmp::GreaterOrEqual, 10, 11), -kErrDenied);
    check("GreaterOrEqual rejects a smaller value",
          probe(SeccompCmp::GreaterOrEqual, 10, 9), -kErrFallback);

    check("Less accepts a smaller value", probe(SeccompCmp::Less, 10, 9),
          -kErrDenied);
    check("Less rejects an equal value", probe(SeccompCmp::Less, 10, 10),
          -kErrFallback);
    check("Less rejects a larger value", probe(SeccompCmp::Less, 10, 11),
          -kErrFallback);

    check("LessOrEqual accepts an equal value",
          probe(SeccompCmp::LessOrEqual, 10, 10), -kErrDenied);
    check("LessOrEqual accepts a smaller value",
          probe(SeccompCmp::LessOrEqual, 10, 9), -kErrDenied);
    check("LessOrEqual rejects a larger value",
          probe(SeccompCmp::LessOrEqual, 10, 11), -kErrFallback);

    check("Masked accepts a value with the bit set",
          probe(SeccompCmp::Masked, 0100, 0100), -kErrDenied);
    check("Masked accepts a value with the bit among others",
          probe(SeccompCmp::Masked, 0100, 0100 | 0101), -kErrDenied);
    check("Masked rejects a value without the bit",
          probe(SeccompCmp::Masked, 0100, 0), -kErrFallback);

    // A 32-bit comparison also matches a truncated value: a test for
    // argument == 0 written as a 32-bit compare would accept an argument of
    // 0x1_00000000, whose low half is zero. The builder reads the high half
    // and abandons the rule when it is non-zero, so a 64-bit argument never
    // matches a rule that only means to constrain 32 bits. This is the
    // difference between a size check and a bypass, and it is the reason the
    // high-half load is in the program at all.
    check("a 64-bit argument does not match a 32-bit equality",
          probe(SeccompCmp::Equal, 0, 0x100000000LL), -kErrFallback);
    check("a 64-bit argument does not match a 32-bit mask",
          probe(SeccompCmp::Masked, 0100, 0x100000000LL | 0100),
          -kErrFallback);

    // An action other than Errno, checked by the return value rather than by
    // the bytecode. Allow lets madvise run, and madvise with a null address
    // and a zero length fails with EINVAL, so an allow is distinguishable
    // from a deny by the fact that the errno is the kernel's and not the
    // policy's. KillProcess cannot be tested this way -- it would end the
    // child before it could report -- so it is checked as a bytecode
    // property below instead.
    {
        auto* p = static_cast<Probe*>(
            ::mmap(nullptr, sizeof(Probe), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0));
        if (p != MAP_FAILED) {
            const pid_t child = ::fork();
            if (child == 0) {
                SeccompPolicy policy;
                policy.fallback = SeccompDefault::KillProcess;
                policy.max_nr = highest_known_syscall();
                policy.rules.push_back(SeccompRule{
                    kNrMadvise, SeccompAction::Allow, 0,
                    {SeccompArgTest{2, SeccompCmp::Equal, 0}}});
                policy.rules.push_back(SeccompRule{
                    kNrExitGroup, SeccompAction::Allow, 0, {}});
                policy.rules.push_back(SeccompRule{
                    kNrRtSigreturn, SeccompAction::Allow, 0, {}});
                const auto program = build_seccomp(policy);
                p->built = program.valid() ? 1 : 0;
                (void)occ::sys::prctl(38 /* PR_SET_NO_NEW_PRIVS */, 1, 0, 0, 0);
                p->installed = occ::sys::seccomp_install(program);
                p->ret = occ::sys::detail::call6(
                             static_cast<long>(kNrMadvise), 0, 0, 0, 0, 0, 0)
                             .value;
                _exit(0);
            }
            int st = 0;
            (void)::waitpid(child, &st, 0);
            check_true("an Allow rule builds", p->built == 1);
            check("an Allow rule installs", p->installed, 0);
            // The point is that the syscall ran rather than being turned
            // into an errno by the filter. madvise(0, 0, 0) is a no-op the
            // kernel accepts, so a return of 0 is the kernel's own answer
            // and a return of -kErrFallback or -kErrDenied would mean the
            // filter had intercepted a call its rule allowed.
            check("an Allow rule lets the syscall run", p->ret, 0);
            (void)::munmap(p, sizeof(Probe));
        }
    }

    // A KillProcess fallback, verified as bytecode. Running it would kill the
    // child, so what is checked is that the program the builder emits
    // carries the kill action in the fallback slots. A fallback that was
    // accidentally Allow would be the difference between a default-deny
    // policy and no policy at all.
    {
        SeccompPolicy policy;
        policy.fallback = SeccompDefault::KillProcess;
        policy.rules.push_back(
            SeccompRule{kNrGetpid, SeccompAction::Allow, 0, {}});
        const auto program = build_seccomp(policy);
        check_true("a KillProcess fallback builds", program.valid());
        const auto* code = program.code();
        const std::size_t n = program.insn_count();

        // The program is: [0] ld arch, [1] jeq arch, [2] ret KILL, [3] ld nr,
        // [4] jgt max_nr, [5] ret FALLBACK, then the rule's three
        // instructions, then the trailing FALLBACK. Both fallback slots --
        // index 5 and the last -- must carry the kill action. The rule's own
        // action is Allow and is deliberately not checked: this policy has
        // one, and a check that demanded kill everywhere would be measuring
        // the wrong thing.
        constexpr std::uint32_t kKill = 0x80000000u; // SECCOMP_RET_KILL_PROCESS
        check("the architecture rejection is a kill",
              static_cast<long>(code[2].k), static_cast<long>(kKill));
        check("the out-of-range fallback is a kill",
              static_cast<long>(code[5].k), static_cast<long>(kKill));
        check("the trailing fallback is a kill",
              static_cast<long>(code[n - 1].k), static_cast<long>(kKill));

        // And the two must be the same instruction shape, because one of
        // them is reached by a conditional branch and the other by falling
        // off the end. A ret that only looks right in one slot is a policy
        // that leaks in the other direction.
        bool both_ret = true;
        for (const std::size_t i : {std::size_t{2}, std::size_t{5},
                                    n - 1}) {
            if ((code[i].code & 0x07) != 0x06) { // BPF_RET
                both_ret = false;
            }
        }
        check_true("every kill slot is a return instruction", both_ret);
    }

    // The instruction count the builder reports has to be the count the
    // kernel is given, because that count is what bounds the program: the
    // kernel rejects anything over 65535 and occ refuses at 65533, and a
    // count that disagreed with the vector would make both checks wrong.
    {
        SeccompPolicy policy;
        policy.fallback_error = 38;
        for (std::uint32_t nr = 0; nr < 8; ++nr) {
            policy.rules.push_back(SeccompRule{nr, SeccompAction::Errno, 22, {}});
        }
        const auto program = build_seccomp(policy);
        check_true("a multi-rule policy builds", program.valid());
        // Six instructions of preamble, then two per rule (entry and pad)
        // plus one action, then the trailing fallback.
        const std::size_t want = 6 + 8 * 3 + 1;
        check("the instruction count is what the policy implies",
              static_cast<long>(program.insn_count()),
              static_cast<long>(want));
        check("the byte count is eight per instruction",
              static_cast<long>(program.byte_count()),
              static_cast<long>(want * 8));
    }

    // An empty policy is a legitimate thing to build: it denies everything by
    // the fallback and mentions nothing. It has to produce a valid program
    // rather than an empty one, because a filter with no instructions is
    // rejected by the kernel and the caller would see an install failure
    // rather than a policy problem.
    {
        SeccompPolicy policy;
        policy.fallback = SeccompDefault::Errno;
        policy.fallback_error = 38;
        const auto program = build_seccomp(policy);
        check_true("an empty policy builds", program.valid());
        check("an empty policy still has the preamble and fallback",
              static_cast<long>(program.insn_count()), 7);
    }

    // The widest rule a policy can express. An argument index runs 0..5 and
    // the builder refuses anything higher, so a rule has at most six tests,
    // which fixes its block size at 6 * 5 + 1 instructions and its entry's
    // not-taken offset at 32. That is well inside the 255 a branch offset
    // can express, which is why the builder's own range check cannot fire
    // for any policy this API can describe.
    //
    // So the range check is unreachable by construction rather than merely
    // untested, and what is asserted here is the invariant that makes it so:
    // the widest legal rule still fits. If a future change raised the
    // argument limit above six, this assertion would fail before the
    // builder started emitting wrapped offsets, which is the point of having
    // it -- a check that cannot fail is worth nothing, and the number it
    // guards is derived rather than assumed.
    {
        SeccompPolicy widest;
        widest.fallback_error = 38;
        SeccompRule big{99, SeccompAction::Errno, 22, {}};
        for (std::uint8_t a = 0; a < 6; ++a) {
            big.args.push_back(SeccompArgTest{a, SeccompCmp::Equal, 0});
        }
        widest.rules.push_back(big);
        const auto program = build_seccomp(widest);
        check_true("a rule using all six arguments builds", program.valid());
        const auto* code = program.code();

        // Six instructions of preamble, then the entry, the pad, six tests
        // and the action, then the trailing fallback.
        const std::size_t want = 6 + 2 + 6 * 5 + 1 + 1;
        check("the widest rule is the size the layout implies",
              static_cast<long>(program.insn_count()),
              static_cast<long>(want));

        // The entry's not-taken offset is the distance past the whole block.
        // Read it back out of the emitted program rather than recomputing it,
        // so the assertion is about what the kernel will see. jf is a
        // std::uint8_t, which is the eight-bit field the protocol defines and
        // the reason the builder's range check exists; it cannot be compared
        // against 255 because it is already an eight-bit value.
        static_assert(sizeof(decltype(code[0].jf)) == 1,
                      "the jump field is one byte wide");
        const std::size_t block = 6 * 5 + 1;
        check("the widest rule's skip offset is what the layout implies",
              static_cast<long>(code[6].jf), static_cast<long>(block + 1));
    }

    // The x32 defence. A number with bit 30 set is an x32 caller, and the
    // kernel will not let it reach a native entry point. The builder's
    // ceiling has to sit above every native number and below that bit, so a
    // number carrying it is refused by the range test before any rule is
    // consulted. The check is on the emitted comparison, because a filter
    // that reached the rules first would already have decided.
    {
        check("the syscall ceiling excludes the x32 bit",
              (highest_known_syscall() & 0x40000000u) == 0 ? 1 : 0, 1);
        check("the syscall ceiling is above the native maximum",
              highest_known_syscall() > 463 ? 1 : 0, 1);

        SeccompPolicy policy;
        policy.fallback = SeccompDefault::Errno;
        policy.fallback_error = 38;
        policy.rules.push_back(
            SeccompRule{kNrWrite, SeccompAction::Errno, 22, {}});
        const auto program = build_seccomp(policy);
        check_true("a policy with a default ceiling builds", program.valid());
        const auto* code = program.code();
        // Instruction 4 is the range test: BPF_JMP | BPF_JGT | BPF_K.
        const std::uint16_t want = 0x05 | 0x20 | 0x00;
        check("the range test is a JGT against the ceiling",
              (code[4].code == want) ? 1 : 0, 1);
        check("the range test compares against the ceiling",
              static_cast<long>(code[4].k),
              static_cast<long>(highest_known_syscall()));
    }

    // A policy that sets max_nr explicitly must use that value rather than
    // the default, since a caller lowering the ceiling is a caller asking for
    // a smaller dispatch table.
    {
        SeccompPolicy policy;
        policy.fallback_error = 38;
        policy.max_nr = 100;
        policy.rules.push_back(
            SeccompRule{kNrWrite, SeccompAction::Errno, 22, {}});
        const auto program = build_seccomp(policy);
        check_true("an explicit ceiling builds", program.valid());
        check("the explicit ceiling is the one emitted",
              static_cast<long>(program.code()[4].k), 100);
    }

    // Installing a program that was never built has to fail rather than
    // install an empty filter, because an empty filter installed
    // successfully would be a filter that permits everything. A default-
    // constructed program is the only way to reach that state, since the
    // builder is the sole thing that can produce a valid one.
    {
        const occ::sys::SeccompProgram unbuilt{};
        check_true("a default-constructed program is not valid",
                   !unbuilt.valid());
        check("an unbuilt program is refused at install",
              static_cast<long>(occ::sys::seccomp_install(unbuilt)), -22);
    }

    // Installing on another thread is not supported, and saying so is the
    // point: a caller that believed a filter was active on a thread it was
    // never installed on would be wrong about the security boundary.
    {
        SeccompPolicy policy;
        policy.fallback_error = 38;
        policy.rules.push_back(
            SeccompRule{kNrWrite, SeccompAction::Errno, 22, {}});
        const auto program = build_seccomp(policy);
        const int rc = occ::sys::seccomp_install_on_thread(program, 0);
        check("installing on another thread reports unsupported",
              static_cast<long>(rc), -95);
    }

    if (g_failures != 0) {
        std::printf("%d check(s) failed\n", g_failures);
        return 1;
    }
    std::printf("all checks passed\n");
    return 0;
}

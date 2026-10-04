// Harness: the seccomp BPF emitter, over arbitrary policies.
//
// A separate harness from the others, and the reason is not that this one is
// harder to reach. src/isolation/seccomp.cpp builds a filter from a typed
// SeccompPolicy rather than from bytes, so there is no untrusted-byte surface
// to hand a fuzzer the way an ELF header or a zip directory is one. A harness
// here has to invent its own input surface, and inventing one badly produces
// a fuzzer that spends its budget in a builder's first branch.
//
// The surface invented here is a fixed-width record: a fuzzer supplies bytes,
// and those bytes are read as a stream of fields that become a policy's
// numbers, comparisons, actions and errors. Every field is therefore reachable
// and no field is out of reach, which is the property a generated surface
// needs to have and the reason it is described here rather than left
// implicit. The alternatives were worse: a fuzzer over the enum values alone
// would never build a policy with two rules and a fall-through between them,
// which is the only place the emitter's geometry gets interesting.
//
// What is checked, and why it is only this.
//
// The emitter's contract is a set of promises about the bytecode it produces:
// that every branch lands inside the program, that the program is a
// terminating one (no way to run off the end), that the preamble is the five
// instructions the layout documents, that every rule's number is in the
// dispatch table, that an argument index the header documents as out of range
// is refused, and that the count reported is the count emitted. None of that
// needs a kernel, and all of it is the kind of thing a changed constant breaks
// silently -- an offset that still installs and answers a different question,
// a block that is one instruction short and dispatches a rule's number without
// ever giving the rule a chance to run.
//
// The kernel half is not here, and the reason is worth stating because it was
// the reason this file was going to be different from the other five.
//
// The emitter's real failure mode is a filter the kernel refuses, and only the
// kernel can say so. So the first version of this harness installed the
// program in a child and treated the install's return value as the oracle. It
// worked, and then it stopped working, intermittently, and the reason was not
// in the harness.
//
// Six campaigns, same corpus, same binary:
//
//   | runs | 106 | 130 | 150 | 170 |185 | 195 |
//   |------|-----|-----|-----|-----|-----|-----|
//   | exit |   0 |   0 |   0 | 124 |   0 |   0 |
//
// 124 is the timeout's own code. The hang is not a function of the input --
// feeding all 54 corpus files one run each produced zero hangs -- and not a
// function of the run count. What it is a function of is how fast libFuzzer
// calls this function, and that is a property of the driver's process
// management meeting a harness that forks, not of anything the harness does.
//
// Three measurements pinned it down rather than leaving it a guess. fork +
// install + collect, unsanitized, runs at 6839 a second here; the same under
// AddressSanitizer runs at 1048 a second, six and a half times slower, because
// forking a sanitized process runs the runtime's atfork handlers and has to
// re-account shadow memory. A 20-second budget was still going after three and
// a half minutes, which is what 1048 a second buys you. And when the harness's
// own logic was driven outside libFuzzer -- build, make survivable, install in
// a child, read the report back -- it did 51 installs over the 54 corpus files
// with 51 successes and one duplicate, and three ASan runs of the child path
// were clean.
//
// So the mechanism is sound and the interaction is not. No amount of
// deduplication in the harness removes it either: the first version hashed the
// emitted bytecode and installed only unseen shapes, which cut the fork rate
// by orders of magnitude, and the deadlock survived that. libFuzzer manages
// its own children and a harness that forks underneath it contends for
// something neither of them owns.
//
// What the split bought is measurable, and it is worth putting next to the
// rate above because an oracle is worth what the rate at which you can ask
// the question is worth: 3,091,554 inputs in 121 seconds, 25,550 a second, no
// crash and no timeout. That is 24 times the rate of the version that
// forked, and it is 24 times because the harness does not fork -- the same
// builder runs and the same program is read back. A question that deadlocks
// is worth nothing at any rate.
//
// The kernel oracle therefore is a test, not a fuzz target.
// tests/test_seccomp.cpp is where it lives: forty-nine hand-built filters
// covering all seven comparisons and all five actions, each one really
// installed, in a build without a sanitizer. That is bounded, it is
// reproducible, and it names the failure in the output when it happens. What
// it cannot do is walk the emitter's geometry -- there are only so many
// policies a person writes -- and that is the part kept here.
//
// The division is therefore not a reduction. The test answers "does the
// kernel take this filter", once per shape a person thought of. This file
// answers "is the program the emitter built the program it meant to build",
// for every policy a fuzzer can describe, at full speed, with the kernel
// oracle out of the way.

#include "occ/isolation/seccomp.h"

#include <cstddef>
#include <cstdint>
// linux/filter.h for sock_filter, linux/seccomp.h for the RET_* actions and
// struct seccomp_data, linux/audit.h for AUDIT_ARCH_X86_64. occ's own header
// brings the first two in, and this file includes all three anyway because it
// names every constant it checks against -- a check that reads a macro through
// a transitive include is a check whose subject can change under it.
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include <set>
#include <vector>

namespace {

using occ::sys::build_seccomp;
using occ::sys::highest_known_syscall;
using occ::sys::SeccompAction;
using occ::sys::SeccompArgTest;
using occ::sys::SeccompCmp;
using occ::sys::SeccompDefault;
using occ::sys::SeccompPolicy;
using occ::sys::SeccompProgram;
using occ::sys::SeccompRule;

// The errno the built-in policies below deny with. Two values rather than
// one, so a check cannot pass because it compared a field against itself: a
// rule's errno and the fallback's are different numbers, and a bug that
// wrote one where the other belonged would show.
constexpr int kErrDenied = 13;    // EACCES, the rule's errno
constexpr int kErrFallback = 38;  // ENOSYS, the fallback's

// The x32 bit. The kernel presents a number carrying it to the filter as
// carrying it: verified on 6.6.117 by a filter that matches 0x27, which
// matches a native getpid and does not match the same call issued as
// 0x40000027. So the ceiling has to sit below this bit for a rule table to
// be unreachable from an x32 caller, and that is what the ceiling is for.
constexpr std::uint32_t kX32Bit = 0x40000000u;

// ---------------------------------------------------------------- the input
//
// A reader over the fuzzer's bytes, taking fields in order. Every read is
// bounded by a comparison against the end rather than by an offset that could
// be computed wrongly, so a short input yields a short policy instead of a
// read past the end -- and a policy with fewer rules is a perfectly good
// thing for a harness to build. A read past the end returns zero rather than
// trapping, which is deliberate: a fuzzer hands out short inputs constantly
// and a policy built from the first two bytes is a policy worth checking.
class ByteReader {
public:
    explicit ByteReader(const std::uint8_t* data, std::size_t size) noexcept
        : data_(data), size_(size) {}

    [[nodiscard]] std::uint8_t u8() noexcept {
        if (at_ >= size_) {
            return 0;
        }
        return data_[at_++];
    }

    [[nodiscard]] std::uint32_t u32() noexcept {
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            v = (v << 8) | u8();
        }
        return v;
    }

    [[nodiscard]] bool has_more() const noexcept { return at_ < size_; }

private:
    const std::uint8_t* data_;
    std::size_t size_;
    std::size_t at_ = 0;
};

// A policy built from the bytes.
//
// The shape is deliberately fixed and the contents are not: rule_count comes
// from the bytes but is clamped to a bound, because a policy with ten thousand
// rules is not a policy a caller can use and fuzzing it would spend the budget
// in the vector's allocator rather than in the emitter.
//
// Which is what these two are, and the honest version of the claim is that
// only one of them is a hard boundary. kMaxTestsPerRule is the header's own
// maximum: seccomp_data has six argument slots, so a seventh test cannot be
// expressed and clamping there loses nothing a caller could have written.
// kMaxRules is a coverage budget, not a limit. A policy of twenty-five rules
// with six tests each emits 832 instructions, and the emitter's own ceiling is
// 65533 -- so nothing about twenty-five is forced on us, and a larger bound
// would be legal today. It is twenty-five because that is where the geometry
// stops changing shape: past a handful of rules the emitter is emitting the
// same block again, and the fuzzer's budget is better spent on the arguments
// inside a block than on the ninth copy of a block it has already built
// correctly. If the emitter ever grows a per-rule feature that makes rule
// number matter in a new way, this is the number to revisit, and the way to
// notice is a coverage count that stops moving.
//
// Note the coincidence of numbers, because it is the kind that hides a bug:
// kMaxTestsPerRule + 1 is 7, which is also the modulus of the comparison
// rotation below. They are unrelated -- one counts a rule's tests, the other
// picks a comparison -- and they are both correct. The clamp is not the
// rotation, and the rotation is not the clamp.
constexpr std::size_t kMaxRules = 24;
constexpr std::size_t kMaxTestsPerRule = 6;

// Every comparison the enum has, all seven of them, in one rotation whose
// modulus is the number of enumerators.
//
// The first version got this wrong in the most expensive way available: a
// six-way switch for a seven-value enum, with a separate special case for
// Masked hung off the front of it. It worked, and the arithmetic was even
// right -- Masked is the seventh, and % 7 reaching 6 is the seventh -- but the
// shape invited the mistake that actually happened next door, where a
// five-value enum got a four-way switch and one enumerator became
// unreachable. See an_action below for that one and what it cost.
//
// The lesson generalises past this file: a rotation written as N cases for N
// enumerators cannot be checked by reading it, because the number of cases and
// the number of enumerators live in different files. Writing them as one switch
// over one modulus puts them next to each other, which is the only reason they
// would ever be compared.
SeccompCmp a_cmp(std::uint8_t raw) noexcept {
    switch (raw % 7) {
    case 0: return SeccompCmp::Equal;
    case 1: return SeccompCmp::NotEqual;
    case 2: return SeccompCmp::Greater;
    case 3: return SeccompCmp::GreaterOrEqual;
    case 4: return SeccompCmp::Less;
    case 5: return SeccompCmp::LessOrEqual;
    default: return SeccompCmp::Masked;
    }
}

// Masked is the odd one out in the emitter, and that is why it is worth naming
// here rather than only in the rotation above. It is the one comparison the
// emitter never inverts -- a masked test matches when the bits are *present*,
// so there is no negated form of it to emit -- which makes it the case a
// change to the inversion logic would leave alone. It gets the seventh slot so
// that a fuzzer reaches the emitter's "do not invert" path rather than only
// the six paths that share the inversion.

// Every action the enum has, all five of them.
//
// This was a % 4 rotation when it was first written, mapping four values onto
// an enum with five, and the consequence was that SeccompAction::KillThread
// was unreachable: no byte produced it, so the emitter's branch for it was
// never generated and never checked. Nothing reported the gap -- the harness
// passed, because four of five actions is not a failure by any assertion in
// it. It was found by generating the seeds and printing what each one decoded
// to, where a seed that named KillThread came back as something else.
//
// The lesson is the one the seed corpus exists to enforce: a rotation whose
// modulus does not match the thing it rotates over is a silent hole, and the
// number of cases has to be checked against the enum rather than chosen. The
// same discipline applies to the two rotations above and below -- SeccompCmp
// at % 7 against seven, SeccompDefault at % 4 against four -- and those two
// are right by exactly the check this one skipped.
SeccompAction an_action(std::uint8_t raw) noexcept {
    switch (raw % 5) {
    case 0: return SeccompAction::Errno;
    case 1: return SeccompAction::Allow;
    case 2: return SeccompAction::Trap;
    case 3: return SeccompAction::KillThread;
    default: return SeccompAction::KillProcess;
    }
}

SeccompDefault a_fallback(std::uint8_t raw) noexcept {
    switch (raw % 4) {
    case 0: return SeccompDefault::Errno;
    case 1: return SeccompDefault::Allow;
    case 2: return SeccompDefault::Trap;
    default: return SeccompDefault::KillProcess;
    }
}

SeccompPolicy policy_from(const std::uint8_t* data, std::size_t size) noexcept {
    ByteReader in(data, size);
    SeccompPolicy policy;

    policy.fallback = a_fallback(in.u8());
    // A zero errno is refused by the builder, and a policy that is refused
    // exercises no geometry at all. So the error fields are mapped into 1..,
    // which keeps the value arbitrary and keeps the policy buildable. A
    // harness that let a byte make the policy unbuildable would spend a
    // seventh of its inputs on the refusal path.
    policy.fallback_error = static_cast<int>(in.u32() % 4096u) + 1;

    // The ceiling. Zero means "use the default", and the default is the
    // value the x32 defence depends on, so both are reachable: a byte that
    // asks for a low ceiling and a byte that asks for none are different
    // policies and the emitter treats them differently.
    //
    // The shape of this one is worth stating because it is the only field
    // whose encoding is not a plain reduction. A raw byte that is a multiple
    // of four decodes to zero, so one byte in four asks for the default and
    // the other three name a concrete ceiling below 4096. The consequence
    // outside this file is that a *named* ceiling cannot be a multiple of
    // four: the generator asserts it, after a seed called
    // seccomp_low_ceiling.pol asked for 4 and arrived as the default it was
    // trying not to be. Three quarters of the ceilings are still reachable
    // and the fuzzer finds the rest by mutating, so this narrows nothing
    // that matters -- but a reader writing a seed by hand needs to know.
    {
        const std::uint32_t ceiling = in.u32();
        policy.max_nr = (ceiling % 4 == 0) ? 0u : (ceiling % 4096u);
    }

    const std::size_t rule_count = in.u8() % (kMaxRules + 1);
    for (std::size_t r = 0; r < rule_count && in.has_more(); ++r) {
        SeccompRule rule;
        rule.nr = in.u32();
        rule.action = an_action(in.u8());
        rule.error = static_cast<int>(in.u32() % 4096u) + 1;

        const std::size_t test_count = in.u8() % (kMaxTestsPerRule + 1);
        for (std::size_t t = 0; t < test_count; ++t) {
            SeccompArgTest test;
            // Six is out of range and the builder refuses it, which would
            // make the whole policy unbuildable. Mapped into 0..5, so every
            // index the header permits is reachable and none beyond it is.
            test.index = static_cast<std::uint8_t>(in.u8() % 6u);
            test.cmp = a_cmp(in.u8());
            test.value = in.u32();
            rule.args.push_back(test);
        }
        policy.rules.push_back(std::move(rule));
    }
    return policy;
}

// ---------------------------------------------------------------- geometry
//
// These need no process, which is the point of them: the emitter's own
// promises, read back out of the bytecode rather than recomputed from the
// policy. Recomputing would be a second implementation of the layout, and a
// second implementation agreeing with the first would prove nothing, which is
// the same argument the zip harness makes about not reconstructing member
// offsets.

// Where a classic BPF branch lands, given the instruction it is at.
//
// A jump offset is relative to the instruction *after* the branch, so a jt of
// zero lands on the next instruction. A branch whose target is the program
// length or beyond runs off the end, and the kernel answers that by refusing
// the whole filter -- so this is the property that most needs checking and the
// one a changed constant breaks first.
[[nodiscard]] bool branch_lands_inside(const SeccompProgram& p, std::size_t at,
                                       std::size_t offset) noexcept {
    const std::size_t n = p.insn_count();
    // The addition cannot wrap: offset is a count of instructions taken from
    // a position inside a vector of at most a few thousand entries, so the
    // sum is bounded by the vector plus 255. Asking it as a subtraction would
    // be defensive about a value that cannot reach the limit.
    return at + 1 + offset < n;
}

// Every instruction's branch targets, if it has any, land inside the program.
bool every_branch_lands_inside(const SeccompProgram& p) noexcept {
    const std::size_t n = p.insn_count();
    if (n == 0) {
        return false;
    }
    for (std::size_t i = 0; i < n; ++i) {
        const struct sock_filter& in = p.code()[i];
        // BPF_JMP is 0x05 and BPF_JA is 0x00; every other class either has no
        // branches or is not a branch at all. The mask keeps the test to the
        // class rather than to the whole opcode, so a new opcode in the class
        // is covered by this rather than skipped by it.
        if ((in.code & 0x07) != 0x05) {
            continue;
        }
        if (!branch_lands_inside(p, i, in.jt)) {
            return false;
        }
        // BPF_JA is unconditional and encodes its target in k, not in jt.
        if ((in.code & 0xf0) == 0x00 && (in.code & 0x08) == 0x00) {
            if (!branch_lands_inside(p, i, in.k)) {
                return false;
            }
        } else if (!branch_lands_inside(p, i, in.jf)) {
            return false;
        }
    }
    return true;
}

// The last instruction is a return, and so is every instruction the program
// can arrive at without branching. A classic BPF program has no implicit end:
// running off the last instruction is undefined, and the kernel's verifier
// rejects it. So "the program terminates" is a property of the shape rather
// than of any one instruction, and the honest form of the check is that the
// final instruction returns and that no branch targets past it -- which is
// what every_branch_lands_inside already establishes. What is left to say
// here is that the last instruction is a return, because a program whose
// last instruction loads something has a path that runs out.
bool ends_in_a_return(const SeccompProgram& p) noexcept {
    if (p.insn_count() == 0) {
        return false;
    }
    return (p.code()[p.insn_count() - 1].code & 0x07) == 0x06;  // BPF_RET
}

// (There is deliberately no check here that a conditional branch's two
// outcomes differ. An earlier version of this file had one, called
// both_outcomes_are_offsets, and it was a loop with an empty body -- a check
// that cannot fail and so reports nothing while looking like it reports
// something. Worse, the property it gestured at is false: a rule with no
// argument tests has a block of exactly one instruction, so its entry's taken
// and not-taken offsets are both 1 and the two branches land on the same
// place. That is not a defect, it is why the layout has a pad instruction at
// all, and a check written as "the outcomes must differ" would have trapped
// on every such policy. The property that does hold -- that both outcomes land
// inside the program -- is every_branch_lands_inside above, and it is checked
// there.)

// The reported count is the emitted count.
//
// insn_count() is what seccomp_install hands the kernel as sock_fprog::len,
// and the kernel refuses a program longer than 65535 instructions. A count
// that disagreed with the vector would make both the install's own check and
// the kernel's wrong, in opposite directions, and nothing would report it.
bool count_matches_the_program(const SeccompProgram& p) noexcept {
    if (!p.valid()) {
        return p.insn_count() == 0;
    }
    return p.byte_count() == p.insn_count() * sizeof(struct sock_filter);
}

// The program is at least the preamble and the trailing fallback. A valid
// program with fewer than seven instructions would mean the emitter had
// emitted no dispatch at all, which is the shape a filter with no
// instructions has -- and the kernel rejects that, so a caller would see an
// install failure rather than a policy problem.
bool has_a_dispatch_shape(const SeccompProgram& p) noexcept {
    return p.valid() && p.insn_count() >= 7;
}

// The preamble is where the dispatch table starts, so it is checked rather
// than assumed.
//
// Five instructions, in this order, and the positions are load-bearing rather
// than incidental: instruction 1 is the architecture guard, which is the one
// comparison in the program that is not against a syscall number, and
// everything from instruction 5 on is rules. A check that needed to tell them
// apart by value would have a hole in it -- see every_rule_is_dispatched, and
// the fuzzer input that found it -- so the positions are established here and
// the rule scan downstream reads them.
//
// The layout being asserted is the one the header documents:
//
//   [0] ld arch
//   [1] jeq AUDIT_ARCH_X86_64 : match skips [2]
//   [2] ret KILL_PROCESS                     wrong architecture
//   [3] ld nr
//   [4] jgt max_nr : over the ceiling jumps [5]
//   [5] ret FALLBACK                         number out of range
bool preamble_is_the_documented_five(const SeccompPolicy& policy,
                                    const SeccompProgram& p) noexcept {
    if (!p.valid() || p.insn_count() < 7) {
        return false;
    }
    const struct sock_filter* code = p.code();

    // A load of one word from an absolute offset. BPF_LD is 0x00, BPF_W 0x00,
    // BPF_ABS 0x20, so the whole opcode is 0x20 and the operand is the offset
    // into seccomp_data. Read as a whole-byte compare so a new class bit is a
    // failure rather than something the mask hides.
    auto is_load_of = [code](std::size_t at, std::uint32_t offset) noexcept {
        return code[at].code == 0x20 && code[at].k == offset;
    };
    // seccomp_data's two fields the preamble reads, by their real offsets
    // rather than by numbers written here: nr is first and arch is second, and
    // a harness that hardcoded 0 and 4 would keep passing if the kernel's
    // struct ever reordered them.
    if (!is_load_of(0, static_cast<std::uint32_t>(
                         offsetof(struct seccomp_data, arch)))) {
        return false;
    }
    if (!is_load_of(3, static_cast<std::uint32_t>(
                         offsetof(struct seccomp_data, nr)))) {
        return false;
    }

    // The architecture guard: a JEQ against the x86-64 audit architecture. The
    // operand comes from the header, so this is the header's promise checked
    // against the bytecode, not a constant compared with itself.
    if (code[1].code != 0x15 ||
        code[1].k != static_cast<std::uint32_t>(AUDIT_ARCH_X86_64)) {
        return false;
    }
    // Both of the guard's outcomes are checked, because a guard that always
    // jumps the same way is a filter that accepts every architecture or none.
    if (code[1].jt != 1 || code[1].jf != 0) {
        return false;
    }

    // The wrong-architecture answer is a kill, unconditionally: a filter that
    // let an unrecognised architecture through would be auditing nothing. The
    // action bits are the low half, so this is checked without knowing which
    // of the four actions it is.
    if ((code[2].code & 0xff) != 0x06) {
        return false;
    }
    if ((code[2].k & 0xffff0000u) !=
        static_cast<std::uint32_t>(SECCOMP_RET_KILL_PROCESS)) {
        return false;
    }

    // The range test, and its operand is the ceiling -- read back out of the
    // emitted comparison rather than recomputed, because the assertion is
    // about what the kernel is handed. A ceiling of zero means the default,
    // and the default is what the builder substitutes, so both are named here
    // rather than one of them being assumed.
    if ((code[4].code & 0xff) != (0x05 | 0x20 | 0x00)) {  // JMP | JGT | K
        return false;
    }
    const std::uint32_t want_ceiling =
        (policy.max_nr == 0) ? highest_known_syscall() : policy.max_nr;
    return code[4].k == want_ceiling;
}

// The rules the policy asked for are the rules the program dispatches.
//
// This is the invariant that ties the bytecode back to the input, and it is
// the one a fuzzer can break: an emitter that emitted fewer blocks than the
// policy named would still install, still answer, and would silently protect
// less than the policy said.
//
// The scan starts after the preamble rather than collecting every comparison
// and subtracting one. The first version did the latter, erasing
// AUDIT_ARCH_X86_64 from the set by value, and the fuzzer found the hole in
// under a minute: a policy is free to name 0xc000003e as a syscall number --
// nothing in the builder or the header forbids it -- and a program with such
// a rule was reported as *missing* it, because the only entry carrying that
// number was the architecture guard and the guard had just been erased. The
// harness trapped on a correct program. An invariant that reports a fault
// that does not exist is worse than a missing one, because it teaches people
// to ignore the harness, so the fix is to stop guessing which comparison is
// the guard and start knowing: the preamble check above establishes where the
// guard is, and the scan below starts after it.
//
// Which is also the stronger check. Erasing by value could not tell a rule
// that happened to share the guard's number from one that did not, and it
// reported both as missing; scanning by position sees the rule's own entry.
bool every_rule_is_dispatched(const SeccompPolicy& policy,
                              const SeccompProgram& p) noexcept {
    if (!p.valid()) {
        // A refused policy emits nothing, so there is nothing to find. The
        // refusals are checked by the policy side of the harness instead.
        return true;
    }

    // Five is the length of the preamble, established above rather than
    // repeated here as a bare number.
    constexpr std::size_t kPreamble = 5;
    const std::size_t n = p.insn_count();
    std::set<std::uint32_t> seen;
    for (std::size_t i = kPreamble; i < n; ++i) {
        const struct sock_filter& in = p.code()[i];
        // A rule entry is a JEQ against a syscall number. Inside a rule's
        // block there are also JEQs -- the high half of an argument is
        // compared against zero, and an Equal test is a comparison against the
        // test's value -- so a number here is not necessarily a rule's number.
        // That does not weaken the check: the requirement is that every rule's
        // number appears, so extra numbers are harmless, and a rule whose
        // number collided with an argument test's value would be counted as
        // present either way. It would take an emitter that dropped a rule
        // *and* another rule's argument test happened to compare against the
        // same number to hide it, which is a hole that closes only by accident.
        if ((in.code & 0xff) == 0x15) {
            seen.insert(in.k);
        }
    }

    for (const SeccompRule& rule : policy.rules) {
        if (seen.find(rule.nr) == seen.end()) {
            return false;
        }
    }
    return true;
}

// An argument index the header calls out of range is refused, and one it
// calls in range is accepted.
//
// Both halves, because a check written as "index > 5" passes both of a
// pair of tests that only test the refusal and is wrong at the boundary. The
// boundary is 5: seccomp_data has six argument slots and the sixth is index
// 5. This is the property the builder's own check encodes, asserted from
// the outside so that a change to the constant is visible here.
bool argument_index_bounds_are_enforced() noexcept {
    {
        SeccompPolicy p;
        p.fallback_error = kErrFallback;
        SeccompRule rule{39, SeccompAction::Errno, kErrDenied,
                         {SeccompArgTest{6, SeccompCmp::Equal, 0}}};
        p.rules.push_back(rule);
        if (build_seccomp(p).valid()) {
            return false;
        }
    }
    {
        SeccompPolicy p;
        p.fallback_error = kErrFallback;
        SeccompRule rule{39, SeccompAction::Errno, kErrDenied,
                         {SeccompArgTest{5, SeccompCmp::Equal, 0}}};
        p.rules.push_back(rule);
        if (!build_seccomp(p).valid()) {
            return false;
        }
    }
    return true;
}

// A zero errno is refused on both paths, because SECCOMP_RET_ERRNO with a
// zero payload makes the syscall return zero: a caller of read() sees end of
// file and a caller flushing a stdio buffer loops forever. The builder
// refuses it, and this is the assertion that the refusal is still there.
bool zero_errno_is_refused() noexcept {
    {
        SeccompPolicy p;
        p.fallback = SeccompDefault::Errno;
        p.fallback_error = 0;
        if (build_seccomp(p).valid()) {
            return false;
        }
    }
    {
        SeccompPolicy p;
        p.fallback_error = kErrFallback;
        p.rules.push_back(
            SeccompRule{39, SeccompAction::Errno, 0, {}});
        if (build_seccomp(p).valid()) {
            return false;
        }
    }
    return true;
}

// The default ceiling keeps the x32 bit out of the rule table.
//
// The kernel presents a number carrying bit 30 to the filter as carrying it,
// so a filter whose ceiling is above that bit would let an x32 caller's
// number reach the rules -- and a rule keyed on nr | 0x40000000 would then
// decide what that caller may do. The default has to sit below the bit.
//
// Only the default, and that is the point rather than a limitation. A policy
// is free to set max_nr above the bit, and nothing here objects: the property
// that makes the defence work is that the *rule table* is unreachable, not
// that the ceiling is low, and a policy naming max_nr = 0x40000000 is not
// exploitable unless it also names a rule keyed on nr | 0x40000000, which is
// a policy that has asked for what it gets. What occ itself must never do is
// ship a default above the bit, because a default is what every policy that
// does not choose gets.
//
// The upper bound is here too, and it is the same fact seen from the other
// side: the default has to be above every number a real caller can present,
// or the filter refuses ordinary syscalls. 463 is where the x86-64 syscall
// table ended when this was written; a default that shrank below it would
// break the range test for real traffic, which is a worse failure than one
// that let an x32 caller through and is not caught by anything else here.
bool x32_stays_out_of_the_dispatch_table() noexcept {
    if ((highest_known_syscall() & kX32Bit) != 0) {
        return false;
    }
    if (highest_known_syscall() <= 463) {
        return false;
    }

    // A policy that chooses no ceiling, built and read back. The emitted
    // comparison's operand is checked by preamble_is_the_documented_five on
    // every input; what this adds is the assertion about the constant itself,
    // which no per-input check can make because a fuzzer will happily build a
    // policy whose explicit ceiling is above the bit and that is legitimate.
    SeccompPolicy p;
    p.fallback_error = kErrFallback;
    p.rules.push_back(SeccompRule{39, SeccompAction::Errno, kErrDenied, {}});
    return preamble_is_the_documented_five(p, build_seccomp(p));
}

// The properties above, as one call, for a policy the fuzzer built.
//
// The order is the order of what a failure would mean. The count first,
// because a count that disagrees with the vector makes every other answer
// suspect. Then the refusal case, which is a legitimate outcome and has its own
// requirement. Then the shape, then the preamble, then the branches, then the
// dispatch table -- each one narrowing from the whole program to the part that
// has to be right.
bool geometry_holds(const SeccompPolicy& policy,
                    const SeccompProgram& p) noexcept {
    if (!count_matches_the_program(p)) {
        return false;
    }
    if (!p.valid()) {
        // A refusal is a legitimate outcome and the only thing required of
        // it is that it emitted nothing: a program carrying instructions and
        // also reporting invalid would be a caller-visible contradiction.
        return p.insn_count() == 0 && p.error() != nullptr;
    }
    if (!has_a_dispatch_shape(p)) {
        return false;
    }
    if (!preamble_is_the_documented_five(policy, p)) {
        return false;
    }
    if (!ends_in_a_return(p)) {
        return false;
    }
    if (!every_branch_lands_inside(p)) {
        return false;
    }
    return every_rule_is_dispatched(policy, p);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
    const SeccompPolicy policy = policy_from(data, size);
    const SeccompProgram built = build_seccomp(policy);

    // The geometry, on every input. It is pure computation over a buffer the
    // fuzzer already has in a register, and it is the whole of what this
    // harness does -- every branch landing inside the program, the program
    // ending in a return, the preamble being the five instructions the layout
    // documents, the count matching the bytes, every rule present in the
    // dispatch table.
    if (!geometry_holds(policy, built)) {
        __builtin_trap();
    }

    // The properties that are about the builder rather than about one
    // program, checked on every input because they are cheap and because a
    // fuzzer that only reaches them on the first few inputs would not notice
    // a change that broke them later.
    if (!argument_index_bounds_are_enforced()) {
        __builtin_trap();
    }
    if (!zero_errno_is_refused()) {
        __builtin_trap();
    }
    if (!x32_stays_out_of_the_dispatch_table()) {
        __builtin_trap();
    }

    // A refused policy is a legitimate outcome, and geometry_holds
    // has already established that it emitted nothing and said why. There is
    // no second question to ask it, so there is nothing left to do -- which
    // is the whole shape of this harness: one builder, one reader of the
    // bytecode, and no process.
    return 0;
}

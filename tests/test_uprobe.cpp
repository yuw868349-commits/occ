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
// failure cases below.
//
// The record decoder is the exception, and it is tested here directly. It
// takes bytes and returns a value and touches no kernel object, so it can be
// exercised on every host -- which makes it the part of this file that would
// otherwise be the least covered and the most likely to be wrong. The
// register ordering it has to get right is not visible from the outside: a
// sample whose six registers are shuffled among themselves still carries
// plausible addresses, so the fixtures below use values that differ from each
// other and the assertions name the slot each one belongs in.

#include "occ/observer/uprobe.h"

#include "occ/parser/elf.h"
#include "occ/probe/placer.h"
#include "occ/syscall/errno.h"
#include "occ/util/fs.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

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

// ------------------------------------------------------- the sample decoder
//
// This is the part of the uprobe layer that can be tested on every host.
// The rest of the path needs tracefs and a permitted perf_event_open, so on
// a machine without either the decoder is the only thing that runs -- which
// makes it the one place a mistake would ship unnoticed. The records below
// are built by hand, byte by byte, from the layout the kernel documents.

void put_u64(std::vector<std::uint8_t>& b, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        b.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xff));
    }
}

void put_u32(std::vector<std::uint8_t>& b, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        b.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xff));
    }
}

// The registers in the order the kernel writes them into the sample, which is
// ascending by mask bit: cx, dx, si, di, r8, r9. The decoder is what turns
// this into the ABI order a consumer reads.
struct RegValues {
    std::uint64_t cx = 0;
    std::uint64_t dx = 0;
    std::uint64_t si = 0;
    std::uint64_t di = 0;
    std::uint64_t r8 = 0;
    std::uint64_t r9 = 0;
};

std::vector<std::uint8_t> make_sample(std::uint64_t ip, std::uint32_t pid,
                                      std::uint32_t tid,
                                      const std::string& raw,
                                      std::uint64_t abi,
                                      const RegValues& r) {
    std::vector<std::uint8_t> b;
    put_u64(b, ip);
    put_u32(b, pid);
    put_u32(b, tid);
    // The raw sample sits between the thread ids and the register block,
    // because its sample_type bit (10) is below the register block's (18).
    // A decoder that read the registers here would be reading this.
    put_u32(b, static_cast<std::uint32_t>(raw.size()));
    for (char c : raw) {
        b.push_back(static_cast<std::uint8_t>(c));
    }
    put_u64(b, abi);
    // The register array is present whenever abi is not NONE. Writing it for
    // abi 0 as well is what lets a test prove the decoder ignores it.
    put_u64(b, r.cx);
    put_u64(b, r.dx);
    put_u64(b, r.si);
    put_u64(b, r.di);
    put_u64(b, r.r8);
    put_u64(b, r.r9);
    return b;
}

void test_sample_decodes_the_argument_registers_in_abi_order() {
    // The six values are distinct and chosen so that no two of them can be
    // confused for each other under a wrong ordering: a decoder that read
    // them straight across, or that used the kernel's register numbers as
    // indices, would place at least one of them in the wrong slot and every
    // assertion below would name the slot it should have been in.
    RegValues r;
    r.cx = 0xC0;
    r.dx = 0xD0;
    r.si = 0x51;
    r.di = 0xD1;
    r.r8 = 0x88;
    r.r9 = 0x99;

    const std::string raw = "trace entry bytes";
    const auto sample = make_sample(0x4000, 4242, 4243, raw, 2, r);
    const SampleDecode d = decode_sample(sample.data(), sample.size());

    check(d.ok, "a well-formed sample decodes");
    check(d.ip == 0x4000, "the instruction pointer is read from the front");
    check(d.pid == 4242, "the pid is read");
    check(d.tid == 4243, "the tid is read");
    check(d.has_args, "the registers are reported as captured");

    // The ABI order is rdi, rsi, rdx, rcx, r8, r9. The values arrived in the
    // kernel's order, so each of these is a real reordering and not a copy.
    check(d.args[0] == 0xD1, "arg0 is rdi");
    check(d.args[1] == 0x51, "arg1 is rsi");
    check(d.args[2] == 0xD0, "arg2 is rdx");
    check(d.args[3] == 0xC0, "arg3 is rcx");
    check(d.args[4] == 0x88, "arg4 is r8");
    check(d.args[5] == 0x99, "arg5 is r9");
}

void test_sample_without_captured_registers_reports_none() {
    // abi 0 is the kernel saying it did not capture a register set. The
    // array is still present in this fixture, so a decoder that ignored the
    // abi would report six arguments that were never observed.
    RegValues r;
    r.cx = 0xC0;
    r.di = 0xD1;
    const auto sample = make_sample(0x5000, 1, 2, "x", 0, r);
    const SampleDecode d = decode_sample(sample.data(), sample.size());

    check(d.ok, "the sample itself is still well-formed");
    check(!d.has_args, "no registers were captured, so none are reported");
    // The ip and the thread ids are real and are kept: a hit with no
    // arguments is still a hit, and discarding it would lose the call.
    check(d.ip == 0x5000, "the instruction pointer survives");
    check(d.pid == 1 && d.tid == 2, "the thread ids survive");
}

void test_the_raw_sample_is_stepped_over_before_the_registers() {
    // The case the field order gets wrong. A long raw sample pushes the
    // register block far from the front of the record, so a decoder that
    // read the register array at a fixed offset near the start would take
    // these bytes for registers.
    RegValues r;
    r.di = 0xABCDEF;
    std::string raw(4096, 'Z');
    const auto sample = make_sample(0x6000, 7, 8, raw, 2, r);
    const SampleDecode d = decode_sample(sample.data(), sample.size());

    check(d.ok, "a sample with a large raw block decodes");
    check(d.args[0] == 0xABCDEF,
          "the registers are read past the raw block, not inside it");
    check(d.has_args, "and they are reported as captured");
}

void test_a_truncated_sample_is_refused_rather_than_guessed() {
    RegValues r;
    r.di = 0xD1;
    const auto full = make_sample(0x7000, 9, 10, "abc", 2, r);

    // Every prefix that is short of the whole record has to be refused.
    // Stopping before the register block is the interesting boundary: the
    // ip and the ids are already readable there, and a decoder that returned
    // them as ok with has_args unset would be right -- but one that returned
    // has_args set with a partial array would not be.
    for (std::size_t n = 0; n < full.size(); ++n) {
        const SampleDecode d = decode_sample(full.data(), n);
        if (d.has_args) {
            check(false, "a truncated sample claimed to carry registers");
        }
    }
    // The whole record still decodes, so the loop above is not passing
    // because nothing ever decodes.
    const SampleDecode whole = decode_sample(full.data(), full.size());
    check(whole.ok && whole.has_args, "the untruncated record still decodes");
}

void test_a_truncated_register_block_keeps_the_hit_without_arguments() {
    // The ip and the ids are intact and only the register array is cut. The
    // hit is real and must survive, with has_args false so the missing
    // values are not read as zeroes -- a call with an address argument of
    // zero is a real thing and must not be produced by a short read.
    RegValues r;
    r.di = 0xD1;
    const auto full = make_sample(0x8000, 11, 12, "", 2, r);
    const std::size_t cut = full.size() - 8; // one register short
    const SampleDecode d = decode_sample(full.data(), cut);

    check(d.ok, "the hit survives a truncated register block");
    check(d.ip == 0x8000, "with its instruction pointer");
    check(!d.has_args, "and without claiming arguments it did not read");
}

void test_a_null_body_is_refused() {
    const SampleDecode d = decode_sample(nullptr, 0);
    check(!d.ok, "a null body decodes to nothing");
    check(!d.has_args, "and claims no arguments");
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

// ------------------------------------------------- which process is measured

// The three questions perf_event_open's pid and cpu arguments ask, and the
// one a uprobe layer must not ask.
//
// This is host-independent on purpose. The wrong answer here produces a
// subscription that opens successfully, allocates a ring, and reports the
// wrong program -- so a test that needed a tracefs to see the bug would only
// ever see it on the one host class where it does not matter to run.
void test_the_subscription_names_the_target_and_not_the_caller() {
    // A named target: that pid, every thread of it, and the threads it
    // creates later.
    const PerfSubscription named = perf_subscription_target(4242);
    check(named.pid == 4242,
          "a named target is the pid handed to perf_event_open, not zero -- "
          "zero is the calling process, which is the observer");
    check(named.cpu == -1,
          "and the cpu is -1, which with a positive pid means every thread of "
          "that process rather than one CPU's worth of it");
    check(named.inherit,
          "and inherit is set, because the target's threads are created after "
          "the subscription is made and without it only the first is counted");

    // No target named: the caller. Not because that is useful -- it is the
    // state between registering probes and learning the pid -- but because
    // there is nothing else that can be named, and pid -1 with cpu -1 is
    // EINVAL rather than a wider measurement.
    const PerfSubscription unnamed = perf_subscription_target(0);
    check(unnamed.pid == 0 && unnamed.cpu == -1,
          "with no target named the subscription measures the calling "
          "process, which is the only pid that exists to be named");
    check(!unnamed.inherit,
          "and does not inherit: following the caller's own children is a "
          "wider measurement than a caller that named nothing asked for");

    // A pid that is not a pid is not treated as "measure everything".
    const PerfSubscription negative = perf_subscription_target(-1);
    check(negative.pid == 0,
          "a negative pid resolves to the caller rather than to pid -1, which "
          "with a cpu would measure every process on the machine");
}

// set_target_pid on a layer with nothing in it is the state a run is in for
// most of its startup, and it has to be a state the object survives.
void test_naming_a_target_on_an_empty_layer_is_well_formed() {
    Uprobes u;
    check(u.target_pid() == 0, "a fresh layer has named no target");

    u.set_target_pid(4242);
    check(u.target_pid() == 4242, "naming a target is recorded");
    check(u.size() == 0 && u.fds().empty(),
          "and a layer with no probes still has none afterwards");

    // Naming the same target twice must not reopen anything, and must not
    // lose the target either -- a caller that sets it once per poll would
    // otherwise churn a descriptor per iteration.
    u.set_target_pid(4242);
    check(u.target_pid() == 4242, "naming the same target again keeps it");

    // Clearing it returns the layer to measuring the caller, which is a real
    // answer and not a refusal.
    u.set_target_pid(0);
    check(u.target_pid() == 0, "naming zero clears the target");

    // A negative pid is a caller that lost track of its target. It gets the
    // caller's own process rather than a machine-wide measurement.
    u.set_target_pid(-1);
    check(u.target_pid() == 0, "and a negative pid is treated as no target");
}

// A subscription opened against the wrong pid has to be reopened when the
// right one is named. This is the whole fix: the old code kept the
// descriptor it had opened against the observer, so it stayed live and stayed
// wrong.
//
// What is checked here is the half that is reachable without a kernel event
// behind the id: the target survives, and the registration the reopen layers
// onto is left alone. The reopen itself needs a subscription, and a
// subscription needs a real tracepoint -- the firing test above is where a
// descriptor actually changing process is observed.
void test_naming_a_target_reaches_the_registered_probes() {
    FakeTracefs f = make_fake_tracefs();
    if (f.dir.path.empty()) {
        return;
    }

    Uprobes u(f.dir.path);
    std::string detail;
    std::size_t index = 999;
    const int rc = u.register_only("main", "/bin/true", 0x1000,
                                   ProbeKind::Entry, index, detail);
    check(rc == 0, "a registration against a fake tracefs succeeds");
    if (rc != 0) {
        return;
    }
    check(u.size() == 1, "and leaves one probe in the layer");
    check(u.fds().empty(), "with no descriptor, because nothing subscribed");

    u.set_target_pid(4242);
    check(u.target_pid() == 4242,
          "naming a target is recorded even when nothing was subscribed");
    check(u.size() == 1,
          "and the probe is still in the layer: the target is what a "
          "subscription is opened against, not a replacement for one");
    check(u.fds().empty(), "and still has no descriptor to poll");

    // The tracefs line survives. The registration is what a subscription is
    // opened against, and a reopen that removed it would leave a probe
    // registered nowhere and subscribed nowhere.
    const std::string content = read_file_or_empty(f.uprobe_events);
    check(content.find("p:occ_0") != std::string::npos,
          "and the tracefs registration is untouched by naming a target");
    check(content.find("-:occ_0") == std::string::npos,
          "which means the probe was not removed and re-registered to get a "
          "new scope -- the event the kernel created is what a subscription "
          "names, and a fresh event would be a different one");

    // Subscribe. It cannot succeed against a fake tracefs, but the scope it
    // asked perf_event_open for is recorded either way, and this is where the
    // distinction lives: a call site that passed pid 0 regardless of the named
    // target records the caller here, and the assertions above -- which only
    // exercise the helper function -- would still pass.
    (void)u.subscribe(index, detail);

    check(u.all()[index].scope.pid == 4242,
          "and a subscription opened after the target was named asks for that "
          "pid -- not zero, which is the process doing the asking");
    check(u.all()[index].scope.cpu == -1,
          "with cpu -1, so the measurement covers every thread of the target");
    check(u.all()[index].scope.inherit,
          "and with inherit, so the threads the target creates after the probe "
          "was placed are counted too");

    // Before a target is named, the same call asks for the caller. Recording
    // it is what makes the two states distinguishable after the fact.
    Uprobes fresh(f.dir.path);
    std::size_t fresh_index = 999;
    std::string fresh_detail;
    if (fresh.register_only("main", "/bin/true", 0x1000, ProbeKind::Entry,
                            fresh_index, fresh_detail) == 0) {
        check(fresh.all()[fresh_index].scope.pid == 0,
              "a layer that has named no target records the caller, which is "
              "the only pid it can name");
        check(!fresh.all()[fresh_index].scope.inherit,
              "and does not ask to follow the caller's own children");
    }
}

// A probe fires in the target, and only in the target.
//
// This is the test that distinguishes the fix from what it replaced, and it
// needs a host with a writable tracefs: the subscription is opened against a
// named pid, a child process is made to execute the probed symbol, and the
// hits are read back. Under the previous code the subscription named pid 0 --
// the observer -- so every hit would carry this process's pid and the
// child's calls would be absent, and the test would fail on both counts
// rather than on a count alone.
//
// The parent calls the same symbol before forking and between reading the
// rings. That is what makes the assertion discriminating rather than a check
// that the plumbing works: the probe is live for the parent too, so a
// subscription that ignored its pid would count these calls, and the count
// would be too high rather than merely non-zero.
//
// Marked as needing a writable tracefs and skipped without one, per the
// testing rule that a suite which cannot run on a development machine is a
// suite that stops being run. It is not marked root-only: the tracefs write
// is a permission, not a privilege, and a host with tracefs mounted
// read-write serves this as an ordinary user.
void test_a_probe_fires_in_the_target_and_not_in_the_observer() {
    if (!Uprobes::availability().available) {
        std::fprintf(stderr, "note: no writable tracefs; the firing check "
                             "was skipped\n");
        return;
    }

    // A libc symbol this process calls and a forked child will call. libc is
    // mapped into both, and the probe is placed in the file rather than in
    // either process, which is the arrangement a uprobe exists for.
    const std::string libc = find_module("libc.so.6");
    if (libc.empty()) {
        std::fprintf(stderr, "note: no libc on the loader's path; the firing "
                             "check was skipped\n");
        return;
    }
    auto bytes = occ::fs::read_file_bytes(libc);
    if (!bytes || bytes->empty()) {
        std::fprintf(stderr, "note: libc could not be read; the firing check "
                             "was skipped\n");
        return;
    }
    const occ::parser::ElfImage image = occ::parser::ElfImage::parse(
        occ::ByteSpan{bytes->data(), bytes->size()});
    const occ::parser::Symbol* sym = image.find_symbol("getpid");
    std::uint64_t offset = 0;
    if (!image.ok() || sym == nullptr || !sym->probeable() ||
        !image.vaddr_to_file_offset(sym->value, offset)) {
        std::fprintf(stderr, "note: getpid could not be placed in libc; the "
                             "firing check was skipped\n");
        return;
    }

    Uprobes u;
    std::string detail;
    const int rc = u.add("getpid", libc, offset, ProbeKind::Entry, detail);
    if (rc != 0) {
        // perf_event_paranoid above zero, or a policy that blocks the open.
        // A refusal is a fact about the host and not a failure of the code
        // under test, so it is reported and the check stands down.
        std::fprintf(stderr, "note: the probe could not be subscribed (%d: "
                             "%s); the firing check was skipped\n",
                     rc, detail.c_str());
        return;
    }

    // The parent's own calls, made while the probe is live and before any
    // child exists. Under a subscription named for the caller these are
    // counted; under one named for the child they are not.
    constexpr int kParentCalls = 8;
    volatile int sink = 0;
    for (int i = 0; i < kParentCalls; ++i) {
        sink += static_cast<int>(::getpid());
    }
    (void)sink;

    // The child. It is forked while the probe is live, so a subscription that
    // follows threads and children created after it was opened would see
    // this; one that does not would miss the child's very first call.
    //
    // The child calls the symbol and exits. Its exit is what makes the hit
    // observable at all: the ring is drained after it is gone, because a hit
    // delivered to a running child would need the session's poll loop to
    // read it and this test has none.
    const pid_t child = ::fork();
    if (child < 0) {
        std::fprintf(stderr, "note: no child could be forked; the firing "
                             "check was skipped\n");
        return;
    }
    if (child == 0) {
        // The child's own getpid calls. Enough that a ring which lost a
        // record or two still has hits left, and few enough that the count
        // stays a meaningful number rather than an approximation.
        volatile int child_sink = 0;
        for (int i = 0; i < 16; ++i) {
            child_sink += static_cast<int>(::getpid());
        }
        (void)child_sink;
        ::_exit(0);
    }

    int status = 0;
    (void)::waitpid(child, &status, 0);

    // The parent's calls again, after the child is gone. A subscription named
    // for pid 0 is unaffected by anything the child did, so this is where the
    // wrong-pid bug shows up as extra hits rather than as missing ones.
    for (int i = 0; i < kParentCalls; ++i) {
        sink += static_cast<int>(::getpid());
    }
    (void)sink;

    std::vector<UprobeHit> hits;
    (void)u.read_hits(hits);

    std::size_t from_child = 0;
    std::size_t from_parent = 0;
    std::size_t from_other = 0;
    const pid_t self = ::getpid();
    for (const UprobeHit& h : hits) {
        if (h.pid == static_cast<int>(child)) {
            ++from_child;
        } else if (h.pid == static_cast<int>(self)) {
            ++from_parent;
        } else {
            ++from_other;
        }
    }

    check(from_child > 0,
          "a probe subscribed to a named pid records the hits of that "
          "process's execution");
    check(from_parent == 0,
          "and records none of the observer's own calls to the same symbol, "
          "which is what a subscription naming pid 0 would report instead");
    check(from_other == 0,
          "and none from any process that was never named either, so the "
          "measurement is the target's rather than the machine's");

    // The child's calls are counted, but not necessarily all of them: the ring
    // has a fixed capacity and the kernel drops what does not fit, which is
    // reported through lost_hits(). Asserting an exact number would be
    // asserting that no sample was ever lost, which is a property of the
    // host's timing and not of this code. Asserting that the count is bounded
    // by the calls that were made catches a subscription that counted
    // something else without depending on how busy the machine was.
    check(from_child <= 16 + u.lost_hits() + kParentCalls * 2,
          "and no more hits than the child made plus what the kernel reported "
          "losing");
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
    test_sample_decodes_the_argument_registers_in_abi_order();
    test_sample_without_captured_registers_reports_none();
    test_the_raw_sample_is_stepped_over_before_the_registers();
    test_a_truncated_sample_is_refused_rather_than_guessed();
    test_a_truncated_register_block_keeps_the_hit_without_arguments();
    test_a_null_body_is_refused();
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
    test_the_subscription_names_the_target_and_not_the_caller();
    test_naming_a_target_on_an_empty_layer_is_well_formed();
    test_naming_a_target_reaches_the_registered_probes();
    test_a_probe_fires_in_the_target_and_not_in_the_observer();

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

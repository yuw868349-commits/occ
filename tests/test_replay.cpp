// Replay (deterministic record-and-replay engine) tests.
//
// The happy path records a synthetic guest session (three API calls, a
// memory write, a random draw) and replays it back in lockstep. The
// failure paths pin the divergence contract: wrong arguments, wrong
// bytes, a checkpoint that drifted, an extra observation past the end of
// the trace, and a peek at an empty trace must each produce the right
// diagnosis. FNV-1a is pinned against a hand-computed vector.

#include "occ/replay/replay.h"

#include <cstdio>
#include <cstring>

using namespace occ::replay;

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

Trace make_trace() {
    Recorder rec;
    rec.record_api(1, 10, "ReadFile", 0x88, 0x1000, 8, 0, 8, 0xAAAA);
    rec.record_api(1, 20, "VirtualAlloc", 0, 0x1000, 0x3000, 0x40, 0x2000,
                   0xBBBB);
    const std::uint8_t bytes[] = {0xDE, 0xAD, 0xBE, 0xEF};
    rec.record_mem(1, 30, 0x2000, bytes, 4, 0xCCCC);
    rec.record_value(EventKind::kRandom, 1, 40, 0x12345678, 0xDDDD);
    rec.record_api(2, 50, "GetProcAddress", 0x1111, 0x2222, 0, 0, 0x9999,
                   0xEEEE);
    return rec.finish();
}

void test_fnv1a() {
    // FNV-1a 64 of "abc" is a well-known vector.
    const std::uint8_t abc[] = {'a', 'b', 'c'};
    check(fnv1a(abc, 3) == 0xe71fa2190541574bull, "fnv1a: abc vector");
    check(fnv1a(nullptr, 0) == 14695981039346656037ull, "fnv1a: empty seed");
}

void test_happy_path() {
    const Trace t = make_trace();
    check(t.size() == 5, "trace: five events");

    Replayer rp(t);
    const Event* e = nullptr;
    check(rp.peek(e) && e != nullptr && e->seq == 0, "replay: peek first");

    Event obs;
    obs.kind = EventKind::kApiCall;
    obs.thread = 1;
    obs.name = "ReadFile";
    obs.a0 = 0x88;
    obs.a1 = 0x1000;
    obs.a2 = 8;
    obs.a3 = 0;
    obs.checkpoint = 0xAAAA;
    StepResult r = rp.step(obs);
    check(r.ok && !r.divergence, "replay: first call matches");
    check(r.ret == 8, "replay: recorded return injected");

    obs.name = "VirtualAlloc";
    obs.a0 = 0;
    obs.a1 = 0x1000;
    obs.a2 = 0x3000;
    obs.a3 = 0x40;
    obs.checkpoint = 0xBBBB;
    r = rp.step(obs);
    check(r.ok && r.ret == 0x2000, "replay: alloc return injected");

    obs.kind = EventKind::kMemWrite;
    obs.addr = 0x2000;
    obs.payload = {0xDE, 0xAD, 0xBE, 0xEF};
    obs.checkpoint = 0xCCCC;
    r = rp.step(obs);
    check(r.ok && r.addr == 0x2000, "replay: memory write matches");

    obs.kind = EventKind::kRandom;
    obs.checkpoint = 0xDDDD;
    r = rp.step(obs);
    check(r.ok && r.ret == 0x12345678, "replay: random value injected");

    obs.kind = EventKind::kApiCall;
    obs.thread = 2;
    obs.name = "GetProcAddress";
    obs.a0 = 0x1111;
    obs.a1 = 0x2222;
    obs.a2 = 0;
    obs.a3 = 0;
    obs.checkpoint = 0xEEEE;
    r = rp.step(obs);
    check(r.ok && r.ret == 0x9999, "replay: last call matches");
    check(rp.finished(), "replay: trace consumed");

    // One more step: exhausted.
    r = rp.step(obs);
    check(r.exhausted, "replay: extra step reports exhausted");
}

void test_divergences() {
    const Trace t = make_trace();
    Replayer rp(t);

    Event obs;
    obs.kind = EventKind::kApiCall;
    obs.thread = 1;
    obs.name = "ReadFile";
    obs.a0 = 0x88;
    obs.a1 = 0x1000;
    obs.a2 = 8;
    obs.a3 = 0;
    obs.checkpoint = 0xAAAA;

    // Wrong argument.
    obs.a2 = 16;
    StepResult r = rp.step(obs);
    check(!r.ok && r.divergence && r.reason.find("arguments") !=
                                      std::string::npos,
          "replay: wrong args diverge");

    // Wrong thread.
    Replayer rp2(t);
    obs.a2 = 8;
    obs.thread = 9;
    r = rp2.step(obs);
    check(!r.ok && r.reason.find("thread") != std::string::npos,
          "replay: wrong thread diverges");

    // Checkpoint drift.
    Replayer rp3(t);
    obs.thread = 1;
    obs.checkpoint = 0x1111;
    r = rp3.step(obs);
    check(!r.ok && r.reason.find("checkpoint") != std::string::npos,
          "replay: checkpoint drift diverges");

    // Memory write bytes drift.
    Replayer rp4(t);
    obs.kind = EventKind::kApiCall;
    obs.name = "ReadFile";
    obs.a0 = 0x88;
    obs.a1 = 0x1000;
    obs.a2 = 8;
    obs.a3 = 0;
    obs.checkpoint = 0xAAAA;
    check(rp4.step(obs).ok, "replay: setup for write test");
    obs.kind = EventKind::kApiCall;
    obs.name = "VirtualAlloc";
    obs.a0 = 0;
    obs.a1 = 0x1000;
    obs.a2 = 0x3000;
    obs.a3 = 0x40;
    obs.checkpoint = 0xBBBB;
    check(rp4.step(obs).ok, "replay: setup for write test 2");
    obs.kind = EventKind::kMemWrite;
    obs.addr = 0x2000;
    obs.payload = {0xDE, 0xAD, 0xBE, 0x99};  // last byte wrong
    obs.checkpoint = 0xCCCC;
    r = rp4.step(obs);
    check(!r.ok && r.reason.find("bytes") != std::string::npos,
          "replay: write bytes diverge");
}

void test_rewind() {
    const Trace t = make_trace();
    Replayer rp(t);

    Event obs;
    obs.kind = EventKind::kApiCall;
    obs.thread = 1;
    obs.name = "ReadFile";
    obs.a0 = 0x88;
    obs.a1 = 0x1000;
    obs.a2 = 8;
    obs.a3 = 0;
    obs.checkpoint = 0xAAAA;
    check(rp.step(obs).ok, "rewind: first pass step");
    check(rp.position() == 1, "rewind: advanced");
    rp.rewind();
    check(rp.position() == 0, "rewind: back to start");
    check(rp.step(obs).ok, "rewind: second pass replays");

    // An empty trace peeks false.
    Replayer empty(Trace{});
    const Event* e = nullptr;
    check(!empty.peek(e), "replay: empty trace peek fails");
}

}  // namespace

int main() {
    test_fnv1a();
    test_happy_path();
    test_divergences();
    test_rewind();
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

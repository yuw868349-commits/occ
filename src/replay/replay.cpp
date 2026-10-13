// The deterministic record-and-replay engine -- implementation.
//
// Matching is strict but fair: the kind, thread, name and argument slots
// must equal what was recorded; memory writes must match address and
// bytes; and the integration's checkpoint must reproduce. Every failure
// path produces a human-readable reason instead of a bare boolean, so an
// integration can tell "guest diverged at API X" from "checkpoint
// drifted at step N" without re-deriving it.

#include "occ/replay/replay.h"

#include <cstring>

namespace occ::replay {

std::uint64_t fnv1a(const std::uint8_t* data, std::size_t n) noexcept {
    std::uint64_t h = 14695981039346656037ull;
    for (std::size_t i = 0; i < n; ++i) {
        h ^= data[i];
        h *= 1099511628211ull;
    }
    return h;
}

bool Replayer::peek(const Event*& out) const noexcept {
    if (finished()) {
        out = nullptr;
        return false;
    }
    out = &trace_.at(pos_);
    return true;
}

StepResult Replayer::step(const Event& observed) noexcept {
    StepResult r;
    if (finished()) {
        r.exhausted = true;
        r.reason = "trace exhausted before the observation";
        return r;
    }
    const Event& rec = trace_.at(pos_);

    auto fail = [&](const char* why) {
        r.ok = false;
        r.divergence = true;
        r.reason = why;
        return r;
    };

    if (observed.kind != rec.kind) {
        return fail("event kind differs from the trace");
    }
    if (observed.thread != rec.thread) {
        return fail("thread differs from the trace");
    }
    switch (rec.kind) {
    case EventKind::kApiCall:
        if (observed.name != rec.name) {
            return fail(("api name differs: recorded " + rec.name +
                         ", observed " + observed.name)
                            .c_str());
        }
        if (observed.a0 != rec.a0 || observed.a1 != rec.a1 ||
            observed.a2 != rec.a2 || observed.a3 != rec.a3) {
            return fail("api arguments differ from the trace");
        }
        if (observed.checkpoint != rec.checkpoint) {
            return fail("checkpoint differs at an api call");
        }
        r.ok = true;
        r.ret = rec.ret;
        ++pos_;
        return r;
    case EventKind::kMemWrite:
        if (observed.addr != rec.addr) {
            return fail("memory write address differs from the trace");
        }
        if (observed.payload.size() != rec.payload.size()) {
            return fail("memory write length differs from the trace");
        }
        if (rec.payload.size() != 0 &&
            std::memcmp(observed.payload.data(), rec.payload.data(),
                        rec.payload.size()) != 0) {
            return fail("memory write bytes differ from the trace");
        }
        if (observed.checkpoint != rec.checkpoint) {
            return fail("checkpoint differs at a memory write");
        }
        r.ok = true;
        r.addr = rec.addr;
        r.payload = rec.payload;
        ++pos_;
        return r;
    case EventKind::kClock:
    case EventKind::kRandom:
        if (observed.checkpoint != rec.checkpoint) {
            return fail("checkpoint differs at an injected value");
        }
        r.ok = true;
        r.ret = rec.ret;
        ++pos_;
        return r;
    }
    return fail("unknown event kind");
}

}  // namespace occ::replay

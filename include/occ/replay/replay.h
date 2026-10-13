// The deterministic record-and-replay engine, in the rr lineage.
//
// A dynamic-analysis runtime is deterministic only when every external
// input -- API return values, asynchronous writes, randomness -- is
// recorded and then replayed identically. This module owns that
// contract:
//
//   * Recording. The integration wraps every guest API call and every
//     memory write the guest performs through the runtime; the recorder
//     appends one Event per observation. Each event carries the logical
//     time, the originating thread, the arguments, and the recorded
//     response (the return value or the written bytes), plus a FNV-1a
//     checkpoint of the guest state the integration declares.
//
//   * Replaying. The replayer consumes the trace in order. At each step
//     the integration reports the event it is about to perform; the
//     replayer verifies kind, arguments and thread against the trace,
//     checks the checkpoint, and returns the recorded response. Any
//     mismatch is a divergence: the guest behaved differently on replay
//     than it did on record, which is exactly the signal a dynamic
//     analysis wants (a target that is not deterministic, or an
//     integration bug).
//
//   * The boundary is honest. The module does not know what a guest is;
//     it only knows the event stream. The checkpoint hash is computed by
//     the integration over whatever state it declares; this module
//     merely records and compares it. Events the integration cannot
//     reproduce exactly (e.g. wall-clock time) must be recorded as their
//     kind so the replayer knows to inject rather than compare.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace occ::replay {

// The kinds of events a trace may hold.
enum class EventKind {
    kApiCall,   // a guest API call with recorded args and return value
    kMemWrite,  // a write of `payload` bytes to `a0`
    kClock,     // a time read; the replayer injects the recorded value
    kRandom,    // a random draw; the replayer injects the recorded value
};

// One recorded or observed event.
struct Event {
    EventKind kind = EventKind::kApiCall;
    std::uint64_t seq = 0;     // global sequence number
    std::uint64_t thread = 0;  // originating thread id
    std::uint64_t when = 0;    // integration logical time
    // For kApiCall: the API name and four arguments.
    std::string name;
    std::uint64_t a0 = 0;
    std::uint64_t a1 = 0;
    std::uint64_t a2 = 0;
    std::uint64_t a3 = 0;
    // For kApiCall: the recorded return value.
    std::uint64_t ret = 0;
    // For kMemWrite: the destination address and the bytes.
    std::uint64_t addr = 0;
    std::vector<std::uint8_t> payload;
    // The integration's FNV-1a checkpoint of guest state at this point.
    std::uint64_t checkpoint = 0;
};

// The immutable trace a recorder produces.
class Trace {
public:
    Trace() = default;
    explicit Trace(std::vector<Event> events) noexcept
        : events_(std::move(events)) {}

    [[nodiscard]] std::size_t size() const noexcept { return events_.size(); }
    [[nodiscard]] bool empty() const noexcept { return events_.empty(); }
    [[nodiscard]] const Event& at(std::size_t i) const noexcept {
        return events_[i];
    }
    [[nodiscard]] const std::vector<Event>& events() const noexcept {
        return events_;
    }

private:
    std::vector<Event> events_;
};

// Appends observations into a trace.
//
// The recorder is append-only and cheap: recording must not perturb the
// guest under analysis, so it never copies payloads eagerly beyond what
// the integration passed.
class Recorder {
public:
    Recorder() = default;

    void record_api(std::uint64_t thread, std::uint64_t when,
                    std::string name, std::uint64_t a0, std::uint64_t a1,
                    std::uint64_t a2, std::uint64_t a3, std::uint64_t ret,
                    std::uint64_t checkpoint) noexcept {
        Event e;
        e.kind = EventKind::kApiCall;
        e.seq = next_seq_++;
        e.thread = thread;
        e.when = when;
        e.name = std::move(name);
        e.a0 = a0;
        e.a1 = a1;
        e.a2 = a2;
        e.a3 = a3;
        e.ret = ret;
        e.checkpoint = checkpoint;
        events_.push_back(std::move(e));
    }

    void record_mem(std::uint64_t thread, std::uint64_t when,
                    std::uint64_t addr, const std::uint8_t* bytes,
                    std::size_t n, std::uint64_t checkpoint) noexcept {
        Event e;
        e.kind = EventKind::kMemWrite;
        e.seq = next_seq_++;
        e.thread = thread;
        e.when = when;
        e.addr = addr;
        e.payload.assign(bytes, bytes + n);
        e.checkpoint = checkpoint;
        events_.push_back(std::move(e));
    }

    void record_value(EventKind kind, std::uint64_t thread,
                      std::uint64_t when, std::uint64_t value,
                      std::uint64_t checkpoint) noexcept {
        Event e;
        e.kind = kind;
        e.seq = next_seq_++;
        e.thread = thread;
        e.when = when;
        e.ret = value;
        e.checkpoint = checkpoint;
        events_.push_back(std::move(e));
    }

    [[nodiscard]] std::size_t size() const noexcept { return events_.size(); }
    [[nodiscard]] Trace finish() noexcept {
        return Trace(std::move(events_));
    }

private:
    std::vector<Event> events_;
    std::uint64_t next_seq_ = 0;
};

// The result of one replay step.
struct StepResult {
    bool ok = false;         // matched the trace
    bool divergence = false; // a real mismatch (kind/args/checkpoint)
    bool exhausted = false;  // trace ended, nothing more to consume
    std::string reason;      // human-readable divergence detail
    // The recorded response to inject when ok.
    std::uint64_t ret = 0;
    std::vector<std::uint8_t> payload;
    std::uint64_t addr = 0;
};

// The FNV-1a hash the integration is expected to use for checkpoints.
[[nodiscard]] std::uint64_t fnv1a(const std::uint8_t* data,
                                  std::size_t n) noexcept;

// The replayer.
//
// Feed it a trace, then one observed event per step. It matches the
// observation against the next recorded event (kind, thread, name and
// arguments; for memory writes, the address and the bytes) and returns
// the recorded response. `expected_checkpoint` is compared against the
// recorded checkpoint; a mismatch is a divergence even when everything
// else matched.
class Replayer {
public:
    explicit Replayer(Trace trace) noexcept
        : trace_(std::move(trace)) {}

    [[nodiscard]] std::size_t position() const noexcept { return pos_; }
    [[nodiscard]] bool finished() const noexcept {
        return pos_ >= trace_.size();
    }

    // The next recorded event, without consuming it. Returns false when
    // the trace is exhausted.
    [[nodiscard]] bool peek(const Event*& out) const noexcept;

    // Steps with the observed event. Consumes exactly one trace entry.
    [[nodiscard]] StepResult step(const Event& observed) noexcept;

    // Rewinds to the beginning (for a fresh replay pass over the same
    // trace).
    void rewind() noexcept { pos_ = 0; }

private:
    Trace trace_;
    std::size_t pos_ = 0;
};

}  // namespace occ::replay

#pragma once

// The event stream.
//
// Every fact a run produces leaves through one writer, and the writer emits
// one JSON object per line. A line-oriented format is chosen because it is
// readable while the run is still going: a consumer tails the stream, parses
// one object at a time, and never has to hold the whole run in memory. The
// same bytes are what a terminal shows and what a tool consumes, so there is
// no second code path that only ever gets exercised by one of the two.
//
// Field order is fixed by the encoder rather than by a map, because a
// stable order makes two runs of the same target diff cleanly, and diffing
// two runs is the main thing a caller does with this.
//
// Times are monotonic nanoseconds since the stream was opened. A wall clock
// would make two runs on two machines incomparable, and this stream is
// meant to be compared.

#include <cstdint>
#include <string>
#include <string_view>

#include "occ/util/span.h"

namespace occ::obs {

// What an event is about. The kind is the first field on every line, so a
// consumer can dispatch on it before it has parsed the rest.
enum class EventKind : std::uint8_t {
    SessionStart,
    SessionEnd,
    ProcessSpawn,
    ProcessExit,
    ImageLoaded,
    Mapping,
    // One section of a PE image. Separate from Mapping because a section is
    // not a mapping: it is a range of the file and a range of the address
    // space, and the loader is what turns one into the other. Reporting a
    // section as a mapping would claim a correspondence the file does not
    // make.
    Section,
    // One DLL a PE imports, in the order the import directory lists them.
    Import,
    FileOpened,
    SyscallBlocked,
    BreakpointHit,
    Signal,
    MemoryWrite,
    Exec,
    // A uprobe was placed, or an attempt to place one failed. Emitted once
    // per probe rather than once per run, because a run that placed nine of
    // ten probes and did not say which one it missed is a run whose output
    // has a silent hole in it.
    //
    // This is separate from a hit: attaching is a fact about the run's
    // setup and happens once, and a hit is a fact about the target and
    // happens as often as the target calls the function.
    ProbeAttached,
    // A probed function was entered or returned from. Carries the probe's
    // name, the pid and tid that hit it, and whatever argument registers
    // were read.
    ProbeHit,
    Note,
};

[[nodiscard]] const char* event_kind_name(EventKind k) noexcept;

// A single event, held as its already-encoded JSON body. Building the body
// at the point the fact is observed keeps the encoder free of any state
// beyond the output sink, and keeps a struct per event kind from being
// needed for the thirty-odd kinds that end up existing.
class Event {
public:
    Event() = default;

    // Appends `"key":value` to the body. The value overloads are what keep
    // a caller from having to quote a string by hand, which is where an
    // unescaped quote would corrupt the stream.
    void add(std::string_view key, std::uint64_t value) noexcept;
    void add(std::string_view key, std::int64_t value) noexcept;
    void add(std::string_view key, std::string_view value) noexcept;
    void add(std::string_view key, bool value) noexcept;
    // A bare pointer would otherwise convert to bool, which is a conversion
    // the compiler is entitled to make and one that turns a name into a
    // truth value. Naming the overload makes the string win, so the hazard
    // is closed at the type rather than at each call site.
    void add(std::string_view key, const char* value) noexcept {
        add(key, std::string_view{value});
    }
    void add_hex(std::string_view key, std::uint64_t value) noexcept;

    [[nodiscard]] const std::string& body() const noexcept { return body_; }
    [[nodiscard]] bool empty() const noexcept { return body_.empty(); }

private:
    void separator() noexcept;

    std::string body_;
};

// Where the encoded lines go. An fd sink rather than a stream, because the
// stream has to survive the process replacement that the run performs and a
// FILE* buffer would be duplicated or lost across it.
class Sink {
public:
    Sink() = default;
    explicit Sink(int fd) noexcept : fd_(fd) {}

    // Writes one line. A partial write is retried; anything else is
    // reported by a false return. The sink never blocks indefinitely on a
    // dead reader: a broken pipe is a disconnection, not a reason to spin.
    [[nodiscard]] bool write_line(std::string_view line) noexcept;

    [[nodiscard]] int fd() const noexcept { return fd_; }

private:
    int fd_ = -1;
};

// The writer. One of these exists per run, and it owns the stream's identity
// so that a consumer can tell two interleaved runs apart.
class Writer {
public:
    Writer() = default;

    // Attaching a sink also clears the failure, because the flag describes
    // the sink that was attached rather than the writer: a writer moved
    // onto a fresh descriptor has not yet failed on it, and a caller that
    // rotated the descriptor after a broken pipe needs the count of lost
    // events to start again rather than to carry the old sink's failure
    // forever.
    void attach(int fd) noexcept {
        sink_ = Sink{fd};
        failed_ = false;
    }

    // Forgets a reported failure without moving the writer. A sink that
    // failed once is not permanently broken: a pipe the reader had not
    // drained reports EAGAIN, and the next write succeeds. Without this a
    // single transient refusal marks every later event of the run as
    // failed, which is what the flag is read for.
    void clear_failure() noexcept { failed_ = false; }

    // Emits an event with the fields every event carries: the kind, the
    // session it belongs to, and the time it was observed. Callers fill in
    // the rest through the returned reference.
    //
    // Beginning while an event is already open returns that event rather
    // than starting a new one. The alternative discards the fields already
    // added to it, and a caller that reached the second begin by a path
    // other than the intended one -- an early return, say -- would lose
    // them with no indication that it had.
    [[nodiscard]] Event& begin(EventKind kind) noexcept;

    // Encodes and writes the event returned by begin. Safe to call when an
    // event was never begun, in which case nothing is written.
    void commit() noexcept;

    // Convenience for the common case of an event with no extra fields
    // beyond a message.
    void note(std::string_view text) noexcept;

    [[nodiscard]] std::uint64_t events_written() const noexcept {
        return written_;
    }
    [[nodiscard]] bool failed() const noexcept { return failed_; }

private:
    // Returns false when the clock could not be read, which is not the
    // same answer as a reading of zero: a failed clock must not put the
    // event at time zero, because a zero timestamp is also what a real
    // reading looks like at the start of the monotonic epoch, and a
    // consumer cannot tell the two apart.
    [[nodiscard]] bool now_ns(std::uint64_t& out) const noexcept;

    Sink sink_;
    Event current_;
    std::uint64_t session_ = 0;
    std::uint64_t written_ = 0;
    // The last time the clock was read successfully. An event whose own
    // reading failed is stamped with this rather than dropped, because a
    // stream with a hole in its ordering is worse than one whose events
    // carry the previous timestamp, and because the alternative -- a zero
    // -- would place the event before every event that came before it.
    std::uint64_t last_ns_ = 0;
    bool failed_ = false;
    bool open_ = false;
};

} // namespace occ::obs

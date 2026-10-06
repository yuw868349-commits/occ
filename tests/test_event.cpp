// Event stream tests.
//
// The stream is the machine-readable output of a run, so the tests are
// mostly about its shape rather than its content: that each value type
// encodes as JSON of the right kind, that a string containing JSON
// metacharacters cannot break the line, and that a field whose name the
// encoder chose cannot be shadowed by a caller. The cases below are the ones
// where a mistake would produce a stream that parses but says the wrong
// thing, which is worse than one that does not parse.

#include "occ/observer/event.h"

#include "occ/syscall/syscall.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <unistd.h>

using namespace occ;
using occ::obs::Event;
using occ::obs::EventKind;
using occ::obs::Writer;

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

// A writer whose sink is a pipe, so the tests read back the exact bytes a
// consumer would see. Encoding into a string and inspecting that would test
// the encoder but not the line framing, and the framing is half the format.
struct Captured {
    int fd_[2] = {-1, -1};
    Writer writer;

    Captured() {
        if (::pipe(fd_) != 0) {
            std::fprintf(stderr, "pipe failed\n");
            return;
        }
        writer.attach(fd_[1]);
    }

    ~Captured() {
        if (fd_[0] >= 0) {
            ::close(fd_[0]);
        }
        if (fd_[1] >= 0) {
            ::close(fd_[1]);
        }
    }

    std::vector<std::string> lines() {
        // The write end is closed so the read terminates. The writer is
        // discarded afterwards: a closed sink is exactly the state the
        // tests want to observe, not a mistake.
        ::close(fd_[1]);
        fd_[1] = -1;

        std::string all;
        char buffer[4096];
        for (;;) {
            const ssize_t n = ::read(fd_[0], buffer, sizeof(buffer));
            if (n <= 0) {
                break;
            }
            all.append(buffer, static_cast<std::size_t>(n));
        }

        std::vector<std::string> out;
        std::size_t start = 0;
        while (start < all.size()) {
            const std::size_t end = all.find('\n', start);
            if (end == std::string::npos) {
                break;
            }
            out.push_back(all.substr(start, end - start));
            start = end + 1;
        }
        return out;
    }
};

void test_kind_names() {
    check(std::strcmp(obs::event_kind_name(EventKind::SessionStart),
                      "session_start") == 0,
          "the session start name");
    check(std::strcmp(obs::event_kind_name(EventKind::ProcessExit),
                      "process_exit") == 0,
          "the process exit name");
    check(std::strcmp(obs::event_kind_name(EventKind::SyscallBlocked),
                      "syscall_blocked") == 0,
          "the blocked syscall name");
    check(std::strcmp(obs::event_kind_name(EventKind::Note), "note") == 0,
          "the note name");
}

void test_value_types() {
    Captured cap;
    auto& e = cap.writer.begin(EventKind::Note);
    e.add("count", static_cast<std::uint64_t>(42));
    e.add("delta", static_cast<std::int64_t>(-7));
    e.add("text", std::string_view{"hello"});
    e.add("flag", true);
    e.add("other", false);
    e.add_hex("addr", 0x401850);
    cap.writer.commit();

    const auto lines = cap.lines();
    check(lines.size() == 1, "one commit writes one line");
    if (lines.empty()) {
        return;
    }

    const std::string& line = lines[0];
    check(line.front() == '{' && line.back() == '}', "the line is an object");
    check(line.find("\"count\":42") != std::string::npos,
          "an unsigned integer is written as a number");
    check(line.find("\"delta\":-7") != std::string::npos,
          "a negative integer keeps its sign");
    check(line.find("\"text\":\"hello\"") != std::string::npos,
          "a string is quoted");
    check(line.find("\"flag\":true") != std::string::npos,
          "true is a JSON literal, not a string");
    check(line.find("\"other\":false") != std::string::npos,
          "false is a JSON literal, not a string");
    // The address is hexadecimal with the prefix and without padding. The
    // width passed to the writer is the number of nibbles it may use, so
    // the digits are what the value needs and nothing more.
    check(line.find("\"addr\":\"0x401850\"") != std::string::npos,
          "an address is hexadecimal with a prefix");
    check(line.find("0x0000000000401850") == std::string::npos,
          "an address is not padded with leading zeros");
}

void test_pointer_not_confused_with_bool() {
    // A const char* would convert to bool if the string overload did not
    // exist, and the event would carry a truth value where a name belongs.
    //
    // This is not hypothetical. The overload set holds a uint64_t, an
    // int64_t, a string_view and a bool, and a pointer reaches bool by a
    // standard conversion while it reaches string_view only by a user-defined
    // one, so without a pointer overload of its own every engine name
    // reached through Engine::name() -- which returns const char* -- is
    // written as `true`. The stream still parses, which is what makes it
    // worth pinning: a consumer reading "engine" gets a boolean and nothing
    // tells it the value is wrong.
    Captured cap;
    auto& e = cap.writer.begin(EventKind::ImageLoaded);
    // A string literal, as the engines that name themselves inline use.
    e.add("engine", "pe");
    // A const char* returned from a function, which is what every engine
    // name actually is at the call site.
    e.add("format", obs::event_kind_name(EventKind::Section));
    // A named variable of pointer type, so the assertion does not depend on
    // the literal case alone.
    const char* named = "apk";
    e.add("packaging", named);
    cap.writer.commit();

    const auto lines = cap.lines();
    check(lines.size() == 1, "the line is written");
    if (lines.empty()) {
        return;
    }
    check(lines[0].find("\"engine\":\"pe\"") != std::string::npos,
          "a bare pointer encodes as its string, not as true");
    check(lines[0].find("\"format\":\"section\"") != std::string::npos,
          "a pointer returned from a function encodes as its string");
    check(lines[0].find("\"packaging\":\"apk\"") != std::string::npos,
          "a pointer in a named variable encodes as its string");
    check(lines[0].find("\"engine\":true") == std::string::npos,
          "a bare pointer does not become a truth value");
    check(lines[0].find("\"format\":true") == std::string::npos,
          "a returned pointer does not become a truth value");
    check(lines[0].find("\"packaging\":true") == std::string::npos,
          "a named pointer does not become a truth value");
    // The bool overload has to keep working: the width events carry three
    // boolean fields, and a fix that removed the overload would push every
    // one of them through the pointer path instead.
    check(lines[0].find("true") == std::string::npos,
          "no field of this line fell through to the bool overload");
}

void test_begin_keeps_an_uncommitted_event() {
    // A begin that arrives while an event is already open must not discard
    // the fields the first one collected. commit() writes whatever the body
    // holds, so a reset here loses them with nothing to indicate it.
    //
    // The caller in this test is one that reached its second begin by a
    // path other than the intended one, which is the shape of the mistake:
    // an early return, or a helper that begins again because it could not
    // tell whether the event was still open.
    Captured cap;
    auto& first = cap.writer.begin(EventKind::Note);
    first.add("collected", static_cast<std::uint64_t>(1));

    auto& second = cap.writer.begin(EventKind::Note);
    second.add("added_later", static_cast<std::uint64_t>(2));
    cap.writer.commit();

    const auto lines = cap.lines();
    check(lines.size() == 1, "the second begin did not open a second event");
    if (lines.empty()) {
        return;
    }
    check(lines[0].find("\"collected\":1") != std::string::npos,
          "a begin during an open event keeps the fields already added");
    check(lines[0].find("\"added_later\":2") != std::string::npos,
          "and the fields the second caller added");
}

void test_failed_writer_can_be_reused() {
    // A sink that fails once is not permanently broken. A pipe nobody is
    // draining fills up and the write reports EAGAIN; drain it and the next
    // write succeeds. A writer that stayed failed from then on would mark
    // every remaining event of the run as lost, which is what failed() is
    // read for.
    int fds[2] = {-1, -1};
    if (::pipe(fds) != 0) {
        std::fprintf(stderr, "  note: pipe failed, skipping reuse test\n");
        return;
    }

    // The write end has to be non-blocking for a full pipe to report rather
    // than wait: a blocking write would park the test until the reader
    // drained it, which is the opposite of the condition under test.
    if (occ::sys::fcntl(fds[1], 4 /* F_SETFL */,
                        0x800 /* O_NONBLOCK */)
            .failed()) {
        std::fprintf(stderr, "  note: cannot set O_NONBLOCK, skipping\n");
        ::close(fds[0]);
        ::close(fds[1]);
        return;
    }

    Writer writer;
    writer.attach(fds[1]);

    // Fill the pipe. How much fits is a property of the kernel, so this
    // keeps writing until the kernel refuses rather than guessing a size,
    // and counts what went in so the drain below can be exact -- a blocking
    // read end would otherwise wait forever on an empty pipe.
    char fill[4096];
    std::memset(fill, 'x', sizeof(fill));
    std::size_t filled = 0;
    for (;;) {
        const auto wrote = occ::sys::write(fds[1], fill, sizeof(fill));
        if (wrote.failed() || wrote.value == 0) {
            break;
        }
        filled += static_cast<std::size_t>(wrote.value);
    }
    check(filled > 0, "the pipe accepted something before refusing");

    writer.note("into a full pipe");
    check(writer.failed(), "a write to a full pipe is a failure");
    check(writer.events_written() == 0, "a failed write counts nothing");

    // Draining the pipe is what the reader would have done. The failure
    // stands -- the flag records what happened -- but the sink works again,
    // which is what makes a permanent flag wrong rather than merely strict.
    char drain[4096];
    std::size_t drained = 0;
    while (drained < filled) {
        const auto got = occ::sys::read(fds[0], drain, sizeof(drain));
        if (got.failed() || got.value == 0) {
            break;
        }
        drained += static_cast<std::size_t>(got.value);
    }
    writer.note("after draining");
    check(writer.events_written() == 1, "the writer works once drained");
    check(writer.failed(),
          "the earlier failure is still what the flag reports");

    // Attaching a fresh sink starts a new stream, and the writer is expected
    // to be usable on it rather than carrying the old descriptor's failure.
    int fds2[2] = {-1, -1};
    if (::pipe(fds2) != 0) {
        std::fprintf(stderr, "  note: second pipe failed, skipping\n");
        ::close(fds[0]);
        ::close(fds[1]);
        return;
    }
    writer.attach(fds2[1]);
    check(!writer.failed(), "attaching a sink clears the failure it reported");
    writer.note("third");
    check(!writer.failed(), "and the writer works on the new sink");
    check(writer.events_written() == 2, "counting continues from where it was");

    ::close(fds2[0]);
    ::close(fds2[1]);
    ::close(fds[0]);
    ::close(fds[1]);
}

void test_clear_failure_resets_the_flag() {
    // clear_failure is the other half of the same guarantee: a caller that
    // has already accounted for a failure in whatever it reports, and wants
    // to keep using this writer without moving it, needs a way to say so.
    Writer writer;
    writer.attach(-1);
    writer.note("nowhere");
    check(writer.failed(), "a closed sink fails");

    writer.clear_failure();
    check(!writer.failed(), "clear_failure forgets the failure");

    // It forgets the flag and nothing else: the sink is still closed, so
    // the next write fails again rather than being counted.
    writer.note("still nowhere");
    check(writer.failed(), "the sink is still unusable after a clear");
    check(writer.events_written() == 0, "and still counts nothing");
}

void test_clock_failure_is_not_a_zero_timestamp() {
    // A timestamp of zero is a value the monotonic clock can genuinely
    // produce, so it cannot double as "the clock could not be read". If it
    // did, a run whose clock failed would emit events that appear to
    // precede every real event, and a consumer sorting on t would order
    // them first.
    //
    // The clock is read through the syscall layer, which cannot be made to
    // fail from here, so what is pinned is the property that holds either
    // way: the writer reports a real reading, and repeated events advance.
    Captured cap;
    {
        auto& e = cap.writer.begin(EventKind::Note);
        e.add("which", static_cast<std::uint64_t>(1));
        cap.writer.commit();
    }
    {
        auto& e = cap.writer.begin(EventKind::Note);
        e.add("which", static_cast<std::uint64_t>(2));
        cap.writer.commit();
    }

    const auto lines = cap.lines();
    check(lines.size() == 2, "both events are written");
    if (lines.size() != 2) {
        return;
    }

    // Pull the "t" value out of each line and compare. The strings are
    // short enough that scanning for the key is unambiguous.
    auto read_t = [](const std::string& line) -> long long {
        const std::string key = "\"t\":";
        const std::size_t at = line.find(key);
        if (at == std::string::npos) {
            return -1;
        }
        return std::strtoll(line.c_str() + at + key.size(), nullptr, 10);
    };

    const long long first = read_t(lines[0]);
    const long long second = read_t(lines[1]);
    check(first > 0, "an event carries a real monotonic reading, not zero");
    check(second >= first,
          "a later event is not stamped before an earlier one");
}

void test_escaped_strings() {
    // A target's path is not under this program's control. A quote or a
    // backslash in it must not end the string early, and a control byte
    // must not be written raw into the line.
    Captured cap;
    auto& e = cap.writer.begin(EventKind::FileOpened);
    e.add("path", std::string_view{"a\"b\\c"});
    e.add("weird", std::string_view{"tab\there"});
    cap.writer.commit();

    const auto lines = cap.lines();
    check(lines.size() == 1, "the escaped line is written");
    if (lines.empty()) {
        return;
    }
    check(lines[0].find("\"path\":\"a\\\"b\\\\c\"") != std::string::npos,
          "a quote and a backslash are escaped");
    check(lines[0].find("\\t") != std::string::npos,
          "a control character is escaped");
    // The raw byte must not appear, or the line would break a consumer that
    // splits on it.
    check(lines[0].find('\t') == std::string::npos,
          "no raw tab is written into the line");
}

void test_begin_resets_fields() {
    // A second event must not inherit the first one's fields. A writer is
    // reused for every event in a run, so this is the difference between a
    // stream that describes one run and one that accumulates.
    Captured cap;
    {
        auto& e = cap.writer.begin(EventKind::Note);
        e.add("first", static_cast<std::uint64_t>(1));
        cap.writer.commit();
    }
    {
        auto& e = cap.writer.begin(EventKind::Note);
        e.add("second", static_cast<std::uint64_t>(2));
        cap.writer.commit();
    }

    const auto lines = cap.lines();
    check(lines.size() == 2, "two commits write two lines");
    if (lines.size() != 2) {
        return;
    }
    check(lines[0].find("\"first\"") != std::string::npos,
          "the first event carries its own field");
    check(lines[0].find("\"second\"") == std::string::npos,
          "the first event does not carry the second's field");
    check(lines[1].find("\"second\"") != std::string::npos,
          "the second event carries its own field");
    check(lines[1].find("\"first\"") == std::string::npos,
          "the second event does not inherit the first's field");
}

void test_every_event_has_kind_and_time() {
    Captured cap;
    {
        auto& e = cap.writer.begin(EventKind::Mapping);
        e.add("index", static_cast<std::uint64_t>(3));
        cap.writer.commit();
    }
    const auto lines = cap.lines();
    check(lines.size() == 1, "the event is written");
    if (lines.empty()) {
        return;
    }
    check(lines[0].find("\"kind\":\"mapping\"") != std::string::npos,
          "every event names its kind");
    check(lines[0].find("\"session\":") != std::string::npos,
          "every event names its session");
    check(lines[0].find("\"t\":") != std::string::npos,
          "every event carries a time");
}

void test_commit_without_begin() {
    // Committing without beginning must write nothing rather than emit an
    // empty object, which a consumer would have to special-case.
    Captured cap;
    cap.writer.commit();
    const auto lines = cap.lines();
    check(lines.empty(), "a commit with no begin writes nothing");
    check(cap.writer.events_written() == 0,
          "a commit with no begin counts nothing");
}

void test_note_shortcut() {
    Captured cap;
    cap.writer.note("something happened");
    const auto lines = cap.lines();
    check(lines.size() == 1, "the note is written");
    if (lines.empty()) {
        return;
    }
    check(lines[0].find("\"kind\":\"note\"") != std::string::npos,
          "the note has the note kind");
    check(lines[0].find("\"text\":\"something happened\"") != std::string::npos,
          "the note carries its text");
}

void test_sink_on_closed_descriptor() {
    // The writer is attached to a closed descriptor when the event stream is
    // not wanted, and every emit has to become a no-op instead of failing.
    Writer writer;
    writer.attach(-1);
    writer.note("this goes nowhere");
    check(writer.events_written() == 0,
          "a write to a closed sink does not count as written");
    check(writer.failed(), "a write to a closed sink is reported as a failure");
}

} // namespace

// The shape a probe_hit takes when it carries argument values.
//
// The encoder is flat -- there is no nested object or array in the API -- so
// the six arguments are six fields, arg0 through arg5, and a consumer reads
// the ABI slot from the position in the key. That convention is only useful
// if it is stable, so it is pinned here rather than left to the emission
// site: a change that started writing arg6 or dropped the "name=" prefix
// would still produce a stream that parses, and every consumer would read
// the wrong argument.
void test_probe_hit_argument_fields() {
    Captured cap;
    auto& e = cap.writer.begin(EventKind::ProbeHit);
    e.add("pid", static_cast<std::uint64_t>(7));
    e.add("tid", static_cast<std::uint64_t>(8));
    e.add("label", std::string_view{"NtCreateFile"});
    e.add_hex("ip", 0x401000);
    // What the emission site writes: the name, an equals sign, and the
    // value in hexadecimal, for each of the six slots.
    e.add("arg0", std::string_view{"FileHandle=0x1f"});
    e.add("arg1", std::string_view{"0x7ffe1234"});
    cap.writer.commit();

    const auto lines = cap.lines();
    check(lines.size() == 1, "one commit writes one line");
    if (lines.empty()) {
        return;
    }
    const std::string& line = lines[0];
    check(line.find("\"arg0\":\"FileHandle=0x1f\"") != std::string::npos,
          "a named argument is written as name=value");
    check(line.find("\"arg1\":\"0x7ffe1234\"") != std::string::npos,
          "an unnamed argument is written as a bare value");
    check(line.find("\"args_captured\"") == std::string::npos,
          "a hit with arguments does not also claim they were uncaptured");
}

// The other half: a hit whose registers the kernel did not capture says so,
// rather than carrying six fields of zero that a reader would take for
// arguments.
void test_probe_hit_without_captured_arguments() {
    Captured cap;
    auto& e = cap.writer.begin(EventKind::ProbeHit);
    e.add("label", std::string_view{"NtCreateFile"});
    e.add("args_captured", false);
    cap.writer.commit();

    const auto lines = cap.lines();
    check(lines.size() == 1, "one commit writes one line");
    if (lines.empty()) {
        return;
    }
    check(lines[0].find("\"args_captured\":false") != std::string::npos,
          "the absence of arguments is stated rather than implied");
    check(lines[0].find("\"arg0\"") == std::string::npos,
          "no zero-valued argument field is invented");
}

int main() {
    test_kind_names();
    test_value_types();
    test_pointer_not_confused_with_bool();
    test_begin_keeps_an_uncommitted_event();
    test_failed_writer_can_be_reused();
    test_clear_failure_resets_the_flag();
    test_clock_failure_is_not_a_zero_timestamp();
    test_escaped_strings();
    test_begin_resets_fields();
    test_every_event_has_kind_and_time();
    test_commit_without_begin();
    test_note_shortcut();
    test_sink_on_closed_descriptor();
    test_probe_hit_argument_fields();
    test_probe_hit_without_captured_arguments();

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

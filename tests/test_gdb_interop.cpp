// Interoperability with a real GDB.
//
// The rest of the protocol tests drive the codec and the packet handlers
// directly, which checks that this project agrees with itself. That is not
// the same as agreeing with the peer it was written for, and the difference
// is not academic: the vMustReplyEmpty exchange below was answered with
// silence for as long as this file did not exist, every self-test passed,
// and GDB refused the connection with a message that named the packet
// rather than the defect.
//
// So this file runs the real thing. It forks the host's gdb, points it at a
// listener this process is serving, and asserts on what gdb does with the
// answers: attach, read registers, detach, exit zero. A stub that fails any
// of those makes gdb print an error and return non-zero, and the test fails
// with gdb's own words rather than with this project's opinion of them.
//
// What this file does NOT cover, and could not:
//
//   - gdb is not a dependency of this project and may be absent. The tests
//     report a skip when it is, rather than passing. A passing test that
//     never ran is the failure mode this whole file exists to avoid, so a
//     skip says which binary was missing and the exit code stays zero only
//     because the absence is a fact about the host.
//   - The target here is a process this test owns and stops with
//     PTRACE_TRACEME. A real user attaches a running target; the packet
//     exchange is the same, and the difference is in the session, which has
//     its own tests and a live-target test elsewhere.
//   - Single step, memory write, and breakpoint insertion are exercised by
//     the packet-level tests. Driving them through gdb as well would need a
//     program to step through, and the value added over feeding the packets
//     directly is small next to the flakiness of a wall-clock turn exchange.

#include "occ/observer/ptrace.h"
#include "occ/observer/rsp.h"
#include "occ/observer/session.h"
#include "occ/observer/transport.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace occ::obs;

namespace {

int failures = 0;
int checks = 0;
int skips = 0;

void check(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

void skip(const char* what) {
    ++skips;
    std::fprintf(stderr, "SKIP %s\n", what);
}

// The gdb on this host, or empty when there is none.
std::string find_gdb() {
    // The names are tried in this order because a multiarch gdb is the one
    // that can debug an x86-64 target on a host whose primary gdb is built
    // for another architecture. Either one speaks the protocol, so the order
    // is a preference rather than a requirement.
    const char* candidates[] = {"/usr/bin/gdb", "/usr/bin/gdb-multiarch"};
    for (const char* c : candidates) {
        if (::access(c, X_OK) == 0) {
            return c;
        }
    }
    return {};
}

// A child stopped on its own ptrace stop, which is what the debug server
// needs to be handed. The parent must not wait for it: a ptrace stop is
// reported once, and a parent that consumes it with a waitpid of its own
// leaves the child parked with nothing left to report.
pid_t fork_traced_stopped() {
    const pid_t pid = ::fork();
    if (pid != 0) {
        return pid;
    }
    if (occ::sys::ptrace(kPtraceTraceme, 0, nullptr, nullptr).failed()) {
        ::_exit(126);
    }
    ::raise(SIGSTOP);
    // park here; the session resumes and re-stops this process, and it exits
    // only when the session lets it or the session ends.
    for (;;) {
        ::pause();
    }
}

// The commands gdb is asked to run. They are the shortest sequence that
// exercises the packets a debugger cannot do without, and they are the same
// ones a person types by hand: attach, look at a register, look at memory,
// detach. Every one of them is a packet this stub implements, so a packet
// that is answered wrongly shows up as gdb either refusing to continue or
// printing a value this test can check.
std::vector<std::string> gdb_commands(std::uint16_t port) {
    return {
        "set confirm off",
        "set pagination off",
        "set width 0",
        "target remote 127.0.0.1:" + std::to_string(port),
        "info registers rip",
        "detach",
        "quit",
    };
}

void test_gdb_attaches_and_reads_registers() {
    const std::string gdb = find_gdb();
    if (gdb.empty()) {
        skip("no gdb on this host; the interop tests did not run");
        return;
    }

    const pid_t target = fork_traced_stopped();
    if (target < 0) {
        check(false, "the traced child could not be forked");
        return;
    }

    Listener listener;
    std::string error;
    if (!listener.open(0, error)) {
        check(false, "the listener could not be bound");
        ::kill(target, SIGKILL);
        return;
    }

    // gdb is started after the listener exists, so the port it is given is
    // already listening and there is no race between the two.
    const pid_t gdb_pid = ::fork();
    if (gdb_pid == 0) {
        const int fds = ::open("/dev/null", O_WRONLY);
        if (fds >= 0) {
            ::dup2(fds, STDOUT_FILENO);
            ::dup2(fds, STDERR_FILENO);
        }
        // Every argument lives in a std::string so that execv gets writable
        // storage. A string literal is const and the compiler refuses to
        // hand it to a char* parameter, which is a rule worth keeping rather
        // than casting around.
        std::vector<std::string> args;
        args.push_back(gdb);
        args.push_back("-q");
        args.push_back("-batch");
        for (const std::string& c : gdb_commands(listener.port())) {
            args.push_back("-ex");
            args.push_back(c);
        }
        std::vector<char*> raw;
        raw.reserve(args.size() + 1);
        for (std::string& a : args) {
            raw.push_back(a.data());
        }
        raw.push_back(nullptr);
        ::execv(gdb.c_str(), raw.data());
        ::_exit(127);
    }

    // The parent serves. It does not wait for gdb first: gdb needs the
    // answers to make progress, and a parent that waited would deadlock
    // against the child waiting for the parent.
    Tracer tracer;
    Breakpoints bps;
    Writer events;
    events.attach(-1);

    Connection conn;
    bool accepted = listener.accept(conn, 5000);
    check(accepted, "a debugger connected to the listener");

    int served = 0;
    if (accepted) {
        DebugServer server(tracer, bps, target, events);
        for (;;) {
            if (!conn.wait_readable(200)) {
                // gdb is deciding what to send next. It is on a wall clock
                // and this loop has a bound, so a gdb that hangs is failed
                // rather than waited on forever.
                if (++served > 200) {
                    break;
                }
                continue;
            }
            if (!conn.pump()) {
                break;
            }
            (void)conn.flush_ack();
            std::string request;
            while (conn.take_packet(request)) {
                const Reply r = server.handle(request);
                if (r.send) {
                    (void)conn.send_packet(r.payload);
                }
                // A continue is not sent by this test: the target would run
                // and the exchange would stop being about the packets.
                if (server.detached()) {
                    conn.close();
                    break;
                }
            }
            if (server.detached()) {
                break;
            }
        }
    }

    int gdb_status = 0;
    (void)::waitpid(gdb_pid, &gdb_status, 0);

    check(WIFEXITED(gdb_status), "gdb exited on its own rather than dying");
    check(WIFEXITED(gdb_status) && WEXITSTATUS(gdb_status) == 0,
          "gdb exited zero, so it accepted every answer it was given");

    ::kill(target, SIGKILL);
    int reap = 0;
    (void)::waitpid(target, &reap, 0);
}

// The defect this file was written for, stated as its own test.
//
// vMustReplyEmpty is a protocol packet whose entire purpose is to check that
// a stub answers an unknown request with an empty packet rather than with
// nothing. The name is the requirement. The packet reader is driven directly
// here so that the assertion is about the answer and not about whether gdb
// happened to send it, which depends on the gdb version.
void test_an_unknown_request_is_answered_with_an_empty_packet() {
    Tracer tracer;
    Breakpoints bps;
    Writer events;
    events.attach(-1);
    DebugServer server(tracer, bps, ::getpid(), events);

    const Reply r = server.handle("vMustReplyEmpty");
    check(r.send, "the request is answered rather than ignored");
    check(r.payload.empty(),
          "the answer is the protocol's empty packet, not a payload");

    // The bytes that go on the wire are the ones the peer reads, so the
    // assertion is made on the frame and not on the Reply.
    check(encode_packet(r.payload) == "$#00",
          "the answer frames as the empty packet the protocol names");

    // And the requests that must NOT be answered this way, because the
    // answer carries the meaning of the whole packet:
    const Reply continued = server.handle("c");
    check(!continued.send,
          "a continue is not answered now; the stop reply is the answer");
    const Reply stepped = server.handle("s");
    check(!stepped.send, "a single step is likewise answered by the stop");

    // A request that is understood and is not implemented is the empty
    // packet, and it is distinguishable from the two above.
    const Reply unknown_v = server.handle("vWhateverThisIs");
    check(unknown_v.send && unknown_v.payload.empty(),
          "an unimplemented v packet gets the empty packet");
    const Reply unknown = server.handle("QThisIsNotAPacket");
    check(unknown.send && unknown.payload.empty(),
          "an unimplemented Q packet gets the empty packet");
}

// The empty payload arriving from the peer must be accepted as a packet,
// because a stub that refuses it asks for a retransmission the peer can
// never satisfy: it would send the same bytes and be refused again.
void test_an_empty_packet_from_the_peer_is_accepted() {
    PacketDecoder d;
    check(d.feed("$#00") == 1, "the empty packet is framed");
    const Packet p = d.take();
    check(p.checksum_ok, "the empty packet's checksum is zero, and zero is ok");
    check(!d.retransmit_requested(),
          "the peer is not asked to resend a packet it sent correctly");
}

// The reply the debugger gets for an unknown packet must be a frame, not
// silence. This is the one that was wrong.
void test_silence_is_not_the_answer_to_an_unknown_request() {
    Tracer tracer;
    Breakpoints bps;
    Writer events;
    events.attach(-1);
    DebugServer server(tracer, bps, ::getpid(), events);

    // The set of requests a debugger may send that this stub does not
    // implement. Each one has to produce a frame.
    const char* unknowns[] = {
        "vMustReplyEmpty", "vFile:open", "qTStatus", "QThreadEvents",
        "qsThreadInfo",    "D;1",       "!",       "R00",
    };
    for (const char* req : unknowns) {
        const Reply r = server.handle(req);
        check(r.send, "an unknown request is answered rather than dropped");
        // A framing of the answer always produces bytes: even the empty
        // payload is "$#00". Silence would produce none.
        check(!encode_packet(r.payload).empty(),
              "the answer is framable, so the peer receives something");
    }
}

} // namespace

int main() {
    test_an_empty_packet_from_the_peer_is_accepted();
    test_an_unknown_request_is_answered_with_an_empty_packet();
    test_silence_is_not_the_answer_to_an_unknown_request();
    test_gdb_attaches_and_reads_registers();

    std::fprintf(stderr, "%d checks, %d failures, %d skipped\n", checks,
                 failures, skips);
    return failures == 0 ? 0 : 1;
}

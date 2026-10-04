#pragma once

// The observation session.
//
// A session owns a traced process and the loop that serves it: it waits for
// stops, decides what each one means, reports it, and answers the remote
// debugger. It is the layer that turns three independent mechanisms into
// one running thing.
//
// The loop is deliberately single-threaded and stop-driven. A tracer that
// polled, or that used a second thread to read events, would have two
// readers of the same process state and no ordering between them, and the
// whole point of an observation session is that the record it produces is
// in the order the stops happened.
//
// The session is also the place where the pieces have to agree about what a
// stop means. A breakpoint, a single step override, a seccomp trap and a
// signal all arrive as the same kind of kernel event, and the session is
// what knows which one it arranged and therefore which one it is looking at.

#include <cstdint>
#include <string>
#include <vector>

#include "occ/observer/event.h"
#include "occ/observer/ptrace.h"
#include "occ/observer/rsp.h"
#include "occ/observer/watchpoint.h"
#include "occ/observer/wx.h"
#include "occ/probe/placer.h"

namespace occ::obs {

struct SessionConfig {
    // The process to observe. It has to be stopped, or the session has to
    // be given the right to stop it.
    int pid = 0;

    // Whether to trace syscalls. Turning this on makes the session stop
    // twice per syscall, which is the single largest cost the observer can
    // add to a target.
    bool trace_syscalls = false;

    // Whether to install the fork and exec event options. A session that
    // does not follow children is a session that stops observing at the
    // first fork, which is why this defaults on.
    bool follow_forks = true;

    // Whether to watch for write-then-execute transitions.
    //
    // This costs the target: a hardware watch takes a debug register, there
    // are four, and every write to a watched region stops the session. It is
    // off by default because a run that is not looking for self-modifying
    // code should not pay for the possibility.
    bool track_wx = false;

    // Which regions the tracker watches when track_wx is on. Empty means
    // "work it out from the target's own maps", which is the right answer
    // for a run that does not know the image in advance. A caller that does
    // know -- an unpacker that has already located the staging buffer --
    // names the regions and skips the scan.
    std::vector<WatchTarget> wx_regions;

    // Whether a region has to be anonymous to be watched. A decoder's
    // staging buffer is anonymous, and requiring it cuts the number of
    // candidate regions to roughly one per allocation rather than one per
    // mapping, which matters when there are four debug registers and a
    // linker maps dozens.
    bool wx_anonymous_only = true;

    // The largest total region size the tracker will consider. A target that
    // maps a gigabyte of writable memory is not going to have its decoder
    // found by watching the first four words of it, and a limit keeps the
    // scan from proposing regions that could never be covered.
    std::uint64_t wx_max_region_bytes = 16u * 1024u * 1024u;

    // Whether to serve a remote debugger. When false the session only
    // produces events, and the loop never reads from the client
    // descriptor.
    bool serve_gdb = false;

    // The descriptor the remote debugger speaks on, and the one it reads
    // from. Two descriptors rather than one because the protocol is
    // full-duplex and a debugger may send an interrupt while it is reading
    // a stop reply.
    int gdb_read_fd = -1;
    int gdb_write_fd = -1;

    // A listening socket to accept the debugger on, rather than a
    // connection that already exists.
    //
    // The distinction is the whole reason a run can print its port before
    // it has a debugger: the caller binds and reports, the target starts, and
    // the debugger connects whenever it is ready. Handing over a live
    // connection instead would mean the run had to wait for a debugger that
    // had not been told where to connect yet, which is a deadlock rather
    // than a feature. The loop accepts at most one debugger; a second
    // connection is refused, because two debuggers cannot both drive one
    // tracee.
    int gdb_listen_fd = -1;

    // The port that socket is bound to, reported in the event stream when a
    // debugger attaches. Zero when the session was handed a connection rather
    // than a listener.
    std::uint16_t gdb_port = 0;

    // The probes to watch, and the layer that placed them.
    //
    // The session does not place them. A probe's offset comes from an ELF
    // read of a module the engine named, and the engine is what knows which
    // module that is: a session that resolved symbols itself would be a
    // second reader of the same image, disagreeing with the first at
    // exactly the moment it matters. So the placer runs before the target
    // starts -- the probe has to be in place before the tracee reaches the
    // function -- and the session is handed the layer to poll.
    //
    // Null means no function-level observation. The syscall trace is
    // unaffected either way, which is the point of keeping the two
    // independent.
    ProbePlacer* probes = nullptr;

    // Whether to hold the target at its first stop until a debugger
    // arrives.
    //
    // Without this the window for setting a breakpoint is a race: the
    // session serves the debugger between the target's stops, so a debugger
    // that connects while the target is running joins it at whatever
    // instruction it happens to be at. For a target that runs to completion
    // in a few milliseconds -- which is most of them -- that window is
    // already closed by the time a person has typed the port number. Holding
    // at the first stop makes "break main" mean what it says.
    bool wait_for_debugger = false;
};

// What a session did.
struct SessionResult {
    bool failed = false;
    std::string detail;

    // The number of stops the session handled, which is the honest measure
    // of how much it observed.
    std::uint64_t stops = 0;
    std::uint64_t syscall_stops = 0;
    std::uint64_t breakpoint_hits = 0;
    std::uint64_t signals = 0;
    std::uint64_t transitions = 0;

    // What the write tracker managed. These are reported rather than assumed
    // because the hardware has four debug registers and a candidate region
    // is a whole page: the honest answer is usually "four bytes of the
    // first region", and a caller that was told "tracking" with no numbers
    // would read that as coverage it does not have.
    std::uint64_t wx_regions = 0;
    std::uint64_t wx_watches = 0;
    std::uint64_t wx_bytes_covered = 0;
    std::uint64_t wx_bytes_total = 0;
    std::uint64_t wx_regions_unwatched = 0;
    // Samples the kernel reported as lost, which are accesses the observer
    // never saw. Nonzero means the record is incomplete.
    std::uint64_t wx_lost_samples = 0;
    // True when no hardware watch could be installed at all, which is the
    // normal result on a host whose policy blocks perf_event_open. It is
    // reported as a fact rather than as a failure because the rest of the
    // session is unaffected.
    bool wx_unavailable = false;

    // Function-level observation. The hit count is the honest measure of
    // how much of the target the probes saw, and the lost count is the part
    // of it they did not: "the ring wrapped" and "the function was never
    // called" are the same absence in a stream that carries neither.
    std::uint64_t probe_hits = 0;
    std::uint64_t probe_lost = 0;
    // How many of the layer's probes were actually polled. A probe that
    // registered but never subscribed has no descriptor, so it can never
    // produce a hit -- and a consumer that was told "twelve probes" would
    // read no hits from the twelfth as a function that was never called.
    std::uint64_t probes_watched = 0;

    int exit_code = 0;
    int term_signal = 0;
    bool signaled = false;
};

// Runs the observation loop until the traced process ends or the debugger
// detaches.
[[nodiscard]] SessionResult observe(const SessionConfig& config,
                                    Writer& events) noexcept;

// ------------------------------------------------------------------- packets
//
// These three are the parts of the packet layer that do not need a live
// process to exercise. They are free functions rather than members because a
// test can then check that every feature announced in qSupported is actually
// answered, which is a contract that is easy to break and impossible to
// notice without a debugger on the other end of a socket.
//
// The target description is the important one. A remote stub that does not
// answer qXfer:features:read makes GDB fall back to its built-in default,
// which describes a 32-bit i386 target, and every register the debugger
// displays is then read at the wrong width from the wrong offset.

// The target description served through qXfer:features:read.
[[nodiscard]] std::string_view target_description() noexcept;

// Answers the packet body after "qXfer:features:read:", which is the annex
// and the range separated by a colon, for example "target.xml:0,400".
// Returns an empty string for a malformed packet, "l" for an annex that does
// not exist, and otherwise the chunk prefixed by 'm' or 'l'.
[[nodiscard]] std::string serve_target_description(std::string_view args) noexcept;

// The size in bytes of the 'g' reply for x86-64, and the width in bits of the
// register at the given position in it.
//
// These are exposed so a test can hold the register block against the
// description. The two are written in different places -- one is the table the
// packer walks, the other is the document GDB reads -- and a register that
// disagrees between them is invisible from either side: the block comes out
// self-consistent and the right length, GDB accepts the description, and every
// register past the mismatch shows a plausible value under the wrong name. The
// only symptom is a debugger whose %st0 holds %fop.
//
// The block is not eight bytes per register. GDB packs a target description
// end to end with no padding, so x86-64 is 300 bytes: seventeen general
// registers and %rip at eight each, %eflags and the six segment selectors at
// four, the eight x87 stack registers at ten, the eight x87 control registers
// at four, and %fs_base, %gs_base and %orig_rax at eight.
[[nodiscard]] std::size_t gdb_register_block_size() noexcept;

// The width of the register at the given position in the 'g' block, in bits, or
// zero if the position is past the end of the block.
[[nodiscard]] unsigned gdb_register_bits(std::size_t index) noexcept;

// The register numbers GDB assigns to the three this stub adds past the core
// feature, which are not positions in the block: GDB reserves 40 through 51
// for the SSE and AVX banks this description does not declare, so the segment
// bases land far past the forty. Exposed so a test can hold the 'p' handler's
// numbering against them.
[[nodiscard]] std::size_t gdb_regnum_fs_base() noexcept;
[[nodiscard]] std::size_t gdb_regnum_gs_base() noexcept;
[[nodiscard]] std::size_t gdb_regnum_orig_rax() noexcept;

// Answers the packet body after "vCont". Consumes and step_requested() are
// set when the packet asked for a resume, which the session loop performs
// rather than the packet layer.
[[nodiscard]] std::string parse_vcont(std::string_view args, int pid,
                                      bool& consume, bool& step,
                                      int& signal) noexcept;

// The remote debugger protocol, as a state machine over one process. Kept
// separate from the loop so that the packet handling can be tested by
// feeding it packets, without a live process to trace.
class DebugServer {
public:
    DebugServer(Tracer& tracer, Breakpoints& breakpoints, int pid,
                Writer& events) noexcept
        : tracer_(&tracer), breakpoints_(&breakpoints), pid_(pid),
          events_(&events) {}

    // Handles one decoded packet and produces the response payload. An
    // empty response means the packet is not supported, which the protocol
    // defines as an answer rather than a failure.
    [[nodiscard]] std::string handle(std::string_view packet) noexcept;

    // True when the client asked to detach. The loop uses it to stop.
    [[nodiscard]] bool detached() const noexcept { return detached_; }

    // True when the client asked for a continue or a step, which the loop
    // has to act on rather than answer.
    [[nodiscard]] bool resume_requested() const noexcept {
        return resume_requested_;
    }
    [[nodiscard]] bool step_requested() const noexcept { return step_; }
    void clear_resume() noexcept {
        resume_requested_ = false;
        step_ = false;
        resume_signal_ = 0;
    }
    [[nodiscard]] int resume_signal() const noexcept { return resume_signal_; }

private:
    std::string handle_query(std::string_view kind) noexcept;
    // Serves "qXfer:features:read:target.xml:OFFSET,LENGTH". The target
    // description is what tells GDB the register file is 64 bits wide; the
    // protocol's built-in default describes a 32-bit i386 target, which
    // makes every offset in a register read wrong.
    std::string handle_qxfer_features(std::string_view args) noexcept;
    // Serves "vCont", the multiplexed form of continue and single step.
    // Implemented alongside the older packets rather than instead of them, so
    // a debugger that does not use vCont is unaffected.
    std::string handle_vcont(std::string_view args) noexcept;
    std::string handle_read_memory(std::string_view args) noexcept;
    std::string handle_write_memory(std::string_view args) noexcept;
    std::string handle_read_registers() noexcept;
    std::string handle_write_registers(std::string_view args) noexcept;
    std::string handle_breakpoint(std::string_view args) noexcept;
    std::string handle_thread() noexcept;

    Tracer* tracer_;
    Breakpoints* breakpoints_;
    int pid_;
    Writer* events_;

    bool detached_ = false;
    bool resume_requested_ = false;
    bool step_ = false;
    int resume_signal_ = 0;
};

} // namespace occ::obs

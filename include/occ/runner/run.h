#pragma once

// A run of a target under observation.
//
// The runner is the layer that knows how the three pieces fit together: the
// parser says what the image wants, the container builds the environment it
// runs in, and the observer reports what it did. None of the three knows
// about the others, which is what keeps each one testable on its own.
//
// What the runner adds is the sequence. It reads the target, decides whether
// the image is one this build can run, builds the container configuration,
// starts the target, reports every fact it has about it, and collects the
// exit status. The order of the reported facts is part of the interface: an
// image_loaded event is written before any mapping event, so a consumer that
// reads the stream top to bottom has a complete picture at every point.

#include <cstdint>
#include <string>
#include <vector>

#include "occ/engine/engine.h"
#include "occ/isolation/container.h"
#include "occ/observer/event.h"
#include "occ/observer/wx.h"
#include "occ/parser/detect.h"

namespace occ::runner {

// What a caller can ask a run to do.
struct RunOptions {
    // Where the new root comes from. Empty means the caller wants a
    // read-only bind of the host's own root, which is the smallest setup
    // that still gives the target a coherent filesystem.
    std::string root_dir;
    std::string upper_dir;
    std::string work_dir;

    isolation::RootKind root_kind = isolation::RootKind::ReadOnlyBind;

    // Resource limits. Zero means unlimited.
    std::uint64_t memory_bytes = 0;
    std::uint64_t pids = 0;
    std::uint32_t cpu_percent = 0;

    // The directory a cgroup is created under. Empty disables the cgroup
    // step, which is what a run without a delegated hierarchy has to do.
    std::string cgroup_parent;

    // Extra bind mounts, applied after the root is assembled.
    std::vector<isolation::ContainerConfig::BindMount> extra_mounts;

    // Whether the target's own output goes to the terminal unchanged. When
    // this is false the target's stdout is still inherited: the event
    // stream goes to its own descriptor, so the two do not interleave.
    bool stream_events = true;

    // Whether to trace the target with ptrace while it runs. A traced
    // target is stopped twice per syscall and cannot be attached to by
    // anything else, so this is off by default: a run that only needs the
    // isolation facts should not pay for observation it did not ask for.
    bool observe = false;

    // Whether to place the probes the engine asked for and report a hit
    // every time the target enters one of the functions.
    //
    // This implies observe, and the implication is not incidental: a probe
    // is a fact reported through the same stream as the stops, and a run
    // that placed probes with no session to read their rings would leave
    // the tracefs events behind for the next run to find. It is separate
    // from observe because a caller who wants a syscall trace should not
    // silently get an ELF read of a Wine installation as well, and separate
    // from the engine because the engine says which probes it wants and
    // this says whether anyone is going to watch them.
    bool probe = false;

    // Forces the probe layer on or off, overriding what `probe` would
    // otherwise imply. OCC_PROBE is consulted for this, because the
    // decision depends on a host property -- whether tracefs is mounted --
    // that a caller may know better than the run does.
    //
    // An explicit off is not the same as an absence. A caller who has said
    // "no probes" has asked for a syscall-only run and should not be told
    // about a probe layer that was unavailable, because nothing was asked
    // of it.
    enum class ProbeMode : std::uint8_t {
        // Act on `probe`, and on what the host offers.
        Automatic,
        // Place probes and report a degradation when the host refuses.
        Force,
        // Place nothing and report nothing.
        Disabled,
    };
    ProbeMode probe_mode = ProbeMode::Automatic;

    // Whether to watch for write-then-execute transitions while observing.
    // It implies observe, because a tracker with no stops has nothing to
    // drain the watch events between.
    bool track_wx = false;

    // Which regions to watch. Empty means the target's own maps are scanned
    // for candidates, which is right for a run that does not know the image
    // in advance.
    std::vector<obs::WatchTarget> wx_regions;

    // Whether a candidate region has to be anonymous. A decoder's staging
    // buffer is, and requiring it keeps the four debug registers from being
    // spent on the parts of a binary that will never hold generated code.
    bool wx_anonymous_only = true;

    // The largest region the tracker will consider.
    std::uint64_t wx_max_region_bytes = 16u * 1024u * 1024u;

    // Where the target is, for a run that is being set up for a debugger to
    // reach later. Empty for an ordinary run.
    std::string session_id;

    // The descriptor a remote debugger speaks on, when one is being served.
    // Negative means none.
    int gdb_read_fd = -1;
    int gdb_write_fd = -1;

    // A listening socket for a debugger to connect to, and the port it is
    // bound to.
    //
    // This is how a run reports where to attach before anyone has: the
    // socket is bound before the target starts, so the port is known and can
    // be printed, and the debugger connects whenever it is ready. Passing a
    // connected descriptor instead would require a debugger to be waiting
    // first, which is a deadlock rather than a handshake.
    int gdb_listen_fd = -1;
    std::uint16_t gdb_port = 0;

    // Whether to hold the target at its first stop until a debugger
    // connects. See SessionConfig::wait_for_debugger for why the default is
    // the other way round.
    bool gdb_wait = false;

    // Environment for the target. Empty means a minimal environment is
    // built from the host's PATH and TERM, which is enough for a static
    // binary and avoids passing through a variable that changes behaviour.
    std::vector<std::string> env;

    // A directory this run owns, created if it does not exist and removed
    // when the run ends. An engine that keeps state on disk needs one, and
    // the runner is what knows when the run is over. Empty means the runner
    // picks one under /run, named after the process so two concurrent runs
    // cannot collide.
    //
    // A caller that names a directory here is responsible for it being
    // somewhere the target's writes cannot outlive the run, which in
    // practice means not a directory the target can reach twice.
    std::string scratch_dir;

    // The engine the caller asked for, by the name an engine reports, or
    // "occ" for whichever engine this build routes the format to. Empty
    // means the caller did not say, and the detection decides.
    //
    // This is an assertion the run verifies rather than a second routing
    // table: the detection still picks the engine, and a caller who named
    // one that would not have been picked is told so instead of silently
    // getting what the detection chose. `occ run --engine=occ hello.exe` is
    // the form a caller writes when they want to say out loud that the run
    // is this build's own runtime and not something found on the host.
    std::string engine;
};

// Whether a run should try to place probes, given the flag and the mode.
//
// A named function rather than three lines inside run(), because it is the
// one place where "no" and "not asked" have to stay apart and inside a
// hundred-line setup path there is nothing that holds them apart. The rule
// is small and total: Force means yes, Disabled means no, and Automatic
// means whatever the flag says. A caller reading this can see that an
// explicit off outranks the flag without reading the run.
[[nodiscard]] bool wants_probes(bool probe_flag,
                               RunOptions::ProbeMode mode) noexcept;

// How a run ended.
struct RunResult {
    // True when the run could not be started or did not complete. An exit
    // code is not an error: a target that exits 3 is a successful run whose
    // target chose 3. This is a separate flag rather than a test on
    // `error.error`, because a refusal has a reason but no errno, and a
    // caller that tested the errno would read a refusal as a success.
    bool failed = false;

    // The stage and errno of a failure, and the human-readable reason.
    isolation::ContainerError error;

    // The reason a run was refused, set when `failed` is true and the
    // failure was a refusal rather than a failing syscall.
    std::string failure_detail;

    int exit_code = 0;
    int term_signal = 0;
    bool signaled = false;

    // Facts about the image, filled in whether or not the target ran, so a
    // caller can report what it would have run even when it refused to.
    bool image_loaded = false;

    // The reader's name for a failure, and its explanation. A string rather
    // than parser::LoadError because two readers report into this and a
    // struct that held both enums would be a tagged union with no tag: a
    // caller testing it would have to know which reader produced the value
    // before it could read it. What a caller does with this is print it or
    // compare it, and a string does both.
    std::string load_error;
    std::string load_detail;

    // The format that was detected and the engine that took it, so a caller
    // can say which of them produced a run without re-reading the file. The
    // engine name is the same token `occ check` prints.
    parser::Format format = parser::Format::Unknown;
    std::string engine;

    std::uint64_t entry = 0;
    std::uint64_t mapping_count = 0;
    std::size_t events = 0;

    // What the engine could not do, and what it did instead. Not a failure:
    // a run continues after a degradation and reports it, because a run
    // that produced less than it was asked for and said nothing is worse
    // than one that produced less.
    std::vector<std::string> degradations;

    // Filled in only when the run was observed. A caller that did not ask
    // for observation gets zeros here, which is the honest answer: nothing
    // was observed.
    std::uint64_t stops = 0;
    std::uint64_t syscall_stops = 0;
    std::uint64_t breakpoint_hits = 0;
    std::uint64_t observed_signals = 0;

    // What the write tracker saw and what it could not see. The coverage
    // numbers are here because "tracking was on" says nothing about whether
    // it watched anything: the hardware has four debug registers, and a
    // region is a page.
    std::uint64_t wx_transitions = 0;
    std::uint64_t wx_regions = 0;
    std::uint64_t wx_watches = 0;
    std::uint64_t wx_bytes_covered = 0;
    std::uint64_t wx_bytes_total = 0;
    std::uint64_t wx_lost_samples = 0;
    bool wx_unavailable = false;

    // What the probes saw. `probes_requested` counts what the engine asked
    // for, `probes_attached` counts what the kernel accepted, and
    // `probe_hits` counts the calls. The three are reported rather than one
    // ratio because each of their differences means something else: a
    // request that was not attached is a hole in the coverage, and an
    // attached probe with no hits is either a function that was never
    // called or a ring that was never polled.
    std::uint64_t probes_requested = 0;
    std::uint64_t probes_attached = 0;
    std::uint64_t probe_hits = 0;
    std::uint64_t probe_lost = 0;
    // The layer's own sentence when no probe could be placed at all.
    std::string probes_unavailable;
};

// Reads `path`, reports what the image is, and runs it under the container
// described by `options`. Facts go to `events` as they are established.
//
// The run is dispatched on the file's format: the detection names an
// engine, the engine reads the image and produces the process to launch,
// and everything after that is the same code whatever the format was. A
// format with no engine, and an engine that refuses, both stop here with a
// named reason.
[[nodiscard]] RunResult run(const std::string& path,
                            const std::vector<std::string>& argv,
                            const RunOptions& options,
                            obs::Writer& events);

// Reads the image and reports it without running anything. Split out so
// that a caller can show what would happen, and so that `occ check` and the
// run path agree on what the image is rather than being two implementations
// that can drift: this calls the same engine the run path calls, on the
// same file, and gets the same answer.
//
// The returned LoadedImage carries the engine that read it, so a caller
// that has one knows which engine's rules the answer was produced under.
[[nodiscard]] engine::LoadedImage inspect(const std::string& path,
                                          obs::Writer* events,
                                          std::string& read_error);

} // namespace occ::runner

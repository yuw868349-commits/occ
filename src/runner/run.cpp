#include "occ/runner/run.h"

#include "occ/engine/engine.h"
#include "occ/observer/session.h"
#include "occ/parser/detect.h"
#include "occ/syscall/errno.h"
#include "occ/syscall/syscall.h"
#include "occ/util/fs.h"
#include "occ/util/log.h"
#include "occ/util/string.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <unistd.h>

namespace occ::runner {

namespace {

// The environment a target gets when the caller did not supply one. Passing
// the whole host environment through would hand the target every variable
// the operator happens to have set, and a variable like LD_PRELOAD changes
// what the binary does. These three are what a static binary needs.
std::vector<std::string> default_environment(const RunOptions& options) {
    if (!options.env.empty()) {
        return options.env;
    }
    std::vector<std::string> env;
    env.emplace_back("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:"
                     "/usr/bin:/sbin:/bin");
    env.emplace_back("TERM=dumb");
    // A run is not interactive. Making that explicit stops a target from
    // waiting on a terminal that will never answer.
    env.emplace_back("OCC_SANDBOX=1");
    return env;
}

// Appends the entries an engine asked for, without displacing one the
// caller set.
//
// The caller's entry wins, and that is the rule rather than an accident of
// iteration order: a caller who set WINEPREFIX has said where the prefix
// goes, and an engine that overrode it would be discarding an explicit
// instruction. A later engine entry still displaces an earlier one, so two
// entries from the same engine resolve the same way regardless of order.
std::vector<std::string> merge_environment(
    const std::vector<std::string>& base,
    const std::vector<std::string>& additions) {
    std::vector<std::string> out = base;
    for (const std::string& entry : additions) {
        const std::size_t eq = entry.find('=');
        if (eq == std::string::npos || eq == 0) {
            // An entry with no '=' is not an environment variable, and
            // passing it to execve would put a nameless entry in the
            // target's environment where it can be read by anything that
            // iterates it. Dropped rather than refused: the engine that
            // produced it has already been asked, and refusing the whole
            // run over a string it will never read is a worse outcome.
            continue;
        }
        const std::string_view key(entry.data(), eq);
        bool replaced = false;
        for (std::string& existing : out) {
            const std::size_t existing_eq = existing.find('=');
            if (existing_eq == std::string::npos) {
                continue;
            }
            if (std::string_view(existing.data(), existing_eq) == key) {
                existing = entry;
                replaced = true;
                break;
            }
        }
        if (!replaced) {
            out.push_back(entry);
        }
    }
    return out;
}

// Reports the end of a session that never started, and the reason. Every
// path that stops before a process exists comes through here, so a stream
// that shows a refusal still ends with a session_end and a reader does not
// have to treat a short stream as a broken one.
RunResult refuse(RunResult out, obs::Writer& events,
                 const std::string& reason) {
    out.failed = true;
    out.failure_detail = reason;
    events.note(reason);
    auto& end = events.begin(obs::EventKind::SessionEnd);
    end.add("started", false);
    events.commit();
    out.events = events.events_written();
    return out;
}

} // namespace

engine::LoadedImage inspect(const std::string& path, obs::Writer* events,
                           std::string& read_error) {
    read_error.clear();

    // The detection reads the file to find out what it is, and the engine
    // reads it again to parse it. Two reads rather than one because they
    // answer different questions and the readers are separate: the
    // detection must be cheap and total -- it has to work on a file no
    // parser can read at all -- and the parser must be exact about a file
    // it has already been told is its own format. A reader that detected
    // and parsed in one pass would have to trust its own signature check
    // before committing to a layout, which is the mistake every
    // format-confused parser makes.
    const parser::Detection detection = parser::detect_file(path);
    if (detection.format == parser::Format::Unknown) {
        read_error = detection.evidence.empty()
                         ? "no signature matched"
                         : detection.evidence.front();
    }

    const engine::Engine* chosen = engine::engine_for(detection);
    if (chosen == nullptr) {
        engine::LoadedImage out;
        out.format = detection.format;
        out.error = "no engine handles this format";
        out.detail = parser::format_name(detection.format);
        if (events != nullptr) {
            auto& e = events->begin(obs::EventKind::ImageLoaded);
            e.add("path", path);
            e.add("engine", "none");
            e.add("size", detection.file_size);
            e.add("ok", false);
            e.add("error", out.error);
            e.add("detail", out.detail);
            events->commit();
        }
        return out;
    }

    // The engine's own judgement on the detection comes before the read, so
    // a refusal that does not need the file does not pay for it. A
    // detection-level refusal says the engine will not take this file, and
    // that is a different fact from the file being unreadable.
    const std::string preflight = chosen->preflight(detection);
    if (!preflight.empty()) {
        engine::LoadedImage out;
        out.format = detection.format;
        out.error = preflight;
        if (events != nullptr) {
            auto& e = events->begin(obs::EventKind::ImageLoaded);
            e.add("path", path);
            e.add("engine", chosen->name());
            e.add("size", detection.file_size);
            e.add("ok", false);
            e.add("error", preflight);
            events->commit();
        }
        return out;
    }

    return chosen->load(path, events);
}

RunResult run(const std::string& path, const std::vector<std::string>& argv,
              const RunOptions& options, obs::Writer& events) {
    RunResult out;

    auto& start = events.begin(obs::EventKind::SessionStart);
    start.add("target", path);
    start.add("argv_count", static_cast<std::uint64_t>(argv.size()));
    events.commit();

    const parser::Detection detection = parser::detect_file(path);
    out.format = detection.format;

    const engine::Engine* chosen = engine::engine_for(detection);
    if (chosen == nullptr) {
        // A format this build recognises but has no engine for is refused by
        // name. The alternative -- exec'ing the file and letting the kernel
        // decide -- produces a run whose isolation nobody designed, which
        // for a tool whose entire claim is what it does to a target is not
        // a thing worth doing.
        std::string why =
            "this build has no engine for a ";
        why += parser::format_name(detection.format);
        why += " image; occ runs Linux executables";
        if (detection.format == parser::Format::Pe) {
            why +=
                ", and a Windows image needs the pe engine, which needs a "
                "Wine loader on this host";
        }
        return refuse(std::move(out), events, why);
    }
    out.engine = chosen->name();

    const std::string preflight = chosen->preflight(detection);
    if (!preflight.empty()) {
        return refuse(std::move(out), events, preflight);
    }

    engine::LoadedImage image = chosen->load(path, &events);
    out.image_loaded = image.ok;
    out.load_error = image.error;
    out.load_detail = image.detail;
    out.entry = image.entry;
    out.mapping_count = image.region_count;

    if (!image.ok) {
        // A refusal names the reason directly. The detail string is the one
        // the reader produced, so the reason a run was refused and the
        // reason a parse failed cannot disagree.
        return refuse(std::move(out), events,
                      "the image is not one this build can run: " +
                          image.error);
    }

    // The scratch directory. An engine that keeps state on disk needs
    // somewhere that belongs to this run and to nothing else, and the
    // runner is what knows when the run ends. It is created before the
    // plan so that an engine which refuses for want of one says so before
    // anything has been built.
    std::string scratch;
    if (options.scratch_dir.empty()) {
        scratch = "/run/occ-scratch-" + std::to_string(::getpid());
    } else {
        scratch = options.scratch_dir;
    }
    if (!fs::mkdir_p(scratch, 0700)) {
        return refuse(std::move(out), events,
                      "the run's scratch directory " + scratch +
                          " could not be created");
    }

    engine::EngineRequest request;
    request.path = path;
    request.argv = argv;
    request.scratch_dir = scratch;

    engine::LaunchPlan plan = chosen->plan(request, image);
    if (!plan.refusal.empty()) {
        (void)fs::remove_tree(scratch);
        return refuse(std::move(out), events, plan.refusal);
    }
    out.degradations = plan.degradations;

    // The container configuration comes from the options and the engine.
    // The options contribute what the caller asked for; the engine
    // contributes what the format needs to run at all.
    isolation::ContainerConfig config;
    config.root_dir = options.root_dir;
    config.upper_dir = options.upper_dir;
    config.work_dir = options.work_dir;
    config.root_kind = options.root_kind;
    config.cgroup_parent = options.cgroup_parent;
    config.limits.memory_bytes = options.memory_bytes;
    config.limits.pids = options.pids;
    config.limits.cpu_percent = options.cpu_percent;
    config.extra_mounts = options.extra_mounts;

    // The engine's binds go after the caller's. Order matters: a later bind
    // of the same target is the one that is in effect, so an engine that
    // needs a directory the caller also bound gets to decide what is at
    // that path -- the alternative is the caller's mount being silently
    // masked by a loader's, which produces a target that fails in a way
    // that names neither.
    for (const isolation::ContainerConfig::BindMount& m : plan.binds) {
        config.extra_mounts.push_back(m);
    }

    // A run with no root named still needs a root, unless the engine named
    // one. The host's own / is bound read-only, which is the smallest setup
    // that gives the target a coherent filesystem: it can read the
    // libraries and data files it expects, and it cannot write anything,
    // because the bind is sealed before the pivot. Binding an empty path
    // instead would be refused by the kernel with EINVAL, and a caller who
    // did not name a root has not asked for an empty one -- they have asked
    // for the default.
    if (config.root_dir.empty() && plan.root_dir.empty() &&
        config.root_kind == isolation::RootKind::ReadOnlyBind) {
        config.root_dir = "/";
    }
    // The engine's root is the last word: an engine that needs a writable
    // root has said so, and a caller who did not name one has not asked to
    // override it.
    if (!plan.root_dir.empty()) {
        config.root_dir = plan.root_dir;
    }

    const std::vector<std::string> env =
        merge_environment(default_environment(options), plan.env);

    // An observed run has to have its target stop at the exec boundary, or
    // the target can complete before the observer reaches it.
    config.stop_at_exec = options.observe;

    isolation::SpawnResult spawned =
        isolation::container_spawn(config, plan.program, plan.argv, env);
    if (!spawned.error.ok()) {
        (void)fs::remove_tree(scratch);
        out.failed = true;
        out.error = spawned.error;
        auto& e = events.begin(obs::EventKind::Note);
        // The literal is named as a string_view: without it the overload set
        // would prefer the bool one and the text would become a truth value.
        e.add("text", std::string_view{"the container could not be started"});
        e.add("stage", isolation::stage_name(spawned.error.stage));
        e.add("errno", static_cast<std::int64_t>(spawned.error.error));
        e.add("detail", spawned.error.detail);
        events.commit();
        auto& end = events.begin(obs::EventKind::SessionEnd);
        end.add("started", false);
        events.commit();
        out.events = events.events_written();
        return out;
    }

    auto& spawn = events.begin(obs::EventKind::ProcessSpawn);
    spawn.add("pid", static_cast<std::uint64_t>(spawned.pid));
    spawn.add("entry", out.entry);
    events.commit();

    // The container releases the target as soon as it has been set up, so
    // there is no stopped process to resume and this call is a no-op. It is
    // deliberately not called: the call is implemented as a non-blocking
    // wait, and a wait that observes the target's exit consumes it, which
    // would leave the reap below with nothing to collect and no exit status
    // to report. The sequence a caller sees is still spawn, then reap.

    if (options.observe) {
        // The observer takes over the wait. It owns the process from here,
        // which is why the reap below is skipped: a process that has been
        // traced reports its exit through the trace, and waiting for it a
        // second time would find nothing.
        obs::SessionConfig sc;
        sc.pid = spawned.pid;
        sc.trace_syscalls = true;
        sc.follow_forks = true;
        sc.serve_gdb = options.gdb_read_fd >= 0 || options.gdb_listen_fd >= 0;
        sc.gdb_read_fd = options.gdb_read_fd;
        sc.gdb_write_fd = options.gdb_write_fd;
        sc.gdb_listen_fd = options.gdb_listen_fd;
        sc.gdb_port = options.gdb_port;
        sc.wait_for_debugger = options.gdb_wait;
        // The tracker is wired through rather than inferred from observe:
        // a run that asked for it gets it, and a run that did not is not
        // charged for the four debug registers it would consume.
        sc.track_wx = options.track_wx;
        sc.wx_regions = options.wx_regions;
        sc.wx_anonymous_only = options.wx_anonymous_only;
        sc.wx_max_region_bytes = options.wx_max_region_bytes;

        const obs::SessionResult sr = obs::observe(sc, events);
        out.stops = sr.stops;
        out.syscall_stops = sr.syscall_stops;
        out.breakpoint_hits = sr.breakpoint_hits;
        out.observed_signals = sr.signals;
        out.wx_transitions = sr.transitions;
        out.wx_regions = sr.wx_regions;
        out.wx_watches = sr.wx_watches;
        out.wx_bytes_covered = sr.wx_bytes_covered;
        out.wx_bytes_total = sr.wx_bytes_total;
        out.wx_lost_samples = sr.wx_lost_samples;
        out.wx_unavailable = sr.wx_unavailable;

        if (sr.failed) {
            out.failed = true;
            out.failure_detail = sr.detail;
        }
        out.exit_code = sr.exit_code;
        out.term_signal = sr.term_signal;
        out.signaled = sr.signaled;

        (void)isolation::container_cleanup(config);
        (void)fs::remove_tree(scratch);

        auto& end = events.begin(obs::EventKind::SessionEnd);
        end.add("started", true);
        end.add("observed", true);
        end.add("stops", sr.stops);
        end.add("exit_code", static_cast<std::int64_t>(out.exit_code));
        end.add("signaled", out.signaled);
        end.add("term_signal", static_cast<std::uint64_t>(out.term_signal));
        events.commit();

        out.events = events.events_written();
        return out;
    }

    const isolation::ContainerResult reaped = isolation::container_reap(spawned.pid);

    if (!reaped.error.ok()) {
        out.failed = true;
        out.error = reaped.error;
    }
    out.exit_code = reaped.exit_code;
    out.term_signal = reaped.term_signal;
    out.signaled = reaped.signaled;

    if (reaped.signaled) {
        auto& e = events.begin(obs::EventKind::Signal);
        e.add("pid", static_cast<std::uint64_t>(spawned.pid));
        e.add("signal", static_cast<std::uint64_t>(reaped.term_signal));
        events.commit();
    }

    auto& exit = events.begin(obs::EventKind::ProcessExit);
    exit.add("pid", static_cast<std::uint64_t>(spawned.pid));
    exit.add("exit_code", static_cast<std::int64_t>(reaped.exit_code));
    exit.add("signaled", reaped.signaled);
    exit.add("term_signal", static_cast<std::uint64_t>(reaped.term_signal));
    events.commit();

    (void)isolation::container_cleanup(config);
    (void)fs::remove_tree(scratch);

    auto& end = events.begin(obs::EventKind::SessionEnd);
    end.add("started", true);
    end.add("exit_code", static_cast<std::int64_t>(out.exit_code));
    end.add("signaled", out.signaled);
    end.add("term_signal", static_cast<std::uint64_t>(out.term_signal));
    events.commit();

    out.events = events.events_written();
    return out;
}

} // namespace occ::runner

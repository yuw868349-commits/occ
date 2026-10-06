#include "occ/commands.h"

#include "occ/observer/event.h"
#include "occ/observer/transport.h"
#include "occ/runner/run.h"
#include "occ/util/log.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

namespace occ {

namespace {

void print_run_usage() {
    std::fprintf(
        stderr,
        "usage: occ run [options] <path> [args...]\n"
        "\n"
        "runs a target under isolation and writes one JSON object per line\n"
        "describing what was observed\n"
        "\n"
        "options:\n"
        "  --root <dir>       use <dir> as the new root (read-only)\n"
        "  --overlay <lower>  run on an overlay of <lower>, writes discarded\n"
        "  --upper <dir>      where overlay writes land; implies --overlay\n"
        "  --work <dir>       overlay work directory\n"
        "  --bind <src>:<dst> bind <src> into the root at <dst>, read-only\n"
        "  --rw-bind <s>:<d>  same, but writable\n"
        "  --memory <bytes>   memory limit for the target\n"
        "  --pids <n>         process count limit for the target\n"
        "  --cpu <percent>    cpu bandwidth, 1..100\n"
        "  --cgroup <dir>     create the run's cgroup under <dir>\n"
        "  --env <K=V>        set an environment variable for the target\n"
        "  --engine <name>    run under the named engine; 'occ' is this\n"
        "                     build's own runtime, and the detection's\n"
        "                     choice must agree\n"
        "  --observe          trace the target with ptrace as it runs\n"
        "  --probe            place the probes the engine asks for and\n"
        "                     report a hit per call (implies --observe)\n"
        "  --no-probe         place none, whatever the engine asked for\n"
        "  --track-wx         watch for write-then-execute transitions\n"
        "  --wx-all           consider file-backed regions too, not just\n"
        "                     anonymous ones\n"
        "  --wx-region <b>:<n>  watch a specific region instead of scanning\n"
        "  --wx-max <bytes>   ignore candidate regions larger than this\n"
        "  --gdb-port <n>     serve the remote protocol on loopback port <n>\n"
        "  --gdb-wait         wait for a debugger before running the target\n"
        "  --no-events        do not write the event stream\n"
        "  --help             print this text\n"
        "\n"
        "the event stream goes to stdout when it is not a terminal, and is\n"
        "suppressed when it is, so an interactive run shows only the\n"
        "target's own output\n"
        "\n"
        "--track-wx needs hardware watch events. There are four debug\n"
        "registers and a candidate region is a whole page, so the stream\n"
        "reports how many bytes were actually covered rather than implying\n"
        "the region was watched in full\n"
        "\n"
        "--gdb-port prints the port before the target starts, so a debugger\n"
        "can be attached at any point during the run. Port 0 asks the kernel\n"
        "for any free port. --gdb-wait holds the target at its first stop\n"
        "until a debugger connects, which is what makes 'break main' work\n"
        "instead of racing the program's first instructions\n"
        "\n"
        "--probe places uprobes on the functions the engine named and\n"
        "writes a probe_hit record each time the target enters one. A\n"
        "Windows image run by this build's own runtime makes no foreign\n"
        "loader calls, so the pe engine asks for none and the flag answers\n"
        "only when an engine asks. The probe layer needs a mounted tracefs\n"
        "and a permitted perf_event_open; when it has neither the run\n"
        "continues with syscall-level observation and says so in\n"
        "probe_attached records. OCC_PROBE=0 forces the layer off and\n"
        "OCC_PROBE=1 forces it on even where the engine's own plan would\n"
        "not ask for it\n");
}

// Parses an unsigned decimal, or a hexadecimal number written with a 0x
// prefix. Addresses are habitually written in hex and a length is not, so
// the prefix is what distinguishes them. Returns false rather than
// clamping, because a limit that silently became a different limit is worse
// than a run that refused to start.
bool parse_u64(std::string_view s, std::uint64_t& out) noexcept {
    if (s.empty()) {
        return false;
    }

    int base = 10;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16;
        s.remove_prefix(2);
    }
    if (s.empty()) {
        return false;
    }

    std::uint64_t v = 0;
    for (char c : s) {
        int digit;
        if (c >= '0' && c <= '9') {
            digit = c - '0';
        } else if (base == 16 && c >= 'a' && c <= 'f') {
            digit = c - 'a' + 10;
        } else if (base == 16 && c >= 'A' && c <= 'F') {
            digit = c - 'A' + 10;
        } else {
            return false;
        }
        const std::uint64_t d = static_cast<std::uint64_t>(digit);
        if (v > (UINT64_MAX - d) / static_cast<std::uint64_t>(base)) {
            return false;
        }
        v = v * static_cast<std::uint64_t>(base) + d;
    }
    out = v;
    return true;
}

// Parses "BASE:LENGTH" into a watch target. The colon is what separates an
// address from a size, which is the same convention --bind uses and the
// reason a caller who has learned one does not have to learn the other.
bool parse_region(std::string_view spec, obs::WatchTarget& out) noexcept {
    const std::size_t colon = spec.find(':');
    if (colon == std::string_view::npos || colon == 0 ||
        colon + 1 >= spec.size()) {
        return false;
    }
    if (!parse_u64(spec.substr(0, colon), out.base)) {
        return false;
    }
    if (!parse_u64(spec.substr(colon + 1), out.length)) {
        return false;
    }
    return out.length != 0;
}

// Splits "source:target" into its two halves. A bind mount with no target
// mounts at the same path it came from, which is the common case for a
// directory the target expects to find where the host has it.
bool split_bind(std::string_view spec, std::string& source,
                std::string& target) noexcept {
    const std::size_t colon = spec.find(':');
    if (colon == std::string_view::npos) {
        if (spec.empty()) {
            return false;
        }
        source.assign(spec);
        target.assign(spec);
        return true;
    }
    if (colon == 0 || colon + 1 >= spec.size()) {
        return false;
    }
    source.assign(spec.substr(0, colon));
    target.assign(spec.substr(colon + 1));
    return true;
}

} // namespace

int cmd_run(int argc, char** argv) {
    runner::RunOptions options;

    std::string target;
    std::vector<std::string> target_argv;

    bool no_events = false;

    // The port to serve the remote protocol on, and whether to hold the
    // target until a debugger arrives. Zero with no --gdb-port means no
    // debugger is served at all.
    std::uint16_t gdb_port = 0;
    bool gdb_serve = false;
    bool gdb_wait = false;

    for (int i = 0; i < argc; ++i) {
        const std::string_view arg = argv[i];

        // Everything after the target path belongs to the target. Parsing
        // stops at the first non-option so that a target's own --help is
        // passed through rather than consumed here.
        if (target.empty() && (arg.empty() || arg[0] != '-')) {
            target.assign(arg);
            continue;
        }

        if (!target.empty()) {
            target_argv.emplace_back(arg);
            continue;
        }

        if (arg == "--help" || arg == "-h") {
            print_run_usage();
            return 0;
        }

        // Each option that takes a value consumes the next argument. A
        // missing value is a usage error, not a silently absent option.
        auto value = [&](const char* name) -> const char* {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "occ run: %s needs a value\n", name);
                return nullptr;
            }
            ++i;
            return argv[i];
        };

        if (arg == "--root") {
            const char* v = value("--root");
            if (v == nullptr) {
                return 2;
            }
            options.root_dir = v;
        } else if (arg == "--overlay") {
            const char* v = value("--overlay");
            if (v == nullptr) {
                return 2;
            }
            options.root_dir = v;
            options.root_kind = isolation::RootKind::Overlay;
        } else if (arg == "--upper") {
            const char* v = value("--upper");
            if (v == nullptr) {
                return 2;
            }
            options.upper_dir = v;
            options.root_kind = isolation::RootKind::Overlay;
        } else if (arg == "--work") {
            const char* v = value("--work");
            if (v == nullptr) {
                return 2;
            }
            options.work_dir = v;
        } else if (arg == "--bind" || arg == "--rw-bind") {
            const char* v = value(arg == "--bind" ? "--bind" : "--rw-bind");
            if (v == nullptr) {
                return 2;
            }
            isolation::ContainerConfig::BindMount mount;
            if (!split_bind(v, mount.source, mount.target)) {
                std::fprintf(stderr, "occ run: bad bind specification '%s'\n",
                             v);
                return 2;
            }
            mount.writable = (arg == "--rw-bind");
            options.extra_mounts.push_back(mount);
        } else if (arg == "--memory") {
            const char* v = value("--memory");
            if (v == nullptr) {
                return 2;
            }
            if (!parse_u64(v, options.memory_bytes)) {
                std::fprintf(stderr, "occ run: bad byte count '%s'\n", v);
                return 2;
            }
        } else if (arg == "--pids") {
            const char* v = value("--pids");
            if (v == nullptr) {
                return 2;
            }
            if (!parse_u64(v, options.pids)) {
                std::fprintf(stderr, "occ run: bad process count '%s'\n", v);
                return 2;
            }
        } else if (arg == "--cpu") {
            const char* v = value("--cpu");
            if (v == nullptr) {
                return 2;
            }
            std::uint64_t percent = 0;
            if (!parse_u64(v, percent) || percent == 0 || percent > 100) {
                std::fprintf(stderr,
                             "occ run: --cpu takes 1..100, got '%s'\n", v);
                return 2;
            }
            options.cpu_percent = static_cast<std::uint32_t>(percent);
        } else if (arg == "--cgroup") {
            const char* v = value("--cgroup");
            if (v == nullptr) {
                return 2;
            }
            options.cgroup_parent = v;
        } else if (arg == "--env") {
            const char* v = value("--env");
            if (v == nullptr) {
                return 2;
            }
            if (std::string_view(v).find('=') == std::string_view::npos) {
                std::fprintf(stderr,
                             "occ run: --env takes KEY=VALUE, got '%s'\n", v);
                return 2;
            }
            options.env.emplace_back(v);
        } else if (arg == "--engine" || arg.rfind("--engine=", 0) == 0) {
            // The value either follows the flag as the next argument or
            // arrives glued to it with an '='. Both spellings are accepted
            // because a caller scripting the run writes whichever reads
            // better on that line, and an option whose spelling is a coin
            // flip is an option scripts get wrong half the time.
            std::string_view name;
            if (arg.size() > 9 && arg[8] == '=') {
                name = arg.substr(9);
            } else {
                const char* v = value("--engine");
                if (v == nullptr) {
                    return 2;
                }
                name = v;
            }
            if (name.empty()) {
                std::fprintf(stderr,
                             "occ run: --engine needs a name ('occ' is this "
                             "build's own runtime)\n");
                return 2;
            }
            // Not validated here: the accepted names are the engines'
            // own, and the run checks the caller's name against the one
            // the detection chose -- one place, with the real names,
            // rather than a second table this loop would have to keep
            // current.
            options.engine = std::string(name);
        } else if (arg == "--observe") {
            options.observe = true;
        } else if (arg == "--probe") {
            // A run that places probes is a run that observes them. There is
            // no useful middle state: the probes would be registered, no
            // session would poll their rings, and the tracefs events would
            // outlive the run that created them.
            options.probe = true;
            options.probe_mode = runner::RunOptions::ProbeMode::Force;
            options.observe = true;
        } else if (arg == "--no-probe") {
            // An explicit off is not the same as an absence, which is why
            // this sets the mode rather than only clearing the flag: a
            // caller who has asked for no probes is not asking to be told
            // that a probe layer was unavailable.
            options.probe = false;
            options.probe_mode = runner::RunOptions::ProbeMode::Disabled;
        } else if (arg == "--track-wx") {
            // Tracking implies tracing: the tracker drains watch events
            // between stops, and with no stops there is nowhere to drain
            // them to. Saying so here rather than failing later means the
            // combination is not a trap.
            options.track_wx = true;
            options.observe = true;
        } else if (arg == "--wx-all") {
            options.wx_anonymous_only = false;
        } else if (arg == "--wx-max") {
            const char* v = value("--wx-max");
            if (v == nullptr) {
                return 2;
            }
            if (!parse_u64(v, options.wx_max_region_bytes) ||
                options.wx_max_region_bytes == 0) {
                std::fprintf(stderr,
                             "occ run: --wx-max takes a byte count, got "
                             "'%s'\n",
                             v);
                return 2;
            }
        } else if (arg == "--wx-region") {
            const char* v = value("--wx-region");
            if (v == nullptr) {
                return 2;
            }
            obs::WatchTarget t;
            if (!parse_region(v, t)) {
                std::fprintf(stderr,
                             "occ run: --wx-region takes BASE:LENGTH with "
                             "hex or decimal BASE, got '%s'\n",
                             v);
                return 2;
            }
            options.wx_regions.push_back(t);
            options.track_wx = true;
            options.observe = true;
        } else if (arg == "--gdb-port" || arg == "--gdb") {
            const char* v = value("--gdb-port");
            if (v == nullptr) {
                return 2;
            }
            std::uint64_t port = 0;
            if (!parse_u64(v, port) || port > 0xffff) {
                std::fprintf(stderr,
                             "occ run: --gdb-port wants a port number 0..65535\n");
                return 2;
            }
            gdb_port = static_cast<std::uint16_t>(port);
            gdb_serve = true;
            // A run that serves a debugger is a run that observes: the
            // session loop is what reads the protocol, and it is the same
            // loop that reports the target's stops. Serving a debugger
            // without observing would mean a target nobody can stop.
            options.observe = true;
        } else if (arg == "--gdb-wait") {
            gdb_wait = true;
            gdb_serve = true;
            options.observe = true;
        } else if (arg == "--no-events") {
            no_events = true;
        } else {
            std::fprintf(stderr, "occ run: unknown option '%s'\n",
                         std::string(arg).c_str());
            print_run_usage();
            return 2;
        }
    }

    if (target.empty()) {
        std::fprintf(stderr, "occ run: no target path\n");
        print_run_usage();
        return 2;
    }

    target_argv.insert(target_argv.begin(), target);

    // The stream is the machine-readable output, so it is written when the
    // caller is not a terminal. Writing it to a terminal would bury an
    // interactive session's own output under a line per fact, which is the
    // one case where the facts are not the point. The decision is made once,
    // by the caller of this function, and handed over in the environment;
    // re-deriving it here would let two isatty calls disagree.
    bool emit_events = false;
    if (!no_events) {
        const char* want = ::getenv("OCC_EVENT_STREAM");
        emit_events = want != nullptr && want[0] == '1';
    }

    // The environment's answer on probes is consulted after the flags and
    // overrides them, which is the direction that makes it useful. The
    // decision that this variable exists to make is about the host -- a
    // container without tracefs, a machine where perf_event_open is denied
    // -- and a caller who exported it has said something about every run
    // they are about to make. An explicit --no-probe is the one exception,
    // because a caller who typed it on this command line meant this command
    // line.
    if (options.probe_mode != runner::RunOptions::ProbeMode::Disabled) {
        const char* probe_env = ::getenv("OCC_PROBE");
        if (probe_env != nullptr && probe_env[0] != '\0') {
            if (probe_env[0] == '0') {
                options.probe = false;
                options.probe_mode = runner::RunOptions::ProbeMode::Disabled;
            } else if (probe_env[0] == '1') {
                options.probe = true;
                options.probe_mode = runner::RunOptions::ProbeMode::Force;
                options.observe = true;
            }
        }
    }

    // Bound before the target starts. The port has to be printed before
    // anyone can connect to it, and a person reading a port number off a
    // terminal is exactly the person who is about to type it into gdb.
    obs::Listener listener;
    if (gdb_serve) {
        std::string error;
        if (!listener.open(gdb_port, error)) {
            log::error(error);
            return 1;
        }
        options.gdb_listen_fd = listener.fd();
        options.gdb_port = listener.port();
        options.gdb_wait = gdb_wait;

        // The notice goes to stderr even when the event stream is on stdout,
        // because it is addressed to a person and not to a consumer of the
        // stream. A parser reading the stream should not have to skip a line
        // that is not an event.
        std::fprintf(stderr,
                     "occ: gdb target remote 127.0.0.1:%u\n",
                     static_cast<unsigned>(listener.port()));
        if (gdb_wait) {
            std::fprintf(stderr,
                         "occ: holding the target until a debugger connects\n");
        }
    }

    obs::Writer events;
    // A sink on a closed descriptor makes every emit a no-op without the
    // call sites having to check. The value is one no real stream uses, so
    // an accidental write fails instead of landing somewhere unexpected.
    events.attach(emit_events ? 1 : -1);

    const runner::RunResult result =
        runner::run(target, target_argv, options, events);

    // The degradations go to stderr and never into the stream.
    //
    // They are sentences addressed to the person who ran the command, and
    // the event stream is a machine-readable record of what happened. A
    // degradation is a fact about what did *not* happen, and a record of a
    // thing that did not happen is exactly the kind of line a consumer
    // would be wrong to read as one. The stream carries the same facts in
    // structured form -- a probe_attached record with ok false, a session
    // that reports no hits -- so a consumer loses nothing by this being on
    // stderr, and a person who was told their trace is coarser than they
    // asked for does not have to grep for it.
    for (const std::string& d : result.degradations) {
        std::fprintf(stderr, "occ: %s\n", d.c_str());
    }

    if (result.failed) {
        // A refusal names the reason directly; a failing syscall names the
        // stage it failed at. Both go to stderr, because stdout carries the
        // event stream and a diagnostic written into the stream would be a
        // record of something that did not happen.
        if (!result.failure_detail.empty()) {
            log::error(result.failure_detail);
        } else if (!result.error.detail.empty()) {
            log::error(result.error.detail);
        } else {
            log::error(std::string("the run failed at ") +
                       isolation::stage_name(result.error.stage));
        }
        return 1;
    }

    if (result.signaled) {
        // A target killed by a signal is reported the way a shell reports
        // it, so that a caller scripting occ sees what it would see from
        // any other runner.
        return 128 + result.term_signal;
    }

    return result.exit_code;
}

} // namespace occ

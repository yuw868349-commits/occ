#include "occ/observer/registry.h"

#include "occ/syscall/errno.h"
#include "occ/syscall/syscall.h"
#include "occ/util/fs.h"
#include "occ/util/log.h"
#include "occ/util/string.h"

#include <climits>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

namespace occ::obs {

namespace {

constexpr const char* kRegistryDir = "/run/occ/sessions";

// The variable that moves the registry. The default above is the right home
// for a session record -- cleared on boot, not world-writable -- and it is a
// single shared location, which is what a registry for one machine has to
// be. A test that wrote there would leave records behind for a later run to
// find, and a second concurrent test would see the first one's sessions, so
// the location is overridable rather than fixed. Naming the override rather
// than reading a temporary directory from the caller keeps every entry point
// pointed at the same place without threading a parameter through all of
// them.
constexpr const char* kRegistryDirEnv = "OCC_SESSION_REGISTRY";

// Field 22 of /proc/<pid>/stat is the process start time in clock ticks
// since boot, counted from 1 per proc(5). It is the kernel's own answer to
// "which process is this", and it is the only value that stays true after a
// pid is recycled.
constexpr int kProcStatStartTime = 22;

constexpr int kAtFdcwd = -100;
constexpr int kOWronly = 1;
constexpr int kOCreat = 0100;
constexpr int kOTrunc = 01000;
constexpr int kOCloexec = 02000000;

// A session id is the pid and the start time, and the pair is what makes it
// unique. A pid alone is reused by the kernel, so an id built from one would
// eventually name a different process, and an attach would reach the wrong
// thing.
std::string make_id(int pid, std::uint64_t start_ticks) {
    std::string out;
    append_hex(out, static_cast<std::uint64_t>(pid), 8);
    out.push_back('-');
    append_hex(out, start_ticks, 16);
    return out;
}

// Parses one decimal field, and refuses anything that is not a run of
// digits.
//
// The trailing-garbage case matters because the value came from a file
// another process wrote and this one did not: "pid=12abc" is not a pid of
// 12, it is a record this build did not write, and accepting the prefix
// would report a truncated field as a fact. An empty value is refused for
// the same reason -- it is the shape a zero-length write leaves behind, and
// reading it as 0 would name a process that cannot exist.
bool parse_decimal(std::string_view text, std::uint64_t& out) noexcept {
    if (text.empty()) {
        return false;
    }
    std::uint64_t value = 0;
    for (char c : text) {
        if (c < '0' || c > '9') {
            return false;
        }
        const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
        // Refuse rather than wrap: a value past the range is a field this
        // build did not write, and a wrapped one names some other process.
        if (value > (UINT64_MAX - digit) / 10) {
            return false;
        }
        value = value * 10 + digit;
    }
    out = value;
    return true;
}

std::string entry_path(const std::string& root, const std::string& id) {
    return root + "/" + id + ".session";
}

// Replaces a record in one step, so a concurrent reader never sees it short.
//
// A truncating write leaves a window in which the file exists with no
// contents. A reader in that window reads an empty file, fails to decode
// it, and skips the record -- and a skipped record is never cleaned up, so
// the entry stays on disk describing a session nobody can attach to until
// somebody removes it by hand. Writing a temporary file and renaming it
// over the target makes the swap atomic: a reader sees the old contents or
// the new ones, never a prefix.
//
// The temporary name carries the writer's pid so two processes registering
// at the same moment do not write through one temporary file and rename
// each other's half-written record into place.
bool write_record(const std::string& path, const std::string& text) noexcept {
    const auto self = sys::getpid();
    const std::string temp = path + "." +
                             std::to_string(static_cast<long>(self.value)) +
                             ".tmp";

    const auto opened = sys::openat(kAtFdcwd, temp.c_str(),
                                    kOWronly | kOCreat | kOTrunc | kOCloexec,
                                    0600);
    if (opened.failed()) {
        return false;
    }
    const int handle = static_cast<int>(opened.value);

    std::size_t off = 0;
    while (off < text.size()) {
        const auto w =
            sys::write(handle, text.data() + off, text.size() - off);
        if (w.failed() && w.error == sys::kEintr) {
            continue;
        }
        // A refused write, and a write that reports success having moved no
        // bytes, both leave the target untouched because nothing has been
        // renamed yet. The temporary file is removed rather than left in the
        // directory: a reader would not see it, but it would sit there for
        // as long as the mount lasts.
        if (w.failed() || w.value == 0) {
            (void)sys::close(handle);
            (void)sys::unlinkat(kAtFdcwd, temp.c_str(), 0);
            return false;
        }
        off += static_cast<std::size_t>(w.value);
    }
    (void)sys::close(handle);

    const auto renamed = sys::renameat2(kAtFdcwd, temp.c_str(), kAtFdcwd,
                                        path.c_str(), 0 /* no flags */);
    if (renamed.failed()) {
        (void)sys::unlinkat(kAtFdcwd, temp.c_str(), 0);
        return false;
    }
    return true;
}

// The record is a flat key=value file with one field per line. It is read
// by hand often enough that a format a person can read at a terminal is
// worth more than a compact one, and there is no field in it that needs
// escaping beyond a newline, which a path can contain only if someone
// deliberately put one there.
std::string encode(const SessionRecord& r) {
    std::string out;
    out += "id=";
    out += r.id;
    out += "\npid=";
    append_uint(out, static_cast<std::uint64_t>(r.pid));
    out += "\ntarget=";
    out += r.target;
    out += "\nstart_ticks=";
    append_uint(out, r.start_ticks);
    out += "\nstream=";
    out += r.stream_path;
    out += "\n";
    return out;
}

bool decode(const std::string& text, const std::string& id,
            const std::string& dir, SessionRecord& out) {
    out = SessionRecord{};
    out.id = id;
    out.directory = dir;

    // The fields that have to be present and well formed are tracked as
    // such. Checking the parsed values alone would accept a record whose pid
    // line was empty whenever the emptiness happened to parse as something
    // plausible.
    bool have_pid = false;
    bool have_start = false;

    std::size_t pos = 0;
    while (pos < text.size()) {
        std::size_t end = text.find('\n', pos);
        if (end == std::string::npos) {
            end = text.size();
        }
        const std::string_view line(text.data() + pos, end - pos);
        const std::size_t eq = line.find('=');
        if (eq != std::string_view::npos) {
            const std::string_view key = line.substr(0, eq);
            const std::string_view value = line.substr(eq + 1);
            if (key == "pid") {
                std::uint64_t v = 0;
                if (!parse_decimal(value, v) || v == 0 ||
                    v > static_cast<std::uint64_t>(INT_MAX)) {
                    return false;
                }
                out.pid = static_cast<int>(v);
                have_pid = true;
            } else if (key == "target") {
                out.target.assign(value);
            } else if (key == "start_ticks") {
                std::uint64_t v = 0;
                if (!parse_decimal(value, v)) {
                    return false;
                }
                out.start_ticks = v;
                have_start = true;
            } else if (key == "stream") {
                out.stream_path.assign(value);
            }
        }
        pos = end + 1;
    }
    // Both are required. A record with no start time cannot be checked
    // against a reused pid, so returning it would defeat the one thing the
    // start time is stored for.
    return have_pid && have_start;
}

} // namespace

bool registry_root(std::string& root, std::string& error) noexcept {
    error.clear();
    // The runtime directory is the right home for this: it is cleared on
    // boot, which is exactly the lifetime of a session record, and it is not
    // world-writable, so another user cannot register a session that this one
    // would then act on.
    const char* configured = ::getenv(kRegistryDirEnv);
    const char* dir = (configured != nullptr && configured[0] != '\0')
                          ? configured
                          : kRegistryDir;
    if (fs::mkdir_p(dir, 0700)) {
        root = dir;
        return true;
    }
    // The path can be unusable because something that is not a directory
    // already sits there, and because it cannot be created. Both are
    // reported the same way because the caller's response is the same: the
    // registry cannot be used. Silently returning the path either way is what
    // made an unavailable registry look like an empty one.
    root.clear();
    error = "the session registry at " + std::string(dir) +
            " is not available";
    if (fs::exists(dir)) {
        error += ": the path exists and is not a directory";
    }
    return false;
}

bool process_start_ticks(int pid, std::uint64_t& out) noexcept {
    if (pid <= 0) {
        return false;
    }
    const auto ticks = fs::proc_stat_field(pid, kProcStatStartTime);
    if (!ticks) {
        return false;
    }
    out = *ticks;
    return true;
}

bool process_alive(int pid) noexcept {
    if (pid <= 0) {
        return false;
    }
    // Signal zero performs the permission and existence checks without
    // delivering anything. EPERM means the process exists and belongs to
    // someone else, which is still alive.
    auto r = sys::kill(pid, 0);
    if (r.ok()) {
        return true;
    }
    return r.error == sys::kEperm;
}

std::string register_session(const std::string& target, int pid,
                             const std::string& stream_path,
                             std::string& error) noexcept {
    error.clear();
    std::string root;
    if (!registry_root(root, error)) {
        return {};
    }

    // The start time is read rather than generated because it has to be the
    // value find_session will later compare against. A time this process
    // invented says nothing about the target: the observer's own monotonic
    // clock keeps running whether or not the target exists, so a record built
    // from it either never matches or matches nothing that can be checked,
    // and the session is swept away as stale while it is still running.
    std::uint64_t started = 0;
    if (!process_start_ticks(pid, started)) {
        error = "the start time of process " + std::to_string(pid) +
                " could not be read, so the session cannot be identified";
        return {};
    }

    SessionRecord r;
    r.id = make_id(pid, started);
    r.pid = pid;
    r.target = target;
    r.start_ticks = started;
    r.stream_path = stream_path;

    const std::string path = entry_path(root, r.id);
    if (!write_record(path, encode(r))) {
        error = "the session record could not be written to " + path;
        return {};
    }
    return r.id;
}

void unregister_session(const std::string& id) noexcept {
    if (id.empty()) {
        return;
    }
    std::string root;
    std::string error;
    if (!registry_root(root, error)) {
        // The record cannot be reached, so it cannot be removed. There is no
        // channel to report through here and no action the caller could take
        // that it is not already taking, so the failure is logged rather than
        // swallowed: a stale record is the thing this call exists to
        // prevent, and a silent failure leaves one behind.
        log::error(error);
        return;
    }
    (void)fs::remove_file(entry_path(root, id));
}

std::vector<SessionRecord> live_sessions() noexcept {
    std::vector<SessionRecord> out;
    std::string root;
    std::string error;
    if (!registry_root(root, error)) {
        // This signature has no channel to report through, so the reason goes
        // where a diagnostic can be seen. Returning an empty list without one
        // would report "no sessions" for a registry that could not be read at
        // all, and the two need different responses from whoever is asking.
        log::error(error);
        return out;
    }

    for (const std::string& name : fs::list_dir(root)) {
        if (!ends_with(name, ".session")) {
            continue;
        }
        const std::string path = root + "/" + name;
        auto content = fs::read_file(path);
        if (!content) {
            continue;
        }

        const std::string id = name.substr(0, name.size() - 8);
        SessionRecord r;
        if (!decode(*content, id, root, r)) {
            // A record that does not parse is one this build did not write.
            // Removing it would lose whatever wrote it, so it is skipped and
            // left for a person to look at.
            continue;
        }

        // The start time is what decides whether this record still describes
        // the process it was written for. A pid that is alive but was started
        // later belongs to something else, and reporting it as a live session
        // sends an attach to an unrelated program.
        std::uint64_t ticks = 0;
        if (!process_start_ticks(r.pid, ticks) || ticks != r.start_ticks) {
            // Either the process is gone or the pid now names a different
            // one. Removing the record here rather than leaving it means the
            // registry is self-cleaning and no caller has to check liveness
            // itself.
            (void)fs::remove_file(path);
            continue;
        }

        out.push_back(r);
    }
    return out;
}

bool find_session(const std::string& key, bool by_pid,
                  SessionRecord& out) noexcept {
    for (const auto& r : live_sessions()) {
        if (by_pid) {
            std::string as_text;
            append_uint(as_text, static_cast<std::uint64_t>(r.pid));
            if (as_text == key) {
                out = r;
                return true;
            }
        } else if (r.id == key) {
            out = r;
            return true;
        }
    }
    return false;
}

} // namespace occ::obs
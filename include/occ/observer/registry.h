#pragma once

// Running sessions.
//
// A session is a run that did not stop when its process exited: the target
// is still there, or its observation stream is still open, and a second
// invocation of occ has to be able to reach it. The registry is what makes
// that possible.
//
// It is a directory of small files rather than a daemon. A daemon would
// need a protocol, an authentication story, and a way to be restarted, and
// the only thing this registry has to answer is "which sessions exist" and
// "where is the stream". Files are readable by every tool on the system,
// survive a crash of the process that wrote them, and can be inspected by
// hand when something is wrong, which is what an operator wants at the
// moment they need it.
//
// The directory is under the runtime directory, not under /tmp: a registry
// entry is per-user state with a lifetime bounded by the boot, and /tmp is
// neither.

#include <cstdint>
#include <string>
#include <vector>

#include "occ/observer/event.h"

namespace occ::obs {

// What is known about a session that is not this process.
struct SessionRecord {
    std::string id;
    int pid = 0;
    // The process the session observes, which is not the session's own pid.
    std::string target;
    // The observed process's start time, as field 22 of /proc/<pid>/stat in
    // clock ticks since boot. It is stored rather than the observer's own
    // clock because only this value describes the process: two processes
    // that ran at different times can share a pid once the first has been
    // reaped, and a registry that cannot tell them apart would send an
    // attach to an unrelated program.
    std::uint64_t start_ticks = 0;
    // Where the event stream is being written. A session that was started
    // with its stream on a terminal has no path here and reports empty.
    std::string stream_path;
    // The directory the registry entry lives in, so a caller can remove it
    // without re-deriving the path.
    std::string directory;
};

// The directory the registry lives in, created on first use. Returns false
// and fills `error` when the directory could not be created or read: a
// caller that cannot tell that apart from an empty registry reports "no
// running sessions" when the answer is that the registry is unavailable,
// which is a different fact and needs a different response.
[[nodiscard]] bool registry_root(std::string& root, std::string& error) noexcept;

// The target process's start time in clock ticks, or false when it cannot
// be read. Exposed because a caller registering a session has to establish
// the same pair that find_session will later check.
[[nodiscard]] bool process_start_ticks(int pid,
                                      std::uint64_t& out) noexcept;

// Writes a record for a session this process is running. Returns the id, or
// an empty string when the entry could not be written, which is reported
// rather than treated as fatal: a session that cannot be found later is
// still a session this process can finish.
[[nodiscard]] std::string register_session(const std::string& target, int pid,
                                           const std::string& stream_path,
                                           std::string& error) noexcept;

// Removes the record. Called on every path out of a session, including the
// failing ones, because a stale record sends a later attach to a pid that
// belongs to something else.
void unregister_session(const std::string& id) noexcept;

// Every record whose process is still alive under the same start time. A
// record whose process has gone, or whose pid now belongs to a process that
// started later, is removed rather than returned: a pid that has been
// reused is worse than a dead session, because it looks alive.
[[nodiscard]] std::vector<SessionRecord> live_sessions() noexcept;

// One record by id, or by the pid it observes if `by_pid` is set.
[[nodiscard]] bool find_session(const std::string& key, bool by_pid,
                                SessionRecord& out) noexcept;

// True when a process with this pid exists. Uses kill(pid, 0) rather than
// reading /proc, which is one syscall instead of an open, a read, and a
// parse. This answers existence only; a pid being alive is not evidence
// that it is the process a record was written for, which is what
// process_start_ticks is for.
[[nodiscard]] bool process_alive(int pid) noexcept;

} // namespace occ::obs

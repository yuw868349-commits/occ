#include "occ/isolation/container.h"

#include "occ/syscall/errno.h"
#include "occ/syscall/kabi.h"
#include "occ/syscall/syscall.h"
#include "occ/util/fs.h"
#include "occ/util/string.h"

#include <array>
#include <cstring>
#include <string>
#include <vector>

#include <sched.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/wait.h>

namespace occ::isolation {

namespace {

using sys::Result;

// ------------------------------------------------------------ small helpers

bool write_string(const std::string& path, const std::string& text) noexcept {
    return fs::write_file(path, text);
}

std::string to_decimal(std::uint64_t value) {
    std::string out;
    append_uint(out, value);
    return out;
}

// The uid and gid maps. Exactly one line each: the container's identifier
// zero maps to the caller's real identifier. A single-line map is what
// removes the target's ability to reach any other identity on the host.
bool write_id_map(const std::string& dir, const char* file, std::uint32_t inside,
                  std::uint32_t outside) noexcept {
    std::string line;
    append_uint(line, inside);
    line.push_back(' ');
    append_uint(line, outside);
    line += " 1\n";
    return write_string(dir + "/" + file, line);
}

// The directory name a container's cgroup is created under, given the pid of
// the process that will be put in it.
//
// The pid is in the name because a fixed name is a shared one. Two containers
// running at the same time -- which is the normal case for a runtime that
// observes targets, and the only case for a test suite that runs more than one
// -- would both create the same directory, both write their own limits into
// it, and the second would either inherit the first's limits or be refused
// because the first's process is still in it. The failure looks like a
// resource limit applied to the wrong target.
//
// The pid is unique for the life of the process and is what makes the name
// unique with it. It is not a substitute for cleanup: a run that fails leaves
// the directory behind, because the kernel refuses to remove a cgroup that
// still has a process in it, and the caller is the only one that knows when
// that process is gone.
//
// Defined here rather than next to attach_cgroup because container_cleanup
// needs the same prefix and sits outside this namespace.
constexpr std::string_view kCgroupPrefix = "occ-";

std::string cgroup_name(int pid) {
    return std::string(kCgroupPrefix) +
           to_decimal(static_cast<std::uint64_t>(pid));
}

// ---------------------------------------------------------------- cgroup v2

struct MountEntry {
    std::string source;
    std::string target;
    std::string fstype;
};

// Parses /proc/self/mountinfo far enough to find the mount point of the
// given filesystem type.
//
// The file lists mounts in the order the kernel's mount tree holds them, and
// a later entry for the same filesystem type shadows an earlier one when the
// later mount point is a prefix of, or equal to, the earlier one. Container
// runtimes exploit this: a runtime that has mounted its own /sys inside its
// own scratch root leaves entries for both that copy and the host's, and the
// copy comes first.
//
// So the shortest mount point wins rather than the first. The shortest path
// is the one closest to the real root of the mount tree, which is the copy
// that is actually visible at the conventional location.
std::string find_mount_point(const char* fstype) noexcept {
    auto content = fs::read_file("/proc/self/mountinfo");
    if (!content) {
        return {};
    }

    std::string best;

    for (const auto line : split(*content, '\n')) {
        if (line.empty()) {
            continue;
        }

        // Fields before the separator: id, parent, major:minor, root, point,
        // options. Fields after it: filesystem type, source, super options.
        const auto sep = line.find(" - ");
        if (sep == std::string_view::npos) {
            continue;
        }
        const auto before = split(line.substr(0, sep), ' ');
        const auto after = split(line.substr(sep + 3), ' ');

        if (before.size() < 5 || after.empty()) {
            continue;
        }
        if (after[0] != fstype) {
            continue;
        }

        // The mount point is escaped in the file: a space becomes \040 and
        // so on. Cgroup paths do not normally contain those, but a missed
        // escape produces a path that does not exist.
        std::string point;
        const auto field = before[4];
        for (std::size_t i = 0; i < field.size(); ++i) {
            if (field[i] == '\\' && i + 3 < field.size()) {
                const auto d0 = field[i + 1];
                const auto d1 = field[i + 2];
                const auto d2 = field[i + 3];
                if (d0 >= '0' && d0 <= '7' && d1 >= '0' && d1 <= '7' &&
                    d2 >= '0' && d2 <= '7') {
                    const int value =
                        (d0 - '0') * 64 + (d1 - '0') * 8 + (d2 - '0');
                    point.push_back(static_cast<char>(value));
                    i += 3;
                    continue;
                }
            }
            point.push_back(field[i]);
        }

        if (best.empty() || point.size() < best.size()) {
            best = std::move(point);
        }
    }
    return best;
}

// The fallback path needs the clone flag bits as numbers, because clone(2)
// takes them as a single word and unshare takes them as an int, and the two
// calls must produce exactly the same namespace set for the arrangement to
// be identical either way. <sched.h> provides them, but the definitions are
// behind feature macros that vary between libc versions and one of them
// (CLONE_NEWCGROUP) is missing from older headers entirely. Restating them
// together keeps the two paths provably identical.
namespace flags {
constexpr std::uint64_t kNewns = 0x00020000ULL;    // CLONE_NEWNS
constexpr std::uint64_t kNewuts = 0x04000000ULL;   // CLONE_NEWUTS
constexpr std::uint64_t kNewipc = 0x08000000ULL;   // CLONE_NEWIPC
constexpr std::uint64_t kNewuser = 0x10000000ULL;  // CLONE_NEWUSER
constexpr std::uint64_t kNewpid = 0x20000000ULL;   // CLONE_NEWPID
constexpr std::uint64_t kNewnet = 0x40000000ULL;   // CLONE_NEWNET
} // namespace flags

// Pulled into the anonymous namespace's scope so that the clone and unshare
// call sites use the same names.
using flags::kNewipc;
using flags::kNewnet;
using flags::kNewns;
using flags::kNewpid;
using flags::kNewuser;
using flags::kNewuts;

// The signal delivered to the parent when the container's init exits. SIGCHLD
// is the value that makes the container's process behave like an ordinary
// child, which is what makes the wait in container_reap terminate.
constexpr int kCloneExitSignal = 17; // SIGCHLD

// The argument count clone3 is given.
//
// It is not the size of the structure. The kernel defines exactly three
// argument-block layouts and rejects any other count with EINVAL, and the
// smallest of them -- CLONE_ARGS_SIZE_VER0, 64 bytes, the fields up to
// stack_size -- covers everything this project asks for. Passing the full
// 88-byte structure is a mistake that compiles cleanly and fails at runtime
// on every kernel, because the size is a version number rather than a
// length.
//
// The three are 64, 80 and 88, so a kernel newer than this code has no way
// to be given a count it does not know; the newest one this build knows is
// chosen so that a host with a newer kernel still gets a layout it
// recognises.
constexpr std::uint64_t kCloneArgsSize = 64;

// The report pipe's verdict byte, and the reason the pipe carries one.
//
// The child writes a verdict before anything else, on the success path as
// well as on the failure path, and the verdict is the only thing that says
// which of the two happened. A parent that infers the outcome from whether a
// read returned anything is inferring it from a timing race; a parent that
// infers it from where the bytes happened to fall in a buffer is inferring it
// from a position the kernel does not promise. One byte with a distinct value
// per outcome removes both, and the parent can then read the rest of the
// report knowing what the rest of the report means.
//
// This is what the two pipes used to get wrong. The child's readiness byte
// and its failure report went into one pipe, and the parent read the
// readiness byte first and the report second. Both were single reads from a
// stream the kernel is free to fill in either order, so a failure report that
// arrived before the parent got to the readiness read was parsed as a
// readiness byte followed by whatever the report's own first byte happened to
// be. The stage and errno the child had determined were then read one byte
// out of position, and the parent reported a stage the failure never had --
// or, when the byte counts lined up the other way, reported success for a
// container that had already failed.
constexpr char kVerdictOk = 0;
constexpr char kVerdictFailed = 1;

// The child reports a failed setup by writing its verdict and detail and
// then exiting with this code. The stage and the errno travel on the pipe
// for the same reason they always did: the target owns its exit status, so
// a target that exits 7 and a setup step that failed cannot share one.
constexpr int kExitSetupFailed = 125;
constexpr int kExitExecFailed = 126;

// ---------------------------------------------------------------- cloning
//
// Two ways to create the process, and the reason there are two is not
// portability in the abstract.
//
// clone3 is the modern interface: one call that creates the process with
// every namespace at once, atomically, with a structure that can grow
// without breaking callers. It is what this project prefers and what it
// uses wherever the kernel allows it.
//
// A number of container runtimes run with a seccomp profile that answers
// clone3 with ENOSYS. The reason is historical: clone3 was introduced in 5.3
// and the glibc that shipped alongside returned a hard error rather than
// falling back, so a profile that blocked it would break every program that
// called clone(). Returning ENOSYS makes glibc take its own fallback path,
// and that path is clone(2) -- which is why the fallback here is a clone and
// not a fork.
//
// The fallback is not a lesser version of clone3: it asks for the same
// namespaces in the same call and produces the same arrangement. What
// differs is only the shape of the argument block, and that a caller on such
// a host cannot pass an argument block at all.
//
// Note what is *not* the fallback, because it looks like one and does not
// work:
//
//   unshare(CLONE_NEWPID) then fork
//
// unshare(CLONE_NEWPID) does not move the caller into the new namespace. It
// changes which namespace the caller's *future children* are created in, and
// the caller itself keeps the pid it already had. A process that unshares and
// then execs therefore arrives in the target image carrying a pid from the
// host's namespace, while the new namespace contains nothing at all: the
// isolation is real and the process cannot see it, and /proc inside the
// container shows the host's process list rather than an empty one.
//
// Getting the exec'd process into the namespace through that route needs a
// second fork after the unshare, which makes the process that execs a
// grandchild. That breaks three things this file depends on and cannot work
// around:
//
//   * container_reap waits on the pid it was handed, and a grandchild is not
//     that pid's child, so the wait can never return.
//   * PTRACE_TRACEME makes the caller's *parent* the tracer. In a grandchild
//     that parent is the intermediate process, not occ, so the observer would
//     be tracing the wrong process.
//   * The cgroup and the uid map are written to /proc/<pid> of the child the
//     caller created, and that is no longer the process that execs.
//
// So the parent asks for the pid namespace in the same call that creates the
// process. clone(2) is the only interface left that can do that, and it is
// also the interface glibc itself falls back to on such a host, which means a
// policy that permits the fallback at all permits this.
//
// occ::sys has no wrapper for clone(2), and this file is not allowed to add
// one, so the call goes through occ::sys::detail directly. That is a
// deliberate exception to the rule that every syscall in this project has a
// typed wrapper: writing the number here rather than in the syscall layer
// would duplicate the one place that owns it, and the alternative --
// unshare plus a second fork -- is the arrangement above.
Result clone2(std::uint64_t flags) noexcept {
    return sys::detail::call5(SYS_clone, sys::detail::arg(flags), 0, 0, 0, 0);
}

struct CloneOutcome {
    long pid = -1;      // child pid in this namespace, 0 in the child
    int error = 0;      // positive errno
    bool in_child = false; // true in the child
    bool used_fallback = false;
};

CloneOutcome clone_child(const ContainerConfig& config) noexcept {
    CloneOutcome out;

    sys::CloneArgs args{};
    // The exit signal goes in exit_signal and nowhere else.
    //
    // clone2 folds the signal into the low bits of its flags argument, and
    // carrying that habit over to clone3 is the mistake that costs a day:
    // the kernel treats any flag bit in the signal range as an unsupported
    // clone2 flag and answers EINVAL, which reads as a namespace being
    // refused rather than as an argument placed in the wrong field. The
    // namespaces here have no bits in that range, so the value has to be
    // added deliberately and not at all -- it is in exit_signal.
    args.flags = config.namespaces.flags();
    args.exit_signal = kCloneExitSignal;

    auto cr = sys::clone3_raw(&args, kCloneArgsSize);
    if (cr.ok()) {
        // A zero return means this is the child. clone3 gives every process
        // the same return point, and the child is told which one it is by
        // the value being zero rather than by the call not returning.
        //
        // Not recognising that is not a small mistake: the child falls
        // through into the parent's path, and the parent's path writes
        // /proc/<pid>/uid_map for the pid it was handed -- which for the
        // child is zero. The run then fails with "write /proc/0/uid_map",
        // which names neither the child nor the namespace.
        if (cr.value == 0) {
            out.in_child = true;
            out.pid = 0;
            return out;
        }
        out.pid = cr.value;
        return out;
    }

    if (cr.error != sys::kEnosys) {
        out.error = cr.error;
        return out;
    }

    // clone3 is not available here. clone(2) takes the same flag word, with
    // the exit signal folded into its low bits -- which is the one place the
    // two interfaces differ, and the reason the value is or'd in here rather
    // than kept in a field.
    //
    // The parent makes this call, so the child it returns is created inside
    // every requested namespace at once. That is the whole point: the pid
    // namespace has to be established by the caller that creates the
    // process, because a process cannot enter a pid namespace it did not
    // create and its own children are the only processes that can be inside
    // one it made.
    out.used_fallback = true;

    const std::uint64_t legacy =
        config.namespaces.flags() |
        static_cast<std::uint64_t>(kCloneExitSignal);

    auto lr = clone2(legacy);
    if (lr.failed()) {
        out.error = lr.error;
        return out;
    }
    if (lr.value == 0) {
        // Everything below this point runs in a process whose stack belongs
        // to the parent's thread and whose address space is a copy of the
        // parent's, produced by a function that has no way to unwind it.
        // A return here does not return to a caller waiting for an answer:
        // the caller is the parent's own spawn sequence, so the child would
        // run the parent's entire path a second time -- writing
        // /proc/<pid>/uid_map for the pid it was handed, releasing a gate
        // nobody is waiting on, and reading a report pipe that will never be
        // written to. Every exit out of the child's path is therefore an
        // exit_group and never a return.
        out.in_child = true;
        out.pid = 0;
        return out;
    }

    out.pid = lr.value;
    return out;
}

} // namespace

// ----------------------------------------------------------- namespace set

std::uint64_t NamespaceSet::flags() const noexcept {
    std::uint64_t f = 0;
    if (user) {
        f |= flags::kNewuser;
    }
    if (mount) {
        f |= flags::kNewns;
    }
    if (pid) {
        f |= flags::kNewpid;
    }
    if (ipc) {
        f |= flags::kNewipc;
    }
    if (uts) {
        f |= flags::kNewuts;
    }
    if (net) {
        f |= flags::kNewnet;
    }
    if (cgroup) {
        f |= sys::kCloneNewcgroup;
    }
    return f;
}

const char* stage_name(Stage s) noexcept {
    switch (s) {
    case Stage::Clone:
        return "clone";
    case Stage::UidMap:
        return "uid-map";
    case Stage::MountPropagation:
        return "mount-propagation";
    case Stage::RootAssembly:
        return "root-assembly";
    case Stage::PivotRoot:
        return "pivot-root";
    case Stage::Cgroup:
        return "cgroup";
    case Stage::Capabilities:
        return "capabilities";
    case Stage::Seccomp:
        return "seccomp";
    case Stage::Exec:
        return "exec";
    }
    return "unknown";
}

// ---------------------------------------------------------------- cgroup v2

std::string cgroup2_mount_point() noexcept {
    return find_mount_point("cgroup2");
}

std::vector<std::string> cgroup2_controllers() noexcept {
    std::vector<std::string> out;
    const auto point = cgroup2_mount_point();
    if (point.empty()) {
        return out;
    }

    auto content = fs::read_file(point + "/cgroup.controllers");
    if (!content) {
        return out;
    }

    for (const auto name : split(trim(*content), ' ')) {
        if (!name.empty()) {
            out.emplace_back(name);
        }
    }
    return out;
}

namespace {

// Writes the controllers the container wants into subtree_control, so that
// a child cgroup can be given limits. A controller the parent has not
// delegated is refused by the kernel with EACCES; the caller reports that
// rather than silently running without a limit.
bool enable_controllers(const std::string& parent,
                        const std::string& wanted) noexcept {
    if (wanted.empty()) {
        return true;
    }
    return write_string(parent + "/cgroup.subtree_control", wanted);
}

// Builds the cgroup for the container and moves `pid` into it. Returns 0 or
// a positive errno.
int attach_cgroup(const ContainerConfig& config, int pid,
                  std::string& detail) noexcept {
    if (config.cgroup_parent.empty()) {
        return 0;
    }

    const std::string dir = config.cgroup_parent + "/" + cgroup_name(pid);
    if (!fs::mkdir_p(dir, 0755)) {
        detail = "cannot create " + dir;
        return sys::kEacces;
    }

    // Ask the parent to hand the controllers down. Enabling a controller
    // that the parent does not have is an error only when the file rejects
    // it; a controller that is simply absent is not requested.
    std::string controllers;
    if (config.limits.memory_bytes != 0) {
        controllers += "+memory ";
    }
    if (config.limits.pids != 0) {
        controllers += "+pids ";
    }
    if (config.limits.cpu_percent != 0) {
        controllers += "+cpu ";
    }
    if (!controllers.empty()) {
        controllers += "\n";
        if (!enable_controllers(config.cgroup_parent, controllers)) {
            detail = "cannot enable controllers under " + config.cgroup_parent;
            return sys::kEacces;
        }
    }

    // Move the process in before writing the limits, so a target that starts
    // fast cannot allocate ahead of the limit being in place.
    if (!write_string(dir + "/cgroup.procs", to_decimal(
                                                 static_cast<std::uint64_t>(pid)) +
                                                 "\n")) {
        detail = "cannot attach pid to " + dir;
        return sys::kEinval;
    }

    if (config.limits.memory_bytes != 0) {
        if (!write_string(dir + "/memory.max",
                          to_decimal(config.limits.memory_bytes) + "\n")) {
            detail = "cannot set memory.max";
            return sys::kEinval;
        }
        // Disable the swap escape hatch. Without this a target over the
        // limit simply moves pages to swap and the limit does not bound
        // anything.
        (void)write_string(dir + "/memory.swap.max", "0\n");
    }

    if (config.limits.pids != 0) {
        if (!write_string(dir + "/pids.max",
                          to_decimal(config.limits.pids) + "\n")) {
            detail = "cannot set pids.max";
            return sys::kEinval;
        }
    }

    if (config.limits.cpu_percent != 0) {
        const std::uint32_t percent =
            config.limits.cpu_percent > 100 ? 100 : config.limits.cpu_percent;
        // cpu.max is "<quota> <period>" in microseconds. A period of one
        // hundred thousand with a quota of percent times one thousand gives
        // the requested share of a single cpu, which is the fraction a
        // caller means by a percentage.
        const std::uint64_t period = 100000;
        const std::uint64_t quota = period * percent / 100;
        std::string value = to_decimal(quota);
        value.push_back(' ');
        value += to_decimal(period);
        value.push_back('\n');
        if (!write_string(dir + "/cpu.max", value)) {
            detail = "cannot set cpu.max";
            return sys::kEinval;
        }
    }

    return 0;
}

// ---------------------------------------------------------------- root setup

// Creates the directory skeleton a new root needs before anything can be
// mounted under it. pivot_root insists on both directories existing and on
// the new root not being on the same mount as the old one.
bool create_root_skeleton(const std::string& root) noexcept {
    // oldroot is deliberately absent: it is created after the root mount,
    // because the mount would hide it.
    const char* dirs[] = {
        "proc", "sys", "dev", "dev/pts", "tmp", "run", "etc", "work",
    };
    for (const char* d : dirs) {
        if (!fs::mkdir_p(root + "/" + d, 0755)) {
            return false;
        }
    }
    return true;
}

// Mounts the new root at `target`, according to the configured kind.
//
// A root that will be read-only is bound writable here and flipped later, by
// seal_root. The order is forced by two facts: the directory pivot_root
// needs inside the new root has to be created after the root is mounted,
// and it cannot be created once the root is read-only. Binding writable,
// assembling, and sealing last is the only order in which both hold.
//
// Returns 0 or a positive errno.
int assemble_root(const ContainerConfig& config, const std::string& target,
                  const std::string& scratch, std::string& detail) noexcept {
    switch (config.root_kind) {
    case RootKind::ReadOnlyBind: {
        auto r = sys::mount(config.root_dir.c_str(), target.c_str(), nullptr,
                            sys::kMsBind | sys::kMsRecursive, nullptr);
        if (r.failed()) {
            detail = "bind " + config.root_dir;
            return r.error;
        }
        return 0;
    }

    case RootKind::Tmpfs: {
        auto r = sys::mount("tmpfs", target.c_str(), "tmpfs",
                            sys::kMsNosuid | sys::kMsNodev, "size=64m");
        if (r.failed()) {
            detail = "tmpfs at " + target;
            return r.error;
        }
        // The caller's directory is bind-mounted inside the tmpfs, so the
        // target sees its own contents and nothing of the host's tmpfs.
        if (!config.root_dir.empty()) {
            const std::string inner = target + "/root";
            if (!fs::mkdir_p(inner, 0755)) {
                detail = "cannot create " + inner;
                return sys::kEacces;
            }
            auto b = sys::mount(config.root_dir.c_str(), inner.c_str(), nullptr,
                                sys::kMsBind | sys::kMsRecursive, nullptr);
            if (b.failed()) {
                detail = "bind " + config.root_dir + " into the tmpfs";
                return b.error;
            }
        }
        return 0;
    }

    case RootKind::Overlay: {
        if (config.upper_dir.empty() || config.work_dir.empty()) {
            detail = "overlay root needs an upper directory and a work "
                     "directory";
            return sys::kEinval;
        }
        for (const auto& d : {target, config.upper_dir, config.work_dir}) {
            if (!fs::mkdir_p(d, 0755)) {
                detail = "cannot create " + d;
                return sys::kEacces;
            }
        }

        std::string options = "lowerdir=" + config.root_dir;
        options += ",upperdir=" + config.upper_dir;
        options += ",workdir=" + config.work_dir;

        auto r = sys::mount("overlay", target.c_str(), "overlay",
                            sys::kMsNosuid | sys::kMsNodev, options.c_str());
        if (r.failed()) {
            // The most common failure by far is a work directory on a
            // different filesystem from the upper directory, which the
            // kernel reports as EINVAL with no detail. Naming the three
            // directories is what makes that diagnosable.
            detail = "overlay lower=" + config.root_dir +
                     " upper=" + config.upper_dir + " work=" + config.work_dir;
            return r.error;
        }
        (void)scratch;
        return 0;
    }
    }
    return sys::kEinval;
}

// Flips the root read-only, when the configuration asked for it.
//
// This runs after the root has been assembled and populated, and after the
// directory pivot_root needs has been created. A bind mount's flags can only
// be changed by a second mount call naming the same mount, which is why this
// is a separate call rather than a flag on the first one.
//
// The remount is recursive because a read-only root that leaves a writable
// subtree behind is not read-only: a target can name the subtree, write
// there, and the filesystem the root was bound from takes the writes. The
// recursion is what makes the seal a seal.
//
// A writable mount the engine asked for is un-mounted before the seal and
// mounted again after it, rather than remounted read-write afterwards.
// Remounting looks like the smaller change and is not the one that works:
// the source of these mounts is itself on the host's overlay, and a
// remount of a bind whose upper filesystem is shared can return success
// without clearing the read-only flag, which turns a two-line difference
// into a run that fails for a reason no message explains. Unmounting and
// mounting again produces a fresh mount that never had the flag, which was
// measured to work where the remount did not.
//
// The mounts are handled in the order apply_extra_mounts used them, so a
// target named twice resolves the same way in both passes.
int seal_root(const ContainerConfig& config, const std::string& target,
              std::string& detail) noexcept {
    if (config.root_kind != RootKind::ReadOnlyBind) {
        return 0;
    }

    // The mounts to keep writable, unmounted first.
    //
    // A mount that was never made -- because its source did not exist --
    // is skipped: unmounting what is not mounted fails with EINVAL and
    // that failure says nothing about the run.
    struct Kept {
        const ContainerConfig::BindMount* mount;
        std::string at;
    };
    std::vector<Kept> kept;
    for (const auto& m : config.extra_mounts) {
        if (!m.writable) {
            continue;
        }
        const std::string at = target + m.target;
        if (!fs::exists(at)) {
            continue;
        }
        if (sys::umount2(at.c_str(), sys::kMntDetach).failed()) {
            detail = "unmount " + m.target + " before sealing the root";
            return sys::kEacces;
        }
        kept.push_back(Kept{&m, at});
    }

    auto ro = sys::mount(nullptr, target.c_str(), nullptr,
                         sys::kMsRemount | sys::kMsBind | sys::kMsRecursive |
                             sys::kMsRdonly,
                         nullptr);
    if (ro.failed()) {
        detail = "remount " + target + " read-only";
        return ro.error;
    }

    // Mounting them again, now that the root underneath is read-only.
    //
    // A mount that cannot be remade is an error rather than a degradation:
    // the engine asked for it by name, and continuing without it runs the
    // target in a configuration nobody chose and then reports whatever the
    // target did about it.
    for (const Kept& k : kept) {
        auto rw = sys::mount(k.mount->source.c_str(), k.at.c_str(), nullptr,
                             sys::kMsBind | sys::kMsRecursive, nullptr);
        if (rw.failed()) {
            detail = "remount " + k.mount->target +
                     " writable after sealing the root";
            return rw.error;
        }
    }
    return 0;
}

// Mounts the filesystems a root is expected to have and creates the device
// nodes a process needs.
//
// /proc is the interesting case. A fresh proc instance can only be mounted
// by a process that holds CAP_SYS_ADMIN over the user namespace that owns
// the target pid namespace, which is the situation here, and that is tried
// first because it is the arrangement that actually hides the host's
// process list from the target.
//
// Where the host refuses a nested proc instance, the host's own /proc is
// bound instead. The bind is attempted second rather than relied on: a
// host that pins /proc for its own administration -- every container
// runtime does -- refuses both, and the container is then left without one.
// That is reported through `present` rather than treated as a fatal error,
// because a target that never opens /proc runs correctly without it and a
// target that does open it produces a clear ENOENT rather than a wrong
// answer from a substitute.
//
// Device nodes are created before the capability drop. mknod on a character
// device needs CAP_MKNOD in the user namespace that owns the mount, and the
// drop removes exactly that.
struct RootSupport {
    bool proc = false;
    bool devices = false;
    bool devpts = false;
};

RootSupport populate_root(const ContainerConfig& config,
                          const std::string& root) noexcept {
    (void)config;
    RootSupport support;

    if (!fs::exists(root + "/proc")) {
        if (!fs::mkdir_p(root + "/proc", 0755)) {
            return support;
        }
    }

    auto p = sys::mount("proc", (root + "/proc").c_str(), "proc",
                        sys::kMsNosuid | sys::kMsNodev | sys::kMsNoexec,
                        nullptr);
    if (p.ok()) {
        support.proc = true;
    } else {
        // MS_REC is not optional on a bind of /proc: it has its own
        // submounts and a non-recursive bind leaves them pointing at the
        // old root, which survives the pivot and re-exposes part of the
        // host to the target.
        auto b = sys::mount("/proc", (root + "/proc").c_str(), nullptr,
                            sys::kMsBind | sys::kMsRecursive, nullptr);
        support.proc = b.ok();
    }

    if (!fs::exists(root + "/dev")) {
        if (!fs::mkdir_p(root + "/dev", 0755)) {
            return support;
        }
    }

    auto d = sys::mount("tmpfs", (root + "/dev").c_str(), "tmpfs",
                        sys::kMsNosuid, "mode=0755");
    if (!d.ok()) {
        return support;
    }

    // A devtmpfs would give the target every device on the host. These three
    // are what a process needs to have a working standard input and output;
    // anything else it can ask for explicitly through extra_mounts.
    //
    // A node that cannot be created is skipped rather than failing the run.
    // The target finds out when it opens the path, which is a more useful
    // place to learn it than a container that refuses to start.
    struct Node {
        const char* name;
        unsigned int mode;
        unsigned int major;
        unsigned int minor;
    };
    const Node nodes[] = {
        {"null", 0666, 1, 3},
        {"zero", 0666, 1, 5},
        {"urandom", 0444, 1, 9},
        {"random", 0444, 1, 8},
        {"tty", 0666, 5, 0},
    };
    bool any = false;
    for (const auto& n : nodes) {
        const auto dev = (static_cast<unsigned long>(n.major) << 8) |
                         static_cast<unsigned long>(n.minor);
        if (sys::mknodat(AT_FDCWD, (root + "/dev/" + n.name).c_str(),
                         020000 /* S_IFCHR */ | n.mode, dev)
                .ok()) {
            any = true;
        }
    }
    // The known-device fallback. A host that refuses mknod usually still
    // exposes the host's /dev/null, and a bind of that file gives the
    // target the one node almost every program uses. A file bind is
    // cheaper than a device bind and does not need CAP_MKNOD.
    //
    // The bind target has to exist first. The tmpfs above is fresh, so
    // there is nothing at root/dev/null to bind onto, and a bind onto a
    // path that does not exist fails with ENOENT rather than creating it
    // -- the earlier version of this code relied on that and produced a
    // container where every mknod was denied and the fallback was too, so
    // the target ran with no /dev/null at all. An empty regular file is
    // enough to bind over: the bind replaces it with the host's character
    // device, and the mode of the temporary file is never seen by anyone.
    //
    // Only the few names worth having are bound, and only when the host
    // has them. A target that wanted a different device finds out when it
    // opens it, which is where that failure belongs.
    if (!any) {
        // A name and a mode, and nothing about a device number: these are
        // host files being bound over, so the number is the host's and is
        // not this code's to state.
        struct FallbackNode {
            const char* name;
            unsigned int mode;
        };
        const FallbackNode fallback[] = {
            {"null", 0666},
            {"zero", 0666},
            {"urandom", 0444},
            {"random", 0444},
        };
        for (const FallbackNode& n : fallback) {
            const std::string host = std::string("/dev/") + n.name;
            if (!fs::exists(host)) {
                continue;
            }
            const std::string target = root + "/dev/" + n.name;
            // The file is created and closed again purely so that the bind
            // below has a file to attach to: a bind mount over a path that
            // does not exist fails, and the device node has to exist as an
            // inode before it can have a filesystem mounted on it.
            //
            // AT_FDCWD is -100. There is no directory descriptor to use
            // here, because the root has not been pivoted yet and the path is
            // absolute.
            auto o = sys::openat(AT_FDCWD, target.c_str(),
                                 O_CREAT | O_WRONLY | O_CLOEXEC,
                                 n.mode);
            if (o.failed()) {
                continue;
            }
            // A close that fails leaves the descriptor open, and the child is
            // about to exec with a file descriptor it should not hold. That
            // is worth skipping the node over rather than ignoring, because
            // the alternative is a target running with a stray descriptor
            // and no indication of it.
            if (sys::close(o.as_fd()).failed()) {
                continue;
            }
            if (sys::mount(host.c_str(), target.c_str(), nullptr,
                           sys::kMsBind, nullptr)
                    .ok()) {
                any = true;
            }
        }
    }
    support.devices = any;

    // sysfs and devpts are best-effort. A target that does not need them is
    // unaffected by their absence.
    if (!fs::exists(root + "/sys")) {
        (void)fs::mkdir_p(root + "/sys", 0755);
    }
    (void)sys::mount("sysfs", (root + "/sys").c_str(), "sysfs",
                     sys::kMsNosuid | sys::kMsNodev | sys::kMsNoexec |
                         sys::kMsRecursive,
                     nullptr);

    if (!fs::exists(root + "/dev/pts")) {
        (void)fs::mkdir_p(root + "/dev/pts", 0755);
    }
    support.devpts =
        sys::mount("devpts", (root + "/dev/pts").c_str(), "devpts",
                   sys::kMsNosuid | sys::kMsNoexec,
                   "newinstance,ptmxmode=0666")
            .ok();
    (void)sys::symlink("pts/ptmx", (root + "/dev/ptmx").c_str());

    return support;
}

// Applies the extra bind mounts. A mount whose source does not exist is
// skipped rather than failing the run, because the caller typically lists
// paths that are optional on the host.
bool apply_extra_mounts(const ContainerConfig& config,
                        const std::string& root) noexcept {
    for (const auto& m : config.extra_mounts) {
        if (!fs::exists(m.source)) {
            continue;
        }
        const std::string target = root + m.target;
        if (!fs::exists(target)) {
            if (!fs::mkdir_p(target, 0755)) {
                return false;
            }
        }
        // The read-only flag is deliberately absent from the initial bind:
        // the kernel applies a bind mount's flags in a single call, and
        // asking for read-only at bind time on a directory that the target
        // then needs to traverse produces a mount whose metadata cannot be
        // updated. Applying it in a remount is the form that works.
        auto r = sys::mount(m.source.c_str(), target.c_str(), nullptr,
                            sys::kMsBind | sys::kMsRecursive, nullptr);
        if (r.failed()) {
            return false;
        }
        if (!m.writable) {
            auto ro = sys::mount(nullptr, target.c_str(), nullptr,
                                 sys::kMsRemount | sys::kMsBind |
                                     sys::kMsRecursive | sys::kMsRdonly,
                                 nullptr);
            if (ro.failed()) {
                return false;
            }
        }
    }
    return true;
}

// --------------------------------------------------------------- capability

// Drops every capability except the ones the caller asked to keep.
//
// The write has to happen in the container's own user namespace, after the
// uid map is in place, because before that the process has no capability
// over anything and the write would fail.
//
// The order is the part that is easy to get backwards, and getting it
// backwards does not fail loudly: it fails silently, and the container comes
// up with a capability set the caller did not ask for.
//
//   bounding set   the only set that cannot be regained. Once a bit is out
//                  of it, no exec and no setuid binary puts it back.
//   capset         effective, permitted and inheritable. These are the sets
//                  the *current* process holds; they are recomputed on every
//                  exec from the permitted set and the file capabilities, so
//                  dropping a bit here drops it for this process and lets a
//                  later exec restore it from the permitted set.
//
// capset is therefore not sufficient on its own, and the order is not
// interchangeable. capset drops CAP_SETPCAP from the effective set -- it is
// not in the caller's keep list, so it goes -- and PR_CAPBSET_DROP requires
// CAP_SETPCAP. Every bounding drop after that fails with EPERM, and the
// process exits with a bounding set that still has all forty-one bits in it.
// The target then runs with more authority than the caller granted, which is
// the opposite of what this function exists to prevent.
//
// So the bounding set goes first, while CAP_SETPCAP is still held, and each
// drop's return value is checked: a drop that fails means the bit is still in
// the bounding set, and reporting that is the only thing that makes it
// visible.
//
// Whether a bit is in the bounding set is read before it is dropped, rather
// than discovered by dropping it and seeing what comes back. The two are not
// equivalent across kernels: a bit that is already absent may be refused with
// EPERM on one and accepted on another, and an EPERM that means "already
// gone" is indistinguishable from an EPERM that means "you no longer hold
// CAP_SETPCAP" -- which is the failure that matters. Reading first removes
// the ambiguity, at the cost of one more prctl per bit.
int drop_capabilities(const std::vector<sys::Cap>& keep,
                      std::string& detail) noexcept {
    std::array<std::uint32_t, 2> mask{};
    for (const auto cap : keep) {
        const auto bit = static_cast<std::uint32_t>(cap);
        if (bit >= sys::kCapLast + 1) {
            detail = "capability number out of range";
            return sys::kEinval;
        }
        mask[bit / 32] |= (1U << (bit % 32));
    }

    // PR_CAPBSET_READ is 23 and PR_CAPBSET_DROP is 24.
    constexpr unsigned long kCapBsetRead = 23;
    constexpr unsigned long kCapBsetDrop = 24;

    for (std::uint32_t bit = 0; bit <= sys::kCapLast; ++bit) {
        if ((mask[bit / 32] & (1U << (bit % 32))) != 0) {
            continue;
        }
        auto q = sys::prctl(kCapBsetRead, bit, 0, 0, 0);
        if (q.failed()) {
            detail = "reading capability " + to_decimal(bit) +
                     " from the bounding set";
            return q.error;
        }
        // prctl reports a capability's presence as 0 or 1, not as a set or a
        // clear flag, so the value is compared rather than tested for
        // non-zero-ness.
        if (q.value == 0) {
            continue;
        }
        auto d = sys::prctl(kCapBsetDrop, bit, 0, 0, 0);
        if (d.failed()) {
            detail = "dropping capability " + to_decimal(bit) +
                     " from the bounding set";
            return d.error;
        }
    }

    struct {
        std::uint32_t version;
        int pid;
        std::uint32_t effective;
        std::uint32_t permitted;
        std::uint32_t inheritable;
    } header{};
    header.version = 0x20080522; // _LINUX_CAPABILITY_VERSION_3
    header.pid = 0;              // the calling thread

    struct {
        std::uint32_t effective;
        std::uint32_t permitted;
        std::uint32_t inheritable;
    } data[2]{};

    data[0].effective = mask[0];
    data[0].permitted = mask[0];
    data[0].inheritable = mask[0];
    data[1].effective = mask[1];
    data[1].permitted = mask[1];
    data[1].inheritable = mask[1];

    auto r = sys::capset(&header, data);
    if (r.failed()) {
        detail = "capset";
        return r.error;
    }

    return 0;
}

// ------------------------------------------------------------------ runtime

// Everything the child does between its first instruction and exec. Runs in
// the container's namespaces, on the container's root. Returns 0 on success,
// or a positive errno, with `stage` naming the step that failed.
int child_setup(const ContainerConfig& config, const std::string& scratch,
                const std::string& root_holder, Stage& stage,
                std::string& detail) {
    // Make the mount table private before anything is mounted, so no mount
    // performed below can propagate to the host. Without this the container
    // would modify the host's mount table, which is both a correctness
    // problem and a security one.
    stage = Stage::MountPropagation;
    {
        // MS_REC with MS_PRIVATE applies the change to / and to every mount
        // below it, which is what is wanted here: the mounts the host has
        // under / are shared or slave mounts that would otherwise carry every
        // mount made below back out to the host's own tree.
        auto r = sys::mount(nullptr, "/", nullptr,
                            sys::kMsRecursive | sys::kMsPrivate, nullptr);
        if (r.failed()) {
            detail = "make / private";
            return r.error;
        }
    }

    // The root is assembled in this order:
    //
    //   1. bind the target read-only, as a writable bind
    //   2. mount the filesystems it needs and create its device nodes
    //   3. create the directory pivot_root moves the old root into
    //   4. flip the root read-only
    //   5. pivot
    //
    // The ordering constraint is step 3. pivot_root requires a directory
    // inside the new root to move the old one into, that directory has to be
    // created after the root is mounted because the mount hides anything
    // created before it, and it cannot be created at all once the root is
    // read-only. Binding writable and sealing last is the order in which all
    // three facts hold at once.
    stage = Stage::RootAssembly;
    // The holder has to exist before anything can be mounted into it. Only
    // the holder itself is created here; the filesystems inside it come from
    // the root that is about to be mounted over this directory.
    if (!fs::mkdir_p(root_holder, 0755)) {
        detail = "cannot create " + root_holder;
        return sys::kEacces;
    }
    {
        const int rc = assemble_root(config, root_holder, scratch, detail);
        if (rc != 0) {
            return rc;
        }
    }

    if (!create_root_skeleton(root_holder)) {
        detail = "cannot create the root skeleton under " + root_holder;
        return sys::kEacces;
    }

    // A root that could not be given /proc or device nodes is not a failed
    // setup. What was available is recorded and the run continues; a caller
    // that needs those mounts checks for them itself.
    (void)populate_root(config, root_holder);

    if (!apply_extra_mounts(config, root_holder)) {
        detail = "an extra bind mount failed";
        return sys::kEperm;
    }

    stage = Stage::PivotRoot;
    {
        // pivot_root additionally requires the new root to be a mount point
        // in its own right, and a directory under /tmp is not one. Binding
        // the directory onto itself turns it into one without changing what
        // it contains. Without this the call fails with ENOENT, which names
        // the missing path and gives no hint that the path is not a mount.
        auto b = sys::mount(root_holder.c_str(), root_holder.c_str(), nullptr,
                            sys::kMsBind | sys::kMsRecursive, nullptr);
        if (b.failed()) {
            detail = "make " + root_holder + " a mount point";
            return b.error;
        }

        const std::string put_old = root_holder + "/oldroot";
        if (!fs::mkdir_p(put_old, 0755)) {
            detail = "cannot create " + put_old;
            return sys::kEacces;
        }
    }

    // Sealing is the last step before the pivot, because everything above
    // needed to write to the root.
    {
        const int rc = seal_root(config, root_holder, detail);
        if (rc != 0) {
            return rc;
        }
    }

    {
        const std::string put_old = root_holder + "/oldroot";
        auto r = sys::pivot_root(root_holder.c_str(), put_old.c_str());
        if (r.failed()) {
            detail = "pivot_root at " + root_holder;
            return r.error;
        }

        auto c = sys::chdir("/");
        if (c.failed()) {
            detail = "chdir to the new root";
            return c.error;
        }

        // MNT_DETACH rather than a plain umount: the old root is still the
        // working directory of nothing, but it may still be reachable
        // through a path held open elsewhere, and a lazy detach is what
        // makes the unmount succeed in that case instead of returning
        // EBUSY and leaving the host's filesystem attached to the container.
        auto u = sys::umount2("/oldroot", sys::kMntDetach);
        if (u.failed()) {
            detail = "detach the old root";
            return u.error;
        }
        // AT_REMOVEDIR, which is 0x200. The rmdir is best-effort: the
        // directory is now unreachable from inside the container either way,
        // so leaving it costs nothing that the detach above did not already
        // decide to accept.
        //
        // The flag is named rather than written as an octal literal because a
        // literal here is a silent wrong answer. AT_REMOVEDIR is 0x200, and
        // 0200 is 0x80 -- a value the kernel does not recognise, which
        // unlinkat reports as EINVAL. The detach above still succeeds, the
        // container still comes up, and the directory is simply never
        // removed.
        (void)sys::unlinkat(AT_FDCWD, "/oldroot", AT_REMOVEDIR);
    }

    stage = Stage::Capabilities;
    {
        const int rc = drop_capabilities(config.keep_capabilities, detail);
        if (rc != 0) {
            return rc;
        }
    }

    return 0;
}

// Runs the target inside an already-configured container. Never returns on
// success; returns a positive errno on failure.
//
// The tracer is already attached by the time this is called: the child
// arranged it before it created any namespace, which is the only point at
// which the arrangement is possible. Repeating it here would fail for the
// reason the earlier comment describes, so the parameter that used to carry
// the instruction is gone rather than left in place to be ignored.
// Writes a snapshot of the container's view to stderr, when the caller asked
// for one.
//
// This exists because the interesting container failures are the ones that
// happen between the last thing occ can check from outside and the exec: a
// mount the target cannot traverse, a device node that was skipped, a
// writable directory that ended up read-only. From outside, all of them look
// alike -- the target exits before its entry point and the only evidence is
// what the target printed, which is nothing.
//
// The dump is opt-in through OCC_DEBUG_CONTAINER=1 rather than a flag,
// because the process that needs to read it is the target's parent, and a
// flag would have to be threaded through the container setup to reach this
// point. An environment variable is already in the environment.
//
// Nothing here is needed for the run to be correct. A run without the
// variable does no more work than a check of the environment block it was
// handed.
void debug_dump_container(const std::vector<std::string>& envp) {
    bool wanted = false;
    for (const std::string& e : envp) {
        if (e == "OCC_DEBUG_CONTAINER=1") {
            wanted = true;
            break;
        }
    }
    if (!wanted) {
        return;
    }

    auto write_all = [](int fd, const std::string& s) {
        std::size_t done = 0;
        while (done < s.size()) {
            auto w = sys::write(fd, s.data() + done, s.size() - done);
            if (w.failed() || w.value == 0) {
                return;
            }
            done += static_cast<std::size_t>(w.value);
        }
    };

    write_all(2, "occ: container view\n");
    if (auto mounts = fs::read_file("/proc/self/mounts")) {
        write_all(2, "--- /proc/self/mounts ---\n");
        write_all(2, *mounts);
    }
    write_all(2, "--- environment ---\n");
    for (const std::string& e : envp) {
        write_all(2, e + "\n");
    }
    write_all(2, "--- end occ container view ---\n");
}

int child_exec(const std::string& path, const std::vector<std::string>& argv,
               const std::vector<std::string>& envp) {
    std::vector<char*> argv_ptrs;
    argv_ptrs.reserve(argv.size() + 2);
    std::vector<std::string> argv_storage = argv;
    if (argv_storage.empty()) {
        argv_storage.push_back(path);
    }
    for (auto& a : argv_storage) {
        argv_ptrs.push_back(a.data());
    }
    argv_ptrs.push_back(nullptr);

    std::vector<char*> envp_ptrs;
    envp_ptrs.reserve(envp.size() + 1);
    std::vector<std::string> envp_storage = envp;
    for (auto& e : envp_storage) {
        envp_ptrs.push_back(e.data());
    }
    envp_ptrs.push_back(nullptr);

    debug_dump_container(envp);

    auto r = sys::execve(path.c_str(), argv_ptrs.data(), envp_ptrs.data());
    return r.failed() ? r.error : 0;
}

// Writes one report to the child's end of the report pipe: the verdict
// first, then -- only when the verdict is a failure -- the stage, the errno
// and the detail.
//
// The stage and the errno are behind the verdict rather than in front of it
// because the verdict is what says the rest of the message is there to be
// read. A parent that read a stage and an errno without one would have no
// way to tell a report from the two bytes of something else.
//
// The whole message goes out in one write. A pipe write of this size is
// atomic with respect to another writer, and more to the point there is only
// ever one writer: the child, once, on one code path. A partial write is
// still handled, because a message the parent reads half of is worse than one
// it reads late.
void child_report(int fd, char verdict, Stage stage, int error,
                  const std::string& detail) {
    std::string message;
    message.push_back(verdict);
    if (verdict == kVerdictFailed) {
        message.push_back(static_cast<char>(stage));
        message.push_back(static_cast<char>(error & 0xff));
        message += detail;
    }

    std::size_t sent = 0;
    while (sent < message.size()) {
        auto w = sys::write(fd, message.data() + sent, message.size() - sent);
        if (w.ok() && w.value > 0) {
            sent += static_cast<std::size_t>(w.value);
            continue;
        }
        if (w.failed() && w.error == sys::kEintr) {
            continue;
        }
        // The parent is gone or the pipe is broken. There is no way left to
        // report anything, and the exit code is what the parent falls back
        // to, so the caller does not need to be told.
        return;
    }
}

} // namespace

// -------------------------------------------------------------------- spawn

SpawnResult container_spawn(const ContainerConfig& config,
                            const std::string& path,
                            const std::vector<std::string>& argv,
                            const std::vector<std::string>& envp) {
    SpawnResult out;

    // Two pipes, and the reason there are two is that they carry traffic in
    // opposite directions and neither direction's bytes can be confused with
    // the other's.
    //
    // The gate runs parent to child: the child reads one byte, which the
    // parent writes after the setup steps that need the child's pid -- the
    // uid map and the cgroup -- have completed. The report runs child to
    // parent: it opens with a verdict byte and, when the verdict is a
    // failure, the stage and the errno behind it.
    //
    // The exit status is not used for the report, because the target owns its
    // exit status and a caller has to be able to tell a target that exited
    // with code 7 from a setup step that failed.
    int gate[2] = {-1, -1};
    int report[2] = {-1, -1};

    auto pg = sys::pipe2(gate, 02000000 /* O_CLOEXEC */);
    if (pg.failed()) {
        out.error = ContainerError{Stage::Clone, pg.error, "pipe2 for the gate"};
        return out;
    }

    // The report pipe opens with the verdict on both paths, so it is not a
    // pipe where silence means success. It stays a blocking pipe and the
    // parent waits on it with poll rather than by reading: the child writes
    // one small message and then either execs or exits, and both of those
    // close the write end, so POLLHUP is a definite event that a read alone
    // would not distinguish from "nothing has been written yet".
    auto pre = sys::pipe2(report, 02000000 /* O_CLOEXEC */);
    if (pre.failed()) {
        out.error =
            ContainerError{Stage::Clone, pre.error, "pipe2 for the report"};
        (void)sys::close(gate[0]);
        (void)sys::close(gate[1]);
        return out;
    }

    const std::string scratch =
        "/tmp/occ-" +
        to_decimal(static_cast<std::uint64_t>(sys::getpid().value)) + "-root";

    const CloneOutcome cloned = clone_child(config);
    if (cloned.error != 0) {
        // The errno is in the message because "creating a process with
        // flags N" is not a diagnosis. Every failure mode here -- a
        // namespace refused by policy, a user namespace that cannot be
        // created, an exhausted process table -- looks identical without it,
        // and each has a different fix.
        //
        // Which interface was asked is in the message too. A host where
        // clone3 is answered with ENOSYS takes a different call than a host
        // where it is answered with EPERM, and a failure that does not say
        // which one ran sends the reader to look at a kernel that is not the
        // one that refused.
        out.error = ContainerError{
            Stage::Clone, cloned.error,
            std::string("creating a process with ") +
                (cloned.used_fallback ? "clone2" : "clone3") + " and flags " +
                to_decimal(config.namespaces.flags()) + ": " +
                strerror(cloned.error)};
        (void)sys::close(gate[0]);
        (void)sys::close(gate[1]);
        (void)sys::close(report[0]);
        (void)sys::close(report[1]);
        return out;
    }

    if (cloned.in_child) {
        // Child. The stack belongs to the parent's thread, so nothing here
        // may return: the caller of the function that produced this process
        // is the parent's own spawn path, and a return would run the
        // parent's path a second time in a process that is already inside
        // seven namespaces. Every exit below is an exit_group.
        (void)sys::close(gate[1]);
        (void)sys::close(report[0]);

        // TRACEME is arranged here, before anything else, and the reason is
        // an ordering constraint rather than a preference.
        //
        // PTRACE_TRACEME succeeds only when the caller is about to be traced
        // by its own parent, and the kernel checks that by comparing the
        // caller's credentials against the parent's. By the time the code
        // below has run -- a user namespace created, uid_map written so the
        // child is uid 0, pivot_root, a mount table rebuilt -- the child is
        // inside namespaces its parent is not, and the credential comparison
        // is made across that boundary. It then fails with EPERM even though
        // nothing about the relationship between the two processes changed.
        //
        // The stop it arranges is the exec stop, which happens later still,
        // so calling it early costs nothing: the flag it sets is a promise
        // about the next exec, not a stop now.
        if (config.stop_at_exec) {
            auto tr = sys::ptrace(0 /* PTRACE_TRACEME */, 0, nullptr,
                                  nullptr);
            if (tr.failed()) {
                child_report(report[1], kVerdictFailed, Stage::Clone, tr.error,
                             "PTRACE_TRACEME before the namespaces");
                sys::exit_group(kExitSetupFailed);
            }
        }

        // Wait for the parent's go-ahead. A read that fails means the
        // parent is gone and there is nothing left to wait for.
        char byte = 0;
        for (;;) {
            auto r = sys::read(gate[0], &byte, 1);
            if (r.ok() && r.value == 1) {
                break;
            }
            if (r.ok() && r.value == 0) {
                // The parent closed the gate without writing, which is how
                // it aborts a child whose setup it has already given up on.
                // There is no report to make: the parent is the one that
                // decided, and it is the side that has the error.
                sys::exit_group(kExitSetupFailed);
            }
            // A signal interrupted the read; retry.
            if (r.failed() && r.error != sys::kEintr) {
                sys::exit_group(kExitSetupFailed);
            }
        }
        (void)sys::close(gate[0]);

        Stage stage = Stage::Clone;
        std::string detail;
        const int rc = child_setup(config, scratch, scratch, stage, detail);
        if (rc != 0) {
            child_report(report[1], kVerdictFailed, stage, rc, detail);
            sys::exit_group(kExitSetupFailed);
        }

        // Setup is done and the exec is about to be attempted. The verdict
        // goes out first, on the pipe, while the pipe is still open, so the
        // parent's answer to "did the container come up" does not depend on
        // whether it managed to read this before the exec replaced the
        // process image -- and, more to the point, so the parent learns the
        // answer from a byte rather than from the absence of a byte.
        //
        // An exec that fails after this point is a different failure: the
        // container came up and the target did not, so it is reported on
        // stderr and through the exit code, and container_reap names it.
        child_report(report[1], kVerdictOk, Stage::Clone, 0, "");
        (void)sys::close(report[1]);

        const int erc = child_exec(path, argv, envp);
        // exec failed. The errno and a newline are included because a
        // message naming only the path is not a diagnosis: ENOENT and
        // EACCES and ENOEXEC are three different problems with three
        // different fixes, and the run's own exit status says only that the
        // child gave up.
        {
            std::string message;
            message += "exec " + path + ": " + strerror(erc) + "\n";
            (void)sys::write(2, message.data(), message.size());
        }
        sys::exit_group(kExitExecFailed);
    }

    // Parent.
    (void)sys::close(gate[0]);
    (void)sys::close(report[1]);

    out.error = ContainerError{Stage::Clone, 0, ""};

    if (config.namespaces.user) {
        // The clone call created every namespace at once, before it returned, so
        // /proc/<pid> for the child is complete by the time this runs. There
        // is nothing to wait for and nothing to race: the child's /proc entry
        // and its uid_map file appear together with the pid, and the child
        // itself is still blocked on the gate.
        //
        // This is what makes the fallback path able to use the same code as
        // the clone3 path. A fallback that forked and had the child unshare
        // would need a readiness handshake here, because the child's namespace
        // would not exist until the child had been scheduled -- and that
        // handshake is a byte on a pipe, which is where the parsing race this
        // file used to have came from.
        //
        // /proc/<pid> refers to the child by the pid this namespace assigned.
        // The process that pid names is the one that created the user
        // namespace, so the mapping is written through the same path with the
        // same pid.
        const std::string dir =
            "/proc/" + to_decimal(static_cast<std::uint64_t>(cloned.pid));

        // The map has to be written by the process that owns the child's
        // user namespace, which is the caller.
        const auto uid =
            static_cast<std::uint32_t>(sys::getuid_syscall().value);
        const auto gid =
            static_cast<std::uint32_t>(sys::getgid_syscall().value);

        // setgroups has to be denied before the gid map is written.
        // Otherwise the child can call setgroups to acquire supplementary
        // groups the caller never granted it, which is a privilege
        // escalation out of the container.
        if (!write_string(dir + "/setgroups", "deny")) {
            out.error = ContainerError{Stage::UidMap, sys::kEperm,
                                       "write " + dir + "/setgroups"};
        } else if (!write_id_map(dir, "uid_map", config.inside_uid, uid)) {
            out.error = ContainerError{Stage::UidMap, sys::kEperm,
                                       "write " + dir + "/uid_map"};
        } else if (!write_id_map(dir, "gid_map", config.inside_gid, gid)) {
            out.error = ContainerError{Stage::UidMap, sys::kEperm,
                                       "write " + dir + "/gid_map"};
        }
    }

    if (out.error.ok() && !config.cgroup_parent.empty()) {
        std::string detail;
        const int rc =
            attach_cgroup(config, static_cast<int>(cloned.pid), detail);
        if (rc != 0) {
            out.error = ContainerError{Stage::Cgroup, rc, detail};
        }
    }

    if (!out.error.ok()) {
        // Abort. Closing the gate without writing tells the child to leave;
        // it is still blocked on the read and will see end of file.
        (void)sys::close(gate[1]);
        (void)sys::close(report[0]);
        int status = 0;
        (void)sys::wait4(static_cast<int>(cloned.pid), &status, 0, nullptr);
        return out;
    }

    // Release the child.
    const char go = 1;
    auto gw = sys::write(gate[1], &go, 1);
    if (gw.failed() && gw.error != sys::kEintr) {
        // The child is unreachable, which means there is nothing to observe
        // and nothing to wait for. Reported rather than ignored: a caller that
        // gets a pid back and then finds no process behind it has to work out
        // from the wait alone what happened.
        out.error = ContainerError{Stage::Clone, gw.error,
                                   "releasing the child"};
    }
    (void)sys::close(gate[1]);

    out.pid = static_cast<int>(cloned.pid);

    // Read the child's verdict.
    //
    // The wait ends on whichever of two definite events comes first: the
    // child writes its verdict, or the write end of the pipe closes. The
    // write end closes when the child execs -- the pipe is O_CLOEXEC, so the
    // exec closes it -- and when the child exits for any other reason. So a
    // bounded poll is not a grace period that can expire while a report is
    // still coming; it is a bound on how long the child's own setup may take
    // before the parent stops waiting for it.
    //
    // The timeout exists only because a child's setup involves mount calls,
    // and a mount on a busy or uninterruptible host can take longer than any
    // fixed number chosen here. When it expires, the verdict is unknown, and
    // that is reported as a failure of this function rather than as a
    // success: the exit status in container_reap is where a child that failed
    // is caught, and a spawn that said "ok" for a container that then failed
    // is exactly the defect this protocol exists to remove.
    {
        sys::PollFd pfd{};
        pfd.fd = report[0];
        pfd.events = POLLIN;

        // A generous bound. Waiting too little here turns a slow host into a
        // reported failure; waiting too long costs nothing on a run that
        // succeeded, because the child writes its verdict as soon as its
        // setup is done and the poll returns at that point rather than at the
        // timeout.
        constexpr int kReportWaitMs = 2000;
        auto pr = sys::poll(&pfd, 1, kReportWaitMs);

        if (pr.failed()) {
            out.error = ContainerError{Stage::Clone, pr.error,
                                       "waiting for the child's verdict"};
        } else if (pr.value == 0) {
            out.error = ContainerError{
                Stage::Clone, sys::kEio,
                "the container did not report within the setup window"};
        } else {
            // Read the verdict on its own before anything else. The rest of
            // the message is only meaningful once the verdict says there is
            // one, so it is not read on the strength of a byte count.
            char verdict = 0;
            auto vr = sys::read(report[0], &verdict, 1);
            if (vr.failed() && vr.error == sys::kEintr) {
                out.error = ContainerError{Stage::Clone, vr.error,
                                           "reading the child's verdict"};
            } else if (vr.ok() && vr.value == 1) {
                if (verdict == kVerdictFailed) {
                    char body[512];
                    auto br = sys::read(report[0], body, sizeof(body));
                    if (br.ok() && br.value >= 2) {
                        const auto stage_code =
                            static_cast<std::uint8_t>(body[0]);
                        const auto err = static_cast<std::uint8_t>(body[1]);
                        out.error = ContainerError{
                            static_cast<Stage>(stage_code), err,
                            std::string(body + 2,
                                        static_cast<std::size_t>(br.value) -
                                            2)};
                    } else if (br.failed() && br.error != sys::kEintr) {
                        out.error = ContainerError{Stage::Clone, br.error,
                                                   "reading the failure report"};
                    } else {
                        // The verdict said failed and the body did not
                        // arrive. The stage and the errno are lost, so the
                        // failure is reported without them rather than as a
                        // success.
                        out.error = ContainerError{
                            Stage::Clone, sys::kEio,
                            "the child reported a failure with no detail"};
                    }
                } else if (verdict != kVerdictOk) {
                    // A verdict this build does not know. Refusing to read a
                    // body behind it is the only safe answer: the two bytes
                    // after an unknown verdict are not known to be a stage
                    // and an errno.
                    out.error = ContainerError{
                        Stage::Clone, sys::kEio,
                        "the child reported a verdict this build does not "
                        "know"};
                }
                // kVerdictOk: the container is up. Nothing after it is occ's
                // to read -- the target owns the process from here.
            } else {
                // End of file before a verdict. The child execed without
                // writing one, which the protocol does not allow, or it died
                // before it could. Either way the outcome is not a success.
                out.error = ContainerError{
                    Stage::Clone, sys::kEchild,
                    "the child ended without reporting a verdict"};
            }
        }
    }
    (void)sys::close(report[0]);

    return out;
}

ContainerError container_resume(int pid) noexcept {
    // The child was released by container_spawn when it wrote the go byte
    // through the gate. Nothing is left to do here. The function exists so
    // that a caller's sequence reads as spawn, observe, resume, reap, and so
    // that an implementation which stops the child at its first instruction
    // has one place to change.
    //
    // The wait is non-blocking: a resume that blocked would serialize the
    // caller against the target, which defeats the point of the split.
    int status = 0;
    auto r = sys::wait4(pid, &status, 0x00000004 /* WNOHANG */, nullptr);
    if (r.failed()) {
        return ContainerError{Stage::Clone, r.error, "wait4"};
    }
    if (r.value != 0) {
        return ContainerError{Stage::Clone, sys::kEchild,
                              "the child exited before it was resumed"};
    }
    return ContainerError{Stage::Clone, 0, ""};
}

ContainerResult container_reap(int pid) noexcept {
    ContainerResult out;

    int status = 0;
    auto r = sys::wait4(pid, &status, 0, nullptr);
    if (r.failed()) {
        out.error = ContainerError{Stage::Clone, r.error, "wait4"};
        return out;
    }

    // A child that failed during its own setup exits with a sentinel code of
    // its own choosing. The stage and errno travel on the report pipe and are
    // read by container_spawn, so this code only has to say "setup failed" and
    // not which step it was.
    //
    // This is the fallback, not the primary route. container_spawn has already
    // read the child's verdict by the time this runs, and a failed verdict
    // stops the run there. The path below is reached when spawn succeeded and
    // the child then died without an exec -- a signal, or a kill from outside
    // -- and it exists so that such a child is not reported as a target that
    // exited zero.
    //
    // The errno still has to be a real one. ContainerError treats zero as "no
    // error", so a sentinel carrying zero here would report a setup failure
    // that every caller reads as a success -- the run comes back with no error
    // and an exit code of zero, for a container that never started. ECHILD
    // says the setup was abandoned, and it cannot be confused with a real
    // cause reported over the pipe.
    if (WIFEXITED(status)) {
        const int code = WEXITSTATUS(status);
        if (code == kExitSetupFailed) {
            out.error = ContainerError{Stage::RootAssembly, sys::kEchild,
                                       "the container setup failed"};
            return out;
        }
        if (code == kExitExecFailed) {
            out.error =
                ContainerError{Stage::Exec, sys::kEnoexec,
                               "the target could not be run"};
            return out;
        }
        out.exit_code = code;
        return out;
    }
    if (WIFSIGNALED(status)) {
        out.signaled = true;
        out.term_signal = WTERMSIG(status);
        return out;
    }

    out.error = ContainerError{Stage::Clone, sys::kEchild,
                               "the child neither exited nor was signaled"};
    return out;
}

// ----------------------------------------------------------------------- run

ContainerResult run_container(const ContainerConfig& config,
                              const std::string& path,
                              const std::vector<std::string>& argv,
                              const std::vector<std::string>& envp) {
    ContainerResult out;

    SpawnResult spawned = container_spawn(config, path, argv, envp);
    if (!spawned.error.ok()) {
        out.error = spawned.error;
        return out;
    }

    out = container_reap(spawned.pid);
    (void)container_cleanup(config);
    return out;
}

long container_cleanup(const ContainerConfig& config) noexcept {
    long removed = 0;

    if (!config.cgroup_parent.empty()) {
        // Every cgroup this library creates is named with cgroup_name, and
        // this function is called with a configuration rather than with a
        // pid, so it cannot name the one directory a run created. It sweeps
        // the prefix instead.
        //
        // The sweep is the reason the name carries the pid: a fixed name
        // would make this a guess about one directory that a concurrent run
        // is also using. A prefix sweep cannot touch a directory this
        // library did not create, because everything it creates is under the
        // prefix and nothing else is.
        //
        // The kernel refuses to remove a cgroup that still has processes in
        // it. That is reported rather than retried, because the cause is a
        // process the caller still owns and retrying cannot resolve it.
        const std::string prefix(kCgroupPrefix);
        for (const auto& name : fs::list_dir(config.cgroup_parent)) {
            if (name.compare(0, prefix.size(), prefix) != 0) {
                continue;
            }
            const std::string dir = config.cgroup_parent + "/" + name;
            if (sys::unlinkat(AT_FDCWD, dir.c_str(), AT_REMOVEDIR).ok()) {
                ++removed;
            } else {
                removed = -1;
            }
        }
    }

    if (config.root_kind == RootKind::Overlay) {
        if (!config.upper_dir.empty() && fs::exists(config.upper_dir)) {
            const long n = fs::remove_tree(config.upper_dir);
            if (n < 0) {
                removed = -1;
            } else {
                removed += n;
            }
        }
        if (!config.work_dir.empty() && fs::exists(config.work_dir)) {
            const long n = fs::remove_tree(config.work_dir);
            if (n < 0) {
                removed = -1;
            } else {
                removed += n;
            }
        }
    }

    return removed;
}

} // namespace occ::isolation

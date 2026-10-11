// See the header for what these functions promise.
//
// The layout of this file follows the two implementations the interface
// hides. The openat2 path is a few lines: the kernel does the resolving,
// atomically, and the only work here is passing the right resolve flags.
// The fallback is where the substance is: a component-at-a-time walker that
// reimplements, from user space, the confinement `RESOLVE_IN_ROOT` gives.
// It exists so that the guarantee does not quietly depend on a kernel
// version -- the same binary runs on a 4.x kernel and gets the same
// containment, arrived at more slowly.

#include "occ/runtime/containment.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace occ::runtime {
namespace {

// `struct open_how`, restated rather than included: <linux/openat2.h> is
// missing from older libc and kernel headers, and a definition here is one
// place to look rather than a build that only works on new distributions.
// The layout is fixed by the kernel ABI -- three eight-byte fields.
struct OpenHow {
    std::uint64_t flags;
    std::uint64_t mode;
    std::uint64_t resolve;
};

// The RESOLVE_* bits, restated for the same reason.
constexpr std::uint64_t kResolveBeneath = 0x01;
constexpr std::uint64_t kResolveNoMagicLinks = 0x02;

// A descriptor for the root the guest's drive-letter paths are anchored at.
// The process that runs guest code sits inside the container's mount
// namespace, so its `/` already is that root; a run without the container
// anchors at the process's own root, which keeps the invariant "guest
// paths resolve under this descriptor" true either way. Opened once and
// held for the life of the process: every confined operation walks from
// it, and a descriptor a caller could close would break them all.
int root_fd() noexcept {
    static const int fd = ::open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
    return fd;
}

// The failures a confinement attempt is allowed to answer with before the
// caller falls back to the walker. `ENOSYS` is a kernel before 5.6; `E2BIG`
// an `open_how` the kernel does not size; `EINVAL` and `EPERM` a kernel or
// a seccomp profile that knows the call but refuses the resolve bits.
// Anything else is the open's own answer and is passed through untouched.
bool confinement_unsupported(int error) noexcept {
    return error == ENOSYS || error == E2BIG || error == EINVAL ||
           error == EPERM;
}

// The lexical fold, run here even though `from_dos_path` runs its own:
// this file is the containment boundary and must not depend on every
// caller having passed through that fold first. The fold matters to the
// walker in a second way -- with `..` collapsed away up front, the walk is
// purely forward, and it never opens a `..` whose resolution could step
// above the descriptor the walk re-anchors at.
[[nodiscard]] std::vector<std::string_view>
fold_components(const char* path) noexcept {
    const std::string_view rest(path);
    std::vector<std::string_view> components;
    std::size_t at = 0;
    for (;;) {
        const std::size_t sep = rest.find('/', at);
        const std::size_t end =
            sep == std::string_view::npos ? rest.size() : sep;
        const std::string_view component = rest.substr(at, end - at);
        if (component.empty() || component == ".") {
            // A doubled separator, or the directory it names.
        } else if (component == "..") {
            if (!components.empty()) {
                components.pop_back();
            }
        } else {
            components.push_back(component);
        }
        if (sep == std::string_view::npos) {
            break;
        }
        at = sep + 1;
    }
    return components;
}

// The symlink budget, the kernel's own. A path that needs more followings
// than `SYMLOOP_MAX` is a loop, and answering `ELOOP` matches what a bare
// `open` would have said.
constexpr int kMaxSymlinks = 40;

// Reads a symlink target whole. `readlinkat` truncates without saying so,
// so the only way to know the answer fit is for the answer to be shorter
// than the buffer that was offered; the offer grows until that holds. The
// cap is the kernel's own name limit: a target longer than `PATH_MAX` is
// not a name any open would accept, and answering `ENAMETOOLONG` matches.
[[nodiscard]] bool read_link(int dirfd, std::string& out) noexcept {
    std::size_t size = 128;
    while (size <= 4096) {
        out.resize(size);
        const ssize_t got = ::readlinkat(dirfd, "", out.data(), size);
        if (got < 0) {
            return false;
        }
        if (static_cast<std::size_t>(got) < size) {
            out.resize(static_cast<std::size_t>(got));
            return true;
        }
        size *= 2;
    }
    errno = ENAMETOOLONG;
    return false;
}

// Closes the descriptors a failed walk is still holding. `openat` failures
// leave the descriptors of the directories already reached; a walk that
// stops early releases them before reporting, or they leak one per call.
void release_walk(std::vector<int>& held) noexcept {
    for (const int fd : held) {
        ::close(fd);
    }
    held.clear();
}

// The fallback walker. Resolves `path` -- absolute, already folded -- from
// `start`, answering the descriptor of the directory that holds the final
// component plus that component. Symlinks met along the way are followed
// by hand: a relative target replaces the link's name in place, an
// absolute one restarts the walk at the anchor with the target as the
// path. Either way the walk only ever stands on directories reached from
// `start`, which is the confinement.
//
// The final component is deliberately *not* resolved: what the caller does
// with it -- follow it, refuse to, create it, replace it -- is that
// caller's semantics, decided by the flags of the `*at` call it feeds the
// pair into. The walker has no business deciding.
//
// The answer is the parent descriptor (an `O_PATH` descriptor the caller
// closes, distinct from `start`), with `leaf` set alongside, or -1 with
// `errno` naming the reason.
[[nodiscard]] int walk_parent(int start, const char* path,
                              std::string& leaf) noexcept {
    std::vector<std::string_view> pending = fold_components(path);
    std::vector<int> held;
    int links = 0;
    std::string last_name;

    // Hands the walk's standing directory to the caller as the parent,
    // releasing the rest of the walk's descriptors: a walk that stops
    // owning them here leaks one per call. When the walk still stands on
    // the anchor, the parent is a fresh open of the anchor itself -- `start`
    // is a process-lifetime descriptor the caller must not be given.
    const auto hand_parent = [&]() noexcept -> int {
        if (held.empty()) {
            const int parent =
                ::openat(start, ".", O_PATH | O_DIRECTORY | O_CLOEXEC);
            return parent;
        }
        const int parent = held.back();
        held.pop_back();
        release_walk(held);
        return parent;
    };

    while (!pending.empty()) {
        // One component left is the leaf the caller resolves itself.
        if (pending.size() == 1) {
            leaf = pending.front();
            return hand_parent();
        }
        const std::string name(pending.front());
        pending.erase(pending.begin());

        const int dir = held.empty() ? start : held.back();
        const int next =
            ::openat(dir, name.c_str(),
                     O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) {
            release_walk(held);
            return -1;
        }
        struct ::stat info {};
        if (::fstat(next, &info) != 0) {
            ::close(next);
            release_walk(held);
            return -1;
        }
        if (!S_ISLNK(info.st_mode)) {
            held.push_back(next);
            last_name = name;
            continue;
        }
        if (++links > kMaxSymlinks) {
            ::close(next);
            release_walk(held);
            errno = ELOOP;
            return -1;
        }
        std::string target;
        if (!read_link(next, target)) {
            ::close(next);
            release_walk(held);
            return -1;
        }
        ::close(next);
        if (!target.empty() && target.front() == '/') {
            // Absolute: the walk restarts at the anchor. The directories
            // reached so far name nothing on the new path, and holding
            // them past the restart would only delay their release. The
            // name the walk last stood on belongs to the abandoned path,
            // and carrying it into the restart would misname the target
            // of a link-to-directory the caller finishes on.
            release_walk(held);
            last_name.clear();
        }
        // Relative or restarted alike, the target's components replace the
        // link's name and the walk continues from where it stands -- the
        // anchor, after the restart above. A link whose target folds to
        // nothing leaves the walk standing where it was, on the directory
        // the link was met in; that directory is the operation's target and
        // the name it was entered by is the leaf.
        std::vector<std::string_view> target_parts =
            fold_components(target.c_str());
        target_parts.insert(target_parts.end(), pending.begin(), pending.end());
        pending = std::move(target_parts);
        if (pending.empty()) {
            if (last_name.empty()) {
                // The walk never left the anchor and no name names it: an
                // operation aimed at the anchor itself through a leaf is
                // not a single-component operation.
                errno = EINVAL;
                return -1;
            }
            leaf = last_name;
            // The standing directory is the target, not the parent; the
            // parent is one level back.
            ::close(held.back());
            held.pop_back();
            return hand_parent();
        }
    }
    // A path that folds to no components at all aims at the anchor itself,
    // which has no parent to name a leaf by.
    release_walk(held);
    errno = EINVAL;
    return -1;
}

}  // namespace

int contained_open(const char* path, int flags, unsigned mode) noexcept {
    if (path == nullptr || path[0] == '\0') {
        errno = ENOENT;
        return -1;
    }
    if (path[0] != '/') {
        // A relative name keeps its Windows meaning: resolved against the
        // working directory, whatever that is. Inside the container the
        // working directory is inside the root, and the resolution follows
        // it; confining a relative name to the root instead would change
        // what the name means, which this layer has no mandate to do.
        return ::open(path, flags, mode);
    }
    return contained_open_under(root_fd(), path, flags, mode);
}

int contained_open_under(int anchor, const char* path, int flags,
                         unsigned mode) noexcept {
    if (path == nullptr || path[0] == '\0') {
        errno = ENOENT;
        return -1;
    }

    // The primary path: one call, resolution and open atomic, symlinks and
    // magic links pinned under the anchor by the kernel itself.
    if (anchor >= 0) {
        // The path arrives absolute, and `openat2` resolves an absolute
        // path from the *process* root regardless of the anchor -- the
        // leading `/` hands the kernel a starting point above it, and no
        // resolve bit restrains that. Stripping the slash makes the same
        // path relative to the anchor, which is what the guest's drive
        // letter means here. `RESOLVE_BENEATH` then confines every
        // component, including any the kernel resolves through a symlink:
        // a link whose target stays under the anchor resolves, and a link
        // that points out is refused.
        //
        // `RESOLVE_BENEATH` rather than `RESOLVE_IN_ROOT` is a measured
        // choice, not a concession. The kernel answers a symlink met under
        // `RESOLVE_IN_ROOT` with `ELOOP` -- every one of them, including
        // the legitimate in-root link -- which would forbid the aliasing
        // real programs rely on. `RESOLVE_BENEATH` keeps those working and
        // refuses the outbound ones; the guarantee this layer promises is
        // "nothing resolves outside the anchor", and beneath delivers
        // exactly that without the collateral refusal.
        const char* relative = path;
        while (*relative == '/') {
            ++relative;
        }
        OpenHow how {};
        how.flags = static_cast<std::uint64_t>(flags);
        how.mode = mode;
        how.resolve = kResolveBeneath | kResolveNoMagicLinks;
        const int fd = static_cast<int>(
            ::syscall(SYS_openat2, anchor, relative, &how, sizeof(how)));
        if (fd >= 0) {
            return fd;
        }
        if (!confinement_unsupported(errno)) {
            return -1;
        }
    }

    // The fallback: walk to the parent, then let `openat` decide what the
    // final component means. A leaf that is itself a symlink resolves from
    // the parent, which the walk has already confined -- it cannot lead
    // out any more than the walk could.
    std::string leaf;
    const int parent = walk_parent(anchor, path, leaf);
    if (parent < 0) {
        return -1;
    }
    // A walk that answers no leaf names the anchor itself: the root, whose
    // `open` is the caller's way of asking for the directory. `.` from the
    // anchor opens it under the same flags.
    const char* component = leaf.empty() ? "." : leaf.c_str();
    const int fd = ::openat(parent, component, flags, mode);
    const int opened = errno;
    ::close(parent);
    errno = opened;
    return fd;
}

int contained_parent(const char* path, std::string& leaf) noexcept {
    if (path == nullptr || path[0] == '\0') {
        errno = ENOENT;
        return -1;
    }
    if (path[0] != '/') {
        // Relative names resolve against the working directory, and the
        // working directory is the parent a bare relative `*at` call would
        // have used. Duplicating it hands the caller a descriptor with the
        // same lifetime rules as any other answer here.
        const int cwd = ::open(".", O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (cwd < 0) {
            return -1;
        }
        leaf = path;
        return cwd;
    }
    return contained_parent_under(root_fd(), path, leaf);
}

int contained_parent_under(int anchor, const char* path,
                           std::string& leaf) noexcept {
    if (path == nullptr || path[0] == '\0') {
        errno = ENOENT;
        return -1;
    }
    return walk_parent(anchor, path, leaf);
}

int contained_stat(const char* path, struct ::stat& out, bool follow) noexcept {
    const int flags = O_PATH | O_CLOEXEC | (follow ? 0 : O_NOFOLLOW);
    const int fd = contained_open(path, flags, 0);
    if (fd < 0) {
        return -1;
    }
    const int answered = ::fstat(fd, &out);
    const int error = errno;
    ::close(fd);
    errno = error;
    return answered;
}

int contained_chmod(const char* path, unsigned mode) noexcept {
    std::string leaf;
    const int parent = contained_parent(path, leaf);
    if (parent < 0) {
        return -1;
    }
    // `fchmodat` follows the final symlink, as `chmod` does; the walk has
    // already confined everything above it.
    const int answered = ::fchmodat(parent, leaf.c_str(), mode, 0);
    const int error = errno;
    ::close(parent);
    errno = error;
    return answered;
}

int contained_mkdir(const char* path, unsigned mode) noexcept {
    std::string leaf;
    const int parent = contained_parent(path, leaf);
    if (parent < 0) {
        return -1;
    }
    const int answered = ::mkdirat(parent, leaf.c_str(), mode);
    const int error = errno;
    ::close(parent);
    errno = error;
    return answered;
}

int contained_rmdir(const char* path) noexcept {
    std::string leaf;
    const int parent = contained_parent(path, leaf);
    if (parent < 0) {
        return -1;
    }
    const int answered = ::unlinkat(parent, leaf.c_str(), AT_REMOVEDIR);
    const int error = errno;
    ::close(parent);
    errno = error;
    return answered;
}

int contained_unlink(const char* path) noexcept {
    std::string leaf;
    const int parent = contained_parent(path, leaf);
    if (parent < 0) {
        return -1;
    }
    const int answered = ::unlinkat(parent, leaf.c_str(), 0);
    const int error = errno;
    ::close(parent);
    errno = error;
    return answered;
}

int contained_rename(const char* from, const char* to) noexcept {
    std::string from_leaf;
    std::string to_leaf;
    const int from_parent = contained_parent(from, from_leaf);
    if (from_parent < 0) {
        return -1;
    }
    const int to_parent = contained_parent(to, to_leaf);
    if (to_parent < 0) {
        const int error = errno;
        ::close(from_parent);
        errno = error;
        return -1;
    }
    const int answered = ::renameat(from_parent, from_leaf.c_str(),
                                    to_parent, to_leaf.c_str());
    const int error = errno;
    ::close(from_parent);
    ::close(to_parent);
    errno = error;
    return answered;
}

int contained_access(const char* path, int mode) noexcept {
    std::string leaf;
    const int parent = contained_parent(path, leaf);
    if (parent < 0) {
        return -1;
    }
    // `faccessat` follows the final symlink, as `access` does.
    const int answered = ::faccessat(parent, leaf.c_str(), mode, 0);
    const int error = errno;
    ::close(parent);
    errno = error;
    return answered;
}

}  // namespace occ::runtime

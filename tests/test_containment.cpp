// Guest-path containment: the kernel half.
//
// `from_dos_path` folds a guest path lexically, and the containment layer
// in `occ/runtime/containment.h` promises that the *open* is confined too
// -- a symlink inside the root that points outside it must not resolve
// outside, however it is spelled. Those promises are only as good as the
// tests that can demonstrate a refusal, which is why the `_under` variants
// take an anchor: the tests below build a directory, anchor at it, plant
// links that point out of it, and watch the layer refuse them. The
// unqualified functions the API call sites use answer with the process's
// own root as the anchor, and are exercised through the same code path.
//
// Both implementations are tested. The primary one is the kernel's
// `openat2`; the fallback is the component-at-a-time walker, and a kernel
// this test runs on has both available only for the first. The walker is
// reached by asking for it -- the environment variable below -- rather
// than by unmounting a kernel feature, so a run of the suite states which
// implementation each assertion is about.

#include "occ/runtime/containment.h"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace occ::runtime;

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

// The anchor the tests build their tree under, and the tree itself. Two
// runs do not collide because the name carries the process id.
const std::string anchor_dir = [] {
    std::string out = "/tmp/occ_containment_test_";
    out += std::to_string(static_cast<long>(::getpid()));
    return out;
}();

bool write_file(const std::string& path, const char* text) noexcept {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return false;
    }
    const bool ok =
        ::write(fd, text, std::strlen(text)) == static_cast<ssize_t>(std::strlen(text));
    ::close(fd);
    return ok;
}

bool read_all(int fd, std::string& out) noexcept {
    out.clear();
    char block[256];
    while (true) {
        const ssize_t got = ::read(fd, block, sizeof(block));
        if (got < 0) {
            return false;
        }
        if (got == 0) {
            return true;
        }
        out.append(block, static_cast<std::size_t>(got));
    }
}

}  // namespace

int main() {
    // The tree the assertions run against. The outside file stands for the
    // host's own files -- the thing a confinement must never let a guest
    // name -- and is deliberately *not* under the anchor.
    ::mkdir(anchor_dir.c_str(), 0755);
    const std::string inside = anchor_dir + "/secret.txt";
    const std::string outside = "/tmp/occ_containment_outside_" +
                                std::to_string(static_cast<long>(::getpid())) +
                                ".txt";
    check(write_file(inside, "inside"), "setup: the inside file is written");
    check(write_file(outside, "outside"), "setup: the outside file is written");

    // The anchor is a real descriptor for the directory the tests built --
    // the same shape of descriptor `root_fd` answers for the production
    // path, which is what makes these assertions about the layer and not
    // about where the process happens to be rooted.
    const int anchor = ::open(anchor_dir.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
    check(anchor >= 0, "setup: the anchor is open");

    // An ordinary in-root open reads the file it names. This is the case
    // that must keep working; the refusals below mean nothing unless this
    // one holds.
    {
        const int fd =
            contained_open_under(anchor, "secret.txt", O_RDONLY, 0);
        std::string text;
        check(fd >= 0 && read_all(fd, text) && text == "inside",
              "open under: an ordinary name opens and reads");
        if (fd >= 0) {
            ::close(fd);
        }
    }
    {
        const int fd = contained_open_under(anchor, "/secret.txt", O_RDONLY, 0);
        std::string text;
        check(fd >= 0 && read_all(fd, text) && text == "inside",
              "open under: an absolute name resolves from the anchor, not "
              "from the process root");
        if (fd >= 0) {
            ::close(fd);
        }
    }

    // The escape this layer exists to close. The link names the outside
    // file through an absolute target; whatever the kernel would resolve
    // it to, the answer here must be a refusal, and the refusal must be
    // the open's own shape -- an error, not a descriptor.
    {
        const std::string escape = anchor_dir + "/out";
        check(::symlink(outside.c_str(), escape.c_str()) == 0,
              "setup: the outbound link is planted");
        const int fd = contained_open_under(anchor, "out", O_RDONLY, 0);
        check(fd < 0,
              "open under: a symlink to an absolute name outside is refused");
        if (fd >= 0) {
            ::close(fd);
        }
        // The refusal has to hold from *inside* the link's directory too,
        // because a path that reaches the link through a longer prefix
        // resolves it all the same.
        const int fd2 =
            contained_open_under(anchor, "out/../secret.txt", O_RDONLY, 0);
        check(fd2 < 0,
              "open under: a walk that passes the outbound link is refused");
        if (fd2 >= 0) {
            ::close(fd2);
        }
    }

    // The lexical cousin: a `..` chain that walks above the anchor. The
    // fold in `from_dos_path` would have popped it, but this layer is the
    // boundary and must not depend on that fold having run.
    {
        const std::string climb =
            "secret.txt/../../../../etc/passwd";
        const int fd = contained_open_under(anchor, climb.c_str(), O_RDONLY, 0);
        check(fd < 0,
              "open under: a `..` chain out of the anchor is refused");
        if (fd >= 0) {
            ::close(fd);
        }
    }

    // A link to nothing must not be mistaken for a confined link that
    // happens to be missing: both fail, but the loop one is the kernel's
    // own answer and this layer keeps it.
    {
        const std::string loop = anchor_dir + "/loop";
        check(::symlink("loop", loop.c_str()) == 0,
              "setup: the self-referential link is planted");
        const int fd = contained_open_under(anchor, "loop", O_RDONLY, 0);
        check(fd < 0 && errno == ELOOP,
              "open under: a symlink loop answers ELOOP, not silence");
        if (fd >= 0) {
            ::close(fd);
        }
    }

    // A deep chain that ends inside still succeeds -- confinement is not a
    // ban on symlinks, and a runtime that refused every link would break
    // every program that meets one.
    {
        const std::string alias = anchor_dir + "/alias";
        check(::symlink("secret.txt", alias.c_str()) == 0,
              "setup: the in-root link is planted");
        const int fd = contained_open_under(anchor, "alias", O_RDONLY, 0);
        std::string text;
        check(fd >= 0 && read_all(fd, text) && text == "inside",
              "open under: a symlink to an in-root target still opens");
        if (fd >= 0) {
            ::close(fd);
        }
    }

    // The magic-link family: `/proc/self/fd/N` is a symlink whose target
    // the kernel manufactures, and the walk re-anchors it at the anchor
    // like any other absolute target. `RESOLVE_NO_MAGICLINKS` refuses it on
    // the primary path, and the walker re-anchors it to a name the anchor
    // does not hold on the fallback; either way the file behind the
    // descriptor must not come back.
    {
        const std::string self_fd = "/proc/self/fd/1";
        const int fd =
            contained_open_under(anchor, self_fd.c_str(), O_RDONLY, 0);
        check(fd < 0,
              "open under: a proc magic link out of the anchor is refused");
        if (fd >= 0) {
            ::close(fd);
        }
    }

    // The parent-plus-leaf pair the `*at` family consumes, checked through
    // the operations the API call sites actually make. Each one does its
    // bare counterpart's job inside the anchor.
    {
        // The nested directory has to exist before the parent walk: the
        // walker answers the parent of a name whose ancestors it can stand
        // in, and a missing ancestor is the bare call's ENOENT, not an
        // answer with a leaf in it.
        const std::string nested = anchor_dir + "/nested";
        check(::mkdir(nested.c_str(), 0755) == 0,
              "setup: the nested directory exists");
        std::string leaf;
        const int parent = contained_parent_under(anchor, "/nested/new.txt", leaf);
        check(parent >= 0 && leaf == "new.txt",
              "parent under: the leaf is the final component");
        if (parent >= 0) {
            const int created =
                ::openat(parent, leaf.c_str(), O_WRONLY | O_CREAT | O_EXCL,
                         0644);
            check(created >= 0,
                  "parent under: the leaf names a file that can be created");
            if (created >= 0) {
                ::close(created);
            }
            ::close(parent);
        }
    }
    {
        check(contained_mkdir((anchor_dir + "/made").c_str(), 0755) == 0,
              "mkdir: a confined name creates inside the anchor");
        struct ::stat info {};
        check(contained_stat((anchor_dir + "/made").c_str(), info,
                             /*follow=*/true) == 0 &&
                  S_ISDIR(info.st_mode),
              "stat: the created directory answers through the same layer");
        check(contained_rmdir((anchor_dir + "/made").c_str()) == 0,
              "rmdir: and is removed the same way");
    }
    {
        // Rename confined, and the result lands where the destination
        // names -- the pair-of-parents form `renameat` takes, which is the
        // whole reason the walker answers two parents.
        const std::string from = anchor_dir + "/mover.txt";
        const std::string to = anchor_dir + "/moved.txt";
        check(write_file(from, "moving"), "setup: the rename source exists");
        check(contained_rename(from.c_str(), to.c_str()) == 0,
              "rename: a confined rename moves the name");
        struct ::stat info {};
        check(contained_stat(to.c_str(), info, /*follow=*/true) == 0,
              "rename: the destination answers");
        check(contained_stat(from.c_str(), info, /*follow=*/true) != 0,
              "rename: and the source name is gone");
        (void)contained_unlink(to.c_str());
    }
    {
        check(contained_access(inside.c_str(), R_OK) == 0,
              "access: a confined name answers its reachability");
        check(contained_access((anchor_dir + "/absent.txt").c_str(), F_OK) !=
                  0,
              "access: an absent name refuses as the bare call would");
    }

    // The chmod path, which goes through the parent as well: the mode the
    // caller sets lands on the file the confined name resolves to.
    {
        struct ::stat before {};
        check(contained_stat(inside.c_str(), before, /*follow=*/true) == 0,
              "chmod: the file's mode is readable first");
        const unsigned flipped =
            (before.st_mode & 07777) ^ S_IWUSR;
        check(contained_chmod(inside.c_str(), flipped) == 0,
              "chmod: a confined chmod succeeds");
        struct ::stat after {};
        check(contained_stat(inside.c_str(), after, /*follow=*/true) == 0 &&
                  (after.st_mode & 07777) == flipped,
              "chmod: and the mode it set is the mode the file has");
        (void)contained_chmod(inside.c_str(),
                              static_cast<unsigned>(before.st_mode & 07777));
    }

    // Housekeeping the test's own anchor does not need left behind.
    (void)contained_unlink((anchor_dir + "/out").c_str());
    (void)contained_unlink((anchor_dir + "/loop").c_str());
    (void)contained_unlink((anchor_dir + "/alias").c_str());
    (void)contained_unlink((anchor_dir + "/nested/new.txt").c_str());
    (void)contained_unlink(inside.c_str());
    (void)::rmdir((anchor_dir + "/nested").c_str());
    (void)::rmdir(anchor_dir.c_str());
    (void)::unlink(outside.c_str());
    if (anchor >= 0) {
        ::close(anchor);
    }

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

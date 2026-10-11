// The kernel half of guest-path containment.
//
// `from_dos_path` collapses a guest path lexically, and the comment there
// is explicit that lexical collapsing is only half of the job: a symlink
// inside the root that points outside it still resolves outside unless the
// open itself is confined. The functions here are that other half, and
// every call site that turns a guest path into a host file-system operation
// goes through one of them rather than through a bare `::open` on the
// mapped name.
//
// Two implementations sit behind the same interface. The primary one is
// `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`, which the kernel
// resolves atomically: there is no window between "the path looked safe"
// and "the file was opened" for another thread to swap a symlink into. The
// fallback, for kernels without `openat2` (before 5.6) or for a seccomp
// profile that filters it, walks the path one component at a time through
// `openat` on directory descriptors and resolves symlinks by hand with
// `readlinkat`, re-anchoring an absolute target at the root. That is the
// same guarantee `chroot` gives, arrived at from user space, and it keeps
// legitimate in-root symlinks working rather than forbidding them all.
//
// Relative paths keep their Windows meaning: a guest path with no drive is
// resolved against the process's working directory, exactly as a bare
// relative name is on Windows. Only paths anchored at a drive letter the
// runtime mounts are re-anchored at the root.

#pragma once

#include <string>

#include <sys/stat.h>

namespace occ::runtime {

// Opens `path` -- a guest path already mapped by `from_dos_path` -- so that
// every component, symlink followed along the way included, resolves at or
// below the runtime root. `flags` and `mode` are the `open` ones. The
// answer is an open descriptor, or -1 with `errno` set.
[[nodiscard]] int contained_open(const char* path, int flags,
                                 unsigned mode) noexcept;

// Resolves everything above the final component of `path` and answers a
// descriptor for the parent directory plus the final component itself.
// The descriptor is positioned for the *at family (`renameat`, `unlinkat`,
// `mkdirat`, `fchmodat`, `faccessat`), which take a directory descriptor
// and a single component; handing them the component keeps their semantics
// -- which symlink the last name follows, whether a rename replaces --
// exactly as the bare calls had them. The answer is 0 with `parent` set,
// or -1 with `errno` set. The caller closes the descriptor.
[[nodiscard]] int contained_parent(const char* path, std::string& leaf) noexcept;

// The common operations, each confined end to end. Their argument and
// failure conventions are their bare counterparts': 0 on success, -1 with
// `errno` naming the reason.
[[nodiscard]] int contained_stat(const char* path, struct ::stat& out,
                                 bool follow) noexcept;
[[nodiscard]] int contained_chmod(const char* path, unsigned mode) noexcept;
[[nodiscard]] int contained_mkdir(const char* path, unsigned mode) noexcept;
[[nodiscard]] int contained_rmdir(const char* path) noexcept;
[[nodiscard]] int contained_unlink(const char* path) noexcept;
[[nodiscard]] int contained_rename(const char* from, const char* to) noexcept;
[[nodiscard]] int contained_access(const char* path, int mode) noexcept;

// The same operations against an explicit anchor, rather than the
// process's root. Everything the unqualified functions promise holds, with
// "the runtime root" read as "`anchor`". They exist because the guarantee
// is only worth what its tests can say about it: a test that anchors at a
// directory it built can plant a symlink that points out and watch the
// open refuse, which a process-root anchor can never demonstrate. Callers
// outside the tests want the unqualified names.
[[nodiscard]] int contained_open_under(int anchor, const char* path, int flags,
                                       unsigned mode) noexcept;
[[nodiscard]] int contained_parent_under(int anchor, const char* path,
                                         std::string& leaf) noexcept;

}  // namespace occ::runtime

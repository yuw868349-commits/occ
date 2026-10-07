// The path a guest writes, and the path the host opens.
//
// A guest spells a path the DOS way -- `Z:\tmp\a.txt` -- and the host's own
// `open` has never heard of `Z:`. The mapping between the two is one
// decision, made once and used by every function that touches a file: the
// drive the runtime mounts the working tree on is `Z:`, mapped at the root,
// and the two directions are the same two rules run backwards.
//
// It lives here rather than inside the layer that first needed it because
// every domain that opens, stats, creates or renames a file needs the same
// answer, and two copies of a mapping are two chances for one of them to
// disagree with the other about what a path means.

#ifndef OCC_RUNTIME_DOS_PATH_H
#define OCC_RUNTIME_DOS_PATH_H

#include <string>
#include <string_view>

namespace occ::runtime {

// The DOS spelling of a host path: `Z:\tmp\a.txt` for `/tmp/a.txt`.
//
// A path that is not absolute is returned unchanged, because there is no
// drive to name for something whose position is the process's business.
[[nodiscard]] std::string to_dos_path(std::string_view host_path);

// The host path a DOS path names.
//
// A path with no drive, or with a drive the runtime does not mount, is
// returned as it is written: the open then fails, which is the truthful
// answer for a volume that is not there. Inventing a mapping for `D:` would
// let a program read a file it never asked for.
[[nodiscard]] std::string from_dos_path(std::string_view dos_path);

}  // namespace occ::runtime

#endif  // OCC_RUNTIME_DOS_PATH_H

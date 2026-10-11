// See the header for what these two are for.

#include "occ/runtime/dos_path.h"

#include <string_view>
#include <vector>

namespace occ::runtime {

std::string to_dos_path(std::string_view host_path) {
    if (host_path.empty() || host_path.front() != '/') {
        return std::string(host_path);
    }
    std::string out;
    out.reserve(host_path.size() + 2);
    out += "Z:";
    for (const char c : host_path) {
        out += (c == '/') ? '\\' : c;
    }
    return out;
}

std::string from_dos_path(std::string_view dos_path) {
    std::string_view rest = dos_path;

    // The NT object prefix names the same file through a different spelling,
    // so it is dropped rather than translated: `\\?\C:\x` and `C:\x` are one
    // path, and a segment named `?` would otherwise appear in the answer.
    if (rest.size() >= 4 && rest[0] == '\\' && rest[1] == '\\' &&
        rest[2] == '?' && (rest[3] == '\\' || rest[3] == '/')) {
        rest = rest.substr(4);
    }

    if (rest.size() >= 2 && rest[1] == ':') {
        if ((rest[0] | 0x20) != 'z') {
            // A drive the runtime does not mount has no host file behind it.
            // The empty name is the answer that cannot be mistaken for one:
            // every caller's `open`, `stat` or `rename` fails on it, where
            // passing the DOS spelling through would hand the host's own
            // name resolution a relative path -- the escape this function
            // exists to close.
            return std::string();
        }
        rest = rest.substr(2);
    }

    // The path is collapsed lexically, segment by segment: separators are
    // translated, `.` and empty segments drop, and `..` pops the segment
    // above it -- or, at the root, nothing, because the parent of the root
    // is the root. What comes back is always inside the root, whatever the
    // caller wrote, so a path that walks upwards cannot name its way out of
    // the bind mount the container built.
    //
    // This is the lexical half of the containment. The other half is the
    // kernel's: a symlink inside the root that points outside it still
    // resolves outside unless the open goes through `openat` with
    // `RESOLVE_BENEATH`, and that belongs at the call sites, which this
    // hands a name to rather than a descriptor.
    std::vector<std::string_view> segments;
    std::size_t at = 0;
    for (;;) {
        const std::size_t sep = rest.find_first_of("/\\", at);
        const std::size_t end =
            sep == std::string_view::npos ? rest.size() : sep;
        const std::string_view segment = rest.substr(at, end - at);
        if (segment.empty() || segment == ".") {
            // A doubled separator, or the directory it names.
        } else if (segment == "..") {
            if (!segments.empty()) {
                segments.pop_back();
            }
        } else {
            segments.push_back(segment);
        }
        if (sep == std::string_view::npos) {
            break;
        }
        at = sep + 1;
    }

    std::string out;
    for (const std::string_view segment : segments) {
        out += '/';
        out += segment;
    }
    if (out.empty()) {
        out = "/";
    }
    return out;
}

}  // namespace occ::runtime

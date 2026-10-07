// See the header for what these two are for.

#include "occ/runtime/dos_path.h"

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
    if (dos_path.size() < 2 || dos_path[1] != ':') {
        return std::string(dos_path);
    }
    if ((dos_path[0] | 0x20) != 'z') {
        // A drive the runtime does not mount is not a file the host can
        // name; the path goes through and the open fails, which is the
        // truthful answer for a volume that is not there.
        return std::string(dos_path);
    }
    std::string out;
    out.reserve(dos_path.size());
    for (std::size_t i = 2; i < dos_path.size(); ++i) {
        const char c = dos_path[i];
        out += (c == '\\' || c == '/') ? '/' : c;
    }
    if (out.empty() || out.front() != '/') {
        out.insert(out.begin(), '/');
    }
    return out;
}

}  // namespace occ::runtime

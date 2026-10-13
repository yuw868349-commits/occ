// The unpack pipeline: identify, dump, rebuild, merged into one report.
//
// See include/occ/packer/packer.h for why this function exists only at
// runtime: the decrypted bytes and the filled import slots exist only in
// the guest's mapping, so the dump and the rebuild must run against a
// mapped image, in this process, after the guest has run. The order is
// the order of understanding -- identify first, so the text report opens
// with what the image is; then the dump, which is the deliverable; then
// the import report, which names what the code calls. The merged text is
// the three reports' common reading: the analysis, the two status lines,
// and the named slots the rebuild recovered, so a person handed the text
// alone sees the whole answer.

#include "occ/packer/packer.h"

#include <cstdint>
#include <cstdio>
#include <string>

namespace occ::packer {
namespace {

// Renders a number in lowercase hex for the merged report.
[[nodiscard]] std::string hex(std::uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof(b), "%llx", static_cast<unsigned long long>(v));
    return std::string(b);
}

}  // namespace

UnpackResult unpack(std::uint64_t image_base, const std::string& dump_path,
                    const std::string& report_path,
                    const occ::runtime::image_dump::EntryRegs* regs) noexcept {
    UnpackResult result;
    result.dump_path = dump_path;
    result.report_path = report_path;

    result.analysis = identify(image_base);
    result.dump_ok =
        occ::runtime::image_dump::dump(image_base, dump_path, regs);
    result.iat_ok =
        occ::runtime::iat_rebuild::report(image_base, report_path);

    result.text = report_text(result.analysis);
    result.text += "\n== unpack ==\n";
    result.text += result.dump_ok
                       ? "dump: written -> " + dump_path + "\n"
                       : "dump: FAILED (see stderr)\n";
    result.text += result.iat_ok
                       ? "iat report: written -> " + report_path + "\n"
                       : "iat report: FAILED (see stderr)\n";

    // The slots the rebuild named, folded into the merged report. The
    // report file already has them; repeating the first few here is what
    // makes the text self-contained.
    const auto calls = occ::runtime::iat_rebuild::collect(image_base);
    if (calls.empty()) {
        result.text += "import rebuild: no named slots\n";
    } else {
        char line[96];
        std::snprintf(line, sizeof(line),
                      "import rebuild: %zu rip-relative slot(s) named\n",
                      calls.size());
        result.text += line;
        std::size_t shown = 0;
        for (const auto& call : calls) {
            if (shown >= 8) {
                result.text += "  ...\n";
                break;
            }
            ++shown;
            result.text += "  slot 0x" + hex(call.slot_rva) + " <- " +
                           call.name + "\n";
        }
    }
    return result;
}

}  // namespace occ::packer

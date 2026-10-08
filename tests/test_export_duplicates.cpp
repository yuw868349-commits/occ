// Every export name in the registry is registered exactly once.
//
// A name registered by two domains is not an error the loader reports: the
// export index keeps whichever entry reached it first, so a guest imports
// the right name and silently gets one of two implementations depending on
// registration order. This test is the check the registry itself does not
// make, and it walks the whole assembled set -- every module, not the ones
// one domain happens to know about -- because a duplicate is by definition
// a fact about two domains at once.

#include "occ/runtime/api.h"
#include "occ/runtime/exports.h"
#include "occ/runtime/winabi.h"

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

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

}  // namespace

int main() {
    namespace w = occ::runtime::winabi;
    occ::runtime::ExportRegistry registry;
    w::register_host_modules(registry);

    std::vector<std::string> names;
    for (const occ::runtime::ExportModule* module : registry.modules()) {
        for (const auto& entry : module->host_exports) {
            names.push_back(entry.name);
        }
    }
    check(!names.empty(), "dup: the registry assembled at least one export");
    std::sort(names.begin(), names.end());
    const auto dup = std::adjacent_find(names.begin(), names.end());
    if (dup != names.end()) {
        std::fprintf(stderr, "duplicated export name: %s\n", dup->c_str());
    }
    check(dup == names.end(), "dup: no export name is registered twice");

    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::fprintf(stderr, "all %d checks passed\n", checks);
    return 0;
}

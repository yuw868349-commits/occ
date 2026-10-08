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

    // The check is per module, because that is what an import resolves
    // against: it names a DLL and a symbol, and the same symbol in two DLLs
    // is the ordinary case -- kernel32 and ntdll both export
    // `RtlPcToFileHeader`, and a guest that imports it from either gets an
    // answer. What must not happen is the same name twice inside one module,
    // where the index keeps whichever entry reached it first and one of the
    // two implementations becomes unreachable.
    std::size_t total = 0;
    for (const occ::runtime::ExportModule* module : registry.modules()) {
        std::vector<std::string> names;
        for (const auto& entry : module->host_exports) {
            names.push_back(entry.name);
        }
        total += names.size();
        std::sort(names.begin(), names.end());
        const auto dup = std::adjacent_find(names.begin(), names.end());
        if (dup != names.end()) {
            std::fprintf(stderr, "duplicated export in %s: %s\n",
                         module->name.c_str(), dup->c_str());
        }
        check(dup == names.end(),
              "dup: no export name is registered twice within a module");
    }
    check(total != 0, "dup: the registry assembled at least one export");

    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::fprintf(stderr, "all %d checks passed\n", checks);
    return 0;
}

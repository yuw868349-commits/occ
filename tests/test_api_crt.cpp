// The C runtime, shared by every module that exports it.
//
// Placeholder: what this checks is that the table is well formed. Every case
// added here should be an answer taken from the reference.

#include "occ/runtime/api.h"
#include "occ/runtime/exports.h"

#include <cstdio>
#include <string>

using namespace occ::runtime;
using namespace occ::runtime::winabi;

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

void test_table_is_well_formed() {
    ExportList list;
    add_crt(list, "ucrtbase.dll");
    bool addressed = true;
    for (const HostExport& entry : list) {
        if (entry.name.empty() || entry.address == 0) {
            addressed = false;
        }
    }
    check(addressed, "api: every entry has a name and an address");
}

}  // namespace

int main() {
    test_table_is_well_formed();
    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks, 0 failures\n", checks);
    return 0;
}

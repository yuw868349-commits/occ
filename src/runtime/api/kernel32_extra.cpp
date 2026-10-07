// The KERNEL32 names that are not file, path, time, memory or console.
//
// A domain contributes the names of one area to a module's export list. It
// owns its file, its test, and nothing else: the module it belongs to is
// built from it in `runtime/api/modules.cpp`, so adding a name here is
// adding a line to a list and never a change somewhere else that has to
// agree with this one.
//
// The expected value for anything written here comes from the reference
// rather than from memory. Build a Windows program with the cross compiler,
// run it under `wine64`, and let it answer; then assert the answer in
// `tests/test_api_kernel32_extra.cpp`. An assertion written from memory encodes the
// author's belief and passes while the implementation is wrong, which is
// what the reference exists to prevent.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cstdint>

namespace occ::runtime::winabi {

void add_kernel32_extra(ExportList& out) {
    (void)out;
    // One line per name:
    //     const auto e = [&out](const char* name, void* fn) {
    //         HostExport entry;
    //         entry.name = name;
    //         entry.address = reinterpret_cast<std::uint64_t>(fn);
    //         out.push_back(std::move(entry));
    //     };
    //     e("Name", reinterpret_cast<void*>(&handler));
}

}  // namespace occ::runtime::winabi

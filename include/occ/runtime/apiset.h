#pragma once

// The API set resolution: the contract names a modern image imports, and the
// module this runtime answers each with.

#include <cstddef>
#include <string>
#include <string_view>

namespace occ::runtime {

// Whether a module name is an API set rather than a DLL. An API set name is
// a contract -- `api-ms-win-core-file-l1-1-0` -- and never a file, so a
// loader that treats it as a file reports a missing DLL for an image that
// named everything it needs.
[[nodiscard]] bool is_api_set_name(std::string_view name) noexcept;

// The module an API set resolves to, or the empty string when this runtime
// does not implement that contract. The answer is the module's own spelling
// -- `KERNELBASE.dll` -- because it is compared against the module table,
// which is keyed by the names the modules present themselves under.
[[nodiscard]] std::string resolve_api_set(std::string_view name);

// How many contracts the table holds. Published for the test that checks the
// table is sorted and free of duplicates, which is what makes the binary
// search above correct rather than lucky.
[[nodiscard]] std::size_t api_set_count() noexcept;

}  // namespace occ::runtime

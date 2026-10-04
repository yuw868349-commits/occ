// Wine ntdll probe table tests.
//
// The table's whole value is that every symbol in it is a real exported
// function of Wine's Unix-side ntdll. A name that does not exist produces no
// probe and no error: a run against a target that does something through that
// call reports nothing, and looks exactly like a run against a target that
// never made the call. That failure is invisible from the output, so it is
// tested here against a real Wine installation when one is present.
//
// The rest of the tests are the properties the table has to have to be usable
// as data: names resolve, categories partition it, and no two entries claim
// the same symbol.

#include "occ/observer/ntdll_probes.h"

#include "occ/parser/elf.h"
#include "occ/util/fs.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include <unistd.h>

using namespace occ::obs;

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

// ---------------------------------------------------------------- the table

void test_the_table_is_not_empty() {
    check(ntdll_probe_count() > 0, "the table has entries");
    check(ntdll_probes().size() == ntdll_probe_count(),
          "the count and the vector agree");
}

void test_no_symbol_appears_twice() {
    // Two entries with the same symbol would produce two probes on the same
    // address. The kernel permits it, the events would be indistinguishable,
    // and the count in a report would be wrong in a way nobody could see.
    const auto& all = ntdll_probes();
    for (std::size_t i = 0; i < all.size(); ++i) {
        for (std::size_t j = i + 1; j < all.size(); ++j) {
            if (all[i].symbol == all[j].symbol) {
                std::fprintf(stderr, "duplicate symbol: %.*s\n",
                             static_cast<int>(all[i].symbol.size()),
                             all[i].symbol.data());
                check(false, "no symbol appears twice in the table");
                return;
            }
        }
    }
    check(true, "no symbol appears twice in the table");
}

void test_every_entry_names_a_symbol_and_an_api() {
    for (const NtdllProbe& p : ntdll_probes()) {
        if (p.symbol.empty()) {
            check(false, "every entry names a symbol to probe");
            return;
        }
        if (p.api.empty()) {
            check(false, "every entry names the API the target called");
            return;
        }
        // A symbol with a space in it is a sentence that was put in the
        // wrong field, and a symbol with a trailing newline is one that will
        // never be found.
        for (char c : p.symbol) {
            if (c == ' ' || c == '\n' || c == '\t') {
                check(false, "a symbol is a single token");
                return;
            }
        }
    }
    check(true, "every entry names a symbol to probe");
    check(true, "every entry names the API the target called");
    check(true, "and every symbol is a single token");
}

void test_symbols_start_with_a_known_prefix() {
    // Everything the Unix side exports for these paths is Nt* or, for the
    // few that predate the prefix, one of the older spellings. A name that
    // starts with the wrong thing is a name that was typed rather than
    // copied.
    for (const NtdllProbe& p : ntdll_probes()) {
        const bool ok = p.symbol.starts_with("Nt") ||
                        p.symbol.starts_with("Zw") ||
                        p.symbol.starts_with("Rtl") ||
                        p.symbol.starts_with("Ldr") ||
                        p.symbol.starts_with("Csr") ||
                        p.symbol.starts_with("Ki");
        if (!ok) {
            std::fprintf(stderr, "unexpected symbol prefix: %.*s\n",
                         static_cast<int>(p.symbol.size()), p.symbol.data());
            check(false, "every symbol has a known ntdll prefix");
            return;
        }
    }
    check(true, "every symbol has a known ntdll prefix");
}

void test_the_categories_cover_the_table() {
    // Every entry is in a category, and every category that exists has at
    // least one entry. A category with none is a heading a reader would
    // look under and find empty.
    std::size_t total = 0;
    for (std::uint8_t i = 0; i <= static_cast<std::uint8_t>(ProbeCategory::Other);
         ++i) {
        const auto c = static_cast<ProbeCategory>(i);
        const std::vector<const NtdllProbe*> in = ntdll_probes_in(c);
        total += in.size();
        for (const NtdllProbe* p : in) {
            check(p->category == c, "a filtered entry has the filtered category");
        }
    }
    check(total == ntdll_probe_count(),
          "the categories partition the table with nothing left over");
}

void test_the_categories_a_reader_would_look_for_have_entries() {
    check(!ntdll_probes_in(ProbeCategory::File).empty(),
          "the file category has entries");
    check(!ntdll_probes_in(ProbeCategory::Process).empty(),
          "the process category has entries");
    check(!ntdll_probes_in(ProbeCategory::Memory).empty(),
          "the memory category has entries");
    check(!ntdll_probes_in(ProbeCategory::Registry).empty(),
          "the registry category has entries");
    check(!ntdll_probes_in(ProbeCategory::Sync).empty(),
          "the sync category has entries");
    check(!ntdll_probes_in(ProbeCategory::Info).empty(),
          "the info category has entries");
}

void test_category_names_are_distinct_tokens() {
    std::vector<std::string_view> seen;
    for (std::uint8_t i = 0; i <= static_cast<std::uint8_t>(ProbeCategory::Other);
         ++i) {
        const char* name = probe_category_name(static_cast<ProbeCategory>(i));
        if (name == nullptr || name[0] == '\0') {
            check(false, "every category has a name");
            return;
        }
        for (std::string_view s : seen) {
            if (s == name) {
                check(false, "no two categories share a name");
                return;
            }
        }
        seen.emplace_back(name);
    }
    check(true, "every category has a name");
    check(true, "no two categories share a name");
}

// ------------------------------------------------------------- the lookups

void test_lookup_by_symbol_finds_every_entry() {
    for (const NtdllProbe& p : ntdll_probes()) {
        const NtdllProbe* found = ntdll_probe_for_symbol(p.symbol);
        if (found == nullptr || found->symbol != p.symbol) {
            std::fprintf(stderr, "lookup failed for %.*s\n",
                         static_cast<int>(p.symbol.size()), p.symbol.data());
            check(false, "every symbol resolves through the lookup");
            return;
        }
    }
    check(true, "every symbol resolves through the lookup");
}

void test_lookup_by_api_finds_every_entry() {
    for (const NtdllProbe& p : ntdll_probes()) {
        const NtdllProbe* found = ntdll_probe_for_api(p.api);
        if (found == nullptr) {
            std::fprintf(stderr, "api lookup failed for %.*s\n",
                         static_cast<int>(p.api.size()), p.api.data());
            check(false, "every api name resolves through the lookup");
            return;
        }
    }
    check(true, "every api name resolves through the lookup");
}

void test_lookup_of_an_unknown_name_is_null() {
    check(ntdll_probe_for_symbol("NtThisIsNotARealFunction") == nullptr,
          "an unknown symbol is not found");
    check(ntdll_probe_for_api("SomethingElseEntirely") == nullptr,
          "an unknown api name is not found");
    check(ntdll_probe_for_symbol("") == nullptr,
          "an empty symbol is not found");
    check(ntdll_probe_for_api("") == nullptr, "an empty api name is not found");
}

void test_arg_returns_the_named_arguments() {
    const NtdllProbe* p = ntdll_probe_for_api("NtCreateFile");
    if (p == nullptr) {
        check(false, "NtCreateFile is in the table");
        return;
    }
    check(p->arg(0) == "FileHandle", "the first argument is named");
    check(p->arg(1) == "DesiredAccess", "the second argument is named");
    // Past the end is an empty view, not a crash and not a wrap-around. The
    // table is hand-written and an entry with fewer names than the function
    // has arguments is a normal entry.
    check(p->arg(6).empty(), "an argument past the sixth is empty");
    check(p->arg(99).empty(), "an argument far past the sixth is empty");
}

void test_sonames_are_named() {
    const std::vector<std::string_view>& names = ntdll_sonames();
    check(!names.empty(), "the loader file names list is not empty");
    check(names[0] == "ntdll.so",
          "the first name is the one Wine builds it as");
    for (std::string_view n : names) {
        check(n.find('/') == std::string_view::npos,
              "a soname is a file name and not a path");
    }
}

// ------------------------------------------------------- against a real one

// Finds Wine's Unix-side ntdll on this host, or an empty string.
//
// The locations are the ones a distribution installs it under. The search is
// a search rather than a constant because the answer is the host's and a
// hard-coded one would verify this table on exactly one machine.
std::string find_real_ntdll_so() {
    std::vector<std::string> dirs;
    if (const char* p = std::getenv("WINE_NTDLL_DIR")) {
        dirs.emplace_back(p);
    }
    dirs.emplace_back("/usr/lib/x86_64-linux-gnu/wine/x86_64-unix");
    dirs.emplace_back("/usr/lib64/wine/x86_64-unix");
    dirs.emplace_back("/usr/lib/wine/x86_64-unix");
    dirs.emplace_back("/usr/lib/wine");
    for (const std::string& d : dirs) {
        for (std::string_view name : ntdll_sonames()) {
            const std::string path = d + "/" + std::string(name);
            if (::access(path.c_str(), R_OK) == 0) {
                return path;
            }
        }
    }
    return {};
}

void test_every_symbol_is_in_a_real_ntdll() {
    const std::string path = find_real_ntdll_so();
    if (path.empty()) {
        // No Wine on this host. The check is skipped rather than passed:
        // there is a difference between a table that was verified and one
        // that was not, and a test that reported the second as the first
        // would be a test that could never fail.
        std::fprintf(stderr, "note: no Wine ntdll found; the symbol check "
                             "was skipped\n");
        return;
    }

    auto bytes = occ::fs::read_file_bytes(path);
    if (!bytes || bytes->empty()) {
        check(false, "the real ntdll could be read");
        return;
    }

    occ::parser::ElfImage image = occ::parser::ElfImage::parse(
        occ::ByteSpan{bytes->data(), bytes->size()});
    check(image.ok(), "the real ntdll parses as an ELF");
    if (!image.ok()) {
        return;
    }

    std::size_t missing = 0;
    for (const NtdllProbe& p : ntdll_probes()) {
        const occ::parser::Symbol* s = image.find_symbol(p.symbol);
        if (s == nullptr) {
            std::fprintf(stderr, "  not exported by %s: %.*s\n", path.c_str(),
                         static_cast<int>(p.symbol.size()), p.symbol.data());
            ++missing;
            continue;
        }
        // Found is not enough: the symbol has to be probeable, which means
        // defined, a function, and at a non-zero address. An undefined
        // import is in the table and has no body to probe; a data symbol
        // with the right name is not the function either.
        if (!s->probeable()) {
            std::fprintf(stderr, "  not probeable in %s: %.*s\n", path.c_str(),
                         static_cast<int>(p.symbol.size()), p.symbol.data());
            ++missing;
        }
    }
    if (missing != 0) {
        std::fprintf(stderr, "%zu of %zu symbols are not probeable in %s\n",
                     missing, ntdll_probe_count(), path.c_str());
    }
    check(missing == 0,
          "every symbol in the table is a probeable function of a real "
          "Wine ntdll");
}

void test_probeable_symbols_have_file_offsets() {
    // The step after finding the symbol is turning its address into the file
    // offset a uprobe line needs, and the two are not the same number. Every
    // entry in the table has to survive that conversion on a real ntdll, or
    // the probe would be placed at a byte nobody chose.
    const std::string path = find_real_ntdll_so();
    if (path.empty()) {
        return;
    }
    auto bytes = occ::fs::read_file_bytes(path);
    if (!bytes || bytes->empty()) {
        return;
    }
    occ::parser::ElfImage image = occ::parser::ElfImage::parse(
        occ::ByteSpan{bytes->data(), bytes->size()});
    if (!image.ok()) {
        return;
    }

    std::size_t unusable = 0;
    for (const NtdllProbe& p : ntdll_probes()) {
        const occ::parser::Symbol* s = image.find_symbol(p.symbol);
        if (s == nullptr || !s->probeable()) {
            continue; // reported by the previous test
        }
        std::uint64_t offset = 0;
        if (!image.vaddr_to_file_offset(s->value, offset)) {
            std::fprintf(stderr, "  no file offset for %.*s (vaddr %#llx)\n",
                         static_cast<int>(p.symbol.size()), p.symbol.data(),
                         static_cast<unsigned long long>(s->value));
            ++unusable;
        }
    }
    check(unusable == 0,
          "every probeable symbol converts to a file offset");
}

} // namespace

int main() {
    test_the_table_is_not_empty();
    test_no_symbol_appears_twice();
    test_every_entry_names_a_symbol_and_an_api();
    test_symbols_start_with_a_known_prefix();
    test_the_categories_cover_the_table();
    test_the_categories_a_reader_would_look_for_have_entries();
    test_category_names_are_distinct_tokens();
    test_lookup_by_symbol_finds_every_entry();
    test_lookup_by_api_finds_every_entry();
    test_lookup_of_an_unknown_name_is_null();
    test_arg_returns_the_named_arguments();
    test_sonames_are_named();
    test_every_symbol_is_in_a_real_ntdll();
    test_probeable_symbols_have_file_offsets();

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

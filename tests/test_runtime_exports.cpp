// The export registry: turning a name into an address.
//
// `LoadContext::resolve` had no implementation, so the fourth step of loading
// an image -- the imports into the IAT -- was a walk that found everything and
// resolved nothing. This file is the other half: a registry of modules and the
// rules for looking a symbol up in one.
//
// The rules are Wine's, read out of `dlls/ntdll/loader.c` rather than guessed
// at, and the four that this file pins down are the four that are decisions
// rather than details:
//
//   * a module name is matched case-insensitively, because Wine's
//     `find_basename_module` passes TRUE to `RtlEqualUnicodeString`
//   * an export's hint is tried first and *believed only after a name
//     comparison*, because a hint is the linker's guess and the sorted name
//     table is the truth
//   * an ordinal is the address-table index plus the directory's base, and a
//     base of zero is legal
//   * a forwarder is decided by the RVA landing inside the export directory,
//     and following one is a lookup in another module -- which is where a
//     cycle has to be stopped, because Wine's `find_forwarded_export`
//     recurses through `load_dll` and has no bound at all
//
// Every case below is written as the case that would pass with a constraint
// missing, and the comment says which constraint. The two that matter most are
// the ones the compiler cannot help with: an ordinal lookup that forgot the
// base still returns an address, and a forwarder cycle still returns *an*
// address -- they just return the wrong one, or none after a very long time.

#include "occ/runtime/exports.h"
#include "occ/runtime/loader.h"
#include "occ/runtime/mapper.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace occ;
using namespace occ::parser;
using namespace occ::runtime;

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

// ------------------------------------------------------- fixture builder

// One export, as a registry entry states it.
//
// Constructed only through the two factories below rather than by aggregate
// initialisation, and that is a decision the compiler asked for: with seven
// fields, a fixture writing `{"Sleep", 0x900, true, "b.dll", "X", false, 0}`
// has to get five of them in exactly the right order to mean what it says,
// and -Wmissing-field-initializers is the only thing that notices when a
// field is quietly left out. A factory names the two things a fixture means
// -- a name and an address -- and leaves the rest to say what they are.
struct Entry {
    std::string name;
    std::uint32_t rva = 0x1000;
    bool forwarder = false;
    std::string forwarder_dll;
    std::string forwarder_name;
    bool forwarder_by_ordinal = false;
    std::uint32_t forwarder_ordinal = 0;
};

// An ordinary export: a name and where it lives.
Entry an_export(std::string name, std::uint32_t rva = 0x1000) {
    Entry e;
    e.name = std::move(name);
    e.rva = rva;
    return e;
}

// An empty slot. Named because `{}` in a fixture reads as "nothing here" and
// is exactly the case: the format keeps the slot so ordinals after it do not
// move, and a fixture has to be able to say that without a comment.
//
// The rva is set rather than left alone, and that is the second thing worth
// naming. `Entry`'s default is 0x1000, so a bare `Entry{}` would produce an
// export at a real address with no name -- which is a forwarder-less ordinary
// export, not a hole. The whole point of this fixture is the rva being zero,
// and a default that quietly supplied a good one would make it a test of
// something else while reading as a test of this.
Entry an_empty_slot() {
    Entry e;
    e.rva = 0;
    return e;
}

// A forwarder entry, named rather than aggregate-initialised: a fixture that
// writes `{..., true, "b.dll", "X", false, 0}` has to get five fields in the
// right order to mean what it says, and the compiler's
// -Wmissing-field-initializers is the only thing standing between a fixture
// and a silently different one.
Entry a_forwarder(std::string name, std::string dll, std::string target,
                  bool by_ordinal = false, std::uint32_t ordinal = 0) {
    Entry e;
    e.name = std::move(name);
    e.rva = 0x900;
    e.forwarder = true;
    e.forwarder_dll = std::move(dll);
    e.forwarder_name = std::move(target);
    e.forwarder_by_ordinal = by_ordinal;
    e.forwarder_ordinal = ordinal;
    return e;
}

ExportModule a_module(std::string name, std::uint64_t base,
                      std::vector<Entry> entries,
                      std::uint32_t ordinal_base = 1) {
    ExportModule m;
    m.name = std::move(name);
    m.base = base;
    m.mapped = true;
    m.ordinal_base = ordinal_base;
    m.exports.reserve(entries.size());
    for (const Entry& e : entries) {
        PeExport x;
        x.name = e.name;
        x.ordinal = ordinal_base + static_cast<std::uint32_t>(m.exports.size());
        x.rva = e.rva;
        x.is_forwarder = e.forwarder;
        x.forwarder_dll = e.forwarder_dll;
        x.forwarder_name = e.forwarder_name;
        x.forwarder_by_ordinal = e.forwarder_by_ordinal;
        x.forwarder_ordinal = e.forwarder_ordinal;
        m.exports.push_back(std::move(x));
    }
    return m;
}

// A module with a handful of ordinary exports, which is what most fixtures
// below modify one entry of rather than build from nothing.
ExportModule a_library(std::string name, std::uint64_t base) {
    return a_module(std::move(name), base,
                    {
                        an_export("CreateFileW", 0x1100),
                        an_export("CloseHandle", 0x1200),
                        an_export("Sleep", 0x1300),
                    });
}

// ------------------------------------------------------------ name rules

// A guest imports `KERNEL32.DLL` and the host registered `kernel32.dll`. If
// this fails, every real Windows program fails, because the format's own
// example imports are spelled in both cases and Windows resolves both.
void test_a_module_name_is_matched_without_regard_to_case() {
    ExportRegistry reg;
    reg.add(a_library("kernel32.dll", 0x7F0000000000ULL));

    check(reg.find("kernel32.dll") != nullptr, "name: the exact name is found");
    check(reg.find("KERNEL32.DLL") != nullptr, "name: upper case is found");
    check(reg.find("Kernel32.Dll") != nullptr,
          "name: mixed case is found -- this is the case a case-sensitive "
          "comparison would refuse, and Windows resolves it");

    // The whole point of the rule: the name the guest asked for, resolved
    // against the name the host registered.
    const ExportLookup up = reg.find_by_name("KERNEL32.DLL", "CreateFileW", 0xFFFF);
    check(up.address == 0x7F0000000000ULL + 0x1100,
          "name: an import spelled in any case reaches the same address");

    check(reg.find("kernel32.dl") == nullptr,
          "name: a different name is still a different module -- folding case "
          "is not folding the name");
    check(reg.find("kernel32.dllx") == nullptr,
          "name: and a prefix of it is not a match either");
}

// Wine splits on `\\` in `alloc_module` because a path reaching its loader is
// always a Windows path. A registry a *host* fills in is not, and a guest that
// imports an absolute path is asking for the same module.
void test_a_path_names_the_module_behind_it() {
    check(module_basename("C:\\windows\\system32\\kernel32.dll") ==
              "kernel32.dll",
          "basename: a windows path yields the file name");
    check(module_basename("/usr/lib/x86_64-linux-gnu/kernel32.dll") ==
              "kernel32.dll",
          "basename: a unix path too, because the registry is filled in by "
          "the host and not only by the guest");
    check(module_basename("kernel32.dll") == "kernel32.dll",
          "basename: a bare name is already the name");
    check(module_basename("") == "",
          "basename: an empty name stays empty rather than becoming the whole "
          "path");
}

// An extension is not stripped. A guest importing `foo` may mean `foo.dll`,
// but that is a search of a directory and a decision about the file system,
// and a registry that guessed would resolve a name nobody asked for.
void test_the_extension_is_part_of_the_name() {
    ExportRegistry reg;
    reg.add(a_library("kernel32.dll", 0x1000));
    check(reg.find("kernel32") == nullptr,
          "basename: a bare name is not a match for one with an extension -- "
          "guessing here would resolve a name the guest never asked for");
    check(reg.find("kernel32.dll") != nullptr,
          "basename: and the spelled name is");
}

// ---------------------------------------------------------- name lookups

// The premise, stated so a failure elsewhere is attributable: a module with no
// exports answers nothing, and a registry with no modules answers nothing.
// Both are correct answers rather than crashes, and both are what `occ check`
// runs with.
void test_an_empty_registry_answers_nothing_rather_than_failing() {
    ExportRegistry reg;
    check(reg.size() == 0, "empty: a new registry has no modules");
    check(reg.find("kernel32.dll") == nullptr, "empty: and finds nothing");
    check(reg.find_by_name("kernel32.dll", "Sleep", 0xFFFF).address == 0,
          "empty: a name lookup answers zero");
    check(reg.find_by_ordinal("kernel32.dll", 1).address == 0,
          "empty: an ordinal lookup too");
    check(reg.modules().empty(), "empty: and reports no modules");
}

void test_a_name_resolves_to_base_plus_rva() {
    ExportRegistry reg;
    reg.add(a_library("kernel32.dll", 0x7F0000000000ULL));

    const ExportLookup r = reg.find_by_name("kernel32.dll", "Sleep", 0xFFFF);
    check(r.address == 0x7F0000000000ULL + 0x1300,
          "lookup: the address is the base plus the export's rva");
    check(r.export_entry != nullptr, "lookup: and the export is named");
    check(r.export_entry != nullptr && r.export_entry->name == "Sleep",
          "lookup: which is the one asked for");
    check(r.module != nullptr && r.module->name == "kernel32.dll",
          "lookup: in the module that was asked");
    check(!r.by_ordinal, "lookup: a name lookup is not an ordinal one");
    check(r.chain.size() == 1 && r.chain[0] == "kernel32.dll",
          "lookup: and the chain is the module itself");
}

// The hint is the linker's guess about which entry of the name table this
// symbol is. Trusting it without comparing the name resolves a stale hint to
// a real, wrong address -- and a wrong address is a corruption rather than a
// refusal, so nothing downstream can notice.
void test_a_hint_is_tried_and_then_verified() {
    ExportRegistry reg;
    reg.add(a_library("kernel32.dll", 0x1000));

    // The hint points at the right entry. Found by the hint, and the report
    // says so -- "found by the hint" and "found by the search" are different
    // facts about an image.
    const ExportLookup good = reg.find_by_name("kernel32.dll", "Sleep", 2);
    check(good.address == 0x1000 + 0x1300, "hint: a correct hint resolves");
    check(good.by_hint, "hint: and the report says the hint is what matched");

    // The hint points at the wrong entry. The name comparison fails, the
    // lookup falls through to the search, and the answer is right. A reader
    // that believed the hint would answer 0x1000 + 0x1100 here -- a real
    // address, holding CreateFileW, for an import of Sleep.
    const ExportLookup stale = reg.find_by_name("kernel32.dll", "Sleep", 0);
    check(stale.address == 0x1000 + 0x1300,
          "hint: a stale hint is not believed -- the name is compared, so a "
          "wrong index still resolves to the right function");
    check(!stale.by_hint,
          "hint: and the report does not claim the hint matched");

    check(reg.find_by_name("kernel32.dll", "Sleep", 0xFFFF).address ==
              0x1000 + 0x1300,
          "hint: an out-of-range hint is not an index into anything and is "
          "simply not tried");
    check(reg.find_by_name("kernel32.dll", "NoSuchFunction", 1).address == 0,
          "hint: a hint that is in range for a name that is not there answers "
          "nothing");

    // The hint *at* the end of the table -- one past the last entry, which is
    // the input an off-by-one gets wrong and which the checks above do not
    // reach. Every other hint in this file is either inside the table or far
    // outside it: 2 and 1 are in range, 0xFFFF could not be further away.
    // `hint < size` and `hint <= size` therefore agree about every input the
    // suite supplies, and the mutation harness confirmed it: widening the
    // comparison survived a suite that looked like it covered the hint.
    //
    // The fixture is a three-entry library, so the boundary hint is 3 -- the
    // first value the table cannot answer. And the answer has to be the
    // scan's, not a refusal: a guest's linker wrote an index, and an index one
    // past the end of a table it drifted from is exactly the stale hint above.
    //
    // `a_library`'s vector holds three elements and its capacity is three, so
    // the mutant reads one `PeExport` past the allocation rather than one
    // past the size within spare capacity. That is a heap overflow, and the
    // sanitizer build turns this check into a hard failure; without it the
    // read returns whatever was there and the answer is right by luck, which
    // is the worst way for a boundary check to be tested.
    check(reg.find_by_name("kernel32.dll", "Sleep", 3).address == 0x1000 + 0x1300,
          "hint: a hint one past the end of the table is not tried, and the "
          "search answers instead -- `hint < size` and `hint <= size` agree "
          "about every other input a suite is likely to try");
    check(!reg.find_by_name("kernel32.dll", "Sleep", 3).by_hint,
          "hint: and the report does not claim a hint matched at the "
          "boundary, because nothing was compared");

    // A hint pointing at a slot with *no name*. The format allows an export
    // to be reachable by ordinal alone, and such a slot is what a hint can
    // legitimately land on when the linker's table and the name table have
    // drifted. The empty-name check is what stops the hint path from matching
    // it: an unnamed entry's name compares equal to an empty string and to
    // nothing else, so the comparison alone would be right -- but a reader
    // that had *also* dropped the check would reach the same answer by a
    // different route, and the difference shows in a lookup for a name that is
    // genuinely empty rather than in any address.
    //
    // What the mutation harness actually found here is subtler, and the test
    // is written for it. Dropping `!table[hint].name.empty()` changes nothing
    // for a non-empty name, because an empty name never matches a non-empty
    // one. So the fixture has to be the case where the *lookup* is for
    // something the unnamed slot could match -- which means the check has to
    // be observed through a different route entirely: an unnamed entry must
    // not be reachable by name at all.
    ExportRegistry unnamed;
    unnamed.add(a_module("mixed.dll", 0x1000,
                        {
                            an_empty_slot(),  // index 0, no name
                            an_export("Named", 0x1200),
                        }));
    check(unnamed.find_by_name("mixed.dll", "Named", 0xFFFF).address ==
              0x1000 + 0x1200,
          "hint: a table mixing an unnamed slot with named ones still "
          "resolves the named export");
    check(unnamed.find_by_name("mixed.dll", "", 0).address == 0,
          "hint: and an unnamed slot is not reachable by name -- not by the "
          "hint that points at it, and not by the search that would compare "
          "its empty name against an empty one");
    check(unnamed.find_by_ordinal("mixed.dll", 1).address == 0,
          "hint: the unnamed slot is reachable by ordinal, which is the only "
          "way the format says it can be");

    // The case the scan's emptiness guard actually decides, and it is not the
    // one above. An unnamed slot with the RVA zero is refused twice over: the
    // scan skips it for having no name, and `walk` would refuse it for having
    // no address. Remove the scan's guard and the answer does not change,
    // which is why the first version of this file's mutation harness reported
    // that mutant surviving and it was correct to.
    //
    // An unnamed slot with a *real* RVA is the case that separates them. The
    // scan's guard refuses it for having no name; without the guard the
    // comparison matches -- "" against "" -- and the lookup answers with a
    // real address in the module for a name nobody exported. The format does
    // not produce this often, but a linker that emits an address for a slot
    // it declined to name produces it, and a reader that answered would be
    // handing a guest a function it never asked for.
    ExportRegistry nameless;
    nameless.add(a_module("odd.dll", 0x1000,
                          {
                              an_export("", 0x1400),  // address, no name
                              an_export("Real", 0x1500),
                          }));
    check(nameless.find_by_name("odd.dll", "", 0xFFFF).address == 0,
          "hint: an export with a real address but no name is not reachable "
          "by an empty name -- the slot is in the table and the address is "
          "real, and answering with it would be a function nobody exported");
    check(nameless.find_by_name("odd.dll", "", 0).address == 0,
          "hint: and the hint path agrees, so a hint pointing straight at it "
          "does not get through where the scan would not");
    check(nameless.find_by_name("odd.dll", "Real", 0xFFFF).address ==
              0x1000 + 0x1500,
          "hint: while the named export beside it still resolves -- the guard "
          "is about names, not about the table being partly unusable");
}

// A name is matched without regard to case, exactly as a module name is.
// Win32's export names are case-sensitive in the file and the loader compares
// them exactly -- this is the one place the two rules genuinely differ, and
// getting it backwards is a silent misresolution.
void test_an_export_name_is_matched_exactly() {
    ExportRegistry reg;
    reg.add(a_library("kernel32.dll", 0x1000));

    check(reg.find_by_name("kernel32.dll", "CreateFileW", 0xFFFF).address ==
              0x1000 + 0x1100,
          "case: the exact name resolves");
    check(reg.find_by_name("kernel32.dll", "createfilew", 0xFFFF).address == 0,
          "case: a different case does not -- export names are compared "
          "exactly, and a reader that folded case would resolve an import "
          "Windows refuses");
    check(reg.find_by_name("kernel32.dll", "CREATEFILEW", 0xFFFF).address == 0,
          "case: and neither does an upper-case one");
}

// -------------------------------------------------------- ordinal lookups

// The ordinal a program imports by is the address-table index plus the
// directory's base. A reader that forgot the base would resolve every ordinal
// import to a neighbouring function, and a reader that used the index raw
// would do the same for every module whose base is not 1.
void test_an_ordinal_is_the_index_plus_the_base() {
    ExportRegistry reg;
    reg.add(a_library("kernel32.dll", 0x1000));
    // Sleep is the third entry, so its index is 2 and its ordinal is 3.
    check(reg.find_by_ordinal("kernel32.dll", 3).address == 0x1000 + 0x1300,
          "ordinal: the third entry is exported as ordinal 3");
    check(reg.find_by_ordinal("kernel32.dll", 3).by_ordinal,
          "ordinal: and the report says it was found by ordinal");
    check(reg.find_by_ordinal("kernel32.dll", 1).address == 0x1000 + 0x1100,
          "ordinal: the first is ordinal 1");

    // A module whose base is not 1 is the only way to tell an addition from a
    // coincidence.
    ExportRegistry shifted;
    shifted.add(a_module("other.dll", 0x2000,
                        {an_export("One", 0x100), an_export("Two", 0x200), an_export("Three", 0x300)},
                        5));
    check(shifted.find_by_ordinal("other.dll", 5).address == 0x2000 + 0x100,
          "ordinal: with a base of 5 the first entry is ordinal 5, not 0");
    check(shifted.find_by_ordinal("other.dll", 7).address == 0x2000 + 0x300,
          "ordinal: and the third is 7");
    check(shifted.find_by_ordinal("other.dll", 4).address == 0,
          "ordinal: an ordinal below the base names nothing -- the "
          "subtraction is checked rather than wrapping into a huge index "
          "that then reads past the table");
}

// A base of zero is legal in the format. A file that states one gets it
// honored, and a reader that treated zero as "unset" would resolve every
// ordinal in such a module to the wrong function.
void test_an_ordinal_base_of_zero_is_honored() {
    ExportRegistry reg;
    reg.add(a_module("zero.dll", 0x3000,
                    {an_export("Alpha", 0x100), an_export("Beta", 0x200)}, 0));
    check(reg.find_by_ordinal("zero.dll", 0).address == 0x3000 + 0x100,
          "base: with a base of zero the first entry is ordinal 0");
    check(reg.find_by_ordinal("zero.dll", 1).address == 0x3000 + 0x200,
          "base: and the second is 1");

    // The same rule on the *forwarder* path, which is a separate copy of the
    // arithmetic and therefore a separate place for it to be wrong. The
    // mutation harness found that a check reading
    //
    //     if (target->ordinal_base == 0 || ordinal < target->ordinal_base)
    //
    // passed every test above: the fixture had a base of 10, so the added
    // clause never fired. A base of zero is legal in the format, and treating
    // it as "unset" refuses every ordinal a forwarder names in such a module.
    ExportRegistry viaForwarder;
    viaForwarder.add(a_module("a.dll", 0x1000,
                             {a_forwarder("Go", "z.dll", "", true, 0)}));
    viaForwarder.add(a_module("z.dll", 0x2000,
                              {an_export("First", 0x2100),
                               an_export("Second", 0x2200)},
                              0));
    check(viaForwarder.find_by_name("a.dll", "Go", 0xFFFF).address ==
              0x2000 + 0x2100,
          "base: a forwarder naming ordinal 0 in a module whose base is 0 "
          "resolves -- a base of zero is a value the format allows, not a "
          "sentinel meaning unset");
}

// The format keeps a slot for a symbol that was removed so the ordinals after
// it do not move. An import naming that slot is a name the guest believes in
// and the module does not provide, and answering with the RVA zero would be
// answering with an address.
void test_an_empty_slot_answers_nothing() {
    ExportRegistry reg;
    reg.add(a_module("holed.dll", 0x4000,
                    {
                        an_export("Alive", 0x100),
                        an_empty_slot(),  // the slot the file leaves empty
                        an_export("AlsoAlive", 0x300),
                    }));
    check(reg.find_by_ordinal("holed.dll", 2).address == 0,
          "hole: an empty slot resolves to nothing rather than to address 0");
    check(reg.find_by_ordinal("holed.dll", 1).address == 0x4000 + 0x100,
          "hole: and the slots after it keep their ordinals -- the table did "
          "not shift to close the gap");
    check(reg.find_by_ordinal("holed.dll", 3).address == 0x4000 + 0x300,
          "hole: both of them");
}

void test_an_ordinal_past_the_table_answers_nothing() {
    ExportRegistry reg;
    reg.add(a_library("kernel32.dll", 0x1000));
    check(reg.find_by_ordinal("kernel32.dll", 99).address == 0,
          "range: an ordinal past the address table answers nothing");
    check(reg.find_by_ordinal("kernel32.dll", 0xFFFF).address == 0,
          "range: and so does the largest a 16-bit field can hold");

    // An ordinal *below* the base, on this path rather than the forwarder's.
    // The address alone cannot catch the guard being removed here: the
    // subtraction wraps to a value near the top of the 32-bit range, and
    // `walk`'s own `index >= exports.size()` refuses it -- the same answer,
    // from a different check. The chain is what separates them, and this is
    // the same observation as the one the forwarder path makes, for the same
    // reason: a lookup refused at the ordinal recorded nothing.
    ExportRegistry below;
    below.add(a_module("shifted.dll", 0x1000,
                       {an_export("One", 0x1100), an_export("Two", 0x1200)},
                       10));
    const ExportLookup wrapped = below.find_by_ordinal("shifted.dll", 3);
    check(wrapped.address == 0,
          "range: an ordinal below the base answers nothing rather than "
          "wrapping the subtraction into an index that names a function");
    check(wrapped.chain.empty(),
          "range: and records no chain, because the refusal is at the ordinal "
          "rather than inside the table walk -- an address of zero with a "
          "chain is a walk that found nothing, and the two are different "
          "events");

    // The positive case, so the assertion above is about the refusal rather
    // than about chains never being recorded on this path either.
    const ExportLookup fine = below.find_by_ordinal("shifted.dll", 11);
    check(fine.address == 0x1000 + 0x1200,
          "range: an in-range ordinal above the base resolves");
    check(fine.chain.size() == 1,
          "range: and records the module, so an empty chain means the walk "
          "never started");
}

// ------------------------------------------------------------- forwarders

// A forwarder is not an address. The export's RVA points at a string inside
// the export directory, and the string names a symbol in a *different*
// module. Following one is a second lookup, and the address that comes back
// belongs to the module that answered.
void test_a_forwarder_resolves_through_the_module_it_names() {
    ExportRegistry reg;
    reg.add(a_module("kernel32.dll", 0x1000,
                    {
                        an_export("CreateFileW", 0x1100),
                        // kernel32 forwards this one, which is what real
                        // kernel32 does for most of its surface.
                        a_forwarder("Sleep", "ntdll.dll", "NtDelayExecution"),
                    }));
    reg.add(a_module("ntdll.dll", 0x2000, {an_export("NtDelayExecution", 0x2100)}));

    const ExportLookup r = reg.find_by_name("kernel32.dll", "Sleep", 0xFFFF);
    check(r.address == 0x2000 + 0x2100,
          "forward: the answer is the *other* module's address, because a "
          "forwarder names a symbol elsewhere");
    check(r.module != nullptr && r.module->name == "ntdll.dll",
          "forward: and the report names the module that answered, which is "
          "not the one that was asked");
    check(r.chain.size() == 2 && r.chain[0] == "kernel32.dll" &&
              r.chain[1] == "ntdll.dll",
          "forward: the chain records the hop, which is the only place a "
          "report can show that kernel32!Sleep is not in kernel32");
}

// `KERNEL32.#27` is the other form: the forwarder names an ordinal rather than
// a name, and the ordinal goes through the same base arithmetic.
void test_a_forwarder_by_ordinal() {
    ExportRegistry reg;
    reg.add(a_module("kernel32.dll", 0x1000,
                    {a_forwarder("Sleep", "ntdll.dll", "", true, 12)}));
    reg.add(a_module("ntdll.dll", 0x2000,
                    {
                        an_export("First", 0x2100),
                        an_export("Second", 0x2200),
                        an_export("Third", 0x2300),
                    },
                    10));

    // Ordinal 12 with a base of 10 is index 2, which is the *third* entry.
    // Getting this wrong is the whole hazard of the arithmetic: 12 - 10 = 2
    // is an index, and an index of 2 in a three-entry table is the last one,
    // not the second. A reader that treated the ordinal as the index directly
    // would land on Second, and a reader that forgot the base entirely would
    // refuse an ordinal the module exports.
    check(reg.find_by_name("kernel32.dll", "Sleep", 0xFFFF).address ==
              0x2000 + 0x2300,
          "forward: an ordinal of 12 with a base of 10 is index 2, which is "
          "the third entry -- the subtraction gives an index, not a position "
          "among the named ones");

    // The two ways the arithmetic can be wrong, and they are wrong in
    // opposite directions. An ordinal below the base is not an index that
    // wrapped -- it is an ordinal the module does not export. An ordinal past
    // the end is not an ordinal the module exports either, and neither answer
    // may be a neighbouring function.
    ExportRegistry edges;
    edges.add(a_module("a.dll", 0x1000,
                      {a_forwarder("Low", "b.dll", "", true, 5),
                       a_forwarder("High", "b.dll", "", true, 99)}));
    edges.add(a_module("b.dll", 0x2000,
                       {an_export("Only", 0x2100), an_export("And", 0x2200)},
                       10));
    check(edges.find_by_name("a.dll", "Low", 0xFFFF).address == 0,
          "forward: an ordinal below the target's base answers nothing rather "
          "than wrapping into an index that names a function");
    check(edges.find_by_name("a.dll", "High", 0xFFFF).address == 0,
          "forward: and so does one past the end of its address table");

    // The address alone cannot tell a *checked* refusal from a bypassed check
    // that something downstream happened to catch. Removing
    // `if (forwarder_ordinal < ordinal_base) return` makes the subtraction
    // wrap to a huge index, and `walk`'s own `index >= exports.size()` stops
    // it -- the same answer, from a check that is not the one under test. The
    // chain is what separates them: a lookup that is refused at the ordinal
    // has recorded nothing, and one that walks into the target and is
    // refused there has recorded both modules on the way.
    //
    // This survived the first run of this file's mutation harness, which is
    // why the assertion is about the chain rather than the address. A test
    // that only checks the answer cannot tell a guard from a coincidence.
    const ExportLookup low = edges.find_by_name("a.dll", "Low", 0xFFFF);
    check(low.chain.empty(),
          "forward: a lookup refused at the ordinal records no chain at all, "
          "because nothing was walked -- a refused subtraction is not the "
          "same event as a walk that found nothing");

    // And the positive case, so the assertion above is about the refusal
    // rather than about chains never being recorded.
    ExportRegistry ok;
    ok.add(a_module("a.dll", 0x1000, {a_forwarder("Go", "b.dll", "", true, 11)}));
    ok.add(a_module("b.dll", 0x2000,
                    {an_export("First", 0x2100), an_export("Second", 0x2200)},
                    10));
    const ExportLookup good = ok.find_by_name("a.dll", "Go", 0xFFFF);
    check(good.address == 0x2000 + 0x2200,
          "forward: an in-range ordinal resolves");
    check(good.chain.size() == 2,
          "forward: and records both modules, so an empty chain means the "
          "walk refused rather than that chains are never kept");
}

// Two real images deep: kernel32 forwards to ntdll, ntdll forwards to
// itself on the Unix side. A walk that only followed one hop would answer
// nothing for the real shape.
void test_a_chain_two_forwarders_deep_resolves() {
    ExportRegistry reg;
    reg.add(a_module("a.dll", 0x1000,
                    {a_forwarder("Go", "b.dll", "Onward")}));
    reg.add(a_module("b.dll", 0x2000,
                    {a_forwarder("Onward", "c.dll", "Final")}));
    reg.add(a_module("c.dll", 0x3000, {an_export("Final", 0x3100)}));

    const ExportLookup r = reg.find_by_name("a.dll", "Go", 0xFFFF);
    check(r.address == 0x3000 + 0x3100,
          "chain: a two-hop chain reaches the module at the end");
    check(r.chain.size() == 3, "chain: and the chain has all three modules in "
                                "order, so a report can show the path");
}

// Wine's `find_forwarded_export` recurses through `load_dll` with no depth
// bound, so two modules forwarding to each other is a load that does not
// terminate. This is the case that has to be stopped, and stopping it is the
// difference between a refusal and a hang.
void test_a_forwarder_cycle_terminates() {
    ExportRegistry reg;
    reg.add(a_module("a.dll", 0x1000, {a_forwarder("Go", "b.dll", "Back")}));
    reg.add(a_module("b.dll", 0x2000, {a_forwarder("Back", "a.dll", "Go")}));

    const ExportLookup r = reg.find_by_name("a.dll", "Go", 0xFFFF);
    check(r.address == 0,
          "cycle: a forwarder that comes back to where it started resolves "
          "to nothing rather than recursing until the stack runs out");
}

// The same bound, reached without a cycle: a chain longer than the bound is
// stopped for the same reason and reported the same way. A real chain is one
// or two deep, so the bound is generous, and a fixture that needed to reach
// it is a fixture describing something no linker produces.
void test_a_chain_deeper_than_the_bound_terminates() {
    ExportRegistry reg;
    // Six modules, each forwarding to the next, which is past the bound of
    // four.
    for (int i = 0; i < 6; ++i) {
        const std::string name = "m" + std::to_string(i) + ".dll";
        const std::string next = "m" + std::to_string(i + 1) + ".dll";
        reg.add(a_module(name, 0x1000 * static_cast<std::uint64_t>(i + 1),
                        {a_forwarder("Go", next, "Go")}));
    }
    reg.add(a_module("m6.dll", 0x7000, {an_export("Go", 0x7100)}));

    const ExportLookup r = reg.find_by_name("m0.dll", "Go", 0xFFFF);
    check(r.address == 0,
          "depth: a chain past the bound resolves to nothing instead of "
          "walking forever");
    check(ExportRegistry::kMaxForwarderDepth == 4,
          "depth: and the bound is four, which is more than any real chain "
          "needs and stated rather than implied");

    // The bound's *edge*, which the test above does not reach. A chain of
    // exactly the bound's length has to resolve, and one longer has to stop;
    // a suite that only builds the long one cannot tell a bound of four from
    // a bound of five or fifty, and the mutation harness found exactly that:
    // widening the bound by one survived, because the fixture was already
    // past both numbers.
    //
    // Built one chain per length rather than one chain and a counter, so a
    // failure names the length that broke rather than a boolean.
    for (std::size_t hops = 0; hops <= ExportRegistry::kMaxForwarderDepth + 2;
         ++hops) {
        ExportRegistry chain;
        for (std::size_t i = 0; i < hops; ++i) {
            const std::string name = "h" + std::to_string(i) + ".dll";
            const std::string next = "h" + std::to_string(i + 1) + ".dll";
            chain.add(a_module(name, 0x1000 * static_cast<std::uint64_t>(i + 1),
                               {a_forwarder("Go", next, "Go")}));
        }
        chain.add(a_module("h" + std::to_string(hops) + ".dll",
                           0x1000 * static_cast<std::uint64_t>(hops + 1),
                           {an_export("Go", 0x7100)}));

        const ExportLookup hop = chain.find_by_name("h0.dll", "Go", 0xFFFF);
        if (hops <= ExportRegistry::kMaxForwarderDepth) {
            check(hop.address == 0x7100 + 0x1000 *
                                      static_cast<std::uint64_t>(hops + 1),
                  "depth: a chain of exactly the bound's length resolves");
        } else {
            check(hop.address == 0,
                  "depth: and one hop past the bound does not, so the bound "
                  "is where it says it is rather than somewhere beyond it");
        }
    }
}

// A forwarder naming a module nobody has, and one naming a symbol a module
// does not have, are different failures and a report that cannot tell them
// apart is a report that sends a reader to the wrong place.
void test_an_unresolved_forwarder_answers_nothing() {
    ExportRegistry reg;
    reg.add(a_module("a.dll", 0x1000,
                    {a_forwarder("Missing", "nowhere.dll", "X")}));
    check(reg.find_by_name("a.dll", "Missing", 0xFFFF).address == 0,
          "forward: a forwarder to a module that is not registered answers "
          "nothing");

    // The fixture above does not catch a fallback, and that is worth knowing
    // rather than assuming. If a reader that could not find `nowhere.dll`
    // answered out of `a.dll`'s own table instead, the name it would look for
    // is "X" -- and a.dll does not export "X" either, so the fallback finds
    // nothing and the answer is right for the wrong reason. The mutation
    // harness caught exactly this: the fallback mutant survived a suite whose
    // fixture made it harmless.
    //
    // The fixture that does catch it is the one where the forwarding module
    // *does* export the name the forwarder names. Then a fallback answers with
    // a real address in the wrong module, which is the corruption rather than
    // the coincidence.
    ExportRegistry shadow;
    shadow.add(a_module("a.dll", 0x1000,
                       {
                           a_forwarder("Go", "nowhere.dll", "X"),
                           an_export("X", 0x1500),
                       }));
    check(shadow.find_by_name("a.dll", "Go", 0xFFFF).address == 0,
          "forward: and it is not answered out of the forwarding module's own "
          "table even when that table has a symbol of the same name -- "
          "answering there would be a real address in the wrong module, and a "
          "guest importing Go would call a function it never asked for");

    ExportRegistry reg2;
    reg2.add(a_module("a.dll", 0x1000,
                     {a_forwarder("Wrong", "b.dll", "NotThere")}));
    reg2.add(a_module("b.dll", 0x2000, {an_export("Something", 0x2100)}));
    check(reg2.find_by_name("a.dll", "Wrong", 0xFFFF).address == 0,
          "forward: and so does one naming a symbol the target does not have");

    // A forwarder to a module that *is* registered, where the symbol is
    // missing, must not fall back to the forwarding module's own table. That
    // fallback would resolve a name to whatever happened to be at that index,
    // which is a real function the guest did not ask for.
    check(reg2.find_by_name("b.dll", "NotThere", 0xFFFF).address == 0,
          "forward: a missing symbol in the target is not answered out of the "
          "forwarding module");
}

// ---------------------------------------------------------- mapped state

// A module whose export table is known but which is not placed has no
// addresses. Handing back an RVA as though it were one is the confusion the
// TLS layer refuses to create, and this is the same refusal: a caller that
// stored base-zero would jump to the start of the address space.
void test_an_unplaced_module_resolves_to_nothing() {
    ExportRegistry reg;
    ExportModule m = a_library("kernel32.dll", 0);
    m.mapped = false;
    reg.add(std::move(m));

    check(reg.find("kernel32.dll") != nullptr,
          "mapped: the module is registered and findable");
    check(reg.find_by_name("kernel32.dll", "Sleep", 0xFFFF).address == 0,
          "mapped: but a lookup answers nothing, because the addresses are "
          "not real yet and an rva is not an address");
    check(reg.find_by_ordinal("kernel32.dll", 3).address == 0,
          "mapped: by ordinal too");
}

// ------------------------------------------------------ registry lifetime

// The lifetime is the caller's. There is no file-scope registry in this
// project, and the reason is the one the TLS layer already established:
// Wine's global `tls_dirs` is shared by every process in the address space,
// and a module that is shared across address spaces belongs to neither. Two
// registries in one process hold two answers, which is what makes a test
// deterministic.
void test_two_registries_do_not_share_anything() {
    ExportRegistry a;
    ExportRegistry b;
    a.add(a_library("only-in-a.dll", 0x1000));

    check(a.size() == 1, "lifetime: the first registry has its module");
    check(b.size() == 0, "lifetime: the second has none");
    check(b.find("only-in-a.dll") == nullptr,
          "lifetime: and does not answer for it");
    check(b.find_by_name("only-in-a.dll", "Sleep", 0xFFFF).address == 0,
          "lifetime: a lookup against the wrong registry answers nothing "
          "rather than the right address from the right one");
}

// Registering a name twice replaces the entry, and which entry answers must
// not depend on registration order. The case that matters is a module
// registered once per image during a load: a forwarder that names a module
// the image also imports directly reaches the registry twice.
void test_registering_a_name_twice_answers_with_the_later_one() {
    ExportRegistry reg;
    reg.add(a_module("kernel32.dll", 0x1000, {an_export("Sleep", 0x1100)}));
    reg.add(a_module("kernel32.dll", 0x9000, {an_export("Sleep", 0x9100)}));

    check(reg.size() == 1, "replace: the registry holds one module, not two");
    check(reg.find_by_name("kernel32.dll", "Sleep", 0xFFFF).address ==
              0x9000 + 0x9100,
          "replace: and the later registration is the one that answers, so "
          "the answer does not depend on the order the walk used");
}

// `add` takes the name apart the same way `find` does, so a module
// registered under a path is findable by its base name.
void test_a_module_registered_under_a_path_is_found_by_its_name() {
    ExportRegistry reg;
    reg.add(a_library("C:\\windows\\system32\\kernel32.dll", 0x1000));

    check(reg.find("kernel32.dll") != nullptr,
          "register: a path is stored as the file name");
    check(reg.find("C:\\windows\\system32\\kernel32.dll") != nullptr,
          "register: and the whole path still finds it, because both spellings "
          "end at the same comparison");
    check(reg.find_by_name("KERNEL32.DLL", "Sleep", 0xFFFF).address ==
              0x1000 + 0x1300,
          "register: and an import resolves through it");
}

void test_modules_lists_what_was_registered() {
    ExportRegistry reg;
    reg.add(a_library("one.dll", 0x1000));
    reg.add(a_library("two.dll", 0x2000));

    const std::vector<const ExportModule*> all = reg.modules();
    check(all.size() == 2, "list: both modules are listed");
    check(all.size() == 2 && all[0]->name == "one.dll" &&
              all[1]->name == "two.dll",
          "list: in registration order, so a report is diffable between runs");

    // The pointers are into the registry's own storage. Holding one across an
    // `add` would dangle, which is why `modules()` hands out pointers rather
    // than a promise -- and why a caller iterates it rather than keeping it.
    check(all[0]->base == 0x1000, "list: and each is the module itself");
}

// -------------------------------------------------- the loader's contract

// The function the loader actually calls. It returns the address and nothing
// else, because the loader reports the rest itself -- and it is a static
// function, so the state pointer is the registry and a null state is a wiring
// mistake that has to be answered rather than dereferenced.
void test_the_resolve_entry_point_matches_the_loaders_signature() {
    ExportRegistry reg;
    reg.add(a_library("kernel32.dll", 0x1000));

    ExportRegistry* self = &reg;
    check(reg.resolve(self, "kernel32.dll", "Sleep", 0, false) == 0x1000 + 0x1300,
          "resolve: a name resolves through the entry point");
    check(reg.resolve(self, "kernel32.dll", "", 3, true) == 0x1000 + 0x1300,
          "resolve: and so does an ordinal, with by_ordinal saying which");

    check(reg.resolve(self, "other.dll", "Sleep", 0, false) == 0,
          "resolve: a module that is not registered answers nothing");
    check(reg.resolve(nullptr, "kernel32.dll", "Sleep", 0, false) == 0,
          "resolve: a null state answers nothing rather than crashing -- a "
          "load with unresolved imports is a report, a crash is not");

    // The hint is dropped at this boundary, and that is stated in the header
    // rather than hidden: the signature does not carry it, and the scan finds
    // the same export. What matters is that dropping it changes the speed and
    // not the answer.
    check(reg.resolve(self, "kernel32.dll", "Sleep", 0, false) ==
              reg.find_by_name("kernel32.dll", "Sleep", 0xFFFF).address,
          "resolve: the answer is the same one the hinted lookup gives, so "
          "the missing hint costs a scan and not a resolution");
}

// ------------------------------------------------- an image with an import
//
// The tests above all build a registry and call it directly, which is the
// right way to test the rules and the wrong way to test the wiring: nothing
// above loads an image, so nothing above proves the loader calls a registry
// at all. That is a gap with a name, and the fix is a real PE with a real
// import table loaded through the real `load_image`.
//
// The bytes are assembled rather than checked in, because a checked-in
// fixture is a binary nobody can review and a mutation harness cannot
// perturb. This one is forty lines of `put32`/`put64`, and every field the
// loader reads is a field a reader can see being set.

constexpr std::size_t kDosSize = 64;
constexpr std::size_t kCoffSize = 20;

// Where the fixture's tables sit, and how much room they need.
//
// The tail is long enough for every table below and not one byte more: the
// import descriptors are at 0x100 and the relocation block at 0x1C0 with a
// four-byte terminator after it. A tail sized to a round number that happens
// to be one field too small is the shape of mistake a sanitizer build exists
// to catch, and this one did -- an instrumented run reported a write past the
// end of a 512-byte buffer that an ordinary run executed without complaint.
constexpr std::size_t kTailBytes = 0x200;

void put16(std::vector<std::uint8_t>& b, std::size_t off, std::uint16_t v) {
    for (int i = 0; i < 2; ++i) {
        b[off + static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>((v >> (8 * i)) & 0xff);
    }
}

void put32(std::vector<std::uint8_t>& b, std::size_t off, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        b[off + static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>((v >> (8 * i)) & 0xff);
    }
}

void put64(std::vector<std::uint8_t>& b, std::size_t off, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        b[off + static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>((v >> (8 * i)) & 0xff);
    }
}

// Read a 64-bit little-endian value out of a mapped image.
//
// The loader's writes land in real memory at the module's base -- the
// `AddressSpace` is the ledger of what is mapped, not the memory itself -- so
// reading the IAT means reading the process's address space directly. That is
// deliberate and it is the point: `LoadResult::imports[i].target_va` is the
// loader's *account* of what it wrote, and this is where a program would jump.
// A loader that recorded the right address and stored the wrong one satisfies
// every assertion that reads the record.
std::uint64_t read_u64_at(std::uint64_t va) {
    std::uint64_t v = 0;
    std::memcpy(&v, reinterpret_cast<const void*>(va), sizeof(v));
    return v;
}

// A base nothing is mapped at, for a fixture that will place an image at one.
//
// Asked of the kernel rather than written down, because a written-down base is
// a claim about what else the process has mapped, and the claim is false in
// both builds this file has to pass in. `0x140000000` -- an ordinary image
// base, and the one this fixture's header names -- is inside the sanitizer
// build's own mappings: a probe under AddressSanitizer found the whole four
// megabytes from 0x140000000 to 0x141000000 already taken, which is more than
// the retry policy can step past. Sixty-four attempts times a sixty-four
// kilobyte step is four megabytes of downward scan, and the whole window was
// occupied, so the search reported "the image was still in the way after 64
// bases" about an address range that was never going to open up.
//
// So the base is mapped with a zero base, which asks the kernel to pick, and
// mapped back out again -- and the release is checked, because a probe that
// cannot give back what it took has not found a free range, it has moved one.
std::uint64_t a_free_base(std::uint64_t bytes) noexcept {
    AddressSpace probe_space;
    Mapper probe(probe_space);
    const Result<std::uint64_t> r =
        probe.map(0, bytes, PageProtection::NoAccess, RegionKind::Private);
    if (!r.ok()) {
        return 0;
    }
    const Result<std::uint64_t> released = probe.unmap(r.value);
    return released.ok() ? r.value : 0;
}

// A PE32+ image with one section and one import descriptor naming
// `kernel32.dll!CreateFileW` by name and `kernel32.dll!Sleep` by ordinal.
//
// Two imports rather than one because the two forms take different paths
// through the resolver, and a wiring test that only walked the named one
// would pass with the ordinal flag wired to nothing.
//
// The ordinal is 0x37 = 55 with a base of 1, so it names index 54 -- past the
// end of any table in this file -- and therefore answers nothing. That is
// deliberate: an image whose ordinal import resolves is an image whose IAT
// slot has to be checked for a *non*-answer, and "nothing is written" is the
// property worth pinning down at this level. The named import resolves, so
// the two slots in the IAT end up in different states and one assertion can
// tell them apart.
struct ImageFixture {
    std::vector<std::uint8_t> bytes;
    std::uint32_t iat_rva = 0;
};

ImageFixture an_image_importing_two_symbols(
    std::uint64_t image_base = 0x140000000) {
    // The import table lives inside the section, at file offset 0x400, which
    // is RVA 0x1200: the section starts at file offset 0x200 and RVA 0x1000,
    // so the two coordinate systems differ by exactly 0x200 and an RVA only
    // resolves because it lands inside a section.
    constexpr std::size_t kTailAt = 0x400;
    // The section's raw extent has to reach the end of the tail, because the
    // parser checks the section's file extent against the file's length and
    // the loader resolves the import directory's RVA through this section.
    constexpr std::size_t kSectionFileStart = 0x200;
    // The section's raw bytes run from the end of the headers to the end of
    // the tail, so every RVA the import directory names resolves to bytes that
    // are actually in the file. A section that stopped short of its own import
    // table is a shape no linker produces, and the parser is right to refuse it
    // -- the fixture has to be built, not merely plausible.
    constexpr std::size_t f_tail_extent = kTailAt + kTailBytes - kSectionFileStart;
    const std::size_t tail_at = kTailAt;
    std::vector<std::uint8_t> tail(kTailBytes, 0);

    const std::uint32_t dll_at = 0x40;
    const std::uint32_t hint_name_at = 0x60;   // IMAGE_IMPORT_BY_NAME
    const std::uint32_t thunk_at = 0x80;
    const std::uint32_t iat_at = 0xC0;
    const std::uint32_t desc_at = 0x100;

    std::memcpy(&tail[dll_at], "kernel32.dll", 13);
    // Hint 0 then the name, which is what an import-by-name thunk points at.
    tail[hint_name_at + 0] = 0;
    tail[hint_name_at + 1] = 0;
    std::memcpy(&tail[hint_name_at + 2], "CreateFileW", 12);

    // Every field below is an RVA, not a file offset, and the difference is
    // the whole reason this fixture was hard to get right: the two coordinate
    // systems are 0xE00 apart here, and an import table written in file
    // offsets is a table of addresses that resolve to nothing. The parser
    // resolves every one of these through the section table, so a field in
    // the wrong system produces a load that succeeds and finds no imports --
    // the most misleading way for a fixture to be wrong, and the reason the
    // conversion is a named constant rather than arithmetic sprinkled over
    // eight lines.
    constexpr std::uint32_t kFileToRva = 0x1000 - 0x200;
    const auto rva = [&](std::size_t file_off) {
        return static_cast<std::uint32_t>(file_off + kFileToRva);
    };

    const std::uint32_t thunk_base = rva(tail_at + thunk_at);
    const std::uint32_t iat_base = rva(tail_at + iat_at);

    // Thunk 0: by name. Thunk 1: ordinal 0x37, which is high-bit-set. Thunk
    // 2: the terminator.
    put64(tail, thunk_at + 0, rva(tail_at + hint_name_at));
    put64(tail, thunk_at + 8, 0x8000000000000037ull);
    put64(tail, thunk_at + 16, 0);
    // The IAT starts out holding the same values a loader reads thunks from,
    // which is what makes an unrelocated import table self-consistent.
    put64(tail, iat_at + 0, rva(tail_at + hint_name_at));
    put64(tail, iat_at + 8, 0x8000000000000037ull);
    put64(tail, iat_at + 16, 0);

    put32(tail, desc_at + 0, thunk_base);        // OriginalFirstThunk
    put32(tail, desc_at + 4, 0);                 // TimeDateStamp
    put32(tail, desc_at + 8, 0);                 // ForwarderChain
    put32(tail, desc_at + 12, rva(tail_at + dll_at));
    put32(tail, desc_at + 16, iat_base);         // FirstThunk

    // The headers, sized so the section table lands where the loader expects.
    // As long as the section claims, plus whatever the tail adds: the file
    // has to be at least `0x200 + SizeOfRawData` or the parser refuses before
    // it reads a single import.
    std::vector<std::uint8_t> b(kSectionFileStart + f_tail_extent, 0);
    const std::size_t coff = kDosSize + 4;
    const std::size_t opt = coff + 4 + kCoffSize;
    const std::size_t dirs = opt + 112;
    const std::size_t sec = opt + 240;

    // "MZ", and the offset of the PE header from the start of the file. A
    // reader that cannot find the PE header refuses the file before it looks
    // at anything else, so a fixture that forgets this fails for a reason
    // that has nothing to do with what it is testing.
    put16(b, 0, 0x5a4d);
    put32(b, 0x3c, static_cast<std::uint32_t>(coff));

    put32(b, coff, 0x00004550);                  // "PE\0\0"
    const std::size_t c = coff + 4;              // the COFF header proper
    put16(b, c + 0, 0x8664);                     // machine: x86-64
    put16(b, c + 2, 1);                          // one section
    put16(b, c + 16, 240);                       // SizeOfOptionalHeader
    put16(b, c + 18, 0x0002);                    // executable, not a DLL
    put16(b, sec + 0, 0);                        // no name
    b[sec + 0] = '.';
    b[sec + 1] = 't';
    b[sec + 2] = 'e';
    b[sec + 3] = 'x';
    b[sec + 4] = 't';
    // The section's raw data starts after the headers rather than at the DOS
    // header, because `SizeOfHeaders` is 0x200 and a section whose raw data
    // began inside the headers would overlap them. The loader checks the
    // section's file extent against the file's length, so a fixture that got
    // this wrong is refused for a reason that has nothing to do with imports.
    constexpr std::size_t kHeadersSize = 0x200;
    // The import table has to be inside the section, because that is the only
    // way an RVA resolves: the parser maps an RVA through the section table,
    // and an RVA past the last section is not an address. So the section
    // covers the whole file from the headers onward and the import table
    // lives inside it -- which is also where a real linker puts it.
    put32(b, sec + 8, 0x2000);                   // VirtualSize
    put32(b, sec + 12, 0x1000);                  // VirtualAddress
    put32(b, sec + 16, static_cast<std::uint32_t>(f_tail_extent)); // SizeOfRawData
    put32(b, sec + 20, static_cast<std::uint32_t>(kHeadersSize)); // PointerToRawData
    put32(b, sec + 36, 0x60000020);              // code, execute, read

    // The optional header's own fields, at the offsets PE32+ puts them --
    // `ImageBase` is eight bytes wide here and `SizeOfHeaders` is at 60, not
    // at 24. A fixture that used the PE32 offsets would write a 64-bit base
    // across the fields below it and the loader would read a header that
    // describes an image nobody built.
    put16(b, opt + 0, 0x20b);                    // PE32+ magic
    // Inside .text, because the loader refuses an entry point that is not in
    // an executable section -- a check this fixture has to satisfy to reach
    // the imports at all, and which is worth naming because a fixture that
    // set it to zero would be refused for a reason unrelated to imports.
    put32(b, opt + 16, 0x1000);                  // AddressOfEntryPoint
    put32(b, opt + 20, 0x1000);                  // BaseOfCode
    put64(b, opt + 24, image_base);              // ImageBase
    put32(b, opt + 32, 0x200000);                // SectionAlignment
    put32(b, opt + 36, 0x200);                   // FileAlignment
    put32(b, opt + 56, 0x10000);                 // SizeOfImage
    put32(b, opt + 60, static_cast<std::uint32_t>(kHeadersSize));
    // The directory count, before the array it counts. Without it the parser
    // computes zero usable directories -- correctly, because a header that
    // does not say how many directories it has has not said where they are --
    // and the import table below is bytes in a file rather than a directory.
    // This is the one field whose absence produces a load that succeeds and
    // finds no imports, which is the most misleading way for a fixture to be
    // wrong.
    put32(b, dirs - 4, 16);                      // NumberOfRvaAndSizes
    // The import directory is directory 1: an RVA and a size. The RVA is a
    // *virtual* address, so it is the file offset plus the section's delta.
    put32(b, dirs + 1 * 8, rva(tail_at + desc_at));
    put32(b, dirs + 1 * 8 + 4, 40);

    // A relocation table, and the reason this fixture needs one is worth
    // stating because the alternative is a test that only runs on a host with
    // a free address space. An image whose header names a base and has no
    // relocations can only be placed at that base and nowhere else, so a
    // plain `load_image` at a fixed address fails under a sanitizer -- whose
    // shadow mapping already occupies the address -- with a conflict that has
    // nothing to do with imports. With relocations the image can go wherever
    // it fits, which is what a real image does and what lets this case be
    // about the IAT rather than about who owns which page.
    //
    // One block, one entry, for the image base itself: HIGHLOW at offset 0,
    // which says "add the load delta to the eight bytes at RVA 0". There is
    // nothing meaningful there, and the loader writes the load delta into it,
    // which is harmless -- the point is that the *table* exists, so the image
    // is relocatable and the mapper has somewhere to put it.
    // Relative to the *tail's* start, not to the file. Every other offset in
    // this fixture is named the same way -- `dll_at`, `thunk_at`, `iat_at`,
    // `desc_at` are all tail-relative -- and one that was not is a write past
    // the end of a buffer that looked fine in an ordinary run. The address
    // sanitizer reported it as one; a reader has to take the comment's word
    // for it.
    constexpr std::size_t reloc_at = 0x1C0;
    put32(tail, reloc_at + 0, 0x1000);            // block RVA: page of 0
    constexpr std::size_t kRelocBlockSize = 10;   // 8 header + 1 two-byte entry
    static_assert(kRelocBlockSize == 8 + 2);
    put32(tail, reloc_at + 4, static_cast<std::uint32_t>(kRelocBlockSize));
    put16(tail, reloc_at + 8, 3);                 // IMAGE_REL_BASED_HIGHLOW
    put16(tail, reloc_at + 10, 0);                // offset 0 within the page
    // There is no terminator block, and the format is right to have one: a
    // real base-relocation table ends with an eight-byte block whose page RVA
    // is zero, so a reader that walks past the last entry finds the end. This
    // fixture omits it because the loader does not walk that far. It stops on
    // `cursor + 8 <= reloc_end`, and the directory below declares the table to
    // be exactly one block long, so the loop ends the moment that block is
    // consumed.
    //
    // That is worth stating rather than leaving as a coincidence, because the
    // terminator is the version of this fixture that looks more correct and
    // fails. Written at `block_size` bytes past the header it is inside the
    // declared table, so the cursor reaches it, reads a header whose size
    // field is zero, and refuses the whole image as malformed --
    // LoadError::BadRelocation, with no detail string to explain it. Making
    // the table one block long is not a workaround for a parser bug; it is
    // the only encoding of "this table ends here" that the loader reads.
    put32(b, dirs + 5 * 8, rva(tail_at + reloc_at));
    put32(b, dirs + 5 * 8 + 4, static_cast<std::uint32_t>(kRelocBlockSize));

    std::memcpy(&b[tail_at], tail.data(), tail.size());

    ImageFixture f;
    f.bytes = std::move(b);
    f.iat_rva = rva(tail_at + iat_at);
    return f;
}

// The end-to-end claim: an image is loaded, its import table is walked, the
// registry is asked, and the answer lands in the IAT *in memory*.
//
// The IAT is read back out of the address space rather than out of the
// `LoadResult`, because `LoadResult::imports[i].target_va` is the loader's
// account of what it wrote and the address space is where a program would
// actually jump. A loader that recorded the right address and wrote the wrong
// one -- a store to the wrong slot, or a store before the protection change
// -- satisfies every other test in this file.
void test_a_real_image_resolves_its_imports_through_the_registry() {
    // The image's own base. It has to be named rather than scanned for,
    // because an image with no relocation table can only be placed where it
    // says it belongs -- which is a fact about this fixture that a reader
    // would otherwise have to discover from a refusal.
    constexpr std::uint64_t kImageBase = 0x140000000;
    const ImageFixture f = an_image_importing_two_symbols(kImageBase);
    const PeImage image =
        PeImage::parse(ByteSpan{f.bytes.data(), f.bytes.size()});

    // kernel32 is *placed* at a base of its own, which is what makes the
    // registry's answer an address rather than an RVA. Without `mapped` the
    // registry refuses every export, and this test would pass for the wrong
    // reason if it did not notice.
    const std::uint64_t k32 = 0x7F0000000000ULL;
    ExportRegistry reg;
    reg.add(a_library("kernel32.dll", k32));

    LoadContext ctx;
    ctx.resolver_state = &reg;
    ctx.resolve = &ExportRegistry::resolve_thunk;

    // A `Mapper`, because without one `load_image` maps nothing at all: it
    // makes every decision and writes no bytes. Reading the IAT back is
    // therefore only possible with a placement, and a test that read it
    // without one would be reading whatever happened to be at the address --
    // which is how the first version of this test crashed.
    AddressSpace sp;
    Mapper m(sp);
    ctx.placement = &m;
    // The retrying load, with a base the kernel picked rather than one this
    // file wrote down. Both halves of that are load-bearing. The retrying
    // load is what treats a conflicting base as a base to try somewhere else,
    // which is what it is for; and the base comes from `a_free_base` because
    // a written-down one is inside the sanitizer build's own mappings and the
    // retry policy's downward scan does not reach past it -- see
    // `a_free_base` for what the probe found there.
    //
    // The image is placed somewhere other than the base its own header names,
    // which is deliberate. `kImageBase` here is 0x140000000 and the placed
    // base is whatever the process had free, so the load delta is nonzero and
    // the single HIGHLOW relocation in the fixture is applied rather than
    // skipped. A fixture that happened to be placed at its own base would
    // pass with the relocation path never entered.
    const std::uint64_t free_base = a_free_base(0x10000);
    if (free_base == 0) {
        std::fprintf(stderr, "SKIP e2e: no free base to place the image at\n");
        return;
    }
    const auto r = load_image_retrying(image,
                                       ByteSpan{f.bytes.data(), f.bytes.size()},
                                       free_base, sp, ctx);
    check(r.ok, "e2e: an image with an import table loads");
    check(r.module.imports.size() == 2,
          "e2e: and its two imports are walked");

    if (r.ok && r.module.imports.size() == 2) {
        // The named import resolved, and to the registry's answer: kernel32's
        // base plus CreateFileW's RVA.
        check(r.module.imports[0].resolved,
              "e2e: the named import is resolved");
        check(r.module.imports[0].name == "CreateFileW",
              "e2e: and it is the name the import table spelled");
        check(r.module.imports[0].target_va == k32 + 0x1100,
              "e2e: the answer is kernel32's base plus the export's RVA, "
              "which is the one thing a resolver wired to nothing could not "
              "produce");

        // The ordinal import names 55 with a base of 1, so it is index 54 and
        // no such slot exists. It stays unresolved, and *nothing is written*:
        // a loader that answered an unresolvable ordinal with the module
        // base would hand a program an address at the image's headers.
        check(!r.module.imports[1].resolved,
              "e2e: an ordinal past the end of the export table does not "
              "resolve");
        check(r.module.imports[1].by_ordinal,
              "e2e: and the record still says it was an ordinal, because "
              "refusing is not the same as misreading");
        check(r.module.imports[1].target_va == 0,
              "e2e: an unresolved import carries no address at all");
    }

    if (r.ok) {
        // Read the IAT back out of memory. This is the assertion the whole
        // file exists for.
        // The slot address comes from the loader's own record rather than
        // from arithmetic here. Recomputing it would mean the test could
        // agree with the loader about the wrong address, which is the one
        // thing this assertion exists to rule out.
        const std::uint64_t named_slot = r.module.imports[0].iat_va;
        const std::uint64_t ordinal_slot = r.module.imports[1].iat_va;
        check(named_slot != 0 && ordinal_slot == named_slot + 8,
              "e2e: the loader reports where each IAT slot is, and the two "
              "are eight bytes apart -- the stride of the thunk table, which "
              "is what makes the second slot the ordinal one");
        check(read_u64_at(named_slot) == k32 + 0x1100,
              "e2e: the IAT slot in memory holds the registry's answer -- "
              "the loader's record and the bytes a program jumps through are "
              "the same fact, and only one of them is the program");
        check(read_u64_at(ordinal_slot) == 0x8000000000000037ull,
              "e2e: and the unresolved slot still holds its original thunk, "
              "because a resolver that cannot answer writes nothing rather "
              "than writing zero");
    }
}

// The same image against a context with no resolver: it loads, the imports
// are walked, and nothing is written. This is `occ check`'s path and it is
// the reason `resolver_state` being null is a supported answer rather than an
// error -- a checker that had to resolve to inspect a file would need the API
// to exist before it could report that it does not.
void test_an_image_without_a_resolver_records_its_imports_and_writes_nothing() {
    // A different base from the case above, and not an arbitrary one: an
    // image with no relocations can only go where its header says, so the two
    // cases differ in the image rather than in the argument.
    constexpr std::uint64_t kImageBase = 0x180000000;
    const ImageFixture f = an_image_importing_two_symbols(kImageBase);
    const PeImage image =
        PeImage::parse(ByteSpan{f.bytes.data(), f.bytes.size()});

    AddressSpace sp;
    Mapper m(sp);
    LoadContext bare;
    bare.placement = &m;
    // The base is the one the kernel offers, for the reason
    // `a_free_base` gives: the header's 0x180000000 is inside the sanitizer
    // build's own mappings, and the case has to run in both builds. Asking
    // for a free base rather than the header's is sound here even though this
    // image is unrelocatable, because the requested base *is* the header's
    // whenever the kernel hands back exactly what was asked for and the
    // fallback path is what the retry policy is for.
    const std::uint64_t free_base = a_free_base(0x10000);
    if (free_base == 0) {
        std::fprintf(stderr,
                     "SKIP no resolver: no free base to place the image at\n");
        return;
    }
    const auto r = load_image_retrying(image,
                                       ByteSpan{f.bytes.data(), f.bytes.size()},
                                       free_base, sp, bare);
    check(r.ok, "no resolver: the image still loads, because inspecting a "
                "file is not the same as running it");
    check(r.module.imports.size() == 2,
          "no resolver: and its imports are still recorded");

    if (r.ok && r.module.imports.size() == 2) {
        check(!r.module.imports[0].resolved && !r.module.imports[1].resolved,
              "no resolver: nothing is resolved, on purpose");
    }
    if (r.ok) {
        // The thunk value the file itself held, which is what the loader
        // copied in and must hand back untouched when nothing resolved it.
        // Asserting against a named constant rather than a literal so that
        // the reader can see the claim is "unchanged", not "zero".
        constexpr std::uint64_t kOriginalNamedThunk =
            0x400 + 0x60 + (0x1000 - 0x200);
        const std::uint64_t iat_va = r.module.imports[0].iat_va;
        check(read_u64_at(iat_va) == kOriginalNamedThunk,
              "no resolver: the IAT is left exactly as the file described "
              "it -- the named slot still holds the hint/name RVA the thunk "
              "held, so a later run that *does* have a resolver sees the same "
              "input");
    }
}

// A LoadContext wired to the registry resolves imports end to end: the loader
// asks, gets an address, and writes it into the IAT. This is the case the
// whole file exists for -- before it, the fourth step of loading could not
// run at all.
void test_a_context_wired_to_a_registry_resolves_and_writes_the_iat() {
    ExportRegistry reg;
    reg.add(a_library("kernel32.dll", 0x7F0000000000ULL));

    LoadContext ctx;
    ctx.resolver_state = &reg;
    // The thunk, not the member: a member function pointer is not assignable
    // to a free function pointer even with an identical signature, so this is
    // the line every real caller writes and it is worth a test that it
    // compiles at all rather than only that it works.
    ctx.resolve = &ExportRegistry::resolve_thunk;

    check(ctx.resolve != nullptr, "context: a context can be wired to a "
                                  "registry, which is the whole point");
    check(ctx.resolve(ctx.resolver_state, "kernel32.dll", "CreateFileW", 0,
                      false) == 0x7F0000000000ULL + 0x1100,
          "context: and the loader's call reaches the registry's answer");

    // Without a resolver the same call does not happen at all, which is what
    // `occ check` relies on: imports are recorded and left alone.
    LoadContext bare;
    check(bare.resolve == nullptr,
          "context: a default context has no resolver, so a load that only "
          "inspects a file resolves nothing on purpose");
}

}  // namespace

int main() {
    test_a_module_name_is_matched_without_regard_to_case();
    test_a_path_names_the_module_behind_it();
    test_the_extension_is_part_of_the_name();
    test_an_empty_registry_answers_nothing_rather_than_failing();
    test_a_name_resolves_to_base_plus_rva();
    test_a_hint_is_tried_and_then_verified();
    test_an_export_name_is_matched_exactly();
    test_an_ordinal_is_the_index_plus_the_base();
    test_an_ordinal_base_of_zero_is_honored();
    test_an_empty_slot_answers_nothing();
    test_an_ordinal_past_the_table_answers_nothing();
    test_a_forwarder_resolves_through_the_module_it_names();
    test_a_forwarder_by_ordinal();
    test_a_chain_two_forwarders_deep_resolves();
    test_a_forwarder_cycle_terminates();
    test_a_chain_deeper_than_the_bound_terminates();
    test_an_unresolved_forwarder_answers_nothing();
    test_an_unplaced_module_resolves_to_nothing();
    test_two_registries_do_not_share_anything();
    test_registering_a_name_twice_answers_with_the_later_one();
    test_a_module_registered_under_a_path_is_found_by_its_name();
    test_modules_lists_what_was_registered();
    test_the_resolve_entry_point_matches_the_loaders_signature();
    test_a_context_wired_to_a_registry_resolves_and_writes_the_iat();
    test_a_real_image_resolves_its_imports_through_the_registry();
    test_an_image_without_a_resolver_records_its_imports_and_writes_nothing();

    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

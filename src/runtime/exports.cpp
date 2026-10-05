#include "occ/runtime/exports.h"

#include <algorithm>
#include <cstdint>
#include <utility>

namespace occ::runtime {

namespace internal {

// One comparison, so the search and the module lookup cannot disagree about
// what "the same name" means.
[[nodiscard]] int compare_ascii(std::string_view a, std::string_view b,
                                bool fold_case) noexcept {
    const std::size_t n = std::min(a.size(), b.size());
    for (std::size_t i = 0; i < n; ++i) {
        unsigned char ca = static_cast<unsigned char>(a[i]);
        unsigned char cb = static_cast<unsigned char>(b[i]);
        // Folded by hand rather than by `tolower`, which is locale-dependent
        // and takes an int it is documented not to like receiving a char
        // whose value is not representable as unsigned char. A guest name is
        // untrusted input, so the narrowing is not hypothetical.
        if (fold_case) {
            ca = (ca >= 'A' && ca <= 'Z') ? static_cast<unsigned char>(ca + 32) : ca;
            cb = (cb >= 'A' && cb <= 'Z') ? static_cast<unsigned char>(cb + 32) : cb;
        }
        if (ca != cb) {
            return ca < cb ? -1 : 1;
        }
    }
    if (a.size() == b.size()) {
        return 0;
    }
    return a.size() < b.size() ? -1 : 1;
}

// An *export* name, compared exactly. This is the one place the two rules
// genuinely differ, and it is worth being precise about why. Win32 export
// names are case-sensitive: the loader's `find_name_in_exports` uses `strcmp`
// on the name table, so a DLL exporting only `Sleep` does not answer to
// `sleep` and a program importing `sleep` fails to link on real Windows.
// Folding case here would resolve an import that Windows refuses -- the same
// class of defect as the hint one, in the other direction: a real address for
// a name nobody exported.
[[nodiscard]] bool export_name_equal(std::string_view a,
                                     std::string_view b) noexcept {
    return compare_ascii(a, b, false) == 0;
}

// The address-table index an ordinal names, or nothing.
//
// The ordinal a program imports by is the outside world's number; the address
// table is indexed from the directory's base. Both of this file's ordinal
// lookups -- a direct one and a forwarder's -- do this arithmetic, and they
// are the same arithmetic, so it is written once.
//
// The subtraction is *signed*, and that is the whole design. The first
// version did it in 32-bit unsigned with a separate `ordinal < base` guard,
// and the two checks were indistinguishable: a 32-bit `ordinal - base` with
// `ordinal < base` wraps to at least 2^31, which no real table is long enough
// to catch, so removing the guard changed no answer. The mutation harness
// found it, twice, and both times correctly -- a check that cannot be
// observed is a check whose removal is a refactor.
//
// Rewriting it as a signed difference makes one comparison do both jobs. A
// negative difference is not a wrapped index, it is a number below zero, and
// "below zero" is exactly the condition the guard was expressing. There is no
// second bounds check to be equivalent with, so there is nothing for the two
// to agree by accident.
//
// The cast to uint64 happens *after* the subtraction, and only to compare
// against a table length. Doing it before would reintroduce the wrap.
[[nodiscard]] bool index_of(std::uint32_t ordinal, std::uint32_t base,
                            std::size_t table_size,
                            std::size_t& index_out) noexcept {
    // Both operands are widened to a signed type that holds their difference
    // without wrapping. int32 would not: a base near the top of the range and
    // an ordinal of zero differ by more than 2^31, and that difference is a
    // legitimate answer rather than a wrapped one.
    // One comparison, and it is the *only* bound this file places on the
    // index it produces. Two earlier versions had two checks here and the
    // mutation harness found both of them untestable, correctly:
    //
    //   * A 32-bit unsigned subtraction behind a separate `ordinal < base`
    //     guard. With the ordinal below the base the difference wraps to at
    //     least 2^31, which no real table is long enough to catch, so
    //     removing the guard changed no answer.
    //
    //   * A signed difference tested as `shifted < 0 || shifted >= length`,
    //     with the sign test reading the difference in its own domain. That
    //     reads as two independent facts and is not: a caller that gets a
    //     negative difference past this check hands it to `walk`, whose own
    //     `index >= exports.size()` refuses it, and the answer is the same
    //     either way.
    //
    // Both were the same mistake -- a second guard in front of one that
    // already existed. The comparison below is the whole of it, in the
    // signed domain so that a negative difference is a negative number
    // rather than a wrapped one, and `walk`'s bounds check is the backstop
    // that makes the answer right whatever this function does. Redundancy
    // that no input can tell apart is not safety; it is the appearance of
    // it, and it costs a reader the question of which check is load-bearing.
    //
    // `table_size` cannot exceed the address table's real length, so
    // converting it to int64 cannot itself overflow -- a table of more than
    // 2^63 entries is not a table this format can describe.
    const std::int64_t shifted = static_cast<std::int64_t>(ordinal) -
                                 static_cast<std::int64_t>(base);
    const std::int64_t length = static_cast<std::int64_t>(table_size);
    if (shifted < 0 || shifted >= length) {
        return false;
    }
    index_out = static_cast<std::size_t>(shifted);
    return true;
}

}  // namespace internal

// A *module* name, compared without regard to case, and declared in the header
// because a caller filtering a report needs to ask the same question this
// class asks internally.
//
// Wine's `find_basename_module` calls `RtlEqualUnicodeString(&name, &mod, TRUE)`
// and the TRUE is the case-insensitive flag, so `KERNEL32.DLL` and
// `kernel32.dll` are the same module to the operating system. A case-sensitive
// comparison here would refuse an import Windows resolves, and the refusal
// would be attributed to the guest.
bool module_name_equal(std::string_view a, std::string_view b) noexcept {
    return internal::compare_ascii(a, b, true) == 0;
}

std::string module_basename(std::string_view path) noexcept {
    // Both separators, because a path here may have been built on either and
    // a guest that imports "C:\windows\system32\kernel32.dll" and one that
    // imports "/usr/lib/kernel32.dll" are asking for the same module. Wine
    // splits on '\\' alone because a path reaching its loader is always a
    // Windows path; a registry that a host fills in is not.
    const std::size_t cut = path.find_last_of("/\\");
    if (cut == std::string_view::npos) {
        return std::string(path);
    }
    return std::string(path.substr(cut + 1));
}

void ExportRegistry::add(ExportModule module) {
    const std::string key = module_basename(module.name);
    for (ExportModule& existing : modules_) {
        if (module_name_equal(existing.name, key)) {
            // Replaced rather than refused, and the header says why. The
            // interesting case is a module registered twice during one load:
            // a forwarder that names a module the image also imports directly
            // reaches the registry twice, and the second registration is at
            // the address the loader actually chose for it. Refusing would
            // leave the first reachable, and which one answered would then
            // depend on the order the walk happened to use.
            existing = std::move(module);
            existing.name = key;
            return;
        }
    }
    module.name = key;
    modules_.push_back(std::move(module));
}

void ExportRegistry::add_from_image(std::string name, const parser::PeImage& image,
                                    std::uint64_t base, bool mapped) {
    ExportModule m;
    m.name = module_basename(name);
    m.base = base;
    m.mapped = mapped;
    m.exports = image.exports();
    m.export_rva = static_cast<std::uint32_t>(image.export_rva());
    m.export_size = image.export_size();
    m.ordinal_base = image.export_ordinal_base();
    add(std::move(m));
}

const ExportModule* ExportRegistry::find(std::string_view name) const noexcept {
    // `key` holds the string rather than viewing it. `module_basename`
    // returns by value, and a string_view over a temporary that died at the
    // end of the full expression is the kind of bug the compiler is right
    // about and wrong to let through: the bytes are usually still intact
    // because the freed block is untouched, so the comparison passes and the
    // failure arrives later as a name that matches nothing.
    const std::string key = module_basename(name);
    for (const ExportModule& m : modules_) {
        if (module_name_equal(m.name, key)) {
            return &m;
        }
    }
    return nullptr;
}

std::vector<const ExportModule*> ExportRegistry::modules() const noexcept {
    std::vector<const ExportModule*> out;
    out.reserve(modules_.size());
    for (const ExportModule& m : modules_) {
        out.push_back(&m);
    }
    return out;
}

ExportLookup ExportRegistry::walk(const ExportModule& module, std::size_t index,
                                  bool by_ordinal, bool by_hint,
                                  std::size_t depth,
                                  std::vector<std::string> chain) const {
    ExportLookup out;
    out.by_ordinal = by_ordinal;
    out.by_hint = by_hint;

    if (depth > kMaxForwarderDepth) {
        // The bound is tested here rather than at the call site so that every
        // path into the walk is bounded, including the one that recurses.
        // `chain` is not cleared, so a caller that reports the failure has
        // the chain that led to it and not just the fact that one existed.
        return out;
    }

    if (index >= module.exports.size()) {
        return out;
    }

    const parser::PeExport& entry = module.exports[index];

    if (entry.rva == 0) {
        // An empty slot. Not a forwarder to zero and not a missing value:
        // the format keeps the slot so ordinals after it do not move, and a
        // guest importing it is asking for something the module removed.
        return out;
    }

    chain.push_back(module.name);

    if (!entry.is_forwarder) {
        if (!module.mapped) {
            // A module described but not placed. Its export table is known
            // and its addresses are not, and an RVA handed back as an address
            // is the confusion this layer refuses: a caller that stored it
            // would store base-zero and jump to the start of the address
            // space. Nothing is reported as found because nothing was.
            return ExportLookup{};
        }
        out.address = module.base + entry.rva;
        out.export_entry = &entry;
        out.module = &module;
        out.chain = std::move(chain);
        return out;
    }

    // A forwarder. The DLL it names is resolved through the same registry,
    // which means a forwarder to a module that is not registered is a
    // `ForwarderUnresolved` rather than a silent zero -- the distinction
    // between "the chain named a module nobody has" and "the chain named a
    // symbol that module does not have" is worth keeping in a report.
    const ExportModule* target = find(entry.forwarder_dll);
    if (target == nullptr) {
        return out;
    }

    // The ordinal the forwarder names, translated to an address-table index
    // the same way an import's ordinal is: the number minus the base, and
    // refusing the subtraction rather than wrapping it.
    std::size_t target_index = 0;
    if (entry.forwarder_by_ordinal) {
        // The same arithmetic as a direct ordinal lookup, and the same
        // helper, because a forwarder naming an ordinal and a guest importing
        // one are asking the same question of the same table.
        if (!internal::index_of(entry.forwarder_ordinal, target->ordinal_base,
                                target->exports.size(), target_index)) {
            return out;
        }
    } else {
        const std::vector<parser::PeExport>& table = target->exports;
        bool found = false;
        for (std::size_t i = 0; i < table.size(); ++i) {
            if (!table[i].name.empty() &&
                internal::export_name_equal(table[i].name, entry.forwarder_name)) {
                target_index = i;
                found = true;
                break;
            }
        }
        if (!found) {
            return out;
        }
    }

    ExportLookup next = walk(*target, target_index, entry.forwarder_by_ordinal,
                             false, depth + 1, std::move(chain));
    if (next.address == 0) {
        return out;
    }
    return next;
}

ExportLookup ExportRegistry::find_by_name(std::string_view dll,
                                          std::string_view name,
                                          std::uint16_t hint) const {
    const ExportModule* module = find(dll);
    if (module == nullptr || module->exports.empty()) {
        return ExportLookup{};
    }

    const std::vector<parser::PeExport>& table = module->exports;

    // The hint is tried first and believed only after comparing the name,
    // which is Wine's order and Wine's reason. A hint is an index the linker
    // wrote; the sorted name table is the truth. A stale hint that was
    // believed resolves a real import to the wrong function without any
    // report, which is a corruption and not a mistake.
    if (hint < table.size() && !table[hint].name.empty() &&
        internal::export_name_equal(table[hint].name, name)) {
        return walk(*module, hint, false, true, 0, {});
    }

    // The search. The export table `PeImage` parsed is in address-table
    // order, which is *not* the sorted order the name table is in, so this
    // cannot be a binary search over `exports()` the way Wine's
    // `find_name_in_exports` is over the name array. It is a linear scan,
    // and saying so is better than sorting a copy per lookup and calling the
    // result a binary search: the table is a few hundred entries at most, and
    // a resolver that is O(n) on a table that fits in a cache line or two is
    // not the thing that makes an import slow.
    for (std::size_t i = 0; i < table.size(); ++i) {
        if (!table[i].name.empty() && internal::export_name_equal(table[i].name, name)) {
            return walk(*module, i, false, false, 0, {});
        }
    }
    return ExportLookup{};
}

ExportLookup ExportRegistry::find_by_ordinal(std::string_view dll,
                                             std::uint16_t ordinal) const {
    const ExportModule* module = find(dll);
    if (module == nullptr || module->exports.empty()) {
        return ExportLookup{};
    }

    // The ordinal is the outside world's number and the address table is
    // indexed from the directory's base, and a base of zero is a value the
    // format allows rather than a sentinel. `index_of` is the whole of that,
    // including the widening that makes its own guard the deciding check.
    std::size_t index = 0;
    if (!internal::index_of(ordinal, module->ordinal_base,
                            module->exports.size(), index)) {
        return ExportLookup{};
    }
    return walk(*module, index, true, false, 0, {});
}

std::uint64_t ExportRegistry::answer(const ExportRegistry& self,
                                     const std::string& dll,
                                     const std::string& name,
                                     std::uint16_t ordinal,
                                     bool by_ordinal) noexcept {
    if (by_ordinal) {
        return self.find_by_ordinal(dll, ordinal).address;
    }
    // No hint is offered here, and that is a real loss rather than a
    // simplification. The thunk's hint field is two bytes the file already
    // holds, and `find_by_name` uses it when it is given one. The signature
    // `LoadContext::resolve` was published with does not carry it, so the
    // hint is dropped at this boundary and the scan finds the same export.
    // Widening that signature is a change to a contract other code already
    // matches, and it is left for whoever has a caller that needs the speed
    // rather than made here to look thorough.
    //
    // 0xFFFF rather than 0: it is outside every real table, and the
    // `find_by_name` contract says an out-of-range hint is not tried at all,
    // so the answer is the scan's rather than "the hint matched something".
    return self.find_by_name(dll, name, 0xFFFF).address;
}

std::uint64_t ExportRegistry::resolve(void* state, const std::string& dll,
                                      const std::string& name,
                                      std::uint16_t ordinal,
                                      bool by_ordinal) const noexcept {
    const auto* self = static_cast<const ExportRegistry*>(state);
    if (self == nullptr) {
        // A null state with a non-null function pointer is a wiring mistake,
        // and it is answered rather than dereferenced. The loader's contract
        // for a resolver that cannot answer is "nothing is written", and
        // honouring it here means the mistake is a load with unresolved
        // imports rather than a crash in the middle of one.
        return 0;
    }
    return answer(*self, dll, name, ordinal, by_ordinal);
}

std::uint64_t ExportRegistry::resolve_thunk(void* state, const std::string& dll,
                                            const std::string& name,
                                            std::uint16_t ordinal,
                                            bool by_ordinal) noexcept {
    // The state is a `void*` because `LoadContext::resolve` is a type-erased
    // callback that predates this class, and the pointer it takes is not
    // const because the contract cannot promise the pointee is not written.
    // Nothing here writes: `answer` reaches only `const` members, and the
    // member it delegates to is where the null check lives so that both entry
    // points share one implementation rather than two that can drift.
    const auto* self = static_cast<const ExportRegistry*>(state);
    if (self == nullptr) {
        return 0;
    }
    return answer(*self, dll, name, ordinal, by_ordinal);
}

}  // namespace occ::runtime

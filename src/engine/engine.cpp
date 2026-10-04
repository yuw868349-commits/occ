#include "occ/engine/engine.h"

namespace occ::engine {

namespace {

// The registry.
//
// A function-local static rather than a namespace-scope one because the
// engines are namespace-scope objects in their own translation units, and
// the order in which those are constructed relative to a namespace-scope
// vector is not specified. Initialising on first use removes the question:
// by the time anything reads the table, every engine it names has been
// constructed.
//
// The order is the order the engines are declared here, and it is the order
// `occ check` reports them in. It is not alphabetical because there is no
// reason for it to be, and a table that claims an order it does not have is
// worse than one that says nothing about order.
const std::vector<const Engine*>& registry() noexcept {
    static const std::vector<const Engine*> table = {
        &elf_engine(),
        &pe_engine(),
        &apk_engine(),
    };
    return table;
}

} // namespace

const char* engine_kind_name(EngineKind k) noexcept {
    switch (k) {
    case EngineKind::Elf:
        return "elf";
    case EngineKind::Pe:
        return "pe";
    case EngineKind::Apk:
        return "apk";
    }
    return "unknown";
}

const Engine* engine_for(parser::Format f) noexcept {
    for (const Engine* e : registry()) {
        // The switch is on the engine's own kind rather than on a table
        // here. A format that gained an engine then needs a change in the
        // engine that handles it, which is the file that has to change
        // anyway -- a second table in this file would be a second place
        // where the same fact is written down.
        switch (e->kind()) {
        case EngineKind::Elf:
            if (f == parser::Format::Elf) {
                return e;
            }
            break;
        case EngineKind::Pe:
            if (f == parser::Format::Pe) {
                return e;
            }
            break;
        case EngineKind::Apk:
            if (f == parser::Format::Apk) {
                return e;
            }
            break;
        }
    }
    return nullptr;
}

const Engine* engine_for(const parser::Detection& d) noexcept {
    return engine_for(d.format);
}

const std::vector<const Engine*>& engines() noexcept {
    return registry();
}

} // namespace occ::engine

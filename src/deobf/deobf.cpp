// The deobfuscation pipeline and its human-readable report.
//
// The pipeline order -- opaque predicates, then flattening, then MBA --
// is the order the analyses depend on, and each stage's evidence is
// carried into the report verbatim: which predicate was proven constant
// by which layer, which dispatcher was recognized and how each edge was
// resolved, and which expressions were rewritten and with what proof.
// The report is the module's audit trail; it states what was proven and
// names everything that was not, in the pass-specific unresolved lists.

#include "occ/deobf/deobf.h"

#include <cstdio>

namespace occ::deobf {

namespace {

std::string pretty_cond(const LiftedFunc& func, devirt::expr::Id cond) {
    if (cond == devirt::expr::kNoId) {
        return "unconditional";
    }
    if (!func.dag.valid(cond)) {
        return "?";
    }
    return func.dag.pretty(cond);
}

}  // namespace

DeobfResult deobfuscate(const LiftedFunc& func, const DeobfOptions& options) {
    DeobfResult out;

    // 1. Opaque predicates first: a predicate edge grafted onto the
    //    dispatcher must be gone before the dispatcher's edges are
    //    required to all be state tests.
    out.func = eliminate_opaque(func, options.opaque, out.opaque);
    if (out.opaque.edges_deleted != 0) {
        out.notes.push_back("opaque-predicate elimination removed " +
                            std::to_string(out.opaque.edges_deleted) +
                            " dead edge(s) before flattening");
    }

    // 2. Flattening recovery on the cleaned function.
    const LiftedFunc& cleaned = out.func;
    out.func = recover_flattening(cleaned, options.flatten, out.flatten);
    if (!out.flatten.recognized) {
        for (const std::string& u : out.flatten.unresolved) {
            out.notes.push_back("flattening not recovered: " + u);
        }
    }

    // 3. MBA simplification of every assignment in the recovered
    //    function.
    out.func =
        simplify_mba_pass(out.func, options.mba, out.mba);
    return out;
}

std::string deobf_dump_cfg(const LiftedFunc& func, const std::string& title) {
    std::string out;
    out += title;
    out += "\n";
    for (const Block& block : func.blocks) {
        out += "  block ";
        out += std::to_string(block.id);
        if (!block.label.empty()) {
            out += " [";
            out += block.label;
            out += "]";
        }
        out += block.id == func.entry ? " (entry)" : "";
        out += "\n";
        for (const Assign& a : block.assigns) {
            out += "    ";
            out += a.dst;
            out += " = ";
            out += func.dag.valid(a.value) ? func.dag.pretty(a.value) : "?";
            out += "\n";
        }
        if (block.edges.empty()) {
            out += "    (no edges; exit)\n";
        }
        for (std::size_t i = 0; i < block.edges.size(); ++i) {
            const Edge& e = block.edges[i];
            out += "    -> ";
            out += std::to_string(e.target);
            out += "  when ";
            out += pretty_cond(func, e.cond);
            out += "\n";
        }
    }
    return out;
}

namespace {

std::string dump_cases(const FlattenResult& f) {
    std::string out;
    for (const auto& [value, target] : f.cases) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx",
                      static_cast<unsigned long long>(value));
        out += "      case ";
        out += buf;
        out += " -> block ";
        out += std::to_string(target);
        out += "\n";
    }
    return out;
}

}  // namespace

std::string deobf_report(const LiftedFunc& original,
                         const DeobfResult& result) {
    std::string out;
    out += deobf_dump_cfg(original, "=== original CFG ===");
    out += "\n";

    // ---- opaque predicates
    out += "=== opaque-predicate elimination ===\n";
    out += "  conditions inspected: ";
    out += std::to_string(result.opaque.conditions_inspected);
    out += "\n";
    if (result.opaque.steps.empty()) {
        out += "  (none)\n";
    }
    for (const OpaqueStep& s : result.opaque.steps) {
        out += "  block ";
        out += std::to_string(s.block);
        out += " edge ";
        out += std::to_string(s.edge);
        out += ": ";
        out += s.cond;
        if (s.constant_true) {
            out += " [always true]";
        } else if (s.constant_false) {
            out += " [always false]";
        }
        out += " -- ";
        out += s.action;
        out += " (";
        out += s.method == devirt::bb::Method::Ring ? "ring" : "sat";
        out += ")";
        if (!s.evidence.empty()) {
            out += " evidence: ";
            out += s.evidence;
        }
        out += "\n";
    }
    out += "\n";

    // ---- flattening
    out += "=== control-flow flattening recovery ===\n";
    if (result.flatten.recognized) {
        out += "  dispatcher: block ";
        out += std::to_string(result.flatten.dispatcher);
        out += ", state variable \"";
        out += result.flatten.state_name;
        out += "\"\n";
        out += "  case table:\n";
        out += dump_cases(result.flatten);
    } else {
        out += "  not recognized\n";
    }
    for (const FlattenStep& s : result.flatten.steps) {
        out += "  ";
        out += s.what;
        out += " block ";
        out += std::to_string(s.block);
        if (!s.detail.empty()) {
            out += " (";
            out += s.detail;
            out += ")";
        }
        if (s.old_target != s.new_target) {
            out += ": " + std::to_string(s.old_target) + " -> " +
                   std::to_string(s.new_target);
        }
        out += "\n";
    }
    if (!result.flatten.unresolved.empty()) {
        out += "  unresolved:\n";
        for (const std::string& u : result.flatten.unresolved) {
            out += "    " + u + "\n";
        }
    }
    out += "\n";

    // ---- MBA
    out += "=== MBA simplification ===\n";
    out += "  expressions simplified: ";
    out += std::to_string(result.mba.expressions_simplified);
    out += ", unsimplified: ";
    out += std::to_string(result.mba.expressions_unsimplified);
    out += "\n";
    if (result.mba.steps.empty()) {
        out += "  (none)\n";
    }
    for (const MbaStep& s : result.mba.steps) {
        out += "  block ";
        out += std::to_string(s.block);
        if (!s.dst.empty()) {
            out += " (" + s.dst + ")";
        }
        out += " [";
        out += s.kind;
        out += " ";
        out += s.method == devirt::bb::Method::Ring ? "ring" : "sat";
        out += "] ";
        if (s.accepted) {
            out += s.from + " -> " + s.to;
        } else {
            out += s.from + " !-> " + s.to + " (rejected: " + s.evidence + ")";
        }
        if (!s.accepted) {
            out += "\n";
            continue;
        }
        out += "  (nodes ";
        out += std::to_string(s.nodes_before);
        out += " -> ";
        out += std::to_string(s.nodes_after);
        out += ")";
        if (!s.evidence.empty()) {
            out += " evidence: " + s.evidence;
        }
        out += "\n";
    }
    out += "\n";

    out += deobf_dump_cfg(result.func, "=== recovered CFG ===");
    out += "\n";

    // ---- notes
    if (!result.notes.empty()) {
        out += "=== notes (unproven / partial) ===\n";
        for (const std::string& n : result.notes) {
            out += "  " + n + "\n";
        }
        out += "\n";
    }
    return out;
}

}  // namespace occ::deobf

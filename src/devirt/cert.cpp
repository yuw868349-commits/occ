// The certificate layer implementation. See cert.h for the design; this
// file is the accounting.
//
// `cfg_certificate` is the one nontrivial builder here. It takes the
// reachable set, the per-handler outcomes of verification, and the CFG
// edges, and turns them into a Report whose every line is either a
// claim with evidence or an explicit admission that no claim is made.
// The honesty rules are structural, not advisory: the loop over the
// reachable set *cannot* skip a handler, because the step for a missing
// outcome is created inside the loop; a dangling edge *cannot* go
// unmentioned, because the edge loop checks both endpoints against the
// reachable set and records a note when either is missing.
//
// The statuses are the vocabulary of the whole layer and the whole
// de-virtualizer: Proven (checked and holds), Unproven (not decided --
// never negative), Refuted (checked and fails), Unmodeled (nothing exact
// to check). `render()` turns the steps into a document that a human
// can read top to bottom and a checker can diff.

#include "occ/devirt/cert.h"

#include <cstdio>
#include <unordered_map>

namespace occ::devirt::cert {

namespace {

const char* status_name(Step::Status s) {
    switch (s) {
    case Step::Status::Proven:   return "proven";
    case Step::Status::Unproven: return "unproven";
    case Step::Status::Refuted:  return "refuted";
    case Step::Status::Unmodeled:return "unmodeled";
    }
    return "?";
}

const char* status_evidence(Step::Status s) {
    switch (s) {
    case Step::Status::Proven:
        return "equivalence established by the verifying layer";
    case Step::Status::Unproven:
        return "no proof recorded (budget exhausted or question not posed)";
    case Step::Status::Refuted:
        return "counterexample found by the verifying layer";
    case Step::Status::Unmodeled:
        return "handler model incomplete; nothing exact to verify";
    }
    return "";
}

bool contains(const std::vector<std::uint64_t>& v, std::uint64_t x) {
    for (const std::uint64_t e : v) {
        if (e == x) {
            return true;
        }
    }
    return false;
}

std::string va_hex(std::uint64_t va) {
    char b[24];
    std::snprintf(b, sizeof(b), "0x%llx",
                  static_cast<unsigned long long>(va));
    return b;
}

// "0x1000, 0x1010"
std::string vmas_text(const std::vector<std::uint64_t>& vmas) {
    std::string text;
    for (std::size_t i = 0; i < vmas.size(); ++i) {
        if (i != 0) {
            text += ", ";
        }
        text += va_hex(vmas[i]);
    }
    return text;
}

}  // namespace

// ----------------------------------------------------------- counts

std::uint64_t Report::proven() const noexcept {
    std::uint64_t n = 0;
    for (const Step& s : steps) {
        if (s.status == Step::Status::Proven) {
            ++n;
        }
    }
    return n;
}

std::uint64_t Report::unproven() const noexcept {
    std::uint64_t n = 0;
    for (const Step& s : steps) {
        if (s.status == Step::Status::Unproven) {
            ++n;
        }
    }
    return n;
}

std::uint64_t Report::refuted() const noexcept {
    std::uint64_t n = 0;
    for (const Step& s : steps) {
        if (s.status == Step::Status::Refuted) {
            ++n;
        }
    }
    return n;
}

std::uint64_t Report::unmodeled() const noexcept {
    std::uint64_t n = 0;
    for (const Step& s : steps) {
        if (s.status == Step::Status::Unmodeled) {
            ++n;
        }
    }
    return n;
}

// ----------------------------------------------------------- render

std::string Report::render() const {
    std::string text;
    char b[64];
    for (std::size_t i = 0; i < steps.size(); ++i) {
        const Step& s = steps[i];
        std::snprintf(b, sizeof(b), "step %zu", i + 1);
        text += b;
        if (!s.vmas.empty()) {
            text += " [";
            text += vmas_text(s.vmas);
            text += ']';
        }
        text += ": ";
        text += s.claim;
        text += " -- ";
        text += status_name(s.status);
        if (!s.evidence.empty()) {
            text += " [";
            text += s.evidence;
            text += ']';
        }
        text += '\n';
    }
    std::snprintf(b, sizeof(b),
                  "proven: %llu, unproven: %llu, refuted: %llu, "
                  "unmodeled: %llu, steps: %zu\n",
                  static_cast<unsigned long long>(proven()),
                  static_cast<unsigned long long>(unproven()),
                  static_cast<unsigned long long>(refuted()),
                  static_cast<unsigned long long>(unmodeled()),
                  steps.size());
    text += b;
    return text;
}

// ------------------------------------------------------- CfgSummary

bool CfgSummary::complete() const noexcept {
    for (const std::uint64_t va : reachable) {
        if (!contains(verified, va)) {
            return false;
        }
    }
    return true;
}

std::vector<std::uint64_t> CfgSummary::unverified() const {
    std::vector<std::uint64_t> out;
    for (const std::uint64_t va : reachable) {
        if (!contains(verified, va)) {
            out.push_back(va);
        }
    }
    return out;
}

// ------------------------------------------------- cfg_certificate

Report cfg_certificate(
    const std::vector<std::uint64_t>& reachable,
    const std::vector<std::pair<std::uint64_t, Step::Status>>& outcomes,
    const std::vector<std::pair<std::uint64_t, std::uint64_t>>& edges) {
    Report report;

    // The recorded outcomes, keyed by handler VA.
    std::unordered_map<std::uint64_t, Step::Status> by_va;
    for (const auto& [va, st] : outcomes) {
        by_va[va] = st;
    }

    // 1. Every reachable handler gets exactly one step. A missing
    //    outcome is Unproven with the fact in the claim -- never a skip,
    //    never a guessed verdict.
    for (const std::uint64_t va : reachable) {
        const auto it = by_va.find(va);
        Step s;
        s.vmas.push_back(va);
        if (it == by_va.end()) {
            s.claim = "handler " + va_hex(va) +
                      ": no outcome recorded by verification";
            s.status = Step::Status::Unproven;
            s.evidence = "missing from outcomes; reported unproven";
        } else {
            s.status = it->second;
            s.claim = "handler " + va_hex(va) + ": " + status_name(s.status);
            s.evidence = status_evidence(s.status);
        }
        report.steps.push_back(std::move(s));
    }

    // 2. Edges. Every edge is checked against the reachable set; a
    //    dangling endpoint is flagged, never papered over. Edges whose
    //    endpoints are both reachable get a step of their own, Proven
    //    only when both endpoints were verified.
    for (const auto& [from, to] : edges) {
        const bool from_in = contains(reachable, from);
        const bool to_in = contains(reachable, to);
        if (!from_in || !to_in) {
            char b[96];
            std::snprintf(b, sizeof(b),
                          "edge %s -> %s has an endpoint outside the "
                          "reachable set",
                          va_hex(from).c_str(), va_hex(to).c_str());
            report.steps.push_back(Step{"dangling edge", Step::Status::Unproven,
                                        b, {from, to}});
            continue;
        }
        Step s;
        s.vmas = {from, to};
        s.claim = "edge " + va_hex(from) + " -> " + va_hex(to) +
                  " stays within the reachable set";
        const auto fit = by_va.find(from);
        const auto tit = by_va.find(to);
        const bool f_ok =
            fit != by_va.end() && fit->second == Step::Status::Proven;
        const bool t_ok =
            tit != by_va.end() && tit->second == Step::Status::Proven;
        if (f_ok && t_ok) {
            s.status = Step::Status::Proven;
            s.evidence = "both endpoints verified";
        } else {
            s.status = Step::Status::Unproven;
            s.evidence = std::string("endpoint ") +
                         (f_ok ? va_hex(to) : va_hex(from)) +
                         " not verified";
        }
        report.steps.push_back(std::move(s));
    }
    return report;
}

}  // namespace occ::devirt::cert

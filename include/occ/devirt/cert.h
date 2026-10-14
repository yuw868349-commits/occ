// The certificate layer: what the de-virtualizer can claim about a
// virtualized control-flow graph, and in what words.
//
// A de-virtualizer that just says "the rebuilt code is equivalent" is
// making a claim without an audit trail. This layer exists so every
// claim carries its evidence with it, in a form that is checkable
// without re-running the pipeline that produced it:
//
//   - A `Step` is one atomic claim: a handler's effect equals its
//     reconstruction, a CFG edge stays inside the reachable set, a
//     handler is or is not covered by the proof. The `Status` is the
//     verdict of the check that produced it, and `evidence` is the
//     artifact that verifies it -- a DRUP trace, the canonical forms of
//     the word-level layer, the rebuilt text, or a counterexample. An
//     unproven claim is reported as unproven, never as proven or as a
//     counterexample, because "the budget ran out" and "the code is
//     different" are different claims that a downstream consumer will
//     act on differently.
//
//   - A `Report` is the ordered set of steps for one verification
//     question, with the counts that summarize it. `render()` turns it
//     into a human-readable certificate document.
//
//   - `CfgSummary` is the coverage view of a virtual CFG: which handlers
//     are reachable, which of those are verified, and what is left
//     unverified. `complete()` is true exactly when nothing reachable is
//     left unverified.
//
// `cfg_certificate` builds a Report from a reachable set, per-handler
// outcomes, and edges. Its honesty rules: every reachable handler gets a
// step, whether or not an outcome was recorded (a missing outcome is a
// `Step::Unproven`, never a skip), and every edge's endpoints must be in
// the reachable set -- a dangling edge is flagged in the notes.

#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace occ::devirt::cert {

// One atomic claim of the certificate.
struct Step {
    // What is being claimed, in one line: "handler 0x1000 equals its
    // reconstruction", "edge 0x1000 -> 0x1010 stays in the reachable
    // set", "handler 0x1000 has no recorded outcome".
    std::string claim;
    enum class Status : std::uint8_t {
        // The claim was checked and holds. `evidence` verifies it.
        Proven,
        // The claim was not decided: no outcome was recorded, a proof
        // budget ran out, the model was not precise enough. This is
        // never a negative claim about the code.
        Unproven,
        // The claim was checked and fails. `evidence` carries the
        // counterexample or the conflicting observation.
        Refuted,
        // The claim could not even be formed: the handler's model is
        // incomplete, so there is nothing exact to verify. Listed so the
        // report accounts for every reachable handler.
        Unmodeled,
    };
    Status status = Status::Unproven;
    // The artifact that verifies the claim: a DRUP trace, the canonical
    // forms of the word-level layer, the rebuilt text, or a
    // counterexample. Empty when no artifact exists.
    std::string evidence;
    // The handlers this step is about.
    std::vector<std::uint64_t> vmas;
};

// The ordered set of steps for one verification question, with the
// counts that summarize it.
struct Report {
    std::vector<Step> steps;

    [[nodiscard]] std::uint64_t proven() const noexcept;
    [[nodiscard]] std::uint64_t unproven() const noexcept;
    [[nodiscard]] std::uint64_t refuted() const noexcept;
    [[nodiscard]] std::uint64_t unmodeled() const noexcept;

    // A complete human-readable certificate document: one line per step
    // with its claim, status and evidence, then the totals.
    [[nodiscard]] std::string render() const;
};

// The coverage view of a virtual CFG.
struct CfgSummary {
    // Every handler the CFG can reach from its entry, in traversal order.
    std::vector<std::uint64_t> reachable;
    // The subset of `reachable` whose reconstruction was verified.
    std::vector<std::uint64_t> verified;
    // Anything the certificate could not say exactly (a dangling edge,
    // an unmodeled handler): one note each.
    std::vector<std::string> notes;

    // True when every reachable handler is verified.
    [[nodiscard]] bool complete() const noexcept;
    // The reachable handlers without a verification, in `reachable`
    // order.
    [[nodiscard]] std::vector<std::uint64_t> unverified() const;
};

// Builds the certificate report for a virtual CFG from:
//   - `reachable`: every handler the CFG reaches, in traversal order;
//   - `outcomes`: the per-handler verdicts that verification produced
//     (each pair is a handler VA and its step status);
//   - `edges`: the CFG edges as (from, to) handler VAs.
//
// Every reachable handler receives exactly one step. A handler with no
// outcome in `outcomes` is reported `Unproven` with a note in the
// claim; it is never skipped. Every edge is checked against the
// reachable set: an edge whose endpoint is not reachable is flagged as a
// note (and, when only one endpoint is reachable, the reachable
// endpoint's step is left Unproven if it was not verified -- the
// certificate never claims more than the CFG shows). Edge steps are
// emitted after the handler steps, one per edge, Proven when both
// endpoints are verified and Unproven otherwise.
[[nodiscard]] Report cfg_certificate(
    const std::vector<std::uint64_t>& reachable,
    const std::vector<std::pair<std::uint64_t, Step::Status>>& outcomes,
    const std::vector<std::pair<std::uint64_t, std::uint64_t>>& edges);

}  // namespace occ::devirt::cert

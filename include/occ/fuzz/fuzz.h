// The coverage-guided fuzzing engine, in the AFL lineage.
//
// The engine drives an arbitrary target -- a parser, a decoder, an
// emulator run -- with mutated inputs, keeps the inputs that reach new
// edges, and reports the inputs that crash it. The pieces are the ones
// AFL proved out over a decade:
//
//   * A fixed-size edge bitmap. The target names every edge it takes
//     (from-block, to-block); `Coverage` folds them into a bitmap with
//     count buckets, and `new_edges` is the interestingness signal the
//     corpus uses to keep an input.
//
//   * A mutation schedule. The deterministic stages first (bit flips,
//     byte arithmetic, interesting values, dictionary tokens) give the
//     corpus its depth; the havoc stage afterwards (splice + random
//     edits) gives it breadth. Every stage is a pure function over the
//     input, so the whole engine is reproducible from a seed.
//
//   * A corpus with energy. `Corpus` keeps the inputs that found new
//     edges, and the picker weights them by how rarely their edges were
//     seen elsewhere -- the rare path gets tried more, which is what
//     drives the search toward untested code.
//
//   * Crash management. Crashes are kept, deduplicated by the address
//     the target reported, and exposed as a reproducible list.
//
// The target interface is deliberately the only thing that touches the
// outside world: `TargetFn` takes a byte buffer and fills a Coverage,
// answering whether the run crashed and where. Nothing here knows what
// the target does; the emulator and the real guest both implement the
// same callback, and the tests drive a synthetic parser through it.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace occ::fuzz {

// The edge coverage bitmap.
//
// Edges are folded as `bitmap[(from ^ to * 3) & mask]` into count
// buckets (saturating at 255), the way a compact coverage signal should:
// exact edge identity is kept only in the count, and the bitmap size is
// a power of two chosen by the caller.
class Coverage {
public:
    explicit Coverage(std::size_t bits) noexcept;

    // Notes one edge. `from` and `to` are the caller's block ids; the
    // fold is this class's business.
    void note(std::uint64_t from, std::uint64_t to) noexcept;

    // Whether this note made a bucket go from 0 to 1 -- the signal the
    // corpus listens for.
    [[nodiscard]] bool last_was_new() const noexcept {
        return last_new_;
    }

    // The number of distinct edges seen so far.
    [[nodiscard]] std::size_t distinct() const noexcept;

    // The folded ids of the edges this run touched, in the order they
    // were first noted. Consumed by the campaign to build the corpus's
    // rarity model.
    [[nodiscard]] std::vector<std::uint64_t> take_edges() noexcept;

    [[nodiscard]] const std::uint8_t* bitmap() const noexcept {
        return bitmap_.data();
    }
    [[nodiscard]] std::size_t size() const noexcept { return bitmap_.size(); }

private:
    std::vector<std::uint8_t> bitmap_;
    std::vector<std::uint64_t> touched_;
    std::size_t distinct_ = 0;
    bool last_new_ = false;
};

// One input the engine tried or kept.
struct Input {
    std::vector<std::uint8_t> data;
    std::vector<std::uint64_t> edge_ids;  // folded edges it reached
    std::size_t edges = 0;      // distinct edges it reached
    std::size_t runs = 0;       // times it has been picked for mutation
    bool crash = false;
    std::uint64_t crash_at = 0;
    std::string crash_name;
};

// The target's answer for one run.
struct TargetResult {
    bool crash = false;
    std::uint64_t crash_at = 0;
    // Optional: a name for the crash ("" to use the address).
    std::string crash_name;
};

// The target callback: executes `data`, fills `cov` with the edges it
// took, and answers whether it crashed. `ctx` is the integration's.
using TargetFn = TargetResult (*)(const uint8_t* data, std::size_t n,
                                  Coverage& cov, void* ctx) noexcept;

// The corpus of interesting inputs.
//
// `add` keeps an input only when it reached new edges (or crashed);
// `pick` selects one for mutation, weighted so that inputs whose edges
// are rarer across the corpus are tried more often.
class Corpus {
public:
    Corpus() noexcept : Corpus(64) {}
    explicit Corpus(std::size_t max_inputs) noexcept
        : max_inputs_(max_inputs) {}

    // Adds an input (copying it) and answers whether it was kept.
    // Crashes are always kept; new-edge inputs are kept up to
    // `max_inputs`, dropping the least-energetic entry when full.
    bool add(const Input& in) noexcept;

    // Picks an input for mutation. Returns false when the corpus is
    // empty.
    bool pick(Input& out) noexcept;

    [[nodiscard]] std::size_t size() const noexcept { return inputs_.size(); }
    [[nodiscard]] bool empty() const noexcept { return inputs_.empty(); }
    [[nodiscard]] const std::vector<Input>& inputs() const noexcept {
        return inputs_;
    }

private:
    // The rarity model: edge id -> how many corpus inputs cover it. An
    // input's energy is the sum of the reciprocals of its edges' counts,
    // so a rarely-covered edge makes its input valuable.
    struct EdgeUse {
        std::uint64_t id;
        std::size_t count;
    };
    std::vector<EdgeUse> edge_use_;
    std::size_t max_inputs_;
    std::vector<Input> inputs_;
    std::size_t next_ = 0;

    [[nodiscard]] std::size_t use_of(std::uint64_t id) const noexcept;
    [[nodiscard]] double energy(const Input& in) const noexcept;
    [[nodiscard]] std::uint64_t next_u64_rng_() noexcept;
};

// The deterministic and random mutation stages.
//
// `deterministic` applies bit-flip, arithmetic and interesting-value
// stages in a fixed order and calls `emit` for each candidate. `havoc`
// applies a random edit sequence (splice from `other` plus random
// mutations) and calls `emit` once. The engine calls these with its own
// corpus state; the functions are pure over their inputs.
class Mutator {
public:
    Mutator() noexcept;

    // The interesting byte values the arithmetic stage tries.
    [[nodiscard]] static const std::vector<std::uint8_t>& interest_bytes()
        noexcept;
    [[nodiscard]] static const std::vector<std::uint16_t>& interest_words()
        noexcept;

    // Walks the deterministic stages for `base` and calls `emit` with
    // each candidate. Returns the number of candidates emitted.
    using EmitFn = void (*)(const std::uint8_t* data, std::size_t n,
                            void* ctx) noexcept;
    std::size_t deterministic(const std::vector<std::uint8_t>& base,
                              EmitFn emit, void* ctx) noexcept;

    // One havoc round over `base` and `other`. Returns the candidate
    // (possibly equal to base when the round produced nothing new).
    void havoc(const std::vector<std::uint8_t>& base,
               const std::vector<std::uint8_t>& other,
               std::vector<std::uint8_t>& out) noexcept;

    // The internal random source, exposed so the campaign can make
    // uniform choices (e.g. which corpus entry to splice with).
    [[nodiscard]] std::size_t next_below(std::size_t n) noexcept;

private:
    std::uint64_t rng_ = 0;
    [[nodiscard]] std::uint64_t next_u64() noexcept;
};

// The engine's run stats.
struct Stats {
    std::size_t runs = 0;
    std::size_t new_edges = 0;
    std::size_t crashes = 0;
    std::size_t corpus_size = 0;
    std::size_t deterministic_runs = 0;
    std::size_t havoc_runs = 0;
};

// Runs the fuzzing campaign.
//
// `seed` is the initial corpus entry. `max_runs` bounds the campaign;
// the engine alternates deterministic stages on each picked input with
// havoc rounds, keeps new-edge and crashing inputs, and stops when the
// budget is spent. Crashes land in `crashes`, deduplicated by
// address+name. `seed` must be non-empty.
[[nodiscard]] Stats fuzz(const std::vector<std::uint8_t>& seed, TargetFn target,
                         void* ctx, std::size_t max_runs,
                         std::size_t bitmap_bits, std::size_t max_corpus,
                         std::vector<Input>& crashes) noexcept;

}  // namespace occ::fuzz

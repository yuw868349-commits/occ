// The coverage-guided fuzzing engine -- implementation.
//
// The rarity model is the heart of the corpus: every edge the campaign
// has seen carries a use count (how many corpus inputs cover it), and an
// input's energy is the sum of the reciprocals of its edges' use counts.
// An input whose edges are covered by everything is cheap; an input
// carrying a rarely-seen edge is expensive and is picked more often.
// That is what turns the deterministic byte-by-byte stages into a
// search: the input that unlocks the next comparison keeps getting
// retried, mutated, and deepened.

#include "occ/fuzz/fuzz.h"

#include <algorithm>
#include <cstring>
#include <iterator>

namespace occ::fuzz {

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

Coverage::Coverage(std::size_t bits) noexcept : bitmap_(std::size_t{1} << bits, 0) {}

void Coverage::note(std::uint64_t from, std::uint64_t to) noexcept {
    if (bitmap_.empty()) {
        return;
    }
    const std::uint64_t id = from ^ (to * 3u);
    const std::size_t slot =
        static_cast<std::size_t>(id) & (bitmap_.size() - 1);
    last_new_ = false;
    if (bitmap_[slot] == 0) {
        ++distinct_;
        last_new_ = true;
        touched_.push_back(id);
    }
    if (bitmap_[slot] < 255) {
        bitmap_[slot] += 1;
    }
}

std::size_t Coverage::distinct() const noexcept { return distinct_; }

std::vector<std::uint64_t> Coverage::take_edges() noexcept {
    std::vector<std::uint64_t> e;
    e.swap(touched_);
    return e;
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

bool Corpus::add(const Input& in) noexcept {
    if (in.crash) {
        inputs_.push_back(in);
        return true;
    }
    if (in.edge_ids.empty()) {
        return false;  // no new information
    }
    // Is any of its edges new to the campaign?
    bool has_new = false;
    for (std::uint64_t e : in.edge_ids) {
        if (use_of(e) == 0) {
            has_new = true;
            break;
        }
    }
    if (!has_new) {
        return false;
    }
    // Record the edges this input covers.
    for (std::uint64_t e : in.edge_ids) {
        bool found = false;
        for (EdgeUse& eu : edge_use_) {
            if (eu.id == e) {
                eu.count += 1;
                found = true;
                break;
            }
        }
        if (!found) {
            edge_use_.push_back(EdgeUse{e, 1});
        }
    }
    if (inputs_.size() < max_inputs_) {
        inputs_.push_back(in);
        return true;
    }
    // Full: replace the least-energetic entry.
    std::size_t weakest = 0;
    double weakest_energy = 0;
    for (std::size_t i = 0; i < inputs_.size(); ++i) {
        const double e = energy(inputs_[i]);
        if (i == 0 || e < weakest_energy) {
            weakest = i;
            weakest_energy = e;
        }
    }
    inputs_[weakest] = in;
    return true;
}

bool Corpus::pick(Input& out) noexcept {
    if (inputs_.empty()) {
        return false;
    }
    // Rotating pick weighted by energy: an energy-proportional roulette
    // over the current entries, biased slightly toward the less-run
    // ones.
    double total = 0;
    for (const Input& in : inputs_) {
        total += energy(in);
    }
    if (total <= 0) {
        out = inputs_[next_ % inputs_.size()];
        next_ = (next_ + 1) % inputs_.size();
        ++out.runs;
        return true;
    }
    double r = static_cast<double>(next_u64_rng_() % 1000000) / 1000000.0 * total;
    std::size_t chosen = 0;
    double acc = 0;
    for (std::size_t i = 0; i < inputs_.size(); ++i) {
        acc += energy(inputs_[i]);
        if (r <= acc) {
            chosen = i;
            break;
        }
    }
    out = inputs_[chosen];
    ++out.runs;
    return true;
}

std::size_t Corpus::use_of(std::uint64_t id) const noexcept {
    for (const EdgeUse& eu : edge_use_) {
        if (eu.id == id) {
            return eu.count;
        }
    }
    return 0;
}

double Corpus::energy(const Input& in) const noexcept {
    double e = 0;
    for (std::uint64_t id : in.edge_ids) {
        const std::size_t use = use_of(id);
        e += 1.0 / static_cast<double>(use == 0 ? 1 : use);
    }
    if (e <= 0) {
        e = 0.1;
    }
    return e;
}

std::uint64_t Corpus::next_u64_rng_() noexcept {
    // A splitmix64-style step, seeded from the address of a static, so
    // two campaigns in the same process still diverge.
    static std::uint64_t x = 0x9E3779B97F4A7C15ull ^
                             reinterpret_cast<std::uintptr_t>(&x);
    x += 0x9E3779B97F4A7C15ull;
    std::uint64_t z = x;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

// ---------------------------------------------------------------------------
// Mutator
// ---------------------------------------------------------------------------

namespace {

// The classic AFL interesting-8 set: boundary and marker bytes that
// parsers and decoders branch on. Missing entries (0x41/0x81/0x82/0xfd/
// 0xfc/0xbf/0x7e...) cost real coverage on any target that checks a
// one-byte magic, which is why the full table matters.
const std::uint8_t kInterest8[] = {
    0x00, 0x01, 0x7f, 0x80, 0xff, 0x81, 0xfe, 0x41, 0x82, 0xfd,
    0x83, 0xfc, 0xbf, 0xc0, 0x7e, 0x7f, 0x40, 0x3f, 0x10, 0x0f,
    0x08, 0x07, 0x04, 0x03, 0x02, 0x20, 0x60, 0xa0, 0xe0, 0xc0,
    0xee, 0xf0, 0xfe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0x55, 0xaa,
};

const std::uint16_t kInterest16[] = {
    0x0001, 0x0002, 0x007f, 0x0080, 0x00ff, 0x0100, 0x3fff, 0x4000,
    0x7fff, 0x8000, 0xfffe, 0xffff, 0x0040, 0x0100, 0x0fff, 0x1000,
};

const std::uint32_t kInterest32[] = {
    0x00000001, 0x00000002, 0x0000007f, 0x00000080, 0x000000ff,
    0x00000100, 0x00003fff, 0x00004000, 0x00007fff, 0x00008000,
    0x0000ffff, 0x00010000, 0x3fffffff, 0x40000000, 0x7fffffff,
    0x80000000, 0xfffffffe, 0xffffffff,
};

const std::int64_t kArith8[] = {1, 2, 4, 8, 16, 32, 64};
const std::int64_t kArith16[] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024};
const std::int64_t kArith32[] = {1, 256, 65536, 0x10000, 0x1000000};

}  // namespace

const std::vector<std::uint8_t>& Mutator::interest_bytes() noexcept {
    static const std::vector<std::uint8_t> v(std::begin(kInterest8),
                                             std::end(kInterest8));
    return v;
}

const std::vector<std::uint16_t>& Mutator::interest_words() noexcept {
    static const std::vector<std::uint16_t> v(std::begin(kInterest16),
                                              std::end(kInterest16));
    return v;
}

std::uint64_t Mutator::next_u64() noexcept {
    rng_ += 0x9E3779B97F4A7C15ull;
    std::uint64_t z = rng_;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

std::size_t Mutator::next_below(std::size_t n) noexcept {
    if (n == 0) {
        return 0;
    }
    return static_cast<std::size_t>(next_u64() % n);
}

Mutator::Mutator() noexcept {
    rng_ = 0x123456789ABCDEFull ^
          (static_cast<std::uint64_t>(
               reinterpret_cast<std::uintptr_t>(&rng_))
           << 1);
}

std::size_t Mutator::deterministic(const std::vector<std::uint8_t>& base,
                                   EmitFn emit, void* ctx) noexcept {
    if (base.empty()) {
        return 0;
    }
    std::size_t emitted = 0;
    auto candidate = [&](const std::vector<std::uint8_t>& v) {
        emit(v.data(), v.size(), ctx);
        ++emitted;
    };

    // Bit-flip stage: every bit of every byte.
    for (std::size_t i = 0; i < base.size(); ++i) {
        for (unsigned bit = 0; bit < 8; ++bit) {
            std::vector<std::uint8_t> v = base;
            v[i] ^= static_cast<std::uint8_t>(1u << bit);
            candidate(v);
        }
    }
    // Byte complement.
    for (std::size_t i = 0; i < base.size(); ++i) {
        std::vector<std::uint8_t> v = base;
        v[i] = static_cast<std::uint8_t>(~v[i]);
        candidate(v);
    }
    // Byte arithmetic.
    for (std::size_t i = 0; i < base.size(); ++i) {
        for (std::int64_t d : kArith8) {
            std::vector<std::uint8_t> v = base;
            v[i] = static_cast<std::uint8_t>(v[i] + d);
            candidate(v);
            v = base;
            v[i] = static_cast<std::uint8_t>(v[i] - d);
            candidate(v);
        }
    }
    // Byte interest values.
    for (std::size_t i = 0; i < base.size(); ++i) {
        for (std::uint8_t iv : kInterest8) {
            std::vector<std::uint8_t> v = base;
            v[i] = iv;
            candidate(v);
        }
    }
    // Word arithmetic and interest, where a word fits.
    for (std::size_t i = 0; i + 2 <= base.size(); i += 2) {
        std::uint16_t w = 0;
        std::memcpy(&w, base.data() + i, 2);
        for (std::int64_t d : kArith16) {
            std::vector<std::uint8_t> v = base;
            const std::uint16_t nw = static_cast<std::uint16_t>(w + d);
            std::memcpy(v.data() + i, &nw, 2);
            candidate(v);
            v = base;
            const std::uint16_t nw2 = static_cast<std::uint16_t>(w - d);
            std::memcpy(v.data() + i, &nw2, 2);
            candidate(v);
        }
        for (std::uint16_t iv : kInterest16) {
            std::vector<std::uint8_t> v = base;
            std::memcpy(v.data() + i, &iv, 2);
            candidate(v);
        }
    }
    // Dword arithmetic and interest.
    for (std::size_t i = 0; i + 4 <= base.size(); i += 4) {
        std::uint32_t w = 0;
        std::memcpy(&w, base.data() + i, 4);
        for (std::int64_t d : kArith32) {
            std::vector<std::uint8_t> v = base;
            const std::uint32_t nw = static_cast<std::uint32_t>(w + d);
            std::memcpy(v.data() + i, &nw, 4);
            candidate(v);
            v = base;
            const std::uint32_t nw2 = static_cast<std::uint32_t>(w - d);
            std::memcpy(v.data() + i, &nw2, 4);
            candidate(v);
        }
        for (std::uint32_t iv : kInterest32) {
            std::vector<std::uint8_t> v = base;
            std::memcpy(v.data() + i, &iv, 4);
            candidate(v);
        }
    }
    // Dictionary stage: try each token at every offset, both overwriting
    // (same length where it fits) and inserting (grows the input). This
    // is what finds format-critical values -- magic numbers, section
    // names, shell markers -- that blind mutation would take forever to
    // rediscover.
    for (const auto& token : dict_) {
        if (token.empty()) {
            continue;
        }
        for (std::size_t i = 0; i < base.size(); ++i) {
            if (i + token.size() <= base.size()) {
                std::vector<std::uint8_t> v = base;
                std::copy(token.begin(), token.end(),
                          v.begin() + static_cast<std::ptrdiff_t>(i));
                candidate(v);
            }
            // Insert at i (kept short: a handful of offsets per token
            // keeps the deterministic stage from exploding combinatorially).
            if (i < 8 && base.size() + token.size() <= 64 * 1024) {
                std::vector<std::uint8_t> v = base;
                v.insert(v.begin() + static_cast<std::ptrdiff_t>(i),
                         token.begin(), token.end());
                candidate(v);
            }
        }
    }
    return emitted;
}

void Mutator::havoc(const std::vector<std::uint8_t>& base,
                    const std::vector<std::uint8_t>& other,
                    std::vector<std::uint8_t>& out) noexcept {
    out = base;
    if (out.empty()) {
        return;
    }
    // Possibly splice from the other input first.
    if (!other.empty() && next_below(4) == 0) {
        const std::size_t cut = next_below(std::min(out.size(), other.size()));
        std::memcpy(out.data() + cut, other.data() + cut,
                    std::min(out.size() - cut, other.size() - cut));
    }
    // 1..8 random edits.
    const std::size_t edits = 1 + next_below(8);
    for (std::size_t e = 0; e < edits; ++e) {
        const std::size_t pos = next_below(out.size());
        switch (next_below(7)) {
        case 0:  // bit flip
            out[pos] ^= static_cast<std::uint8_t>(1u << next_below(8));
            break;
        case 1:  // random byte set
            out[pos] = static_cast<std::uint8_t>(next_u64());
            break;
        case 2:  // byte arithmetic
            out[pos] = static_cast<std::uint8_t>(
                out[pos] + static_cast<std::int8_t>(next_below(36) - 18));
            break;
        case 3:  // byte complement
            out[pos] = static_cast<std::uint8_t>(~out[pos]);
            break;
        case 4:  // block copy (a random block over a random offset)
            if (out.size() > 1) {
                const std::size_t len =
                    1 + next_below(std::min<std::size_t>(16, out.size()));
                const std::size_t src = next_below(out.size() - len + 1);
                const std::size_t dst = next_below(out.size() - len + 1);
                std::memmove(out.data() + dst, out.data() + src, len);
            }
            break;
        case 5:  // block delete
            if (out.size() > 1) {
                const std::size_t len = 1 + next_below(out.size());
                out.erase(out.begin() + static_cast<std::ptrdiff_t>(pos),
                          out.begin() +
                              static_cast<std::ptrdiff_t>(
                                  std::min(pos + len, out.size())));
                if (out.empty()) {
                    out.push_back(0);
                }
            }
            break;
        case 6:  // block insert
            if (out.size() < 512) {
                const std::size_t len = 1 + next_below(16);
                std::vector<std::uint8_t> chunk(len);
                for (std::uint8_t& b : chunk) {
                    b = static_cast<std::uint8_t>(next_u64());
                }
                out.insert(out.begin() + static_cast<std::ptrdiff_t>(pos),
                           chunk.begin(), chunk.end());
            }
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Campaign
// ---------------------------------------------------------------------------

// The campaign state lives behind a plain struct so the deterministic
// stage's C-style callback can reach it through the context pointer --
// the callback is a function pointer, not a capture.
struct Campaign {
    Stats st;
    Corpus corpus;
    Mutator mut;
    TargetFn target;
    void* ctx;
    std::size_t max_runs;
    std::size_t bitmap_bits;
    std::vector<Input>* crashes;
};

namespace {

bool campaign_dedup(Campaign& cam, std::uint64_t at) noexcept {
    for (const Input& c : *cam.crashes) {
        if (c.crash_at == at) {
            return true;
        }
    }
    return false;
}

void campaign_note(Campaign& cam, const TargetResult& tr,
                   std::vector<std::uint8_t> data,
                   std::vector<std::uint64_t> edges,
                   std::size_t distinct) noexcept {
    Input in;
    in.data = std::move(data);
    in.edge_ids = std::move(edges);
    in.edges = distinct;
    in.crash = tr.crash;
    in.crash_at = tr.crash_at;
    in.crash_name = tr.crash_name;
    if (tr.crash && !campaign_dedup(cam, tr.crash_at)) {
        cam.crashes->push_back(in);
        ++cam.st.crashes;
    }
    if (cam.corpus.add(in)) {
        ++cam.st.new_edges;
    }
    cam.st.corpus_size = cam.corpus.size();
}

void campaign_emit(const std::uint8_t* d, std::size_t n, void* c) noexcept {
    auto& cam = *static_cast<Campaign*>(c);
    if (cam.st.runs >= cam.max_runs) {
        return;
    }
    ++cam.st.runs;
    ++cam.st.deterministic_runs;
    Coverage cov(cam.bitmap_bits);
    const TargetResult tr = cam.target(d, n, cov, cam.ctx);
    campaign_note(cam, tr, std::vector<std::uint8_t>(d, d + n),
                  cov.take_edges(), cov.distinct());
}

}  // namespace

Stats fuzz(const std::vector<std::uint8_t>& seed, TargetFn target, void* ctx,
           std::size_t max_runs, std::size_t bitmap_bits,
           std::size_t max_corpus, std::vector<Input>& crashes) noexcept {
    Campaign cam;
    cam.target = target;
    cam.ctx = ctx;
    cam.max_runs = max_runs;
    cam.bitmap_bits = bitmap_bits;
    cam.crashes = &crashes;
    cam.corpus = Corpus(max_corpus);

    if (seed.empty()) {
        return cam.st;
    }

    // Seed the corpus with the initial input.
    {
        Coverage cov(bitmap_bits);
        const TargetResult tr = target(seed.data(), seed.size(), cov, ctx);
        Input in;
        in.data = seed;
        in.edge_ids = cov.take_edges();
        in.edges = cov.distinct();
        in.crash = tr.crash;
        in.crash_at = tr.crash_at;
        in.crash_name = tr.crash_name;
        if (tr.crash && !campaign_dedup(cam, tr.crash_at)) {
            crashes.push_back(in);
            ++cam.st.crashes;
        }
        cam.corpus.add(in);
        cam.st.corpus_size = cam.corpus.size();
    }

    while (cam.st.runs < max_runs) {
        Input base;
        if (!cam.corpus.pick(base)) {
            break;
        }

        // Deterministic stage on the picked input: every candidate runs
        // through the target and the corpus decides.
        cam.mut.deterministic(base.data, campaign_emit, &cam);

        // Havoc rounds, budgeted to a small multiple of the corpus size.
        const std::size_t havoc_budget = std::min<std::size_t>(
            16, std::max<std::size_t>(4, cam.corpus.size()));
        for (std::size_t h = 0; h < havoc_budget &&
                                cam.st.runs < max_runs;
             ++h) {
            ++cam.st.havoc_runs;
            ++cam.st.runs;
            const Input& other =
                cam.corpus.inputs()[cam.mut.next_below(cam.corpus.size())];
            std::vector<std::uint8_t> candidate;
            cam.mut.havoc(base.data, other.data, candidate);
            Coverage cov(bitmap_bits);
            const TargetResult tr =
                target(candidate.data(), candidate.size(), cov, ctx);
            campaign_note(cam, tr, std::move(candidate), cov.take_edges(),
                          cov.distinct());
        }
    }
    return cam.st;
}

}  // namespace occ::fuzz

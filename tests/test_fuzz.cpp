// Fuzz (coverage-guided fuzzing engine) tests.
//
// The star test is the guided search: a four-byte magic check where every
// comparison is an interest-table value, seeded with four zero bytes.
// Random search over that space is hopeless (2^32 candidates); the
// engine must find the crash through the coverage signal alone -- each
// byte that matches unlocks a new edge, the corpus keeps that input, and
// the next stage mutates it onward. The remaining tests pin the
// primitives: the coverage bitmap, the corpus's rare-edge retention and
// its full-capacity replacement, and the mutator's deterministic and
// havoc stages.

#include "occ/fuzz/fuzz.h"

#include <cstdio>
#include <cstring>

using namespace occ::fuzz;

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

// The guided-search target. Every comparison value is in the mutator's
// interest table, so each stage is reachable by byte replacement alone.
TargetResult magic_target(const std::uint8_t* data, std::size_t n,
                          Coverage& cov, void*) noexcept {
    cov.note(0, 1);
    if (n < 1 || data[0] != 0xFF) {
        return TargetResult{};
    }
    cov.note(1, 2);
    if (n < 2 || data[1] != 0xFE) {
        return TargetResult{};
    }
    cov.note(2, 3);
    if (n < 3 || data[2] != 0x40) {
        return TargetResult{};
    }
    cov.note(3, 4);
    if (n < 4 || data[3] != 0x3F) {
        return TargetResult{};
    }
    cov.note(4, 5);
    return TargetResult{true, 0x100000, "magic-hit"};
}

// A target that crashes on any byte equal to 0x41 (a one-byte magic): the
// trivial case for the mutator stages.
TargetResult one_byte_target(const std::uint8_t* data, std::size_t n,
                             Coverage& cov, void*) noexcept {
    cov.note(0, 1);
    if (n == 0 || data[0] != 0x41) {
        return TargetResult{};
    }
    cov.note(1, 2);
    return TargetResult{true, 0x200000, "one-byte"};
}

void test_coverage() {
    Coverage c(16);
    c.note(1, 2);
    check(c.last_was_new(), "cov: first edge is new");
    c.note(1, 2);
    check(!c.last_was_new(), "cov: same edge is not new");
    check(c.distinct() == 1, "cov: distinct count");
    c.note(3, 4);
    check(c.distinct() == 2, "cov: second edge counted");
    const auto edges = c.take_edges();
    check(edges.size() == 2, "cov: take_edges returns both");
    check(c.take_edges().empty(), "cov: take_edges consumes");
}

void test_corpus() {
    Corpus c(4);

    Input a;
    a.data = {0xAA};
    a.edge_ids = {11, 12};
    check(c.add(a), "corpus: new edges kept");
    check(c.size() == 1, "corpus: one entry");

    // Same edges: not new, not kept.
    Input dup;
    dup.data = {0xBB};
    dup.edge_ids = {11, 12};
    check(!c.add(dup), "corpus: no new edges rejected");

    // A new edge is kept.
    Input b;
    b.data = {0xCC};
    b.edge_ids = {13};
    check(c.add(b), "corpus: second input kept");
    check(c.size() == 2, "corpus: two entries");

    // Fill to capacity, then a new-edge input replaces the weakest.
    Input c1;
    c1.data = {0x01};
    c1.edge_ids = {21, 22, 23};
    check(c.add(c1), "corpus: fill 3");
    Input c2;
    c2.data = {0x02};
    c2.edge_ids = {31, 32, 33, 34};
    check(c.add(c2), "corpus: fill 4");
    check(c.size() == 4, "corpus: at capacity");

    Input fresh;
    fresh.data = {0x77};
    fresh.edge_ids = {41};
    check(c.add(fresh), "corpus: full but new edges kept");
    check(c.size() == 4, "corpus: capacity held");

    // Picking works and returns one of the entries.
    Input picked;
    check(c.pick(picked), "corpus: pick works");
    check(!picked.data.empty(), "corpus: picked has data");
}

void test_mutator_deterministic() {
    Mutator m;
    std::size_t emitted = 0;
    const std::vector<std::uint8_t> base = {0x00, 0x00};
    emitted = m.deterministic(
        base, [](const std::uint8_t*, std::size_t, void* ctx) noexcept {
            ++*static_cast<std::size_t*>(ctx);
        },
        &emitted);
    check(emitted > 100, "mut: deterministic emits many candidates");
    check(m.interest_bytes().size() >= 10, "mut: interest table present");
}

void test_mutator_dict() {
    Mutator m;
    m.set_dict({{'M', 'Z'}, {'P', 'E'}});
    const std::vector<std::uint8_t> base = {0x41, 0x42, 0x43};
    struct Seen {
        std::size_t emitted = 0;
        bool mz = false;
        bool pe = false;
    } seen;
    m.deterministic(
        base,
        [](const std::uint8_t* d, std::size_t n, void* ctx) noexcept {
            auto* s = static_cast<Seen*>(ctx);
            ++s->emitted;
            for (std::size_t i = 0; i + 1 < n; ++i) {
                if (d[i] == 'M' && d[i + 1] == 'Z') {
                    s->mz = true;
                }
                if (d[i] == 'P' && d[i + 1] == 'E') {
                    s->pe = true;
                }
            }
        },
        &seen);
    check(seen.mz, "dict: MZ token reached as candidate");
    check(seen.pe, "dict: PE token reached as candidate");
    check(seen.emitted > 0, "dict: candidates emitted");
    check(m.dict().size() == 2, "dict: accessor returns tokens");
}

void test_mutator_havoc() {
    Mutator m;
    std::vector<std::uint8_t> out;
    const std::vector<std::uint8_t> base = {0x11, 0x22, 0x33, 0x44, 0x55};
    m.havoc(base, base, out);
    check(!out.empty(), "havoc: output nonempty");
    // Havoc keeps the length within a bounded range of the base.
    check(out.size() <= 512 + 5, "havoc: length bounded");
}

void test_guided_search() {
    // Seed: four zero bytes. The magic is {FF FE 40 3F}; each byte is an
    // interest value, so byte-replacement alone can unlock every stage.
    const std::vector<std::uint8_t> seed = {0x00, 0x00, 0x00, 0x00};
    std::vector<Input> crashes;
    const Stats st = fuzz(seed, magic_target, nullptr, 50000, 16, 128,
                          crashes);
    check(!crashes.empty(), "fuzz: guided search found the crash");
    if (!crashes.empty()) {
        check(crashes[0].crash_at == 0x100000, "fuzz: crash address right");
        check(crashes[0].crash_name == "magic-hit", "fuzz: crash name kept");
    }
    check(st.runs <= 50000, "fuzz: budget honored");
    check(st.new_edges >= 4, "fuzz: at least the four magic edges found");
}

void test_trivial_one_byte() {
    const std::vector<std::uint8_t> seed = {0x00, 0x00, 0x00, 0x00};
    std::vector<Input> crashes;
    const Stats st = fuzz(seed, one_byte_target, nullptr, 20000, 16, 64,
                          crashes);
    check(!crashes.empty(), "fuzz: one-byte magic found");
    check(st.crashes >= 1, "fuzz: crash stat counted");
}

}  // namespace

int main() {
    test_coverage();
    test_corpus();
    test_mutator_deterministic();
    test_mutator_dict();
    test_mutator_havoc();
    test_guided_search();
    test_trivial_one_byte();
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

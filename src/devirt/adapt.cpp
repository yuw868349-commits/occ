// Adaptation of the lift engine to a VM that does not record its own
// conventions, plus a purely static (trace-free) lift of the handler
// graph. The two jobs share one principle: evidence or refuse. Nothing
// here hard-codes a register name or guesses a dispatch target.
//
// == infer_convention: which register plays which role ==
//
// A variant built on a different register assignment produces a trace
// whose sampled fields move differently from the engine's own. The
// evidence is the movement of each sampled field across adjacent
// dispatches: the stack and the cursor move in small steps every
// dispatch, the table and engine bases stay put, and a table base being
// switched jumps large. Distinguishing the two small-stepping registers
// leans on what a real VM does: the virtual stack pointer steps in
// qword-sized, eight-aligned increments (slots are qwords), while the
// bytecode cursor steps by instruction sizes that are frequently not
// multiples of eight. The method measures, per field:
//
//   zero_frac    share of dispatches that leave it alone
//   small_frac   share of dispatches that move it by <= 64 bytes
//   big_frac     share of dispatches that jump it by > 64 bytes
//   align8_frac  share of nonzero moves that are multiples of eight
//   mean_abs     mean magnitude of the nonzero moves
//
// and then assigns roles: the (expected two) fields with small_frac at
// least kMoverFrac are the stack/cursor pair, separated by an alignment
// margin (or a 2x magnitude fallback); the static fields (zero_frac at
// least kStaticFrac) hold the table base -- the one with the large jumps
// -- and the engine base, the most static of the rest, unique. Every
// role needs its measured margin; when the trace does not separate the
// roles the inference refuses (default convention, confident=false,
// notes explaining what could not be told apart). It never guesses.
//
// == lift_static: a fixpoint over resolvable dispatch edges ==
//
// The engine's own trace tells which handler runs when; without it the
// only ground truth is the image. The lift engine already turns the
// dispatcher's decrypt-and-jump pattern -- `mov rax,[rsi]; rol rax,n;
// add rsi,8; jmp rax` -- into a Dispatch transfer whose target is an
// expression over the bytecode. Bind those Code inputs to the actual
// image bytes at a known entry cursor and the expression evaluates to a
// concrete address: one handler's model provably names the next
// handler's entry. A worklist over handlers reaches a fixpoint, and the
// cursor is carried along the edges -- each handler's rsi_new, resolved
// under the same binding, becomes its successor's entry cursor -- so a
// stream of decrypt handlers chains naturally and a handler that leaves
// the cursor alone passes the cursor through. Everything the image
// cannot supply -- the stack pointer, a host register, an unknown, a
// load behind an unresolvable address -- leaves the target expression
// unbound, and the node is reported indirect and the lift incomplete:
// honest, never guessed. Budgets bound the worklist and the per-handler
// walk, and exhausting one is reported the same way.
//
// Both methods are thresholded by named constants so the behavior is
// auditable and the tests can construct traces that separate the roles.

#include "occ/devirt/adapt.h"

#include <cstdio>
#include <map>
#include <string>
#include <vector>

namespace occ::devirt::adapt {

namespace {

// ------------------------------------------------------------------ stats

// A "small step" for the movement pattern: the stack pointer and the
// bytecode cursor move by tens of bytes per dispatch at most; anything
// bigger is a jump (a table being switched, a handler list being
// relocated).
constexpr std::uint64_t kSmallStep = 64;

// A field is a *mover* (stack/cursor candidate) when at least half of
// the dispatches move it by a small step, and *static* (table/engine
// candidate) when at least three quarters of the dispatches leave it
// alone. The two thresholds are deliberately slack: a dispatcher that
// occasionally pushes the host stack must not disqualify that field
// from the static pool, and a cursor that stalls for a dispatch must
// not stop being a mover.
constexpr double kMoverFrac = 0.5;
constexpr double kStaticFrac = 0.75;

// The margin that separates the stack from the cursor. Alignment is the
// primary signal (the stack steps in multiples of eight, the cursor in
// instruction sizes); magnitude is the fallback for an odd-slot engine.
constexpr double kAlignMargin = 0.2;
constexpr double kMagnitudeRatio = 2.0;

struct FieldStats {
    const char* name = nullptr;
    std::uint64_t transitions = 0;
    std::uint64_t nonzero = 0;
    std::uint64_t small = 0;     // 0 < |d| <= kSmallStep
    std::uint64_t big = 0;       // |d| > kSmallStep
    std::uint64_t aligned8 = 0;  // |d| % 8 == 0, nonzero moves only
    std::uint64_t sum_abs = 0;   // |d| summed over nonzero moves
    std::uint64_t max_abs = 0;

    [[nodiscard]] double frac_zero() const {
        if (transitions == 0) {
            return 0.0;
        }
        return static_cast<double>(transitions - nonzero) /
               static_cast<double>(transitions);
    }
    [[nodiscard]] double frac_small() const {
        if (transitions == 0) {
            return 0.0;
        }
        return static_cast<double>(small) / static_cast<double>(transitions);
    }
    [[nodiscard]] double frac_big() const {
        if (transitions == 0) {
            return 0.0;
        }
        return static_cast<double>(big) / static_cast<double>(transitions);
    }
    [[nodiscard]] double frac_aligned8() const {
        if (nonzero == 0) {
            return 0.0;
        }
        return static_cast<double>(aligned8) / static_cast<double>(nonzero);
    }
    [[nodiscard]] double mean_abs() const {
        if (nonzero == 0) {
            return 0.0;
        }
        return static_cast<double>(sum_abs) / static_cast<double>(nonzero);
    }
};

// Measures the movement of one sampled Row field across adjacent
// dispatches. The delta is the unsigned magnitude of the difference, so
// a cursor that counts down and a stack that grows up are measured the
// same way.
FieldStats stats_of(const std::vector<lift::Row>& rows, const char* name,
                    const std::uint64_t lift::Row::* field) {
    FieldStats s;
    s.name = name;
    s.transitions = rows.size() - 1;
    for (std::size_t i = 0; i + 1 < rows.size(); ++i) {
        const std::uint64_t a = rows[i].*field;
        const std::uint64_t b = rows[i + 1].*field;
        std::uint64_t d = 0;
        if (b >= a) {
            d = b - a;
        } else {
            d = a - b;
        }
        if (d == 0) {
            continue;
        }
        ++s.nonzero;
        if (d <= kSmallStep) {
            ++s.small;
        } else {
            ++s.big;
        }
        if (d % 8 == 0) {
            ++s.aligned8;
        }
        s.sum_abs += d;
        if (d > s.max_abs) {
            s.max_abs = d;
        }
    }
    return s;
}

}  // namespace

InferResult infer_convention(const std::vector<lift::Row>& rows) {
    InferResult out;
    if (rows.size() < 2) {
        out.notes.push_back(
            "fewer than two dispatches: no movement to measure");
        return out;
    }

    // The five registers the trace samples. Which physical register each
    // role lands on is decided by the measurements below, never by the
    // register's name.
    const char* const names[5] = {"rbp", "rsi", "rdi", "rsp", "r12"};
    const std::uint64_t lift::Row::* const fields[5] = {
        &lift::Row::rbp, &lift::Row::rsi, &lift::Row::rdi,
        &lift::Row::rsp, &lift::Row::r12};
    FieldStats all[5];
    for (int i = 0; i < 5; ++i) {
        all[i] = stats_of(rows, names[i], fields[i]);
    }

    const FieldStats* movers[5] = {};
    const FieldStats* statics[5] = {};
    int n_movers = 0;
    int n_statics = 0;
    for (int i = 0; i < 5; ++i) {
        if (all[i].frac_small() >= kMoverFrac) {
            movers[n_movers++] = &all[i];
        }
        if (all[i].frac_zero() >= kStaticFrac) {
            statics[n_statics++] = &all[i];
        }
    }

    if (n_movers != 2) {
        out.notes.push_back(
            "expected exactly two small-stepping registers (the stack and "
            "the cursor), found " +
            std::to_string(n_movers));
        return out;
    }
    if (n_statics < 2) {
        out.notes.push_back(
            "expected at least two static registers (the table and engine "
            "bases), found " +
            std::to_string(n_statics));
        return out;
    }

    // Stack vs cursor: the more eight-aligned small-stepping register is
    // the stack (qword slots); the other is the cursor (instruction
    // sizes). Magnitude is the fallback when neither steps in multiples
    // of eight.
    const FieldStats* first = movers[0];
    const FieldStats* second = movers[1];
    const FieldStats* stack = first;
    const FieldStats* cursor = second;
    if (second->frac_aligned8() > first->frac_aligned8()) {
        stack = second;
        cursor = first;
    }
    bool separated =
        stack->frac_aligned8() - cursor->frac_aligned8() >= kAlignMargin;
    if (!separated &&
        stack->mean_abs() >= kMagnitudeRatio * cursor->mean_abs()) {
        separated = true;
    }
    if (!separated) {
        out.notes.push_back(
            "the two small-stepping registers move too alike to tell the "
            "stack pointer from the bytecode cursor");
        return out;
    }

    // Table vs engine: the static register with the large jumps is the
    // handler-table base (a VM switches tables by jumping the base); the
    // engine base is the most static of the rest, and must be unique for
    // the inference to commit to it.
    const FieldStats* table = nullptr;
    for (int i = 0; i < n_statics; ++i) {
        if (table == nullptr || statics[i]->frac_big() > table->frac_big()) {
            table = statics[i];
        }
    }
    if (table == nullptr || table->big == 0) {
        out.notes.push_back(
            "no static register makes large jumps: the handler-table base "
            "cannot be told apart from the engine base");
        return out;
    }
    const FieldStats* engine = nullptr;
    for (int i = 0; i < n_statics; ++i) {
        if (statics[i] == table) {
            continue;
        }
        if (engine == nullptr ||
            statics[i]->frac_zero() > engine->frac_zero()) {
            engine = statics[i];
        }
    }
    if (engine == nullptr) {
        out.notes.push_back(
            "only one static register besides the table base: the engine "
            "base is unidentifiable");
        return out;
    }
    for (int i = 0; i < n_statics; ++i) {
        if (statics[i] != table && statics[i] != engine &&
            statics[i]->frac_zero() == engine->frac_zero()) {
            out.notes.push_back(
                "two static registers share the top stillness: the engine "
                "base is ambiguous");
            return out;
        }
    }

    out.convention.stack = stack->name;
    out.convention.cursor = cursor->name;
    out.convention.table = table->name;
    out.convention.engine = engine->name;
    out.confident = true;
    out.notes.push_back(std::string("stack=") + stack->name +
                        " cursor=" + cursor->name + " table=" + table->name +
                        " engine=" + engine->name);
    return out;
}

namespace {

// ------------------------------------------------------------------ static

// The image addressed by virtual address. A read is a little-endian
// load of `width` bits from `va`; anything outside the image is unread,
// which is what makes an unresolvable target an honest indirect node
// instead of a guessed address.
struct Image {
    const std::uint8_t* p = nullptr;
    std::size_t n = 0;
    std::uint64_t base = 0;

    [[nodiscard]] bool contains(std::uint64_t va, std::size_t bytes) const {
        if (va < base) {
            return false;
        }
        const std::uint64_t off = va - base;
        return off <= n && bytes <= n - off;
    }
    [[nodiscard]] bool read(std::uint64_t va, unsigned width,
                            std::uint64_t* out) const {
        const std::size_t bytes = width / 8;
        if (!contains(va, bytes)) {
            return false;
        }
        std::uint64_t v = 0;
        const std::size_t off = static_cast<std::size_t>(va - base);
        for (std::size_t i = 0; i < bytes; ++i) {
            v |= static_cast<std::uint64_t>(p[off + i]) << (8 * i);
        }
        *out = v;
        return true;
    }
};

// The per-handler binding of the model's inputs to concrete values, for
// resolving dispatch targets and the next cursor. Only what the image
// and the carried cursor supply is bound; everything else stays unbound,
// and an expression that leans on an unbound input is unresolvable
// (reported, never guessed). Resolving an expression requires every
// input it reaches to be bound -- this is what keeps a `select` over an
// unknown condition from silently picking an arm, which `evaluate` alone
// would do by treating the unknown as zero.
struct StaticBinder {
    std::vector<std::uint64_t> values;
    std::vector<std::uint8_t> bound;
    explicit StaticBinder(const lift::Model& m)
        : values(m.inputs.size(), 0), bound(m.inputs.size(), 0) {}
    void bind(unsigned ordinal, std::uint64_t value) {
        if (ordinal < bound.size()) {
            values[ordinal] = value;
            bound[ordinal] = 1;
        }
    }
    [[nodiscard]] bool all_bound(const std::vector<unsigned>& ordinals) const {
        for (const unsigned o : ordinals) {
            if (o >= bound.size() || bound[o] == 0) {
                return false;
            }
        }
        return true;
    }
    [[nodiscard]] bool resolve(const expr::DAG& dag, expr::Id id,
                               std::uint64_t* out) const {
        if (id == expr::kNoId) {
            return false;
        }
        const std::vector<unsigned> ins = dag.inputs_of(id);
        if (!all_bound(ins)) {
            return false;
        }
        *out = dag.evaluate(id, values);
        return true;
    }
};

std::string hex_of(std::uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx",
                  static_cast<unsigned long long>(v));
    return std::string(buf);
}

}  // namespace

StaticLift lift_static(const std::uint8_t* image, std::size_t image_size,
                       std::uint64_t image_base, std::uint64_t entry_va,
                       const lift::Convention& convention,
                       const StaticOptions& options) {
    StaticLift out;
    out.complete = true;
    if (image == nullptr || image_size == 0) {
        out.complete = false;
        out.notes.push_back("empty image: nothing to lift");
        return out;
    }
    const Image img{image, image_size, image_base};

    // The worklist holds handler addresses to lift, in discovery order;
    // `node_of` maps an address to its CfgNode/Handler index so a
    // revisited handler terminates the fixpoint instead of looping.
    struct Task {
        std::uint64_t va = 0;
        std::size_t node = 0;
    };
    std::vector<Task> worklist;
    std::map<std::uint64_t, std::size_t> node_of;
    std::vector<bool> lifted;
    std::vector<bool> cursor_known;
    std::vector<std::uint64_t> cursor;

    const auto enqueue = [&](std::uint64_t va, bool ck, std::uint64_t cv) {
        if (node_of.find(va) != node_of.end()) {
            return;
        }
        const std::size_t idx = out.nodes.size();
        node_of[va] = idx;
        out.nodes.push_back(CfgNode{});
        out.nodes.back().va = va;
        out.handlers.emplace_back();
        lifted.push_back(false);
        cursor_known.push_back(ck);
        cursor.push_back(cv);
        worklist.push_back(Task{va, idx});
    };

    enqueue(entry_va, options.cursor_known, options.entry_cursor);

    while (!worklist.empty()) {
        if (options.max_handlers != 0 &&
            out.iterations >= options.max_handlers) {
            out.complete = false;
            out.notes.push_back(
                "handler budget exhausted: lifted " +
                std::to_string(out.iterations) + " handlers, more remained");
            break;
        }
        const Task t = worklist.back();
        worklist.pop_back();
        if (lifted[t.node]) {
            continue;
        }
        lifted[t.node] = true;
        ++out.iterations;
        CfgNode& node = out.nodes[t.node];

        if (!img.contains(t.va, 1)) {
            node.indirect = true;
            node.note = "handler entry is outside the image";
            out.complete = false;
            out.notes.push_back("handler at " + hex_of(t.va) +
                                " is outside the image");
            continue;
        }

        // One model per handler: the DAG is this handler's alone, so the
        // target expression resolves against this handler's own inputs.
        lift::Model model;
        model.convention = convention;
        lift::Handler& h = out.handlers[t.node];
        h = lift::summarize(model, image, image_size, image_base, t.va,
                            options.max_instructions_per_handler);

        // Bind what the image and the carried cursor can supply. Code
        // inputs read at the entry cursor plus their displacement; Image
        // inputs read at their own address; a Load input reads through
        // its (resolved) address; the cursor register holds the carried
        // cursor. Everything else -- the stack pointer, host registers,
        // slots, unknowns -- stays unbound.
        StaticBinder b(model);
        const bool cursor_ok = cursor_known[t.node];
        for (std::size_t k = 0; k < model.inputs.size(); ++k) {
            const lift::Model::Input& in = model.inputs[k];
            const unsigned ord = static_cast<unsigned>(k);
            switch (in.kind) {
            case lift::Model::Input::Kind::Reg:
                if (cursor_ok && in.name == convention.cursor) {
                    b.bind(ord, cursor[t.node]);
                }
                break;
            case lift::Model::Input::Kind::Code:
                if (cursor_ok) {
                    std::uint64_t v = 0;
                    if (img.read(cursor[t.node] +
                                     static_cast<std::uint64_t>(in.disp),
                                 in.width, &v)) {
                        b.bind(ord, v);
                    }
                }
                break;
            case lift::Model::Input::Kind::Image: {
                std::uint64_t v = 0;
                if (img.read(in.va, in.width, &v)) {
                    b.bind(ord, v);
                }
                break;
            }
            case lift::Model::Input::Kind::Load: {
                std::uint64_t at = 0;
                if (b.resolve(model.dag, in.addr, &at)) {
                    std::uint64_t v = 0;
                    if (img.read(at, in.width, &v)) {
                        b.bind(ord, v);
                    }
                }
                break;
            }
            case lift::Model::Input::Kind::Slot:
            case lift::Model::Input::Kind::Unknown:
                break;
            }
        }

        // The next handler's entry cursor is this handler's rsi_new under
        // the same binding: a decrypt handler hands its successor the
        // advanced cursor, a handler that leaves the cursor alone passes
        // it through, and an unresolvable rsi_new leaves the successor's
        // code inputs unbound (which the successor then reports honestly).
        std::uint64_t next_cursor = 0;
        const bool next_known =
            cursor_ok && b.resolve(model.dag, h.rsi_new, &next_cursor);

        if (h.transfer == lift::Handler::Transfer::Dispatch) {
            std::uint64_t target = 0;
            if (b.resolve(model.dag, h.target_expr, &target)) {
                node.successors.push_back(target);
                enqueue(target, next_known, next_cursor);
            } else {
                node.indirect = true;
                node.note = "dispatch target is not resolvable statically";
                out.complete = false;
                out.notes.push_back("handler at " + hex_of(t.va) +
                                    ": dispatch target not resolvable");
            }
        } else if (h.transfer == lift::Handler::Transfer::Return) {
            node.note = "return: the VM exits here";
        } else if (h.transfer == lift::Handler::Transfer::Call) {
            node.indirect = true;
            node.note =
                "call out of the VM: the resume point is not statically "
                "known";
            out.complete = false;
            out.notes.push_back("handler at " + hex_of(t.va) +
                                ": call out of the VM");
        } else {
            node.indirect = true;
            node.note = h.modeled ? "transfer unknown" : h.reason;
            out.complete = false;
            out.notes.push_back("handler at " + hex_of(t.va) + ": " +
                                node.note);
        }
    }
    return out;
}

}  // namespace occ::devirt::adapt

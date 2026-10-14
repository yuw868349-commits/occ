// Rebuilding VM handler models as linear IR, and certifying the rebuild.
// See include/occ/devirt/codegen.h for the interface contract and the
// design rationale; this file is the implementation.
//
// The pipeline is three layers, each kept deliberately dumb.
//
//  1. rebuild -- instruction selection. Every effect of the lift Handler
//     (each write's value, each computed write's address, rbp_new, rsi_new,
//     the dispatch target) is an expression over the model's DAG. The
//     emitter walks each effect expression bottom-up and materializes every
//     DAG node into a 64-bit scratch register exactly once: constants
//     become immediate operands, slot/code/image reads become memory
//     operands (fused into the consuming instruction where the widths
//     agree), register inputs are the entry registers themselves, and every
//     operation becomes one instruction with the operands it already has.
//     Because the DAG is hash-consed, two effects that share a node share
//     its register -- that is the whole of the common-subexpression
//     elimination, and it is why "at most once" is free. Dead code dies by
//     construction: only nodes reachable from an effect are ever visited.
//     The selector is explicitly not optimal (instruction selection over
//     DAGs is NP-hard and the effects are tiny); it is correct and
//     readable, and the next layer proves the correctness claim.
//
//  2. emit_asm -- rendering. One instruction per line, Intel syntax, a
//     comment header naming the handler VA, the modeled flag, the write
//     count and the transfer kind. Purely textual; no semantics live here.
//
//  3. verify -- the certificate. A small symbolic interpreter executes the
//     IR over the model's entry state: registers hold DAG expression ids
//     (rbp/rsi start as the model's entry-pointer inputs), memory reads
//     resolve to the model's inputs -- a slot read at [rbp+d] is the
//     vst[+d] input, [rsi+d] is code[+d], an absolute address is img[va],
//     a computed address is the matching load input -- unless an earlier IR
//     store wrote the same cell, in which case the stored expression is
//     read back (byte-composed for partial stores). Each instruction then
//     builds the DAG node its semantics call for, so the simulated effects
//     are expressions again. Every simulated effect is compared against the
//     Handler's claim with prove_equivalent (the ring layer answers pure
//     arithmetic without search; the bit-blaster proves the rest; a budget
//     exhaustion is reported unproven, never as "different"). ok is true
//     only when every comparison was proved.
//
// Where the model cannot name a value -- an unknown input, a kNoId write
// value, an address it could not compute -- the rebuild emits what it can
// and records a note, and verify reports the missing or diverging effect as
// a failure: the certificate is allowed to say "unproven", never to wave a
// gap through.
//
// Semantics the simulator and the emitter agree on, stated once:
//   - Registers are 64-bit and always hold zero-extended values; memory
//     operands carry an access width and reads zero-extend.
//   - Arithmetic truncates to the destination width; sub-64-bit DAG nodes
//     are emitted as a 64-bit operation followed by an explicit mask, so a
//     register's high bits are never garbage.
//   - Shifts follow the DAG's semantics (amount at or past the width: zero
//     for shl/shr, sign-fill for sar). Generated code only shifts by
//     literal amounts, where hardware agrees; a symbolic amount at or past
//     the width on a sub-64-bit node is emitted with a mask and noted as an
//     approximation -- the miter flags it honestly if it ever diverges.
//   - A select is expanded branchlessly as (a & -c) | (b & ~-c) for a 1-bit
//     condition c; comparisons are expanded into arithmetic (see
//     materialize_cmp_*). The expansions are exact and the miter proves
//     them.
//   - Cmp/Jcc have no flag model (flags are not among the claimed effects);
//     the simulator treats them as effect-free and rebuild never emits them.
//
// The scratch pool excludes every register that is an entry input of the
// model, plus rbp/rsi/rsp, so a temp never clobbers a live entry value.
// On exhaustion the oldest temp is evicted and its cached node recomputed
// on demand -- a linear-scan allocator; more instructions, same semantics.

#include "occ/devirt/codegen.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace occ::devirt::codegen {

// ------------------------------------------------------------- helpers

// The register a model input stands for: kind==Reg inputs carry the name
// directly; kind==Unknown inputs carry it inside `unk[NAME]#k` (lift's
// disclosure that the walk could not model the value but knows which
// register it is -- the cpuid clobbers in the junk fixture). Both must map
// to the same register in the rebuild and in the simulator, otherwise the
// pointers and the dispatch target of an unmodeled handler cannot be
// reproduced. Returns the empty string for every other input kind.
std::string reg_name_from_input(const lift::Model::Input& in) {
    if (in.kind == lift::Model::Input::Kind::Reg) {
        return in.name;
    }
    if (in.kind == lift::Model::Input::Kind::Unknown) {
        constexpr const char* kPrefix = "unk[";
        if (in.name.compare(0, 4, kPrefix) == 0) {
            const std::size_t close = in.name.find("]#");
            if (close != std::string::npos) {
                return in.name.substr(4, close - 4);
            }
        }
    }
    return "";
}

// The model input that is the entry value of register `name`, or kNoId.
expr::Id entry_reg_id(const lift::Model& model, const std::string& name) {
    for (const lift::Model::Input& in : model.inputs) {
        if (reg_name_from_input(in) == name) {
            return in.id;
        }
    }
    return expr::kNoId;
}

namespace {

// ------------------------------------------------------------- helpers

std::uint64_t mask_of(unsigned width) {
    if (width >= 64) {
        return ~std::uint64_t{0};
    }
    return (std::uint64_t{1} << width) - 1;
}

// The aligned 8-byte displacement containing `d`; the virtual stack is
// addressed a byte at a time but its inputs are keyed by cell.
std::int64_t align8(std::int64_t d) { return d & ~std::int64_t{7}; }

Operand make_reg(const std::string& reg, unsigned width = 64) {
    Operand o;
    o.kind = Operand::Kind::Reg;
    o.reg = reg;
    o.width = width;
    return o;
}
Operand make_imm(std::uint64_t imm, unsigned width) {
    Operand o;
    o.kind = Operand::Kind::Imm;
    o.imm = imm;
    o.width = width;
    return o;
}
Operand make_slot(std::int64_t disp, unsigned width) {
    Operand o;
    o.kind = Operand::Kind::Slot;
    o.disp = disp;
    o.width = width;
    return o;
}
Operand make_mem(const std::string& base, std::int64_t disp, unsigned width) {
    Operand o;
    o.kind = Operand::Kind::Mem;
    o.reg = base;
    o.disp = disp;
    o.width = width;
    return o;
}

// The model input whose DAG node is `id`, or nullptr.
const lift::Model::Input* input_by_id(const lift::Model& m, expr::Id id) {
    for (const lift::Model::Input& in : m.inputs) {
        if (in.id == id) {
            return &in;
        }
    }
    return nullptr;
}

const char* transfer_name(lift::Handler::Transfer t) {
    switch (t) {
    case lift::Handler::Transfer::Unknown:  return "unknown";
    case lift::Handler::Transfer::Dispatch: return "dispatch";
    case lift::Handler::Transfer::Return:   return "return";
    case lift::Handler::Transfer::Call:     return "call";
    }
    return "?";
}

// ------------------------------------------------------------ emitter

// Bottom-up expression-to-IR selector. See the file comment; the state here
// is the temp pool, the per-node cache (node id -> the operand that names
// its value; op nodes always name a register), and the notes about what
// could not be expressed.
struct Emitter {
    const lift::Model* m = nullptr;
    std::vector<Insn>* out = nullptr;
    expr::Id entry_rbp = expr::kNoId;
    expr::Id entry_rsi = expr::kNoId;
    std::vector<std::string> temps;
    std::vector<bool> temp_used;
    std::vector<std::string> alloc_order;
    std::vector<std::pair<expr::Id, Operand>> cache;
    // use_count[id]: how many consumers a DAG node has (sibling nodes plus
    // effect roots). A count of one makes destructive in-place reuse safe.
    std::vector<std::uint32_t> use_count;
    // reg_owner[reg]: the node id whose value currently lives in the
    // scratch register (kNoId when unclaimed). Cache hits re-check this:
    // a recycled register must never be served for an older node.
    std::map<std::string, expr::Id> reg_owner;
    // Pinned registers: values that must survive the materialization of a
    // sibling subtree (e.g. a linear accumulation chain). fresh_temp and
    // fresh_temps never recycle a pinned register, so the accumulator of a
    // byte-composition chain stays alive for the whole chain without being
    // re-emitted at every step.
    std::vector<std::string> pins;
    bool is_pinned(const std::string& r) const {
        for (const std::string& p : pins) {
            if (p == r) {
                return true;
            }
        }
        return false;
    }
    std::vector<std::string> notes;

    Emitter(const lift::Model& model, const Options& /*options*/,
            std::vector<Insn>* insns)
        : m(&model), out(insns) {
        entry_rbp = entry_reg_id(model, "rbp");
        entry_rsi = entry_reg_id(model, "rsi");
        // Scratch registers: everything except the VM's own pointers and
        // whatever is an entry input of the model.
        const std::vector<std::string> candidates = {
            "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
            "rax", "rcx", "rdx", "rdi", "rbx"};
        for (const std::string& r : candidates) {
            bool entry = false;
            for (const lift::Model::Input& in : model.inputs) {
                if (reg_name_from_input(in) == r) {
                    entry = true;
                    break;
                }
            }
            if (entry || r == "rbp" || r == "rsi" || r == "rsp") {
                continue;
            }
            temps.push_back(r);
            temp_used.push_back(false);
        }
    }

    void emit(Insn::Op op, Operand dst, Operand a, Operand b = {}) {
        if (dst.kind == Operand::Kind::Reg && is_pool_reg(dst.reg)) {
            // Every store into a scratch register destroys whatever node
            // was previously cached there. materialize() re-checks
            // reg_owner before serving a cache entry, so dropping the
            // ownership here is enough to keep a stale value from ever
            // being served again -- including values overwritten by raw
            // expansion emits (select arms, in-place ALU steps) that do
            // not go through the materialize() bookkeeping.
            reg_owner[dst.reg] = expr::kNoId;
        }
        Insn in;
        in.op = op;
        in.dst = dst;
        in.a = a;
        in.b = b;
        out->push_back(in);
    }

    std::string fresh_temp() {
        for (std::size_t i = 0; i < temps.size(); ++i) {
            if (!temp_used[i]) {
                temp_used[i] = true;
                alloc_order.push_back(temps[i]);
                reg_owner[temps[i]] = expr::kNoId;
                return temps[i];
            }
        }
        // Pool exhausted: evict the oldest allocation and forget the nodes
        // cached to it; a later use recomputes them into a fresh temp.
        // Pinned registers (live accumulator chains) are never recycled.
        for (std::size_t i = 0; i < alloc_order.size(); ++i) {
            if (!is_pinned(alloc_order[i])) {
                const std::string evicted = alloc_order[i];
                alloc_order.erase(alloc_order.begin() +
                                  static_cast<std::ptrdiff_t>(i));
                alloc_order.push_back(evicted);
                reg_owner[evicted] = expr::kNoId;
                for (auto it = cache.begin(); it != cache.end();) {
                    if (it->second.kind == Operand::Kind::Reg &&
                        it->second.reg == evicted) {
                        it = cache.erase(it);
                    } else {
                        ++it;
                    }
                }
                return evicted;
            }
        }
        notes.push_back("no scratch register available");
        return "";
    }

    // Allocates n scratch registers that are all distinct, so that no
    // materializer ever holds two intermediates in the same register.
    // Returns false when fewer than n registers can be obtained; callers
    // must abandon the node (a note is recorded) rather than emit wrong
    // code. The batch also drops every cache entry of the registers it
    // recycles; later materialize() calls recompute those nodes.
    bool fresh_temps(std::size_t n, std::vector<std::string>* regs_out) {
        regs_out->clear();
        if (n > temps.size()) {
            return false;
        }
        for (std::size_t i = 0; i < temps.size() && regs_out->size() < n; ++i) {
            if (!temp_used[i]) {
                temp_used[i] = true;
                alloc_order.push_back(temps[i]);
                reg_owner[temps[i]] = expr::kNoId;
                regs_out->push_back(temps[i]);
            }
        }
        while (regs_out->size() < n) {
            std::string evicted;
            for (const std::string& r : alloc_order) {
                bool taken = false;
                for (const std::string& b : *regs_out) {
                    if (b == r) {
                        taken = true;
                        break;
                    }
                }
                if (!taken && !is_pinned(r)) {
                    evicted = r;
                    break;
                }
            }
            if (evicted.empty()) {
                notes.push_back("scratch pool exhausted by a materializer");
                return false;
            }
            for (auto it = alloc_order.begin(); it != alloc_order.end(); ++it) {
                if (*it == evicted) {
                    alloc_order.erase(it);
                    break;
                }
            }
            alloc_order.push_back(evicted);
            reg_owner[evicted] = expr::kNoId;
            for (auto it = cache.begin(); it != cache.end();) {
                if (it->second.kind == Operand::Kind::Reg &&
                    it->second.reg == evicted) {
                    it = cache.erase(it);
                } else {
                    ++it;
                }
            }
            regs_out->push_back(evicted);
        }
        return true;
    }

    bool is_pool_reg(const std::string& r) const {
        for (const std::string& t : temps) {
            if (t == r) {
                return true;
            }
        }
        return false;
    }

    // Re-materializes an operand whose scratch register was recycled while
    // a sibling subtree was being built. Imm/memory operands and entry
    // registers (which are never recycled) pass through untouched.
    Operand ensure_valid(expr::Id id, Operand op) {
        if (op.kind == Operand::Kind::Reg && is_pool_reg(op.reg) &&
            reg_owner[op.reg] != id) {
            return materialize(id);
        }
        return op;
    }

    // Counts each node's consumers: other DAG nodes plus the effect roots
    // (write values/addresses, rbp_new, rsi_new, target). A node with a
    // single consumer can be computed in place and its register reused.
    void compute_use_counts(const lift::Handler& h) {
        const expr::DAG& dag = m->dag;
        use_count.assign(dag.size(), 0);
        for (expr::Id i = 1; i < dag.size(); ++i) {
            const expr::Node& n = dag.node(i);
            if (n.a != expr::kNoId) {
                use_count[n.a]++;
            }
            if (n.b != expr::kNoId) {
                use_count[n.b]++;
            }
            if (n.c != expr::kNoId) {
                use_count[n.c]++;
            }
        }
        for (const lift::Handler::Write& w : h.writes) {
            if (w.value != expr::kNoId) {
                use_count[w.value]++;
            }
            if (!w.to_slot && w.addr != expr::kNoId) {
                use_count[w.addr]++;
            }
        }
        if (h.rbp_new != expr::kNoId) {
            use_count[h.rbp_new]++;
        }
        if (h.rsi_new != expr::kNoId) {
            use_count[h.rsi_new]++;
        }
        if (h.target_expr != expr::kNoId) {
            use_count[h.target_expr]++;
        }
    }

    // Removes the cache entry that maps node `id` to a register, if any
    // (used before destructively overwriting that register).
    void drop_cache(expr::Id id) {
        for (auto it = cache.begin(); it != cache.end(); ++it) {
            if (it->first == id) {
                cache.erase(it);
                return;
            }
        }
    }

    // Turns any operand into a register: immediates move into one, memory
    // operands load from it (zero-extending).
    Operand force_reg(Operand a) {
        if (a.kind == Operand::Kind::Reg) {
            return a;
        }
        if (a.kind == Operand::Kind::None) {
            return a;
        }
        const std::string r = fresh_temp();
        if (r.empty()) {
            return {};
        }
        emit(Insn::Op::Mov, make_reg(r, 64), a);
        return make_reg(r, 64);
    }

    // ---- node materialization ---------------------------------------

    // The operand naming node `id`'s value. Every node is materialized at
    // most once (cache); op nodes always land in a register.
    Operand materialize(expr::Id id) {
        for (auto it = cache.begin(); it != cache.end(); ++it) {
            if (it->first != id) {
                continue;
            }
            if (it->second.kind == Operand::Kind::Reg &&
                is_pool_reg(it->second.reg) &&
                reg_owner[it->second.reg] != id) {
                // The register was recycled after this node was cached;
                // recompute the node into a fresh register.
                cache.erase(it);
                break;
            }
            return it->second;
        }
        const expr::DAG& dag = m->dag;
        const expr::Node& n = dag.node(id);
        Operand r;
        switch (n.op) {
        case expr::Op::Const:
            r = make_imm(n.imm, n.width);
            break;
        case expr::Op::Input:
            r = materialize_input(id);
            break;
        case expr::Op::Resize:
            r = materialize_resize(n);
            break;
        case expr::Op::Not:
        case expr::Op::Neg:
            r = materialize_unary(n);
            break;
        case expr::Op::Add:
        case expr::Op::Sub:
        case expr::Op::Mul:
        case expr::Op::And:
        case expr::Op::Or:
        case expr::Op::Xor:
        case expr::Op::Shl:
        case expr::Op::Shr:
        case expr::Op::Sar:
            r = materialize_binary(id, n);
            break;
        case expr::Op::Select:
            r = materialize_select(n);
            break;
        case expr::Op::CmpEQ:
            r = materialize_cmp_eq(n);
            break;
        case expr::Op::CmpULT:
            r = materialize_cmp_ult(n);
            break;
        case expr::Op::CmpSLT:
            r = materialize_cmp_slt(n);
            break;
        }
        cache.push_back(std::make_pair(id, r));
        if (r.kind == Operand::Kind::Reg && is_pool_reg(r.reg)) {
            reg_owner[r.reg] = id;
        }
        return r;
    }

    Operand materialize_input(expr::Id id) {
        const lift::Model::Input* in = input_by_id(*m, id);
        if (in == nullptr) {
            notes.push_back("input node without a model record");
            return {};
        }
        switch (in->kind) {
        case lift::Model::Input::Kind::Reg:
            return make_reg(in->name, 64);
        case lift::Model::Input::Kind::Slot:
            return make_slot(in->disp, in->width);
        case lift::Model::Input::Kind::Code:
            return make_mem("rsi", in->disp, in->width);
        case lift::Model::Input::Kind::Image:
            return make_mem("", static_cast<std::int64_t>(in->va),
                            in->width);
        case lift::Model::Input::Kind::Load: {
            // A read through a computed address: compute the address, then
            // read through it. The address may be any expression; it must
            // end in a register (an immediate address becomes one).
            Operand addr = materialize(in->addr);
            addr = force_reg(addr);
            if (addr.kind != Operand::Kind::Reg) {
                notes.push_back("load input with unmaterializable address");
                return {};
            }
            return make_mem(addr.reg, 0, in->width);
        }
        case lift::Model::Input::Kind::Unknown: {
            // A register whose value the walk could not model (`unk[rax]#k`).
            // The register name is still known, so the operand is that
            // register; the miter treats the value as fresh and matches the
            // model's own use of the same input.
            const std::string reg = reg_name_from_input(*in);
            if (!reg.empty()) {
                return make_reg(reg, 64);
            }
            notes.push_back("unknown input: " + in->name);
            return {};
        }
        }
        return {};
    }

    Operand materialize_resize(const expr::Node& n) {
        const unsigned src_width = m->dag.width(n.a);
        Operand a = materialize(n.a);
        if (a.kind == Operand::Kind::None) {
            return a;
        }
        if (n.width >= src_width) {
            // Widening: an immediate is already zero-extended, a register
            // already holds the zero-extended value; a memory read must go
            // through a register to widen.
            if (a.kind == Operand::Kind::Imm) {
                return make_imm(a.imm, n.width);
            }
            if (a.kind == Operand::Kind::Reg) {
                return make_reg(a.reg, 64);
            }
            const std::string r = fresh_temp();
            if (r.empty()) {
                return {};
            }
            emit(Insn::Op::Mov, make_reg(r, 64), a);
            return make_reg(r, 64);
        }
        // Narrowing: mask the low bits into a fresh register.
        if (a.kind == Operand::Kind::Imm) {
            return make_imm(a.imm & mask_of(n.width), n.width);
        }
        const std::string r = fresh_temp();
        if (r.empty()) {
            return {};
        }
        emit(Insn::Op::Mov, make_reg(r, 64), ensure_valid(n.a, a));
        emit(Insn::Op::And, make_reg(r, 64), make_imm(mask_of(n.width), 64));
        return make_reg(r, 64);
    }

    Operand materialize_unary(const expr::Node& n) {
        Operand a = materialize(n.a);
        if (a.kind == Operand::Kind::None) {
            return a;
        }
        const std::string r = fresh_temp();
        if (r.empty()) {
            return {};
        }
        emit(Insn::Op::Mov, make_reg(r, 64), ensure_valid(n.a, a));
        emit(n.op == expr::Op::Not ? Insn::Op::Not : Insn::Op::Neg,
             make_reg(r, 64), {});
        if (n.width < 64) {
            emit(Insn::Op::And, make_reg(r, 64),
                 make_imm(mask_of(n.width), 64));
        }
        return make_reg(r, 64);
    }

    // The shift amount when it is a literal; the DAG folds constant shifts
    // of constant bases, so a symbolic base with a literal amount stays a
    // node and lands here.
    bool shift_amount(const expr::Node& n, std::uint64_t* value) const {
        if (m->dag.valid(n.b) && m->dag.is_const(n.b)) {
            *value = m->dag.const_value(n.b);
            return true;
        }
        return false;
    }

    Operand materialize_binary(expr::Id id, const expr::Node& n) {
        Operand a = materialize(n.a);
        if (a.kind == Operand::Kind::None) {
            notes.push_back("binary op with unmaterializable operand");
            return {};
        }

        const bool shift = n.op == expr::Op::Shl || n.op == expr::Op::Shr ||
                           n.op == expr::Op::Sar;
        const Insn::Op op = [&] {
            switch (n.op) {
            case expr::Op::Add: return Insn::Op::Add;
            case expr::Op::Sub: return Insn::Op::Sub;
            case expr::Op::Mul: return Insn::Op::Mul;
            case expr::Op::And: return Insn::Op::And;
            case expr::Op::Or:  return Insn::Op::Or;
            case expr::Op::Xor: return Insn::Op::Xor;
            case expr::Op::Shl: return Insn::Op::Shl;
            case expr::Op::Shr: return Insn::Op::Shr;
            case expr::Op::Sar: return Insn::Op::Sar;
            default:            return Insn::Op::Mov;
            }
        }();

        std::uint64_t amount = 0;
        const bool literal_amount = shift && shift_amount(n, &amount);

        // In-place accumulation: when the left operand lives in a scratch
        // register and its node has no other consumer, the result can use
        // the same register (`op r, rhs` with r already holding the left
        // value). Linear chains such as the byte-composition or's then use
        // one register for the whole chain instead of one per node, which
        // keeps the live set far below the scratch pool size.
        Operand acc = a;
        if (a.kind != Operand::Kind::Reg || !is_pool_reg(a.reg) ||
            (std::size_t)n.a >= use_count.size() ||
            use_count[n.a] != 1) {
            acc = {};
        }

        // Pin the accumulator while the right operand materializes: the
        // right subtree may otherwise recycle the register that holds the
        // running value, forcing a full re-emission of the whole prefix
        // (exponential on a linear chain). With the pin, the chain stays
        // in place and the IR stays linear.
        const bool acc_pinned = acc.kind == Operand::Kind::Reg;
        if (acc_pinned) {
            pins.push_back(acc.reg);
        }
        Operand b = materialize(n.b);
        if (acc_pinned) {
            pins.pop_back();
        }
        if (b.kind == Operand::Kind::None) {
            notes.push_back("binary op with unmaterializable operand");
            return {};
        }

        // The right-hand side: an immediate folds into the instruction, a
        // variable shift count must live in a register (x86's count is CL),
        // and any other memory operand stays fused into the ALU form.
        Operand rhs;
        std::vector<std::string> batch;
        if (b.kind == Operand::Kind::Imm) {
            rhs = b;
        } else if (shift) {
            // The count register must survive the destination allocation:
            // grab both in one batch so they are distinct.
            const std::size_t need = acc.kind == Operand::Kind::Reg ? 1u : 2u;
            if (!fresh_temps(need, &batch)) {
                notes.push_back("shift count register unavailable");
                return {};
            }
            rhs = make_reg(batch[0], 64);
            emit(Insn::Op::Mov, make_reg(batch[0], 64), ensure_valid(n.b, b));
        } else {
            rhs = b;
        }

        // A register destination (fresh or the accumulator) must still hold
        // its value after all the allocations above; revalidate.
        if (acc.kind == Operand::Kind::Reg && reg_owner[acc.reg] == n.a) {
            const std::string r = acc.reg;
            drop_cache(n.a);
            emit(op, make_reg(r, 64), rhs);
            if (shift && n.width < 64) {
                // shl/shr of a sub-64-bit value: mask keeps the low bits
                // (shifts below the width are unaffected by the mask).
                emit(Insn::Op::And, make_reg(r, 64),
                     make_imm(mask_of(n.width), 64));
            } else if (!shift && n.width < 64) {
                emit(Insn::Op::And, make_reg(r, 64),
                     make_imm(mask_of(n.width), 64));
            }
            cache.push_back(std::make_pair(id, make_reg(r, 64)));
            reg_owner[r] = id;
            return make_reg(r, 64);
        }

        // The accumulator register was recycled while the right operand
        // materialized (or accumulation was never possible): use a fresh
        // destination. The shift count, if any, lives in batch[0]; a batch
        // of one only carried the count, so the destination is a new temp.
        std::string r;
        if (batch.size() >= 2) {
            r = batch[1];
        } else {
            r = fresh_temp();
        }
        if (r.empty()) {
            return {};
        }
        // Validate-then-use, one operand at a time: a re-validation may
        // allocate (recycling another register), so each operand is checked
        // again immediately before its own use instruction.
        emit(Insn::Op::Mov, make_reg(r, 64), ensure_valid(n.a, a));

        if (shift && literal_amount && amount >= n.width) {
            // At or past the width: shl/shr give zero, sar sign-fills
            // (the value is already in r from the Mov above).
            if (n.op == expr::Op::Sar) {
                if (n.width < 64) {
                    emit(Insn::Op::Shl, make_reg(r, 64),
                         make_imm(64 - n.width, 64));
                    emit(Insn::Op::Sar, make_reg(r, 64),
                         make_imm(63, 64));
                    emit(Insn::Op::And, make_reg(r, 64),
                         make_imm(mask_of(n.width), 64));
                } else {
                    emit(Insn::Op::Sar, make_reg(r, 64), make_imm(63, 64));
                }
            } else {
                // shl/shr at or past the width give zero; overwrite r.
                emit(Insn::Op::Mov, make_reg(r, 64), make_imm(0, 64));
            }
            return make_reg(r, 64);
        }

        if (shift && n.width < 64 && n.op == expr::Op::Sar) {
            // Arithmetic shift of a sub-64-bit value: move the sign bit to
            // bit 63 first, then shift, then keep the low width.
            emit(Insn::Op::Shl, make_reg(r, 64), make_imm(64 - n.width, 64));
            emit(Insn::Op::Sar, make_reg(r, 64), rhs);
            emit(Insn::Op::And, make_reg(r, 64),
                 make_imm(mask_of(n.width), 64));
        } else {
            // A shift count that had to be loaded lives in a batch register
            // that nothing recycles; every other rhs is re-validated right
            // here, next to its use.
            const Operand rhs_now = shift ? rhs : ensure_valid(n.b, rhs);
            emit(op, make_reg(r, 64), rhs_now);
            if (shift && n.width < 64) {
                // shl/shr of a sub-64-bit value: mask keeps the low bits
                // (shifts below the width are unaffected by the mask).
                emit(Insn::Op::And, make_reg(r, 64),
                     make_imm(mask_of(n.width), 64));
            } else if (!shift && n.width < 64) {
                emit(Insn::Op::And, make_reg(r, 64),
                     make_imm(mask_of(n.width), 64));
            }
        }
        return make_reg(r, 64);
    }

    Operand materialize_select(const expr::Node& n) {
        Operand c = materialize(n.c);
        if (c.kind == Operand::Kind::Imm) {
            // Constant conditions folded at construction; defensive only.
            return materialize(c.imm != 0 ? n.a : n.b);
        }
        Operand a = materialize(n.a);
        Operand b = materialize(n.b);
        if (c.kind == Operand::Kind::None || a.kind == Operand::Kind::None ||
            b.kind == Operand::Kind::None) {
            notes.push_back("select with unmaterializable operand");
            return {};
        }
        // Branchless: (a & -c) | (b & ~-c), exact for a 1-bit c. All three
        // scratch registers come from one batch so they are distinct, and
        // each operand is re-validated right before its own use.
        std::vector<std::string> t;
        if (!fresh_temps(3, &t)) {
            notes.push_back("select scratch registers unavailable");
            return {};
        }
        const std::string& rm = t[0];
        const std::string& rn = t[1];
        const std::string& ru = t[2];
        emit(Insn::Op::Mov, make_reg(rm, 64), ensure_valid(n.c, c));
        emit(Insn::Op::Neg, make_reg(rm, 64), {});
        emit(Insn::Op::Mov, make_reg(rn, 64), ensure_valid(n.a, a));
        emit(Insn::Op::And, make_reg(rn, 64), make_reg(rm, 64));
        emit(Insn::Op::Not, make_reg(rm, 64), {});
        emit(Insn::Op::Mov, make_reg(ru, 64), ensure_valid(n.b, b));
        emit(Insn::Op::And, make_reg(ru, 64), make_reg(rm, 64));
        emit(Insn::Op::Or, make_reg(rn, 64), make_reg(ru, 64));
        if (n.width < 64) {
            emit(Insn::Op::And, make_reg(rn, 64),
                 make_imm(mask_of(n.width), 64));
        }
        return make_reg(rn, 64);
    }

    // The comparison width: comparisons produce one bit but compare
    // operands of their natural widths; the sign bit for CmpSLT lives at
    // the wider operand's top, which is where bitblast reads it.
    unsigned cmp_operand_width(const expr::Node& n) const {
        const unsigned wa = m->dag.width(n.a);
        const unsigned wb = m->dag.width(n.b);
        return wa > wb ? wa : wb;
    }

    // eq(a,b) = ~(((a ^ b) | -(a ^ b)) >> 63) & 1
    Operand materialize_cmp_eq(const expr::Node& n) {
        Operand a = materialize(n.a);
        Operand b = materialize(n.b);
        if (a.kind == Operand::Kind::None || b.kind == Operand::Kind::None) {
            return {};
        }
        std::vector<std::string> t;
        if (!fresh_temps(2, &t)) {
            notes.push_back("cmp eq scratch registers unavailable");
            return {};
        }
        const std::string& rd = t[0];
        const std::string& rt = t[1];
        emit(Insn::Op::Mov, make_reg(rd, 64), ensure_valid(n.a, a));
        emit(Insn::Op::Xor, make_reg(rd, 64), ensure_valid(n.b, b));
        emit(Insn::Op::Mov, make_reg(rt, 64), make_reg(rd, 64));
        emit(Insn::Op::Neg, make_reg(rt, 64), {});
        emit(Insn::Op::Or, make_reg(rd, 64), make_reg(rt, 64));
        emit(Insn::Op::Shr, make_reg(rd, 64), make_imm(63, 64));
        emit(Insn::Op::Not, make_reg(rd, 64), {});
        emit(Insn::Op::And, make_reg(rd, 64), make_imm(1, 64));
        return make_reg(rd, 64);
    }

    // unsigned less-than into a register: the borrow of a - b, computed
    // exactly for 64-bit operands as
    //   borrow = bit63((~a & b) | ((~a | b) & (a - b))).
    // The naive `(a - b) >> 63` is the *sign* of the difference, not the
    // borrow: for x = 0xff..f, y = 0 it reads "less" though x >=u y, so the
    // bit-blaster would hand the miter a counterexample. This form matches
    // CmpULT for every pair and the miter proves it. All four scratch
    // registers are batched (distinct), and the operands are re-validated
    // at each use because the batch may recycle their registers.
    Operand emit_cmp_ult_reg(expr::Id aid, expr::Id bid, Operand a,
                             Operand b) {
        std::vector<std::string> t;
        if (!fresh_temps(4, &t)) {
            notes.push_back("cmp ult scratch registers unavailable");
            return {};
        }
        const std::string& rn = t[0];
        const std::string& ro = t[1];
        const std::string& rr = t[2];
        const std::string& rs = t[3];
        emit(Insn::Op::Mov, make_reg(rn, 64), ensure_valid(aid, a));
        emit(Insn::Op::Not, make_reg(rn, 64), {});      // ~a
        emit(Insn::Op::Mov, make_reg(ro, 64), ensure_valid(bid, b));
        emit(Insn::Op::Mov, make_reg(rr, 64), make_reg(rn, 64));
        emit(Insn::Op::And, make_reg(rr, 64), make_reg(ro, 64));  // ~a & b
        emit(Insn::Op::Or, make_reg(rn, 64), make_reg(ro, 64));   // ~a | b
        emit(Insn::Op::Mov, make_reg(rs, 64), ensure_valid(aid, a));
        emit(Insn::Op::Sub, make_reg(rs, 64), ensure_valid(bid, b));  // a - b
        emit(Insn::Op::And, make_reg(rn, 64), make_reg(rs, 64));  // (~a|b)&(a-b)
        emit(Insn::Op::Or, make_reg(rr, 64), make_reg(rn, 64));
        emit(Insn::Op::Shr, make_reg(rr, 64), make_imm(63, 64));
        emit(Insn::Op::And, make_reg(rr, 64), make_imm(1, 64));
        return make_reg(rr, 64);
    }

    // ult(a,b): the unsigned borrow.
    Operand materialize_cmp_ult(const expr::Node& n) {
        Operand a = materialize(n.a);
        Operand b = materialize(n.b);
        if (a.kind == Operand::Kind::None || b.kind == Operand::Kind::None) {
            return {};
        }
        return emit_cmp_ult_reg(n.a, n.b, a, b);
    }

    // slt(a,b): signed less-than via sign-flip and unsigned borrow:
    // (a^s) <u (b^s), s = 1 << (width-1), which is exact for any width.
    Operand materialize_cmp_slt(const expr::Node& n) {
        Operand a = materialize(n.a);
        Operand b = materialize(n.b);
        if (a.kind == Operand::Kind::None || b.kind == Operand::Kind::None) {
            return {};
        }
        const unsigned w = cmp_operand_width(n);
        const std::uint64_t sign =
            w >= 64 ? std::uint64_t{0x8000000000000000ULL}
                    : (std::uint64_t{1} << (w - 1));
        // Six distinct scratch registers: the sign-flipped operands plus the
        // borrow computation. Batching keeps them all distinct, so no
        // intermediate can be recycled before its use.
        std::vector<std::string> t;
        if (!fresh_temps(6, &t)) {
            notes.push_back("cmp slt scratch registers unavailable");
            return {};
        }
        const std::string& ra = t[0];
        const std::string& rb = t[1];
        const std::string& rn = t[2];
        const std::string& ro = t[3];
        const std::string& rr = t[4];
        const std::string& rs = t[5];
        emit(Insn::Op::Mov, make_reg(ra, 64), ensure_valid(n.a, a));
        emit(Insn::Op::Xor, make_reg(ra, 64), make_imm(sign, 64));
        emit(Insn::Op::Mov, make_reg(rb, 64), ensure_valid(n.b, b));
        emit(Insn::Op::Xor, make_reg(rb, 64), make_imm(sign, 64));
        emit(Insn::Op::Mov, make_reg(rn, 64), make_reg(ra, 64));
        emit(Insn::Op::Not, make_reg(rn, 64), {});      // ~(a^s)
        emit(Insn::Op::Mov, make_reg(ro, 64), make_reg(rb, 64));
        emit(Insn::Op::Mov, make_reg(rr, 64), make_reg(rn, 64));
        emit(Insn::Op::And, make_reg(rr, 64), make_reg(ro, 64));
        emit(Insn::Op::Or, make_reg(rn, 64), make_reg(ro, 64));
        emit(Insn::Op::Mov, make_reg(rs, 64), make_reg(ra, 64));
        emit(Insn::Op::Sub, make_reg(rs, 64), make_reg(rb, 64));
        emit(Insn::Op::And, make_reg(rn, 64), make_reg(rs, 64));
        emit(Insn::Op::Or, make_reg(rr, 64), make_reg(rn, 64));
        emit(Insn::Op::Shr, make_reg(rr, 64), make_imm(63, 64));
        emit(Insn::Op::And, make_reg(rr, 64), make_imm(1, 64));
        return make_reg(rr, 64);
    }

    // Updates a live register (rbp/rsi) to hold the node's value, using a
    // direct `add/sub reg, imm` when the value is the entry pointer moved
    // by a literal -- the form the handlers' pointer arithmetic takes.
    bool materialize_to(const std::string& reg, expr::Id id) {
        if (id == expr::kNoId) {
            notes.push_back("effect without an expression: " + reg);
            return false;
        }
        const expr::DAG& dag = m->dag;
        const expr::Node& n = dag.node(id);
        const lift::Model::Input* in = input_by_id(*m, id);
        if (in != nullptr && reg_name_from_input(*in) == reg) {
            return true;  // the register is already this value
        }
        if (n.op == expr::Op::Const) {
            emit(Insn::Op::Mov, make_reg(reg, 64), make_imm(n.imm, 64));
            return true;
        }
        const expr::Id entry =
            reg == "rbp" ? entry_rbp : (reg == "rsi" ? entry_rsi : expr::kNoId);
        if (entry != expr::kNoId && n.op == expr::Op::Add &&
            n.a == entry && dag.is_const(n.b)) {
            emit(Insn::Op::Add, make_reg(reg, 64),
                 make_imm(dag.const_value(n.b), 64));
            return true;
        }
        if (entry != expr::kNoId && n.op == expr::Op::Sub &&
            n.a == entry && dag.is_const(n.b)) {
            emit(Insn::Op::Sub, make_reg(reg, 64),
                 make_imm(dag.const_value(n.b), 64));
            return true;
        }
        Operand v = materialize(id);
        if (v.kind == Operand::Kind::None) {
            return false;
        }
        if (v.kind != Operand::Kind::Reg) {
            v = force_reg(v);
        }
        emit(Insn::Op::Mov, make_reg(reg, 64), v);
        return true;
    }
};

// ------------------------------------------------------------- rebuild

}  // namespace

Function rebuild(const lift::Model& model, const lift::Handler& h,
                 const Options& options) {
    Function f;
    f.va = h.va;
    f.modeled = h.modeled;
    f.rbp_new = h.rbp_new;
    f.rsi_new = h.rsi_new;
    f.writes = h.writes;
    f.transfer = h.transfer;
    f.target_expr = h.target_expr;

    Emitter em(model, options, &f.insns);
    em.compute_use_counts(h);

    // Writes first: their values are computed from the entry state, and the
    // stores land at entry-relative addresses; only then do the pointers
    // move and control leave.
    for (const lift::Handler::Write& w : h.writes) {
        if (w.value == expr::kNoId) {
            em.notes.push_back("write with unknown value");
            continue;
        }
        Operand val = em.materialize(w.value);
        if (val.kind == Operand::Kind::None) {
            em.notes.push_back("write value not materializable");
            continue;
        }
        if (w.to_slot) {
            em.emit(Insn::Op::Mov, make_slot(w.disp, w.width), val);
            continue;
        }
        if (w.addr == expr::kNoId) {
            em.notes.push_back("write through an unknown address");
            continue;
        }
        Operand addr = em.materialize(w.addr);
        if (addr.kind != Operand::Kind::Reg) {
            addr = em.force_reg(addr);
        }
        if (addr.kind != Operand::Kind::Reg) {
            em.notes.push_back("write address not materializable");
            continue;
        }
        em.emit(Insn::Op::Mov, make_mem(addr.reg, 0, w.width), val);
    }

    em.materialize_to("rbp", h.rbp_new);
    em.materialize_to("rsi", h.rsi_new);

    switch (h.transfer) {
    case lift::Handler::Transfer::Dispatch: {
        if (h.target_expr == expr::kNoId) {
            em.notes.push_back("dispatch target unknown");
            break;
        }
        Operand t = em.materialize(h.target_expr);
        if (t.kind == Operand::Kind::None) {
            em.notes.push_back("dispatch target not materializable");
            break;
        }
        if (t.kind != Operand::Kind::Reg) {
            t = em.force_reg(t);
        }
        em.emit(Insn::Op::Jmp, {}, t);
        break;
    }
    case lift::Handler::Transfer::Return:
        em.emit(Insn::Op::Ret, {}, {});
        break;
    case lift::Handler::Transfer::Call: {
        if (h.target_expr != expr::kNoId) {
            Operand t = em.materialize(h.target_expr);
            if (t.kind != Operand::Kind::Reg) {
                t = em.force_reg(t);
            }
            if (t.kind == Operand::Kind::Reg) {
                em.emit(Insn::Op::Call, {}, t);
                break;
            }
        }
        em.notes.push_back("call target unknown; emitting bare call");
        em.emit(Insn::Op::Call, {}, {});
        break;
    }
    case lift::Handler::Transfer::Unknown:
        break;
    }

    return f;
}

namespace {

// --------------------------------------------------------- renderer

std::string size_prefix(unsigned width) {
    switch (width) {
    case 8:  return "byte ptr ";
    case 16: return "word ptr ";
    case 32: return "dword ptr ";
    case 64: return "qword ptr ";
    default: return "";
    }
}

std::string render_mem(const std::string& base, std::int64_t disp,
                       unsigned width) {
    std::string s = size_prefix(width);
    s += '[';
    if (base.empty()) {
        char b[32];
        std::snprintf(b, sizeof(b), "0x%llx",
                      static_cast<unsigned long long>(
                          static_cast<std::uint64_t>(disp)));
        s += b;
    } else {
        s += base;
        if (disp != 0) {
            char b[40];
            if (disp < 0) {
                std::snprintf(b, sizeof(b), "-0x%llx",
                              static_cast<unsigned long long>(
                                  static_cast<std::uint64_t>(-disp)));
            } else {
                std::snprintf(b, sizeof(b), "+0x%llx",
                              static_cast<unsigned long long>(
                                  static_cast<std::uint64_t>(disp)));
            }
            s += b;
        }
    }
    s += ']';
    return s;
}

std::string render_operand(const Operand& op) {
    switch (op.kind) {
    case Operand::Kind::None:
        return "<none>";
    case Operand::Kind::Reg:
        return op.reg;
    case Operand::Kind::Imm: {
        char b[32];
        std::snprintf(b, sizeof(b), "0x%llx",
                      static_cast<unsigned long long>(op.imm));
        return b;
    }
    case Operand::Kind::Slot:
        return render_mem("rbp", op.disp, op.width);
    case Operand::Kind::Mem:
        return render_mem(op.reg, op.disp, op.width);
    }
    return "<none>";
}

const char* mnemonic_of(Insn::Op op, const Insn& in) {
    switch (op) {
    case Insn::Op::Mov:
        // A register load from a narrow memory operand renders as movzx.
        if (in.dst.kind == Operand::Kind::Reg &&
            (in.a.kind == Operand::Kind::Slot ||
             in.a.kind == Operand::Kind::Mem) &&
            in.a.width < 64) {
            return "movzx";
        }
        return "mov";
    case Insn::Op::Add: return "add";
    case Insn::Op::Sub: return "sub";
    case Insn::Op::Mul:
        return in.a.kind == Operand::Kind::Imm ? "imul" : "mul";
    case Insn::Op::And: return "and";
    case Insn::Op::Or:  return "or";
    case Insn::Op::Xor: return "xor";
    case Insn::Op::Shl: return "shl";
    case Insn::Op::Shr: return "shr";
    case Insn::Op::Sar: return "sar";
    case Insn::Op::Not: return "not";
    case Insn::Op::Neg: return "neg";
    case Insn::Op::Lea: return "lea";
    case Insn::Op::Cmp: return "cmp";
    case Insn::Op::Jmp: return "jmp";
    case Insn::Op::Jcc: return "jcc";
    case Insn::Op::Ret: return "ret";
    case Insn::Op::Call: return "call";
    }
    return "?";
}

std::string render_insn(const Insn& in) {
    std::string s = mnemonic_of(in.op, in);
    switch (in.op) {
    case Insn::Op::Not:
    case Insn::Op::Neg:
        s += ' ';
        s += render_operand(in.dst);
        break;
    case Insn::Op::Ret:
        break;  // `ret` alone
    case Insn::Op::Jmp:
    case Insn::Op::Call:
        if (in.a.kind != Operand::Kind::None) {
            s += ' ';
            s += render_operand(in.a);
        }
        break;
    case Insn::Op::Jcc:
        s += ' ';
        s += render_operand(in.dst);
        s += " ; if ";
        s += render_operand(in.a);
        break;
    default:
        s += ' ';
        s += render_operand(in.dst);
        s += ", ";
        s += render_operand(in.a);
        if (in.b.kind != Operand::Kind::None) {
            s += ", ";
            s += render_operand(in.b);
        }
        break;
    }
    return s;
}

// ------------------------------------------------------- simulator

// The symbolic interpreter of the IR. Registers map to DAG expression ids;
// memory is a list of stores (slot-space or computed-address) that reads
// compose over, falling back to the model's inputs for bytes no store put
// there.
struct Sim {
    expr::DAG dag;  // a copy: verify must not mutate the caller's model
    const lift::Model* m = nullptr;
    expr::Id entry_rbp = expr::kNoId;
    expr::Id entry_rsi = expr::kNoId;
    std::map<std::string, expr::Id> regs;

    struct Store {
        bool slot = false;
        std::int64_t disp = 0;      // slot-space displacement
        expr::Id addr = expr::kNoId;  // expression-space address
        unsigned width = 64;
        expr::Id value = expr::kNoId;
    };
    std::vector<Store> stores;

    bool transfer_set = false;
    lift::Handler::Transfer transfer = lift::Handler::Transfer::Unknown;
    expr::Id target = expr::kNoId;
    std::vector<std::string> notes;
    std::uint64_t unknown_counter = 0;

    explicit Sim(const lift::Model& model) : m(&model) {
        dag = model.dag;
        // Seed the machine registers with the model's entry values, for both
        // Reg inputs and the `unk[REG]#k` Unknown inputs (an unmodeled
        // register whose name the walk still disclosed).
        for (const lift::Model::Input& in : model.inputs) {
            const std::string rn = reg_name_from_input(in);
            if (!rn.empty()) {
                regs[rn] = in.id;
            }
        }
        entry_rbp = regs.count("rbp") != 0 ? regs["rbp"] : expr::kNoId;
        entry_rsi = regs.count("rsi") != 0 ? regs["rsi"] : expr::kNoId;
        if (entry_rbp == expr::kNoId) {
            entry_rbp = dag.input("rbp", 64);
            regs["rbp"] = entry_rbp;
        }
        if (entry_rsi == expr::kNoId) {
            entry_rsi = dag.input("rsi", 64);
            regs["rsi"] = entry_rsi;
        }
    }

    expr::Id reg_read(const std::string& name) {
        const auto it = regs.find(name);
        if (it != regs.end()) {
            return it->second;
        }
        // A register the IR reads that is not an entry input: a fresh
        // unconstrained input, so the expression stays an expression.
        const expr::Id id = dag.input(name, 64);
        regs[name] = id;
        return id;
    }

    expr::Id zext64(expr::Id v) { return dag.resize(v, 64); }
    expr::Id truncw(expr::Id v, unsigned w) { return dag.resize(v, w); }

    expr::Id fresh_unknown(const std::string& hint) {
        char b[96];
        std::snprintf(b, sizeof(b), "%s#%llu", hint.c_str(),
                      static_cast<unsigned long long>(unknown_counter++));
        return dag.input(b, 64);
    }

    // ---- memory -----------------------------------------------------

    expr::Id addr_of(const Operand& op) {
        switch (op.kind) {
        case Operand::Kind::Slot:
            return dag.add(reg_read("rbp"),
                           dag.constant(
                               static_cast<std::uint64_t>(op.disp), 64));
        case Operand::Kind::Mem: {
            if (op.reg.empty()) {
                return dag.constant(static_cast<std::uint64_t>(op.disp),
                                    64);
            }
            return dag.add(reg_read(op.reg),
                           dag.constant(static_cast<std::uint64_t>(op.disp),
                                        64));
        }
        default:
            return expr::kNoId;
        }
    }

    // The model input a read at this displacement/width maps to, or kNoId.
    expr::Id model_input(lift::Model::Input::Kind kind, std::int64_t key,
                         unsigned width) const {
        for (const lift::Model::Input& in : m->inputs) {
            if (in.kind != kind) {
                continue;
            }
            const std::int64_t in_key =
                kind == lift::Model::Input::Kind::Image
                    ? static_cast<std::int64_t>(in.va)
                    : in.disp;
            if (in_key == key && in.width == width) {
                return in.id;
            }
        }
        return expr::kNoId;
    }

    bool ranges_overlap(std::int64_t a0, unsigned aw, std::int64_t b0,
                        unsigned bw) {
        const std::int64_t a1 = a0 + static_cast<std::int64_t>(aw / 8);
        const std::int64_t b1 = b0 + static_cast<std::int64_t>(bw / 8);
        return a0 < b1 && b0 < a1;
    }

    // A read in slot space (entry-relative): an exact latest store answers
    // whole; otherwise the byte composition of the latest stores that cover
    // each byte and the entry input bytes in between.
    expr::Id read_slot_space(std::int64_t disp, unsigned width) {
        for (std::size_t i = stores.size(); i-- > 0;) {
            const Store& s = stores[i];
            if (s.slot && s.disp == disp && s.width == width) {
                return zext64(s.value);
            }
        }
        bool any_overlap = false;
        for (const Store& s : stores) {
            if (s.slot && ranges_overlap(s.disp, s.width, disp, width)) {
                any_overlap = true;
                break;
            }
        }
        if (!any_overlap) {
            const expr::Id in = model_input(lift::Model::Input::Kind::Slot,
                                            disp, width);
            if (in != expr::kNoId) {
                return zext64(in);
            }
        }
        expr::Id acc = dag.constant(0, 64);
        const unsigned nbytes = width / 8;
        for (unsigned i = 0; i < nbytes; ++i) {
            const std::int64_t d = disp + static_cast<std::int64_t>(i);
            expr::Id src = expr::kNoId;
            std::int64_t off = 0;
            for (std::size_t j = stores.size(); j-- > 0;) {
                const Store& s = stores[j];
                if (s.slot && d >= s.disp &&
                    d < s.disp + static_cast<std::int64_t>(s.width / 8)) {
                    src = s.value;
                    off = d - s.disp;
                    break;
                }
            }
            if (src == expr::kNoId) {
                const std::int64_t floor = align8(d);
                src = model_input(lift::Model::Input::Kind::Slot, floor, 64);
                if (src == expr::kNoId) {
                    src = fresh_unknown("byte");
                }
                off = d - floor;
            }
            expr::Id byte = dag.bit_and(
                dag.shr(src, dag.constant(static_cast<std::uint64_t>(off * 8),
                                          64)),
                dag.constant(0xFF, 64));
            byte = dag.shl(byte, dag.constant(static_cast<std::uint64_t>(i * 8),
                                              64));
            acc = dag.bit_or(acc, byte);
        }
        return acc;
    }

    // A read through a computed address expression.
    expr::Id read_expr(expr::Id addr, unsigned width) {
        for (std::size_t i = stores.size(); i-- > 0;) {
            const Store& s = stores[i];
            if (!s.slot && s.addr == addr && s.width == width) {
                return zext64(s.value);
            }
        }
        for (const lift::Model::Input& in : m->inputs) {
            if (in.kind == lift::Model::Input::Kind::Load &&
                in.addr == addr && in.width == width) {
                return zext64(in.id);
            }
        }
        return zext64(fresh_unknown("mem"));
    }

    // A read through the virtual stack. The rebuilt IR is a reconstruction,
    // not a concrete machine trace: `[rbp+disp]` reads and writes are keyed
    // by the entry-relative displacement (slot space), never by the current
    // value of the rbp register -- the handler may move rbp at any point
    // and the model's slot inputs are entry-anchored either way.
    expr::Id read_slot(std::int64_t disp, unsigned width) {
        return read_slot_space(disp, width);
    }

    // The entry-anchored address expression of a code read at `disp`.
    expr::Id code_addr(std::int64_t disp) {
        return dag.add(entry_rsi,
                       dag.constant(static_cast<std::uint64_t>(disp), 64));
    }

    // A read from the byte stream the cursor walks. Like slots, code reads
    // are entry-anchored: `[rsi+disp]` denotes the model's Code input at
    // entry offset `disp` regardless of how far the IR moved rsi in
    // between. Bytes with no exact-width input are extracted from the
    // covering input (the decrypt handler reads 8 bytes the model captured
    // as one 64-bit code input), and from stores that wrote the same
    // address expression when a hand-built IR places one.
    expr::Id read_code_space(std::int64_t disp, unsigned width) {
        const expr::Id addr = code_addr(disp);
        for (std::size_t i = stores.size(); i-- > 0;) {
            const Store& s = stores[i];
            if (!s.slot && s.addr == addr && s.width == width) {
                return zext64(s.value);
            }
        }
        const expr::Id exact =
            model_input(lift::Model::Input::Kind::Code, disp, width);
        if (exact != expr::kNoId) {
            return zext64(exact);
        }
        expr::Id acc = dag.constant(0, 64);
        const unsigned nbytes = width / 8;
        for (unsigned i = 0; i < nbytes; ++i) {
            const std::int64_t d = disp + static_cast<std::int64_t>(i);
            expr::Id src = expr::kNoId;
            std::int64_t off = 0;
            for (std::size_t j = stores.size(); j-- > 0;) {
                const Store& s = stores[j];
                if (!s.slot && s.addr == code_addr(d)) {
                    src = s.value;
                    off = 0;
                    break;
                }
            }
            if (src == expr::kNoId) {
                // The widest code input covering this byte. The model keeps
                // one input per read the handler performed; byte re-reads
                // of the same input must extract from it.
                unsigned best_width = 0;
                for (const lift::Model::Input& in : m->inputs) {
                    if (in.kind != lift::Model::Input::Kind::Code) {
                        continue;
                    }
                    const std::int64_t end =
                        in.disp + static_cast<std::int64_t>(in.width / 8);
                    if (in.disp <= d && d < end && in.width > best_width) {
                        src = in.id;
                        off = d - in.disp;
                        best_width = in.width;
                    }
                }
            }
            if (src == expr::kNoId) {
                src = fresh_unknown("code");
            }
            expr::Id byte = dag.bit_and(
                dag.shr(src, dag.constant(static_cast<std::uint64_t>(off * 8),
                                          64)),
                dag.constant(0xFF, 64));
            byte = dag.shl(byte,
                           dag.constant(static_cast<std::uint64_t>(i * 8), 64));
            acc = dag.bit_or(acc, byte);
        }
        return acc;
    }

    expr::Id read_code(std::int64_t disp, unsigned width) {
        return read_code_space(disp, width);
    }

    expr::Id read_image(std::int64_t va, unsigned width) {
        const expr::Id addr =
            dag.constant(static_cast<std::uint64_t>(va), 64);
        for (std::size_t i = stores.size(); i-- > 0;) {
            const Store& s = stores[i];
            if (!s.slot && s.addr == addr && s.width == width) {
                return zext64(s.value);
            }
        }
        const expr::Id in =
            model_input(lift::Model::Input::Kind::Image, va, width);
        if (in != expr::kNoId) {
            return zext64(in);
        }
        return zext64(fresh_unknown("img"));
    }

    expr::Id resolve(const Operand& op) {
        switch (op.kind) {
        case Operand::Kind::Reg:
            return reg_read(op.reg);
        case Operand::Kind::Imm:
            return dag.constant(op.imm, 64);
        case Operand::Kind::Slot:
            return read_slot(op.disp, op.width);
        case Operand::Kind::Mem:
            if (op.reg.empty()) {
                return read_image(op.disp, op.width);
            }
            if (op.reg == "rsi") {
                return read_code(op.disp, op.width);
            }
            if (op.reg == "rbp") {
                return read_slot(op.disp, op.width);
            }
            return read_expr(reg_read(op.reg), op.width);
        case Operand::Kind::None:
            return expr::kNoId;
        }
        return expr::kNoId;
    }

    void store(const Operand& dst, unsigned width, expr::Id value) {
        const expr::Id v = truncw(value, width);
        if (dst.kind == Operand::Kind::Slot) {
            Store s;
            s.slot = true;
            s.disp = dst.disp;
            s.addr = dag.add(reg_read("rbp"),
                             dag.constant(
                                 static_cast<std::uint64_t>(dst.disp), 64));
            s.width = width;
            s.value = v;
            stores.push_back(s);
            return;
        }
        if (dst.kind == Operand::Kind::Mem) {
            if (dst.reg == "rbp" && reg_read("rbp") == entry_rbp) {
                store(make_slot(dst.disp, width), width, value);
                return;
            }
            Store s;
            s.slot = false;
            s.addr = addr_of(dst);
            s.width = width;
            s.value = v;
            stores.push_back(s);
        }
    }

    // ---- execution ---------------------------------------------------

    void run(const std::vector<Insn>& insns) {
        for (const Insn& in : insns) {
            execute(in);
            if (transfer_set) {
                // A transfer ends the function; later instructions are
                // unreachable and ignored (they are dead code by
                // construction, but a hand-built IR may place them).
                return;
            }
        }
    }

    void execute(const Insn& in) {
        switch (in.op) {
        case Insn::Op::Mov: {
            if (in.dst.kind == Operand::Kind::Reg) {
                regs[in.dst.reg] = resolve(in.a);
                return;
            }
            if (in.dst.kind == Operand::Kind::Slot ||
                in.dst.kind == Operand::Kind::Mem) {
                store(in.dst, in.dst.width, resolve(in.a));
                return;
            }
            notes.push_back("Mov with non-memory destination");
            return;
        }
        case Insn::Op::Add:
        case Insn::Op::Sub:
        case Insn::Op::Mul:
        case Insn::Op::And:
        case Insn::Op::Or:
        case Insn::Op::Xor:
        case Insn::Op::Shl:
        case Insn::Op::Shr:
        case Insn::Op::Sar: {
            // The machine executes these at 64 bits; sub-64 values are
            // already masked by the IR (or are memory loads, zero-extended).
            // Reading the destination as a value is the IR's contract:
            // binary instructions are reg <- reg OP src, never mem OP mem.
            const expr::Id a = zext64(resolve(in.dst));
            const expr::Id b = zext64(resolve(in.a));
            expr::Id r = expr::kNoId;
            switch (in.op) {
            case Insn::Op::Add: r = dag.add(a, b); break;
            case Insn::Op::Sub: r = dag.sub(a, b); break;
            case Insn::Op::Mul: r = dag.mul(a, b); break;
            case Insn::Op::And: r = dag.bit_and(a, b); break;
            case Insn::Op::Or:  r = dag.bit_or(a, b); break;
            case Insn::Op::Xor: r = dag.bit_xor(a, b); break;
            case Insn::Op::Shl: r = dag.shl(a, b); break;
            case Insn::Op::Shr: r = dag.shr(a, b); break;
            case Insn::Op::Sar: r = dag.sar(a, b); break;
            default: break;
            }
            if (in.dst.kind == Operand::Kind::Reg) {
                regs[in.dst.reg] = r;
            } else if (in.dst.kind == Operand::Kind::Slot ||
                       in.dst.kind == Operand::Kind::Mem) {
                store(in.dst, in.dst.width, r);
            } else {
                notes.push_back("ALU with non-memory destination");
            }
            return;
        }
        case Insn::Op::Not:
        case Insn::Op::Neg: {
            const expr::Id a = zext64(resolve(in.dst));
            const expr::Id r = in.op == Insn::Op::Not ? dag.bit_not(a)
                                                      : dag.neg(a);
            if (in.dst.kind == Operand::Kind::Reg) {
                regs[in.dst.reg] = r;
            } else if (in.dst.kind == Operand::Kind::Slot ||
                       in.dst.kind == Operand::Kind::Mem) {
                store(in.dst, in.dst.width, r);
            }
            return;
        }
        case Insn::Op::Lea: {
            if (in.dst.kind == Operand::Kind::Reg) {
                regs[in.dst.reg] = addr_of(in.a);
            }
            return;
        }
        case Insn::Op::Cmp:
            // The flags are not among the claimed effects; resolving both
            // operands keeps the simulator total, but nothing is recorded.
            (void)resolve(in.dst);
            (void)resolve(in.a);
            notes.push_back("Cmp: flag effects are not modeled");
            return;
        case Insn::Op::Jcc:
            notes.push_back("Jcc: conditional transfer is not modeled");
            return;
        case Insn::Op::Jmp:
            transfer_set = true;
            transfer = lift::Handler::Transfer::Dispatch;
            target = resolve(in.a);
            return;
        case Insn::Op::Ret:
            transfer_set = true;
            transfer = lift::Handler::Transfer::Return;
            return;
        case Insn::Op::Call:
            transfer_set = true;
            transfer = lift::Handler::Transfer::Call;
            if (in.a.kind != Operand::Kind::None) {
                target = resolve(in.a);
            }
            return;
        }
    }
};

// ---------------------------------------------------------- miters

// One equivalence question: normalize both sides to 64 bits (so a compare
// never depends on the widths the expressions happened to be built at) and
// ask the ring layer first, then the bit-blaster, honoring the budget.
void compare(Check& out, expr::DAG& dag, const std::string& what, expr::Id a,
             expr::Id b, const bb::Budget& budget) {
    ++out.miters;
    if (a == expr::kNoId || b == expr::kNoId) {
        out.failures.push_back(what + ": UNPROVEN (缺少表达式)");
        return;
    }
    const unsigned wa = dag.width(a);
    const unsigned wb = dag.width(b);
    const expr::Id a64 = wa >= 64 ? a : dag.resize(a, 64);
    const expr::Id b64 = wb >= 64 ? b : dag.resize(b, 64);
    if (a64 == b64) {
        out.items.push_back(what + ": " + dag.pretty(a) + " == " +
                            dag.pretty(b) + " [Identical]");
        return;
    }
    const bb::Equivalence eq =
        bb::prove_equivalent(dag, a64, b64, false, false, budget);
    out.conflicts += eq.conflicts;
    if (eq.equal && !eq.unproven) {
        const char* method = eq.method == bb::Method::Ring ? "Ring" : "Sat";
        out.items.push_back(what + ": " + dag.pretty(a) + " == " +
                            dag.pretty(b) + " [" + method + "]");
        return;
    }
    if (eq.unproven) {
        out.failures.push_back(what + ": UNPROVEN (预算耗尽)");
        return;
    }
    out.failures.push_back(what + ": NOT EQUAL");
}

}  // namespace

std::string emit_asm(const Function& f, const Options& options) {
    std::string out;
    char b[128];
    std::snprintf(b, sizeof(b), "; rebuilt handler @ 0x%llx\n",
                  static_cast<unsigned long long>(f.va));
    out += b;
    if (options.emit_comments) {
        std::snprintf(b, sizeof(b),
                      "; modeled: %s, writes: %zu, transfer: %s\n",
                      f.modeled ? "true" : "false", f.writes.size(),
                      transfer_name(f.transfer));
        out += b;
    }
    for (const Insn& in : f.insns) {
        out += "    ";
        out += render_insn(in);
        out += '\n';
    }
    return out;
}

// ------------------------------------------------------------- verify

Check verify(const lift::Model& model, const lift::Handler& h,
             const Function& f, const bb::Budget& budget) {
    Check out;
    if (f.va != h.va) {
        out.failures.push_back("handler VA mismatch");
    }

    Sim sim(model);
    sim.run(f.insns);

    // Every claimed write must be reproduced by the IR. Slot writes are
    // compared at the cell level: the value the IR leaves in the cell
    // (composed over its stores and the entry bytes) against the model's
    // claimed final value. Computed-address writes are matched by address
    // expression and compared at their access width.
    for (std::size_t i = 0; i < f.writes.size(); ++i) {
        const lift::Handler::Write& w = f.writes[i];
        if (w.to_slot) {
            bool present = false;
            for (const Sim::Store& s : sim.stores) {
                if (s.slot && s.disp == w.disp) {
                    present = true;
                    break;
                }
            }
            char b[64];
            std::snprintf(b, sizeof(b), "write[%zu] addr: slot %+lld",
                          i, static_cast<long long>(w.disp));
            if (!present) {
                out.failures.push_back(std::string(b) +
                                       ": IR 未在该槽位写入");
            } else {
                out.items.push_back(std::string(b) + " (present)");
            }
            compare(out, sim.dag, "write[" + std::to_string(i) + "] value",
                    sim.read_slot_space(w.disp, 64), w.value, budget);
        } else {
            const Sim::Store* found = nullptr;
            for (std::size_t j = sim.stores.size(); j-- > 0;) {
                const Sim::Store& s = sim.stores[j];
                if (!s.slot && s.addr == w.addr && s.width == w.width) {
                    found = &s;
                    break;
                }
            }
            if (found == nullptr) {
                out.failures.push_back("write[" + std::to_string(i) +
                                       "] addr: IR 无对应计算地址写入");
            } else {
                out.items.push_back("write[" + std::to_string(i) +
                                    "] addr: 计算地址一致");
            }
            compare(out, sim.dag, "write[" + std::to_string(i) + "] value",
                    found != nullptr ? sim.truncw(found->value, w.width)
                                     : expr::kNoId,
                    sim.truncw(w.value, w.width), budget);
        }
    }

    // Every IR store must be accounted for by some claimed write.
    for (const Sim::Store& s : sim.stores) {
        if (s.slot) {
            bool claimed = false;
            for (const lift::Handler::Write& w : f.writes) {
                if (w.to_slot &&
                    sim.ranges_overlap(w.disp, w.width, s.disp, s.width)) {
                    claimed = true;
                    break;
                }
            }
            if (!claimed) {
                out.failures.push_back("IR 执行了模型未声称的写入 @ slot " +
                                       std::to_string(s.disp));
            }
        } else {
            bool claimed = false;
            for (const lift::Handler::Write& w : f.writes) {
                if (!w.to_slot && w.addr == s.addr && w.width == s.width) {
                    claimed = true;
                    break;
                }
            }
            if (!claimed) {
                out.failures.push_back(
                    "IR 执行了模型未声称的写入 @ 计算地址");
            }
        }
    }

    // The pointers after the IR, and the dispatch target.
    compare(out, sim.dag, "rbp_new", sim.reg_read("rbp"), f.rbp_new, budget);
    compare(out, sim.dag, "rsi_new", sim.reg_read("rsi"), f.rsi_new, budget);

    if (f.transfer == lift::Handler::Transfer::Dispatch) {
        if (!sim.transfer_set || sim.transfer != f.transfer) {
            out.failures.push_back("transfer: IR 未以 Dispatch 结束");
        } else {
            compare(out, sim.dag, "target", sim.target, f.target_expr,
                    budget);
        }
    } else if (f.transfer == lift::Handler::Transfer::Return) {
        if (!sim.transfer_set || sim.transfer != f.transfer) {
            out.failures.push_back("transfer: IR 未以 Ret 结束");
        }
    } else if (f.transfer == lift::Handler::Transfer::Call) {
        if (!sim.transfer_set || sim.transfer != f.transfer) {
            out.failures.push_back("transfer: IR 未以 Call 结束");
        }
    } else if (sim.transfer_set) {
        out.failures.push_back("transfer: 模型无转移，IR 却执行了转移");
    }

    char b[64];
    std::snprintf(b, sizeof(b), "handler @ 0x%llx: va matches function",
                  static_cast<unsigned long long>(h.va));
    out.items.push_back(b);

    out.ok = out.failures.empty();
    return out;
}

}  // namespace occ::devirt::codegen

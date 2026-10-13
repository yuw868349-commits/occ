// The API behavior sandbox for a guest that cannot be trusted.
//
// A packer or a packed sample runs native API calls as the fastest way to
// touch the world: file, network, registry, process, memory. A sandbox's
// job is to let those calls happen under observation, to deny or simulate
// the ones the analyst does not want to reach a real resource, and to keep
// a structured, auditable record of everything that did happen.
//
// The design splits the work into five pieces so each is independently
// testable and the integration point stays small:
//
//   * ArgDecoder. Windows x64 calling convention: RCX, RDX, R8, R9 then the
//     stack. The decoder reads those registers plus the first stack slots
//     and marks pointer / string candidates, without dereferencing guest
//     memory (the caller owns that decision).
//
//   * BehaviorClass. A coarse classification of what an API touches. The
//     classification drives the policy; the policy never has to know the
//     full API name universe.
//
//   * Policy. Per-class default actions plus exact-address overrides. The
//     actions are allow / deny / simulate / monitor, and the decision is a
//     pure function of (class, callee) so it can be tested exhaustively.
//
//   * Simulator. Deterministic stand-ins for the calls a policy routes to
//     kSimulate: a file-existence set, an environment-variable set, a
//     configurable success/failure answer. Everything the simulator answers
//     is derived from data the analyst supplied; it never touches the real
//     object.
//
//   * TaintTracker. Mark regions of guest memory as attacker-controlled
//     inputs and propagate that mark through writes and returns. The
//     propagation is address-range based and coarse (it is a sandbox, not
//     a taint engine), but it gives fuzz and replay the exact "does this
//     return value derive from an input?" question.
//
// The sandbox itself (Sandbox) is a thin composition: decode args, classify
// the call, decide the action, optionally simulate, log the record, and
// notify hooks before and after. Nothing here touches real OS resources.

#ifndef OCC_BEHAVE_BEHAVE_H
#define OCC_BEHAVE_BEHAVE_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace occ::behave {

// x64 calling conventions the decoder understands.
enum class CallingConvention {
    kWin64, // RCX, RDX, R8, R9, then stack
    kSysV,  // RDI, RSI, RDX, RCX, R8, R9, then stack
};

// One decoded argument.
struct Arg {
    std::uint64_t value = 0;
    std::size_t slot = 0;    // 0..3 are the register slots, 4+ the stack
    bool is_pointer = false; // value looks like a guest pointer
    bool string_candidate = false; // value looks like an ASCII/UTF-16 ptr
};

// The decoded view of one call site.
struct CallContext {
    std::uint64_t callee = 0; // target API address
    std::uint64_t caller = 0; // return address
    std::uint32_t thread_id = 0;
    CallingConvention conv = CallingConvention::kWin64;
    std::array<Arg, 8> args{};
    std::size_t argc = 0;
};

// What an API call touches.
enum class BehaviorClass {
    kFile,
    kNetwork,
    kRegistry,
    kProcess,
    kMemory,
    kSync,
    kTime,
    kCrypt,
    kEnvironment,
    kThread,
    kHeap,
    kOther,
};

constexpr std::size_t kBehaviorClassCount = 12;

// Decoder entry point: fills a CallContext from raw register/stack values.
// regs[0..5] are the convention registers (RCX..R9 or RDI..R9), stack
// values are read by the caller into sp[0..]. max_args caps argc.
[[nodiscard]] CallContext decode(CallingConvention conv, std::uint64_t callee,
                                 std::uint64_t caller,
                                 std::uint32_t thread_id,
                                 const std::uint64_t* regs,
                                 const std::uint64_t* sp,
                                 std::size_t max_args) noexcept;

// Human-readable class name (used by logging and describe()).
[[nodiscard]] std::string_view class_name(BehaviorClass c) noexcept;

// Policy actions. kMonitor observes and logs without restricting; kDeny
// refuses; kSimulate hands the call to the Simulator; kAllow passes it to
// the real API untouched.
enum class Action {
    kMonitor,
    kDeny,
    kSimulate,
    kAllow,
};

// The policy table: default action per class, plus exact-address overrides.
// Decisions are pure: the same (class, callee) always yields the same
// action for a given policy, which makes the table exhaustively testable.
class Policy {
public:
    Policy();

    // Per-class default (initialized to kMonitor).
    void set_default(BehaviorClass c, Action a) noexcept;
    [[nodiscard]] Action default_for(BehaviorClass c) const noexcept;

    // Exact-address override (e.g. a specific CreateFileA stub).
    void override_api(std::uint64_t callee, Action a) noexcept;
    [[nodiscard]] bool has_override(std::uint64_t callee,
                                    Action* out) const noexcept;

    // The combined decision.
    [[nodiscard]] Action decide(BehaviorClass c,
                                std::uint64_t callee) const noexcept;

private:
    std::array<Action, kBehaviorClassCount> defaults_{};
    std::map<std::uint64_t, Action> overrides_;
};

// Deterministic stand-ins. The analyst supplies the sets; the simulator
// only ever answers from them.
class Simulator {
public:
    // File existence: map_file(path, true/false).
    void map_file(std::string path, bool exists);
    [[nodiscard]] bool file_exists(std::string_view path) const noexcept;

    // Environment variables.
    void set_env(std::string name, std::string value);
    [[nodiscard]] bool env_get(std::string_view name,
                               std::string* out) const noexcept;

    // Registry values (key path -> value).
    void set_registry(std::string path, std::uint64_t value);
    [[nodiscard]] bool registry_get(std::string_view path,
                                    std::uint64_t* out) const noexcept;

    // The generic answer used by kSimulate calls the policy routed here
    // but the simulator has no specific model: success by default, and a
    // seeded failure fraction for stress runs.
    void set_generic_status(bool success) noexcept;
    void set_failure_fraction(double f) noexcept;
    [[nodiscard]] bool generic_status() const noexcept;

private:
    std::map<std::string, bool> files_;
    std::map<std::string, std::string> env_;
    std::map<std::string, std::uint64_t> registry_;
    bool status_ = true;
    double failure_fraction_ = 0.0;
};

// One auditable call record.
struct CallRecord {
    std::uint64_t seq = 0;    // global, monotonically increasing
    std::uint64_t callee = 0;
    std::uint64_t caller = 0;
    std::uint32_t thread_id = 0;
    BehaviorClass cls = BehaviorClass::kOther;
    Action action = Action::kMonitor;
    std::array<std::uint64_t, 8> args{};
    std::size_t argc = 0;
    std::uint64_t ret = 0;
    bool simulated = false;
};

// A structured, append-only log. Records are stored in memory and can be
// replayed in order; replay() walks the same sequence a consumer would see
// if it re-executed the guest.
class CallLog {
public:
    void append(const CallRecord& r);
    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] const CallRecord& at(std::size_t i) const noexcept;
    [[nodiscard]] const std::vector<CallRecord>& records() const noexcept;

    // Replay hook: invoked once per record, in order.
    using ReplayFn = std::function<void(const CallRecord&)>;
    void replay(ReplayFn fn) const;

private:
    std::vector<CallRecord> records_;
    std::uint64_t seq_ = 0;
};

// Address-range taint. Coarse by design: mark a guest memory range as
// attacker-controlled, query it, and propagate taint to a written range
// when the write was derived from a tainted read. The granularity is a
// page-sized bucket so the map stays small.
class TaintTracker {
public:
    static constexpr std::size_t kBucket = 4096;

    void mark(std::uint64_t addr, std::size_t size);
    void clear(std::uint64_t addr, std::size_t size);
    [[nodiscard]] bool is_tainted(std::uint64_t addr,
                                  std::size_t size) const noexcept;
    // Propagate: taint dst if the read range was tainted.
    void propagate(std::uint64_t dst, std::size_t dst_size,
                   std::uint64_t src, std::size_t src_size) noexcept;
    [[nodiscard]] std::size_t bucket_count() const noexcept;

private:
    std::set<std::uint64_t> buckets_;
};

// Callbacks a sandbox consumer registers.
struct Hooks {
    // Called before the policy decision, with the decoded context.
    std::function<void(const CallContext&)> on_call{};
    // Called after the call completed (or was simulated/denied).
    std::function<void(const CallRecord&)> on_result{};
};

// The sandbox itself: decode -> classify -> decide -> (simulate|deny) ->
// log -> notify.
class Sandbox {
public:
    Sandbox();
    explicit Sandbox(Policy policy);

    [[nodiscard]] Policy& policy() noexcept;
    [[nodiscard]] const Policy& policy() const noexcept;
    [[nodiscard]] Simulator& simulator() noexcept;
    [[nodiscard]] const Simulator& simulator() const noexcept;
    [[nodiscard]] CallLog& log() noexcept;
    [[nodiscard]] const CallLog& log() const noexcept;
    [[nodiscard]] TaintTracker& taint() noexcept;
    [[nodiscard]] const TaintTracker& taint() const noexcept;
    [[nodiscard]] Hooks& hooks() noexcept;

    // Run one call through the sandbox. Returns the record; ret is the
    // value a simulated call produced, or 0 for denied/monitored calls
    // (the caller decides what to do with it).
    [[nodiscard]] CallRecord run(const CallContext& ctx);

private:
    Policy policy_;
    Simulator sim_;
    CallLog log_;
    TaintTracker taint_;
    Hooks hooks_;
    std::uint64_t seq_ = 0;
};

} // namespace occ::behave

#endif // OCC_BEHAVE_BEHAVE_H

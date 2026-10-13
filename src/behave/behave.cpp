// Implementation of the API behavior sandbox (see behave.h).

#include "occ/behave/behave.h"

#include <algorithm>
#include <cmath>
#include <random>

namespace occ::behave {

namespace {

constexpr std::uint64_t kUserSpaceLow = 0x0000000000010000ull;
constexpr std::uint64_t kUserSpaceHigh = 0x00007FFFFFFFFFFFull;

// Whether a value is in the canonical user-space pointer range. A value
// that big and aligned looks like a pointer even before dereferencing.
bool looks_like_pointer(std::uint64_t v) noexcept {
    return v >= kUserSpaceLow && v <= kUserSpaceHigh;
}

// A pointer "looks like a string" if the first two bytes are printable
// ASCII or the UTF-16 form of one. This is a heuristic for the sandbox;
// the caller dereferences only when it decides to.
bool looks_like_string(std::uint64_t v) noexcept {
    if (!looks_like_pointer(v)) {
        return false;
    }
    const std::uint64_t lo = v & 0xFFFF;
    const char c0 = static_cast<char>(lo & 0xFF);
    const char c1 = static_cast<char>((lo >> 8) & 0xFF);
    const bool ascii = (c0 >= 0x20 && c0 < 0x7F) || c0 == '\0';
    const bool utf16 = (lo & 0xFF) != 0 &&
                       (c0 >= 0x20 && c0 < 0x7F) && c1 == '\0';
    return ascii || utf16;
}

} // namespace

CallContext decode(CallingConvention conv, std::uint64_t callee,
                   std::uint64_t caller, std::uint32_t thread_id,
                   const std::uint64_t* regs, const std::uint64_t* sp,
                   std::size_t max_args) noexcept {
    CallContext ctx;
    ctx.callee = callee;
    ctx.caller = caller;
    ctx.thread_id = thread_id;
    ctx.conv = conv;
    if (max_args > ctx.args.size()) {
        max_args = ctx.args.size();
    }
    // Register slots depend on the convention (Win64: RCX,RDX,R8,R9;
    // SysV: RDI,RSI,RDX,RCX,R8,R9). regs[] arrives in hardware order, so
    // the register argument i reads regs[i]. Stack slots begin after the
    // register count (and after the Win64 shadow space).
    const std::size_t reg_arg_count = (conv == CallingConvention::kSysV) ? 6
                                                                         : 4;
    for (std::size_t i = 0; i < max_args; ++i) {
        Arg a;
        a.slot = i;
        if (i < reg_arg_count) {
            a.value = regs[i];
        } else {
            a.value = sp[i - reg_arg_count];
        }
        a.is_pointer = looks_like_pointer(a.value);
        a.string_candidate = looks_like_string(a.value);
        ctx.args[i] = a;
        ctx.argc = i + 1;
    }
    return ctx;
}

BehaviorClass classify(std::string_view module, std::string_view name) noexcept {
    const std::string_view n = name;
    if (n.starts_with("CreateFile") || n.starts_with("ReadFile") ||
        n.starts_with("WriteFile") || n.starts_with("DeleteFile") ||
        n.starts_with("MoveFile") || n.starts_with("CopyFile") ||
        n.starts_with("GetFileAttributes") || n.starts_with("SetFile") ||
        n.starts_with("FindFirstFile") || n.starts_with("FindNextFile") ||
        n.starts_with("NtCreateFile") || n.starts_with("NtReadFile") ||
        n.starts_with("NtWriteFile") || n.starts_with("NtDeleteFile") ||
        n.starts_with("NtSetInformationFile") ||
        n.starts_with("NtQueryInformationFile") ||
        n.starts_with("CloseHandle")) {
        return BehaviorClass::kFile;
    }
    if (n.starts_with("socket") || n.starts_with("connect") ||
        n.starts_with("bind") || n.starts_with("listen") ||
        n.starts_with("accept") || n.starts_with("send") ||
        n.starts_with("recv") || n.starts_with("Internet") ||
        n.starts_with("WinHttp") || n.starts_with("WSA")) {
        return BehaviorClass::kNetwork;
    }
    if (n.starts_with("Reg") || n.starts_with("NtOpenKey") ||
        n.starts_with("NtCreateKey") || n.starts_with("NtQueryKey") ||
        n.starts_with("NtSetValueKey") || n.starts_with("NtQueryValueKey") ||
        n.starts_with("NtDeleteKey") || n.starts_with("NtDeleteValueKey")) {
        return BehaviorClass::kRegistry;
    }
    if (n.starts_with("CreateProcess") || n.starts_with("OpenProcess") ||
        n.starts_with("TerminateProcess") || n.starts_with("ExitProcess") ||
        n.starts_with("NtCreateProcess") || n.starts_with("NtOpenProcess") ||
        n.starts_with("NtTerminateProcess")) {
        return BehaviorClass::kProcess;
    }
    if (n.starts_with("CreateThread") || n.starts_with("OpenThread") ||
        n.starts_with("SuspendThread") || n.starts_with("ResumeThread") ||
        n.starts_with("NtCreateThread") || n.starts_with("NtOpenThread") ||
        n.starts_with("TlsAlloc") || n.starts_with("TlsFree")) {
        return BehaviorClass::kThread;
    }
    if (n.starts_with("VirtualAlloc") || n.starts_with("VirtualFree") ||
        n.starts_with("VirtualProtect") || n.starts_with("VirtualQuery") ||
        n.starts_with("MapViewOfFile") || n.starts_with("UnmapViewOfFile") ||
        n.starts_with("NtAllocateVirtualMemory") ||
        n.starts_with("NtFreeVirtualMemory") ||
        n.starts_with("NtProtectVirtualMemory")) {
        return BehaviorClass::kMemory;
    }
    if (n.starts_with("HeapAlloc") || n.starts_with("HeapFree") ||
        n.starts_with("HeapCreate") || n.starts_with("HeapDestroy")) {
        return BehaviorClass::kHeap;
    }
    if (n.starts_with("Sleep") || n.starts_with("Wait") ||
        n.starts_with("NtWait") || n.starts_with("CreateEvent") ||
        n.starts_with("CreateMutex") || n.starts_with("CreateSemaphore") ||
        n.starts_with("ReleaseMutex") || n.starts_with("ReleaseSemaphore")) {
        return BehaviorClass::kSync;
    }
    if (n.starts_with("GetTickCount") || n.starts_with("QueryPerformance") ||
        n.starts_with("NtQuerySystemTime") || n.starts_with("GetSystemTime") ||
        n.starts_with("GetLocalTime") || n.starts_with("GetCurrentTime") ||
        n.starts_with("GetProcessTimes") || n.starts_with("GetThreadTimes")) {
        return BehaviorClass::kTime;
    }
    if (n.starts_with("Crypt") || n.starts_with("BCrypt") ||
        n.starts_with("NCrypt") || n.starts_with("Cert")) {
        return BehaviorClass::kCrypt;
    }
    if (n.starts_with("GetEnvironment") || n.starts_with("SetEnvironment") ||
        n.starts_with("ExpandEnvironment")) {
        return BehaviorClass::kEnvironment;
    }
    (void)module;
    return BehaviorClass::kOther;
}

std::string_view class_name(BehaviorClass c) noexcept {
    switch (c) {
    case BehaviorClass::kFile:
        return "file";
    case BehaviorClass::kNetwork:
        return "network";
    case BehaviorClass::kRegistry:
        return "registry";
    case BehaviorClass::kProcess:
        return "process";
    case BehaviorClass::kMemory:
        return "memory";
    case BehaviorClass::kSync:
        return "sync";
    case BehaviorClass::kTime:
        return "time";
    case BehaviorClass::kCrypt:
        return "crypt";
    case BehaviorClass::kEnvironment:
        return "environment";
    case BehaviorClass::kThread:
        return "thread";
    case BehaviorClass::kHeap:
        return "heap";
    case BehaviorClass::kOther:
        return "other";
    }
    return "?";
}

Policy::Policy() {
    defaults_.fill(Action::kMonitor);
}

void Policy::set_default(BehaviorClass c, Action a) noexcept {
    defaults_[static_cast<std::size_t>(c)] = a;
}

Action Policy::default_for(BehaviorClass c) const noexcept {
    return defaults_[static_cast<std::size_t>(c)];
}

void Policy::override_api(std::uint64_t callee, Action a) noexcept {
    overrides_[callee] = a;
}

bool Policy::has_override(std::uint64_t callee, Action* out) const noexcept {
    const auto it = overrides_.find(callee);
    if (it == overrides_.end()) {
        return false;
    }
    if (out != nullptr) {
        *out = it->second;
    }
    return true;
}

Action Policy::decide(BehaviorClass c, std::uint64_t callee) const noexcept {
    Action a{};
    if (has_override(callee, &a)) {
        return a;
    }
    return default_for(c);
}

void Simulator::map_file(std::string path, bool exists) {
    files_[std::move(path)] = exists;
}

bool Simulator::file_exists(std::string_view path) const noexcept {
    const auto it = files_.find(std::string(path));
    if (it == files_.end()) {
        return false;
    }
    return it->second;
}

void Simulator::set_env(std::string name, std::string value) {
    env_[std::move(name)] = std::move(value);
}

bool Simulator::env_get(std::string_view name, std::string* out) const noexcept {
    const auto it = env_.find(std::string(name));
    if (it == env_.end()) {
        return false;
    }
    if (out != nullptr) {
        *out = it->second;
    }
    return true;
}

void Simulator::set_registry(std::string path, std::uint64_t value) {
    registry_[std::move(path)] = value;
}

bool Simulator::registry_get(std::string_view path,
                             std::uint64_t* out) const noexcept {
    const auto it = registry_.find(std::string(path));
    if (it == registry_.end()) {
        return false;
    }
    if (out != nullptr) {
        *out = it->second;
    }
    return true;
}

void Simulator::set_generic_status(bool success) noexcept {
    status_ = success;
}

void Simulator::set_failure_fraction(double f) noexcept {
    failure_fraction_ = std::clamp(f, 0.0, 1.0);
}

bool Simulator::generic_status() const noexcept {
    if (failure_fraction_ > 0.0) {
        // Fixed-seed PRNG: the answer sequence is reproducible for a
        // given failure fraction, so the sandbox stays deterministic
        // (the header contract) while still exercising failure paths.
        std::mt19937_64 rng(0x4f545f524e47);  // "OCC_RNG" tag
        const double r = static_cast<double>(rng() % 100) / 100.0;
        return r >= failure_fraction_;
    }
    return status_;
}

void CallLog::append(const CallRecord& r) {
    records_.push_back(r);
}

std::size_t CallLog::size() const noexcept {
    return records_.size();
}

const CallRecord& CallLog::at(std::size_t i) const noexcept {
    return records_[i];
}

const std::vector<CallRecord>& CallLog::records() const noexcept {
    return records_;
}

void CallLog::replay(ReplayFn fn) const {
    for (const auto& r : records_) {
        fn(r);
    }
}

void TaintTracker::mark(std::uint64_t addr, std::size_t size) {
    const std::uint64_t first = addr / kBucket;
    const std::uint64_t last = (addr + size - 1) / kBucket;
    for (std::uint64_t b = first; b <= last; ++b) {
        buckets_.insert(b);
    }
}

void TaintTracker::clear(std::uint64_t addr, std::size_t size) {
    const std::uint64_t first = addr / kBucket;
    const std::uint64_t last = (addr + size - 1) / kBucket;
    for (std::uint64_t b = first; b <= last; ++b) {
        buckets_.erase(b);
    }
}

bool TaintTracker::is_tainted(std::uint64_t addr,
                              std::size_t size) const noexcept {
    if (size == 0) {
        return false;
    }
    const std::uint64_t first = addr / kBucket;
    const std::uint64_t last = (addr + size - 1) / kBucket;
    for (std::uint64_t b = first; b <= last; ++b) {
        if (buckets_.count(b) != 0) {
            return true;
        }
    }
    return false;
}

void TaintTracker::propagate(std::uint64_t dst, std::size_t dst_size,
                             std::uint64_t src, std::size_t src_size) noexcept {
    if (is_tainted(src, src_size)) {
        mark(dst, dst_size);
    }
}

std::size_t TaintTracker::bucket_count() const noexcept {
    return buckets_.size();
}

Sandbox::Sandbox() = default;

Sandbox::Sandbox(Policy policy) : policy_(std::move(policy)) {}

Policy& Sandbox::policy() noexcept {
    return policy_;
}

const Policy& Sandbox::policy() const noexcept {
    return policy_;
}

Simulator& Sandbox::simulator() noexcept {
    return sim_;
}

const Simulator& Sandbox::simulator() const noexcept {
    return sim_;
}

CallLog& Sandbox::log() noexcept {
    return log_;
}

const CallLog& Sandbox::log() const noexcept {
    return log_;
}

TaintTracker& Sandbox::taint() noexcept {
    return taint_;
}

const TaintTracker& Sandbox::taint() const noexcept {
    return taint_;
}

Hooks& Sandbox::hooks() noexcept {
    return hooks_;
}

void Sandbox::set_classifier(std::function<BehaviorClass(std::uint64_t)> fn) {
    classifier_ = std::move(fn);
}

const std::function<BehaviorClass(std::uint64_t)>& Sandbox::classifier()
    const noexcept {
    return classifier_;
}

CallRecord Sandbox::run(const CallContext& ctx) {
    if (hooks_.on_call) {
        hooks_.on_call(ctx);
    }

    // Classification is coarse and caller-provided today; the sandbox
    // itself has no symbol table. A consumer that knows the callee maps
    // it to a BehaviorClass before calling run(); the default is kOther.
    CallRecord r;
    r.seq = seq_++;
    r.callee = ctx.callee;
    r.caller = ctx.caller;
    r.thread_id = ctx.thread_id;
    r.cls = classifier_ ? classifier_(ctx.callee) : ctx.cls;
    r.argc = ctx.argc;
    for (std::size_t i = 0; i < ctx.argc; ++i) {
        r.args[i] = ctx.args[i].value;
    }

    r.action = policy_.decide(r.cls, r.callee);
    switch (r.action) {
    case Action::kDeny:
        r.ret = 0;
        break;
    case Action::kSimulate: {
        // Deterministic answers: file existence, env, registry, then the
        // generic status. Callers that need per-API shape override the
        // Simulator sets before running.
        r.simulated = true;
        if (ctx.argc > 0 && sim_.file_exists(
                                std::to_string(ctx.args[0].value))) {
            r.ret = 1;
        } else if (ctx.argc > 0 &&
                   sim_.registry_get(std::to_string(ctx.args[0].value),
                                     &r.ret)) {
            // registry answer already in ret
        } else if (sim_.generic_status()) {
            r.ret = 1;
        } else {
            r.ret = 0;
        }
        break;
    }
    case Action::kAllow:
    case Action::kMonitor:
    default:
        r.ret = 0; // the integration fills the real return value
        break;
    }

    log_.append(r);
    if (hooks_.on_result) {
        hooks_.on_result(r);
    }
    return r;
}

} // namespace occ::behave

// Behave (API behavior sandbox) tests.
//
// The decoder is checked for the Win64 and SysV register conventions;
// classification is pinned across the buckets; the policy is exercised
// for defaults, overrides and precedence; the simulator answers only
// from analyst-supplied sets; the taint tracker marks, clears and
// propagates page buckets; and the sandbox end to end decodes,
// classifies through an installed hook, decides, simulates, logs and
// notifies.

#include "occ/behave/behave.h"

#include <cstdio>
#include <cstring>
#include <string>

using namespace occ::behave;

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

void test_decode() {
    // Win64: RCX, RDX, R8, R9 then stack.
    const std::uint64_t regs[6] = {0x1000, 0x2000, 0x3000, 0x4000, 0x5000,
                                   0x6000};
    const std::uint64_t sp[4] = {0x7000, 0x8000, 0, 0};
    const CallContext c =
        decode(CallingConvention::kWin64, 0x1234, 0x5678, 7, regs, sp, 6);
    check(c.callee == 0x1234 && c.caller == 0x5678, "decode: callee/caller");
    check(c.thread_id == 7, "decode: thread id");
    check(c.argc == 6, "decode: argc");
    check(c.args[0].value == 0x1000 && c.args[3].value == 0x4000,
          "decode: register args");
    check(c.args[4].value == 0x7000 && c.args[5].value == 0x8000,
          "decode: stack args");

    // SysV: RDI, RSI, RDX, RCX, R8, R9.
    const CallContext s =
        decode(CallingConvention::kSysV, 0x1234, 0x5678, 1, regs, sp, 3);
    check(s.args[0].value == 0x1000 && s.args[1].value == 0x2000 &&
              s.args[2].value == 0x3000,
          "decode: sysv register order");
}

void test_classify() {
    check(classify("kernel32", "CreateFileW") == BehaviorClass::kFile,
          "cls: file");
    check(classify("ntdll", "NtWriteFile") == BehaviorClass::kFile,
          "cls: nt file");
    check(classify("advapi32", "RegOpenKeyExW") == BehaviorClass::kRegistry,
          "cls: registry");
    check(classify("ws2_32", "socket") == BehaviorClass::kNetwork,
          "cls: socket");
    check(classify("kernel32", "CreateProcessW") == BehaviorClass::kProcess,
          "cls: process");
    check(classify("kernel32", "CreateThread") == BehaviorClass::kThread,
          "cls: thread");
    check(classify("kernel32", "VirtualAlloc") == BehaviorClass::kMemory,
          "cls: memory");
    check(classify("kernel32", "HeapAlloc") == BehaviorClass::kHeap,
          "cls: heap");
    check(classify("kernel32", "Sleep") == BehaviorClass::kSync,
          "cls: sync");
    check(classify("kernel32", "GetTickCount") == BehaviorClass::kTime,
          "cls: time");
    check(classify("advapi32", "CryptAcquireContextW") == BehaviorClass::kCrypt,
          "cls: crypt");
    check(classify("kernel32", "GetEnvironmentVariableW") ==
              BehaviorClass::kEnvironment,
          "cls: environment");
    check(classify("kernel32", "ExitProcess") == BehaviorClass::kProcess,
          "cls: exit process");
    check(classify("kernel32", "SomeUnknownApi") == BehaviorClass::kOther,
          "cls: other");
    check(class_name(BehaviorClass::kFile) == "file", "cls: name");
}

void test_policy() {
    Policy p;
    check(p.default_for(BehaviorClass::kFile) == Action::kMonitor,
          "policy: default is monitor");
    p.set_default(BehaviorClass::kFile, Action::kDeny);
    check(p.default_for(BehaviorClass::kFile) == Action::kDeny,
          "policy: default changed");
    p.override_api(0x1111, Action::kSimulate);
    Action a = Action::kAllow;
    check(p.has_override(0x1111, &a) && a == Action::kSimulate,
          "policy: override present");
    check(p.decide(BehaviorClass::kFile, 0x1111) == Action::kSimulate,
          "policy: override wins over default");
    check(p.decide(BehaviorClass::kFile, 0x2222) == Action::kDeny,
          "policy: default applies elsewhere");
    check(p.decide(BehaviorClass::kNetwork, 0x2222) == Action::kMonitor,
          "policy: per-class defaults independent");
}

void test_simulator() {
    Simulator s;
    s.map_file("C:\\exists.txt", true);
    check(s.file_exists("C:\\exists.txt"), "sim: mapped file exists");
    check(!s.file_exists("C:\\missing.txt"), "sim: unmapped file missing");
    s.set_env("PATH", "/usr/bin");
    std::string out;
    check(s.env_get("PATH", &out) && out == "/usr/bin", "sim: env value");
    check(!s.env_get("HOME", &out), "sim: unset env absent");
    s.set_registry("HKLM\\Software\\X", 42);
    std::uint64_t v = 0;
    check(s.registry_get("HKLM\\Software\\X", &v) && v == 42,
          "sim: registry value");
    check(s.generic_status(), "sim: generic status default true");
    s.set_generic_status(false);
    check(!s.generic_status(), "sim: generic status changed");
}

void test_taint() {
    TaintTracker t;
    t.mark(0x1000, 4096);
    check(t.is_tainted(0x1000, 1), "taint: marked page tainted");
    check(!t.is_tainted(0x2000, 1), "taint: unmarked page clean");
    check(t.bucket_count() == 1, "taint: one bucket");
    t.propagate(0x5000, 4096, 0x1000, 4096);
    check(t.is_tainted(0x5000, 1), "taint: propagate to dst");
    t.clear(0x1000, 4096);
    check(!t.is_tainted(0x1000, 1), "taint: cleared");
}

void test_log() {
    CallLog log;
    CallRecord a;
    a.seq = 0;
    a.callee = 0x1111;
    log.append(a);
    CallRecord b;
    b.seq = 1;
    b.callee = 0x2222;
    log.append(b);
    check(log.size() == 2, "log: size");
    check(log.at(1).callee == 0x2222, "log: ordered access");
    std::size_t seen = 0;
    log.replay([&](const CallRecord&) { ++seen; });
    check(seen == 2, "log: replay visits every record");
}

void test_sandbox() {
    Policy p;
    p.set_default(BehaviorClass::kFile, Action::kDeny);
    p.set_default(BehaviorClass::kNetwork, Action::kSimulate);
    p.override_api(0x3000, Action::kMonitor);

    Sandbox sb(std::move(p));
    // A classifier hook that maps the callees used here.
    sb.set_classifier([](std::uint64_t callee) {
        if (callee == 0x1000) {
            return BehaviorClass::kFile;
        }
        if (callee == 0x2000) {
            return BehaviorClass::kNetwork;
        }
        if (callee == 0x3000) {
            return BehaviorClass::kMemory;
        }
        return BehaviorClass::kOther;
    });
    int calls = 0;
    int results = 0;
    sb.hooks().on_call = [&](const CallContext&) { ++calls; };
    sb.hooks().on_result = [&](const CallRecord&) { ++results; };

    CallContext ctx;
    ctx.callee = 0x1000;  // file -> deny
    ctx.caller = 0x7777;
    ctx.thread_id = 1;
    ctx.conv = CallingConvention::kWin64;
    const CallRecord r1 = sb.run(ctx);
    check(r1.action == Action::kDeny, "sandbox: deny routed");
    check(r1.ret == 0, "sandbox: deny returns 0");

    ctx.callee = 0x2000;  // network -> simulate
    const CallRecord r2 = sb.run(ctx);
    check(r2.action == Action::kSimulate && r2.simulated,
          "sandbox: simulate routed");
    check(r1.seq + 1 == r2.seq, "sandbox: seq increments");

    ctx.callee = 0x3000;  // memory -> override monitor
    const CallRecord r3 = sb.run(ctx);
    check(r3.action == Action::kMonitor, "sandbox: override monitor");

    check(sb.log().size() == 3, "sandbox: all calls logged");
    check(calls == 3 && results == 3, "sandbox: hooks fired");
}

}  // namespace

int main() {
    test_decode();
    test_classify();
    test_policy();
    test_simulator();
    test_taint();
    test_log();
    test_sandbox();
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

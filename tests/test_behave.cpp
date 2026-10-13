// API behavior sandbox tests: arg decoding, policy decisions, simulator
// determinism, call logging, replay, and taint propagation.

#include "occ/behave/behave.h"

#include <array>
#include <cstdio>
#include <cstring>

namespace {

int failures = 0;
int checks = 0;

void check(bool ok, const char* name) {
    ++checks;
    if (!ok) {
        std::printf("FAIL %s\n", name);
        ++failures;
    }
}

void test_decode_win64() {
    // RCX=10, RDX=20, R8=30, R9=40; stack: 50, 60, 70.
    const std::uint64_t regs[6] = {10, 20, 30, 40, 50, 60};
    const std::uint64_t sp[4] = {50, 60, 70, 80};
    const occ::behave::CallContext ctx = occ::behave::decode(
        occ::behave::CallingConvention::kWin64, 0x1000, 0x2000, 7, regs, sp,
        8);
    check(ctx.argc == 8, "decode: eight args decoded");
    check(ctx.args[0].value == 10 && ctx.args[1].value == 20 &&
              ctx.args[2].value == 30 && ctx.args[3].value == 40,
          "decode: win64 register args in RCX RDX R8 R9 order");
    check(ctx.args[4].value == 50 && ctx.args[5].value == 60 &&
              ctx.args[6].value == 70 && ctx.args[7].value == 80,
          "decode: win64 stack args follow");
    check(ctx.callee == 0x1000 && ctx.caller == 0x2000 &&
              ctx.thread_id == 7,
          "decode: context fields preserved");
}

void test_decode_sysv() {
    // RDI, RSI, RDX, RCX, R8, R9.
    const std::uint64_t regs[6] = {1, 2, 3, 4, 5, 6};
    const std::uint64_t sp[2] = {7, 8};
    const occ::behave::CallContext ctx = occ::behave::decode(
        occ::behave::CallingConvention::kSysV, 0, 0, 0, regs, sp, 6);
    check(ctx.args[0].value == 1 && ctx.args[1].value == 2 &&
              ctx.args[2].value == 3 && ctx.args[3].value == 4 &&
              ctx.args[4].value == 5 && ctx.args[5].value == 6,
          "decode: sysv register order");
}

void test_decode_pointers() {
    const std::uint64_t regs[6] = {0x00007FF000001000ull, 0x41, 0, 0, 0, 0};
    const occ::behave::CallContext ctx = occ::behave::decode(
        occ::behave::CallingConvention::kWin64, 0, 0, 0, regs, nullptr, 2);
    check(ctx.args[0].is_pointer, "decode: user-range value is a pointer");
    check(ctx.args[0].string_candidate,
          "decode: pointer to 'A' is a string candidate");
    check(!ctx.args[1].is_pointer, "decode: small value is not a pointer");
}

void test_class_names() {
    check(occ::behave::class_name(occ::behave::BehaviorClass::kFile) ==
              std::string_view("file"),
          "class: file named");
    check(occ::behave::class_name(occ::behave::BehaviorClass::kNetwork) ==
              std::string_view("network"),
          "class: network named");
    check(occ::behave::class_name(occ::behave::BehaviorClass::kOther) ==
              std::string_view("other"),
          "class: other named");
}

void test_policy() {
    occ::behave::Policy p;
    check(p.default_for(occ::behave::BehaviorClass::kFile) ==
              occ::behave::Action::kMonitor,
          "policy: default is monitor");

    p.set_default(occ::behave::BehaviorClass::kFile,
                  occ::behave::Action::kDeny);
    p.set_default(occ::behave::BehaviorClass::kNetwork,
                  occ::behave::Action::kSimulate);
    check(p.decide(occ::behave::BehaviorClass::kFile, 0x1111) ==
              occ::behave::Action::kDeny,
          "policy: class default applied");

    p.override_api(0x2222, occ::behave::Action::kAllow);
    check(p.decide(occ::behave::BehaviorClass::kFile, 0x2222) ==
              occ::behave::Action::kAllow,
          "policy: exact override beats class default");
    check(p.decide(occ::behave::BehaviorClass::kNetwork, 0x2222) ==
              occ::behave::Action::kAllow,
          "policy: override applies across classes");
}

void test_simulator() {
    occ::behave::Simulator s;
    s.map_file("C:\\temp\\flag.txt", true);
    s.map_file("C:\\temp\\missing.txt", false);
    check(s.file_exists("C:\\temp\\flag.txt"),
          "sim: mapped file exists");
    check(!s.file_exists("C:\\temp\\missing.txt"),
          "sim: mapped file absent");
    check(!s.file_exists("C:\\unmapped\\x.txt"),
          "sim: unmapped file absent");

    s.set_env("OLLYDBG", "1");
    std::string v;
    check(s.env_get("OLLYDBG", &v) && v == "1", "sim: env answered");
    check(!s.env_get("NOT_SET", nullptr), "sim: unset env absent");

    s.set_registry("HKLM\\SOFTWARE\\Test", 0x1234);
    std::uint64_t rv = 0;
    check(s.registry_get("HKLM\\SOFTWARE\\Test", &rv) && rv == 0x1234,
          "sim: registry answered");
    check(!s.registry_get("HKLM\\SOFTWARE\\Nope", &rv),
          "sim: unset registry absent");

    s.set_generic_status(true);
    check(s.generic_status(), "sim: generic success");
    s.set_generic_status(false);
    check(!s.generic_status(), "sim: generic failure");
}

void test_call_log() {
    occ::behave::CallLog log;
    occ::behave::CallRecord a;
    a.seq = 1;
    a.callee = 0x1111;
    occ::behave::CallRecord b;
    b.seq = 2;
    b.callee = 0x2222;
    log.append(a);
    log.append(b);
    check(log.size() == 2, "log: two records");
    check(log.at(0).callee == 0x1111 && log.at(1).callee == 0x2222,
          "log: records in order");

    std::size_t seen = 0;
    log.replay([&](const occ::behave::CallRecord& r) {
        check(r.callee == (seen == 0 ? 0x1111ull : 0x2222ull),
              "log: replay order");
        ++seen;
    });
    check(seen == 2, "log: replay visited all");
}

void test_taint() {
    occ::behave::TaintTracker t;
    check(!t.is_tainted(0x100000, 1), "taint: clean by default");
    t.mark(0x100000, 100);
    check(t.is_tainted(0x100000, 1), "taint: marked range reported");
    check(t.is_tainted(0x100040, 1), "taint: within bucket");
    check(!t.is_tainted(0x200000, 1), "taint: other page clean");
    check(t.bucket_count() == 1, "taint: one bucket");

    t.propagate(0x300000, 64, 0x100000, 4);
    check(t.is_tainted(0x300000, 1), "taint: propagated through write");
    check(t.bucket_count() == 2, "taint: two buckets after propagate");

    t.clear(0x100000, 4096);
    check(!t.is_tainted(0x100000, 1), "taint: clear removes the mark");
}

void test_classifier_callback() {
    // A callee -> class map installed on the sandbox wins over the
    // context's own class.
    occ::behave::Sandbox sb;
    sb.set_classifier([](std::uint64_t callee) {
        if (callee == 0x6000) {
            return occ::behave::BehaviorClass::kFile;
        }
        if (callee == 0x7000) {
            return occ::behave::BehaviorClass::kNetwork;
        }
        return occ::behave::BehaviorClass::kOther;
    });
    sb.policy().set_default(occ::behave::BehaviorClass::kFile,
                            occ::behave::Action::kDeny);

    const std::array<std::uint64_t, 6> regs{0, 0, 0, 0, 0, 0};
    occ::behave::CallContext ctx = occ::behave::decode(
        occ::behave::CallingConvention::kWin64, 0x6000, 0x2000, 1, regs.data(),
        nullptr, 1);
    ctx.cls = occ::behave::BehaviorClass::kOther;  // misleading context
    const occ::behave::CallRecord r = sb.run(ctx);
    check(r.cls == occ::behave::BehaviorClass::kFile,
          "classifier: callee map wins");
    check(r.action == occ::behave::Action::kDeny,
          "classifier: class drives policy");
    check(sb.classifier() != nullptr, "classifier: accessor returns it");
}

void test_sandbox_run() {
    occ::behave::Policy p;
    p.set_default(occ::behave::BehaviorClass::kFile,
                  occ::behave::Action::kDeny);
    p.set_default(occ::behave::BehaviorClass::kNetwork,
                  occ::behave::Action::kSimulate);

    occ::behave::Sandbox sb(std::move(p));

    // Denied file call.
    const std::array<std::uint64_t, 6> a1{0x1111, 0, 0, 0, 0, 0};
    occ::behave::CallContext c1 = occ::behave::decode(
        occ::behave::CallingConvention::kWin64, 0x1111, 0x2000, 1, a1.data(),
        nullptr, 1);
    c1.cls = occ::behave::BehaviorClass::kFile;
    const occ::behave::CallRecord r1 = sb.run(c1);
    check(r1.action == occ::behave::Action::kDeny && r1.ret == 0,
          "sandbox: denied call returns 0");
    check(r1.seq == 0, "sandbox: first record seq 0");

    // Simulated network call.
    const std::array<std::uint64_t, 6> a2{0x2222, 0, 0, 0, 0, 0};
    occ::behave::CallContext c2 = occ::behave::decode(
        occ::behave::CallingConvention::kWin64, 0x2222, 0x2000, 1, a2.data(),
        nullptr, 1);
    c2.cls = occ::behave::BehaviorClass::kNetwork;
    const occ::behave::CallRecord r2 = sb.run(c2);
    check(r2.action == occ::behave::Action::kSimulate && r2.simulated,
          "sandbox: simulated call flagged");
    check(sb.log().size() == 2, "sandbox: both calls logged");

    // Hooks fire.
    std::size_t calls = 0;
    std::size_t results = 0;
    occ::behave::Sandbox sb2;
    sb2.hooks().on_call = [&](const occ::behave::CallContext&) { ++calls; };
    sb2.hooks().on_result = [&](const occ::behave::CallRecord&) {
        ++results;
    };
    const std::array<std::uint64_t, 6> a3{0, 0, 0, 0, 0, 0};
    occ::behave::CallContext c3 = occ::behave::decode(
        occ::behave::CallingConvention::kWin64, 0x3333, 0x2000, 1, a3.data(),
        nullptr, 1);
    c3.cls = occ::behave::BehaviorClass::kTime;
    (void)sb2.run(c3);
    check(calls == 1 && results == 1, "sandbox: hooks fired once each");
}

} // namespace

int main() {
    test_decode_win64();
    test_decode_sysv();
    test_decode_pointers();
    test_class_names();
    test_policy();
    test_simulator();
    test_call_log();
    test_taint();
    test_classifier_callback();
    test_sandbox_run();
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

// Anti-debug hardening engine tests: PEB patch facts, the clock model,
// the debug-query answers, environment fingerprints, and plan assembly.

#include "occ/hostile/hostile.h"

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

void test_peb_patches() {
    const occ::hostile::PebPatches p = occ::hostile::compute_peb_patches();
    check(p.needs_heap, "peb: heap resolution required");
    check(p.patches.size() >= 5, "peb: five patches");

    // BeingDebugged: +0x02, 1 byte, mask all.
    bool found_bd = false;
    for (const auto& pa : p.patches) {
        if (pa.offset == 0x02 && pa.width == 1 && pa.mask == 0xFF &&
            !pa.optional) {
            found_bd = true;
        }
    }
    check(found_bd, "peb: BeingDebugged patch facts");

    // NtGlobalFlag: +0x68, 4 bytes, debug bits cleared.
    bool found_ngf = false;
    for (const auto& pa : p.patches) {
        if (pa.offset == 0x68 && pa.width == 4 && (pa.mask & 0x70) == 0x70 &&
            (pa.mask & 0x02000000) != 0) {
            found_ngf = true;
        }
    }
    check(found_ngf, "peb: NtGlobalFlag patch facts");

    // Heap patches are optional (conditional on the heap pointer).
    bool heap_optional = false;
    for (const auto& pa : p.patches) {
        if ((pa.offset == 0x70 || pa.offset == 0x74) && pa.optional) {
            heap_optional = true;
        }
    }
    check(heap_optional, "peb: heap patches are conditional");
}

void test_clock_model() {
    occ::hostile::ClockModel m(1000, 100, 10000); // qpc0=1000, ms0=100,
                                                  // 10 MHz
    check(m.valid(), "clock: single-sample model valid");
    // At qpc 1000 the wall time is exactly ms0.
    check(m.now_ms(1000) == 100, "clock: now at qpc0 equals ms0");
    // 10 MHz: 10000 ticks per ms; 200000 ticks later is 20 ms later.
    check(m.now_ms(201000) == 120, "clock: 200000 ticks -> 20 ms");

    const occ::hostile::ClockModel c =
        occ::hostile::ClockModel::calibrate(0, 0, 100000, 10);
    check(c.valid(), "clock: calibration valid");
    check(c.now_ms(50000) == 5, "clock: calibrated slope applied");
    check(c.qpc_for(5) == 50000, "clock: inverse read returns the qpc");

    const occ::hostile::ClockModel bad =
        occ::hostile::ClockModel::calibrate(100, 100, 100, 100);
    check(!bad.valid(), "clock: zero elapsed window refused");
    check(bad.now_ms(500) == 100, "clock: invalid model clamps to ms0");
}

void test_answer_process_info() {
    auto a = occ::hostile::answer_process_info(7, 0);
    check(a.modeled && a.status == 0 && a.out == 0,
          "query: ProcessDebugPort -> 0 success");

    a = occ::hostile::answer_process_info(8, 0);
    check(a.modeled && a.out == 0, "query: ProcessDebugObjectHandle -> NULL");

    a = occ::hostile::answer_process_info(30, 0);
    check(a.modeled && a.out == 1, "query: ProcessDebugFlags -> 1");

    a = occ::hostile::answer_process_info(31, 0); // unmodeled class
    check(!a.modeled, "query: unmodeled class passed through");
}

void test_answer_system_info() {
    auto a = occ::hostile::answer_system_info(34);
    check(a.modeled && a.out == 0, "query: KernelDebuggerInformation -> clear");

    a = occ::hostile::answer_system_info(5);
    check(!a.modeled, "query: unrelated system class passed through");
}

void test_environment_hidden() {
    check(occ::hostile::environment_hidden("OLLYDBG"), "env: OllyDbg class");
    check(occ::hostile::environment_hidden("ollydbg"), "env: lowercase");
    check(occ::hostile::environment_hidden("X64DBG"), "env: x64dbg");
    check(!occ::hostile::environment_hidden("normal-class"),
          "env: unrelated name visible");
    check(!occ::hostile::environment_hidden("Olly"), "env: prefix not matched");
}

void test_build_plan() {
    occ::hostile::Config cfg;
    const occ::hostile::Plan p = occ::hostile::build_plan(cfg);
    check(p.has_peb_patches, "plan: peb patches present by default");
    check(p.has_clock, "plan: clock present by default");
    check(!p.replace_answers.empty(), "plan: debug answers wired");
    check(p.traps.int3 == occ::hostile::TrapDisposition::kDeliverToGuest,
          "plan: int3 delivered to guest by default");

    occ::hostile::Config off;
    off.hide_peb = false;
    off.uniform_time = false;
    off.answer_debug_queries = false;
    const occ::hostile::Plan q = occ::hostile::build_plan(off);
    check(!q.has_peb_patches, "plan: peb surface can be disabled");
    check(!q.has_clock, "plan: clock surface can be disabled");
    check(q.replace_answers.empty(), "plan: answers can be disabled");
}

} // namespace

int main() {
    test_peb_patches();
    test_clock_model();
    test_answer_process_info();
    test_answer_system_info();
    test_environment_hidden();
    test_build_plan();
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

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

void test_thread_queries() {
    using occ::hostile::answer_thread_info;
    using occ::hostile::answer_set_thread_info;
    const occ::hostile::QueryAnswer q =
        answer_thread_info(static_cast<std::uint32_t>(
            occ::hostile::ThreadInfoClass::kHideFromDebugger));
    check(q.modeled, "thread: hide query modeled");
    check(q.status == 0, "thread: hide query success");
    const occ::hostile::QueryAnswer other = answer_thread_info(0x1234);
    check(!other.modeled, "thread: unknown class passed through");
    const occ::hostile::QueryAnswer s =
        answer_set_thread_info(static_cast<std::uint32_t>(
            occ::hostile::ThreadInfoClass::kHideFromDebugger));
    check(s.modeled, "thread: set-hide modeled");
    check(s.status == 0, "thread: set-hide succeeds");
}

void test_clock_reads() {
    // Calibrate on two samples: 1000->2000 qpc over 50 ms is 20 qpc/ms.
    const occ::hostile::ClockModel m =
        occ::hostile::ClockModel::calibrate(1000, 50000, 2000, 50050);
    check(m.valid(), "clock: calibrated");
    const occ::hostile::TimeAnswers a =
        occ::hostile::clock_reads(m, 3000, 100000);
    // Elapsed qpc is 2000 at 20 qpc/ms -> 100 ms of uptime.
    check(a.tick_count64_ms == 50100, "clock: tick64 from model");
    check(a.tick_count_ms == 50100, "clock: tick32 raw value");
    check(a.qpc == 3000, "clock: qpc is the host sample");
    check(a.rdtsc == 3000, "clock: rdtsc low dword");
    const std::uint64_t ft = (100000ull + 11644473600000ull) * 10000ull;
    check(a.system_time_ft == ft, "clock: filetime 1601 epoch");
}

void test_fingerprint_kinds() {
    using occ::hostile::FingerprintKind;
    using occ::hostile::environment_hidden;
    check(environment_hidden("OLLYDBG", FingerprintKind::kWindowClass),
          "fp: OllyDbg class by kind");
    check(!environment_hidden("ollydbg.exe", FingerprintKind::kWindowClass),
          "fp: wrong kind not matched");
    check(environment_hidden("ollydbg.exe", FingerprintKind::kProcessName),
          "fp: process by kind");
    check(environment_hidden("OLLYDBG.EXE", FingerprintKind::kProcessName),
          "fp: process case-insensitive");
    check(environment_hidden("Software\\OLLYDBG",
                             FingerprintKind::kRegistryKey),
          "fp: registry key by kind");
    check(environment_hidden("TsDebug", FingerprintKind::kMutex),
          "fp: TitanHide legacy mutex");
    const auto& table = occ::hostile::fingerprint_table();
    check(!table.empty(), "fp: table non-empty");
    bool has_process = false;
    bool has_class = false;
    for (const occ::hostile::Fingerprint& f : table) {
        has_process = has_process ||
                      f.kind == FingerprintKind::kProcessName;
        has_class = has_class ||
                    f.kind == FingerprintKind::kWindowClass;
    }
    check(has_process, "fp: table covers processes");
    check(has_class, "fp: table covers window classes");
}

void test_trap_policy() {
    using occ::hostile::TrapDisposition;
    using occ::hostile::TrapKind;
    using occ::hostile::TrapPolicy;
    using occ::hostile::policy_for;
    const TrapPolicy p; // all honest defaults
    check(policy_for(p, TrapKind::kInt3) == TrapDisposition::kDeliverToGuest,
          "trap: int3 delivered");
    check(policy_for(p, TrapKind::kInt2D) == TrapDisposition::kDeliverToGuest,
          "trap: int2d delivered");
    check(policy_for(p, TrapKind::kPrivilegedInstruction) ==
              TrapDisposition::kDeliverToGuest,
          "trap: privileged probe delivered");
    TrapPolicy s;
    s.int3 = TrapDisposition::kSwallow;
    check(policy_for(s, TrapKind::kInt3) == TrapDisposition::kSwallow,
          "trap: int3 swallow honors config");
    check(policy_for(s, TrapKind::kBreakpointFault) ==
              TrapDisposition::kFault,
          "trap: bp fault stays fault");
}

void test_debug_registers() {
    const occ::hostile::DebugRegisters dr = occ::hostile::undebugged_dr();
    check(dr.dr0 == 0 && dr.dr1 == 0 && dr.dr2 == 0 && dr.dr3 == 0,
          "dr: no addresses");
    check(dr.dr6 == 0, "dr: no pending status");
    check(dr.dr7 == 0, "dr: no enabled breakpoints");
}

void test_breakpoint_scan() {
    const std::uint8_t img[] = {
        0x48, 0x89, 0xE5, 0xCC, 0x90, 0xCC, 0xC3,
    };
    const std::uint8_t pristine[] = {
        0x48, 0x89, 0xE5, 0x8B, 0x90, 0x48, 0xC3,
    };
    const auto hits = occ::hostile::scan_breakpoints(img, sizeof(img));
    check(hits.size() == 2, "bp: two int3 found");
    check(hits[0].offset == 3, "bp: first offset");
    check(hits[1].offset == 5, "bp: second offset");
    check(!hits[0].original_known, "bp: pristine unknown without source");
    const auto with_src =
        occ::hostile::scan_breakpoints(img, sizeof(img), pristine);
    check(with_src.size() == 2, "bp: with pristine still two");
    check(with_src[0].original == 0x8B, "bp: original byte recovered");
    check(with_src[0].original_known, "bp: original known with source");
    const auto none =
        occ::hostile::scan_breakpoints(pristine, sizeof(pristine));
    check(none.empty(), "bp: clean image has no hits");
}

void test_probe_host() {
    using occ::hostile::probe_host;
    const occ::hostile::HostProbe clean = probe_host(
        "Name:\tocc\nTracerPid:\t0\nUid:\t1000\n",
        "12345 (occ) S 1 12345 12345 0 -1 4194304 82 0 0 0 0 0 0 0 20 0 "
        "1 0 12345 0 0\n",
        "00400000-00401000 r-xp 00000000 00:00 0 /occ\n"
        "7f0000000000-7f0000001000 rw-p 00000000 00:00 0 [heap]\n");
    check(!clean.traced, "host: not traced");
    check(clean.tracer_pid == 0, "host: tracer pid zero");
    check(clean.parent_pid == 1, "host: parent parsed from stat");
    check(!clean.analyst_in_maps, "host: clean maps");

    const occ::hostile::HostProbe traced = probe_host(
        "TracerPid:\t4242\n",
        "77 (weird) name) S 9 77 77 0 -1 0 0 0 0 0 0 0 0 0 0 20 0 1 0 "
        "77 0 0\n",
        "7f0000000000-7f0000001000 r-xp 00000000 00:00 0 /opt/x64dbg/"
        "x64dbg\n");
    check(traced.traced, "host: traced detected");
    check(traced.tracer_pid == 4242, "host: tracer pid parsed");
    check(traced.parent_pid == 9, "host: parent with parens in comm");
    check(traced.analyst_in_maps, "host: analyst image in maps");
}

int main() {
    test_peb_patches();
    test_clock_model();
    test_answer_process_info();
    test_answer_system_info();
    test_environment_hidden();
    test_build_plan();
    test_thread_queries();
    test_clock_reads();
    test_fingerprint_kinds();
    test_trap_policy();
    test_debug_registers();
    test_breakpoint_scan();
    test_probe_host();
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

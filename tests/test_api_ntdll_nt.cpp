// The Nt* and Zw* half of ntdll. In user mode the two are one function.
//
// The thread-information pair is what this domain carries. The answers
// below are the kernel's shapes: success for a set whose state this
// runtime has no reader for, the invalid-parameter code for a query
// without a buffer, and the length-mismatch code for a buffer that cannot
// hold the four-byte answer. A wine run against the same calls answers
// the same codes, which is the comparison these checks encode. The hide
// flag itself is checked for the round trip it exists for: a set is read
// back by the next query on the same thread, and a thread that never set
// it reads zero.

#include "occ/runtime/api.h"
#include "occ/runtime/exports.h"

#include <cstdint>
#include <cstdio>

using namespace occ::runtime;
using namespace occ::runtime::winabi;

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

// The host functions the tests call. They are declared here rather than
// in a header because they are the guest-facing surface -- `ms_abi`, C
// names -- and the only caller that needs their C++ name is this test.
// The attribute is on the declaration because the host's own convention
// is not the one these bodies read their arguments in.
extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtSetInformationThread(
    std::uint64_t, std::uint32_t, const void*, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t
nt_NtQueryInformationThread(std::uint64_t, std::uint32_t, void*,
                            std::uint32_t, std::uint32_t*) noexcept;

void test_table_is_well_formed() {
    ExportList list;
    add_ntdll_nt(list);
    bool addressed = true;
    int names = 0;
    for (const HostExport& entry : list) {
        if (entry.name.empty() || entry.address == 0) {
            addressed = false;
        }
        ++names;
    }
    check(addressed, "api: every entry has a name and an address");
    check(names == 4, "api: the pair registers under four spellings");
}

// The query answers its four bytes, and names the count it wrote. This
// runs before anything has set the flag on this thread, so the tracked
// class reads clear -- what a fresh thread sees.
void test_query_answers_four_bytes() {
    std::uint32_t out = 0xFFFFFFFFu;
    std::uint32_t written = 0;
    const std::uint32_t status =
        nt_NtQueryInformationThread(0xFFFFFFFFFFFFFFFEull, 0x11, &out, 4,
                                    &written);
    check(status == 0, "ntdll: a four-byte query succeeds");
    check(out == 0, "ntdll: the flag reads as clear for a fresh thread");
    check(written == 4, "ntdll: the count names the four bytes");
}

// The set succeeds. A hide-from-debugger request is the ordinary case:
// the call succeeds and the flag is kept, and nothing else observable
// changes -- which is what the same call does in a process with no
// debugger.
void test_set_succeeds() {
    check(nt_NtSetInformationThread(0xFFFFFFFFFFFFFFFEull, 0x11, nullptr, 0) ==
              0,
          "ntdll: ThreadHideFromDebugger succeeds");
    check(nt_NtSetInformationThread(0xFFFFFFFFFFFFFFFEull, 0x10, nullptr, 0) ==
              0,
          "ntdll: an untracked class succeeds");
}

// The round trip is what the flag exists for: a query after a set reads
// the bit the set left, on the same thread the set named. An untracked
// class still answers zero, because the query reads the flag of its own
// class only.
void test_set_then_query_agrees() {
    std::uint32_t out = 0;
    std::uint32_t written = 0;
    check(nt_NtQueryInformationThread(0xFFFFFFFFFFFFFFFEull, 0x11, &out, 4,
                                      &written) == 0,
          "ntdll: the query after a set succeeds");
    check(out == 1, "ntdll: the flag reads back as set");
    out = 0xFFFFFFFFu;
    check(nt_NtQueryInformationThread(0xFFFFFFFFFFFFFFFEull, 0x10, &out, 4,
                                      &written) == 0,
          "ntdll: the untracked class query succeeds");
    check(out == 0, "ntdll: an untracked class still reads clear");
}

// A buffer that cannot hold the answer is the length-mismatch code, and a
// query without a buffer is the invalid-parameter code -- the kernel's
// own shapes for the two.
void test_query_rejects_the_bad_shapes() {
    std::uint32_t out = 0;
    std::uint32_t written = 0;
    check(nt_NtQueryInformationThread(0xFFFFFFFFFFFFFFFEull, 0x11, &out, 2,
                                      &written) == 0xC0000004u,
          "ntdll: a short buffer is the length-mismatch code");
    check(nt_NtQueryInformationThread(0xFFFFFFFFFFFFFFFEull, 0x11, nullptr, 4,
                                      &written) == 0xC000000Du,
          "ntdll: a missing buffer is the invalid-parameter code");
}

}  // namespace

int main() {
    test_table_is_well_formed();
    test_query_answers_four_bytes();
    test_set_succeeds();
    test_set_then_query_agrees();
    test_query_rejects_the_bad_shapes();
    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks, 0 failures\n", checks);
    return 0;
}

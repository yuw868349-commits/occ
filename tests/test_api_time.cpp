// The time family.
//
// A timestamp moves, so most of what a test can pin down is the arithmetic
// rather than the value: that a conversion round-trips, that the epoch
// offset is the one Windows uses, and that the fields a caller branches on
// are in range. The anchors below are constants, and they are what makes the
// epoch checkable -- `1970-01-01` is `116444736000000000` ticks from 1601,
// and a conversion that lost the offset would answer a number four
// centuries away rather than a number that is merely wrong.
//
// Two behaviours here depart from the reference and the tests assert the
// departure rather than the reference's answer, because both are choices
// this runtime makes on purpose. The reference accepts a `SYSTEMTIME` with
// month 13 and normalises it, and it will move the machine's clock; this
// refuses both, and the reasons are where each refusal is.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

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

constexpr std::size_t kSysBytes = 16;
const std::size_t kSysYear = 0;
const std::size_t kSysMonth = 2;
const std::size_t kSysDayOfWeek = 4;
const std::size_t kSysDay = 6;
const std::size_t kSysHour = 8;
const std::size_t kSysMinute = 10;
const std::size_t kSysSecond = 12;
const std::size_t kSysMilliseconds = 14;

// The ticks between the start of 1601 and the start of 1970, which is the
// constant every conversion here rests on.
constexpr std::uint64_t kEpochDeltaSeconds = 11644473600ULL;
constexpr std::uint64_t kTicksPerSecond = 10000000ULL;

std::uint16_t read_u16(const std::uint8_t* base, std::size_t at) {
    std::uint16_t value = 0;
    std::memcpy(&value, base + at, sizeof(value));
    return value;
}

std::uint32_t read_u32(const std::uint8_t* base, std::size_t at) {
    std::uint32_t value = 0;
    std::memcpy(&value, base + at, sizeof(value));
    return value;
}

std::uint64_t read_ticks(const std::uint8_t* base) {
    return (static_cast<std::uint64_t>(read_u32(base, 4)) << 32) |
           read_u32(base, 0);
}

void write_civil(std::uint8_t* base, std::uint16_t year, std::uint16_t month,
                 std::uint16_t day, std::uint16_t hour, std::uint16_t minute,
                 std::uint16_t second, std::uint16_t milli) {
    std::memset(base, 0, kSysBytes);
    const auto put = [base](std::size_t at, std::uint16_t value) {
        std::memcpy(base + at, &value, sizeof(value));
    };
    put(kSysYear, year);
    put(kSysMonth, month);
    put(kSysDay, day);
    put(kSysHour, hour);
    put(kSysMinute, minute);
    put(kSysSecond, second);
    put(kSysMilliseconds, milli);
}

void test_epoch_anchor() {
    // 1970-01-01 00:00:00 UTC is exactly the offset from 1601. This is the
    // one value in the family that is a constant rather than a reading, so
    // it is the check that the offset is the one Windows uses.
    std::uint8_t civil[kSysBytes];
    write_civil(civil, 1970, 1, 1, 0, 0, 0, 0);
    std::uint8_t ticks[8];
    std::memset(ticks, 0, sizeof(ticks));
    check(k32t_SystemTimeToFileTime(civil, ticks) == 1,
          "time: the epoch converts");
    check(read_ticks(ticks) == kEpochDeltaSeconds * kTicksPerSecond,
          "time: 1970-01-01 is the offset from 1601, in ticks");

    // 2001-01-01 is 978307200 seconds after 1970, so it is that plus the
    // offset, in ticks.
    write_civil(civil, 2001, 1, 1, 0, 0, 0, 0);
    check(k32t_SystemTimeToFileTime(civil, ticks) == 1,
          "time: a later date converts");
    check(read_ticks(ticks) == (978307200ULL + kEpochDeltaSeconds) *
                                   kTicksPerSecond,
          "time: and lands on the tick its seconds name");

    // The first day the format can represent converts to zero, and zero is
    // the value the reverse conversion refuses -- because a zero FILETIME is
    // what an uninitialised structure holds, and reading it as a date would
    // turn a field nothing wrote into the year 1601.
    write_civil(civil, 1601, 1, 1, 0, 0, 0, 0);
    check(k32t_SystemTimeToFileTime(civil, ticks) == 1,
          "time: the first representable day converts");
    check(read_ticks(ticks) == 0,
          "time: and is zero ticks from the start of 1601");
    std::uint8_t back[kSysBytes];
    check(k32t_FileTimeToSystemTime(ticks, back) == 0,
          "time: a zero FILETIME is refused by the reverse conversion");
}

void test_round_trip() {
    std::uint8_t civil[kSysBytes];
    write_civil(civil, 2026, 10, 7, 22, 6, 42, 144);
    std::uint8_t ticks[8];
    std::memset(ticks, 0, sizeof(ticks));
    check(k32t_SystemTimeToFileTime(civil, ticks) == 1, "time: a date converts");

    std::uint8_t back[kSysBytes];
    std::memset(back, 0, sizeof(back));
    check(k32t_FileTimeToSystemTime(ticks, back) == 1,
          "time: and converts back");
    check(read_u16(back, kSysYear) == 2026 && read_u16(back, kSysMonth) == 10 &&
              read_u16(back, kSysDay) == 7,
          "time: with the date it was given");
    check(read_u16(back, kSysHour) == 22 && read_u16(back, kSysMinute) == 6 &&
              read_u16(back, kSysSecond) == 42,
          "time: and the time it was given");
    check(read_u16(back, kSysMilliseconds) == 144,
          "time: and the milliseconds");

    // 2026-10-07 is a Wednesday, which is 3 in a SYSTEMTIME: the field runs
    // from zero for Sunday.
    check(read_u16(back, kSysDayOfWeek) == 3,
          "time: and the day of week, counted from Sunday");
}

void test_invalid_dates() {
    std::uint8_t civil[kSysBytes];
    std::uint8_t ticks[8];

    // The reference accepts month 13 and normalises it into the next year.
    // This refuses, which is what the documentation says and what a caller
    // comparing the answer against what it passed needs.
    write_civil(civil, 2026, 13, 1, 0, 0, 0, 0);
    set_last_error(0);
    check(k32t_SystemTimeToFileTime(civil, ticks) == 0,
          "time: a month of 13 is refused");

    write_civil(civil, 2026, 2, 30, 0, 0, 0, 0);
    check(k32t_SystemTimeToFileTime(civil, ticks) == 0,
          "time: a day the month does not have is refused");

    write_civil(civil, 2026, 0, 1, 0, 0, 0, 0);
    check(k32t_SystemTimeToFileTime(civil, ticks) == 0,
          "time: a month of 0 is refused");

    write_civil(civil, 2026, 1, 1, 24, 0, 0, 0);
    check(k32t_SystemTimeToFileTime(civil, ticks) == 0,
          "time: an hour of 24 is refused");

    write_civil(civil, 1600, 1, 1, 0, 0, 0, 0);
    check(k32t_SystemTimeToFileTime(civil, ticks) == 0,
          "time: a year before the epoch the format starts at is refused");

    // 2024 is a leap year and 2023 is not, so the same day in February is
    // legal in one and not the other.
    write_civil(civil, 2024, 2, 29, 0, 0, 0, 0);
    check(k32t_SystemTimeToFileTime(civil, ticks) == 1,
          "time: the 29th of February is accepted in a leap year");
    write_civil(civil, 2023, 2, 29, 0, 0, 0, 0);
    check(k32t_SystemTimeToFileTime(civil, ticks) == 0,
          "time: and refused in a year that is not one");

    // A null argument is refused rather than read.
    check(k32t_SystemTimeToFileTime(nullptr, ticks) == 0,
          "time: a null date is refused");
    check(k32t_FileTimeToSystemTime(ticks, nullptr) == 0,
          "time: a null output is refused");
}

void test_now() {
    std::uint8_t civil[kSysBytes];
    std::memset(civil, 0, sizeof(civil));
    k32t_GetSystemTime(civil);
    const std::uint16_t year = read_u16(civil, kSysYear);
    check(year >= 2020 && year <= 2200,
          "time: the current time is a year a run could be happening in");
    check(read_u16(civil, kSysMonth) >= 1 && read_u16(civil, kSysMonth) <= 12,
          "time: with a month in range");
    check(read_u16(civil, kSysDayOfWeek) <= 6,
          "time: and a day of week in range");

    std::uint8_t ticks[8];
    std::memset(ticks, 0, sizeof(ticks));
    k32t_GetSystemTimeAsFileTime(ticks);
    check(read_ticks(ticks) > kEpochDeltaSeconds * kTicksPerSecond,
          "time: the current time as ticks is after 1970");
}

void test_ticks() {
    const std::uint32_t small = k32t_GetTickCount();
    const std::uint64_t large = k32t_GetTickCount64();
    check(large > 0, "time: the 64-bit tick count is running");
    // The 32-bit count is the low half of the 64-bit one, which is the
    // relationship a caller that compares the two depends on.
    check(static_cast<std::uint32_t>(large) >= small,
          "time: the two tick counts agree about the low bits");
}

void test_compare() {
    std::uint8_t a[8];
    std::uint8_t b[8];
    const auto set = [](std::uint8_t* out, std::uint64_t value) {
        std::memcpy(out, &value, sizeof(value));
    };
    set(a, 5);
    set(b, 5);
    check(k32t_CompareFileTime(a, b) == 0, "time: equal times compare equal");
    set(b, 6);
    check(k32t_CompareFileTime(a, b) < 0, "time: a smaller time compares less");
    check(k32t_CompareFileTime(b, a) > 0,
          "time: a larger time compares greater");

    // The comparison is over the whole 64 bits as one unsigned number.
    //
    // The values below both have their top bit set, which is what makes the
    // check sensitive to the sign rather than only to the ordering: read as
    // signed, `0xFFFFFFFF00000000` is negative and sorts below
    // `0x00000000FFFFFFFF`, which is the order a caller comparing timestamps
    // would get wrong in the year 30828 and nowhere else. Values below the
    // top bit compare the same either way, so a case built from those would
    // pass against an implementation with the bug.
    set(a, 0xFFFFFFFF00000000ULL);
    set(b, 0x00000000FFFFFFFFULL);
    check(k32t_CompareFileTime(a, b) > 0,
          "time: the halves are compared as one unsigned count");
    check(k32t_CompareFileTime(b, a) < 0,
          "time: and in the other direction");
}

void test_zone() {
    std::uint8_t zone[256];
    std::memset(zone, 0xFF, sizeof(zone));
    const std::uint32_t id = k32t_GetTimeZoneInformation(zone);
    check(id == 0, "time: the zone query answers the unknown identifier");

    std::int32_t bias = 0;
    std::memcpy(&bias, zone, sizeof(bias));
    // A bias is minutes and within a day either way, which is the range a
    // caller uses to sanity-check what it read.
    check(bias > -1440 && bias < 1440, "time: the bias is a real offset");

    // The names are filled rather than left empty, so a program that prints
    // one prints something.
    std::uint16_t first = 0;
    std::memcpy(&first, zone + 4, sizeof(first));
    check(first != 0, "time: the zone name is filled in");
}

void test_local_round_trip() {
    std::uint8_t civil[kSysBytes];
    write_civil(civil, 2026, 6, 15, 12, 0, 0, 0);
    std::uint8_t ticks[8];
    std::memset(ticks, 0, sizeof(ticks));
    k32t_SystemTimeToFileTime(civil, ticks);

    std::uint8_t local[8];
    std::memset(local, 0, sizeof(local));
    check(k32t_FileTimeToLocalFileTime(ticks, local) == 1,
          "time: a time converts to local");
    std::uint8_t round[8];
    std::memset(round, 0, sizeof(round));
    check(k32t_LocalFileTimeToFileTime(local, round) == 1,
          "time: and back");
    check(read_ticks(round) == read_ticks(ticks),
          "time: landing where it started");

    // The pair is an exact inverse, which is what makes it usable: the zone
    // conversion has to be undone by the same offset it applied.
    std::uint8_t tz_local[kSysBytes];
    std::memset(tz_local, 0, sizeof(tz_local));
    check(k32t_SystemTimeToTzSpecificLocalTime(nullptr, civil, tz_local) == 1,
          "time: a date converts to a zone-specific one");
    std::uint8_t tz_utc[kSysBytes];
    std::memset(tz_utc, 0, sizeof(tz_utc));
    check(k32t_TzSpecificLocalTimeToSystemTime(nullptr, tz_local, tz_utc) == 1,
          "time: and back");
    check(read_u16(tz_utc, kSysYear) == 2026 &&
              read_u16(tz_utc, kSysMonth) == 6 &&
              read_u16(tz_utc, kSysDay) == 15 &&
              read_u16(tz_utc, kSysHour) == 12,
          "time: landing on the date it started from");
}

void test_clock_writes_are_refused() {
    std::uint8_t civil[kSysBytes];
    std::memset(civil, 0, sizeof(civil));
    k32t_GetSystemTime(civil);

    // The reference will move the machine's clock from inside a run. A guest
    // that does it moves it for everything else on the machine, which is the
    // one side effect a container exists to prevent, so this answers the
    // error a caller without the privilege already handles.
    set_last_error(0);
    check(k32t_SetSystemTime(civil) == 0,
          "time: setting the system clock is refused");
    check(k32_GetLastError() == 1314,
          "time: with the privilege error a caller already handles");
    check(k32t_SetLocalTime(civil) == 0,
          "time: setting the local clock is refused");

    // The refusal is not a silent one: a caller that ignores the result
    // still reads an error code.
    check(k32_GetLastError() != 0, "time: and the error is left set");
}

void test_system_times() {
    std::uint8_t idle[8];
    std::uint8_t kernel[8];
    std::uint8_t user[8];
    std::memset(idle, 0xFF, sizeof(idle));
    check(k32t_GetSystemTimes(idle, kernel, user) == 1,
          "time: the system times are answered");
    // A process that has been running has used time, so the answer is not
    // zero -- which is what a version returning an uninitialised structure
    // would give.
    check(read_ticks(kernel) > 0 || read_ticks(user) > 0,
          "time: and the answer reflects a running process");
    check(k32t_GetSystemTimes(nullptr, kernel, user) == 0,
          "time: and a null output is refused");
}

// The table itself.
void test_registration() {
    ExportList list;
    add_time_kernel32(list);

    bool duplicate = false;
    for (std::size_t i = 0; i < list.size() && !duplicate; ++i) {
        for (std::size_t k = i + 1; k < list.size(); ++k) {
            if (list[i].name == list[k].name) {
                duplicate = true;
                break;
            }
        }
    }
    check(!duplicate, "time: no name is registered twice");

    bool addressed = true;
    for (const HostExport& entry : list) {
        if (entry.name.empty() || entry.address == 0) {
            addressed = false;
        }
    }
    check(addressed, "time: every entry has a name and an address");
    check(list.size() == 20, "time: the domain contributes twenty names");
}

}  // namespace

int main() {
    test_epoch_anchor();
    test_round_trip();
    test_invalid_dates();
    test_now();
    test_ticks();
    test_compare();
    test_zone();
    test_local_round_trip();
    test_clock_writes_are_refused();
    test_system_times();
    test_registration();

    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks, 0 failures\n", checks);
    return 0;
}

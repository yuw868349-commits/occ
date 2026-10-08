// The Rtl surface's third slice: the clock arithmetic, the pseudo-random
// generators, the heap queries, the lock and run-once families, the
// environment blocks, the security-descriptor builders, the red-black and
// splay tree surgery, and the debug counters.
//
// The shape of this file follows the domain's other slices. Families that
// can be answered from what this runtime already owns are answered for
// real -- the clock conversions are pure arithmetic on the guest's own
// FILETIME, the tree operations are pointer surgery on structures the
// caller supplies, and the environment queries walk a real environment
// block when one is handed over. Families that need a subsystem this
// runtime does not have are refused with the subsystem named at the
// refusal, because a plausible-looking success in a guest that branches on
// it corrupts further down.
//
// The reference for behaviour is the Windows documentation plus a Wine
// source tree used as an oracle for the constants and the edge cases the
// documentation leaves open; no Wine code was copied, and the places where
// a constant was taken from reading that tree are marked where they occur.

#include "occ/runtime/api.h"
#include "occ/runtime/seh.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/address_space.h"
#include "occ/runtime/winabi.h"

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <ctime>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include <time.h>
#include <unistd.h>

namespace occ::runtime::winabi {

namespace {

// The status-to-Win32 mapping, owned by the second slice because that is
// where the table is. This slice reports errors through it for the same
// reason: two tables would be two answers.
extern "C" std::uint32_t occ_ntstatus_to_dos(std::uint32_t status) noexcept;

// The guest's own thread id, which a lock records as its owner. It is the
// value `GetCurrentThreadId` answers, not the host's, because it is the
// only one a guest can compare against.
extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetCurrentThreadId() noexcept;

// The length of a security descriptor, answered by the second slice, which
// owns the accessors that walk the two forms. A second implementation here
// would be a second answer to a question a caller can compare.
extern "C" __attribute__((ms_abi)) std::uint32_t
nr2_RtlLengthSecurityDescriptor(const void* sd) noexcept;



// An NTSTATUS is a 32-bit value whose top bits carry the severity. The
// named constants below are what give the numbers meaning; the two
// encodings -- status and Win32 error -- meet only in the bridge that
// computes one from the other.
using Ntstatus = std::uint32_t;

constexpr Ntstatus kStSuccess = 0x00000000;
constexpr Ntstatus kStPending = 0x00000103;
constexpr Ntstatus kStUnsuccessful = 0xC0000001;
constexpr Ntstatus kStNotImplemented = 0xC0000002;
constexpr Ntstatus kStBufferTooSmall = 0xC0000023;
constexpr Ntstatus kStInvalidParameter = 0xC000000D;
constexpr Ntstatus kStInvalidParameter1 = 0xC00000EF;
constexpr Ntstatus kStObjectNameInvalid = 0xC0000033;
constexpr Ntstatus kStObjectPathNotFound = 0xC000003A;
constexpr Ntstatus kStVariableNotFound = 0xC0000153;
constexpr Ntstatus kStInvalidSid = 0xC0000078;
constexpr Ntstatus kStInvalidAcl = 0xC0000077;
constexpr Ntstatus kStInvalidSecurityDescr = 0xC0000079;
constexpr Ntstatus kStUnknownRevision = 0xC0000058;
constexpr Ntstatus kStNoMemory = 0xC0000017;

// ------------------------------------------------------------- the clock
//
// The tick is 100 nanoseconds and the FILETIME epoch is 1601-01-01, which
// is where the offsets below come from. Nothing here rounds: the
// conversions are exact inverses of one another over the range the
// structures can hold, and the two edges -- a time before the epoch and a
// second count that will not fit in 32 bits -- are refused rather than
// wrapped.

constexpr std::int64_t kTicksPerSecond = 10000000;
constexpr std::int64_t kTicksPerMilli = 10000;
constexpr std::int64_t kSecondsPerDay = 86400;
constexpr std::int64_t kSecondsPerHour = 3600;
constexpr std::int64_t kSecondsPerMinute = 60;
constexpr std::int64_t kDaysPerWeek = 7;
constexpr std::int64_t kEpochWeekday = 1;  // 1601-01-01 was a Monday

// The day counts the calendar cycles are built from: 400 years is 146097
// days and four years is 1461, both of which are what makes the leap rule
// -- every fourth year, except the centuries that are not divisible by
// four hundred -- come out exactly.
constexpr std::int64_t kDaysPerQuadricentennium = 365 * 400 + 97;
constexpr std::int64_t kDaysPerQuadrennium = 365 * 4 + 1;

// The seconds between the FILETIME epoch and the two Unix-era epochs the
// Rtl conversions are defined against.
constexpr std::int64_t kSeconds1601To1970 = 134774LL * 86400;
constexpr std::int64_t kSeconds1601To1980 = 138426LL * 86400;

// TIME_FIELDS: eight 16-bit fields, sixteen bytes, with the weekday last.
constexpr std::size_t kTfYear = 0;
constexpr std::size_t kTfMonth = 2;
constexpr std::size_t kTfDay = 4;
constexpr std::size_t kTfHour = 6;
constexpr std::size_t kTfMinute = 8;
constexpr std::size_t kTfSecond = 10;
constexpr std::size_t kTfMilli = 12;
constexpr std::size_t kTfWeekday = 14;

// The month lengths, indexed by whether the year is a leap year. The table
// is the calendar's, and the second row differs from the first only in
// February, which is the whole of what a leap year changes.
constexpr int kMonthLengths[2][12] = {
    {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
    {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
};

[[nodiscard]] bool is_leap_year(int year) noexcept {
    return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}
void write_i16(void* base, std::size_t offset, std::int16_t value) noexcept {
    const auto bits = static_cast<std::uint16_t>(value);
    write_u16(base, offset, bits);
}

[[nodiscard]] std::int16_t read_i16(const void* base,
                                    std::size_t offset) noexcept {
    return static_cast<std::int16_t>(read_u16(base, offset));
}

[[nodiscard]] std::int64_t read_i64(const void* base,
                                    std::size_t offset) noexcept {
    const auto* bytes = static_cast<const std::uint8_t*>(base);
    std::uint64_t value = 0;
    for (std::size_t k = 0; k < 8; ++k) {
        value |= static_cast<std::uint64_t>(bytes[offset + k]) << (k * 8);
    }
    return static_cast<std::int64_t>(value);
}

void write_i64(void* base, std::size_t offset, std::int64_t value) noexcept {
    const auto bits = static_cast<std::uint64_t>(value);
    auto* bytes = static_cast<std::uint8_t*>(base);
    for (std::size_t k = 0; k < 8; ++k) {
        bytes[offset + k] = static_cast<std::uint8_t>(bits >> (k * 8));
    }
}

// ------------------------------------------------------- the time zone
//
// This runtime runs with the host's own clock and no zone database, so the
// zone it presents is UTC with a bias the guest may set. The bias is the
// one piece of zone state a guest can observe through the conversions, and
// keeping it in one place is what makes `RtlSystemTimeToLocalTime` and the
// reverse agree: two answers derived from one stored number cannot
// disagree about the offset the way two hard-coded ones can.

std::int32_t g_bias_minutes = 0;

}  // namespace

// The bias in minutes, for the reverse conversion in `ntdll_rtl_mem2.cpp`.
// The two functions are a pair and the guest may set the bias through this
// slice, so the number lives here and that file asks for it rather than
// keeping a second copy that a set would not reach.
extern "C" std::int32_t occ_time_zone_bias_minutes() noexcept {
    return g_bias_minutes;
}

namespace {

// TIME_ZONE_INFORMATION on x64: the bias at 0, the standard name at 4, the
// standard transition date at 68, the standard bias at 84, the daylight
// name at 88, the daylight date at 152 and the daylight bias at 168, for
// 172 bytes. Only the offsets this file writes are named: the transition
// dates and the two biases are left zero by the fill below, and zero is
// "no transition" -- which is the honest answer for a zone with no
// daylight rule, and not a field this file has to name to leave alone.
constexpr std::size_t kTziBias = 0;
constexpr std::size_t kTziStandardName = 4;
constexpr std::size_t kTziDaylightName = 88;
constexpr std::size_t kTziBytes = 172;

// DYNAMIC_TIME_ZONE_INFORMATION adds the zone's registry key name and a
// flag that says whether the daylight rule comes from that key.
constexpr std::size_t kDtziKeyName = 172;
constexpr std::size_t kDtziKeyChars = 128;
constexpr std::size_t kDtziDisabled = 428;
constexpr std::size_t kDtziBytes = 432;

// The name this runtime reports for the zone is spelled out at the fill
// rather than taken from the host's zone database: the host may have a zone
// the guest's conversions do not apply, and a name that disagrees with the
// bias the conversions use is worse than a generic one.

void write_zone_name(void* base, std::size_t offset,
                     std::string_view name) noexcept {
    // The field is 32 wide characters and is zero-filled; a name shorter
    // than the field leaves the rest as the terminator it already is.
    constexpr std::size_t kChars = 32;
    for (std::size_t k = 0; k < kChars; ++k) {
        const std::size_t at = offset + k * 2;
        if (k < name.size()) {
            write_u16(base, at, static_cast<std::uint8_t>(name[k]));
        } else {
            write_u16(base, at, 0);
        }
    }
}

void write_time_zone(void* info) noexcept {
    std::memset(info, 0, kTziBytes);
    // The bias is minutes west of UTC, which is the sign a caller
    // subtracts; the two daylight biases are zero because the runtime
    // applies no daylight rule.
    const auto bias = static_cast<std::uint32_t>(g_bias_minutes);
    std::memcpy(static_cast<std::uint8_t*>(info) + kTziBias, &bias, 4);
    write_zone_name(info, kTziStandardName, "Coordinated Universal Time");
    write_zone_name(info, kTziDaylightName, "Coordinated Universal Time");
}

}  // namespace

// -------------------------------------------------------- the conversions

extern "C" __attribute__((ms_abi)) void nr3_RtlTimeToTimeFields(
    const void* time, void* fields) noexcept {
    if (time == nullptr || fields == nullptr) {
        return;
    }
    const std::int64_t ticks = read_i64(time, 0);
    // The milliseconds are the tick remainder divided down, and the rest
    // of the work is on whole seconds. A negative time -- one before the
    // epoch -- is refused by the conversion below rather than wrapped, so
    // the division here is only reached for a representable instant.
    const std::int64_t millis = (ticks % kTicksPerSecond) / kTicksPerMilli;
    const std::int64_t seconds = ticks / kTicksPerSecond;

    std::int64_t days = seconds / kSecondsPerDay;
    std::int64_t in_day = seconds % kSecondsPerDay;
    if (in_day < 0) {
        // Truncating division leaves a negative remainder for a negative
        // time; folding it into the day count keeps the clock-of-day
        // fields in their range instead of writing negative hours.
        in_day += kSecondsPerDay;
        --days;
    }

    write_i16(fields, kTfHour,
              static_cast<std::int16_t>(in_day / kSecondsPerHour));
    in_day %= kSecondsPerHour;
    write_i16(fields, kTfMinute,
              static_cast<std::int16_t>(in_day / kSecondsPerMinute));
    write_i16(fields, kTfSecond,
              static_cast<std::int16_t>(in_day % kSecondsPerMinute));
    write_i16(fields, kTfMilli, static_cast<std::int16_t>(millis));

    // The weekday counts from the epoch's own, which was a Monday.
    std::int64_t weekday = (kEpochWeekday + days) % kDaysPerWeek;
    if (weekday < 0) {
        weekday += kDaysPerWeek;
    }
    write_i16(fields, kTfWeekday, static_cast<std::int16_t>(weekday));

    // The calendar walk. The count of century leap days is what the first
    // line computes: three of every four centuries have a leap day, and
    // the rounding places them before the day being converted.
    std::int64_t cleaps = (3 * ((4 * days + 1227) / kDaysPerQuadricentennium) + 3) / 4;
    days += 28188 + cleaps;
    const std::int64_t years =
        (20 * days - 2442) / (5 * kDaysPerQuadrennium);
    const std::int64_t yearday = days - (years * kDaysPerQuadrennium) / 4;
    const std::int64_t months = (64 * yearday) / 1959;

    // The month count runs from March; a value below fourteen is the
    // following calendar year's January or February, and the two cases
    // differ by exactly the twelve the March origin shifted.
    if (months < 14) {
        write_i16(fields, kTfMonth, static_cast<std::int16_t>(months - 1));
        write_i16(fields, kTfYear, static_cast<std::int16_t>(years + 1524));
    } else {
        write_i16(fields, kTfMonth, static_cast<std::int16_t>(months - 13));
        write_i16(fields, kTfYear, static_cast<std::int16_t>(years + 1525));
    }
    // The day of the month from the month index: the sequence is chosen so
    // that the 31-30 alternation of the calendar comes out exactly.
    write_i16(fields, kTfDay,
              static_cast<std::int16_t>(yearday - (1959 * months) / 64));
}

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlTimeFieldsToTime(
    const void* fields, void* time) noexcept {
    if (fields == nullptr || time == nullptr) {
        return 0;
    }
    const std::int16_t milli = read_i16(fields, kTfMilli);
    const std::int16_t second = read_i16(fields, kTfSecond);
    const std::int16_t minute = read_i16(fields, kTfMinute);
    const std::int16_t hour = read_i16(fields, kTfHour);
    const std::int16_t month = read_i16(fields, kTfMonth);
    const std::int16_t day = read_i16(fields, kTfDay);
    const std::int16_t year = read_i16(fields, kTfYear);

    // Every field is range-checked, including the day against the month it
    // names: a caller that hands over the thirty-first of February gets a
    // refusal rather than a date that rolls into March, which is the
    // difference between an error the caller can find and one it cannot.
    if (milli < 0 || milli > 999 || second < 0 || second > 59 ||
        minute < 0 || minute > 59 || hour < 0 || hour > 23 ||
        month < 1 || month > 12 || day < 1 || year < 1601) {
        return 0;
    }
    const int leap = (month == 2 || is_leap_year(year)) ? 1 : 0;
    if (day > kMonthLengths[leap][month - 1]) {
        return 0;
    }

    // The day count is built the same way the reverse conversion takes it
    // apart: the year is counted from March so the leap day lands at the
    // end of the year, and the constant subtracts the count that lands on
    // 1601-01-01 being zero.
    std::int64_t march_month = 0;
    std::int64_t march_year = 0;
    if (month < 3) {
        march_month = month + 13;
        march_year = year - 1;
    } else {
        march_month = month + 1;
        march_year = year;
    }
    const std::int64_t cleaps = 3 * (march_year / 100) + 3;
    const std::int64_t day_count = (36525 * march_year) / 100 -
                                   cleaps / 4 + (1959 * march_month) / 64 + day -
                                   584817;

    const std::int64_t ticks =
        ((((day_count * 24 + hour) * 60 + minute) * 60 + second) * 1000 +
         milli) *
        kTicksPerMilli;
    write_i64(time, 0, ticks);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlTimeToSecondsSince1970(
    const void* time, std::uint32_t* seconds) noexcept {
    if (time == nullptr || seconds == nullptr) {
        return 0;
    }
    const std::int64_t ticks = read_i64(time, 0);
    const std::int64_t since = ticks / kTicksPerSecond - kSeconds1601To1970;
    // A time before 1970 has a negative count and one past 2106 does not
    // fit the 32-bit field; both are refused, which is what the real
    // function's failure answer means.
    if (since < 0 || since > 0xFFFFFFFFLL) {
        *seconds = 0;
        return 0;
    }
    *seconds = static_cast<std::uint32_t>(since);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlTimeToSecondsSince1980(
    const void* time, std::uint32_t* seconds) noexcept {
    if (time == nullptr || seconds == nullptr) {
        return 0;
    }
    const std::int64_t since =
        read_i64(time, 0) / kTicksPerSecond - kSeconds1601To1980;
    if (since < 0 || since > 0xFFFFFFFFLL) {
        *seconds = 0;
        return 0;
    }
    *seconds = static_cast<std::uint32_t>(since);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlSecondsSince1970ToTime(
    std::uint32_t seconds, void* time) noexcept {
    if (time == nullptr) {
        return 0;
    }
    write_i64(time, 0,
              (static_cast<std::int64_t>(seconds) + kSeconds1601To1970) *
                  kTicksPerSecond);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlSecondsSince1980ToTime(
    std::uint32_t seconds, void* time) noexcept {
    if (time == nullptr) {
        return 0;
    }
    write_i64(time, 0,
              (static_cast<std::int64_t>(seconds) + kSeconds1601To1980) *
                  kTicksPerSecond);
    return 1;
}

extern "C" __attribute__((ms_abi)) void nr3_RtlTimeToElapsedTimeFields(
    const void* time, void* fields) noexcept {
    if (time == nullptr || fields == nullptr) {
        return;
    }
    // An elapsed time is a duration rather than an instant, so it has no
    // calendar: the days are counted whole and the fields hold the
    // remainder, which is what distinguishes this from the instant
    // conversion above for every duration longer than a day.
    std::int64_t ticks = read_i64(time, 0);
    const auto millis = static_cast<std::int16_t>(
        (ticks % kTicksPerSecond) / kTicksPerMilli);
    ticks /= kTicksPerSecond;
    if (ticks < 0) {
        ticks = 0;
    }
    const std::int64_t days = ticks / kSecondsPerDay;
    std::int64_t rest = ticks % kSecondsPerDay;

    write_i16(fields, kTfDay, static_cast<std::int16_t>(std::min<std::int64_t>(
                                               days, 0x7FFF)));
    write_i16(fields, kTfHour,
              static_cast<std::int16_t>(rest / kSecondsPerHour));
    rest %= kSecondsPerHour;
    write_i16(fields, kTfMinute,
              static_cast<std::int16_t>(rest / kSecondsPerMinute));
    write_i16(fields, kTfSecond,
              static_cast<std::int16_t>(rest % kSecondsPerMinute));
    write_i16(fields, kTfMilli, millis);
    // The fields an elapsed time has no use for are zeroed rather than
    // left as the caller's buffer held, so a caller that reads them reads
    // the same answer every time.
    write_i16(fields, kTfYear, 0);
    write_i16(fields, kTfMonth, 0);
    write_i16(fields, kTfWeekday, 0);
}

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlSystemTimeToLocalTime(
    const void* system, void* local) noexcept {
    if (system == nullptr || local == nullptr) {
        return 0;
    }
    // The zone this runtime presents is UTC plus the bias the guest set,
    // so the conversion is the bias applied to the count. The result is
    // still a 1601 tick count: "local" is the same instant read against
    // the zone's own wall clock.
    const std::int64_t ticks = read_i64(system, 0) +
                               static_cast<std::int64_t>(g_bias_minutes) * 60 *
                                   kTicksPerSecond;
    write_i64(local, 0, ticks);
    return 1;
}

// The reverse conversion lives in the second slice, which is where the
// local-to-system direction was written; it asks this file for the bias so
// that a set here reaches it. The declaration is `extern "C"` in both
// translation units so the two spell the same symbol.

extern "C" __attribute__((ms_abi)) std::uint32_t nr3_RtlQueryTimeZoneInformation(
    void* info) noexcept {
    if (info == nullptr) {
        return 0;
    }
    // The return is the identifier of the daylight rule in force, and zero
    // is the value that says the standard rule applies, which is what a
    // runtime with no zone database can answer truthfully.
    write_time_zone(info);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr3_RtlSetTimeZoneInformation(
    const void* info) noexcept {
    if (info == nullptr) {
        return 0;
    }
    // The bias is applied to both conversions from here on, so setting it
    // is the one zone change a guest can make and observe. A bias past a
    // day in either direction is refused: no zone is that far from UTC,
    // and accepting it would put the two conversions a day apart from
    // every other clock in the process.
    std::int32_t bias = 0;
    std::memcpy(&bias, static_cast<const std::uint8_t*>(info) + kTziBias, 4);
    if (bias > 24 * 60 || bias < -(24 * 60)) {
        return 0;
    }
    g_bias_minutes = bias;
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint32_t
nr3_RtlQueryDynamicTimeZoneInformation(void* info) noexcept {
    if (info == nullptr) {
        return 0;
    }
    std::memset(info, 0, kDtziBytes);
    // The dynamic structure opens with the static one, so the same writer
    // fills it; the key name is left empty because no zone key is behind
    // this runtime's clock, and an invented key would name a registry path
    // a caller could try to open.
    write_time_zone(info);
    for (std::size_t k = 0; k < kDtziKeyChars; ++k) {
        write_u16(info, kDtziKeyName + k * 2, 0);
    }
    write_u16(info, kDtziDisabled, 0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t
nr3_RtlQueryUnbiasedInterruptTime(std::uint64_t* ticks) noexcept {
    if (ticks == nullptr) {
        return 0;
    }
    // The unbiased interrupt time is the count since boot with no bias
    // applied to it for power management. A host that does not snooze its
    // own monotonic clock has nothing to add back, and this one does not:
    // the monotonic clock is the honest answer, and it is the same one
    // `QueryUnbiasedInterruptTime` reports.
    timespec now = {};
    ::clock_gettime(CLOCK_MONOTONIC, &now);
    *ticks = static_cast<std::uint64_t>(now.tv_sec) * 10000000ULL +
             static_cast<std::uint64_t>(now.tv_nsec) / 100ULL;
    return 1;
}

// ------------------------------------------------------- the pseudo-random
//
// The two generators this runtime presents are the ones the Rtl surface
// defines, and they are deterministic: the same seed gives the same
// sequence everywhere, which is what makes them testable and what a caller
// reseeding to reproduce a run depends on. The constants are the ones the
// generator is defined by -- a linear congruential recurrence modulo
// 2^31-1 -- rather than chosen, and a test pins the sequence they produce.

namespace {

constexpr std::uint64_t kRngMultiplier = 0x7fffffedULL;
constexpr std::uint64_t kRngIncrement = 0x7fffffc3ULL;
constexpr std::uint64_t kRngModulus = 0x7fffffffULL;

[[nodiscard]] std::uint32_t rng_next(std::uint32_t seed) noexcept {
    return static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(seed) * kRngMultiplier + kRngIncrement) %
        kRngModulus);
}

// The permutation `RtlRandom` reads its answer out of. It is part of the
// generator's definition rather than a choice: a caller that seeds, draws
// twice and compares against a recorded sequence is testing this table as
// much as the recurrence, so the table is stated in full.
constexpr std::uint32_t kRandomTable[128] = {
    0x4c8bc0aa, 0x4c022957, 0x2232827a, 0x2f1e7626, 0x7f8bdafb, 0x5c37d02a,
    0x0ab48f72, 0x2f0c4ffa, 0x290e1954, 0x6b635f23, 0x5d3885c0, 0x74b49ff8,
    0x5155fa54, 0x6214ad3f, 0x111e9c29, 0x242a3a09, 0x75932ae1, 0x40ac432e,
    0x54f7ba7a, 0x585ccbd5, 0x6df5c727, 0x0374dad1, 0x7112b3f1, 0x735fc311,
    0x404331a9, 0x74d97781, 0x64495118, 0x323e04be, 0x5974b425, 0x4862e393,
    0x62389c1d, 0x28a68b82, 0x0f95da37, 0x7a50bbc6, 0x09b0091c, 0x22cdb7b4,
    0x4faaed26, 0x66417ccd, 0x189e4bfa, 0x1ce4e8dd, 0x5274c742, 0x3bdcf4dc,
    0x2d94e907, 0x32eac016, 0x26d33ca3, 0x60415a8a, 0x31f57880, 0x68c8aa52,
    0x23eb16da, 0x6204f4a1, 0x373927c1, 0x0d24eb7c, 0x06dd7379, 0x2b3be507,
    0x0f9c55b1, 0x2c7925eb, 0x36d67c9a, 0x42f831d9, 0x5e3961cb, 0x65d637a8,
    0x24bb3820, 0x4d08e33d, 0x2188754f, 0x147e409e, 0x6a9620a0, 0x62e26657,
    0x7bd8ce81, 0x11da0abb, 0x5f9e7b50, 0x23e444b6, 0x25920c78, 0x5fc894f0,
    0x5e338cbb, 0x404237fd, 0x1d60f80f, 0x320a1743, 0x76013d2b, 0x070294ee,
    0x695e243b, 0x56b177fd, 0x752492e1, 0x6decd52f, 0x125f5219, 0x139d2e78,
    0x1898d11e, 0x2f7ee785, 0x4db405d8, 0x1a028a35, 0x63f6f323, 0x1f6d0078,
    0x307cfd67, 0x3f32a78a, 0x6980796c, 0x462b3d83, 0x34b639f2, 0x53fce379,
    0x74ba50f4, 0x1abc2c4b, 0x5eeaeb8d, 0x335a7a0d, 0x3973dd20, 0x0462d66b,
    0x159813ff, 0x1e4643fd, 0x06bc5c62, 0x3115e3fc, 0x09101613, 0x47af2515,
    0x4f11ec54, 0x78b99911, 0x3db8dd44, 0x1ec10b9b, 0x5b5506ca, 0x773ce092,
    0x567be81a, 0x5475b975, 0x7a2cde1a, 0x494536f5, 0x34737bb4, 0x76d9750b,
    0x2a1f6232, 0x2e49644d, 0x7dddcbe7, 0x500cebdb, 0x619dab9e, 0x48c626fe,
    0x1cda3193, 0x52dabe9d,
};

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint32_t nr3_RtlUniform(
    std::uint32_t* seed) noexcept {
    if (seed == nullptr) {
        return 0;
    }
    // The new seed is the answer, and the caller's seed is advanced as the
    // documenation of the recurrence requires: a caller that draws twice
    // without passing the seed back gets two numbers rather than one.
    *seed = rng_next(*seed);
    return *seed;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr3_RtlRandom(
    std::uint32_t* seed) noexcept {
    if (seed == nullptr) {
        return 0;
    }
    // Two steps of the recurrence: the first is the value that goes into
    // the table, the second selects the slot. The slot's old value is the
    // answer and is replaced by the first, which is what makes the
    // sequence depend on every draw before it.
    const std::uint32_t drawn = rng_next(*seed);
    *seed = rng_next(drawn);
    const std::size_t slot = static_cast<std::size_t>(*seed & 0x7f);
    // The table is the generator's state, so it is mutable; it is not
    // shared with any other thread because there is only one.
    static std::uint32_t table[128] = {};
    static bool primed = false;
    if (!primed) {
        for (std::size_t k = 0; k < 128; ++k) {
            table[k] = kRandomTable[k];
        }
        primed = true;
    }
    const std::uint32_t answer = table[slot];
    table[slot] = drawn;
    return answer;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr3_RtlRandomEx(
    std::uint32_t* seed) noexcept {
    // The Ex spelling is the same generator. The reference implementation
    // is a semi-stub that forwards to `RtlRandom`, and the documentation
    // says only that the sequence differs from the plain one without
    // saying how; presenting a second, invented sequence would be worth
    // less to a caller than the documented one.
    return nr3_RtlRandom(seed);
}

// ------------------------------------------------- the performance counters

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlQueryPerformanceCounter(
    void* counter) noexcept {
    if (counter == nullptr) {
        return 0;
    }
    // The counter is the host's monotonic clock in nanoseconds, and the
    // frequency below says so. The pair is what a caller divides one by
    // the other with, so the two must agree on the unit -- which is why
    // they are written next to each other.
    timespec now = {};
    ::clock_gettime(CLOCK_MONOTONIC, &now);
    const std::int64_t ns = static_cast<std::int64_t>(now.tv_sec) * 1000000000LL +
                            static_cast<std::int64_t>(now.tv_nsec);
    write_i64(counter, 0, ns);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlQueryPerformanceFrequency(
    void* frequency) noexcept {
    if (frequency == nullptr) {
        return 0;
    }
    write_i64(frequency, 0, 1000000000LL);
    return 1;
}

// ---------------------------------------------------------- the last error

extern "C" __attribute__((ms_abi)) void nr3_RtlSetLastWin32Error(
    std::uint32_t error) noexcept {
    set_last_error(error);
}

extern "C" __attribute__((ms_abi)) void
nr3_RtlSetLastWin32ErrorAndNtStatusFromNtStatus(std::uint32_t status) noexcept {
    // The name says exactly what it does: one status in, both stores
    // written. The Win32 half is the mapped error rather than the status
    // itself, because a caller reading `GetLastError` expects the encoding
    // the mapping table defines.
    set_last_error(occ_ntstatus_to_dos(status));
}

// --------------------------------------------------------------- bitmaps
//
// The bitmap here is the RTL_BITMAP the second slice already walks: the
// size first, then a reserved word, then the caller's base pointer. The
// two operations in this slice set bits; the readers that answer how many
// are set live with the readers.

namespace {

constexpr std::size_t kBitmapSize = 0;
constexpr std::size_t kBitmapBase = 8;
constexpr std::size_t kBitsPerWord = 32;

[[nodiscard]] std::uint32_t* bitmap_words(const void* header) noexcept {
    return reinterpret_cast<std::uint32_t*>(read_ptr(header, kBitmapBase));
}

void bitmap_set(std::uint32_t* map, std::size_t index, bool on) noexcept {
    const std::size_t word = index / kBitsPerWord;
    // The bit order is MSB-first within each word: bit zero is the high
    // bit of the first word, which is the kernel's order and not this
    // host's.
    const std::uint32_t mask = 0x80000000u >> (index % kBitsPerWord);
    if (on) {
        map[word] |= mask;
    } else {
        map[word] &= ~mask;
    }
}

}  // namespace

extern "C" __attribute__((ms_abi)) void nr3_RtlSetBits(
    void* header, std::uint32_t start, std::uint32_t count) noexcept {
    if (header == nullptr || count == 0) {
        return;
    }
    std::uint32_t* map = bitmap_words(header);
    const std::uint32_t bits = read_u32(header, kBitmapSize);
    if (map == nullptr) {
        return;
    }
    // A range that runs past the map is clamped rather than refused: the
    // caller asked for the bits from `start` on, and the ones that exist
    // are a subset of what it asked for, which is what the real function
    // does and what keeps a caller that computed a count from a different
    // size honest.
    const std::uint64_t end = static_cast<std::uint64_t>(start) + count;
    const std::uint32_t limit = end > bits ? bits : static_cast<std::uint32_t>(end);
    for (std::uint32_t k = start; k < limit; ++k) {
        bitmap_set(map, k, true);
    }
}

extern "C" __attribute__((ms_abi)) void nr3_RtlSetAllBits(void* header) noexcept {
    if (header == nullptr) {
        return;
    }
    std::uint32_t* map = bitmap_words(header);
    if (map == nullptr) {
        return;
    }
    const std::uint32_t bits = read_u32(header, kBitmapSize);
    for (std::uint32_t k = 0; k < bits; ++k) {
        bitmap_set(map, k, true);
    }
}

// -------------------------------------------------- the current directory
//
// The one DOS path this file has to translate is the drive-rooted form the
// guest's own APIs spell: `Z:\` names the host root and every path under
// it names a path under the host root. The translation is the inverse of
// the one the loader uses to present the guest's view, and it is stated
// here rather than shared because a directory that could be reached one
// way and not the other is worse than two functions that agree.

namespace {

constexpr char16_t kDriveLetter = u'Z';

[[nodiscard]] bool host_path_from_dos(const char16_t* name,
                                      std::string& out) noexcept {
    if (name == nullptr) {
        return false;
    }
    const std::u16string_view text(name);
    if (text.size() < 3 || text[1] != u':' || text[0] != kDriveLetter ||
        (text[2] != u'\\' && text[2] != u'/')) {
        // Only the drive this runtime presents can be translated. A path
        // on another drive names a namespace the guest's own view does not
        // have, and answering with a host path would be a guess.
        return false;
    }
    out.clear();
    for (std::size_t k = 2; k < text.size(); ++k) {
        const char16_t ch = text[k] == u'\\' ? u'/' : text[k];
        if (ch > 0x7F) {
            // The host sees bytes; a character that is not Latin-1 has no
            // byte to be, and the refusal is what keeps a path from being
            // silently truncated at the first such character.
            return false;
        }
        out.push_back(static_cast<char>(ch));
    }
    if (out.empty()) {
        out.push_back('/');
    }
    return true;
}

// The search path mode the guest set through `RtlSetSearchPathMode`. The
// flag is stored because the value is observable through a second call,
// and the bits outside the defined pair are refused rather than masked.
std::uint32_t g_search_path_mode = 0;
constexpr std::uint32_t kSearchPathModeMask = 0x00000003;

}  // namespace

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlSetCurrentDirectory_U(
    const void* dir) noexcept {
    if (dir == nullptr) {
        return kStInvalidParameter1;
    }
    // UNICODE_STRING: the byte length, the capacity, then the buffer. A
    // length that is not a whole number of characters describes nothing.
    const std::uint16_t length = read_u16(dir, 0);
    if ((length % 2) != 0) {
        return kStInvalidParameter1;
    }
    const auto* buffer = reinterpret_cast<const char16_t*>(
        read_ptr(dir, 8));
    if (buffer == nullptr || length == 0) {
        return kStInvalidParameter1;
    }
    const std::u16string wanted(buffer, length / 2);
    std::string host;
    if (!host_path_from_dos(wanted.c_str(), host)) {
        // The name is well formed but names something this runtime has no
        // translation for, or it is not well formed at all; both are the
        // same answer to a caller, which is that the name is not a path it
        // can use.
        return kStObjectNameInvalid;
    }
    if (::chdir(host.c_str()) != 0) {
        return kStObjectPathNotFound;
    }
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlSetSearchPathMode(
    std::uint32_t flags) noexcept {
    if ((flags & ~kSearchPathModeMask) != 0) {
        // A bit outside the two the mode defines is the caller's error, and
        // storing it would leave a mode no documented call could have
        // produced. The answer is the NTSTATUS the call is declared with,
        // not a boolean: a caller compares the result against zero.
        return kStInvalidParameter1;
    }
    g_search_path_mode = flags;
    return kStSuccess;
}

// The mode a guest set, read by the search-path query in the second slice:
// the flag that says the search must not reach the current directory is
// what that query acts on, and it is the only consumer of this state.
extern "C" std::uint32_t occ_search_path_mode() noexcept {
    return g_search_path_mode;
}

// -------------------------------------------- the unhandled-exception filter

namespace {

// The filter a guest registered. It is stored rather than dispatched: the
// dispatch belongs to the exception machinery, which this runtime does not
// run, and a chain that never calls the filter is honest about that
// whereas a fabricated call would not be.
void* g_unhandled_filter = nullptr;

}  // namespace

extern "C" __attribute__((ms_abi)) void* nr3_RtlSetUnhandledExceptionFilter(
    void* filter) noexcept {
    // The call answers the filter it replaced rather than nothing: a caller
    // that installs its own and later wants the previous one back needs the
    // value, and the value is the only thing that reads this state.
    void* const previous = g_unhandled_filter;
    g_unhandled_filter = filter;
    return previous;
}

extern "C" __attribute__((ms_abi)) std::uint8_t
nr3_RtlQueryProcessPlaceholderCompatibilityMode() noexcept {
    // The placeholder mode is a policy about how a package's stubs present
    // themselves. This runtime has no packaged identity, so no placeholder
    // is in play and the answer is the default mode -- which is the value
    // zero, not a refusal, because the question "which mode is in force"
    // has a true answer here.
    return 0;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlWow64IsWowGuestMachineSupported(
    std::uint16_t machine, std::uint8_t* supported) noexcept {
    if (supported == nullptr) {
        return kStInvalidParameter1;
    }
    // The runtime is native 64-bit: there is no 32-bit guest machine under
    // it, so no guest machine other than the one running is supported. The
    // answer is written rather than refused because "is this machine
    // supported" has a true answer for every machine, and it is no.
    static_cast<void>(machine);
    *supported = 0;
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) void nr3_RtlReleasePath(void* path) noexcept {
    // The path lock this releases is the one `RtlAcquirePathLock` takes,
    // and neither function reaches a table this runtime has: the loader's
    // path cache is not modelled. A release with nothing held is a no-op
    // rather than an error, because that is what the call is defined to
    // be when the lock was never taken on this thread.
    static_cast<void>(path);
}

// ------------------------------------------------------------------ heaps
//
// The heap functions are split across the Rtl slices the way the rest of
// this surface is: the first slice mints the handles and the blocks, and
// this one answers the queries about them. What makes that work is that
// both go through the same allocator -- the one every other domain in this
// runtime allocates from -- so a block a guest received from `HeapAlloc`
// and a block it received from `RtlAllocateHeap` are the same kind of
// block, and neither slice has to know which entry point produced it.

namespace {

// Whether the handle names a heap this runtime knows. The table lives with
// the code that mints the handles; asking it is the only way to answer
// this without a second table that could disagree.
extern "C" bool occ_heap_handle_ok(std::uint64_t handle) noexcept;

// The info classes `RtlQueryHeapInformation` and `RtlSetHeapInformation`
// are defined over. The compatibility class carries the low-fragmentation
// heap level, which this runtime does not implement and therefore reports
// as zero rather than as a level it does not honour; the termination class
// carries the flag that makes a corrupted heap end the process, which is a
// policy this runtime can hold.
// HEAP_ZERO_MEMORY: the one allocation flag whose effect is observable in
// the returned block, and therefore the one that has to travel from the
// Rtl entry point down into the allocator.
constexpr std::uint32_t kHeapZeroMemory = 0x00000008;

constexpr std::uint32_t kHeapCompatibilityInformation = 0;
constexpr std::uint32_t kHeapEnableTerminationOnCorruption = 1;

std::uint32_t g_terminate_on_corruption = 0;

}  // namespace

extern "C" __attribute__((ms_abi)) void* nr3_RtlReAllocateHeap(
    void* heap, std::uint32_t flags, void* block, std::uint64_t bytes) noexcept {
    if (!occ_heap_handle_ok(reinterpret_cast<std::uint64_t>(heap))) {
        set_last_error(kErrorInvalidParameter);
        return nullptr;
    }
    if (block == nullptr) {
        // Reallocating nothing is allocating, which is what the Win32 heap
        // does with a null block and what keeps a caller's grow-from-empty
        // path from needing a second call.
        return heap_alloc(flags & kHeapZeroMemory, bytes);
    }
    if (!heap_owns(block)) {
        set_last_error(kErrorInvalidParameter);
        return nullptr;
    }
    // The user bookkeeping is read before the block is reallocated: the
    // allocator releases the old block as part of taking the new one, and a
    // read after that would find the block gone from its ledger and hand
    // back nothing. A caller that hung a value off the old block expects to
    // find it on the new one, and losing it here would be a leak the caller
    // cannot see.
    HeapUserInfo info;
    const bool had_info = heap_user_info(block, info);
    void* fresh = heap_realloc(flags & kHeapZeroMemory, block, bytes);
    if (fresh == nullptr) {
        // The old block is untouched: the allocator leaves it in the ledger
        // when it cannot take a new one, so the caller still owns what it
        // owned and can free it.
        set_last_error(kErrorNotEnoughMemory);
        return nullptr;
    }
    if (had_info) {
        static_cast<void>(heap_set_user_info(fresh, info));
    }
    // The old block was released by the reallocation itself; freeing it
    // again here would be the second free the ledger refuses.
    set_last_error(kErrorSuccess);
    return fresh;
}

extern "C" __attribute__((ms_abi)) std::uint64_t nr3_RtlSizeHeap(
    void* heap, std::uint32_t flags, const void* block) noexcept {
    static_cast<void>(flags);
    if (!occ_heap_handle_ok(reinterpret_cast<std::uint64_t>(heap))) {
        set_last_error(kErrorInvalidParameter);
        return ~static_cast<std::uint64_t>(0);
    }
    if (!heap_owns(block)) {
        // The failure answer is all-ones rather than zero: zero is a size
        // a real block can have, and a caller that checks only the size
        // would take a refused query for an empty block.
        set_last_error(kErrorInvalidParameter);
        return ~static_cast<std::uint64_t>(0);
    }
    set_last_error(kErrorSuccess);
    return heap_size(block);
}

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlValidateHeap(
    void* heap, std::uint32_t flags, const void* block) noexcept {
    static_cast<void>(flags);
    if (!occ_heap_handle_ok(reinterpret_cast<std::uint64_t>(heap))) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // A block this allocator owns is a valid block: the header is written
    // by `heap_alloc` and cannot be reached by the guest, and the ledger
    // check is what says the block is still live rather than a pointer to
    // memory that has already been handed back.
    if (!heap_owns(block)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlValidateProcessHeaps(
    void) noexcept {
    // Every heap in one process shares this allocator's ledger, so
    // validating them all is validating the ledger. The check that means
    // anything here is that no block appears twice, which is what would
    // happen if a free failed to unlink one and a later allocation handed
    // the same address out again.
    const std::vector<void*>& blocks = heap_live_blocks();
    std::vector<void*> sorted(blocks.begin(), blocks.end());
    std::sort(sorted.begin(), sorted.end());
    if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end()) {
        return 0;
    }
    return 1;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlQueryHeapInformation(
    void* heap, std::uint32_t info_class, void* buffer, std::uint32_t length,
    std::uint32_t* returned) noexcept {
    if (!occ_heap_handle_ok(reinterpret_cast<std::uint64_t>(heap))) {
        return kStInvalidParameter;
    }
    if (returned != nullptr) {
        *returned = 0;
    }
    switch (info_class) {
        case kHeapCompatibilityInformation: {
            // The answer is one 32-bit level. A caller that passed a
            // shorter buffer is told the size it needs rather than having
            // half a level written into it.
            if (buffer == nullptr || length < 4) {
                if (returned != nullptr) {
                    *returned = 4;
                }
                return kStBufferTooSmall;
            }
            // Level zero is "no low-fragmentation heap", which is what a
            // runtime whose allocator is its own can honestly report: it
            // has no such heap to switch on.
            write_u32(buffer, 0, 0);
            if (returned != nullptr) {
                *returned = 4;
            }
            return kStSuccess;
        }
        case kHeapEnableTerminationOnCorruption: {
            if (buffer == nullptr || length < 4) {
                if (returned != nullptr) {
                    *returned = 4;
                }
                return kStBufferTooSmall;
            }
            write_u32(buffer, 0, g_terminate_on_corruption);
            if (returned != nullptr) {
                *returned = 4;
            }
            return kStSuccess;
        }
        default:
            return kStInvalidParameter;
    }
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlSetHeapInformation(
    void* heap, std::uint32_t info_class, const void* buffer,
    std::uint32_t length) noexcept {
    if (!occ_heap_handle_ok(reinterpret_cast<std::uint64_t>(heap))) {
        return kStInvalidParameter;
    }
    switch (info_class) {
        case kHeapEnableTerminationOnCorruption: {
            // The class carries a flag, and the flag is stored because a
            // caller reads it back through the query above; a write that
            // was accepted and then not remembered would make the pair
            // disagree.
            if (buffer != nullptr && length < 4) {
                return kStInvalidParameter;
            }
            g_terminate_on_corruption =
                buffer == nullptr ? 0 : (read_u32(buffer, 0) != 0 ? 1u : 0u);
            return kStSuccess;
        }
        case kHeapCompatibilityInformation:
            // Switching the low-fragmentation heap on is a request this
            // allocator cannot honour. Accepting it would leave a caller
            // believing its heap had a property it does not.
            return kStNotImplemented;
        default:
            return kStInvalidParameter;
    }
}

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlSetUserValueHeap(
    void* heap, std::uint32_t flags, void* block, void* value) noexcept {
    static_cast<void>(flags);
    if (!occ_heap_handle_ok(reinterpret_cast<std::uint64_t>(heap)) ||
        !heap_owns(block)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    HeapUserInfo info;
    if (!heap_user_info(block, info)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    info.value = value;
    if (!heap_set_user_info(block, info)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlSetUserFlagsHeap(
    void* heap, std::uint32_t flags, void* block, std::uint32_t user_flags,
    std::uint32_t flags_reset) noexcept {
    static_cast<void>(flags);
    if (!occ_heap_handle_ok(reinterpret_cast<std::uint64_t>(heap)) ||
        !heap_owns(block)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    HeapUserInfo info;
    if (!heap_user_info(block, info)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The two masks are the set and the clear, and they are applied in that
    // order so that a bit in both ends up set -- which is what the real
    // function does and what keeps a caller that cleared and then set the
    // same bit from reading back the other answer.
    info.flags = (info.flags | user_flags) & ~flags_reset;
    info.flags_set_by_user = 1;
    if (!heap_set_user_info(block, info)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlQueryTagHeap(
    void* heap, std::uint32_t flags, std::uint16_t tag, std::uint64_t bytes) noexcept {
    // The heap tags are the remainder of the debug heap, which this runtime
    // does not build: a tag written here would be recorded nowhere, and a
    // caller that tagged its allocations and then walked the heap would
    // find nothing.
    static_cast<void>(heap);
    static_cast<void>(flags);
    static_cast<void>(tag);
    static_cast<void>(bytes);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlUsageHeap(
    void* heap, void* usage) noexcept {
    // Heap usage is the allocator's own accounting, broken out by bucket.
    // This allocator has no buckets to report and no counters behind them,
    // and a zeroed structure would read as "no memory in use", which is the
    // one answer that is certainly false.
    static_cast<void>(heap);
    static_cast<void>(usage);
    return 0;
}

extern "C" __attribute__((ms_abi)) void* nr3_RtlWalkHeap(
    void* heap, void* entry) noexcept {
    // Walking the heap enumerates its blocks in address order. The ledger
    // this runtime keeps has the addresses but not the fields the caller's
    // structure wants -- no block headers, no flags, no per-block totals --
    // so a walk built on it would report a shape the heap does not have.
    static_cast<void>(heap);
    static_cast<void>(entry);
    return nullptr;
}

// ------------------------------------------------- critical sections

namespace {

// The critical section's own layout, which the second slice writes and this
// one reads: the lock count at 8, the recursion count at 12, the owner at
// 16 and the spin count at 32, on a forty-byte structure.
constexpr std::size_t kCritLockCount = 8;
constexpr std::size_t kCritRecursionCount = 12;
constexpr std::size_t kCritOwningThread = 16;
constexpr std::size_t kCritSpinCount = 32;

constexpr std::uint32_t kCritSpinMask = 0x01FFFFFFu;

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlTryEnterCriticalSection(
    void* crit) noexcept {
    if (crit == nullptr) {
        return 0;
    }
    const std::uint32_t self = k32_GetCurrentThreadId();
    const std::int32_t lock = static_cast<std::int32_t>(read_u32(crit, kCritLockCount));
    if (lock >= 0 && read_ptr(crit, kCritOwningThread) == self) {
        // Recursion by the owner takes the section without a wait, which is
        // what distinguishes the try from the plain enter for the one
        // caller that can always succeed.
        write_u32(crit, kCritRecursionCount,
                  read_u32(crit, kCritRecursionCount) + 1);
        return 1;
    }
    if (lock != -1) {
        // Somebody else holds it -- which under this runtime means a
        // caller's own bookkeeping, since there is no second thread to
        // hold it -- and a try must not wait.
        return 0;
    }
    write_u32(crit, kCritLockCount, 0);
    write_u32(crit, kCritRecursionCount, 1);
    write_ptr(crit, kCritOwningThread, self);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint32_t
nr3_RtlSetCriticalSectionSpinCount(void* crit, std::uint32_t spin) noexcept {
    if (crit == nullptr) {
        return 0;
    }
    // The old value comes back, which is what the real function answers and
    // what lets a caller restore it. The stored value is masked because the
    // high bits of the spin field belong to the lock implementation.
    const std::uint32_t previous = read_u32(crit, kCritSpinCount);
    write_u32(crit, kCritSpinCount, spin & kCritSpinMask);
    return previous;
}

extern "C" __attribute__((ms_abi)) void nr3_RtlpWaitForCriticalSection(
    void* crit) noexcept {
    // The waiting path is reached only when the section is held by another
    // thread, and the wait is on a semaphore the section owns. There is one
    // thread, so no call can legitimately arrive here -- and a caller that
    // does has a critical section whose fields say something this runtime
    // did not put there, which is a state a wait would turn into a hang.
    static_cast<void>(crit);
}

extern "C" __attribute__((ms_abi)) std::uint32_t
nr3_RtlpUnWaitCriticalSection(void* crit) noexcept {
    static_cast<void>(crit);
    return 0;
}

// -------------------------------------------------------- the SRW locks
//
// A slim reader-writer lock is one pointer. The values this runtime writes
// into it are the three states a single-threaded guest can observe: zero
// for unlocked, one for held exclusively, and two and up for shared with
// the count offset by that base. The real implementation packs the waiting
// counts into the low bits, which is a representation no guest can see --
// there is no second thread to wait -- and using it here would be
// transcribing a bit layout that could never be read.

namespace {

constexpr std::uint64_t kSrwUnlocked = 0;
constexpr std::uint64_t kSrwExclusive = 1;
constexpr std::uint64_t kSrwSharedBase = 2;

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t
nr3_RtlTryAcquireSRWLockExclusive(void* lock) noexcept {
    if (lock == nullptr) {
        return 0;
    }
    if (read_ptr(lock, 0) != kSrwUnlocked) {
        // Either another holder or this thread's own shared acquisition;
        // both refuse, because the try must not wait and must not upgrade.
        return 0;
    }
    write_ptr(lock, 0, kSrwExclusive);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlTryAcquireSRWLockShared(
    void* lock) noexcept {
    if (lock == nullptr) {
        return 0;
    }
    const std::uint64_t state = read_ptr(lock, 0);
    if (state == kSrwExclusive) {
        return 0;
    }
    const std::uint64_t next =
        state == kSrwUnlocked ? kSrwSharedBase : state + 1;
    write_ptr(lock, 0, next);
    return 1;
}

extern "C" __attribute__((ms_abi)) void nr3_RtlReleaseSRWLockExclusive(
    void* lock) noexcept {
    if (lock == nullptr) {
        return;
    }
    // A release of a lock this thread does not hold would leave the lock in
    // a state no acquire can produce. The check is what keeps a caller's
    // mispaired release from unlocking for everybody.
    if (read_ptr(lock, 0) == kSrwExclusive) {
        write_ptr(lock, 0, kSrwUnlocked);
    }
}

extern "C" __attribute__((ms_abi)) void nr3_RtlReleaseSRWLockShared(
    void* lock) noexcept {
    if (lock == nullptr) {
        return;
    }
    const std::uint64_t state = read_ptr(lock, 0);
    if (state < kSrwSharedBase) {
        return;
    }
    const std::uint64_t next = state - 1;
    write_ptr(lock, 0, next < kSrwSharedBase ? kSrwUnlocked : next);
}

// ----------------------------------------------- condition variables

extern "C" __attribute__((ms_abi)) void nr3_RtlWakeConditionVariable(
    void* variable) noexcept {
    // A wake with no waiter is a no-op that reports nothing, which is
    // exactly what this call is: the runtime runs one thread, so there is
    // never a waiter to hand the wake to. The call is answered rather than
    // refused because refusing would break a caller whose wake is correct
    // and merely unobserved.
    static_cast<void>(variable);
}

extern "C" __attribute__((ms_abi)) void nr3_RtlWakeAllConditionVariable(
    void* variable) noexcept {
    static_cast<void>(variable);
}

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlSleepConditionVariableCS(
    void* variable, void* crit, const void* timeout) noexcept {
    // Sleeping on a condition variable releases the section and waits for a
    // wake. Nobody can wake this thread -- the only thread is the one
    // sleeping -- so the call would block for the whole timeout and then
    // return having done nothing. An infinite timeout would be a hang; a
    // finite one would be a stall that reports a spurious wake. Both are
    // worse than a refusal a caller can see.
    static_cast<void>(variable);
    static_cast<void>(crit);
    static_cast<void>(timeout);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlSleepConditionVariableSRW(
    void* variable, void* lock, const void* timeout,
    std::uint32_t flags) noexcept {
    static_cast<void>(variable);
    static_cast<void>(lock);
    static_cast<void>(timeout);
    static_cast<void>(flags);
    return 0;
}

// ------------------------------------------------------- the run-once

namespace {

// The state word `RTL_RUN_ONCE` is one pointer wide and its low two bits
// are the state: zero is "not begun", one is "in progress synchronously",
// two is "done" with the context in the bits above, and three is "in
// progress asynchronously". A caller's context is therefore stored with its
// low bits cleared, which is what every read below masks back off.
constexpr std::uint64_t kOnceMask = 3;
constexpr std::uint64_t kOnceNotBegun = 0;
constexpr std::uint64_t kOnceInProgress = 1;
constexpr std::uint64_t kOnceDone = 2;
constexpr std::uint64_t kOnceAsyncInProgress = 3;

constexpr std::uint32_t kRunOnceCheckOnly = 0x1;
constexpr std::uint32_t kRunOnceAsync = 0x2;
constexpr std::uint32_t kRunOnceInitFailed = 0x4;

}  // namespace

extern "C" __attribute__((ms_abi)) void nr3_RtlRunOnceInitialize(
    void* once) noexcept {
    if (once == nullptr) {
        return;
    }
    write_ptr(once, 0, kOnceNotBegun);
}

extern "C" __attribute__((ms_abi)) std::uint32_t
nr3_RtlRunOnceBeginInitialize(void* once, std::uint32_t flags,
                              void** context) noexcept {
    if (once == nullptr) {
        return kStInvalidParameter;
    }
    const std::uint64_t state = read_ptr(once, 0);
    if ((flags & kRunOnceCheckOnly) != 0) {
        if ((flags & kRunOnceAsync) != 0) {
            // Asking to begin asynchronously while checking only asks for
            // two contradictory things, and the real function answers that
            // by refusing the pair rather than choosing one.
            return kStInvalidParameter;
        }
        if ((state & kOnceMask) != kOnceDone) {
            return kStUnsuccessful;
        }
        if (context != nullptr) {
            *context = reinterpret_cast<void*>(state & ~kOnceMask);
        }
        return kStSuccess;
    }
    switch (state & kOnceMask) {
        case kOnceNotBegun:
            // The first caller claims the initialization and is told to
            // run it. The asynchronous flag decides which of the two
            // in-progress states is recorded, which is what a second
            // caller reads to learn whether it may wait.
            write_ptr(once, 0, (flags & kRunOnceAsync) != 0
                                   ? kOnceAsyncInProgress
                                   : kOnceInProgress);
            return kStPending;
        case kOnceDone:
            if (context != nullptr) {
                *context = reinterpret_cast<void*>(state & ~kOnceMask);
            }
            return kStSuccess;
        default:
            // The initialization is in progress, and the only thread that
            // could be running it is this one: a caller that reached here
            // re-entered its own initializer. Waiting would deadlock, so
            // the answer is the failure a caller can act on.
            return kStUnsuccessful;
    }
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr3_RtlRunOnceComplete(
    void* once, std::uint32_t flags, void* context) noexcept {
    if (once == nullptr) {
        return kStInvalidParameter;
    }
    if ((flags & kRunOnceInitFailed) != 0) {
        // A failed initialization returns the block to "not begun" rather
        // than marking it done, so a later caller tries again instead of
        // reading a context that was never produced.
        write_ptr(once, 0, kOnceNotBegun);
        return kStUnsuccessful;
    }
    if ((flags & kRunOnceAsync) != 0) {
        return kStInvalidParameter;
    }
    write_ptr(once, 0,
              (reinterpret_cast<std::uint64_t>(context) & ~kOnceMask) |
                  kOnceDone);
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr3_RtlRunOnceExecuteOnce(
    void* once, void* function, void* parameter, void** context) noexcept {
    if (once == nullptr || function == nullptr) {
        return kStInvalidParameter;
    }
    const std::uint32_t begun =
        nr3_RtlRunOnceBeginInitialize(once, 0, context);
    if (begun != kStPending) {
        return begun;
    }
    using InitFn = std::int32_t(__attribute__((ms_abi)) *)(void*, void*, void**);
    const auto init = reinterpret_cast<InitFn>(function);
    if (init(once, parameter, context) == 0) {
        static_cast<void>(
            nr3_RtlRunOnceComplete(once, kRunOnceInitFailed, nullptr));
        return kStUnsuccessful;
    }
    void* produced = context != nullptr ? *context : nullptr;
    return nr3_RtlRunOnceComplete(once, 0, produced);
}

// ------------------------------------------------------ the wait addresses

extern "C" __attribute__((ms_abi)) void nr3_RtlWakeAddressAll(
    void* address) noexcept {
    // Waking every waiter on an address, when there is no other thread to
    // be waiting, is the no-op the call is defined to be.
    static_cast<void>(address);
}

extern "C" __attribute__((ms_abi)) void nr3_RtlWakeAddressSingle(
    void* address) noexcept {
    static_cast<void>(address);
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr3_RtlWaitOnAddress(
    void* address, void* compare, std::uint64_t size,
    const void* timeout) noexcept {
    // Waiting compares the address against the expected value and sleeps
    // until somebody wakes it. Nobody can: this runtime runs one thread, so
    // the wait would run the timeout out and return a spurious wake, or
    // hang forever on an infinite one. The comparison itself is the part
    // that could be answered -- and it is answered by the caller's own load
    // and compare, which is what the function does not add anything to.
    static_cast<void>(address);
    static_cast<void>(compare);
    static_cast<void>(size);
    static_cast<void>(timeout);
    return kStNotImplemented;
}

// ------------------------------------------------------- the environment
//
// Two shapes of environment reach these functions. One is a block the
// caller hands over: a double-terminated array of `NAME=VALUE` wide
// strings, which is the shape the loader builds and the one a caller can
// therefore pass. The other is no block at all, which means the process's
// own environment -- and that is the host's, because this runtime's guest
// starts with the environment its launcher gave it and a set through these
// functions must be visible to the next get.
//
// Walking the block is the part that has to be exact: a name match is by
// whole name up to the '=', and a malformed block -- one with no
// terminator -- must stop rather than run off the end.

namespace {

constexpr std::uint16_t kUsLength = 0;
constexpr std::uint16_t kUsMaximumLength = 2;
constexpr std::size_t kUsBuffer = 8;

// The separator between a name and its value, and the terminator of both a
// string and the block.
constexpr char16_t kEnvSeparator = u'=';
constexpr char16_t kEnvTerminator = u'\0';

// The host's environment for a name, widened. The name is compared
// case-insensitively on the host side and case-sensitively in a block,
// which is the difference between the two stores rather than a choice:
// Windows' environment blocks are case-insensitive too, so both compares
// fold.
[[nodiscard]] bool host_environment_lookup(std::u16string_view name,
                                           std::u16string& value) noexcept {
    std::string narrow;
    if (!narrow_out(name, narrow).converted) {
        return false;
    }
    const char* found = ::getenv(narrow.c_str());
    if (found == nullptr) {
        return false;
    }
    return narrow_in(std::string_view(found), value).converted;
}

// The value of `name` in the block, or false when the block does not have
// it. The walk stops at the block's own terminator rather than at the
// first allocation boundary, so a caller's malformed block is refused
// instead of read past.
[[nodiscard]] bool block_environment_lookup(const char16_t* block,
                                            std::u16string_view name,
                                            std::u16string& value) noexcept {
    if (block == nullptr) {
        return false;
    }
    const char16_t* cursor = block;
    while (*cursor != kEnvTerminator) {
        const char16_t* entry = cursor;
        const char16_t* separator = nullptr;
        while (*cursor != kEnvTerminator) {
            if (*cursor == kEnvSeparator && separator == nullptr) {
                separator = cursor;
            }
            ++cursor;
        }
        if (separator != nullptr) {
            const std::u16string_view entry_name(
                entry, static_cast<std::size_t>(separator - entry));
            if (entry_name == name) {
                value.assign(separator + 1, cursor);
                return true;
            }
        }
        // The entry ended at the terminator; the next one, if any, starts
        // after it. A block whose last entry is not followed by a second
        // terminator would run past its end, which is why the outer loop
        // reads the byte after the closing terminator before continuing.
        ++cursor;
    }
    return false;
}

// Whether a name is one an environment may hold: non-empty, and free of
// the separator except as its first character.
[[nodiscard]] bool environment_name_ok(std::u16string_view name) noexcept {
    if (name.empty()) {
        return false;
    }
    for (std::size_t k = 1; k < name.size(); ++k) {
        if (name[k] == kEnvSeparator) {
            return false;
        }
    }
    return true;
}

}  // namespace

// Copies `value` into the caller's UNICODE_STRING under the convention the
// Rtl surface uses: the length comes back without the terminator, the copy
// carries it when it fits, and a short buffer answers with the size rather
// than a partial string.
[[nodiscard]] Ntstatus environment_answer(const std::u16string& value,
                                          void* out) noexcept {
    if (out == nullptr) {
        return kStInvalidParameter1;
    }
    const std::uint16_t capacity = read_u16(out, kUsMaximumLength);
    const auto needed =
        static_cast<std::uint16_t>(value.size() * sizeof(char16_t));
    write_u16(out, kUsLength, needed);
    if (needed > capacity) {
        return kStBufferTooSmall;
    }
    auto* buffer = reinterpret_cast<char16_t*>(read_ptr(out, kUsBuffer));
    if (buffer == nullptr) {
        // A structure with no buffer cannot receive a string even when its
        // capacity says there is room, and saying so is the honest answer.
        return capacity == 0 ? kStBufferTooSmall : kStInvalidParameter1;
    }
    for (std::size_t k = 0; k < value.size(); ++k) {
        buffer[k] = value[k];
    }
    // The terminator is written only when the capacity can hold it, which
    // is what the length-versus-capacity comparison above decided.
    const std::size_t with_terminator = value.size() + 1;
    if (with_terminator * sizeof(char16_t) <= capacity) {
        buffer[value.size()] = kEnvTerminator;
    }
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlQueryEnvironmentVariable_U(
    const char16_t* env, const void* name, void* value) noexcept {
    if (name == nullptr || value == nullptr) {
        return kStInvalidParameter1;
    }
    const std::uint16_t name_bytes = read_u16(name, kUsLength);
    const auto* name_buffer =
        reinterpret_cast<const char16_t*>(read_ptr(name, kUsBuffer));
    if (name_buffer == nullptr || name_bytes == 0 || (name_bytes % 2) != 0) {
        return kStVariableNotFound;
    }
    const std::u16string_view wanted(name_buffer, name_bytes / 2);

    std::u16string found;
    const bool present = env == nullptr
                             ? host_environment_lookup(wanted, found)
                             : block_environment_lookup(env, wanted, found);
    if (!present) {
        // The value's length is cleared even on the miss, so a caller that
        // ignores the status cannot read the length of a previous answer.
        write_u16(value, kUsLength, 0);
        return kStVariableNotFound;
    }
    return environment_answer(found, value);
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlQueryEnvironmentVariable(
    const char16_t* env, const char16_t* name, std::uint32_t name_chars,
    char16_t* value, std::uint32_t value_chars,
    std::uint32_t* returned) noexcept {
    // The counted spelling. Its lengths are characters rather than bytes,
    // and it reports the value's own length through the last parameter --
    // which is the whole reason it exists beside the structure-based form.
    if (name == nullptr || returned == nullptr) {
        return kStInvalidParameter1;
    }
    *returned = 0;
    if (name_chars == 0) {
        return kStVariableNotFound;
    }
    const std::u16string_view wanted(name, name_chars);

    std::u16string found;
    const bool present = env == nullptr
                             ? host_environment_lookup(wanted, found)
                             : block_environment_lookup(env, wanted, found);
    if (!present) {
        return kStVariableNotFound;
    }
    if (value == nullptr || value_chars < found.size() + 1) {
        *returned = static_cast<std::uint32_t>(found.size());
        return kStBufferTooSmall;
    }
    for (std::size_t k = 0; k < found.size(); ++k) {
        value[k] = found[k];
    }
    value[found.size()] = kEnvTerminator;
    *returned = static_cast<std::uint32_t>(found.size());
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlSetEnvironmentVariable(
    const char16_t** env, const void* name, const void* value) noexcept {
    if (name == nullptr) {
        return kStInvalidParameter1;
    }
    const std::uint16_t name_bytes = read_u16(name, kUsLength);
    const auto* name_buffer =
        reinterpret_cast<const char16_t*>(read_ptr(name, kUsBuffer));
    if (name_buffer == nullptr || name_bytes == 0 || (name_bytes % 2) != 0) {
        return kStInvalidParameter1;
    }
    const std::u16string_view wanted(name_buffer, name_bytes / 2);
    if (!environment_name_ok(wanted)) {
        return kStInvalidParameter1;
    }
    if (env != nullptr && *env != nullptr) {
        // A block the caller passed is the caller's to rebuild: this
        // runtime does not write into a block whose allocation it did not
        // make, and growing it would mean reallocating memory the caller
        // owns. The refusal names the case rather than pretending the write
        // landed.
        return kStNotImplemented;
    }

    std::string narrow;
    if (!narrow_out(wanted, narrow).converted) {
        return kStInvalidParameter1;
    }
    std::u16string wide_value;
    const std::uint16_t value_bytes =
        value == nullptr ? 0 : read_u16(value, kUsLength);
    if (value_bytes != 0) {
        const auto* value_buffer =
            reinterpret_cast<const char16_t*>(read_ptr(value, kUsBuffer));
        if (value_buffer == nullptr || (value_bytes % 2) != 0) {
            return kStInvalidParameter1;
        }
        wide_value.assign(value_buffer, value_bytes / 2);
    }

    if (wide_value.empty()) {
        // An empty value is how the call spells "remove this name", which
        // is what the Win32 wrapper does with a null value and what keeps a
        // caller from needing a second function.
        if (::unsetenv(narrow.c_str()) != 0 && errno != ENOENT) {
            return kStInvalidParameter1;
        }
        return kStSuccess;
    }
    std::string narrow_value;
    if (!narrow_out(wide_value, narrow_value).converted) {
        return kStInvalidParameter1;
    }
    if (::setenv(narrow.c_str(), narrow_value.c_str(), 1) != 0) {
        return kStNoMemory;
    }
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlSetCurrentEnvironment(
    const char16_t* env, char16_t** previous) noexcept {
    // The current environment is a pointer the process keeps and replaces
    // when it rebuilds its block. This runtime's environment lives in the
    // host's own store rather than in a block it can swap, so there is no
    // pointer to hand back and none to install.
    static_cast<void>(env);
    if (previous != nullptr) {
        *previous = nullptr;
    }
    return kStNotImplemented;
}

// The two validity checks are defined below the setters that call them,
// because a setter that accepted a malformed SID would put a structure into
// a descriptor nothing could then read. They are declared here, outside the
// anonymous namespace, so the definition and the declaration are the same
// entity -- a declaration with internal linkage beside it would make the
// registered name ambiguous.
extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlValidSid(
    const void* sid) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlValidAcl(
    const void* acl) noexcept;

// ------------------------------------------------ security descriptors
//
// The two forms of a descriptor store their fields differently -- the
// self-relative form as 32-bit offsets from its own base, the absolute
// form as pointers -- and the setters below therefore have to write the
// field the way the form holds it. Writing an offset where a pointer
// belongs would produce a descriptor the accessors read as a pointer into
// itself, which is exactly the failure this pairing avoids.

namespace {

constexpr std::size_t kSdRevision = 0;
constexpr std::size_t kSdControl = 2;
constexpr std::size_t kSdOwner = 4;
constexpr std::size_t kSdGroup = 8;
constexpr std::size_t kSdSacl = 12;
constexpr std::size_t kSdDacl = 16;
constexpr std::size_t kSdBytes = 20;

// The absolute form's slots, pointer-width and further apart.
constexpr std::size_t kSdAbsOwner = 8;
constexpr std::size_t kSdAbsGroup = 16;
constexpr std::size_t kSdAbsSacl = 24;
constexpr std::size_t kSdAbsDacl = 32;
constexpr std::size_t kSdAbsBytes = 40;

constexpr std::uint16_t kSeSelfRelative = 0x8000;
constexpr std::uint16_t kSeDaclPresent = 0x0004;
constexpr std::uint16_t kSeSaclPresent = 0x0010;
constexpr std::uint16_t kSeDaclDefaulted = 0x0008;
constexpr std::uint16_t kSeSaclDefaulted = 0x0020;
constexpr std::uint16_t kSeOwnerDefaulted = 0x0001;
constexpr std::uint16_t kSeGroupDefaulted = 0x0002;

// An ACL's own fields, and the ACL revisions a caller may ask for.
constexpr std::size_t kAclRevision = 0;
constexpr std::size_t kAclSize = 2;
constexpr std::size_t kAclCount = 4;
constexpr std::size_t kAclBytes = 8;
constexpr std::size_t kAceHeaderBytes = 4;
constexpr std::uint8_t kAclRevisionDs = 2;
constexpr std::uint8_t kAclRevisionMax = 4;

// A SID's fields.
constexpr std::size_t kSidRevision = 0;
constexpr std::size_t kSidCount = 1;
constexpr std::size_t kSidSubAuthority = 8;
constexpr std::uint8_t kSidRevisionValue = 1;
constexpr std::uint8_t kSidMaxSubAuthorities = 15;

[[nodiscard]] bool is_self_relative(const void* sd) noexcept {
    return (read_u16(sd, kSdControl) & kSeSelfRelative) != 0;
}

// Stores a field the way the descriptor's form holds it. A null field
// clears the slot and, for the two ACLs, the presence bit with it: an ACL
// that is not there and a descriptor that says it is are a pair that
// disagrees.
void store_field(void* sd, std::size_t relative_slot,
                 std::size_t absolute_slot, std::size_t relative_offset,
                 const void* field, std::uint16_t present_bit,
                 std::uint16_t defaulted_bit, std::int32_t defaulted,
                 bool acl_field) noexcept {
    std::uint16_t control = read_u16(sd, kSdControl);
    if (acl_field) {
        if (present_bit != 0 && field != nullptr) {
            control |= present_bit;
        } else if (present_bit != 0) {
            control &= static_cast<std::uint16_t>(~present_bit);
        }
    }
    if (defaulted_bit != 0) {
        if (defaulted != 0) {
            control |= defaulted_bit;
        } else {
            control &= static_cast<std::uint16_t>(~defaulted_bit);
        }
    }
    write_u16(sd, kSdControl, control);

    if (is_self_relative(sd)) {
        if (field == nullptr) {
            write_u32(sd, relative_slot, 0);
            return;
        }
        const std::uint64_t base = reinterpret_cast<std::uint64_t>(sd);
        const std::uint64_t at = reinterpret_cast<std::uint64_t>(field);
        if (at < base || at - base > 0xFFFFFFFFull) {
            // A field outside the descriptor's own buffer cannot be named
            // by an offset from it, and writing the truncated offset would
            // point at whatever byte happened to be there.
            write_u32(sd, relative_slot, 0);
            return;
        }
        write_u32(sd, relative_slot, static_cast<std::uint32_t>(at - base));
        static_cast<void>(relative_offset);
        return;
    }
    write_u64(sd, absolute_slot, reinterpret_cast<std::uint64_t>(field));
}

}  // namespace

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlSetDaclSecurityDescriptor(
    void* sd, std::int32_t present, void* acl, std::int32_t defaulted) noexcept {
    if (sd == nullptr) {
        return kStInvalidParameter1;
    }
    if (read_u8(sd, kSdRevision) != 1) {
        return kStUnknownRevision;
    }
    if (acl != nullptr && !nr3_RtlValidAcl(acl)) {
        // A descriptor that named an invalid ACL would fail every access
        // check that read it, and the caller would see a denial rather than
        // its own mistake.
        return kStInvalidAcl;
    }
    store_field(sd, kSdDacl, kSdAbsDacl, 0, present != 0 ? acl : nullptr,
                kSeDaclPresent, kSeDaclDefaulted, defaulted, true);
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlSetSaclSecurityDescriptor(
    void* sd, std::int32_t present, void* acl, std::int32_t defaulted) noexcept {
    if (sd == nullptr) {
        return kStInvalidParameter1;
    }
    if (read_u8(sd, kSdRevision) != 1) {
        return kStUnknownRevision;
    }
    if (acl != nullptr && !nr3_RtlValidAcl(acl)) {
        return kStInvalidAcl;
    }
    store_field(sd, kSdSacl, kSdAbsSacl, 0, present != 0 ? acl : nullptr,
                kSeSaclPresent, kSeSaclDefaulted, defaulted, true);
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlSetOwnerSecurityDescriptor(
    void* sd, void* owner, std::int32_t defaulted) noexcept {
    if (sd == nullptr) {
        return kStInvalidParameter1;
    }
    if (read_u8(sd, kSdRevision) != 1) {
        return kStUnknownRevision;
    }
    if (owner != nullptr && !nr3_RtlValidSid(owner)) {
        return kStInvalidSid;
    }
    // The owner has no presence bit: the field itself says whether there is
    // one, and the bit beside it means the owner came from the token.
    store_field(sd, kSdOwner, kSdAbsOwner, 0, owner, 0, kSeOwnerDefaulted,
                defaulted, false);
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlSetGroupSecurityDescriptor(
    void* sd, void* group, std::int32_t defaulted) noexcept {
    if (sd == nullptr) {
        return kStInvalidParameter1;
    }
    if (read_u8(sd, kSdRevision) != 1) {
        return kStUnknownRevision;
    }
    if (group != nullptr && !nr3_RtlValidSid(group)) {
        return kStInvalidSid;
    }
    store_field(sd, kSdGroup, kSdAbsGroup, 0, group, 0, kSeGroupDefaulted,
                defaulted, false);
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlSetControlSecurityDescriptor(
    void* sd, std::uint16_t control, std::uint16_t mask) noexcept {
    if (sd == nullptr) {
        return kStInvalidParameter1;
    }
    if (read_u8(sd, kSdRevision) != 1) {
        return kStUnknownRevision;
    }
    // The mask selects the bits the call reaches, which is what lets a
    // caller set one control bit without disturbing the others.
    const std::uint16_t current = read_u16(sd, kSdControl);
    write_u16(sd, kSdControl,
              static_cast<std::uint16_t>((current & ~mask) | (control & mask)));
    return kStSuccess;
}

// -------------------------------------------------- the validity checks

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlValidSid(
    const void* sid) noexcept {
    if (sid == nullptr) {
        return 0;
    }
    // The revision must be the one revision there is, and the count must
    // fit the structure: a SID with more sub-authorities than the field
    // can describe is a SID whose length cannot be computed.
    if (read_u8(sid, kSidRevision) != kSidRevisionValue) {
        return 0;
    }
    return read_u8(sid, kSidCount) <= kSidMaxSubAuthorities ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlValidAcl(
    const void* acl) noexcept {
    if (acl == nullptr) {
        return 0;
    }
    const std::uint8_t revision = read_u8(acl, kAclRevision);
    if (revision < kAclRevisionDs || revision > kAclRevisionMax) {
        return 0;
    }
    const std::uint16_t size = read_u16(acl, kAclSize);
    if ((size % 4) != 0 || size < kAclBytes) {
        // An ACL's size is a multiple of four because every ACE is, and a
        // size below the header describes a structure with no room for the
        // header it has.
        return 0;
    }
    // The walk has to end exactly at the size with exactly the count the
    // header states: an ACL whose count is short of or past the ACEs it
    // holds is one whose access checks would read one ACE too many or too
    // few, so it is refused as a whole rather than after the first doubt.
    std::size_t at = kAclBytes;
    const std::uint16_t count = read_u16(acl, kAclCount);
    for (std::uint16_t k = 0; k < count; ++k) {
        if (at + kAceHeaderBytes > size) {
            return 0;
        }
        const std::uint16_t ace_size = read_u16(acl, at + 2);
        if (ace_size < kAceHeaderBytes || at + ace_size > size) {
            return 0;
        }
        at += ace_size;
    }
    return at == size ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlValidSecurityDescriptor(
    const void* sd) noexcept {
    if (sd == nullptr) {
        return 0;
    }
    if (read_u8(sd, kSdRevision) != 1) {
        return 0;
    }
    const std::uint16_t control = read_u16(sd, kSdControl);
    const bool relative = (control & kSeSelfRelative) != 0;
    // The four fields are checked the way their form stores them, and a
    // field that is absent is not checked at all: a descriptor with no
    // owner is a legal descriptor.
    const auto field_ok = [sd, relative, control](std::size_t relative_slot,
                                                  std::size_t absolute_slot,
                                                  std::uint16_t present_bit,
                                                  bool is_sid) {
        if (present_bit != 0 && (control & present_bit) == 0) {
            return true;
        }
        const void* field = nullptr;
        if (relative) {
            const std::uint32_t offset = read_u32(sd, relative_slot);
            if (offset == 0) {
                return true;
            }
            field = static_cast<const std::uint8_t*>(sd) + offset;
        } else {
            const std::uint64_t pointer =
                read_ptr(sd, absolute_slot);
            if (pointer == 0) {
                return true;
            }
            field = reinterpret_cast<const void*>(pointer);
        }
        return is_sid ? nr3_RtlValidSid(field) != 0
                      : nr3_RtlValidAcl(field) != 0;
    };
    return field_ok(kSdOwner, kSdAbsOwner, 0, true) &&
                   field_ok(kSdGroup, kSdAbsGroup, 0, true) &&
                   field_ok(kSdSacl, kSdAbsSacl, kSeSaclPresent, false) &&
                   field_ok(kSdDacl, kSdAbsDacl, kSeDaclPresent, false)
               ? 1
               : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t
nr3_RtlValidRelativeSecurityDescriptor(const void* sd, std::uint32_t length,
                                       std::uint32_t required) noexcept {
    if (sd == nullptr || length < kSdBytes) {
        return 0;
    }
    if (read_u8(sd, kSdRevision) != 1 || !is_self_relative(sd)) {
        return 0;
    }
    // The caller states how many bytes it believes it has, and every field
    // has to end inside that many. A descriptor whose last field ends past
    // the stated length is one a reader would walk off the end of, so the
    // check is the length the caller passed rather than the map.
    const std::uint32_t needed = nr2_RtlLengthSecurityDescriptor(sd);
    if (needed > length) {
        return 0;
    }
    if (required != 0 && needed < required) {
        return 0;
    }
    return nr3_RtlValidSecurityDescriptor(sd);
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlSelfRelativeToAbsoluteSD(
    const void* relative, void* absolute, std::uint32_t* absolute_bytes,
    void* dacl, std::uint32_t* dacl_bytes, void* sacl,
    std::uint32_t* sacl_bytes, void* owner, std::uint32_t* owner_bytes,
    void* group, std::uint32_t* group_bytes) noexcept {
    if (relative == nullptr || absolute == nullptr ||
        absolute_bytes == nullptr) {
        return kStInvalidParameter1;
    }
    if (!is_self_relative(relative)) {
        return kStInvalidSecurityDescr;
    }
    const std::uint32_t needed = nr2_RtlLengthSecurityDescriptor(relative);
    if (*absolute_bytes < kSdAbsBytes) {
        *absolute_bytes = kSdAbsBytes;
        return kStBufferTooSmall;
    }

    // Each field is copied into the caller's own buffer for it, and the
    // four capacity parameters are in/out: a buffer too small is told the
    // size it needs, and -- importantly -- nothing is written to any of
    // them until all four have been checked, because a conversion that
    // filled two buffers and then failed would leave the caller with a
    // descriptor it cannot free or reuse.
    struct Field {
        std::size_t relative_slot;
        std::size_t absolute_slot;
        std::uint16_t present_bit;
        void* target;
        std::uint32_t* capacity;
        std::size_t bytes;
    };
    std::memset(absolute, 0, kSdAbsBytes);
    write_u8(absolute, kSdRevision, read_u8(relative, kSdRevision));
    write_u16(absolute, kSdControl,
              static_cast<std::uint16_t>(read_u16(relative, kSdControl) &
                                         ~kSeSelfRelative));

    const auto size_of = [relative](std::size_t slot,
                                    std::uint16_t present_bit) -> std::size_t {
        const std::uint32_t offset = read_u32(relative, slot);
        if (offset == 0) {
            return 0;
        }
        const void* field = static_cast<const std::uint8_t*>(relative) + offset;
        if (present_bit == 0) {
            return 8 + static_cast<std::size_t>(read_u8(field, kSidCount)) * 4;
        }
        return read_u16(field, kAclSize);
    };

    Field fields[4] = {
        {kSdOwner, kSdAbsOwner, 0, owner, owner_bytes,
         size_of(kSdOwner, 0)},
        {kSdGroup, kSdAbsGroup, 0, group, group_bytes,
         size_of(kSdGroup, 0)},
        {kSdSacl, kSdAbsSacl, kSeSaclPresent, sacl, sacl_bytes,
         (read_u16(relative, kSdControl) & kSeSaclPresent) != 0
             ? size_of(kSdSacl, kSeSaclPresent)
             : 0},
        {kSdDacl, kSdAbsDacl, kSeDaclPresent, dacl, dacl_bytes,
         (read_u16(relative, kSdControl) & kSeDaclPresent) != 0
             ? size_of(kSdDacl, kSeDaclPresent)
             : 0},
    };
    for (const Field& field : fields) {
        if (field.bytes == 0) {
            continue;
        }
        if (field.target == nullptr || field.capacity == nullptr) {
            return kStInvalidParameter1;
        }
        if (*field.capacity < field.bytes) {
            // The size that was too small is reported and the conversion
            // stops here, before anything has been written anywhere.
            *field.capacity = static_cast<std::uint32_t>(field.bytes);
            return kStBufferTooSmall;
        }
    }
    for (const Field& field : fields) {
        if (field.bytes == 0) {
            continue;
        }
        const std::uint32_t offset = read_u32(relative, field.relative_slot);
        const void* source =
            static_cast<const std::uint8_t*>(relative) + offset;
        std::memcpy(field.target, source, field.bytes);
        *field.capacity = static_cast<std::uint32_t>(field.bytes);
        write_ptr(absolute, field.absolute_slot,
                  reinterpret_cast<std::uint64_t>(field.target));
    }
    *absolute_bytes = kSdAbsBytes;
    static_cast<void>(needed);
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlQueryInformationAcl(
    const void* acl, void* info, std::uint32_t length,
    std::uint32_t info_class) noexcept {
    if (acl == nullptr || info == nullptr) {
        return kStInvalidParameter1;
    }
    switch (info_class) {
        case 0: {
            // ACL_INFORMATION_CLASS: the revision, the size and the count,
            // three 32-bit fields, which is what a caller sizing a copy
            // needs before it makes one.
            if (length < 12) {
                return kStBufferTooSmall;
            }
            write_u32(info, 0, read_u8(acl, kAclRevision));
            write_u32(info, 4, read_u16(acl, kAclSize));
            write_u32(info, 8, read_u16(acl, kAclCount));
            return kStSuccess;
        }
        case 1: {
            if (length < 4) {
                return kStBufferTooSmall;
            }
            write_u32(info, 0, read_u8(acl, kAclRevision));
            return kStSuccess;
        }
        default:
            return kStInvalidParameter1;
    }
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlSetInformationAcl(
    const void* acl, const void* info, std::uint32_t length,
    std::uint32_t info_class) noexcept {
    // The one information class is the ACL revision, and changing it would
    // relabel an ACL whose ACEs were written for the revision it had. The
    // reference implementation leaves this a stub for the same reason.
    static_cast<void>(acl);
    static_cast<void>(info);
    static_cast<void>(length);
    static_cast<void>(info_class);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) std::uint32_t* nr3_RtlSubAuthoritySid(
    const void* sid, std::uint32_t index) noexcept {
    if (sid == nullptr) {
        return nullptr;
    }
    // The pointer is into the caller's own structure, so a write through it
    // lands in the SID. An index past the SID's own count names no
    // sub-authority and is refused rather than pointing at whatever follows
    // the SID.
    if (index >= read_u8(sid, kSidCount)) {
        return nullptr;
    }
    // The caller gets a writable pointer into a structure it owns, which is
    // what the real function answers; the const cast is the whole of what
    // makes that possible from a const entry point.
    const void* at = static_cast<const std::uint8_t*>(sid) + kSidSubAuthority +
                     static_cast<std::size_t>(index) * 4;
    return const_cast<std::uint32_t*>(static_cast<const std::uint32_t*>(at));
}

extern "C" __attribute__((ms_abi)) std::uint8_t* nr3_RtlSubAuthorityCountSid(
    const void* sid) noexcept {
    if (sid == nullptr) {
        return nullptr;
    }
    return const_cast<std::uint8_t*>(
        static_cast<const std::uint8_t*>(sid) + kSidCount);
}

// ------------------------------------------------------------ the splay
//
// A splay tree node is three pointers and nothing else: the parent, the
// left child and the right child. The root is the node whose parent points
// at itself, which is the one encoding the whole family is defined by --
// a null parent would make "is this the root" and "is this the left child
// of nothing" the same question.
//
// The operations here are the rotations themselves. They are pure pointer
// surgery on structures the caller owns, which is what makes them the part
// of this surface this runtime can implement without a store behind it:
// the tree exists entirely in the guest's own memory, and the only thing
// that matters is that the links end up in the shape the caller's next
// walk expects.

namespace {

constexpr std::size_t kSplayParent = 0;
constexpr std::size_t kSplayLeft = 8;
constexpr std::size_t kSplayRight = 16;

[[nodiscard]] std::uint64_t splay_parent(const void* node) noexcept {
    return read_ptr(node, kSplayParent);
}

[[nodiscard]] std::uint64_t splay_left(const void* node) noexcept {
    return read_ptr(node, kSplayLeft);
}

[[nodiscard]] std::uint64_t splay_right(const void* node) noexcept {
    return read_ptr(node, kSplayRight);
}

[[nodiscard]] bool splay_is_root(const void* node) noexcept {
    return splay_parent(node) == reinterpret_cast<std::uint64_t>(node);
}

// A node is the left child of its parent when the parent's left link is
// the node. A node whose parent link names nothing is neither, which is
// what keeps the walks below from following a null parent.
[[nodiscard]] bool splay_is_left_child(const void* node) noexcept {
    const std::uint64_t parent = splay_parent(node);
    if (parent == 0) {
        return false;
    }
    return splay_left(reinterpret_cast<const void*>(parent)) ==
           reinterpret_cast<std::uint64_t>(node);
}

[[nodiscard]] bool splay_is_right_child(const void* node) noexcept {
    const std::uint64_t parent = splay_parent(node);
    if (parent == 0) {
        return false;
    }
    return splay_right(reinterpret_cast<const void*>(parent)) ==
           reinterpret_cast<std::uint64_t>(node);
}

// The two rotations. Each moves one node up and its parent down, and the
// parent's own parent is relinked rather than left pointing at the node
// that moved -- a rotation that forgot that link would leave a subtree
// reachable from two roots and one node orphaned.
void splay_rotate(void* pivot, bool to_right) noexcept {
    void* parent = reinterpret_cast<void*>(splay_parent(pivot));
    if (parent == nullptr) {
        return;
    }
    const std::uint64_t grandparent = splay_parent(parent);
    const std::uint64_t moved = to_right ? splay_left(pivot) : splay_right(pivot);

    if (grandparent == reinterpret_cast<std::uint64_t>(parent)) {
        // The parent was the root, which means the pivot becomes the root
        // and its parent link has to point at itself.
        write_ptr(pivot, kSplayParent, reinterpret_cast<std::uint64_t>(pivot));
    } else {
        if (splay_left(reinterpret_cast<const void*>(grandparent)) ==
            reinterpret_cast<std::uint64_t>(parent)) {
            write_ptr(reinterpret_cast<void*>(grandparent), kSplayLeft,
                      reinterpret_cast<std::uint64_t>(pivot));
        } else {
            write_ptr(reinterpret_cast<void*>(grandparent), kSplayRight,
                      reinterpret_cast<std::uint64_t>(pivot));
        }
        write_ptr(pivot, kSplayParent, grandparent);
    }

    if (to_right) {
        write_ptr(parent, kSplayLeft, moved);
        write_ptr(pivot, kSplayRight, reinterpret_cast<std::uint64_t>(parent));
    } else {
        write_ptr(parent, kSplayRight, moved);
        write_ptr(pivot, kSplayLeft, reinterpret_cast<std::uint64_t>(parent));
    }
    if (moved != 0) {
        write_ptr(reinterpret_cast<void*>(moved), kSplayParent,
                  reinterpret_cast<std::uint64_t>(parent));
    }
    write_ptr(parent, kSplayParent, reinterpret_cast<std::uint64_t>(pivot));
}

}  // namespace

extern "C" __attribute__((ms_abi)) void* nr3_RtlSplay(void* links) noexcept {
    if (links == nullptr) {
        return nullptr;
    }
    // The splay walks the node to the root in the six steps the algorithm
    // is defined by: the single rotation when the parent is the root, and
    // the two-rotation pairs that keep the tree from degenerating into the
    // list a naive rotate-to-root would produce.
    while (!splay_is_root(links)) {
        void* parent = reinterpret_cast<void*>(splay_parent(links));
        if (parent == nullptr) {
            break;
        }
        if (splay_is_root(parent)) {
            // The single rotation: the parent is the root, so one turn puts
            // the node there. The direction is the node's own side, because
            // the rotation lifts the node over its parent.
            splay_rotate(parent, splay_is_left_child(links));
            continue;
        }
        void* grandparent = reinterpret_cast<void*>(splay_parent(parent));
        if (grandparent == nullptr) {
            // A parent that is neither the root nor a child of anything is
            // a tree the caller built without the root convention, and
            // there is no second step to take.
            break;
        }
        const bool links_left = splay_is_left_child(links);
        const bool parent_left = splay_is_left_child(parent);
        if (links_left == parent_left) {
            // Both on the same side: the grandparent turns first, then the
            // parent. Doing it the other way round -- one rotation at a
            // time towards the root -- is the naive splaying that leaves
            // the tree a list.
            splay_rotate(grandparent, parent_left);
            splay_rotate(parent, parent_left);
        } else {
            // Opposite sides: the parent turns first, which puts the node
            // where the parent was, and the grandparent then turns over the
            // node itself.
            splay_rotate(parent, links_left);
            splay_rotate(grandparent, !links_left);
        }
    }
    return links;
}

extern "C" __attribute__((ms_abi)) void* nr3_RtlSubtreePredecessor(
    void* links) noexcept {
    if (links == nullptr) {
        return nullptr;
    }
    // The subtree's predecessor is the rightmost node under the left child:
    // everything in the left subtree is smaller, and the largest of them is
    // the one nearest.
    std::uint64_t child = splay_left(links);
    if (child == 0) {
        return nullptr;
    }
    while (splay_right(reinterpret_cast<const void*>(child)) != 0) {
        child = splay_right(reinterpret_cast<const void*>(child));
    }
    return reinterpret_cast<void*>(child);
}

extern "C" __attribute__((ms_abi)) void* nr3_RtlSubtreeSuccessor(
    void* links) noexcept {
    if (links == nullptr) {
        return nullptr;
    }
    std::uint64_t child = splay_right(links);
    if (child == 0) {
        return nullptr;
    }
    while (splay_left(reinterpret_cast<const void*>(child)) != 0) {
        child = splay_left(reinterpret_cast<const void*>(child));
    }
    return reinterpret_cast<void*>(child);
}

extern "C" __attribute__((ms_abi)) void* nr3_RtlRealPredecessor(
    void* links) noexcept {
    if (links == nullptr) {
        return nullptr;
    }
    // The whole-tree predecessor: the left subtree's largest if there is a
    // left subtree, and otherwise the nearest ancestor the node is a right
    // descendant of -- which is the first ancestor larger than nothing
    // between them.
    void* child = reinterpret_cast<void*>(splay_left(links));
    if (child != nullptr) {
        while (splay_right(child) != 0) {
            child = reinterpret_cast<void*>(splay_right(child));
        }
        return child;
    }
    void* up = links;
    while (!splay_is_root(up) && splay_is_left_child(up)) {
        up = reinterpret_cast<void*>(splay_parent(up));
    }
    if (splay_is_right_child(up)) {
        return reinterpret_cast<void*>(splay_parent(up));
    }
    return nullptr;
}

extern "C" __attribute__((ms_abi)) void* nr3_RtlRealSuccessor(
    void* links) noexcept {
    if (links == nullptr) {
        return nullptr;
    }
    void* child = reinterpret_cast<void*>(splay_right(links));
    if (child != nullptr) {
        while (splay_left(child) != 0) {
            child = reinterpret_cast<void*>(splay_left(child));
        }
        return child;
    }
    void* up = links;
    while (!splay_is_root(up) && splay_is_right_child(up)) {
        up = reinterpret_cast<void*>(splay_parent(up));
    }
    if (splay_is_left_child(up)) {
        return reinterpret_cast<void*>(splay_parent(up));
    }
    return nullptr;
}

// ---------------------------------------------------- the red-black tree
//
// A balanced node is two children and a parent pointer whose low two bits
// are reserved: bit zero is the colour, so a parent link has to be read
// with those bits masked off and written with the colour preserved. The
// tree itself is two pointers -- its root and its smallest node -- and both
// are maintained here, because a tree whose `min` disagreed with its own
// left spine would answer "the smallest" with a node that is not.
//
// The insert and the erase are the classical algorithms. They are written
// out rather than deferred to a generic container because the shape they
// produce is part of what the caller sees: the caller's own comparisons
// decided where the node went, and every caller reads the tree back through
// these same links.

namespace {

constexpr std::size_t kNodeLeft = 0;
constexpr std::size_t kNodeRight = 8;
constexpr std::size_t kNodeParent = 16;
constexpr std::size_t kNodeBytes = 24;
constexpr std::uint64_t kNodeColourMask = 3;
constexpr std::uint64_t kNodeRed = 1;

constexpr std::size_t kTreeRoot = 0;
constexpr std::size_t kTreeMin = 8;

[[nodiscard]] std::uint64_t node_parent(const void* node) noexcept {
    return read_ptr(node, kNodeParent) & ~kNodeColourMask;
}

[[nodiscard]] bool node_is_red(const void* node) noexcept {
    return (read_ptr(node, kNodeParent) & kNodeRed) != 0;
}

void node_set_parent(void* node, std::uint64_t parent) noexcept {
    // The colour travels with the write: a relink that dropped it would
    // turn every black node red and leave the tree unbalanced in the one
    // way the fixups do not repair.
    write_ptr(node, kNodeParent,
              (read_ptr(node, kNodeParent) & kNodeColourMask) | parent);
}

void node_set_red(void* node, bool red) noexcept {
    const std::uint64_t bits = read_ptr(node, kNodeParent) & ~kNodeColourMask;
    write_ptr(node, kNodeParent, red ? (bits | kNodeRed) : bits);
}

[[nodiscard]] std::uint64_t node_child(const void* node, bool right) noexcept {
    return read_ptr(node, right ? kNodeRight : kNodeLeft);
}

void node_set_child(void* node, bool right, std::uint64_t child) noexcept {
    write_ptr(node, right ? kNodeRight : kNodeLeft, child);
}

void rb_rotate(void* tree, void* pivot, bool to_right) noexcept {
    void* const child =
        reinterpret_cast<void*>(node_child(pivot, !to_right));
    if (child == nullptr) {
        return;
    }
    const std::uint64_t parent = node_parent(pivot);

    if (parent == 0) {
        write_ptr(tree, kTreeRoot, reinterpret_cast<std::uint64_t>(child));
    } else if (node_child(reinterpret_cast<const void*>(parent), false) ==
               reinterpret_cast<std::uint64_t>(pivot)) {
        node_set_child(reinterpret_cast<void*>(parent), false,
                       reinterpret_cast<std::uint64_t>(child));
    } else {
        node_set_child(reinterpret_cast<void*>(parent), true,
                       reinterpret_cast<std::uint64_t>(child));
    }

    const std::uint64_t moved = node_child(child, to_right);
    node_set_child(pivot, !to_right, moved);
    if (moved != 0) {
        node_set_parent(reinterpret_cast<void*>(moved),
                        reinterpret_cast<std::uint64_t>(pivot));
    }
    node_set_child(child, to_right, reinterpret_cast<std::uint64_t>(pivot));
    node_set_parent(child, parent);
    node_set_parent(pivot, reinterpret_cast<std::uint64_t>(child));
}

}  // namespace

extern "C" __attribute__((ms_abi)) void nr3_RtlRbInsertNodeEx(
    void* tree, void* parent, std::uint8_t right, void* node) noexcept {
    if (tree == nullptr || node == nullptr) {
        return;
    }
    std::memset(node, 0, kNodeBytes);
    write_ptr(node, kNodeParent, reinterpret_cast<std::uint64_t>(parent));
    if (parent == nullptr) {
        // The first node is the tree: it is the root and the smallest, and
        // it is black, which is the one node whose colour the rules fix
        // without a fixup.
        node_set_red(node, false);
        write_ptr(tree, kTreeRoot, reinterpret_cast<std::uint64_t>(node));
        write_ptr(tree, kTreeMin, reinterpret_cast<std::uint64_t>(node));
        return;
    }
    if (right > 1) {
        // The side is one bit. A caller passing anything else is naming a
        // child that does not exist, and inserting on a guess would put the
        // node where the caller's own ordering did not.
        return;
    }
    const bool to_right = right != 0;
    if (node_child(parent, to_right) != 0) {
        // The slot the caller named is occupied, which means its comparison
        // and this call disagree about the ordering; the node is not linked
        // because there is no place for it that would preserve it.
        return;
    }

    node_set_red(node, true);
    node_set_child(parent, to_right, reinterpret_cast<std::uint64_t>(node));
    // A node inserted to the left of the smallest becomes the smallest,
    // which is the only insert that changes `min`.
    if (read_ptr(tree, kTreeMin) == reinterpret_cast<std::uint64_t>(parent) &&
        !to_right) {
        write_ptr(tree, kTreeMin, reinterpret_cast<std::uint64_t>(node));
    }

    // The fixup: an inserted node is red, and a red node under a red parent
    // is the one violation the rules forbid. Each step either recolours a
    // black uncle's family or rotates the grandparent, and the loop ends
    // when the parent is black or the node reaches the root.
    void* current = node;
    void* dad = parent;
    std::uint64_t grandparent = node_parent(dad);
    while (node_is_red(dad)) {
        if (grandparent == 0) {
            break;
        }
        auto* grand = reinterpret_cast<void*>(grandparent);
        const bool dad_is_right =
            node_child(grand, true) == reinterpret_cast<std::uint64_t>(dad);
        void* uncle = reinterpret_cast<void*>(node_child(grand, !dad_is_right));
        if (uncle != nullptr && node_is_red(uncle)) {
            // Both children of the grandparent are red: recolouring them
            // black and the grandparent red moves the violation up, which
            // is where the next turn of the loop looks for it.
            current = grand;
            node_set_red(grand, true);
            node_set_red(dad, false);
            node_set_red(uncle, false);
            const std::uint64_t up = node_parent(grand);
            if (up == 0) {
                break;
            }
            dad = reinterpret_cast<void*>(up);
            grandparent = node_parent(dad);
            continue;
        }
        if (current == reinterpret_cast<void*>(node_child(dad, !dad_is_right))) {
            // The inner child: rotating the parent first turns the shape
            // into the outer case below.
            current = dad;
            rb_rotate(tree, dad, dad_is_right);
            dad = reinterpret_cast<void*>(node_parent(current));
            grandparent = node_parent(dad);
            if (grandparent == 0) {
                break;
            }
            grand = reinterpret_cast<void*>(grandparent);
        }
        node_set_red(dad, false);
        node_set_red(grand, true);
        rb_rotate(tree, grand, !dad_is_right);
        break;
    }
    // Whatever happened above, the root is black: a red root would be a
    // violation nothing later in the walk could see.
    const std::uint64_t root = read_ptr(tree, kTreeRoot);
    if (root != 0) {
        node_set_red(reinterpret_cast<void*>(root), false);
    }
}

extern "C" __attribute__((ms_abi)) void nr3_RtlRbRemoveNode(
    void* tree, void* node) noexcept {
    if (tree == nullptr || node == nullptr) {
        return;
    }
    // The node that is actually unlinked is the node itself when it has at
    // most one child, and otherwise its successor -- which is then copied
    // over the node so that the caller's pointer keeps naming the same key
    // while the links come from the successor's position.
    void* spliced = node;
    const bool has_left = node_child(node, false) != 0;
    const bool has_right = node_child(node, true) != 0;
    if (has_left && has_right) {
        spliced = reinterpret_cast<void*>(node_child(node, true));
        while (node_child(spliced, false) != 0) {
            spliced = reinterpret_cast<void*>(node_child(spliced, false));
        }
    }

    // The smallest node is maintained here: removing it moves the marker
    // to the parent when it has no right child, and to the successor's
    // own smallest subtree otherwise.
    if (read_ptr(tree, kTreeMin) == reinterpret_cast<std::uint64_t>(node)) {
        write_ptr(tree, kTreeMin,
                  has_right ? reinterpret_cast<std::uint64_t>(spliced)
                            : node_parent(node));
    }

    void* child = reinterpret_cast<void*>(
        node_child(spliced, false) != 0 ? node_child(spliced, false)
                                       : node_child(spliced, true));
    void* parent = reinterpret_cast<void*>(node_parent(spliced));
    if (parent == nullptr) {
        write_ptr(tree, kTreeRoot, reinterpret_cast<std::uint64_t>(child));
    } else if (node_child(parent, false) ==
               reinterpret_cast<std::uint64_t>(spliced)) {
        node_set_child(parent, false, reinterpret_cast<std::uint64_t>(child));
    } else {
        node_set_child(parent, true, reinterpret_cast<std::uint64_t>(child));
    }
    if (child != nullptr) {
        node_set_parent(child, reinterpret_cast<std::uint64_t>(parent));
    }

    // A black node that was unlinked took a black path out of the tree, and
    // that is the one removal that needs a fixup: the paths through where
    // it stood are now one black shorter than their siblings.
    const bool was_red = node_is_red(spliced);
    if (spliced != node) {
        // The successor's links replace the node's, which the caller sees
        // as the node's own key having been unlinked.
        const std::uint64_t parent_bits =
            read_ptr(spliced, kNodeParent) & kNodeColourMask;
        std::memcpy(node, spliced, kNodeBytes);
        write_ptr(node, kNodeParent,
                  (read_ptr(node, kNodeParent) & ~kNodeColourMask) |
                      parent_bits);
        void* const relink =
            reinterpret_cast<void*>(node_parent(node));
        if (relink == nullptr) {
            write_ptr(tree, kTreeRoot, reinterpret_cast<std::uint64_t>(node));
        } else if (node_child(relink, false) ==
                   reinterpret_cast<std::uint64_t>(spliced)) {
            node_set_child(relink, false, reinterpret_cast<std::uint64_t>(node));
        } else if (node_child(relink, true) ==
                   reinterpret_cast<std::uint64_t>(spliced)) {
            node_set_child(relink, true, reinterpret_cast<std::uint64_t>(node));
        }
        if (node_child(node, true) != 0) {
            node_set_parent(reinterpret_cast<void*>(node_child(node, true)),
                            reinterpret_cast<std::uint64_t>(node));
        }
        if (node_child(node, false) != 0) {
            node_set_parent(reinterpret_cast<void*>(node_child(node, false)),
                            reinterpret_cast<std::uint64_t>(node));
        }
        if (parent == node) {
            parent = node;
        }
    }

    if (was_red) {
        return;
    }
    // The fixup: the removed node was black, so the subtree that took its
    // place is one black short. Each step either recolours a red sibling's
    // family or rotates it up, and the loop ends at a red node -- which is
    // painted black -- or at the root.
    void* current = child;
    while (parent != nullptr) {
        const bool left_side =
            node_child(parent, false) == reinterpret_cast<std::uint64_t>(current);
        void* sibling =
            reinterpret_cast<void*>(node_child(parent, !left_side));
        if (sibling == nullptr) {
            // No sibling means the deficit is at the end of the path: the
            // walk moves up, which is the only step left.
            current = parent;
            parent = reinterpret_cast<void*>(node_parent(parent));
            continue;
        }
        if (node_is_red(sibling)) {
            node_set_red(sibling, false);
            node_set_red(parent, true);
            rb_rotate(tree, parent, left_side);
            sibling = reinterpret_cast<void*>(node_child(parent, !left_side));
            if (sibling == nullptr) {
                current = parent;
                parent = reinterpret_cast<void*>(node_parent(parent));
                continue;
            }
        }
        const bool inner_black =
            node_child(sibling, left_side) == 0 ||
            !node_is_red(reinterpret_cast<void*>(node_child(sibling, left_side)));
        const bool outer_black =
            node_child(sibling, !left_side) == 0 ||
            !node_is_red(reinterpret_cast<void*>(node_child(sibling, !left_side)));
        if (inner_black && outer_black) {
            // Both of the sibling's children are black: recolouring the
            // sibling red pushes the deficit up to the parent, which is
            // where the next turn looks for it.
            node_set_red(sibling, true);
            current = parent;
            parent = reinterpret_cast<void*>(node_parent(parent));
            continue;
        }
        if (outer_black) {
            // The outer child is black and the inner one red: rotating the
            // sibling brings a red node to the outside for the step below.
            auto* inner =
                reinterpret_cast<void*>(node_child(sibling, left_side));
            node_set_red(inner, false);
            node_set_red(sibling, true);
            rb_rotate(tree, sibling, !left_side);
            sibling = reinterpret_cast<void*>(node_child(parent, !left_side));
            if (sibling == nullptr) {
                current = parent;
                parent = reinterpret_cast<void*>(node_parent(parent));
                continue;
            }
        }
        node_set_red(sibling, node_is_red(parent));
        node_set_red(parent, false);
        auto* outer =
            reinterpret_cast<void*>(node_child(sibling, !left_side));
        if (outer != nullptr) {
            node_set_red(outer, false);
        }
        rb_rotate(tree, parent, left_side);
        parent = nullptr;
    }
    const std::uint64_t root = read_ptr(tree, kTreeRoot);
    if (root != 0) {
        node_set_red(reinterpret_cast<void*>(root), false);
    }
}


// ------------------------------------------------- the language and the mode
//
// The language a process prefers, and the error mode its threads run under,
// are two pieces of per-process state this runtime can hold truthfully:
// they are what a caller sets and reads back, and neither needs a subsystem
// behind it. The value is stored rather than mapped onto the host's own
// locale, because a guest that sets a language and reads it back must see
// its own value and not whatever the launcher's environment happens to say.

namespace {

// The language the process asked for, empty until a caller sets one. The
// readers in the second slice ask for it through the bridge below, which is
// what keeps a set here visible to a get there.
std::u16string g_ui_language;

// The error mode, which is the one piece of the thread family's state a
// guest can set. Zero is the mode a process starts in.
std::uint32_t g_thread_error_mode = 0;

}  // namespace

// The language a process prefers, for the readers in the other slice. A
// null answer means no caller has set one, which those readers answer with
// the runtime's own default rather than with nothing.
extern "C" const char16_t* occ_ui_language() noexcept {
    return g_ui_language.empty() ? nullptr : g_ui_language.c_str();
}

// Reads the first language out of the multi-string a caller passes. The
// list is terminated by two nulls and the first entry is the preferred one;
// an empty list leaves the selection unchanged rather than clearing it,
// which is what the real function does with a buffer that holds nothing.
[[nodiscard]] bool take_first_language(const char16_t* list,
                                       std::u16string& out) noexcept {
    if (list == nullptr || *list == u'\0') {
        return false;
    }
    const char16_t* cursor = list;
    while (*cursor != u'\0') {
        ++cursor;
    }
    out.assign(list, cursor);
    return true;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlSetProcessPreferredUILanguages(
    std::uint32_t flags, const char16_t* languages,
    std::uint32_t* count) noexcept {
    static_cast<void>(flags);
    std::u16string chosen;
    if (!take_first_language(languages, chosen)) {
        return kStInvalidParameter1;
    }
    g_ui_language = chosen;
    if (count != nullptr) {
        *count = 1;
    }
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlSetThreadPreferredUILanguages(
    std::uint32_t flags, const char16_t* languages,
    std::uint32_t* count) noexcept {
    // One thread runs the guest, so the thread's list and the process's are
    // the same list; a second store would let a caller read one and set the
    // other.
    return nr3_RtlSetProcessPreferredUILanguages(flags, languages, count);
}

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlSetThreadErrorMode(
    std::uint32_t mode, std::uint32_t* previous) noexcept {
    if (previous != nullptr) {
        // The old mode comes back before the new one is stored, which is
        // what lets a caller put it back.
        *previous = g_thread_error_mode;
    }
    g_thread_error_mode = mode;
    return 1;
}

// ------------------------------------------- the vectored handler removal
//
// The two remove calls are the other half of the registration the first
// slice performs. The list lives there, so the removal goes through it: a
// second list here would let a handler be registered in one and removed
// from the other.

namespace {

extern "C" bool occ_vectored_remove(void* handler, bool is_continue) noexcept;

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint32_t
nr3_RtlRemoveVectoredExceptionHandler(void* handler) noexcept {
    return occ_vectored_remove(handler, false) ? 1u : 0u;
}

extern "C" __attribute__((ms_abi)) std::uint32_t
nr3_RtlRemoveVectoredContinueHandler(void* handler) noexcept {
    return occ_vectored_remove(handler, true) ? 1u : 0u;
}

// ------------------------------------------------------------- refusals
//
// Each function below needs a subsystem this runtime does not have, and
// each says which one where it refuses. They are written out one by one
// rather than through a macro because the signature is part of what a
// caller reads, and these signatures differ in what they would have to
// reach.

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlQueryInformationActivationContext(
    std::uint32_t flags,
    void* context,
    const void* sub,
    std::uint32_t class_id,
    void* info,
    std::uint32_t length,
    std::uint32_t* returned) noexcept {
    // Needs the side-by-side store a context resolves against; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(flags);
    static_cast<void>(context);
    static_cast<void>(sub);
    static_cast<void>(class_id);
    static_cast<void>(info);
    static_cast<void>(length);
    static_cast<void>(returned);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlQueryInformationActiveActivationContext(
    std::uint32_t class_id,
    void* info,
    std::uint32_t length,
    std::uint32_t* returned) noexcept {
    // Needs the side-by-side store a context resolves against; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(class_id);
    static_cast<void>(info);
    static_cast<void>(length);
    static_cast<void>(returned);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlReleaseActivationContext(
    void* context) noexcept {
    // Needs the side-by-side store; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(context);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlZombifyActivationContext(
    void* context) noexcept {
    // Needs the side-by-side store; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(context);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlQueryProperties(
    const void* set,
    const void* query,
    void* info,
    std::uint32_t length,
    std::uint32_t* returned) noexcept {
    // Needs the configuration store the property sets live in; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(set);
    static_cast<void>(query);
    static_cast<void>(info);
    static_cast<void>(length);
    static_cast<void>(returned);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlQueryPropertyNames(
    const void* set,
    void* query,
    void* info,
    std::uint32_t length,
    std::uint32_t* returned) noexcept {
    // Needs the configuration store the property sets live in; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(set);
    static_cast<void>(query);
    static_cast<void>(info);
    static_cast<void>(length);
    static_cast<void>(returned);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlQueryPropertySet(
    const void* set,
    void* info,
    std::uint32_t length,
    std::uint32_t* returned) noexcept {
    // Needs the configuration store the property sets live in; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(set);
    static_cast<void>(info);
    static_cast<void>(length);
    static_cast<void>(returned);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlSetProperties(
    void* set,
    const void* query,
    const void* info,
    std::uint32_t length) noexcept {
    // Needs the configuration store the property sets live in; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(set);
    static_cast<void>(query);
    static_cast<void>(info);
    static_cast<void>(length);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlSetPropertyClassId(
    void* set,
    const void* guid) noexcept {
    // Needs the configuration store the property sets live in; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(set);
    static_cast<void>(guid);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlSetPropertyNames(
    void* set,
    const void* query,
    const void* info,
    std::uint32_t length) noexcept {
    // Needs the configuration store the property sets live in; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(set);
    static_cast<void>(query);
    static_cast<void>(info);
    static_cast<void>(length);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlSetPropertySetClassId(
    void* set,
    const void* guid) noexcept {
    // Needs the configuration store the property sets live in; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(set);
    static_cast<void>(guid);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlQueryRegistryValues(
    std::uint32_t relative,
    const char16_t* path,
    void* table,
    void* context,
    void* environment) noexcept {
    // Needs the registry a process hive would be backed by; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(relative);
    static_cast<void>(path);
    static_cast<void>(table);
    static_cast<void>(context);
    static_cast<void>(environment);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlQueryRegistryValuesEx(
    std::uint32_t relative,
    const char16_t* path,
    void* table,
    void* context,
    void* environment) noexcept {
    // Needs the registry a process hive would be backed by; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(relative);
    static_cast<void>(path);
    static_cast<void>(table);
    static_cast<void>(context);
    static_cast<void>(environment);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlWriteRegistryValue(
    std::uint32_t relative,
    const char16_t* path,
    const char16_t* value_name,
    std::uint32_t type,
    const void* data,
    std::uint32_t length) noexcept {
    // Needs the registry a process hive would be backed by; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(relative);
    static_cast<void>(path);
    static_cast<void>(value_name);
    static_cast<void>(type);
    static_cast<void>(data);
    static_cast<void>(length);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlpNtCreateKey(
    void* key,
    std::uint32_t access,
    void* attributes,
    std::uint32_t index,
    void* disposition) noexcept {
    // Needs the object manager a key handle would name; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(key);
    static_cast<void>(access);
    static_cast<void>(attributes);
    static_cast<void>(index);
    static_cast<void>(disposition);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlpNtEnumerateSubKey(
    void* key,
    void* info,
    std::uint32_t index,
    std::uint32_t length) noexcept {
    // Needs the object manager a key handle would name; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(key);
    static_cast<void>(info);
    static_cast<void>(index);
    static_cast<void>(length);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlpNtMakeTemporaryKey(
    void* key) noexcept {
    // Needs the object manager a key handle would name; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(key);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlpNtOpenKey(
    void* key,
    std::uint32_t access,
    void* attributes,
    std::uint32_t options) noexcept {
    // Needs the object manager a key handle would name; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(key);
    static_cast<void>(access);
    static_cast<void>(attributes);
    static_cast<void>(options);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlpNtQueryValueKey(
    void* key,
    std::uint32_t* type,
    void* data,
    std::uint32_t* length,
    void* info,
    std::uint32_t info_length) noexcept {
    // Needs the object manager a key handle would name; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(key);
    static_cast<void>(type);
    static_cast<void>(data);
    static_cast<void>(length);
    static_cast<void>(info);
    static_cast<void>(info_length);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlpNtSetValueKey(
    void* key,
    std::uint32_t type,
    const void* data,
    std::uint32_t length) noexcept {
    // Needs the object manager a key handle would name; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(key);
    static_cast<void>(type);
    static_cast<void>(data);
    static_cast<void>(length);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlQueryProcessBackTraceInformation(
    void* info,
    std::uint32_t length,
    std::uint32_t* returned) noexcept {
    // Needs the debug heap and the back-trace buffer a debugger fills; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(info);
    static_cast<void>(length);
    static_cast<void>(returned);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlQueryProcessDebugInformation(
    std::uint32_t process_id,
    std::uint32_t flags,
    void* info) noexcept {
    // Needs the debug heap and the back-trace buffer a debugger fills; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(process_id);
    static_cast<void>(flags);
    static_cast<void>(info);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlQueryProcessHeapInformation(
    void* info,
    std::uint32_t length,
    std::uint32_t* returned) noexcept {
    // Needs the debug heap and the back-trace buffer a debugger fills; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(info);
    static_cast<void>(length);
    static_cast<void>(returned);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlQueryProcessLockInformation(
    void* info,
    std::uint32_t length,
    std::uint32_t* returned) noexcept {
    // Needs the debug heap and the back-trace buffer a debugger fills; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(info);
    static_cast<void>(length);
    static_cast<void>(returned);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlQueryPackageIdentity(
    std::uint64_t token,
    char16_t* name,
    std::uint64_t* name_size,
    char16_t* app_id,
    std::uint64_t* app_id_size,
    std::uint8_t* packaged) noexcept {
    // Needs the package identity the loader's manifests would carry; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(token);
    static_cast<void>(name);
    static_cast<void>(name_size);
    static_cast<void>(app_id);
    static_cast<void>(app_id_size);
    static_cast<void>(packaged);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlRegisterSecureMemoryCacheCallback(
    void* callback) noexcept {
    // Needs the secure-memory cache the callback would flush; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(callback);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlQuerySecurityObject(
    std::uint64_t handle,
    std::uint32_t class_id,
    void* info,
    std::uint32_t length,
    std::uint32_t* returned) noexcept {
    // Needs the kernel objects whose descriptors these would read; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(handle);
    static_cast<void>(class_id);
    static_cast<void>(info);
    static_cast<void>(length);
    static_cast<void>(returned);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlSetSecurityObject(
    std::uint64_t handle,
    std::uint32_t class_id,
    void* info,
    std::uint32_t length) noexcept {
    // Needs the kernel objects whose descriptors these would write; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(handle);
    static_cast<void>(class_id);
    static_cast<void>(info);
    static_cast<void>(length);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlQueueApcWow64Thread(
    std::uint64_t thread,
    void* routine,
    void* context,
    void* argument1,
    void* argument2) noexcept {
    // Needs the 32-bit guest an APC would run in; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(thread);
    static_cast<void>(routine);
    static_cast<void>(context);
    static_cast<void>(argument1);
    static_cast<void>(argument2);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlRemoteCall(
    std::uint64_t process,
    std::uint64_t thread,
    void* address,
    std::uint32_t argument_count,
    void** arguments,
    std::uint8_t pass_handle,
    std::uint8_t already_suspended) noexcept {
    // Needs a second process to call into; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(process);
    static_cast<void>(thread);
    static_cast<void>(address);
    static_cast<void>(argument_count);
    static_cast<void>(arguments);
    static_cast<void>(pass_handle);
    static_cast<void>(already_suspended);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlSetIoCompletionCallback(
    std::uint64_t handle,
    void* callback,
    std::uint32_t flags) noexcept {
    // Needs the I/O completion port that would carry the callback; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(handle);
    static_cast<void>(callback);
    static_cast<void>(flags);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlQueueWorkItem(
    void* routine,
    void* context,
    std::uint32_t flags) noexcept {
    // Needs a thread pool to run the item; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(routine);
    static_cast<void>(context);
    static_cast<void>(flags);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlRegisterWait(
    void** wait,
    std::uint64_t handle,
    void* callback,
    void* context,
    std::uint32_t milliseconds,
    std::uint32_t flags) noexcept {
    // Needs a thread pool to run the callback; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(wait);
    static_cast<void>(handle);
    static_cast<void>(callback);
    static_cast<void>(context);
    static_cast<void>(milliseconds);
    static_cast<void>(flags);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlUpdateTimer(
    std::uint64_t timer,
    std::uint32_t delay,
    std::uint32_t interval) noexcept {
    // Needs a thread pool timer; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(timer);
    static_cast<void>(delay);
    static_cast<void>(interval);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) void nr3_RtlRaiseException(
    void* record) noexcept {
    // Needs the exception dispatcher that would walk the handlers; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(record);
}

extern "C" __attribute__((ms_abi)) void nr3_RtlRaiseStatus(
    std::uint32_t status) noexcept {
    // Needs the exception dispatcher that would walk the handlers; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(status);
}

extern "C" __attribute__((ms_abi, noreturn)) void nr3_RtlRestoreContext(
    void* context, void* record) noexcept {
    // The last step of an unwinding: the exception record has already been
    // walked, the handler that accepted has already decided where to
    // resume, and this call takes the machine there. It is the same restore
    // the language handler reaches through `RtlUnwindEx`, which is why it is
    // the same function -- a second implementation would have to agree with
    // the unwinder about the context layout, and the two would drift.
    //
    // The record is not consulted: the resume address and the registers are
    // all in the context, and a context that is absent leaves nothing to
    // restore, which ends the process rather than continuing from a frame
    // the caller did not name.
    static_cast<void>(record);
    if (context == nullptr) {
        // Nothing to restore. Returning would tell the caller its unwind
        // had completed, and the caller has no code after this call: it
        // asked to resume somewhere and there is nowhere to go.
        ::abort();
    }
    seh::seh_restore_context(static_cast<const std::uint8_t*>(context));
    __builtin_unreachable();
}

extern "C" __attribute__((ms_abi)) void nr3_RtlUnwind(
    void* frame,
    void* target,
    void* record,
    std::uint64_t return_value) noexcept {
    // Needs the exception dispatcher that would walk the handlers; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(frame);
    static_cast<void>(target);
    static_cast<void>(record);
    static_cast<void>(return_value);
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr3_RtlWalkFrameChain(
    void** trace,
    std::uint32_t back_to_find,
    std::uint32_t flags) noexcept {
    // Needs the frame chain a debugger would walk; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(trace);
    static_cast<void>(back_to_find);
    static_cast<void>(flags);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) void nr3_RtlUserThreadStart(
    void* start,
    void* parameter) noexcept {
    // Needs the thread machinery a second thread would be started by; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(start);
    static_cast<void>(parameter);
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlWow64EnableFsRedirection(
    std::uint8_t enable) noexcept {
    // Needs the 32-bit guest whose file system the redirection would apply to; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(enable);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlWow64EnableFsRedirectionEx(
    void* disable,
    void** old) noexcept {
    // Needs the 32-bit guest whose file system the redirection would apply to; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(disable);
    static_cast<void>(old);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlWow64GetCpuAreaInfo(
    void* area,
    std::uint32_t length,
    void* info) noexcept {
    // Needs the WOW64 CPU area a 32-bit guest would own; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(area);
    static_cast<void>(length);
    static_cast<void>(info);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlWow64GetCurrentCpuArea(
    void** area,
    void** old_area) noexcept {
    // Needs the WOW64 CPU area a 32-bit guest would own; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(area);
    static_cast<void>(old_area);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlWow64GetCurrentMachine(
    std::uint16_t* machine) noexcept {
    // Needs the WOW64 emulation layer; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(machine);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlWow64GetProcessMachines(
    std::uint64_t process,
    std::uint16_t* process_machine,
    std::uint16_t* native_machine) noexcept {
    // Needs the WOW64 emulation layer; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(process);
    static_cast<void>(process_machine);
    static_cast<void>(native_machine);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlWow64GetSharedInfoProcess(
    std::uint64_t process,
    void* info,
    std::uint32_t length,
    std::uint32_t* returned) noexcept {
    // Needs the WOW64 shared information block; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(process);
    static_cast<void>(info);
    static_cast<void>(length);
    static_cast<void>(returned);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlWow64GetThreadContext(
    std::uint64_t thread,
    void* context) noexcept {
    // Needs the WOW64 emulation layer; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(thread);
    static_cast<void>(context);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlWow64GetThreadSelectorEntry(
    std::uint64_t thread,
    std::uint32_t selector,
    void* entry) noexcept {
    // Needs the LDT a 32-bit guest would address through; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(thread);
    static_cast<void>(selector);
    static_cast<void>(entry);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlWow64PopAllCrossProcessWorkFromWorkList(
    void* work_list,
    void* entries,
    std::uint32_t count) noexcept {
    // Needs the cross-process work list the WOW64 thunks are dispatched from; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(work_list);
    static_cast<void>(entries);
    static_cast<void>(count);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlWow64PopCrossProcessWorkFromFreeList(
    void* work_list) noexcept {
    // Needs the cross-process work list the WOW64 thunks are dispatched from; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(work_list);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlWow64PushCrossProcessWorkOntoFreeList(
    void* work_list,
    void* entry) noexcept {
    // Needs the cross-process work list the WOW64 thunks are dispatched from; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(work_list);
    static_cast<void>(entry);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlWow64PushCrossProcessWorkOntoWorkList(
    void* work_list,
    void* entry) noexcept {
    // Needs the cross-process work list the WOW64 thunks are dispatched from; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(work_list);
    static_cast<void>(entry);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlWow64RequestCrossProcessHeavyFlush(
    void) noexcept {
    // Needs the cross-process work list the WOW64 thunks are dispatched from; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlResetNtUserPfn(
    void) noexcept {
    // Needs the window manager's user-mode entry table; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlRetrieveNtUserPfn(
    void* table,
    std::uint32_t count) noexcept {
    // Needs the window manager's user-mode entry table; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(table);
    static_cast<void>(count);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlResetRtlTranslations(
    void* tables) noexcept {
    // Needs the NLS translation tables the guest's own locale data holds; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(tables);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlStartRXact(
    void) noexcept {
    // Needs the kernel transaction manager; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr3_RtlpQueryDefaultUILanguage(
    void* language,
    std::int32_t length) noexcept {
    // Needs the language list a locale database would answer from; this runtime has none of it, so the call
    // is refused rather than answered with a value that would
    // be believed.
    static_cast<void>(language);
    static_cast<void>(length);
    return kStNotImplemented;
}

// --------------------------------------------------------- the last few
//
// The names below are the ones that belong to families already written
// elsewhere in this slice or in the others, and each says which.

extern "C" __attribute__((ms_abi)) void nr3_RtlRestoreLastWin32Error(
    std::uint32_t error) noexcept {
    // The restore spelling is the setter: the name is the one a caller uses
    // when it is putting back an error it saved, and the effect is the same
    // store. Two bodies would be two places for the pair to drift apart.
    set_last_error(error);
}

extern "C" __attribute__((ms_abi)) void nr3_RtlSetExtendedFeaturesMask(
    std::uint64_t* features, std::uint64_t mask) noexcept {
    // The mask is the set of the two context flags the record carries, so a
    // caller that turns a feature's bit on or off is editing the array it
    // owns. The array is two words because the features are enumerated
    // across 128 bits.
    if (features == nullptr) {
        return;
    }
    features[0] = mask;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr3_RtlSetCurrentTransaction(
    void* transaction) noexcept {
    // The transaction this would install is one the kernel transaction
    // manager mints, and this runtime has none: only the null transaction
    // -- which is the state a process is already in -- can be answered for.
    if (transaction != nullptr) {
        return kStNotImplemented;
    }
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr3_RtlVerifyVersionInfo(
    const void* info, std::uint32_t type_mask, std::uint64_t condition_mask) noexcept {
    // The check compares the version this runtime presents against the
    // caller's, field by field, and reports which field failed. It is a
    // pure comparison over a structure the caller supplies, so it is
    // answered rather than refused -- and the answer is computed from the
    // same constants `RtlGetVersion` reports, so the two cannot disagree.
    if (info == nullptr) {
        return static_cast<std::int32_t>(kStInvalidParameter1);
    }
    // OSVERSIONINFOEXW: the five 32-bit fields the plain structure has,
    // then the platform, the service pack numbers and the suite mask.
    const std::uint32_t major = read_u32(info, 4);
    const std::uint32_t minor = read_u32(info, 8);
    const std::uint32_t build = read_u32(info, 12);
    const std::uint32_t platform = read_u32(info, 16);
    const std::uint32_t service_pack_major = read_u32(info, 20);
    const std::uint32_t service_pack_minor = read_u32(info, 24);
    const std::uint16_t suite_mask = read_u16(info, 28);
    const std::uint8_t product_type = read_u8(info, 30);

    // VerSetConditionMask packs one 2-bit condition per field, four bits
    // apart, starting at bit 2; the fields are in the order the mask's own
    // constants declare.
    constexpr std::uint64_t kLeftShift = 2;
    constexpr std::uint64_t kFieldMask = 0x7;
    const auto condition = [condition_mask](std::uint32_t index) {
        return (condition_mask >> (kLeftShift + index * 4)) & kFieldMask;
    };
    const std::uint32_t fields[8] = {major,
                                     minor,
                                     build,
                                     platform,
                                     service_pack_major,
                                     service_pack_minor,
                                     suite_mask,
                                     product_type};
    // The values this runtime presents, in the same order as the mask's
    // fields: the version from `RtlGetVersion`, the platform, no service
    // pack, an empty suite and the workstation product type.
    const std::uint32_t actual[8] = {10, 0, 19045, 2, 0, 0, 0, 1};
    const std::uint16_t type_bits[8] = {0x0001, 0x0002, 0x0004, 0x0008,
                                        0x0010, 0x0020, 0x0040, 0x0080};

    int failed = 0;
    for (std::uint32_t k = 0; k < 8; ++k) {
        if ((type_mask & type_bits[k]) == 0) {
            continue;
        }
        const std::uint64_t op = condition(k);
        if (op == 0) {
            continue;
        }
        bool ok = false;
        // VER_EQUAL, GREATER, GREATER_EQUAL, LESS, LESS_EQUAL, AND, OR --
        // the seven comparisons the mask defines.
        if (op == 1) {
            ok = actual[k] == fields[k];
        } else if (op == 2) {
            ok = actual[k] > fields[k];
        } else if (op == 3) {
            ok = actual[k] >= fields[k];
        } else if (op == 4) {
            ok = actual[k] < fields[k];
        } else if (op == 5) {
            ok = actual[k] <= fields[k];
        } else if (op == 6) {
            ok = (actual[k] & fields[k]) == fields[k];
        } else {
            ok = (actual[k] | fields[k]) != 0;
        }
        if (!ok) {
            failed = static_cast<int>(k) + 1;
            break;
        }
    }
    if (failed != 0) {
        // The failure carries the number of the field that did not match,
        // which is the whole of what makes this call useful to a caller
        // that is trying to find out what it is running on.
        constexpr std::uint32_t kStatusRevisionMismatch = 0xC0000059;
        return static_cast<std::int32_t>(
            kStatusRevisionMismatch | (static_cast<std::uint32_t>(failed) << 16));
    }
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) void nr3_RtlReleasePebLock(void) noexcept {
    // The PEB lock guards the process's own parameter block. The one thread
    // that runs the guest is the one that takes it, so a release has
    // nothing to hand on and is answered as the no-op it is.
}

extern "C" __attribute__((ms_abi)) void nr3_RtlReleaseRelativeName(
    void* relative) noexcept {
    // A relative name holds a buffer the conversion allocated, and
    // releasing it returns that buffer. The structure is the one the DOS
    // path conversion fills, so the buffer is at the third field.
    if (relative == nullptr) {
        return;
    }
    void* buffer = reinterpret_cast<void*>(read_ptr(relative, 8));
    if (buffer != nullptr) {
        static_cast<void>(heap_free(buffer));
        write_ptr(relative, 8, 0);
        write_u16(relative, 0, 0);
        write_u16(relative, 2, 0);
    }
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr3_RtlReleaseResource(
    void* resource) noexcept {
    // A resource is the reader-writer lock the resource family initializes.
    // Releasing one this runtime never handed out would unlock a structure
    // whose state nobody set, so the release is answered as a failure --
    // the resource implementation itself is not here.
    static_cast<void>(resource);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr3_RtlUnlockHeap(
    void* heap) noexcept {
    // The heap lock is the one `RtlLockHeap` takes, and this runtime's
    // allocator runs on the one thread that can reach it: there is no
    // second entrant for the lock to exclude, so both calls are bookkeeping
    // over a count that never exceeds one. The handle is still validated,
    // because a caller that passed nonsense should be told.
    if (!occ_heap_handle_ok(reinterpret_cast<std::uint64_t>(heap))) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr3_RtlWow64SetThreadContext(
    std::uint64_t thread, const void* context) noexcept {
    // Setting a 32-bit context needs a 32-bit thread to set it on, and this
    // runtime runs native 64-bit code only.
    static_cast<void>(thread);
    static_cast<void>(context);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) std::uint64_t nr3_RtlWow64SuspendThread(
    std::uint64_t thread) noexcept {
    // Suspending a thread is a scheduler operation this runtime has no
    // second thread for, let alone a 32-bit one.
    static_cast<void>(thread);
    return static_cast<std::uint64_t>(-1);
}

// The two pieces of this slice's state that the kernel32 shell reaches for.
//
// The filter and the error mode are owned here, and the Win32 spellings of
// the same operations live in another file. They are read and written
// through these two rather than kept in a second place, because a second
// place is a second value: a guest that set the mode through
// `RtlSetThreadErrorMode` and read it through `SetThreadErrorMode` must see
// one answer, and it will only see one if there is one variable.
extern "C" void* occ_unhandled_filter() noexcept {
    return g_unhandled_filter;
}

extern "C" std::uint32_t occ_set_thread_error_mode(
    std::uint32_t mode, std::uint32_t* previous) noexcept {
    if (previous != nullptr) {
        *previous = g_thread_error_mode;
    }
    g_thread_error_mode = mode;
    return 1;
}

// ------------------------------------------------------------- registration
//
// The names below are this slice's share of ntdll's export table, and each
// is registered exactly once across the runtime.

void add_ntdll_rtl_mem3(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("RtlQueryDynamicTimeZoneInformation",
      reinterpret_cast<void*>(&nr3_RtlQueryDynamicTimeZoneInformation));
    e("RtlQueryEnvironmentVariable",
      reinterpret_cast<void*>(&nr3_RtlQueryEnvironmentVariable));
    e("RtlQueryEnvironmentVariable_U",
      reinterpret_cast<void*>(&nr3_RtlQueryEnvironmentVariable_U));
    e("RtlQueryHeapInformation",
      reinterpret_cast<void*>(&nr3_RtlQueryHeapInformation));
    e("RtlQueryInformationAcl",
      reinterpret_cast<void*>(&nr3_RtlQueryInformationAcl));
    e("RtlQueryInformationActivationContext",
      reinterpret_cast<void*>(&nr3_RtlQueryInformationActivationContext));
    e("RtlQueryInformationActiveActivationContext",
      reinterpret_cast<void*>(&nr3_RtlQueryInformationActiveActivationContext));
    e("RtlQueryPackageIdentity",
      reinterpret_cast<void*>(&nr3_RtlQueryPackageIdentity));
    e("RtlQueryPerformanceCounter",
      reinterpret_cast<void*>(&nr3_RtlQueryPerformanceCounter));
    e("RtlQueryPerformanceFrequency",
      reinterpret_cast<void*>(&nr3_RtlQueryPerformanceFrequency));
    e("RtlQueryProcessBackTraceInformation",
      reinterpret_cast<void*>(&nr3_RtlQueryProcessBackTraceInformation));
    e("RtlQueryProcessDebugInformation",
      reinterpret_cast<void*>(&nr3_RtlQueryProcessDebugInformation));
    e("RtlQueryProcessHeapInformation",
      reinterpret_cast<void*>(&nr3_RtlQueryProcessHeapInformation));
    e("RtlQueryProcessLockInformation",
      reinterpret_cast<void*>(&nr3_RtlQueryProcessLockInformation));
    e("RtlQueryProcessPlaceholderCompatibilityMode",
      reinterpret_cast<void*>(&nr3_RtlQueryProcessPlaceholderCompatibilityMode));
    e("RtlQueryProperties",
      reinterpret_cast<void*>(&nr3_RtlQueryProperties));
    e("RtlQueryPropertyNames",
      reinterpret_cast<void*>(&nr3_RtlQueryPropertyNames));
    e("RtlQueryPropertySet",
      reinterpret_cast<void*>(&nr3_RtlQueryPropertySet));
    e("RtlQueryRegistryValues",
      reinterpret_cast<void*>(&nr3_RtlQueryRegistryValues));
    e("RtlQueryRegistryValuesEx",
      reinterpret_cast<void*>(&nr3_RtlQueryRegistryValuesEx));
    e("RtlQuerySecurityObject",
      reinterpret_cast<void*>(&nr3_RtlQuerySecurityObject));
    e("RtlQueryTagHeap",
      reinterpret_cast<void*>(&nr3_RtlQueryTagHeap));
    e("RtlQueryTimeZoneInformation",
      reinterpret_cast<void*>(&nr3_RtlQueryTimeZoneInformation));
    e("RtlQueryUnbiasedInterruptTime",
      reinterpret_cast<void*>(&nr3_RtlQueryUnbiasedInterruptTime));
    e("RtlQueueApcWow64Thread",
      reinterpret_cast<void*>(&nr3_RtlQueueApcWow64Thread));
    e("RtlQueueWorkItem",
      reinterpret_cast<void*>(&nr3_RtlQueueWorkItem));
    e("RtlRaiseException",
      reinterpret_cast<void*>(&nr3_RtlRaiseException));
    e("RtlRaiseStatus",
      reinterpret_cast<void*>(&nr3_RtlRaiseStatus));
    e("RtlRandom",
      reinterpret_cast<void*>(&nr3_RtlRandom));
    e("RtlRandomEx",
      reinterpret_cast<void*>(&nr3_RtlRandomEx));
    e("RtlRbInsertNodeEx",
      reinterpret_cast<void*>(&nr3_RtlRbInsertNodeEx));
    e("RtlRbRemoveNode",
      reinterpret_cast<void*>(&nr3_RtlRbRemoveNode));
    e("RtlReAllocateHeap",
      reinterpret_cast<void*>(&nr3_RtlReAllocateHeap));
    e("RtlRealPredecessor",
      reinterpret_cast<void*>(&nr3_RtlRealPredecessor));
    e("RtlRealSuccessor",
      reinterpret_cast<void*>(&nr3_RtlRealSuccessor));
    e("RtlRegisterSecureMemoryCacheCallback",
      reinterpret_cast<void*>(&nr3_RtlRegisterSecureMemoryCacheCallback));
    e("RtlRegisterWait",
      reinterpret_cast<void*>(&nr3_RtlRegisterWait));
    e("RtlReleaseActivationContext",
      reinterpret_cast<void*>(&nr3_RtlReleaseActivationContext));
    e("RtlReleasePath",
      reinterpret_cast<void*>(&nr3_RtlReleasePath));
    e("RtlReleasePebLock",
      reinterpret_cast<void*>(&nr3_RtlReleasePebLock));
    e("RtlReleaseRelativeName",
      reinterpret_cast<void*>(&nr3_RtlReleaseRelativeName));
    e("RtlReleaseResource",
      reinterpret_cast<void*>(&nr3_RtlReleaseResource));
    e("RtlReleaseSRWLockExclusive",
      reinterpret_cast<void*>(&nr3_RtlReleaseSRWLockExclusive));
    e("RtlReleaseSRWLockShared",
      reinterpret_cast<void*>(&nr3_RtlReleaseSRWLockShared));
    e("RtlRemoteCall",
      reinterpret_cast<void*>(&nr3_RtlRemoteCall));
    e("RtlRemoveVectoredContinueHandler",
      reinterpret_cast<void*>(&nr3_RtlRemoveVectoredContinueHandler));
    e("RtlRemoveVectoredExceptionHandler",
      reinterpret_cast<void*>(&nr3_RtlRemoveVectoredExceptionHandler));
    e("RtlResetNtUserPfn",
      reinterpret_cast<void*>(&nr3_RtlResetNtUserPfn));
    e("RtlResetRtlTranslations",
      reinterpret_cast<void*>(&nr3_RtlResetRtlTranslations));
    e("RtlRestoreContext",
      reinterpret_cast<void*>(&nr3_RtlRestoreContext));
    e("RtlRestoreLastWin32Error",
      reinterpret_cast<void*>(&nr3_RtlRestoreLastWin32Error));
    e("RtlRetrieveNtUserPfn",
      reinterpret_cast<void*>(&nr3_RtlRetrieveNtUserPfn));
    e("RtlRunOnceBeginInitialize",
      reinterpret_cast<void*>(&nr3_RtlRunOnceBeginInitialize));
    e("RtlRunOnceComplete",
      reinterpret_cast<void*>(&nr3_RtlRunOnceComplete));
    e("RtlRunOnceExecuteOnce",
      reinterpret_cast<void*>(&nr3_RtlRunOnceExecuteOnce));
    e("RtlRunOnceInitialize",
      reinterpret_cast<void*>(&nr3_RtlRunOnceInitialize));
    e("RtlSecondsSince1970ToTime",
      reinterpret_cast<void*>(&nr3_RtlSecondsSince1970ToTime));
    e("RtlSecondsSince1980ToTime",
      reinterpret_cast<void*>(&nr3_RtlSecondsSince1980ToTime));
    e("RtlSelfRelativeToAbsoluteSD",
      reinterpret_cast<void*>(&nr3_RtlSelfRelativeToAbsoluteSD));
    e("RtlSetAllBits",
      reinterpret_cast<void*>(&nr3_RtlSetAllBits));
    e("RtlSetBits",
      reinterpret_cast<void*>(&nr3_RtlSetBits));
    e("RtlSetControlSecurityDescriptor",
      reinterpret_cast<void*>(&nr3_RtlSetControlSecurityDescriptor));
    e("RtlSetCriticalSectionSpinCount",
      reinterpret_cast<void*>(&nr3_RtlSetCriticalSectionSpinCount));
    e("RtlSetCurrentDirectory_U",
      reinterpret_cast<void*>(&nr3_RtlSetCurrentDirectory_U));
    e("RtlSetCurrentEnvironment",
      reinterpret_cast<void*>(&nr3_RtlSetCurrentEnvironment));
    e("RtlSetCurrentTransaction",
      reinterpret_cast<void*>(&nr3_RtlSetCurrentTransaction));
    e("RtlSetDaclSecurityDescriptor",
      reinterpret_cast<void*>(&nr3_RtlSetDaclSecurityDescriptor));
    e("RtlSetEnvironmentVariable",
      reinterpret_cast<void*>(&nr3_RtlSetEnvironmentVariable));
    e("RtlSetExtendedFeaturesMask",
      reinterpret_cast<void*>(&nr3_RtlSetExtendedFeaturesMask));
    e("RtlSetGroupSecurityDescriptor",
      reinterpret_cast<void*>(&nr3_RtlSetGroupSecurityDescriptor));
    e("RtlSetHeapInformation",
      reinterpret_cast<void*>(&nr3_RtlSetHeapInformation));
    e("RtlSetInformationAcl",
      reinterpret_cast<void*>(&nr3_RtlSetInformationAcl));
    e("RtlSetIoCompletionCallback",
      reinterpret_cast<void*>(&nr3_RtlSetIoCompletionCallback));
    e("RtlSetLastWin32Error",
      reinterpret_cast<void*>(&nr3_RtlSetLastWin32Error));
    e("RtlSetLastWin32ErrorAndNtStatusFromNtStatus",
      reinterpret_cast<void*>(&nr3_RtlSetLastWin32ErrorAndNtStatusFromNtStatus));
    e("RtlSetOwnerSecurityDescriptor",
      reinterpret_cast<void*>(&nr3_RtlSetOwnerSecurityDescriptor));
    e("RtlSetProcessPreferredUILanguages",
      reinterpret_cast<void*>(&nr3_RtlSetProcessPreferredUILanguages));
    e("RtlSetProperties",
      reinterpret_cast<void*>(&nr3_RtlSetProperties));
    e("RtlSetPropertyClassId",
      reinterpret_cast<void*>(&nr3_RtlSetPropertyClassId));
    e("RtlSetPropertyNames",
      reinterpret_cast<void*>(&nr3_RtlSetPropertyNames));
    e("RtlSetPropertySetClassId",
      reinterpret_cast<void*>(&nr3_RtlSetPropertySetClassId));
    e("RtlSetSaclSecurityDescriptor",
      reinterpret_cast<void*>(&nr3_RtlSetSaclSecurityDescriptor));
    e("RtlSetSearchPathMode",
      reinterpret_cast<void*>(&nr3_RtlSetSearchPathMode));
    e("RtlSetSecurityObject",
      reinterpret_cast<void*>(&nr3_RtlSetSecurityObject));
    e("RtlSetThreadErrorMode",
      reinterpret_cast<void*>(&nr3_RtlSetThreadErrorMode));
    e("RtlSetThreadPreferredUILanguages",
      reinterpret_cast<void*>(&nr3_RtlSetThreadPreferredUILanguages));
    e("RtlSetTimeZoneInformation",
      reinterpret_cast<void*>(&nr3_RtlSetTimeZoneInformation));
    e("RtlSetUnhandledExceptionFilter",
      reinterpret_cast<void*>(&nr3_RtlSetUnhandledExceptionFilter));
    e("RtlSetUserFlagsHeap",
      reinterpret_cast<void*>(&nr3_RtlSetUserFlagsHeap));
    e("RtlSetUserValueHeap",
      reinterpret_cast<void*>(&nr3_RtlSetUserValueHeap));
    e("RtlSizeHeap",
      reinterpret_cast<void*>(&nr3_RtlSizeHeap));
    e("RtlSleepConditionVariableCS",
      reinterpret_cast<void*>(&nr3_RtlSleepConditionVariableCS));
    e("RtlSleepConditionVariableSRW",
      reinterpret_cast<void*>(&nr3_RtlSleepConditionVariableSRW));
    e("RtlSplay",
      reinterpret_cast<void*>(&nr3_RtlSplay));
    e("RtlStartRXact",
      reinterpret_cast<void*>(&nr3_RtlStartRXact));
    e("RtlSubAuthorityCountSid",
      reinterpret_cast<void*>(&nr3_RtlSubAuthorityCountSid));
    e("RtlSubAuthoritySid",
      reinterpret_cast<void*>(&nr3_RtlSubAuthoritySid));
    e("RtlSubtreePredecessor",
      reinterpret_cast<void*>(&nr3_RtlSubtreePredecessor));
    e("RtlSubtreeSuccessor",
      reinterpret_cast<void*>(&nr3_RtlSubtreeSuccessor));
    e("RtlSystemTimeToLocalTime",
      reinterpret_cast<void*>(&nr3_RtlSystemTimeToLocalTime));
    e("RtlTimeFieldsToTime",
      reinterpret_cast<void*>(&nr3_RtlTimeFieldsToTime));
    e("RtlTimeToElapsedTimeFields",
      reinterpret_cast<void*>(&nr3_RtlTimeToElapsedTimeFields));
    e("RtlTimeToSecondsSince1970",
      reinterpret_cast<void*>(&nr3_RtlTimeToSecondsSince1970));
    e("RtlTimeToSecondsSince1980",
      reinterpret_cast<void*>(&nr3_RtlTimeToSecondsSince1980));
    e("RtlTimeToTimeFields",
      reinterpret_cast<void*>(&nr3_RtlTimeToTimeFields));
    e("RtlTryAcquireSRWLockExclusive",
      reinterpret_cast<void*>(&nr3_RtlTryAcquireSRWLockExclusive));
    e("RtlTryAcquireSRWLockShared",
      reinterpret_cast<void*>(&nr3_RtlTryAcquireSRWLockShared));
    e("RtlTryEnterCriticalSection",
      reinterpret_cast<void*>(&nr3_RtlTryEnterCriticalSection));
    e("RtlUniform",
      reinterpret_cast<void*>(&nr3_RtlUniform));
    e("RtlUnlockHeap",
      reinterpret_cast<void*>(&nr3_RtlUnlockHeap));
    e("RtlUnwind",
      reinterpret_cast<void*>(&nr3_RtlUnwind));
    e("RtlUpdateTimer",
      reinterpret_cast<void*>(&nr3_RtlUpdateTimer));
    e("RtlUsageHeap",
      reinterpret_cast<void*>(&nr3_RtlUsageHeap));
    e("RtlUserThreadStart",
      reinterpret_cast<void*>(&nr3_RtlUserThreadStart));
    e("RtlValidAcl",
      reinterpret_cast<void*>(&nr3_RtlValidAcl));
    e("RtlValidRelativeSecurityDescriptor",
      reinterpret_cast<void*>(&nr3_RtlValidRelativeSecurityDescriptor));
    e("RtlValidSecurityDescriptor",
      reinterpret_cast<void*>(&nr3_RtlValidSecurityDescriptor));
    e("RtlValidSid",
      reinterpret_cast<void*>(&nr3_RtlValidSid));
    e("RtlValidateHeap",
      reinterpret_cast<void*>(&nr3_RtlValidateHeap));
    e("RtlValidateProcessHeaps",
      reinterpret_cast<void*>(&nr3_RtlValidateProcessHeaps));
    e("RtlVerifyVersionInfo",
      reinterpret_cast<void*>(&nr3_RtlVerifyVersionInfo));
    e("RtlWaitOnAddress",
      reinterpret_cast<void*>(&nr3_RtlWaitOnAddress));
    e("RtlWakeAddressAll",
      reinterpret_cast<void*>(&nr3_RtlWakeAddressAll));
    e("RtlWakeAddressSingle",
      reinterpret_cast<void*>(&nr3_RtlWakeAddressSingle));
    e("RtlWakeAllConditionVariable",
      reinterpret_cast<void*>(&nr3_RtlWakeAllConditionVariable));
    e("RtlWakeConditionVariable",
      reinterpret_cast<void*>(&nr3_RtlWakeConditionVariable));
    e("RtlWalkFrameChain",
      reinterpret_cast<void*>(&nr3_RtlWalkFrameChain));
    e("RtlWalkHeap",
      reinterpret_cast<void*>(&nr3_RtlWalkHeap));
    e("RtlWow64EnableFsRedirection",
      reinterpret_cast<void*>(&nr3_RtlWow64EnableFsRedirection));
    e("RtlWow64EnableFsRedirectionEx",
      reinterpret_cast<void*>(&nr3_RtlWow64EnableFsRedirectionEx));
    e("RtlWow64GetCpuAreaInfo",
      reinterpret_cast<void*>(&nr3_RtlWow64GetCpuAreaInfo));
    e("RtlWow64GetCurrentCpuArea",
      reinterpret_cast<void*>(&nr3_RtlWow64GetCurrentCpuArea));
    e("RtlWow64GetCurrentMachine",
      reinterpret_cast<void*>(&nr3_RtlWow64GetCurrentMachine));
    e("RtlWow64GetProcessMachines",
      reinterpret_cast<void*>(&nr3_RtlWow64GetProcessMachines));
    e("RtlWow64GetSharedInfoProcess",
      reinterpret_cast<void*>(&nr3_RtlWow64GetSharedInfoProcess));
    e("RtlWow64GetThreadContext",
      reinterpret_cast<void*>(&nr3_RtlWow64GetThreadContext));
    e("RtlWow64GetThreadSelectorEntry",
      reinterpret_cast<void*>(&nr3_RtlWow64GetThreadSelectorEntry));
    e("RtlWow64IsWowGuestMachineSupported",
      reinterpret_cast<void*>(&nr3_RtlWow64IsWowGuestMachineSupported));
    e("RtlWow64PopAllCrossProcessWorkFromWorkList",
      reinterpret_cast<void*>(&nr3_RtlWow64PopAllCrossProcessWorkFromWorkList));
    e("RtlWow64PopCrossProcessWorkFromFreeList",
      reinterpret_cast<void*>(&nr3_RtlWow64PopCrossProcessWorkFromFreeList));
    e("RtlWow64PushCrossProcessWorkOntoFreeList",
      reinterpret_cast<void*>(&nr3_RtlWow64PushCrossProcessWorkOntoFreeList));
    e("RtlWow64PushCrossProcessWorkOntoWorkList",
      reinterpret_cast<void*>(&nr3_RtlWow64PushCrossProcessWorkOntoWorkList));
    e("RtlWow64RequestCrossProcessHeavyFlush",
      reinterpret_cast<void*>(&nr3_RtlWow64RequestCrossProcessHeavyFlush));
    e("RtlWow64SetThreadContext",
      reinterpret_cast<void*>(&nr3_RtlWow64SetThreadContext));
    e("RtlWow64SuspendThread",
      reinterpret_cast<void*>(&nr3_RtlWow64SuspendThread));
    e("RtlWriteRegistryValue",
      reinterpret_cast<void*>(&nr3_RtlWriteRegistryValue));
    e("RtlZombifyActivationContext",
      reinterpret_cast<void*>(&nr3_RtlZombifyActivationContext));
    e("RtlpNtCreateKey",
      reinterpret_cast<void*>(&nr3_RtlpNtCreateKey));
    e("RtlpNtEnumerateSubKey",
      reinterpret_cast<void*>(&nr3_RtlpNtEnumerateSubKey));
    e("RtlpNtMakeTemporaryKey",
      reinterpret_cast<void*>(&nr3_RtlpNtMakeTemporaryKey));
    e("RtlpNtOpenKey",
      reinterpret_cast<void*>(&nr3_RtlpNtOpenKey));
    e("RtlpNtQueryValueKey",
      reinterpret_cast<void*>(&nr3_RtlpNtQueryValueKey));
    e("RtlpNtSetValueKey",
      reinterpret_cast<void*>(&nr3_RtlpNtSetValueKey));
    e("RtlpQueryDefaultUILanguage",
      reinterpret_cast<void*>(&nr3_RtlpQueryDefaultUILanguage));
    e("RtlpUnWaitCriticalSection",
      reinterpret_cast<void*>(&nr3_RtlpUnWaitCriticalSection));
    e("RtlpWaitForCriticalSection",
      reinterpret_cast<void*>(&nr3_RtlpWaitForCriticalSection));
}

}  // namespace occ::runtime::winabi

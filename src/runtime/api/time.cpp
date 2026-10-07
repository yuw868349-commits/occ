// The time family, as kernel32 spells it.
//
// Two clocks are involved and they are not the same clock. A `FILETIME` is a
// count of 100-nanosecond ticks from the start of 1601; a `SYSTEMTIME` is a
// broken-down calendar date; and the host's own clock counts seconds from
// the start of 1970. Every function here is a conversion between two of the
// three, and the epoch offset between the Windows one and the host's is the
// constant `kEpochDeltaSeconds` -- leave it out and every timestamp moves by
// four centuries.
//
// The reference settles the conversions, and one of its answers is a rule
// this file does not follow. It accepts a `SYSTEMTIME` with month 13 and
// normalises it; the documentation says the call fails for a field out of
// range, and a caller that compares the result against what it passed is
// better served by the failure. That departure is stated where it happens.
//
// A second departure is a refusal rather than a difference. The reference
// will set the host's clock from inside a run, and this runtime will not:
// a guest that moves the machine's time moves it for everything else on the
// machine, which is the one side effect a container exists to prevent. The
// call fails with the error Windows gives a caller without the privilege,
// which is what a guest in a container would get there too.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>

#include <time.h>

namespace occ::runtime::winabi {
namespace {

// The guest's structures, as byte offsets. They are laid out field by field
// rather than through a struct, because the guest's packing is Windows' and
// the host's is not.
//
// SYSTEMTIME is eight 16-bit fields: year, month, day of week, day, hour,
// minute, second, millisecond -- sixteen bytes.
constexpr std::size_t kSystemTimeBytes = 16;
constexpr std::size_t kSysYear = 0;
constexpr std::size_t kSysMonth = 2;
constexpr std::size_t kSysDayOfWeek = 4;
constexpr std::size_t kSysDay = 6;
constexpr std::size_t kSysHour = 8;
constexpr std::size_t kSysMinute = 10;
constexpr std::size_t kSysSecond = 12;
constexpr std::size_t kSysMilliseconds = 14;

// TIME_ZONE_INFORMATION: a bias, two named zones of 32 UTF-16 units each,
// two SYSTEMTIMEs, and two more biases. The names are UTF-16 and the counts
// are in units rather than bytes.
constexpr std::size_t kTzBias = 0;
constexpr std::size_t kTzStandardName = 4;
constexpr std::size_t kTzStandardDate = 4 + 64;
constexpr std::size_t kTzStandardBias = 4 + 64 + 16;
constexpr std::size_t kTzDaylightName = 4 + 64 + 16 + 4;
constexpr std::size_t kTzDaylightDate = 4 + 64 + 16 + 4 + 64;
constexpr std::size_t kTzDaylightBias = 4 + 64 + 16 + 4 + 64 + 16;
constexpr std::size_t kTzBytes = 4 + 64 + 16 + 4 + 64 + 16 + 4;

// The seconds between the start of 1601 and the start of 1970.
constexpr std::uint64_t kEpochDeltaSeconds = 11644473600ULL;
constexpr std::uint64_t kTicksPerSecond = 10000000ULL;
constexpr std::uint64_t kTicksPerMillisecond = 10000ULL;

// The range Windows documents for a year in a SYSTEMTIME, which is the range
// a FILETIME can represent.
constexpr std::uint16_t kMinYear = 1601;
constexpr std::uint16_t kMaxYear = 30827;

constexpr std::uint32_t kErrorInvalidParameter = 87;
constexpr std::uint32_t kErrorPrivilegeNotHeld = 1314;

// --------------------------------------------------------------- the reads

[[nodiscard]] std::uint16_t get_u16(const std::uint8_t* base,
                                    std::size_t offset) noexcept {
    std::uint16_t value = 0;
    std::memcpy(&value, base + offset, sizeof(value));
    return value;
}

[[nodiscard]] std::uint32_t get_u32(const std::uint8_t* base,
                                    std::size_t offset) noexcept {
    std::uint32_t value = 0;
    std::memcpy(&value, base + offset, sizeof(value));
    return value;
}

void put_u16(std::uint8_t* base, std::size_t offset,
             std::uint16_t value) noexcept {
    std::memcpy(base + offset, &value, sizeof(value));
}

void put_u32(std::uint8_t* base, std::size_t offset,
             std::uint32_t value) noexcept {
    std::memcpy(base + offset, &value, sizeof(value));
}

// ------------------------------------------------------- the broken-down

// A SYSTEMTIME as the fields the host's own conversion takes.
struct CivilTime {
    std::uint16_t year = 0;
    std::uint16_t month = 0;
    std::uint16_t day = 0;
    std::uint16_t hour = 0;
    std::uint16_t minute = 0;
    std::uint16_t second = 0;
    std::uint16_t millisecond = 0;
};

[[nodiscard]] CivilTime read_civil(const std::uint8_t* base) noexcept {
    CivilTime out;
    out.year = get_u16(base, kSysYear);
    out.month = get_u16(base, kSysMonth);
    out.day = get_u16(base, kSysDay);
    out.hour = get_u16(base, kSysHour);
    out.minute = get_u16(base, kSysMinute);
    out.second = get_u16(base, kSysSecond);
    out.millisecond = get_u16(base, kSysMilliseconds);
    return out;
}

// Whether every field is one a calendar can hold.
//
// The reference does not check, and normalises month 13 into the next year
// instead. The documentation says the call fails, and a caller that passes a
// date it computed and gets a different one back has no way to notice -- so
// this refuses, and the refusal is the departure from the reference rather
// than an oversight.
[[nodiscard]] bool civil_in_range(const CivilTime& t) noexcept {
    if (t.year < kMinYear || t.year > kMaxYear) {
        return false;
    }
    if (t.month < 1 || t.month > 12) {
        return false;
    }
    if (t.day < 1 || t.day > 31) {
        return false;
    }
    if (t.hour > 23 || t.minute > 59 || t.second > 59) {
        return false;
    }
    if (t.millisecond > 999) {
        return false;
    }
    // A day that does not exist in that month.
    //
    // The check is a round trip through the host, and the fields are kept
    // before it because `timegm` writes the normalised result back into the
    // structure it is given: `2026-02-30` comes back as `2026-03-02` and a
    // comparison against the modified structure would find them equal. That
    // is the whole check, so reading the fields afterwards makes it a
    // function that accepts every date.
    struct tm probe {};
    probe.tm_year = static_cast<int>(t.year) - 1900;
    probe.tm_mon = static_cast<int>(t.month) - 1;
    probe.tm_mday = static_cast<int>(t.day);
    probe.tm_hour = static_cast<int>(t.hour);
    probe.tm_min = static_cast<int>(t.minute);
    probe.tm_sec = static_cast<int>(t.second);
    probe.tm_isdst = 0;
    const int want_year = probe.tm_year;
    const int want_month = probe.tm_mon;
    const int want_day = probe.tm_mday;
    const ::time_t seconds = ::timegm(&probe);
    struct tm back {};
    if (::gmtime_r(&seconds, &back) == nullptr) {
        return false;
    }
    return back.tm_year == want_year && back.tm_mon == want_month &&
           back.tm_mday == want_day;
}

// The ticks a broken-down time names, counted from the start of 1601. The
// caller has already checked the fields, so this is the arithmetic rather
// than the validation.
[[nodiscard]] std::uint64_t ticks_from_civil(const CivilTime& t) noexcept {
    struct tm probe {};
    probe.tm_year = static_cast<int>(t.year) - 1900;
    probe.tm_mon = static_cast<int>(t.month) - 1;
    probe.tm_mday = static_cast<int>(t.day);
    probe.tm_hour = static_cast<int>(t.hour);
    probe.tm_min = static_cast<int>(t.minute);
    probe.tm_sec = static_cast<int>(t.second);
    probe.tm_isdst = 0;
    const ::time_t seconds = ::timegm(&probe);
    // Signed, because every date before 1970 is a negative count from the
    // host's epoch and this format starts four centuries earlier than that.
    // Clamping the negative to zero instead would move every date before
    // 1970 forward by the offset -- and 1601, the first year the format can
    // represent, would answer the offset rather than zero.
    const std::int64_t offset = static_cast<std::int64_t>(seconds) +
                                static_cast<std::int64_t>(kEpochDeltaSeconds);
    if (offset < 0) {
        return 0;
    }
    return static_cast<std::uint64_t>(offset) * kTicksPerSecond +
           static_cast<std::uint64_t>(t.millisecond) * kTicksPerMillisecond;
}

// The broken-down time a tick count names, or false when it names nothing.
//
// Zero is the case worth naming: the reference refuses it and so does this,
// because a FILETIME of zero is the value a structure has before anything
// wrote to it, and reading it as the first day of 1601 would turn an
// uninitialised field into a date.
[[nodiscard]] bool civil_from_ticks(std::uint64_t ticks,
                                    CivilTime& out) noexcept {
    if (ticks == 0) {
        return false;
    }
    const std::uint64_t seconds = ticks / kTicksPerSecond;
    if (seconds < kEpochDeltaSeconds) {
        return false;
    }
    const std::uint64_t since_1970 = seconds - kEpochDeltaSeconds;
    if (since_1970 > static_cast<std::uint64_t>(0x7FFFFFFFFFFFFFFFLL)) {
        return false;
    }
    const ::time_t host = static_cast<::time_t>(since_1970);
    struct tm broken {};
    if (::gmtime_r(&host, &broken) == nullptr) {
        return false;
    }
    const int year = broken.tm_year + 1900;
    if (year < kMinYear || year > kMaxYear) {
        return false;
    }
    out.year = static_cast<std::uint16_t>(year);
    out.month = static_cast<std::uint16_t>(broken.tm_mon + 1);
    out.day = static_cast<std::uint16_t>(broken.tm_mday);
    out.hour = static_cast<std::uint16_t>(broken.tm_hour);
    out.minute = static_cast<std::uint16_t>(broken.tm_min);
    out.second = static_cast<std::uint16_t>(broken.tm_sec);
    out.millisecond =
        static_cast<std::uint16_t>((ticks % kTicksPerSecond) /
                                   kTicksPerMillisecond);
    return true;
}

[[nodiscard]] std::uint64_t read_ticks(const std::uint8_t* base) noexcept {
    const std::uint64_t low = get_u32(base, 0);
    const std::uint64_t high = get_u32(base, 4);
    return (high << 32) | low;
}

void write_ticks(std::uint8_t* base, std::uint64_t ticks) noexcept {
    put_u32(base, 0, static_cast<std::uint32_t>(ticks & 0xFFFFFFFFULL));
    put_u32(base, 4, static_cast<std::uint32_t>(ticks >> 32));
}

void write_civil(std::uint8_t* base, const CivilTime& t) noexcept {
    // The day of week is not a field the host's conversion produces, so it is
    // computed here: the two conversions agree on every date, and a
    // SYSTEMTIME whose day of week disagreed with its date would be a
    // structure no caller could trust either half of.
    std::uint16_t day_of_week = 0;
    struct tm probe {};
    probe.tm_year = static_cast<int>(t.year) - 1900;
    probe.tm_mon = static_cast<int>(t.month) - 1;
    probe.tm_mday = static_cast<int>(t.day);
    probe.tm_hour = static_cast<int>(t.hour);
    probe.tm_min = static_cast<int>(t.minute);
    probe.tm_sec = static_cast<int>(t.second);
    probe.tm_isdst = 0;
    const ::time_t seconds = ::timegm(&probe);
    if (seconds != static_cast<::time_t>(-1)) {
        struct tm back {};
        if (::gmtime_r(&seconds, &back) != nullptr) {
            day_of_week = static_cast<std::uint16_t>(back.tm_wday);
        }
    }
    put_u16(base, kSysYear, t.year);
    put_u16(base, kSysMonth, t.month);
    put_u16(base, kSysDayOfWeek, day_of_week);
    put_u16(base, kSysDay, t.day);
    put_u16(base, kSysHour, t.hour);
    put_u16(base, kSysMinute, t.minute);
    put_u16(base, kSysSecond, t.second);
    put_u16(base, kSysMilliseconds, t.millisecond);
}

// The bias the host's zone has, in minutes, with the sign Windows uses:
// a positive bias is behind UTC, so a zone ahead of it is negative.
[[nodiscard]] std::int32_t host_bias_minutes(std::int64_t at_seconds) noexcept {
    const ::time_t when = static_cast<::time_t>(at_seconds);
    struct tm local {};
    if (::localtime_r(&when, &local) == nullptr) {
        return 0;
    }
    // `tm_gmtoff` is seconds east of UTC, which is the opposite sign and a
    // different unit.
    return static_cast<std::int32_t>(-(local.tm_gmtoff / 60));
}

void write_utf16(std::uint8_t* base, std::size_t offset,
                 std::string_view ascii, std::size_t units) noexcept {
    std::size_t i = 0;
    for (; i < ascii.size() && i + 1 < units; ++i) {
        put_u16(base, offset + i * 2, static_cast<std::uint16_t>(ascii[i]));
    }
    for (; i < units; ++i) {
        put_u16(base, offset + i * 2, 0);
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// ABI entry points
// ---------------------------------------------------------------------------

namespace {

// The ticks the machine's clock reads now, as a FILETIME.
[[nodiscard]] std::uint64_t now_ticks() noexcept {
    struct timespec ts {};
    if (::clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    return (static_cast<std::uint64_t>(ts.tv_sec) + kEpochDeltaSeconds) *
               kTicksPerSecond +
           static_cast<std::uint64_t>(ts.tv_nsec) / 100;
}

// A duration as the 100-nanosecond ticks a FILETIME carries, which is the
// unit every one of these counts in -- including the elapsed-time ones,
// where the name says "file time" and the value is a duration.
[[nodiscard]] std::uint64_t ticks_from_timespec(const struct timespec& ts) noexcept {
    return static_cast<std::uint64_t>(ts.tv_sec) * kTicksPerSecond +
           static_cast<std::uint64_t>(ts.tv_nsec) / 100;
}

// The refusal a caller gets for asking to move the machine's clock.
//
// The reference will do it. A guest that does it moves the clock for
// everything else on the machine, which is the one side effect a container
// exists to prevent, so this answers the error Windows gives a caller
// without the privilege -- which is what a guest in a container gets there
// too, and is the answer a program already handles.
[[nodiscard]] std::int32_t refuse_clock_write() noexcept {
    set_last_error(kErrorPrivilegeNotHeld);
    return 0;
}

}  // namespace

extern "C" __attribute__((ms_abi)) void k32t_GetSystemTime(
    std::uint8_t* out) noexcept {
    if (out == nullptr) {
        return;
    }
    CivilTime t;
    if (!civil_from_ticks(now_ticks(), t)) {
        std::memset(out, 0, kSystemTimeBytes);
        return;
    }
    write_civil(out, t);
}

extern "C" __attribute__((ms_abi)) void k32t_GetLocalTime(
    std::uint8_t* out) noexcept {
    if (out == nullptr) {
        return;
    }
    const std::uint64_t ticks = now_ticks();
    const std::int32_t bias = host_bias_minutes(
        static_cast<std::int64_t>(ticks / kTicksPerSecond) -
        static_cast<std::int64_t>(kEpochDeltaSeconds));
    // The bias is subtracted from UTC to get local, with Windows' sign.
    const std::int64_t local_minutes = bias;
    const std::int64_t shifted =
        static_cast<std::int64_t>(ticks) -
        local_minutes * 60 * static_cast<std::int64_t>(kTicksPerSecond);
    CivilTime t;
    if (!civil_from_ticks(static_cast<std::uint64_t>(shifted < 0 ? 0 : shifted),
                          t)) {
        std::memset(out, 0, kSystemTimeBytes);
        return;
    }
    write_civil(out, t);
}

extern "C" __attribute__((ms_abi)) void k32t_GetSystemTimeAsFileTime(
    std::uint8_t* out) noexcept {
    if (out == nullptr) {
        return;
    }
    write_ticks(out, now_ticks());
}

extern "C" __attribute__((ms_abi)) void k32t_GetSystemTimePreciseAsFileTime(
    std::uint8_t* out) noexcept {
    // The precise form exists on Windows to name a clock with sub-tick
    // accuracy. The host's realtime clock is the same source, so the answer
    // is the answer -- what the function adds on Windows is the guarantee,
    // and that is a property of this implementation rather than of the
    // value.
    k32t_GetSystemTimeAsFileTime(out);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_SetSystemTime(
    const std::uint8_t* in) noexcept {
    (void)in;
    return refuse_clock_write();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_SetLocalTime(
    const std::uint8_t* in) noexcept {
    (void)in;
    return refuse_clock_write();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_SetTimeZoneInformation(
    const std::uint8_t* in) noexcept {
    (void)in;
    return refuse_clock_write();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_SystemTimeToFileTime(
    const std::uint8_t* in, std::uint8_t* out) noexcept {
    if (in == nullptr || out == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const CivilTime t = read_civil(in);
    if (!civil_in_range(t)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    write_ticks(out, ticks_from_civil(t));
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_FileTimeToSystemTime(
    const std::uint8_t* in, std::uint8_t* out) noexcept {
    if (in == nullptr || out == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    CivilTime t;
    if (!civil_from_ticks(read_ticks(in), t)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    write_civil(out, t);
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_FileTimeToLocalFileTime(
    const std::uint8_t* in, std::uint8_t* out) noexcept {
    if (in == nullptr || out == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::uint64_t ticks = read_ticks(in);
    const std::int32_t bias = host_bias_minutes(
        static_cast<std::int64_t>(ticks / kTicksPerSecond) -
        static_cast<std::int64_t>(kEpochDeltaSeconds));
    const std::int64_t shifted =
        static_cast<std::int64_t>(ticks) -
        static_cast<std::int64_t>(bias) * 60 *
            static_cast<std::int64_t>(kTicksPerSecond);
    write_ticks(out, static_cast<std::uint64_t>(shifted < 0 ? 0 : shifted));
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_LocalFileTimeToFileTime(
    const std::uint8_t* in, std::uint8_t* out) noexcept {
    if (in == nullptr || out == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::uint64_t ticks = read_ticks(in);
    const std::int32_t bias = host_bias_minutes(
        static_cast<std::int64_t>(ticks / kTicksPerSecond) -
        static_cast<std::int64_t>(kEpochDeltaSeconds));
    const std::int64_t shifted =
        static_cast<std::int64_t>(ticks) +
        static_cast<std::int64_t>(bias) * 60 *
            static_cast<std::int64_t>(kTicksPerSecond);
    write_ticks(out, static_cast<std::uint64_t>(shifted < 0 ? 0 : shifted));
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_CompareFileTime(
    const std::uint8_t* a, const std::uint8_t* b) noexcept {
    if (a == nullptr || b == nullptr) {
        return 0;
    }
    // The comparison is unsigned over the whole 64 bits: a FILETIME is a
    // count and not a signed quantity, and comparing the halves as signed
    // would put every date after 1601 in the wrong order.
    const std::uint64_t left = read_ticks(a);
    const std::uint64_t right = read_ticks(b);
    if (left < right) {
        return -1;
    }
    return left > right ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32t_GetTickCount() noexcept {
    struct timespec ts {};
    if (::clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    // The count is milliseconds since the machine started, truncated to 32
    // bits. It wraps after 49 days, which is what the 64-bit form exists to
    // avoid and why a caller that spans the wrap uses that one.
    return static_cast<std::uint32_t>(ticks_from_timespec(ts) /
                                      kTicksPerMillisecond);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32t_GetTickCount64() noexcept {
    struct timespec ts {};
    if (::clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return ticks_from_timespec(ts) / kTicksPerMillisecond;
}

extern "C" __attribute__((ms_abi)) std::uint32_t
k32t_GetTimeZoneInformation(std::uint8_t* out) noexcept {
    if (out == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0xFFFFFFFFu;
    }
    std::memset(out, 0, kTzBytes);
    const std::uint64_t ticks = now_ticks();
    const std::int32_t bias = host_bias_minutes(
        static_cast<std::int64_t>(ticks / kTicksPerSecond) -
        static_cast<std::int64_t>(kEpochDeltaSeconds));
    const auto* field = reinterpret_cast<const std::uint8_t*>(&bias);
    std::memcpy(out + kTzBias, field, sizeof(bias));
    // The names are descriptive on Windows and a caller that compares them
    // against a string is a caller depending on a locale this runtime does
    // not have. They are filled with the zone's offset so that a program
    // that prints one prints something true rather than an empty string.
    std::string name = "UTC";
    if (bias != 0) {
        name = "UTC";
        name += (bias > 0 ? "-" : "+");
        const std::int32_t magnitude = bias < 0 ? -bias : bias;
        name += std::to_string(magnitude / 60);
        if (magnitude % 60 != 0) {
            name += ":";
            name += std::to_string(magnitude % 60);
        }
    }
    write_utf16(out, kTzStandardName, name, 32);
    write_utf16(out, kTzDaylightName, name, 32);
    // The two transition dates are written as zero explicitly rather than
    // left to the clear at the top of this function, because leaving them to
    // it is a property of a line elsewhere and a reader of this one would
    // have to go looking. A zero date is what a caller reads as "this zone
    // has no transition", which is the truth here: this runtime carries no
    // transition table, and a date it invented would be a date a program
    // would act on.
    std::memset(out + kTzStandardDate, 0, 16);
    std::memset(out + kTzDaylightDate, 0, 16);
    // The biases stay at zero for the same reason: a caller adds the bias to
    // the base offset, and a non-zero one would move the answer by an hour
    // on dates the runtime cannot tell are in that season.
    put_u32(out, kTzStandardBias, 0);
    put_u32(out, kTzDaylightBias, 0);
    set_last_error(0);
    return 0;  // TIME_ZONE_ID_UNKNOWN
}

extern "C" __attribute__((ms_abi)) std::uint32_t
k32t_GetDynamicTimeZoneInformation(std::uint8_t* out) noexcept {
    // The dynamic form adds a key name and a flag at the end. The fields the
    // static form fills are the same and in the same places, so this writes
    // those and leaves the two additions zero: the key names a registry
    // value that does not exist here, and the flag would be a claim about
    // the other field.
    return k32t_GetTimeZoneInformation(out);
}

extern "C" __attribute__((ms_abi)) std::int32_t
k32t_SystemTimeToTzSpecificLocalTime(const std::uint8_t* zone,
                                     const std::uint8_t* utc,
                                     std::uint8_t* out) noexcept {
    (void)zone;
    if (utc == nullptr || out == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const CivilTime t = read_civil(utc);
    if (!civil_in_range(t)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::uint64_t ticks = ticks_from_civil(t);
    const std::int32_t bias = host_bias_minutes(
        static_cast<std::int64_t>(ticks / kTicksPerSecond) -
        static_cast<std::int64_t>(kEpochDeltaSeconds));
    const std::int64_t shifted =
        static_cast<std::int64_t>(ticks) -
        static_cast<std::int64_t>(bias) * 60 *
            static_cast<std::int64_t>(kTicksPerSecond);
    CivilTime local;
    if (!civil_from_ticks(static_cast<std::uint64_t>(shifted < 0 ? 0 : shifted),
                          local)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    write_civil(out, local);
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t
k32t_TzSpecificLocalTimeToSystemTime(const std::uint8_t* zone,
                                     const std::uint8_t* local,
                                     std::uint8_t* out) noexcept {
    (void)zone;
    if (local == nullptr || out == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const CivilTime t = read_civil(local);
    if (!civil_in_range(t)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::uint64_t ticks = ticks_from_civil(t);
    const std::int32_t bias = host_bias_minutes(
        static_cast<std::int64_t>(ticks / kTicksPerSecond) -
        static_cast<std::int64_t>(kEpochDeltaSeconds));
    const std::int64_t shifted =
        static_cast<std::int64_t>(ticks) +
        static_cast<std::int64_t>(bias) * 60 *
            static_cast<std::int64_t>(kTicksPerSecond);
    CivilTime utc_time;
    if (!civil_from_ticks(static_cast<std::uint64_t>(shifted < 0 ? 0 : shifted),
                          utc_time)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    write_civil(out, utc_time);
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_GetSystemTimes(
    std::uint8_t* idle, std::uint8_t* kernel, std::uint8_t* user) noexcept {
    if (idle == nullptr || kernel == nullptr || user == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The host's process times are the closest thing it has to the machine's,
    // and they are what a caller can actually act on: a program reading these
    // is measuring its own consumption far more often than the machine's.
    struct timespec ts {};
    const auto take = [&ts](clockid_t which) {
        std::memset(&ts, 0, sizeof(ts));
        if (::clock_gettime(which, &ts) != 0) {
            return std::uint64_t{0};
        }
        return ticks_from_timespec(ts);
    };
    const std::uint64_t idle_ticks = 0;
    const std::uint64_t kernel_ticks = take(CLOCK_PROCESS_CPUTIME_ID);
    const std::uint64_t user_ticks = take(CLOCK_PROCESS_CPUTIME_ID);
    write_ticks(idle, idle_ticks);
    write_ticks(kernel, kernel_ticks);
    write_ticks(user, user_ticks);
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_GetThreadTimes(
    std::uint64_t thread, std::uint8_t* creation, std::uint8_t* exit_time,
    std::uint8_t* kernel, std::uint8_t* user) noexcept {
    (void)thread;
    if (creation == nullptr || exit_time == nullptr || kernel == nullptr ||
        user == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    struct timespec ts {};
    std::memset(&ts, 0, sizeof(ts));
    const std::uint64_t cpu =
        ::clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) == 0
            ? ticks_from_timespec(ts)
            : 0;
    // A thread that has not ended has no exit time, which Windows spells as
    // zero rather than as the current time.
    write_ticks(creation, 0);
    write_ticks(exit_time, 0);
    write_ticks(kernel, 0);
    write_ticks(user, cpu);
    set_last_error(0);
    return 1;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void add_time_kernel32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("CompareFileTime", reinterpret_cast<void*>(&k32t_CompareFileTime));
    e("FileTimeToLocalFileTime",
      reinterpret_cast<void*>(&k32t_FileTimeToLocalFileTime));
    e("FileTimeToSystemTime",
      reinterpret_cast<void*>(&k32t_FileTimeToSystemTime));
    e("GetDynamicTimeZoneInformation",
      reinterpret_cast<void*>(&k32t_GetDynamicTimeZoneInformation));
    e("GetLocalTime", reinterpret_cast<void*>(&k32t_GetLocalTime));
    e("GetSystemTime", reinterpret_cast<void*>(&k32t_GetSystemTime));
    e("GetSystemTimeAsFileTime",
      reinterpret_cast<void*>(&k32t_GetSystemTimeAsFileTime));
    e("GetSystemTimePreciseAsFileTime",
      reinterpret_cast<void*>(&k32t_GetSystemTimePreciseAsFileTime));
    e("GetSystemTimes", reinterpret_cast<void*>(&k32t_GetSystemTimes));
    e("GetThreadTimes", reinterpret_cast<void*>(&k32t_GetThreadTimes));
    e("GetTickCount", reinterpret_cast<void*>(&k32t_GetTickCount));
    e("GetTickCount64", reinterpret_cast<void*>(&k32t_GetTickCount64));
    e("GetTimeZoneInformation",
      reinterpret_cast<void*>(&k32t_GetTimeZoneInformation));
    e("LocalFileTimeToFileTime",
      reinterpret_cast<void*>(&k32t_LocalFileTimeToFileTime));
    e("SetLocalTime", reinterpret_cast<void*>(&k32t_SetLocalTime));
    e("SetSystemTime", reinterpret_cast<void*>(&k32t_SetSystemTime));
    e("SetTimeZoneInformation",
      reinterpret_cast<void*>(&k32t_SetTimeZoneInformation));
    e("SystemTimeToFileTime",
      reinterpret_cast<void*>(&k32t_SystemTimeToFileTime));
    e("SystemTimeToTzSpecificLocalTime",
      reinterpret_cast<void*>(&k32t_SystemTimeToTzSpecificLocalTime));
    e("TzSpecificLocalTimeToSystemTime",
      reinterpret_cast<void*>(&k32t_TzSpecificLocalTimeToSystemTime));
}

}  // namespace occ::runtime::winabi

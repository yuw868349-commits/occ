// The multimedia timers, as `winmm.dll` spells them.
//
// A program asks `winmm` for two things: a finer scheduler tick, and a
// millisecond clock. The first is a request to the operating system's
// timer interrupt; the second is a clock read. Both have host answers --
// the tick request changes nothing this scheduler was not already
// prepared for, and the clock is the host's monotonic one -- and both are
// honest here for the same reason they are on Windows: a program that
// asked for a finer tick and then read the clock wants the clock to have
// advanced, and it does.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"

#include <cstdint>
#include <cstring>

#include <time.h>

namespace occ::runtime::winabi {

namespace {

// The timer-resolution request this runtime records. A request is recorded
// rather than dropped because `timeEndPeriod` asks whether a matching
// request was made -- and because a caller that reads its own state back
// through `timeGetDevCaps` is asking what the platform allows, which this
// answers with the range the host scheduler was built around.
std::uint32_t g_active_period = 0;

[[nodiscard]] std::uint64_t monotonic_millis() noexcept {
    struct timespec now;
    ::clock_gettime(CLOCK_MONOTONIC, &now);
    return static_cast<std::uint64_t>(now.tv_sec) * 1000ULL +
           static_cast<std::uint64_t>(now.tv_nsec) / 1000000ULL;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint32_t k32wm_timeBeginPeriod(
    std::uint32_t period) noexcept {
    // Windows refuses zero and answers one for a request it accepted; the
    // period is the caller's floor on the scheduler tick, and zero is not
    // a floor.
    if (period == 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    g_active_period = period;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32wm_timeEndPeriod(
    std::uint32_t period) noexcept {
    if (period == 0 || g_active_period != period) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    g_active_period = 0;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32wm_timeGetTime() noexcept {
    set_last_error(kErrorSuccess);
    return static_cast<std::uint32_t>(monotonic_millis());
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32wm_timeGetDevCaps(
    void* caps, std::uint32_t size) noexcept {
    // TIMECAPS: the minimum and maximum period the platform accepts, as
    // the two millisecond values a caller checks its request against.
    if (caps == nullptr || size < 8) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::uint32_t period_min = 1;
    const std::uint32_t period_max = 1000;
    std::memcpy(caps, &period_min, 4);
    std::memcpy(static_cast<std::uint8_t*>(caps) + 4, &period_max, 4);
    set_last_error(kErrorSuccess);
    return 1;
}

void add_winmm(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("timeBeginPeriod", reinterpret_cast<void*>(&k32wm_timeBeginPeriod));
    e("timeEndPeriod", reinterpret_cast<void*>(&k32wm_timeEndPeriod));
    e("timeGetTime", reinterpret_cast<void*>(&k32wm_timeGetTime));
    e("timeGetDevCaps", reinterpret_cast<void*>(&k32wm_timeGetDevCaps));
}

}  // namespace occ::runtime::winabi

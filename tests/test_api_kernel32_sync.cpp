// The synchronization family.
//
// The tests here are about the parts of the contract a program can tell apart
// from each other, not about the parts that merely do not crash:
//
//   * `WAIT_OBJECT_0 + i` names *which* object released a multi-object wait,
//     so the assertions signal one object of several and check that the
//     answer is its index. A wait implemented as a boolean could not pass
//     these, which is the point of them.
//   * An auto-reset event spends its signal on the wait that found it and a
//     manual-reset one does not, so both are checked by waiting twice: the
//     first wait succeeds either way and only the second tells them apart.
//   * A zero timeout is a poll and returns immediately, so it is checked by
//     wall-clock as well as by answer -- a wait that slept before answering
//     would give the right status too slowly to be usable in a loop.
//   * A mutex remembers its owner and a semaphore counts, so a recursive take
//     succeeds without blocking while a second thread's take does not, and
//     the count is checked through the ceiling `ReleaseSemaphore` enforces.
//   * A refusal is asserted by its error code. "Returns zero" would pass for
//     a function that returned zero for the wrong reason, so each refusal
//     below checks the code a caller would branch on.
//
// The `A` and `W` spellings of each pair are given the same input and their
// answers compared, because the pair is only one implementation if they agree.
//
// The expected values come from the Windows documentation of each call and
// from the ABI, not from a reference run: the reference tree this project
// normally checks answers against was not reachable while this was written,
// so the codes below are the documented ones and are marked where the
// behaviour they assert is inferred rather than quoted.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/objects.h"
#include "occ/runtime/winabi.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace occ::runtime;
using namespace occ::runtime::winabi;

namespace occ::runtime::winabi {
// The entry points, declared here rather than through `api.h` because this
// domain's names are not in that header yet; the same declarations will move
// there when the domain is wired in.
void add_kernel32_sync(ExportList& out);
extern "C" __attribute__((ms_abi)) std::uint32_t k32s_WaitForMultipleObjects(
    std::uint32_t count, const std::uint64_t* handles, std::int32_t wait_all,
    std::uint32_t milliseconds) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32s_WaitForMultipleObjectsEx(
    std::uint32_t count, const std::uint64_t* handles, std::int32_t wait_all,
    std::uint32_t milliseconds, std::int32_t alertable) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32s_SleepEx(
    std::uint32_t milliseconds, std::int32_t alertable) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32s_SignalObjectAndWait(
    std::uint64_t signal_object, std::uint64_t wait_object,
    std::uint32_t milliseconds, std::uint32_t flags) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32s_PulseEvent(
    std::uint64_t handle) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateEventExW(
    void* attributes, const char16_t* name, std::uint32_t flags,
    std::uint32_t access) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateEventExA(
    void* attributes, const char* name, std::uint32_t flags,
    std::uint32_t access) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateMutexW(
    const char16_t* name, std::int32_t initial_owner,
    void* attributes) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateMutexA(
    const char* name, std::int32_t initial_owner, void* attributes) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateMutexExW(
    void* attributes, const char16_t* name, std::uint32_t flags,
    std::uint32_t access) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateSemaphoreW(
    void* attributes, std::int32_t initial_count, std::int32_t maximum_count,
    const char16_t* name) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateSemaphoreA(
    void* attributes, std::int32_t initial_count, std::int32_t maximum_count,
    const char* name) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32s_ReleaseMutex(
    std::uint64_t handle) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32s_ReleaseSemaphore(
    std::uint64_t handle, std::int32_t release_count,
    std::int32_t* previous_count) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32s_OpenEventW(
    std::uint32_t access, std::int32_t inherit,
    const char16_t* name) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32s_OpenMutexA(
    std::uint32_t access, std::int32_t inherit, const char* name) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateWaitableTimerW(
    void* attributes, std::int32_t manual_reset,
    const char16_t* name) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateTimerQueue()
    noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateThreadpoolWait(
    std::uint64_t callback, std::uint64_t context,
    std::uint64_t pool) noexcept;
extern "C" __attribute__((ms_abi)) Hresult k32s_SetThreadpoolTimerEx(
    std::uint64_t timer, std::uint64_t due, std::int64_t due_100ns,
    std::int32_t period_ms, std::uint32_t flags) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t
k32s_RegisterWaitForSingleObject(std::uint64_t object, std::uint64_t context,
                                 std::uint64_t callback,
                                 std::uint32_t flags,
                                 std::uint32_t milliseconds) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32s_SleepConditionVariableSRW(
    std::uint64_t condition, std::uint64_t lock, std::uint32_t milliseconds,
    std::uint32_t flags) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32s_SetEventWhenCallbackReturns(
    std::int32_t* set, std::uint64_t event) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32s_WaitForDebugEvent(
    std::uint32_t* process, std::uint32_t* thread,
    std::uint32_t milliseconds) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32s_WaitCommEvent(
    std::uint64_t port, std::uint64_t overlapped,
    std::uint32_t* mask) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32s_WaitNamedPipeW(
    const char16_t* name, std::uint32_t milliseconds) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32s_GetConsoleInputWaitHandle()
    noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32s_GenerateConsoleCtrlEvent(
    std::uint32_t control, std::uint32_t group) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32s_SetWaitableTimer(
    std::uint64_t handle, const std::int64_t* due, std::int32_t period,
    std::int32_t resume, std::uint64_t completion) noexcept;
}  // namespace occ::runtime::winabi

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

// The four wait statuses, as the numbers a guest compares against.
constexpr std::uint32_t kWaitObject0 = 0;
constexpr std::uint32_t kWaitTimeout = 258;
constexpr std::uint32_t kWaitFailed = 0xFFFFFFFFu;

constexpr std::uint32_t kInfinite = 0xFFFFFFFFu;
constexpr std::uint32_t kCreateEventManualReset = 1;
constexpr std::uint32_t kCreateMutexInitialOwner = 1;

constexpr std::uint32_t kErrorSuccess = 0;
constexpr std::uint32_t kErrorInvalidParameter = 87;
constexpr std::uint32_t kErrorNotSupported = 50;
constexpr std::uint32_t kErrorCallNotImplemented = 120;
constexpr std::uint32_t kErrorInvalidHandle = 6;
constexpr std::uint32_t kErrorNotOwner = 288;

// A handle that names nothing, in both of the two senses that matter: zero
// is the null handle and all-ones is `INVALID_HANDLE_VALUE`. A wait for
// either is a wait for an object that is not there.
constexpr std::uint64_t kNotAnObject = 0x40000000;

// How long a poll is allowed to take. Generous enough not to be flaky on a
// loaded machine, tight enough that a wait which slept before answering
// would fail: the point is that a zero timeout returns without sleeping at
// all, and 50ms is far below any sleep a correct implementation would make.
constexpr long kPollBudgetMs = 50;

long elapsed_ms(std::chrono::steady_clock::time_point from) {
    const auto spent = std::chrono::steady_clock::now() - from;
    return static_cast<long>(
        std::chrono::duration_cast<std::chrono::milliseconds>(spent).count());
}

// Waits on one handle. A wait over a single object is the same wait Windows
// performs, and routing the tests through the multi-object entry point keeps
// them on the code path a program that only has one object would still take
// through the family's own surface.
std::uint32_t wait_one(std::uint64_t handle, std::uint32_t ms) {
    const std::uint64_t handles[1] = {handle};
    return k32s_WaitForMultipleObjects(1, handles, 1, ms);
}

void test_auto_reset_consumes_its_signal() {
    // An auto-reset event releases one waiter and returns to non-signalled.
    // The first wait cannot tell it apart from a manual-reset one; only the
    // second can, which is why there are two waits and not one.
    const std::uint64_t event =
        k32s_CreateEventExW(nullptr, nullptr, 0, 0xFFFFFFFFu);
    check(event != kInvalidHandle, "event: an anonymous event is created");
    check(k32_GetLastError() == kErrorSuccess,
          "event: and reports success through GetLastError");

    check(objects::set_event(event), "event: it can be signalled");
    check(wait_one(event, 0) == kWaitObject0,
          "event: a signalled event answers the wait");
    check(wait_one(event, 0) == kWaitTimeout,
          "event: and an auto-reset one does not answer twice");

    // A manual-reset event keeps the signal, so the same two waits both
    // succeed. This is the assertion that distinguishes the two kinds: a
    // runtime that ignored the reset mode would fail the auto-reset case
    // above, and one that made everything auto-reset would fail this one.
    const std::uint64_t manual = k32s_CreateEventExW(
        nullptr, nullptr, kCreateEventManualReset, 0xFFFFFFFFu);
    check(manual != kInvalidHandle,
          "event: a manual-reset event is created");
    check(objects::set_event(manual), "manual: it can be signalled");
    check(wait_one(manual, 0) == kWaitObject0,
          "manual: the first wait succeeds");
    check(wait_one(manual, 0) == kWaitObject0,
          "manual: and the second does too");

    // A manual-reset event stays signalled until something resets it, which
    // is the other half of the difference: an auto-reset event is already
    // non-signalled, so a reset changes nothing for it.
    check(objects::reset_event(manual), "manual: it can be reset");
    check(wait_one(manual, 0) == kWaitTimeout,
          "manual: and is non-signalled afterwards");
    check(wait_one(event, 0) == kWaitTimeout,
          "event: resetting a non-signalled auto-reset event is harmless");
}

void test_zero_timeout_is_a_poll() {
    // A zero timeout asks about the state now. The answer has to come back
    // without sleeping, because a program waiting in a loop on a signalled
    // object would otherwise spend most of its time asleep -- so this checks
    // the elapsed time as well as the status, which a status-only assertion
    // could not.
    const std::uint64_t event =
        k32s_CreateEventExW(nullptr, nullptr, kCreateEventManualReset, 0);
    check(wait_one(event, 0) == kWaitTimeout,
          "poll: a non-signalled event times out at once");

    const auto before = std::chrono::steady_clock::now();
    (void)wait_one(event, 0);
    (void)wait_one(event, 0);
    const long spent = elapsed_ms(before);
    check(spent < kPollBudgetMs, "poll: two polls do not sleep between them");

    check(objects::set_event(event), "poll: the event can be signalled");
    const auto marked = std::chrono::steady_clock::now();
    check(wait_one(event, 0) == kWaitObject0,
          "poll: a signalled event answers without waiting");
    check(elapsed_ms(marked) < kPollBudgetMs,
          "poll: and answers without sleeping either");

    // A named event is refused, so `OpenEvent` has nothing to find. An
    // anonymous object standing in for the named one would be invisible to
    // the caller and worse than the failure.
    set_last_error(0);
    check(k32s_CreateEventExW(nullptr, u"Local\\nope", 0, 0) == kInvalidHandle,
          "named: a named event is refused");
    check(k32_GetLastError() == kErrorNotSupported,
          "named: and says the name namespace is not supported");
    check(k32s_OpenEventW(0x1F0003, 0, u"Local\\nope") == kInvalidHandle,
          "named: opening one is refused the same way");
    check(k32s_OpenEventW(0, 0, nullptr) == kInvalidHandle,
          "named: and a null name is not an anonymous one");
}

void test_invalid_handles_fail_the_wait() {
    // A wait for a handle that names nothing is a bug in the caller, and it
    // is a different answer from a timeout: a program polls in a loop and
    // must be able to tell "nothing yet" from "never".
    for (std::uint64_t bad : {std::uint64_t(0), kNotAnObject,
                              kInvalidHandleValue}) {
        set_last_error(0);
        const std::uint32_t status = wait_one(bad, 0);
        check(status == kWaitFailed, "bad handle: the wait fails");
        check(k32_GetLastError() == kErrorInvalidHandle,
              "bad handle: and reports an invalid handle");
    }

    // The same for a wait over several: one bad handle fails the whole wait
    // rather than answering for the good ones, because a caller cannot act on
    // "the second of these three signalled" when the third is not an object.
    const std::uint64_t good =
        k32s_CreateEventExW(nullptr, nullptr, kCreateEventManualReset, 0);
    const std::uint64_t handles[2] = {good, kNotAnObject};
    set_last_error(0);
    check(k32s_WaitForMultipleObjects(2, handles, 0, 0) == kWaitFailed,
          "bad handle: a multi-object wait fails as a whole");
    check(k32_GetLastError() == kErrorInvalidHandle,
          "bad handle: and says which kind of wrong it was");

    // The argument shapes Windows refuses before it looks at any handle.
    set_last_error(0);
    check(k32s_WaitForMultipleObjects(0, handles, 0, 0) == kWaitFailed,
          "bad argument: waiting over no objects fails");
    check(k32_GetLastError() == kErrorInvalidParameter,
          "bad argument: and reports a bad parameter");
    set_last_error(0);
    check(k32s_WaitForMultipleObjects(2, nullptr, 0, 0) == kWaitFailed,
          "bad argument: a null handle array fails");
    // `MAXIMUM_WAIT_OBJECTS` is 64 and the boundary is inclusive: 64 objects
    // is a legal wait and 65 is not.
    std::vector<std::uint64_t> many(65, good);
    set_last_error(0);
    check(k32s_WaitForMultipleObjects(65, many.data(), 1, 0) == kWaitFailed,
          "bad argument: more than sixty-four objects fails");
    check(k32_GetLastError() == kErrorInvalidParameter,
          "bad argument: and says why");
    check(k32s_WaitForMultipleObjects(64, many.data(), 1, 0) == kWaitObject0,
          "bad argument: sixty-four is inside the limit");
}

void test_multi_object_names_the_object() {
    // The defining property of a multi-object wait: the answer is
    // `WAIT_OBJECT_0 + i` for the object that released it. Each case signals
    // exactly one object of four and asserts that its index comes back, so a
    // wait implemented as "somebody was signalled" cannot pass -- it would
    // have no way to choose between the four answers.
    std::uint64_t handles[4];
    for (std::uint64_t& handle : handles) {
        handle = k32s_CreateEventExW(nullptr, nullptr,
                                     kCreateEventManualReset, 0);
    }

    for (std::uint32_t i = 0; i < 4; ++i) {
        check(objects::set_event(handles[i]), "multi: an event can be signalled");
        check(k32s_WaitForMultipleObjects(4, handles, 0, 0) ==
                  kWaitObject0 + i,
              "multi: the answer names the object that signalled");
        check(objects::reset_event(handles[i]),
              "multi: and it can be reset for the next case");
    }

    // Two signalled at once: the lowest index is the answer. Windows reports
    // the lowest-indexed object that was available, and a program waiting on
    // a set of objects relies on the order to know which of its own cases ran.
    check(objects::set_event(handles[2]) && objects::set_event(handles[1]),
          "multi: two events can be signalled");
    check(k32s_WaitForMultipleObjects(4, handles, 0, 0) == kWaitObject0 + 1,
          "multi: the lowest available index answers");
    check(objects::reset_event(handles[1]) && objects::reset_event(handles[2]),
          "multi: and both can be reset");

    // Nothing signalled is a timeout, which is a different answer from a
    // failure and the one a polling loop depends on.
    check(k32s_WaitForMultipleObjects(4, handles, 0, 0) == kWaitTimeout,
          "multi: no object available is a timeout");

    // `WAIT_ALL` needs the whole set at once, and one unsignalled object is
    // enough to make the round fail -- so the signalled ones must not be
    // quietly consumed by the attempt.
    check(objects::set_event(handles[0]) && objects::set_event(handles[1]),
          "multi: two of four can be signalled");
    check(k32s_WaitForMultipleObjects(4, handles, 1, 0) == kWaitTimeout,
          "multi: WAIT_ALL with two of four times out");
    check(objects::reset_event(handles[0]) && objects::reset_event(handles[1]),
          "multi: and the partial round consumed neither");
    check(objects::set_event(handles[0]) && objects::set_event(handles[1]) &&
              objects::set_event(handles[2]) &&
              objects::set_event(handles[3]),
          "multi: all four can be signalled");
    check(k32s_WaitForMultipleObjects(4, handles, 1, 0) == kWaitObject0,
          "multi: WAIT_ALL with all four succeeds");

    // The alertable variant takes one more argument and answers the same
    // questions: this runtime runs no APCs, so there is nothing a wait could
    // be alerted by, and a different status here would be one no program
    // could act on.
    check(k32s_WaitForMultipleObjectsEx(4, handles, 1, 0, 1) == kWaitObject0,
          "multi: the alertable variant agrees when all are available");
    check(k32s_WaitForMultipleObjectsEx(4, handles, 1, 0, 0) == kWaitObject0,
          "multi: and when the request is not alertable");
    check(objects::reset_event(handles[3]),
          "multi: one object reset for the timeout case");
    check(k32s_WaitForMultipleObjectsEx(4, handles, 1, 0, 1) == kWaitTimeout,
          "multi: the alertable variant reports a timeout the same way");
}

void test_mutex_has_an_owner() {
    // A mutex created unowned is available, and taking it makes it owned --
    // which is the property that makes it a mutex rather than an event. A
    // Windows mutex is *recursive*, so the owner taking it again does not
    // block and does not queue: it nests. That is why the checks below count
    // releases against takes instead of treating one release as freeing the
    // mutex -- a runtime that made the mutex non-recursive would deadlock any
    // program using it as a lock inside a call it already held, and one that
    // let a single release free it would let two threads into the critical
    // section at once.
    const std::uint64_t mutex = k32s_CreateMutexW(nullptr, 0, nullptr);
    check(mutex != kInvalidHandle, "mutex: an anonymous mutex is created");

    check(wait_one(mutex, 0) == kWaitObject0, "mutex: an unowned one is free");
    // The owner may take it again without blocking, which is what recursion
    // means. Windows answers this at once rather than queueing the thread
    // behind itself.
    check(wait_one(mutex, 0) == kWaitObject0, "mutex: the owner may re-take it");
    // Two takes outstanding means two releases, so the first release frees
    // nobody and the second frees the mutex. Counting them against each other
    // is the whole of what recursion means here.
    check(k32s_ReleaseMutex(mutex) == 1, "mutex: and release one level");
    check(k32s_ReleaseMutex(mutex) == 1, "mutex: and release the next");
    check(wait_one(mutex, 0) == kWaitObject0, "mutex: which frees it again");
    // Freed means available, and this take is the one that claims it -- so a
    // third release now has nothing to release.
    check(k32s_ReleaseMutex(mutex) == 1, "mutex: and it can be taken back");

    // Releasing a mutex this thread does not hold is `ERROR_NOT_OWNER`, not a
    // generic failure and not a bad handle: the handle is fine and the caller
    // has a bug, and a program that gets this wrong needs to be able to tell.
    check(k32s_ReleaseMutex(mutex) == 0,
          "mutex: releasing a mutex nobody holds fails");
    check(k32_GetLastError() == kErrorNotOwner,
          "mutex: and reports that it is not owned");
    check(k32s_ReleaseMutex(kNotAnObject) == 0,
          "mutex: releasing something that is not a mutex fails");
    check(k32_GetLastError() == kErrorInvalidHandle,
          "mutex: and reports an invalid handle instead");
    // An event is a live object but not a mutex, and the two are told apart
    // by the kind rather than by whether the handle resolves.
    const std::uint64_t event =
        k32s_CreateEventExW(nullptr, nullptr, kCreateEventManualReset, 0);
    check(k32s_ReleaseMutex(event) == 0,
          "mutex: releasing an event is not releasing a mutex");
    check(k32_GetLastError() == kErrorInvalidHandle,
          "mutex: and says the handle is not one");

    // Created owned, the creating thread holds it from the start, and its
    // first release is the one that matches the take it never made.
    const std::uint64_t owned = k32s_CreateMutexW(nullptr, 1, nullptr);
    check(owned != kInvalidHandle, "mutex: one can be created owned");
    check(k32s_ReleaseMutex(owned) == 1, "mutex: and released by its creator");
    check(wait_one(owned, 0) == kWaitObject0, "mutex: which frees it");

    // The `Ex` spelling takes the initial owner as a flag rather than an
    // argument, and the flag has to mean the same thing.
    const std::uint64_t flag = k32s_CreateMutexExW(
        nullptr, nullptr, kCreateMutexInitialOwner, 0x1F0001);
    check(flag != kInvalidHandle, "mutex: the Ex form creates one");
    check(k32s_ReleaseMutex(flag) == 1,
          "mutex: and the initial-owner flag gives it to this thread");
    const std::uint64_t unflagged = k32s_CreateMutexExW(nullptr, nullptr, 0, 0);
    check(wait_one(unflagged, 0) == kWaitObject0,
          "mutex: without the flag it starts free");

    // A named mutex needs the cross-process name namespace, and a fresh
    // anonymous mutex under the name the caller asked for would be a lie the
    // caller cannot see.
    set_last_error(0);
    check(k32s_CreateMutexW(u"Local\\thing", 0, nullptr) == kInvalidHandle,
          "mutex: a named one is refused");
    check(k32_GetLastError() == kErrorNotSupported,
          "mutex: with the name namespace named as the reason");
    check(k32s_OpenMutexA(0x1F0001, 0, "Local\\thing") == kInvalidHandle,
          "mutex: and so is opening one");
}

void test_semaphore_counts() {
    // A semaphore is a count, which is the one thing an event cannot be: ten
    // tokens release ten waiters through an object holding a single bit. The
    // checks below take tokens one at a time and watch the count fall, and
    // then check that the eleventh take fails rather than blocking forever.
    const std::uint64_t sem =
        k32s_CreateSemaphoreW(nullptr, 3, 3, nullptr);
    check(sem != kInvalidHandle, "semaphore: one is created with three tokens");

    for (std::int32_t taken = 1; taken <= 3; ++taken) {
        check(wait_one(sem, 0) == kWaitObject0,
              "semaphore: a token is available while the count lasts");
    }
    check(wait_one(sem, 0) == kWaitTimeout,
          "semaphore: and the fourth take finds the count empty");

    // Releasing puts one back and reports the count from before the release,
    // which is what lets a caller account for what it had.
    std::int32_t previous = -1;
    check(k32s_ReleaseSemaphore(sem, 1, &previous) == 1,
          "semaphore: a release succeeds");
    check(previous == 0, "semaphore: and reports the count before it");
    check(wait_one(sem, 0) == kWaitObject0, "semaphore: which is then takeable");

    // The ceiling is enforced. A program that created a bounded semaphore
    // depends on being told when a release would exceed it rather than on
    // silently getting an unbounded one. Releasing exactly the ceiling is
    // allowed -- the boundary has to work in both directions, and a check
    // written only against an over-release would not notice an off-by-one
    // that refused a legal release.
    set_last_error(0);
    previous = -1;
    check(k32s_ReleaseSemaphore(sem, 3, &previous) == 1,
          "semaphore: a release up to the ceiling is allowed");
    check(previous == 0, "semaphore: and reports the count before it");
    check(k32s_ReleaseSemaphore(sem, 1, &previous) == 0,
          "semaphore: one token past the ceiling fails");
    check(k32_GetLastError() == kErrorInvalidParameter,
          "semaphore: and says the parameter was wrong");
    check(previous == 0,
          "semaphore: and reports no count on failure, since the release "
          "did not happen");

    // Releasing nothing is a request that cannot be satisfied, not a no-op.
    set_last_error(0);
    check(k32s_ReleaseSemaphore(sem, 0, nullptr) == 0,
          "semaphore: releasing nothing fails");
    check(k32_GetLastError() == kErrorInvalidParameter,
          "semaphore: with the same code");

    // A release is refused on a handle that is not a semaphore, even a live
    // one, because the kinds are told apart rather than by whether the handle
    // resolves.
    const std::uint64_t mutex = k32s_CreateMutexW(nullptr, 0, nullptr);
    set_last_error(0);
    check(k32s_ReleaseSemaphore(mutex, 1, nullptr) == 0,
          "semaphore: releasing a mutex is not releasing tokens");
    check(k32_GetLastError() == kErrorInvalidHandle,
          "semaphore: and says the handle is not one");
    set_last_error(0);
    check(k32s_ReleaseSemaphore(kNotAnObject, 1, nullptr) == 0,
          "semaphore: releasing nothing fails on the handle");

    // A semaphore that starts empty is not available, and one that starts
    // full is: the initial count decides whether the wait is satisfied before
    // anything is released.
    const std::uint64_t empty =
        k32s_CreateSemaphoreW(nullptr, 0, 1, nullptr);
    check(wait_one(empty, 0) == kWaitTimeout,
          "semaphore: one created empty is not available");
    check(k32s_ReleaseSemaphore(empty, 1, nullptr) == 1,
          "semaphore: and becomes available when released");

    // The counts the create call accepts are bounded on both sides: a
    // semaphore with no ceiling cannot be created, and neither can one whose
    // initial count is above the ceiling it was given.
    set_last_error(0);
    check(k32s_CreateSemaphoreW(nullptr, 0, 0, nullptr) == kInvalidHandle,
          "semaphore: a ceiling of zero is refused");
    check(k32_GetLastError() == kErrorInvalidParameter,
          "semaphore: with a bad parameter");
    set_last_error(0);
    check(k32s_CreateSemaphoreW(nullptr, 5, 2, nullptr) == kInvalidHandle,
          "semaphore: an initial count above the ceiling is refused");
    check(k32_GetLastError() == kErrorInvalidParameter,
          "semaphore: with the same code");
    set_last_error(0);
    check(k32s_CreateSemaphoreW(nullptr, -1, 4, nullptr) == kInvalidHandle,
          "semaphore: a negative initial count is refused");

    // One token short of the ceiling is the boundary that has to work.
    const std::uint64_t nearly =
        k32s_CreateSemaphoreW(nullptr, 1, 2, nullptr);
    check(nearly != kInvalidHandle, "semaphore: one below the ceiling works");
    check(k32s_ReleaseSemaphore(nearly, 1, nullptr) == 1,
          "semaphore: and can be filled to the ceiling");
    check(k32s_ReleaseSemaphore(nearly, 1, nullptr) == 0,
          "semaphore: and not past it");
}

void test_anon_and_named_agree() {
    // Each `A`/`W` pair is one implementation spelled twice, so the same input
    // has to produce the same answer either way. A pair that disagreed would
    // mean one of them had a second implementation, which is the thing the
    // pairing exists to prevent.
    const std::uint64_t wide =
        k32s_CreateEventExW(nullptr, nullptr, kCreateEventManualReset, 0);
    const std::uint64_t narrow =
        k32s_CreateEventExA(nullptr, nullptr, kCreateEventManualReset, 0);
    check(wide != kInvalidHandle && narrow != kInvalidHandle,
          "pair: both spellings of CreateEventEx create an event");
    check(objects::set_event(wide) && objects::set_event(narrow),
          "pair: and both can be signalled");
    check(wait_one(wide, 0) == wait_one(narrow, 0),
          "pair: both answer a signalled event the same way");
    check(objects::reset_event(wide) && objects::reset_event(narrow),
          "pair: and both can be reset");
    check(wait_one(wide, 0) == wait_one(narrow, 0),
          "pair: and both answer a non-signalled event the same way");

    const std::uint64_t wide_mutex = k32s_CreateMutexW(nullptr, 0, nullptr);
    const std::uint64_t narrow_mutex = k32s_CreateMutexA(nullptr, 0, nullptr);
    check(wide_mutex != kInvalidHandle && narrow_mutex != kInvalidHandle,
          "pair: both spellings of CreateMutex create a mutex");
    check(wait_one(wide_mutex, 0) == wait_one(narrow_mutex, 0),
          "pair: both answer an unowned mutex the same way");
    check(k32s_ReleaseMutex(wide_mutex) == k32s_ReleaseMutex(narrow_mutex),
          "pair: and both are released the same way");

    const std::uint64_t wide_sem = k32s_CreateSemaphoreW(nullptr, 1, 2, nullptr);
    const std::uint64_t narrow_sem =
        k32s_CreateSemaphoreA(nullptr, 1, 2, nullptr);
    check(wide_sem != kInvalidHandle && narrow_sem != kInvalidHandle,
          "pair: both spellings of CreateSemaphore create a semaphore");
    check(wait_one(wide_sem, 0) == wait_one(narrow_sem, 0),
          "pair: both answer a semaphore the same way");
    // The same invalid arguments have to be refused by both spellings, which
    // is what makes the refusal a property of the call rather than of one
    // way of spelling it.
    set_last_error(0);
    const std::uint64_t wide_bad = k32s_CreateSemaphoreW(nullptr, 5, 2, nullptr);
    const std::uint32_t wide_error = k32_GetLastError();
    set_last_error(0);
    const std::uint64_t narrow_bad =
        k32s_CreateSemaphoreA(nullptr, 5, 2, nullptr);
    check(wide_bad == narrow_bad, "pair: both refuse a bad count");
    check(k32_GetLastError() == wide_error,
          "pair: and both report the same error for it");

    // A name is refused by both spellings, and a name the narrow side cannot
    // even convert is refused differently -- as a bad parameter rather than
    // as a missing namespace, because the text was never a name.
    set_last_error(0);
    check(k32s_CreateMutexW(u"Local\\x", 0, nullptr) == kInvalidHandle &&
              k32s_CreateMutexA("Local\\x", 0, nullptr) == kInvalidHandle,
          "pair: both refuse a named mutex");
    set_last_error(0);
    const char bad_name[] = {'L', 'o', 'c', 'a', 'l', static_cast<char>(0xFF),
                             '\\', 'x', '\0'};
    check(k32s_CreateMutexA(bad_name, 0, nullptr) == kInvalidHandle,
          "pair: a name that is not text is refused");
    check(k32_GetLastError() == kErrorInvalidParameter,
          "pair: as a bad parameter rather than as a missing namespace");
    // The empty name is text, so it is refused as a name -- which is the
    // boundary between the two refusals.
    set_last_error(0);
    check(k32s_CreateMutexA("", 0, nullptr) == kInvalidHandle,
          "pair: an empty name is still a name");
    check(k32_GetLastError() == kErrorNotSupported,
          "pair: and is refused as one");
}

void test_signal_and_wait() {
    // Signalling one object and waiting on another, which is the handshake a
    // producer and a consumer use. The flag word has to be the one Windows
    // defines, and anything else is refused before either object is touched.
    const std::uint64_t release =
        k32s_CreateEventExW(nullptr, nullptr, kCreateEventManualReset, 0);
    const std::uint64_t ready =
        k32s_CreateEventExW(nullptr, nullptr, kCreateEventManualReset, 0);

    // The wait half of the call has to have something to find: a handshake
    // is arranged before the call happens, so the target starts signalled.
    // It is a manual-reset event, so the call's wait does not consume the
    // signal and the state is visible after the call too.
    check(objects::set_event(ready),
          "handshake: the wait target starts signalled");
    check(k32s_SignalObjectAndWait(release, ready, 0, 0) == kWaitObject0,
          "handshake: signalling an event releases the waiter");
    check(wait_one(ready, 0) == kWaitObject0,
          "handshake: and the waiting object is signalled afterwards");
    // Reset before the cases below, which wait on a quiet object.
    check(objects::reset_event(ready),
          "handshake: and can be quieted for the cases below");

    set_last_error(0);
    check(k32s_SignalObjectAndWait(release, ready, 0, 1) == kWaitFailed,
          "handshake: an undefined flag word is refused");
    check(k32_GetLastError() == kErrorInvalidParameter,
          "handshake: and says the parameter was wrong");

    // Nothing waiting on the second object is a timeout, not a failure: the
    // signal was delivered and there was simply nobody there.
    const std::uint64_t nobody =
        k32s_CreateEventExW(nullptr, nullptr, kCreateEventManualReset, 0);
    check(k32s_SignalObjectAndWait(release, nobody, 0, 0) == kWaitTimeout,
          "handshake: with nobody waiting the answer is a timeout");
    check(objects::set_event(release),
          "handshake: and the signal was delivered anyway");

    set_last_error(0);
    check(k32s_SignalObjectAndWait(kNotAnObject, ready, 0, 0) == kWaitFailed,
          "handshake: a handle that names nothing fails");
    check(k32_GetLastError() == kErrorInvalidHandle,
          "handshake: as an invalid handle");

    // A mutex is the other object Windows lets this call signal, and
    // signalling it is releasing it -- which only its owner may do.
    const std::uint64_t mutex = k32s_CreateMutexW(nullptr, 1, nullptr);
    set_last_error(0);
    check(k32s_SignalObjectAndWait(mutex, ready, 0, 0) == kWaitTimeout,
          "handshake: signalling a mutex this thread owns releases it");
    check(k32s_ReleaseMutex(mutex) == 0,
          "handshake: and so it is no longer held");
    check(k32_GetLastError() == kErrorNotOwner,
          "handshake: which is what the second release reports");
}

void test_pulse_leaves_nothing_behind() {
    // A pulse sets an event and returns it to non-signalled, so it releases
    // whoever was already waiting and leaves nothing for the next one. The
    // second wait is the assertion: a pulse that only set would answer twice.
    const std::uint64_t event =
        k32s_CreateEventExW(nullptr, nullptr, kCreateEventManualReset, 0);
    check(k32s_PulseEvent(event) == 1, "pulse: an event can be pulsed");
    check(k32_GetLastError() == kErrorSuccess, "pulse: and reports success");
    check(wait_one(event, 0) == kWaitTimeout,
          "pulse: and leaves nothing signalled behind it");

    set_last_error(0);
    check(k32s_PulseEvent(kNotAnObject) == 0,
          "pulse: a handle that names nothing fails");
    check(k32_GetLastError() == kErrorInvalidHandle,
          "pulse: as an invalid handle");
}

void test_sleep_ex_returns_without_running_anything() {
    // `SleepEx` returns zero because it ran no APC, and it slept for the time
    // asked for. A zero-length sleep has to return rather than block, which
    // is the case a program that is polling others depends on.
    const auto before = std::chrono::steady_clock::now();
    check(k32s_SleepEx(0, 0) == 0, "sleep: a zero sleep returns");
    check(elapsed_ms(before) < kPollBudgetMs, "sleep: without sleeping");

    const auto marked = std::chrono::steady_clock::now();
    check(k32s_SleepEx(20, 0) == 0, "sleep: a sleep returns zero");
    const long spent = elapsed_ms(marked);
    check(spent >= 10, "sleep: after waiting about as long as asked");
    check(spent < 2000, "sleep: and not for an unbounded time");

    // The alertable request is honoured the only way it can be here, by
    // behaving as the non-alertable call: there are no APCs to run, so the
    // answer is the same rather than a status nothing can act on.
    const auto alert = std::chrono::steady_clock::now();
    check(k32s_SleepEx(20, 1) == 0,
          "sleep: an alertable sleep returns the same answer");
    check(elapsed_ms(alert) >= 10,
          "sleep: and waited the same time for it");
}

void test_refusals_say_why() {
    // Each refusal below is a facility this runtime does not have, and the
    // assertion is on the error code rather than on the zero: a caller
    // branches on which of these happened, so "returns zero" would be true of
    // a function that failed for the wrong reason.
    set_last_error(0);
    check(k32s_CreateWaitableTimerW(nullptr, 0, nullptr) == kInvalidHandle,
          "refused: a waitable timer is not created");
    check(k32_GetLastError() == kErrorCallNotImplemented,
          "refused: and the reason is that the facility is absent");

    // Arming one is refused for the same reason, and refused rather than
    // accepted-and-ignored: an armed timer that never fires turns every wait
    // on it into a hang the caller cannot detect.
    set_last_error(0);
    const std::int64_t due = -1000000;
    check(k32s_SetWaitableTimer(0, &due, 0, 0, 0) == 0,
          "refused: arming one fails");
    check(k32_GetLastError() == kErrorCallNotImplemented,
          "refused: with the same reason");

    check(k32s_CreateTimerQueue() == kInvalidHandle,
          "refused: a timer queue is not created");
    check(k32s_CreateThreadpoolWait(0, 0, 0) == kInvalidHandle,
          "refused: a threadpool wait is not created");
    check(k32_GetLastError() == kErrorCallNotImplemented,
          "refused: with the same reason");
    // The one refusal in this family that answers an `HRESULT`, which is a
    // signed code where the high bit says failure.
    check(failed(k32s_SetThreadpoolTimerEx(0, 0, 0, 0, 0)),
          "refused: the Ex timer reports a failed HRESULT");
    check(k32s_RegisterWaitForSingleObject(0, 0, 0, 0, 0) == kInvalidHandle,
          "refused: a registered wait is not created");

    // A condition variable would have to release the caller's own lock, and
    // the critical-section and SRW-lock implementations this runtime has are
    // not reachable from this file.
    check(k32s_SleepConditionVariableSRW(0, 0, 0, 0) == 0,
          "refused: sleeping on a condition variable fails");
    check(k32_GetLastError() == kErrorCallNotImplemented,
          "refused: with the facility named as the reason");

    // A deferred release needs an APC queue to deliver through.
    std::int32_t flag = 0;
    check(k32s_SetEventWhenCallbackReturns(&flag, 0) == 0,
          "refused: a deferred release is not queued");
    check(k32_GetLastError() == kErrorCallNotImplemented,
          "refused: with the same reason");

    // The debugger, the event log and the communications port are all absent,
    // and each says so rather than inventing an answer.
    check(k32s_WaitForDebugEvent(nullptr, nullptr, 0) == 0,
          "refused: there is no debug event to wait for");
    check(k32_GetLastError() == kErrorCallNotImplemented,
          "refused: with the facility named as the reason");
    check(k32s_WaitNamedPipeW(u"\\\\.\\pipe\\none", 0) == 0,
          "refused: there is no named pipe to wait for");
    check(k32_GetLastError() == kErrorCallNotImplemented,
          "refused: with the same reason");
    // The console calls answer the way a redirected run answers on Windows:
    // `ERROR_INVALID_HANDLE`, because there is no console to hold them.
    check(k32s_WaitCommEvent(0, 0, nullptr) == 0,
          "refused: there is no comm port behind the handle");
    check(k32_GetLastError() == kErrorInvalidHandle,
          "refused: which is an invalid handle rather than a missing call");
    check(k32s_GenerateConsoleCtrlEvent(0, 0) == 0,
          "refused: a control event has no console to raise");
    check(k32_GetLastError() == kErrorInvalidHandle,
          "refused: and says there is no console");
    // This one answers `INVALID_HANDLE_VALUE` rather than null, because that
    // is what the call documents and a caller testing for it would read a
    // null as a valid zero handle.
    check(k32s_GetConsoleInputWaitHandle() == kInvalidHandleValue,
          "refused: the console wait handle is the invalid one");
    check(k32_GetLastError() == kErrorInvalidHandle,
          "refused: and says there is no console");
}

void test_registration() {
    // The domain contributes its names and nothing else: every entry has a
    // name and an address, and no name appears twice. A duplicate would be
    // two domains claiming one export, which the registry reports rather than
    // resolving quietly.
    ExportList list;
    add_kernel32_sync(list);

    bool addressed = true;
    for (const HostExport& entry : list) {
        if (entry.name.empty() || entry.address == 0) {
            addressed = false;
        }
    }
    check(addressed, "api: every entry has a name and an address");

    bool unique = true;
    for (std::size_t i = 0; i < list.size(); ++i) {
        for (std::size_t k = i + 1; k < list.size(); ++k) {
            if (list[i].name == list[k].name) {
                unique = false;
            }
        }
    }
    check(unique, "api: and no name is contributed twice");

    // The count is the order's, so a name added here without a line in the
    // order -- or dropped from one without the other -- is a mismatch the
    // next agent would otherwise find by accident.
    check(list.size() == 75,
          "api: the synchronization domain contributes seventy-five names");
}

}  // namespace

int main() {
    test_auto_reset_consumes_its_signal();
    test_zero_timeout_is_a_poll();
    test_invalid_handles_fail_the_wait();
    test_multi_object_names_the_object();
    test_mutex_has_an_owner();
    test_semaphore_counts();
    test_anon_and_named_agree();
    test_signal_and_wait();
    test_pulse_leaves_nothing_behind();
    test_sleep_ex_returns_without_running_anything();
    test_refusals_say_why();
    test_registration();

    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks, 0 failures\n", checks);
    return 0;
}
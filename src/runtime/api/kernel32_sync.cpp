// The synchronization family, as kernel32 spells it.
//
// The object table in `runtime/objects.cpp` is the substrate here rather
// than a starting point: a handle this domain hands out is an index into
// that table, so `CloseHandle` -- which is not this file's -- already knows
// how to release one, and a handle from here cannot be confused with a file
// descriptor because the two namespaces do not overlap. What this file adds
// is the part of the Windows contract the table does not carry: which of the
// `WAIT_` answers a wait gives, that `WAIT_OBJECT_0 + i` names *which* of
// several objects was the one that released the wait, an owner for a mutex,
// and a count for a semaphore.
//
// **The table has no mutex or semaphore of its own.** `objects.h` names
// `Kind::Mutex` and `Kind::Semaphore`, and `wait_one` refuses anything that
// is not `Kind::Event` -- so a mutex here is an *auto-reset event* plus a
// record of who holds it, and a semaphore is an event that stands for "at
// least one token is available" plus the count of tokens. The event is what
// makes the object waitable and what `CloseHandle` releases; the record is
// what makes it a mutex or a semaphore rather than a one-shot wakeup. That
// split is why a released mutex re-signals its event while a released
// semaphore re-signals it only when the count crosses zero, and it is why
// this file keeps a table of its own keyed by handle.
//
// **What is refused, and why.** Each refusal below is a facility this
// runtime does not have rather than a behaviour that was hard to write, and
// each names the missing thing in a comment at the refusal:
//
//   * Anything named. `OpenEvent`, `OpenMutex`, `OpenSemaphore`,
//     `OpenWaitableTimer` and the named forms of the `Create` family need a
//     cross-process name namespace to look a name up in. There is none, so
//     they answer `ERROR_NOT_SUPPORTED` rather than hand back an anonymous
//     object under the name the caller asked for. This matches what
//     `CreateEvent` already does in `winabi.cpp` for the same reason.
//   * The waitable timers, the timer queues and the thread pool. Arming any
//     of them means a thread of this runtime has to exist to fire later, and
//     this runtime has no thread to lend: an object that would be armed and
//     then never signalled turns every wait on it into a hang, which is a
//     worse answer than a refusal a caller can branch on.
//   * `SleepConditionVariable*`, which would have to block on the guest's
//     own `CRITICAL_SECTION` or `SRWLOCK` state, and the
//     `*WhenCallbackReturns` family, which delivers an APC to the calling
//     thread. Neither the lock nor an APC queue is reachable from here.
//   * The console, debug, event-log, UMS and communications names, for the
//     same absence of a console, a debugger, a log, a UMS thread or a comm
//     port. These answer the way `api/console.cpp` answers a redirected run.
//
// **`WAIT_ABANDONED` is never returned.** Reporting it needs to know that the
// thread holding a mutex died, and this runtime keeps no registry of guest
// threads and gets no notification when one ends -- so a wait on a mutex
// whose owner went away blocks, where Windows would hand the lock to the
// next waiter and say so. Returning the constant without the fact behind it
// would tell a program its lock had been stolen when nothing had happened.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/objects.h"
#include "occ/runtime/winabi.h"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <time.h>

namespace occ::runtime::winabi {
namespace {

// --------------------------------------------------------------- the answers
//
// The `WAIT_` statuses, named as the numbers they are on the wire because a
// guest compares against those numbers and a reader should not have to look
// them up. `WAIT_ABANDONED` is named here so that its absence below reads as
// a decision rather than as an oversight.
constexpr std::uint32_t kWaitObject0 = 0x00000000u;
constexpr std::uint32_t kWaitTimeout = 0x00000102u;
constexpr std::uint32_t kWaitFailed = 0xFFFFFFFFu;

// `MAXIMUM_WAIT_OBJECTS`. A multi-object wait holds a bitmask of the objects
// it has taken, so that a wait which turns out not to be satisfied can hand
// every one of them back, and a bitmask is what bounds it at 64.
constexpr std::uint32_t kMaxWaitObjects = 64;

// `CREATE_EVENT_MANUAL_RESET` and `CREATE_MUTEX_INITIAL_OWNER`, the two flag
// words the `Ex` creators take.
constexpr std::uint32_t kCreateEventManualReset = 0x00000001u;
constexpr std::uint32_t kCreateMutexInitialOwner = 0x00000001u;

// `ERROR_NOT_OWNER`, which `ReleaseMutex` reports for a mutex this thread
// does not hold. It is the one code this family needs that `api_common.h`
// does not carry, so it is named here rather than written as a bare literal
// at the one place that uses it.
constexpr std::uint32_t kErrorNotOwner = 288;

// How long a multi-object wait sleeps between rounds of polling its
// objects. The object table waits on one object; a wait over several has to
// ask each in turn, so this interval is the resolution at which a signal
// arriving between two questions is noticed. One millisecond is short enough
// that a program polling in a loop behaves as it does on Windows and long
// enough that the loop is not a spin.
constexpr std::uint32_t kPollIntervalMs = 1;

// ------------------------------------------------------------------ a thread
//
// A mutex has to know whether the thread releasing it is the thread that
// took it, and this runtime has no guest thread registry to ask. A token
// minted once per host thread is the identity that question needs: two calls
// from one thread compare equal, and calls from two threads do not, which is
// the whole of what `ReleaseMutex` checks.
std::uint64_t next_thread_token() noexcept {
    static std::atomic<std::uint64_t> counter{1};
    return counter.fetch_add(1, std::memory_order_relaxed);
}

std::uint64_t current_thread_token() noexcept {
    static thread_local const std::uint64_t token = next_thread_token();
    return token;
}

// ------------------------------------------------------- what a handle means
//
// The state the object table cannot hold. A mutex needs an owner because a
// wait on a mutex held by somebody else blocks, and an event cannot express
// that: it is signalled or it is not, with no question of who. A semaphore
// needs a count because ten tokens release ten waiters and an event releases
// one.
enum class SyncKind : std::uint8_t {
    Mutex,
    Semaphore,
};

struct SyncRecord {
    std::uint64_t handle = kInvalidHandle;
    SyncKind kind = SyncKind::Mutex;
    // The mutex owner, and how many times it has been taken. A mutex is
    // recursive, so a second take by the owner is not a second wait -- it is
    // a nesting count that `ReleaseMutex` unwinds one level at a time.
    std::uint64_t owner = 0;
    std::uint32_t recursion = 0;
    // The semaphore's available tokens and the ceiling `ReleaseSemaphore`
    // refuses to exceed. The ceiling is remembered because Windows reports a
    // release past it as an error, and a program that asked for a bounded
    // semaphore depends on being told.
    std::int64_t count = 0;
    std::int64_t maximum = 0;
};

// The records, under one lock.
//
// The lock is this file's own rather than the object table's, and the two
// never hold each other at the same time: every path that calls into the
// table does so with this lock released, and every path that changes a
// record releases this lock before signalling. A path that held both, in
// one order or the other, would be a deadlock waiting for the first caller
// to find it.
//
// A record can outlive its object, because `CloseHandle` is `winabi.cpp`'s
// and nothing tells this file when it runs. A record whose handle the table
// no longer holds is dropped when it is next looked up, rather than being
// answered for an object that is gone.
std::mutex g_sync_lock;
std::vector<SyncRecord> g_sync_records;

// The record for a handle that is still a live object. A record whose
// handle the table has released is erased here, which is the whole of the
// staleness check and the reason a closed mutex reports `WAIT_FAILED`
// instead of answering as a mutex nobody holds.
//
// Callers hold `g_sync_lock`. The record is found by index rather than by a
// pointer so that it can be erased from inside the same lookup that rejected
// it -- handing back a pointer and then erasing it would leave the caller
// holding one into freed storage.
[[nodiscard]] SyncRecord* live_locked(std::uint64_t handle) noexcept {
    const std::size_t index = [&] {
        for (std::size_t i = 0; i < g_sync_records.size(); ++i) {
            if (g_sync_records[i].handle == handle) {
                return i;
            }
        }
        return g_sync_records.size();
    }();
    if (index == g_sync_records.size()) {
        return nullptr;
    }
    if (objects::is_object(handle)) {
        return &g_sync_records[index];
    }
    g_sync_records.erase(g_sync_records.begin() +
                         static_cast<std::ptrdiff_t>(index));
    return nullptr;
}

// Whether `handle` names a mutex or a semaphore this file made, as opposed
// to a plain event. A caller that only needs to know the object is
// waitable does not need this.
[[nodiscard]] bool is_synchronised(std::uint64_t handle) noexcept {
    const std::lock_guard<std::mutex> guard(g_sync_lock);
    return live_locked(handle) != nullptr;
}

// The three outcomes a take can have, which are the three a wait reports.
enum class Take : std::uint8_t {
    Signalled,
    TimedOut,
    NoSuchObject,
};

// How long is left before `deadline`, as the wait calls count it. Zero means
// the deadline has passed, which is the answer a zero-timeout poll wants.
[[nodiscard]] std::uint32_t remaining_ms(
    const std::chrono::steady_clock::time_point& deadline) noexcept {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
        return 0;
    }
    const auto left =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now)
            .count();
    if (left <= 0) {
        return 0;
    }
    constexpr std::int64_t kMaxMs = 0x7FFFFFFF;
    return static_cast<std::uint32_t>(left > kMaxMs ? kMaxMs : left);
}

// One object, taken if it is available.
//
// For a plain event this is the table's own wait and the whole answer. For a
// mutex and a semaphore it is the table's wait underneath the record: the
// event's signal is what releases a blocked thread, and the record is what
// the thread does once it is awake -- take ownership, or take a token.
//
// This lock is dropped before the blocking wait and taken again afterwards,
// because the thread that will make this object available is a different
// thread and it needs the same lock to do it.
[[nodiscard]] Take take(std::uint64_t handle,
                        std::uint32_t timeout_ms) noexcept {
    const bool forever = timeout_ms == objects::kInfinite;
    // The deadline is computed once. A wait that recomputed it after every
    // wakeup would extend itself by the time it had already spent, and a
    // program that asked for a second would get as many as it was woken.
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);

    for (;;) {
        bool resignal = false;
        {
            const std::lock_guard<std::mutex> guard(g_sync_lock);
            SyncRecord* const record = live_locked(handle);
            if (record != nullptr) {
                if (record->kind == SyncKind::Mutex) {
                    if (record->owner == current_thread_token() &&
                        record->recursion != 0) {
                        // A recursive take by the owner is not a wait. The
                        // mutex is already held, so there is nothing to block
                        // for, and the count `ReleaseMutex` unwinds goes up.
                        ++record->recursion;
                        return Take::Signalled;
                    }
                } else if (record->count > 0) {
                    // A token is available without touching the event at
                    // all. Signalling here would leave a signal on an object
                    // nobody is waiting for, which the next waiter would
                    // consume and find nothing to take.
                    --record->count;
                    return Take::Signalled;
                }
            }
        }

        const std::uint32_t slice =
            forever ? objects::kInfinite : remaining_ms(deadline);
        const objects::WaitOutcome outcome = objects::wait_one(handle, slice);

        if (outcome == objects::WaitOutcome::NoSuchObject) {
            return Take::NoSuchObject;
        }
        if (outcome == objects::WaitOutcome::TimedOut) {
            return Take::TimedOut;
        }

        {
            const std::lock_guard<std::mutex> guard(g_sync_lock);
            SyncRecord* const record = live_locked(handle);
            if (record == nullptr) {
                // A plain event: the table's wait already consumed whatever
                // the wakeup was, and there is nothing to add.
                return Take::Signalled;
            }
            if (record->kind == SyncKind::Mutex) {
                // The signal was this thread's, because an auto-reset event
                // gives it to exactly one waiter. Claim it.
                record->owner = current_thread_token();
                record->recursion = 1;
                return Take::Signalled;
            }
            // A semaphore's event wakes every thread it touched but gives
            // the signal to one of them, so the token count -- not the
            // wakeup -- decides who proceeds. A token still here after this
            // one has been taken has to re-signal, or the waiter behind this
            // one would sleep through a semaphore that has something in it.
            if (record->count > 0) {
                --record->count;
                resignal = record->count > 0;
                if (!resignal) {
                    return Take::Signalled;
                }
            }
            // A wakeup with no token behind it is a stale signal left on the
            // event by a release another thread's take already spent, or an
            // event that was signalled for a reason of its own. Either way
            // the count is the truth and asking again is correct.
        }
        // Signalled with the lock released: `SetEvent` takes the object
        // table's own lock, and holding both at once is the deadlock the
        // comment on `g_sync_lock` says this file does not have.
        if (resignal) {
            (void)objects::set_event(handle);
        }
        if (!forever && remaining_ms(deadline) == 0) {
            return Take::TimedOut;
        }
    }
}

// Hands back what `take` took, which is what a wait over several objects
// does with the ones it took before it learned it could not be satisfied.
//
// The names matter: for an event this is `SetEvent`, for a mutex it is a
// release by the owner, and for a semaphore it is one token back. Anything
// else would leave the object in a state no program asked for.
void put_back(std::uint64_t handle) noexcept {
    bool signal = false;
    {
        const std::lock_guard<std::mutex> guard(g_sync_lock);
        SyncRecord* const record = live_locked(handle);
        if (record == nullptr) {
            // A plain event, which `take` found signalled and the table's
            // wait left non-signalled if it was auto-reset.
            signal = true;
        } else if (record->kind == SyncKind::Mutex) {
            if (record->owner != current_thread_token() ||
                record->recursion == 0) {
                // Not ours to release. Reporting this as handed back would
                // be a claim about a lock this thread does not hold.
                return;
            }
            record->recursion -= 1;
            if (record->recursion == 0) {
                record->owner = 0;
                signal = true;
            }
        } else {
            ++record->count;
            signal = record->count == 1;
        }
    }
    if (signal) {
        (void)objects::set_event(handle);
    }
}

// Hands back everything a round of a multi-object wait took, which is what
// a wait does with the objects it took before it learned that the round
// could not be satisfied.
void release_round(const std::uint64_t* handles, std::uint64_t held,
                   std::uint32_t count) noexcept {
    for (std::uint32_t i = 0; i < count; ++i) {
        if ((held & (std::uint64_t(1) << i)) != 0) {
            put_back(handles[i]);
        }
    }
}

// Creates a semaphore, which is the one object whose creation validates its
// arguments rather than only its name: `lMaximumCount` of zero has no
// meaning, and an initial count above the ceiling is a request for a
// semaphore that could never be brought into existence.
[[nodiscard]] std::uint64_t create_semaphore(std::int32_t initial_count,
                                              std::int32_t maximum_count) noexcept {
    if (maximum_count <= 0 || initial_count < 0 ||
        initial_count > maximum_count) {
        set_last_error(kErrorInvalidParameter);
        return kInvalidHandle;
    }
    const std::int64_t tokens = static_cast<std::int64_t>(initial_count);
    // The event stands for "at least one token", so it starts signalled
    // exactly when the semaphore starts non-empty.
    const std::uint64_t handle = objects::create_event(false, tokens > 0);
    if (handle == kInvalidHandle) {
        set_last_error(kErrorNotEnoughMemory);
        return kInvalidHandle;
    }
    const std::lock_guard<std::mutex> guard(g_sync_lock);
    SyncRecord record;
    record.handle = handle;
    record.kind = SyncKind::Semaphore;
    record.count = tokens;
    record.maximum = static_cast<std::int64_t>(maximum_count);
    g_sync_records.push_back(record);
    set_last_error(kErrorSuccess);
    return handle;
}

// Creates a mutex. The object is an auto-reset event -- one waiter at a time
// -- and the record beside it says who holds it, which is what makes
// `ReleaseMutex` answerable by a thread that did not take it.
//
// `initial_owner` is why the event starts signalled when nobody holds it: a
// mutex nobody owns is available, and one this thread owns is not.
[[nodiscard]] std::uint64_t create_mutex(std::int32_t initial_owner) noexcept {
    const bool owned = initial_owner != 0;
    const std::uint64_t handle = objects::create_event(false, !owned);
    if (handle == kInvalidHandle) {
        set_last_error(kErrorNotEnoughMemory);
        return kInvalidHandle;
    }
    const std::lock_guard<std::mutex> guard(g_sync_lock);
    SyncRecord record;
    record.handle = handle;
    record.kind = SyncKind::Mutex;
    record.owner = owned ? current_thread_token() : 0;
    record.recursion = owned ? 1u : 0u;
    g_sync_records.push_back(record);
    set_last_error(kErrorSuccess);
    return handle;
}

// -------------------------------------------------------------- text lengths
//
// `narrow_in` takes a view, and a guest's name is a counted string in the
// guest's memory rather than a view. This measures it first.
[[nodiscard]] std::size_t measure(const char* text) noexcept {
    if (text == nullptr) {
        return 0;
    }
    std::size_t length = 0;
    while (text[length] != '\0') {
        ++length;
    }
    return length;
}

// An `A` entry point's name, converted for the `W` one that carries the
// decision. A null name is an anonymous object on Windows and has to stay
// one, so the null check comes before the conversion rather than after it.
[[nodiscard]] bool narrow_name(const char* name,
                              std::u16string& wide) noexcept {
    if (name == nullptr) {
        return true;
    }
    return narrow_in(std::string_view(name, measure(name)), wide).converted;
}

// -------------------------------------------------------------- refusals
//
// One refusal per facility. `ERROR_CALL_NOT_IMPLEMENTED` is the code for a
// facility this runtime does not have; `ERROR_NOT_SUPPORTED` is for one it
// has but will not provide, which for this family is the name namespace and
// nothing else.
[[nodiscard]] std::int32_t no_facility() noexcept {
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

[[nodiscard]] std::uint64_t no_facility_handle() noexcept {
    set_last_error(kErrorCallNotImplemented);
    return kInvalidHandle;
}

[[nodiscard]] std::uint64_t no_named_object() noexcept {
    set_last_error(kErrorNotSupported);
    return kInvalidHandle;
}

void sleep_ms(std::uint32_t ms) noexcept {
    if (ms == 0) {
        return;
    }
    timespec request;
    request.tv_sec = static_cast<time_t>(ms / 1000u);
    request.tv_nsec = static_cast<long>(ms % 1000u) * 1000000L;
    while (::nanosleep(&request, &request) < 0) {
        // A signal that interrupted the wait consumed part of it, and the
        // guest asked for the whole, so the remainder is resumed.
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// Waiting
// ---------------------------------------------------------------------------
//
// The single-object wait is `winabi.cpp`'s and not this file's; it maps the
// table's outcome onto the same statuses this file does, so a program that
// waits through either entry point sees the same answers. What is here is
// the multi-object wait, whose defining property is that `WAIT_OBJECT_0 + i`
// says *which* object released it -- an answer that cannot be reduced to a
// yes or a no, and the reason this entry point exists separately.

extern "C" __attribute__((ms_abi)) std::uint32_t k32s_WaitForMultipleObjects(
    std::uint32_t count, const std::uint64_t* handles, std::int32_t wait_all,
    std::uint32_t milliseconds) noexcept {
    if (handles == nullptr || count == 0 || count > kMaxWaitObjects) {
        // Windows refuses a wait over no objects and over more than
        // `MAXIMUM_WAIT_OBJECTS`, and neither refusal is a timeout.
        set_last_error(kErrorInvalidParameter);
        return kWaitFailed;
    }

    // Every handle is checked before any object is taken, because a wait
    // that found a bad handle half way through would have to give back the
    // objects it had already taken, and Windows does not report a partial
    // set as the wait it was asked for.
    for (std::uint32_t i = 0; i < count; ++i) {
        if (!objects::is_object(handles[i])) {
            set_last_error(kErrorInvalidHandle);
            return kWaitFailed;
        }
    }

    if (count == 1) {
        // One object is the single-object case and is answered by the
        // blocking wait rather than by a poll, so a caller waiting on one
        // object is not subject to the polling interval below.
        switch (take(handles[0], milliseconds)) {
        case Take::Signalled:
            return kWaitObject0;
        case Take::TimedOut:
            return kWaitTimeout;
        case Take::NoSuchObject:
            break;
        }
        set_last_error(kErrorInvalidHandle);
        return kWaitFailed;
    }

    const bool all = wait_all != 0;
    const bool forever = milliseconds == objects::kInfinite;
    // The deadline is computed once, for the reason `take` gives.
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(milliseconds);
    const std::uint64_t every =
        (std::uint64_t(1) << count) - std::uint64_t(1);

    for (;;) {
        // What this round has taken. It starts empty every time: an
        // any-object wait keeps only the object that released it, and an
        // all-object wait has to hold the whole set simultaneously, so
        // neither has a reason to carry a partial round into the next one.
        std::uint64_t held = 0;

        for (std::uint32_t i = 0; i < count; ++i) {
            const std::uint64_t bit = std::uint64_t(1) << i;
            const Take outcome = take(handles[i], 0);
            if (outcome == Take::NoSuchObject) {
                // Closed underneath the wait, which a program can do to
                // itself. Whatever this round took goes back first.
                release_round(handles, held, count);
                set_last_error(kErrorInvalidHandle);
                return kWaitFailed;
            }
            if (outcome == Take::TimedOut) {
                if (!all) {
                    // This object is not the one that releases an
                    // any-object wait, and the wait answers for the lowest
                    // index that *is* -- so a non-signalled object is not the
                    // end of the scan, it is one object that was not
                    // available. The scan continues.
                    continue;
                }
                // `WAIT_ALL` has to hold every object at once, so a partial
                // round is given back whole rather than kept as progress
                // towards a set that was never simultaneously available.
                release_round(handles, held, count);
                break;
            }
            held |= bit;
            if (!all) {
                // Any one object releases the wait, and the answer names it.
                // Because the scan is in ascending order this is the lowest
                // index that was available, which is the index Windows
                // answers with.
                return kWaitObject0 + i;
            }
        }

        if (all && held == every) {
            return kWaitObject0;
        }

        if (!forever && remaining_ms(deadline) == 0) {
            // A zero timeout is a poll: the round above has already asked
            // every object, so the answer is the timeout without having slept
            // at all.
            return kWaitTimeout;
        }
        sleep_ms(kPollIntervalMs);
    }
}

// The alertable variant. This runtime delivers no asynchronous procedure
// calls, so there is nothing a wait could be alerted by, and a caller that
// asked for alertable waiting gets the same wait. The alternative -- an
// answer of `WAIT_IO_COMPLETION` for an APC this runtime cannot run -- would
// be a status no program could act on.
extern "C" __attribute__((ms_abi)) std::uint32_t k32s_WaitForMultipleObjectsEx(
    std::uint32_t count, const std::uint64_t* handles, std::int32_t wait_all,
    std::uint32_t milliseconds, std::int32_t alertable) noexcept {
    (void)alertable;
    return k32s_WaitForMultipleObjects(count, handles, wait_all, milliseconds);
}

// `SleepEx` with no APCs to run is `Sleep`: it returns zero because nothing
// was executed, and an alertable request is honoured the only way it can be,
// by behaving as the non-alertable call.
extern "C" __attribute__((ms_abi)) std::uint32_t k32s_SleepEx(
    std::uint32_t milliseconds, std::int32_t alertable) noexcept {
    (void)alertable;
    sleep_ms(milliseconds);
    return 0;
}

// Signal one object, then wait on another, without letting another thread
// take the second between the two halves. `flags` must name
// `SIGNAL_OBJECT_0`, which is zero and the only object Windows defines here.
extern "C" __attribute__((ms_abi)) std::uint32_t k32s_SignalObjectAndWait(
    std::uint64_t signal_object, std::uint64_t wait_object,
    std::uint32_t milliseconds, std::uint32_t flags) noexcept {
    if (flags != 0) {
        set_last_error(kErrorInvalidParameter);
        return kWaitFailed;
    }
    if (!objects::is_object(signal_object) ||
        !objects::is_object(wait_object)) {
        set_last_error(kErrorInvalidHandle);
        return kWaitFailed;
    }

    {
        const std::lock_guard<std::mutex> guard(g_sync_lock);
        SyncRecord* const record = live_locked(signal_object);
        if (record != nullptr) {
            if (record->kind == SyncKind::Mutex) {
                // Signalling a mutex is releasing it, which only its owner
                // may do.
                if (record->owner != current_thread_token() ||
                    record->recursion == 0) {
                    set_last_error(kErrorNotOwner);
                    return kWaitFailed;
                }
                record->recursion -= 1;
                if (record->recursion == 0) {
                    record->owner = 0;
                }
            } else {
                if (record->count >= record->maximum) {
                    set_last_error(kErrorInvalidParameter);
                    return kWaitFailed;
                }
                ++record->count;
            }
        }
    }
    // Signalled with the lock released, for the reason `put_back` gives. An
    // object with no record is an event, and signalling an event is
    // `SetEvent`.
    if (!objects::set_event(signal_object)) {
        // Not an event and not one of this file's synchronised objects, so
        // there was nothing to signal. A semaphore whose count rose above
        // zero is already signalled by construction; a mutex that went free
        // likewise, so reaching here means the handle named neither.
        if (!is_synchronised(signal_object)) {
            set_last_error(kErrorInvalidHandle);
            return kWaitFailed;
        }
    }

    switch (take(wait_object, milliseconds)) {
    case Take::Signalled:
        return kWaitObject0;
    case Take::TimedOut:
        return kWaitTimeout;
    case Take::NoSuchObject:
        break;
    }
    set_last_error(kErrorInvalidHandle);
    return kWaitFailed;
}

// Set an event and return it to non-signalled, which releases the threads
// already waiting on it and leaves nothing behind for the next one. Windows
// documents this as unreliable for that purpose and this implements only the
// documented state transition -- set, then reset -- with no claim about
// which waiter observes it.
extern "C" __attribute__((ms_abi)) std::int32_t k32s_PulseEvent(
    std::uint64_t handle) noexcept {
    if (!objects::set_event(handle)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    (void)objects::reset_event(handle);
    set_last_error(kErrorSuccess);
    return 1;
}

// ---------------------------------------------------------------------------
// Creating the objects
// ---------------------------------------------------------------------------
//
// An access mask is accepted and ignored throughout this section rather than
// refused: there is no second process to keep an object from and no handle to
// inherit, so the mask has nothing to select between, and refusing it would
// fail a call whose every other requirement is satisfiable here.

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateEventExW(
    void* attributes, const char16_t* name, std::uint32_t flags,
    std::uint32_t access) noexcept {
    (void)attributes;
    (void)access;
    if (name != nullptr) {
        return no_named_object();
    }
    const bool manual_reset = (flags & kCreateEventManualReset) != 0;
    // Created non-signalled: `CreateEventEx` has no initial-state argument,
    // so an event from it is always a wait that has not been satisfied yet.
    const std::uint64_t handle = objects::create_event(manual_reset, false);
    if (handle == kInvalidHandle) {
        set_last_error(kErrorNotEnoughMemory);
        return kInvalidHandle;
    }
    set_last_error(kErrorSuccess);
    return handle;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateEventExA(
    void* attributes, const char* name, std::uint32_t flags,
    std::uint32_t access) noexcept {
    if (name != nullptr) {
        std::u16string wide;
        if (!narrow_name(name, wide)) {
            set_last_error(kErrorInvalidParameter);
            return kInvalidHandle;
        }
        return no_named_object();
    }
    return k32s_CreateEventExW(attributes, nullptr, flags, access);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateMutexW(
    const char16_t* name, std::int32_t initial_owner,
    void* attributes) noexcept {
    (void)attributes;
    if (name != nullptr) {
        return no_named_object();
    }
    return create_mutex(initial_owner);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateMutexA(
    const char* name, std::int32_t initial_owner, void* attributes) noexcept {
    (void)attributes;
    if (name != nullptr) {
        std::u16string wide;
        if (!narrow_name(name, wide)) {
            set_last_error(kErrorInvalidParameter);
            return kInvalidHandle;
        }
        return no_named_object();
    }
    return create_mutex(initial_owner);
}

// The `Ex` form takes the initial owner as a flag word instead of an
// argument, so it is the same mutex with the bit read.
extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateMutexExW(
    void* attributes, const char16_t* name, std::uint32_t flags,
    std::uint32_t access) noexcept {
    (void)access;
    const std::int32_t initial_owner =
        (flags & kCreateMutexInitialOwner) != 0 ? 1 : 0;
    return k32s_CreateMutexW(name, initial_owner, attributes);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateMutexExA(
    void* attributes, const char* name, std::uint32_t flags,
    std::uint32_t access) noexcept {
    (void)access;
    const std::int32_t initial_owner =
        (flags & kCreateMutexInitialOwner) != 0 ? 1 : 0;
    return k32s_CreateMutexA(name, initial_owner, attributes);
}

// Release a mutex this thread holds. A mutex this thread does not hold is
// `ERROR_NOT_OWNER` rather than a generic failure, because a program that
// gets this wrong has a bug the code distinguishes from a bad handle.
extern "C" __attribute__((ms_abi)) std::int32_t k32s_ReleaseMutex(
    std::uint64_t handle) noexcept {
    bool signal = false;
    {
        const std::lock_guard<std::mutex> guard(g_sync_lock);
        SyncRecord* const record = live_locked(handle);
        if (record == nullptr || record->kind != SyncKind::Mutex) {
            set_last_error(kErrorInvalidHandle);
            return 0;
        }
        if (record->owner != current_thread_token() || record->recursion == 0) {
            set_last_error(kErrorNotOwner);
            return 0;
        }
        record->recursion -= 1;
        if (record->recursion == 0) {
            record->owner = 0;
            signal = true;
        }
    }
    // Signalled with the lock released, for the reason `put_back` gives.
    if (signal) {
        (void)objects::set_event(handle);
    }
    set_last_error(kErrorSuccess);
    return 1;
}

// A semaphore is a count. The event underneath stands for "at least one
// token", so a release that takes the count from zero to one has to signal
// and a release that does not has nothing to wake -- which is what lets ten
// tokens release ten waiters through an object that holds one bit.
extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateSemaphoreW(
    void* attributes, std::int32_t initial_count, std::int32_t maximum_count,
    const char16_t* name) noexcept {
    (void)attributes;
    if (name != nullptr) {
        return no_named_object();
    }
    return create_semaphore(initial_count, maximum_count);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateSemaphoreA(
    void* attributes, std::int32_t initial_count, std::int32_t maximum_count,
    const char* name) noexcept {
    (void)attributes;
    if (name != nullptr) {
        std::u16string wide;
        if (!narrow_name(name, wide)) {
            set_last_error(kErrorInvalidParameter);
            return kInvalidHandle;
        }
        return no_named_object();
    }
    return create_semaphore(initial_count, maximum_count);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateSemaphoreExW(
    void* attributes, const char16_t* name, std::uint32_t flags,
    std::uint32_t access, std::int32_t initial_count,
    std::int32_t maximum_count) noexcept {
    (void)flags;
    (void)access;
    return k32s_CreateSemaphoreW(attributes, initial_count, maximum_count,
                                 name);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateSemaphoreExA(
    void* attributes, const char* name, std::uint32_t flags,
    std::uint32_t access, std::int32_t initial_count,
    std::int32_t maximum_count) noexcept {
    (void)flags;
    (void)access;
    return k32s_CreateSemaphoreA(attributes, initial_count, maximum_count,
                                 name);
}

// Add tokens. Windows refuses a release that would pass the ceiling the
// semaphore was created with, and a program that asked for a bounded
// semaphore depends on being told rather than on silently getting an
// unbounded one.
extern "C" __attribute__((ms_abi)) std::int32_t k32s_ReleaseSemaphore(
    std::uint64_t handle, std::int32_t release_count,
    std::int32_t* previous_count) noexcept {
    if (previous_count != nullptr) {
        *previous_count = 0;
    }
    if (release_count <= 0) {
        // Releasing nothing is not a no-op on Windows; it is a request that
        // cannot be satisfied, and is reported as one.
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    bool signal = false;
    {
        const std::lock_guard<std::mutex> guard(g_sync_lock);
        SyncRecord* const record = live_locked(handle);
        if (record == nullptr || record->kind != SyncKind::Semaphore) {
            set_last_error(kErrorInvalidHandle);
            return 0;
        }
        const std::int64_t released = static_cast<std::int64_t>(release_count);
        if (record->count + released > record->maximum) {
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
        if (previous_count != nullptr) {
            *previous_count = static_cast<std::int32_t>(record->count);
        }
        const bool was_empty = record->count == 0;
        record->count += released;
        signal = was_empty;
    }
    if (signal) {
        (void)objects::set_event(handle);
    }
    set_last_error(kErrorSuccess);
    return 1;
}

// ---------------------------------------------------------------------------
// The name namespace, which this runtime does not have
// ---------------------------------------------------------------------------
//
// Each of these looks a name up in a namespace shared between processes.
// There is none: a handle here is an index into one process's table and
// nothing outside this process can name it. Handing back a fresh anonymous
// object would be worse than the refusal, because the caller would believe
// it had found an object somebody else had created.

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_OpenEventW(
    std::uint32_t access, std::int32_t inherit,
    const char16_t* name) noexcept {
    (void)access;
    (void)inherit;
    (void)name;
    return no_named_object();
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_OpenEventA(
    std::uint32_t access, std::int32_t inherit, const char* name) noexcept {
    (void)access;
    (void)inherit;
    (void)name;
    return no_named_object();
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_OpenMutexW(
    std::uint32_t access, std::int32_t inherit,
    const char16_t* name) noexcept {
    (void)access;
    (void)inherit;
    (void)name;
    return no_named_object();
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_OpenMutexA(
    std::uint32_t access, std::int32_t inherit, const char* name) noexcept {
    (void)access;
    (void)inherit;
    (void)name;
    return no_named_object();
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_OpenSemaphoreW(
    std::uint32_t access, std::int32_t inherit,
    const char16_t* name) noexcept {
    (void)access;
    (void)inherit;
    (void)name;
    return no_named_object();
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_OpenSemaphoreA(
    std::uint32_t access, std::int32_t inherit, const char* name) noexcept {
    (void)access;
    (void)inherit;
    (void)name;
    return no_named_object();
}

// ---------------------------------------------------------------------------
// The waitable timers
// ---------------------------------------------------------------------------
//
// A waitable timer is an event that becomes signalled when its due time
// arrives. Something has to notice the due time passing, and the only thing
// that could is a thread of this runtime waiting on a clock. There is none,
// and an armed timer that never fires is the worst of the available
// answers: the object looks like a synchronization object, so a program waits
// on it and the wait never returns. A refusal the caller can branch on is
// strictly better than a hang it cannot detect.

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateWaitableTimerW(
    void* attributes, std::int32_t manual_reset,
    const char16_t* name) noexcept {
    (void)attributes;
    (void)manual_reset;
    (void)name;
    return no_facility_handle();
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateWaitableTimerA(
    void* attributes, std::int32_t manual_reset, const char* name) noexcept {
    (void)attributes;
    (void)manual_reset;
    (void)name;
    return no_facility_handle();
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateWaitableTimerExW(
    void* attributes, const char16_t* name, std::uint32_t flags,
    std::uint32_t access) noexcept {
    (void)attributes;
    (void)name;
    (void)flags;
    (void)access;
    return no_facility_handle();
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateWaitableTimerExA(
    void* attributes, const char* name, std::uint32_t flags,
    std::uint32_t access) noexcept {
    (void)attributes;
    (void)name;
    (void)flags;
    (void)access;
    return no_facility_handle();
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32s_SetWaitableTimer(
    std::uint64_t handle, const std::int64_t* due, std::int32_t period,
    std::int32_t resume, std::uint64_t completion) noexcept {
    (void)handle;
    (void)due;
    (void)period;
    (void)resume;
    (void)completion;
    return static_cast<std::uint32_t>(no_facility());
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32s_SetWaitableTimerEx(
    std::uint64_t handle, const std::int64_t* due, std::int32_t period,
    std::int32_t resume, std::uint64_t completion,
    std::uint32_t flags) noexcept {
    (void)handle;
    (void)due;
    (void)period;
    (void)resume;
    (void)completion;
    (void)flags;
    return static_cast<std::uint32_t>(no_facility());
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s_CancelWaitableTimer(
    std::uint64_t handle) noexcept {
    (void)handle;
    return no_facility();
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_OpenWaitableTimerW(
    std::uint32_t access, std::int32_t inherit,
    const char16_t* name) noexcept {
    (void)access;
    (void)inherit;
    (void)name;
    return no_facility_handle();
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_OpenWaitableTimerA(
    std::uint32_t access, std::int32_t inherit, const char* name) noexcept {
    (void)access;
    (void)inherit;
    (void)name;
    return no_facility_handle();
}

// ---------------------------------------------------------------------------
// The timer queue
// ---------------------------------------------------------------------------
//
// The same absence as the waitable timers, one level up: a timer queue is a
// thread owning a list of timers, and there is no thread here to own it.

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateTimerQueue()
    noexcept {
    return no_facility_handle();
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateTimerQueueTimer(
    std::uint64_t queue, std::uint64_t callback, std::uint64_t parameter,
    std::uint32_t due, std::uint32_t period, std::uint32_t flags) noexcept {
    (void)queue;
    (void)callback;
    (void)parameter;
    (void)due;
    (void)period;
    (void)flags;
    return no_facility_handle();
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_SetTimerQueueTimer(
    std::uint64_t queue, std::uint64_t callback, std::uint64_t parameter,
    std::uint32_t period, std::uint32_t flags) noexcept {
    (void)queue;
    (void)callback;
    (void)parameter;
    (void)period;
    (void)flags;
    return no_facility_handle();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s_ChangeTimerQueueTimer(
    std::uint64_t queue, std::uint64_t timer, std::uint32_t period,
    std::uint32_t arguments) noexcept {
    (void)queue;
    (void)timer;
    (void)period;
    (void)arguments;
    return no_facility();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s_DeleteTimerQueueTimer(
    std::uint64_t queue, std::uint64_t timer,
    std::uint64_t completion) noexcept {
    (void)queue;
    (void)timer;
    (void)completion;
    return no_facility();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s_CancelTimerQueueTimer(
    std::uint64_t queue, std::uint64_t timer) noexcept {
    (void)queue;
    (void)timer;
    return no_facility();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s_DeleteTimerQueue(
    std::uint64_t queue) noexcept {
    (void)queue;
    return no_facility();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s_DeleteTimerQueueEx(
    std::uint64_t queue, std::uint64_t event,
    std::uint64_t completion) noexcept {
    (void)queue;
    (void)event;
    (void)completion;
    return no_facility();
}

// ---------------------------------------------------------------------------
// The thread pool
// ---------------------------------------------------------------------------
//
// Every one of these exists to hand work to a thread pool. There is no pool,
// so a registration that succeeded would be a promise about a thread that
// does not exist.

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateThreadpoolTimer(
    std::uint64_t callback, std::uint64_t context,
    std::uint64_t pool) noexcept {
    (void)callback;
    (void)context;
    (void)pool;
    return no_facility_handle();
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_CreateThreadpoolWait(
    std::uint64_t callback, std::uint64_t context,
    std::uint64_t pool) noexcept {
    (void)callback;
    (void)context;
    (void)pool;
    return no_facility_handle();
}

extern "C" __attribute__((ms_abi)) void k32s_SetThreadpoolTimer(
    std::uint64_t timer, std::uint64_t due, std::int32_t due_ms,
    std::int32_t period_ms, std::uint32_t flags) noexcept {
    (void)timer;
    (void)due;
    (void)due_ms;
    (void)period_ms;
    (void)flags;
    set_last_error(kErrorCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) Hresult k32s_SetThreadpoolTimerEx(
    std::uint64_t timer, std::uint64_t due, std::int64_t due_100ns,
    std::int32_t period_ms, std::uint32_t flags) noexcept {
    (void)timer;
    (void)due;
    (void)due_100ns;
    (void)period_ms;
    (void)flags;
    return kENoInterface;
}

extern "C" __attribute__((ms_abi)) void k32s_SetThreadpoolWait(
    std::uint64_t wait, std::uint64_t object, std::int64_t timeout) noexcept {
    (void)wait;
    (void)object;
    (void)timeout;
    set_last_error(kErrorCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s_IsThreadpoolTimerSet(
    std::uint64_t timer) noexcept {
    (void)timer;
    return no_facility();
}

extern "C" __attribute__((ms_abi)) void k32s_CloseThreadpoolTimer(
    std::uint64_t timer) noexcept {
    (void)timer;
    set_last_error(kErrorCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) void k32s_CloseThreadpoolWait(
    std::uint64_t wait) noexcept {
    (void)wait;
    set_last_error(kErrorCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t
k32s_WaitForThreadpoolIoCallbacks(std::uint64_t pool,
                                  std::int32_t cancel) noexcept {
    (void)pool;
    (void)cancel;
    return no_facility();
}

extern "C" __attribute__((ms_abi)) std::int32_t
k32s_WaitForThreadpoolTimerCallbacks(std::uint64_t pool,
                                     std::int32_t cancel) noexcept {
    (void)pool;
    (void)cancel;
    return no_facility();
}

extern "C" __attribute__((ms_abi)) std::int32_t
k32s_WaitForThreadpoolWaitCallbacks(std::uint64_t pool,
                                    std::int32_t cancel) noexcept {
    (void)pool;
    (void)cancel;
    return no_facility();
}

extern "C" __attribute__((ms_abi)) std::int32_t
k32s_WaitForThreadpoolWorkCallbacks(std::uint64_t pool,
                                    std::int32_t cancel) noexcept {
    (void)pool;
    (void)cancel;
    return no_facility();
}

// ---------------------------------------------------------------------------
// Deferred releases
// ---------------------------------------------------------------------------
//
// Each of these queues an operation to run when the calling thread next
// returns to user mode, through a user-mode APC. Delivering an APC means
// running a guest routine on a guest thread at a point the runtime chooses,
// and this runtime has one thread, no APC queue, and no point at which it
// could run one. The operations themselves are all implemented above -- a
// caller can release a mutex or set an event directly -- so what is missing
// is the deferral, and that is what is refused.

extern "C" __attribute__((ms_abi)) std::int32_t
k32s_ReleaseMutexWhenCallbackReturns(std::int32_t* release,
                                     std::uint64_t mutex) noexcept {
    (void)release;
    (void)mutex;
    return no_facility();
}

extern "C" __attribute__((ms_abi)) std::int32_t
k32s_ReleaseSemaphoreWhenCallbackReturns(std::int32_t* release,
                                         std::uint64_t semaphore,
                                         std::int32_t count) noexcept {
    (void)release;
    (void)semaphore;
    (void)count;
    return no_facility();
}

extern "C" __attribute__((ms_abi)) std::int32_t
k32s_SetEventWhenCallbackReturns(std::int32_t* set,
                                 std::uint64_t event) noexcept {
    (void)set;
    (void)event;
    return no_facility();
}

// ---------------------------------------------------------------------------
// Registering a callback on a wait
// ---------------------------------------------------------------------------
//
// `RegisterWaitForSingleObject` is the thread pool by another name: it hands
// the wait to a pool thread that calls back when the object signals. No pool,
// no callback. `RegisterWaitForInputIdle` additionally waits for a window to
// become idle, which needs a message queue this runtime does not pump.

extern "C" __attribute__((ms_abi)) std::uint64_t
k32s_RegisterWaitForSingleObject(std::uint64_t object, std::uint64_t context,
                                 std::uint64_t callback, std::uint32_t flags,
                                 std::uint32_t milliseconds) noexcept {
    (void)object;
    (void)context;
    (void)callback;
    (void)flags;
    (void)milliseconds;
    return no_facility_handle();
}

extern "C" __attribute__((ms_abi)) std::int32_t
k32s_RegisterWaitForSingleObjectEx(std::uint64_t object,
                                   std::uint64_t context,
                                   std::uint64_t callback,
                                   std::uint32_t flags,
                                   std::uint32_t milliseconds,
                                   std::uint64_t* registration) noexcept {
    (void)object;
    (void)context;
    (void)callback;
    (void)flags;
    (void)milliseconds;
    (void)registration;
    return no_facility();
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_RegisterWaitForInputIdle(
    std::uint64_t process, std::int32_t inherit, std::uint64_t callback,
    std::uint64_t context) noexcept {
    (void)process;
    (void)inherit;
    (void)callback;
    (void)context;
    return no_facility_handle();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s_UnregisterWait(
    std::uint64_t registration) noexcept {
    (void)registration;
    return no_facility();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s_UnregisterWaitEx(
    std::uint64_t registration, std::uint64_t completion) noexcept {
    (void)registration;
    (void)completion;
    return no_facility();
}

// ---------------------------------------------------------------------------
// Condition variables
// ---------------------------------------------------------------------------
//
// These block on a lock the caller owns -- a `CRITICAL_SECTION` or an
// `SRWLOCK` in the guest's own memory -- and put the thread to sleep only
// after releasing it. The critical-section implementation is `winabi.cpp`'s
// and private to it, and this runtime has no SRW lock at all, so there is
// nothing here that could release a lock it does not own. A caller holding
// one is a caller this file cannot help.

extern "C" __attribute__((ms_abi)) std::int32_t k32s_SleepConditionVariableCS(
    std::uint64_t condition, std::uint64_t critical_section,
    std::uint32_t milliseconds) noexcept {
    (void)condition;
    (void)critical_section;
    (void)milliseconds;
    return no_facility();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s_SleepConditionVariableSRW(
    std::uint64_t condition, std::uint64_t lock, std::uint32_t milliseconds,
    std::uint32_t flags) noexcept {
    (void)condition;
    (void)lock;
    (void)milliseconds;
    (void)flags;
    return no_facility();
}

// ---------------------------------------------------------------------------
// The console, the debugger, the event log, UMS and communications
// ---------------------------------------------------------------------------
//
// Each of these needs something this runtime does not have, and each answers
// the way `api/console.cpp` answers a run whose handles are redirected: with
// the error that says the thing was not there, and never with a plausible
// value standing in for it.

extern "C" __attribute__((ms_abi)) std::int32_t k32s_GenerateConsoleCtrlEvent(
    std::uint32_t control, std::uint32_t group) noexcept {
    (void)control;
    (void)group;
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s_GetConsoleInputWaitHandle()
    noexcept {
    // The one handle-answering name here that answers `INVALID_HANDLE_VALUE`
    // rather than null, because that is what this call documents and a
    // caller testing for it would read null as a valid zero handle.
    set_last_error(kErrorInvalidHandle);
    return kInvalidHandleValue;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s_SetLastConsoleEventActive(
    std::int32_t active) noexcept {
    (void)active;
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s_SetMessageWaitingIndicator(
    std::int32_t enabled) noexcept {
    (void)enabled;
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s_WaitForDebugEvent(
    std::uint32_t* process, std::uint32_t* thread,
    std::uint32_t milliseconds) noexcept {
    (void)process;
    (void)thread;
    (void)milliseconds;
    // No debugger is attached to this process, so there is no debug event to
    // wait for and none that could arrive.
    return no_facility();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s_WaitForDebugEventEx(
    std::uint32_t* process, std::uint32_t* thread, std::uint32_t milliseconds,
    std::int32_t alertable) noexcept {
    (void)process;
    (void)thread;
    (void)milliseconds;
    (void)alertable;
    return no_facility();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s_ContinueDebugEvent(
    std::uint32_t process, std::uint32_t thread,
    std::uint32_t status) noexcept {
    (void)process;
    (void)thread;
    (void)status;
    return no_facility();
}

extern "C" __attribute__((ms_abi)) std::int32_t
k32s_QueryNumberOfEventLogRecords(std::uint64_t log,
                                  std::int32_t* count) noexcept {
    (void)log;
    (void)count;
    // The event log is a service with a file behind it, and there is neither.
    return no_facility();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s_QueryOldestEventLogRecord(
    std::uint64_t log, std::uint32_t* oldest) noexcept {
    (void)log;
    (void)oldest;
    return no_facility();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s_GetUmsCompletionListEvent(
    std::uint64_t list, std::uint64_t* event) noexcept {
    (void)list;
    (void)event;
    // User-mode scheduling needs threads this runtime does not run and a
    // completion list this runtime does not keep.
    return no_facility();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s_WaitCommEvent(
    std::uint64_t port, std::uint64_t overlapped,
    std::uint32_t* mask) noexcept {
    (void)port;
    (void)overlapped;
    (void)mask;
    // A communications port is a device this runtime never opens, so the
    // handle is one no serial port answers for.
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s_WaitNamedPipeW(
    const char16_t* name, std::uint32_t milliseconds) noexcept {
    (void)name;
    (void)milliseconds;
    // Named pipes need a server that creates them and a namespace they are
    // found under. Neither exists here, so there is nothing to wait for.
    return no_facility();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s_WaitNamedPipeA(
    const char* name, std::uint32_t milliseconds) noexcept {
    (void)name;
    (void)milliseconds;
    return no_facility();
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void add_kernel32_sync(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("CancelTimerQueueTimer",
      reinterpret_cast<void*>(&k32s_CancelTimerQueueTimer));
    e("CancelWaitableTimer",
      reinterpret_cast<void*>(&k32s_CancelWaitableTimer));
    e("ChangeTimerQueueTimer",
      reinterpret_cast<void*>(&k32s_ChangeTimerQueueTimer));
    e("CloseThreadpoolTimer",
      reinterpret_cast<void*>(&k32s_CloseThreadpoolTimer));
    e("CloseThreadpoolWait",
      reinterpret_cast<void*>(&k32s_CloseThreadpoolWait));
    e("ContinueDebugEvent",
      reinterpret_cast<void*>(&k32s_ContinueDebugEvent));
    e("CreateEventExA", reinterpret_cast<void*>(&k32s_CreateEventExA));
    e("CreateEventExW", reinterpret_cast<void*>(&k32s_CreateEventExW));
    e("CreateMutexA", reinterpret_cast<void*>(&k32s_CreateMutexA));
    e("CreateMutexExA", reinterpret_cast<void*>(&k32s_CreateMutexExA));
    e("CreateMutexExW", reinterpret_cast<void*>(&k32s_CreateMutexExW));
    e("CreateMutexW", reinterpret_cast<void*>(&k32s_CreateMutexW));
    e("CreateSemaphoreA", reinterpret_cast<void*>(&k32s_CreateSemaphoreA));
    e("CreateSemaphoreExA",
      reinterpret_cast<void*>(&k32s_CreateSemaphoreExA));
    e("CreateSemaphoreExW",
      reinterpret_cast<void*>(&k32s_CreateSemaphoreExW));
    e("CreateSemaphoreW", reinterpret_cast<void*>(&k32s_CreateSemaphoreW));
    e("CreateThreadpoolTimer",
      reinterpret_cast<void*>(&k32s_CreateThreadpoolTimer));
    e("CreateThreadpoolWait",
      reinterpret_cast<void*>(&k32s_CreateThreadpoolWait));
    e("CreateTimerQueue", reinterpret_cast<void*>(&k32s_CreateTimerQueue));
    e("CreateTimerQueueTimer",
      reinterpret_cast<void*>(&k32s_CreateTimerQueueTimer));
    e("CreateWaitableTimerA",
      reinterpret_cast<void*>(&k32s_CreateWaitableTimerA));
    e("CreateWaitableTimerExA",
      reinterpret_cast<void*>(&k32s_CreateWaitableTimerExA));
    e("CreateWaitableTimerExW",
      reinterpret_cast<void*>(&k32s_CreateWaitableTimerExW));
    e("CreateWaitableTimerW",
      reinterpret_cast<void*>(&k32s_CreateWaitableTimerW));
    e("DeleteTimerQueue", reinterpret_cast<void*>(&k32s_DeleteTimerQueue));
    e("DeleteTimerQueueEx",
      reinterpret_cast<void*>(&k32s_DeleteTimerQueueEx));
    e("DeleteTimerQueueTimer",
      reinterpret_cast<void*>(&k32s_DeleteTimerQueueTimer));
    e("GenerateConsoleCtrlEvent",
      reinterpret_cast<void*>(&k32s_GenerateConsoleCtrlEvent));
    e("GetConsoleInputWaitHandle",
      reinterpret_cast<void*>(&k32s_GetConsoleInputWaitHandle));
    e("GetUmsCompletionListEvent",
      reinterpret_cast<void*>(&k32s_GetUmsCompletionListEvent));
    e("IsThreadpoolTimerSet",
      reinterpret_cast<void*>(&k32s_IsThreadpoolTimerSet));
    e("OpenEventA", reinterpret_cast<void*>(&k32s_OpenEventA));
    e("OpenEventW", reinterpret_cast<void*>(&k32s_OpenEventW));
    e("OpenMutexA", reinterpret_cast<void*>(&k32s_OpenMutexA));
    e("OpenMutexW", reinterpret_cast<void*>(&k32s_OpenMutexW));
    e("OpenSemaphoreA", reinterpret_cast<void*>(&k32s_OpenSemaphoreA));
    e("OpenSemaphoreW", reinterpret_cast<void*>(&k32s_OpenSemaphoreW));
    e("OpenWaitableTimerA",
      reinterpret_cast<void*>(&k32s_OpenWaitableTimerA));
    e("OpenWaitableTimerW",
      reinterpret_cast<void*>(&k32s_OpenWaitableTimerW));
    e("PulseEvent", reinterpret_cast<void*>(&k32s_PulseEvent));
    e("QueryNumberOfEventLogRecords",
      reinterpret_cast<void*>(&k32s_QueryNumberOfEventLogRecords));
    e("QueryOldestEventLogRecord",
      reinterpret_cast<void*>(&k32s_QueryOldestEventLogRecord));
    e("RegisterWaitForInputIdle",
      reinterpret_cast<void*>(&k32s_RegisterWaitForInputIdle));
    e("RegisterWaitForSingleObject",
      reinterpret_cast<void*>(&k32s_RegisterWaitForSingleObject));
    e("RegisterWaitForSingleObjectEx",
      reinterpret_cast<void*>(&k32s_RegisterWaitForSingleObjectEx));
    e("ReleaseMutex", reinterpret_cast<void*>(&k32s_ReleaseMutex));
    e("ReleaseMutexWhenCallbackReturns",
      reinterpret_cast<void*>(&k32s_ReleaseMutexWhenCallbackReturns));
    e("ReleaseSemaphore", reinterpret_cast<void*>(&k32s_ReleaseSemaphore));
    e("ReleaseSemaphoreWhenCallbackReturns",
      reinterpret_cast<void*>(&k32s_ReleaseSemaphoreWhenCallbackReturns));
    e("SetEventWhenCallbackReturns",
      reinterpret_cast<void*>(&k32s_SetEventWhenCallbackReturns));
    e("SetLastConsoleEventActive",
      reinterpret_cast<void*>(&k32s_SetLastConsoleEventActive));
    e("SetMessageWaitingIndicator",
      reinterpret_cast<void*>(&k32s_SetMessageWaitingIndicator));
    e("SetThreadpoolTimer", reinterpret_cast<void*>(&k32s_SetThreadpoolTimer));
    e("SetThreadpoolTimerEx",
      reinterpret_cast<void*>(&k32s_SetThreadpoolTimerEx));
    e("SetThreadpoolWait", reinterpret_cast<void*>(&k32s_SetThreadpoolWait));
    e("SetTimerQueueTimer",
      reinterpret_cast<void*>(&k32s_SetTimerQueueTimer));
    e("SetWaitableTimer", reinterpret_cast<void*>(&k32s_SetWaitableTimer));
    e("SetWaitableTimerEx",
      reinterpret_cast<void*>(&k32s_SetWaitableTimerEx));
    e("SignalObjectAndWait",
      reinterpret_cast<void*>(&k32s_SignalObjectAndWait));
    e("SleepConditionVariableCS",
      reinterpret_cast<void*>(&k32s_SleepConditionVariableCS));
    e("SleepConditionVariableSRW",
      reinterpret_cast<void*>(&k32s_SleepConditionVariableSRW));
    e("SleepEx", reinterpret_cast<void*>(&k32s_SleepEx));
    e("UnregisterWait", reinterpret_cast<void*>(&k32s_UnregisterWait));
    e("UnregisterWaitEx", reinterpret_cast<void*>(&k32s_UnregisterWaitEx));
    e("WaitCommEvent", reinterpret_cast<void*>(&k32s_WaitCommEvent));
    e("WaitForDebugEvent", reinterpret_cast<void*>(&k32s_WaitForDebugEvent));
    e("WaitForDebugEventEx",
      reinterpret_cast<void*>(&k32s_WaitForDebugEventEx));
    e("WaitForMultipleObjects",
      reinterpret_cast<void*>(&k32s_WaitForMultipleObjects));
    e("WaitForMultipleObjectsEx",
      reinterpret_cast<void*>(&k32s_WaitForMultipleObjectsEx));
    e("WaitForThreadpoolIoCallbacks",
      reinterpret_cast<void*>(&k32s_WaitForThreadpoolIoCallbacks));
    e("WaitForThreadpoolTimerCallbacks",
      reinterpret_cast<void*>(&k32s_WaitForThreadpoolTimerCallbacks));
    e("WaitForThreadpoolWaitCallbacks",
      reinterpret_cast<void*>(&k32s_WaitForThreadpoolWaitCallbacks));
    e("WaitForThreadpoolWorkCallbacks",
      reinterpret_cast<void*>(&k32s_WaitForThreadpoolWorkCallbacks));
    e("WaitNamedPipeA", reinterpret_cast<void*>(&k32s_WaitNamedPipeA));
    e("WaitNamedPipeW", reinterpret_cast<void*>(&k32s_WaitNamedPipeW));
}

}  // namespace occ::runtime::winabi
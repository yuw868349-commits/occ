#include "occ/runtime/objects.h"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <vector>

namespace occ::runtime::objects {

namespace {

// One table entry. The fields are a union written out flat: the kinds this
// table holds share a handle namespace and a life cycle, and a `variant`
// would say so with a type the switch below has to unwrap before it can
// read two bits. `signalled` is meaningful for every kind -- it is the
// question a wait asks first -- and what it means differs, which is what
// `kind` is for.
struct Entry {
    Kind kind = Kind::Event;
    bool in_use = false;
    bool manual_reset = false;  // Event only
    bool signalled = false;
};

// The table and the lock over it.
//
// The lock is a mutex rather than a futex pair of this file's own, which is
// what the critical-section implementation uses. The difference is what the
// lock is held across: a critical section is copied into the guest's memory
// and its encoding is part of the layout the guest reads back, so it has to
// be spelled here. This lock is private, nothing outside this file can
// observe it, and a standard mutex is the version of it that has been
// tested by more people than this file ever will be.
std::mutex g_lock;
std::condition_variable g_wake;
std::vector<Entry> g_entries;
std::uint64_t g_live = 0;

// The entry a handle names, or null. Callers hold `g_lock`: every field it
// reads is one another thread can change, and returning the pointer for a
// caller to use after unlocking would be the bug the lock exists to
// prevent.
Entry* find(std::uint64_t handle) noexcept {
    if (handle < kHandleBase) {
        return nullptr;
    }
    const std::uint64_t index = handle - kHandleBase;
    if (index >= g_entries.size()) {
        return nullptr;
    }
    Entry* const entry = &g_entries[static_cast<std::size_t>(index)];
    return entry->in_use ? entry : nullptr;
}

}  // namespace

std::uint64_t create_event(bool manual_reset, bool initial_state) noexcept {
    const std::lock_guard<std::mutex> guard(g_lock);

    // The lowest free slot, so that a program which creates and destroys
    // events in a loop does not walk the table upward forever. Windows
    // reuses handle values for the same reason and a program is allowed to
    // depend on neither, so the choice is free; this one is the one that
    // keeps the table from growing without a bound.
    for (std::size_t i = 0; i < g_entries.size(); ++i) {
        if (!g_entries[i].in_use) {
            Entry& entry = g_entries[i];
            entry = Entry{};
            entry.kind = Kind::Event;
            entry.in_use = true;
            entry.manual_reset = manual_reset;
            entry.signalled = initial_state;
            ++g_live;
            return kHandleBase + i;
        }
    }

    g_entries.push_back(Entry{});
    Entry& entry = g_entries.back();
    entry.kind = Kind::Event;
    entry.in_use = true;
    entry.manual_reset = manual_reset;
    entry.signalled = initial_state;
    ++g_live;
    return kHandleBase + g_entries.size() - 1;
}

bool set_event(std::uint64_t handle) noexcept {
    {
        const std::lock_guard<std::mutex> guard(g_lock);
        Entry* const entry = find(handle);
        if (entry == nullptr || entry->kind != Kind::Event) {
            return false;
        }
        entry->signalled = true;
    }
    // Woken after the state is visible and not inside the lock. Every
    // waiter is woken rather than the one this signal belongs to: a
    // condition variable cannot name a thread, and the alternative is a
    // queue and a handoff of its own. The cost is that a run with many
    // waiters on one object wakes them all to release one; the answer is
    // still correct, because each re-reads the state under the lock.
    g_wake.notify_all();
    return true;
}

bool reset_event(std::uint64_t handle) noexcept {
    const std::lock_guard<std::mutex> guard(g_lock);
    Entry* const entry = find(handle);
    if (entry == nullptr || entry->kind != Kind::Event) {
        return false;
    }
    entry->signalled = false;
    return true;
}

WaitOutcome wait_one(std::uint64_t handle, std::uint32_t timeout_ms) noexcept {
    // The deadline is computed once. A wait that recomputed it after every
    // wakeup would extend itself by the time it had already spent, and a
    // program that asked for a second would get as many seconds as it was
    // woken.
    const bool forever = timeout_ms == kInfinite;
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);

    std::unique_lock<std::mutex> lock(g_lock);
    for (;;) {
        Entry* const entry = find(handle);
        if (entry == nullptr || entry->kind != Kind::Event) {
            return WaitOutcome::NoSuchObject;
        }
        if (entry->signalled) {
            // An auto-reset event spends its signal on the wait that found
            // it. This is the whole difference between the two kinds: one
            // `SetEvent` on a manual-reset event releases every waiter and
            // stays signalled, and on an auto-reset event releases one.
            if (!entry->manual_reset) {
                entry->signalled = false;
            }
            return WaitOutcome::Signalled;
        }
        if (!forever && timeout_ms == 0) {
            // A zero timeout asks about the state now rather than waiting
            // for it to change, and the answer is the timeout.
            return WaitOutcome::TimedOut;
        }
        if (forever) {
            // A spurious wakeup returns here and the loop re-reads the
            // state, which is what makes the wait correct rather than
            // merely usually correct.
            g_wake.wait(lock);
            continue;
        }
        if (g_wake.wait_until(lock, deadline) == std::cv_status::timeout) {
            // The wait may have timed out in the same instant a signal
            // arrived, so the state is read once more rather than reported
            // as a timeout on the strength of the clock alone.
            Entry* const last = find(handle);
            if (last == nullptr || last->kind != Kind::Event) {
                return WaitOutcome::NoSuchObject;
            }
            if (last->signalled) {
                if (!last->manual_reset) {
                    last->signalled = false;
                }
                return WaitOutcome::Signalled;
            }
            return WaitOutcome::TimedOut;
        }
    }
}

bool is_object(std::uint64_t handle) noexcept {
    const std::lock_guard<std::mutex> guard(g_lock);
    return find(handle) != nullptr;
}

bool close(std::uint64_t handle) noexcept {
    const std::lock_guard<std::mutex> guard(g_lock);
    Entry* const entry = find(handle);
    if (entry == nullptr) {
        return false;
    }
    *entry = Entry{};
    --g_live;
    return true;
}

std::uint64_t live_count() noexcept {
    const std::lock_guard<std::mutex> guard(g_lock);
    return g_live;
}

}  // namespace occ::runtime::objects

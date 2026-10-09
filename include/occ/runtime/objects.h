// The objects a handle can name, and the waiting that comes with them.
//
// A Windows program synchronises on handles. It creates an event or a
// mutex, hands the handle to another thread, and waits on it; the wait is
// what makes the API a synchronisation API rather than a set of setters.
// The handles this runtime issued before this file existed named files and
// nothing else: a file handle was a host descriptor plus an offset, and
// `CloseHandle` closed a descriptor. That is enough for a program that
// reads and writes on one thread, and it is not enough for anything else,
// which is why the synchronization surface had no implementation at all.
//
// So an object lives in a table and its handle is an index into it. The
// entry carries the three things a wait needs: what kind of object it is,
// whether it is signalled, and -- for the kinds where a wait consumes
// something -- the state the wait changes.
//
// **The handles do not collide with the ones already issued.** Files use a
// range above the standard handles, the standard handles are three fixed
// values, and the pseudo-handles are two more; objects start above all of
// them, so `CloseHandle` can tell which namespace a handle came from by
// looking at the number rather than by consulting a table that would have
// to hold every file as well.

#ifndef OCC_RUNTIME_OBJECTS_H
#define OCC_RUNTIME_OBJECTS_H

#include <cstdint>

namespace occ::runtime::objects {

// What a handle names. The kinds are the ones a wait can distinguish
// between: an event's state is a bit, a mutex has an owner, and a
// semaphore has a count, so "signalled" means something different in each
// and the wait has to know which one it is looking at.
enum class Kind : std::uint8_t {
    Event,
    Mutex,
    Semaphore,
};

// The base of the handle range this table issues. Above every file handle
// -- those run from `kFileHandleBase` for a megabyte -- so a handle's
// namespace is a property of its value.
constexpr std::uint64_t kHandleBase = 0x200000;

// What a wait returned, which is what `WaitForSingleObject` maps onto the
// two status codes and the failure value Windows defines for it.
enum class WaitOutcome : std::uint8_t {
    // The object was signalled. For an auto-reset event this wait consumed
    // the signal and the object is now non-signalled.
    Signalled,
    // The timeout expired with the object non-signalled.
    TimedOut,
    // The handle names no object, in which case the caller raises
    // ERROR_INVALID_HANDLE.
    NoSuchObject,
};

// An event. `manual_reset` events stay signalled until something resets
// them; auto-reset ones return to non-signalled as the wait that found them
// signalled returns, which is what makes them a one-shot wakeup.
[[nodiscard]] std::uint64_t create_event(bool manual_reset,
                                         bool initial_state) noexcept;

// Sets an event signalled, and one waiter is released. Returns false when
// the handle names no event.
bool set_event(std::uint64_t handle) noexcept;

// Returns an event to non-signalled. Returns false when the handle names no
// event.
bool reset_event(std::uint64_t handle) noexcept;

// Waits for one object. `timeout_ms` of `kInfinite` waits without a
// deadline; zero asks about the object's state now rather than waiting for
// it to change.
//
// A wait that finds an auto-reset event signalled consumes that signal, so
// two waiters cannot both be released by one `SetEvent` -- which is the
// whole difference between the two event kinds, and the reason this
// function needs to know which kind it was given.
[[nodiscard]] WaitOutcome wait_one(std::uint64_t handle,
                                   std::uint32_t timeout_ms) noexcept;

// The value `WaitForSingleObject` treats as "no deadline".
constexpr std::uint32_t kInfinite = 0xFFFFFFFFu;

// Whether the handle names an object this table issued, which is the test
// `CloseHandle` makes to decide which namespace a handle belongs to.
[[nodiscard]] bool is_object(std::uint64_t handle) noexcept;

// The kind of object a handle names. Answers false when the handle names no
// object, and writes the kind through `out` when it does. A caller that has
// to describe a handle it was handed -- the object-type query of the
// anti-debug surface is the one -- needs the kind rather than the bare
// existence test `is_object` gives.
[[nodiscard]] bool kind_of(std::uint64_t handle, Kind& out) noexcept;

// Releases an object. Returns false when the handle names none.
bool close(std::uint64_t handle) noexcept;

// The number of live objects, for tests that need to know whether a close
// released anything. Not part of the API surface; a guest has no way to ask.
[[nodiscard]] std::uint64_t live_count() noexcept;

}  // namespace occ::runtime::objects

#endif

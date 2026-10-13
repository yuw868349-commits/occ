// The thread family a debugger and an injector reach for first: a thread
// started in another process, and an asynchronous procedure call queued to a
// thread that is waiting alertably.
//
// `CreateRemoteThread` is `CreateThread` with a process handle in front.
// This runtime runs one process, so the only process handle that can stand
// behind it is the pseudo-handle of the process itself: a remote thread in
// the only process there is is a thread in this one, which the thread
// machinery already creates. Any other handle is refused with
// `ERROR_INVALID_HANDLE` rather than answered with a plausible value -- the
// same refusal `VirtualAllocEx` gives a handle for a process that does not
// exist.
//
// `QueueUserAPC` is the other injection channel, and it is implemented
// rather than stubbed. An APC is a routine queued to a thread and run the
// next time that thread waits alertably (`SleepEx`,
// `WaitForSingleObjectEx`, `WaitForMultipleObjectsEx`). Each thread carries
// its own queue in its `GuestState`; the waiter drains it, runs each
// routine with the guest ABI, and answers `WAIT_IO_COMPLETION`, which is
// the status Windows gives a wait that was interrupted by an APC. A thread
// that never waits alertably keeps its queue, which is what Windows does.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <utility>

namespace occ::runtime::winabi {
namespace {

// The pseudo-handle every process answers for itself. `CreateRemoteThread`
// accepts it and nothing else: there is one process, and a handle for a
// stranger is refused the way the rest of this runtime refuses one.
constexpr std::uint64_t kCurrentProcessHandle = 0xFFFFFFFFFFFFFFFFULL;

// `CREATE_SUSPENDED`, the only thread-creation flag with an effect here. The
// other flag a caller may set narrows the stack's meaning, which a mapping
// of the guest's address space is either way.
constexpr std::uint32_t kCreateSuspended = 0x00000004u;

}  // namespace

// Drains the calling thread's APC queue, running each routine with the
// guest ABI. Answers true when at least one routine ran, which is what an
// alertable wait tests before deciding between `WAIT_IO_COMPLETION` and the
// wait it was asked for.
//
// The routines are guest code in this address space, and the thread that
// runs them is the thread the queue belongs to -- the same thread that is
// waiting, whose segment base is already the guest's -- so a call is the
// same `ms_abi` call the thread machinery uses to enter a guest entry
// point.
bool run_pending_apcs(GuestState& self) noexcept {
    std::vector<GuestState::ApcEntry> pending;
    {
        std::lock_guard<std::mutex> lock(self.apc.mutex);
        pending.swap(self.apc.queue);
    }
    if (pending.empty()) {
        return false;
    }

    using ApcRoutine = void(__attribute__((ms_abi)) *)(std::uint64_t);
    for (const GuestState::ApcEntry& entry : pending) {
        const ApcRoutine routine =
            reinterpret_cast<ApcRoutine>(entry.routine);
        if (routine != nullptr) {
            routine(entry.argument);
        }
    }
    return true;
}

// Queues an APC to the thread a handle names, and answers whether it was
// queued. The third argument is the value the routine receives when it
// runs: `QueueUserAPC(routine, thread, data)` runs `routine(data)` at the
// next alertable wait, which is how a caller passes data to the queued
// code. The handle resolution is the thread table's own: a handle the table
// minted names that thread, and any other handle names the calling thread,
// which is the trust `guest_thread_state_for` extends to a self handle.
extern "C" __attribute__((ms_abi)) std::int32_t k32te_QueueUserAPC(
    std::uint64_t routine, std::uint64_t thread, std::uint64_t data) noexcept {
    if (routine == 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    GuestState* state = guest_thread_state_for(thread);
    if (state == nullptr) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    GuestState::ApcEntry entry;
    entry.routine = routine;
    entry.argument = data;
    {
        std::lock_guard<std::mutex> lock(state->apc.mutex);
        state->apc.queue.push_back(entry);
    }
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32te_CreateRemoteThread(
    std::uint64_t process, void* attributes, std::uint64_t stack_size,
    std::uint64_t start, void* parameter, std::uint32_t flags,
    std::uint32_t* thread_id) noexcept {
    static_cast<void>(attributes);
    if (process != kCurrentProcessHandle) {
        // A handle for another process. There is no other process in this
        // runtime, so the answer is the one Windows gives for a process
        // handle that names nothing: an invalid-handle error, not a thread
        // that quietly appears in this one.
        set_last_error(kErrorInvalidHandle);
        return 0;
    }

    GuestThreadRequest request;
    request.start = start;
    request.parameter = reinterpret_cast<std::uint64_t>(parameter);
    request.stack_size = stack_size;
    request.suspended = (flags & kCreateSuspended) != 0;

    std::uint32_t id = 0;
    const std::uint64_t handle = create_guest_thread(request, &id);
    if (handle == 0) {
        return 0;
    }
    if (thread_id != nullptr) {
        *thread_id = id;
    }
    return handle;
}

void add_kernel32_threads_ext(ExportList& out) {
    const auto e = [](const char* n, void* fn) {
        HostExport entry;
        entry.name = n;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        return entry;
    };
    out.push_back(e("CreateRemoteThread",
                    reinterpret_cast<void*>(&k32te_CreateRemoteThread)));
    out.push_back(e("QueueUserAPC",
                    reinterpret_cast<void*>(&k32te_QueueUserAPC)));
}

}  // namespace occ::runtime::winabi

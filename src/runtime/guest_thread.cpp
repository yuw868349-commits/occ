// A second thread of the guest's own.
//
// The guest runs on a host thread, and everything a thunk needs to know
// about the guest it is serving -- the address space, the TEB, the last
// error, the TLS slots -- hangs off a thread-local pointer to a
// `GuestState`. A second guest thread is therefore a second host thread,
// and it needs the three things that make one: its own `GuestState`, its
// own TEB, and its own stack. All three are built here, and the code the
// guest asked to run is called on them.
//
// The TEB is the part that has to be exactly right. A Windows program reads
// its thread's identity through the segment base -- `mov %gs:0x48` for the
// thread id, `mov %gs:0x30` for the TEB's own address -- and the base is not
// something a program can compute, which is why this file sets it with
// `arch_prctl` on the new thread before any guest code runs. The fields are
// written at the same offsets `pe_process.cpp` writes them at for the first
// thread, because the offsets are the interface between the two files and
// there is no header that could make them agree.
//
// What is *not* shared between threads is the last error and the TLS slots:
// both live inside the TEB, and a TEB per thread is what keeps a
// `SetLastError` on one thread from overwriting another's. What is shared
// is the address space, the PEB and the module list, because that is what
// a process is.

#include "occ/runtime/api_common.h"
#include "occ/runtime/mapper.h"
#include "occ/runtime/winabi.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <pthread.h>
#include <signal.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

namespace occ::runtime::winabi {
namespace {

// The handle base for a thread. A guest handle has to be distinguishable
// from every other kind this runtime mints: files from 0x2000, the
// synchronization objects from 0x200000, sockets from 0x400000, and the
// thread-pool objects from 0x600000. Threads start above all of them.
constexpr std::uint64_t kThreadHandleBase = 0x800000;
constexpr std::uint64_t kThreadHandleSpan = 0x100000;

// The two things a thread owns, in the sizes Windows gives them. The TEB is
// two pages, which is what `pe_process.cpp` maps for the first thread, and
// the default stack is a megabyte, which is what a linker puts in an image
// that does not say otherwise.
constexpr std::uint64_t kTebBytes = 0x2000;
constexpr std::uint64_t kDefaultStackBytes = 1024 * 1024;
constexpr std::uint64_t kGranularity = 0x10000;

// The offsets inside the TEB, the same numbers `pe_process.cpp` writes the
// first thread's TEB with. They are repeated rather than shared for the
// reason that file gives: the offset is the interface, and a shared constant
// would still be two files that have to agree.
constexpr std::size_t kTebExceptionList = 0x00;
constexpr std::size_t kTebStackBase = 0x08;
constexpr std::size_t kTebStackLimit = 0x10;
constexpr std::size_t kTebSelf = 0x30;
constexpr std::size_t kTebProcessId = 0x40;
constexpr std::size_t kTebThreadId = 0x48;
constexpr std::size_t kTebTlsPointer = 0x58;
constexpr std::size_t kTebPeb = 0x60;
constexpr std::size_t kTebLastError = 0x68;
constexpr std::size_t kTlsArrayOffset = 0x1480;

// The `arch_prctl` selector for the GS base, and the value that clears it.
constexpr unsigned long kArchSetGs = 0x1001;

// The wait results, in the values the guest reads.
constexpr std::uint32_t kWaitObject0 = 0x00000000u;
constexpr std::uint32_t kWaitTimeout = 0x00000102u;
constexpr std::uint32_t kWaitFailed = 0xFFFFFFFFu;
constexpr std::uint32_t kStillActive = 259;

// The suspend signal. A running thread is stopped by sending it this one and
// having its handler wait; `SIGRTMIN` is the first signal the C library does
// not use for anything of its own, so a program that installs handlers for
// the others is not disturbed. It is a run-time value rather than a constant
// because the C library computes it, and the signal is read once at the
// point it is installed.
[[nodiscard]] int suspend_signal() noexcept {
    return SIGRTMIN;
}

// One guest thread, from the moment it is asked for until its handle is
// closed. The record outlives the thread itself -- a caller that waits for
// the thread and then reads its exit code needs both after the thread is
// gone -- so it is released by the handle, not by the thread.
struct ThreadRecord {
    // The guest-visible identity: the id the TEB holds and a caller reads
    // back through `GetCurrentThreadId`, and the handle `CreateThread`
    // answers with.
    std::uint32_t id = 0;
    std::uint64_t handle = 0;

    // The thread's own memory in the guest's address space.
    std::uint64_t teb = 0;
    std::uint64_t stack_base = 0;
    std::uint64_t stack_limit = 0;

    // The state the thunks this thread calls will serve. Owned here, so that
    // it lives exactly as long as the thread does and no longer.
    std::unique_ptr<GuestState> state;

    // The host thread. Valid once it has been created.
    pthread_t host = 0;
    bool host_valid = false;

    // What the guest asked to run.
    std::uint64_t start = 0;
    std::uint64_t parameter = 0;

    // The gate a `CREATE_SUSPENDED` thread waits at until it is resumed, and
    // the count `SuspendThread` maintains for a thread that is already
    // running.
    std::mutex mutex;
    std::condition_variable gate;
    std::condition_variable done;
    std::condition_variable resumed;
    bool released = false;
    std::uint32_t suspend_count = 0;
    std::atomic<bool> suspended_by_signal{false};
    bool running = false;

    // How the thread ended. `finished` is what a wait is answered from; the
    // code is what `GetExitCodeThread` reads.
    bool finished = false;
    std::uint32_t exit_code = 0;

    // Whether the handle has been closed. A record whose handle is gone is
    // still in the table until the thread itself has finished, because the
    // thread holds a pointer to it.
    bool handle_open = true;
};

// The table, and the number that names the next thread. Both are behind one
// lock, because a `CreateThread` and a `CloseHandle` on another thread are
// the two things that can happen at once here.
std::mutex& table_lock() noexcept {
    static std::mutex lock;
    return lock;
}

std::vector<std::unique_ptr<ThreadRecord>>& thread_table() noexcept {
    static std::vector<std::unique_ptr<ThreadRecord>> table;
    return table;
}

// The address the next thread's control region starts at. It is chosen once,
// above the stack the loader placed for the first thread, and then walked
// upward -- so a machine with several threads has their control regions in
// an order, and the order is what a program that compares two thread stacks
// observes.
std::uint64_t& next_floor() noexcept {
    static std::uint64_t floor = 0;
    return floor;
}

std::uint32_t& next_thread_id() noexcept {
    static std::uint32_t id = 0;
    return id;
}

// A handle's index into the table, or the invalid value when the handle is
// not one this file minted.
[[nodiscard]] bool thread_index_of(std::uint64_t handle,
                                   std::size_t& index) noexcept {
    if (handle < kThreadHandleBase || handle >= kThreadHandleBase + kThreadHandleSpan) {
        return false;
    }
    index = static_cast<std::size_t>(handle - kThreadHandleBase);
    return true;
}

// The record a handle names, or nullptr. The caller holds no lock; the
// record is released only when its handle is closed *and* its thread has
// finished, and the lookup and the use are both under the table lock in
// every caller below.
[[nodiscard]] ThreadRecord* record_of(std::uint64_t handle) noexcept {
    std::size_t index = 0;
    if (!thread_index_of(handle, index)) {
        return nullptr;
    }
    auto& table = thread_table();
    if (index >= table.size()) {
        return nullptr;
    }
    return table[index].get();
}

// The record of the thread this call runs on, kept per thread so that the
// suspend handler below can reach it without taking a lock -- a signal
// handler runs wherever the thread happened to be, including inside the
// table's own critical section, and a handler that took that lock would
// deadlock the thread it was sent to stop.
thread_local ThreadRecord* g_self_record = nullptr;

// Stops the thread this signal was delivered to, and lets it go when its
// suspend count returns to zero.
//
// A signal handler is the only way to stop a thread that is executing guest
// code, because the runtime controls no point at which that code may be
// paused. Everything in here is async-signal-safe: a thread-local read, an
// atomic load, and `nanosleep`, which is on the list for exactly this reason.
void suspend_handler(int signal) noexcept {
    static_cast<void>(signal);
    ThreadRecord* self = g_self_record;
    if (self == nullptr) {
        return;
    }
    while (self->suspended_by_signal.load(std::memory_order_acquire)) {
        timespec delay {};
        delay.tv_nsec = 1000000L;  // one millisecond
        ::nanosleep(&delay, nullptr);
    }
}

void ensure_suspend_handler() noexcept {
    static std::once_flag once;
    std::call_once(once, [] {
        struct ::sigaction action {};
        action.sa_handler = &suspend_handler;
        action.sa_flags = 0;
        ::sigemptyset(&action.sa_mask);
        ::sigaction(suspend_signal(), &action, nullptr);
    });
}

// The exit path a guest thread's own `ExitProcess` and `exit` reach. A
// thread that asks its process to end ends it, which is what the call means:
// the alternative -- returning up this thread's stack and leaving the other
// threads running -- is `ExitThread`, not this.
void thread_terminate(std::uint32_t code) noexcept {
    ::fflush(nullptr);
    ::_exit(static_cast<int>(code & 0xFFu));
}

// The record for the thread this call is running on, or nullptr when the
// caller is the process's first thread, which was not created here.
[[nodiscard]] ThreadRecord* current_record() noexcept {
    for (const std::unique_ptr<ThreadRecord>& record : thread_table()) {
        if (record != nullptr && record->host_valid &&
            ::pthread_equal(record->host, ::pthread_self())) {
            return record.get();
        }
    }
    return nullptr;
}

// Ends the thread this call is on, with the code the guest asked for. Called
// from the thread's own body, so it records and lets `pthread_exit` unwind
// to the thread's own cleanup.
[[noreturn]] void finish_current_thread(std::uint32_t code) noexcept {
    ThreadRecord* self = nullptr;
    {
        std::lock_guard<std::mutex> lock(table_lock());
        self = current_record();
        if (self != nullptr) {
            self->exit_code = code;
            self->finished = true;
        }
    }

    if (self == nullptr) {
        // The first thread asking to end itself. Windows ends the process
        // when its last thread ends, and the first thread is the one the
        // image's own entry point runs on -- returning from it is how the
        // process ends, so ending it here ends the process.
        ::fflush(nullptr);
        ::_exit(static_cast<int>(code & 0xFFu));
    }

    // The module callbacks that watch threads end, before the state they
    // read is taken away.
    if (self->state != nullptr) {
        run_thread_detach_callbacks(*self->state);
    }

    self->done.notify_all();
    install_terminate_path(nullptr);
    set_guest_state(nullptr);
    ::pthread_exit(nullptr);
}

// The body of a guest thread. It waits at the gate a suspended creation put
// it behind, sets the segment base, and calls the guest's function.
void* guest_thread_main(void* raw) noexcept {
    auto* record = static_cast<ThreadRecord*>(raw);
    if (record == nullptr) {
        return nullptr;
    }

    {
        std::unique_lock<std::mutex> lock(record->mutex);
        while (!record->released) {
            record->gate.wait(lock);
        }
        while (record->suspend_count > 0 &&
               !record->suspended_by_signal.load()) {
            record->resumed.wait(lock);
        }
        record->running = true;
    }

    // The segment base. Everything the guest reads through `%gs` -- the
    // thread id, the TEB's own address, the last error -- reads from here,
    // and it has to be set before the first guest instruction runs.
    ::syscall(SYS_arch_prctl, kArchSetGs, record->teb);
    g_self_record = record;
    set_guest_state(record->state.get());
    install_terminate_path(&thread_terminate);

    // The thread's own static TLS blocks. Without these the first
    // `__declspec(thread)` variable the new thread reads is reached through
    // a null block, which is a fault in a place with no relation to the
    // cause. An image that declares no TLS needs no block, which is why the
    // result is not treated as a failure here.
    static_cast<void>(install_thread_tls(*record->state));

    using GuestThreadEntry =
        std::uint32_t(__attribute__((ms_abi)) *)(std::uint64_t);
    const GuestThreadEntry entry =
        reinterpret_cast<GuestThreadEntry>(record->start);
    const std::uint32_t code = entry(record->parameter);

    finish_current_thread(code);
}

// Writes the fields of a new thread's TEB. The `ThreadId` and the `Self`
// field are what a program reads to identify itself; `StackBase` and
// `StackLimit` are what `_chkstk` and a structured exception handler
// compare against; `Peb` is the same PEB every thread of the process sees.
void fill_teb(std::uint64_t teb, std::uint64_t stack_base,
              std::uint64_t stack_limit, std::uint32_t process_id,
              std::uint32_t thread_id, std::uint64_t peb) noexcept {
    auto* bytes = reinterpret_cast<std::uint8_t*>(teb);
    auto put64 = [bytes](std::size_t offset, std::uint64_t value) {
        std::memcpy(bytes + offset, &value, sizeof(value));
    };
    auto put32 = [bytes](std::size_t offset, std::uint32_t value) {
        std::memcpy(bytes + offset, &value, sizeof(value));
    };

    put64(kTebExceptionList, 0xFFFFFFFFFFFFFFFFULL);
    put64(kTebStackBase, stack_base);
    put64(kTebStackLimit, stack_limit);
    put64(kTebSelf, teb);
    put32(kTebProcessId, process_id);
    put32(kTebThreadId, thread_id);
    put64(kTebTlsPointer, teb + kTlsArrayOffset);
    put64(kTebPeb, peb);
    put32(kTebLastError, 0);
}

// The process id the first thread's TEB carries. A second thread reports the
// same number, because a process has one id and every thread of it names
// that id.
[[nodiscard]] std::uint32_t process_id_of(const GuestState& state) noexcept {
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(state.teb);
    std::uint32_t value = 0;
    std::memcpy(&value, bytes + kTebProcessId, sizeof(value));
    return value;
}

[[nodiscard]] std::uint64_t peb_of(const GuestState& state) noexcept {
    return state.peb;
}

}  // namespace

// --------------------------------------------------------------------------
// The thread lifecycle
// --------------------------------------------------------------------------

[[noreturn]] void exit_current_guest_thread(std::uint32_t code) noexcept {
    // `ExitThread` ends the thread that calls it. On a thread this file
    // created that is a record and a `pthread_exit`; on the process's first
    // thread it is the end of the process, because the first thread is the
    // one whose return ends the image.
    finish_current_thread(code);
}

std::uint64_t create_guest_thread(const GuestThreadRequest& request,
                                  std::uint32_t* thread_id) noexcept {
    const GuestState* main_state = guest_state();
    if (main_state == nullptr || main_state->space == nullptr ||
        main_state->mapper == nullptr) {
        set_last_error(kErrorCallNotImplemented);
        return 0;
    }

    auto record = std::make_unique<ThreadRecord>();
    record->start = request.start;
    record->parameter = request.parameter;
    record->released = !request.suspended;

    // The control region and the stack, in the guest's own address space.
    // They are placed above the first thread's stack and above every thread
    // placed before this one, so that the regions are ordered and a program
    // that walks from one to the next finds them where it left them.
    std::uint64_t floor = next_floor();
    if (floor == 0) {
        floor = (main_state->stack_high + kGranularity - 1) & ~(kGranularity - 1);
    }
    const std::uint64_t stack_bytes =
        (request.stack_size == 0)
            ? kDefaultStackBytes
            : ((request.stack_size + AddressSpace::kPageSize - 1) &
               ~(AddressSpace::kPageSize - 1));

    const Result<std::uint64_t> control = main_state->mapper->map_above(
        floor, kTebBytes, PageProtection::ReadWrite, RegionKind::Control);
    if (!control.ok()) {
        set_last_error(kErrorNotEnoughMemory);
        return 0;
    }
    const std::uint64_t teb = control.value;
    const std::uint64_t stack_floor =
        (teb + kTebBytes + kGranularity - 1) & ~(kGranularity - 1);

    const Result<std::uint64_t> stack = main_state->mapper->map_above(
        stack_floor, stack_bytes, PageProtection::ReadWrite, RegionKind::Stack);
    if (!stack.ok()) {
        set_last_error(kErrorNotEnoughMemory);
        return 0;
    }
    next_floor() = stack.value + stack_bytes;

    record->teb = teb;
    record->stack_base = stack.value + stack_bytes;
    // One page below the limit is left as a guard, the same way the first
    // thread's stack keeps one: a `_chkstk` probe then faults against the
    // guard rather than against the end of a region something else owns.
    record->stack_limit = stack.value + AddressSpace::kPageSize;

    // The state the new thread's thunks serve: the process-wide facts copied
    // from the caller's, and the thread-wide ones replaced.
    record->state = std::make_unique<GuestState>(*main_state);
    record->state->teb = teb;
    record->state->stack_low = stack.value;
    record->state->stack_high = record->stack_base;
    // The argument vector is rebuilt because the copy's pointers point into
    // the *copied* strings' storage, and a vector that has been copied has
    // its elements somewhere else.
    record->state->argv_table.clear();
    record->state->argv_table.reserve(record->state->arguments.size() + 1);
    for (const std::string& argument : record->state->arguments) {
        record->state->argv_table.push_back(argument.c_str());
    }
    record->state->argv_table.push_back(nullptr);
    record->state->faulted = false;
    record->state->resume_mask_valid = false;

    {
        std::lock_guard<std::mutex> lock(table_lock());
        std::uint32_t& id = next_thread_id();
        if (id == 0) {
            // Thread ids are multiples of four, as Windows hands them out,
            // and the first one is four past the id the loader gave the
            // first thread.
            std::uint32_t first = 0;
            std::memcpy(&first,
                        reinterpret_cast<const std::uint8_t*>(main_state->teb) +
                            kTebThreadId,
                        sizeof(first));
            id = (first + 4) & ~3u;
        }
        record->id = id;
        id += 4;

        fill_teb(teb, record->stack_base, record->stack_limit,
                 process_id_of(*main_state), record->id, peb_of(*main_state));

        const std::size_t index = thread_table().size();
        record->handle = kThreadHandleBase + index;
        if (thread_id != nullptr) {
            *thread_id = record->id;
        }
        thread_table().push_back(std::move(record));
    }

    ThreadRecord* const stored = thread_table().back().get();

    // The host thread, on the stack the guest's own TEB describes.
    ::pthread_attr_t attributes;
    ::pthread_attr_init(&attributes);
    ::pthread_attr_setstack(&attributes,
                            reinterpret_cast<void*>(stack.value),
                            static_cast<std::size_t>(stack_bytes));
    const int status =
        ::pthread_create(&stored->host, &attributes, &guest_thread_main, stored);
    ::pthread_attr_destroy(&attributes);

    if (status != 0) {
        // The thread could not be started. The record is left in the table
        // with the failure recorded rather than removed, because the handle
        // was already answered and a handle that names nothing is worse than
        // one whose thread never ran.
        set_last_error(kErrorNotEnoughMemory);
        return 0;
    }

    {
        std::lock_guard<std::mutex> lock(stored->mutex);
        stored->host_valid = true;
    }
    if (!request.suspended) {
        stored->gate.notify_all();
    }

    set_last_error(0);
    return stored->handle;
}

bool is_guest_thread_handle(std::uint64_t handle) noexcept {
    std::lock_guard<std::mutex> lock(table_lock());
    return record_of(handle) != nullptr;
}

std::uint32_t guest_thread_exit_code(std::uint64_t handle,
                                     std::uint32_t* code) noexcept {
    if (code == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return kWaitFailed;
    }
    std::lock_guard<std::mutex> lock(table_lock());
    ThreadRecord* record = record_of(handle);
    if (record == nullptr) {
        set_last_error(kErrorInvalidHandle);
        return kWaitFailed;
    }
    *code = record->finished ? record->exit_code : kStillActive;
    set_last_error(0);
    return kWaitObject0;
}

std::uint32_t wait_guest_thread(std::uint64_t handle,
                                std::int64_t milliseconds) noexcept {
    ThreadRecord* record = nullptr;
    {
        std::lock_guard<std::mutex> lock(table_lock());
        record = record_of(handle);
        if (record == nullptr) {
            set_last_error(kErrorInvalidHandle);
            return kWaitFailed;
        }
    }

    if (milliseconds < 0) {
        std::unique_lock<std::mutex> lock(record->mutex);
        record->done.wait(lock, [record] { return record->finished; });
    } else {
        std::unique_lock<std::mutex> lock(record->mutex);
        if (!record->done.wait_for(
                lock, std::chrono::milliseconds(milliseconds),
                [record] { return record->finished; })) {
            set_last_error(0);
            return kWaitTimeout;
        }
    }

    // The thread has finished, but its host side may still be unwinding.
    // Joining here is what makes the stack and the record's memory safe to
    // release when the handle is closed.
    {
        std::lock_guard<std::mutex> lock(table_lock());
        if (record->host_valid) {
            ::pthread_join(record->host, nullptr);
            record->host_valid = false;
        }
    }

    set_last_error(0);
    return kWaitObject0;
}

bool close_guest_thread(std::uint64_t handle) noexcept {
    std::lock_guard<std::mutex> lock(table_lock());
    ThreadRecord* record = record_of(handle);
    if (record == nullptr) {
        return false;
    }
    record->handle_open = false;
    return true;
}

std::uint32_t resume_guest_thread(std::uint64_t handle,
                                  std::uint32_t* previous) noexcept {
    std::lock_guard<std::mutex> lock(table_lock());
    ThreadRecord* record = record_of(handle);
    if (record == nullptr) {
        set_last_error(kErrorInvalidHandle);
        return kWaitFailed;
    }
    std::lock_guard<std::mutex> state_lock(record->mutex);
    const std::uint32_t before = record->suspend_count;
    if (!record->released) {
        // A thread created suspended has not started at all: releasing it is
        // the whole of the resume, and the count it reports is zero.
        record->released = true;
        record->gate.notify_all();
        if (previous != nullptr) {
            *previous = 0;
        }
        set_last_error(0);
        return 0;
    }
    if (record->suspend_count > 0) {
        --record->suspend_count;
        if (record->suspend_count == 0) {
            record->suspended_by_signal.store(false);
            record->resumed.notify_all();
        }
    }
    if (previous != nullptr) {
        *previous = before;
    }
    set_last_error(0);
    return before;
}

std::uint32_t suspend_guest_thread(std::uint64_t handle) noexcept {
    ensure_suspend_handler();

    ThreadRecord* record = nullptr;
    {
        std::lock_guard<std::mutex> lock(table_lock());
        record = record_of(handle);
        if (record == nullptr) {
            set_last_error(kErrorInvalidHandle);
            return kWaitFailed;
        }
        std::lock_guard<std::mutex> state_lock(record->mutex);
        const std::uint32_t before = record->suspend_count;
        ++record->suspend_count;
        if (record->running) {
            // A thread already executing guest code is stopped where it
            // stands: the signal interrupts it and the handler parks it
            // until the count returns to zero.
            record->suspended_by_signal.store(true);
            if (record->host_valid) {
                ::pthread_kill(record->host, suspend_signal());
            }
        }
        set_last_error(0);
        return before;
    }
}

std::uint64_t open_guest_thread(std::uint32_t thread_id) noexcept {
    std::lock_guard<std::mutex> lock(table_lock());
    for (const std::unique_ptr<ThreadRecord>& record : thread_table()) {
        if (record != nullptr && record->id == thread_id &&
            record->handle_open) {
            set_last_error(0);
            return record->handle;
        }
    }
    set_last_error(kErrorInvalidParameter);
    return 0;
}

std::size_t guest_thread_count() noexcept {
    std::lock_guard<std::mutex> lock(table_lock());
    return thread_table().size();
}

bool guest_thread_at(std::size_t index, std::uint32_t* thread_id) noexcept {
    std::lock_guard<std::mutex> lock(table_lock());
    if (index >= thread_table().size() ||
        thread_table()[index] == nullptr) {
        return false;
    }
    if (thread_id != nullptr) {
        *thread_id = thread_table()[index]->id;
    }
    return true;
}

bool guest_thread_exit_code_at(std::size_t index,
                               std::uint32_t* code) noexcept {
    std::lock_guard<std::mutex> lock(table_lock());
    if (index >= thread_table().size() ||
        thread_table()[index] == nullptr) {
        return false;
    }
    if (code != nullptr) {
        *code = thread_table()[index]->finished
                    ? thread_table()[index]->exit_code
                    : kStillActive;
    }
    return true;
}

}  // namespace occ::runtime::winabi

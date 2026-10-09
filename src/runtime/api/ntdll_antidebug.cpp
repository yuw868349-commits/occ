// The ntdll surface a hardened program probes: what the process is, what is
// attached to it, and what the machine it runs on looks like.
//
// A program that defends itself asks the kernel questions rather than the
// API above it, because the API above it is a wrapper that can be patched and
// the kernel call is the thing the wrapper calls. `NtQueryInformationProcess`
// with `ProcessDebugObjectHandle`, `NtQueryObject` with the type of a handle,
// `NtQuerySystemInformation` with the kernel debugger's state -- these are the
// questions a packer asks to decide whether it is being watched, and a runtime
// that answers them the way an unwatched machine answers them is a runtime a
// packer will run on.
//
// The answers below are therefore not "safe defaults". Each is the value the
// machine the program believes it is on would produce:
//
//   * `ProcessDebugPort` is zero and `ProcessDebugFlags` is one, because a
//     process with no debugger has no debug port and reports the "no debug
//     inherit" flag set. `ProcessDebugObjectHandle` fails with
//     `STATUS_PORT_NOT_SET`, which is precisely the error a process without a
//     debug object receives -- an error, and not a success carrying zero,
//     because the two are distinguishable and a checker knows which it wants.
//
//   * `NtQueryObject` answers with the object's real type name. This runtime
//     has no debug objects, so the type is never `DebugObject`, and the
//     enumeration of every type does not list one.
//
//   * `SystemKernelDebuggerInformation` reports the kernel debugger absent and
//     not enabled, which is a machine running without `bcdedit /debug on`.
//
// Where a class is one this runtime does not model, the answer is the error a
// kernel returns for that class rather than a buffer of zeroes: a caller that
// asked a question and got "invalid information class" has learned something
// true, and a caller that got zeroes has learned something false.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/ntdll.h"
#include "occ/runtime/objects.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstring>
#include <ctime>
#include <sched.h>
#include <string>
#include <time.h>
#include <unistd.h>
#include <vector>

// The identity of the process the guest runs in, reached through the same
// calls the kernel32 domain answers them with, so that a query here and a
// query there cannot disagree.
extern "C" __attribute__((ms_abi)) std::uint32_t
k32_GetCurrentProcessId() noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t
k32_GetCurrentThreadId() noexcept;

namespace occ::runtime::winabi {
namespace {

// ---------------------------------------------------------------------------
// The NTSTATUS values these calls answer with
// ---------------------------------------------------------------------------
//
// An NTSTATUS is the kernel's return: zero for success, and a value whose top
// two bits are set for a failure. The failures below are the ones each call
// documents, and they are written as the numbers they are on the wire because
// a program compares them numerically.

constexpr std::uint32_t kStatusSuccess = 0x00000000u;
constexpr std::uint32_t kStatusInvalidInfoClass = 0xC0000003u;
constexpr std::uint32_t kStatusInfoLengthMismatch = 0xC0000004u;
constexpr std::uint32_t kStatusInvalidHandle = 0xC0000008u;
constexpr std::uint32_t kStatusInvalidParameter = 0xC000000Du;
constexpr std::uint32_t kStatusNoMemory = 0xC0000017u;
constexpr std::uint32_t kStatusBufferTooSmall = 0xC0000023u;
constexpr std::uint32_t kStatusAccessDenied = 0xC0000022u;
constexpr std::uint32_t kStatusNotImplemented = 0xC0000002u;
constexpr std::uint32_t kStatusNotSupported = 0xC00000BBu;
// The answer `ProcessDebugObjectHandle` gives a process with no debugger. It
// is the whole point of the class: a caller that gets this knows there is no
// debug object, and a caller that gets a success knows there is one.
constexpr std::uint32_t kStatusPortNotSet = 0xC0000353u;

// ---------------------------------------------------------------------------
// The process-information classes
// ---------------------------------------------------------------------------
//
// The numbers are the class enum's, and only the ones a defender reads are
// named. Every other number falls through to the invalid-class error, which is
// what the kernel returns for a class it does not define.

constexpr std::uint32_t kProcessBasicInformation = 0;
constexpr std::uint32_t kProcessIoCounters = 2;
constexpr std::uint32_t kProcessPriorityClass = 0x12;
constexpr std::uint32_t kProcessHandleCount = 0x14;
constexpr std::uint32_t kProcessWow64Information = 0x1A;
constexpr std::uint32_t kProcessImageFileName = 0x1B;
constexpr std::uint32_t kProcessDebugPort = 7;
constexpr std::uint32_t kProcessDebugFlags = 0x1F;
constexpr std::uint32_t kProcessDebugObjectHandle = 0x1E;
constexpr std::uint32_t kProcessExecuteFlags = 0x22;
constexpr std::uint32_t kProcessCookie = 0x24;
constexpr std::uint32_t kProcessImageFileNameWin32 = 0x2B;

// ---------------------------------------------------------------------------
// The object-information classes
// ---------------------------------------------------------------------------

constexpr std::uint32_t kObjectBasicInformation = 0;
constexpr std::uint32_t kObjectNameInformation = 1;
constexpr std::uint32_t kObjectTypeInformation = 2;
constexpr std::uint32_t kObjectTypesInformation = 3;
constexpr std::uint32_t kObjectHandleFlagInformation = 4;

// ---------------------------------------------------------------------------
// The system-information classes
// ---------------------------------------------------------------------------

constexpr std::uint32_t kSystemBasicInformation = 0;
constexpr std::uint32_t kSystemProcessorInformation = 1;
constexpr std::uint32_t kSystemPerformanceInformation = 2;
constexpr std::uint32_t kSystemTimeOfDayInformation = 3;
constexpr std::uint32_t kSystemProcessInformation = 5;
constexpr std::uint32_t kSystemModuleInformation = 0x0B;
constexpr std::uint32_t kSystemKernelDebuggerInformation = 0x23;
constexpr std::uint32_t kSystemKernelDebuggerInformationEx = 0x95;
constexpr std::uint32_t kSystemHypervisorInformation = 0x7D;
constexpr std::uint32_t kSystemPageSizeInformation = 0x8A;

// ---------------------------------------------------------------------------
// The structures, at the 64-bit layout
// ---------------------------------------------------------------------------
//
// Windows places these fields at offsets this host's compiler would not choose
// on its own, so every writer below places each field by hand against the
// offset the guest reads it at. A structure written with this host's `sizeof`
// would be right up to the first difference in padding and silently wrong
// afterwards, which is why the offsets are named rather than derived.

// The layout of a `UNICODE_STRING` on the 64-bit ABI: two lengths and a
// pointer, with four bytes of padding so the pointer lands 8-byte aligned.
struct UnicodeStringLayout {
    static constexpr std::size_t kLength = 0;         // USHORT, in bytes
    static constexpr std::size_t kMaximumLength = 2;  // USHORT, in bytes
    static constexpr std::size_t kBuffer = 8;         // PWSTR
    static constexpr std::size_t kBytes = 16;
};

// Writes a `UNICODE_STRING` and the characters it names into one buffer: the
// header first, then the text immediately after it, with the header's buffer
// pointer aimed at the text. The two live in the caller's buffer so that the
// string outlives nothing -- a caller frees its buffer and the string goes
// with it, which is the ownership the API documents.
[[nodiscard]] bool write_unicode_string_in_buffer(
    void* base, std::uint64_t capacity, std::u16string_view text,
    std::uint64_t& used) noexcept {
    // The characters, then the header, then the header's pointer. The chars
    // follow the header so that the whole answer is one contiguous block.
    const std::uint64_t chars = text.size();
    const std::uint64_t need = UnicodeStringLayout::kBytes + (chars + 1) * 2;
    used = need;
    if (capacity < UnicodeStringLayout::kBytes) {
        return false;
    }
    auto* p = static_cast<std::uint8_t*>(base);
    write_u16(p, UnicodeStringLayout::kLength,
              static_cast<std::uint16_t>(chars * 2));
    write_u16(p, UnicodeStringLayout::kMaximumLength,
              static_cast<std::uint16_t>((chars + 1) * 2));
    if (capacity >= need) {
        // The text lives right after the header, in the caller's own buffer;
        // the buffer pointer is a guest address, and the guest's address
        // space is this one, so its address is the host address of that spot.
        std::memcpy(p + UnicodeStringLayout::kBytes, text.data(), chars * 2);
        std::memcpy(p + UnicodeStringLayout::kBytes + chars * 2, "\0\0", 2);
        write_u64(p, UnicodeStringLayout::kBuffer,
                  reinterpret_cast<std::uint64_t>(p + UnicodeStringLayout::kBytes));
        return true;
    }
    // The buffer cannot hold the text: the header reports what it would need,
    // with a null buffer, which is what the kernel's own short-buffer path
    // leaves behind.
    write_u64(p, UnicodeStringLayout::kBuffer, 0);
    return false;
}

// The process this runtime serves, for the calls that ask "which process am
// I". A handle of `NtCurrentProcess()` -- the all-ones pseudo handle -- or the
// current process id both name this process, and both are accepted. Any other
// value is refused rather than silently treated as self, because answering a
// question about another process with the answer for this one is how a
// checker for a remote process is fooled into a wrong conclusion.
[[nodiscard]] bool is_self_process(std::uint64_t handle) noexcept {
    constexpr std::uint64_t kCurrentProcess = ~std::uint64_t{0};
    if (handle == kCurrentProcess) {
        return true;
    }
    if (handle == 0) {
        return false;
    }
    // A handle that is the current process id, or that carries this runtime's
    // own process-handle shape, names this process too. The comparison is
    // against the id rather than a range because the id is the only stable
    // name a caller can pass besides the pseudo handle.
    const std::uint64_t self = k32_GetCurrentProcessId();
    return handle == self;
}

// The window a file handle this runtime issued falls in. The file domain
// mints handles from 0x2000 upwards for a megabyte, which is above the
// standard handles and below the object table, so a handle's namespace is a
// property of its value and not something a table has to be asked about.
constexpr std::uint64_t kFileHandleBase = 0x2000;
constexpr std::uint64_t kFileHandleSpan = 0x100000;

[[nodiscard]] bool is_file_handle(std::uint64_t handle) noexcept {
    return handle >= kFileHandleBase &&
           handle < kFileHandleBase + kFileHandleSpan;
}

[[nodiscard]] std::uint64_t peb_address() noexcept {
    GuestState* g = guest_state();
    return g != nullptr ? g->peb : 0;
}

// The image's DOS path, as the guest sees it. The process-parameters answer
// and the image-file-name answer are both this string.
[[nodiscard]] const std::string& image_path() noexcept {
    static const std::string empty;
    GuestState* g = guest_state();
    return g != nullptr ? g->image_path_dos : empty;
}

// The parent process id, answered the way a launcher reports it. A process
// started by a shell has the shell as its parent; this runtime's guest is
// started by this process, so the answer is the host's parent. Reporting zero
// would claim the process has no creator, which is a state a checker reads as
// "started by the debugger" -- the opposite of what this runtime is claiming.
[[nodiscard]] std::uint32_t parent_process_id() noexcept {
    return static_cast<std::uint32_t>(::getppid());
}

}  // namespace

// ===========================================================================
// NtQueryInformationProcess
// ===========================================================================
//
// The process-information query, which is where a hardened program does most
// of its asking. The classes a defender reads are handled with real answers;
// the classes this runtime does not carry state for answer the invalid-class
// error, which is the kernel's own answer for a class it does not define.

extern "C" __attribute__((ms_abi)) std::uint32_t
nt_NtQueryInformationProcess(std::uint64_t process_handle,
                             std::uint32_t info_class, void* information,
                             std::uint32_t length,
                             std::uint32_t* return_length) noexcept {
    if (!is_self_process(process_handle)) {
        return kStatusInvalidHandle;
    }
    // `ReturnLength` is optional on Windows and is written whenever the caller
    // supplied it, on success and on the length-mismatch failure alike, which
    // is what lets a caller size its buffer by retrying.
    auto report = [return_length](std::uint32_t n) {
        if (return_length != nullptr) {
            *return_length = n;
        }
    };
    auto* out = static_cast<std::uint8_t*>(information);

    switch (info_class) {
    case kProcessBasicInformation: {
        // PROCESS_BASIC_INFORMATION: the exit status, the PEB address, the
        // affinity mask, the base priority, this process's id and its
        // creator's. A program that reads `PebBaseAddress` here expects the
        // same address it finds at `gs:[0x60]`, and it does, because both are
        // this runtime's PEB.
        constexpr std::uint32_t kNeed = 48;
        report(kNeed);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < kNeed) {
            return kStatusInfoLengthMismatch;
        }
        write_u32(out, 0, kStatusSuccess);              // ExitStatus
        write_u64(out, 0x08, peb_address());            // PebBaseAddress
        write_u64(out, 0x10, ~std::uint64_t{0});        // AffinityMask: all
        write_u32(out, 0x18, 8);                        // BasePriority: normal
        write_u64(out, 0x20, k32_GetCurrentProcessId());  // UniqueProcessId
        write_u64(out, 0x28, parent_process_id());      // InheritedFromUniqueProcessId
        return kStatusSuccess;
    }

    case kProcessDebugPort: {
        // A HANDLE-width answer: zero means no debug port, which means no
        // debugger. This is the oldest and most direct of the checks.
        constexpr std::uint32_t kNeed = 8;
        report(kNeed);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < kNeed) {
            return kStatusInfoLengthMismatch;
        }
        write_u64(out, 0, 0);
        return kStatusSuccess;
    }

    case kProcessDebugObjectHandle: {
        // The debug object handle. A process with no debugger has no debug
        // object, and the call fails with `STATUS_PORT_NOT_SET` -- an error,
        // not a zero. A checker distinguishes the two, so the answer is the
        // error.
        constexpr std::uint32_t kNeed = 8;
        report(kNeed);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < kNeed) {
            return kStatusInfoLengthMismatch;
        }
        write_u64(out, 0, 0);
        return kStatusPortNotSet;
    }

    case kProcessDebugFlags: {
        // `NoDebugInherit`. A process that is not being debugged reports one;
        // a debugged process reports zero. One is the unwatched answer.
        constexpr std::uint32_t kNeed = 4;
        report(kNeed);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < kNeed) {
            return kStatusInfoLengthMismatch;
        }
        write_u32(out, 0, 1);
        return kStatusSuccess;
    }

    case kProcessHandleCount: {
        // The number of open handles. A plausible count rather than zero: a
        // process always has a few open, and a checker that reads zero as "the
        // process has been tampered with" should not be told that.
        constexpr std::uint32_t kNeed = 4;
        report(kNeed);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < kNeed) {
            return kStatusInfoLengthMismatch;
        }
        write_u32(out, 0, 16);
        return kStatusSuccess;
    }

    case kProcessWow64Information: {
        // The WOW64 PEB, or zero on a 64-bit process. This runtime executes
        // 64-bit images, so the answer is zero, and a checker that treats a
        // nonzero value as "32-bit process under WOW64" is correctly told it
        // is not.
        constexpr std::uint32_t kNeed = 8;
        report(kNeed);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < kNeed) {
            return kStatusInfoLengthMismatch;
        }
        write_u64(out, 0, 0);
        return kStatusSuccess;
    }

    case kProcessImageFileName:
    case kProcessImageFileNameWin32: {
        // The image's path, as a `UNICODE_STRING` in the caller's buffer. The
        // string is written after the header, inside the same buffer, so a
        // caller that frees the buffer frees the string with it.
        const std::string& path = image_path();
        std::u16string wide;
        static_cast<void>(utf8_to_utf16(path, wide));
        std::uint64_t used = 0;
        const bool fits = write_unicode_string_in_buffer(
            information, length, wide, used);
        report(static_cast<std::uint32_t>(used));
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (!fits) {
            return length < UnicodeStringLayout::kBytes
                       ? kStatusInfoLengthMismatch
                       : kStatusBufferTooSmall;
        }
        return kStatusSuccess;
    }

    case kProcessExecuteFlags: {
        // The process's execute flags. The default is zero on a machine that
        // has not enabled DEP-policy flags, which is the ordinary state.
        constexpr std::uint32_t kNeed = 4;
        report(kNeed);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < kNeed) {
            return kStatusInfoLengthMismatch;
        }
        write_u32(out, 0, 0);
        return kStatusSuccess;
    }

    case kProcessCookie: {
        // The process's cookie, a per-process value the loader mixes into
        // stack cookies. It is stable for the process's life and non-zero;
        // the value itself is the guest's business.
        constexpr std::uint32_t kNeed = 4;
        report(kNeed);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < kNeed) {
            return kStatusInfoLengthMismatch;
        }
        write_u32(out, 0, 0x0DEFACEDu);
        return kStatusSuccess;
    }

    case kProcessIoCounters: {
        // IO_COUNTERS: six 64-bit counters of bytes and operations. Zeroes are
        // the honest reading for a process that has performed no I/O the
        // kernel charged to it through these counters.
        constexpr std::uint32_t kNeed = 48;
        report(kNeed);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < kNeed) {
            return kStatusInfoLengthMismatch;
        }
        std::memset(out, 0, kNeed);
        return kStatusSuccess;
    }

    case kProcessPriorityClass: {
        constexpr std::uint32_t kNeed = 4;
        report(kNeed);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < kNeed) {
            return kStatusInfoLengthMismatch;
        }
        write_u32(out, 0, 2);  // NORMAL_PRIORITY_CLASS
        return kStatusSuccess;
    }

    default:
        // A class this runtime does not answer. The kernel's answer for an
        // unknown class is this error, and answering it is more honest than a
        // zeroed buffer that a caller would read as a real value.
        report(0);
        return kStatusInvalidInfoClass;
    }
}

// ===========================================================================
// NtSetInformationProcess
// ===========================================================================
//
// The process-information setter. A hardened program uses it to turn things
// off -- the execute flags, the debug flags -- and the calls succeeding without
// a reader is the same shape the thread-information setter takes: the state
// the call would set has no observer in a runtime with one process and no
// debugger.

extern "C" __attribute__((ms_abi)) std::uint32_t
nt_NtSetInformationProcess(std::uint64_t process_handle,
                           std::uint32_t info_class, const void* information,
                           std::uint32_t length) noexcept {
    if (!is_self_process(process_handle)) {
        return kStatusInvalidHandle;
    }
    (void)information;
    (void)length;
    switch (info_class) {
    case kProcessExecuteFlags:
    case kProcessPriorityClass:
    case kProcessDebugFlags:
    case 0x01:  // ProcessQuotaLimits
    case 0x03:  // ProcessBasePriority
    case 0x0B:  // ProcessAffinityMask
    case 0x0D:  // ProcessPriorityBoost
    case 0x0E:  // ProcessDefaultHardErrorMode
        // Accepted with no effect. Each names state whose reader is absent
        // here, and a call that succeeded on the kernel succeeding here is
        // what the caller is checking for.
        return kStatusSuccess;
    default:
        return kStatusInvalidInfoClass;
    }
}

// ===========================================================================
// NtQueryObject
// ===========================================================================
//
// The object query. A defender uses it two ways: to learn the *type* of a
// handle it holds, and to enumerate *every* type the system has. The first is
// how the "am I my own debugger" check works -- a process that opened itself
// with `DebugObject` and asks the handle's type is told `DebugObject` only
// when a debug object is really there. The second is the same question asked
// of the whole system, and the answer is checked for a `DebugObject` entry.
//
// This runtime has no debug objects, so neither answer can name one: a handle
// it hands out is a process, a thread, or an object it does not classify, and
// the enumeration lists the ordinary types without a debug object among them.

namespace {

// The object type a handle names. This runtime does not carry a type per
// handle -- the handles it hands out are the ones the file, sync and process
// domains minted, and each of those is a different object on the same pool --
// so the classification is by the handle value's meaning: the two pseudo
// handles the process and thread calls return are named, and everything else
// answers a type that is not `DebugObject`. The generic name is the honest
// answer for a handle whose type this runtime cannot attribute, and it is the
// one that keeps a self-debug check from being told "yes".
[[nodiscard]] const char16_t* object_type_name(std::uint64_t handle) noexcept {
    constexpr std::uint64_t kCurrentProcess = ~std::uint64_t{0};
    constexpr std::uint64_t kCurrentThread = ~std::uint64_t{1};
    if (handle == kCurrentProcess) {
        return u"Process";
    }
    if (handle == kCurrentThread) {
        return u"Thread";
    }
    // A thread this runtime created names a thread, whether or not it is the
    // caller's own.
    if (is_guest_thread_handle(handle)) {
        return u"Thread";
    }
    // A file handle names a file, which is what a program that opened a file
    // and asked its type expects to be told.
    if (is_file_handle(handle)) {
        return u"File";
    }
    // An object from the waitable table names itself by its kind. The mutex
    // is spelled `Mutant` because that is the kernel's name for the type --
    // `Mutex` is the Win32 word for it -- and a checker compares against the
    // kernel's spelling.
    objects::Kind kind{};
    if (objects::kind_of(handle, kind)) {
        switch (kind) {
        case objects::Kind::Mutex:
            return u"Mutant";
        case objects::Kind::Semaphore:
            return u"Semaphore";
        case objects::Kind::Event:
        default:
            return u"Event";
        }
    }
    // Nothing this runtime issued carries the value, so the type is unknown.
    // The name is deliberately not any real type: a checker comparing
    // against `DebugObject` -- which is the whole reason this query is made
    // -- is told a name that is not one.
    return u"Unknown";
}

// Writes an `OBJECT_TYPE_INFORMATION` and the type name it points at into one
// buffer. The structure is a `UNICODE_STRING` and then a run of counters and
// watermarks, laid out at the offsets the guest reads them at.
struct ObjectTypeInfoLayout {
    static constexpr std::size_t kTypeName = 0x00;         // UNICODE_STRING
    static constexpr std::size_t kTotalObjects = 0x10;
    static constexpr std::size_t kTotalHandles = 0x14;
    static constexpr std::size_t kTotalPagedPool = 0x18;
    static constexpr std::size_t kTotalNonPagedPool = 0x1C;
    static constexpr std::size_t kTotalNamePool = 0x20;
    static constexpr std::size_t kTotalHandleTable = 0x24;
    static constexpr std::size_t kHighWaterObjects = 0x28;
    static constexpr std::size_t kHighWaterHandles = 0x2C;
    static constexpr std::size_t kHighWaterPagedPool = 0x30;
    static constexpr std::size_t kHighWaterNonPagedPool = 0x34;
    static constexpr std::size_t kHighWaterNamePool = 0x38;
    static constexpr std::size_t kHighWaterHandleTable = 0x3C;
    static constexpr std::size_t kInvalidAttributes = 0x40;
    static constexpr std::size_t kGenericMapping = 0x44;   // 4 x ULONG
    static constexpr std::size_t kValidAccessMask = 0x54;
    static constexpr std::size_t kSecurityRequired = 0x58;  // BOOLEAN
    static constexpr std::size_t kMaintainHandleCount = 0x59;
    static constexpr std::size_t kTypeIndex = 0x5A;
    static constexpr std::size_t kPoolType = 0x5C;
    static constexpr std::size_t kDefaultPagedPool = 0x60;
    static constexpr std::size_t kDefaultNonPagedPool = 0x64;
    static constexpr std::size_t kBytes = 0x68;
};

// The length of a null-terminated UTF-16 string in bytes, terminator
// excluded, which is the `Length` a `UNICODE_STRING` reports.
[[nodiscard]] std::size_t wide_len(const char16_t* s) noexcept {
    std::size_t n = 0;
    while (s[n] != u'\0') {
        ++n;
    }
    return n;
}

// One object type as the enumeration lists it: the `UNICODE_STRING` header,
// the run of reserved counters, and the name's characters after them, with
// the whole entry padded to an eight-byte multiple so the next begins aligned.
struct PublicObjectTypeLayout {
    static constexpr std::size_t kHeader = 0x68;  // matches the type info
};

// The names the enumeration answers with: the ordinary object types a
// Windows machine has, including `DebugObject`, because the *type* exists on
// every machine -- it is the type of a debug object, not a debugger. What a
// defender reads out of this list is not whether the type is present but
// whether any object of it exists, and none of the entries below reports an
// instance, because this runtime has none to report.
constexpr const char16_t* kObjectTypeNames[] = {
    u"Type",      u"Directory", u"SymbolicLink", u"Token", u"Process",
    u"Thread",    u"Job",       u"DebugObject",  u"Event", u"EventPair",
    u"Mutant",    u"Callback",  u"Semaphore",    u"Timer", u"KeyedEvent",
    u"WindowStation", u"Desktop", u"Section",    u"Key",   u"File",
    u"IoCompletion", u"WaitCompletionPacket", u"Device", u"Driver",
    u"Adapter",   u"Controller", u"WmiGuid",     u"FilterConnectionPort",
};

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtQueryObject(
    std::uint64_t handle, std::uint32_t info_class, void* information,
    std::uint32_t length, std::uint32_t* return_length) noexcept {
    if (handle == 0) {
        return kStatusInvalidHandle;
    }
    auto report = [return_length](std::uint32_t n) {
        if (return_length != nullptr) {
            *return_length = n;
        }
    };
    auto* out = static_cast<std::uint8_t*>(information);

    switch (info_class) {
    case kObjectBasicInformation: {
        // OBJECT_BASIC_INFORMATION: the handle's attributes, its access, its
        // reference counts, and the sizes of the name and type. A handle this
        // runtime minted has no name, so the name length is zero and the type
        // length is what the type query above would return.
        constexpr std::uint32_t kNeed = 0x38;
        report(kNeed);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < kNeed) {
            return kStatusInfoLengthMismatch;
        }
        std::memset(out, 0, kNeed);
        write_u32(out, 0x00, 0);       // Attributes: no inherit, not permanent
        write_u32(out, 0x04, 0x001F0000);  // GrantedAccess: all of a generic
        write_u32(out, 0x08, 1);       // HandleCount
        write_u32(out, 0x0C, 1);       // PointerCount
        write_u32(out, 0x24, 0);       // NameInformationLength: unnamed
        write_u32(out, 0x28, 0);       // TypeInformationLength: filled if asked
        write_u32(out, 0x2C, 0);       // SecurityQuota
        return kStatusSuccess;
    }

    case kObjectNameInformation: {
        // The object's name. Handles this runtime hands out are unnamed, so
        // the answer is an empty `UNICODE_STRING` with a null buffer, which is
        // exactly what the kernel returns for an unnamed object.
        constexpr std::uint32_t kNeed = UnicodeStringLayout::kBytes;
        report(kNeed);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < kNeed) {
            return kStatusInfoLengthMismatch;
        }
        write_u16(out, UnicodeStringLayout::kLength, 0);
        write_u16(out, UnicodeStringLayout::kMaximumLength, 0);
        write_u64(out, UnicodeStringLayout::kBuffer, 0);
        return kStatusSuccess;
    }

    case kObjectTypeInformation: {
        // The type of the handle. The name is written after the structure in
        // the caller's own buffer, and the structure's `TypeName` points at it.
        const char16_t* name = object_type_name(handle);
        const std::size_t chars = wide_len(name);
        const std::uint32_t need = static_cast<std::uint32_t>(
            ObjectTypeInfoLayout::kBytes + (chars + 1) * 2);
        report(need);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < ObjectTypeInfoLayout::kBytes) {
            return kStatusInfoLengthMismatch;
        }
        if (length < need) {
            // The header fits but the name does not: the header is written
            // with a null buffer so the caller can see the size and retry.
            std::memset(out, 0, ObjectTypeInfoLayout::kBytes);
            write_u16(out, ObjectTypeInfoLayout::kTypeName, 0);
            write_u16(out, ObjectTypeInfoLayout::kTypeName + 2, 0);
            write_u64(out, ObjectTypeInfoLayout::kTypeName + 8, 0);
            return kStatusBufferTooSmall;
        }
        std::memset(out, 0, ObjectTypeInfoLayout::kBytes);
        auto* name_at = out + ObjectTypeInfoLayout::kBytes;
        std::memcpy(name_at, name, chars * 2);
        std::memcpy(name_at + chars * 2, "\0\0", 2);
        write_u16(out, ObjectTypeInfoLayout::kTypeName,
                  static_cast<std::uint16_t>(chars * 2));
        write_u16(out, ObjectTypeInfoLayout::kTypeName + 2,
                  static_cast<std::uint16_t>((chars + 1) * 2));
        write_u64(out, ObjectTypeInfoLayout::kTypeName + 8,
                  reinterpret_cast<std::uint64_t>(name_at));
        write_u32(out, ObjectTypeInfoLayout::kTotalObjects, 0);
        write_u32(out, ObjectTypeInfoLayout::kTotalHandles, 1);
        write_u32(out, ObjectTypeInfoLayout::kValidAccessMask, 0x001F0000);
        write_u8(out, ObjectTypeInfoLayout::kSecurityRequired, 0);
        write_u8(out, ObjectTypeInfoLayout::kMaintainHandleCount, 0);
        write_u8(out, ObjectTypeInfoLayout::kTypeIndex, 0);
        write_u32(out, ObjectTypeInfoLayout::kPoolType, 1 /* NonPagedPool */);
        return kStatusSuccess;
    }

    case kObjectTypesInformation: {
        // Every object type, as a count and then one entry per type. Each
        // entry is a `PUBLIC_OBJECT_TYPE_INFORMATION` -- the type's
        // `UNICODE_STRING` and its reserved counters -- followed by the name's
        // characters, padded so the next entry starts aligned. A defender
        // walks this looking for `DebugObject`; there is none, because there
        // is no debug object on this machine.
        const std::size_t count =
            sizeof(kObjectTypeNames) / sizeof(kObjectTypeNames[0]);
        // First pass: the total size, so a short buffer is reported before
        // anything is written.
        std::uint32_t total = 8;  // the count, padded to an 8-byte multiple
        for (std::size_t i = 0; i < count; ++i) {
            const std::size_t chars = wide_len(kObjectTypeNames[i]);
            const std::size_t entry =
                PublicObjectTypeLayout::kHeader + (chars + 1) * 2;
            total += static_cast<std::uint32_t>((entry + 7) & ~std::size_t{7});
        }
        report(total);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < total) {
            return kStatusInfoLengthMismatch;
        }
        std::memset(out, 0, total);
        write_u32(out, 0, static_cast<std::uint32_t>(count));
        std::uint32_t at = 8;
        for (std::size_t i = 0; i < count; ++i) {
            const char16_t* name = kObjectTypeNames[i];
            const std::size_t chars = wide_len(name);
            auto* entry = out + at;
            auto* name_at = entry + PublicObjectTypeLayout::kHeader;
            std::memcpy(name_at, name, chars * 2);
            std::memcpy(name_at + chars * 2, "\0\0", 2);
            write_u16(entry, UnicodeStringLayout::kLength,
                      static_cast<std::uint16_t>(chars * 2));
            write_u16(entry, UnicodeStringLayout::kMaximumLength,
                      static_cast<std::uint16_t>((chars + 1) * 2));
            write_u64(entry, UnicodeStringLayout::kBuffer,
                      reinterpret_cast<std::uint64_t>(name_at));
            const std::size_t entry_bytes =
                PublicObjectTypeLayout::kHeader + (chars + 1) * 2;
            at += static_cast<std::uint32_t>((entry_bytes + 7) &
                                             ~std::size_t{7});
        }
        return kStatusSuccess;
    }

    case kObjectHandleFlagInformation: {
        // OBJECT_HANDLE_FLAG_INFORMATION: two booleans, whether the handle is
        // inherited and whether it is protected from close. This runtime's
        // handles are neither.
        constexpr std::uint32_t kNeed = 2;
        report(kNeed);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < kNeed) {
            return kStatusInfoLengthMismatch;
        }
        write_u8(out, 0, 0);
        write_u8(out, 1, 0);
        return kStatusSuccess;
    }

    default:
        return kStatusInvalidInfoClass;
    }
}

// ===========================================================================
// NtQuerySystemInformation
// ===========================================================================
//
// The system query, which is where a defender asks about the machine rather
// than about itself. The kernel debugger's state is the answer a packer reads
// to decide whether the machine is being debugged at the kernel level, and the
// module list is the one it reads to look for a sandbox's drivers. Both answer
// the clean-machine value, and the classes this runtime does not model answer
// the invalid-class error rather than a buffer of zeroes.

namespace {

// A kernel module, for the module enumeration below. The base addresses live
// in the kernel's own range -- above the user address space -- because that is
// where `SystemModuleInformation` lists them and a caller that range-checks
// them expects them there.
struct KernelModule {
    const char* path;
    std::uint64_t base;
    std::uint32_t size;
};

// The modules a stock Windows kernel carries. The list is the one a defender
// compares a sandbox's driver names against, so it names the ordinary set and
// nothing a virtual machine or a sandbox adds: no `VBoxGuest`, no `vmci`, no
// `SbieDrv`, which is the answer a machine that is neither would give.
constexpr KernelModule kKernelModules[] = {
    {"\\SystemRoot\\system32\\ntoskrnl.exe", 0xFFFFF80000000000ULL, 0x00C00000},
    {"\\SystemRoot\\system32\\hal.dll", 0xFFFFF80000C00000ULL, 0x00080000},
    {"\\SystemRoot\\system32\\kd.dll", 0xFFFFF80000C80000ULL, 0x00030000},
    {"\\SystemRoot\\system32\\ci.dll", 0xFFFFF80000CB0000ULL, 0x00080000},
    {"\\SystemRoot\\system32\\pshed.dll", 0xFFFFF80000D30000ULL, 0x00010000},
    {"\\SystemRoot\\system32\\clfs.sys", 0xFFFFF80000D40000ULL, 0x00060000},
    {"\\SystemRoot\\system32\\drivers\\acpi.sys", 0xFFFFF80000DA0000ULL, 0x000A0000},
    {"\\SystemRoot\\system32\\drivers\\msrpc.sys", 0xFFFFF80000E40000ULL, 0x00050000},
    {"\\SystemRoot\\system32\\drivers\\ksecdd.sys", 0xFFFFF80000E90000ULL, 0x00040000},
    {"\\SystemRoot\\system32\\drivers\\werkernel.sys", 0xFFFFF80000ED0000ULL, 0x00020000},
    {"\\SystemRoot\\system32\\drivers\\fltmgr.sys", 0xFFFFF80000EF0000ULL, 0x00070000},
    {"\\SystemRoot\\system32\\drivers\\ndis.sys", 0xFFFFF80000F60000ULL, 0x00100000},
    {"\\SystemRoot\\system32\\drivers\\tcpip.sys", 0xFFFFF80001060000ULL, 0x00140000},
    {"\\SystemRoot\\system32\\drivers\\ntfs.sys", 0xFFFFF800011A0000ULL, 0x00160000},
    {"\\SystemRoot\\System32\\drivers\\volmgr.sys", 0xFFFFF80001300000ULL, 0x00040000},
    {"\\SystemRoot\\system32\\drivers\\volsnap.sys", 0xFFFFF80001340000ULL, 0x00060000},
};

// The layout of one `RTL_PROCESS_MODULE_INFORMATION` and of the array it
// heads. Each entry is a fixed 0x128 bytes: a 0x28 header and a 256-byte path.
struct ProcessModuleLayout {
    static constexpr std::size_t kSection = 0x00;
    static constexpr std::size_t kMappedBase = 0x08;
    static constexpr std::size_t kImageBase = 0x10;
    static constexpr std::size_t kImageSize = 0x18;
    static constexpr std::size_t kFlags = 0x1C;
    static constexpr std::size_t kLoadOrderIndex = 0x20;
    static constexpr std::size_t kInitOrderIndex = 0x22;
    static constexpr std::size_t kLoadCount = 0x24;
    static constexpr std::size_t kOffsetToFileName = 0x26;
    static constexpr std::size_t kFullPathName = 0x28;
    static constexpr std::size_t kPathBytes = 256;
    static constexpr std::size_t kBytes = 0x28 + kPathBytes;  // 0x128
};

// The current time as a `FILETIME` count: 100-nanosecond units since 1601.
[[nodiscard]] std::uint64_t now_filetime() noexcept {
    struct timespec ts;
    ::clock_gettime(CLOCK_REALTIME, &ts);
    constexpr std::uint64_t kEpochTo1601 = 11644473600ULL;
    return (static_cast<std::uint64_t>(ts.tv_sec) + kEpochTo1601) * 10000000ULL +
           static_cast<std::uint64_t>(ts.tv_nsec) / 100ULL;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtQuerySystemInformation(
    std::uint32_t info_class, void* information, std::uint32_t length,
    std::uint32_t* return_length) noexcept {
    auto report = [return_length](std::uint32_t n) {
        if (return_length != nullptr) {
            *return_length = n;
        }
    };
    auto* out = static_cast<std::uint8_t*>(information);

    switch (info_class) {
    case kSystemBasicInformation: {
        // SYSTEM_BASIC_INFORMATION. Modern Windows keeps only a fraction of
        // this structure alive, but a caller still reads the page size, the
        // granularity and the processor count out of it.
        constexpr std::uint32_t kNeed = 0x40;
        report(kNeed);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < kNeed) {
            return kStatusInfoLengthMismatch;
        }
        std::memset(out, 0, kNeed);
        write_u32(out, 0x00, 0);            // Reserved
        write_u32(out, 0x04, 156250);       // TimerResolution (100ns units)
        write_u32(out, 0x08, 4096);         // PageSize
        write_u32(out, 0x0C, 0x400000);     // NumberOfPhysicalPages
        write_u32(out, 0x10, 1);            // LowestPhysicalPageNumber
        write_u32(out, 0x14, 0x400000);     // HighestPhysicalPageNumber
        write_u32(out, 0x18, 0x10000);      // AllocationGranularity (64 KiB)
        write_u64(out, 0x20, 0x10000);      // MinimumUserModeAddress
        write_u64(out, 0x28, 0x00007FFFFFFEFFFFULL);  // MaximumUserModeAddress
        write_u64(out, 0x30, 1);            // ActiveProcessorsAffinityMask
        write_u8(out, 0x38, 1);             // NumberOfProcessors
        return kStatusSuccess;
    }

    case kSystemProcessorInformation: {
        // SYSTEM_PROCESSOR_INFORMATION. The architecture is AMD64, which is
        // what a 64-bit guest must be told it runs on.
        constexpr std::uint32_t kNeed = 12;
        report(kNeed);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < kNeed) {
            return kStatusInfoLengthMismatch;
        }
        std::memset(out, 0, kNeed);
        write_u16(out, 0x00, 9);   // PROCESSOR_ARCHITECTURE_AMD64
        write_u16(out, 0x02, 6);   // ProcessorLevel
        write_u16(out, 0x04, 0x3F00);  // ProcessorRevision
        write_u16(out, 0x06, 64);  // MaximumProcessors
        write_u32(out, 0x08, 0);   // ProcessorFeatureBits
        return kStatusSuccess;
    }

    case kSystemPerformanceInformation: {
        // SYSTEM_PERFORMANCE_INFORMATION. This runtime does not instrument the
        // kernel, so the counters are the zeros a freshly booted machine would
        // report for the ones the kernel has not touched.
        constexpr std::uint32_t kNeed = 0x150;
        report(kNeed);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < kNeed) {
            return kStatusInfoLengthMismatch;
        }
        std::memset(out, 0, kNeed);
        return kStatusSuccess;
    }

    case kSystemTimeOfDayInformation: {
        // SYSTEM_TIMEOFDAY_INFORMATION: when the machine booted, what time it
        // is now, and the zone it is in. The current time is the host clock;
        // the boot time is projected from the uptime so that "now minus boot"
        // is the uptime a machine would report.
        constexpr std::uint32_t kNeed = 0x30;
        report(kNeed);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < kNeed) {
            return kStatusInfoLengthMismatch;
        }
        struct timespec up;
        ::clock_gettime(CLOCK_MONOTONIC, &up);
        const std::uint64_t uptime_100ns =
            static_cast<std::uint64_t>(up.tv_sec) * 10000000ULL +
            static_cast<std::uint64_t>(up.tv_nsec) / 100ULL;
        const std::uint64_t now = now_filetime();
        std::memset(out, 0, kNeed);
        write_u64(out, 0x00, now >= uptime_100ns ? now - uptime_100ns : 0);
        write_u64(out, 0x08, now);
        write_u64(out, 0x10, 0);   // TimeZoneBias
        write_u32(out, 0x18, 0);   // TimeZoneId: UTC
        write_u32(out, 0x1C, 0);   // Reserved
        write_u64(out, 0x20, 0);   // BootTimeBias
        write_u64(out, 0x28, 0);   // SleepTimeBias
        return kStatusSuccess;
    }

    case kSystemModuleInformation: {
        // RTL_PROCESS_MODULES: the kernel's loaded modules. A defender walks
        // this looking for a sandbox's or a hypervisor's driver; the list
        // below is a stock kernel's, with none of those in it.
        const std::size_t count =
            sizeof(kKernelModules) / sizeof(kKernelModules[0]);
        const std::uint32_t total = static_cast<std::uint32_t>(
            8 + count * ProcessModuleLayout::kBytes);
        report(total);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < total) {
            return kStatusInfoLengthMismatch;
        }
        std::memset(out, 0, total);
        write_u32(out, 0, static_cast<std::uint32_t>(count));
        for (std::size_t i = 0; i < count; ++i) {
            const KernelModule& m = kKernelModules[i];
            auto* entry = out + 8 + i * ProcessModuleLayout::kBytes;
            write_u64(entry, ProcessModuleLayout::kSection, 0);
            write_u64(entry, ProcessModuleLayout::kMappedBase, 0);
            write_u64(entry, ProcessModuleLayout::kImageBase, m.base);
            write_u32(entry, ProcessModuleLayout::kImageSize, m.size);
            write_u32(entry, ProcessModuleLayout::kFlags, 0x0400);  // driver
            write_u16(entry, ProcessModuleLayout::kLoadOrderIndex,
                      static_cast<std::uint16_t>(i));
            write_u16(entry, ProcessModuleLayout::kInitOrderIndex,
                      static_cast<std::uint16_t>(i));
            write_u16(entry, ProcessModuleLayout::kLoadCount, 1);
            // The file name's offset within the path, which is where the last
            // backslash ends.
            const std::string path = m.path;
            std::size_t slash = path.rfind('\\');
            const std::size_t name_off = slash == std::string::npos ? 0 : slash + 1;
            write_u16(entry, ProcessModuleLayout::kOffsetToFileName,
                      static_cast<std::uint16_t>(name_off));
            std::memcpy(entry + ProcessModuleLayout::kFullPathName, path.data(),
                        std::min<std::size_t>(path.size(),
                                              ProcessModuleLayout::kPathBytes - 1));
        }
        return kStatusSuccess;
    }

    case kSystemKernelDebuggerInformation: {
        // SYSTEM_KERNEL_DEBUGGER_INFORMATION: two booleans, whether the kernel
        // debugger is enabled and whether it is not present. A machine without
        // `bcdedit /debug on` answers "not enabled, not present".
        constexpr std::uint32_t kNeed = 2;
        report(kNeed);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < kNeed) {
            return kStatusInfoLengthMismatch;
        }
        write_u8(out, 0, 0);  // DebuggerEnabled
        write_u8(out, 1, 1);  // DebuggerNotPresent
        return kStatusSuccess;
    }

    case kSystemKernelDebuggerInformationEx: {
        // SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX: allowed, enabled, present.
        // A machine that permits a kernel debugger but has none running
        // answers "not enabled, not present".
        constexpr std::uint32_t kNeed = 3;
        report(kNeed);
        if (information == nullptr) {
            return kStatusInvalidParameter;
        }
        if (length < kNeed) {
            return kStatusInfoLengthMismatch;
        }
        write_u8(out, 0, 0);  // DebuggerAllowed
        write_u8(out, 1, 0);  // DebuggerEnabled
        write_u8(out, 2, 0);  // DebuggerPresent
        return kStatusSuccess;
    }

    default:
        return kStatusInvalidInfoClass;
    }
}

// ===========================================================================
// NtQueryVirtualMemory, NtQuerySection and the volume query
// ===========================================================================
//
// These three are the "what is at this address, what is this object, what is
// this volume" family. The memory query is the one a defender leans on hardest
// -- it compares the protection of its own image against what it expects,
// looking for a page an interceptor made writable -- so it answers from the
// same region ledger the loader built, which is what makes the answer agree
// with a `VirtualQuery` the program performed itself.

extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtQueryVirtualMemory(
    std::uint64_t process_handle, const void* base_address,
    std::uint32_t info_class, void* buffer, std::uint64_t length,
    std::uint64_t* return_length) noexcept {
    if (!is_self_process(process_handle)) {
        return kStatusInvalidHandle;
    }
    GuestState* g = guest_state();
    if (g == nullptr || g->space == nullptr || g->mapper == nullptr) {
        return kStatusInvalidParameter;
    }
    NtContext ctx;
    ctx.space = g->space;
    ctx.placement = g->mapper;
    std::uint64_t got = 0;
    const Result<std::uint64_t> r = nt_query_virtual_memory(
        ctx, reinterpret_cast<std::uint64_t>(base_address),
        static_cast<MemoryInformationClass>(info_class), buffer, length, &got);
    if (return_length != nullptr) {
        *return_length = got;
    }
    if (!r.ok()) {
        return static_cast<std::uint32_t>(r.status);
    }
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtQuerySection(
    std::uint64_t section_handle, std::uint32_t info_class, void* buffer,
    std::uint64_t length, std::uint64_t* return_length) noexcept {
    // This runtime hands out no section handles to a guest: the sections a
    // program creates through `NtCreateSection` are the concern of a loader
    // that does not create them, so there is no handle here that names one.
    // A query for one is answered the way the kernel answers a handle that
    // names no section -- with the invalid-handle status -- rather than with
    // a zeroed structure a caller would read as a real section.
    (void)section_handle;
    (void)info_class;
    (void)buffer;
    (void)length;
    if (return_length != nullptr) {
        *return_length = 0;
    }
    return kStatusInvalidHandle;
}

extern "C" __attribute__((ms_abi)) std::uint32_t
nt_NtQueryVolumeInformationFile(std::uint64_t file_handle,
                                void* io_status_block, void* fs_information,
                                std::uint32_t length,
                                std::uint32_t fs_info_class) noexcept {
    // The IO_STATUS_BLOCK's status field is the first thing a caller reads,
    // and a caller that got a status in the return value still reads it here;
    // writing it keeps the two in agreement.
    auto set_io_status = [io_status_block](std::uint32_t status,
                                           std::uint64_t info) {
        if (io_status_block != nullptr) {
            auto* p = static_cast<std::uint8_t*>(io_status_block);
            write_u64(p, 0, status);
            write_u64(p, 8, info);
        }
    };
    if (!is_file_handle(file_handle)) {
        set_io_status(kStatusInvalidHandle, 0);
        return kStatusInvalidHandle;
    }
    auto* out = static_cast<std::uint8_t*>(fs_information);
    switch (fs_info_class) {
    case 1: {  // FileFsVolumeInformation
        // The volume's serial number and label. The serial is a fixed value:
        // an anti-VM check compares it against the serials a virtual disk
        // reports, and a number that is none of those is the answer a machine
        // with a physical disk gives.
        const std::u16string label = u"";
        const std::uint32_t need =
            static_cast<std::uint32_t>(0x14 + (label.size() + 1) * 2);
        if (out == nullptr || length < need) {
            set_io_status(kStatusInfoLengthMismatch, 0);
            return kStatusInfoLengthMismatch;
        }
        std::memset(out, 0, need);
        write_u64(out, 0x00, now_filetime());   // VolumeCreationTime
        write_u32(out, 0x08, 0x7C3A1F02u);      // VolumeSerialNumber
        write_u32(out, 0x0C, 0);                // VolumeLabelLength
        write_u8(out, 0x10, 0);                 // SupportsObjects
        set_io_status(kStatusSuccess, need);
        return kStatusSuccess;
    }
    case 3: {  // FileFsSizeInformation
        constexpr std::uint32_t kNeed = 0x18;
        if (out == nullptr || length < kNeed) {
            set_io_status(kStatusInfoLengthMismatch, 0);
            return kStatusInfoLengthMismatch;
        }
        std::memset(out, 0, kNeed);
        write_u64(out, 0x00, 0x0EEEE000ULL);  // TotalAllocationUnits
        write_u64(out, 0x08, 0x05000000ULL);  // AvailableAllocationUnits
        write_u32(out, 0x10, 8);              // SectorsPerAllocationUnit
        write_u32(out, 0x14, 512);            // BytesPerSector
        set_io_status(kStatusSuccess, kNeed);
        return kStatusSuccess;
    }
    case 4: {  // FileFsDeviceInformation
        constexpr std::uint32_t kNeed = 8;
        if (out == nullptr || length < kNeed) {
            set_io_status(kStatusInfoLengthMismatch, 0);
            return kStatusInfoLengthMismatch;
        }
        std::memset(out, 0, kNeed);
        write_u32(out, 0x00, 7);   // FILE_DEVICE_DISK
        write_u32(out, 0x04, 0);   // Characteristics
        set_io_status(kStatusSuccess, kNeed);
        return kStatusSuccess;
    }
    case 5: {  // FileFsAttributeInformation
        const std::u16string fs_name = u"NTFS";
        const std::uint32_t need =
            static_cast<std::uint32_t>(0x0C + (fs_name.size() + 1) * 2);
        if (out == nullptr || length < need) {
            set_io_status(kStatusInfoLengthMismatch, 0);
            return kStatusInfoLengthMismatch;
        }
        std::memset(out, 0, need);
        write_u32(out, 0x00, 0x000700FFu);  // FileSystemAttributes
        write_u32(out, 0x04, 255);          // MaximumComponentNameLength
        write_u32(out, 0x08,
                  static_cast<std::uint32_t>(fs_name.size() * 2));
        std::memcpy(out + 0x0C, fs_name.data(), fs_name.size() * 2);
        set_io_status(kStatusSuccess, need);
        return kStatusSuccess;
    }
    default:
        set_io_status(kStatusInvalidInfoClass, 0);
        return kStatusInvalidInfoClass;
    }
}

// ===========================================================================
// NtClose
// ===========================================================================
//
// The close, and one of the sharper anti-debug probes. A process that closes
// a handle which names nothing gets `STATUS_INVALID_HANDLE` back on a machine
// with no debugger; on a machine with one, the kernel raises an exception
// first, and a program that wrapped the call in `__try`/`__except` reads the
// exception as "a debugger is here". The answer below is the no-debugger one:
// a handle this runtime did not issue is refused with the status, and no
// exception is raised.

extern "C" __attribute__((ms_abi)) std::int32_t k32_CloseHandle(
    std::uint64_t handle) noexcept;

extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtClose(
    std::uint64_t handle) noexcept {
    constexpr std::uint64_t kCurrentProcess = ~std::uint64_t{0};
    constexpr std::uint64_t kCurrentThread = ~std::uint64_t{1};
    if (handle == 0) {
        return kStatusInvalidHandle;
    }
    // The two pseudo handles name the running process and thread and cannot
    // be closed: the kernel refuses them, and so does this.
    if (handle == kCurrentProcess || handle == kCurrentThread) {
        return kStatusInvalidHandle;
    }
    // A handle in the range this runtime issues is released through the same
    // path `CloseHandle` uses, so that one close and the other cannot leave
    // the object table in two different states.
    if (handle < 0x10000000) {
        (void)k32_CloseHandle(handle);
        return kStatusSuccess;
    }
    // Anything above the range this runtime issues names no object here, and
    // the kernel's answer for that is the invalid-handle status.
    return kStatusInvalidHandle;
}

// ===========================================================================
// The clock, the locale and the yield
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtQueryPerformanceCounter(
    void* counter, void* frequency) noexcept {
    // The performance counter is the host's monotonic clock expressed in
    // 100-nanosecond units, and the frequency is the fixed 10 MHz every
    // Windows machine reports. A caller that times itself with these gets the
    // real elapsed time, which is what makes a timing check see a program
    // that actually ran rather than one that was stepped.
    if (counter == nullptr) {
        return kStatusInvalidParameter;
    }
    struct timespec ts;
    ::clock_gettime(CLOCK_MONOTONIC, &ts);
    const std::uint64_t ticks =
        static_cast<std::uint64_t>(ts.tv_sec) * 10000000ULL +
        static_cast<std::uint64_t>(ts.tv_nsec) / 100ULL;
    write_u64(counter, 0, ticks);
    if (frequency != nullptr) {
        write_u64(frequency, 0, 10000000ULL);
    }
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtQuerySystemTime(
    void* system_time) noexcept {
    if (system_time == nullptr) {
        return kStatusInvalidParameter;
    }
    write_u64(system_time, 0, now_filetime());
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtQueryDefaultLocale(
    std::uint32_t user_default, void* locale_id) noexcept {
    (void)user_default;
    if (locale_id == nullptr) {
        return kStatusInvalidParameter;
    }
    // The default locale is the one a machine with the US English settings
    // reports: 0x0409, the language id for English (United States).
    write_u32(locale_id, 0, 0x0409);
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtYieldExecution() noexcept {
    // The yield itself is the host's scheduler's: giving up the processor
    // here hands it to whatever the host runs next, which is what the call
    // asks for. The status reports that a switch happened, which is the
    // ordinary outcome of a yield under load.
    sched_yield();
    return kStatusSuccess;
}

// ===========================================================================
// NtQueryInformationJobObject
// ===========================================================================
//
// A process that is not a member of a job has no job to describe, and the
// kernel answers a query for one with the invalid-handle status. A sandbox
// frequently places the processes it starts into a job, so "there is no job"
// is itself the answer a machine outside a sandbox gives.

extern "C" __attribute__((ms_abi)) std::uint32_t
nt_NtQueryInformationJobObject(std::uint64_t job_handle,
                               std::uint32_t info_class, void* information,
                               std::uint32_t length,
                               std::uint32_t* return_length) noexcept {
    (void)job_handle;
    (void)info_class;
    (void)information;
    (void)length;
    if (return_length != nullptr) {
        *return_length = 0;
    }
    return kStatusInvalidHandle;
}

// ===========================================================================
// NtCreateThreadEx
// ===========================================================================
//
// The modern thread creation, whose flags a hardened program sets to hide a
// worker thread from a debugger. The thread is created through the same path
// `CreateThread` uses, so that a thread made here and a thread made there are
// one kind of thread; the hide-from-debugger flag is accepted without an
// observer to hide from, which is the same shape the thread-information setter
// takes.

extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtCreateThreadEx(
    void* thread_handle, std::uint32_t desired_access, void* object_attributes,
    std::uint64_t process_handle, std::uint64_t start_routine, void* argument,
    std::uint32_t create_flags, std::uint64_t zero_bits,
    std::uint64_t stack_size, std::uint64_t maximum_stack_size,
    void* attribute_list) noexcept {
    (void)desired_access;
    (void)object_attributes;
    (void)zero_bits;
    (void)maximum_stack_size;
    (void)attribute_list;
    if (thread_handle == nullptr) {
        return kStatusInvalidParameter;
    }
    if (!is_self_process(process_handle)) {
        write_u64(thread_handle, 0, 0);
        return kStatusInvalidHandle;
    }
    // THREAD_CREATE_FLAGS_CREATE_SUSPENDED is bit 0 of the create flags; the
    // rest -- hide-from-debugger, skip-attach -- select behaviours this
    // runtime has no observer for and no second thread to attach.
    constexpr std::uint32_t kCreateSuspended = 0x00000001;
    GuestThreadRequest request;
    request.start = start_routine;
    request.parameter = reinterpret_cast<std::uint64_t>(argument);
    request.stack_size = stack_size;
    request.suspended = (create_flags & kCreateSuspended) != 0;
    std::uint32_t id = 0;
    const std::uint64_t handle = create_guest_thread(request, &id);
    if (handle == 0) {
        write_u64(thread_handle, 0, 0);
        return kStatusNoMemory;
    }
    write_u64(thread_handle, 0, handle);
    return kStatusSuccess;
}

// ===========================================================================
// The registration
// ===========================================================================

void add_ntdll_antidebug(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    const auto pair = [&e](const char* nt_name, const char* zw_name, void* fn) {
        e(nt_name, fn);
        e(zw_name, fn);
    };
    // The process-information pair, which is the heart of the answering.
    pair("NtQueryInformationProcess", "ZwQueryInformationProcess",
         reinterpret_cast<void*>(&nt_NtQueryInformationProcess));
    pair("NtSetInformationProcess", "ZwSetInformationProcess",
         reinterpret_cast<void*>(&nt_NtSetInformationProcess));
    // The object query, whose type answer a self-debug check reads.
    pair("NtQueryObject", "ZwQueryObject",
         reinterpret_cast<void*>(&nt_NtQueryObject));
    // The system query, whose kernel-debugger answer a checker reads.
    pair("NtQuerySystemInformation", "ZwQuerySystemInformation",
         reinterpret_cast<void*>(&nt_NtQuerySystemInformation));
    // The memory and section queries.
    pair("NtQueryVirtualMemory", "ZwQueryVirtualMemory",
         reinterpret_cast<void*>(&nt_NtQueryVirtualMemory));
    pair("NtQuerySection", "ZwQuerySection",
         reinterpret_cast<void*>(&nt_NtQuerySection));
    pair("NtQueryVolumeInformationFile", "ZwQueryVolumeInformationFile",
         reinterpret_cast<void*>(&nt_NtQueryVolumeInformationFile));
    // The close, whose invalid-handle answer an exception-based check reads.
    pair("NtClose", "ZwClose", reinterpret_cast<void*>(&nt_NtClose));
    // The clock, the locale and the yield.
    pair("NtQueryPerformanceCounter", "ZwQueryPerformanceCounter",
         reinterpret_cast<void*>(&nt_NtQueryPerformanceCounter));
    pair("NtQuerySystemTime", "ZwQuerySystemTime",
         reinterpret_cast<void*>(&nt_NtQuerySystemTime));
    pair("NtQueryDefaultLocale", "ZwQueryDefaultLocale",
         reinterpret_cast<void*>(&nt_NtQueryDefaultLocale));
    pair("NtYieldExecution", "ZwYieldExecution",
         reinterpret_cast<void*>(&nt_NtYieldExecution));
    // The job query and the modern thread creation.
    pair("NtQueryInformationJobObject", "ZwQueryInformationJobObject",
         reinterpret_cast<void*>(&nt_NtQueryInformationJobObject));
    pair("NtCreateThreadEx", "ZwCreateThreadEx",
         reinterpret_cast<void*>(&nt_NtCreateThreadEx));
}

}  // namespace occ::runtime::winabi

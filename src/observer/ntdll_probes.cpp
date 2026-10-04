#include "occ/observer/ntdll_probes.h"

#include <array>

namespace occ::obs {

namespace {

// The table.
//
// Every symbol here was checked against the dynamic symbol table of a real
// Wine build's x86_64-unix/ntdll.so, and every one of them is a defined
// function symbol. A name that does not exist would produce no probe and no
// error, which is the worst kind of mistake in a table like this: the run
// looks like it worked and one of the things it was supposed to watch was
// never watched. So the names are not remembered or guessed at.
//
// The argument names are the Windows prototypes', because that is the
// interface the target believes it is calling. Where the Unix side's
// signature differs the first arguments are still the ones the Windows
// caller passed, which is what a probe reads.
//
// Ordered by category rather than alphabetically, so that a reader looking
// for "what does this watch for files" reads one contiguous block.
constexpr NtdllProbe kProbes[] = {
    // ------------------------------------------------------------- files
    {"NtCreateFile", "NtCreateFile", ProbeCategory::File,
     "FileHandle", "DesiredAccess", "ObjectAttributes", "IoStatusBlock",
     "AllocationSize", "FileAttributes",
     "The one call every file open goes through, including the loader's. "
     "The name is inside the OBJECT_ATTRIBUTES the third argument points "
     "at, which is why this probe reports a pointer rather than a path."},
    {"NtOpenFile", "NtOpenFile", ProbeCategory::File,
     "FileHandle", "DesiredAccess", "ObjectAttributes", "IoStatusBlock",
     "ShareAccess", "OpenOptions",
     "Opening an existing file, as distinct from creating one. A program "
     "that reads a configuration file it did not write comes through here."},
    {"NtReadFile", "NtReadFile", ProbeCategory::File,
     "FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock",
     "Buffer",
     "Every read, including the reads a loader makes. The handle is what "
     "ties this back to the open that produced it."},
    {"NtWriteFile", "NtWriteFile", ProbeCategory::File,
     "FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock",
     "Buffer",
     "Every write. For a program whose observable effect is a file it "
     "produces, this is the call that produces it."},
    {"NtQueryInformationFile", "NtQueryInformationFile", ProbeCategory::File,
     "FileHandle", "IoStatusBlock", "FileInformation", "Length",
     "FileInformationClass", "",
     "How a program finds out a file's size, type, or attributes. A "
     "program that behaves differently based on them does it here."},
    {"NtSetInformationFile", "NtSetInformationFile", ProbeCategory::File,
     "FileHandle", "IoStatusBlock", "FileInformation", "Length",
     "FileInformationClass", "",
     "Rename, delete-on-close, and the other changes a handle can make to "
     "the file behind it."},
    {"NtQueryAttributesFile", "NtQueryAttributesFile", ProbeCategory::File,
     "ObjectAttributes", "FileInformation", "", "", "", "",
     "A stat without an open. Seen before the open in a run, it is a "
     "program checking whether something exists."},
    {"NtQueryFullAttributesFile", "NtQueryFullAttributesFile",
     ProbeCategory::File, "ObjectAttributes", "FileInformation", "", "", "",
     "",
     "The same query with the full information set, which is what a program "
     "uses when it wants the size before it opens."},
    {"NtQueryDirectoryFile", "NtQueryDirectoryFile", ProbeCategory::File,
     "FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock",
     "FileInformation",
     "Directory listing, which is how a program discovers what it was not "
     "told about. Repeated calls are one enumeration."},
    {"NtDeviceIoControlFile", "NtDeviceIoControlFile", ProbeCategory::File,
     "FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock",
     "IoControlCode",
     "The ioctl path. A Windows program that talks to a device driver "
     "arrives here even when the device is one Wine emulates."},
    {"NtFsControlFile", "NtFsControlFile", ProbeCategory::File,
     "FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock",
     "FsControlCode",
     "Filesystem control, which is where reparse points and mount points "
     "are handled."},
    {"NtLockFile", "NtLockFile", ProbeCategory::File,
     "FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock",
     "ByteOffset",
     "Taking a byte-range lock. Relevant to a program that coordinates with "
     "another through a file."},
    {"NtUnlockFile", "NtUnlockFile", ProbeCategory::File,
     "FileHandle", "IoStatusBlock", "ByteOffset", "Length", "Key", "",
     "Releasing one."},
    {"NtFlushBuffersFile", "NtFlushBuffersFile", ProbeCategory::File,
     "FileHandle", "IoStatusBlock", "", "", "", "",
     "An explicit flush. A program that calls this is one that cares "
     "whether its writes reached the disk."},
    {"NtDeleteFile", "NtDeleteFile", ProbeCategory::File,
     "ObjectAttributes", "", "", "", "", "",
     "Deleting by name rather than by handle."},
    {"NtClose", "NtClose", ProbeCategory::File,
     "Handle", "", "", "", "", "",
     "Every handle close, of every kind. Paired with the calls that opened "
     "them it is how a reader sees lifetime, and an unbalanced count is a "
     "leak."},
    {"NtCreateNamedPipeFile", "NtCreateNamedPipeFile", ProbeCategory::File,
     "FileHandle", "DesiredAccess", "ObjectAttributes", "IoStatusBlock",
     "ShareAccess", "OpenOptions",
     "Named pipes, which on Wine are emulated and which a program using "
     "them treats as its cross-process mechanism."},
    {"NtCreateMailslotFile", "NtCreateMailslotFile", ProbeCategory::File,
     "FileHandle", "DesiredAccess", "ObjectAttributes", "IoStatusBlock",
     "ShareAccess", "OpenOptions",
     "Mailslots, the one-way counterpart."},

    // ----------------------------------------------------------- process
    {"NtCreateUserProcess", "NtCreateUserProcess", ProbeCategory::Process,
     "ProcessHandle", "ThreadHandle", "ProcessDesiredAccess",
     "ThreadDesiredAccess", "ProcessObjectAttributes",
     "ThreadObjectAttributes",
     "The single call that creates a Windows process, and the one that "
     "replaces the old fork-then-exec pair. A child of the target arrives "
     "here."},
    {"NtOpenProcess", "NtOpenProcess", ProbeCategory::Process,
     "ProcessHandle", "DesiredAccess", "ObjectAttributes", "ClientId", "",
     "",
     "Opening a handle to a process, which is the first step of inspecting "
     "or manipulating another one."},
    {"NtTerminateProcess", "NtTerminateProcess", ProbeCategory::Process,
     "ProcessHandle", "ExitStatus", "", "", "", "",
     "A process ending, whether its own or another's. The exit status says "
     "which."},
    {"NtQueryInformationProcess", "NtQueryInformationProcess",
     ProbeCategory::Process, "ProcessHandle", "ProcessInformationClass",
     "ProcessInformation", "ProcessInformationLength",
     "ReturnLength", "",
     "The query a Windows program makes about a process, including whether "
     "it is being debugged."},
    {"NtSetInformationProcess", "NtSetInformationProcess",
     ProbeCategory::Process, "ProcessHandle", "ProcessInformationClass",
     "ProcessInformation", "ProcessInformationLength", "", "",
     "The setter, including the debug-port and affinity settings that "
     "change how the process runs."},
    {"NtCreateThreadEx", "NtCreateThreadEx", ProbeCategory::Process,
     "ThreadHandle", "DesiredAccess", "ObjectAttributes", "ProcessHandle",
     "StartRoutine", "Argument",
     "Starting a thread in a process. The start address is the interesting "
     "field: it names the code the thread runs."},
    {"NtOpenThread", "NtOpenThread", ProbeCategory::Process,
     "ThreadHandle", "DesiredAccess", "ObjectAttributes", "ClientId", "",
     "",
     "Opening a handle to a thread."},
    {"NtTerminateThread", "NtTerminateThread", ProbeCategory::Process,
     "ThreadHandle", "ExitStatus", "", "", "", "",
     "A thread ending."},
    {"NtSuspendThread", "NtSuspendThread", ProbeCategory::Process,
     "ThreadHandle", "PreviousSuspendCount", "", "", "", "",
     "Suspending a thread. Together with resume it is what an injector "
     "does before it writes memory."},
    {"NtResumeThread", "NtResumeThread", ProbeCategory::Process,
     "ThreadHandle", "PreviousSuspendCount", "", "", "", "",
     "Resuming one."},
    {"NtQueryInformationThread", "NtQueryInformationThread",
     ProbeCategory::Process, "ThreadHandle", "ThreadInformationClass",
     "ThreadInformation", "ThreadInformationLength", "ReturnLength", "",
     "Querying a thread."},
    {"NtDelayExecution", "NtDelayExecution", ProbeCategory::Process,
     "Alertable", "DelayInterval", "", "", "", "",
     "Sleeping. A program that waits is doing so here, and the duration is "
     "in the second argument."},
    {"NtYieldExecution", "NtYieldExecution", ProbeCategory::Process,
     "", "", "", "", "", "",
     "Giving up the rest of a time slice. Frequent in a spin loop."},
    {"NtAlertThread", "NtAlertThread", ProbeCategory::Process,
     "ThreadHandle", "", "", "", "", "",
     "Waking an alertable wait."},
    {"NtTestAlert", "NtTestAlert", ProbeCategory::Process,
     "", "", "", "", "", "",
     "Running any queued APCs, which is how a program driven by asynchronous "
     "callbacks advances."},
    {"NtDuplicateObject", "NtDuplicateObject", ProbeCategory::Process,
     "SourceProcessHandle", "SourceHandle", "TargetProcessHandle",
     "TargetHandle", "DesiredAccess", "Options",
     "Copying a handle into another process, which is how a handle gets "
     "shared rather than inherited."},

    // ------------------------------------------------------------ memory
    {"NtAllocateVirtualMemory", "NtAllocateVirtualMemory",
     ProbeCategory::Memory, "ProcessHandle", "BaseAddress", "ZeroBits",
     "RegionSize", "AllocationType", "Protect",
     "Reserving or committing a region. The protect bits say whether the "
     "region is going to hold code."},
    {"NtFreeVirtualMemory", "NtFreeVirtualMemory", ProbeCategory::Memory,
     "ProcessHandle", "BaseAddress", "RegionSize", "FreeType", "", "",
     "Releasing one."},
    {"NtProtectVirtualMemory", "NtProtectVirtualMemory",
     ProbeCategory::Memory, "ProcessHandle", "BaseAddress", "RegionSize",
     "NewProtect", "OldProtect", "",
     "Changing a region's permissions. A region that goes executable after "
     "being written is the shape of a self-modifying or unpacking program, "
     "and this is the call that does it."},
    {"NtQueryVirtualMemory", "NtQueryVirtualMemory", ProbeCategory::Memory,
     "ProcessHandle", "BaseAddress", "MemoryInformationClass",
     "MemoryInformation", "MemoryInformationLength", "ReturnLength",
     "Asking what a region is, which a program that walks its own address "
     "space does."},
    {"NtReadVirtualMemory", "NtReadVirtualMemory", ProbeCategory::Memory,
     "ProcessHandle", "BaseAddress", "Buffer", "NumberOfBytesToRead",
     "NumberOfBytesRead", "",
     "Reading another process's memory. A debugger does this constantly."},
    {"NtWriteVirtualMemory", "NtWriteVirtualMemory", ProbeCategory::Memory,
     "ProcessHandle", "BaseAddress", "Buffer", "NumberOfBytesToWrite",
     "NumberOfBytesWritten", "",
     "Writing another process's memory, which is how code is placed into a "
     "running one."},
    {"NtCreateSection", "NtCreateSection", ProbeCategory::Memory,
     "SectionHandle", "DesiredAccess", "ObjectAttributes",
     "MaximumSize", "SectionPageProtection", "AllocationAttributes",
     "Creating a section object, which is what a mapped file or a shared "
     "memory region is made from."},
    {"NtOpenSection", "NtOpenSection", ProbeCategory::Memory,
     "SectionHandle", "DesiredAccess", "ObjectAttributes", "", "", "",
     "Opening an existing one by name."},
    {"NtMapViewOfSection", "NtMapViewOfSection", ProbeCategory::Memory,
     "SectionHandle", "ProcessHandle", "BaseAddress", "ZeroBits",
     "CommitSize", "SectionOffset",
     "Mapping a section into a process. Every DLL the program loads and "
     "every file it maps arrives through this call."},
    {"NtUnmapViewOfSection", "NtUnmapViewOfSection", ProbeCategory::Memory,
     "ProcessHandle", "BaseAddress", "", "", "", "",
     "Unmapping one. An unmap of the image's own base is what an unpacker "
     "does before it remaps."},
    {"NtQuerySection", "NtQuerySection", ProbeCategory::Memory,
     "SectionHandle", "SectionInformationClass", "SectionInformation",
     "SectionInformationLength", "ReturnLength", "",
     "Querying a section's properties."},

    // ---------------------------------------------------------- registry
    {"NtCreateKey", "NtCreateKey", ProbeCategory::Registry,
     "KeyHandle", "DesiredAccess", "ObjectAttributes", "TitleIndex",
     "Class", "CreateOptions",
     "Creating or opening a key. Nearly every settings read in a Windows "
     "program begins here."},
    {"NtOpenKey", "NtOpenKey", ProbeCategory::Registry,
     "KeyHandle", "DesiredAccess", "ObjectAttributes", "", "", "",
     "Opening an existing key without creating it."},
    {"NtOpenKeyEx", "NtOpenKeyEx", ProbeCategory::Registry,
     "KeyHandle", "DesiredAccess", "ObjectAttributes", "OpenOptions", "",
     "",
     "The same with options, which is the form that can open a link without "
     "following it."},
    {"NtQueryValueKey", "NtQueryValueKey", ProbeCategory::Registry,
     "KeyHandle", "ValueName", "KeyValueInformationClass",
     "KeyValueInformation", "Length", "ResultLength",
     "Reading a value. A program that behaves differently for two machines "
     "reads the difference here."},
    {"NtSetValueKey", "NtSetValueKey", ProbeCategory::Registry,
     "KeyHandle", "ValueName", "TitleIndex", "Type", "Data", "DataSize",
     "Writing a value, which a program does when it stores a setting or a "
     "licence state."},
    {"NtDeleteKey", "NtDeleteKey", ProbeCategory::Registry,
     "KeyHandle", "", "", "", "", "",
     "Deleting a key."},
    {"NtDeleteValueKey", "NtDeleteValueKey", ProbeCategory::Registry,
     "KeyHandle", "ValueName", "", "", "", "",
     "Deleting a value."},
    {"NtEnumerateKey", "NtEnumerateKey", ProbeCategory::Registry,
     "KeyHandle", "Index", "KeyInformationClass", "KeyInformation",
     "Length", "ResultLength",
     "Walking a key's subkeys, which is what an installer or a scanner "
     "does."},
    {"NtEnumerateValueKey", "NtEnumerateValueKey", ProbeCategory::Registry,
     "KeyHandle", "Index", "KeyValueInformationClass",
     "KeyValueInformation", "Length", "ResultLength",
     "Walking a key's values."},
    {"NtQueryKey", "NtQueryKey", ProbeCategory::Registry,
     "KeyHandle", "KeyInformationClass", "KeyInformation", "Length",
     "ResultLength", "",
     "Querying a key's own properties, including its name."},
    {"NtFlushKey", "NtFlushKey", ProbeCategory::Registry,
     "KeyHandle", "", "", "", "", "",
     "Forcing a key to disk. Rare, and deliberate when it appears."},
    {"NtLoadKey", "NtLoadKey", ProbeCategory::Registry,
     "TargetKey", "SourceFile", "", "", "", "",
     "Loading a hive from a file, which an installer does and nothing else "
     "does."},

    // -------------------------------------------------------------- sync
    {"NtCreateEvent", "NtCreateEvent", ProbeCategory::Sync,
     "EventHandle", "DesiredAccess", "ObjectAttributes", "EventType",
     "InitialState", "",
     "Creating an event, the primitive a Windows program synchronises on "
     "most."},
    {"NtOpenEvent", "NtOpenEvent", ProbeCategory::Sync,
     "EventHandle", "DesiredAccess", "ObjectAttributes", "", "", "",
     "Opening one by name, which is how two processes find the same event."},
    {"NtSetEvent", "NtSetEvent", ProbeCategory::Sync,
     "EventHandle", "PreviousState", "", "", "", "",
     "Signalling one."},
    {"NtResetEvent", "NtResetEvent", ProbeCategory::Sync,
     "EventHandle", "PreviousState", "", "", "", "",
     "Clearing one."},
    {"NtCreateMutant", "NtCreateMutant", ProbeCategory::Sync,
     "MutantHandle", "DesiredAccess", "ObjectAttributes", "InitialOwner",
     "", "",
     "A mutant, which is Windows for a mutex."},
    {"NtCreateSemaphore", "NtCreateSemaphore", ProbeCategory::Sync,
     "SemaphoreHandle", "DesiredAccess", "ObjectAttributes", "InitialCount",
     "MaximumCount", "",
     "Creating a semaphore."},
    {"NtReleaseSemaphore", "NtReleaseSemaphore", ProbeCategory::Sync,
     "SemaphoreHandle", "ReleaseCount", "PreviousCount", "", "", "",
     "Releasing one."},
    {"NtCreateTimer", "NtCreateTimer", ProbeCategory::Sync,
     "TimerHandle", "DesiredAccess", "ObjectAttributes", "TimerType", "",
     "",
     "Creating a timer."},
    {"NtSetTimer", "NtSetTimer", ProbeCategory::Sync,
     "TimerHandle", "DueTime", "TimerApcRoutine", "TimerContext",
     "ResumeTimer", "Period",
     "Arming one. A program driven by a timer arms it here."},
    {"NtCancelTimer", "NtCancelTimer", ProbeCategory::Sync,
     "TimerHandle", "CurrentState", "", "", "", "",
     "Disarming one."},

    // ------------------------------------------------------------ module
    {"NtQuerySystemInformation", "NtQuerySystemInformation",
     ProbeCategory::Info, "SystemInformationClass", "SystemInformation",
     "SystemInformationLength", "ReturnLength", "", "",
     "The broad query a program makes about the machine, including the "
     "loaded module list."},
    {"NtQueryInformationToken", "NtQueryInformationToken",
     ProbeCategory::Info, "TokenHandle", "TokenInformationClass",
     "TokenInformation", "TokenInformationLength", "ReturnLength", "",
     "Querying a token, which is where a program reads its own privilege "
     "and integrity level."},
    {"NtQuerySystemTime", "NtQuerySystemTime", ProbeCategory::Info,
     "SystemTime", "", "", "", "", "",
     "Reading the clock. A call whose presence says the program is "
     "timestamping something."},
    {"NtQueryPerformanceCounter", "NtQueryPerformanceCounter",
     ProbeCategory::Info, "PerformanceCounter", "PerformanceFrequency",
     "", "", "", "",
     "Reading the high-resolution counter."},
    {"NtQueryDefaultLocale", "NtQueryDefaultLocale", ProbeCategory::Info,
     "UserDefault", "DefaultLocaleId", "", "", "", "",
     "Asking the system locale, which a program that localises its output "
     "does first."},
    {"NtQueryObject", "NtQueryObject", ProbeCategory::Info,
     "Handle", "ObjectInformationClass", "ObjectInformation",
     "ObjectInformationLength", "ReturnLength", "",
     "Querying a handle's own properties, including its name and type -- "
     "the call a program makes when it has a handle and wants to know what "
     "it is."},
};

constexpr std::size_t kProbeCount = sizeof(kProbes) / sizeof(kProbes[0]);

constexpr std::array<std::string_view, 2> kSonames = {
    // Wine's own build name first, then the versioned spelling some
    // distributions use for the same file.
    "ntdll.so",
    "ntdll.dll.so",
};

} // namespace

const char* probe_category_name(ProbeCategory c) noexcept {
    switch (c) {
    case ProbeCategory::File: return "file";
    case ProbeCategory::Process: return "process";
    case ProbeCategory::Memory: return "memory";
    case ProbeCategory::Registry: return "registry";
    case ProbeCategory::Sync: return "sync";
    case ProbeCategory::Module: return "module";
    case ProbeCategory::Info: return "info";
    case ProbeCategory::Other: return "other";
    }
    return "other";
}

const char* probe_category_detail(ProbeCategory c) noexcept {
    switch (c) {
    case ProbeCategory::File:
        return "opening, reading, writing, and closing files and devices";
    case ProbeCategory::Process:
        return "creating, ending, and querying processes and threads";
    case ProbeCategory::Memory:
        return "reserving, protecting, mapping, and reading address space";
    case ProbeCategory::Registry:
        return "reading and writing the registry, which a Windows program "
               "treats as its own state";
    case ProbeCategory::Sync:
        return "events, mutexes, semaphores, and the waits on them";
    case ProbeCategory::Module:
        return "loading and looking up modules and exported symbols";
    case ProbeCategory::Info:
        return "queries a program makes about the system, the clock, and "
               "itself";
    case ProbeCategory::Other:
        return "a call worth seeing that does not fit the above";
    }
    return "";
}

std::string_view NtdllProbe::arg(std::size_t index) const noexcept {
    switch (index) {
    case 0: return arg0;
    case 1: return arg1;
    case 2: return arg2;
    case 3: return arg3;
    case 4: return arg4;
    case 5: return arg5;
    default: return {};
    }
}

const std::vector<NtdllProbe>& ntdll_probes() noexcept {
    // Built once into a vector so that the public interface can return the
    // same type regardless of whether the table ends up static or grown.
    // Constructed on first use rather than at load time so that a program
    // that never runs a PE never copies it.
    static const std::vector<NtdllProbe> table(std::begin(kProbes),
                                               std::end(kProbes));
    return table;
}

std::vector<const NtdllProbe*> ntdll_probes_in(
    ProbeCategory category) noexcept {
    std::vector<const NtdllProbe*> out;
    for (const NtdllProbe& p : ntdll_probes()) {
        if (p.category == category) {
            out.push_back(&p);
        }
    }
    return out;
}

const NtdllProbe* ntdll_probe_for_symbol(std::string_view symbol) noexcept {
    for (const NtdllProbe& p : ntdll_probes()) {
        if (p.symbol == symbol) {
            return &p;
        }
    }
    return nullptr;
}

const NtdllProbe* ntdll_probe_for_api(std::string_view api) noexcept {
    for (const NtdllProbe& p : ntdll_probes()) {
        if (p.api == api) {
            return &p;
        }
    }
    return nullptr;
}

std::size_t ntdll_probe_count() noexcept { return kProbeCount; }

const std::vector<std::string_view>& ntdll_sonames() noexcept {
    static const std::vector<std::string_view> names(kSonames.begin(),
                                                     kSonames.end());
    return names;
}

} // namespace occ::obs

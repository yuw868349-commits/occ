#pragma once

// The Wine ntdll probes.
//
// A PE run is a Linux process running Wine, and the interesting events of a
// Windows program are not visible in that process's syscalls. Wine turns
// NtCreateFile into an open, an NtWriteFile into a write, and both of those
// are indistinguishable from the loader opening its own libraries. What is
// not ambiguous is the call site: Wine's Unix-side ntdll is host-native ELF,
// its Nt* entry points are real exported functions with real addresses, and a
// uprobe at one of them fires exactly when the Windows program asked for that
// service and never when Wine asked for something of its own.
//
// So this is a table of functions worth stopping at, and it is a table rather
// than a list of names because each entry has to carry three things that are
// not derivable from the others:
//
//   - The symbol, which is what the ELF parser is asked to find. It is the
//     Unix-side entry point, not the Windows export: the PE-side NtCreateFile
//     is a syscall thunk that jumps into __wine_syscall_dispatcher, and the
//     dispatcher indexes a table of Unix functions. The symbol here is the
//     Unix function, because that is the one with a body to probe.
//
//   - The category, which is what kind of thing the call is. A consumer that
//     wants only file access asks for the file category; without it, the only
//     way to select is by name, and selecting by name means a consumer hard-
//     codes symbol names and then has to be updated when the table is.
//
//   - The parameter names, which are for the output. A uprobe can read up to
//     six argument registers, and a report that prints "r1=3 r2=0x7ffe1234"
//     is a report nobody reads. The names come from the Windows prototypes,
//     because that is the interface the target thinks it is calling.
//
// The table is deliberately not exhaustive. Every probe costs a tracefs event
// and a perf ring, and a run that probes three thousand functions produces a
// stream that is a record of everything rather than an answer to anything.
// What is here is the set a person asking "what did this program do" wants
// first: files, processes, memory, registry, synchronisation, dynamic loading,
// and the query calls a program makes about itself.

#include <cstdint>
#include <string_view>
#include <vector>

namespace occ::obs {

// What kind of service a probe is at. The categories are the ones a reader
// would sort events into, not the ones a kernel would: two calls in the same
// category are reported together because a person asking about a program's
// file access wants both of them, even though the kernel implements one as a
// file lookup and the other as a handle close.
enum class ProbeCategory : std::uint8_t {
    File,       // Opening, reading, writing, and closing files and devices.
    Process,    // Process and thread creation, termination, and querying.
    Memory,     // Address space and allocation.
    Registry,   // The registry, which a Windows program treats as state.
    Sync,       // Events, mutexes, semaphores, waits.
    Module,     // Loading and looking up DLLs and exported symbols.
    Info,       // Queries a program makes about itself, the system, or time.
    Other,      // A call worth seeing that does not fit the above.
};

[[nodiscard]] const char* probe_category_name(ProbeCategory c) noexcept;
[[nodiscard]] const char* probe_category_detail(ProbeCategory c) noexcept;

// One function worth probing.
//
// Everything is a string_view into a static table, so an entry costs no
// allocation and the whole table lives in the read-only data segment where a
// mistake is a crash at build time rather than a runtime surprise.
struct NtdllProbe {
    // The symbol to look up in the Unix-side ntdll. This is the name the ELF
    // parser is given, so it has to match a real exported symbol exactly: a
    // name that does not exist produces no probe, and the report of that is
    // a missing event rather than an error.
    std::string_view symbol;

    ProbeCategory category = ProbeCategory::Other;

    // Argument names, in the order the calling convention passes them. Empty
    // entries are permitted for arguments a reader does not need named. An
    // entry list shorter than the arguments the function takes is fine: the
    // ones that are named are the ones this project has something to say
    // about, and naming the rest would be quoting a prototype back.
    std::string_view arg0;
    std::string_view arg1;
    std::string_view arg2;
    std::string_view arg3;
    std::string_view arg4;
    std::string_view arg5;

    // A sentence on why this call is worth a probe, for the report that
    // explains what a run observed. Empty is allowed and means the name and
    // the category say enough.
    std::string_view note;

    // The name at the given position, or an empty view. Out-of-range is an
    // empty view rather than a crash, because the table is hand-written and
    // an entry with fewer names than arguments is a normal entry.
    [[nodiscard]] std::string_view arg(std::size_t index) const noexcept;
};

// Every probe in the table, in a stable order that is the order they are
// declared. Stable because a report that reorders between runs is a report
// that has to be diffed by hand.
[[nodiscard]] const std::vector<NtdllProbe>& ntdll_probes() noexcept;

// The probes in one category, in table order. A copy rather than a view,
// because the table is small and a caller that filters is usually about to
// iterate the result rather than hold it.
[[nodiscard]] std::vector<const NtdllProbe*> ntdll_probes_in(
    ProbeCategory category) noexcept;

// The entry for a symbol, or nullptr. Matches on the symbol rather than the
// API name, because the symbol is what a probe is placed on.
[[nodiscard]] const NtdllProbe* ntdll_probe_for_symbol(
    std::string_view symbol) noexcept;

// How many probes are in the table. Reported by `occ doctor` and by the
// engine's degradation notes, so that "no probes were placed" can be
// distinguished from "there were none to place".
[[nodiscard]] std::size_t ntdll_probe_count() noexcept;

// The file names the Unix-side ntdll is found under, most specific first.
//
// `ntdll.so` is the name Wine builds it as. The versioned spellings exist
// because a distribution that ships Wine as a set of versioned libraries
// names it that way, and a search that only knew the unversioned name would
// report no ntdll on a host that has one.
[[nodiscard]] const std::vector<std::string_view>& ntdll_sonames() noexcept;

} // namespace occ::obs

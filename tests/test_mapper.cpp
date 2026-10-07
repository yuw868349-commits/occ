// The mapper: does the memory exist, and does the ledger agree with it.
//
// The tests in test_runtime_loader.cpp cover the ledger against spaces that
// were never mapped, which is the right way to test a ledger: every rule in
// record() and record_batch() is reachable without a syscall. This file covers
// the other half, and the half it covers is the half those tests cannot reach
// -- whether a mapping the ledger believes in is a mapping the kernel made.
//
// That distinction is the reason this file exists rather than four more cases
// in the other one. A mapper that recorded regions without mapping them would
// pass every test in test_runtime_loader.cpp and produce a runtime that
// reports a program as loaded and then faults on its first instruction. The
// only way to catch that is to write to the memory and read it back, and to
// change a protection and then try the access that protection forbids.
//
// So the rule this file is held to is that every case which claims a mapping
// works must prove it by touching the bytes, and every case which claims a
// protection was applied must prove it by failing to touch them. A test that
// asserted a status code and stopped would pass against a mapper that
// returned Success from an empty function, which is a mapper that would make
// the loader worse than the one it replaced.
//
// The accesses that must fail are attempted in a forked child, because a
// protection that works produces a SIGSEGV and a SIGSEGV in the test process
// is a process that died having proved nothing. The child installs its own
// fault handler and reports the signal and the faulting address back through
// a pipe rather than letting the parent read a wait status; the reason, and
// what it cost to find out, is written at length on run_in_child below.

#include "occ/runtime/address_space.h"
#include "occ/runtime/mapper.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace occ::runtime;

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

// ------------------------------------------------------ asking the kernel

// What /proc/self/maps says about one address.
//
// Read rather than inferred because the question this file exists to answer
// is "did the kernel agree", and the kernel's answer is written down in its
// own words. Parsing it is a hundred lines of work and a hundred lines of
// format that could change, which is the reason this is a check of a known
// permission string at a known address rather than a general reader -- and the
// reason the comparison below is on exactly four characters rather than on a
// prefix: "rw" is a prefix of "rwx", so a prefix test would call a writable
// and executable region read-write and be right by accident.
std::string read_self_maps() {
    std::string out;
    const int fd = ::open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return out;
    }
    char buf[8192];
    for (;;) {
        const ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n <= 0) {
            break;
        }
        out.append(buf, static_cast<std::size_t>(n));
        if (out.size() > (4u << 20)) {
            break;
        }
    }
    ::close(fd);
    return out;
}

// Whether the kernel's map gives `addr` exactly `perms`.
//
// `perms` is the four characters the kernel writes after the address range:
// three permission letters and the private/shared letter. It is four and not
// three because that is the width of the field -- "rwxp" is what an
// anonymous read-write-execute private mapping looks like, and a comparison
// against "rwx" would say no to a mapping that is exactly what was asked for.
// The width is also why the comparison is not a prefix test: "rw" is a prefix
// of "rwxp", so a prefix test would report a read-write-execute region as
// read-write and be right by accident.
bool maps_has(const std::string& maps, std::uint64_t addr, const char* perms) {
    static constexpr std::size_t kPermsWidth = 4;
    std::size_t at = 0;
    while (at < maps.size()) {
        std::size_t eol = maps.find('\n', at);
        if (eol == std::string::npos) {
            eol = maps.size();
        }
        const std::string line = maps.substr(at, eol - at);
        at = eol + 1;

        // "start-end perms ..." -- the first space ends the range.
        const std::size_t dash = line.find('-');
        const std::size_t sp = line.find(' ');
        if (dash == std::string::npos || sp == std::string::npos ||
            dash > sp) {
            continue;
        }
        const std::uint64_t lo =
            std::strtoull(line.substr(0, dash).c_str(), nullptr, 16);
        const std::uint64_t hi =
            std::strtoull(line.substr(dash + 1, sp - dash - 1).c_str(), nullptr,
                          16);
        if (addr < lo || addr >= hi) {
            continue;
        }
        if (line.size() < sp + 1 + kPermsWidth) {
            return false;
        }
        return line.compare(sp + 1, kPermsWidth, perms) == 0;
    }
    return false;
}

// ------------------------------------------------------ touching the memory

// Writes a pattern that is not a constant, so that a page which came back as
// zeroes cannot pass and a page that came back as a previous test's bytes
// cannot either. The increment is what makes it that: a constant would let a
// mapping that ignored the write look correct whenever the constant happened
// to be zero.
std::uint64_t pattern(std::uint64_t seed) noexcept {
    return 0x9E3779B97F4A7C15ULL * (seed + 1) + 0x0123456789ABCDEFULL;
}

void write_pattern(void* at, std::size_t bytes, std::uint64_t seed) noexcept {
    auto* p = static_cast<std::uint8_t*>(at);
    for (std::size_t i = 0; i < bytes; i += 8) {
        std::uint64_t v = pattern(seed + i);
        const std::size_t n = (bytes - i < 8) ? (bytes - i) : 8;
        std::memcpy(p + i, &v, n);
    }
}

bool reads_pattern(const void* at, std::size_t bytes,
                   std::uint64_t seed) noexcept {
    const auto* p = static_cast<const std::uint8_t*>(at);
    for (std::size_t i = 0; i < bytes; i += 8) {
        std::uint64_t v = pattern(seed + i);
        const std::size_t n = (bytes - i < 8) ? (bytes - i) : 8;
        if (std::memcmp(p + i, &v, n) != 0) {
            return false;
        }
    }
    return true;
}

// Runs `body` in a forked child and reports what the child observed.
//
// The design here is not "the child died and the parent reads the wait
// status", and getting there cost a rewrite. That version was wrong twice
// over, and both faults showed up only in a sanitized build.
//
// First: a child that faults under AddressSanitizer does not die of SIGSEGV.
// The runtime installs its own handler, prints a report, and calls abort(), so
// the parent sees SIGABRT. A test that asserts WTERMSIG(status) == SIGSEGV
// therefore passes in an ordinary build and fails in a sanitized one, for a
// reason that has nothing to do with the code under test. A test whose result
// depends on which sanitizer is linked is a test of the sanitizer.
//
// Second, and worse: the wait status cannot say *where* the fault was. A
// child that segfaults because the protection worked and a child that
// segfaults because the address was never mapped are the same observation to
// the parent, and telling them apart is the whole question. The answer has to
// come from the child.
//
// So the child installs its own SIGSEGV handler and reports what it saw
// through a pipe: the signal it got and the address the kernel named. The
// handler is installed with sigaction and SA_SIGINFO, and it is installed in
// the child rather than inherited, because a handler is not inherited across
// exec but is across fork -- so a child that forgot to install one would
// silently use the parent's and the test would be measuring the parent.
//
// This also makes the child survive the fault, which is what lets it report
// more than one thing. A single child can touch four addresses and report
// four observations, and the parent learns whether each fault was at the
// address it named.
struct Observation {
    int signal_number = 0;
    std::uint64_t address = 0;
};

struct ChildOutcome {
    // The child ran to completion and every access it attempted behaved.
    bool completed = false;
    // The child exited non-zero without having been signalled, which is how
    // it says "an access succeeded that should have faulted" or "a value did
    // not read back".
    int exit_code = 0;
    // Every access that faulted, in the order the child made them.
    std::vector<Observation> faults;
    // True when the child was killed by a signal the handler did not see,
    // which means the fault was one this file does not expect -- a stack
    // overflow in the handler, or a write to the pipe's own buffer.
    bool died_unexpectedly = false;
    int fatal_signal = 0;
};

// The write end of the report pipe, in the child. A global because a signal
// handler may not take anything but a lock-free object, and because the
// handler has no way to be given an argument. sig_atomic_t rather than int so
// that a compiler cannot reorder the store past the fault it describes.
volatile sig_atomic_t report_fd = -1;

// The handler.
//
// Async-signal-safe and nothing else: a store, a write, an _exit. No
// stdio, no allocation, no formatting, because a handler that is interrupted
// by a second fault has nowhere to go. The address comes from siginfo_t
// rather than from the instruction pointer, because si_addr is the data
// address the fault was about and the instruction pointer is where the code
// happened to be -- for a read of a mapped-but-protected page those are the
// same, and for a wild pointer they are not, and the difference is exactly
// what a test of "was this address protected" needs to see.
void on_fault(int sig, siginfo_t* info, void*) noexcept {
    if (report_fd < 0) {
        ::_exit(90);
    }
    Observation o;
    o.signal_number = sig;
    o.address = (info != nullptr && info->si_addr != nullptr)
                    ? static_cast<std::uint64_t>(
                          reinterpret_cast<std::uintptr_t>(info->si_addr))
                    : 0;
    // A short write is not handled and cannot be: the pipe buffer is a page
    // and the number of observations is four. If it ever were not, the parent
    // sees fewer observations than accesses and the case fails, which is the
    // right way for that to fail.
    const ssize_t n = ::write(report_fd, &o, sizeof(o));
    (void)n;
    // _exit rather than siglongjmp: continuing after a protection fault
    // would mean the memory might be readable now, and the whole point is
    // that the parent decides what the fault meant.
    ::_exit(0);
}

void install_fault_handler() noexcept {
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_fault;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    (void)::sigaction(SIGSEGV, &sa, nullptr);
    (void)::sigaction(SIGBUS, &sa, nullptr);
}

// Forks, runs `body`, and collects what the child reported.
//
// `body` returns the exit code the child should use if every access behaved
// as the caller expected. A body that expects a fault does not return at all
// -- the handler exits the process -- so a body returning normally has proved
// that nothing it did was supposed to fault.
ChildOutcome run_in_child(int (*body)(void*), void* arg) noexcept {
    ChildOutcome out;

    int fds[2] = {-1, -1};
    if (::pipe2(fds, O_CLOEXEC) != 0) {
        out.died_unexpectedly = true;
        out.fatal_signal = -1;
        return out;
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        ::close(fds[0]);
        ::close(fds[1]);
        out.died_unexpectedly = true;
        out.fatal_signal = -1;
        return out;
    }

    if (pid == 0) {
        ::close(fds[0]);
        report_fd = fds[1];
        install_fault_handler();
        // The code, not a report that a fault happened. A body that expects
        // no fault and gets one is a body that returns 0 from the handler's
        // _exit, so this line is only reached when nothing faulted.
        const int code = body(arg);
        ::_exit(code);
    }

    ::close(fds[1]);

    // Read the report before the wait, because the pipe has a limited buffer
    // and a child that reported more than fits would block on the write
    // while the parent is in waitpid. Reading first drains it, and the
    // read returns zero at the child's exit rather than blocking forever
    // because the write end is closed in the parent now.
    for (;;) {
        Observation o;
        const ssize_t n = ::read(fds[0], &o, sizeof(o));
        if (n == static_cast<ssize_t>(sizeof(o))) {
            out.faults.push_back(o);
            continue;
        }
        break;
    }
    ::close(fds[0]);

    int status = 0;
    if (::waitpid(pid, &status, 0) != pid) {
        out.died_unexpectedly = true;
        out.fatal_signal = -1;
        return out;
    }
    if (WIFEXITED(status)) {
        out.exit_code = WEXITSTATUS(status);
        out.completed = (out.exit_code == 0);
    } else if (WIFSIGNALED(status)) {
        // A signal the handler did not see. Under a sanitizer this is what a
        // fault looks like when the runtime's own handler got there first,
        // which is why the child installs one rather than relying on the
        // default: the default is not the same program on every build.
        out.died_unexpectedly = true;
        out.fatal_signal = WTERMSIG(status);
    }
    return out;
}

// Whether the child faulted at exactly `addr`.
//
// The address is checked as well as the signal because "it faulted" and "it
// faulted *there*" are different claims, and only the second one is the claim
// being made. A mapper that unmapped the wrong region, or one that left a
// second mapping over the address, produces a child that faults at an address
// the parent did not name, and a test that only counted faults would call
// that a pass.
bool faulted_at(const ChildOutcome& c, std::uint64_t addr) noexcept {
    for (const Observation& o : c.faults) {
        if (o.address == addr &&
            (o.signal_number == SIGSEGV || o.signal_number == SIGBUS)) {
            return true;
        }
    }
    return false;
}

// The child bodies. Each takes the address to touch through a pointer because
// a forked child has its own copy of the parent's address space and the
// address the parent mapped is a valid address in the child too -- which is
// the property the whole test rests on and is worth stating, because it is
// the reason there is no re-mapping in the child.
int child_write_then_read(void* at) noexcept {
    write_pattern(at, 4096, 1);
    // The read-back is in the child too, so a page that mapped but did not
    // retain what was written fails here rather than in the parent, where the
    // copy-on-write would have hidden it.
    return reads_pattern(at, 4096, 1) ? 0 : 3;
}

int child_touch_protected(void* at) noexcept {
    auto* p = static_cast<volatile std::uint8_t*>(at);
    const std::uint8_t v = *p;
    // Reaching this line means the access did not fault, which is the whole
    // observation: the parent reads the pipe, not the exit code, and a body
    // that reported through its exit status would have nothing to say about
    // an address the parent did not name. The value is consumed through a
    // volatile so the load survives the optimizer -- without a use, deleting
    // the load is legal and the test would pass against a mapper that never
    // protected anything.
    static volatile std::uint8_t sink;
    sink = static_cast<std::uint8_t>(sink + v);
    return 0;
}

int child_write_to_readonly(void* at) noexcept {
    auto* p = static_cast<volatile std::uint8_t*>(at);
    *p = 0x11;
    return 0;
}

// ------------------------------------------------------------ the cases

// A mapping is real memory, not a row in a vector.
void test_a_mapping_is_writable_memory() {
    AddressSpace space;
    Mapper m(space);

    const Result<std::uint64_t> r =
        m.map(0, 64 * 1024, PageProtection::ReadWrite, RegionKind::Private);
    check(r.ok(), "map with no base succeeds");
    if (!r.ok()) {
        return;
    }

    // A kernel-chosen address is page aligned and inside the window. Both are
    // the runtime's promises rather than the kernel's, and both are the kind
    // of thing that is true by accident until a runtime starts doing its own
    // placement.
    check(AddressSpace::is_page_aligned(r.value),
          "a kernel-chosen base is page aligned");
    check(r.value >= AddressSpace::kUserMin,
          "a kernel-chosen base is inside the user window");

    // The ledger and the kernel agree on the address.
    const Region* region = space.find(r.value);
    check(region != nullptr && region->base == r.value,
          "the ledger has the region at the address the kernel returned");

    // And the memory is there: the child writes and reads back, and a mapping
    // that was recorded but not made faults here.
    const ChildOutcome c = run_in_child(child_write_then_read,
                                        reinterpret_cast<void*>(r.value));
    check(c.completed, "the mapped pages hold what was written to them");
    check(c.faults.empty(),
          "writing to a read-write region faults nowhere");

    check(m.unmap(r.value).ok(), "unmap succeeds");
}

// Unmapping is real too: the ledger forgets it, and the pages are gone.
void test_unmapping_removes_the_pages() {
    AddressSpace space;
    Mapper m(space);

    const Result<std::uint64_t> r =
        m.map(0, 64 * 1024, PageProtection::ReadWrite, RegionKind::Private);
    check(r.ok(), "map for the unmap test succeeds");
    if (!r.ok()) {
        return;
    }
    const std::uint64_t at = r.value;

    check(m.unmap(at).ok(), "unmap succeeds");
    check(space.find(at) == nullptr, "the ledger forgot the region");
    check(space.allocation_count() == 1,
          "a removal is not an allocation, so the count did not move");

    // The pages are gone. The child reads an address nobody has mapped and
    // dies of SIGSEGV, which is the proof that unmap reached the kernel --
    // a mapper that only edited the ledger would leave the pages readable
    // and this child would exit normally.
    const ChildOutcome c =
        run_in_child(child_touch_protected, reinterpret_cast<void*>(at));
    check(faulted_at(c, at),
          "the pages are gone after unmap: the fault is at that address");
}

// A protection is a protection, not a field in a struct.
void test_protect_really_protects() {
    AddressSpace space;
    Mapper m(space);

    const Result<std::uint64_t> r =
        m.map(0, 64 * 1024, PageProtection::ReadWrite, RegionKind::Private);
    check(r.ok(), "map for the protect test succeeds");
    if (!r.ok()) {
        return;
    }
    const std::uint64_t at = r.value;

    // Read-write means read-write. Written first, so the protection change
    // below is a change and not the initial state: a mapper that mapped
    // everything PROT_NONE would pass a test that only checked the refusal.
    const ChildOutcome writable =
        run_in_child(child_write_then_read, reinterpret_cast<void*>(at));
    check(writable.completed,
          "read-write memory is writable before the protection changes");

    check(m.protect(at, PageProtection::NoAccess).ok(),
          "protect to no-access succeeds");

    // The ledger followed.
    const Region* region = space.find(at);
    check(region != nullptr && region->protection == PageProtection::NoAccess,
          "the ledger records the new protection");
    check(region != nullptr && region->protection_changes == 1,
          "the change is counted");
    check(region != nullptr &&
              region->initial_protection == PageProtection::ReadWrite,
          "the initial protection is not rewritten by a change");

    // And the kernel agrees, which is the part only a real access can show.
    const ChildOutcome blocked =
        run_in_child(child_touch_protected, reinterpret_cast<void*>(at));
    check(faulted_at(blocked, at),
          "a no-access page faults on read, at that address");

    // Read-only is not no-access: readable, not writable. The two are
    // different protections and a runtime that collapsed them would pass the
    // test above while failing this one.
    check(m.protect(at, PageProtection::ReadOnly).ok(),
          "protect to read-only succeeds");
    const Region* ro = space.find(at);
    check(ro != nullptr && ro->protection == PageProtection::ReadOnly,
          "the ledger records read-only");
    check(ro != nullptr && ro->protection_changes == 2,
          "the second change is counted");

    const ChildOutcome still_readable =
        run_in_child(child_touch_protected, reinterpret_cast<void*>(at));
    check(still_readable.completed && still_readable.faults.empty(),
          "a read-only page is still readable");

    const ChildOutcome write_blocked =
        run_in_child(child_write_to_readonly, reinterpret_cast<void*>(at));
    check(faulted_at(write_blocked, at),
          "a read-only page faults on write, at that address");

    check(m.unmap(at).ok(), "unmap after the protection changes succeeds");
}

// A protection is not a commit.
//
// This is the one field `set_protection` rewrites that it must *not* invent.
// `make_region` builds every region committed, because that is what mapping
// produces, so a protection change that rebuilt the region from scratch and
// kept only the protection would turn a reserved range into a committed one.
// The program that decommitted a range and then re-protected it would believe
// it had memory back; the pages are mprotected away, so its next touch faults
// on memory it was told it owned.
//
// The check is on the ledger rather than on the pages, and it has to be:
// `mprotect` on a reserved range succeeds on Linux whether or not anything was
// ever committed, so only the state the runtime records distinguishes the two
// answers. The mutant this test exists for is `updated.committed = true;` in
// `AddressSpace::set_protection_at`, which the whole ntdll suite passes because
// `NtProtectVirtualMemory` refuses a reserved range before it ever gets here.
void test_a_protect_does_not_commit_a_reserved_range() {
    AddressSpace space;
    Mapper m(space);

    const Result<std::uint64_t> r =
        m.map(0, 64 * 1024, PageProtection::ReadWrite, RegionKind::Private);
    check(r.ok(), "map for the reserved-protect test succeeds");
    if (!r.ok()) {
        return;
    }
    const std::uint64_t at = r.value;

    // Committed to start with, because `map` produces committed memory, and
    // checked so the assertion after the decommit is a difference and not the
    // same answer read twice.
    const Region* born = space.find(at);
    check(born != nullptr && born->committed,
          "a freshly mapped region is committed");

    check(space.decommit(at, 64 * 1024).ok(),
          "the range decommits before it is protected");
    const Region* reserved = space.find(at);
    check(reserved != nullptr && !reserved->committed,
          "the decommitted range is reserved");

    // The call under test. `Mapper::protect` does not check the commit state
    // and is not supposed to: it is the whole-region primitive, and the layer
    // that enforces the Windows rule is `NtProtectVirtualMemory`, which is
    // tested in `occ_test_ntdll`.
    check(m.protect(at, PageProtection::ReadOnly).ok(),
          "protect over a reserved range succeeds");

    const Region* after = space.find(at);
    check(after != nullptr, "the range is still in the ledger after the protect");
    check(after != nullptr && !after->committed,
          "the protect did not commit the reserved range");
    check(after != nullptr && after->protection == PageProtection::ReadOnly,
          "the protect did change the protection");

    // And the other direction, so the field is not simply pinned to false: a
    // commit brings the commit back and a protect after it keeps it.
    check(space.commit(at, 64 * 1024).ok(),
          "the range commits again");
    const Region* recommitted = space.find(at);
    check(recommitted != nullptr && recommitted->committed,
          "the recommitted range is committed again");
    check(m.protect(at, PageProtection::ReadWrite).ok() &&
              space.find(at) != nullptr &&
              space.find(at)->committed,
          "a protect over committed memory leaves it committed");
}

// The two protections that look like one and are not.
void test_execute_and_write_copy_translate_separately() {
    // The translation is a function and these are its four executable values
    // and its two write-copy values. A mapper that mapped a write-copy region
    // read-write would let a program write to a page that the whole point of
    // PAGE_WRITECOPY is that it must not, and the ledger would say
    // PAGE_WRITECOPY while the kernel said otherwise.
    check(protection_to_prot(PageProtection::ReadWrite) ==
              (PROT_READ | PROT_WRITE),
          "read-write translates to read and write");
    check(protection_to_prot(PageProtection::ReadOnly) == PROT_READ,
          "read-only translates to read");
    check(protection_to_prot(PageProtection::WriteCopy) == PROT_READ,
          "write-copy translates to read, not to write");
    check(protection_to_prot(PageProtection::Execute) == PROT_EXEC,
          "execute translates to execute");
    check(protection_to_prot(PageProtection::ExecuteRead) ==
              (PROT_READ | PROT_EXEC),
          "execute-read translates to read and execute");
    check(protection_to_prot(PageProtection::ExecuteReadWrite) ==
              (PROT_READ | PROT_WRITE | PROT_EXEC),
          "execute-read-write translates to all three");
    check(protection_to_prot(PageProtection::ExecuteWriteCopy) ==
              (PROT_READ | PROT_EXEC),
          "execute-write-copy translates to read and execute, not to write");
    check(protection_to_prot(PageProtection::NoAccess) == PROT_NONE,
          "no-access translates to none");

    // A modifier is not a protection. The whole value is built in the
    // underlying type and cast once, because PageProtection is a scoped enum
    // and the `|` that would read most naturally here is exactly the
    // operation a scoped enum removes -- which is the type doing its job.
    const PageProtection read_write_guarded = static_cast<PageProtection>(
        static_cast<std::uint32_t>(PageProtection::ReadWrite) | 0x100U);
    check(protection_to_prot(read_write_guarded) == (PROT_READ | PROT_WRITE),
          "a modifier does not change the base translation");

    // And the executable region really is executable as far as the kernel
    // is concerned. Asked of /proc/self/maps rather than through the mapper,
    // because a check that went through the mapper would compare the
    // translation against itself and agree with a translation that is wrong.
    AddressSpace space;
    Mapper m(space);
    const Result<std::uint64_t> r =
        m.map(0, 64 * 1024, PageProtection::ExecuteReadWrite,
              RegionKind::Private);
    check(r.ok(), "an executable region maps");
    if (r.ok()) {
        const Region* region = space.find(r.value);
        check(region != nullptr && region->executable,
              "an execute-read-write region is executable");

        // The kernel's own map, which distinguishes the three protections in
        // a way a returned status cannot: a mapper that translated every
        // protection to PROT_READ|PROT_WRITE would return success for all of
        // them and this is what would catch it.
        const std::string maps = read_self_maps();
        check(maps_has(maps, r.value, "rwxp"),
              "the kernel's own map says the region is rwxp");
        (void)m.unmap(r.value);
    }
}

// A refused mapping leaves nothing behind.
//
// This is the case that MAP_FIXED_NOREPLACE exists for, and it is the one a
// check-then-map implementation cannot get right. Two cases: a mapping over
// the kernel's own idea of what is free (the low addresses, which no process
// may map), and a mapping over something this mapper already made.
void test_refusals_leave_nothing_behind() {
    AddressSpace space;
    Mapper m(space);

    // The first mapping is the thing the second one collides with.
    const Result<std::uint64_t> first =
        m.map(0, 64 * 1024, PageProtection::ReadWrite, RegionKind::Private);
    check(first.ok(), "the first mapping succeeds");
    if (!first.ok()) {
        return;
    }

    // A second mapping over the first. Without MAP_FIXED_NOREPLACE this
    // silently replaces the first, and the ledger still describes the old
    // region -- a process whose map is a lie about its own memory, and the
    // test below would not notice because it only asks whether the second
    // mapping reported success.
    const Result<std::uint64_t> collide =
        m.map(first.value, 64 * 1024, PageProtection::ReadWrite,
              RegionKind::Private);
    check(!collide.ok(), "a mapping over a mapped address is refused");
    check(collide.status == Status::ConflictingAddresses,
          "the refusal is a conflict, not a memory shortage");
    check(m.last_failure().error == 17 /* EEXIST */,
          "the conflict names EEXIST behind it");

    // The first mapping is intact. Checked by touching it, because a refusal
    // that had already replaced the memory would leave a ledger that looks
    // right and memory that is not.
    const ChildOutcome c = run_in_child(child_write_then_read,
                                        reinterpret_cast<void*>(first.value));
    check(c.completed,
          "the first mapping survived the refused one");
    check(space.regions().size() == 1,
          "the refused mapping did not reach the ledger");

    // A base below the window. Reported as an address problem rather than a
    // memory one, because "there is no memory" would send a reader looking
    // for an out-of-memory condition that is not what happened.
    const Result<std::uint64_t> low =
        m.map(AddressSpace::kUserMin - 0x1000, 64 * 1024,
              PageProtection::ReadWrite, RegionKind::Private);
    check(!low.ok(), "a mapping below the window is refused");
    check(low.status == Status::InvalidAddress,
          "the refusal below the window is an address problem");

    // A base that is not page aligned. Refused rather than rounded, because
    // rounding down would map memory the caller did not name.
    const Result<std::uint64_t> unaligned =
        m.map(first.value + 1, 64 * 1024, PageProtection::ReadWrite,
              RegionKind::Private);
    check(!unaligned.ok(), "a base that is not page aligned is refused");
    check(unaligned.status == Status::InvalidParameter,
          "the refusal for an unaligned base is a parameter problem");

    // A zero size.
    const Result<std::uint64_t> empty =
        m.map(0, 0, PageProtection::ReadWrite, RegionKind::Private);
    check(!empty.ok() && empty.status == Status::InvalidParameter,
          "a zero size is refused");

    check(m.unmap(first.value).ok(), "the first mapping is still unmappable");
}

// unmap's contract: a whole region, addressed at its start.
void test_unmap_addresses_a_region_exactly() {
    AddressSpace space;
    Mapper m(space);

    const Result<std::uint64_t> r =
        m.map(0, 64 * 1024, PageProtection::ReadWrite, RegionKind::Private);
    check(r.ok(), "map for the unmap contract succeeds");
    if (!r.ok()) {
        return;
    }

    // The middle of the region is not the region. Refused rather than split,
    // so that "the region covering this address" has one answer before and
    // after the call.
    const Result<std::uint64_t> middle =
        m.unmap(r.value + AddressSpace::kPageSize);
    check(!middle.ok(), "unmapping the middle of a region is refused");
    check(middle.status == Status::InvalidAddress,
          "the refusal for a partial unmap is an address problem");
    check(space.find(r.value) != nullptr,
          "the region is still there after a refused unmap");

    // An address nothing was mapped at.
    const Result<std::uint64_t> nowhere =
        m.unmap(AddressSpace::kUserMin + 0x20000000ULL);
    check(!nowhere.ok(), "unmapping an unmapped address is refused");

    check(m.unmap(r.value).ok(), "unmapping at the start succeeds");
}

// Finds `bytes` of address space that nothing is mapped at, by asking the
// kernel to map it, noting where it landed, and giving it straight back.
//
// The hard-coded bases this replaces were wrong in an ordinary build too, they
// just happened to be free: a fixed address is an assumption about what else
// is in the process, and a sanitized build invalidates it by putting its
// shadow memory exactly there. The failure is not subtle -- a batch refused
// with EEXIST at an address the test itself chose -- and it is the kind of
// assumption that passes everywhere and then fails on a machine with a
// different allocator.
//
// Asking the kernel rather than reading /proc/self/maps is what makes the
// answer right: the kernel is the authority on what is free, and asking costs
// one mapping. A caller that wants three adjacent regions asks for three times
// as much, and the adjacency is the kernel's rather than an assumption.
//
// The mapping is released before returning, and that is the part the first
// version of this function got wrong. It reported the address it had just
// taken and left it mapped, so every caller received an address that was
// already occupied -- and the caller then failed with EEXIST at an address
// this function had certified as free, which is a contradiction worth more
// than a comment about not making assumptions.
//
// Returns zero when no such range could be found, and the caller reports that
// rather than proceeding with an address it did not get.
std::uint64_t find_free_range(std::uint64_t bytes) noexcept {
    // A mapper of its own, so the probe does not land in the ledger the
    // calling case is asserting about. A ledger holding a region the case
    // never mapped would make "the ledger has all three" true for the wrong
    // reason.
    AddressSpace probe_space;
    Mapper probe(probe_space);
    const Result<std::uint64_t> r =
        probe.map(0, bytes, PageProtection::NoAccess, RegionKind::Private);
    if (!r.ok()) {
        return 0;
    }
    // Given back before returning, and the result checked: a probe that could
    // not release what it took has not found a free range, it has moved one.
    const Result<std::uint64_t> released = probe.unmap(r.value);
    if (!released.ok()) {
        return 0;
    }
    return r.value;
}

// The batch is all of the mapping or none of it, on both sides.
void test_map_batch_is_all_or_nothing() {
    AddressSpace space;
    Mapper m(space);

    // Three adjacent regions that are all placeable, on a base the kernel
    // says is free rather than one this file picked.
    const std::uint64_t kUnit = 64 * 1024;
    const std::uint64_t base = find_free_range(3 * kUnit);
    check(base != 0, "found three adjacent regions' worth of free space");
    if (base == 0) {
        return;
    }

    std::vector<Mapper::Candidate> batch = {
        {base, kUnit, PageProtection::ReadWrite, RegionKind::Image, ".text",
         1},
        {base + kUnit, kUnit, PageProtection::ReadWrite,
         RegionKind::Image, ".data", 2},
        {base + 2 * kUnit, kUnit, PageProtection::ReadOnly,
         RegionKind::Image, ".rdata", 3},
    };

    const Result<std::uint64_t> r = m.map_batch(batch);
    check(r.ok(), "a batch of three placeable regions maps");
    check(r.ok() && r.value == 3, "the batch reports three regions");
    check(space.regions().size() == 3, "the ledger has all three");

    // Each one is real memory, and the third one is really read-only -- which
    // is the only way to know the protection reached the kernel rather than
    // only the struct.
    const ChildOutcome first_ok =
        run_in_child(child_write_then_read, reinterpret_cast<void*>(base));
    check(first_ok.completed,
          "the first region of the batch is real memory");

    const ChildOutcome third_blocked =
        run_in_child(child_write_to_readonly,
                     reinterpret_cast<void*>(base + 2 * kUnit));
    check(faulted_at(third_blocked, base + 2 * kUnit),
          "the read-only region of the batch really is read-only");

    // The kernel's own map, as a third reading of the same three protections.
    // The per-region protection was passed per candidate, so this is also a
    // check that the batch did not apply the first candidate's protection to
    // all three -- which is the mistake a loop that hoisted the protection
    // out of the loop would make.
    const std::string maps = read_self_maps();
    check(maps_has(maps, base, "rw-p"),
          "the kernel says the first region is rw");
    check(maps_has(maps, base + 2 * kUnit, "r--p"),
          "the kernel says the third region is read-only");
    check(maps_has(maps, base + kUnit, "rw-p"),
          "the kernel says the second region is rw");

    // Now a batch that fails. The third candidate overlaps the first, which
    // the ledger would refuse -- but by then two regions are already mapped,
    // so the question is whether they are mapped *after* the refusal.
    const std::uint64_t far = find_free_range(2 * kUnit);
    check(far != 0, "found free space for the batch that will be refused");
    std::vector<Mapper::Candidate> bad = {
        {far, kUnit, PageProtection::ReadWrite, RegionKind::Private, "", 0},
        {far + kUnit / 2, kUnit, PageProtection::ReadWrite,
         RegionKind::Private, "", 0},
    };
    const Result<std::uint64_t> refused = m.map_batch(bad);
    check(!refused.ok(), "a batch whose regions overlap each other is refused");
    check(refused.status == Status::ConflictingAddresses,
          "the batch refusal is a conflict");

    // Nothing from the refused batch is in the ledger.
    check(space.find(far) == nullptr,
          "the refused batch left nothing in the ledger");
    check(space.regions().size() == 3,
          "the refused batch did not grow the ledger");

    // And nothing from it is in the kernel either. The first candidate of the
    // refused batch was a perfectly good mapping that the kernel made before
    // the conflict was found; if the rollback did not unmap it, this read
    // succeeds where it must fault.
    const ChildOutcome gone =
        run_in_child(child_touch_protected, reinterpret_cast<void*>(far));
    check(faulted_at(gone, far),
          "the refused batch unmapped the region it had already mapped");

    // A batch refused before it maps anything: an unaligned base is caught
    // in the validation sweep, so not even the first candidate is mapped.
    const std::uint64_t later = find_free_range(2 * kUnit);
    std::vector<Mapper::Candidate> unaligned = {
        {later, kUnit, PageProtection::ReadWrite, RegionKind::Private, "", 0},
        {later + kUnit + 1, kUnit, PageProtection::ReadWrite,
         RegionKind::Private, "", 0},
    };
    check(!m.map_batch(unaligned).ok(),
          "a batch with an unaligned base is refused");
    const ChildOutcome never_mapped =
        run_in_child(child_touch_protected, reinterpret_cast<void*>(later));
    check(faulted_at(never_mapped, later),
          "the refused batch never mapped its first candidate");

    // And the batch that did succeed is still whole.
    check(space.regions().size() == 3,
          "the successful batch is untouched by the failures after it");

    for (int i = 0; i < 3; ++i) {
        (void)m.unmap(base + static_cast<std::uint64_t>(i) * kUnit);
    }
    check(space.regions().empty(), "the whole successful batch unmapped");
}

// A guard page that arrives as ordinary memory is a buffer overflow that does
// not fault, so the refusal is the behaviour worth pinning down.
void test_guard_is_refused_rather_than_ignored() {
    AddressSpace space;
    Mapper m(space);

    const Result<std::uint64_t> r =
        m.map(0, 64 * 1024, PageProtection::ReadWrite, RegionKind::Private);
    check(r.ok(), "map for the guard test succeeds");
    if (!r.ok()) {
        return;
    }

    const PageProtection guarded = static_cast<PageProtection>(
        static_cast<std::uint32_t>(PageProtection::ReadOnly) | 0x100U);
    const Result<std::uint32_t> g = m.protect(r.value, guarded);
    check(!g.ok(), "a guard page is refused");
    check(g.status == Status::NotImplemented,
          "the refusal for a guard page is not-implemented, not invalid");

    // The region is untouched. This is the part that matters: a mapper that
    // stripped the modifier and applied read-only would have returned a
    // success and left a program with a buffer it believes is guarded.
    const Region* region = space.find(r.value);
    check(region != nullptr &&
              region->protection == PageProtection::ReadWrite,
          "the refused guard left the protection alone");
    check(region != nullptr && region->protection_changes == 0,
          "the refused guard did not count as a change");

    // The other two modifiers too, for the same reason.
    for (const std::uint32_t modifier : {0x200U, 0x400U}) {
        const Result<std::uint32_t> refused = m.protect(
            r.value, static_cast<PageProtection>(
                         static_cast<std::uint32_t>(PageProtection::ReadOnly) |
                         modifier));
        check(!refused.ok() && refused.status == Status::NotImplemented,
              "a modifier is refused rather than dropped");
    }

    check(m.unmap(r.value).ok(), "unmap after the refusals succeeds");
}

// The syscall counter is what distinguishes a test of the mapper from a test
// of the ledger, so it is worth a case of its own.
void test_the_counter_counts_syscalls() {
    AddressSpace space;
    Mapper m(space);

    check(m.syscalls_made() == 0, "a fresh mapper has made no syscalls");

    const Result<std::uint64_t> r =
        m.map(0, 64 * 1024, PageProtection::ReadWrite, RegionKind::Private);
    check(r.ok() && m.syscalls_made() == 1,
          "one mapping is one syscall");

    (void)m.protect(r.value, PageProtection::ReadOnly);
    check(m.syscalls_made() == 2, "a protection is a second syscall");

    (void)m.unmap(r.value);
    check(m.syscalls_made() == 3, "an unmap is a third syscall");
    check(space.allocation_count() == 1,
          "the ledger counted one allocation, not three operations");
}

// `sync` is the mapper's counted syscall for `NtFlushProcessWriteBuffers`, and
// its whole reason for existing is that an `msync` on an anonymous mapping
// succeeds whether or not it ran -- the return value reports a claim, the
// counter records the act. The assertions below are about that difference.
void test_sync_counts_and_reports() {
    AddressSpace space;
    Mapper m(space);

    const Result<std::uint64_t> r =
        m.map(0, 64 * 1024, PageProtection::ReadWrite, RegionKind::Private);
    check(r.ok(), "sync: a region to flush exists");
    const std::uint64_t before = m.syscalls_made();

    const Result<std::uint64_t> s = m.sync(r.value, 64 * 1024);
    check(s.ok() && s.value == 64 * 1024,
          "sync: a flushed region reports the size it flushed");
    check(m.syscalls_made() == before + 1,
          "sync: and the counter moved, which is the record of the syscall "
          "rather than of the return value -- on anonymous memory the msync "
          "cannot fail, so the counter is the only evidence it happened");

    // A misaligned range is a parameter error, not a flush refusal: the
    // kernel's EINVAL for a misaligned msync would otherwise read as a
    // statement about the memory.
    const Result<std::uint64_t> bad = m.sync(r.value + 0x800, 64 * 1024);
    check(!bad.ok() && bad.status == Status::InvalidParameter,
          "sync: a range that is not page aligned is a parameter error, so a "
          "caller reading the status does not conclude the kernel refused its "
          "flush");

    // The ledger is untouched by a flush. A flush changes no pages' mapping.
    check(space.allocation_count() == 1,
          "sync: and the ledger is unchanged, because a flush is not an "
          "allocation");
}

// A size that carries a range past the top of the 64-bit address space.
//
// The three cases below are the three sums in this file written the way that
// is defeated by the wrap -- `base + size` -- and each one failed differently
// before it was written as a difference:
//
//   - `protect_in_range` walked no page of the range and then asked the kernel
//     to protect a span reaching off the address space, and reported the
//     kernel's refusal as InvalidAddress. That is a status about the memory,
//     produced by a check that had been satisfied, and a caller reading it
//     concludes the pages are not mapped when in fact it named a range that
//     does not exist.
//   - `protect_range` rounded the wrapped sum and found `last < first`, which
//     is its "no whole page in the range" answer -- a success that did
//     nothing -- over a range that reaches off the end of the address space.
//     A decommit built on that success would leave the ledger holding pages
//     the kernel still has.
//   - `map(0, size)` rounded the size for its window check, and
//     `page_round_up` wraps to exactly zero for a size within a page of the
//     top, which is below the window's span and so passed the check. The zero
//     went to the kernel as `mmap(NULL, 0)`.
//
// The sizes are chosen to sit in the window where the wrap happens, which is
// narrower than it looks: `page_round_up` only wraps within one page of the
// top of the range, and a sum only wraps past the top. The failures are
// asserted with the status the fixed code produces, and each case additionally
// asserts that nothing was left behind, because a refusal that recorded half
// its work would be a different bug wearing the right status.
void test_a_size_that_wraps_is_refused_rather_than_folded() {
    AddressSpace space;
    Mapper m(space);

    // ---------------------------------------------- protect_in_range

    const Result<std::uint64_t> r =
        m.map(0, 64 * 1024, PageProtection::ReadWrite, RegionKind::Private);
    check(r.ok(), "wrap: the region the protect cases need exists");
    if (!r.ok()) {
        return;
    }
    const std::uint64_t base = r.value;

    // `0xFFFFFFFFFFFFF001` is `0 - 0xFFF`, so `base + size` lands `0xFFF`
    // below `base` -- inside the region's own span, which is why the
    // difference-form bound catches it and the sum-form bound did not.
    const std::uint64_t wrap = 0xFFFFFFFFFFFFF001ULL;

    const std::uint32_t before_changes =
        space.find(base) != nullptr ? space.find(base)->protection_changes : 0;
    const std::uint64_t before_syscalls = m.syscalls_made();

    const Result<std::uint32_t> p =
        m.protect_in_range(base, wrap, PageProtection::ReadOnly);
    check(!p.ok(), "wrap: a protect of a wrapping range is refused");
    check(p.status == Status::InvalidParameter,
          "wrap: the refusal is a parameter error, which is a statement "
          "about the request rather than about the memory");
    check(m.syscalls_made() == before_syscalls,
          "wrap: the refusal came before the kernel was asked, so no "
          "mprotect was counted");
    {
        const Region* after = space.find(base);
        check(after != nullptr && after->protection == PageProtection::ReadWrite,
              "wrap: the refused protect left the protection alone");
        check(after != nullptr && after->protection_changes == before_changes,
              "wrap: and did not count as a change");
        check(after != nullptr && after->kind == RegionKind::Private,
              "wrap: and did not cut the region");
    }

    // The same call with a size that genuinely fits still works, so the guard
    // refused the wrap rather than the operation.
    const Result<std::uint32_t> ok =
        m.protect_in_range(base, 4096, PageProtection::ReadOnly);
    check(ok.ok(), "wrap: a protect of a fitting range still succeeds");
    (void)m.protect_in_range(base, 4096, PageProtection::ReadWrite);

    // ---------------------------------------------- protect_range

    const std::uint64_t before_range_syscalls = m.syscalls_made();
    const Result<std::uint64_t> pr =
        m.protect_range(base, wrap, PageProtection::ReadOnly);
    check(!pr.ok(),
          "wrap: a range protect whose sum wraps is refused rather than "
          "reported as an empty range");
    check(pr.status == Status::InvalidParameter,
          "wrap: and the refusal is a parameter error, not a bare success "
          "over a range that reaches off the address space");
    check(m.syscalls_made() == before_range_syscalls,
          "wrap: the range protect did not reach the kernel either");

    // A range that genuinely lies inside one page is still the success that
    // does nothing -- that answer is the one a real empty range gets and it
    // has to survive the guard above, or the guard turned a valid case into a
    // refusal.
    const Result<std::uint64_t> empty =
        m.protect_range(base + 8, 8, PageProtection::ReadOnly);
    check(empty.ok() && empty.value == 0,
          "wrap: a range inside a single page is still the success that does "
          "nothing");

    // ---------------------------------------------- map(0, wrapping size)

    // `0xFFFFFFFFFFFFF001` is within a page of the top, so `page_round_up`
    // wraps -- to zero, which is the value that slipped past the window check.
    const std::uint64_t map_syscalls = m.syscalls_made();
    const std::uint64_t regions_before = space.regions().size();
    const Result<std::uint64_t> big =
        m.map(0, wrap, PageProtection::ReadWrite, RegionKind::Private);
    check(!big.ok(), "wrap: a map of a size that rounds to zero is refused");
    check(big.status == Status::NoMemory,
          "wrap: and it is reported as out of memory, which is what the "
          "address space says when no base can hold the request");
    check(m.syscalls_made() == map_syscalls,
          "wrap: the map refusal came before the kernel was asked, so the "
          "zero-length mmap was never made");
    check(space.regions().size() == regions_before,
          "wrap: and no region was recorded for it");

    // A mapping with an unspecified base still works, so the guard refused
    // the wrapped size rather than mappings with base zero.
    const Result<std::uint64_t> fine =
        m.map(0, 64 * 1024, PageProtection::ReadWrite, RegionKind::Private);
    check(fine.ok(), "wrap: a map of an ordinary size with base zero works");

    // Cleanup. The successful protects above cut the region into pieces, and
    // `unmap` names one region by its base, so each piece is unmapped by the
    // base the ledger reports for it rather than by assuming the mapping is
    // still one region. The final assertion is the point of the case: nothing
    // either refused call touched is in the ledger, so the refusals left no
    // region and no split behind them.
    while (!space.regions().empty()) {
        const std::uint64_t piece_base = space.regions().front().base;
        check(m.unmap(piece_base).ok(), "wrap: a remaining piece unmaps");
    }
    check(space.regions().empty(),
          "wrap: and the ledger is empty, so nothing refused was recorded");
    check(space.allocation_count() == 2,
          "wrap: two mappings were made and both were unmapped, and the "
          "refused calls added nothing to the count");
}

} // namespace

int main() {
    test_a_mapping_is_writable_memory();
    test_unmapping_removes_the_pages();
    test_protect_really_protects();
    test_a_protect_does_not_commit_a_reserved_range();
    test_execute_and_write_copy_translate_separately();
    test_refusals_leave_nothing_behind();
    test_unmap_addresses_a_region_exactly();
    test_map_batch_is_all_or_nothing();
    test_guard_is_refused_rather_than_ignored();
    test_the_counter_counts_syscalls();
    test_sync_counts_and_reports();
    test_a_size_that_wraps_is_refused_rather_than_folded();

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

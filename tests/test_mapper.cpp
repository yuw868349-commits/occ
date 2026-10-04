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
// The accesses that must fail are attempted in a forked child. A protection
// that works produces a SIGSEGV, and a SIGSEGV in the test process is a
// process that dies having proved nothing; a child that dies of SIGSEGV is a
// child whose death is the observation, and the parent reads the wait status
// and learns whether the signal was the one that was supposed to happen.

#include "occ/runtime/address_space.h"
#include "occ/runtime/mapper.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

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

// Runs `body` in a forked child and reports how it ended.
//
// The three outcomes a caller has to tell apart are: it finished, it died of
// a signal the protection was supposed to cause, and it died of a signal it
// was not supposed to cause. Collapsing the last two into "the child died" is
// how a test of a guard ends up passing because the child ran out of stack.
struct ChildOutcome {
    bool exited_normally = false;
    int exit_code = 0;
    bool signalled = false;
    int signal_number = 0;
};

ChildOutcome run_in_child(void (*body)(void*), void* arg) noexcept {
    ChildOutcome out;
    const pid_t pid = ::fork();
    if (pid < 0) {
        out.signalled = true;
        out.signal_number = -1;
        return out;
    }
    if (pid == 0) {
        // _exit rather than exit: the parent's stdio buffers are copied into
        // this process and a flush here would write them out twice.
        body(arg);
        ::_exit(0);
    }
    int status = 0;
    if (::waitpid(pid, &status, 0) != pid) {
        out.signalled = true;
        out.signal_number = -1;
        return out;
    }
    if (WIFEXITED(status)) {
        out.exited_normally = true;
        out.exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        out.signalled = true;
        out.signal_number = WTERMSIG(status);
    }
    return out;
}

// The two child bodies. Each takes the address to touch through a pointer
// because a forked child has its own copy of the parent's address space and
// the address the parent mapped is a valid address in the child too -- which
// is the property the whole test rests on and is worth stating, because it is
// the reason there is no re-mapping in the child.
void child_write_then_read(void* at) noexcept {
    write_pattern(at, 4096, 1);
    // The read-back is in the child too, so a page that mapped but did not
    // retain what was written fails here rather than in the parent, where the
    // copy-on-write would have hidden it.
    ::_exit(reads_pattern(at, 4096, 1) ? 0 : 3);
}

void child_touch_protected(void* at) noexcept {
    // A read of a PROT_NONE page. If the protection is real this does not
    // return; if it is not, the child writes a byte and exits 0, which the
    // parent reports as a protection that was accepted and not applied.
    auto* p = static_cast<volatile std::uint8_t*>(at);
    const std::uint8_t v = *p;
    ::_exit(v == 0xff ? 0 : 4);
}

void child_write_to_readonly(void* at) noexcept {
    auto* p = static_cast<volatile std::uint8_t*>(at);
    *p = 0x11;
    ::_exit(0);
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
    check(c.exited_normally && c.exit_code == 0,
          "the mapped pages hold what was written to them");

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
    check(c.signalled && c.signal_number == SIGSEGV,
          "the pages are gone after unmap");
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
    check(writable.exited_normally && writable.exit_code == 0,
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
    check(blocked.signalled && blocked.signal_number == SIGSEGV,
          "a no-access page faults on read");

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
    check(!still_readable.signalled,
          "a read-only page is still readable");

    const ChildOutcome write_blocked =
        run_in_child(child_write_to_readonly, reinterpret_cast<void*>(at));
    check(write_blocked.signalled && write_blocked.signal_number == SIGSEGV,
          "a read-only page faults on write");

    check(m.unmap(at).ok(), "unmap after the protection changes succeeds");
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
    check(c.exited_normally && c.exit_code == 0,
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

// The batch is all of the mapping or none of it, on both sides.
void test_map_batch_is_all_or_nothing() {
    AddressSpace space;
    Mapper m(space);

    // Three regions that are all placeable. The base is chosen far enough
    // above the window floor to be out of the way of everything else the
    // process has, so the test is about the batch and not about a collision
    // with the C library.
    const std::uint64_t base = 0x200000000ULL;
    std::vector<Mapper::Candidate> batch = {
        {base, 64 * 1024, PageProtection::ReadWrite, RegionKind::Image, ".text",
         1},
        {base + 64 * 1024, 64 * 1024, PageProtection::ReadWrite,
         RegionKind::Image, ".data", 2},
        {base + 128 * 1024, 64 * 1024, PageProtection::ReadOnly,
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
    check(first_ok.exited_normally && first_ok.exit_code == 0,
          "the first region of the batch is real memory");

    const ChildOutcome third_blocked =
        run_in_child(child_write_to_readonly,
                     reinterpret_cast<void*>(base + 128 * 1024));
    check(third_blocked.signalled && third_blocked.signal_number == SIGSEGV,
          "the read-only region of the batch really is read-only");

    // The kernel's own map, as a third reading of the same three protections.
    // The per-region protection was passed per candidate, so this is also a
    // check that the batch did not apply the first candidate's protection to
    // all three -- which is the mistake a loop that hoisted the protection
    // out of the loop would make.
    const std::string maps = read_self_maps();
    check(maps_has(maps, base, "rw-p"),
          "the kernel says the first region is rw");
    check(maps_has(maps, base + 128 * 1024, "r--p"),
          "the kernel says the third region is read-only");
    check(maps_has(maps, base + 64 * 1024, "rw-p"),
          "the kernel says the second region is rw");

    // Now a batch that fails. The third candidate overlaps the first, which
    // the ledger would refuse -- but by then two regions are already mapped,
    // so the question is whether they are mapped *after* the refusal.
    const std::uint64_t far = 0x300000000ULL;
    std::vector<Mapper::Candidate> bad = {
        {far, 64 * 1024, PageProtection::ReadWrite, RegionKind::Private, "", 0},
        {far + 32 * 1024, 64 * 1024, PageProtection::ReadWrite,
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
    check(gone.signalled && gone.signal_number == SIGSEGV,
          "the refused batch unmapped the regions it had already mapped");

    // A batch refused before it maps anything: an unaligned base is caught
    // in the validation sweep, so not even the first candidate is mapped.
    const std::uint64_t later = 0x400000000ULL;
    std::vector<Mapper::Candidate> unaligned = {
        {later, 64 * 1024, PageProtection::ReadWrite, RegionKind::Private, "",
         0},
        {later + 64 * 1024 + 1, 64 * 1024, PageProtection::ReadWrite,
         RegionKind::Private, "", 0},
    };
    check(!m.map_batch(unaligned).ok(),
          "a batch with an unaligned base is refused");
    const ChildOutcome never_mapped =
        run_in_child(child_touch_protected, reinterpret_cast<void*>(later));
    check(never_mapped.signalled && never_mapped.signal_number == SIGSEGV,
          "the refused batch never mapped its first candidate");

    // And the batch that did succeed is still whole.
    check(space.regions().size() == 3,
          "the successful batch is untouched by the failures after it");

    for (int i = 0; i < 3; ++i) {
        (void)m.unmap(base + static_cast<std::uint64_t>(i) * 64 * 1024);
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

} // namespace

int main() {
    test_a_mapping_is_writable_memory();
    test_unmapping_removes_the_pages();
    test_protect_really_protects();
    test_execute_and_write_copy_translate_separately();
    test_refusals_leave_nothing_behind();
    test_unmap_addresses_a_region_exactly();
    test_map_batch_is_all_or_nothing();
    test_guard_is_refused_rather_than_ignored();
    test_the_counter_counts_syscalls();

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

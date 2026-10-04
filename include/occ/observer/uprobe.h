#pragma once

// Userspace probes.
//
// A uprobe is the kernel inserting a trap into the text of a file the
// target has mapped. Occ asks for it; the kernel writes the bytes. Occ
// never writes the target's code, and docs/SECURITY.md states that
// distinction without hedging, because a reader who assumes Occ writes the
// trap will draw the wrong conclusion about what Occ guarantees.
//
// What a uprobe is for here is function-level observation on a target whose
// syscalls say too little. Wine's Unix-side ntdll is the case that matters:
// a PE request becomes a Unix syscall there, and the syscall alone does not
// say which Win32 call produced it. A probe on the ntdll function does,
// without touching the PE.
//
// ------------------------------------------------------------------ the ABI
//
// There is no single syscall that registers a probe. The mechanism the
// kernel actually offers is a two-step one:
//
//   1. A probe event is written to a text file in tracefs, one line of the
//      form
//
//          p:occ_0 /path/to/lib.so:0x1234
//          r:occ_1 /path/to/lib.so:0x1234
//
//      The kernel parses the line, resolves the file and the offset against
//      the probes it can attach to, and creates a dynamic trace event.
//      Reading back the same file yields the name the kernel assigned and,
//      alongside it, an id under .../events/<name>/id.
//
//   2. A perf event is opened with type PERF_TYPE_TRACEPOINT and config set
//      to that id. The perf event is what delivers hits: the tracefs entry
//      is the registration and the perf event is the subscription.
//
// So this layer has two resources per probe, not one. The event line has to
// be removed when the probe is, and the removal has to be by the name the
// kernel assigned and not by the line that was written -- a line that names
// a file the kernel could not resolve is accepted into the file and
// silently attaches nothing.
//
// The p and r prefixes are the two directions: p is an entry probe and r is
// a return probe, which the kernel implements by also probing the function's
// return address. A function whose return offset is zero cannot carry an r
// probe and the kernel refuses the line, which is reported rather than
// retried.
//
// ------------------------------------------------------------------ offsets
//
// The offset in a uprobe line is a file offset, not a virtual address. That
// is the reason the ELF reader grew vaddr_to_file_offset, and it is the
// single most expensive thing to get wrong here: an offset that is not in
// the file is refused at registration, and the error names the offset rather
// than the conversion that produced it.

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace occ::obs {

// Which direction a probe fires in.
enum class ProbeKind : std::uint8_t {
    // Before the function's first instruction runs. This is the one that
    // answers "was this called".
    Entry,
    // After the function returns. Paired with an entry probe it gives a
    // duration; on its own it gives the return value for a function whose
    // ABI this layer knows, which is most of the ntdll surface.
    Return,
};

// One registered probe.
struct Uprobe {
    // The name this layer was asked for, which is the symbol's name. It is
    // what a consumer matches against and it is not what tracefs sees.
    std::string name;
    // The name the kernel assigned, of the form occ_<n>. Removing a probe
    // requires this and not the symbol name: the tracefs interface matches
    // the group and event name it created, and a removal that writes back
    // the original line reports nothing while leaving the event in place.
    std::string event;
    // The id of the dynamic event, which is what a perf event's config
    // field takes.
    std::uint64_t id = 0;
    std::string path;
    std::uint64_t offset = 0;
    ProbeKind kind = ProbeKind::Entry;
    // The perf descriptor delivering hits, or -1 when the probe is
    // registered but no subscription was made. See Uprobes::enable for why
    // the two steps can be separated.
    int fd = -1;

    void* ring = nullptr;
    std::size_t ring_bytes = 0;
    std::size_t ring_data_offset = 0;
    std::size_t ring_tail = 0;
};

// One hit, decoded out of a perf ring buffer record.
struct UprobeHit {
    int pid = 0;
    int tid = 0;
    // The probe's name, resolved through the id the record carries. Empty
    // when the id does not match a probe this object registered, which is
    // what a hit from a probe that was removed between the sample and the
    // read looks like.
    std::string name;
    // The instruction pointer in the target at the moment of the hit. For
    // an entry probe it is the function's first byte; for a return probe it
    // is the address the function returned to.
    std::uint64_t ip = 0;
    // The argument registers, in the order the x86-64 ABI passes them:
    // rdi, rsi, rdx, rcx, r8, r9. Zero when the sample did not carry them,
    // which is the case when the probe was opened without the register
    // fields requested.
    std::uint64_t args[6] = {0, 0, 0, 0, 0, 0};
    bool has_args = false;
};

// Why a probe layer is unavailable, and what is still possible without it.
//
// This is the failure that DESIGN.md calls a degradation rather than a
// failure: function-level events stop and syscall-level events continue. A
// session that reported a failure would be claiming nothing can be
// observed, which is not what happened.
struct ProbeAvailability {
    // True when a probe could be registered right now.
    bool available = false;
    // The tracefs directory that would be written, empty when none is
    // mounted. Reported because "no tracefs" and "tracefs that refuses
    // writes" are different problems with different fixes.
    std::string tracefs_root;
    // A sentence describing why the answer is no. Empty when available.
    std::string reason;
};

class Uprobes {
public:
    Uprobes() = default;
    // Binds the layer to a named tracefs instead of the two standard
    // mounts. The root is checked when the first probe is registered, not
    // here, so that constructing one of these costs nothing and cannot fail.
    explicit Uprobes(std::string tracefs_root)
        : explicit_root_(std::move(tracefs_root)) {}
    Uprobes(const Uprobes&) = delete;
    Uprobes& operator=(const Uprobes&) = delete;
    ~Uprobes();

    // Whether this host can register a probe at all.
    //
    // Checked without registering one, because the answer is wanted before
    // anything has been touched: a caller deciding whether to offer
    // function-level observation asks first, and a check that left an event
    // behind would have to be undone in a place that may not be reached.
    //
    // The two things that can make it unavailable are separate and both are
    // reported: no tracefs is mounted, or tracefs is mounted and
    // uprobe_events is not writable. The second is a host with tracefs and
    // without the permission, which is a configuration rather than a
    // missing feature, and it says so.
    //
    // `explicit_root` names the tracefs to use instead of searching the two
    // standard mounts. A container can mount tracefs anywhere, and a run
    // that has been given one path should not be told the two it did not
    // use are absent -- the message would be about this layer's search
    // rather than about the host's state. Empty means search.
    [[nodiscard]] static ProbeAvailability availability(
        const std::string& explicit_root = {}) noexcept;

    // Registers one probe. The offset is a file offset.
    //
    // Registration and subscription are separate steps, and this performs
    // both: the tracefs line is written, the id is read back, and a perf
    // event is opened on it. A probe that is registered without a
    // subscription delivers its hits to the trace buffer and this layer
    // never sees them, which is one failure mode that cannot be detected
    // from the outside -- so they are not left separable.
    //
    // Returns 0 on success and a negative errno otherwise, with `detail`
    // holding a sentence that names what failed.
    [[nodiscard]] int add(const std::string& name, const std::string& path,
                          std::uint64_t offset, ProbeKind kind,
                          std::string& detail) noexcept;

    // Writes the tracefs line and reads back the id the kernel assigned,
    // leaving the probe in the layer without a subscription. Returns the
    // index of the new probe through `out`, 0 on success.
    //
    // This is the half of add that touches tracefs, and it is a public
    // method because a caller registering many probes may want to write
    // all of them before opening any subscription -- the tracefs write is
    // the slow part and doing them together is one syscall batch instead
    // of one per probe. It is also the only way to reach the registered-
    // but-unsubscribed state, which is why add does not leave it
    // reachable on its own.
    //
    // Because the state it produces is the one that cannot be detected
    // from outside, a caller that uses it owns the subscription: a probe
    // left here after a failure delivers hits nobody reads.
    [[nodiscard]] int register_only(const std::string& name,
                                    const std::string& path,
                                    std::uint64_t offset, ProbeKind kind,
                                    std::size_t& out_index,
                                    std::string& detail) noexcept;

    // Opens the subscription for a probe that is registered. Used by add,
    // and exposed so that a caller that wants to register many probes and
    // subscribe to them together can. A probe already subscribed to is left
    // alone.
    [[nodiscard]] int subscribe(std::size_t index,
                                std::string& detail) noexcept;

    // Removes every probe and the tracefs events behind them.
    void clear() noexcept;

    // The descriptors to poll. A probe that is registered but not
    // subscribed has no descriptor and is not listed.
    [[nodiscard]] std::vector<int> fds() const noexcept;

    // Drains every ring buffer and appends the decoded hits to `out`.
    // Returns the number of hits produced.
    //
    // A record that cannot be decoded is skipped rather than guessed at.
    // The rings are per probe, so a corrupt record costs its own probe's
    // events and not the others'.
    std::size_t read_hits(std::vector<UprobeHit>& out) noexcept;

    [[nodiscard]] const std::vector<Uprobe>& all() const noexcept {
        return probes_;
    }
    [[nodiscard]] std::size_t size() const noexcept { return probes_.size(); }

    // The tracefs root this layer resolved, empty until the first
    // registration resolved one. Reported because a caller that placed ten
    // probes wants to say which tracefs they went into, and because a layer
    // that placed none can be asked where it would have.
    [[nodiscard]] const std::string& tracefs_root() const noexcept {
        return root_;
    }

    // How many hits the kernel reported as lost. A lost hit is a call the
    // observer never saw, and in a call-counting tool that is a wrong
    // number rather than a missing one. Kept for the same reason the watch
    // ring keeps it: "the ring wrapped" and "the function was never called"
    // are indistinguishable in the output otherwise.
    [[nodiscard]] std::uint64_t lost_hits() const noexcept {
        return lost_hits_;
    }

private:
    // Removes one probe's tracefs event and closes its descriptor, without
    // touching the vector. Shared by clear and the destructor.
    static void release(Uprobe& p) noexcept;

    // Reads the id for an event the kernel created. Returns 0 and fills
    // `out` on success.
    [[nodiscard]] static int read_event_id(const std::string& root,
                                           const std::string& event,
                                           std::uint64_t& out) noexcept;

    std::vector<Uprobe> probes_;
    std::uint64_t lost_hits_ = 0;
    // The next event number to try. The kernel requires the name to be
    // unique within the group, and a name that collides is refused -- so
    // the counter is advanced on every attempt rather than only on success,
    // because the collision is exactly what advancing resolves.
    std::uint64_t next_event_ = 0;
    // The tracefs this layer resolved on its first registration, and the
    // root it was told to use if any. The second is what is passed to
    // availability(); the first is what the answer named and is what every
    // later path is built from, so a root chosen once is the root used for
    // the life of the object.
    std::string explicit_root_;
    std::string root_;
};

} // namespace occ::obs

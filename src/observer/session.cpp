#include "occ/observer/session.h"

#include "occ/observer/transport.h"

#include "occ/syscall/errno.h"
#include "occ/syscall/syscall.h"
#include "occ/util/string.h"

#include <cerrno>

#include <poll.h>
#include <unistd.h>

namespace occ::obs {

namespace {

constexpr int kSigstop = 19;

// The syscall numbers the tracker has to recognise by hand. They are
// restated from the kernel's x86-64 table because there is no syscall that
// reports "what syscall is this" -- the tracee is stopped at the
// instruction, and reading the number out of the register block is the only
// way to know.
//
// Only the ones that change what memory is mapped or what it may be used
// for are listed. A transition to executable requires one of these, and
// nothing else in the syscall table can produce one.
constexpr std::uint64_t kSysMmap = 9;
constexpr std::uint64_t kSysMprotect = 10;
constexpr std::uint64_t kSysMunmap = 11;
constexpr std::uint64_t kSysMremap = 25;

// The syscalls that name a path, and so are the ones a file-access event can
// be built from. open and openat are the two a dynamically linked target
// actually uses -- the C library's open() is a wrapper around openat on this
// architecture -- and openat2 is the same operation with a flags struct, so
// it is recognised by number but reported with the path its arguments carry.
//
// openat2 takes a how{} structure rather than a flags word, and reading that
// structure needs a second memory read whose layout is the kernel's rather
// than the C library's. It is recognised but reported without flags, because
// a report that guessed the struct's layout would be worse than one that
// reported less.
constexpr std::uint64_t kSysOpen = 2;
constexpr std::uint64_t kSysOpenat = 257;
constexpr std::uint64_t kSysOpenat2 = 437;

// The longest path reported. A path longer than this is truncated and the
// record says so, because the alternative is a record whose size is set by
// the target: a program that opens a megabyte-long path would make every
// consumer allocate a megabyte to read one line of a trace.
constexpr std::size_t kMaxPathLength = 512;

} // namespace

namespace {

// The digits the register block is written in. The 'g' reply is hex, and
// writing the nibbles directly is cheaper than converting each byte through a
// format call on a path that runs on every stop.
constexpr std::string_view kHexDigits = "0123456789abcdef";

// How many registers the target description below declares: the forty GDB
// requires of "org.gnu.gdb.i386.core", plus %fs_base, %gs_base and %orig_rax.
// The count itself is derived from kGdbFields below, so this comment is about
// why that table has the shape it does.
//
// The forty are not ours to choose. GDB validates a target description against
// the layout its own x86-64 tdep declares, in i386_validate_tdesc_p: it walks
// the first num_core_regs entries of the core feature and requires each one to
// be present, in order, under the name that tdep lists for it. num_core_regs is
// forty on x86-64, because the core feature ends at %fop and not at %gs. A
// description that stops at the general registers is rejected outright with
// "Architecture rejected target-supplied description", and the rejection is
// only a warning: GDB then falls back to its built-in 32-bit defaults and reads
// the rest of the 'g' reply at the wrong offsets, so every register past the
// gap shows a plausible value under the wrong name.
//
// Note this is a count of registers, not a count of bytes. The block itself is
// kGdbRegisterBytes, and the two are not related by a factor of eight -- see
// fill_gdb_registers.

// The register GDB treats as the program counter, per the description below.
constexpr std::size_t kPcRegnum = 16;

// The register numbers GDB assigns to the three this stub adds past the core
// feature. These are not free choices: they come from GDB's own i386 register
// enum, and reading the wrong one answers a question about %gs_base with the
// syscall number. The core forty occupy 0 through 39 in that enum and GDB
// reserves 40 through 51 for the SSE and AVX banks, so %fs_base and %gs_base
// land well past this stub's block -- at 152 and 153 -- and %orig_rax, which
// has no number in the enum at all, is reported at the one past the end.
constexpr std::size_t kFsBaseRegnum = 152;
constexpr std::size_t kGsBaseRegnum = 153;
constexpr std::size_t kOrigRaxRegnum = 154;

// One register's place in the 'g' block: where it starts and how wide it is.
// The order is the order fill_gdb_registers writes and the order
// handle_write_registers parses, and all three read this one table, so a
// register cannot be described in the document at one width and supplied at
// another. That mistake is invisible from either side alone -- each path is
// self-consistent -- and it does not corrupt one register, it shifts every
// register after the gap, so %st0 ends up holding %fop and a backtrace names
// the wrong frame.
struct GdbField {
    std::size_t offset;
    unsigned bits;
};

// The x86-64 block, in bytes: seventeen general registers and %rip at eight
// bytes each, then %eflags and the six segment selectors at four, then the
// eight x87 stack registers at ten, then the eight x87 control registers at
// four, then %fs_base, %gs_base and %orig_rax at eight. GDB packs a target
// description end to end with no padding, so these add up to exactly the size
// below -- 300 bytes, and not one more.
constexpr GdbField kGdbFields[] = {
    {0, 64},   {8, 64},   {16, 64},  {24, 64},  {32, 64},  {40, 64},
    {48, 64},  {56, 64},  {64, 64},  {72, 64},  {80, 64},  {88, 64},
    {96, 64},  {104, 64}, {112, 64}, {120, 64}, {128, 64},
    {136, 32}, {140, 32}, {144, 32}, {148, 32}, {152, 32}, {156, 32},
    {160, 32},
    {164, 80}, {174, 80}, {184, 80}, {194, 80}, {204, 80}, {214, 80},
    {224, 80}, {234, 80},
    {244, 32}, {248, 32}, {252, 32}, {256, 32}, {260, 32}, {264, 32},
    {268, 32}, {272, 32},
    {276, 64}, {284, 64}, {292, 64},
};

constexpr std::size_t kGdbRegisterCount =
    sizeof(kGdbFields) / sizeof(kGdbFields[0]);

// The size of the block, summed from the table at compile time so it cannot
// disagree with the widths the description declares.
constexpr std::size_t kGdbRegisterBytes = []{
    std::size_t total = 0;
    for (const GdbField& f : kGdbFields) {
        total += (f.bits + 7u) / 8u;
    }
    return total;
}();

// One register out of the block, by the index the target description gives.
//
// The indexing is by the register number GDB uses, not by position in the 'g'
// block. Those are the same for the forty core registers -- GDB numbers them
// 0 through 39 in document order -- but they part company past that, because
// GDB reserves 40 through 51 for the SSE and AVX banks this description does
// not declare. So %fs_base is position 40 in the block and register 152 to
// GDB. The 'p' handler asks by register number and the 'g' handler walks the
// block in order, and both land here.
std::uint64_t gdb_register(const Registers& r, std::size_t regnum) noexcept {
    switch (regnum) {
    case 0: return r.rax;
    case 1: return r.rbx;
    case 2: return r.rcx;
    case 3: return r.rdx;
    case 4: return r.rsi;
    case 5: return r.rdi;
    case 6: return r.rbp;
    case 7: return r.rsp;
    case 8: return r.r8;
    case 9: return r.r9;
    case 10: return r.r10;
    case 11: return r.r11;
    case 12: return r.r12;
    case 13: return r.r13;
    case 14: return r.r14;
    case 15: return r.r15;
    case 16: return r.rip;
    case 17: return r.eflags;
    case 18: return r.cs;
    case 19: return r.ss;
    case 20: return r.ds;
    case 21: return r.es;
    case 22: return r.fs;
    case 23: return r.gs;
    // Registers 24 through 39 are the x87 stack (%st0-%st7) and the x87
    // control block (%fctrl-%fop). The kernel's user_regs_struct does not
    // carry them and a stop in a syscall is not an x87 context, so there is
    // nothing truthful to report and zero is the honest answer. They are still
    // named here so that asking for one gets an answer rather than a refusal.
    case kFsBaseRegnum: return r.fs_base;
    case kGsBaseRegnum: return r.gs_base;
    case kOrigRaxRegnum: return r.orig_rax;
    default: return 0;
    }
}

// Writes back the registers the kernel accepts from SETREGS on this
// architecture: the sixteen general registers and %rip.
//
// Everything else the block names is deliberately not written. The caller
// leaves those entries zeroed, so assigning them here would push a zero into
// the tracee's context for a register the debugger never mentioned -- clearing
// the thread and group selectors, or worse, the flags, on the strength of a
// packet this stub only understood in part. %eflags and the segment selectors
// are the sharpest case: they are present in the block and readable, and the
// kernel's setregs rejects them on x86-64, so honouring them would either
// error out or be silently dropped depending on the kernel.
void set_gdb_register(Registers& r, const std::uint64_t* values) noexcept {
    r.rax = values[0];
    r.rbx = values[1];
    r.rcx = values[2];
    r.rdx = values[3];
    r.rsi = values[4];
    r.rdi = values[5];
    r.rbp = values[6];
    r.rsp = values[7];
    r.r8 = values[8];
    r.r9 = values[9];
    r.r10 = values[10];
    r.r11 = values[11];
    r.r12 = values[12];
    r.r13 = values[13];
    r.r14 = values[14];
    r.r15 = values[15];
    r.rip = values[16];
    // values[17..23] are %eflags and the segment selectors, values[24..39] the
    // x87 block, and values[40..42] %fs_base, %gs_base and %orig_rax. All of
    // them stay as the kernel last reported them.
}

// The register block GDB expects for x86-64, packed in the order and at the
// widths the target description below declares.
//
// The block is not an array of eight-byte cells and this used to assume it was.
// The description gives each register its own width and GDB packs them
// end to end with no padding, so the block for x86-64 is 300 bytes and not one
// byte more: seventeen general registers and %rip at eight bytes each, then the
// seven 32-bit registers %eflags and the segment selectors, then the eight x87
// stack registers at ten bytes each, then the eight 32-bit x87 control
// registers, then %fs_base, %gs_base and %orig_rax at eight bytes each.
//
// Getting this wrong is quiet in the worst way. Sending eight bytes for a
// four-byte register does not make GDB read that one wrongly -- it shifts every
// register after it, so %st0 shows up holding %fop and a backtrace names the
// wrong frame. And because the sizes are only described in the document, nothing
// in this file would catch it: the same register list, packed two different
// ways, produces two self-consistent builds. The table below is therefore the
// single place the layout is written down, and the byte count is checked
// against it rather than recomputed.
// Appends one register of the given width in bits, little endian, which is the
// order every register in this block is stored in.
void append_gdb_register(std::string& out, std::uint64_t value,
                         unsigned bits) noexcept {
    const unsigned bytes = (bits + 7u) / 8u;
    // Mask off anything above the declared width first. A 32-bit register fed a
    // 64-bit value has to come back as the low half, exactly as the kernel
    // would report it, and sending the surplus would push the rest of the block
    // out of alignment.
    if (bits < 64) {
        value &= (std::uint64_t{1} << bits) - 1u;
    }
    for (unsigned i = 0; i < bytes; ++i) {
        const auto byte = static_cast<unsigned>((value >> (8u * i)) & 0xFFu);
        out += kHexDigits[byte >> 4];
        out += kHexDigits[byte & 0xFu];
    }
}

void fill_gdb_registers(const Registers& r, std::string& out) noexcept {
    out.clear();
    out.reserve(kGdbRegisterBytes * 2);

    for (std::size_t i = 0; i < kGdbRegisterCount; ++i) {
        // gdb_register answers by GDB's register number, which is the same as
        // the position in this table for the forty core registers. It is not
        // the same past those: GDB reserves 40 through 51 for the SSE and AVX
        // banks this description does not declare, so %fs_base sits at 152
        // there and at 40 here. Reading the table below by GDB's numbering
        // would answer a question about %orig_rax with %fs_base.
        const unsigned bits = kGdbFields[i].bits;
        if (i < 17) {
            append_gdb_register(out, gdb_register(r, i), bits);
        } else if (i < 24) {
            // %eflags and the six segment selectors. The kernel reports these
            // as 32 bits and the description declares them that way, so they
            // are sent as four bytes. Sending eight would shift the whole x87
            // block that follows.
            append_gdb_register(out, gdb_register(r, i), bits);
        } else if (i < 40) {
            // The x87 stack and its control block. The kernel's
            // user_regs_struct does not carry them and a thread stopped at a
            // syscall entry is not an x87 context, so there is nothing
            // truthful to report and zero is the honest answer. They still
            // occupy their ten and four bytes: the description has to declare
            // them for GDB to accept the layout at all, and leaving them out
            // here would shorten the block by eighty-eight bytes.
            append_gdb_register(out, 0, bits);
        } else if (i == 40) {
            // %fs_base is the thread pointer and %gs_base the group selector.
            // %orig_rax is the syscall the thread is stopped in, which is the
            // most valuable thing this stub can show a debugger that asked.
            append_gdb_register(out, r.fs_base, bits);
        } else if (i == 41) {
            append_gdb_register(out, r.gs_base, bits);
        } else {
            append_gdb_register(out, r.orig_rax, bits);
        }
    }
}

// The target description GDB reads through qXfer:features:read.
//
// The register block has to be described here rather than left to the
// protocol's defaults, because the defaults describe a 32-bit i386 target:
// GDB sizes every register from this document, and a register it believes is
// four bytes wide makes every offset in the 'g' packet wrong. The order in
// this list is the order of the 'g' reply, which is also the order
// fill_gdb_registers writes, and the two are cross-checked by the register
// count below.
//
// The core feature is the part GDB checks hardest. i386_validate_tdesc_p walks
// the first num_core_regs registers of "org.gnu.gdb.i386.core" and requires
// each to be present, in order, under the name its x86-64 tdep lists for it --
// the list runs rax..gs, then st0..st7, then fctrl..fop, and ends at %fop. A
// description that stops after %gs is rejected whole, and the rejection is only
// a warning: GDB then falls back to its built-in defaults and reads the rest of
// the 'g' reply at the wrong offsets, so every register after the gap shows a
// plausible value under the wrong name. The x87 registers are declared here to
// satisfy that walk and read as zero, because a thread stopped at a syscall
// entry has no x87 state this stub can see.
//
// %orig_rax is the syscall number the thread is stopped in. GDB has no
// register number for it, so it goes in a feature of its own rather than at
// the end of the core feature, where it would take the slot belonging to %st0
// and shift the whole x87 block up by one.
//
// %fs_base and %gs_base are the thread pointer and the group selector. They
// live in "org.gnu.gdb.i386.segments", which is the feature GDB looks for them
// in by name; declaring them in the core feature instead would leave GDB
// believing %fs has no base, and every backtrace would show a wrong thread
// pointer.
//
// No regnum attribute appears anywhere below, and that is deliberate. GDB
// numbers the registers itself, in document order, from its own tdep enum --
// the numbers in this file would be a second, parallel numbering that GDB
// never consults when it validates the description, and one that would drift
// the moment a register were added. Writing them buys nothing and risks
// GDB believing a layout this file does not actually implement.
//
// The vector size is in bytes and is the x86-64 requirement.
constexpr std::string_view kTargetXml = R"(<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target version="1.0">
  <architecture>i386:x86-64</architecture>
  <feature name="org.gnu.gdb.i386.core">
    <flags id="i386_eflags" size="4">
      <field name="CF" start="0" end="0"/>
      <field name="PF" start="2" end="2"/>
      <field name="AF" start="4" end="4"/>
      <field name="ZF" start="6" end="6"/>
      <field name="SF" start="7" end="7"/>
      <field name="TF" start="8" end="8"/>
      <field name="IF" start="9" end="9"/>
      <field name="DF" start="10" end="10"/>
      <field name="OF" start="11" end="11"/>
      <field name="NT" start="14" end="14"/>
      <field name="RF" start="16" end="16"/>
      <field name="VM" start="17" end="17"/>
      <field name="AC" start="18" end="18"/>
      <field name="VIF" start="19" end="19"/>
      <field name="VIP" start="20" end="20"/>
      <field name="ID" start="21" end="21"/>
    </flags>
    <reg name="rax" bitsize="64" type="int64"/>
    <reg name="rbx" bitsize="64" type="int64"/>
    <reg name="rcx" bitsize="64" type="int64"/>
    <reg name="rdx" bitsize="64" type="int64"/>
    <reg name="rsi" bitsize="64" type="int64"/>
    <reg name="rdi" bitsize="64" type="int64"/>
    <reg name="rbp" bitsize="64" type="data_ptr"/>
    <reg name="rsp" bitsize="64" type="data_ptr"/>
    <reg name="r8" bitsize="64" type="int64"/>
    <reg name="r9" bitsize="64" type="int64"/>
    <reg name="r10" bitsize="64" type="int64"/>
    <reg name="r11" bitsize="64" type="int64"/>
    <reg name="r12" bitsize="64" type="int64"/>
    <reg name="r13" bitsize="64" type="int64"/>
    <reg name="r14" bitsize="64" type="int64"/>
    <reg name="r15" bitsize="64" type="int64"/>
    <reg name="rip" bitsize="64" type="code_ptr"/>
    <reg name="eflags" bitsize="32" type="i386_eflags"/>
    <reg name="cs" bitsize="32" type="int32"/>
    <reg name="ss" bitsize="32" type="int32"/>
    <reg name="ds" bitsize="32" type="int32"/>
    <reg name="es" bitsize="32" type="int32"/>
    <reg name="fs" bitsize="32" type="int32"/>
    <reg name="gs" bitsize="32" type="int32"/>
    <reg name="st0" bitsize="80" type="i387_ext"/>
    <reg name="st1" bitsize="80" type="i387_ext"/>
    <reg name="st2" bitsize="80" type="i387_ext"/>
    <reg name="st3" bitsize="80" type="i387_ext"/>
    <reg name="st4" bitsize="80" type="i387_ext"/>
    <reg name="st5" bitsize="80" type="i387_ext"/>
    <reg name="st6" bitsize="80" type="i387_ext"/>
    <reg name="st7" bitsize="80" type="i387_ext"/>
    <reg name="fctrl" bitsize="32" type="int" group="float"/>
    <reg name="fstat" bitsize="32" type="int" group="float"/>
    <reg name="ftag" bitsize="32" type="int" group="float"/>
    <reg name="fiseg" bitsize="32" type="int" group="float"/>
    <reg name="fioff" bitsize="32" type="int" group="float"/>
    <reg name="foseg" bitsize="32" type="int" group="float"/>
    <reg name="fooff" bitsize="32" type="int" group="float"/>
    <reg name="fop" bitsize="32" type="int" group="float"/>
  </feature>
  <feature name="org.gnu.gdb.i386.segments">
    <reg name="fs_base" bitsize="64" type="int64"/>
    <reg name="gs_base" bitsize="64" type="int64"/>
  </feature>
  <feature name="org.gnu.gdb.i386.syscall">
    <reg name="orig_rax" bitsize="64" type="int64"/>
  </feature>
</target>
)";

// Reads a NUL-terminated string out of a tracee, one bounded chunk at a
// time.
//
// The read is bounded twice over, and both bounds are load-bearing. The
// total is capped at kMaxPathLength so that a record's size is a property of
// this program rather than of the target, and the single read is capped at a
// page because a path that crosses into an unmapped page must fail rather
// than fault the tracee: process_vm_readv on an unmapped address returns
// EFAULT rather than killing the caller, but a request that spans the end of
// a mapping can still be refused wholesale, so a chunked read is what makes a
// long path across several mappings work.
//
// The return value distinguishes three outcomes, because a consumer needs to
// tell them apart: a path that was read, a path that was longer than the cap
// (reported as truncated, with the bytes that did fit), and a path that could
// not be read at all. The third is not a rare case -- a target that unlinks
// a file and immediately opens a path it has just made inaccessible passes a
// perfectly good pointer to a page that is no longer there.
struct PathRead {
    bool ok = false;
    bool truncated = false;
    std::string text;
};

PathRead read_remote_path(Tracer& tracer, int pid, std::uint64_t addr) {
    PathRead out;
    if (addr == 0) {
        // A null path is a target's own bug rather than something to report,
        // and the kernel will return EFAULT for it a moment from now.
        return out;
    }

    constexpr std::size_t kChunk = 256;
    char buffer[kChunk];

    for (std::size_t read = 0; read < kMaxPathLength;) {
        const auto res =
            tracer.read_memory(pid, addr + read, buffer, kChunk);
        if (res.failed() || res.value <= 0) {
            // A read that fails after some bytes have already arrived still
            // has a path in hand -- it is the path up to the point the
            // mapping ended. Reporting it is more useful than reporting
            // nothing, and the truncation flag says it is incomplete.
            out.ok = !out.text.empty();
            out.truncated = true;
            return out;
        }
        const auto got = static_cast<std::size_t>(res.value);
        for (std::size_t i = 0; i < got; ++i) {
            if (buffer[i] == '\0') {
                out.ok = true;
                return out;
            }
            out.text.push_back(buffer[i]);
        }
        read += got;
        if (got < kChunk) {
            // A short read with no terminator means the mapping ends here.
            out.ok = !out.text.empty();
            out.truncated = true;
            return out;
        }
    }

    out.ok = true;
    out.truncated = true;
    return out;
}

} // namespace

Reply DebugServer::handle(std::string_view packet) noexcept {
    if (packet.empty()) {
        // A packet with no command byte. The peer sent "$#00", which is a
        // well-formed packet that asks for nothing in particular; the
        // protocol's answer to a request it does not implement is an empty
        // packet, so it gets one back. Going silent here would be the one
        // answer vMustReplyEmpty exists to catch.
        return Reply::unsupported();
    }

    const char cmd = packet[0];
    const std::string_view args = packet.size() > 1 ? packet.substr(1)
                                                    : std::string_view{};

    switch (cmd) {
    case '?': {
        // Why did we stop. The stop reply carries the program counter,
        // because that is the register a debugger needs to decide what the
        // stop was and it should not have to ask for it separately. Reading
        // it here rather than answering with zero matters: a debugger that
        // resumes from address zero because this returned zero is looking
        // at a target that has already faulted.
        Registers now{};
        std::uint64_t pc = 0;
        if (tracer_->get_regs(pid_, now).ok()) {
            pc = gdb_register(now, kPcRegnum);
        }
        return Reply::packet(encode_stop_reply(gdb_signal_for_trap(), pc));
    }

    case 'v':
        // Only vCont is implemented. A 'v' packet for anything else answers
        // with an empty packet, which is what the protocol defines as
        // unsupported, and the debugger falls back to the single-threaded
        // packets it knows. vMustReplyEmpty is the case that makes this
        // observable: it is named for the answer, and a stub that stays
        // silent fails it.
        if (starts_with(args, "Cont")) {
            return Reply::packet(
                handle_vcont(args.substr(std::string_view{"Cont"}.size())));
        }
        return Reply::unsupported();

    case 'q':
        return Reply::packet(handle_query(args));

    case 'g':
        return Reply::packet(handle_read_registers());

    case 'G':
        return Reply::packet(handle_write_registers(args));

    case 'p': {
        // Read one register by number. The number is the one GDB assigned in
        // its own register enum, not the position in the 'g' block -- the two
        // agree only across the forty core registers, because GDB reserves
        // 40 through 51 for the SSE and AVX banks this description does not
        // declare. Reading by a different index than the description gives is
        // how a debugger ends up displaying one register's value under
        // another's name, so the bound below is the highest number this stub
        // answers for rather than the count of registers in the block.
        //
        // The number arrives as a variable-width hexadecimal value, so "p0"
        // asks for the first register and "p1a" for the twenty-sixth. It is
        // read as a protocol number rather than as a register block: the
        // latter wants eight digits and would refuse both.
        std::uint64_t which = 0;
        if (!parse_hex_number(args, which)) {
            return Reply::unsupported();
        }
        if (which > kOrigRaxRegnum) {
            // Out of range is not "unsupported": the packet is understood
            // and the register does not exist. An empty packet says the
            // former, which would send the debugger looking for a
            // different way to ask.
            return Reply::packet(std::string{});
        }
        Registers r{};
        if (tracer_->get_regs(pid_, r).failed()) {
            return Reply::packet("E01");
        }
        return Reply::packet(
            hex_u64_le(gdb_register(r, static_cast<std::size_t>(which))));
    }

    case 'm':
        return Reply::packet(handle_read_memory(args));

    case 'M':
        return Reply::packet(handle_write_memory(args));

    case 'Z':
    case 'z':
        return Reply::packet(handle_breakpoint(packet));

    case 'H':
        return Reply::packet(handle_thread());

    case 'c':
        // Continue, optionally with a signal to deliver. The session does
        // not resume inside the handler: the loop owns the tracee and has
        // to be the one that decides when it runs.
        //
        // Nothing is sent now, and that is the correct answer rather than
        // an omission. A continue is not a question: the answer is the
        // stop reply, which the loop sends when the target stops again. An
        // empty packet here would say "unsupported" and the debugger would
        // take it for a target that cannot be resumed.
        resume_requested_ = true;
        step_ = false;
        resume_signal_ = 0;
        if (!args.empty()) {
            std::uint64_t sig = 0;
            // A signal number is a variable-width hexadecimal value, which
            // the protocol conventionally writes with two digits.
            if (parse_hex_number(args, sig)) {
                resume_signal_ = static_cast<int>(sig);
            }
        }
        return Reply::nothing();

    case 's':
        resume_requested_ = true;
        step_ = true;
        resume_signal_ = 0;
        return Reply::nothing();

    case 'D':
        detached_ = true;
        return Reply::packet("OK");

    case 'k':
        // A kill request. The session reports it as a detach and lets the
        // caller decide; killing a process the user did not ask to kill is
        // not something a debugger stub does on its own. The detach is the
        // answer and it is carried by the session ending, so nothing is
        // sent on the wire.
        detached_ = true;
        return Reply::nothing();

    case '#':
        // The checksum the decoder has already consumed never reaches a
        // command byte. Reaching here means a payload that began with '#',
        // which no request does.
        return Reply::unsupported();

    default:
        // Anything else is unsupported, and an empty packet is the
        // protocol's way of saying so.
        return Reply::unsupported();
    }
}

std::string DebugServer::handle_query(std::string_view kind) noexcept {
    if (starts_with(kind, "Supported")) {
        // The features this stub implements.
        //
        // The list is a contract and it is kept honest in both directions.
        // Claiming a feature that is not implemented makes the debugger take
        // a code path that then fails in a way that looks like a bug in the
        // debugger; omitting one that is implemented makes the debugger fall
        // back to a slower or less precise path it did not have to take.
        // Every entry below names the packet that implements it.
        //
        // vContSupported+ is here because handle_vcont() implements the
        // actions, and qXfer:features:read+ because
        // handle_qxfer_features() serves the target description.
        //
        // xmlRegisters=i386 is what makes the debugger fetch the target
        // description at all. Without it gdb keeps its built-in default,
        // which describes a 32-bit i386 target with 17 registers, and every
        // register read is then the wrong width at the wrong offset -- the
        // 'g' reply is rejected as truncated and no register is shown. The
        // name is i386 even for an x86-64 target: it names the register
        // description format, not the processor.
        return "qXfer:features:read+;swbreak+;hwbreak+;vContSupported+;"
               "xmlRegisters=i386";
    }
    if (starts_with(kind, "Xfer:features:read:")) {
        return handle_qxfer_features(
            kind.substr(std::string_view{"Xfer:features:read:"}.size()));
    }
    if (starts_with(kind, "Attached")) {
        // Already attached, because the session was created from a process
        // it owns rather than by asking the target to spawn one.
        return "1";
    }
    if (starts_with(kind, "C")) {
        // The current thread. This stub observes one process, so the answer
        // is always that process.
        return "QC" + hex_number(static_cast<std::uint64_t>(pid_));
    }
    if (starts_with(kind, "fThreadInfo")) {
        return "m" + hex_number(static_cast<std::uint64_t>(pid_));
    }
    if (starts_with(kind, "sThreadInfo")) {
        return "l";
    }
    if (starts_with(kind, "TStatus")) {
        return "T0";
    }
    // qSymbol and every other query this stub does not answer fall through
    // to an empty response, which the protocol defines as "not supported".
    return {};
}

std::string_view target_description() noexcept {
    return kTargetXml;
}

std::size_t gdb_register_block_size() noexcept {
    return kGdbRegisterBytes;
}

unsigned gdb_register_bits(std::size_t index) noexcept {
    if (index >= kGdbRegisterCount) {
        return 0;
    }
    return kGdbFields[index].bits;
}

std::size_t gdb_regnum_fs_base() noexcept {
    return kFsBaseRegnum;
}

std::size_t gdb_regnum_gs_base() noexcept {
    return kGsBaseRegnum;
}

std::size_t gdb_regnum_orig_rax() noexcept {
    return kOrigRaxRegnum;
}

std::string serve_target_description(std::string_view args) noexcept {
    // The packet is "qXfer:features:read:ANNEX:OFFSET,LENGTH" and the
    // dispatcher has already removed the "qXfer:features:read:" prefix, so
    // what arrives here is the annex and the range, separated by one colon.
    //
    // The prefix that comes off is fixed text naming this one object, so the
    // annex is whatever is left before the colon. Only "target.xml" exists;
    // a request for any other annex answers "l", the protocol's way of
    // saying there is no such object, so a debugger that asks for a file it
    // might find elsewhere stops asking rather than treating the absence as
    // an error.
    const std::size_t colon = args.find(':');
    if (colon == std::string_view::npos) {
        return {};
    }
    const std::string_view annex = args.substr(0, colon);
    const std::string_view range = args.substr(colon + 1);

    if (annex != "target.xml") {
        return "l";
    }

    const std::size_t comma = range.find(',');
    if (comma == std::string_view::npos) {
        return {};
    }
    std::uint64_t offset = 0;
    std::uint64_t length = 0;
    if (!parse_hex_number(range.substr(0, comma), offset) ||
        !parse_hex_number(range.substr(comma + 1), length)) {
        return {};
    }

    const std::string_view xml = kTargetXml;

    // An offset at or past the end answers 'l' rather than an error. GDB
    // fetches the document in chunks and the final request legitimately
    // lands exactly at the end, which is not the same as running off it.
    if (offset >= xml.size() || length == 0) {
        return "l";
    }

    // The subtraction cannot underflow: offset is below xml.size() and both
    // are the same type, so available is at least one and take is at most
    // that. The clamp is what keeps a length larger than the remainder from
    // asking substr for more than the document holds.
    const std::size_t available = xml.size() - static_cast<std::size_t>(offset);
    const std::size_t take = length < available
                                 ? static_cast<std::size_t>(length)
                                 : available;

    // The leading 'm' or 'l' says whether more remains. Deciding it here
    // rather than always answering 'm' is what stops GDB from asking for one
    // more chunk forever.
    std::string out;
    out.reserve(take + 1);
    out += (take < available) ? 'm' : 'l';
    // The document is ASCII, so its bytes are already the wire form. The
    // escaping a binary packet needs is applied by encode_packet.
    out.append(xml.substr(static_cast<std::size_t>(offset), take));
    return out;
}

std::string parse_vcont(std::string_view args, int pid, bool& consume,
                        bool& step, int& signal) noexcept {
    // vCont is the multiplexed form of c, s, C and S. The packet is
    // "vCont[;action[:thread-id]]...", where an action is a letter
    // optionally followed by a condition, and an absent thread-id means every
    // thread. The older packets remain the fallback for a debugger that does
    // not use it, so implementing vCont does not replace them.
    //
    // "vCont?" asks which actions are supported. The answer is the list of
    // them, separated by colons, exactly as it would appear in a request,
    // and it is the answer that lets a debugger choose vCont at all.
    //
    // The outputs are cleared before the query is answered rather than
    // after. A debugger sends the query before any action, and a stub that
    // answered it while leaving the caller's flags as they were would resume
    // with whatever an earlier packet happened to set: a debugger that asked
    // what is supported and then asked to continue would single-step.
    consume = false;
    step = false;
    signal = 0;

    if (args.empty()) {
        return "c:C;s:S;r:t";
    }

    std::size_t pos = 0;
    while (pos <= args.size()) {
        const std::size_t next = args.find(';', pos);
        const std::string_view action =
            args.substr(pos, next == std::string_view::npos
                                 ? std::string_view::npos
                                 : next - pos);
        if (!action.empty()) {
            // An action is one letter followed by an optional signal, then an
            // optional thread id: "c", "C05", "s:2", "S0b:2". The signal
            // follows the letter directly and is hexadecimal, which is why it
            // is split off by taking the single leading letter rather than by
            // looking for a separator -- reading "C05" as a whole word finds
            // neither a known verb nor a signal, and the action is then
            // silently dropped and the process never resumes.
            const std::string_view verb = action.substr(0, 1);

            if (verb == "c" || verb == "C" || verb == "s" || verb == "S") {
                step = (verb == "s" || verb == "S");
                consume = true;
                signal = 0;
                // Only the capitalised forms carry a signal. The lowercase
                // "c" and "s" resume without one, and a digit after them
                // would be the thread id rather than a signal, so nothing
                // here is read.
                if (verb == "C" || verb == "S") {
                    const std::size_t sig_begin = 1;
                    std::size_t sig_end = action.find(':');
                    if (sig_end == std::string_view::npos) {
                        sig_end = action.size();
                    }
                    std::uint64_t sig = 0;
                    if (sig_end > sig_begin &&
                        parse_hex_number(action.substr(sig_begin, sig_end - sig_begin),
                                         sig)) {
                        signal = static_cast<int>(sig);
                    }
                }
                break;
            }
            // "r" starts and "t" stops. A remote target may support them, but
            // this stub owns the process it traces and the session loop is
            // the only thing that resumes it, so neither can be honoured
            // here and neither is advertised by vCont?.
        }

        if (next == std::string_view::npos) {
            break;
        }
        pos = next + 1;
    }

    if (!consume) {
        return {};
    }
    // The reply is the thread that was selected, which is the only thread
    // there is. The session does not resume inside the packet layer: the
    // loop owns the tracee and decides when it runs.
    return "T" + hex_number(static_cast<std::uint64_t>(pid));
}


std::string DebugServer::handle_qxfer_features(std::string_view args) noexcept {
    return serve_target_description(args);
}

std::string DebugServer::handle_vcont(std::string_view args) noexcept {
    // The reply is returned unchanged whether or not a resume was requested:
    // "vCont?" produces an answer with no resume behind it, and a resume the
    // loop has not yet performed still answers with the thread it named. The
    // flags come back through the same references the loop reads, so the
    // packet layer does not decide when the tracee runs.
    return parse_vcont(args, pid_, resume_requested_, step_, resume_signal_);
}

std::string DebugServer::handle_read_registers() noexcept {
    Registers r{};
    auto res = tracer_->get_regs(pid_, r);
    if (res.failed()) {
        return "E01";
    }
    std::string out;
    fill_gdb_registers(r, out);
    return out;
}

std::string DebugServer::handle_write_registers(std::string_view args) noexcept {
    // A 'G' packet carries every register, so its length is fixed by the target
    // description rather than by what the debugger happened to send. The block
    // is not sixteen hex characters per register: the description gives each
    // register its own width and GDB packs them end to end, so the whole block
    // is kGdbRegisterBytes and a field is eight or twenty hex characters wide
    // depending on which register it is. Parsing it as a fixed-stride array
    // would read %st0 out of the middle of %fop.
    if (args.size() < kGdbRegisterBytes * 2) {
        return "E01";
    }

    // Only the first seventeen are writable through SETREGS on this
    // architecture: the sixteen general registers and %rip. %eflags and the
    // segment selectors are named because the description has to name them, and
    // the kernel's setregs rejects them here; the x87 block is not accepted at
    // all, and %fs_base, %gs_base and %orig_rax belong to the syscall entry
    // path. Writing any of them would be either refused or silently undone,
    // which is worse than ignoring the request, so they are left as zero here
    // and never reach the tracee.
    std::uint64_t values[kGdbRegisterCount] = {};
    for (std::size_t i = 0; i < 17 && i < kGdbRegisterCount; ++i) {
        const GdbField& f = kGdbFields[i];
        const std::string_view field =
            args.substr(f.offset * 2, (f.bits / 8u) * 2u);
        if (!parse_hex_u64_le(field, values[i])) {
            return "E01";
        }
    }

    // The current values are read rather than zeroed, because three of the
    // registers the block names -- orig_rax, fs_base and gs_base -- are not
    // writable through SETREGS on this architecture. Starting from zero and
    // writing the whole block would clear the thread and group selectors,
    // and a debugger that set one register would corrupt two it never
    // mentioned. Reading first and overwriting only the writable fields is
    // what makes a partial intent harmless.
    Registers r{};
    auto res = tracer_->get_regs(pid_, r);
    if (res.failed()) {
        return "E01";
    }

    set_gdb_register(r, values);

    if (tracer_->set_regs(pid_, r).failed()) {
        return "E01";
    }
    return "OK";
}

std::string DebugServer::handle_read_memory(std::string_view args) noexcept {
    const std::size_t comma = args.find(',');
    if (comma == std::string_view::npos) {
        return "E01";
    }

    std::uint64_t addr = 0;
    std::uint64_t length = 0;
    {
        std::uint64_t a = 0;
        for (char c : args.substr(0, comma)) {
            const int d = (c >= '0' && c <= '9')
                              ? c - '0'
                              : (c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1);
            if (d < 0) {
                return "E01";
            }
            a = (a << 4) | static_cast<std::uint64_t>(d);
        }
        addr = a;
    }
    {
        std::uint64_t l = 0;
        for (char c : args.substr(comma + 1)) {
            const int d = (c >= '0' && c <= '9')
                              ? c - '0'
                              : (c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1);
            if (d < 0) {
                break;
            }
            l = (l << 4) | static_cast<std::uint64_t>(d);
        }
        length = l;
    }

    // The protocol's read is capped by what fits in one packet. A debugger
    // that asks for more than that is asking for a transfer the framing
    // cannot carry, and the cap is what keeps the answer well-formed.
    constexpr std::uint64_t kMaxRead = 4096;
    if (length == 0 || length > kMaxRead) {
        return "E01";
    }

    std::vector<std::uint8_t> buffer(static_cast<std::size_t>(length));
    auto res = tracer_->read_memory(pid_, addr, buffer.data(), buffer.size());
    if (res.failed() || res.value <= 0) {
        return "E01";
    }

    std::string out;
    out.reserve(static_cast<std::size_t>(res.value) * 2);
    for (long i = 0; i < res.value; ++i) {
        out += hex_u8(buffer[static_cast<std::size_t>(i)]);
    }
    return out;
}

std::string DebugServer::handle_write_memory(std::string_view args) noexcept {
    const std::size_t comma = args.find(',');
    if (comma == std::string_view::npos) {
        return "E01";
    }

    std::uint64_t addr = 0;
    for (char c : args.substr(0, comma)) {
        const int d = (c >= '0' && c <= '9')
                          ? c - '0'
                          : (c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1);
        if (d < 0) {
            return "E01";
        }
        addr = (addr << 4) | static_cast<std::uint64_t>(d);
    }

    const std::size_t colon = args.find(':', comma);
    if (colon == std::string_view::npos) {
        return "E01";
    }
    // The length field between the address and the colon is redundant with
    // the payload and the protocol allows it to be omitted. It is not
    // trusted here: the payload is what is written.

    std::vector<std::uint8_t> bytes;
    if (!parse_hex_bytes(args.substr(colon + 1), bytes)) {
        return "E01";
    }

    auto res = tracer_->write_memory(pid_, addr, bytes.data(), bytes.size());
    if (res.failed()) {
        return "E01";
    }
    return "OK";
}

std::string DebugServer::handle_breakpoint(std::string_view args) noexcept {
    // The packet is Z<type>,<addr>,<kind> or z<type>,<addr>,<kind>. The
    // kind is the instruction length on some targets and is ignored here.
    if (args.size() < 2) {
        return "E01";
    }
    const bool insert = args[0] == 'Z';
    const char type = args[1];

    std::string_view rest = args.substr(3);
    const std::size_t comma = rest.find(',');
    if (comma == std::string_view::npos) {
        return "E01";
    }

    std::uint64_t addr = 0;
    for (char c : rest.substr(0, comma)) {
        const int d = (c >= '0' && c <= '9')
                          ? c - '0'
                          : (c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1);
        if (d < 0) {
            return "E01";
        }
        addr = (addr << 4) | static_cast<std::uint64_t>(d);
    }

    if (type != '0') {
        // Only software breakpoints are implemented. A hardware breakpoint
        // request would have to be served from the four debug registers,
        // and those are the scarce resource the write tracker uses; giving
        // them to the debugger without saying so would silently disable the
        // tracker. Reported as unsupported instead.
        return {};
    }

    std::string detail;
    if (insert) {
        const int rc = breakpoints_->add(*tracer_, pid_, addr, detail);
        if (rc != 0) {
            if (events_ != nullptr) {
                auto& e = events_->begin(EventKind::Note);
                e.add("text", std::string_view{"a breakpoint could not be "
                                               "installed"});
                e.add("address", std::string_view{detail});
                events_->commit();
            }
            return "E01";
        }
    } else {
        (void)breakpoints_->remove(*tracer_, pid_, addr);
    }
    return "OK";
}

std::string DebugServer::handle_thread() noexcept {
    // Thread selection. There is one process and its thread id is its pid,
    // so the selection is always satisfied.
    return "OK";
}

// -------------------------------------------------------------------- loop

SessionResult observe(const SessionConfig& config, Writer& events) noexcept {
    SessionResult out;

    if (config.pid <= 0) {
        out.failed = true;
        out.detail = "the session was given no process to observe";
        return out;
    }

    Tracer tracer;
    Breakpoints breakpoints;
    WriteExecuteTracker wx;

    // The watch manager exists whether or not tracking was asked for,
    // because the debugger's hardware breakpoints would need it too. It is
    // created here so that its destructor runs after the tracker has
    // released its own watches, rather than the other way round.
    Watchpoints watchpoints;

    // How a permission change is noticed.
    //
    // A W-to-X transition is two facts at two different times: the region
    // was written, and later the region became executable. The write is seen
    // through a hardware watch, because there is no other way to observe an
    // access without stopping the target. The permission change is seen
    // through mprotect, because that is the only syscall that can make a
    // mapped page executable, and a program that makes one executable
    // without asking the kernel is not something the kernel lets it do.
    //
    // Intercepting mprotect is therefore not a heuristic that might catch a
    // transition. It is the complete set of places the transition can
    // happen, and a tracker that watched only the writes would know that
    // something was written without ever learning that it ran.
    struct PendingProtect {
        int pid;
        std::uint64_t addr;
        std::uint64_t length;
        bool valid;
    };
    std::vector<PendingProtect> pending_protect;

    auto protect_entry_for = [&](int pid) -> PendingProtect& {
        for (auto& p : pending_protect) {
            if (p.pid == pid) {
                p.valid = false;
                return p;
            }
        }
        pending_protect.push_back(PendingProtect{pid, 0, 0, false});
        return pending_protect.back();
    };

    // The target called PTRACE_TRACEME before its exec, so this process is
    // already its tracer and the target is already stopped at the exec
    // boundary. Seizing it here would be refused, because a process that
    // has called TRACEME belongs to its parent and cannot be seized by it
    // twice.
    //
    // What is left is to consume the initial stop. It is the exec stop the
    // kernel raised on the tracer's behalf, and it has to be read before
    // any options can be set: the kernel ignores SETOPTIONS on a process
    // that has not reported its first stop.
    {
        Stop initial = tracer.wait_pid(config.pid);
        if (initial.kind == StopKind::Exited) {
            out.failed = true;
            out.detail = "the target exited before observation began";
            // The reason is reported because "exited" and "the wait failed"
            // are the same kind here, and they have nothing in common: the
            // first is a target that ran, the second is a tracer that never
            // received its first stop. A caller debugging a run that saw
            // nothing needs to know which one happened.
            auto& e = events.begin(EventKind::Note);
            e.add("text", std::string_view{
                             "no first stop: the wait reported a failure or "
                             "an exit"});
            e.add("pid", static_cast<std::uint64_t>(config.pid));
            e.add("errno", static_cast<std::int64_t>(initial.signal));
            e.add("status", static_cast<std::int64_t>(initial.raw_status));
            events.commit();
            return out;
        }
    }

    unsigned long options = kPtraceO_TRACESYSGOOD | kPtraceO_EXITKILL |
                            kPtraceO_TRACEEXEC | kPtraceO_TRACESECCOMP;
    if (config.follow_forks) {
        options |= kPtraceO_TRACEFORK | kPtraceO_TRACEVFORK |
                   kPtraceO_TRACECLONE | kPtraceO_TRACEVFORKDONE;
    }
    auto opts = tracer.set_options(config.pid, options);
    if (opts.failed()) {
        out.failed = true;
        out.detail = "the trace options were refused";
        (void)tracer.detach(config.pid, 0);
        return out;
    }

    DebugServer server(tracer, breakpoints, config.pid, events);

    // A run that asked for a debugger port hands over the listening socket
    // rather than a connection, because the person running it has to be told
    // where to connect before they can connect. The first pass through the
    // loop accepts whoever arrives; every pass after that serves them.
    Connection connection;

    // Set once the debugger has said to continue. Until then the target stays
    // stopped, which is the point of holding at all: the alternative is a
    // target that has already run past main by the time anybody could have
    // attached.
    bool released_for_debugger = false;

    // The process has been seized and is stopped. The first resume is what
    // lets it run at all.
    const bool trace_syscalls = config.trace_syscalls;
    auto resume = [&](int pid, int signal) -> int {
        auto r = trace_syscalls ? tracer.syscall(pid, signal)
                                : tracer.cont(pid, signal);
        return r.failed() ? r.error : 0;
    };

    // A session that was asked to wait for a debugger does not resume here.
    // The process is stopped at its first instruction of the new image and
    // stays there while the loop below serves the protocol, so a debugger
    // that connects gets a target it can set breakpoints in rather than one
    // that has already run.
    //
    // The resume itself happens inside the loop, once a continue arrives,
    // because the loop is what has to be running to deliver that continue.
    const bool hold_for_debugger = config.wait_for_debugger && config.serve_gdb;
    if (!hold_for_debugger && resume(config.pid, 0) != 0) {
        out.failed = true;
        out.detail = "the process could not be resumed after being seized";
        (void)tracer.detach(config.pid, 0);
        return out;
    }

    // The traced set. A fork adds to it, an exit removes from it, and the
    // loop ends when it is empty rather than when one particular pid exits.
    std::vector<int> traced{config.pid};

    // How many of the layer's probes actually have a subscription. A probe
    // that was registered and never subscribed has no descriptor and can
    // never fire, so the number that matters to a reader of the hit stream
    // is this one and not the layer's size.
    if (config.probes != nullptr) {
        out.probes_watched =
            static_cast<std::uint64_t>(config.probes->layer().fds().size());
    }

    // ---------------------------------------------------------- wx setup
    //
    // The regions to watch come either from the caller, which is the case
    // when something already knows where the target stages its decoded code,
    // or from the target's own maps, which is the case for a run that does
    // not. The scan is done once here rather than on every stop: a target's
    // regions change when it allocates, and re-reading maps per stop would
    // turn the tracker into the largest cost in the session.
    if (config.track_wx) {
        if (!Watchpoints::hardware_available()) {
            // Reported, not treated as a failure. The rest of the session
            // works without the tracker, and a host that blocks
            // perf_event_open should still produce a full event stream --
            // just one with an honest hole in it.
            out.wx_unavailable = true;
            auto& e = events.begin(EventKind::Note);
            e.add("text", std::string_view{
                             "write tracking is off: this host does not "
                             "permit hardware watch events"});
            events.commit();
        } else {
            std::vector<WatchTarget> wanted = config.wx_regions;

            if (wanted.empty()) {
                for (const auto& r : process_regions(config.pid)) {
                    if (config.wx_anonymous_only && !r.anonymous) {
                        continue;
                    }
                    if (r.length == 0 || r.length > config.wx_max_region_bytes) {
                        continue;
                    }
                    // A region that is neither writable nor executable is
                    // not a candidate: nothing can be written to it and
                    // nothing can run from it without a permission change
                    // first, and the permission change is intercepted
                    // separately.
                    if (r.kind == RegionClass::Other) {
                        continue;
                    }
                    WatchTarget t;
                    t.base = r.base;
                    t.length = r.length;
                    wanted.push_back(t);
                }
            }

            for (const auto& t : wanted) {
                std::string detail;
                (void)wx.watch(config.pid, t.base, t.length, detail);
            }

            const ArmReport arms = wx.arm(watchpoints, config.pid);
            out.wx_regions = wx.region_count();
            out.wx_watches = arms.watches_installed;
            out.wx_bytes_covered = arms.bytes_covered;
            out.wx_bytes_total = arms.bytes_total;
            out.wx_regions_unwatched = arms.unwatched.size();

            // The coverage is reported as an event rather than only in the
            // summary because it is the difference between "watching" and
            // "watching these bytes". A consumer reading the stream has to
            // be able to see that four debug registers covered 32 bytes of a
            // 4096-byte region, because that is the fact that limits what
            // the rest of the stream can claim.
            auto& e = events.begin(EventKind::Note);
            e.add("text", std::string_view{"write tracking armed"});
            e.add("regions", static_cast<std::uint64_t>(out.wx_regions));
            e.add("watches", out.wx_watches);
            e.add("bytes_covered", out.wx_bytes_covered);
            e.add("bytes_total", out.wx_bytes_total);
            e.add("unwatched_regions", out.wx_regions_unwatched);
            events.commit();

            for (const auto& u : arms.unwatched) {
                auto& n = events.begin(EventKind::Note);
                n.add("text", std::string_view{
                                  "a region could not be watched: no debug "
                                  "register was left"});
                n.add_hex("base", u.base);
                n.add("length", u.length);
                events.commit();
            }
        }
    }

    // Drains every watch event and feeds it to the tracker. The event's data
    // address is what is attributed, not the watched address: the kernel
    // reports which address inside the watch actually matched, and a write
    // to the second half of an eight-byte watch is a different fact from one
    // to the first.
    std::vector<WatchEvent> watch_events;
    auto drain_watches = [&]() {
        if (!config.track_wx || out.wx_unavailable) {
            return;
        }
        watch_events.clear();
        (void)watchpoints.read_events(watch_events);
        for (const auto& ev : watch_events) {
            if (ev.kind != WatchKind::Write || !ev.has_address) {
                continue;
            }
            // The width of the access is not in the record -- the kernel
            // reports the address, not how much was touched -- so it comes
            // from the instruction. A decoder that stores a byte at a time
            // and one that stores a quadword at a time produce the same
            // address and different byte counts, and the byte count is what
            // tells them apart.
            std::uint64_t width = 1;
            std::uint8_t code[16];
            const auto rr = tracer.peek(ev.pid, ev.rip);
            if (rr.ok()) {
                (void)tracer.read_memory(ev.pid, ev.rip, code, sizeof(code));
                const AccessDecode d = decode_access(code, sizeof(code));
                if (d.valid && d.width != 0) {
                    width = d.width;
                }
            }
            wx.note_write(ev.pid, ev.address, width, ev.rip);
            auto& e = events.begin(EventKind::MemoryWrite);
            e.add("pid", static_cast<std::uint64_t>(ev.pid));
            e.add_hex("address", ev.address);
            e.add_hex("rip", ev.rip);
            e.add("bytes", width);
            e.add("kind", std::string_view{"watch"});
            events.commit();
        }
        out.wx_lost_samples = watchpoints.lost_samples();
    };

    // Drains every probe ring and reports each hit.
    //
    // A uprobe hit is not a stop. The kernel writes a record into a perf
    // ring associated with the probe, and the traced process never pauses:
    // a target can enter a probed function a thousand times between two of
    // its own syscalls. This is why a uprobe costs the target far less than
    // a breakpoint with the same coverage, and it is also why the hits have
    // to be drained wherever the loop happens to be, rather than in a
    // handler for a stop that would never come.
    //
    // The hits are attributed by which ring produced them and not by
    // anything in the record. Each probe owns its own buffer, so the name
    // recovered here is the name of the probe whose descriptor was polled,
    // which is a stronger statement than a name looked up from an id: the
    // kernel cannot deliver a probe's record to another probe's ring.
    std::vector<UprobeHit> probe_hits;
    auto drain_probes = [&]() {
        if (config.probes == nullptr) {
            return;
        }
        Uprobes& layer = config.probes->layer();
        if (layer.size() == 0) {
            return;
        }
        probe_hits.clear();
        (void)layer.read_hits(probe_hits);
        for (const UprobeHit& hit : probe_hits) {
            ++out.probe_hits;
            auto& e = events.begin(EventKind::ProbeHit);
            e.add("pid", static_cast<std::uint64_t>(hit.pid));
            e.add("tid", static_cast<std::uint64_t>(hit.tid));
            e.add("label", hit.name);
            e.add_hex("ip", hit.ip);
            // The argument registers, when the sample carried them.
            //
            // The event encoder writes flat key and value pairs and has no
            // way to nest, so the six are six fields: arg0 through arg5, in
            // ABI order, each "name=0xvalue" when the probe named the
            // argument and "0xvalue" when it did not. The position in the
            // key is the ABI slot, so a consumer that wants rdx reads arg2,
            // and the name is carried alongside rather than looked up
            // because the name belongs to the prototype and the stream is
            // the only thing that knows which function was called.
            //
            // When the kernel did not capture a register set there is
            // nothing to report, and `args_captured: false` says that
            // rather than the six fields being absent: an absent field is
            // indistinguishable from a consumer reading an older stream
            // that never had them, and the two call for different
            // conclusions.
            if (hit.has_args) {
                for (std::size_t i = 0; i < 6; ++i) {
                    std::string key = "arg";
                    key += static_cast<char>('0' + i);
                    std::string value;
                    const std::string_view nm = hit.arg_names[i];
                    if (!nm.empty()) {
                        value.assign(nm);
                        value += '=';
                    }
                    value += "0x";
                    value += to_hex(hit.args[i], 16);
                    e.add(key, value);
                }
            } else {
                e.add("args_captured", false);
            }
            events.commit();
        }
        // Reported per drain rather than once at the end: a run whose rings
        // wrapped is a run whose hit count is short, and a consumer reading
        // the stream as it arrives has to be able to see that before the
        // session ends.
        out.probe_lost = layer.lost_hits();
    };

    // The syscall state per process. A syscall stop alternates between
    // entry and exit and the kernel does not say which; the only way to
    // know is to remember what the last one was.
    //
    // A process is entered as "the next stop is an entry". Getting this
    // backwards is not a cosmetic mistake: on an entry stop rax still holds
    // the previous syscall's result, and for the first syscall of a process
    // that is -ENOSYS because the kernel has not run anything yet. Labelling
    // the first stop as an exit therefore reports -ENOSYS as the return
    // value of a syscall that has not happened.
    struct SyscallState {
        int pid;
        bool next_is_entry;
        // The path the current syscall named, captured on entry.
        //
        // It has to be read there. On the way out the register that held it
        // has been reused by the kernel for the return value, and the string
        // it pointed at may have been freed by the syscall itself -- an
        // unlink followed by an open of the same name is the common case,
        // and reading the path afterwards would read whatever now occupies
        // that memory. A trace that reported the wrong path would be worse
        // than one that reported none, so an entry that was not a path
        // syscall leaves this empty and the exit reports nothing.
        std::string open_path;
        std::uint64_t open_flags = 0;
        // Whether the flags word was actually read. Recorded on entry
        // because orig_rax is not stable at the exit stop -- the kernel is
        // free to have used the register for the return value -- and a
        // record whose field depends on which register happened to survive
        // would report a different thing for the same syscall on different
        // kernels.
        bool flags_known = false;
        bool was_open = false;
    };
    std::vector<SyscallState> syscall_state;
    auto syscall_entry_for = [&](int pid, bool& at_entry) -> SyscallState& {
        for (auto& s : syscall_state) {
            if (s.pid == pid) {
                at_entry = s.next_is_entry;
                s.next_is_entry = !s.next_is_entry;
                if (at_entry) {
                    // Entering a new syscall. Whatever the previous one
                    // captured has already been reported, and clearing it
                    // here rather than at the exit is what keeps the exit's
                    // own report intact: the exit stop is where the record
                    // is emitted, so a clear that ran before that point
                    // would erase the path before it was read.
                    s.was_open = false;
                    s.open_path.clear();
                    s.open_flags = 0;
                    s.flags_known = false;
                }
                return s;
            }
        }
        // The first stop for a process is an entry, because the process was
        // resumed and the kernel stopped it before running the instruction.
        syscall_state.push_back(
            SyscallState{pid, false, {}, 0, false, false});
        at_entry = true;
        return syscall_state.back();
    };

    for (;;) {
        if (traced.empty()) {
            break;
        }

        // Serves the debugger between stops. Two things happen here and the
        // order matters: a listening socket is accepted on first, and only
        // then is there a connection to read from.
        //
        // The accept is non-blocking. A run started with a debugger port and
        // no debugger attached still has to run its target, or asking for a
        // port would be a way to run nothing. It is the tracee's stops that
        // drive this loop, so a debugger that has not arrived yet is simply
        // not there yet.
        if (config.serve_gdb && !connection.valid()) {
            const int listen_fd = config.gdb_listen_fd >= 0
                                      ? config.gdb_listen_fd
                                      : config.gdb_read_fd;
            if (listen_fd >= 0) {
                sys::PollFd pfd{};
                pfd.fd = listen_fd;
                pfd.events = 0x0001; // POLLIN
                pfd.revents = 0;
                const auto ready = sys::poll(&pfd, 1, 0);
                if (ready.ok() && ready.value > 0) {
                    const auto accepted =
                        sys::accept4(listen_fd, nullptr, nullptr,
                                     0x80000 /* SOCK_CLOEXEC */);
                    if (accepted.ok()) {
                        connection.adopt(static_cast<int>(accepted.value));
                        auto& note = events.begin(EventKind::Note);
                        note.add("text", std::string_view{"a debugger attached"});
                        note.add("port",
                                 static_cast<std::uint64_t>(config.gdb_port));
                        events.commit();
                    }
                }
            }
        } else if (config.serve_gdb && connection.valid()) {
            // Reading with a zero timeout keeps the tracee's stops from being
            // delayed by a debugger that has nothing to say. The target is
            // the thing making progress here; the debugger is a passenger.
            if (connection.wait_readable(0)) {
                if (connection.pump()) {
                    // Acknowledge before handling. A debugger that has sent
                    // a packet is waiting for the '+' before it will send the
                    // next one, so answering after the reply would make every
                    // exchange take a round of timeouts.
                    (void)connection.flush_ack();
                    if (connection.retransmit_requested()) {
                        // The far end saw a checksum fail. The same bytes go
                        // back, because its copy is the only one known to be
                        // what it meant to send.
                        connection.clear_retransmit();
                        const std::string& again = connection.last_packet();
                        (void)sys::write(connection.fd(), again.data(),
                                          again.size());
                    }
                    std::string request;
                    while (connection.take_packet(request)) {
                        // Every request gets an answer, including the ones
                        // that are not supported. An empty payload in a
                        // framed packet is the protocol's way of saying "not
                        // supported", and sending nothing at all is not: a
                        // debugger that asked a question and got silence
                        // waits for the answer forever, which is a stub that
                        // looks hung rather than one that looks limited.
                        //
                        // The handler decides which of the two applies, and
                        // Reply carries that decision rather than leaving it
                        // to be re-derived from an empty string -- where the
                        // two cases are indistinguishable and the wrong one
                        // is easy to pick.
                        const Reply reply = server.handle(request);
                        if (reply.send) {
                            (void)connection.send_packet(reply.payload);
                        }
                        if (server.detached()) {
                            (void)tracer.detach(config.pid, 0);
                            connection.close();
                            break;
                        }
                    }
                } else {
                    // The debugger disconnected. The process is left to run
                    // rather than killed, because a debugger that goes away
                    // is not a request to end the target.
                    server.clear_resume();
                    connection.close();
                }
            }
        }

        if (server.detached()) {
            (void)tracer.detach(config.pid, 0);
            break;
        }

        // Holding at the first stop: the target is stopped and stays stopped
        // until the debugger asks it to run. The wait is a sleep rather than
        // a blocking read because the loop has to keep draining the event
        // stream and servicing the protocol while it waits, and because a
        // debugger that connects and then goes quiet must not wedge the run.
        if (hold_for_debugger && !released_for_debugger) {
            // Nothing is resumed until a continue arrives, so this branch
            // runs on every pass and is the run's whole behaviour while it
            // waits. The poll with no descriptors is a sleep that cannot
            // fail: the loop has to come back to accept a connection and
            // drain the event stream, and a debugger that connects and then
            // says nothing must not wedge the run.
            if (server.resume_requested()) {
                const int signal = server.resume_signal();
                server.clear_resume();
                released_for_debugger = true;
                auto& note = events.begin(EventKind::Note);
                note.add("text", std::string_view{
                                    "the debugger resumed the target"});
                Registers held{};
                if (tracer.get_regs(config.pid, held).ok()) {
                    note.add_hex("pc", held.rip);
                    note.add_hex("sp", held.rsp);
                }
                events.commit();
                if (resume(config.pid, signal) != 0) {
                    out.failed = true;
                    out.detail = "the target could not be resumed by the debugger";
                    break;
                }
            } else {
                sys::PollFd idle{};
                idle.fd = -1;
                idle.events = 0;
                idle.revents = 0;
                (void)sys::poll(&idle, 0, 20);
            }
            continue;
        }

        // A session with probes cannot wait indefinitely for a ptrace stop.
        //
        // A uprobe does not stop the target, so its record arrives while
        // the tracee is running and no wait will ever report it. A loop
        // that blocked on waitpid would therefore hold every hit in the
        // ring until the target's next syscall -- and a target that enters
        // a probed function and then computes for a second would have its
        // entire function-level trace delivered a second late, in a burst,
        // or not at all if the ring wrapped first.
        //
        // So the probe descriptors are polled with no wait behind them. The
        // order is deliberate: readiness is established first, and only
        // then is a hit consumed. Polling, draining, and only afterwards
        // checking for a stop would reverse the two, and a stop that was
        // already pending when the drain ran would be attributed to the
        // wrong point in the target's history.
        //
        // The poll timeout is the one thing here that is a choice rather
        // than a fact. Zero would make the loop spin, and an infinite
        // timeout would make it miss. Fifty milliseconds is short enough
        // that a hit is reported while the target is still in the function
        // that produced it in every case a person is watching, and long
        // enough that a target making hundreds of calls a second does not
        // cost the observer a wakeup per call.
        if (config.probes != nullptr) {
            const std::vector<int> probe_fds = config.probes->layer().fds();
            if (!probe_fds.empty()) {
                std::vector<sys::PollFd> pfds(probe_fds.size());
                for (std::size_t i = 0; i < probe_fds.size(); ++i) {
                    pfds[i].fd = probe_fds[i];
                    pfds[i].events = 0x0001; // POLLIN
                    pfds[i].revents = 0;
                }
                const auto ready = sys::poll(pfds.data(), pfds.size(), 50);
                if (!ready.failed() && ready.value > 0) {
                    drain_probes();
                }
            }
        }

        Stop stop = tracer.wait(0);

        ++out.stops;

        // The probes are drained again after the stop, because a record
        // that arrived between the poll above and the wait below would
        // otherwise wait for the next pass -- which on a target that stops
        // once and exits is never.
        drain_probes();

        if (stop.kind == StopKind::Exited) {
            // The wait reported either an exit or a failure. The signal
            // field carries the errno for a failure, which is how the two
            // are told apart.
            if (stop.term_signal) {
                out.signaled = true;
                out.term_signal = stop.exit_code;
            } else if (stop.signal == 0) {
                out.exit_code = stop.exit_code;
            }

            auto& e = events.begin(EventKind::ProcessExit);
            e.add("pid", static_cast<std::uint64_t>(stop.pid));
            e.add("exit_code", static_cast<std::int64_t>(stop.exit_code));
            e.add("signaled", stop.term_signal);
            e.add("term_signal", static_cast<std::uint64_t>(stop.exit_code));
            events.commit();

            // Remove the process from the traced set. Reaping happens here
            // rather than in a separate pass because a process that has
            // reported its exit status is already reaped by the wait.
            //
            // The watches on it go first. A watch is a debug register held
            // for a process that no longer exists, and leaving it installed
            // would consume one of the four for the rest of the session --
            // on a fork-tracing run, four forks would exhaust the hardware
            // and the tracker would stop working for the rest of the target's
            // life.
            if (config.track_wx && !out.wx_unavailable) {
                drain_watches();
                (void)watchpoints.remove_all_for(stop.pid);
            }
            for (auto it = traced.begin(); it != traced.end(); ++it) {
                if (*it == stop.pid) {
                    traced.erase(it);
                    break;
                }
            }
            if (traced.empty()) {
                break;
            }
            continue;
        }

        if (stop.kind == StopKind::NewChild) {
            // The child inherits the tracing and has to be configured
            // before it is allowed to run, or its first syscall would be
            // missed.
            auto msg = tracer.event_message(stop.pid);
            if (msg.ok()) {
                const int child = static_cast<int>(msg.value);
                traced.push_back(child);
                auto& e = events.begin(EventKind::ProcessSpawn);
                e.add("pid", static_cast<std::uint64_t>(child));
                e.add("parent", static_cast<std::uint64_t>(stop.pid));
                events.commit();
                (void)resume(child, 0);
            }
            (void)resume(stop.pid, 0);
            continue;
        }

        if (stop.kind == StopKind::Exec) {
            // Every cached address is stale after an exec. The breakpoints
            // are dropped rather than carried over, because a breakpoint at
            // an address that meant something in the old image means
            // something else in the new one.
            for (const auto& b : breakpoints.all()) {
                (void)tracer.poke(stop.pid, b.address,
                                  static_cast<std::uint64_t>(b.saved));
            }
            // The same is true of the watches, with one extra problem: a
            // watch placed on the old image's address now points at
            // whatever the new image put there, so it would fire on an
            // access to unrelated memory and call it a write to a region
            // that no longer exists. They are released and the new image's
            // regions are watched instead.
            if (config.track_wx && !out.wx_unavailable) {
                wx.release(watchpoints);
                wx = WriteExecuteTracker();
            }
            auto& e = events.begin(EventKind::Exec);
            e.add("pid", static_cast<std::uint64_t>(stop.pid));
            events.commit();
            (void)resume(stop.pid, 0);
            continue;
        }

        if (stop.kind == StopKind::SeccompTrap) {
            auto& e = events.begin(EventKind::SyscallBlocked);
            e.add("pid", static_cast<std::uint64_t>(stop.pid));
            auto msg = tracer.event_message(stop.pid);
            if (msg.ok()) {
                e.add_hex("nr", static_cast<std::uint64_t>(msg.value));
            }
            events.commit();
            (void)resume(stop.pid, 0);
            continue;
        }

        if (stop.kind == StopKind::SyscallStop) {
            ++out.syscall_stops;

            bool at_entry = false;
            SyscallState& state = syscall_entry_for(stop.pid, at_entry);

            Registers regs{};
            auto gr = tracer.get_regs(stop.pid, regs);
            if (gr.ok()) {
                const std::uint64_t nr = regs.orig_rax;

                // On entry, a path syscall's argument is still a pointer the
                // target chose and the kernel has not yet acted on. This is
                // the only moment at which the string can be read, and the
                // reason a file event can name a file at all.
                if (at_entry &&
                    (nr == kSysOpen || nr == kSysOpenat ||
                     nr == kSysOpenat2)) {
                    // open(path) puts the path in rdi and openat(dirfd,
                    // path) puts it in rsi; openat2 has it there too. The
                    // first is unreachable on a dynamically linked target,
                    // where open() is a wrapper around openat, but a static
                    // one can issue it directly.
                    const std::uint64_t path_addr =
                        (nr == kSysOpen) ? regs.rdi : regs.rsi;
                    // open's flags are the mode; openat's are the third
                    // argument too, so one read covers both. openat2's are
                    // inside a structure this does not read, so they are
                    // left at zero and the record says they are unknown
                    // rather than reporting the structure's first word --
                    // which is how.flags on this kernel, and is not
                    // something a uapi header guarantees.
                    state.open_flags =
                        (nr == kSysOpenat2) ? 0 : regs.rdx;
                    state.flags_known = (nr != kSysOpenat2);
                    const PathRead pr =
                        read_remote_path(tracer, stop.pid, path_addr);
                    if (pr.ok) {
                        state.open_path = pr.text;
                        state.was_open = true;
                    }
                }

                // The permission syscalls are the whole of the transition
                // story. On entry the arguments are the ones the target
                // asked for; on exit the kernel has either applied them or
                // refused, and the maps say which. Reading the maps after
                // the call rather than trusting the arguments is what makes
                // this correct for a call that failed: a refused mprotect
                // leaves the region non-executable, and reporting a
                // transition for it would be a fabrication.
                if (config.track_wx && !out.wx_unavailable) {
                    if (at_entry) {
                        if (nr == kSysMprotect) {
                            PendingProtect& p = protect_entry_for(stop.pid);
                            p.addr = regs.rdi;
                            p.length = regs.rsi;
                            p.valid = true;
                        } else if (nr == kSysMmap) {
                            PendingProtect& p = protect_entry_for(stop.pid);
                            // mmap reports its address in the return value,
                            // not the first argument, so the range is not
                            // known until the call returns. What is known
                            // on entry is the requested protection, which
                            // is enough to decide whether the result is
                            // worth looking at.
                            p.length = regs.rsi;
                            p.valid = true;
                        } else if (nr == kSysMunmap || nr == kSysMremap) {
                            PendingProtect& p = protect_entry_for(stop.pid);
                            p.addr = regs.rdi;
                            p.length = regs.rsi;
                            p.valid = true;
                        }
                    } else {
                        for (auto& p : pending_protect) {
                            if (p.pid != stop.pid || !p.valid) {
                                continue;
                            }
                            p.valid = false;

                            // The address the region ended up at. For mmap
                            // that is the return value; for the others it
                            // is the argument the target passed.
                            const std::uint64_t addr =
                                (nr == kSysMmap && static_cast<long>(regs.rax) >= 0)
                                    ? static_cast<std::uint64_t>(regs.rax)
                                    : p.addr;
                            if (addr == 0) {
                                continue;
                            }

                            // A fresh mapping is where a decoder's staging
                            // buffer appears, so the hardware slots are moved
                            // onto it as soon as it exists. Doing this at
                            // startup alone cannot work: the region does not
                            // exist yet, and the four debug registers would
                            // be spent on the loader's data segments instead.
                            if (nr == kSysMmap) {
                                const ArmReport chased =
                                    wx.chase(watchpoints, stop.pid, addr,
                                             p.length);
                                if (chased.watches_installed > 0) {
                                    out.wx_watches = watchpoints.fds().size();
                                    auto& c =
                                        events.begin(EventKind::Note);
                                    c.add("text", std::string_view{
                                                     "chased a new mapping"});
                                    c.add_hex("base",
                                              addr & ~(std::uint64_t{4095}));
                                    c.add("length", p.length);
                                    c.add("watches",
                                          chased.watches_installed);
                                    c.add("bytes_covered",
                                          chased.bytes_covered);
                                    c.add("bytes_total", chased.bytes_total);
                                    events.commit();
                                }
                            }

                            RegionPerms perms;
                            if (!read_region_perms(stop.pid, addr, perms)) {
                                // The mapping is gone, which is what munmap
                                // does. There is nothing to compare.
                                continue;
                            }
                            if (wx.note_permission(stop.pid, addr, perms)) {
                                wx.flush(stop.pid, events);
                                out.transitions += 1;
                            }
                        }
                    }
                }

                auto& e = events.begin(EventKind::Note);
                if (at_entry) {
                    e.add("text", std::string_view{"syscall entry"});
                    e.add("nr", static_cast<std::int64_t>(
                                    static_cast<long>(regs.orig_rax)));
                    e.add_hex("arg0", regs.rdi);
                    e.add_hex("arg1", regs.rsi);
                    e.add_hex("arg2", regs.rdx);
                } else {
                    e.add("text", std::string_view{"syscall exit"});
                    e.add("ret", static_cast<std::int64_t>(
                                      static_cast<long>(regs.rax)));

                    // A file event is emitted on the way out, not on the
                    // way in, because only here is the result known. A path
                    // that was opened and failed was not opened, and a
                    // consumer counting the files a program touched would be
                    // wrong by one per failed attempt.
                    if (state.was_open && !state.open_path.empty()) {
                        auto& f = events.begin(EventKind::FileOpened);
                        f.add("pid", static_cast<std::uint64_t>(stop.pid));
                        f.add("path", state.open_path);
                        f.add("ret", static_cast<std::int64_t>(
                                        static_cast<long>(regs.rax)));
                        f.add("flags", state.open_flags);
                        f.add("flags_known", state.flags_known);
                        events.commit();
                    }
                }
                e.add("pid", static_cast<std::uint64_t>(stop.pid));
                events.commit();
            }

            // The watch events are drained after the syscall rather than
            // before, because a write the syscall made is a write that has
            // already happened by the time the kernel reports the call.
            drain_watches();

            (void)resume(stop.pid, 0);
            continue;
        }

        if (stop.kind == StopKind::Signal) {
            // A watch fires as a stop of its own on the traced process, and
            // this is where those stops arrive. The events are drained
            // before anything else because the instruction that wrote is
            // only available while the process is still stopped here.
            drain_watches();

            // A synthetic stop is one ptrace arranged and must not be
            // redelivered. A real signal has to reach the process, or a
            // target that handles SIGSEGV would never see it.
            const int deliver = stop.synthetic ? 0 : stop.signal;

            if (!stop.synthetic && stop.signal != 0) {
                ++out.signals;
                auto& e = events.begin(EventKind::Signal);
                e.add("pid", static_cast<std::uint64_t>(stop.pid));
                e.add("signal", static_cast<std::uint64_t>(stop.signal));
                events.commit();
            }

            // A trap that lands on a breakpoint the session installed is a
            // breakpoint hit, not a stray signal. The distinction is made
            // by looking at rip, because that is the only thing that says
            // where the trap came from.
            Registers regs{};
            if (tracer.get_regs(stop.pid, regs).ok()) {
                if (breakpoints.find(regs.rip - 1) != nullptr) {
                    ++out.breakpoint_hits;
                    auto& e = events.begin(EventKind::BreakpointHit);
                    e.add("pid", static_cast<std::uint64_t>(stop.pid));
                    e.add_hex("address", regs.rip - 1);
                    events.commit();

                    if (server.resume_requested() && !server.step_requested()) {
                        // The debugger asked to continue. The breakpoint
                        // byte has to come out, the instruction has to run,
                        // and the breakpoint has to go back in. That is a
                        // single step with the original byte in place.
                        std::string detail;
                        const int rc = breakpoints.step_over(tracer, stop.pid,
                                                            detail);
                        if (rc == 0) {
                            // The step consumed a wait. The next wait is the
                            // resume the caller asked for.
                            server.clear_resume();
                            (void)resume(stop.pid, 0);
                        } else {
                            (void)resume(stop.pid, 0);
                        }
                        continue;
                    }
                }
            }

            if (server.resume_requested()) {
                const int sig = server.resume_signal();
                const bool step = server.step_requested();
                server.clear_resume();
                if (step) {
                    auto r = tracer.singlestep(stop.pid, sig);
                    (void)r;
                } else {
                    (void)resume(stop.pid, sig);
                }
                continue;
            }

            (void)resume(stop.pid, deliver);
            continue;
        }

        if (stop.kind == StopKind::GroupStop) {
            // A group stop is continued with a zero signal, or with SIGCONT
            // to actually deliver the stop to the group. Continuing with
            // SIGSTOP here would re-stop the process immediately.
            (void)resume(stop.pid, stop.signal == kSigstop ? 0 : stop.signal);
            continue;
        }
    }

    // The last drain of the probe rings. A target that entered a probed
    // function and then exited immediately would otherwise have that call
    // recorded in a ring nobody read, which is the one case the probes
    // exist for -- the same argument as the write tracker's final flush,
    // and for the same reason: the interesting call is often the last one.
    //
    // This drain is unconditional rather than gated on a poll, because the
    // session is ending and there is nothing left to wait for. The hits are
    // read whether or not the descriptor was reported ready; a ring that
    // holds a record is a ring whose record was produced, and a readiness
    // check here would drop hits that were written between the last poll
    // and the target's exit.
    drain_probes();

    // The session is over. Any process still in the traced set is one whose
    // exit the loop did not see, which happens when the debugger detached
    // first; they are continued so that they are not left stopped.
    for (int pid : traced) {
        (void)tracer.detach(pid, 0);
    }

    // The last drain and the last transition report. A target that wrote its
    // payload and made it executable and then exited within one syscall
    // interval would otherwise have its transition never reported, which is
    // the one case the tracker exists for.
    if (config.track_wx && !out.wx_unavailable) {
        drain_watches();
        // The count is taken before the flush, because flushing is what
        // writes the transitions out and it clears them. Reading it after
        // would always be zero, which is exactly the number a caller would
        // believe if the tracker had found nothing.
        const std::size_t pending = wx.transitions().size();
        wx.flush(config.pid, events);
        out.transitions += pending;
        wx.release(watchpoints);
    }

    return out;
}

} // namespace occ::obs

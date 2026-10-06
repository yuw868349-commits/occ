// Observer layer tests.
//
// Two parts of the observer can be tested without a process to trace, and
// they are the two where a mistake produces something that looks right:
// the remote protocol's framing, where a packet that decodes to the wrong
// payload still decodes, and the instruction decoder, where a wrong answer
// about a memory access is indistinguishable from a correct one until
// something acts on it.
//
// The framing cases are the ones a byte-stream reader gets wrong: a packet
// split across two reads, two packets in one read, a checksum that fails,
// and a payload that contains the framing characters.

#include "occ/observer/ptrace.h"
#include "occ/observer/rsp.h"
#include "occ/observer/session.h"
#include "occ/observer/transport.h"
#include "occ/observer/watchpoint.h"
#include "occ/observer/wx.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "occ/syscall/syscall.h"

using namespace occ::obs;
using namespace occ::sys;

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

// ------------------------------------------------------------- packet framing

void test_checksum() {
    // The checksum is the low byte of the sum of the payload bytes. The
    // values here are the ones the protocol's own examples use, which is
    // what makes them checkable against the specification rather than
    // against this implementation.
    check(encode_packet("?") == "$?#3f", "the stop-reason packet checksum");
    check(encode_packet("g") == "$g#67", "the read-registers packet checksum");

    // m4010c0 sums to 0x6d + 0x34 + 0x30 + 0x31 + 0x30 + 0x63 + 0x30 =
    // 0x1c5, and the checksum is the low byte.
    check(encode_packet("m4010c0") == "$m4010c0#c5",
          "the checksum is the low byte of the payload sum");
}

// A packet with no payload is a packet.
//
// This test previously asserted the opposite, and the assertion was wrong.
// The checksum of no bytes is zero, so "$#00" is well-formed by the
// protocol's own rule; refusing it as a checksum failure makes a peer that
// sent one retransmit forever, because its retransmission is the same
// bytes and they will fail the same way. The protocol uses exactly this
// packet for "not implemented" -- the request vMustReplyEmpty is named
// after -- so a stub that cannot accept it cannot hold a conversation with
// a debugger that follows up an unknown packet with it.
//
// What an empty payload *means* is decided one layer up, where it answers
// "unsupported". This layer only judges the bytes.
void test_empty_payload_is_a_packet() {
    PacketDecoder d;
    check(d.feed("$#00") == 1, "an empty frame is still framed");
    const Packet p = d.take();
    check(p.checksum_ok, "an empty payload passes the checksum test");
    check(p.data.empty(), "an empty payload carries no data");

    // The same thing arriving in the middle of a stream: a real packet,
    // then an empty one, then another real one. All three are packets.
    PacketDecoder d2;
    const std::string wire = encode_packet("g") + "$#00" + encode_packet("m1,1");
    check(d2.feed(wire) == 3, "the good packets around it still decode");
    const Packet first = d2.take();
    check(first.checksum_ok && first.data == "g", "the first packet is intact");
    const Packet middle = d2.take();
    check(middle.checksum_ok, "the empty frame is a packet");
    check(middle.data.empty(), "and it carries no payload");
    const Packet last = d2.take();
    check(last.checksum_ok && last.data == "m1,1",
          "the packet after it is intact");
}

// The two halves of the codec have to agree, in this direction: an encoder
// that framed an empty payload into bytes its own decoder refused would
// send a packet it could never receive. They now agree -- the encoder
// frames "$#00" and the decoder accepts it -- and the boundary is that
// one byte is still framed the same way it always was.
void test_encode_frames_empty_payload() {
    check(encode_packet("") == "$#00",
          "an empty payload frames as the protocol's empty packet");
    check(encode_packet("g") == "$g#67", "a one-byte payload is framed");
}

void test_single_packet() {
    PacketDecoder d;
    const std::string packet = encode_packet("g");
    check(d.feed(packet) == 1, "one packet is decoded from one feed");
    check(d.has_packet(), "the packet is available");

    const Packet p = d.take();
    check(p.data == "g", "the payload is the command");
    check(p.checksum_ok, "the checksum is verified");
    check(!d.has_packet(), "the packet is consumed");
}

void test_split_across_reads() {
    // A socket delivers bytes in whatever chunks it has. A decoder that
    // assumed one packet per read works on a local socket and fails on
    // everything else.
    PacketDecoder d;
    const std::string packet = encode_packet("m4010c0");

    for (std::size_t i = 0; i + 1 < packet.size(); ++i) {
        const std::size_t produced = d.feed(packet.data() + i, 1);
        if (i + 1 < packet.size()) {
            check(produced == 0 || i + 1 == packet.size() - 1,
                  "a partial packet produces nothing until it completes");
        }
    }

    // The final byte completes it.
    check(d.feed(packet.data() + packet.size() - 1, 1) == 1,
          "the last byte completes the packet");
    const Packet p = d.take();
    check(p.data == "m4010c0", "the split packet decodes to its payload");
}

void test_two_packets_in_one_read() {
    PacketDecoder d;
    std::string both = encode_packet("g");
    both += encode_packet("m1000,4");

    check(d.feed(both) == 2, "two packets are decoded from one feed");
    const Packet first = d.take();
    const Packet second = d.take();
    check(first.data == "g", "the first payload");
    check(second.data == "m1000,4", "the second payload");
}

void test_bad_checksum() {
    PacketDecoder d;
    std::string packet = encode_packet("g");
    // Corrupt the last checksum digit. 0 and 1 differ in one bit, so the
    // packet stays well-framed and only the checksum is wrong.
    packet[packet.size() - 1] = (packet[packet.size() - 1] == '0') ? '1' : '0';

    check(d.feed(packet) == 1, "a bad-checksum packet is still recognized");
    const Packet p = d.take();
    check(!p.checksum_ok, "the checksum is reported as bad");
    check(p.data.empty(), "a bad packet yields no payload");
    // The request for a resend is the '-' this owes the sender, not a state
    // saying we should replay our own last packet. The distinction is
    // covered in test_a_damaged_packet_does_not_ask_for_a_retransmission.
    check(d.pending_ack() == '-',
          "a bad checksum asks the far end to send the packet again");
}

void test_retransmit_request() {
    PacketDecoder d;
    d.feed("-", 1);
    check(d.retransmit_requested(),
          "a lone minus asks for a retransmission");
    d.clear_retransmit();
    check(!d.retransmit_requested(), "the request can be cleared");
}

void test_acknowledgment() {
    // '+' is an acknowledgment and is not a packet.
    PacketDecoder d;
    check(d.feed("+", 1) == 0, "an acknowledgment is not a packet");
    check(!d.has_packet(), "an acknowledgment produces nothing");

    // A '+' followed by a packet decodes the packet.
    PacketDecoder d2;
    std::string data = "+";
    data += encode_packet("g");
    check(d2.feed(data) == 1, "a packet after an acknowledgment is decoded");
    check(d2.take().data == "g", "the payload after an acknowledgment");
}

void test_escaping() {
    // The framing characters and the escape byte have to survive a payload
    // that contains them.
    const std::string payload = "a$b#c}d";
    const std::string packet = encode_packet(payload);

    // The framing characters must not appear unescaped in the body.
    check(packet.substr(1, packet.size() - 4).find('$') == std::string::npos,
          "a literal $ does not appear unescaped in a packet body");
    check(packet.substr(1, packet.size() - 4).find('#') == std::string::npos,
          "a literal # does not appear unescaped in a packet body");

    PacketDecoder d;
    d.feed(packet);
    const Packet p = d.take();
    check(p.data == payload, "the escaped payload round-trips");
    check(p.checksum_ok, "the escaped packet's checksum is over the escaped "
                         "form");
}

void test_escape_helpers() {
    check(escape("abc") == "abc", "a plain string is not escaped");
    check(escape("$") == "}\x04", "the start byte is escaped");
    check(unescape("}\x04") == "$", "the escape is undone");
    check(unescape(escape("a$b#c}d")) == "a$b#c}d", "escape and unescape are "
                                                    "inverse");
}

void test_split_packet_helper() {
    std::string_view head;
    std::string_view tail;

    split_packet("g", head, tail);
    check(head == "g" && tail.empty(), "a packet with no colon");

    split_packet("m4010c0,10", head, tail);
    check(head == "m" && tail == "4010c0,10",
          "the command letter is split from its arguments");

    split_packet("Z0,401000,4", head, tail);
    check(head == "Z" && tail == "0,401000,4", "a breakpoint packet splits");
}

// ------------------------------------------------------------------- hex

void test_hex_round_trip() {
    check(hex_u64_le(0x1122334455667788ULL) == "8877665544332211",
          "an unsigned 64-bit value is least significant byte first");
    check(hex_u64_be(0x1122334455667788ULL) == "1122334455667788",
          "a big-endian value is most significant byte first");
    check(hex_u32_le(0x11223344U) == "44332211",
          "an unsigned 32-bit value is little-endian");
    check(hex_u8(0xab) == "ab", "a byte is two digits");
    check(hex_u8(0x05) == "05", "a byte keeps its leading zero");

    std::uint64_t v = 0;
    check(parse_hex_u64_le("8877665544332211", v), "a 64-bit value parses");
    check(v == 0x1122334455667788ULL,
          "the parsed value has the byte order undone");

    std::uint32_t w = 0;
    check(parse_hex_u32_le("44332211", w), "a 32-bit value parses");
    check(w == 0x11223344U, "the parsed 32-bit value");

    // Too short is a refusal, not a partial read.
    check(!parse_hex_u64_le("8877", v), "a short value is refused");
    check(!parse_hex_u32_le("ab", w), "a short 32-bit value is refused");
}

void test_hex_number() {
    // A protocol number is not a register value. The difference is both the
    // byte order and the width: an offset or a thread id is written most
    // significant digit first with no padding, so reading one with the
    // register-block reader reverses its digits and refuses it for being
    // shorter than eight.
    check(hex_number(0) == "0", "zero is one digit");
    check(hex_number(1) == "1", "a small number has no padding");
    check(hex_number(10) == "a", "ten is hexadecimal a");
    check(hex_number(0x1092) == "1092",
          "a thread id is most significant digit first");
    check(hex_number(0xdeadbeefULL) == "deadbeef",
          "a large number keeps every digit");

    // The encoding is the one GDB sends, so reading it back has to give the
    // original. A round trip is the property the packet handlers rely on.
    for (const std::uint64_t original : {std::uint64_t{0},
                                         std::uint64_t{1},
                                         std::uint64_t{5},
                                         std::uint64_t{11},
                                         std::uint64_t{255},
                                         std::uint64_t{4242},
                                         std::uint64_t{0x7fffffff},
                                         std::uint64_t{0xffffffffffffffffULL}}) {
        std::uint64_t back = 0;
        check(parse_hex_number(hex_number(original), back) && back == original,
              "a protocol number round trips");
    }

    // The signal numbers the protocol writes with two digits must mean the
    // number a person would write, which is the whole reason a leading zero
    // is not significant.
    std::uint64_t sig = 0;
    check(parse_hex_number("05", sig) && sig == 5, "a padded signal means five");
    check(parse_hex_number("0b", sig) && sig == 11, "a padded signal means eleven");

    // Empty is not a number. A field with nothing in it is malformed rather
    // than zero, because zero is spelled "0".
    check(!parse_hex_number("", sig), "an empty number is refused");
    check(!parse_hex_number("zz", sig), "a non-hexadecimal digit is refused");
    check(!parse_hex_number("0x10", sig), "a prefix is refused");
    check(!parse_hex_number(" 10", sig), "a leading space is refused");

    // Seventeen digits cannot fit, and the value that would wrap is refused
    // rather than silently truncated.
    check(!parse_hex_number("00000000000000000", sig),
          "an over-long number is refused");
    check(!parse_hex_number("fffffffffffffffff", sig),
          "an over-long number does not wrap");
}

void test_hex_bytes() {
    std::vector<std::uint8_t> bytes;
    check(parse_hex_bytes("001122ff", bytes), "a byte string parses");
    check(bytes.size() == 4, "the byte count is half the digit count");
    check(bytes[0] == 0x00 && bytes[1] == 0x11 && bytes[2] == 0x22 &&
              bytes[3] == 0xff,
          "the bytes are in order");

    check(!parse_hex_bytes("abc", bytes), "an odd digit count is refused");
    check(!parse_hex_bytes("zz", bytes), "a non-hex digit is refused");
}

void test_stop_reply() {
    const std::string reply = encode_stop_reply(5, 0x401850);
    check(reply[0] == 'T', "the reply is the T form");
    check(reply.substr(1, 2) == "05", "the signal is two hex digits");
    check(reply.find("10:") != std::string::npos,
          "the reply names rip as register 16");
    // rip 0x401850 little-endian is 50 18 40 00 00 00 00 00, so the digit
    // string begins "501840". Reading it big-endian would give "0000...".
    check(reply.find("10:501840") != std::string::npos,
          "rip is encoded least significant byte first");
    check(reply.back() == ';', "the register list is terminated");
}

// ------------------------------------------------- instruction decoding

// Assembles a byte sequence for a decode test.
AccessDecode decode(std::initializer_list<std::uint8_t> bytes) {
    const std::vector<std::uint8_t> v(bytes);
    return decode_access(v.data(), v.size());
}

void test_decode_store() {
    // 48 89 18 is mov [rax], rbx: a write, based on rax, 8 bytes wide.
    const AccessDecode d = decode({0x48, 0x89, 0x18});
    check(d.valid, "a mov with a memory destination decodes");
    check(d.is_write, "the access is a write");
    check(d.base_register == 0, "the base register is rax");
    check(d.width == 8, "the rex.w prefix makes the access eight bytes");
}

void test_decode_load() {
    // 48 8b 18 is mov rbx, [rax]: a read.
    const AccessDecode d = decode({0x48, 0x8b, 0x18});
    check(d.valid, "a mov with a memory source decodes");
    check(!d.is_write, "the access is a read");
    check(d.base_register == 0, "the base register is rax");
    check(d.width == 8, "the read is eight bytes wide");
}

void test_decode_without_rex() {
    // 89 18 is mov [rax], ebx: a four-byte write.
    const AccessDecode d = decode({0x89, 0x18});
    check(d.valid, "a mov without a rex prefix decodes");
    check(d.is_write, "the access is a write");
    check(d.width == 4, "the access is four bytes without rex.w");
}

void test_decode_byte_form() {
    // 88 18 is mov [rax], bl: a single-byte write. The opcode's low bit is
    // what selects the width, and reading it as the 32-bit form would
    // report a four-byte access for a one-byte store.
    const AccessDecode d = decode({0x88, 0x18});
    check(d.valid, "the byte form decodes");
    check(d.is_write, "the byte form is a write");
    check(d.width == 1, "the byte form is one byte wide");
}

void test_decode_displacement() {
    // 48 89 58 10 is mov [rax+0x10], rbx.
    const AccessDecode d = decode({0x48, 0x89, 0x58, 0x10});
    check(d.valid, "a displaced store decodes");
    check(d.base_register == 0, "the base register is rax");
    check(d.displacement == 0x10, "the displacement is read as a signed byte");

    // 48 89 98 00 01 00 00 is mov [rax+0x100], rbx.
    const AccessDecode d2 = decode({0x48, 0x89, 0x98, 0x00, 0x01, 0x00, 0x00});
    check(d2.valid, "a 32-bit displacement decodes");
    check(d2.displacement == 0x100, "the 32-bit displacement is read");
}

void test_decode_register_to_register() {
    // 48 89 d8 is mov rax, rbx: no memory access at all, so it cannot be
    // the instruction that faulted on a watch.
    const AccessDecode d = decode({0x48, 0x89, 0xd8});
    check(!d.valid, "a register-to-register move is not a memory access");
}

void test_decode_non_mov() {
    // A non-mov opcode is reported as undetermined rather than guessed at.
    // A wrong is_write would make the tracker act on an access that never
    // happened.
    check(!decode({0x48, 0x01, 0x18}).valid, "an add is not decoded");
    check(!decode({0xe8, 0x00, 0x00, 0x00, 0x00}).valid, "a call is not "
                                                         "decoded");
    check(!decode({0x90}).valid, "a nop is not decoded");
    check(!decode_access(nullptr, 0).valid, "an empty buffer does not decode");
}

void test_decode_rip_relative() {
    // 48 89 05 10 00 00 00 is mov [rip+0x10], rax. The base is the
    // instruction pointer, which the decode cannot know, so it is reported
    // as absent rather than as a register.
    const AccessDecode d = decode({0x48, 0x89, 0x05, 0x10, 0x00, 0x00, 0x00});
    check(d.valid, "a rip-relative store decodes");
    check(d.is_write, "the rip-relative store is a write");
    check(d.base_register == -1, "a rip-relative access has no base register");
    check(d.displacement == 0x10, "the rip displacement is read");
}

void test_decode_truncated() {
    // A buffer that ends inside the instruction must not be decoded from
    // whatever happens to be past the end.
    check(!decode({0x48, 0x89}).valid, "a truncated instruction is refused");
    check(!decode({0x48, 0x89, 0x98, 0x00}).valid,
          "a truncated displacement is refused");
}

void test_hardware_slots_probe() {
    // The probe reports what the kernel allows. Zero is a valid answer for
    // a kernel without the capability, so the check is that the call is
    // safe and bounded, not that it is non-zero.
    const std::uint32_t slots = Watchpoints::probe_slots();
    check(slots <= 16, "the hardware slot count is bounded");
    std::fprintf(stderr, "  note: hardware debug registers reported: %u\n",
                 slots);
}

void test_watch_alignment() {
    // A watch has to be naturally aligned for its width. Reporting the
    // refusal here names the reason; the kernel's answer is the same but
    // arrives as a bare errno.
    Watchpoints w;
    std::string detail;

    const int rc = w.add(static_cast<int>(::getpid()), 0x1001, WatchKind::Write,
                         WatchSize::Bytes8, detail);
    check(rc != 0, "a misaligned watch is refused");
    check(detail.find("aligned") != std::string::npos,
          "the refusal names the alignment");

    const int rr = w.add(static_cast<int>(::getpid()), 0x1000, WatchKind::Read,
                         WatchSize::Bytes8, detail);
    check(rr != 0, "a read-only watch is refused");
    check(detail.find("read-only") != std::string::npos,
          "the refusal names the read-only limitation");
}

void test_write_watch_width() {
    // A one or two byte write watch is not encodable on x86-64 and the
    // kernel refuses it with a bare EINVAL, which is indistinguishable from
    // a host with no debug registers at all. The refusal therefore has to
    // happen here, where the reason can be named.
    //
    // This check exists because the tracker used to accept these widths and
    // then report the host as incapable of write tracking.
    Watchpoints w;
    std::string detail;

    const int one = w.add(static_cast<int>(::getpid()), 0x2000,
                          WatchKind::Write, WatchSize::Bytes1, detail);
    check(one != 0, "a one byte write watch is refused");
    check(detail.find("four or eight") != std::string::npos,
          "the refusal names the write watch widths");

    detail.clear();
    const int two = w.add(static_cast<int>(::getpid()), 0x2000,
                          WatchKind::Write, WatchSize::Bytes2, detail);
    check(two != 0, "a two byte write watch is refused");

    // A four byte read watch is legal. The restriction is on the write type
    // alone, which is why the check above is specific to it.
    detail.clear();
    const int four = w.add(static_cast<int>(::getpid()), 0x3000,
                           WatchKind::ReadWrite, WatchSize::Bytes4, detail);
    const bool available = Watchpoints::hardware_available();
    check(!available || four == 0,
          "a four byte read-or-write watch is accepted where hardware exists");
    if (four == 0) {
        std::fprintf(stderr,
                     "  note: installed a four byte read-or-write watch on the "
                     "test process at 0x3000\n");
    }
}

void test_wx_chase_prefers_new_mapping() {
    // A decoder's staging buffer does not exist when the process starts, so
    // arming the watches once at startup cannot reach it. The chase is what
    // moves the scarce debug registers onto a region that appeared while
    // the session was running, and this checks that it covers the region it
    // was asked about rather than reporting a coverage it does not have.
    WriteExecuteTracker tracker;
    Watchpoints watches;

    const int pid = static_cast<int>(::getpid());

    // Two regions the tracker is told about before anything is armed. They
    // stand in for the writable data segments a process image carries.
    std::string detail;
    (void)tracker.watch(pid, 0x100000, 24576, detail);
    (void)tracker.watch(pid, 0x200000, 4096, detail);
    check(tracker.region_count() == 2, "both regions are tracked");

    const ArmReport armed = tracker.arm(watches, pid);
    check(armed.watches_installed <= 4,
          "arming never exceeds the hardware slot count");
    check(armed.bytes_covered <= armed.bytes_total,
          "coverage never exceeds the requested bytes");
    std::fprintf(stderr,
                 "  note: armed %zu watches, covered %llu of %llu bytes\n",
                 armed.watches_installed,
                 static_cast<unsigned long long>(armed.bytes_covered),
                 static_cast<unsigned long long>(armed.bytes_total));

    // The shorter region is served first. That is the point of the ordering:
    // four registers of eight bytes cover thirty-two bytes, and a region of
    // thirty-two bytes or less can be covered completely, while a large one
    // can only be sampled. Longest-first would hand every register to the
    // 24576-byte region and guarantee never seeing a write to the 4096-byte
    // one.
    //
    // The assertion is about the allocation, not about a coverage that only
    // a machine with debug registers can produce. A kernel without them arms
    // nothing and reports every region unwatched, and that is a correct
    // answer that must not fail the test.
    if (armed.watches_installed > 0) {
        bool small_covered = false;
        for (const auto& partial : armed.partial) {
            if (partial.target.base == 0x200000) {
                small_covered = true;
            }
        }
        bool small_unwatched = false;
        for (const auto& u : armed.unwatched) {
            if (u.base == 0x200000) {
                small_unwatched = true;
            }
        }
        check(small_covered || small_unwatched,
              "the short region is served before the long one");
        check(armed.watches_installed <= 32 / 8,
              "no more watches are installed than the registers hold");
    }

    // A region that appears later is chased, and the cold watches on regions
    // nothing wrote to are released to make room for it.
    const ArmReport chased = tracker.chase(watches, pid, 0x300000, 4096);
    check(chased.bytes_total == 4096, "the chased region is measured");
    check(chased.bytes_covered <= 4096, "the chased coverage fits the region");
    std::fprintf(stderr,
                 "  note: chased 0x300000, installed %zu watches, covered "
                 "%llu of %llu bytes\n",
                 chased.watches_installed,
                 static_cast<unsigned long long>(chased.bytes_covered),
                 static_cast<unsigned long long>(chased.bytes_total));

    // Chasing the same region again is idempotent rather than a second set of
    // watches on the same address, which would waste a debug register.
    const ArmReport again = tracker.chase(watches, pid, 0x300000, 4096);
    check(again.watches_installed == 0,
          "re-chasing an armed region installs nothing new");

    // A region that has been written is never evicted: it holds the only
    // evidence a transition can still be built from.
    tracker.note_write(pid, 0x300000, 8, 0x401000);
    const std::size_t before = watches.fds().size();
    (void)tracker.evict_cold(watches, 100);
    check(watches.fds().size() == before,
          "a written region keeps its watches through an eviction");

    tracker.release(watches);
    check(watches.fds().empty(), "releasing the tracker frees every watch");
}

void test_wx_permission_transition() {
    // The transition the tracker exists to report: a region written while it
    // was not executable, then made executable. Reported once, because a
    // decoder that writes a byte at a time would otherwise produce one
    // report per byte.
    WriteExecuteTracker tracker;
    std::string detail;
    (void)tracker.watch(static_cast<int>(::getpid()), 0x400000, 4096, detail);

    RegionPerms data;
    data.readable = true;
    data.writable = true;
    data.executable = false;

    tracker.note_write(static_cast<int>(::getpid()), 0x400000, 4, 0x401000);
    check(!tracker.note_permission(static_cast<int>(::getpid()), 0x400000, data),
          "a region that is still not executable is not a transition");

    RegionPerms code = data;
    code.executable = true;
    check(tracker.note_permission(static_cast<int>(::getpid()), 0x400000, code),
          "becoming executable after a write is a transition");
    check(tracker.transitions().size() == 1, "one transition is recorded");
    check(!tracker.note_permission(static_cast<int>(::getpid()), 0x400000, code),
          "the same transition is not reported twice");
    check(tracker.transitions().size() == 1, "still one transition");

    // A region that became executable without being written is not a
    // transition. It is ordinary relro tightening or lazy binding.
    WriteExecuteTracker plain;
    (void)plain.watch(static_cast<int>(::getpid()), 0x500000, 4096, detail);
    check(!plain.note_permission(static_cast<int>(::getpid()), 0x500000, code),
          "an unwritten region becoming executable is not a transition");
    check(plain.transitions().empty(), "and no transition is recorded");
}

// The two entry points that install watches describe a region the same way.
// A caller that chased a mapping and got back a report with no partial entry
// would read the region as fully watched, however few of its bytes the
// registers actually reached -- and it would reach that conclusion because of
// which function it called rather than because of anything about the target.
void test_wx_chase_reports_partial_coverage() {
    WriteExecuteTracker tracker;
    Watchpoints watches;
    const int pid = static_cast<int>(::getpid());

    if (Watchpoints::machine_slots() == 0) {
        // A kernel without debug registers arms nothing, and every region is
        // correctly reported unwatched. Asserting coverage here would be
        // asserting a property of the host.
        std::fprintf(stderr,
                     "  note: no hardware debug registers, skipping the "
                     "chase parity check\n");
        return;
    }

    // Longer than the four registers can cover, so whatever is installed is
    // necessarily partial.
    const ArmReport first = tracker.chase(watches, pid, 0x340000, 4096);
    if (first.watches_installed == 0) {
        std::fprintf(stderr,
                     "  note: no watch could be installed, skipping the "
                     "chase parity check\n");
        return;
    }
    check(first.bytes_covered <= first.bytes_total,
          "the chased coverage fits inside the region");

    // Reaching the same region again goes down the already-armed path, which
    // is the one that used to report the coverage and nothing else.
    const ArmReport again = tracker.chase(watches, pid, 0x340000, 4096);
    check(again.watches_installed == 0,
          "re-chasing an armed region installs nothing new");
    check(again.bytes_covered == first.bytes_covered,
          "and reports the coverage the region already had");

    if (again.bytes_covered < again.bytes_total) {
        check(!again.partial.empty(),
              "a region reached through the already-armed path is still "
              "reported as partial");
        check(!again.complete(),
              "so the report does not claim the region is fully watched");
    }

    // The two reports agree about whether coverage was complete, which is the
    // property a caller comparing them depends on.
    check(first.complete() == again.complete(),
          "both reports agree on whether the region is fully covered");

    tracker.release(watches);
}

// The cached public view has to notice a length change from a merge as well
// as from an extension. A merge changes a region's length while leaving the
// number of regions alone, which is the case a size-only invalidation misses:
// a caller sizing work from the stale length would be working from a range
// that no longer exists.
void test_wx_targets_track_a_merged_length() {
    WriteExecuteTracker tracker;
    const int pid = static_cast<int>(::getpid());
    std::string detail;

    (void)tracker.watch(pid, 0x350000, 4096, detail);
    (void)tracker.watch(pid, 0x360000, 4096, detail);
    check(tracker.targets().size() == 2, "two disjoint regions are reported");

    // Read the cached view so it is warm, then merge into the first region.
    check(tracker.targets()[0].length == 4096,
          "the first region starts one page long");
    (void)tracker.watch(pid, 0x350800, 4096, detail);

    const auto& after = tracker.targets();
    check(after.size() == 2, "the overlapping range did not add a region");
    bool merged = false;
    for (const auto& t : after) {
        if (t.base == 0x350000 && t.length == 8192) {
            merged = true;
        }
    }
    check(merged,
          "the merged region reports the union's length rather than the one "
          "the cache was built with");
}

// ------------------------------------------------------------- gdb transport

// The transport is tested against a real socket rather than a mock because
// the things that go wrong here are the things a mock cannot show: a port
// that was not really bound, an accept that returned a descriptor which is
// not the one the listener owns, and a read that blocks instead of
// returning. Each of those is a hang or a wrong connection at run time, and
// both are invisible to an interface that pretends the bytes arrived.

void test_listener_binds_loopback() {
    // Port zero asks the kernel for any free port, which is the only way to
    // run this check without colliding with whatever else is on the machine.
    Listener listener;
    std::string error;
    const bool opened = listener.open(0, error);
    if (!opened) {
        // A sandbox that forbids sockets is a legitimate environment; the
        // check is that the refusal is explained rather than that it
        // succeeds.
        std::fprintf(stderr, "  note: cannot bind a socket here: %s\n",
                     error.c_str());
        check(!error.empty(), "a refusal names its reason");
        return;
    }
    check(listener.valid(), "a bound listener is valid");
    check(listener.port() != 0, "the bound port is reported back");
    check(!error.empty() == false, "a successful bind reports no error");

    // A second bind on the same port has to fail, and has to say why. Two
    // sessions silently sharing a port would mean a debugger attached to one
    // of them drives the other.
    Listener second;
    std::string second_error;
    const bool reopened = second.open(listener.port(), second_error);
    if (reopened) {
        // The kernel allows this when the first socket did not request
        // SO_REUSEADDR, which is the default, so a success here means the
        // platform allows it and there is nothing to assert.
        std::fprintf(stderr, "  note: rebinding an in-use port was allowed\n");
    } else {
        check(!second_error.empty(), "a refused bind names its reason");
        // The busy-port case is told apart from every other bind failure,
        // because the two call for different responses from whoever asked
        // for the port: one means wait, the other means something is wrong
        // with the address.
        //
        // The comparison this depends on is against the positive errno. A
        // failed Result carries the errno negated in its value field, so
        // comparing that against kEaddrinuse is never true -- the branch
        // stays in the source, looks like it handles the busy port, and never
        // runs. What the caller would see instead is the strerror of a
        // negative number.
        check(second_error.find("already in use") != std::string::npos,
              "a bind refused because the port is busy says so specifically");
        check(second_error.find("Unknown error") == std::string::npos,
              "and does not report a negative errno as the reason");
    }

    listener.close();
    check(!listener.valid(), "a closed listener is not valid");
}

void test_listener_stays_listening() {
    // The listener has to keep listening for as long as the run lasts, not
    // only until the first accept. A run that binds a port, prints it, and
    // then closes the socket looks correct right up to the moment somebody
    // tries to connect to the number it printed.
    Listener listener;
    std::string error;
    if (!listener.open(0, error)) {
        std::fprintf(stderr, "  note: skipping: %s\n", error.c_str());
        return;
    }
    const std::uint16_t port = listener.port();

    // Nothing has accepted yet, so the socket must still be connectable.
    // This is checked by connecting, not by inspecting the descriptor: an
    // open socket that was never told to listen refuses a connection, and so
    // does one that was closed after being told to.
    const auto client = occ::sys::socket(2, 1, 0);
    if (client.failed()) {
        std::fprintf(stderr, "  note: cannot create a client socket\n");
        return;
    }
    struct SockAddrIn {
        std::uint16_t family;
        std::uint16_t port;
        std::uint32_t addr;
        std::uint8_t zero[8];
    } addr{};
    addr.family = 2;
    addr.port = static_cast<std::uint16_t>((port >> 8) | (port << 8));
    addr.addr = 0x0100007f;
    const auto connected =
        occ::sys::connect(static_cast<int>(client.value), &addr, sizeof(addr));
    check(connected.ok(), "the port accepts a connection before any accept");

    // And the accept still succeeds afterwards, which is the property that
    // a closed socket would fail.
    Connection conn;
    check(listener.accept(conn, 1000),
          "the listener is still listening when accept is called");
    check(conn.valid(), "the accepted connection is valid");

    (void)occ::sys::close(static_cast<int>(client.value));
    conn.close();
}

void test_listener_accept_times_out() {
    Listener listener;
    std::string error;
    if (!listener.open(0, error)) {
        std::fprintf(stderr, "  note: skipping accept test: %s\n", error.c_str());
        return;
    }

    // Nobody connects, so the accept has to give up on its own. Without the
    // deadline this call blocks forever, which is what a run with a debugger
    // port would do to a user who started the run and walked away.
    Connection conn;
    const bool got = listener.accept(conn, 50);
    check(!got, "an accept with no peer times out");
    check(!conn.valid(), "a timed-out accept yields no connection");
}

void test_connection_round_trip() {
    Listener listener;
    std::string error;
    if (!listener.open(0, error)) {
        std::fprintf(stderr, "  note: skipping round trip test: %s\n",
                     error.c_str());
        return;
    }

    // A client socket connected to the listener, which stands in for the
    // debugger. It is made by hand rather than through the Listener because a
    // real debugger connects from outside the process.
    const auto client =
        occ::sys::socket(2 /* AF_INET */, 1 /* SOCK_STREAM */, 0);
    if (client.failed()) {
        std::fprintf(stderr, "  note: cannot create a client socket\n");
        return;
    }

    // 127.0.0.1 in network byte order, and the port the listener reported.
    struct SockAddrIn {
        std::uint16_t family;
        std::uint16_t port;
        std::uint32_t addr;
        std::uint8_t zero[8];
    } addr{};
    // The family is a host-order number. Writing it in network order, as the
    // other two fields are, is a mistake the kernel answers with an
    // address-family error that reads like a policy refusal rather than a
    // bug -- and it is why a listener written this way binds nowhere.
    addr.family = 2; // AF_INET
    addr.port = static_cast<std::uint16_t>((listener.port() >> 8) |
                                            (listener.port() << 8));
    addr.addr = 0x0100007f; // 127.0.0.1

    const auto connected = occ::sys::connect(static_cast<int>(client.value),
                                             &addr, sizeof(addr));
    if (connected.failed()) {
        std::fprintf(stderr, "  note: connect failed, skipping\n");
        (void)occ::sys::close(static_cast<int>(client.value));
        return;
    }

    Connection conn;
    check(listener.accept(conn, 1000), "a waiting accept returns a connection");
    check(conn.valid(), "the accepted connection is valid");

    // The port the listener reports must be the port that was actually
    // bound, or a person told to connect to it connects to nothing.
    check(conn.fd() >= 0, "the connection owns a descriptor");

    // A packet written by the client arrives whole, even when it arrives in
    // pieces: the framing is what makes a byte stream into messages.
    const std::string request = encode_packet("qSupported");
    const std::size_t half = request.size() / 2;
    check(occ::sys::write(static_cast<int>(client.value), request.data(), half).ok(),
          "the first half of a packet is written");
    check(conn.wait_readable(1000), "the connection becomes readable");
    check(conn.pump(), "a partial packet is read");
    check(!conn.has_packet(), "half a packet is not a packet");
    check(occ::sys::write(static_cast<int>(client.value), request.data() + half,
                     request.size() - half)
              .ok(),
          "the second half of a packet is written");
    check(conn.wait_readable(1000), "the connection is readable again");
    check(conn.pump(), "the rest of the packet is read");
    check(conn.has_packet(), "a whole packet is now available");

    std::string packet;
    check(conn.take_packet(packet), "the packet is taken");
    check(packet == "qSupported", "the payload survives the round trip");
    check(!conn.has_packet(), "the queue is empty again");

    // A reply goes back the same way. The framing is applied here rather than
    // by the caller, because a reply sent without it is a byte the debugger
    // discards.
    check(conn.send_packet("OK"), "a reply is sent");
    char buffer[64] = {};
    const auto got = occ::sys::read(static_cast<int>(client.value), buffer,
                               sizeof(buffer));
    check(got.ok(), "the client read the reply");
    if (got.ok()) {
        const std::string_view wire(buffer, static_cast<std::size_t>(got.value));
        check(wire == encode_packet("OK"), "the reply arrives framed");
    }

    // A closed peer is how a debugger that quit is noticed. Reporting it as
    // an error would make a normal disconnect look like a fault.
    (void)occ::sys::close(static_cast<int>(client.value));
    check(conn.wait_readable(1000), "the close is visible as readable");
    check(!conn.pump(), "a closed peer ends the connection");

    conn.close();
    check(!conn.valid(), "a closed connection is not valid");
}

void test_connection_drops_corrupt_packet() {
    // A packet whose checksum is wrong has to be refused rather than acted
    // on. A command read out of a corrupt packet is a command nobody sent,
    // and the worst thing this stub could do with one is resume a process or
    // write its memory on the strength of a transmission error.
    PacketDecoder decoder;
    // 'g' with a checksum that cannot match.
    decoder.feed("$g#00", 5);
    check(decoder.has_packet(), "a corrupt packet is still framed");
    Packet p = decoder.take();
    check(!p.checksum_ok, "a bad checksum is reported");

    // A failed checksum asks the sender for the packet again, and that is
    // what the sender does about it: the protocol has no other way to
    // recover a packet that arrived damaged. The resend is requested with
    // '-', and the packet itself is the sender's to resend -- it is not a
    // request for this side to replay its own last reply, which is the other
    // direction entirely and would put a packet on the wire nobody asked
    // for.
    PacketDecoder again;
    again.feed("$g#00", 5);
    check(again.has_packet(), "the corrupt packet is framed");
    (void)again.take();
    check(again.pending_ack() == '-',
          "a failed checksum asks the sender to send the packet again");
    check(!again.retransmit_requested(),
          "a failed checksum does not ask us to replay our last packet");
    // The packet to resend is the last one that arrived intact, not the
    // damaged one: replying with damaged bytes would reproduce the same
    // error. Nothing intact has arrived here, so there is nothing to resend.
    check(again.last_packet().empty(),
          "a damaged packet is not offered for retransmission");
    again.clear_retransmit();
    check(!again.retransmit_requested(), "the request is cleared once handled");

    // A packet that arrives intact does not ask for one, and this is the
    // property that keeps a good connection from retransmitting forever.
    PacketDecoder good;
    good.feed(encode_packet("g"));
    check(good.has_packet(), "an intact packet is framed");
    const Packet ok = good.take();
    check(ok.checksum_ok, "an intact packet passes its checksum");
    check(!good.retransmit_requested(),
          "an intact packet asks for no retransmission");
    check(good.last_packet() == encode_packet("g"),
          "an intact packet is the one to resend");
}

// Returns the name of the index'th <reg> element, or an empty view when the
// description is shorter than that. The order is the one GDB numbers by.
//
// The scan matches a whole "<reg " tag and nothing else. A looser search --
// find the next "<reg " and read to the next "/>" -- walks into the <flags>
// element that declares the eflags bit layout, because its <field> children
// end in "/>" too, and from there the offsets are wrong. Skipping non-register
// elements instead is worse: deciding where a <feature> ends means matching
// nesting, and getting that wrong skips a whole feature and reports the
// registers after it as missing. A register tag carries no children, so its
// own "/>" is the end of it, and matching that is enough.
std::string_view reg_name_at(std::string_view xml, std::size_t index_wanted) {
    std::size_t pos = 0;
    std::size_t index = 0;
    while (pos < xml.size()) {
        const std::size_t reg = xml.find("<reg ", pos);
        if (reg == std::string_view::npos) {
            return {};
        }
        // Reject a partial match: "<reg" has to be followed by a space, and
        // the name attribute has to open before the tag closes.
        const std::size_t end = xml.find("/>", reg);
        if (end == std::string_view::npos) {
            return {};
        }
        const std::size_t name = xml.find("name=\"", reg);
        if (name == std::string_view::npos || name >= end) {
            // Not a register element after all, or a malformed one. Step past
            // this tag and keep looking rather than giving up.
            pos = reg + 5;
            continue;
        }
        if (index == index_wanted) {
            const std::size_t first = name + 6;
            const std::size_t close = xml.find('"', first);
            if (close == std::string_view::npos || close > end) {
                return {};
            }
            return xml.substr(first, close - first);
        }
        ++index;
        pos = end;
    }
    return {};
}

// ------------------------------------------------------- target description

// Counts the register elements in the description. The count is what has to
// agree with the 'g' reply, and it is checked against the wire format rather
// than against a constant so that a register added to one place and not the
// other is caught here instead of by a debugger showing shifted values.
std::size_t count_registers(std::string_view xml) {
    std::size_t seen = 0;
    for (std::size_t i = 0; !reg_name_at(xml, i).empty(); ++i) {
        ++seen;
    }
    return seen;
}


void test_target_description() {
    const std::string_view xml = target_description();
    check(!xml.empty(), "the target description is not empty");
    check(xml.find("i386:x86-64") != std::string_view::npos,
          "the description names the x86-64 architecture");

    // The core feature has to carry all forty registers GDB's x86-64 tdep
    // walks, in the order it walks them. i386_validate_tdesc_p compares each
    // of the first num_core_regs entries against the name its own list holds,
    // and rejects the whole description if one is missing or out of place. The
    // rejection is only a warning from the user's side, and the consequence is
    // that GDB falls back to its own 32-bit defaults and reads the rest of the
    // 'g' reply at the wrong offsets. So this is the single assertion that
    // keeps the description usable at all, and it is written out in full
    // because the list is GDB's, not ours.
    static const char *const kCoreNames[] = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
        "rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs",
        "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
        "fctrl", "fstat", "ftag", "fiseg", "fioff", "foseg", "fooff", "fop",
    };
    bool core_ok = true;
    for (std::size_t i = 0; i < sizeof(kCoreNames) / sizeof(kCoreNames[0]);
         ++i) {
        if (reg_name_at(xml, i) != kCoreNames[i]) {
            core_ok = false;
            break;
        }
    }
    check(core_ok,
          "the core feature carries all forty registers in GDB's order, "
          "ending at %fop rather than %gs");

    // The three this stub adds are the 41st through 43rd, and %orig_rax is
    // last because GDB has no register number for it at all: putting it in the
    // middle would displace %st0 and shift the whole x87 block up by one.
    check(reg_name_at(xml, 40) == "fs_base", "fs_base follows the core block");
    check(reg_name_at(xml, 41) == "gs_base", "gs_base follows fs_base");
    check(reg_name_at(xml, 42) == "orig_rax", "orig_rax is the last register");
    check(count_registers(xml) == 43,
          "the description carries the core forty and the three it adds");

    // The program counter is the register a debugger reads first, and its
    // width is load-bearing: it is the field the 'g' reply and the 'p' packet
    // both size from. A description that made it narrower would shift every
    // register after it.
    check(reg_name_at(xml, 16) == "rip", "rip is the seventeenth register");
    check(xml.find("name=\"rip\" bitsize=\"64\"") != std::string_view::npos,
          "rip is sixty-four bits wide");

    // eflags and the segment selectors are thirty-two bit, and the x87 stack
    // registers are eighty. Describing either as a full word makes the 'g'
    // reply longer than the debugger expects and shifts every field after it,
    // so %st0 ends up holding %fop and a backtrace names the wrong frame.
    check(xml.find("name=\"eflags\" bitsize=\"32\"") != std::string_view::npos,
          "eflags is thirty-two bits");
    check(xml.find("name=\"cs\" bitsize=\"32\"") != std::string_view::npos,
          "cs is thirty-two bits");
    check(xml.find("name=\"st0\" bitsize=\"80\"") != std::string_view::npos,
          "st0 is the eighty-bit x87 extended format");

    // No regnum attribute anywhere. GDB numbers the registers itself, in
    // document order, from its own tdep enum; a regnum written here would be a
    // second parallel numbering that GDB never consults when it validates the
    // description, and one that would silently drift out of step with it.
    check(xml.find("regnum=") == std::string_view::npos,
          "the description leaves register numbering to GDB");

    // eflags is described through a flags element, which has to be declared
    // before the register that refers to it or GDB reports an unknown type and
    // drops the whole description.
    const std::size_t flags = xml.find("<flags id=\"i386_eflags\"");
    const std::size_t eflags = xml.find("name=\"eflags\"");
    check(flags != std::string_view::npos && flags < eflags,
          "the eflags bit layout is declared before the register using it");

    // %fs_base and %gs_base have to live in the segments feature. GDB looks
    // for them there by name, and a description that put them in the core
    // feature leaves it believing %fs has no base, so every backtrace shows a
    // wrong thread pointer.
    const std::size_t segments = xml.find("org.gnu.gdb.i386.segments");
    const std::size_t fs_base = xml.find("name=\"fs_base\"");
    const std::size_t gs_base = xml.find("name=\"gs_base\"");
    check(segments != std::string_view::npos && segments < fs_base &&
              fs_base < gs_base,
          "the segment bases are declared in the segments feature, in order");
}

// The bitsize the description gives a register, found by the same scan a
// debugger's parser would do.
std::size_t reg_bitsize(std::string_view xml, std::string_view name) {
    const std::string needle = "name=\"" + std::string(name) + "\" bitsize=\"";
    const std::size_t at = xml.find(needle);
    if (at == std::string_view::npos) {
        return 0;
    }
    const std::size_t first = at + needle.size();
    std::size_t value = 0;
    for (std::size_t i = first; i < xml.size() && xml[i] != '"'; ++i) {
        const char c = xml[i];
        if (c < '0' || c > '9') {
            return 0;
        }
        value = value * 10 + static_cast<std::size_t>(c - '0');
    }
    return value;
}

void test_register_block_matches_description() {
    // The block the 'g' handler writes and the document GDB reads are written
    // in different places, and nothing in either one checks the other. A
    // register that disagrees between them is invisible from both sides: the
    // block is self-consistent, the description is self-consistent, GDB accepts
    // the description and reads the block at the widths the description gives.
    // Every register past the mismatch then shows a plausible value under the
    // wrong name -- %st0 holding %fop, a backtrace naming the wrong frame --
    // and nothing reports an error. So the two are held against each other
    // here, name by name, rather than trusted to stay in step.
    const std::string_view xml = target_description();
    const std::size_t count = count_registers(xml);

    bool widths_agree = true;
    for (std::size_t i = 0; i < count; ++i) {
        const std::string_view name = reg_name_at(xml, i);
        if (name.empty()) {
            widths_agree = false;
            break;
        }
        if (reg_bitsize(xml, name) != gdb_register_bits(i)) {
            widths_agree = false;
            break;
        }
    }
    check(widths_agree,
          "every register is packed at the width the description declares");

    // The block is not eight bytes per register, and treating it as one is the
    // mistake that makes the check above pass while the wire format is wrong.
    // GDB packs the description end to end with no padding, so x86-64 comes to
    // 300 bytes -- and a stub that sent 43 eight-byte cells would be 44 bytes
    // long and refused outright.
    check(gdb_register_block_size() == 300,
          "the block is 300 bytes, not eight per register");
    check(gdb_register_bits(0) == 64, "rax is 64 bits");
    check(gdb_register_bits(16) == 64, "rip is 64 bits");
    check(gdb_register_bits(17) == 32, "eflags is 32 bits");
    check(gdb_register_bits(23) == 32, "gs is 32 bits");
    check(gdb_register_bits(24) == 80, "st0 is 80 bits");
    check(gdb_register_bits(31) == 80, "st7 is 80 bits");
    check(gdb_register_bits(32) == 32, "fctrl is 32 bits");
    check(gdb_register_bits(39) == 32, "fop is 32 bits");
    check(gdb_register_bits(40) == 64, "fs_base is 64 bits");
    check(gdb_register_bits(42) == 64, "orig_rax is 64 bits");
    check(gdb_register_bits(43) == 0, "there is no forty-fourth register");

    // The 'p' handler is asked by the register number GDB assigned, and that is
    // not the position in the block: GDB reserves 40 through 51 for the SSE and
    // AVX banks this description does not declare, so the segment bases land at
    // 152 and 153. Reading them by position would answer a question about
    // %gs_base with %st4.
    check(gdb_regnum_fs_base() == 152, "fs_base is register 152 to GDB");
    check(gdb_regnum_gs_base() == 153, "gs_base is register 153 to GDB");
    check(gdb_regnum_orig_rax() == 154,
          "orig_rax is answered just past the bases");
}

void test_serve_target_description() {
    const std::string_view xml = target_description();

    // A request for an annex that does not exist answers "l", which is how
    // the protocol says there is nothing here. Answering an error instead
    // makes a debugger that probes for optional files treat the stub as
    // broken.
    check(serve_target_description("features:read:no-such.xml:0,100") == "l",
          "an unknown annex answers l");

    // Malformed packets answer empty, the protocol's "not supported".
    check(serve_target_description("").empty(),
          "an empty request is refused");
    check(serve_target_description("target.xml").empty(),
          "a request without a range is refused");
    check(serve_target_description("target.xml:0").empty(),
          "a range without a length is refused");
    check(serve_target_description("target.xml:zz,10").empty(),
          "a non-hexadecimal offset is refused");

    // A zero-length read answers "l": there is nothing to send and saying
    // "m" would invite the debugger to ask again forever.
    check(serve_target_description("target.xml:0,0") == "l",
          "a zero length answers l");

    // An offset exactly at the end is what the last chunked request looks
    // like, so it answers "l" rather than being treated as out of range.
    const std::string at_end =
        serve_target_description("target.xml:" + hex_number(xml.size()) + ",10");
    check(at_end == "l", "an offset at the end answers l");

    // An offset past the end is out of range, and also answers "l".
    const std::string past_end = serve_target_description(
        "target.xml:" + hex_number(xml.size() + 4096) + ",10");
    check(past_end == "l", "an offset past the end answers l");

    // A short read in the middle is prefixed 'm', meaning more follows. The
    // range is hexadecimal, so the length is written with hex_number rather
    // than spelled as a decimal count -- "64" is one hundred bytes, which is
    // the mistake that makes a stub appear to work in a hand-written test
    // and fail against a real debugger.
    const std::string first =
        serve_target_description("target.xml:0," + hex_number(64));
    check(first.size() == 65, "a chunk is the requested length plus a marker");
    check(!first.empty() && first[0] == 'm', "a partial chunk is marked m");
    check(std::string_view(first).substr(1) == xml.substr(0, 64),
          "the chunk is the document from the requested offset");

    // The length is read as hexadecimal, not as a decimal digit count. This
    // is the property the check above depends on and the one a debugger
    // depends on: it sends "400" meaning one kilobyte and expects a
    // thousand and twenty eight bytes back.
    check(serve_target_description("target.xml:0,10").size() == 17,
          "a length is read as hexadecimal");

    // A read that reaches the end is prefixed 'l', meaning the document is
    // complete. Always answering 'm' is what makes a debugger loop.
    const std::string whole =
        serve_target_description("target.xml:0," + hex_number(xml.size()));
    check(whole.size() == xml.size() + 1, "a full read covers the document");
    check(!whole.empty() && whole[0] == 'l', "a complete chunk is marked l");
    check(std::string_view(whole).substr(1) == xml,
          "a full read is the whole document");

    // A read that asks for more than remains is clamped and marked 'l' rather
    // than being reported as a short read.
    const std::string over =
        serve_target_description("target.xml:0," + hex_number(xml.size() + 1000));
    check(over.size() == xml.size() + 1, "an over-long read is clamped");
    check(over[0] == 'l', "a clamped read is marked l");

    // Reassembling the chunks the way GDB does must reproduce the document
    // exactly. This is the property that matters and the one no single
    // request above establishes.
    std::string rebuilt;
    std::size_t offset = 0;
    for (int guard = 0; guard < 64; ++guard) {
        const std::string chunk =
            serve_target_description("target.xml:" + hex_number(offset) + "," + hex_number(200));
        if (chunk.empty()) {
            check(false, "a chunk request in the middle returned empty");
            break;
        }
        // The marker is the first character and the data follows it, so the
        // last chunk is "l" plus the tail of the document rather than the
        // one-character "l" that means "no such object". Appending from the
        // second character either way is what makes the reassembly
        // independent of where the chunks happened to be cut.
        const bool last = chunk[0] == 'l';
        rebuilt.append(chunk, 1, std::string::npos);
        offset += chunk.size() - 1;
        if (last) {
            break;
        }
    }
    check(rebuilt == xml, "the chunked reads reassemble into the document");
    check(offset == xml.size(), "the reassembly consumed the whole document");
}

void test_parse_vcont() {
    // The capability query. A debugger sends this to decide whether to use
    // vCont at all, and answers with the actions it may then send. Advertising
    // an action that is not implemented is worse than advertising none.
    //
    // The list and the resume answers are covered by
    // test_vcont_query_lists_the_actions and
    // test_vcont_resume_is_answered_with_silence, which also check what
    // happens to the empty answer on the wire. This covers the action
    // parsing the two share.
    bool consume = true;
    bool step = true;
    int signal = 0;
    (void)parse_vcont("", 4242, consume, step, signal);
    check(!consume, "the capability query asks for no resume");
    check(!step, "the capability query sets no step");
    check(signal == 0, "the capability query carries no signal");

    // A continue consumes without stepping.
    consume = false;
    step = true;
    signal = 0;
    (void)parse_vcont(";c", 4242, consume, step, signal);
    check(consume, "a continue consumes");
    check(!step, "a continue does not step");
    check(signal == 0, "a continue carries no signal");

    // A step consumes and steps.
    consume = false;
    step = false;
    signal = 0;
    (void)parse_vcont(";s", 7, consume, step, signal);
    check(consume, "a step consumes");
    check(step, "a step steps");
    check(signal == 0, "a step carries no signal");

    // The capitalised forms carry the signal to deliver, as a two digit hex
    // number. Signal 5 is SIGTRAP and signal 11 is SIGSEGV, both of which a
    // debugger sends when it wants the target to take a fault deliberately.
    consume = false;
    step = false;
    signal = 0;
    (void)parse_vcont(";C05", 9, consume, step, signal);
    check(consume && !step, "a continue with a signal consumes without stepping");
    check(signal == 5, "the signal is carried through");

    consume = false;
    step = false;
    signal = 0;
    (void)parse_vcont(";S0b", 9, consume, step, signal);
    check(consume && step, "a step with a signal steps");
    check(signal == 11, "the signal is carried through a step");

    // A lowercase verb ignores a trailing condition. "c:thread" selects a
    // thread, not a signal, and reading a thread number as a signal would
    // deliver a signal the debugger never asked for.
    consume = false;
    step = false;
    signal = 0;
    (void)parse_vcont(";c:2", 9, consume, step, signal);
    check(consume && !step, "a threaded continue consumes");
    check(signal == 0, "a thread number is not read as a signal");

    // The first resume action wins. A debugger sends one per thread, and
    // acting on the last would resume a thread the debugger listed first.
    consume = false;
    step = false;
    signal = 0;
    (void)parse_vcont(";s;c", 9, consume, step, signal);
    check(consume && step, "the first action decides the step");

    consume = false;
    step = false;
    signal = 0;
    (void)parse_vcont(";r;c", 9, consume, step, signal);
    check(consume && !step, "an unsupported leading action is skipped");

    // Nothing resumable in the packet means no resume, which the protocol
    // defines as an empty answer.
    consume = true;
    step = true;
    signal = 7;
    check(parse_vcont(";t", 9, consume, step, signal).empty(),
          "a stop-only packet asks for no resume");
    check(!consume, "a stop-only packet does not consume");
    check(!step, "a stop-only packet does not step");
    check(signal == 0, "a stop-only packet clears the signal");
}

// ------------------------------------------------- ptrace stop classification

// Builds the wait status a stop arrives in.
//
// The layout is the kernel's: the stop signal in bits 0-6, bit 7 as the
// marker PTRACE_O_TRACESYSGOOD sets on a syscall stop, the event number in
// bits 16-23, and the exit code in the top byte. The values are the ones the
// host produces -- a fork stop here is 0x0001057f and the PTRACE_EVENT_STOP
// that PTRACE_INTERRUPT raises is 0x0080057f -- so these are the numbers
// classify_status has to read rather than numbers invented to suit it.
constexpr int status_for(int event, int signal) noexcept {
    return (event << 16) | (signal << 8) | 0x7f;
}

void test_event_number_is_in_the_high_byte() {
    // A fork stop. Read as `status >> 8` the event comes out as 0x105, which
    // is not an event number at all: the shift picks up the signal and the
    // syscall marker instead. Every event then misses its case and the stop
    // is reported as a bare SIGTRAP, so the child the event announced is
    // never configured and never resumed.
    const Stop fork_stop =
        classify_status(4242, status_for(kPtraceEventFork, 5));
    check(fork_stop.kind == StopKind::NewChild,
          "a fork event is a new-child stop");
    check(fork_stop.synthetic,
          "a fork event is synthetic and must not be redelivered");

    // The events the session acts on differently. Each reaching the right
    // case is the point: a misrouted exec or seccomp trap is reported as a
    // breakpoint and the target runs on past a change the observer was
    // supposed to see.
    check(classify_status(1, status_for(kPtraceEventClone, 5)).kind ==
              StopKind::NewChild,
          "a clone event is a new-child stop");
    check(classify_status(1, status_for(kPtraceEventVfork, 5)).kind ==
              StopKind::NewChild,
          "a vfork event is a new-child stop");
    check(classify_status(1, status_for(kPtraceEventExec, 5)).kind ==
              StopKind::Exec,
          "an exec event is an exec stop");
    check(classify_status(1, status_for(kPtraceEventSeccomp, 5)).kind ==
              StopKind::SeccompTrap,
          "a seccomp event is a seccomp trap");
    check(classify_status(1, status_for(kPtraceEventExit, 5)).kind ==
              StopKind::Exited,
          "an exit event is the final stop");
    check(classify_status(1, status_for(kPtraceEventVforkDone, 5)).kind ==
              StopKind::Signal,
          "a vfork-done event is a stop to be resumed");

    // The number is 128 and it shares the byte every other event uses, so it
    // has to be matched as a value. Read as anything else, a
    // PTRACE_INTERRUPT is reported as a plain SIGTRAP and the session's
    // redelivery rule then suppresses a signal the tracee should have seen.
    const Stop interrupt = classify_status(1, status_for(kPtraceEventStop, 5));
    check(interrupt.kind == StopKind::GroupStop,
          "PTRACE_EVENT_STOP is a group stop");
    check(interrupt.signal == 19,
          "PTRACE_EVENT_STOP carries the group-stop signal");

    // A real SIGTRAP with no event is a breakpoint or a single step, and it
    // is the only case that may be read as a signal. It is the case the
    // event-number read has to leave alone.
    const Stop plain = classify_status(1, status_for(0, 5));
    check(plain.kind == StopKind::Signal, "a bare SIGTRAP is a signal stop");
    check(plain.signal == 5, "a bare SIGTRAP carries SIGTRAP");

    // A syscall stop is distinguished by the marker bit, not by the event
    // byte. It differs from a bare SIGTRAP only in bit 7 of the signal byte,
    // so a classifier that read the wrong place would call every syscall stop
    // a breakpoint and the session would emit a breakpoint event per
    // syscall.
    const Stop syscall_stop = classify_status(1, status_for(0, 5 | 0x80));
    check(syscall_stop.kind == StopKind::SyscallStop,
          "the TRACESYSGOOD marker is a syscall stop");
    check(syscall_stop.synthetic,
          "a syscall stop is synthetic and must not be redelivered");

    // A status with the top bit set is negative as an int and arrives that
    // way from the kernel. The event byte is read from the unsigned value, so
    // this is a shape the read has to survive rather than an artificial one.
    const int negative = static_cast<int>(0x8000'0000u) | 0x057f;
    check(classify_status(1, negative).kind == StopKind::Signal,
          "a status with the top bit set is still classified");

    // Exits are decided before the event byte is consulted, and the exit
    // code is the low byte rather than anything above it.
    check(classify_status(1, 0x00000007).kind == StopKind::Exited,
          "an exited process is reported as exited");
    check(classify_status(1, 0x00000007).exit_code == 7,
          "the exit code is read from the status");
}

void test_group_stop_is_not_an_event() {
    // A group stop carries no event: the event byte is zero and the signal
    // is SIGSTOP. It proves the event field and the signal field are read
    // from different places -- reading the event as `status >> 8` finds 0x13
    // here, which is not an event, and sends the stop down the SIGTRAP path.
    const Stop group = classify_status(7, status_for(0, 19));
    check(group.kind == StopKind::GroupStop, "SIGSTOP is a group stop");
    check(!group.synthetic,
          "a group stop is not synthetic: SIGSTOP has a meaning to deliver");
}

// -------------------------------------------------------------- the vCont answers

void test_vcont_query_lists_the_actions() {
    // "vCont?" is the packet with the "vCont" prefix already stripped, so
    // the question mark is all that is left. Answering it with an empty
    // packet -- which is what "this packet names no action I can perform"
    // produces -- is read as a stub that does not implement vCont.
    bool consume = true;
    bool step = true;
    int signal = 0;
    const std::string q = parse_vcont("?", 4242, consume, step, signal);
    check(q == "vCont;c;C;s;S", "the query lists the supported actions");
    check(!q.empty(), "the query is answered with a packet, not with silence");
    check(!consume, "the query asks for no resume");
    check(!step, "the query sets no step");
    check(signal == 0, "the query carries no signal");

    // Every advertised action has to be one the parser acts on. "r" and "t"
    // used to be advertised and then refused by the action scan, so a
    // debugger believing the reply could ask for a restart and get silence.
    //
    // The check is on the action list rather than on the whole answer,
    // because the answer carries the "vCont" prefix and the "t" in it is not
    // an advertised stop action.
    const std::size_t prefix = q.find(';');
    check(prefix != std::string::npos, "the answer names its own prefix");
    const std::string actions = q.substr(prefix);
    check(actions == ";c;C;s;S",
          "the advertised actions are exactly the four that are performed");
    check(actions.find('r') == std::string::npos,
          "the query does not advertise a restart it cannot perform");
    check(actions.find('t') == std::string::npos,
          "the query does not advertise a stop it cannot perform");

    // Each advertised letter resumes when sent, which is what makes the list
    // a statement about this parser rather than a fixed string.
    for (const char* verb : {"c", "C05", "s", "S05"}) {
        consume = false;
        step = false;
        signal = 0;
        (void)parse_vcont(std::string(";") + verb, 4242, consume, step, signal);
        check(consume, "every advertised action resumes the tracee");
    }
}

void test_vcont_resume_is_answered_with_silence() {
    // A continue is not answered with a packet. The resume is the answer and
    // the stop reply follows when the target actually stops, so anything sent
    // here describes a stop that has not happened -- and the debugger, having
    // resumed, takes it for the stop it was waiting for and reports the
    // target at a program counter it has not reached.
    //
    // The two ways of saying nothing are the same std::string and mean
    // opposite things on the wire, so what is checked is that the string is
    // empty and the caller's decision to send nothing comes from the flags
    // rather than from the emptiness.
    bool consume = false;
    bool step = false;
    int signal = 0;
    const std::string reply = parse_vcont(";c", 4242, consume, step, signal);
    check(consume, "a continue asks for a resume");
    check(reply.empty(),
          "a continue is answered with no packet rather than a stop reply");

    // And it must not be a stop reply in disguise. "T" followed by a thread
    // number is what this returned before: a malformed stop reply, since the
    // byte after T is the signal, describing a stop that never happened.
    check(reply.empty() || reply[0] != 'T',
          "a continue is not answered with a T-form stop reply");
}

void test_vcont_through_the_dispatcher_answers_correctly() {
    // The parser alone cannot be wrong about silence: it returns a string
    // either way. The defect lived one level up, where the return value was
    // framed unconditionally -- so an empty answer became "$#00", which is
    // the protocol's "not supported" and the exact opposite of the intended
    // silence. Only Reply distinguishes them, so the dispatch is what has to
    // be tested.
    Tracer tracer;
    Breakpoints bps;
    Writer events;
    DebugServer server(tracer, bps, 4242, events);

    const Reply query = server.handle("vCont?");
    check(query.send, "the capability query is answered on the wire");
    check(query.payload == "vCont;c;C;s;S",
          "the query answers with the action list");

    server.clear_resume();
    const Reply resume = server.handle("vCont;c");
    check(!resume.send, "a vCont continue sends nothing at all");
    check(resume.payload.empty(), "a vCont continue has no payload to frame");
    check(server.resume_requested(), "the continue is left for the loop");

    // A vCont naming only an action this stub cannot perform is a different
    // case and keeps the empty packet: the packet was understood and is not
    // implemented, which is what "$#00" means.
    server.clear_resume();
    const Reply unsupported = server.handle("vCont;t");
    check(unsupported.send, "a stop-only vCont is answered on the wire");
    check(unsupported.payload.empty(),
          "a stop-only vCont frames as the empty packet");
}

// ------------------------------------------------------------- register widths

// A child stopped on its own ptrace stop, which is what the handlers need to
// be handed: a read of the tracee's memory or registers only succeeds
// against a process this one controls.
//
// The stop is waited for here rather than left to the caller. A tracer
// cannot read a tracee that has not reported its stop -- GETREGS fails with
// ESRCH -- so a helper that left the wait to the caller would hand back a
// pid that answers E01 to everything, and the tests using it would pass
// without having checked anything. Nothing waits again afterwards: a ptrace
// stop is reported once, and a second wait would consume nothing and leave
// the child parked, so the tests only kill it.
int fork_traced_stopped() {
    const int pid = ::fork();
    if (pid != 0) {
        int status = 0;
        ::waitpid(pid, &status, __WALL);
        return pid;
    }
    if (ptrace(kPtraceTraceme, 0, nullptr, nullptr).failed()) {
        ::_exit(126);
    }
    ::raise(SIGSTOP);
    for (;;) {
        ::pause();
    }
}

void test_single_register_is_answered_at_its_own_width() {
    // A 'p' reply is sized by the target description, not by the width of
    // the register file. Eight bytes for %eflags is not padding GDB
    // discards: it reads the four it expects and then reads the next four as
    // the following register, so every register after the first short one
    // shows a shifted value under the wrong name.
    check(gdb_regnum_width(0) == 64, "rax is answered at eight bytes");
    check(gdb_regnum_width(16) == 64, "rip is answered at eight bytes");
    check(gdb_regnum_width(17) == 32, "eflags is answered at four bytes");
    check(gdb_regnum_width(18) == 32, "cs is answered at four bytes");
    check(gdb_regnum_width(23) == 32, "gs is answered at four bytes");
    check(gdb_regnum_width(24) == 80, "st0 is answered at ten bytes");
    check(gdb_regnum_width(31) == 80, "st7 is answered at ten bytes");
    check(gdb_regnum_width(32) == 32, "fctrl is answered at four bytes");
    check(gdb_regnum_width(39) == 32, "fop is answered at four bytes");

    // The three past the core feature are not at the block index. GDB
    // reserves 40 through 51 for the SSE and AVX banks this description does
    // not declare, so a width looked up by block position would answer a
    // question about %fs_base with %st0's ten bytes.
    check(gdb_regnum_width(gdb_regnum_fs_base()) == 64,
          "fs_base is answered at eight bytes");
    check(gdb_regnum_width(gdb_regnum_gs_base()) == 64,
          "gs_base is answered at eight bytes");
    check(gdb_regnum_width(gdb_regnum_orig_rax()) == 64,
          "orig_rax is answered at eight bytes");

    // A register in the SSE/AVX gap has no width, because the description
    // does not declare it. Zero is what says "no answer", and it keeps the
    // handler from framing an undeclared register as eight bytes of zero.
    check(gdb_regnum_width(40) == 0, "an undeclared register has no width");
    check(gdb_regnum_width(45) == 0, "an AVX register has no width");
    check(gdb_regnum_width(151) == 0, "a number below the bases has none");

    // The widths above are what the handler is told to use; what matters is
    // the length that reaches the wire. A 'p' reply is sized by the
    // description on the other end, so a reply that is eight bytes for a
    // four-byte register is not padded over -- GDB reads four bytes as the
    // register and the next four as the register after it.
    //
    // This needs a tracee, because the handler reads the registers through
    // ptrace and answers E01 for a pid it cannot read. The length is then
    // checked against the width the description declares.
    const int pid = fork_traced_stopped();
    if (pid == 0) {
        return;
    }

    Tracer tracer;
    Breakpoints bps;
    Writer events;
    DebugServer server(tracer, bps, pid, events);

    struct Expectation {
        const char* packet;
        std::size_t digits;
        const char* what;
    };
    // Every entry is a register whose width is not eight bytes, plus %rip as
    // the control: it is eight, and a handler that padded everything to
    // eight would pass the narrow cases only by being wrong about all of
    // them.
    const Expectation cases[] = {
        {"p10", 16, "rip is sent as eight bytes"},
        {"p11", 8, "eflags is sent as four bytes"},
        {"p12", 8, "cs is sent as four bytes"},
        {"p17", 8, "gs is sent as four bytes"},
        {"p18", 20, "st0 is sent as ten bytes"},
        {"p1f", 20, "st7 is sent as ten bytes"},
        {"p20", 8, "fctrl is sent as four bytes"},
        {"p27", 8, "fop is sent as four bytes"},
        {"p98", 16, "fs_base is sent as eight bytes"},
        {"p99", 16, "gs_base is sent as eight bytes"},
        {"p9a", 16, "orig_rax is sent as eight bytes"},
    };
    for (const Expectation& c : cases) {
        const Reply r = server.handle(c.packet);
        check(r.payload.size() == c.digits, c.what);
    }

    // A register in the undeclared gap gets no payload at all rather than
    // eight bytes of zero: GDB has no width for it, so there is nothing it
    // could read correctly out of a reply.
    check(server.handle("p28").payload.empty(),
          "an undeclared register is answered with no bytes");

    // The kill is the cleanup, not part of what is being checked, and a
    // child that outlives the test is a leaked process rather than a failed
    // assertion. The status it would report is discarded deliberately.
    (void)tracer.kill(pid);
}

// --------------------------------------------------------------- hex on the wire

// A protocol number spelled with uppercase digits.
//
// hex_number is the canonical form and produces lowercase, because that is
// what this implementation emits. The tests need the other case as an input,
// and a separate helper is clearer than transforming hex_number's output:
// what is under test is that a packet spelled in a case this code never
// produces is still read.
std::string to_upper_hex(std::uint64_t value) noexcept {
    std::string digits = hex_number(value);
    for (char& c : digits) {
        if (c >= 'a' && c <= 'f') {
            c = static_cast<char>(c - 'a' + 'A');
        }
    }
    return digits;
}

void test_hex_fields_accept_both_cases() {
    // The address and length fields of m, M and Z are read by this file's
    // own scanner rather than by the shared helpers, and it used to accept
    // lowercase only. GDB writes either case depending on the packet, so a
    // request whose address was spelled with uppercase digits was answered
    // E01 -- which the debugger reports as "cannot access memory" rather
    // than as a parse failure, and that is why the defect survived.
    //
    // The read is against a real tracee so that a successful parse is
    // distinguishable from a refused one. Against a pid that cannot be traced
    // every spelling answers E01 and the case is invisible, which would make
    // this test pass with or without the fix.
    const int pid = fork_traced_stopped();
    if (pid == 0) {
        return;
    }

    Tracer tracer;
    Breakpoints bps;
    Writer events;
    DebugServer server(tracer, bps, pid, events);

    // The stack pointer is an address the tracee has mapped and can be read
    // at, which a hardcoded one is not: the text segment is somewhere in the
    // high half and an address invented for the test is very likely to be
    // unmapped, and an unmapped address answers E01 whatever the parser did
    // with the digits.
    Registers regs{};
    if (tracer.get_regs(pid, regs).failed()) {
        check(false, "the tracee's registers are readable");
        (void)tracer.kill(pid);
        return;
    }

    // Aligned down a page. The pointer itself is readable, but the sixteen
    // bytes above it are whatever the child was doing when it stopped and
    // the value is not stable between runs; below the pointer the stack is
    // mapped and already unwound, so the bytes are the same on every run and
    // the two spellings can be compared for equality rather than for size.
    const std::uint64_t page = regs.rsp & ~static_cast<std::uint64_t>(0xfff);
    const std::string lower_addr = "m" + hex_number(page) + ",10";
    const std::string upper_addr = "m" + to_upper_hex(page) + ",10";

    // Both spellings have to return the same bytes, and they have to return
    // bytes rather than an error: an uppercase address that parsed produces
    // the same payload as the lowercase one, and one that did not produces
    // E01.
    const std::string lower = server.handle(lower_addr).payload;
    const std::string upper = server.handle(upper_addr).payload;
    // Sixteen bytes is thirty-two hex digits, and the count is what says the
    // read reached the tracee rather than being refused.
    check(lower.size() == 32, "a lowercase memory read reaches the tracee");
    check(lower == upper,
          "an uppercase memory address parses like a lowercase one");

    // The length field goes through the same scan as the address, so it has
    // to take both cases too. Ten bytes is twenty hex digits: if the digits
    // parsed we get twenty, and if they did not we get the three of E01.
    const std::string lower_len =
        server.handle("m" + hex_number(page) + ",a").payload;
    const std::string upper_len =
        server.handle("m" + hex_number(page) + ",A").payload;
    check(lower_len.size() == 20, "a lowercase length reads ten bytes");
    check(upper_len == lower_len,
          "an uppercase length reads the same bytes as a lowercase one");

    // Garbage is still refused. A scanner that accepted both cases by
    // ignoring the ones it did not recognise would read wherever the
    // truncated number landed and return bytes for it.
    check(server.handle("m" + hex_number(page) + ",zz").payload == "E01",
          "a non-hexadecimal length is still refused");
    check(server.handle("mzzzzzzzzzzzz,10").payload == "E01",
          "a non-hexadecimal address is still refused");
    check(server.handle("m" + hex_number(page) + ",").payload == "E01",
          "an empty length is still refused");

    // A breakpoint packet's address goes through the same scan, and a
    // lowercase-only reader refused the whole packet there too. The address
    // is the stack pointer again: what is under test is whether the digits
    // parsed, and an address that could not be poked would refuse the packet
    // for a second reason.
    const std::string bp_lower =
        server.handle("Z0," + hex_number(page) + ",1").payload;
    const std::string bp_upper =
        server.handle("Z0," + to_upper_hex(page) + ",1").payload;
    check(bp_lower == bp_upper,
          "a breakpoint address parses the same in either case");
    check(server.handle("Z0,ZZZZZZZZZZZZ,1").payload != "OK",
          "a non-hexadecimal breakpoint address is refused");

    // The kill is the cleanup, not part of what is being checked, and a child
    // that outlives the test is a leaked process rather than a failed
    // assertion. The status it would report is discarded deliberately.
    (void)tracer.kill(pid);
}

// ------------------------------------------------------------- damaged packets

void test_a_damaged_packet_does_not_ask_for_a_retransmission() {
    // A packet whose checksum does not match is one we could not read. The
    // protocol's answer is '-' -- send it again -- which is what the pending
    // acknowledgment already says.
    //
    // It is not a request for us to resend our own last packet. That flag
    // means the far end saw a checksum fail on something we sent, and
    // setting it on receipt of a damaged packet makes the session echo its
    // last reply at a debugger that never asked: the debugger sees an answer
    // to a question it did not pose, and the retransmission it does send
    // arrives beside a packet meaning something else. Both directions are
    // then off by one for the rest of the session.
    PacketDecoder d;
    std::string packet = encode_packet("g");
    packet[packet.size() - 1] = (packet[packet.size() - 1] == '0') ? '1' : '0';

    check(d.feed(packet) == 1, "the damaged packet is still framed");
    const Packet p = d.take();
    check(!p.checksum_ok, "the checksum is reported as bad");
    check(d.pending_ack() == '-', "a damaged packet is acknowledged with -");
    check(!d.retransmit_requested(),
          "a damaged packet does not put us in a resend state");

    // A real retransmission request is the other direction and still works,
    // which is what makes the absence above a decision rather than a missing
    // feature.
    PacketDecoder e;
    e.feed("-", 1);
    check(e.retransmit_requested(),
          "a minus from the far end still asks for a retransmission");
}

} // namespace

int main() {
    test_checksum();
    test_empty_payload_is_a_packet();
    test_encode_frames_empty_payload();
    test_single_packet();
    test_split_across_reads();
    test_two_packets_in_one_read();
    test_bad_checksum();
    test_retransmit_request();
    test_acknowledgment();
    test_escaping();
    test_escape_helpers();
    test_split_packet_helper();
    test_hex_round_trip();
    test_hex_number();
    test_hex_bytes();
    test_stop_reply();
    test_decode_store();
    test_decode_load();
    test_decode_without_rex();
    test_decode_byte_form();
    test_decode_displacement();
    test_decode_register_to_register();
    test_decode_non_mov();
    test_decode_rip_relative();
    test_decode_truncated();
    test_hardware_slots_probe();
    test_watch_alignment();
    test_write_watch_width();
    test_wx_chase_prefers_new_mapping();
    test_wx_chase_reports_partial_coverage();
    test_wx_targets_track_a_merged_length();
    test_wx_permission_transition();
    test_listener_binds_loopback();
    test_listener_stays_listening();
    test_listener_accept_times_out();
    test_connection_round_trip();
    test_connection_drops_corrupt_packet();
    test_target_description();
    test_register_block_matches_description();
    test_serve_target_description();
    test_parse_vcont();
    test_event_number_is_in_the_high_byte();
    test_group_stop_is_not_an_event();
    test_vcont_query_lists_the_actions();
    test_vcont_resume_is_answered_with_silence();
    test_vcont_through_the_dispatcher_answers_correctly();
    test_single_register_is_answered_at_its_own_width();
    test_hex_fields_accept_both_cases();
    test_a_damaged_packet_does_not_ask_for_a_retransmission();

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

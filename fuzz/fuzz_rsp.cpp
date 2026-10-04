// Harness: the GDB Remote Serial Protocol codec over arbitrary bytes.
//
// The peer here is a network socket, so this is the second surface where
// untrusted bytes arrive, and it is the one with the most arithmetic: every
// quantity a debugger sends is hexadecimal, in one of two byte orders,
// optionally escaped, and a length that is attacker-controlled.
//
// The decoder's contract is unusual in a way worth stating, because it is
// what the harness asserts. A classic BPF-style framing decoder that
// encounters a truncated packet could either wait for more or report what it
// has. This one resynchronises: a '$' inside a payload restarts framing, and
// a truncated escape is passed through rather than dropped. Neither is
// obvious, and both are places where a decoder that survives can still have
// produced a payload that is wrong -- so the properties below are asserted
// rather than assumed.
//
// The round-trip properties are the core of it. encode_packet followed by
// the decoder must return the payload that was encoded, for every payload
// including the ones containing the three characters that need escaping. A
// codec that fails that has either a framing bug or an escaping bug, and
// both are silent: the failure shows up as a debugger that hangs, not as a
// crash.

#include "occ/observer/rsp.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace {

using occ::obs::PacketDecoder;

// Feeds bytes to a decoder and drains everything that became ready.
//
// The two-call shape is not incidental: feed() appends to an internal queue
// and take() pops from it, and a harness that only fed would never exercise
// the queue's own bookkeeping, which is where an off-by-one would live.
std::size_t round_trip(const std::string& wire, bool& all_ok) noexcept {
    PacketDecoder decoder;
    all_ok = true;

    const std::size_t ready = decoder.feed(wire.data(), wire.size());
    std::size_t taken = 0;
    while (taken < ready) {
        const auto packet = decoder.take();
        // A framed packet with a bad checksum is reported rather than
        // dropped, and its data is empty. Anything else -- a packet that
        // claims to be good but carries nothing -- would mean the queue
        // handed back an entry that was never filled in.
        if (packet.checksum_ok && packet.data.empty()) {
            all_ok = false;
        }
        ++taken;
    }
    // Nothing beyond what feed() reported may be sitting in the queue.
    if (decoder.take().data.size() != 0) {
        all_ok = false;
    }
    return taken;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data,
                                      std::size_t size) noexcept {
    const std::string_view input(reinterpret_cast<const char*>(data), size);

    // 1. Decode whatever the fuzzer produced. This is the path a hostile or
    //    merely broken debugger takes, and it must not read out of bounds
    //    however the framing is malformed.
    {
        bool all_ok = false;
        (void)round_trip(std::string(input), all_ok);
        if (!all_ok) {
            __builtin_trap();
        }
    }

    // 2. The escape helpers in isolation. unescape(escape(x)) == x is the
    //    property they exist to provide, and it holds for every byte value
    //    including NUL, which is why this runs on raw input rather than on
    //    the framed path: a payload is not required to be printable.
    {
        const std::string escaped = occ::obs::escape(input);
        const std::string back = occ::obs::unescape(escaped);
        if (back != input) {
            __builtin_trap();
        }
        // A trailing lone escape is passed through rather than dropped, so
        // escaping an already-escaped string is not the identity and the
        // input is not required to be fixed by the second pass. What must
        // hold is that escaping never loses a byte: the escaped form is at
        // least as long as the input.
        if (escaped.size() < input.size()) {
            __builtin_trap();
        }
    }

    // 3. The hex readers, each against its own width contract.
    //
    //    parse_hex_u64_le wants exactly sixteen digits -- a register is
    //    eight bytes and the wire form is fixed. parse_hex_number wants one
    //    to sixteen and is most significant first. Using one to read the
    //    other is the bug this separation exists to prevent, so the test is
    //    that they disagree where they should.
    {
        std::uint64_t value = 0;
        if (occ::obs::parse_hex_u64_le(input, value)) {
            // Sixteen digits of target-order hex. The high byte and the low
            // byte must be where the encoding puts them, and re-encoding
            // must produce the same sixteen characters -- modulo case, which
            // the reader accepts and the writer does not emit.
            const std::string re = occ::obs::hex_u64_le(value);
            if (re.size() != 16) {
                __builtin_trap();
            }
            std::uint64_t again = 0;
            if (!occ::obs::parse_hex_u64_le(re, again) || again != value) {
                __builtin_trap();
            }
        }

        if (occ::obs::parse_hex_number(input, value)) {
            // The same value the other reader accepted has to come back the
            // same from this one only if the input happened to be a register
            // block. hex_number drops leading zeros, so the round trip is
            // on the value rather than on the string.
            const std::string re = occ::obs::hex_number(value);
            std::uint64_t again = 0;
            if (!occ::obs::parse_hex_number(re, again) || again != value) {
                __builtin_trap();
            }
            // A number never grows past sixteen digits, and never renders
            // empty -- zero is "0", which is the one value that cannot drop
            // a leading digit.
            if (re.empty() || re.size() > 16) {
                __builtin_trap();
            }
        }

        // A register number arriving as a protocol number must survive the
        // distinction: "p0" is one character and parse_hex_u64_le must
        // refuse it, which is the property that stops a narrow index being
        // read as a wide register.
        if (input == "0") {
            std::uint64_t wide = 0;
            if (occ::obs::parse_hex_u64_le(input, wide)) {
                __builtin_trap();
            }
        }
    }

    // 4. The byte reader. An odd-length string is refused rather than
    //    truncated, and what it accepts round-trips through hex_u8.
    {
        std::vector<std::uint8_t> bytes;
        if (occ::obs::parse_hex_bytes(input, bytes)) {
            if (bytes.size() * 2 != input.size()) {
                __builtin_trap();
            }
            std::string re;
            re.reserve(bytes.size() * 2);
            for (const std::uint8_t b : bytes) {
                re += occ::obs::hex_u8(b);
            }
            std::vector<std::uint8_t> again;
            if (!occ::obs::parse_hex_bytes(re, again) || again != bytes) {
                __builtin_trap();
            }
        } else if ((input.size() % 2) != 0) {
            // Refusing an odd length is correct. Refusing an even one is
            // also correct if a character was not hex, so nothing is
            // asserted here beyond the length rule the reader documents.
        }
    }

    // 5. The framing round trip, on a payload the fuzzer chose. This is the
    //    property a debugger depends on: what goes on the wire comes back
    //    unchanged, including when the payload contains '$', '#' or '}'.
    //
    //    An empty payload has no round trip to assert. There is no such
    //    thing as a well-framed empty packet -- its checksum would be the
    //    sum of nothing -- so both halves of this codec refuse to produce
    //    one, and asserting that they do would be asserting the bug.
    if (!input.empty()) {
        const std::string framed = occ::obs::encode_packet(input);
        if (framed.empty()) {
            __builtin_trap();
        }
        PacketDecoder decoder;
        const std::size_t ready =
            decoder.feed(framed.data(), framed.size());
        if (ready == 0) {
            __builtin_trap();
        }
        const auto packet = decoder.take();
        if (!packet.checksum_ok) {
            __builtin_trap();
        }
        if (packet.data != input) {
            __builtin_trap();
        }
        // Nothing beyond what feed() reported may be waiting. An encoder
        // that framed one packet and a decoder that found two would leave
        // the second in the queue for a caller that has already moved on.
        if (decoder.take().data.size() != 0) {
            __builtin_trap();
        }
    } else if (!occ::obs::encode_packet(input).empty()) {
        // The other half of the same rule: an empty payload must produce no
        // frame at all. A "$#00" here would be a packet this project sends
        // and its own decoder rejects.
        __builtin_trap();
    }

    // 6. The split, which decides where a command's arguments begin. A
    //    packet is one command letter and then its arguments, so the split
    //    falls after the first byte -- and not at a ':', because a memory
    //    write is M<addr>,<len>:<bytes> and a ':' inside the arguments
    //    must not move where the boundary is.
    //
    //    The property worth asserting is that the two halves reassemble
    //    into what went in. A split that dropped or reordered a byte would
    //    still satisfy "head is at most one byte long", so the size check
    //    alone is not enough to catch it.
    {
        std::string_view head;
        std::string_view tail;
        occ::obs::split_packet(input, head, tail);
        // Head is the command letter, so at most one byte, and exactly one
        // for any non-empty input.
        if (head.size() > 1) {
            __builtin_trap();
        }
        if (input.empty() ? !head.empty() || !tail.empty()
                          : head.size() != 1) {
            __builtin_trap();
        }
        // Head and tail are views into the input rather than copies, so
        // the reassembly is checked by address as well as by content: a
        // view that pointed at unrelated memory of the same bytes would
        // pass a comparison and fail the caller.
        if (!input.empty() &&
            (head.data() != input.data() || tail.data() != input.data() + 1)) {
            __builtin_trap();
        }
        std::string rebuilt(head);
        rebuilt.append(tail);
        if (rebuilt != input) {
            __builtin_trap();
        }
        // The reason the split is not at the ':'. When a packet carries
        // one, the head is still the first byte and the colon stays in the
        // tail with the arguments it belongs to.
        const std::size_t colon = input.find(':');
        if (colon != std::string_view::npos && colon != 0) {
            if (tail.find(':') == std::string_view::npos) {
                __builtin_trap();
            }
        }
    }

    return 0;
}

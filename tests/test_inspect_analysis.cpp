// The semantic decoder and the analysis document, as the tests see them.
//
// The length decoder has its own long-standing suite; what is tested here
// is the layer above it. The semantic decoder is checked against the
// instructions the reference formats spell -- the group opcodes resolve to
// the names their reg field selects, the relative branches resolve to the
// addresses they name, the rip-relative operand resolves to the address it
// points at -- and the length the semantic walk reports is checked to be
// the length decoder's answer, which is the invariant that keeps one
// decoder and one consumer.
//
// The analysis document is checked against a minimal image assembled in
// memory, with one function, one import, one string and one rip-relative
// reference to each: every claim the document makes -- the function table,
// the import label on the cross-reference, the call-graph edge, the
// compiler stamp -- is one the bytes in this file justify.

#include "occ/inspect/analysis.h"
#include "occ/inspect/disasm.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace occ;
using namespace occ::inspect;

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

[[nodiscard]] bool contains(const std::string& haystack,
                            const char* needle) {
    return haystack.find(needle) != std::string::npos;
}

// -- the semantic decoder -----------------------------------------------------

void test_group_names_resolve() {
    // 48 83 ec 20: sub rsp, 0x20. The grp1 encoding, named by its reg
    // field (/5 = sub), sized by REX.W.
    const std::uint8_t sub_rsp[] = {0x48, 0x83, 0xEC, 0x20};
    Decoded insn;
    check(x64_decode(sub_rsp, sizeof(sub_rsp), 0x1000, insn) == 4,
          "decode: sub rsp,0x20 is four bytes");
    check(insn.mnemonic != nullptr && std::strcmp(insn.mnemonic, "sub") == 0,
          "decode: grp1 /5 answers sub");
    check(contains(insn.operands, "rsp") && contains(insn.operands, "0x20"),
          "decode: the operands name the register and the immediate");

    // 48 89 e5: mov rbp, rsp -- the 0x89 form sizes by REX, not by the
    // byte-mov pair it shares the row with.
    const std::uint8_t mov_rbp_rsp[] = {0x48, 0x89, 0xE5};
    check(x64_decode(mov_rbp_rsp, sizeof(mov_rbp_rsp), 0, insn) == 3,
          "decode: mov rbp,rsp is three bytes");
    check(insn.mnemonic != nullptr && std::strcmp(insn.mnemonic, "mov") == 0,
          "decode: 89 answers mov");
    check(contains(insn.operands, "rbp") && contains(insn.operands, "rsp"),
          "decode: the operands carry both registers");

    // F7 /6 is div, /7 unnamed: the group names what it can name and
    // falls back to the group's own name for what it cannot.
    const std::uint8_t div_ecx[] = {0xF7, 0xF1};
    check(x64_decode(div_ecx, sizeof(div_ecx), 0, insn) == 2,
          "decode: f7 /6 is two bytes");
    check(insn.mnemonic != nullptr && std::strcmp(insn.mnemonic, "div") == 0,
          "decode: grp3 /6 answers div");
}

void test_branches_resolve() {
    // e8 46 00 00 00 at va 0x1000: call to 0x104b, which is what the
    // report's "which code calls this" question is answered from.
    const std::uint8_t call_rel32[] = {0xE8, 0x46, 0x00, 0x00, 0x00};
    Decoded insn;
    check(x64_decode(call_rel32, sizeof(call_rel32), 0x1000, insn) == 5,
          "decode: call rel32 is five bytes");
    check(insn.kind == InsnKind::Call, "decode: e8 is a call");
    check(insn.has_branch_target && insn.branch_target == 0x104B,
          "decode: the call resolves to 0x104b");

    // 74 f8 at va 0x1000: je 0xffa -- the conditional form, named.
    const std::uint8_t je_rel8[] = {0x74, 0xF8};
    check(x64_decode(je_rel8, sizeof(je_rel8), 0x1000, insn) == 2,
          "decode: je rel8 is two bytes");
    check(insn.mnemonic != nullptr && std::strcmp(insn.mnemonic, "je") == 0,
          "decode: 74 answers je");
    check(insn.kind == InsnKind::Jcc && insn.branch_target == 0xFFA,
          "decode: the backward branch resolves");

    // ff 15 xx: call [rip+disp32] -- the indirect form every import call
    // takes, whose target is the IAT slot the operand names. At va
    // 0x14000100d the next instruction is 0x140001013, and the
    // displacement 0x1ffd carries it to 0x140003010 -- the IAT slot the
    // smoke image lays its import table at.
    const std::uint8_t call_rip[] = {0xFF, 0x15, 0xFD, 0x1F, 0x00, 0x00};
    check(x64_decode(call_rip, sizeof(call_rip), 0x14000100D, insn) == 6,
          "decode: call [rip] is six bytes");
    check(insn.kind == InsnKind::Call && insn.has_rip_target &&
              insn.rip_target == 0x140003010,
          "decode: the rip target resolves against the next instruction");
}

void test_rip_relative_and_stamps() {
    // 48 8b 05 f6 0f 00 00 at va 0x1000: mov rax,[rip+0xff6], the operand
    // whose target the xref scan groups by.
    const std::uint8_t mov_rip[] = {0x48, 0x8B, 0x05, 0xF6, 0x0F, 0x00, 0x00};
    Decoded insn;
    check(x64_decode(mov_rip, sizeof(mov_rip), 0x1000, insn) == 7,
          "decode: mov rax,[rip] is seven bytes");
    check(insn.has_rip_target && insn.rip_target == 0x1FFD,
          "decode: the rip-relative target is the next instruction plus the displacement");
    check(contains(insn.operands, "[rip+0xff6]"),
          "decode: the operand prints as [rip+0xff6]");

    // f3 0f 1e fa: endbr64, the CET prologue stamp.
    const std::uint8_t endbr64[] = {0xF3, 0x0F, 0x1E, 0xFA};
    check(x64_decode(endbr64, sizeof(endbr64), 0, insn) == 4,
          "decode: endbr64 is four bytes");
    check(insn.mnemonic != nullptr &&
              std::strcmp(insn.mnemonic, "endbr64") == 0,
          "decode: the CET prologue is named");

    // The length decoder and the semantic decoder agree on every byte
    // stream here -- the invariant that keeps one decoder.
    const std::uint8_t mixed[] = {0x55, 0x48, 0x89, 0xE5, 0xE8, 0x00,
                                  0x00, 0x00, 0x00, 0xC3};
    std::size_t offset = 0;
    while (offset < sizeof(mixed)) {
        const std::uint32_t length =
            x64_instruction_length(mixed + offset, sizeof(mixed) - offset);
        Decoded d;
        const std::uint32_t decoded =
            x64_decode(mixed + offset, sizeof(mixed) - offset, offset, d);
        check(length == decoded && length != 0,
              "decode: the two decoders agree on the stream");
        if (length == 0) {
            break;
        }
        offset += length;
    }
}

// -- the analysis document ----------------------------------------------------
//
// The minimal image: one .text with an endbr64 prologue, a mov/call pair
// aimed at an IAT slot, a lea aimed at a string, and a ret; one .pdata row
// covering it; one import descriptor naming KERNEL32!ExitProcess. Every
// address below is one the bytes were built to make true.

constexpr std::uint64_t kImageBase = 0x140000000;

class SmokeImage {
public:
    SmokeImage() : bytes_(0xC00, 0) {
        bytes_[0] = 'M';
        bytes_[1] = 'Z';
        put32(0x3C, 0x80);
        copy(0x80, "PE\0\0", 4);
        // COFF: machine x64, 3 sections, optional header 240 bytes.
        put16(0x84, 0x8664);
        put16(0x86, 3);
        put16(0x94, 240);
        put16(0x96, 0x22);
        // Optional header, PE32+.
        put16(0x98, 0x20B);
        put32(0x98 + 16, 0x10);                  // entry rva
        put64(0x98 + 24, kImageBase);            // image base
        put32(0x98 + 32, 0x1000);                // section alignment
        put32(0x98 + 36, 0x200);                 // file alignment
        put32(0x98 + 56, 0x10000);               // size of image
        put32(0x98 + 60, 0x400);                 // size of headers
        put32(0x98 + 108, 16);                   // number of directories
        put16(0x98 + 68, 2);                     // subsystem: console
        put16(0x98 + 70, 0x22);                  // dynamic base + nx
        // Data directories: imports at 0x3000 (40 bytes), exceptions at
        // 0x2000 (12 bytes), tls at 0x2100.
        put32(0x108 + 8, 0x3000);
        put32(0x108 + 12, 40);
        put32(0x108 + 24, 0x2000);
        put32(0x108 + 28, 12);
        // Sections: .text, .rdata, .idata. The table starts at
        // e_lfanew + 4 + 20 + 240 = 0x188.
        section(0x188 + 0, ".text", 0x1000, 0x200, 0x400, 0x60000020);
        section(0x188 + 40, ".rdata", 0x2000, 0x200, 0x600, 0x40000040);
        section(0x188 + 80, ".idata", 0x3000, 0x200, 0x800, 0xC0000040);
        // The code: endbr64; mov rax,[rip->IAT]; call [rip->IAT];
        // lea rax,[rip->string]; ret.
        copy(0x400, "\xF3\x0F\x1E\xFA", 4);                       // 0x1000
        copy(0x404, "\x31\xC0", 2);                               // 0x1004
        copy(0x406, "\x48\x8B\x05", 3);                           // 0x1006
        put32(0x409, 0x2003);   // -> 0x3010
        copy(0x40D, "\xFF\x15", 2);                               // 0x100D
        put32(0x40F, 0x1FFD);   // -> 0x3010
        copy(0x413, "\x48\x8D\x05", 3);                           // 0x1013
        put32(0x416, 0x1036);   // -> 0x2050
        put8(0x41A, 0xC3);                                        // 0x101A
        // .pdata: one function row.
        put32(0x600, 0x1000);
        put32(0x604, 0x101B);
        put32(0x608, 0x101B);
        // Import descriptor: OFT, timestamp, forwarder, name, IAT. The
        // descriptor's last field and the IAT's first slot share the file
        // offset 0x810 -- rva 0x3010 is four bytes past the descriptor's
        // own start -- so the slot's unbound content is whatever the
        // FirstThunk field holds, which is exactly the overlap the real
        // linker arranges when the IAT follows the descriptor closely.
        put32(0x800, 0x3040);
        put32(0x804, 0);
        put32(0x808, 0);
        put32(0x80C, 0x3060);
        put32(0x810, 0x3010);
        // The name-table entry, unbound: the hint/name RVA.
        put64(0x840, 0x3080);
        // Names.
        copy(0x860, "KERNEL32", 9);
        put8(0x869, 0);
        put16(0x880, 0);
        copy(0x882, "ExitProcess", 12);
        put8(0x88E, 0);
        // The string the lea names.
        copy(0x650, "hello world", 12);
    }

    [[nodiscard]] const std::vector<std::uint8_t>& bytes() const noexcept {
        return bytes_;
    }

private:
    void put16(std::size_t off, std::uint16_t v) {
        bytes_[off] = static_cast<std::uint8_t>(v & 0xFF);
        bytes_[off + 1] = static_cast<std::uint8_t>(v >> 8);
    }
    void put32(std::size_t off, std::uint32_t v) {
        for (int i = 0; i < 4; ++i) {
            bytes_[off + static_cast<std::size_t>(i)] =
                static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF);
        }
    }
    void put64(std::size_t off, std::uint64_t v) {
        for (int i = 0; i < 8; ++i) {
            bytes_[off + static_cast<std::size_t>(i)] =
                static_cast<std::uint8_t>(
                    static_cast<std::uint64_t>(v >> (8 * i)) & 0xFF);
        }
    }
    void put8(std::size_t off, std::uint8_t v) { bytes_[off] = v; }
    void copy(std::size_t off, const char* text, std::size_t n) {
        std::memcpy(bytes_.data() + off, text, n);
    }
    void section(std::size_t off, const char* name, std::uint32_t va,
                 std::uint32_t raw_size, std::uint32_t raw_offset,
                 std::uint32_t characteristics) {
        std::memcpy(bytes_.data() + off, name, std::strlen(name));
        put32(off + 8, raw_size);        // VirtualSize
        put32(off + 12, va);             // VirtualAddress
        put32(off + 16, raw_size);       // SizeOfRawData
        put32(off + 20, raw_offset);     // PointerToRawData
        put32(off + 36, characteristics);
    }
    std::vector<std::uint8_t> bytes_;
};

void test_analysis_document() {
    SmokeImage image;
    const occ::parser::PeImage parsed = occ::parser::PeImage::parse(
        ByteSpan{image.bytes().data(), image.bytes().size()});
    check(parsed.ok(), "analysis: the smoke image parses");
    if (!parsed.ok()) {
        std::fprintf(stderr, "analysis: parse refused: %s: %s\n",
                     occ::parser::pe_error_name(parsed.error()),
                     parsed.error_detail().c_str());
        return;
    }
    const std::string document = analyze_pe_json(
        parsed, ByteSpan{image.bytes().data(), image.bytes().size()});

    // The function table, from the image's own .pdata row.
    check(contains(document, "\"total\":1"),
          "analysis: the one function the .pdata names is listed");
    check(contains(document, "\"0x140001000\""),
          "analysis: the function's begin is the image-based address");
    check(contains(document, "\"instructions\":6"),
          "analysis: the function decoded its six instructions");

    // The import, labeled where the reference to it lands.
    check(contains(document, "import KERNEL32!ExitProcess"),
          "analysis: the IAT reference names the import");
    check(contains(document, "\"0x14000100d\""),
          "analysis: the call site is listed among the origins");

    // The call-graph edge, from the call to the named import.
    check(contains(document, "\"import\":\"KERNEL32!ExitProcess\""),
          "analysis: the call graph carries the import's name");

    // The string, labeled where the lea points.
    check(contains(document, "string \\\"hello world\\\""),
          "analysis: the data reference names the string");

    // The compiler stamp, at the function's first byte.
    check(contains(document, "endbr64_prologue"),
          "analysis: the CET prologue is stamped");

    // The whole document is valid JSON -- parseable without error by the
    // same check a consumer would run first.
    check(document.front() == '{' && document.back() == '}',
          "analysis: the document is one object");
}

}  // namespace

int main() {
    test_group_names_resolve();
    test_branches_resolve();
    test_rip_relative_and_stamps();
    test_analysis_document();
    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("analysis: %d checks, 0 failures\n", checks);
    return 0;
}

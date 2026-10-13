// Dump-and-rebuild pipeline tests over a synthetic mapped image.
//
// The image here is a mapped-layout PE32+: headers at offset 0, .text at
// its RVA (0x1000) holding a real `call [rip+disp32]` reference to an
// import slot, and a .data section. This is the shape the runtime hands
// the unpack pipeline: the guest has run, the slot holds a real address
// this process handed out (registered through api_hook::note), and the
// only place those bytes exist is this mapping.
//
// The test then checks the three halves of the pipeline against ground
// truth:
//
//   * iat_rebuild::collect names the slot from the registered address --
//     the call site at RVA 0x1000, the slot at 0x1100, named
//     "KERNEL32.dll!FakeApi";
//   * image_dump::dump writes a file whose section table is sane, whose
//     code no longer references the old slot (the displacement was
//     repointed at the rebuilt table), and which carries the appended
//     .occimp and .occregs sections;
//   * unpack merges the analysis and the two repairs into one text that
//     names the slot.

#include "occ/packer/packer.h"

#include "occ/runtime/api_hook.h"
#include "occ/runtime/iat_rebuild.h"
#include "occ/runtime/image_dump.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

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

// ---------------------------------------------------------- pe (mapped)

constexpr std::uint32_t kSecRead = 0x40000000;
constexpr std::uint32_t kSecExec = 0x20000000;
constexpr std::uint32_t kSecCode = 0x00000020;
constexpr std::uint32_t kSecInit = 0x00000040;

constexpr std::uint32_t kPe32PlusMagic = 0x20B;
constexpr std::uint32_t kSectionAlign = 0x1000;
constexpr std::uint32_t kFileAlign = 0x200;
constexpr std::uint32_t kHeadersSize = 0x400;
constexpr std::uint32_t kImageSize = 0x3000;

// The address the slot will hold and that api_hook::note registers.
// Deliberately a host-looking address outside the image, so name_for_address
// resolves it to the registered name.
constexpr std::uint64_t kFakeApiAddress = 0x00007F0012345678ULL;

void wr16(std::vector<std::uint8_t>& b, std::size_t at, std::uint16_t v) {
    b[at] = static_cast<std::uint8_t>(v);
    b[at + 1] = static_cast<std::uint8_t>(v >> 8);
}

void wr32(std::vector<std::uint8_t>& b, std::size_t at, std::uint32_t v) {
    b[at] = static_cast<std::uint8_t>(v);
    b[at + 1] = static_cast<std::uint8_t>(v >> 8);
    b[at + 2] = static_cast<std::uint8_t>(v >> 16);
    b[at + 3] = static_cast<std::uint8_t>(v >> 24);
}

void wr64(std::vector<std::uint8_t>& b, std::size_t at, std::uint64_t v) {
    wr32(b, at, static_cast<std::uint32_t>(v));
    wr32(b, at + 4, static_cast<std::uint32_t>(v >> 32));
}

std::uint16_t rd16(const std::vector<std::uint8_t>& b, std::size_t at) {
    return static_cast<std::uint16_t>(b[at]) |
           static_cast<std::uint16_t>(b[at + 1] << 8);
}

std::uint32_t rd32(const std::vector<std::uint8_t>& b, std::size_t at) {
    return static_cast<std::uint32_t>(b[at]) |
           (static_cast<std::uint32_t>(b[at + 1]) << 8) |
           (static_cast<std::uint32_t>(b[at + 2]) << 16) |
           (static_cast<std::uint32_t>(b[at + 3]) << 24);
}

// Reads a file into a byte vector; false when the file is unreadable.
bool read_file(const std::string& path, std::vector<std::uint8_t>& out) {
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (f == nullptr) {
        return false;
    }
    std::fseek(f, 0, SEEK_END);
    const long end = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (end < 0) {
        std::fclose(f);
        return false;
    }
    out.assign(static_cast<std::size_t>(end), 0);
    const std::size_t got = std::fread(out.data(), 1, out.size(), f);
    std::fclose(f);
    return got == out.size();
}

// A mapped-layout PE with a .text section holding
// `call [rip+0xFA]` (slot at RVA 0x1100) and a .data section.
struct MappedPe {
    std::vector<std::uint8_t> buffer;
    std::uint64_t image_base = 0;
};

[[nodiscard]] MappedPe build_mapped_pe() {
    MappedPe m;
    m.buffer.assign(kImageSize, 0);
    std::vector<std::uint8_t>& out = m.buffer;

    out[0] = 'M';
    out[1] = 'Z';
    wr32(out, 0x3C, 0x40);
    wr32(out, 0x40, 0x00004550);
    wr16(out, 0x44, 0x8664);
    wr16(out, 0x46, 2);  // .text, .data
    wr16(out, 0x54, 0xF0);

    const std::size_t opt = 0x58;
    wr16(out, opt + 0x00, static_cast<std::uint16_t>(kPe32PlusMagic));
    wr32(out, opt + 0x10, 0x1000);  // entry at .text
    wr32(out, opt + 0x20, kSectionAlign);
    wr32(out, opt + 0x24, kFileAlign);
    wr32(out, opt + 0x38, kImageSize);
    wr32(out, opt + 0x3C, kHeadersSize);

    // The code: `FF 15 FA 00 00 00` at RVA 0x1000. The displacement is
    // measured from the end of the instruction (0x1006), so the slot it
    // names sits at RVA 0x1100.
    out[0x1000] = 0xFF;
    out[0x1001] = 0x15;
    out[0x1002] = 0xFA;
    out[0x1003] = 0x00;
    out[0x1004] = 0x00;
    out[0x1005] = 0x00;
    // The slot's value: the address the guest resolved at run time.
    wr64(out, 0x1100, kFakeApiAddress);

    const std::size_t table = opt + 0xF0;
    std::memcpy(out.data() + table, ".text", 6);
    // .text: executable, readable, code+initialized.
    wr32(out, table + 0x08, 0x200);
    wr32(out, table + 0x0C, 0x1000);
    wr32(out, table + 0x10, 0x200);
    wr32(out, table + 0x14, 0x1000);
    wr32(out, table + 0x24, kSecRead | kSecExec | kSecCode | kSecInit);
    std::memcpy(out.data() + table + 40, ".data", 6);
    // .data: readable+initialized.
    wr32(out, table + 40 + 0x08, 0x100);
    wr32(out, table + 40 + 0x0C, 0x2000);
    wr32(out, table + 40 + 0x10, 0x100);
    wr32(out, table + 40 + 0x14, 0x2000);
    wr32(out, table + 40 + 0x24, kSecRead | kSecInit);

    m.image_base = reinterpret_cast<std::uint64_t>(out.data());
    return m;
}

// --------------------------------------------------------------- tests

void test_slot_naming() {
    const MappedPe m = build_mapped_pe();
    // Register the address the slot holds, as the module surface would.
    static_cast<void>(occ::runtime::api_hook::note(
        "KERNEL32.dll", "FakeApi", kFakeApiAddress));

    const std::vector<occ::runtime::iat_rebuild::CallRef> calls =
        occ::runtime::iat_rebuild::collect(m.image_base);
    check(calls.size() == 1, "dump: exactly one call slot recovered");
    if (calls.size() == 1) {
        check(calls[0].site_rva == 0x1000, "dump: call site rva is 0x1000");
        check(calls[0].slot_rva == 0x1100, "dump: slot rva is 0x1100");
        check(calls[0].form == occ::runtime::iat_rebuild::RefForm::Call,
              "dump: reference form is a call");
        check(calls[0].name == "KERNEL32.dll!FakeApi",
              "dump: slot named from the registry");
    }
}

void test_dump_and_unpack() {
    const MappedPe m = build_mapped_pe();
    static_cast<void>(occ::runtime::api_hook::note("KERNEL32.dll", "FakeApi",
                                                   kFakeApiAddress));

    const std::string dump_path = "/tmp/test_packer_dump_out.dll";
    const std::string report_path = "/tmp/test_packer_dump_iat.txt";

    occ::runtime::image_dump::EntryRegs regs;
    regs.rdx = 0x111;
    regs.r12 = 0x222;
    regs.rdi = 0x333;

    const occ::packer::UnpackResult u = occ::packer::unpack(
        m.image_base, dump_path, report_path, &regs);
    check(u.dump_ok, "dump: image_dump::dump succeeded");
    check(u.iat_ok, "dump: iat_rebuild::report succeeded");
    check(u.analysis.valid, "dump: unpack's identify parsed the image");
    check(u.text.find("packer identify") != std::string::npos,
          "dump: merged report carries the analysis");
    check(u.text.find("dump: written") != std::string::npos,
          "dump: merged report carries the dump status");
    check(u.text.find("iat report: written") != std::string::npos,
          "dump: merged report carries the iat status");
    check(u.text.find("FakeApi") != std::string::npos,
          "dump: merged report names the rebuilt slot");

    // The dumped file: a PE whose section table says where each section
    // landed, with the two appended sections.
    std::vector<std::uint8_t> file;
    check(read_file(dump_path, file), "dump: dump file readable");
    if (!file.empty()) {
        check(rd16(file, 0) == 0x5A4D, "dump: file starts with MZ");
        check(rd32(file, 0x3C) == 0x40, "dump: file has e_lfanew");
        check(rd32(file, 0x40) == 0x00004550, "dump: file has the PE signature");
        const std::uint16_t nsec = rd16(file, 0x46);
        check(nsec == 4, "dump: four sections in the dump");
        const std::size_t table = 0x58 + 0xF0;
        bool have_text = false;
        bool have_imp = false;
        bool have_regs = false;
        for (std::uint16_t i = 0; i < nsec; ++i) {
            const std::size_t e = table + static_cast<std::size_t>(i) * 40;
            // The name is an 8-byte field, cut at the first NUL; a section
            // named with all eight bytes (".occregs") has no NUL at all.
            std::string name;
            for (std::size_t k = 0; k < 8; ++k) {
                const char c = static_cast<char>(file[e + k]);
                if (c == '\0') {
                    break;
                }
                name.push_back(c);
            }
            if (name == ".text") {
                have_text = true;
                check(rd32(file, e + 0x08) == 0x200,
                      "dump: .text virtual size preserved");
                check(rd32(file, e + 0x10) == 0x200,
                      "dump: .text raw size rewritten");
                check(rd32(file, e + 0x14) == 0x400,
                      "dump: .text raw pointer is right after the headers");
            }
            if (name == ".occimp") {
                have_imp = true;
            }
            if (name == ".occregs") {
                have_regs = true;
            }
        }
        check(have_text, "dump: .text section present");
        check(have_imp, "dump: rebuilt import section present");
        check(have_regs, "dump: entry-register section present");

        // The code was repointed at the rebuilt table: the displacement at
        // the call site no longer names the old slot, and the slot it now
        // names falls inside the rebuilt .occimp section's range.
        const std::uint32_t disp = rd32(file, 0x400 + 2);
        check(disp != 0xFA, "dump: call displacement was repointed");
        const std::uint32_t target = 0x1000 + 6 + disp;
        check(target >= 0x3000 && target < 0x4000,
              "dump: repointed target lands in the rebuilt section");
    }

    // The IAT report names the slot in MODULE!function form.
    std::vector<std::uint8_t> rep;
    check(read_file(report_path, rep), "dump: iat report file readable");
    if (!rep.empty()) {
        const std::string text(reinterpret_cast<const char*>(rep.data()),
                               rep.size());
        check(text.find("KERNEL32.dll!FakeApi") != std::string::npos,
              "dump: iat report contains MODULE!function");
    }
}

}  // namespace

int main() {
    const auto run = [](const char* name, void (*fn)()) {
        std::printf("-- %s\n", name);
        std::fflush(stdout);
        fn();
    };
    run("slot_naming", test_slot_naming);
    run("dump_and_unpack", test_dump_and_unpack);
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

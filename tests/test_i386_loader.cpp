// The 32-bit interpreter's loader promises, as the tests see it.
//
// The image the test runs is built byte by byte: a minimal 32-bit PE
// whose import table names `ExitProcess` and whose TLS directory declares
// four bytes of raw data, a zero-fill tail, a slot index, and one
// callback. The guest reads its own TLS block through `fs:[0x2C]`, the
// PEB's `BeingDebugged` through `fs:[0x30]`, and exits with the sum --
// so every loader promise the interpreter keeps is one the exit code
// would miss if the promise were broken: the block would not carry the
// raw data, the callback would not have run, and the PEB would not have
// been built.

#include "occ/runtime/i386.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using occ::runtime::i386::Machine;
using occ::runtime::i386::Memory;

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

void put16(std::vector<std::uint8_t>& image, std::size_t at,
           std::uint16_t value) {
    image[at] = static_cast<std::uint8_t>(value);
    image[at + 1] = static_cast<std::uint8_t>(value >> 8);
}

void put32(std::vector<std::uint8_t>& image, std::size_t at,
           std::uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        image[at + static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>(value >> (8 * i));
    }
}

constexpr std::uint32_t kBase = 0x400000;

// The section's raw bytes, at RVA 0x1000. The layout below is the one
// the headers name: code first, then the TLS shapes, then the import
// shapes.
void build_section(std::vector<std::uint8_t>& raw) {
    raw.assign(0x200, 0);
    auto word = [&raw](std::size_t at, std::uint32_t v) {
        put32(raw, at, v);
    };
    // The entry, at RVA 0x1000. The walk: the TEB's TLS pointer array,
    // the block it names, the raw data the block starts with, the zero
    // tail the callback wrote into, the PEB's BeingDebugged, and the
    // exit with the sum.
    std::size_t at = 0;
    const auto emit = [&raw, &at](const std::vector<std::uint8_t>& bytes) {
        for (const std::uint8_t b : bytes) {
            raw[at++] = b;
        }
    };
    emit({0x64, 0xA1, 0x2C, 0x00, 0x00, 0x00});  // mov eax, fs:[0x2C]
    emit({0x8B, 0x00});                          // mov eax, [eax]
    emit({0x8B, 0x08});                          // mov ecx, [eax]
    emit({0x03, 0x48, 0x04});                    // add ecx, [eax+4]
    emit({0x64, 0xA1, 0x30, 0x00, 0x00, 0x00});  // mov eax, fs:[0x30]
    emit({0x80, 0x78, 0x02, 0x00});              // cmp byte [eax+2], 0
    emit({0x75, 0x05});                          // jne past the add
    emit({0x83, 0xC1, 0x01});                    // add ecx, 1
    emit({0x51});                                // push ecx
    emit({0xFF, 0x15, 0x50, 0x10, 0x40, 0x00});  // call [0x401050] (IAT)
    emit({0xF4});                                // hlt, if the call returns
    check(at == 0x24, "the entry code ends at 0x24");
    // The callback, at RVA 0x1030: the block's zero tail grows by 7.
    at = 0x30;
    emit({0x64, 0xA1, 0x2C, 0x00, 0x00, 0x00});  // mov eax, fs:[0x2C]
    emit({0x8B, 0x00});                          // mov eax, [eax]
    emit({0x83, 0x40, 0x04, 0x07});              // add dword [eax+4], 7
    emit({0xC3});                                // ret
    // The TLS shapes.
    word(0x40, 0x2A);              // 0x1040: the raw data
    word(0x44, 0);                 // 0x1044: the slot index, the loader writes
    word(0x48, kBase + 0x1030);    // 0x1048: the callback array
    word(0x4C, 0);                 //        ...terminated by null
    // The import shapes. The descriptor's Name and FirstThunk are RVAs,
    // which is what the PE spec makes them and what the loader's walk
    // reads them as; the IAT thunk names the hint/name entry the same way.
    word(0x50, 0x107C);            // 0x1050: the IAT thunk, hint/name RVA
    word(0x54, 0);                 //        ...terminated by null
    word(0x58, 0);                 // 0x1058: OriginalFirstThunk: none
    word(0x5C, 0);                 //        TimeDateStamp
    word(0x60, 0);                 //        ForwarderChain
    word(0x64, 0x106C);            //        the dll name (an RVA)
    word(0x68, 0x1050);            //        FirstThunk: the IAT (an RVA)
    for (std::size_t i = 0; i < 13; ++i) {  // 0x106C: "kernel32.dll"
        raw[0x6C + i] =
            static_cast<std::uint8_t>(i < 12 ? "kernel32.dll"[i] : 0);
    }
    for (std::size_t i = 0; i < 14; ++i) {  // 0x107C: hint and "ExitProcess\0"
        raw[0x7C + i] = static_cast<std::uint8_t>(
            i < 2 ? 0 : (i < 13 ? "ExitProcess"[i - 2] : 0));
    }
    // The TLS directory itself, at RVA 0x10A0: the five 32-bit fields the
    // 32-bit image's directory carries.
    word(0xA0, kBase + 0x1040);    // StartAddressOfRawData
    word(0xA4, kBase + 0x1044);    // EndAddressOfRawData
    word(0xA8, kBase + 0x1044);    // AddressOfIndex
    word(0xAC, kBase + 0x1048);    // AddressOfCallBacks
    word(0xB0, 4);                 // SizeOfZeroFill
    word(0xB4, 0);                 // Characteristics
}

[[nodiscard]] std::vector<std::uint8_t> build_image() {
    std::vector<std::uint8_t> image(0x200, 0);
    // The DOS header.
    image[0] = 'M';
    image[1] = 'Z';
    put32(image, 0x3C, 0x40);
    // The PE signature.
    image[0x40] = 'P';
    image[0x41] = 'E';
    // The COFF header.
    put16(image, 0x44, 0x014C);  // i386
    put16(image, 0x46, 1);       // one section
    put16(image, 0x54, 0xE0);    // SizeOfOptionalHeader
    put16(image, 0x56, 0x0102);  // executable image, 32-bit
    // The optional header, whose base is 0x58: signature at 0x40, COFF
    // at 0x44, optional at 0x58.
    put16(image, 0x58, 0x010B);         // PE32
    put32(image, 0x58 + 4, 0x200);      // SizeOfCode
    put32(image, 0x58 + 16, 0x1000);    // AddressOfEntryPoint
    put32(image, 0x58 + 20, 0x1000);    // BaseOfCode
    put32(image, 0x58 + 28, kBase);     // ImageBase
    put32(image, 0x58 + 32, 0x1000);    // SectionAlignment
    put32(image, 0x58 + 36, 0x200);     // FileAlignment
    put32(image, 0x58 + 56, 0x2000);    // SizeOfImage
    put32(image, 0x58 + 60, 0x200);     // SizeOfHeaders
    put16(image, 0x58 + 68, 3);         // Subsystem: console
    put32(image, 0x58 + 92, 16);        // NumberOfRvaAndSizes
    // The data directories: import at 1, TLS at 9.
    put32(image, 0x58 + 96 + 8 + 0, 0x1058);   // import RVA
    put32(image, 0x58 + 96 + 8 + 4, 0x28);     // import size
    put32(image, 0x58 + 96 + 72 + 0, 0x10A0);  // TLS RVA
    put32(image, 0x58 + 96 + 72 + 4, 24);      // TLS size
    // The section header, at 0x58 + 0xE0.
    std::memcpy(image.data() + 0x138, ".text\0\0\0", 8);
    put32(image, 0x138 + 8, 0x1000);       // VirtualSize
    put32(image, 0x138 + 12, 0x1000);      // VirtualAddress
    put32(image, 0x138 + 16, 0x200);       // SizeOfRawData
    put32(image, 0x138 + 20, 0x200);       // PointerToRawData
    put32(image, 0x138 + 36, 0x60000020);  // code, execute, read
    // The section itself, at the file offset the header names.
    std::vector<std::uint8_t> section;
    build_section(section);
    image.resize(0x200 + section.size());
    std::memcpy(image.data() + 0x200, section.data(), section.size());
    return image;
}

// The host seam: every import resolves, and the one call the guest makes
// -- ExitProcess -- takes the code from the stack and stops the machine.
bool resolve(void*, const char*, const char*) noexcept {
    return true;
}

bool host_call(void*, const char* dll, const char* name, Machine& m,
               Memory& mem) noexcept {
    if (std::strcmp(dll, "kernel32.dll") == 0 &&
        std::strcmp(name, "ExitProcess") == 0) {
        m.exit_code = mem.read32(m.regs[Machine::kEsp] + 4);
        m.halted = true;
        return true;
    }
    return false;
}

void test_teb_peb_and_tls() {
    const std::vector<std::uint8_t> image = build_image();
    Machine m;
    std::string fault;
    const bool done = occ::runtime::i386::run(
        image.data(), image.size(), "test32.exe", &resolve, nullptr,
        &host_call, nullptr, m, 1000000, &fault);
    check(done, "the run completes");
    if (!done) {
        std::fprintf(stderr, "  fault: %s\n", fault.c_str());
        return;
    }
    // The sum the guest exits with: the raw data the loader copied into
    // the TLS block (0x2A), the 7 the callback wrote into the block's
    // zero-fill, and the 1 the PEB's clear BeingDebugged byte adds. Every
    // loader promise is one the number would miss.
    check(m.exit_code == 0x2A + 7 + 1, "the exit code names every promise");
    check(m.fs_base != 0, "fs names the TEB");
}

}  // namespace

int main() {
    test_teb_peb_and_tls();
    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

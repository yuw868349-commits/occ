// ESP-law unpacker tests: a synthetic UPX-style wrapper.

#include "occ/packer/esp_law.h"

#include <cstdint>
#include <cstdio>
#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace {

int g_fail = 0;
int g_checks = 0;

void check(bool cond, const char* what) {
    ++g_checks;
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        ++g_fail;
    }
}

void put16(std::vector<std::uint8_t>& v, std::size_t at, std::uint16_t x) {
    v[at] = static_cast<std::uint8_t>(x);
    v[at + 1] = static_cast<std::uint8_t>(x >> 8);
}

void put32(std::vector<std::uint8_t>& v, std::size_t at, std::uint32_t x) {
    v[at] = static_cast<std::uint8_t>(x);
    v[at + 1] = static_cast<std::uint8_t>(x >> 8);
    v[at + 2] = static_cast<std::uint8_t>(x >> 16);
    v[at + 3] = static_cast<std::uint8_t>(x >> 24);
}

// Builds a minimal PE32+ with two sections:
//   .upx0  VA 0x1000, VS 0x200, raw at 0x200  -- encrypted code section
//   .upx1  VA 0x2000, VS 0x400, raw at 0x400  -- the wrapper itself
// The wrapper: push rdi/rsi/rdx/rcx/rax, a xor-byte decryption loop
// (rsi -> 0x2200 source, rdi -> 0x1000 target, rcx = 0x100 count), the
// matching pops, and a jmp to 0x1000, the OEP.
std::vector<std::uint8_t> build_shell_pe() {
    std::vector<std::uint8_t> f(0x800, 0);
    // DOS header.
    f[0] = 'M';
    f[1] = 'Z';
    put32(f, 0x3C, 0x40);
    // PE signature + COFF header at 0x40.
    f[0x40] = 'P';
    f[0x41] = 'E';
    put16(f, 0x44, 0x8664);        // machine x64
    put16(f, 0x46, 2);             // sections
    put16(f, 0x54, 0xF0);          // size of optional header
    put16(f, 0x56, 0x22);          // characteristics: EXECUTABLE | LARGE_ADDRESS
    // Optional header at 0x58.
    put16(f, 0x58, 0x20B);         // magic PE32+
    put16(f, 0x5A, 14);            // linker version
    put32(f, 0x5C, 0x400);         // size of code
    put32(f, 0x60, 0x400);         // size of initialized data
    put32(f, 0x68, 0x2000);        // address of entry point (RVA)
    put32(f, 0x78, 0x1000);        // section alignment
    put32(f, 0x7C, 0x200);         // file alignment
    put32(f, 0x90, 0x3000);        // size of image (opt + 56)
    put32(f, 0x94, 0x200);         // size of headers (opt + 60)
    // Section table at 0x58 + 0xF0 = 0x148.
    std::memcpy(&f[0x148], ".upx0", 6);
    put32(f, 0x150, 0x200);        // virtual size
    put32(f, 0x154, 0x1000);       // virtual address
    put32(f, 0x158, 0x200);        // size of raw data
    put32(f, 0x15C, 0x200);        // pointer to raw data
    put32(f, 0x160, 0xE0000020u);  // code|execute|read
    std::memcpy(&f[0x170], ".upx1", 6);
    put32(f, 0x178, 0x400);        // virtual size
    put32(f, 0x17C, 0x2000);       // virtual address
    put32(f, 0x180, 0x400);        // size of raw data
    put32(f, 0x184, 0x400);        // pointer to raw data
    put32(f, 0x188, 0xE0000020u);  // code|execute|read

    // Encrypted section bytes at file 0x200 (RVA 0x1000): plaintext
    // 0xAA repeated, encrypted with xor 0x55 => 0xFF.
    for (std::size_t i = 0; i < 0x200; ++i) {
        f[0x200 + i] = 0xFF;
    }
    // Wrapper at file 0x400 (RVA 0x2000).
    std::size_t w = 0x400;
    const std::uint8_t shell[] = {
        0x50,                          // push rax
        0x51,                          // push rcx
        0x52,                          // push rdx
        0x56,                          // push rsi
        0x57,                          // push rdi
        0x48, 0xC7, 0xC7, 0x00, 0x10, 0x00, 0x00,  // mov rdi, 0x1000
        0x48, 0xC7, 0xC6, 0x00, 0x22, 0x00, 0x00,  // mov rsi, 0x2200
        0x48, 0xC7, 0xC1, 0x00, 0x01, 0x00, 0x00,  // mov rcx, 0x100
        // loop:
        0x8A, 0x06,                    // mov al, [rsi]
        0x34, 0x55,                    // xor al, 0x55
        0x88, 0x07,                    // mov [rdi], al
        0x48, 0xFF, 0xC6,              // inc rsi
        0x48, 0xFF, 0xC7,              // inc rdi
        0x48, 0xFF, 0xC9,              // dec rcx
        0x75, 0xEF,                    // jnz loop  (0x201A)
        0x5F,                          // pop rdi
        0x5E,                          // pop rsi
        0x5A,                          // pop rdx
        0x59,                          // pop rcx
        0x58,                          // pop rax
        0xE9, 0xCB, 0xEF, 0xFF, 0xFF,  // jmp 0x1000
    };
    std::memcpy(&f[w], shell, sizeof(shell));
    // Cipher text for the loop at RVA 0x2200 (file 0x600).
    for (std::size_t i = 0; i < 0x100; ++i) {
        f[0x600 + i] = 0xFF;  // encrypted: plaintext 0xAA ^ 0x55
    }
    return f;
}

}  // namespace

int main() {
    const std::vector<std::uint8_t> pe = build_shell_pe();
    const occ::packer::esp_law::EspLawResult r =
        occ::packer::esp_law::analyze(pe.data(), pe.size());

    check(r.ok, "esp_law: run succeeded");
    check(r.oep_rva == 0x1000,
          "esp_law: OEP detected at 0x1000");
    check(r.reason.find("balanced-stack transfer") != std::string::npos,
          "esp_law: reason names the balanced-stack transfer");
    check(r.steps > 20, "esp_law: executed the decryption loop");
    check(r.smc.size() == 0x100,
          "esp_law: one SMC write event per decrypted byte");
    check(r.writes == r.smc.size(),
          "esp_law: write count matches the SMC stream");
    check(r.api_calls.empty(),
          "esp_law: no out-of-image calls in this wrapper");

    // The decrypted image must carry plaintext 0xAA over the 0x100
    // bytes the loop decrypted (the rest of the section stays as the
    // wrapper left it).
    if (r.image.size() >= 0x400) {
        bool decrypted = true;
        for (std::size_t i = 0; i < 0x100; ++i) {
            if (r.image[0x200 + i] != 0xAA) {
                decrypted = false;
                break;
            }
        }
        check(decrypted, "esp_law: section decrypted in the output image");
        // The second half of the section was never touched by the loop.
        bool untouched = true;
        for (std::size_t i = 0x100; i < 0x200; ++i) {
            if (r.image[0x200 + i] != 0xFF) {
                untouched = false;
                break;
            }
        }
        check(untouched, "esp_law: untouched section bytes preserved");
    } else {
        check(false, "esp_law: output image has the expected size");
    }

    // A truncated file must be refused, not read past.
    const occ::packer::esp_law::EspLawResult bad =
        occ::packer::esp_law::analyze(pe.data(), 0x100);
    check(!bad.ok && !bad.error.empty(),
          "esp_law: truncated image refused with an error");

    // Step cap: a wrapper that never balances must stop at the cap.
    {
        std::vector<std::uint8_t> pe2 = pe;
        // Overwrite the pops with nop so the stack never balances and
        // the transfer never happens: entry pushes, loop, then nops.
        pe2[0x400 + 0x2B] = 0x90;
        pe2[0x400 + 0x2C] = 0x90;
        pe2[0x400 + 0x2D] = 0x90;
        pe2[0x400 + 0x2E] = 0x90;
        pe2[0x400 + 0x2F] = 0x90;
        // jmp OEP -> jmp to self (infinite, cap stops it)
        pe2[0x400 + 0x30] = 0xEB;
        pe2[0x400 + 0x31] = 0xFE;
        pe2[0x400 + 0x32] = 0x90;
        const occ::packer::esp_law::EspLawResult c =
            occ::packer::esp_law::analyze(pe2.data(), pe2.size(), 5000);
        check(!c.ok, "esp_law: non-balancing wrapper does not report an OEP");
        check(c.steps >= 5000 || c.reason.find("step cap") !=
                                     std::string::npos,
              "esp_law: cap stopping is reported");
    }

    // A wrapper that calls out of the image before decrypting: the call
    // must be stubbed and recorded, and the OEP still found afterwards.
    {
        std::vector<std::uint8_t> pe2 = pe;
        // Insert `call 0x7777` (E8, rel32 = 0x7777 - 0x2005 - 5) after
        // the pushes at 0x2005; then the original movs shift down by 5.
        const std::uint32_t rel = 0x7777u - 0x2005u - 5u;
        std::vector<std::uint8_t> body;
        // Rebuild: pushes, call, movs, loop, pops, jmp. Simplest is to
        // rewrite the whole wrapper at 0x400.
        const std::uint8_t shell2[] = {
            0x50, 0x51, 0x52, 0x56, 0x57,
            0xE8, static_cast<std::uint8_t>(rel),
            static_cast<std::uint8_t>(rel >> 8),
            static_cast<std::uint8_t>(rel >> 16),
            static_cast<std::uint8_t>(rel >> 24),  // call 0x7777 (stub)
            0x48, 0xC7, 0xC7, 0x00, 0x10, 0x00, 0x00,
            0x48, 0xC7, 0xC6, 0x00, 0x22, 0x00, 0x00,
            0x48, 0xC7, 0xC1, 0x00, 0x01, 0x00, 0x00,
            0x8A, 0x06, 0x34, 0x55, 0x88, 0x07,
            0x48, 0xFF, 0xC6, 0x48, 0xFF, 0xC7, 0x48, 0xFF, 0xC9,
            0x75, 0xEF,
            0x5F, 0x5E, 0x5A, 0x59, 0x58,
            // jmp lands at 0x2035 + 5 = 0x203A; rel = 0x1000 - 0x203A.
            0xE9, 0xC6, 0xEF, 0xFF, 0xFF,
        };
        std::fill(pe2.begin() + 0x400, pe2.begin() + 0x600, 0x90);
        std::memcpy(&pe2[0x400], shell2, sizeof(shell2));
        const occ::packer::esp_law::EspLawResult r2 =
            occ::packer::esp_law::analyze(pe2.data(), pe2.size());
        check(r2.ok, "esp_law: api-stub wrapper still unpacks");
        check(r2.oep_rva == 0x1000,
              "esp_law: api-stub wrapper OEP detected");
        check(r2.api_calls.size() == 1,
              "esp_law: out-of-image call recorded once");
        if (!r2.api_calls.empty()) {
            check(r2.api_calls[0].target == 0x7777,
                  "esp_law: stub records the call target");
            check(r2.api_calls[0].ret_rax == 0,
                  "esp_law: stub leaves RAX zero");
        }
        check(r2.smc.size() == 0x100,
              "esp_law: api-stub wrapper decrypted the section");
    }

    // --- the offline composition: identify gates the loop ----------------
    // The gate is a refusal to guess. An image the identifier calls
    // packed gets the loop; an image it calls unpacked is reported with
    // the loop's absence stated, not silently skipped; an image it cannot
    // parse is reported with the parse error and no loop.
    {
        const occ::packer::esp_law::OfflineUnpack u =
            occ::packer::esp_law::offline_unpack(pe.data(), pe.size());
        check(u.analysis.valid, "offline: identification ran");
        check(u.ran, "offline: shell PE is packed, so the loop ran");
        check(u.skip_reason.empty(), "offline: no skip reason when it ran");
        check(u.law.ok, "offline: loop found the OEP");
        check(u.law.oep_rva == 0x1000, "offline: same OEP as the raw loop");
        const std::string text =
            occ::packer::esp_law::offline_report_text(u);
        check(text.find("== packer identify ==") != std::string::npos,
              "offline: text opens with the identification");
        check(text.find("== esp-law ==") != std::string::npos,
              "offline: text carries the loop section");
        check(text.find("OEP at rva 0x1000") != std::string::npos,
              "offline: text names the OEP");
        check(text.find("loop: OEP at rva") != std::string::npos,
              "offline: text says the loop succeeded");
    }

    // --- the gate refuses to run the loop on an unpacked image -----------
    {
        // A plain PE: ordinary section names, ordinary entropy, ordinary
        // imports. identify must call it unpacked, and the composition
        // must not run the loop on it -- a step cap reported as a finding
        // would be a lie about an image that has no wrapper.
        std::vector<std::uint8_t> plain(0x600, 0);
        plain[0] = 'M';
        plain[1] = 'Z';
        put32(plain, 0x3C, 0x40);
        plain[0x40] = 'P';
        plain[0x41] = 'E';
        put16(plain, 0x44, 0x8664);
        put16(plain, 0x46, 1);
        put16(plain, 0x54, 0xF0);
        put16(plain, 0x56, 0x22);
        put16(plain, 0x58, 0x20B);
        put32(plain, 0x68, 0x1000);   // entry rva
        put32(plain, 0x78, 0x1000);
        put32(plain, 0x7C, 0x200);
        put32(plain, 0x90, 0x2000);
        put32(plain, 0x94, 0x200);
        std::memcpy(&plain[0x148], ".text", 6);
        put32(plain, 0x150, 0x400);
        put32(plain, 0x154, 0x1000);
        put32(plain, 0x158, 0x200);
        put32(plain, 0x15C, 0x200);
        put32(plain, 0x160, 0x60000020u);
        // Ordinary code: a short prologue repeated, low entropy, no
        // packer idiom at the entry.
        static const std::uint8_t kCode[] = {0x48, 0x89, 0x5C, 0x24, 0x08,
                                             0x57, 0x48, 0x83, 0xEC, 0x20,
                                             0x90, 0xC3};
        for (std::size_t i = 0; i < 0x200; ++i) {
            plain[0x200 + i] = kCode[i % sizeof(kCode)];
        }

        const occ::packer::esp_law::OfflineUnpack u =
            occ::packer::esp_law::offline_unpack(plain.data(), plain.size());
        check(u.analysis.valid, "offline unpacked: identification ran");
        check(!u.ran, "offline unpacked: loop did not run");
        check(!u.skip_reason.empty(),
              "offline unpacked: skip reason is stated");
        check(u.skip_reason.find("not run") != std::string::npos,
              "offline unpacked: reason says it was not run");
        const std::string text =
            occ::packer::esp_law::offline_report_text(u);
        check(text.find("not run") != std::string::npos,
              "offline unpacked: text states the loop did not run");
    }

    // --- the gate refuses to run the loop on an unparsable image ---------
    {
        const occ::packer::esp_law::OfflineUnpack u =
            occ::packer::esp_law::offline_unpack(pe.data(), 0x100);
        check(!u.analysis.valid, "offline truncated: identification failed");
        check(!u.ran, "offline truncated: loop did not run");
        check(u.skip_reason.find("identification failed") != std::string::npos,
              "offline truncated: reason names the identification failure");
    }

    // --- the file form: a path that cannot be read is a report ----------
    {
        const occ::packer::esp_law::OfflineUnpack u =
            occ::packer::esp_law::offline_unpack_file(
                "/nonexistent/definitely/not/here.exe");
        check(!u.analysis.valid, "offline file: missing file is invalid");
        check(!u.analysis.error.empty(),
              "offline file: error names the failure");
        check(!u.ran, "offline file: loop did not run");
    }

    std::fprintf(stdout, "%d checks, %d failures\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}

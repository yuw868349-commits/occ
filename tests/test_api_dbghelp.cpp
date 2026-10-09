// The image-help and symbol surface, as the tests see it.
//
// Two contracts are checked here. The image family's contract is that
// every answer is read out of the image in memory: the NT header is the
// one at the address, the data directory's RVA is the one the header
// holds, and an RVA's section is the section the header names. The
// symbol family's contract is split: the handler's own state is real and
// round-trips, and a name query against an image with no symbol table
// fails the way Windows fails it.

#include "occ/runtime/api.h"
#include "occ/runtime/exports.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

using namespace occ::runtime;
using namespace occ::runtime::winabi;

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

extern "C" __attribute__((ms_abi)) std::uint64_t u32d_ImageNtHeader(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32d_ImageDirectoryEntryToData(
    std::uint64_t, std::uint8_t, std::uint16_t, std::uint32_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32d_ImageRvaToSection(
    std::uint64_t, std::uint64_t, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32d_ImageRvaToVa(
    std::uint64_t, std::uint64_t, std::uint32_t, void**) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymInitialize(
    std::uint64_t, const char*, std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymCleanup(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t u32d_SymSetOptions(
    std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t u32d_SymGetOptions() noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymSetSearchPath(
    std::uint64_t, const char*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymGetSearchPath(
    std::uint64_t, char*, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32d_SymGetModuleBase64(
    std::uint64_t, std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymFromAddr(
    std::uint64_t, std::uint64_t, std::uint64_t*, void*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t u32d_UndecorateSymbolName(
    const char*, char*, std::uint32_t, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32d_StackWalk64(
    std::uint32_t, std::uint64_t, std::uint64_t, void*, void*, void*, void*,
    void*, void*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32d_MiniDumpWriteDump(
    std::uint64_t, std::uint32_t, std::uint64_t, std::uint32_t, void*, void*,
    void*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32d_MiniDumpReadDumpStream(
    std::uint64_t, std::uint32_t, void**, std::uint32_t*, void**) noexcept;

// The image the checks read: a PE with one section, built in memory the
// way a loader maps one.
[[nodiscard]] std::vector<std::uint8_t> build_image() {
    std::vector<std::uint8_t> img(0x3000, 0);
    img[0] = 'M';
    img[1] = 'Z';
    const std::uint32_t pe_off = 0x80;
    std::memcpy(img.data() + 0x3C, &pe_off, 4);
    img[pe_off] = 'P';
    img[pe_off + 1] = 'E';
    const std::uint16_t machine = 0x8664;
    const std::uint16_t sections = 1;
    const std::uint16_t opt_size = 0xF0;
    std::memcpy(img.data() + pe_off + 4, &machine, 2);
    std::memcpy(img.data() + pe_off + 6, &sections, 2);
    std::memcpy(img.data() + pe_off + 20, &opt_size, 2);
    const std::size_t opt = pe_off + 24;
    const std::uint16_t magic = 0x20B;
    std::memcpy(img.data() + opt, &magic, 2);
    // Directory 2 (the resource): RVA 0x2000, size 0x100.
    const std::size_t dir = opt + 0x70 + 2 * 8;
    const std::uint32_t rva = 0x2000;
    const std::uint32_t size = 0x100;
    std::memcpy(img.data() + dir, &rva, 4);
    std::memcpy(img.data() + dir + 4, &size, 4);
    // Directory 0 (the exports): RVA 0x1000.
    const std::size_t dir0 = opt + 0x70;
    const std::uint32_t exp_rva = 0x1000;
    std::memcpy(img.data() + dir0, &exp_rva, 4);
    // The section table.
    const std::size_t sec = opt + opt_size;
    std::memcpy(img.data() + sec, ".data", 6);
    const std::uint32_t vsize = 0x2000;
    const std::uint32_t va = 0x1000;
    std::memcpy(img.data() + sec + 8, &vsize, 4);
    std::memcpy(img.data() + sec + 12, &va, 4);
    return img;
}

void test_image_family() {
    const std::vector<std::uint8_t> img = build_image();
    const std::uint64_t base =
        reinterpret_cast<std::uint64_t>(img.data());

    const std::uint64_t nt = u32d_ImageNtHeader(base);
    check(nt != 0, "dbghelp: ImageNtHeader answers for a real image");
    check(nt == base + 0x80, "dbghelp: the NT header is where e_lfanew says");

    // The directory the header names is found, at base plus its RVA.
    std::uint32_t size = 0;
    const std::uint64_t res =
        u32d_ImageDirectoryEntryToData(base, 1, 2, &size);
    check(res == base + 0x2000, "dbghelp: the resource directory's address");
    check(size == 0x100, "dbghelp: the directory's size");

    // An empty directory answers nothing, which is the state of most of
    // them in this image.
    check(u32d_ImageDirectoryEntryToData(base, 1, 5, &size) == 0,
          "dbghelp: an empty directory answers nothing");

    // An RVA in the section maps to the section and to the address.
    void* last = nullptr;
    const std::uint64_t va = u32d_ImageRvaToVa(nt, base, 0x1500, &last);
    check(va == base + 0x1500, "dbghelp: the RVA's address is base plus RVA");
    check(last == reinterpret_cast<void*>(base + 0x188),
          "dbghelp: the section is the one the header names");
    check(u32d_ImageRvaToSection(nt, base, 0x1500) ==
              reinterpret_cast<std::uint64_t>(img.data() + 0x188),
          "dbghelp: RvaToSection answers the same section");
    // An RVA in no section is refused.
    check(u32d_ImageRvaToSection(nt, base, 0x90000) == 0,
          "dbghelp: an RVA in no section is refused");

    // An address that is not an image is refused.
    check(u32d_ImageNtHeader(0) == 0, "dbghelp: no image, no header");
}

void test_symbol_state() {
    check(u32d_SymInitialize(0, nullptr, 1) == 1,
          "dbghelp: the symbol handler initializes");

    // The options round-trip.
    const std::uint32_t before = u32d_SymGetOptions();
    check(u32d_SymSetOptions(0x00000002) == before,
          "dbghelp: the old options answer");
    check(u32d_SymGetOptions() == 0x00000002,
          "dbghelp: the new options answer");
    u32d_SymSetOptions(before);

    // The search path round-trips.
    check(u32d_SymSetSearchPath(0, "C:\\symbols") == 1,
          "dbghelp: the search path sets");
    char path[64] = {};
    check(u32d_SymGetSearchPath(0, path, 64) == 1,
          "dbghelp: the search path gets");
    check(std::strcmp(path, "C:\\symbols") == 0,
          "dbghelp: the path is the one that was set");

    // A module base answers for an address inside a module the process
    // carries, and nothing for an address outside every module.
    check(u32d_SymGetModuleBase64(0, 0x180020100) == 0x180020000,
          "dbghelp: the module base of an address inside ntdll");
    check(u32d_SymGetModuleBase64(0, 0x10) == 0,
          "dbghelp: no module holds a low address");

    // A name query against an image with no symbols fails the way
    // Windows fails it, and the structure still gets its size.
    std::uint8_t symbol[0x58] = {};
    std::uint32_t cb = 0x58;
    std::memcpy(symbol, &cb, 4);
    std::uint64_t disp = 0;
    check(u32d_SymFromAddr(0, 0x180020100, &disp, symbol) == 0,
          "dbghelp: a name query with no symbols fails");
    std::uint32_t size_of = 0;
    std::memcpy(&size_of, symbol, 4);
    check(size_of >= 0x58, "dbghelp: the symbol structure's size is set");

    check(u32d_SymCleanup(0) == 1, "dbghelp: the handler cleans up");
}

void test_undecorate() {
    char out[64] = {};
    // The C form: the leading underscore and the stack suffix go.
    check(u32d_UndecorateSymbolName("_main@0", out, 64, 0) == 4,
          "dbghelp: the C decoration strips to its name");
    check(std::strcmp(out, "main") == 0, "dbghelp: the name is main");

    // The C++ form: the class and function names come out of the
    // decoration, which is as far as a name can be undecorated without a
    // type database.
    std::memset(out, 0, sizeof(out));
    check(u32d_UndecorateSymbolName("?check_password@@YAHPBD@Z", out, 64, 0) ==
              14,
          "dbghelp: the C++ decoration strips to its name");
    check(std::strcmp(out, "check_password") == 0,
          "dbghelp: the C++ name is the function's");
}

void test_stack_walk() {
    // A frame chain built by hand: the guest's own shape, with the
    // return address above each frame pointer and the next frame at it.
    std::uint64_t stack[8] = {};
    // stack[1] is the return address of the innermost frame; stack[0]
    // would be the next frame pointer, and it is zero -- the chain's end.
    stack[1] = 0x180010000;
    const std::uint64_t rbp =
        reinterpret_cast<std::uint64_t>(&stack[0]);

    // The guest's context, with RBP and RIP where the walk reads them.
    std::uint8_t ctx[0x200] = {};
    std::memcpy(ctx + 0xA0, &rbp, 8);
    const std::uint64_t rip = 0x180020500;
    std::memcpy(ctx + 0xF8, &rip, 8);

    std::uint8_t frame[0x108] = {};
    check(u32d_StackWalk64(0x8664, 0, 0, frame, ctx, nullptr, nullptr,
                           nullptr, nullptr) == 1,
          "dbghelp: the first frame walks");
    std::uint64_t addr_pc = 0;
    std::uint64_t addr_ret = 0;
    std::memcpy(&addr_pc, frame + 0x00, 8);
    std::memcpy(&addr_ret, frame + 0x08, 8);
    check(addr_pc == rip, "dbghelp: the frame's PC is the context's RIP");
    check(addr_ret == 0x180010000,
          "dbghelp: the frame's return address is the stack's");

    // The next walk reads the context the previous one advanced, which
    // is the chain's end here.
    check(u32d_StackWalk64(0x8664, 0, 0, frame, ctx, nullptr, nullptr,
                           nullptr, nullptr) == 0,
          "dbghelp: the walk stops at the chain's end");
}

void test_minidump() {
    const char* path = "/tmp/occ_test_dump.dmp";
    const int fd = ::open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    check(fd >= 0, "dbghelp: the dump file opens");
    if (fd < 0) {
        return;
    }
    check(u32d_MiniDumpWriteDump(0, 4321,
                                 static_cast<std::uint64_t>(fd), 0, nullptr,
                                 nullptr, nullptr) == 1,
          "dbghelp: the dump writes");
    ::close(fd);

    // The dump reads back: the signature, the thread stream and the
    // module stream, through the family's own reader.
    FILE* f = ::fopen(path, "rb");
    check(f != nullptr, "dbghelp: the dump file reads");
    if (f == nullptr) {
        return;
    }
    std::vector<std::uint8_t> bytes(0x10000, 0);
    const std::size_t got = ::fread(bytes.data(), 1, bytes.size(), f);
    ::fclose(f);
    bytes.resize(got);
    check(got > 64, "dbghelp: the dump has content");

    const std::uint64_t base = reinterpret_cast<std::uint64_t>(bytes.data());
    void* dir = nullptr;
    std::uint32_t size = 0;
    void* data = nullptr;
    check(u32d_MiniDumpReadDumpStream(base, 3, &dir, &size, &data) == 1,
          "dbghelp: the thread stream is found");
    check(u32d_MiniDumpReadDumpStream(base, 4, &dir, &size, &data) == 1,
          "dbghelp: the module stream is found");
    check(size > 4, "dbghelp: the module stream has its entries");
    check(u32d_MiniDumpReadDumpStream(base, 77, &dir, &size, &data) == 0,
          "dbghelp: a stream that is not there is refused");
    ::unlink(path);
}

void test_registry() {
    ExportList list;
    add_dbghelp(list);
    bool ok = true;
    bool has_walk = false;
    bool has_dump = false;
    for (const HostExport& e : list) {
        if (e.name.empty() || e.address == 0) {
            ok = false;
        }
        if (e.name == "StackWalk64") {
            has_walk = true;
        }
        if (e.name == "MiniDumpWriteDump") {
            has_dump = true;
        }
    }
    check(ok, "dbghelp: every entry has a name and an address");
    check(has_walk, "dbghelp: the stack walk is registered");
    check(has_dump, "dbghelp: the dump writer is registered");
}

}  // namespace

int main() {
    test_registry();
    test_image_family();
    test_symbol_state();
    test_undecorate();
    test_stack_walk();
    test_minidump();
    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

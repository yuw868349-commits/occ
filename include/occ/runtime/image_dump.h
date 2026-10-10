// Dumping the guest's image back out as a PE file.
//
// This is the first half of unpacking, and it exists because of a fact
// about the runtime that is easy to forget while reading its other code:
// the guest is native, and its image lives in this process's own address
// space. Reading the image is therefore a `memcpy` from an address this
// process holds, not a cross-process read -- there is no `ptrace` here and
// none is needed, which is the same reason the observer cannot see this
// guest and the runtime can.
//
// What gets written is not the file the guest arrived as. A packed image
// keeps its payload encrypted on disk and decrypts it into memory, so the
// bytes that matter exist only in the mapping: the crackme this was
// written against ships a `.data` section whose file bytes are 2 KB of
// padding under a virtual size of 0x3b9b4, and everything that section
// really holds appears only once the program has run. A dump taken after
// the run is the only place those bytes are together in one place.
//
// The written file keeps every RVA where it was and rewrites the file
// layout around them: each section is emitted at its full virtual size,
// file-aligned, and the section table is patched to point at where each
// one landed. Data directories are left alone on purpose -- they name
// RVAs, and no RVA has moved. A tool that maps the file by its section
// table sees the same image the guest saw, which is what makes the result
// worth handing to one.
//
// What this does not do is rebuild the import table. An image that
// resolves its APIs at run time has no import directory to rewrite, and
// one whose IAT was filled in memory has an IAT full of addresses that
// mean nothing in a file. Rebuilding that is the other half of unpacking
// and it is not this file's job.

#ifndef OCC_RUNTIME_IMAGE_DUMP_H_
#define OCC_RUNTIME_IMAGE_DUMP_H_

#include <cstdint>
#include <string>

namespace occ::runtime::image_dump {

// Whether the run asks for a dump, and where it should go. Read from
// `OCC_DUMP_IMAGE`, which -- like the other two switches -- is passed to
// the runner by the command that starts it, because the process that runs
// the guest is not the process that read the environment the user set.
[[nodiscard]] bool enabled() noexcept;
[[nodiscard]] std::string path();

// The entry registers of a packed image, captured at the moment the stub
// hands control to the real entry point.
//
// The real entry point of a packed image is not a plain Windows entry: the
// stub has been running in the image and hands over with a register state
// that only exists at run time -- this run's unpacked layout, this run's
// branch decisions. Windows calls an entry with undefined registers and the
// loader cannot guess what a stub left; only the moment itself knows. The
// OEP trap is that moment, and the dump keeps the state so that a later
// load of the unpacked image can hand the same registers to the same entry
// point and take the same branch.
//
// The order is fixed and the loader's restore reads by offset, so the
// layout is spelled out rather than derived: r12 is last because the
// restore uses r12 as its own pointer and can only take its saved value
// after every other register.
struct EntryRegs {
    std::uint64_t rdx = 0;
    std::uint64_t rcx = 0;
    std::uint64_t r8 = 0;
    std::uint64_t r9 = 0;
    std::uint64_t r10 = 0;
    std::uint64_t r11 = 0;
    std::uint64_t rbx = 0;
    std::uint64_t rbp = 0;
    std::uint64_t rsi = 0;
    std::uint64_t rdi = 0;
    std::uint64_t r13 = 0;
    std::uint64_t r14 = 0;
    std::uint64_t r15 = 0;
    std::uint64_t r12 = 0;
};
static_assert(sizeof(EntryRegs) == 14 * sizeof(std::uint64_t),
              "the loader restores by offset and needs the layout flat");

// Writes the image at `image_base` out as a PE file.
//
// Everything needed is read from the image's own headers rather than from
// the runtime's records, so this works on any mapped PE and does not
// depend on which fields the runtime happened to keep. False means the
// headers did not parse, the file could not be written, or a section's
// bytes were not readable; the reason is printed rather than guessed at.
//
// When `regs` is not null the dump appends a `.occregs` section holding
// the entry register state, and the section is what a later load restores
// from -- see the loader's handling of the same name.
[[nodiscard]] bool dump(std::uint64_t image_base,
                        const std::string& out_path,
                        const EntryRegs* regs = nullptr) noexcept;

}  // namespace occ::runtime::image_dump

#endif  // OCC_RUNTIME_IMAGE_DUMP_H_

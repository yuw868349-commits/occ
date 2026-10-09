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

// Writes the image at `image_base` out as a PE file.
//
// Everything needed is read from the image's own headers rather than from
// the runtime's records, so this works on any mapped PE and does not
// depend on which fields the runtime happened to keep. False means the
// headers did not parse, the file could not be written, or a section's
// bytes were not readable; the reason is printed rather than guessed at.
[[nodiscard]] bool dump(std::uint64_t image_base,
                        const std::string& out_path) noexcept;

}  // namespace occ::runtime::image_dump

#endif  // OCC_RUNTIME_IMAGE_DUMP_H_

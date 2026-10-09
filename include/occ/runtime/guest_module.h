#pragma once

// The API modules, as images the guest can see.
//
// A program does not always call an API through its import table. The ones
// that do not -- shells, protectors, malware, and half the tools written to
// survive either -- find the modules themselves: they walk the PEB's loader
// list for a base address, then read that base the way the loader would,
// DOS header, NT headers, export directory and the three tables behind it.
// What that walk needs is not an answer from an export registry. It needs
// bytes at an address, laid out in the shapes Windows lays them out in.
//
// This file lays those shapes out. For every API module the host implements,
// it places an image in the guest's own address space whose headers parse,
// whose export directory carries the module's real names, and whose function
// table points at trampolines the guest can call -- a `movabs` of the host
// thunk's address into a register and a `jmp` through it, which is the whole
// of the distance between "a pointer the guest holds" and "a call that
// arrives". It then builds the loader list entries the PEB names, hung on
// the three lists in the order Windows hangs them, so a walk that starts at
// `gs:[0x30]` and follows `Ldr` finds every module with its base, its size
// and its names.
//
// The alternative -- answering `GetModuleHandleW` from a table while the
// PEB's list stays empty -- is a runtime that tells the truth through its
// own exports and lies through the structures a hand-rolled walker reads,
// and a walker that reads the lie faults on it. The image is the truth the
// walker can verify: every field it parses is one this code wrote to mean
// what the field means.

#include <cstdint>
#include <string>
#include <vector>

namespace occ::runtime::guest_module {

// One export of one module, as this file needs it: the name a hand-rolled
// walker matches against, the ordinal a by-ordinal import names, and the
// host address the trampoline leads to.
struct Export {
    std::string name;
    std::uint32_t ordinal = 0;
    std::uint64_t address = 0;
};

// One API module to place. The name is spelled as the module declares it;
// the walk matches module names without regard to case, which is the
// caller's problem to normalize, and this file spells what it is told.
struct ModuleInput {
    std::string name;
    std::vector<Export> exports;
};

// What `install` needs. The address space supplies the placements; the PEB
// supplies the loader list's home; the image supplies the first entry, which
// is the one module whose image is real and needs nothing built for it.
struct InstallRequest {
    // Where placements are made and regions are recorded.
    void* space = nullptr;
    void* mapper = nullptr;

    // The PEB the loader list hangs off, already built and mapped.
    std::uint64_t peb = 0;

    // The image: base, size, and the name its loader entry carries.
    std::uint64_t image_base = 0;
    std::uint64_t image_size = 0;
    std::string image_name;

    // The API modules, in the order the loader list should name them. The
    // order matters: a walker that wants the second entry to be `ntdll.dll`
    // -- which is where it is on Windows -- is reading a fact this list
    // decides, and the order below is the one Windows builds.
    std::vector<ModuleInput> modules;
};

// Places the images, builds the loader list, and installs the lookup index
// `module_base` and `proc_address` answer from. Returns false only when a
// placement failed, in which case the PEB's list is left as it was -- an
// empty list is the smaller lie than a list naming images that are not
// there.
bool install(const InstallRequest& request) noexcept;

// The base a module lookup answers with, by the folded (lower-case) module
// name, zero for a module this process has no image of. The image's own
// base answers for its own name, the way `GetModuleHandle(nullptr)` does.
[[nodiscard]] std::uint64_t module_base(std::string_view folded_name) noexcept;

// The address a `GetProcAddress` answers with: the trampoline inside the
// module's image, which the guest calls and which leads to the host thunk.
// Zero for a module the base does not name or a name the module does not
// carry. An ordinal ask passes the ordinal as `name`'s integer value, which
// is what `MAKEINTRESOURCEA` builds.
[[nodiscard]] std::uint64_t proc_address(std::uint64_t module_base,
                                         const char* name) noexcept;

}  // namespace occ::runtime::guest_module

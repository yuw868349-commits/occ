// Naming the addresses a running image calls through.
//
// The other half of unpacking. A packed image resolves its APIs at run
// time and calls them through slots it filled in itself, so the file on
// disk has no import directory worth reading and the dump -- which has the
// bytes but not the meaning -- needs the meaning put back. What this file
// writes is that meaning: for every slot the code reaches through a
// rip-relative indirect call or jump, the name of the function the slot
// holds.
//
// Two facts make this possible and neither is invented here. The first is
// that the slot addresses are in the code: `call qword ptr [rip+disp32]`
// and `jmp qword ptr [rip+disp32]` name their slot in the instruction
// itself, so a scan of the executable sections recovers the set of slots
// without running anything. The second is that the value in a slot is an
// address this process handed out -- the runtime's own export surface --
// so the API hook's registry can turn it back into `MODULE!function`.
//
// The scan is a byte pattern rather than a disassembly pass, and that is a
// deliberate limit: `FF 15` and `FF 25` can also occur inside an immediate
// or a displacement, and those false hits are kept out not by decoding
// around them but by what comes next. A candidate is only reported when
// its computed target lands inside the image and the eight bytes there
// name a registered export. A pattern that survives both is a slot, and a
// coincidence that survives both would have to name a real export at an
// address the code happens to reference -- which is the answer, not a
// coincidence.

#ifndef OCC_RUNTIME_IAT_REBUILD_H_
#define OCC_RUNTIME_IAT_REBUILD_H_

#include <cstdint>
#include <string>
#include <vector>

namespace occ::runtime::iat_rebuild {

// One rip-relative reference the code makes to an import slot.
//
// `site_rva` is where the `call [rip+disp32]` lives, `slot_rva` is the
// slot it names, and `name` is what the registry says the slot's value
// was. A rebuild needs all three: the slots to build the import table
// from, and the sites to repoint at the rebuilt table -- because a rebuilt
// table does not have to keep the guest's own layout, and the code has to
// follow it.
struct CallRef {
    std::uint64_t site_rva = 0;
    std::uint64_t slot_rva = 0;
    std::string name;  // "MODULE!function", as the registry registered it
};

// Scans the image's executable sections and answers every slot the code
// reaches through a rip-relative indirect call or jump, named, with the
// site that reaches it.
//
// This is the whole of the scan; the report and the import rebuild are
// two renderings of the same answer, which is why the scan lives here and
// they do not.
[[nodiscard]] std::vector<CallRef> collect(
    std::uint64_t image_base) noexcept;

// Writes the report to `out_path`. False means the headers did not parse
// or the file could not be written; the reason is printed.
[[nodiscard]] bool report(std::uint64_t image_base,
                          const std::string& out_path) noexcept;

}  // namespace occ::runtime::iat_rebuild

#endif  // OCC_RUNTIME_IAT_REBUILD_H_

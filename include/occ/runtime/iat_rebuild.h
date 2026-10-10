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
// `site_rva` is where the reference lives, `slot_rva` is the slot it
// names, and `name` is what the registry says the slot's value was. A
// rebuild needs all three: the slots to build the import table from, and
// the sites to repoint at the rebuilt table -- because a rebuilt table
// does not have to keep the guest's own layout, and the code has to
// follow it.
//
// The reference forms differ in the byte the displacement starts at and
// the length of the instruction: a `call [rip+disp32]` or `jmp
// [rip+disp32]` is six bytes with the disp at +2, a `mov reg,[rip+disp32]`
// is seven with it at +3. A repoint that did not know which form a site
// was would patch the wrong byte half the time, so the form is part of
// the record.
enum class RefForm {
    Call,  // `call [rip+disp32]` -- the disp at site+2, six bytes
    Jump,  // `jmp  [rip+disp32]` -- the disp at site+2, six bytes
    Mov,   // `mov  reg,[rip+disp32]` -- the disp at site+3, seven bytes
};

struct CallRef {
    std::uint64_t site_rva = 0;
    std::uint64_t slot_rva = 0;
    RefForm form = RefForm::Call;
    std::string name;  // "MODULE!function", as the registry registered it
};

// One rip-relative data reference the code makes to a slot, where the
// slot's value at dump time is one byte out of place.
//
// A packed image exports whole globals the way it exports functions: the
// code loads `mov reg,[rip+disp32]`, the slot names a data address, and
// the dump's copy of that slot sometimes holds the address shifted one
// byte left -- 0x140008040 arrives as 0x14000804000. The fix is the
// reverse shift, and it is only offered when the shifted value lands back
// inside the image; a value that does not is left alone rather than
// guessed at.
struct DataExport {
    std::uint64_t site_rva = 0;  // where the `mov [rip+disp32]` lives
    std::uint64_t slot_rva = 0;  // the slot that names the global
    std::uint64_t fixed = 0;     // the value the slot should hold
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

// Scans the same sections for the `mov reg,[rip+disp32]` form and answers
// the slots whose values are one byte out of place, with the corrected
// value each should hold. The call-slot scan and this one are separate
// passes because they answer different questions: calls name functions and
// the registry names them back, while these name data and the image itself
// holds the answer.
[[nodiscard]] std::vector<DataExport> collect_data_exports(
    std::uint64_t image_base) noexcept;

// Writes the report to `out_path`. False means the headers did not parse
// or the file could not be written; the reason is printed.
[[nodiscard]] bool report(std::uint64_t image_base,
                          const std::string& out_path) noexcept;

}  // namespace occ::runtime::iat_rebuild

#endif  // OCC_RUNTIME_IAT_REBUILD_H_

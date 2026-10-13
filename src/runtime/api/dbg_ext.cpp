// The debugger-side flag a debuggee sets about its own fate: whether the
// debugger's exit should take the debuggee with it.
//
// The flag is real state with a real default -- Windows keeps it set until
// a program clears it, and `DebugActiveProcess` at the other end of the
// session is the thing whose exit the flag governs. This runtime is one
// process, so the flag has no second process to act on at exit; what is
// kept is the fact itself, which is what the call means by "set". The
// alternative -- answering success for a request to clear a flag this
// runtime then forgets -- would make a program that checks the contract
// twice read two different answers.

#include "occ/runtime/api_common.h"
#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cstdint>

namespace occ::runtime::winabi {
namespace {

// The kill-on-exit flag, set by default the way Windows sets it. A program
// that wants its debugger's exit to leave it standing clears it. The flag's
// reader is the debug session at its exit, which this single-process
// runtime never reaches; the storage keeps the fact for that path and for
// any later integration, so it is marked as potentially-unread to keep the
// compiler from treating a state keeper as dead code.
[[maybe_unused]] bool g_kill_on_exit = true;

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t k32dbe_DebugSetProcessKillOnExit(
    std::int32_t flag) noexcept {
    g_kill_on_exit = flag != 0;
    set_last_error(0);
    return 1;
}

void add_kernel32_dbg_ext(ExportList& out) {
    const auto e = [](const char* n, void* fn) {
        HostExport entry;
        entry.name = n;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        return entry;
    };
    out.push_back(e("DebugSetProcessKillOnExit",
                    reinterpret_cast<void*>(&k32dbe_DebugSetProcessKillOnExit)));
}

}  // namespace occ::runtime::winabi

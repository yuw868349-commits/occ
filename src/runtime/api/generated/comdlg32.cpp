// The COMDLG32 surface this runtime did not answer.
//
// One function per export, in the shape every other domain here has: an
// `ms_abi` entry point and a registration function. Every signature below
// is the platform's own, read from the mingw headers by preprocessor, so
// that the argument count and the return type are the ones the guest's
// compiler will call with. A signature guessed here would not be a subtle
// defect: it would be a call whose arguments are read out of the wrong
// registers.
//
// Each entry point states which of two things it is:
//
//   * an implementation, where the behaviour is defined by a format, a
//     structure layout or an arithmetic rule and needs no capability this
//     machine lacks;
//   * a refusal, where the subsystem the call belongs to is not in this
//     runtime -- a window manager, a service database, a device tree. The
//     refusal is `ERROR_CALL_NOT_IMPLEMENTED` through `SetLastError`, which
//     is the answer Windows gives for an entry point whose subsystem is not
//     present, and the comment names the subsystem.
//
// What none of them does is answer success for work that did not happen. A
// guest holding a handle it was never given, or a buffer whose "length" was
// never measured, is in a worse state than one that was told the call is
// unavailable: the first failure lands somewhere else entirely, in code
// that has no reason to suspect what went wrong.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace occ::runtime::winabi {
namespace {

// The code a refusal reports. It is the platform's own -- an entry point
// whose subsystem is absent -- and a guest that handles it is not being
// lied to.
constexpr std::uint32_t kNotImplemented = 120;

extern "C" __attribute__((ms_abi)) std::int32_t kcomdlg32G_ChooseColorA(void* arg0) noexcept {
    // Refused: the common dialogs.
    //
    // the common dialogs are modal windows over a shell namespace; neither the
    // window manager nor the shell namespace exists here
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomdlg32G_ChooseColorW(void* arg0) noexcept {
    // Refused: the common dialogs.
    //
    // the common dialogs are modal windows over a shell namespace; neither the
    // window manager nor the shell namespace exists here
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomdlg32G_ChooseFontA(void* arg0) noexcept {
    // Refused: the common dialogs.
    //
    // the common dialogs are modal windows over a shell namespace; neither the
    // window manager nor the shell namespace exists here
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomdlg32G_ChooseFontW(void* arg0) noexcept {
    // Refused: the common dialogs.
    //
    // the common dialogs are modal windows over a shell namespace; neither the
    // window manager nor the shell namespace exists here
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kcomdlg32G_CommDlgExtendedError() noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcomdlg32G_FindTextA(void* arg0) noexcept {
    // Refused: the common dialogs.
    //
    // the common dialogs are modal windows over a shell namespace; neither the
    // window manager nor the shell namespace exists here
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kcomdlg32G_FindTextW(void* arg0) noexcept {
    // Refused: the common dialogs.
    //
    // the common dialogs are modal windows over a shell namespace; neither the
    // window manager nor the shell namespace exists here
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int16_t kcomdlg32G_GetFileTitleA(const char* arg0, char* arg1, std::uint16_t arg2) noexcept {
    // Refused: the common dialogs.
    //
    // the common dialogs are modal windows over a shell namespace; neither the
    // window manager nor the shell namespace exists here
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int16_t kcomdlg32G_GetFileTitleW(const char16_t* arg0, char16_t* arg1, std::uint16_t arg2) noexcept {
    // Refused: the common dialogs.
    //
    // the common dialogs are modal windows over a shell namespace; neither the
    // window manager nor the shell namespace exists here
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomdlg32G_GetOpenFileNameA(void* arg0) noexcept {
    // Refused: the common dialogs.
    //
    // the common dialogs are modal windows over a shell namespace; neither the
    // window manager nor the shell namespace exists here
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomdlg32G_GetOpenFileNameW(void* arg0) noexcept {
    // Refused: the common dialogs.
    //
    // the common dialogs are modal windows over a shell namespace; neither the
    // window manager nor the shell namespace exists here
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomdlg32G_GetSaveFileNameA(void* arg0) noexcept {
    // Refused: the common dialogs.
    //
    // the common dialogs are modal windows over a shell namespace; neither the
    // window manager nor the shell namespace exists here
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomdlg32G_GetSaveFileNameW(void* arg0) noexcept {
    // Refused: the common dialogs.
    //
    // the common dialogs are modal windows over a shell namespace; neither the
    // window manager nor the shell namespace exists here
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomdlg32G_PageSetupDlgA(void* arg0) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomdlg32G_PageSetupDlgW(void* arg0) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomdlg32G_PrintDlgA(void* arg0) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomdlg32G_PrintDlgW(void* arg0) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcomdlg32G_ReplaceTextA(void* arg0) noexcept {
    // Refused: the common dialogs.
    //
    // the common dialogs are modal windows over a shell namespace; neither the
    // window manager nor the shell namespace exists here
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kcomdlg32G_ReplaceTextW(void* arg0) noexcept {
    // Refused: the common dialogs.
    //
    // the common dialogs are modal windows over a shell namespace; neither the
    // window manager nor the shell namespace exists here
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return nullptr;
}

}  // namespace

void add_generated_comdlg32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("ChooseColorA", reinterpret_cast<void*>(&kcomdlg32G_ChooseColorA));
    e("ChooseColorW", reinterpret_cast<void*>(&kcomdlg32G_ChooseColorW));
    e("ChooseFontA", reinterpret_cast<void*>(&kcomdlg32G_ChooseFontA));
    e("ChooseFontW", reinterpret_cast<void*>(&kcomdlg32G_ChooseFontW));
    e("CommDlgExtendedError", reinterpret_cast<void*>(&kcomdlg32G_CommDlgExtendedError));
    e("FindTextA", reinterpret_cast<void*>(&kcomdlg32G_FindTextA));
    e("FindTextW", reinterpret_cast<void*>(&kcomdlg32G_FindTextW));
    e("GetFileTitleA", reinterpret_cast<void*>(&kcomdlg32G_GetFileTitleA));
    e("GetFileTitleW", reinterpret_cast<void*>(&kcomdlg32G_GetFileTitleW));
    e("GetOpenFileNameA", reinterpret_cast<void*>(&kcomdlg32G_GetOpenFileNameA));
    e("GetOpenFileNameW", reinterpret_cast<void*>(&kcomdlg32G_GetOpenFileNameW));
    e("GetSaveFileNameA", reinterpret_cast<void*>(&kcomdlg32G_GetSaveFileNameA));
    e("GetSaveFileNameW", reinterpret_cast<void*>(&kcomdlg32G_GetSaveFileNameW));
    e("PageSetupDlgA", reinterpret_cast<void*>(&kcomdlg32G_PageSetupDlgA));
    e("PageSetupDlgW", reinterpret_cast<void*>(&kcomdlg32G_PageSetupDlgW));
    e("PrintDlgA", reinterpret_cast<void*>(&kcomdlg32G_PrintDlgA));
    e("PrintDlgW", reinterpret_cast<void*>(&kcomdlg32G_PrintDlgW));
    e("ReplaceTextA", reinterpret_cast<void*>(&kcomdlg32G_ReplaceTextA));
    e("ReplaceTextW", reinterpret_cast<void*>(&kcomdlg32G_ReplaceTextW));
}
}  // namespace occ::runtime::winabi

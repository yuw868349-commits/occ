// The MSACM32 surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmDriverAddA(void* phadid, void* hinstModule, std::int64_t lParam, std::uint32_t dwPriority, std::uint32_t fdwAdd) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(phadid);
    static_cast<void>(hinstModule);
    static_cast<void>(lParam);
    static_cast<void>(dwPriority);
    static_cast<void>(fdwAdd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmDriverAddW(void* phadid, void* hinstModule, std::int64_t lParam, std::uint32_t dwPriority, std::uint32_t fdwAdd) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(phadid);
    static_cast<void>(hinstModule);
    static_cast<void>(lParam);
    static_cast<void>(dwPriority);
    static_cast<void>(fdwAdd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmDriverClose(void* had, std::uint32_t fdwClose) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(had);
    static_cast<void>(fdwClose);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmDriverDetailsA(void* hadid, std::uint64_t padd, std::uint32_t fdwDetails) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(hadid);
    static_cast<void>(padd);
    static_cast<void>(fdwDetails);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmDriverDetailsW(void* hadid, std::uint64_t padd, std::uint32_t fdwDetails) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(hadid);
    static_cast<void>(padd);
    static_cast<void>(fdwDetails);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmDriverEnum(std::uint64_t fnCallback, std::uint64_t dwInstance, std::uint32_t fdwEnum) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(fnCallback);
    static_cast<void>(dwInstance);
    static_cast<void>(fdwEnum);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmDriverID(std::uint64_t hao, void* phadid, std::uint32_t fdwDriverID) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(hao);
    static_cast<void>(phadid);
    static_cast<void>(fdwDriverID);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kmsacm32G_acmDriverMessage(void* had, std::uint32_t uMsg, std::int64_t lParam1, std::int64_t lParam2) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(had);
    static_cast<void>(uMsg);
    static_cast<void>(lParam1);
    static_cast<void>(lParam2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmDriverOpen(void* phad, void* hadid, std::uint32_t fdwOpen) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(phad);
    static_cast<void>(hadid);
    static_cast<void>(fdwOpen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmDriverPriority(void* hadid, std::uint32_t dwPriority, std::uint32_t fdwPriority) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(hadid);
    static_cast<void>(dwPriority);
    static_cast<void>(fdwPriority);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmDriverRemove(void* hadid, std::uint32_t fdwRemove) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(hadid);
    static_cast<void>(fdwRemove);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmFilterChooseA(std::uint64_t pafltrc) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(pafltrc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmFilterChooseW(std::uint64_t pafltrc) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(pafltrc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmFilterDetailsA(void* had, std::uint64_t pafd, std::uint32_t fdwDetails) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(had);
    static_cast<void>(pafd);
    static_cast<void>(fdwDetails);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmFilterDetailsW(void* had, std::uint64_t pafd, std::uint32_t fdwDetails) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(had);
    static_cast<void>(pafd);
    static_cast<void>(fdwDetails);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmFilterEnumA(void* had, std::uint64_t pafd, std::uint64_t fnCallback, std::uint64_t dwInstance, std::uint32_t fdwEnum) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(had);
    static_cast<void>(pafd);
    static_cast<void>(fnCallback);
    static_cast<void>(dwInstance);
    static_cast<void>(fdwEnum);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmFilterEnumW(void* had, std::uint64_t pafd, std::uint64_t fnCallback, std::uint64_t dwInstance, std::uint32_t fdwEnum) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(had);
    static_cast<void>(pafd);
    static_cast<void>(fnCallback);
    static_cast<void>(dwInstance);
    static_cast<void>(fdwEnum);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmFilterTagDetailsA(void* had, std::uint64_t paftd, std::uint32_t fdwDetails) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(had);
    static_cast<void>(paftd);
    static_cast<void>(fdwDetails);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmFilterTagDetailsW(void* had, std::uint64_t paftd, std::uint32_t fdwDetails) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(had);
    static_cast<void>(paftd);
    static_cast<void>(fdwDetails);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmFilterTagEnumA(void* had, std::uint64_t paftd, std::uint64_t fnCallback, std::uint64_t dwInstance, std::uint32_t fdwEnum) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(had);
    static_cast<void>(paftd);
    static_cast<void>(fnCallback);
    static_cast<void>(dwInstance);
    static_cast<void>(fdwEnum);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmFilterTagEnumW(void* had, std::uint64_t paftd, std::uint64_t fnCallback, std::uint64_t dwInstance, std::uint32_t fdwEnum) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(had);
    static_cast<void>(paftd);
    static_cast<void>(fnCallback);
    static_cast<void>(dwInstance);
    static_cast<void>(fdwEnum);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmFormatChooseA(std::uint64_t pafmtc) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(pafmtc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmFormatChooseW(std::uint64_t pafmtc) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(pafmtc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmFormatDetailsA(void* had, std::uint64_t pafd, std::uint32_t fdwDetails) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(had);
    static_cast<void>(pafd);
    static_cast<void>(fdwDetails);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmFormatDetailsW(void* had, std::uint64_t pafd, std::uint32_t fdwDetails) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(had);
    static_cast<void>(pafd);
    static_cast<void>(fdwDetails);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmFormatEnumA(void* had, std::uint64_t pafd, std::uint64_t fnCallback, std::uint64_t dwInstance, std::uint32_t fdwEnum) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(had);
    static_cast<void>(pafd);
    static_cast<void>(fnCallback);
    static_cast<void>(dwInstance);
    static_cast<void>(fdwEnum);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmFormatEnumW(void* had, std::uint64_t pafd, std::uint64_t fnCallback, std::uint64_t dwInstance, std::uint32_t fdwEnum) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(had);
    static_cast<void>(pafd);
    static_cast<void>(fnCallback);
    static_cast<void>(dwInstance);
    static_cast<void>(fdwEnum);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmFormatTagDetailsA(void* had, std::uint64_t paftd, std::uint32_t fdwDetails) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(had);
    static_cast<void>(paftd);
    static_cast<void>(fdwDetails);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmFormatTagDetailsW(void* had, std::uint64_t paftd, std::uint32_t fdwDetails) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(had);
    static_cast<void>(paftd);
    static_cast<void>(fdwDetails);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmFormatTagEnumA(void* had, std::uint64_t paftd, std::uint64_t fnCallback, std::uint64_t dwInstance, std::uint32_t fdwEnum) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(had);
    static_cast<void>(paftd);
    static_cast<void>(fnCallback);
    static_cast<void>(dwInstance);
    static_cast<void>(fdwEnum);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmFormatTagEnumW(void* had, std::uint64_t paftd, std::uint64_t fnCallback, std::uint64_t dwInstance, std::uint32_t fdwEnum) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(had);
    static_cast<void>(paftd);
    static_cast<void>(fnCallback);
    static_cast<void>(dwInstance);
    static_cast<void>(fdwEnum);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmGetVersion() noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmMetrics(std::uint64_t hao, std::uint32_t uMetric, void* pMetric) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(hao);
    static_cast<void>(uMetric);
    static_cast<void>(pMetric);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmStreamConvert(void* has, std::uint64_t pash, std::uint32_t fdwConvert) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(has);
    static_cast<void>(pash);
    static_cast<void>(fdwConvert);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmStreamMessage(void* has, std::uint32_t uMsg, std::int64_t lParam1, std::int64_t lParam2) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(has);
    static_cast<void>(uMsg);
    static_cast<void>(lParam1);
    static_cast<void>(lParam2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmStreamOpen(void* phas, void* had, void* pwfxSrc, void* pwfxDst, std::uint64_t pwfltr, std::uint64_t dwCallback, std::uint64_t dwInstance, std::uint32_t fdwOpen) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(phas);
    static_cast<void>(had);
    static_cast<void>(pwfxSrc);
    static_cast<void>(pwfxDst);
    static_cast<void>(pwfltr);
    static_cast<void>(dwCallback);
    static_cast<void>(dwInstance);
    static_cast<void>(fdwOpen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmStreamPrepareHeader(void* has, std::uint64_t pash, std::uint32_t fdwPrepare) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(has);
    static_cast<void>(pash);
    static_cast<void>(fdwPrepare);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmStreamReset(void* has, std::uint32_t fdwReset) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(has);
    static_cast<void>(fdwReset);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmStreamSize(void* has, std::uint32_t cbInput, std::uint32_t* pdwOutputBytes, std::uint32_t fdwSize) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(has);
    static_cast<void>(cbInput);
    static_cast<void>(pdwOutputBytes);
    static_cast<void>(fdwSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmsacm32G_acmStreamUnprepareHeader(void* has, std::uint64_t pash, std::uint32_t fdwUnprepare) noexcept {
    // Refused: the audio compression manager.
    //
    // an audio codec is a driver; there is no audio device in this runtime for
    // one to attach to
    static_cast<void>(has);
    static_cast<void>(pash);
    static_cast<void>(fdwUnprepare);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_msacm32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("acmDriverAddA", reinterpret_cast<void*>(&kmsacm32G_acmDriverAddA));
    e("acmDriverAddW", reinterpret_cast<void*>(&kmsacm32G_acmDriverAddW));
    e("acmDriverClose", reinterpret_cast<void*>(&kmsacm32G_acmDriverClose));
    e("acmDriverDetailsA", reinterpret_cast<void*>(&kmsacm32G_acmDriverDetailsA));
    e("acmDriverDetailsW", reinterpret_cast<void*>(&kmsacm32G_acmDriverDetailsW));
    e("acmDriverEnum", reinterpret_cast<void*>(&kmsacm32G_acmDriverEnum));
    e("acmDriverID", reinterpret_cast<void*>(&kmsacm32G_acmDriverID));
    e("acmDriverMessage", reinterpret_cast<void*>(&kmsacm32G_acmDriverMessage));
    e("acmDriverOpen", reinterpret_cast<void*>(&kmsacm32G_acmDriverOpen));
    e("acmDriverPriority", reinterpret_cast<void*>(&kmsacm32G_acmDriverPriority));
    e("acmDriverRemove", reinterpret_cast<void*>(&kmsacm32G_acmDriverRemove));
    e("acmFilterChooseA", reinterpret_cast<void*>(&kmsacm32G_acmFilterChooseA));
    e("acmFilterChooseW", reinterpret_cast<void*>(&kmsacm32G_acmFilterChooseW));
    e("acmFilterDetailsA", reinterpret_cast<void*>(&kmsacm32G_acmFilterDetailsA));
    e("acmFilterDetailsW", reinterpret_cast<void*>(&kmsacm32G_acmFilterDetailsW));
    e("acmFilterEnumA", reinterpret_cast<void*>(&kmsacm32G_acmFilterEnumA));
    e("acmFilterEnumW", reinterpret_cast<void*>(&kmsacm32G_acmFilterEnumW));
    e("acmFilterTagDetailsA", reinterpret_cast<void*>(&kmsacm32G_acmFilterTagDetailsA));
    e("acmFilterTagDetailsW", reinterpret_cast<void*>(&kmsacm32G_acmFilterTagDetailsW));
    e("acmFilterTagEnumA", reinterpret_cast<void*>(&kmsacm32G_acmFilterTagEnumA));
    e("acmFilterTagEnumW", reinterpret_cast<void*>(&kmsacm32G_acmFilterTagEnumW));
    e("acmFormatChooseA", reinterpret_cast<void*>(&kmsacm32G_acmFormatChooseA));
    e("acmFormatChooseW", reinterpret_cast<void*>(&kmsacm32G_acmFormatChooseW));
    e("acmFormatDetailsA", reinterpret_cast<void*>(&kmsacm32G_acmFormatDetailsA));
    e("acmFormatDetailsW", reinterpret_cast<void*>(&kmsacm32G_acmFormatDetailsW));
    e("acmFormatEnumA", reinterpret_cast<void*>(&kmsacm32G_acmFormatEnumA));
    e("acmFormatEnumW", reinterpret_cast<void*>(&kmsacm32G_acmFormatEnumW));
    e("acmFormatTagDetailsA", reinterpret_cast<void*>(&kmsacm32G_acmFormatTagDetailsA));
    e("acmFormatTagDetailsW", reinterpret_cast<void*>(&kmsacm32G_acmFormatTagDetailsW));
    e("acmFormatTagEnumA", reinterpret_cast<void*>(&kmsacm32G_acmFormatTagEnumA));
    e("acmFormatTagEnumW", reinterpret_cast<void*>(&kmsacm32G_acmFormatTagEnumW));
    e("acmGetVersion", reinterpret_cast<void*>(&kmsacm32G_acmGetVersion));
    e("acmMetrics", reinterpret_cast<void*>(&kmsacm32G_acmMetrics));
    e("acmStreamConvert", reinterpret_cast<void*>(&kmsacm32G_acmStreamConvert));
    e("acmStreamMessage", reinterpret_cast<void*>(&kmsacm32G_acmStreamMessage));
    e("acmStreamOpen", reinterpret_cast<void*>(&kmsacm32G_acmStreamOpen));
    e("acmStreamPrepareHeader", reinterpret_cast<void*>(&kmsacm32G_acmStreamPrepareHeader));
    e("acmStreamReset", reinterpret_cast<void*>(&kmsacm32G_acmStreamReset));
    e("acmStreamSize", reinterpret_cast<void*>(&kmsacm32G_acmStreamSize));
    e("acmStreamUnprepareHeader", reinterpret_cast<void*>(&kmsacm32G_acmStreamUnprepareHeader));
}
}  // namespace occ::runtime::winabi

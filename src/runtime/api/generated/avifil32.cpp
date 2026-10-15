// The AVIFIL32 surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIBuildFilterA(char* lpszFilter, std::int32_t cbFilter, std::int32_t fSaving) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(lpszFilter);
    static_cast<void>(cbFilter);
    static_cast<void>(fSaving);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIBuildFilterW(char16_t* lpszFilter, std::int32_t cbFilter, std::int32_t fSaving) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(lpszFilter);
    static_cast<void>(cbFilter);
    static_cast<void>(fSaving);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIClearClipboard() noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kavifil32G_AVIFileAddRef(void* pfile) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pfile);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIFileCreateStreamA(void* pfile, void* ppavi, void* psi) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pfile);
    static_cast<void>(ppavi);
    static_cast<void>(psi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIFileCreateStreamW(void* pfile, void* ppavi, void* psi) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pfile);
    static_cast<void>(ppavi);
    static_cast<void>(psi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIFileEndRecord(void* pfile) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pfile);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kavifil32G_AVIFileExit() noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIFileGetStream(void* pfile, void* ppavi, std::uint32_t fccType, std::int32_t lParam) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pfile);
    static_cast<void>(ppavi);
    static_cast<void>(fccType);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIFileInfoA(void* pfile, void* pfi, std::int32_t lSize) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pfile);
    static_cast<void>(pfi);
    static_cast<void>(lSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIFileInfoW(void* pfile, void* pfi, std::int32_t lSize) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pfile);
    static_cast<void>(pfi);
    static_cast<void>(lSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kavifil32G_AVIFileInit() noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIFileOpenA(void* ppfile, const char* szFile, std::uint32_t uMode, void* lpHandler) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(ppfile);
    static_cast<void>(szFile);
    static_cast<void>(uMode);
    static_cast<void>(lpHandler);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIFileOpenW(void* ppfile, const char16_t* szFile, std::uint32_t uMode, void* lpHandler) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(ppfile);
    static_cast<void>(szFile);
    static_cast<void>(uMode);
    static_cast<void>(lpHandler);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIFileReadData(void* pfile, std::uint32_t ckid, void* lpData, std::int32_t* lpcbData) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pfile);
    static_cast<void>(ckid);
    static_cast<void>(lpData);
    static_cast<void>(lpcbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kavifil32G_AVIFileRelease(void* pfile) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pfile);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIFileWriteData(void* pfile, std::uint32_t ckid, void* lpData, std::int32_t cbData) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pfile);
    static_cast<void>(ckid);
    static_cast<void>(lpData);
    static_cast<void>(cbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIGetFromClipboard(void* lppf) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(lppf);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIMakeCompressedStream(void* ppsCompressed, void* ppsSource, void* lpOptions, void* pclsidHandler) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(ppsCompressed);
    static_cast<void>(ppsSource);
    static_cast<void>(lpOptions);
    static_cast<void>(pclsidHandler);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIMakeFileFromStreams(void* ppfile, std::int32_t nStreams, void* papStreams) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(ppfile);
    static_cast<void>(nStreams);
    static_cast<void>(papStreams);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIMakeStreamFromClipboard(std::uint32_t cfFormat, void* hGlobal, void* ppstream) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(cfFormat);
    static_cast<void>(hGlobal);
    static_cast<void>(ppstream);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIPutFileOnClipboard(void* pf) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pf);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVISaveA(const char* szFile, void* pclsidHandler, std::uint64_t lpfnCallback, std::int32_t nStreams, void* pfile, void* lpOptions, ...) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(szFile);
    static_cast<void>(pclsidHandler);
    static_cast<void>(lpfnCallback);
    static_cast<void>(nStreams);
    static_cast<void>(pfile);
    static_cast<void>(lpOptions);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kavifil32G_AVISaveOptions(void* hwnd, std::uint32_t uiFlags, std::int32_t nStreams, void* ppavi, void* plpOptions) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(hwnd);
    static_cast<void>(uiFlags);
    static_cast<void>(nStreams);
    static_cast<void>(ppavi);
    static_cast<void>(plpOptions);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVISaveOptionsFree(std::int32_t nStreams, void* plpOptions) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(nStreams);
    static_cast<void>(plpOptions);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVISaveVA(const char* szFile, void* pclsidHandler, std::uint64_t lpfnCallback, std::int32_t nStreams, void* ppavi, void* plpOptions) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(szFile);
    static_cast<void>(pclsidHandler);
    static_cast<void>(lpfnCallback);
    static_cast<void>(nStreams);
    static_cast<void>(ppavi);
    static_cast<void>(plpOptions);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVISaveVW(const char16_t* szFile, void* pclsidHandler, std::uint64_t lpfnCallback, std::int32_t nStreams, void* ppavi, void* plpOptions) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(szFile);
    static_cast<void>(pclsidHandler);
    static_cast<void>(lpfnCallback);
    static_cast<void>(nStreams);
    static_cast<void>(ppavi);
    static_cast<void>(plpOptions);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVISaveW(const char16_t* szFile, void* pclsidHandler, std::uint64_t lpfnCallback, std::int32_t nStreams, void* pfile, void* lpOptions, ...) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(szFile);
    static_cast<void>(pclsidHandler);
    static_cast<void>(lpfnCallback);
    static_cast<void>(nStreams);
    static_cast<void>(pfile);
    static_cast<void>(lpOptions);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kavifil32G_AVIStreamAddRef(void* pavi) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIStreamBeginStreaming(void* pavi, std::int32_t lStart, std::int32_t lEnd, std::int32_t lRate) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    static_cast<void>(lStart);
    static_cast<void>(lEnd);
    static_cast<void>(lRate);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIStreamCreate(void* ppavi, std::int32_t lParam1, std::int32_t lParam2, void* pclsidHandler) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(ppavi);
    static_cast<void>(lParam1);
    static_cast<void>(lParam2);
    static_cast<void>(pclsidHandler);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIStreamEndStreaming(void* pavi) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIStreamFindSample(void* pavi, std::int32_t lPos, std::int32_t lFlags) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    static_cast<void>(lPos);
    static_cast<void>(lFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kavifil32G_AVIStreamGetFrame(std::uint64_t pg, std::int32_t lPos) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pg);
    static_cast<void>(lPos);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIStreamGetFrameClose(std::uint64_t pg) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pg);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kavifil32G_AVIStreamGetFrameOpen(void* pavi, void* lpbiWanted) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    static_cast<void>(lpbiWanted);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIStreamInfoA(void* pavi, void* psi, std::int32_t lSize) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    static_cast<void>(psi);
    static_cast<void>(lSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIStreamInfoW(void* pavi, void* psi, std::int32_t lSize) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    static_cast<void>(psi);
    static_cast<void>(lSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIStreamLength(void* pavi) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIStreamOpenFromFileA(void* ppavi, const char* szFile, std::uint32_t fccType, std::int32_t lParam, std::uint32_t mode, void* pclsidHandler) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(ppavi);
    static_cast<void>(szFile);
    static_cast<void>(fccType);
    static_cast<void>(lParam);
    static_cast<void>(mode);
    static_cast<void>(pclsidHandler);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIStreamOpenFromFileW(void* ppavi, const char16_t* szFile, std::uint32_t fccType, std::int32_t lParam, std::uint32_t mode, void* pclsidHandler) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(ppavi);
    static_cast<void>(szFile);
    static_cast<void>(fccType);
    static_cast<void>(lParam);
    static_cast<void>(mode);
    static_cast<void>(pclsidHandler);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIStreamRead(void* pavi, std::int32_t lStart, std::int32_t lSamples, void* lpBuffer, std::int32_t cbBuffer, std::int32_t* plBytes, std::int32_t* plSamples) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    static_cast<void>(lStart);
    static_cast<void>(lSamples);
    static_cast<void>(lpBuffer);
    static_cast<void>(cbBuffer);
    static_cast<void>(plBytes);
    static_cast<void>(plSamples);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIStreamReadData(void* pavi, std::uint32_t fcc, void* lp, std::int32_t* lpcb) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    static_cast<void>(fcc);
    static_cast<void>(lp);
    static_cast<void>(lpcb);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIStreamReadFormat(void* pavi, std::int32_t lPos, void* lpFormat, std::int32_t* lpcbFormat) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    static_cast<void>(lPos);
    static_cast<void>(lpFormat);
    static_cast<void>(lpcbFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kavifil32G_AVIStreamRelease(void* pavi) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIStreamSampleToTime(void* pavi, std::int32_t lSample) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    static_cast<void>(lSample);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIStreamSetFormat(void* pavi, std::int32_t lPos, void* lpFormat, std::int32_t cbFormat) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    static_cast<void>(lPos);
    static_cast<void>(lpFormat);
    static_cast<void>(cbFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIStreamStart(void* pavi) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIStreamTimeToSample(void* pavi, std::int32_t lTime) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    static_cast<void>(lTime);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIStreamWrite(void* pavi, std::int32_t lStart, std::int32_t lSamples, void* lpBuffer, std::int32_t cbBuffer, std::uint32_t dwFlags, std::int32_t* plSampWritten, std::int32_t* plBytesWritten) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    static_cast<void>(lStart);
    static_cast<void>(lSamples);
    static_cast<void>(lpBuffer);
    static_cast<void>(cbBuffer);
    static_cast<void>(dwFlags);
    static_cast<void>(plSampWritten);
    static_cast<void>(plBytesWritten);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_AVIStreamWriteData(void* pavi, std::uint32_t fcc, void* lp, std::int32_t cb) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    static_cast<void>(fcc);
    static_cast<void>(lp);
    static_cast<void>(cb);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_CreateEditableStream(void* ppsEditable, void* psSource) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(ppsEditable);
    static_cast<void>(psSource);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_DllCanUnloadNow() noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_DllGetClassObject(const void* rclsid, const void* riid, void** ppv) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(rclsid);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_EditStreamClone(void* pavi, void* ppResult) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    static_cast<void>(ppResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_EditStreamCopy(void* pavi, std::int32_t* plStart, std::int32_t* plLength, void* ppResult) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    static_cast<void>(plStart);
    static_cast<void>(plLength);
    static_cast<void>(ppResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_EditStreamCut(void* pavi, std::int32_t* plStart, std::int32_t* plLength, void* ppResult) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    static_cast<void>(plStart);
    static_cast<void>(plLength);
    static_cast<void>(ppResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_EditStreamPaste(void* pavi, std::int32_t* plPos, std::int32_t* plLength, void* pstream, std::int32_t lStart, std::int32_t lEnd) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    static_cast<void>(plPos);
    static_cast<void>(plLength);
    static_cast<void>(pstream);
    static_cast<void>(lStart);
    static_cast<void>(lEnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_EditStreamSetInfoA(void* pavi, void* lpInfo, std::int32_t cbInfo) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    static_cast<void>(lpInfo);
    static_cast<void>(cbInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_EditStreamSetInfoW(void* pavi, void* lpInfo, std::int32_t cbInfo) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    static_cast<void>(lpInfo);
    static_cast<void>(cbInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_EditStreamSetNameA(void* pavi, const char* lpszName) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    static_cast<void>(lpszName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kavifil32G_EditStreamSetNameW(void* pavi, const char16_t* lpszName) noexcept {
    // Refused: the video-for-windows layer.
    //
    // the AVIFile layer reads through device streams and installed codecs, and
    // this runtime has neither
    static_cast<void>(pavi);
    static_cast<void>(lpszName);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_avifil32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("AVIBuildFilterA", reinterpret_cast<void*>(&kavifil32G_AVIBuildFilterA));
    e("AVIBuildFilterW", reinterpret_cast<void*>(&kavifil32G_AVIBuildFilterW));
    e("AVIClearClipboard", reinterpret_cast<void*>(&kavifil32G_AVIClearClipboard));
    e("AVIFileAddRef", reinterpret_cast<void*>(&kavifil32G_AVIFileAddRef));
    e("AVIFileCreateStreamA", reinterpret_cast<void*>(&kavifil32G_AVIFileCreateStreamA));
    e("AVIFileCreateStreamW", reinterpret_cast<void*>(&kavifil32G_AVIFileCreateStreamW));
    e("AVIFileEndRecord", reinterpret_cast<void*>(&kavifil32G_AVIFileEndRecord));
    e("AVIFileExit", reinterpret_cast<void*>(&kavifil32G_AVIFileExit));
    e("AVIFileGetStream", reinterpret_cast<void*>(&kavifil32G_AVIFileGetStream));
    e("AVIFileInfoA", reinterpret_cast<void*>(&kavifil32G_AVIFileInfoA));
    e("AVIFileInfoW", reinterpret_cast<void*>(&kavifil32G_AVIFileInfoW));
    e("AVIFileInit", reinterpret_cast<void*>(&kavifil32G_AVIFileInit));
    e("AVIFileOpenA", reinterpret_cast<void*>(&kavifil32G_AVIFileOpenA));
    e("AVIFileOpenW", reinterpret_cast<void*>(&kavifil32G_AVIFileOpenW));
    e("AVIFileReadData", reinterpret_cast<void*>(&kavifil32G_AVIFileReadData));
    e("AVIFileRelease", reinterpret_cast<void*>(&kavifil32G_AVIFileRelease));
    e("AVIFileWriteData", reinterpret_cast<void*>(&kavifil32G_AVIFileWriteData));
    e("AVIGetFromClipboard", reinterpret_cast<void*>(&kavifil32G_AVIGetFromClipboard));
    e("AVIMakeCompressedStream", reinterpret_cast<void*>(&kavifil32G_AVIMakeCompressedStream));
    e("AVIMakeFileFromStreams", reinterpret_cast<void*>(&kavifil32G_AVIMakeFileFromStreams));
    e("AVIMakeStreamFromClipboard", reinterpret_cast<void*>(&kavifil32G_AVIMakeStreamFromClipboard));
    e("AVIPutFileOnClipboard", reinterpret_cast<void*>(&kavifil32G_AVIPutFileOnClipboard));
    e("AVISaveA", reinterpret_cast<void*>(&kavifil32G_AVISaveA));
    e("AVISaveOptions", reinterpret_cast<void*>(&kavifil32G_AVISaveOptions));
    e("AVISaveOptionsFree", reinterpret_cast<void*>(&kavifil32G_AVISaveOptionsFree));
    e("AVISaveVA", reinterpret_cast<void*>(&kavifil32G_AVISaveVA));
    e("AVISaveVW", reinterpret_cast<void*>(&kavifil32G_AVISaveVW));
    e("AVISaveW", reinterpret_cast<void*>(&kavifil32G_AVISaveW));
    e("AVIStreamAddRef", reinterpret_cast<void*>(&kavifil32G_AVIStreamAddRef));
    e("AVIStreamBeginStreaming", reinterpret_cast<void*>(&kavifil32G_AVIStreamBeginStreaming));
    e("AVIStreamCreate", reinterpret_cast<void*>(&kavifil32G_AVIStreamCreate));
    e("AVIStreamEndStreaming", reinterpret_cast<void*>(&kavifil32G_AVIStreamEndStreaming));
    e("AVIStreamFindSample", reinterpret_cast<void*>(&kavifil32G_AVIStreamFindSample));
    e("AVIStreamGetFrame", reinterpret_cast<void*>(&kavifil32G_AVIStreamGetFrame));
    e("AVIStreamGetFrameClose", reinterpret_cast<void*>(&kavifil32G_AVIStreamGetFrameClose));
    e("AVIStreamGetFrameOpen", reinterpret_cast<void*>(&kavifil32G_AVIStreamGetFrameOpen));
    e("AVIStreamInfoA", reinterpret_cast<void*>(&kavifil32G_AVIStreamInfoA));
    e("AVIStreamInfoW", reinterpret_cast<void*>(&kavifil32G_AVIStreamInfoW));
    e("AVIStreamLength", reinterpret_cast<void*>(&kavifil32G_AVIStreamLength));
    e("AVIStreamOpenFromFileA", reinterpret_cast<void*>(&kavifil32G_AVIStreamOpenFromFileA));
    e("AVIStreamOpenFromFileW", reinterpret_cast<void*>(&kavifil32G_AVIStreamOpenFromFileW));
    e("AVIStreamRead", reinterpret_cast<void*>(&kavifil32G_AVIStreamRead));
    e("AVIStreamReadData", reinterpret_cast<void*>(&kavifil32G_AVIStreamReadData));
    e("AVIStreamReadFormat", reinterpret_cast<void*>(&kavifil32G_AVIStreamReadFormat));
    e("AVIStreamRelease", reinterpret_cast<void*>(&kavifil32G_AVIStreamRelease));
    e("AVIStreamSampleToTime", reinterpret_cast<void*>(&kavifil32G_AVIStreamSampleToTime));
    e("AVIStreamSetFormat", reinterpret_cast<void*>(&kavifil32G_AVIStreamSetFormat));
    e("AVIStreamStart", reinterpret_cast<void*>(&kavifil32G_AVIStreamStart));
    e("AVIStreamTimeToSample", reinterpret_cast<void*>(&kavifil32G_AVIStreamTimeToSample));
    e("AVIStreamWrite", reinterpret_cast<void*>(&kavifil32G_AVIStreamWrite));
    e("AVIStreamWriteData", reinterpret_cast<void*>(&kavifil32G_AVIStreamWriteData));
    e("CreateEditableStream", reinterpret_cast<void*>(&kavifil32G_CreateEditableStream));
    e("DllCanUnloadNow", reinterpret_cast<void*>(&kavifil32G_DllCanUnloadNow));
    e("DllGetClassObject", reinterpret_cast<void*>(&kavifil32G_DllGetClassObject));
    e("EditStreamClone", reinterpret_cast<void*>(&kavifil32G_EditStreamClone));
    e("EditStreamCopy", reinterpret_cast<void*>(&kavifil32G_EditStreamCopy));
    e("EditStreamCut", reinterpret_cast<void*>(&kavifil32G_EditStreamCut));
    e("EditStreamPaste", reinterpret_cast<void*>(&kavifil32G_EditStreamPaste));
    e("EditStreamSetInfoA", reinterpret_cast<void*>(&kavifil32G_EditStreamSetInfoA));
    e("EditStreamSetInfoW", reinterpret_cast<void*>(&kavifil32G_EditStreamSetInfoW));
    e("EditStreamSetNameA", reinterpret_cast<void*>(&kavifil32G_EditStreamSetNameA));
    e("EditStreamSetNameW", reinterpret_cast<void*>(&kavifil32G_EditStreamSetNameW));
}
}  // namespace occ::runtime::winabi

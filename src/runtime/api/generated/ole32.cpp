// The OLE32 surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::int32_t kole32G_BindMoniker(void* pmk, std::uint32_t grfOpt, const void* iidResult, void** ppvResult) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pmk);
    static_cast<void>(grfOpt);
    static_cast<void>(iidResult);
    static_cast<void>(ppvResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kole32G_CLIPFORMAT_UserFree(std::uint32_t* arg0, std::uint16_t* arg1) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* kole32G_CLIPFORMAT_UserMarshal(std::uint32_t* arg0, std::uint8_t* arg1, std::uint16_t* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kole32G_CLIPFORMAT_UserSize(std::uint32_t* arg0, std::uint32_t arg1, std::uint16_t* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* kole32G_CLIPFORMAT_UserUnmarshal(std::uint32_t* arg0, std::uint8_t* arg1, std::uint16_t* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CLSIDFromProgID(const char16_t* lpszProgID, void* lpclsid) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(lpszProgID);
    static_cast<void>(lpclsid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CLSIDFromProgIDEx(const char16_t* lpszProgID, void* lpclsid) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(lpszProgID);
    static_cast<void>(lpclsid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CLSIDFromString(const char16_t* lpsz, void* pclsid) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(lpsz);
    static_cast<void>(pclsid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kole32G_CoAddRefServerProcess() noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoAllowSetForegroundWindow(void* pUnk, void* lpvReserved) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pUnk);
    static_cast<void>(lpvReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoAllowUnmarshalerCLSID(const void* clsid) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(clsid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kole32G_CoBuildVersion() noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoCancelCall(std::uint32_t dwThreadId, std::uint32_t ulTimeout) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(dwThreadId);
    static_cast<void>(ulTimeout);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoCopyProxy(void* pProxy, void** ppCopy) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pProxy);
    static_cast<void>(ppCopy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoCreateFreeThreadedMarshaler(void* punkOuter, void* ppunkMarshal) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(punkOuter);
    static_cast<void>(ppunkMarshal);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoCreateGuid(void* pguid) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pguid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoCreateInstance(const void* rclsid, void* pUnkOuter, std::uint32_t dwClsContext, const void* riid, void** ppv) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(rclsid);
    static_cast<void>(pUnkOuter);
    static_cast<void>(dwClsContext);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoCreateInstanceEx(const void* Clsid, void* punkOuter, std::uint32_t dwClsCtx, void* pServerInfo, std::uint32_t dwCount, void* pResults) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(Clsid);
    static_cast<void>(punkOuter);
    static_cast<void>(dwClsCtx);
    static_cast<void>(pServerInfo);
    static_cast<void>(dwCount);
    static_cast<void>(pResults);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoCreateInstanceFromApp(const void* Clsid, void* punkOuter, std::uint32_t dwClsCtx, void* reserved, std::uint32_t dwCount, void* pResults) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(Clsid);
    static_cast<void>(punkOuter);
    static_cast<void>(dwClsCtx);
    static_cast<void>(reserved);
    static_cast<void>(dwCount);
    static_cast<void>(pResults);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoDecodeProxy(std::uint32_t dwClientPid, std::uint64_t ui64ProxyAddress, std::uint64_t pServerInformation) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(dwClientPid);
    static_cast<void>(ui64ProxyAddress);
    static_cast<void>(pServerInformation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoDecrementMTAUsage(std::uint64_t Cookie) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(Cookie);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoDisableCallCancellation(void* pReserved) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoDisconnectContext(std::uint32_t dwTimeout) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(dwTimeout);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoDisconnectObject(void* pUnk, std::uint32_t dwReserved) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pUnk);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoDosDateTimeToFileTime(std::uint16_t nDosDate, std::uint16_t nDosTime, std::uint64_t* lpFileTime) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(nDosDate);
    static_cast<void>(nDosTime);
    static_cast<void>(lpFileTime);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoEnableCallCancellation(void* pReserved) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoFileTimeNow(std::uint64_t* lpFileTime) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(lpFileTime);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoFileTimeToDosDateTime(std::uint64_t* lpFileTime, std::uint16_t* lpDosDate, std::uint16_t* lpDosTime) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(lpFileTime);
    static_cast<void>(lpDosDate);
    static_cast<void>(lpDosTime);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kole32G_CoFreeAllLibraries() noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kole32G_CoFreeLibrary(void* hInst) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(hInst);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kole32G_CoFreeUnusedLibraries() noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kole32G_CoFreeUnusedLibrariesEx(std::uint32_t dwUnloadDelay, std::uint32_t dwReserved) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(dwUnloadDelay);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoGetCallContext(const void* riid, void** ppInterface) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(riid);
    static_cast<void>(ppInterface);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoGetCallerTID(std::uint32_t* lpdwTID) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(lpdwTID);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoGetCancelObject(std::uint32_t dwThreadId, const void* iid, void** ppUnk) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(dwThreadId);
    static_cast<void>(iid);
    static_cast<void>(ppUnk);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoGetClassObject(const void* rclsid, std::uint32_t dwClsContext, void* pvReserved, const void* riid, void** ppv) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(rclsid);
    static_cast<void>(dwClsContext);
    static_cast<void>(pvReserved);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoGetContextToken(std::uint64_t* pToken) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pToken);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoGetCurrentLogicalThreadId(void* pguid) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pguid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kole32G_CoGetCurrentProcess() noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoGetDefaultContext(std::uint64_t aptType, const void* riid, void** ppv) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(aptType);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoGetInstanceFromFile(void* pServerInfo, void* pClsid, void* punkOuter, std::uint32_t dwClsCtx, std::uint32_t grfMode, char16_t* pwszName, std::uint32_t dwCount, void* pResults) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pServerInfo);
    static_cast<void>(pClsid);
    static_cast<void>(punkOuter);
    static_cast<void>(dwClsCtx);
    static_cast<void>(grfMode);
    static_cast<void>(pwszName);
    static_cast<void>(dwCount);
    static_cast<void>(pResults);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoGetInstanceFromIStorage(void* pServerInfo, void* pClsid, void* punkOuter, std::uint32_t dwClsCtx, void* pstg, std::uint32_t dwCount, void* pResults) noexcept {
    // Refused: the COM marshalling and storage layer.
    //
    // this call reaches a COM interface by vtable, and the vtable that would
    // answer it belongs to an object nobody here created: COM needs a class
    // registry, an apartment and a marshaller
    static_cast<void>(pServerInfo);
    static_cast<void>(pClsid);
    static_cast<void>(punkOuter);
    static_cast<void>(dwClsCtx);
    static_cast<void>(pstg);
    static_cast<void>(dwCount);
    static_cast<void>(pResults);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kole32G_CoGetInterceptor() noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    //
    // The signature is not in the headers, so this thunk declares no
    // parameters at all. That is safe on this ABI: the caller allocates
    // and releases the shadow space, and a callee that names no
    // parameter reads neither it nor the registers the arguments
    // arrived in. The answer is a zero, which is the answer a refused
    // call already gives.
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kole32G_CoGetInterceptorFromTypeInfo() noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    //
    // The signature is not in the headers, so this thunk declares no
    // parameters at all. That is safe on this ABI: the caller allocates
    // and releases the shadow space, and a callee that names no
    // parameter reads neither it nor the registers the arguments
    // arrived in. The answer is a zero, which is the answer a refused
    // call already gives.
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoGetInterfaceAndReleaseStream(void* pStm, const void* iid, void** ppv) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pStm);
    static_cast<void>(iid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoGetMalloc(std::uint32_t dwMemContext, void* ppMalloc) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(dwMemContext);
    static_cast<void>(ppMalloc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoGetMarshalSizeMax(std::uint32_t* pulSize, const void* riid, void* pUnk, std::uint32_t dwDestContext, void* pvDestContext, std::uint32_t mshlflags) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pulSize);
    static_cast<void>(riid);
    static_cast<void>(pUnk);
    static_cast<void>(dwDestContext);
    static_cast<void>(pvDestContext);
    static_cast<void>(mshlflags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoGetObject(const char16_t* pszName, void* pBindOptions, const void* riid, void** ppv) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pszName);
    static_cast<void>(pBindOptions);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoGetObjectContext(const void* riid, void** ppv) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoGetPSClsid(const void* riid, void* pClsid) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(riid);
    static_cast<void>(pClsid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoGetStandardMarshal(const void* riid, void* pUnk, std::uint32_t dwDestContext, void* pvDestContext, std::uint32_t mshlflags, void* ppMarshal) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(riid);
    static_cast<void>(pUnk);
    static_cast<void>(dwDestContext);
    static_cast<void>(pvDestContext);
    static_cast<void>(mshlflags);
    static_cast<void>(ppMarshal);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoGetStdMarshalEx(void* pUnkOuter, std::uint32_t smexflags, void* ppUnkInner) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pUnkOuter);
    static_cast<void>(smexflags);
    static_cast<void>(ppUnkInner);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoGetSystemSecurityPermissions(std::uint64_t comSDType, void* ppSD) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(comSDType);
    static_cast<void>(ppSD);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoGetTreatAsClass(const void* clsidOld, void* pClsidNew) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(clsidOld);
    static_cast<void>(pClsidNew);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoImpersonateClient() noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoIncrementMTAUsage(void* pCookie) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pCookie);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoInitialize(void* pvReserved) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pvReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoInitializeSecurity(void* pSecDesc, std::int32_t cAuthSvc, void* asAuthSvc, void* pReserved1, std::uint32_t dwAuthnLevel, std::uint32_t dwImpLevel, void* pAuthList, std::uint32_t dwCapabilities, void* pReserved3) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pSecDesc);
    static_cast<void>(cAuthSvc);
    static_cast<void>(asAuthSvc);
    static_cast<void>(pReserved1);
    static_cast<void>(dwAuthnLevel);
    static_cast<void>(dwImpLevel);
    static_cast<void>(pAuthList);
    static_cast<void>(dwCapabilities);
    static_cast<void>(pReserved3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoInstall(void* pbc, std::uint32_t dwFlags, void* pClassSpec, void* pQuery, char16_t* pszCodeBase) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pbc);
    static_cast<void>(dwFlags);
    static_cast<void>(pClassSpec);
    static_cast<void>(pQuery);
    static_cast<void>(pszCodeBase);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoInvalidateRemoteMachineBindings(char16_t* pszMachineName) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pszMachineName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoIsHandlerConnected(void* pUnk) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pUnk);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoIsOle1Class(const void* rclsid) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(rclsid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kole32G_CoLoadLibrary(char16_t* lpszLibName, std::int32_t bAutoFree) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(lpszLibName);
    static_cast<void>(bAutoFree);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoLockObjectExternal(void* pUnk, std::int32_t fLock, std::int32_t fLastUnlockReleases) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pUnk);
    static_cast<void>(fLock);
    static_cast<void>(fLastUnlockReleases);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoMarshalHresult(void* pstm, std::int32_t hresult) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pstm);
    static_cast<void>(hresult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoMarshalInterThreadInterfaceInStream(const void* riid, void* pUnk, void* ppStm) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(riid);
    static_cast<void>(pUnk);
    static_cast<void>(ppStm);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoMarshalInterface(void* pStm, const void* riid, void* pUnk, std::uint32_t dwDestContext, void* pvDestContext, std::uint32_t mshlflags) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pStm);
    static_cast<void>(riid);
    static_cast<void>(pUnk);
    static_cast<void>(dwDestContext);
    static_cast<void>(pvDestContext);
    static_cast<void>(mshlflags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoQueryAuthenticationServices(std::uint32_t* pcAuthSvc, void** asAuthSvc) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(pcAuthSvc);
    static_cast<void>(asAuthSvc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoQueryClientBlanket(std::uint32_t* pAuthnSvc, std::uint32_t* pAuthzSvc, char16_t** pServerPrincName, std::uint32_t* pAuthnLevel, std::uint32_t* pImpLevel, void** pPrivs, std::uint32_t* pCapabilities) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pAuthnSvc);
    static_cast<void>(pAuthzSvc);
    static_cast<void>(pServerPrincName);
    static_cast<void>(pAuthnLevel);
    static_cast<void>(pImpLevel);
    static_cast<void>(pPrivs);
    static_cast<void>(pCapabilities);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoQueryProxyBlanket(void* pProxy, std::uint32_t* pwAuthnSvc, std::uint32_t* pAuthzSvc, char16_t** pServerPrincName, std::uint32_t* pAuthnLevel, std::uint32_t* pImpLevel, void** pAuthInfo, std::uint32_t* pCapabilites) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pProxy);
    static_cast<void>(pwAuthnSvc);
    static_cast<void>(pAuthzSvc);
    static_cast<void>(pServerPrincName);
    static_cast<void>(pAuthnLevel);
    static_cast<void>(pImpLevel);
    static_cast<void>(pAuthInfo);
    static_cast<void>(pCapabilites);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoRegisterChannelHook(const void* ExtensionUuid, void* pChannelHook) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(ExtensionUuid);
    static_cast<void>(pChannelHook);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoRegisterClassObject(const void* rclsid, void* pUnk, std::uint32_t dwClsContext, std::uint32_t flags, std::uint32_t* lpdwRegister) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(rclsid);
    static_cast<void>(pUnk);
    static_cast<void>(dwClsContext);
    static_cast<void>(flags);
    static_cast<void>(lpdwRegister);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoRegisterInitializeSpy(std::uint64_t pSpy, std::uint64_t* puliCookie) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pSpy);
    static_cast<void>(puliCookie);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoRegisterMallocSpy(std::uint64_t pMallocSpy) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pMallocSpy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoRegisterMessageFilter(std::uint64_t lpMessageFilter, void* lplpMessageFilter) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(lpMessageFilter);
    static_cast<void>(lplpMessageFilter);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoRegisterPSClsid(const void* riid, const void* rclsid) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(riid);
    static_cast<void>(rclsid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoRegisterSurrogate(std::uint64_t pSurrogate) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pSurrogate);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoReleaseMarshalData(void* pStm) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pStm);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kole32G_CoReleaseServerProcess() noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoResumeClassObjects() noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoRevertToSelf() noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoRevokeClassObject(std::uint32_t dwRegister) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(dwRegister);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoRevokeInitializeSpy(std::uint64_t uliCookie) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(uliCookie);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoRevokeMallocSpy() noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoSetCancelObject(void* pUnk) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pUnk);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoSetProxyBlanket(void* pProxy, std::uint32_t dwAuthnSvc, std::uint32_t dwAuthzSvc, char16_t* pServerPrincName, std::uint32_t dwAuthnLevel, std::uint32_t dwImpLevel, void* pAuthInfo, std::uint32_t dwCapabilities) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pProxy);
    static_cast<void>(dwAuthnSvc);
    static_cast<void>(dwAuthzSvc);
    static_cast<void>(pServerPrincName);
    static_cast<void>(dwAuthnLevel);
    static_cast<void>(dwImpLevel);
    static_cast<void>(pAuthInfo);
    static_cast<void>(dwCapabilities);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoSuspendClassObjects() noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoSwitchCallContext(void* pNewObject, void** ppOldObject) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pNewObject);
    static_cast<void>(ppOldObject);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kole32G_CoTaskMemAlloc(std::uint64_t cb) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(cb);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void kole32G_CoTaskMemFree(void* pv) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pv);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void* kole32G_CoTaskMemRealloc(void* pv, std::uint64_t cb) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pv);
    static_cast<void>(cb);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoTestCancel() noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoTreatAsClass(const void* clsidOld, const void* clsidNew) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(clsidOld);
    static_cast<void>(clsidNew);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoUnmarshalHresult(void* pstm, std::int32_t* phresult) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pstm);
    static_cast<void>(phresult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoUnmarshalInterface(void* pStm, const void* riid, void** ppv) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pStm);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CoWaitForMultipleObjects(std::uint32_t dwFlags, std::uint32_t dwTimeout, std::uint32_t cHandles, const void* pHandles, std::uint32_t* lpdwindex) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(dwFlags);
    static_cast<void>(dwTimeout);
    static_cast<void>(cHandles);
    static_cast<void>(pHandles);
    static_cast<void>(lpdwindex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CreateAntiMoniker(void** ppmk) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(ppmk);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CreateBindCtx(std::uint32_t reserved, void* ppbc) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(reserved);
    static_cast<void>(ppbc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CreateClassMoniker(const void* rclsid, void** ppmk) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(rclsid);
    static_cast<void>(ppmk);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CreateDataAdviseHolder(void* ppDAHolder) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(ppDAHolder);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CreateDataCache(void* pUnkOuter, const void* rclsid, const void* iid, void** ppv) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pUnkOuter);
    static_cast<void>(rclsid);
    static_cast<void>(iid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CreateErrorInfo(void** pperrinfo) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pperrinfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CreateFileMoniker(const char16_t* lpszPathName, void** ppmk) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(lpszPathName);
    static_cast<void>(ppmk);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CreateGenericComposite(void* pmkFirst, void* pmkRest, void** ppmkComposite) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pmkFirst);
    static_cast<void>(pmkRest);
    static_cast<void>(ppmkComposite);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CreateILockBytesOnHGlobal(void* hGlobal, std::int32_t fDeleteOnRelease, void* pplkbyt) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(hGlobal);
    static_cast<void>(fDeleteOnRelease);
    static_cast<void>(pplkbyt);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CreateItemMoniker(const char16_t* lpszDelim, const char16_t* lpszItem, void** ppmk) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(lpszDelim);
    static_cast<void>(lpszItem);
    static_cast<void>(ppmk);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CreateObjrefMoniker(void* punk, void** ppmk) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(punk);
    static_cast<void>(ppmk);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CreateOleAdviseHolder(void* ppOAHolder) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(ppOAHolder);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CreatePointerMoniker(void* punk, void** ppmk) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(punk);
    static_cast<void>(ppmk);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CreateStdProgressIndicator(void* hwndParent, const char16_t* pszTitle, void* pIbscCaller, void** ppIbsc) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(hwndParent);
    static_cast<void>(pszTitle);
    static_cast<void>(pIbscCaller);
    static_cast<void>(ppIbsc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_CreateStreamOnHGlobal(void* hGlobal, std::int32_t fDeleteOnRelease, void* ppstm) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(hGlobal);
    static_cast<void>(fDeleteOnRelease);
    static_cast<void>(ppstm);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_DcomChannelSetHResult(void* pvReserved, std::uint32_t* pulReserved, std::int32_t appsHR) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pvReserved);
    static_cast<void>(pulReserved);
    static_cast<void>(appsHR);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_DoDragDrop(void* pDataObj, std::uint64_t pDropSource, std::uint32_t dwOKEffects, std::uint32_t* pdwEffect) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pDataObj);
    static_cast<void>(pDropSource);
    static_cast<void>(dwOKEffects);
    static_cast<void>(pdwEffect);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_FmtIdToPropStgName(const void* pfmtid, char16_t* oszName) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pfmtid);
    static_cast<void>(oszName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_FreePropVariantArray(std::uint32_t cVariants, void* rgvars) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(cVariants);
    static_cast<void>(rgvars);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_GetClassFile(const char16_t* szFilename, void* pclsid) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(szFilename);
    static_cast<void>(pclsid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_GetConvertStg(void* pStg) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pStg);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_GetErrorInfo(std::uint32_t dwReserved, void** pperrinfo) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(dwReserved);
    static_cast<void>(pperrinfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_GetHGlobalFromILockBytes(std::uint64_t plkbyt, void* phglobal) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(plkbyt);
    static_cast<void>(phglobal);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_GetHGlobalFromStream(void* pstm, void* phglobal) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pstm);
    static_cast<void>(phglobal);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_GetRunningObjectTable(std::uint32_t reserved, void* pprot) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(reserved);
    static_cast<void>(pprot);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kole32G_HACCEL_UserFree(std::uint32_t* arg0, void* arg1) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* kole32G_HACCEL_UserMarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kole32G_HACCEL_UserSize(std::uint32_t* arg0, std::uint32_t arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* kole32G_HACCEL_UserUnmarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void kole32G_HBITMAP_UserFree(std::uint32_t* arg0, void* arg1) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* kole32G_HBITMAP_UserMarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kole32G_HBITMAP_UserSize(std::uint32_t* arg0, std::uint32_t arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* kole32G_HBITMAP_UserUnmarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void kole32G_HDC_UserFree(std::uint32_t* arg0, void* arg1) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* kole32G_HDC_UserMarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kole32G_HDC_UserSize(std::uint32_t* arg0, std::uint32_t arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* kole32G_HDC_UserUnmarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void kole32G_HGLOBAL_UserFree(std::uint32_t* arg0, void* arg1) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* kole32G_HGLOBAL_UserMarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kole32G_HGLOBAL_UserSize(std::uint32_t* arg0, std::uint32_t arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* kole32G_HGLOBAL_UserUnmarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void kole32G_HICON_UserFree(std::uint32_t* arg0, void* arg1) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* kole32G_HICON_UserMarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kole32G_HICON_UserSize(std::uint32_t* arg0, std::uint32_t arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* kole32G_HICON_UserUnmarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void kole32G_HMENU_UserFree(std::uint32_t* arg0, void* arg1) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* kole32G_HMENU_UserMarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kole32G_HMENU_UserSize(std::uint32_t* arg0, std::uint32_t arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* kole32G_HMENU_UserUnmarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void kole32G_HWND_UserFree(std::uint32_t* arg0, void* arg1) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* kole32G_HWND_UserMarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kole32G_HWND_UserSize(std::uint32_t* arg0, std::uint32_t arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* kole32G_HWND_UserUnmarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_IIDFromString(const char16_t* lpsz, void* lpiid) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(lpsz);
    static_cast<void>(lpiid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_IsAccelerator(void* hAccel, std::int32_t cAccelEntries, void* lpMsg, std::uint16_t* lpwCmd) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(hAccel);
    static_cast<void>(cAccelEntries);
    static_cast<void>(lpMsg);
    static_cast<void>(lpwCmd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_MkParseDisplayName(std::uint64_t pbc, const char16_t* szUserName, std::uint32_t* pchEaten, void** ppmk) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pbc);
    static_cast<void>(szUserName);
    static_cast<void>(pchEaten);
    static_cast<void>(ppmk);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_MonikerCommonPrefixWith(void* pmkThis, void* pmkOther, void** ppmkCommon) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(pmkThis);
    static_cast<void>(pmkOther);
    static_cast<void>(ppmkCommon);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_MonikerRelativePathTo(void* pmkSrc, void* pmkDest, void** ppmkRelPath, std::int32_t dwReserved) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pmkSrc);
    static_cast<void>(pmkDest);
    static_cast<void>(ppmkRelPath);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kole32G_OleBuildVersion() noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleConvertIStorageToOLESTREAM(void* pstg, void* lpolestream) noexcept {
    // Refused: the COM marshalling and storage layer.
    //
    // this call reaches a COM interface by vtable, and the vtable that would
    // answer it belongs to an object nobody here created: COM needs a class
    // registry, an apartment and a marshaller
    static_cast<void>(pstg);
    static_cast<void>(lpolestream);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleConvertIStorageToOLESTREAMEx(void* pstg, std::uint16_t cfFormat, std::int32_t lWidth, std::int32_t lHeight, std::uint32_t dwSize, std::uint64_t pmedium, void* polestm) noexcept {
    // Refused: the COM marshalling and storage layer.
    //
    // this call reaches a COM interface by vtable, and the vtable that would
    // answer it belongs to an object nobody here created: COM needs a class
    // registry, an apartment and a marshaller
    static_cast<void>(pstg);
    static_cast<void>(cfFormat);
    static_cast<void>(lWidth);
    static_cast<void>(lHeight);
    static_cast<void>(dwSize);
    static_cast<void>(pmedium);
    static_cast<void>(polestm);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleConvertOLESTREAMToIStorage(void* lpolestream, void* pstg, const void* ptd) noexcept {
    // Refused: the COM marshalling and storage layer.
    //
    // this call reaches a COM interface by vtable, and the vtable that would
    // answer it belongs to an object nobody here created: COM needs a class
    // registry, an apartment and a marshaller
    static_cast<void>(lpolestream);
    static_cast<void>(pstg);
    static_cast<void>(ptd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleConvertOLESTREAMToIStorageEx(void* polestm, void* pstg, std::uint16_t* pcfFormat, std::int32_t* plwWidth, std::int32_t* plHeight, std::uint32_t* pdwSize, std::uint64_t pmedium) noexcept {
    // Refused: the COM marshalling and storage layer.
    //
    // this call reaches a COM interface by vtable, and the vtable that would
    // answer it belongs to an object nobody here created: COM needs a class
    // registry, an apartment and a marshaller
    static_cast<void>(polestm);
    static_cast<void>(pstg);
    static_cast<void>(pcfFormat);
    static_cast<void>(plwWidth);
    static_cast<void>(plHeight);
    static_cast<void>(pdwSize);
    static_cast<void>(pmedium);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleCreate(const void* rclsid, const void* riid, std::uint32_t renderopt, void* pFormatEtc, void* pClientSite, void* pStg, void** ppvObj) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(rclsid);
    static_cast<void>(riid);
    static_cast<void>(renderopt);
    static_cast<void>(pFormatEtc);
    static_cast<void>(pClientSite);
    static_cast<void>(pStg);
    static_cast<void>(ppvObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleCreateDefaultHandler(const void* clsid, void* pUnkOuter, const void* riid, void** lplpObj) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(clsid);
    static_cast<void>(pUnkOuter);
    static_cast<void>(riid);
    static_cast<void>(lplpObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleCreateEmbeddingHelper(const void* clsid, void* pUnkOuter, std::uint32_t flags, std::uint64_t pCF, const void* riid, void** lplpObj) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(clsid);
    static_cast<void>(pUnkOuter);
    static_cast<void>(flags);
    static_cast<void>(pCF);
    static_cast<void>(riid);
    static_cast<void>(lplpObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleCreateEx(const void* rclsid, const void* riid, std::uint32_t dwFlags, std::uint32_t renderopt, std::uint32_t cFormats, std::uint32_t* rgAdvf, void* rgFormatEtc, void* lpAdviseSink, std::uint32_t* rgdwConnection, void* pClientSite, void* pStg, void** ppvObj) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(rclsid);
    static_cast<void>(riid);
    static_cast<void>(dwFlags);
    static_cast<void>(renderopt);
    static_cast<void>(cFormats);
    static_cast<void>(rgAdvf);
    static_cast<void>(rgFormatEtc);
    static_cast<void>(lpAdviseSink);
    static_cast<void>(rgdwConnection);
    static_cast<void>(pClientSite);
    static_cast<void>(pStg);
    static_cast<void>(ppvObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleCreateFromData(void* pSrcDataObj, const void* riid, std::uint32_t renderopt, void* pFormatEtc, void* pClientSite, void* pStg, void** ppvObj) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pSrcDataObj);
    static_cast<void>(riid);
    static_cast<void>(renderopt);
    static_cast<void>(pFormatEtc);
    static_cast<void>(pClientSite);
    static_cast<void>(pStg);
    static_cast<void>(ppvObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleCreateFromDataEx(void* pSrcDataObj, const void* riid, std::uint32_t dwFlags, std::uint32_t renderopt, std::uint32_t cFormats, std::uint32_t* rgAdvf, void* rgFormatEtc, void* lpAdviseSink, std::uint32_t* rgdwConnection, void* pClientSite, void* pStg, void** ppvObj) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pSrcDataObj);
    static_cast<void>(riid);
    static_cast<void>(dwFlags);
    static_cast<void>(renderopt);
    static_cast<void>(cFormats);
    static_cast<void>(rgAdvf);
    static_cast<void>(rgFormatEtc);
    static_cast<void>(lpAdviseSink);
    static_cast<void>(rgdwConnection);
    static_cast<void>(pClientSite);
    static_cast<void>(pStg);
    static_cast<void>(ppvObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleCreateFromFile(const void* rclsid, const char16_t* lpszFileName, const void* riid, std::uint32_t renderopt, void* lpFormatEtc, void* pClientSite, void* pStg, void** ppvObj) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(rclsid);
    static_cast<void>(lpszFileName);
    static_cast<void>(riid);
    static_cast<void>(renderopt);
    static_cast<void>(lpFormatEtc);
    static_cast<void>(pClientSite);
    static_cast<void>(pStg);
    static_cast<void>(ppvObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleCreateFromFileEx(const void* rclsid, const char16_t* lpszFileName, const void* riid, std::uint32_t dwFlags, std::uint32_t renderopt, std::uint32_t cFormats, std::uint32_t* rgAdvf, void* rgFormatEtc, void* lpAdviseSink, std::uint32_t* rgdwConnection, void* pClientSite, void* pStg, void** ppvObj) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(rclsid);
    static_cast<void>(lpszFileName);
    static_cast<void>(riid);
    static_cast<void>(dwFlags);
    static_cast<void>(renderopt);
    static_cast<void>(cFormats);
    static_cast<void>(rgAdvf);
    static_cast<void>(rgFormatEtc);
    static_cast<void>(lpAdviseSink);
    static_cast<void>(rgdwConnection);
    static_cast<void>(pClientSite);
    static_cast<void>(pStg);
    static_cast<void>(ppvObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleCreateLink(void* pmkLinkSrc, const void* riid, std::uint32_t renderopt, void* lpFormatEtc, void* pClientSite, void* pStg, void** ppvObj) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pmkLinkSrc);
    static_cast<void>(riid);
    static_cast<void>(renderopt);
    static_cast<void>(lpFormatEtc);
    static_cast<void>(pClientSite);
    static_cast<void>(pStg);
    static_cast<void>(ppvObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleCreateLinkEx(void* pmkLinkSrc, const void* riid, std::uint32_t dwFlags, std::uint32_t renderopt, std::uint32_t cFormats, std::uint32_t* rgAdvf, void* rgFormatEtc, void* lpAdviseSink, std::uint32_t* rgdwConnection, void* pClientSite, void* pStg, void** ppvObj) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pmkLinkSrc);
    static_cast<void>(riid);
    static_cast<void>(dwFlags);
    static_cast<void>(renderopt);
    static_cast<void>(cFormats);
    static_cast<void>(rgAdvf);
    static_cast<void>(rgFormatEtc);
    static_cast<void>(lpAdviseSink);
    static_cast<void>(rgdwConnection);
    static_cast<void>(pClientSite);
    static_cast<void>(pStg);
    static_cast<void>(ppvObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleCreateLinkFromData(void* pSrcDataObj, const void* riid, std::uint32_t renderopt, void* pFormatEtc, void* pClientSite, void* pStg, void** ppvObj) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pSrcDataObj);
    static_cast<void>(riid);
    static_cast<void>(renderopt);
    static_cast<void>(pFormatEtc);
    static_cast<void>(pClientSite);
    static_cast<void>(pStg);
    static_cast<void>(ppvObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleCreateLinkFromDataEx(void* pSrcDataObj, const void* riid, std::uint32_t dwFlags, std::uint32_t renderopt, std::uint32_t cFormats, std::uint32_t* rgAdvf, void* rgFormatEtc, void* lpAdviseSink, std::uint32_t* rgdwConnection, void* pClientSite, void* pStg, void** ppvObj) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pSrcDataObj);
    static_cast<void>(riid);
    static_cast<void>(dwFlags);
    static_cast<void>(renderopt);
    static_cast<void>(cFormats);
    static_cast<void>(rgAdvf);
    static_cast<void>(rgFormatEtc);
    static_cast<void>(lpAdviseSink);
    static_cast<void>(rgdwConnection);
    static_cast<void>(pClientSite);
    static_cast<void>(pStg);
    static_cast<void>(ppvObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleCreateLinkToFile(const char16_t* lpszFileName, const void* riid, std::uint32_t renderopt, void* lpFormatEtc, void* pClientSite, void* pStg, void** ppvObj) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(lpszFileName);
    static_cast<void>(riid);
    static_cast<void>(renderopt);
    static_cast<void>(lpFormatEtc);
    static_cast<void>(pClientSite);
    static_cast<void>(pStg);
    static_cast<void>(ppvObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleCreateLinkToFileEx(const char16_t* lpszFileName, const void* riid, std::uint32_t dwFlags, std::uint32_t renderopt, std::uint32_t cFormats, std::uint32_t* rgAdvf, void* rgFormatEtc, void* lpAdviseSink, std::uint32_t* rgdwConnection, void* pClientSite, void* pStg, void** ppvObj) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(lpszFileName);
    static_cast<void>(riid);
    static_cast<void>(dwFlags);
    static_cast<void>(renderopt);
    static_cast<void>(cFormats);
    static_cast<void>(rgAdvf);
    static_cast<void>(rgFormatEtc);
    static_cast<void>(lpAdviseSink);
    static_cast<void>(rgdwConnection);
    static_cast<void>(pClientSite);
    static_cast<void>(pStg);
    static_cast<void>(ppvObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kole32G_OleCreateMenuDescriptor(void* hmenuCombined, std::uint64_t lpMenuWidths) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(hmenuCombined);
    static_cast<void>(lpMenuWidths);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleCreateStaticFromData(void* pSrcDataObj, const void* iid, std::uint32_t renderopt, void* pFormatEtc, void* pClientSite, void* pStg, void** ppvObj) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pSrcDataObj);
    static_cast<void>(iid);
    static_cast<void>(renderopt);
    static_cast<void>(pFormatEtc);
    static_cast<void>(pClientSite);
    static_cast<void>(pStg);
    static_cast<void>(ppvObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleDestroyMenuDescriptor(std::uint64_t holemenu) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(holemenu);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleDoAutoConvert(void* pStg, void* pClsidNew) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pStg);
    static_cast<void>(pClsidNew);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleDraw(void* pUnknown, std::uint32_t dwAspect, void* hdcDraw, void* lprcBounds) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pUnknown);
    static_cast<void>(dwAspect);
    static_cast<void>(hdcDraw);
    static_cast<void>(lprcBounds);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kole32G_OleDuplicateData(void* hSrc, std::uint16_t cfFormat, std::uint32_t uiFlags) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(hSrc);
    static_cast<void>(cfFormat);
    static_cast<void>(uiFlags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleFlushClipboard() noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleGetAutoConvert(const void* clsidOld, void* pClsidNew) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(clsidOld);
    static_cast<void>(pClsidNew);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleGetClipboard(void** ppDataObj) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(ppDataObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kole32G_OleGetIconOfClass(const void* rclsid, char16_t* lpszLabel, std::int32_t fUseTypeAsLabel) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(rclsid);
    static_cast<void>(lpszLabel);
    static_cast<void>(fUseTypeAsLabel);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kole32G_OleGetIconOfFile(char16_t* lpszPath, std::int32_t fUseFileAsLabel) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(lpszPath);
    static_cast<void>(fUseFileAsLabel);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleInitialize(void* pvReserved) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pvReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleIsCurrentClipboard(void* pDataObj) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pDataObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleIsRunning(std::uint64_t pObject) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pObject);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleLoad(void* pStg, const void* riid, void* pClientSite, void** ppvObj) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pStg);
    static_cast<void>(riid);
    static_cast<void>(pClientSite);
    static_cast<void>(ppvObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleLoadFromStream(void* pStm, const void* iidInterface, void** ppvObj) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pStm);
    static_cast<void>(iidInterface);
    static_cast<void>(ppvObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleLockRunning(void* pUnknown, std::int32_t fLock, std::int32_t fLastUnlockCloses) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pUnknown);
    static_cast<void>(fLock);
    static_cast<void>(fLastUnlockCloses);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kole32G_OleMetafilePictFromIconAndLabel(void* hIcon, char16_t* lpszLabel, char16_t* lpszSourceFile, std::uint32_t iIconIndex) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(hIcon);
    static_cast<void>(lpszLabel);
    static_cast<void>(lpszSourceFile);
    static_cast<void>(iIconIndex);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleNoteObjectVisible(void* pUnknown, std::int32_t fVisible) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pUnknown);
    static_cast<void>(fVisible);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleQueryCreateFromData(void* pSrcDataObject) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pSrcDataObject);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleQueryLinkFromData(void* pSrcDataObject) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pSrcDataObject);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleRegEnumFormatEtc(const void* clsid, std::uint32_t dwDirection, void* ppenum) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(clsid);
    static_cast<void>(dwDirection);
    static_cast<void>(ppenum);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleRegEnumVerbs(const void* clsid, void* ppenum) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(clsid);
    static_cast<void>(ppenum);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleRegGetMiscStatus(const void* clsid, std::uint32_t dwAspect, std::uint32_t* pdwStatus) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(clsid);
    static_cast<void>(dwAspect);
    static_cast<void>(pdwStatus);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleRegGetUserType(const void* clsid, std::uint32_t dwFormOfType, char16_t** pszUserType) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(clsid);
    static_cast<void>(dwFormOfType);
    static_cast<void>(pszUserType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleRun(void* pUnknown) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pUnknown);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleSave(std::uint64_t pPS, void* pStg, std::int32_t fSameAsLoad) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pPS);
    static_cast<void>(pStg);
    static_cast<void>(fSameAsLoad);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleSaveToStream(std::uint64_t pPStm, void* pStm) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pPStm);
    static_cast<void>(pStm);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleSetAutoConvert(const void* clsidOld, const void* clsidNew) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(clsidOld);
    static_cast<void>(clsidNew);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleSetClipboard(void* pDataObj) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pDataObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleSetContainedObject(void* pUnknown, std::int32_t fContained) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pUnknown);
    static_cast<void>(fContained);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleSetMenuDescriptor(std::uint64_t holemenu, void* hwndFrame, void* hwndActiveObject, std::uint64_t lpFrame, std::uint64_t lpActiveObj) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(holemenu);
    static_cast<void>(hwndFrame);
    static_cast<void>(hwndActiveObject);
    static_cast<void>(lpFrame);
    static_cast<void>(lpActiveObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_OleTranslateAccelerator(std::uint64_t lpFrame, std::uint64_t lpFrameInfo, void* lpmsg) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(lpFrame);
    static_cast<void>(lpFrameInfo);
    static_cast<void>(lpmsg);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kole32G_OleUninitialize() noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_ProgIDFromCLSID(const void* clsid, char16_t** lplpszProgID) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(clsid);
    static_cast<void>(lplpszProgID);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_PropStgNameToFmtId(char16_t* oszName, void* pfmtid) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(oszName);
    static_cast<void>(pfmtid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_PropVariantClear(void* pvar) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pvar);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_PropVariantCopy(void* pvarDest, const void* pvarSrc) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pvarDest);
    static_cast<void>(pvarSrc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_ReadClassStg(void* pStg, void* pclsid) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pStg);
    static_cast<void>(pclsid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_ReadClassStm(void* pStm, void* pclsid) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pStm);
    static_cast<void>(pclsid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_ReadFmtUserTypeStg(void* pstg, std::uint16_t* pcf, char16_t** lplpszUserType) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pstg);
    static_cast<void>(pcf);
    static_cast<void>(lplpszUserType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_RegisterDragDrop(void* hwnd, std::uint64_t pDropTarget) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hwnd);
    static_cast<void>(pDropTarget);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kole32G_ReleaseStgMedium(std::uint64_t arg0) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_RevokeDragDrop(void* hwnd) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hwnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kole32G_SNB_UserFree(std::uint32_t* arg0, void* arg1) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* kole32G_SNB_UserMarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kole32G_SNB_UserSize(std::uint32_t* arg0, std::uint32_t arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* kole32G_SNB_UserUnmarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void kole32G_STGMEDIUM_UserFree(std::uint32_t* arg0, void* arg1) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* kole32G_STGMEDIUM_UserMarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kole32G_STGMEDIUM_UserSize(std::uint32_t* arg0, std::uint32_t arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* kole32G_STGMEDIUM_UserUnmarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_SetConvertStg(void* pStg, std::int32_t fConvert) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pStg);
    static_cast<void>(fConvert);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_SetErrorInfo(std::uint32_t dwReserved, void* perrinfo) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(dwReserved);
    static_cast<void>(perrinfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kole32G_StgConvertVariantToProperty(const void* pvar, std::uint16_t CodePage, void* pprop, std::uint32_t* pcb, std::uint64_t pid, std::uint8_t fReserved, std::uint32_t* pcIndirect) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pvar);
    static_cast<void>(CodePage);
    static_cast<void>(pprop);
    static_cast<void>(pcb);
    static_cast<void>(pid);
    static_cast<void>(fReserved);
    static_cast<void>(pcIndirect);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_StgCreateDocfile(const char16_t* pwcsName, std::uint32_t grfMode, std::uint32_t reserved, void** ppstgOpen) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pwcsName);
    static_cast<void>(grfMode);
    static_cast<void>(reserved);
    static_cast<void>(ppstgOpen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_StgCreateDocfileOnILockBytes(void* plkbyt, std::uint32_t grfMode, std::uint32_t reserved, void** ppstgOpen) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(plkbyt);
    static_cast<void>(grfMode);
    static_cast<void>(reserved);
    static_cast<void>(ppstgOpen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_StgCreatePropSetStg(void* pStorage, std::uint32_t dwReserved, void** ppPropSetStg) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pStorage);
    static_cast<void>(dwReserved);
    static_cast<void>(ppPropSetStg);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_StgCreatePropStg(void* pUnk, const void* fmtid, const void* pclsid, std::uint32_t grfFlags, std::uint32_t dwReserved, void** ppPropStg) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pUnk);
    static_cast<void>(fmtid);
    static_cast<void>(pclsid);
    static_cast<void>(grfFlags);
    static_cast<void>(dwReserved);
    static_cast<void>(ppPropStg);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_StgCreateStorageEx(const char16_t* pwcsName, std::uint32_t grfMode, std::uint32_t stgfmt, std::uint32_t grfAttrs, void* pStgOptions, void* pSecurityDescriptor, const void* riid, void** ppObjectOpen) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pwcsName);
    static_cast<void>(grfMode);
    static_cast<void>(stgfmt);
    static_cast<void>(grfAttrs);
    static_cast<void>(pStgOptions);
    static_cast<void>(pSecurityDescriptor);
    static_cast<void>(riid);
    static_cast<void>(ppObjectOpen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_StgGetIFillLockBytesOnFile(char16_t* pwcsName, void** ppflb) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pwcsName);
    static_cast<void>(ppflb);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_StgGetIFillLockBytesOnILockBytes(void* pilb, void** ppflb) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pilb);
    static_cast<void>(ppflb);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_StgIsStorageFile(const char16_t* pwcsName) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pwcsName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_StgIsStorageILockBytes(void* plkbyt) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(plkbyt);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_StgOpenAsyncDocfileOnIFillLockBytes(void* pflb, std::uint32_t grfMode, std::uint32_t asyncFlags, void** ppstgOpen) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pflb);
    static_cast<void>(grfMode);
    static_cast<void>(asyncFlags);
    static_cast<void>(ppstgOpen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_StgOpenPropStg(void* pUnk, const void* fmtid, std::uint32_t grfFlags, std::uint32_t dwReserved, void** ppPropStg) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pUnk);
    static_cast<void>(fmtid);
    static_cast<void>(grfFlags);
    static_cast<void>(dwReserved);
    static_cast<void>(ppPropStg);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_StgOpenStorage(const char16_t* pwcsName, void* pstgPriority, std::uint32_t grfMode, std::uint64_t snbExclude, std::uint32_t reserved, void** ppstgOpen) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pwcsName);
    static_cast<void>(pstgPriority);
    static_cast<void>(grfMode);
    static_cast<void>(snbExclude);
    static_cast<void>(reserved);
    static_cast<void>(ppstgOpen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_StgOpenStorageEx(const char16_t* pwcsName, std::uint32_t grfMode, std::uint32_t stgfmt, std::uint32_t grfAttrs, void* pStgOptions, void* pSecurityDescriptor, const void* riid, void** ppObjectOpen) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pwcsName);
    static_cast<void>(grfMode);
    static_cast<void>(stgfmt);
    static_cast<void>(grfAttrs);
    static_cast<void>(pStgOptions);
    static_cast<void>(pSecurityDescriptor);
    static_cast<void>(riid);
    static_cast<void>(ppObjectOpen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_StgOpenStorageOnILockBytes(void* plkbyt, void* pstgPriority, std::uint32_t grfMode, std::uint64_t snbExclude, std::uint32_t reserved, void** ppstgOpen) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(plkbyt);
    static_cast<void>(pstgPriority);
    static_cast<void>(grfMode);
    static_cast<void>(snbExclude);
    static_cast<void>(reserved);
    static_cast<void>(ppstgOpen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_StgSetTimes(const char16_t* lpszName, const std::uint64_t* pctime, const std::uint64_t* patime, const std::uint64_t* pmtime) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(lpszName);
    static_cast<void>(pctime);
    static_cast<void>(patime);
    static_cast<void>(pmtime);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_StringFromCLSID(const void* rclsid, char16_t** lplpsz) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(rclsid);
    static_cast<void>(lplpsz);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_StringFromGUID2(const void* rguid, char16_t* lpsz, std::int32_t cchMax) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(rguid);
    static_cast<void>(lpsz);
    static_cast<void>(cchMax);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_StringFromIID(const void* rclsid, char16_t** lplpsz) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(rclsid);
    static_cast<void>(lplpsz);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_WriteClassStg(void* pStg, const void* rclsid) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pStg);
    static_cast<void>(rclsid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_WriteClassStm(void* pStm, const void* rclsid) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pStm);
    static_cast<void>(rclsid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kole32G_WriteFmtUserTypeStg(void* pstg, std::uint16_t cf, char16_t* lpszUserType) noexcept {
    // Refused: the COM runtime.
    //
    // the call needs an apartment, a class registry or a marshaller, none of
    // which this runtime establishes
    static_cast<void>(pstg);
    static_cast<void>(cf);
    static_cast<void>(lpszUserType);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_ole32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("BindMoniker", reinterpret_cast<void*>(&kole32G_BindMoniker));
    e("CLIPFORMAT_UserFree", reinterpret_cast<void*>(&kole32G_CLIPFORMAT_UserFree));
    e("CLIPFORMAT_UserMarshal", reinterpret_cast<void*>(&kole32G_CLIPFORMAT_UserMarshal));
    e("CLIPFORMAT_UserSize", reinterpret_cast<void*>(&kole32G_CLIPFORMAT_UserSize));
    e("CLIPFORMAT_UserUnmarshal", reinterpret_cast<void*>(&kole32G_CLIPFORMAT_UserUnmarshal));
    e("CLSIDFromProgID", reinterpret_cast<void*>(&kole32G_CLSIDFromProgID));
    e("CLSIDFromProgIDEx", reinterpret_cast<void*>(&kole32G_CLSIDFromProgIDEx));
    e("CLSIDFromString", reinterpret_cast<void*>(&kole32G_CLSIDFromString));
    e("CoAddRefServerProcess", reinterpret_cast<void*>(&kole32G_CoAddRefServerProcess));
    e("CoAllowSetForegroundWindow", reinterpret_cast<void*>(&kole32G_CoAllowSetForegroundWindow));
    e("CoAllowUnmarshalerCLSID", reinterpret_cast<void*>(&kole32G_CoAllowUnmarshalerCLSID));
    e("CoBuildVersion", reinterpret_cast<void*>(&kole32G_CoBuildVersion));
    e("CoCancelCall", reinterpret_cast<void*>(&kole32G_CoCancelCall));
    e("CoCopyProxy", reinterpret_cast<void*>(&kole32G_CoCopyProxy));
    e("CoCreateFreeThreadedMarshaler", reinterpret_cast<void*>(&kole32G_CoCreateFreeThreadedMarshaler));
    e("CoCreateGuid", reinterpret_cast<void*>(&kole32G_CoCreateGuid));
    e("CoCreateInstance", reinterpret_cast<void*>(&kole32G_CoCreateInstance));
    e("CoCreateInstanceEx", reinterpret_cast<void*>(&kole32G_CoCreateInstanceEx));
    e("CoCreateInstanceFromApp", reinterpret_cast<void*>(&kole32G_CoCreateInstanceFromApp));
    e("CoDecodeProxy", reinterpret_cast<void*>(&kole32G_CoDecodeProxy));
    e("CoDecrementMTAUsage", reinterpret_cast<void*>(&kole32G_CoDecrementMTAUsage));
    e("CoDisableCallCancellation", reinterpret_cast<void*>(&kole32G_CoDisableCallCancellation));
    e("CoDisconnectContext", reinterpret_cast<void*>(&kole32G_CoDisconnectContext));
    e("CoDisconnectObject", reinterpret_cast<void*>(&kole32G_CoDisconnectObject));
    e("CoDosDateTimeToFileTime", reinterpret_cast<void*>(&kole32G_CoDosDateTimeToFileTime));
    e("CoEnableCallCancellation", reinterpret_cast<void*>(&kole32G_CoEnableCallCancellation));
    e("CoFileTimeNow", reinterpret_cast<void*>(&kole32G_CoFileTimeNow));
    e("CoFileTimeToDosDateTime", reinterpret_cast<void*>(&kole32G_CoFileTimeToDosDateTime));
    e("CoFreeAllLibraries", reinterpret_cast<void*>(&kole32G_CoFreeAllLibraries));
    e("CoFreeLibrary", reinterpret_cast<void*>(&kole32G_CoFreeLibrary));
    e("CoFreeUnusedLibraries", reinterpret_cast<void*>(&kole32G_CoFreeUnusedLibraries));
    e("CoFreeUnusedLibrariesEx", reinterpret_cast<void*>(&kole32G_CoFreeUnusedLibrariesEx));
    e("CoGetCallContext", reinterpret_cast<void*>(&kole32G_CoGetCallContext));
    e("CoGetCallerTID", reinterpret_cast<void*>(&kole32G_CoGetCallerTID));
    e("CoGetCancelObject", reinterpret_cast<void*>(&kole32G_CoGetCancelObject));
    e("CoGetClassObject", reinterpret_cast<void*>(&kole32G_CoGetClassObject));
    e("CoGetContextToken", reinterpret_cast<void*>(&kole32G_CoGetContextToken));
    e("CoGetCurrentLogicalThreadId", reinterpret_cast<void*>(&kole32G_CoGetCurrentLogicalThreadId));
    e("CoGetCurrentProcess", reinterpret_cast<void*>(&kole32G_CoGetCurrentProcess));
    e("CoGetDefaultContext", reinterpret_cast<void*>(&kole32G_CoGetDefaultContext));
    e("CoGetInstanceFromFile", reinterpret_cast<void*>(&kole32G_CoGetInstanceFromFile));
    e("CoGetInstanceFromIStorage", reinterpret_cast<void*>(&kole32G_CoGetInstanceFromIStorage));
    e("CoGetInterceptor", reinterpret_cast<void*>(&kole32G_CoGetInterceptor));
    e("CoGetInterceptorFromTypeInfo", reinterpret_cast<void*>(&kole32G_CoGetInterceptorFromTypeInfo));
    e("CoGetInterfaceAndReleaseStream", reinterpret_cast<void*>(&kole32G_CoGetInterfaceAndReleaseStream));
    e("CoGetMalloc", reinterpret_cast<void*>(&kole32G_CoGetMalloc));
    e("CoGetMarshalSizeMax", reinterpret_cast<void*>(&kole32G_CoGetMarshalSizeMax));
    e("CoGetObject", reinterpret_cast<void*>(&kole32G_CoGetObject));
    e("CoGetObjectContext", reinterpret_cast<void*>(&kole32G_CoGetObjectContext));
    e("CoGetPSClsid", reinterpret_cast<void*>(&kole32G_CoGetPSClsid));
    e("CoGetStandardMarshal", reinterpret_cast<void*>(&kole32G_CoGetStandardMarshal));
    e("CoGetStdMarshalEx", reinterpret_cast<void*>(&kole32G_CoGetStdMarshalEx));
    e("CoGetSystemSecurityPermissions", reinterpret_cast<void*>(&kole32G_CoGetSystemSecurityPermissions));
    e("CoGetTreatAsClass", reinterpret_cast<void*>(&kole32G_CoGetTreatAsClass));
    e("CoImpersonateClient", reinterpret_cast<void*>(&kole32G_CoImpersonateClient));
    e("CoIncrementMTAUsage", reinterpret_cast<void*>(&kole32G_CoIncrementMTAUsage));
    e("CoInitialize", reinterpret_cast<void*>(&kole32G_CoInitialize));
    e("CoInitializeSecurity", reinterpret_cast<void*>(&kole32G_CoInitializeSecurity));
    e("CoInstall", reinterpret_cast<void*>(&kole32G_CoInstall));
    e("CoInvalidateRemoteMachineBindings", reinterpret_cast<void*>(&kole32G_CoInvalidateRemoteMachineBindings));
    e("CoIsHandlerConnected", reinterpret_cast<void*>(&kole32G_CoIsHandlerConnected));
    e("CoIsOle1Class", reinterpret_cast<void*>(&kole32G_CoIsOle1Class));
    e("CoLoadLibrary", reinterpret_cast<void*>(&kole32G_CoLoadLibrary));
    e("CoLockObjectExternal", reinterpret_cast<void*>(&kole32G_CoLockObjectExternal));
    e("CoMarshalHresult", reinterpret_cast<void*>(&kole32G_CoMarshalHresult));
    e("CoMarshalInterThreadInterfaceInStream", reinterpret_cast<void*>(&kole32G_CoMarshalInterThreadInterfaceInStream));
    e("CoMarshalInterface", reinterpret_cast<void*>(&kole32G_CoMarshalInterface));
    e("CoQueryAuthenticationServices", reinterpret_cast<void*>(&kole32G_CoQueryAuthenticationServices));
    e("CoQueryClientBlanket", reinterpret_cast<void*>(&kole32G_CoQueryClientBlanket));
    e("CoQueryProxyBlanket", reinterpret_cast<void*>(&kole32G_CoQueryProxyBlanket));
    e("CoRegisterChannelHook", reinterpret_cast<void*>(&kole32G_CoRegisterChannelHook));
    e("CoRegisterClassObject", reinterpret_cast<void*>(&kole32G_CoRegisterClassObject));
    e("CoRegisterInitializeSpy", reinterpret_cast<void*>(&kole32G_CoRegisterInitializeSpy));
    e("CoRegisterMallocSpy", reinterpret_cast<void*>(&kole32G_CoRegisterMallocSpy));
    e("CoRegisterMessageFilter", reinterpret_cast<void*>(&kole32G_CoRegisterMessageFilter));
    e("CoRegisterPSClsid", reinterpret_cast<void*>(&kole32G_CoRegisterPSClsid));
    e("CoRegisterSurrogate", reinterpret_cast<void*>(&kole32G_CoRegisterSurrogate));
    e("CoReleaseMarshalData", reinterpret_cast<void*>(&kole32G_CoReleaseMarshalData));
    e("CoReleaseServerProcess", reinterpret_cast<void*>(&kole32G_CoReleaseServerProcess));
    e("CoResumeClassObjects", reinterpret_cast<void*>(&kole32G_CoResumeClassObjects));
    e("CoRevertToSelf", reinterpret_cast<void*>(&kole32G_CoRevertToSelf));
    e("CoRevokeClassObject", reinterpret_cast<void*>(&kole32G_CoRevokeClassObject));
    e("CoRevokeInitializeSpy", reinterpret_cast<void*>(&kole32G_CoRevokeInitializeSpy));
    e("CoRevokeMallocSpy", reinterpret_cast<void*>(&kole32G_CoRevokeMallocSpy));
    e("CoSetCancelObject", reinterpret_cast<void*>(&kole32G_CoSetCancelObject));
    e("CoSetProxyBlanket", reinterpret_cast<void*>(&kole32G_CoSetProxyBlanket));
    e("CoSuspendClassObjects", reinterpret_cast<void*>(&kole32G_CoSuspendClassObjects));
    e("CoSwitchCallContext", reinterpret_cast<void*>(&kole32G_CoSwitchCallContext));
    e("CoTaskMemAlloc", reinterpret_cast<void*>(&kole32G_CoTaskMemAlloc));
    e("CoTaskMemFree", reinterpret_cast<void*>(&kole32G_CoTaskMemFree));
    e("CoTaskMemRealloc", reinterpret_cast<void*>(&kole32G_CoTaskMemRealloc));
    e("CoTestCancel", reinterpret_cast<void*>(&kole32G_CoTestCancel));
    e("CoTreatAsClass", reinterpret_cast<void*>(&kole32G_CoTreatAsClass));
    e("CoUnmarshalHresult", reinterpret_cast<void*>(&kole32G_CoUnmarshalHresult));
    e("CoUnmarshalInterface", reinterpret_cast<void*>(&kole32G_CoUnmarshalInterface));
    e("CoWaitForMultipleObjects", reinterpret_cast<void*>(&kole32G_CoWaitForMultipleObjects));
    e("CreateAntiMoniker", reinterpret_cast<void*>(&kole32G_CreateAntiMoniker));
    e("CreateBindCtx", reinterpret_cast<void*>(&kole32G_CreateBindCtx));
    e("CreateClassMoniker", reinterpret_cast<void*>(&kole32G_CreateClassMoniker));
    e("CreateDataAdviseHolder", reinterpret_cast<void*>(&kole32G_CreateDataAdviseHolder));
    e("CreateDataCache", reinterpret_cast<void*>(&kole32G_CreateDataCache));
    e("CreateErrorInfo", reinterpret_cast<void*>(&kole32G_CreateErrorInfo));
    e("CreateFileMoniker", reinterpret_cast<void*>(&kole32G_CreateFileMoniker));
    e("CreateGenericComposite", reinterpret_cast<void*>(&kole32G_CreateGenericComposite));
    e("CreateILockBytesOnHGlobal", reinterpret_cast<void*>(&kole32G_CreateILockBytesOnHGlobal));
    e("CreateItemMoniker", reinterpret_cast<void*>(&kole32G_CreateItemMoniker));
    e("CreateObjrefMoniker", reinterpret_cast<void*>(&kole32G_CreateObjrefMoniker));
    e("CreateOleAdviseHolder", reinterpret_cast<void*>(&kole32G_CreateOleAdviseHolder));
    e("CreatePointerMoniker", reinterpret_cast<void*>(&kole32G_CreatePointerMoniker));
    e("CreateStdProgressIndicator", reinterpret_cast<void*>(&kole32G_CreateStdProgressIndicator));
    e("CreateStreamOnHGlobal", reinterpret_cast<void*>(&kole32G_CreateStreamOnHGlobal));
    e("DcomChannelSetHResult", reinterpret_cast<void*>(&kole32G_DcomChannelSetHResult));
    e("DoDragDrop", reinterpret_cast<void*>(&kole32G_DoDragDrop));
    e("FmtIdToPropStgName", reinterpret_cast<void*>(&kole32G_FmtIdToPropStgName));
    e("FreePropVariantArray", reinterpret_cast<void*>(&kole32G_FreePropVariantArray));
    e("GetClassFile", reinterpret_cast<void*>(&kole32G_GetClassFile));
    e("GetConvertStg", reinterpret_cast<void*>(&kole32G_GetConvertStg));
    e("GetErrorInfo", reinterpret_cast<void*>(&kole32G_GetErrorInfo));
    e("GetHGlobalFromILockBytes", reinterpret_cast<void*>(&kole32G_GetHGlobalFromILockBytes));
    e("GetHGlobalFromStream", reinterpret_cast<void*>(&kole32G_GetHGlobalFromStream));
    e("GetRunningObjectTable", reinterpret_cast<void*>(&kole32G_GetRunningObjectTable));
    e("HACCEL_UserFree", reinterpret_cast<void*>(&kole32G_HACCEL_UserFree));
    e("HACCEL_UserMarshal", reinterpret_cast<void*>(&kole32G_HACCEL_UserMarshal));
    e("HACCEL_UserSize", reinterpret_cast<void*>(&kole32G_HACCEL_UserSize));
    e("HACCEL_UserUnmarshal", reinterpret_cast<void*>(&kole32G_HACCEL_UserUnmarshal));
    e("HBITMAP_UserFree", reinterpret_cast<void*>(&kole32G_HBITMAP_UserFree));
    e("HBITMAP_UserMarshal", reinterpret_cast<void*>(&kole32G_HBITMAP_UserMarshal));
    e("HBITMAP_UserSize", reinterpret_cast<void*>(&kole32G_HBITMAP_UserSize));
    e("HBITMAP_UserUnmarshal", reinterpret_cast<void*>(&kole32G_HBITMAP_UserUnmarshal));
    e("HDC_UserFree", reinterpret_cast<void*>(&kole32G_HDC_UserFree));
    e("HDC_UserMarshal", reinterpret_cast<void*>(&kole32G_HDC_UserMarshal));
    e("HDC_UserSize", reinterpret_cast<void*>(&kole32G_HDC_UserSize));
    e("HDC_UserUnmarshal", reinterpret_cast<void*>(&kole32G_HDC_UserUnmarshal));
    e("HGLOBAL_UserFree", reinterpret_cast<void*>(&kole32G_HGLOBAL_UserFree));
    e("HGLOBAL_UserMarshal", reinterpret_cast<void*>(&kole32G_HGLOBAL_UserMarshal));
    e("HGLOBAL_UserSize", reinterpret_cast<void*>(&kole32G_HGLOBAL_UserSize));
    e("HGLOBAL_UserUnmarshal", reinterpret_cast<void*>(&kole32G_HGLOBAL_UserUnmarshal));
    e("HICON_UserFree", reinterpret_cast<void*>(&kole32G_HICON_UserFree));
    e("HICON_UserMarshal", reinterpret_cast<void*>(&kole32G_HICON_UserMarshal));
    e("HICON_UserSize", reinterpret_cast<void*>(&kole32G_HICON_UserSize));
    e("HICON_UserUnmarshal", reinterpret_cast<void*>(&kole32G_HICON_UserUnmarshal));
    e("HMENU_UserFree", reinterpret_cast<void*>(&kole32G_HMENU_UserFree));
    e("HMENU_UserMarshal", reinterpret_cast<void*>(&kole32G_HMENU_UserMarshal));
    e("HMENU_UserSize", reinterpret_cast<void*>(&kole32G_HMENU_UserSize));
    e("HMENU_UserUnmarshal", reinterpret_cast<void*>(&kole32G_HMENU_UserUnmarshal));
    e("HWND_UserFree", reinterpret_cast<void*>(&kole32G_HWND_UserFree));
    e("HWND_UserMarshal", reinterpret_cast<void*>(&kole32G_HWND_UserMarshal));
    e("HWND_UserSize", reinterpret_cast<void*>(&kole32G_HWND_UserSize));
    e("HWND_UserUnmarshal", reinterpret_cast<void*>(&kole32G_HWND_UserUnmarshal));
    e("IIDFromString", reinterpret_cast<void*>(&kole32G_IIDFromString));
    e("IsAccelerator", reinterpret_cast<void*>(&kole32G_IsAccelerator));
    e("MkParseDisplayName", reinterpret_cast<void*>(&kole32G_MkParseDisplayName));
    e("MonikerCommonPrefixWith", reinterpret_cast<void*>(&kole32G_MonikerCommonPrefixWith));
    e("MonikerRelativePathTo", reinterpret_cast<void*>(&kole32G_MonikerRelativePathTo));
    e("OleBuildVersion", reinterpret_cast<void*>(&kole32G_OleBuildVersion));
    e("OleConvertIStorageToOLESTREAM", reinterpret_cast<void*>(&kole32G_OleConvertIStorageToOLESTREAM));
    e("OleConvertIStorageToOLESTREAMEx", reinterpret_cast<void*>(&kole32G_OleConvertIStorageToOLESTREAMEx));
    e("OleConvertOLESTREAMToIStorage", reinterpret_cast<void*>(&kole32G_OleConvertOLESTREAMToIStorage));
    e("OleConvertOLESTREAMToIStorageEx", reinterpret_cast<void*>(&kole32G_OleConvertOLESTREAMToIStorageEx));
    e("OleCreate", reinterpret_cast<void*>(&kole32G_OleCreate));
    e("OleCreateDefaultHandler", reinterpret_cast<void*>(&kole32G_OleCreateDefaultHandler));
    e("OleCreateEmbeddingHelper", reinterpret_cast<void*>(&kole32G_OleCreateEmbeddingHelper));
    e("OleCreateEx", reinterpret_cast<void*>(&kole32G_OleCreateEx));
    e("OleCreateFromData", reinterpret_cast<void*>(&kole32G_OleCreateFromData));
    e("OleCreateFromDataEx", reinterpret_cast<void*>(&kole32G_OleCreateFromDataEx));
    e("OleCreateFromFile", reinterpret_cast<void*>(&kole32G_OleCreateFromFile));
    e("OleCreateFromFileEx", reinterpret_cast<void*>(&kole32G_OleCreateFromFileEx));
    e("OleCreateLink", reinterpret_cast<void*>(&kole32G_OleCreateLink));
    e("OleCreateLinkEx", reinterpret_cast<void*>(&kole32G_OleCreateLinkEx));
    e("OleCreateLinkFromData", reinterpret_cast<void*>(&kole32G_OleCreateLinkFromData));
    e("OleCreateLinkFromDataEx", reinterpret_cast<void*>(&kole32G_OleCreateLinkFromDataEx));
    e("OleCreateLinkToFile", reinterpret_cast<void*>(&kole32G_OleCreateLinkToFile));
    e("OleCreateLinkToFileEx", reinterpret_cast<void*>(&kole32G_OleCreateLinkToFileEx));
    e("OleCreateMenuDescriptor", reinterpret_cast<void*>(&kole32G_OleCreateMenuDescriptor));
    e("OleCreateStaticFromData", reinterpret_cast<void*>(&kole32G_OleCreateStaticFromData));
    e("OleDestroyMenuDescriptor", reinterpret_cast<void*>(&kole32G_OleDestroyMenuDescriptor));
    e("OleDoAutoConvert", reinterpret_cast<void*>(&kole32G_OleDoAutoConvert));
    e("OleDraw", reinterpret_cast<void*>(&kole32G_OleDraw));
    e("OleDuplicateData", reinterpret_cast<void*>(&kole32G_OleDuplicateData));
    e("OleFlushClipboard", reinterpret_cast<void*>(&kole32G_OleFlushClipboard));
    e("OleGetAutoConvert", reinterpret_cast<void*>(&kole32G_OleGetAutoConvert));
    e("OleGetClipboard", reinterpret_cast<void*>(&kole32G_OleGetClipboard));
    e("OleGetIconOfClass", reinterpret_cast<void*>(&kole32G_OleGetIconOfClass));
    e("OleGetIconOfFile", reinterpret_cast<void*>(&kole32G_OleGetIconOfFile));
    e("OleInitialize", reinterpret_cast<void*>(&kole32G_OleInitialize));
    e("OleIsCurrentClipboard", reinterpret_cast<void*>(&kole32G_OleIsCurrentClipboard));
    e("OleIsRunning", reinterpret_cast<void*>(&kole32G_OleIsRunning));
    e("OleLoad", reinterpret_cast<void*>(&kole32G_OleLoad));
    e("OleLoadFromStream", reinterpret_cast<void*>(&kole32G_OleLoadFromStream));
    e("OleLockRunning", reinterpret_cast<void*>(&kole32G_OleLockRunning));
    e("OleMetafilePictFromIconAndLabel", reinterpret_cast<void*>(&kole32G_OleMetafilePictFromIconAndLabel));
    e("OleNoteObjectVisible", reinterpret_cast<void*>(&kole32G_OleNoteObjectVisible));
    e("OleQueryCreateFromData", reinterpret_cast<void*>(&kole32G_OleQueryCreateFromData));
    e("OleQueryLinkFromData", reinterpret_cast<void*>(&kole32G_OleQueryLinkFromData));
    e("OleRegEnumFormatEtc", reinterpret_cast<void*>(&kole32G_OleRegEnumFormatEtc));
    e("OleRegEnumVerbs", reinterpret_cast<void*>(&kole32G_OleRegEnumVerbs));
    e("OleRegGetMiscStatus", reinterpret_cast<void*>(&kole32G_OleRegGetMiscStatus));
    e("OleRegGetUserType", reinterpret_cast<void*>(&kole32G_OleRegGetUserType));
    e("OleRun", reinterpret_cast<void*>(&kole32G_OleRun));
    e("OleSave", reinterpret_cast<void*>(&kole32G_OleSave));
    e("OleSaveToStream", reinterpret_cast<void*>(&kole32G_OleSaveToStream));
    e("OleSetAutoConvert", reinterpret_cast<void*>(&kole32G_OleSetAutoConvert));
    e("OleSetClipboard", reinterpret_cast<void*>(&kole32G_OleSetClipboard));
    e("OleSetContainedObject", reinterpret_cast<void*>(&kole32G_OleSetContainedObject));
    e("OleSetMenuDescriptor", reinterpret_cast<void*>(&kole32G_OleSetMenuDescriptor));
    e("OleTranslateAccelerator", reinterpret_cast<void*>(&kole32G_OleTranslateAccelerator));
    e("OleUninitialize", reinterpret_cast<void*>(&kole32G_OleUninitialize));
    e("ProgIDFromCLSID", reinterpret_cast<void*>(&kole32G_ProgIDFromCLSID));
    e("PropStgNameToFmtId", reinterpret_cast<void*>(&kole32G_PropStgNameToFmtId));
    e("PropVariantClear", reinterpret_cast<void*>(&kole32G_PropVariantClear));
    e("PropVariantCopy", reinterpret_cast<void*>(&kole32G_PropVariantCopy));
    e("ReadClassStg", reinterpret_cast<void*>(&kole32G_ReadClassStg));
    e("ReadClassStm", reinterpret_cast<void*>(&kole32G_ReadClassStm));
    e("ReadFmtUserTypeStg", reinterpret_cast<void*>(&kole32G_ReadFmtUserTypeStg));
    e("RegisterDragDrop", reinterpret_cast<void*>(&kole32G_RegisterDragDrop));
    e("ReleaseStgMedium", reinterpret_cast<void*>(&kole32G_ReleaseStgMedium));
    e("RevokeDragDrop", reinterpret_cast<void*>(&kole32G_RevokeDragDrop));
    e("SNB_UserFree", reinterpret_cast<void*>(&kole32G_SNB_UserFree));
    e("SNB_UserMarshal", reinterpret_cast<void*>(&kole32G_SNB_UserMarshal));
    e("SNB_UserSize", reinterpret_cast<void*>(&kole32G_SNB_UserSize));
    e("SNB_UserUnmarshal", reinterpret_cast<void*>(&kole32G_SNB_UserUnmarshal));
    e("STGMEDIUM_UserFree", reinterpret_cast<void*>(&kole32G_STGMEDIUM_UserFree));
    e("STGMEDIUM_UserMarshal", reinterpret_cast<void*>(&kole32G_STGMEDIUM_UserMarshal));
    e("STGMEDIUM_UserSize", reinterpret_cast<void*>(&kole32G_STGMEDIUM_UserSize));
    e("STGMEDIUM_UserUnmarshal", reinterpret_cast<void*>(&kole32G_STGMEDIUM_UserUnmarshal));
    e("SetConvertStg", reinterpret_cast<void*>(&kole32G_SetConvertStg));
    e("SetErrorInfo", reinterpret_cast<void*>(&kole32G_SetErrorInfo));
    e("StgConvertVariantToProperty", reinterpret_cast<void*>(&kole32G_StgConvertVariantToProperty));
    e("StgCreateDocfile", reinterpret_cast<void*>(&kole32G_StgCreateDocfile));
    e("StgCreateDocfileOnILockBytes", reinterpret_cast<void*>(&kole32G_StgCreateDocfileOnILockBytes));
    e("StgCreatePropSetStg", reinterpret_cast<void*>(&kole32G_StgCreatePropSetStg));
    e("StgCreatePropStg", reinterpret_cast<void*>(&kole32G_StgCreatePropStg));
    e("StgCreateStorageEx", reinterpret_cast<void*>(&kole32G_StgCreateStorageEx));
    e("StgGetIFillLockBytesOnFile", reinterpret_cast<void*>(&kole32G_StgGetIFillLockBytesOnFile));
    e("StgGetIFillLockBytesOnILockBytes", reinterpret_cast<void*>(&kole32G_StgGetIFillLockBytesOnILockBytes));
    e("StgIsStorageFile", reinterpret_cast<void*>(&kole32G_StgIsStorageFile));
    e("StgIsStorageILockBytes", reinterpret_cast<void*>(&kole32G_StgIsStorageILockBytes));
    e("StgOpenAsyncDocfileOnIFillLockBytes", reinterpret_cast<void*>(&kole32G_StgOpenAsyncDocfileOnIFillLockBytes));
    e("StgOpenPropStg", reinterpret_cast<void*>(&kole32G_StgOpenPropStg));
    e("StgOpenStorage", reinterpret_cast<void*>(&kole32G_StgOpenStorage));
    e("StgOpenStorageEx", reinterpret_cast<void*>(&kole32G_StgOpenStorageEx));
    e("StgOpenStorageOnILockBytes", reinterpret_cast<void*>(&kole32G_StgOpenStorageOnILockBytes));
    e("StgSetTimes", reinterpret_cast<void*>(&kole32G_StgSetTimes));
    e("StringFromCLSID", reinterpret_cast<void*>(&kole32G_StringFromCLSID));
    e("StringFromGUID2", reinterpret_cast<void*>(&kole32G_StringFromGUID2));
    e("StringFromIID", reinterpret_cast<void*>(&kole32G_StringFromIID));
    e("WriteClassStg", reinterpret_cast<void*>(&kole32G_WriteClassStg));
    e("WriteClassStm", reinterpret_cast<void*>(&kole32G_WriteClassStm));
    e("WriteFmtUserTypeStg", reinterpret_cast<void*>(&kole32G_WriteFmtUserTypeStg));
}
}  // namespace occ::runtime::winabi

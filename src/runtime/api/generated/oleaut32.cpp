// The OLEAUT32 surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) void koleaut32G_BSTR_UserFree(std::uint32_t* arg0, char16_t** arg1) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* koleaut32G_BSTR_UserMarshal(std::uint32_t* arg0, std::uint8_t* arg1, char16_t** arg2) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t koleaut32G_BSTR_UserSize(std::uint32_t* arg0, std::uint32_t arg1, char16_t** arg2) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* koleaut32G_BSTR_UserUnmarshal(std::uint32_t* arg0, std::uint8_t* arg1, char16_t** arg2) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_BstrFromVector(void* psa, char16_t** pbstr) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    static_cast<void>(pbstr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void koleaut32G_ClearCustData(std::uint64_t pCustData) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pCustData);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_CreateDispTypeInfo(void* pidata, std::uint32_t lcid, void** pptinfo) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pidata);
    static_cast<void>(lcid);
    static_cast<void>(pptinfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_CreateErrorInfo(void** pperrinfo) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pperrinfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_CreateStdDispatch(void* punkOuter, void* pvThis, void* ptinfo, void** ppunkStdDisp) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(punkOuter);
    static_cast<void>(pvThis);
    static_cast<void>(ptinfo);
    static_cast<void>(ppunkStdDisp);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_CreateTypeLib(std::uint32_t syskind, const char16_t* szFile, void** ppctlib) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(syskind);
    static_cast<void>(szFile);
    static_cast<void>(ppctlib);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_CreateTypeLib2(std::uint32_t syskind, const char16_t* szFile, void** ppctlib) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(syskind);
    static_cast<void>(szFile);
    static_cast<void>(ppctlib);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_DispCallFunc(void* pvInstance, std::uint64_t oVft, std::uint64_t cc, std::uint16_t vtReturn, std::uint32_t cActuals, std::uint16_t* prgvt, void** prgpvarg, void* pvargResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvInstance);
    static_cast<void>(oVft);
    static_cast<void>(cc);
    static_cast<void>(vtReturn);
    static_cast<void>(cActuals);
    static_cast<void>(prgvt);
    static_cast<void>(prgpvarg);
    static_cast<void>(pvargResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_DispGetIDsOfNames(void* ptinfo, char16_t** rgszNames, std::uint32_t cNames, std::int32_t* rgdispid) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ptinfo);
    static_cast<void>(rgszNames);
    static_cast<void>(cNames);
    static_cast<void>(rgdispid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_DispGetParam(void* pdispparams, std::uint32_t position, std::uint16_t vtTarg, void* pvarResult, std::uint32_t* puArgErr) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdispparams);
    static_cast<void>(position);
    static_cast<void>(vtTarg);
    static_cast<void>(pvarResult);
    static_cast<void>(puArgErr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_DispInvoke(void* _this, void* ptinfo, std::int32_t dispidMember, std::uint16_t wFlags, void* pparams, void* pvarResult, void* pexcepinfo, std::uint32_t* puArgErr) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(_this);
    static_cast<void>(ptinfo);
    static_cast<void>(dispidMember);
    static_cast<void>(wFlags);
    static_cast<void>(pparams);
    static_cast<void>(pvarResult);
    static_cast<void>(pexcepinfo);
    static_cast<void>(puArgErr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_DllCanUnloadNow() noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_DllGetClassObject(const void* rclsid, const void* riid, void** ppv) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(rclsid);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_DosDateTimeToVariantTime(std::uint16_t wDosDate, std::uint16_t wDosTime, double* pvtime) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(wDosDate);
    static_cast<void>(wDosTime);
    static_cast<void>(pvtime);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_GetActiveObject(const void* rclsid, void* pvReserved, void** ppunk) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(rclsid);
    static_cast<void>(pvReserved);
    static_cast<void>(ppunk);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_GetAltMonthNames(std::uint32_t lcid, char16_t*** prgp) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(lcid);
    static_cast<void>(prgp);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_GetErrorInfo(std::uint32_t dwReserved, void** pperrinfo) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dwReserved);
    static_cast<void>(pperrinfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_GetRecordInfoFromGuids(const void* rGuidTypeLib, std::uint32_t uVerMajor, std::uint32_t uVerMinor, std::uint32_t lcid, const void* rGuidTypeInfo, void** ppRecInfo) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(rGuidTypeLib);
    static_cast<void>(uVerMajor);
    static_cast<void>(uVerMinor);
    static_cast<void>(lcid);
    static_cast<void>(rGuidTypeInfo);
    static_cast<void>(ppRecInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_GetRecordInfoFromTypeInfo(void* pTypeInfo, void** ppRecInfo) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pTypeInfo);
    static_cast<void>(ppRecInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t koleaut32G_LHashValOfNameSys(std::uint32_t syskind, std::uint32_t lcid, const char16_t* szName) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(syskind);
    static_cast<void>(lcid);
    static_cast<void>(szName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t koleaut32G_LHashValOfNameSysA(std::uint32_t syskind, std::uint32_t lcid, const char* szName) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(syskind);
    static_cast<void>(lcid);
    static_cast<void>(szName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void koleaut32G_LPSAFEARRAY_UserFree(std::uint32_t* arg0, void* arg1) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* koleaut32G_LPSAFEARRAY_UserMarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t koleaut32G_LPSAFEARRAY_UserSize(std::uint32_t* arg0, std::uint32_t arg1, void* arg2) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* koleaut32G_LPSAFEARRAY_UserUnmarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_LoadRegTypeLib(const void* rguid, std::uint16_t wVerMajor, std::uint16_t wVerMinor, std::uint32_t lcid, void** pptlib) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(rguid);
    static_cast<void>(wVerMajor);
    static_cast<void>(wVerMinor);
    static_cast<void>(lcid);
    static_cast<void>(pptlib);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_LoadTypeLib(const char16_t* szFile, void** pptlib) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(szFile);
    static_cast<void>(pptlib);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_LoadTypeLibEx(const char16_t* szFile, std::uint64_t regkind, void** pptlib) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(szFile);
    static_cast<void>(regkind);
    static_cast<void>(pptlib);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t koleaut32G_OaBuildVersion() noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_QueryPathOfRegTypeLib(const void* guid, std::uint16_t wMaj, std::uint16_t wMin, std::uint32_t lcid, char16_t** lpbstrPathName) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(guid);
    static_cast<void>(wMaj);
    static_cast<void>(wMin);
    static_cast<void>(lcid);
    static_cast<void>(lpbstrPathName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_RegisterActiveObject(void* punk, const void* rclsid, std::uint32_t dwFlags, std::uint32_t* pdwRegister) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(punk);
    static_cast<void>(rclsid);
    static_cast<void>(dwFlags);
    static_cast<void>(pdwRegister);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_RegisterTypeLib(void* ptlib, const char16_t* szFullPath, const char16_t* szHelpDir) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ptlib);
    static_cast<void>(szFullPath);
    static_cast<void>(szHelpDir);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_RevokeActiveObject(std::uint32_t dwRegister, void* pvReserved) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dwRegister);
    static_cast<void>(pvReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArrayAccessData(void* psa, void** ppvData) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    static_cast<void>(ppvData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArrayAllocData(void* psa) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArrayAllocDescriptor(std::uint32_t cDims, void** ppsaOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cDims);
    static_cast<void>(ppsaOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArrayAllocDescriptorEx(std::uint16_t vt, std::uint32_t cDims, void** ppsaOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(vt);
    static_cast<void>(cDims);
    static_cast<void>(ppsaOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArrayCopy(void* psa, void** ppsaOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    static_cast<void>(ppsaOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArrayCopyData(void* psaSource, void* psaTarget) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psaSource);
    static_cast<void>(psaTarget);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* koleaut32G_SafeArrayCreate(std::uint16_t vt, std::uint32_t cDims, void* rgsabound) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(vt);
    static_cast<void>(cDims);
    static_cast<void>(rgsabound);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* koleaut32G_SafeArrayCreateEx(std::uint16_t vt, std::uint32_t cDims, void* rgsabound, void* pvExtra) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(vt);
    static_cast<void>(cDims);
    static_cast<void>(rgsabound);
    static_cast<void>(pvExtra);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* koleaut32G_SafeArrayCreateVector(std::uint16_t vt, std::int32_t lLbound, std::uint32_t cElements) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(vt);
    static_cast<void>(lLbound);
    static_cast<void>(cElements);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* koleaut32G_SafeArrayCreateVectorEx(std::uint16_t vt, std::int32_t lLbound, std::uint32_t cElements, void* pvExtra) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(vt);
    static_cast<void>(lLbound);
    static_cast<void>(cElements);
    static_cast<void>(pvExtra);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArrayDestroy(void* psa) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArrayDestroyData(void* psa) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArrayDestroyDescriptor(void* psa) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t koleaut32G_SafeArrayGetDim(void* psa) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArrayGetElement(void* psa, std::int32_t* rgIndices, void* pv) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    static_cast<void>(rgIndices);
    static_cast<void>(pv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t koleaut32G_SafeArrayGetElemsize(void* psa) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArrayGetIID(void* psa, void* pguid) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    static_cast<void>(pguid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArrayGetLBound(void* psa, std::uint32_t nDim, std::int32_t* plLbound) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    static_cast<void>(nDim);
    static_cast<void>(plLbound);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArrayGetRecordInfo(void* psa, void** prinfo) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    static_cast<void>(prinfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArrayGetUBound(void* psa, std::uint32_t nDim, std::int32_t* plUbound) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    static_cast<void>(nDim);
    static_cast<void>(plUbound);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArrayGetVartype(void* psa, std::uint16_t* pvt) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    static_cast<void>(pvt);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArrayLock(void* psa) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArrayPtrOfIndex(void* psa, std::int32_t* rgIndices, void** ppvData) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    static_cast<void>(rgIndices);
    static_cast<void>(ppvData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArrayPutElement(void* psa, std::int32_t* rgIndices, void* pv) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    static_cast<void>(rgIndices);
    static_cast<void>(pv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArrayRedim(void* psa, void* psaboundNew) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    static_cast<void>(psaboundNew);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArraySetIID(void* psa, const void* guid) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    static_cast<void>(guid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArraySetRecordInfo(void* psa, void* prinfo) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    static_cast<void>(prinfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArrayUnaccessData(void* psa) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SafeArrayUnlock(void* psa) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psa);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SetErrorInfo(std::uint32_t dwReserved, void* perrinfo) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dwReserved);
    static_cast<void>(perrinfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) char16_t* koleaut32G_SysAllocString(const char16_t* arg0) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char16_t* koleaut32G_SysAllocStringByteLen(const char* psz, std::uint32_t len) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(psz);
    static_cast<void>(len);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char16_t* koleaut32G_SysAllocStringLen(const char16_t* arg0, std::uint32_t arg1) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void koleaut32G_SysFreeString(char16_t* arg0) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SysReAllocString(char16_t** arg0, const char16_t* arg1) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SysReAllocStringLen(char16_t** arg0, const char16_t* arg1, std::uint32_t arg2) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t koleaut32G_SysStringByteLen(char16_t* bstr) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(bstr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t koleaut32G_SysStringLen(char16_t* arg0) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_SystemTimeToVariantTime(void* lpSystemTime, double* pvtime) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(lpSystemTime);
    static_cast<void>(pvtime);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_UnRegisterTypeLib(const void* libID, std::uint16_t wVerMajor, std::uint16_t wVerMinor, std::uint32_t lcid, std::uint32_t syskind) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(libID);
    static_cast<void>(wVerMajor);
    static_cast<void>(wVerMinor);
    static_cast<void>(lcid);
    static_cast<void>(syskind);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void koleaut32G_VARIANT_UserFree(std::uint32_t* arg0, void* arg1) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* koleaut32G_VARIANT_UserMarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t koleaut32G_VARIANT_UserSize(std::uint32_t* arg0, std::uint32_t arg1, void* arg2) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* koleaut32G_VARIANT_UserUnmarshal(std::uint32_t* arg0, std::uint8_t* arg1, void* arg2) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarAbs(void* pvarIn, void* pvarResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarIn);
    static_cast<void>(pvarResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarAdd(void* pvarLeft, void* pvarRight, void* pvarResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarLeft);
    static_cast<void>(pvarRight);
    static_cast<void>(pvarResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarAnd(void* pvarLeft, void* pvarRight, void* pvarResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarLeft);
    static_cast<void>(pvarRight);
    static_cast<void>(pvarResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBoolFromCy(std::int64_t cyIn, std::int16_t* pboolOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyIn);
    static_cast<void>(pboolOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBoolFromDate(double dateIn, std::int16_t* pboolOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dateIn);
    static_cast<void>(pboolOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBoolFromDec(void* pdecIn, std::int16_t* pboolOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecIn);
    static_cast<void>(pboolOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBoolFromDisp(void* pdispIn, std::uint32_t lcid, std::int16_t* pboolOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdispIn);
    static_cast<void>(lcid);
    static_cast<void>(pboolOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBoolFromI1(char cIn, std::int16_t* pboolOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cIn);
    static_cast<void>(pboolOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBoolFromI2(std::int16_t sIn, std::int16_t* pboolOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(sIn);
    static_cast<void>(pboolOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBoolFromI4(std::int32_t lIn, std::int16_t* pboolOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(lIn);
    static_cast<void>(pboolOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBoolFromI8(std::int64_t i64In, std::int16_t* pboolOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(i64In);
    static_cast<void>(pboolOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBoolFromR4(float fltIn, std::int16_t* pboolOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(fltIn);
    static_cast<void>(pboolOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBoolFromR8(double dblIn, std::int16_t* pboolOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dblIn);
    static_cast<void>(pboolOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBoolFromStr(const char16_t* strIn, std::uint32_t lcid, std::uint32_t dwFlags, std::int16_t* pboolOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(strIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pboolOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBoolFromUI1(std::uint8_t bIn, std::int16_t* pboolOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(bIn);
    static_cast<void>(pboolOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBoolFromUI2(std::uint16_t uiIn, std::int16_t* pboolOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(uiIn);
    static_cast<void>(pboolOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBoolFromUI4(std::uint32_t ulIn, std::int16_t* pboolOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ulIn);
    static_cast<void>(pboolOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBoolFromUI8(std::uint64_t i64In, std::int16_t* pboolOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(i64In);
    static_cast<void>(pboolOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBstrCat(char16_t* bstrLeft, char16_t* bstrRight, char16_t** pbstrResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(bstrLeft);
    static_cast<void>(bstrRight);
    static_cast<void>(pbstrResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBstrCmp(char16_t* bstrLeft, char16_t* bstrRight, std::uint32_t lcid, std::uint32_t dwFlags) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(bstrLeft);
    static_cast<void>(bstrRight);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBstrFromBool(std::int16_t boolIn, std::uint32_t lcid, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(boolIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBstrFromCy(std::int64_t cyIn, std::uint32_t lcid, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBstrFromDate(double dateIn, std::uint32_t lcid, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dateIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBstrFromDec(void* pdecIn, std::uint32_t lcid, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBstrFromDisp(void* pdispIn, std::uint32_t lcid, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdispIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBstrFromI1(char cIn, std::uint32_t lcid, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBstrFromI2(std::int16_t iVal, std::uint32_t lcid, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(iVal);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBstrFromI4(std::int32_t lIn, std::uint32_t lcid, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(lIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBstrFromI8(std::int64_t i64In, std::uint32_t lcid, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(i64In);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBstrFromR4(float fltIn, std::uint32_t lcid, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(fltIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBstrFromR8(double dblIn, std::uint32_t lcid, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dblIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBstrFromUI1(std::uint8_t bVal, std::uint32_t lcid, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(bVal);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBstrFromUI2(std::uint16_t uiIn, std::uint32_t lcid, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(uiIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBstrFromUI4(std::uint32_t ulIn, std::uint32_t lcid, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ulIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarBstrFromUI8(std::uint64_t ui64In, std::uint32_t lcid, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ui64In);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCat(void* pvarLeft, void* pvarRight, void* pvarResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarLeft);
    static_cast<void>(pvarRight);
    static_cast<void>(pvarResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCmp(void* pvarLeft, void* pvarRight, std::uint32_t lcid, std::uint32_t dwFlags) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarLeft);
    static_cast<void>(pvarRight);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyAbs(std::int64_t cyIn, std::int64_t* pcyResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyIn);
    static_cast<void>(pcyResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyAdd(std::int64_t cyLeft, std::int64_t cyRight, std::int64_t* pcyResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyLeft);
    static_cast<void>(cyRight);
    static_cast<void>(pcyResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyCmp(std::int64_t cyLeft, std::int64_t cyRight) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyLeft);
    static_cast<void>(cyRight);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyCmpR8(std::int64_t cyLeft, double dblRight) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyLeft);
    static_cast<void>(dblRight);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyFix(std::int64_t cyIn, std::int64_t* pcyResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyIn);
    static_cast<void>(pcyResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyFromBool(std::int16_t boolIn, std::int64_t* pcyOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(boolIn);
    static_cast<void>(pcyOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyFromDate(double dateIn, std::int64_t* pcyOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dateIn);
    static_cast<void>(pcyOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyFromDec(void* pdecIn, std::int64_t* pcyOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecIn);
    static_cast<void>(pcyOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyFromDisp(void* pdispIn, std::uint32_t lcid, std::int64_t* pcyOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdispIn);
    static_cast<void>(lcid);
    static_cast<void>(pcyOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyFromI1(char cIn, std::int64_t* pcyOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cIn);
    static_cast<void>(pcyOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyFromI2(std::int16_t sIn, std::int64_t* pcyOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(sIn);
    static_cast<void>(pcyOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyFromI4(std::int32_t lIn, std::int64_t* pcyOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(lIn);
    static_cast<void>(pcyOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyFromI8(std::int64_t i64In, std::int64_t* pcyOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(i64In);
    static_cast<void>(pcyOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyFromR4(float fltIn, std::int64_t* pcyOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(fltIn);
    static_cast<void>(pcyOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyFromR8(double dblIn, std::int64_t* pcyOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dblIn);
    static_cast<void>(pcyOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyFromStr(const char16_t* strIn, std::uint32_t lcid, std::uint32_t dwFlags, std::int64_t* pcyOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(strIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pcyOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyFromUI1(std::uint8_t bIn, std::int64_t* pcyOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(bIn);
    static_cast<void>(pcyOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyFromUI2(std::uint16_t uiIn, std::int64_t* pcyOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(uiIn);
    static_cast<void>(pcyOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyFromUI4(std::uint32_t ulIn, std::int64_t* pcyOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ulIn);
    static_cast<void>(pcyOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyFromUI8(std::uint64_t ui64In, std::int64_t* pcyOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ui64In);
    static_cast<void>(pcyOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyInt(std::int64_t cyIn, std::int64_t* pcyResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyIn);
    static_cast<void>(pcyResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyMul(std::int64_t cyLeft, std::int64_t cyRight, std::int64_t* pcyResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyLeft);
    static_cast<void>(cyRight);
    static_cast<void>(pcyResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyMulI4(std::int64_t cyLeft, std::int32_t lRight, std::int64_t* pcyResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyLeft);
    static_cast<void>(lRight);
    static_cast<void>(pcyResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyMulI8(std::int64_t cyLeft, std::int64_t lRight, std::int64_t* pcyResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyLeft);
    static_cast<void>(lRight);
    static_cast<void>(pcyResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyNeg(std::int64_t cyIn, std::int64_t* pcyResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyIn);
    static_cast<void>(pcyResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCyRound(std::int64_t cyIn, std::int32_t cDecimals, std::int64_t* pcyResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyIn);
    static_cast<void>(cDecimals);
    static_cast<void>(pcyResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarCySub(std::int64_t cyLeft, std::int64_t cyRight, std::int64_t* pcyResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyLeft);
    static_cast<void>(cyRight);
    static_cast<void>(pcyResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDateFromBool(std::int16_t boolIn, double* pdateOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(boolIn);
    static_cast<void>(pdateOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDateFromCy(std::int64_t cyIn, double* pdateOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyIn);
    static_cast<void>(pdateOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDateFromDec(void* pdecIn, double* pdateOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecIn);
    static_cast<void>(pdateOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDateFromDisp(void* pdispIn, std::uint32_t lcid, double* pdateOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdispIn);
    static_cast<void>(lcid);
    static_cast<void>(pdateOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDateFromI1(char cIn, double* pdateOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cIn);
    static_cast<void>(pdateOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDateFromI2(std::int16_t sIn, double* pdateOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(sIn);
    static_cast<void>(pdateOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDateFromI4(std::int32_t lIn, double* pdateOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(lIn);
    static_cast<void>(pdateOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDateFromI8(std::int64_t i64In, double* pdateOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(i64In);
    static_cast<void>(pdateOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDateFromR4(float fltIn, double* pdateOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(fltIn);
    static_cast<void>(pdateOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDateFromR8(double dblIn, double* pdateOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dblIn);
    static_cast<void>(pdateOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDateFromStr(const char16_t* strIn, std::uint32_t lcid, std::uint32_t dwFlags, double* pdateOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(strIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pdateOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDateFromUI1(std::uint8_t bIn, double* pdateOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(bIn);
    static_cast<void>(pdateOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDateFromUI2(std::uint16_t uiIn, double* pdateOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(uiIn);
    static_cast<void>(pdateOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDateFromUI4(std::uint32_t ulIn, double* pdateOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ulIn);
    static_cast<void>(pdateOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDateFromUI8(std::uint64_t ui64In, double* pdateOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ui64In);
    static_cast<void>(pdateOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDateFromUdate(void* pudateIn, std::uint32_t dwFlags, double* pdateOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pudateIn);
    static_cast<void>(dwFlags);
    static_cast<void>(pdateOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDateFromUdateEx(void* pudateIn, std::uint32_t lcid, std::uint32_t dwFlags, double* pdateOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pudateIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pdateOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecAbs(void* pdecIn, void* pdecResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecIn);
    static_cast<void>(pdecResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecAdd(void* pdecLeft, void* pdecRight, void* pdecResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecLeft);
    static_cast<void>(pdecRight);
    static_cast<void>(pdecResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecCmp(void* pdecLeft, void* pdecRight) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecLeft);
    static_cast<void>(pdecRight);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecCmpR8(void* pdecLeft, double dblRight) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecLeft);
    static_cast<void>(dblRight);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecDiv(void* pdecLeft, void* pdecRight, void* pdecResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecLeft);
    static_cast<void>(pdecRight);
    static_cast<void>(pdecResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecFix(void* pdecIn, void* pdecResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecIn);
    static_cast<void>(pdecResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecFromBool(std::int16_t boolIn, void* pdecOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(boolIn);
    static_cast<void>(pdecOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecFromCy(std::int64_t cyIn, void* pdecOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyIn);
    static_cast<void>(pdecOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecFromDate(double dateIn, void* pdecOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dateIn);
    static_cast<void>(pdecOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecFromDisp(void* pdispIn, std::uint32_t lcid, void* pdecOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdispIn);
    static_cast<void>(lcid);
    static_cast<void>(pdecOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecFromI1(char cIn, void* pdecOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cIn);
    static_cast<void>(pdecOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecFromI2(std::int16_t uiIn, void* pdecOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(uiIn);
    static_cast<void>(pdecOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecFromI4(std::int32_t lIn, void* pdecOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(lIn);
    static_cast<void>(pdecOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecFromI8(std::int64_t i64In, void* pdecOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(i64In);
    static_cast<void>(pdecOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecFromR4(float fltIn, void* pdecOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(fltIn);
    static_cast<void>(pdecOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecFromR8(double dblIn, void* pdecOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dblIn);
    static_cast<void>(pdecOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecFromStr(const char16_t* strIn, std::uint32_t lcid, std::uint32_t dwFlags, void* pdecOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(strIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pdecOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecFromUI1(std::uint8_t bIn, void* pdecOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(bIn);
    static_cast<void>(pdecOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecFromUI2(std::uint16_t uiIn, void* pdecOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(uiIn);
    static_cast<void>(pdecOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecFromUI4(std::uint32_t ulIn, void* pdecOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ulIn);
    static_cast<void>(pdecOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecFromUI8(std::uint64_t ui64In, void* pdecOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ui64In);
    static_cast<void>(pdecOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecInt(void* pdecIn, void* pdecResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecIn);
    static_cast<void>(pdecResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecMul(void* pdecLeft, void* pdecRight, void* pdecResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecLeft);
    static_cast<void>(pdecRight);
    static_cast<void>(pdecResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecNeg(void* pdecIn, void* pdecResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecIn);
    static_cast<void>(pdecResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecRound(void* pdecIn, std::int32_t cDecimals, void* pdecResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecIn);
    static_cast<void>(cDecimals);
    static_cast<void>(pdecResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDecSub(void* pdecLeft, void* pdecRight, void* pdecResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecLeft);
    static_cast<void>(pdecRight);
    static_cast<void>(pdecResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarDiv(void* pvarLeft, void* pvarRight, void* pvarResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarLeft);
    static_cast<void>(pvarRight);
    static_cast<void>(pvarResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarEqv(void* pvarLeft, void* pvarRight, void* pvarResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarLeft);
    static_cast<void>(pvarRight);
    static_cast<void>(pvarResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarFix(void* pvarIn, void* pvarResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarIn);
    static_cast<void>(pvarResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarFormat(void* pvarIn, char16_t* pstrFormat, std::int32_t iFirstDay, std::int32_t iFirstWeek, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarIn);
    static_cast<void>(pstrFormat);
    static_cast<void>(iFirstDay);
    static_cast<void>(iFirstWeek);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarFormatCurrency(void* pvarIn, std::int32_t iNumDig, std::int32_t iIncLead, std::int32_t iUseParens, std::int32_t iGroup, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarIn);
    static_cast<void>(iNumDig);
    static_cast<void>(iIncLead);
    static_cast<void>(iUseParens);
    static_cast<void>(iGroup);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarFormatDateTime(void* pvarIn, std::int32_t iNamedFormat, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarIn);
    static_cast<void>(iNamedFormat);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarFormatFromTokens(void* pvarIn, char16_t* pstrFormat, std::uint8_t* pbTokCur, std::uint32_t dwFlags, char16_t** pbstrOut, std::uint32_t lcid) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pvarIn);
    static_cast<void>(pstrFormat);
    static_cast<void>(pbTokCur);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    static_cast<void>(lcid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarFormatNumber(void* pvarIn, std::int32_t iNumDig, std::int32_t iIncLead, std::int32_t iUseParens, std::int32_t iGroup, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarIn);
    static_cast<void>(iNumDig);
    static_cast<void>(iIncLead);
    static_cast<void>(iUseParens);
    static_cast<void>(iGroup);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarFormatPercent(void* pvarIn, std::int32_t iNumDig, std::int32_t iIncLead, std::int32_t iUseParens, std::int32_t iGroup, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarIn);
    static_cast<void>(iNumDig);
    static_cast<void>(iIncLead);
    static_cast<void>(iUseParens);
    static_cast<void>(iGroup);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI1FromBool(std::int16_t boolIn, char* pcOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(boolIn);
    static_cast<void>(pcOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI1FromCy(std::int64_t cyIn, char* pcOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyIn);
    static_cast<void>(pcOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI1FromDate(double dateIn, char* pcOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dateIn);
    static_cast<void>(pcOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI1FromDec(void* pdecIn, char* pcOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecIn);
    static_cast<void>(pcOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI1FromDisp(void* pdispIn, std::uint32_t lcid, char* pcOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdispIn);
    static_cast<void>(lcid);
    static_cast<void>(pcOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI1FromI2(std::int16_t uiIn, char* pcOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(uiIn);
    static_cast<void>(pcOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI1FromI4(std::int32_t lIn, char* pcOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(lIn);
    static_cast<void>(pcOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI1FromI8(std::int64_t i64In, char* pcOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(i64In);
    static_cast<void>(pcOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI1FromR4(float fltIn, char* pcOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(fltIn);
    static_cast<void>(pcOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI1FromR8(double dblIn, char* pcOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dblIn);
    static_cast<void>(pcOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI1FromStr(const char16_t* strIn, std::uint32_t lcid, std::uint32_t dwFlags, char* pcOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(strIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pcOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI1FromUI1(std::uint8_t bIn, char* pcOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(bIn);
    static_cast<void>(pcOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI1FromUI2(std::uint16_t uiIn, char* pcOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(uiIn);
    static_cast<void>(pcOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI1FromUI4(std::uint32_t ulIn, char* pcOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ulIn);
    static_cast<void>(pcOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI1FromUI8(std::uint64_t i64In, char* pcOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(i64In);
    static_cast<void>(pcOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI2FromBool(std::int16_t boolIn, std::int16_t* psOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(boolIn);
    static_cast<void>(psOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI2FromCy(std::int64_t cyIn, std::int16_t* psOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyIn);
    static_cast<void>(psOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI2FromDate(double dateIn, std::int16_t* psOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dateIn);
    static_cast<void>(psOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI2FromDec(void* pdecIn, std::int16_t* psOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecIn);
    static_cast<void>(psOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI2FromDisp(void* pdispIn, std::uint32_t lcid, std::int16_t* psOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdispIn);
    static_cast<void>(lcid);
    static_cast<void>(psOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI2FromI1(char cIn, std::int16_t* psOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cIn);
    static_cast<void>(psOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI2FromI4(std::int32_t lIn, std::int16_t* psOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(lIn);
    static_cast<void>(psOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI2FromI8(std::int64_t i64In, std::int16_t* psOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(i64In);
    static_cast<void>(psOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI2FromR4(float fltIn, std::int16_t* psOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(fltIn);
    static_cast<void>(psOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI2FromR8(double dblIn, std::int16_t* psOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dblIn);
    static_cast<void>(psOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI2FromStr(const char16_t* strIn, std::uint32_t lcid, std::uint32_t dwFlags, std::int16_t* psOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(strIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(psOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI2FromUI1(std::uint8_t bIn, std::int16_t* psOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(bIn);
    static_cast<void>(psOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI2FromUI2(std::uint16_t uiIn, std::int16_t* psOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(uiIn);
    static_cast<void>(psOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI2FromUI4(std::uint32_t ulIn, std::int16_t* psOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ulIn);
    static_cast<void>(psOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI2FromUI8(std::uint64_t ui64In, std::int16_t* psOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ui64In);
    static_cast<void>(psOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI4FromBool(std::int16_t boolIn, std::int32_t* plOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(boolIn);
    static_cast<void>(plOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI4FromCy(std::int64_t cyIn, std::int32_t* plOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyIn);
    static_cast<void>(plOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI4FromDate(double dateIn, std::int32_t* plOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dateIn);
    static_cast<void>(plOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI4FromDec(void* pdecIn, std::int32_t* plOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecIn);
    static_cast<void>(plOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI4FromDisp(void* pdispIn, std::uint32_t lcid, std::int32_t* plOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdispIn);
    static_cast<void>(lcid);
    static_cast<void>(plOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI4FromI1(char cIn, std::int32_t* plOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cIn);
    static_cast<void>(plOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI4FromI2(std::int16_t sIn, std::int32_t* plOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(sIn);
    static_cast<void>(plOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI4FromI8(std::int64_t i64In, std::int32_t* plOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(i64In);
    static_cast<void>(plOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI4FromR4(float fltIn, std::int32_t* plOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(fltIn);
    static_cast<void>(plOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI4FromR8(double dblIn, std::int32_t* plOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dblIn);
    static_cast<void>(plOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI4FromStr(const char16_t* strIn, std::uint32_t lcid, std::uint32_t dwFlags, std::int32_t* plOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(strIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(plOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI4FromUI1(std::uint8_t bIn, std::int32_t* plOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(bIn);
    static_cast<void>(plOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI4FromUI2(std::uint16_t uiIn, std::int32_t* plOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(uiIn);
    static_cast<void>(plOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI4FromUI4(std::uint32_t ulIn, std::int32_t* plOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ulIn);
    static_cast<void>(plOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI4FromUI8(std::uint64_t ui64In, std::int32_t* plOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ui64In);
    static_cast<void>(plOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI8FromBool(std::int16_t boolIn, std::int64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(boolIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI8FromCy(std::int64_t cyIn, std::int64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI8FromDate(double dateIn, std::int64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dateIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI8FromDec(void* pdecIn, std::int64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI8FromDisp(void* pdispIn, std::uint32_t lcid, std::int64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdispIn);
    static_cast<void>(lcid);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI8FromI1(char cIn, std::int64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI8FromI2(std::int16_t sIn, std::int64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(sIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI8FromR4(float fltIn, std::int64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(fltIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI8FromR8(double dblIn, std::int64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dblIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI8FromStr(const char16_t* strIn, std::uint32_t lcid, std::uint32_t dwFlags, std::int64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(strIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI8FromUI1(std::uint8_t bIn, std::int64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(bIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI8FromUI2(std::uint16_t uiIn, std::int64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(uiIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI8FromUI4(std::uint32_t ulIn, std::int64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ulIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarI8FromUI8(std::uint64_t ui64In, std::int64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ui64In);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarIdiv(void* pvarLeft, void* pvarRight, void* pvarResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarLeft);
    static_cast<void>(pvarRight);
    static_cast<void>(pvarResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarImp(void* pvarLeft, void* pvarRight, void* pvarResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarLeft);
    static_cast<void>(pvarRight);
    static_cast<void>(pvarResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarInt(void* pvarIn, void* pvarResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarIn);
    static_cast<void>(pvarResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarMod(void* pvarLeft, void* pvarRight, void* pvarResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarLeft);
    static_cast<void>(pvarRight);
    static_cast<void>(pvarResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarMonthName(std::int32_t iMonth, std::int32_t fAbbrev, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(iMonth);
    static_cast<void>(fAbbrev);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarMul(void* pvarLeft, void* pvarRight, void* pvarResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarLeft);
    static_cast<void>(pvarRight);
    static_cast<void>(pvarResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarNeg(void* pvarIn, void* pvarResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarIn);
    static_cast<void>(pvarResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarNot(void* pvarIn, void* pvarResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarIn);
    static_cast<void>(pvarResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarNumFromParseNum(void* pnumprs, std::uint8_t* rgbDig, std::uint32_t dwVtBits, void* pvar) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pnumprs);
    static_cast<void>(rgbDig);
    static_cast<void>(dwVtBits);
    static_cast<void>(pvar);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarOr(void* pvarLeft, void* pvarRight, void* pvarResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarLeft);
    static_cast<void>(pvarRight);
    static_cast<void>(pvarResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarParseNumFromStr(const char16_t* strIn, std::uint32_t lcid, std::uint32_t dwFlags, void* pnumprs, std::uint8_t* rgbDig) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(strIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pnumprs);
    static_cast<void>(rgbDig);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarPow(void* pvarLeft, void* pvarRight, void* pvarResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarLeft);
    static_cast<void>(pvarRight);
    static_cast<void>(pvarResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR4CmpR8(float fltLeft, double dblRight) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(fltLeft);
    static_cast<void>(dblRight);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR4FromBool(std::int16_t boolIn, float* pfltOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(boolIn);
    static_cast<void>(pfltOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR4FromCy(std::int64_t cyIn, float* pfltOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyIn);
    static_cast<void>(pfltOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR4FromDate(double dateIn, float* pfltOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dateIn);
    static_cast<void>(pfltOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR4FromDec(void* pdecIn, float* pfltOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecIn);
    static_cast<void>(pfltOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR4FromDisp(void* pdispIn, std::uint32_t lcid, float* pfltOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdispIn);
    static_cast<void>(lcid);
    static_cast<void>(pfltOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR4FromI1(char cIn, float* pfltOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cIn);
    static_cast<void>(pfltOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR4FromI2(std::int16_t sIn, float* pfltOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(sIn);
    static_cast<void>(pfltOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR4FromI4(std::int32_t lIn, float* pfltOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(lIn);
    static_cast<void>(pfltOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR4FromI8(std::int64_t i64In, float* pfltOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(i64In);
    static_cast<void>(pfltOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR4FromR8(double dblIn, float* pfltOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dblIn);
    static_cast<void>(pfltOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR4FromStr(const char16_t* strIn, std::uint32_t lcid, std::uint32_t dwFlags, float* pfltOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(strIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pfltOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR4FromUI1(std::uint8_t bIn, float* pfltOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(bIn);
    static_cast<void>(pfltOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR4FromUI2(std::uint16_t uiIn, float* pfltOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(uiIn);
    static_cast<void>(pfltOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR4FromUI4(std::uint32_t ulIn, float* pfltOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ulIn);
    static_cast<void>(pfltOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR4FromUI8(std::uint64_t ui64In, float* pfltOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ui64In);
    static_cast<void>(pfltOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR8FromBool(std::int16_t boolIn, double* pdblOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(boolIn);
    static_cast<void>(pdblOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR8FromCy(std::int64_t cyIn, double* pdblOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyIn);
    static_cast<void>(pdblOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR8FromDate(double dateIn, double* pdblOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dateIn);
    static_cast<void>(pdblOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR8FromDec(void* pdecIn, double* pdblOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecIn);
    static_cast<void>(pdblOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR8FromDisp(void* pdispIn, std::uint32_t lcid, double* pdblOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdispIn);
    static_cast<void>(lcid);
    static_cast<void>(pdblOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR8FromI1(char cIn, double* pdblOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cIn);
    static_cast<void>(pdblOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR8FromI2(std::int16_t sIn, double* pdblOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(sIn);
    static_cast<void>(pdblOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR8FromI4(std::int32_t lIn, double* pdblOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(lIn);
    static_cast<void>(pdblOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR8FromI8(std::int64_t i64In, double* pdblOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(i64In);
    static_cast<void>(pdblOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR8FromR4(float fltIn, double* pdblOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(fltIn);
    static_cast<void>(pdblOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR8FromStr(const char16_t* strIn, std::uint32_t lcid, std::uint32_t dwFlags, double* pdblOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(strIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pdblOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR8FromUI1(std::uint8_t bIn, double* pdblOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(bIn);
    static_cast<void>(pdblOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR8FromUI2(std::uint16_t uiIn, double* pdblOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(uiIn);
    static_cast<void>(pdblOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR8FromUI4(std::uint32_t ulIn, double* pdblOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ulIn);
    static_cast<void>(pdblOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR8FromUI8(std::uint64_t ui64In, double* pdblOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ui64In);
    static_cast<void>(pdblOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR8Pow(double dblLeft, double dblRight, double* pdblResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dblLeft);
    static_cast<void>(dblRight);
    static_cast<void>(pdblResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarR8Round(double dblIn, std::int32_t cDecimals, double* pdblResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dblIn);
    static_cast<void>(cDecimals);
    static_cast<void>(pdblResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarRound(void* pvarIn, std::int32_t cDecimals, void* pvarResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarIn);
    static_cast<void>(cDecimals);
    static_cast<void>(pvarResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarSub(void* pvarLeft, void* pvarRight, void* pvarResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarLeft);
    static_cast<void>(pvarRight);
    static_cast<void>(pvarResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarTokenizeFormatString(char16_t* pstrFormat, std::uint8_t* rgbTok, std::int32_t cbTok, std::int32_t iFirstDay, std::int32_t iFirstWeek, std::uint32_t lcid, std::int32_t* pcbActual) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pstrFormat);
    static_cast<void>(rgbTok);
    static_cast<void>(cbTok);
    static_cast<void>(iFirstDay);
    static_cast<void>(iFirstWeek);
    static_cast<void>(lcid);
    static_cast<void>(pcbActual);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI1FromBool(std::int16_t boolIn, std::uint8_t* pbOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(boolIn);
    static_cast<void>(pbOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI1FromCy(std::int64_t cyIn, std::uint8_t* pbOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyIn);
    static_cast<void>(pbOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI1FromDate(double dateIn, std::uint8_t* pbOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dateIn);
    static_cast<void>(pbOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI1FromDec(void* pdecIn, std::uint8_t* pbOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecIn);
    static_cast<void>(pbOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI1FromDisp(void* pdispIn, std::uint32_t lcid, std::uint8_t* pbOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdispIn);
    static_cast<void>(lcid);
    static_cast<void>(pbOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI1FromI1(char cIn, std::uint8_t* pbOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cIn);
    static_cast<void>(pbOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI1FromI2(std::int16_t sIn, std::uint8_t* pbOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(sIn);
    static_cast<void>(pbOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI1FromI4(std::int32_t lIn, std::uint8_t* pbOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(lIn);
    static_cast<void>(pbOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI1FromI8(std::int64_t i64In, std::uint8_t* pbOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(i64In);
    static_cast<void>(pbOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI1FromR4(float fltIn, std::uint8_t* pbOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(fltIn);
    static_cast<void>(pbOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI1FromR8(double dblIn, std::uint8_t* pbOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dblIn);
    static_cast<void>(pbOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI1FromStr(const char16_t* strIn, std::uint32_t lcid, std::uint32_t dwFlags, std::uint8_t* pbOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(strIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pbOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI1FromUI2(std::uint16_t uiIn, std::uint8_t* pbOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(uiIn);
    static_cast<void>(pbOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI1FromUI4(std::uint32_t ulIn, std::uint8_t* pbOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ulIn);
    static_cast<void>(pbOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI1FromUI8(std::uint64_t ui64In, std::uint8_t* pbOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ui64In);
    static_cast<void>(pbOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI2FromBool(std::int16_t boolIn, std::uint16_t* puiOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(boolIn);
    static_cast<void>(puiOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI2FromCy(std::int64_t cyIn, std::uint16_t* puiOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyIn);
    static_cast<void>(puiOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI2FromDate(double dateIn, std::uint16_t* puiOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dateIn);
    static_cast<void>(puiOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI2FromDec(void* pdecIn, std::uint16_t* puiOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecIn);
    static_cast<void>(puiOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI2FromDisp(void* pdispIn, std::uint32_t lcid, std::uint16_t* puiOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdispIn);
    static_cast<void>(lcid);
    static_cast<void>(puiOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI2FromI1(char cIn, std::uint16_t* puiOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cIn);
    static_cast<void>(puiOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI2FromI2(std::int16_t uiIn, std::uint16_t* puiOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(uiIn);
    static_cast<void>(puiOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI2FromI4(std::int32_t lIn, std::uint16_t* puiOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(lIn);
    static_cast<void>(puiOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI2FromI8(std::int64_t i64In, std::uint16_t* puiOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(i64In);
    static_cast<void>(puiOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI2FromR4(float fltIn, std::uint16_t* puiOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(fltIn);
    static_cast<void>(puiOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI2FromR8(double dblIn, std::uint16_t* puiOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dblIn);
    static_cast<void>(puiOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI2FromStr(const char16_t* strIn, std::uint32_t lcid, std::uint32_t dwFlags, std::uint16_t* puiOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(strIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(puiOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI2FromUI1(std::uint8_t bIn, std::uint16_t* puiOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(bIn);
    static_cast<void>(puiOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI2FromUI4(std::uint32_t ulIn, std::uint16_t* puiOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ulIn);
    static_cast<void>(puiOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI2FromUI8(std::uint64_t i64In, std::uint16_t* puiOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(i64In);
    static_cast<void>(puiOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI4FromBool(std::int16_t boolIn, std::uint32_t* pulOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(boolIn);
    static_cast<void>(pulOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI4FromCy(std::int64_t cyIn, std::uint32_t* pulOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyIn);
    static_cast<void>(pulOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI4FromDate(double dateIn, std::uint32_t* pulOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dateIn);
    static_cast<void>(pulOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI4FromDec(void* pdecIn, std::uint32_t* pulOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecIn);
    static_cast<void>(pulOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI4FromDisp(void* pdispIn, std::uint32_t lcid, std::uint32_t* pulOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdispIn);
    static_cast<void>(lcid);
    static_cast<void>(pulOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI4FromI1(char cIn, std::uint32_t* pulOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cIn);
    static_cast<void>(pulOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI4FromI2(std::int16_t uiIn, std::uint32_t* pulOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(uiIn);
    static_cast<void>(pulOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI4FromI4(std::int32_t lIn, std::uint32_t* pulOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(lIn);
    static_cast<void>(pulOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI4FromI8(std::int64_t i64In, std::uint32_t* plOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(i64In);
    static_cast<void>(plOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI4FromR4(float fltIn, std::uint32_t* pulOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(fltIn);
    static_cast<void>(pulOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI4FromR8(double dblIn, std::uint32_t* pulOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dblIn);
    static_cast<void>(pulOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI4FromStr(const char16_t* strIn, std::uint32_t lcid, std::uint32_t dwFlags, std::uint32_t* pulOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(strIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pulOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI4FromUI1(std::uint8_t bIn, std::uint32_t* pulOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(bIn);
    static_cast<void>(pulOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI4FromUI2(std::uint16_t uiIn, std::uint32_t* pulOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(uiIn);
    static_cast<void>(pulOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI4FromUI8(std::uint64_t ui64In, std::uint32_t* plOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ui64In);
    static_cast<void>(plOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI8FromBool(std::int16_t boolIn, std::uint64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(boolIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI8FromCy(std::int64_t cyIn, std::uint64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cyIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI8FromDate(double dateIn, std::uint64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dateIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI8FromDec(void* pdecIn, std::uint64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdecIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI8FromDisp(void* pdispIn, std::uint32_t lcid, std::uint64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pdispIn);
    static_cast<void>(lcid);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI8FromI1(char cIn, std::uint64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(cIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI8FromI2(std::int16_t sIn, std::uint64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(sIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI8FromI8(std::int64_t ui64In, std::uint64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ui64In);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI8FromR4(float fltIn, std::uint64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(fltIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI8FromR8(double dblIn, std::uint64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dblIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI8FromStr(const char16_t* strIn, std::uint32_t lcid, std::uint32_t dwFlags, std::uint64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(strIn);
    static_cast<void>(lcid);
    static_cast<void>(dwFlags);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI8FromUI1(std::uint8_t bIn, std::uint64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(bIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI8FromUI2(std::uint16_t uiIn, std::uint64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(uiIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUI8FromUI4(std::uint32_t ulIn, std::uint64_t* pi64Out) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(ulIn);
    static_cast<void>(pi64Out);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarUdateFromDate(double dateIn, std::uint32_t dwFlags, void* pudateOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(dateIn);
    static_cast<void>(dwFlags);
    static_cast<void>(pudateOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarWeekdayName(std::int32_t iWeekday, std::int32_t fAbbrev, std::int32_t iFirstDay, std::uint32_t dwFlags, char16_t** pbstrOut) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(iWeekday);
    static_cast<void>(fAbbrev);
    static_cast<void>(iFirstDay);
    static_cast<void>(dwFlags);
    static_cast<void>(pbstrOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VarXor(void* pvarLeft, void* pvarRight, void* pvarResult) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarLeft);
    static_cast<void>(pvarRight);
    static_cast<void>(pvarResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VariantChangeType(void* pvargDest, void* pvarSrc, std::uint16_t wFlags, std::uint16_t vt) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvargDest);
    static_cast<void>(pvarSrc);
    static_cast<void>(wFlags);
    static_cast<void>(vt);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VariantChangeTypeEx(void* pvargDest, void* pvarSrc, std::uint32_t lcid, std::uint16_t wFlags, std::uint16_t vt) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvargDest);
    static_cast<void>(pvarSrc);
    static_cast<void>(lcid);
    static_cast<void>(wFlags);
    static_cast<void>(vt);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VariantClear(void* pvarg) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarg);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VariantCopy(void* pvargDest, void* pvargSrc) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvargDest);
    static_cast<void>(pvargSrc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VariantCopyInd(void* pvarDest, void* pvargSrc) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarDest);
    static_cast<void>(pvargSrc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void koleaut32G_VariantInit(void* pvarg) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(pvarg);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VariantTimeToDosDateTime(double vtime, std::uint16_t* pwDosDate, std::uint16_t* pwDosTime) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(vtime);
    static_cast<void>(pwDosDate);
    static_cast<void>(pwDosTime);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VariantTimeToSystemTime(double vtime, void* lpSystemTime) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(vtime);
    static_cast<void>(lpSystemTime);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t koleaut32G_VectorFromBstr(char16_t* bstr, void** ppsa) noexcept {
    // Refused: the OLE automation library.
    //
    // the call belongs to the automation type library support this runtime
    // does not carry
    static_cast<void>(bstr);
    static_cast<void>(ppsa);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_oleaut32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("BSTR_UserFree", reinterpret_cast<void*>(&koleaut32G_BSTR_UserFree));
    e("BSTR_UserMarshal", reinterpret_cast<void*>(&koleaut32G_BSTR_UserMarshal));
    e("BSTR_UserSize", reinterpret_cast<void*>(&koleaut32G_BSTR_UserSize));
    e("BSTR_UserUnmarshal", reinterpret_cast<void*>(&koleaut32G_BSTR_UserUnmarshal));
    e("BstrFromVector", reinterpret_cast<void*>(&koleaut32G_BstrFromVector));
    e("ClearCustData", reinterpret_cast<void*>(&koleaut32G_ClearCustData));
    e("CreateDispTypeInfo", reinterpret_cast<void*>(&koleaut32G_CreateDispTypeInfo));
    e("CreateErrorInfo", reinterpret_cast<void*>(&koleaut32G_CreateErrorInfo));
    e("CreateStdDispatch", reinterpret_cast<void*>(&koleaut32G_CreateStdDispatch));
    e("CreateTypeLib", reinterpret_cast<void*>(&koleaut32G_CreateTypeLib));
    e("CreateTypeLib2", reinterpret_cast<void*>(&koleaut32G_CreateTypeLib2));
    e("DispCallFunc", reinterpret_cast<void*>(&koleaut32G_DispCallFunc));
    e("DispGetIDsOfNames", reinterpret_cast<void*>(&koleaut32G_DispGetIDsOfNames));
    e("DispGetParam", reinterpret_cast<void*>(&koleaut32G_DispGetParam));
    e("DispInvoke", reinterpret_cast<void*>(&koleaut32G_DispInvoke));
    e("DllCanUnloadNow", reinterpret_cast<void*>(&koleaut32G_DllCanUnloadNow));
    e("DllGetClassObject", reinterpret_cast<void*>(&koleaut32G_DllGetClassObject));
    e("DosDateTimeToVariantTime", reinterpret_cast<void*>(&koleaut32G_DosDateTimeToVariantTime));
    e("GetActiveObject", reinterpret_cast<void*>(&koleaut32G_GetActiveObject));
    e("GetAltMonthNames", reinterpret_cast<void*>(&koleaut32G_GetAltMonthNames));
    e("GetErrorInfo", reinterpret_cast<void*>(&koleaut32G_GetErrorInfo));
    e("GetRecordInfoFromGuids", reinterpret_cast<void*>(&koleaut32G_GetRecordInfoFromGuids));
    e("GetRecordInfoFromTypeInfo", reinterpret_cast<void*>(&koleaut32G_GetRecordInfoFromTypeInfo));
    e("LHashValOfNameSys", reinterpret_cast<void*>(&koleaut32G_LHashValOfNameSys));
    e("LHashValOfNameSysA", reinterpret_cast<void*>(&koleaut32G_LHashValOfNameSysA));
    e("LPSAFEARRAY_UserFree", reinterpret_cast<void*>(&koleaut32G_LPSAFEARRAY_UserFree));
    e("LPSAFEARRAY_UserMarshal", reinterpret_cast<void*>(&koleaut32G_LPSAFEARRAY_UserMarshal));
    e("LPSAFEARRAY_UserSize", reinterpret_cast<void*>(&koleaut32G_LPSAFEARRAY_UserSize));
    e("LPSAFEARRAY_UserUnmarshal", reinterpret_cast<void*>(&koleaut32G_LPSAFEARRAY_UserUnmarshal));
    e("LoadRegTypeLib", reinterpret_cast<void*>(&koleaut32G_LoadRegTypeLib));
    e("LoadTypeLib", reinterpret_cast<void*>(&koleaut32G_LoadTypeLib));
    e("LoadTypeLibEx", reinterpret_cast<void*>(&koleaut32G_LoadTypeLibEx));
    e("OaBuildVersion", reinterpret_cast<void*>(&koleaut32G_OaBuildVersion));
    e("QueryPathOfRegTypeLib", reinterpret_cast<void*>(&koleaut32G_QueryPathOfRegTypeLib));
    e("RegisterActiveObject", reinterpret_cast<void*>(&koleaut32G_RegisterActiveObject));
    e("RegisterTypeLib", reinterpret_cast<void*>(&koleaut32G_RegisterTypeLib));
    e("RevokeActiveObject", reinterpret_cast<void*>(&koleaut32G_RevokeActiveObject));
    e("SafeArrayAccessData", reinterpret_cast<void*>(&koleaut32G_SafeArrayAccessData));
    e("SafeArrayAllocData", reinterpret_cast<void*>(&koleaut32G_SafeArrayAllocData));
    e("SafeArrayAllocDescriptor", reinterpret_cast<void*>(&koleaut32G_SafeArrayAllocDescriptor));
    e("SafeArrayAllocDescriptorEx", reinterpret_cast<void*>(&koleaut32G_SafeArrayAllocDescriptorEx));
    e("SafeArrayCopy", reinterpret_cast<void*>(&koleaut32G_SafeArrayCopy));
    e("SafeArrayCopyData", reinterpret_cast<void*>(&koleaut32G_SafeArrayCopyData));
    e("SafeArrayCreate", reinterpret_cast<void*>(&koleaut32G_SafeArrayCreate));
    e("SafeArrayCreateEx", reinterpret_cast<void*>(&koleaut32G_SafeArrayCreateEx));
    e("SafeArrayCreateVector", reinterpret_cast<void*>(&koleaut32G_SafeArrayCreateVector));
    e("SafeArrayCreateVectorEx", reinterpret_cast<void*>(&koleaut32G_SafeArrayCreateVectorEx));
    e("SafeArrayDestroy", reinterpret_cast<void*>(&koleaut32G_SafeArrayDestroy));
    e("SafeArrayDestroyData", reinterpret_cast<void*>(&koleaut32G_SafeArrayDestroyData));
    e("SafeArrayDestroyDescriptor", reinterpret_cast<void*>(&koleaut32G_SafeArrayDestroyDescriptor));
    e("SafeArrayGetDim", reinterpret_cast<void*>(&koleaut32G_SafeArrayGetDim));
    e("SafeArrayGetElement", reinterpret_cast<void*>(&koleaut32G_SafeArrayGetElement));
    e("SafeArrayGetElemsize", reinterpret_cast<void*>(&koleaut32G_SafeArrayGetElemsize));
    e("SafeArrayGetIID", reinterpret_cast<void*>(&koleaut32G_SafeArrayGetIID));
    e("SafeArrayGetLBound", reinterpret_cast<void*>(&koleaut32G_SafeArrayGetLBound));
    e("SafeArrayGetRecordInfo", reinterpret_cast<void*>(&koleaut32G_SafeArrayGetRecordInfo));
    e("SafeArrayGetUBound", reinterpret_cast<void*>(&koleaut32G_SafeArrayGetUBound));
    e("SafeArrayGetVartype", reinterpret_cast<void*>(&koleaut32G_SafeArrayGetVartype));
    e("SafeArrayLock", reinterpret_cast<void*>(&koleaut32G_SafeArrayLock));
    e("SafeArrayPtrOfIndex", reinterpret_cast<void*>(&koleaut32G_SafeArrayPtrOfIndex));
    e("SafeArrayPutElement", reinterpret_cast<void*>(&koleaut32G_SafeArrayPutElement));
    e("SafeArrayRedim", reinterpret_cast<void*>(&koleaut32G_SafeArrayRedim));
    e("SafeArraySetIID", reinterpret_cast<void*>(&koleaut32G_SafeArraySetIID));
    e("SafeArraySetRecordInfo", reinterpret_cast<void*>(&koleaut32G_SafeArraySetRecordInfo));
    e("SafeArrayUnaccessData", reinterpret_cast<void*>(&koleaut32G_SafeArrayUnaccessData));
    e("SafeArrayUnlock", reinterpret_cast<void*>(&koleaut32G_SafeArrayUnlock));
    e("SetErrorInfo", reinterpret_cast<void*>(&koleaut32G_SetErrorInfo));
    e("SysAllocString", reinterpret_cast<void*>(&koleaut32G_SysAllocString));
    e("SysAllocStringByteLen", reinterpret_cast<void*>(&koleaut32G_SysAllocStringByteLen));
    e("SysAllocStringLen", reinterpret_cast<void*>(&koleaut32G_SysAllocStringLen));
    e("SysFreeString", reinterpret_cast<void*>(&koleaut32G_SysFreeString));
    e("SysReAllocString", reinterpret_cast<void*>(&koleaut32G_SysReAllocString));
    e("SysReAllocStringLen", reinterpret_cast<void*>(&koleaut32G_SysReAllocStringLen));
    e("SysStringByteLen", reinterpret_cast<void*>(&koleaut32G_SysStringByteLen));
    e("SysStringLen", reinterpret_cast<void*>(&koleaut32G_SysStringLen));
    e("SystemTimeToVariantTime", reinterpret_cast<void*>(&koleaut32G_SystemTimeToVariantTime));
    e("UnRegisterTypeLib", reinterpret_cast<void*>(&koleaut32G_UnRegisterTypeLib));
    e("VARIANT_UserFree", reinterpret_cast<void*>(&koleaut32G_VARIANT_UserFree));
    e("VARIANT_UserMarshal", reinterpret_cast<void*>(&koleaut32G_VARIANT_UserMarshal));
    e("VARIANT_UserSize", reinterpret_cast<void*>(&koleaut32G_VARIANT_UserSize));
    e("VARIANT_UserUnmarshal", reinterpret_cast<void*>(&koleaut32G_VARIANT_UserUnmarshal));
    e("VarAbs", reinterpret_cast<void*>(&koleaut32G_VarAbs));
    e("VarAdd", reinterpret_cast<void*>(&koleaut32G_VarAdd));
    e("VarAnd", reinterpret_cast<void*>(&koleaut32G_VarAnd));
    e("VarBoolFromCy", reinterpret_cast<void*>(&koleaut32G_VarBoolFromCy));
    e("VarBoolFromDate", reinterpret_cast<void*>(&koleaut32G_VarBoolFromDate));
    e("VarBoolFromDec", reinterpret_cast<void*>(&koleaut32G_VarBoolFromDec));
    e("VarBoolFromDisp", reinterpret_cast<void*>(&koleaut32G_VarBoolFromDisp));
    e("VarBoolFromI1", reinterpret_cast<void*>(&koleaut32G_VarBoolFromI1));
    e("VarBoolFromI2", reinterpret_cast<void*>(&koleaut32G_VarBoolFromI2));
    e("VarBoolFromI4", reinterpret_cast<void*>(&koleaut32G_VarBoolFromI4));
    e("VarBoolFromI8", reinterpret_cast<void*>(&koleaut32G_VarBoolFromI8));
    e("VarBoolFromR4", reinterpret_cast<void*>(&koleaut32G_VarBoolFromR4));
    e("VarBoolFromR8", reinterpret_cast<void*>(&koleaut32G_VarBoolFromR8));
    e("VarBoolFromStr", reinterpret_cast<void*>(&koleaut32G_VarBoolFromStr));
    e("VarBoolFromUI1", reinterpret_cast<void*>(&koleaut32G_VarBoolFromUI1));
    e("VarBoolFromUI2", reinterpret_cast<void*>(&koleaut32G_VarBoolFromUI2));
    e("VarBoolFromUI4", reinterpret_cast<void*>(&koleaut32G_VarBoolFromUI4));
    e("VarBoolFromUI8", reinterpret_cast<void*>(&koleaut32G_VarBoolFromUI8));
    e("VarBstrCat", reinterpret_cast<void*>(&koleaut32G_VarBstrCat));
    e("VarBstrCmp", reinterpret_cast<void*>(&koleaut32G_VarBstrCmp));
    e("VarBstrFromBool", reinterpret_cast<void*>(&koleaut32G_VarBstrFromBool));
    e("VarBstrFromCy", reinterpret_cast<void*>(&koleaut32G_VarBstrFromCy));
    e("VarBstrFromDate", reinterpret_cast<void*>(&koleaut32G_VarBstrFromDate));
    e("VarBstrFromDec", reinterpret_cast<void*>(&koleaut32G_VarBstrFromDec));
    e("VarBstrFromDisp", reinterpret_cast<void*>(&koleaut32G_VarBstrFromDisp));
    e("VarBstrFromI1", reinterpret_cast<void*>(&koleaut32G_VarBstrFromI1));
    e("VarBstrFromI2", reinterpret_cast<void*>(&koleaut32G_VarBstrFromI2));
    e("VarBstrFromI4", reinterpret_cast<void*>(&koleaut32G_VarBstrFromI4));
    e("VarBstrFromI8", reinterpret_cast<void*>(&koleaut32G_VarBstrFromI8));
    e("VarBstrFromR4", reinterpret_cast<void*>(&koleaut32G_VarBstrFromR4));
    e("VarBstrFromR8", reinterpret_cast<void*>(&koleaut32G_VarBstrFromR8));
    e("VarBstrFromUI1", reinterpret_cast<void*>(&koleaut32G_VarBstrFromUI1));
    e("VarBstrFromUI2", reinterpret_cast<void*>(&koleaut32G_VarBstrFromUI2));
    e("VarBstrFromUI4", reinterpret_cast<void*>(&koleaut32G_VarBstrFromUI4));
    e("VarBstrFromUI8", reinterpret_cast<void*>(&koleaut32G_VarBstrFromUI8));
    e("VarCat", reinterpret_cast<void*>(&koleaut32G_VarCat));
    e("VarCmp", reinterpret_cast<void*>(&koleaut32G_VarCmp));
    e("VarCyAbs", reinterpret_cast<void*>(&koleaut32G_VarCyAbs));
    e("VarCyAdd", reinterpret_cast<void*>(&koleaut32G_VarCyAdd));
    e("VarCyCmp", reinterpret_cast<void*>(&koleaut32G_VarCyCmp));
    e("VarCyCmpR8", reinterpret_cast<void*>(&koleaut32G_VarCyCmpR8));
    e("VarCyFix", reinterpret_cast<void*>(&koleaut32G_VarCyFix));
    e("VarCyFromBool", reinterpret_cast<void*>(&koleaut32G_VarCyFromBool));
    e("VarCyFromDate", reinterpret_cast<void*>(&koleaut32G_VarCyFromDate));
    e("VarCyFromDec", reinterpret_cast<void*>(&koleaut32G_VarCyFromDec));
    e("VarCyFromDisp", reinterpret_cast<void*>(&koleaut32G_VarCyFromDisp));
    e("VarCyFromI1", reinterpret_cast<void*>(&koleaut32G_VarCyFromI1));
    e("VarCyFromI2", reinterpret_cast<void*>(&koleaut32G_VarCyFromI2));
    e("VarCyFromI4", reinterpret_cast<void*>(&koleaut32G_VarCyFromI4));
    e("VarCyFromI8", reinterpret_cast<void*>(&koleaut32G_VarCyFromI8));
    e("VarCyFromR4", reinterpret_cast<void*>(&koleaut32G_VarCyFromR4));
    e("VarCyFromR8", reinterpret_cast<void*>(&koleaut32G_VarCyFromR8));
    e("VarCyFromStr", reinterpret_cast<void*>(&koleaut32G_VarCyFromStr));
    e("VarCyFromUI1", reinterpret_cast<void*>(&koleaut32G_VarCyFromUI1));
    e("VarCyFromUI2", reinterpret_cast<void*>(&koleaut32G_VarCyFromUI2));
    e("VarCyFromUI4", reinterpret_cast<void*>(&koleaut32G_VarCyFromUI4));
    e("VarCyFromUI8", reinterpret_cast<void*>(&koleaut32G_VarCyFromUI8));
    e("VarCyInt", reinterpret_cast<void*>(&koleaut32G_VarCyInt));
    e("VarCyMul", reinterpret_cast<void*>(&koleaut32G_VarCyMul));
    e("VarCyMulI4", reinterpret_cast<void*>(&koleaut32G_VarCyMulI4));
    e("VarCyMulI8", reinterpret_cast<void*>(&koleaut32G_VarCyMulI8));
    e("VarCyNeg", reinterpret_cast<void*>(&koleaut32G_VarCyNeg));
    e("VarCyRound", reinterpret_cast<void*>(&koleaut32G_VarCyRound));
    e("VarCySub", reinterpret_cast<void*>(&koleaut32G_VarCySub));
    e("VarDateFromBool", reinterpret_cast<void*>(&koleaut32G_VarDateFromBool));
    e("VarDateFromCy", reinterpret_cast<void*>(&koleaut32G_VarDateFromCy));
    e("VarDateFromDec", reinterpret_cast<void*>(&koleaut32G_VarDateFromDec));
    e("VarDateFromDisp", reinterpret_cast<void*>(&koleaut32G_VarDateFromDisp));
    e("VarDateFromI1", reinterpret_cast<void*>(&koleaut32G_VarDateFromI1));
    e("VarDateFromI2", reinterpret_cast<void*>(&koleaut32G_VarDateFromI2));
    e("VarDateFromI4", reinterpret_cast<void*>(&koleaut32G_VarDateFromI4));
    e("VarDateFromI8", reinterpret_cast<void*>(&koleaut32G_VarDateFromI8));
    e("VarDateFromR4", reinterpret_cast<void*>(&koleaut32G_VarDateFromR4));
    e("VarDateFromR8", reinterpret_cast<void*>(&koleaut32G_VarDateFromR8));
    e("VarDateFromStr", reinterpret_cast<void*>(&koleaut32G_VarDateFromStr));
    e("VarDateFromUI1", reinterpret_cast<void*>(&koleaut32G_VarDateFromUI1));
    e("VarDateFromUI2", reinterpret_cast<void*>(&koleaut32G_VarDateFromUI2));
    e("VarDateFromUI4", reinterpret_cast<void*>(&koleaut32G_VarDateFromUI4));
    e("VarDateFromUI8", reinterpret_cast<void*>(&koleaut32G_VarDateFromUI8));
    e("VarDateFromUdate", reinterpret_cast<void*>(&koleaut32G_VarDateFromUdate));
    e("VarDateFromUdateEx", reinterpret_cast<void*>(&koleaut32G_VarDateFromUdateEx));
    e("VarDecAbs", reinterpret_cast<void*>(&koleaut32G_VarDecAbs));
    e("VarDecAdd", reinterpret_cast<void*>(&koleaut32G_VarDecAdd));
    e("VarDecCmp", reinterpret_cast<void*>(&koleaut32G_VarDecCmp));
    e("VarDecCmpR8", reinterpret_cast<void*>(&koleaut32G_VarDecCmpR8));
    e("VarDecDiv", reinterpret_cast<void*>(&koleaut32G_VarDecDiv));
    e("VarDecFix", reinterpret_cast<void*>(&koleaut32G_VarDecFix));
    e("VarDecFromBool", reinterpret_cast<void*>(&koleaut32G_VarDecFromBool));
    e("VarDecFromCy", reinterpret_cast<void*>(&koleaut32G_VarDecFromCy));
    e("VarDecFromDate", reinterpret_cast<void*>(&koleaut32G_VarDecFromDate));
    e("VarDecFromDisp", reinterpret_cast<void*>(&koleaut32G_VarDecFromDisp));
    e("VarDecFromI1", reinterpret_cast<void*>(&koleaut32G_VarDecFromI1));
    e("VarDecFromI2", reinterpret_cast<void*>(&koleaut32G_VarDecFromI2));
    e("VarDecFromI4", reinterpret_cast<void*>(&koleaut32G_VarDecFromI4));
    e("VarDecFromI8", reinterpret_cast<void*>(&koleaut32G_VarDecFromI8));
    e("VarDecFromR4", reinterpret_cast<void*>(&koleaut32G_VarDecFromR4));
    e("VarDecFromR8", reinterpret_cast<void*>(&koleaut32G_VarDecFromR8));
    e("VarDecFromStr", reinterpret_cast<void*>(&koleaut32G_VarDecFromStr));
    e("VarDecFromUI1", reinterpret_cast<void*>(&koleaut32G_VarDecFromUI1));
    e("VarDecFromUI2", reinterpret_cast<void*>(&koleaut32G_VarDecFromUI2));
    e("VarDecFromUI4", reinterpret_cast<void*>(&koleaut32G_VarDecFromUI4));
    e("VarDecFromUI8", reinterpret_cast<void*>(&koleaut32G_VarDecFromUI8));
    e("VarDecInt", reinterpret_cast<void*>(&koleaut32G_VarDecInt));
    e("VarDecMul", reinterpret_cast<void*>(&koleaut32G_VarDecMul));
    e("VarDecNeg", reinterpret_cast<void*>(&koleaut32G_VarDecNeg));
    e("VarDecRound", reinterpret_cast<void*>(&koleaut32G_VarDecRound));
    e("VarDecSub", reinterpret_cast<void*>(&koleaut32G_VarDecSub));
    e("VarDiv", reinterpret_cast<void*>(&koleaut32G_VarDiv));
    e("VarEqv", reinterpret_cast<void*>(&koleaut32G_VarEqv));
    e("VarFix", reinterpret_cast<void*>(&koleaut32G_VarFix));
    e("VarFormat", reinterpret_cast<void*>(&koleaut32G_VarFormat));
    e("VarFormatCurrency", reinterpret_cast<void*>(&koleaut32G_VarFormatCurrency));
    e("VarFormatDateTime", reinterpret_cast<void*>(&koleaut32G_VarFormatDateTime));
    e("VarFormatFromTokens", reinterpret_cast<void*>(&koleaut32G_VarFormatFromTokens));
    e("VarFormatNumber", reinterpret_cast<void*>(&koleaut32G_VarFormatNumber));
    e("VarFormatPercent", reinterpret_cast<void*>(&koleaut32G_VarFormatPercent));
    e("VarI1FromBool", reinterpret_cast<void*>(&koleaut32G_VarI1FromBool));
    e("VarI1FromCy", reinterpret_cast<void*>(&koleaut32G_VarI1FromCy));
    e("VarI1FromDate", reinterpret_cast<void*>(&koleaut32G_VarI1FromDate));
    e("VarI1FromDec", reinterpret_cast<void*>(&koleaut32G_VarI1FromDec));
    e("VarI1FromDisp", reinterpret_cast<void*>(&koleaut32G_VarI1FromDisp));
    e("VarI1FromI2", reinterpret_cast<void*>(&koleaut32G_VarI1FromI2));
    e("VarI1FromI4", reinterpret_cast<void*>(&koleaut32G_VarI1FromI4));
    e("VarI1FromI8", reinterpret_cast<void*>(&koleaut32G_VarI1FromI8));
    e("VarI1FromR4", reinterpret_cast<void*>(&koleaut32G_VarI1FromR4));
    e("VarI1FromR8", reinterpret_cast<void*>(&koleaut32G_VarI1FromR8));
    e("VarI1FromStr", reinterpret_cast<void*>(&koleaut32G_VarI1FromStr));
    e("VarI1FromUI1", reinterpret_cast<void*>(&koleaut32G_VarI1FromUI1));
    e("VarI1FromUI2", reinterpret_cast<void*>(&koleaut32G_VarI1FromUI2));
    e("VarI1FromUI4", reinterpret_cast<void*>(&koleaut32G_VarI1FromUI4));
    e("VarI1FromUI8", reinterpret_cast<void*>(&koleaut32G_VarI1FromUI8));
    e("VarI2FromBool", reinterpret_cast<void*>(&koleaut32G_VarI2FromBool));
    e("VarI2FromCy", reinterpret_cast<void*>(&koleaut32G_VarI2FromCy));
    e("VarI2FromDate", reinterpret_cast<void*>(&koleaut32G_VarI2FromDate));
    e("VarI2FromDec", reinterpret_cast<void*>(&koleaut32G_VarI2FromDec));
    e("VarI2FromDisp", reinterpret_cast<void*>(&koleaut32G_VarI2FromDisp));
    e("VarI2FromI1", reinterpret_cast<void*>(&koleaut32G_VarI2FromI1));
    e("VarI2FromI4", reinterpret_cast<void*>(&koleaut32G_VarI2FromI4));
    e("VarI2FromI8", reinterpret_cast<void*>(&koleaut32G_VarI2FromI8));
    e("VarI2FromR4", reinterpret_cast<void*>(&koleaut32G_VarI2FromR4));
    e("VarI2FromR8", reinterpret_cast<void*>(&koleaut32G_VarI2FromR8));
    e("VarI2FromStr", reinterpret_cast<void*>(&koleaut32G_VarI2FromStr));
    e("VarI2FromUI1", reinterpret_cast<void*>(&koleaut32G_VarI2FromUI1));
    e("VarI2FromUI2", reinterpret_cast<void*>(&koleaut32G_VarI2FromUI2));
    e("VarI2FromUI4", reinterpret_cast<void*>(&koleaut32G_VarI2FromUI4));
    e("VarI2FromUI8", reinterpret_cast<void*>(&koleaut32G_VarI2FromUI8));
    e("VarI4FromBool", reinterpret_cast<void*>(&koleaut32G_VarI4FromBool));
    e("VarI4FromCy", reinterpret_cast<void*>(&koleaut32G_VarI4FromCy));
    e("VarI4FromDate", reinterpret_cast<void*>(&koleaut32G_VarI4FromDate));
    e("VarI4FromDec", reinterpret_cast<void*>(&koleaut32G_VarI4FromDec));
    e("VarI4FromDisp", reinterpret_cast<void*>(&koleaut32G_VarI4FromDisp));
    e("VarI4FromI1", reinterpret_cast<void*>(&koleaut32G_VarI4FromI1));
    e("VarI4FromI2", reinterpret_cast<void*>(&koleaut32G_VarI4FromI2));
    e("VarI4FromI8", reinterpret_cast<void*>(&koleaut32G_VarI4FromI8));
    e("VarI4FromR4", reinterpret_cast<void*>(&koleaut32G_VarI4FromR4));
    e("VarI4FromR8", reinterpret_cast<void*>(&koleaut32G_VarI4FromR8));
    e("VarI4FromStr", reinterpret_cast<void*>(&koleaut32G_VarI4FromStr));
    e("VarI4FromUI1", reinterpret_cast<void*>(&koleaut32G_VarI4FromUI1));
    e("VarI4FromUI2", reinterpret_cast<void*>(&koleaut32G_VarI4FromUI2));
    e("VarI4FromUI4", reinterpret_cast<void*>(&koleaut32G_VarI4FromUI4));
    e("VarI4FromUI8", reinterpret_cast<void*>(&koleaut32G_VarI4FromUI8));
    e("VarI8FromBool", reinterpret_cast<void*>(&koleaut32G_VarI8FromBool));
    e("VarI8FromCy", reinterpret_cast<void*>(&koleaut32G_VarI8FromCy));
    e("VarI8FromDate", reinterpret_cast<void*>(&koleaut32G_VarI8FromDate));
    e("VarI8FromDec", reinterpret_cast<void*>(&koleaut32G_VarI8FromDec));
    e("VarI8FromDisp", reinterpret_cast<void*>(&koleaut32G_VarI8FromDisp));
    e("VarI8FromI1", reinterpret_cast<void*>(&koleaut32G_VarI8FromI1));
    e("VarI8FromI2", reinterpret_cast<void*>(&koleaut32G_VarI8FromI2));
    e("VarI8FromR4", reinterpret_cast<void*>(&koleaut32G_VarI8FromR4));
    e("VarI8FromR8", reinterpret_cast<void*>(&koleaut32G_VarI8FromR8));
    e("VarI8FromStr", reinterpret_cast<void*>(&koleaut32G_VarI8FromStr));
    e("VarI8FromUI1", reinterpret_cast<void*>(&koleaut32G_VarI8FromUI1));
    e("VarI8FromUI2", reinterpret_cast<void*>(&koleaut32G_VarI8FromUI2));
    e("VarI8FromUI4", reinterpret_cast<void*>(&koleaut32G_VarI8FromUI4));
    e("VarI8FromUI8", reinterpret_cast<void*>(&koleaut32G_VarI8FromUI8));
    e("VarIdiv", reinterpret_cast<void*>(&koleaut32G_VarIdiv));
    e("VarImp", reinterpret_cast<void*>(&koleaut32G_VarImp));
    e("VarInt", reinterpret_cast<void*>(&koleaut32G_VarInt));
    e("VarMod", reinterpret_cast<void*>(&koleaut32G_VarMod));
    e("VarMonthName", reinterpret_cast<void*>(&koleaut32G_VarMonthName));
    e("VarMul", reinterpret_cast<void*>(&koleaut32G_VarMul));
    e("VarNeg", reinterpret_cast<void*>(&koleaut32G_VarNeg));
    e("VarNot", reinterpret_cast<void*>(&koleaut32G_VarNot));
    e("VarNumFromParseNum", reinterpret_cast<void*>(&koleaut32G_VarNumFromParseNum));
    e("VarOr", reinterpret_cast<void*>(&koleaut32G_VarOr));
    e("VarParseNumFromStr", reinterpret_cast<void*>(&koleaut32G_VarParseNumFromStr));
    e("VarPow", reinterpret_cast<void*>(&koleaut32G_VarPow));
    e("VarR4CmpR8", reinterpret_cast<void*>(&koleaut32G_VarR4CmpR8));
    e("VarR4FromBool", reinterpret_cast<void*>(&koleaut32G_VarR4FromBool));
    e("VarR4FromCy", reinterpret_cast<void*>(&koleaut32G_VarR4FromCy));
    e("VarR4FromDate", reinterpret_cast<void*>(&koleaut32G_VarR4FromDate));
    e("VarR4FromDec", reinterpret_cast<void*>(&koleaut32G_VarR4FromDec));
    e("VarR4FromDisp", reinterpret_cast<void*>(&koleaut32G_VarR4FromDisp));
    e("VarR4FromI1", reinterpret_cast<void*>(&koleaut32G_VarR4FromI1));
    e("VarR4FromI2", reinterpret_cast<void*>(&koleaut32G_VarR4FromI2));
    e("VarR4FromI4", reinterpret_cast<void*>(&koleaut32G_VarR4FromI4));
    e("VarR4FromI8", reinterpret_cast<void*>(&koleaut32G_VarR4FromI8));
    e("VarR4FromR8", reinterpret_cast<void*>(&koleaut32G_VarR4FromR8));
    e("VarR4FromStr", reinterpret_cast<void*>(&koleaut32G_VarR4FromStr));
    e("VarR4FromUI1", reinterpret_cast<void*>(&koleaut32G_VarR4FromUI1));
    e("VarR4FromUI2", reinterpret_cast<void*>(&koleaut32G_VarR4FromUI2));
    e("VarR4FromUI4", reinterpret_cast<void*>(&koleaut32G_VarR4FromUI4));
    e("VarR4FromUI8", reinterpret_cast<void*>(&koleaut32G_VarR4FromUI8));
    e("VarR8FromBool", reinterpret_cast<void*>(&koleaut32G_VarR8FromBool));
    e("VarR8FromCy", reinterpret_cast<void*>(&koleaut32G_VarR8FromCy));
    e("VarR8FromDate", reinterpret_cast<void*>(&koleaut32G_VarR8FromDate));
    e("VarR8FromDec", reinterpret_cast<void*>(&koleaut32G_VarR8FromDec));
    e("VarR8FromDisp", reinterpret_cast<void*>(&koleaut32G_VarR8FromDisp));
    e("VarR8FromI1", reinterpret_cast<void*>(&koleaut32G_VarR8FromI1));
    e("VarR8FromI2", reinterpret_cast<void*>(&koleaut32G_VarR8FromI2));
    e("VarR8FromI4", reinterpret_cast<void*>(&koleaut32G_VarR8FromI4));
    e("VarR8FromI8", reinterpret_cast<void*>(&koleaut32G_VarR8FromI8));
    e("VarR8FromR4", reinterpret_cast<void*>(&koleaut32G_VarR8FromR4));
    e("VarR8FromStr", reinterpret_cast<void*>(&koleaut32G_VarR8FromStr));
    e("VarR8FromUI1", reinterpret_cast<void*>(&koleaut32G_VarR8FromUI1));
    e("VarR8FromUI2", reinterpret_cast<void*>(&koleaut32G_VarR8FromUI2));
    e("VarR8FromUI4", reinterpret_cast<void*>(&koleaut32G_VarR8FromUI4));
    e("VarR8FromUI8", reinterpret_cast<void*>(&koleaut32G_VarR8FromUI8));
    e("VarR8Pow", reinterpret_cast<void*>(&koleaut32G_VarR8Pow));
    e("VarR8Round", reinterpret_cast<void*>(&koleaut32G_VarR8Round));
    e("VarRound", reinterpret_cast<void*>(&koleaut32G_VarRound));
    e("VarSub", reinterpret_cast<void*>(&koleaut32G_VarSub));
    e("VarTokenizeFormatString", reinterpret_cast<void*>(&koleaut32G_VarTokenizeFormatString));
    e("VarUI1FromBool", reinterpret_cast<void*>(&koleaut32G_VarUI1FromBool));
    e("VarUI1FromCy", reinterpret_cast<void*>(&koleaut32G_VarUI1FromCy));
    e("VarUI1FromDate", reinterpret_cast<void*>(&koleaut32G_VarUI1FromDate));
    e("VarUI1FromDec", reinterpret_cast<void*>(&koleaut32G_VarUI1FromDec));
    e("VarUI1FromDisp", reinterpret_cast<void*>(&koleaut32G_VarUI1FromDisp));
    e("VarUI1FromI1", reinterpret_cast<void*>(&koleaut32G_VarUI1FromI1));
    e("VarUI1FromI2", reinterpret_cast<void*>(&koleaut32G_VarUI1FromI2));
    e("VarUI1FromI4", reinterpret_cast<void*>(&koleaut32G_VarUI1FromI4));
    e("VarUI1FromI8", reinterpret_cast<void*>(&koleaut32G_VarUI1FromI8));
    e("VarUI1FromR4", reinterpret_cast<void*>(&koleaut32G_VarUI1FromR4));
    e("VarUI1FromR8", reinterpret_cast<void*>(&koleaut32G_VarUI1FromR8));
    e("VarUI1FromStr", reinterpret_cast<void*>(&koleaut32G_VarUI1FromStr));
    e("VarUI1FromUI2", reinterpret_cast<void*>(&koleaut32G_VarUI1FromUI2));
    e("VarUI1FromUI4", reinterpret_cast<void*>(&koleaut32G_VarUI1FromUI4));
    e("VarUI1FromUI8", reinterpret_cast<void*>(&koleaut32G_VarUI1FromUI8));
    e("VarUI2FromBool", reinterpret_cast<void*>(&koleaut32G_VarUI2FromBool));
    e("VarUI2FromCy", reinterpret_cast<void*>(&koleaut32G_VarUI2FromCy));
    e("VarUI2FromDate", reinterpret_cast<void*>(&koleaut32G_VarUI2FromDate));
    e("VarUI2FromDec", reinterpret_cast<void*>(&koleaut32G_VarUI2FromDec));
    e("VarUI2FromDisp", reinterpret_cast<void*>(&koleaut32G_VarUI2FromDisp));
    e("VarUI2FromI1", reinterpret_cast<void*>(&koleaut32G_VarUI2FromI1));
    e("VarUI2FromI2", reinterpret_cast<void*>(&koleaut32G_VarUI2FromI2));
    e("VarUI2FromI4", reinterpret_cast<void*>(&koleaut32G_VarUI2FromI4));
    e("VarUI2FromI8", reinterpret_cast<void*>(&koleaut32G_VarUI2FromI8));
    e("VarUI2FromR4", reinterpret_cast<void*>(&koleaut32G_VarUI2FromR4));
    e("VarUI2FromR8", reinterpret_cast<void*>(&koleaut32G_VarUI2FromR8));
    e("VarUI2FromStr", reinterpret_cast<void*>(&koleaut32G_VarUI2FromStr));
    e("VarUI2FromUI1", reinterpret_cast<void*>(&koleaut32G_VarUI2FromUI1));
    e("VarUI2FromUI4", reinterpret_cast<void*>(&koleaut32G_VarUI2FromUI4));
    e("VarUI2FromUI8", reinterpret_cast<void*>(&koleaut32G_VarUI2FromUI8));
    e("VarUI4FromBool", reinterpret_cast<void*>(&koleaut32G_VarUI4FromBool));
    e("VarUI4FromCy", reinterpret_cast<void*>(&koleaut32G_VarUI4FromCy));
    e("VarUI4FromDate", reinterpret_cast<void*>(&koleaut32G_VarUI4FromDate));
    e("VarUI4FromDec", reinterpret_cast<void*>(&koleaut32G_VarUI4FromDec));
    e("VarUI4FromDisp", reinterpret_cast<void*>(&koleaut32G_VarUI4FromDisp));
    e("VarUI4FromI1", reinterpret_cast<void*>(&koleaut32G_VarUI4FromI1));
    e("VarUI4FromI2", reinterpret_cast<void*>(&koleaut32G_VarUI4FromI2));
    e("VarUI4FromI4", reinterpret_cast<void*>(&koleaut32G_VarUI4FromI4));
    e("VarUI4FromI8", reinterpret_cast<void*>(&koleaut32G_VarUI4FromI8));
    e("VarUI4FromR4", reinterpret_cast<void*>(&koleaut32G_VarUI4FromR4));
    e("VarUI4FromR8", reinterpret_cast<void*>(&koleaut32G_VarUI4FromR8));
    e("VarUI4FromStr", reinterpret_cast<void*>(&koleaut32G_VarUI4FromStr));
    e("VarUI4FromUI1", reinterpret_cast<void*>(&koleaut32G_VarUI4FromUI1));
    e("VarUI4FromUI2", reinterpret_cast<void*>(&koleaut32G_VarUI4FromUI2));
    e("VarUI4FromUI8", reinterpret_cast<void*>(&koleaut32G_VarUI4FromUI8));
    e("VarUI8FromBool", reinterpret_cast<void*>(&koleaut32G_VarUI8FromBool));
    e("VarUI8FromCy", reinterpret_cast<void*>(&koleaut32G_VarUI8FromCy));
    e("VarUI8FromDate", reinterpret_cast<void*>(&koleaut32G_VarUI8FromDate));
    e("VarUI8FromDec", reinterpret_cast<void*>(&koleaut32G_VarUI8FromDec));
    e("VarUI8FromDisp", reinterpret_cast<void*>(&koleaut32G_VarUI8FromDisp));
    e("VarUI8FromI1", reinterpret_cast<void*>(&koleaut32G_VarUI8FromI1));
    e("VarUI8FromI2", reinterpret_cast<void*>(&koleaut32G_VarUI8FromI2));
    e("VarUI8FromI8", reinterpret_cast<void*>(&koleaut32G_VarUI8FromI8));
    e("VarUI8FromR4", reinterpret_cast<void*>(&koleaut32G_VarUI8FromR4));
    e("VarUI8FromR8", reinterpret_cast<void*>(&koleaut32G_VarUI8FromR8));
    e("VarUI8FromStr", reinterpret_cast<void*>(&koleaut32G_VarUI8FromStr));
    e("VarUI8FromUI1", reinterpret_cast<void*>(&koleaut32G_VarUI8FromUI1));
    e("VarUI8FromUI2", reinterpret_cast<void*>(&koleaut32G_VarUI8FromUI2));
    e("VarUI8FromUI4", reinterpret_cast<void*>(&koleaut32G_VarUI8FromUI4));
    e("VarUdateFromDate", reinterpret_cast<void*>(&koleaut32G_VarUdateFromDate));
    e("VarWeekdayName", reinterpret_cast<void*>(&koleaut32G_VarWeekdayName));
    e("VarXor", reinterpret_cast<void*>(&koleaut32G_VarXor));
    e("VariantChangeType", reinterpret_cast<void*>(&koleaut32G_VariantChangeType));
    e("VariantChangeTypeEx", reinterpret_cast<void*>(&koleaut32G_VariantChangeTypeEx));
    e("VariantClear", reinterpret_cast<void*>(&koleaut32G_VariantClear));
    e("VariantCopy", reinterpret_cast<void*>(&koleaut32G_VariantCopy));
    e("VariantCopyInd", reinterpret_cast<void*>(&koleaut32G_VariantCopyInd));
    e("VariantInit", reinterpret_cast<void*>(&koleaut32G_VariantInit));
    e("VariantTimeToDosDateTime", reinterpret_cast<void*>(&koleaut32G_VariantTimeToDosDateTime));
    e("VariantTimeToSystemTime", reinterpret_cast<void*>(&koleaut32G_VariantTimeToSystemTime));
    e("VectorFromBstr", reinterpret_cast<void*>(&koleaut32G_VectorFromBstr));
}
}  // namespace occ::runtime::winabi

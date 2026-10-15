// The SETUPAPI surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CMP_WaitNoPendingInstallEvents(std::uint32_t dwTimeout) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dwTimeout);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Add_Empty_Log_Conf(std::uint64_t* plcLogConf, std::uint32_t dnDevInst, std::uint64_t Priority, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(plcLogConf);
    static_cast<void>(dnDevInst);
    static_cast<void>(Priority);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Add_Empty_Log_Conf_Ex(std::uint64_t* plcLogConf, std::uint32_t dnDevInst, std::uint64_t Priority, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(plcLogConf);
    static_cast<void>(dnDevInst);
    static_cast<void>(Priority);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Add_IDA(std::uint32_t dnDevInst, char* pszID, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(pszID);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Add_IDW(std::uint32_t dnDevInst, char16_t* pszID, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(pszID);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Add_ID_ExA(std::uint32_t dnDevInst, char* pszID, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(pszID);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Add_ID_ExW(std::uint32_t dnDevInst, char16_t* pszID, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(pszID);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Add_Range(std::uint64_t ullStartValue, std::uint64_t ullEndValue, std::uint64_t rlh, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ullStartValue);
    static_cast<void>(ullEndValue);
    static_cast<void>(rlh);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Add_Res_Des(std::uint64_t* prdResDes, std::uint64_t lcLogConf, std::uint32_t ResourceID, const void* ResourceData, std::uint32_t ResourceLen, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(prdResDes);
    static_cast<void>(lcLogConf);
    static_cast<void>(ResourceID);
    static_cast<void>(ResourceData);
    static_cast<void>(ResourceLen);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Add_Res_Des_Ex(std::uint64_t* prdResDes, std::uint64_t lcLogConf, std::uint32_t ResourceID, const void* ResourceData, std::uint32_t ResourceLen, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(prdResDes);
    static_cast<void>(lcLogConf);
    static_cast<void>(ResourceID);
    static_cast<void>(ResourceData);
    static_cast<void>(ResourceLen);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Connect_MachineA(const char* UNCServerName, void* phMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(UNCServerName);
    static_cast<void>(phMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Connect_MachineW(const char16_t* UNCServerName, void* phMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(UNCServerName);
    static_cast<void>(phMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Create_DevNodeA(void* pdnDevInst, const char* pDeviceID, std::uint32_t dnParent, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pdnDevInst);
    static_cast<void>(pDeviceID);
    static_cast<void>(dnParent);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Create_DevNodeW(void* pdnDevInst, const char16_t* pDeviceID, std::uint32_t dnParent, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pdnDevInst);
    static_cast<void>(pDeviceID);
    static_cast<void>(dnParent);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Create_DevNode_ExA(void* pdnDevInst, const char* pDeviceID, std::uint32_t dnParent, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pdnDevInst);
    static_cast<void>(pDeviceID);
    static_cast<void>(dnParent);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Create_DevNode_ExW(void* pdnDevInst, const char16_t* pDeviceID, std::uint32_t dnParent, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pdnDevInst);
    static_cast<void>(pDeviceID);
    static_cast<void>(dnParent);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Create_Range_List(void* prlh, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(prlh);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Delete_Class_Key(void* ClassGuid, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Delete_Class_Key_Ex(void* ClassGuid, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Delete_DevNode_Key(std::uint64_t dnDevNode, std::uint32_t ulHardwareProfile, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevNode);
    static_cast<void>(ulHardwareProfile);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Delete_DevNode_Key_Ex(std::uint64_t dnDevNode, std::uint32_t ulHardwareProfile, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevNode);
    static_cast<void>(ulHardwareProfile);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Delete_Range(std::uint64_t ullStartValue, std::uint64_t ullEndValue, std::uint64_t rlh, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ullStartValue);
    static_cast<void>(ullEndValue);
    static_cast<void>(rlh);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Detect_Resource_Conflict(std::uint32_t dnDevInst, std::uint32_t ResourceID, const void* ResourceData, std::uint32_t ResourceLen, std::int32_t* pbConflictDetected, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ResourceID);
    static_cast<void>(ResourceData);
    static_cast<void>(ResourceLen);
    static_cast<void>(pbConflictDetected);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Detect_Resource_Conflict_Ex(std::uint32_t dnDevInst, std::uint32_t ResourceID, const void* ResourceData, std::uint32_t ResourceLen, std::int32_t* pbConflictDetected, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ResourceID);
    static_cast<void>(ResourceData);
    static_cast<void>(ResourceLen);
    static_cast<void>(pbConflictDetected);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Disable_DevNode(std::uint32_t dnDevInst, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Disable_DevNode_Ex(std::uint32_t dnDevInst, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Disconnect_Machine(void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Dup_Range_List(std::uint64_t rlhOld, std::uint64_t rlhNew, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(rlhOld);
    static_cast<void>(rlhNew);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Enable_DevNode(std::uint32_t dnDevInst, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Enable_DevNode_Ex(std::uint32_t dnDevInst, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Enumerate_Classes(std::uint32_t ulClassIndex, void* ClassGuid, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ulClassIndex);
    static_cast<void>(ClassGuid);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Enumerate_Classes_Ex(std::uint32_t ulClassIndex, void* ClassGuid, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ulClassIndex);
    static_cast<void>(ClassGuid);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Enumerate_EnumeratorsA(std::uint32_t ulEnumIndex, char* Buffer, std::uint32_t* pulLength, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ulEnumIndex);
    static_cast<void>(Buffer);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Enumerate_EnumeratorsW(std::uint32_t ulEnumIndex, char16_t* Buffer, std::uint32_t* pulLength, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ulEnumIndex);
    static_cast<void>(Buffer);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Enumerate_Enumerators_ExA(std::uint32_t ulEnumIndex, char* Buffer, std::uint32_t* pulLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ulEnumIndex);
    static_cast<void>(Buffer);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Enumerate_Enumerators_ExW(std::uint32_t ulEnumIndex, char16_t* Buffer, std::uint32_t* pulLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ulEnumIndex);
    static_cast<void>(Buffer);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Find_Range(std::uint64_t* pullStart, std::uint64_t ullStart, std::uint32_t ulLength, std::uint64_t ullAlignment, std::uint64_t ullEnd, std::uint64_t rlh, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pullStart);
    static_cast<void>(ullStart);
    static_cast<void>(ulLength);
    static_cast<void>(ullAlignment);
    static_cast<void>(ullEnd);
    static_cast<void>(rlh);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_First_Range(std::uint64_t rlh, std::uint64_t* pullStart, std::uint64_t* pullEnd, std::uint64_t preElement, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(rlh);
    static_cast<void>(pullStart);
    static_cast<void>(pullEnd);
    static_cast<void>(preElement);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Free_Log_Conf(std::uint64_t lcLogConfToBeFreed, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(lcLogConfToBeFreed);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Free_Log_Conf_Ex(std::uint64_t lcLogConfToBeFreed, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(lcLogConfToBeFreed);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Free_Log_Conf_Handle(std::uint64_t lcLogConf) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(lcLogConf);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Free_Range_List(std::uint64_t rlh, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(rlh);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Free_Res_Des(std::uint64_t* prdResDes, std::uint64_t rdResDes, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(prdResDes);
    static_cast<void>(rdResDes);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Free_Res_Des_Ex(std::uint64_t* prdResDes, std::uint64_t rdResDes, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(prdResDes);
    static_cast<void>(rdResDes);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Free_Res_Des_Handle(std::uint64_t rdResDes) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(rdResDes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Free_Resource_Conflict_Handle(std::uint64_t clConflictList) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(clConflictList);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Child(void* pdnDevInst, std::uint32_t dnDevInst, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pdnDevInst);
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Child_Ex(void* pdnDevInst, std::uint32_t dnDevInst, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pdnDevInst);
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Class_Key_NameA(void* ClassGuid, char* pszKeyName, std::uint32_t* pulLength, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(pszKeyName);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Class_Key_NameW(void* ClassGuid, char16_t* pszKeyName, std::uint32_t* pulLength, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(pszKeyName);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Class_Key_Name_ExA(void* ClassGuid, char* pszKeyName, std::uint32_t* pulLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(pszKeyName);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Class_Key_Name_ExW(void* ClassGuid, char16_t* pszKeyName, std::uint32_t* pulLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(pszKeyName);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Class_NameA(void* ClassGuid, char* Buffer, std::uint32_t* pulLength, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(Buffer);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Class_NameW(void* ClassGuid, char16_t* Buffer, std::uint32_t* pulLength, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(Buffer);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Class_Name_ExA(void* ClassGuid, char* Buffer, std::uint32_t* pulLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(Buffer);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Class_Name_ExW(void* ClassGuid, char16_t* Buffer, std::uint32_t* pulLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(Buffer);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Class_Registry_PropertyA(void* ClassGUID, std::uint32_t ulProperty, std::uint32_t* pulRegDataType, void* Buffer, std::uint32_t* pulLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGUID);
    static_cast<void>(ulProperty);
    static_cast<void>(pulRegDataType);
    static_cast<void>(Buffer);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Class_Registry_PropertyW(void* ClassGUID, std::uint32_t ulProperty, std::uint32_t* pulRegDataType, void* Buffer, std::uint32_t* pulLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGUID);
    static_cast<void>(ulProperty);
    static_cast<void>(pulRegDataType);
    static_cast<void>(Buffer);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Depth(std::uint32_t* pulDepth, std::uint32_t dnDevInst, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pulDepth);
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Depth_Ex(std::uint32_t* pulDepth, std::uint32_t dnDevInst, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pulDepth);
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_DevNode_Custom_PropertyA(std::uint32_t dnDevInst, const char* pszCustomPropertyName, std::uint32_t* pulRegDataType, void* Buffer, std::uint32_t* pulLength, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(pszCustomPropertyName);
    static_cast<void>(pulRegDataType);
    static_cast<void>(Buffer);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_DevNode_Custom_PropertyW(std::uint32_t dnDevInst, const char16_t* pszCustomPropertyName, std::uint32_t* pulRegDataType, void* Buffer, std::uint32_t* pulLength, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(pszCustomPropertyName);
    static_cast<void>(pulRegDataType);
    static_cast<void>(Buffer);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_DevNode_Custom_Property_ExA(std::uint32_t dnDevInst, const char* pszCustomPropertyName, std::uint32_t* pulRegDataType, void* Buffer, std::uint32_t* pulLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(pszCustomPropertyName);
    static_cast<void>(pulRegDataType);
    static_cast<void>(Buffer);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_DevNode_Custom_Property_ExW(std::uint32_t dnDevInst, const char16_t* pszCustomPropertyName, std::uint32_t* pulRegDataType, void* Buffer, std::uint32_t* pulLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(pszCustomPropertyName);
    static_cast<void>(pulRegDataType);
    static_cast<void>(Buffer);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_DevNode_Registry_PropertyA(std::uint32_t dnDevInst, std::uint32_t ulProperty, std::uint32_t* pulRegDataType, void* Buffer, std::uint32_t* pulLength, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ulProperty);
    static_cast<void>(pulRegDataType);
    static_cast<void>(Buffer);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_DevNode_Registry_PropertyW(std::uint32_t dnDevInst, std::uint32_t ulProperty, std::uint32_t* pulRegDataType, void* Buffer, std::uint32_t* pulLength, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ulProperty);
    static_cast<void>(pulRegDataType);
    static_cast<void>(Buffer);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_DevNode_Registry_Property_ExA(std::uint32_t dnDevInst, std::uint32_t ulProperty, std::uint32_t* pulRegDataType, void* Buffer, std::uint32_t* pulLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ulProperty);
    static_cast<void>(pulRegDataType);
    static_cast<void>(Buffer);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_DevNode_Registry_Property_ExW(std::uint32_t dnDevInst, std::uint32_t ulProperty, std::uint32_t* pulRegDataType, void* Buffer, std::uint32_t* pulLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ulProperty);
    static_cast<void>(pulRegDataType);
    static_cast<void>(Buffer);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_DevNode_Status(std::uint32_t* pulStatus, std::uint32_t* pulProblemNumber, std::uint32_t dnDevInst, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pulStatus);
    static_cast<void>(pulProblemNumber);
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_DevNode_Status_Ex(std::uint32_t* pulStatus, std::uint32_t* pulProblemNumber, std::uint32_t dnDevInst, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pulStatus);
    static_cast<void>(pulProblemNumber);
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_IDA(std::uint32_t dnDevInst, char* Buffer, std::uint32_t BufferLen, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(Buffer);
    static_cast<void>(BufferLen);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_IDW(std::uint32_t dnDevInst, char16_t* Buffer, std::uint32_t BufferLen, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(Buffer);
    static_cast<void>(BufferLen);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_ID_ExA(std::uint32_t dnDevInst, char* Buffer, std::uint32_t BufferLen, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(Buffer);
    static_cast<void>(BufferLen);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_ID_ExW(std::uint32_t dnDevInst, char16_t* Buffer, std::uint32_t BufferLen, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(Buffer);
    static_cast<void>(BufferLen);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_ID_ListA(const char* pszFilter, char* Buffer, std::uint32_t BufferLen, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pszFilter);
    static_cast<void>(Buffer);
    static_cast<void>(BufferLen);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_ID_ListW(const char16_t* pszFilter, char16_t* Buffer, std::uint32_t BufferLen, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pszFilter);
    static_cast<void>(Buffer);
    static_cast<void>(BufferLen);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_ID_List_ExA(const char* pszFilter, char* Buffer, std::uint32_t BufferLen, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pszFilter);
    static_cast<void>(Buffer);
    static_cast<void>(BufferLen);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_ID_List_ExW(const char16_t* pszFilter, char16_t* Buffer, std::uint32_t BufferLen, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pszFilter);
    static_cast<void>(Buffer);
    static_cast<void>(BufferLen);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_ID_List_SizeA(std::uint32_t* pulLen, const char* pszFilter, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pulLen);
    static_cast<void>(pszFilter);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_ID_List_SizeW(std::uint32_t* pulLen, const char16_t* pszFilter, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pulLen);
    static_cast<void>(pszFilter);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_ID_List_Size_ExA(std::uint32_t* pulLen, const char* pszFilter, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pulLen);
    static_cast<void>(pszFilter);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_ID_List_Size_ExW(std::uint32_t* pulLen, const char16_t* pszFilter, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pulLen);
    static_cast<void>(pszFilter);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_ID_Size(std::uint32_t* pulLen, std::uint32_t dnDevInst, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pulLen);
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_ID_Size_Ex(std::uint32_t* pulLen, std::uint32_t dnDevInst, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pulLen);
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_Interface_AliasA(const char* pszDeviceInterface, void* AliasInterfaceGuid, char* pszAliasDeviceInterface, std::uint32_t* pulLength, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pszDeviceInterface);
    static_cast<void>(AliasInterfaceGuid);
    static_cast<void>(pszAliasDeviceInterface);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_Interface_AliasW(const char16_t* pszDeviceInterface, void* AliasInterfaceGuid, char16_t* pszAliasDeviceInterface, std::uint32_t* pulLength, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pszDeviceInterface);
    static_cast<void>(AliasInterfaceGuid);
    static_cast<void>(pszAliasDeviceInterface);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_Interface_Alias_ExA(const char* pszDeviceInterface, void* AliasInterfaceGuid, char* pszAliasDeviceInterface, std::uint32_t* pulLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pszDeviceInterface);
    static_cast<void>(AliasInterfaceGuid);
    static_cast<void>(pszAliasDeviceInterface);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_Interface_Alias_ExW(const char16_t* pszDeviceInterface, void* AliasInterfaceGuid, char16_t* pszAliasDeviceInterface, std::uint32_t* pulLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pszDeviceInterface);
    static_cast<void>(AliasInterfaceGuid);
    static_cast<void>(pszAliasDeviceInterface);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_Interface_ListA(void* InterfaceClassGuid, const char* pDeviceID, char* Buffer, std::uint32_t BufferLen, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InterfaceClassGuid);
    static_cast<void>(pDeviceID);
    static_cast<void>(Buffer);
    static_cast<void>(BufferLen);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_Interface_ListW(void* InterfaceClassGuid, const char16_t* pDeviceID, char16_t* Buffer, std::uint32_t BufferLen, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InterfaceClassGuid);
    static_cast<void>(pDeviceID);
    static_cast<void>(Buffer);
    static_cast<void>(BufferLen);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_Interface_List_ExA(void* InterfaceClassGuid, const char* pDeviceID, char* Buffer, std::uint32_t BufferLen, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InterfaceClassGuid);
    static_cast<void>(pDeviceID);
    static_cast<void>(Buffer);
    static_cast<void>(BufferLen);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_Interface_List_ExW(void* InterfaceClassGuid, const char16_t* pDeviceID, char16_t* Buffer, std::uint32_t BufferLen, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InterfaceClassGuid);
    static_cast<void>(pDeviceID);
    static_cast<void>(Buffer);
    static_cast<void>(BufferLen);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_Interface_List_SizeA(std::uint32_t* pulLen, void* InterfaceClassGuid, const char* pDeviceID, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pulLen);
    static_cast<void>(InterfaceClassGuid);
    static_cast<void>(pDeviceID);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_Interface_List_SizeW(std::uint32_t* pulLen, void* InterfaceClassGuid, const char16_t* pDeviceID, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pulLen);
    static_cast<void>(InterfaceClassGuid);
    static_cast<void>(pDeviceID);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_Interface_List_Size_ExA(std::uint32_t* pulLen, void* InterfaceClassGuid, const char* pDeviceID, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pulLen);
    static_cast<void>(InterfaceClassGuid);
    static_cast<void>(pDeviceID);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Device_Interface_List_Size_ExW(std::uint32_t* pulLen, void* InterfaceClassGuid, const char16_t* pDeviceID, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pulLen);
    static_cast<void>(InterfaceClassGuid);
    static_cast<void>(pDeviceID);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_First_Log_Conf(std::uint64_t* plcLogConf, std::uint32_t dnDevInst, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(plcLogConf);
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_First_Log_Conf_Ex(std::uint64_t* plcLogConf, std::uint32_t dnDevInst, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(plcLogConf);
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Global_State(std::uint32_t* pulState, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pulState);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Global_State_Ex(std::uint32_t* pulState, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pulState);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_HW_Prof_FlagsA(const char* szDevInstName, std::uint32_t ulHardwareProfile, std::uint32_t* pulValue, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(szDevInstName);
    static_cast<void>(ulHardwareProfile);
    static_cast<void>(pulValue);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_HW_Prof_FlagsW(const char16_t* szDevInstName, std::uint32_t ulHardwareProfile, std::uint32_t* pulValue, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(szDevInstName);
    static_cast<void>(ulHardwareProfile);
    static_cast<void>(pulValue);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_HW_Prof_Flags_ExA(const char* szDevInstName, std::uint32_t ulHardwareProfile, std::uint32_t* pulValue, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(szDevInstName);
    static_cast<void>(ulHardwareProfile);
    static_cast<void>(pulValue);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_HW_Prof_Flags_ExW(const char16_t* szDevInstName, std::uint32_t ulHardwareProfile, std::uint32_t* pulValue, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(szDevInstName);
    static_cast<void>(ulHardwareProfile);
    static_cast<void>(pulValue);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Hardware_Profile_InfoA(std::uint32_t ulIndex, std::uint64_t pHWProfileInfo, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ulIndex);
    static_cast<void>(pHWProfileInfo);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Hardware_Profile_InfoW(std::uint32_t ulIndex, std::uint64_t pHWProfileInfo, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ulIndex);
    static_cast<void>(pHWProfileInfo);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Hardware_Profile_Info_ExA(std::uint32_t ulIndex, std::uint64_t pHWProfileInfo, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ulIndex);
    static_cast<void>(pHWProfileInfo);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Hardware_Profile_Info_ExW(std::uint32_t ulIndex, std::uint64_t pHWProfileInfo, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ulIndex);
    static_cast<void>(pHWProfileInfo);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Log_Conf_Priority(std::uint64_t lcLogConf, std::uint64_t pPriority, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(lcLogConf);
    static_cast<void>(pPriority);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Log_Conf_Priority_Ex(std::uint64_t lcLogConf, std::uint64_t pPriority, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(lcLogConf);
    static_cast<void>(pPriority);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Next_Log_Conf(std::uint64_t* plcLogConf, std::uint64_t lcLogConf, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(plcLogConf);
    static_cast<void>(lcLogConf);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Next_Log_Conf_Ex(std::uint64_t* plcLogConf, std::uint64_t lcLogConf, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(plcLogConf);
    static_cast<void>(lcLogConf);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Next_Res_Des(std::uint64_t* prdResDes, std::uint64_t rdResDes, std::uint32_t ForResource, std::uint32_t* pResourceID, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(prdResDes);
    static_cast<void>(rdResDes);
    static_cast<void>(ForResource);
    static_cast<void>(pResourceID);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Next_Res_Des_Ex(std::uint64_t* prdResDes, std::uint64_t rdResDes, std::uint32_t ForResource, std::uint32_t* pResourceID, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(prdResDes);
    static_cast<void>(rdResDes);
    static_cast<void>(ForResource);
    static_cast<void>(pResourceID);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Parent(void* pdnDevInst, std::uint32_t dnDevInst, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pdnDevInst);
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Parent_Ex(void* pdnDevInst, std::uint32_t dnDevInst, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pdnDevInst);
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Res_Des_Data(std::uint64_t rdResDes, void* Buffer, std::uint32_t BufferLen, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(rdResDes);
    static_cast<void>(Buffer);
    static_cast<void>(BufferLen);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Res_Des_Data_Ex(std::uint64_t rdResDes, void* Buffer, std::uint32_t BufferLen, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(rdResDes);
    static_cast<void>(Buffer);
    static_cast<void>(BufferLen);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Res_Des_Data_Size(std::uint32_t* pulSize, std::uint64_t rdResDes, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pulSize);
    static_cast<void>(rdResDes);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Res_Des_Data_Size_Ex(std::uint32_t* pulSize, std::uint64_t rdResDes, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pulSize);
    static_cast<void>(rdResDes);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Resource_Conflict_Count(std::uint64_t clConflictList, std::uint32_t* pulCount) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(clConflictList);
    static_cast<void>(pulCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Resource_Conflict_DetailsA(std::uint64_t clConflictList, std::uint32_t ulIndex, std::uint64_t pConflictDetails) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(clConflictList);
    static_cast<void>(ulIndex);
    static_cast<void>(pConflictDetails);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Resource_Conflict_DetailsW(std::uint64_t clConflictList, std::uint32_t ulIndex, std::uint64_t pConflictDetails) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(clConflictList);
    static_cast<void>(ulIndex);
    static_cast<void>(pConflictDetails);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Sibling(void* pdnDevInst, std::uint32_t DevInst, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pdnDevInst);
    static_cast<void>(DevInst);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Get_Sibling_Ex(void* pdnDevInst, std::uint32_t DevInst, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pdnDevInst);
    static_cast<void>(DevInst);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t ksetupapiG_CM_Get_Version() noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t ksetupapiG_CM_Get_Version_Ex(void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Intersect_Range_List(std::uint64_t rlhOld1, std::uint64_t rlhOld2, std::uint64_t rlhNew, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(rlhOld1);
    static_cast<void>(rlhOld2);
    static_cast<void>(rlhNew);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Invert_Range_List(std::uint64_t rlhOld, std::uint64_t rlhNew, std::uint64_t ullMaxValue, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(rlhOld);
    static_cast<void>(rlhNew);
    static_cast<void>(ullMaxValue);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Is_Dock_Station_Present(std::int32_t* pbPresent) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pbPresent);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Is_Dock_Station_Present_Ex(std::int32_t* pbPresent, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pbPresent);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_CM_Is_Version_Available(std::uint16_t wVersion) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(wVersion);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_CM_Is_Version_Available_Ex(std::uint16_t wVersion, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(wVersion);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Locate_DevNodeA(void* pdnDevInst, const char* pDeviceID, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pdnDevInst);
    static_cast<void>(pDeviceID);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Locate_DevNodeW(void* pdnDevInst, const char16_t* pDeviceID, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pdnDevInst);
    static_cast<void>(pDeviceID);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Locate_DevNode_ExA(void* pdnDevInst, const char* pDeviceID, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pdnDevInst);
    static_cast<void>(pDeviceID);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Locate_DevNode_ExW(void* pdnDevInst, const char16_t* pDeviceID, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pdnDevInst);
    static_cast<void>(pDeviceID);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Merge_Range_List(std::uint64_t rlhOld1, std::uint64_t rlhOld2, std::uint64_t rlhNew, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(rlhOld1);
    static_cast<void>(rlhOld2);
    static_cast<void>(rlhNew);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Modify_Res_Des(std::uint64_t* prdResDes, std::uint64_t rdResDes, std::uint32_t ResourceID, const void* ResourceData, std::uint32_t ResourceLen, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(prdResDes);
    static_cast<void>(rdResDes);
    static_cast<void>(ResourceID);
    static_cast<void>(ResourceData);
    static_cast<void>(ResourceLen);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Modify_Res_Des_Ex(std::uint64_t* prdResDes, std::uint64_t rdResDes, std::uint32_t ResourceID, const void* ResourceData, std::uint32_t ResourceLen, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(prdResDes);
    static_cast<void>(rdResDes);
    static_cast<void>(ResourceID);
    static_cast<void>(ResourceData);
    static_cast<void>(ResourceLen);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Move_DevNode(std::uint32_t dnFromDevInst, std::uint32_t dnToDevInst, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnFromDevInst);
    static_cast<void>(dnToDevInst);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Move_DevNode_Ex(std::uint32_t dnFromDevInst, std::uint32_t dnToDevInst, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnFromDevInst);
    static_cast<void>(dnToDevInst);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Next_Range(std::uint64_t preElement, std::uint64_t* pullStart, std::uint64_t* pullEnd, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(preElement);
    static_cast<void>(pullStart);
    static_cast<void>(pullEnd);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Open_Class_KeyA(void* ClassGuid, const char* pszClassName, std::uint32_t samDesired, std::uint32_t Disposition, void** phkClass, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(pszClassName);
    static_cast<void>(samDesired);
    static_cast<void>(Disposition);
    static_cast<void>(phkClass);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Open_Class_KeyW(void* ClassGuid, const char16_t* pszClassName, std::uint32_t samDesired, std::uint32_t Disposition, void** phkClass, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(pszClassName);
    static_cast<void>(samDesired);
    static_cast<void>(Disposition);
    static_cast<void>(phkClass);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Open_Class_Key_ExA(void* pszClassGuid, const char* pszClassName, std::uint32_t samDesired, std::uint32_t Disposition, void** phkClass, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pszClassGuid);
    static_cast<void>(pszClassName);
    static_cast<void>(samDesired);
    static_cast<void>(Disposition);
    static_cast<void>(phkClass);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Open_Class_Key_ExW(void* pszClassGuid, const char16_t* pszClassName, std::uint32_t samDesired, std::uint32_t Disposition, void** phkClass, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pszClassGuid);
    static_cast<void>(pszClassName);
    static_cast<void>(samDesired);
    static_cast<void>(Disposition);
    static_cast<void>(phkClass);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Open_DevNode_Key(std::uint32_t dnDevNode, std::uint32_t samDesired, std::uint32_t ulHardwareProfile, std::uint32_t Disposition, void** phkDevice, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevNode);
    static_cast<void>(samDesired);
    static_cast<void>(ulHardwareProfile);
    static_cast<void>(Disposition);
    static_cast<void>(phkDevice);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Open_DevNode_Key_Ex(std::uint32_t dnDevNode, std::uint32_t samDesired, std::uint32_t ulHardwareProfile, std::uint32_t Disposition, void** phkDevice, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevNode);
    static_cast<void>(samDesired);
    static_cast<void>(ulHardwareProfile);
    static_cast<void>(Disposition);
    static_cast<void>(phkDevice);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Query_And_Remove_SubTreeA(std::uint32_t dnAncestor, void* pVetoType, char* pszVetoName, std::uint32_t ulNameLength, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnAncestor);
    static_cast<void>(pVetoType);
    static_cast<void>(pszVetoName);
    static_cast<void>(ulNameLength);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Query_And_Remove_SubTreeW(std::uint32_t dnAncestor, void* pVetoType, char16_t* pszVetoName, std::uint32_t ulNameLength, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnAncestor);
    static_cast<void>(pVetoType);
    static_cast<void>(pszVetoName);
    static_cast<void>(ulNameLength);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Query_And_Remove_SubTree_ExA(std::uint32_t dnAncestor, void* pVetoType, char* pszVetoName, std::uint32_t ulNameLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnAncestor);
    static_cast<void>(pVetoType);
    static_cast<void>(pszVetoName);
    static_cast<void>(ulNameLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Query_And_Remove_SubTree_ExW(std::uint32_t dnAncestor, void* pVetoType, char16_t* pszVetoName, std::uint32_t ulNameLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnAncestor);
    static_cast<void>(pVetoType);
    static_cast<void>(pszVetoName);
    static_cast<void>(ulNameLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Query_Arbitrator_Free_Data(void* pData, std::uint32_t DataLen, std::uint32_t dnDevInst, std::uint32_t ResourceID, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pData);
    static_cast<void>(DataLen);
    static_cast<void>(dnDevInst);
    static_cast<void>(ResourceID);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Query_Arbitrator_Free_Data_Ex(void* pData, std::uint32_t DataLen, std::uint32_t dnDevInst, std::uint32_t ResourceID, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pData);
    static_cast<void>(DataLen);
    static_cast<void>(dnDevInst);
    static_cast<void>(ResourceID);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Query_Arbitrator_Free_Size(std::uint32_t* pulSize, std::uint32_t dnDevInst, std::uint32_t ResourceID, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pulSize);
    static_cast<void>(dnDevInst);
    static_cast<void>(ResourceID);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Query_Arbitrator_Free_Size_Ex(std::uint32_t* pulSize, std::uint32_t dnDevInst, std::uint32_t ResourceID, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pulSize);
    static_cast<void>(dnDevInst);
    static_cast<void>(ResourceID);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Query_Remove_SubTree(std::uint32_t dnAncestor, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnAncestor);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Query_Remove_SubTree_Ex(std::uint32_t dnAncestor, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnAncestor);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Query_Resource_Conflict_List(std::uint64_t* pclConflictList, std::uint32_t dnDevInst, std::uint32_t ResourceID, const void* ResourceData, std::uint32_t ResourceLen, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pclConflictList);
    static_cast<void>(dnDevInst);
    static_cast<void>(ResourceID);
    static_cast<void>(ResourceData);
    static_cast<void>(ResourceLen);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Reenumerate_DevNode(std::uint32_t dnDevInst, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Reenumerate_DevNode_Ex(std::uint32_t dnDevInst, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Register_Device_Driver(std::uint32_t dnDevInst, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Register_Device_Driver_Ex(std::uint32_t dnDevInst, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Register_Device_InterfaceA(std::uint32_t dnDevInst, void* InterfaceClassGuid, const char* pszReference, char* pszDeviceInterface, std::uint32_t* pulLength, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(InterfaceClassGuid);
    static_cast<void>(pszReference);
    static_cast<void>(pszDeviceInterface);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Register_Device_InterfaceW(std::uint32_t dnDevInst, void* InterfaceClassGuid, const char16_t* pszReference, char16_t* pszDeviceInterface, std::uint32_t* pulLength, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(InterfaceClassGuid);
    static_cast<void>(pszReference);
    static_cast<void>(pszDeviceInterface);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Register_Device_Interface_ExA(std::uint32_t dnDevInst, void* InterfaceClassGuid, const char* pszReference, char* pszDeviceInterface, std::uint32_t* pulLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(InterfaceClassGuid);
    static_cast<void>(pszReference);
    static_cast<void>(pszDeviceInterface);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Register_Device_Interface_ExW(std::uint32_t dnDevInst, void* InterfaceClassGuid, const char16_t* pszReference, char16_t* pszDeviceInterface, std::uint32_t* pulLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(InterfaceClassGuid);
    static_cast<void>(pszReference);
    static_cast<void>(pszDeviceInterface);
    static_cast<void>(pulLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Remove_SubTree(std::uint32_t dnAncestor, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnAncestor);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Remove_SubTree_Ex(std::uint32_t dnAncestor, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnAncestor);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Request_Device_EjectA(std::uint32_t dnDevInst, void* pVetoType, char* pszVetoName, std::uint32_t ulNameLength, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(pVetoType);
    static_cast<void>(pszVetoName);
    static_cast<void>(ulNameLength);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Request_Device_EjectW(std::uint32_t dnDevInst, void* pVetoType, char16_t* pszVetoName, std::uint32_t ulNameLength, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(pVetoType);
    static_cast<void>(pszVetoName);
    static_cast<void>(ulNameLength);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Request_Device_Eject_ExA(std::uint32_t dnDevInst, void* pVetoType, char* pszVetoName, std::uint32_t ulNameLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(pVetoType);
    static_cast<void>(pszVetoName);
    static_cast<void>(ulNameLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Request_Device_Eject_ExW(std::uint32_t dnDevInst, void* pVetoType, char16_t* pszVetoName, std::uint32_t ulNameLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(pVetoType);
    static_cast<void>(pszVetoName);
    static_cast<void>(ulNameLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Request_Eject_PC() noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Request_Eject_PC_Ex(void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Run_Detection(std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Run_Detection_Ex(std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Set_Class_Registry_PropertyA(void* ClassGUID, std::uint32_t ulProperty, const void* Buffer, std::uint32_t ulLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGUID);
    static_cast<void>(ulProperty);
    static_cast<void>(Buffer);
    static_cast<void>(ulLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Set_Class_Registry_PropertyW(void* ClassGUID, std::uint32_t ulProperty, const void* Buffer, std::uint32_t ulLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGUID);
    static_cast<void>(ulProperty);
    static_cast<void>(Buffer);
    static_cast<void>(ulLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Set_DevNode_Problem(std::uint32_t dnDevInst, std::uint32_t ulProblem, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ulProblem);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Set_DevNode_Problem_Ex(std::uint32_t dnDevInst, std::uint32_t ulProblem, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ulProblem);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Set_DevNode_Registry_PropertyA(std::uint32_t dnDevInst, std::uint32_t ulProperty, const void* Buffer, std::uint32_t ulLength, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ulProperty);
    static_cast<void>(Buffer);
    static_cast<void>(ulLength);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Set_DevNode_Registry_PropertyW(std::uint32_t dnDevInst, std::uint32_t ulProperty, const void* Buffer, std::uint32_t ulLength, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ulProperty);
    static_cast<void>(Buffer);
    static_cast<void>(ulLength);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Set_DevNode_Registry_Property_ExA(std::uint32_t dnDevInst, std::uint32_t ulProperty, const void* Buffer, std::uint32_t ulLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ulProperty);
    static_cast<void>(Buffer);
    static_cast<void>(ulLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Set_DevNode_Registry_Property_ExW(std::uint32_t dnDevInst, std::uint32_t ulProperty, const void* Buffer, std::uint32_t ulLength, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ulProperty);
    static_cast<void>(Buffer);
    static_cast<void>(ulLength);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Set_HW_Prof(std::uint32_t ulHardwareProfile, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ulHardwareProfile);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Set_HW_Prof_Ex(std::uint32_t ulHardwareProfile, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ulHardwareProfile);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Set_HW_Prof_FlagsA(const char* szDevInstName, std::uint32_t ulConfig, std::uint32_t ulValue, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(szDevInstName);
    static_cast<void>(ulConfig);
    static_cast<void>(ulValue);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Set_HW_Prof_FlagsW(const char16_t* szDevInstName, std::uint32_t ulConfig, std::uint32_t ulValue, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(szDevInstName);
    static_cast<void>(ulConfig);
    static_cast<void>(ulValue);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Set_HW_Prof_Flags_ExA(const char* szDevInstName, std::uint32_t ulConfig, std::uint32_t ulValue, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(szDevInstName);
    static_cast<void>(ulConfig);
    static_cast<void>(ulValue);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Set_HW_Prof_Flags_ExW(const char16_t* szDevInstName, std::uint32_t ulConfig, std::uint32_t ulValue, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(szDevInstName);
    static_cast<void>(ulConfig);
    static_cast<void>(ulValue);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Setup_DevNode(std::uint32_t dnDevInst, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Setup_DevNode_Ex(std::uint32_t dnDevInst, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnDevInst);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Test_Range_Available(std::uint64_t ullStartValue, std::uint64_t ullEndValue, std::uint64_t rlh, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ullStartValue);
    static_cast<void>(ullEndValue);
    static_cast<void>(rlh);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Uninstall_DevNode(std::uint64_t dnPhantom, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnPhantom);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Uninstall_DevNode_Ex(std::uint64_t dnPhantom, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(dnPhantom);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Unregister_Device_InterfaceA(const char* pszDeviceInterface, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pszDeviceInterface);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Unregister_Device_InterfaceW(const char16_t* pszDeviceInterface, std::uint32_t ulFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pszDeviceInterface);
    static_cast<void>(ulFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Unregister_Device_Interface_ExA(const char* pszDeviceInterface, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pszDeviceInterface);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_CM_Unregister_Device_Interface_ExW(const char16_t* pszDeviceInterface, std::uint32_t ulFlags, void* hMachine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(pszDeviceInterface);
    static_cast<void>(ulFlags);
    static_cast<void>(hMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void ksetupapiG_InstallHinfSectionA(void* Window, void* ModuleHandle, const char* CommandLine, std::int32_t ShowCommand) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Window);
    static_cast<void>(ModuleHandle);
    static_cast<void>(CommandLine);
    static_cast<void>(ShowCommand);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void ksetupapiG_InstallHinfSectionW(void* Window, void* ModuleHandle, const char16_t* CommandLine, std::int32_t ShowCommand) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Window);
    static_cast<void>(ModuleHandle);
    static_cast<void>(CommandLine);
    static_cast<void>(ShowCommand);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupAddInstallSectionToDiskSpaceListA(std::uint64_t DiskSpace, std::uint64_t InfHandle, std::uint64_t LayoutInfHandle, const char* SectionName, void* Reserved1, std::uint32_t Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DiskSpace);
    static_cast<void>(InfHandle);
    static_cast<void>(LayoutInfHandle);
    static_cast<void>(SectionName);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupAddInstallSectionToDiskSpaceListW(std::uint64_t DiskSpace, std::uint64_t InfHandle, std::uint64_t LayoutInfHandle, const char16_t* SectionName, void* Reserved1, std::uint32_t Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DiskSpace);
    static_cast<void>(InfHandle);
    static_cast<void>(LayoutInfHandle);
    static_cast<void>(SectionName);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupAddSectionToDiskSpaceListA(std::uint64_t DiskSpace, std::uint64_t InfHandle, std::uint64_t ListInfHandle, const char* SectionName, std::uint32_t Operation, void* Reserved1, std::uint32_t Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DiskSpace);
    static_cast<void>(InfHandle);
    static_cast<void>(ListInfHandle);
    static_cast<void>(SectionName);
    static_cast<void>(Operation);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupAddSectionToDiskSpaceListW(std::uint64_t DiskSpace, std::uint64_t InfHandle, std::uint64_t ListInfHandle, const char16_t* SectionName, std::uint32_t Operation, void* Reserved1, std::uint32_t Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DiskSpace);
    static_cast<void>(InfHandle);
    static_cast<void>(ListInfHandle);
    static_cast<void>(SectionName);
    static_cast<void>(Operation);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupAddToDiskSpaceListA(std::uint64_t DiskSpace, const char* TargetFilespec, std::int64_t FileSize, std::uint32_t Operation, void* Reserved1, std::uint32_t Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DiskSpace);
    static_cast<void>(TargetFilespec);
    static_cast<void>(FileSize);
    static_cast<void>(Operation);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupAddToDiskSpaceListW(std::uint64_t DiskSpace, const char16_t* TargetFilespec, std::int64_t FileSize, std::uint32_t Operation, void* Reserved1, std::uint32_t Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DiskSpace);
    static_cast<void>(TargetFilespec);
    static_cast<void>(FileSize);
    static_cast<void>(Operation);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupAddToSourceListA(std::uint32_t Flags, const char* Source) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Flags);
    static_cast<void>(Source);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupAddToSourceListW(std::uint32_t Flags, const char16_t* Source) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Flags);
    static_cast<void>(Source);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupAdjustDiskSpaceListA(std::uint64_t DiskSpace, const char* DriveRoot, std::int64_t Amount, void* Reserved1, std::uint32_t Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DiskSpace);
    static_cast<void>(DriveRoot);
    static_cast<void>(Amount);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupAdjustDiskSpaceListW(std::uint64_t DiskSpace, const char16_t* DriveRoot, std::int64_t Amount, void* Reserved1, std::uint32_t Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DiskSpace);
    static_cast<void>(DriveRoot);
    static_cast<void>(Amount);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_SetupBackupErrorA(void* hwndParent, const char* DialogTitle, const char* SourceFile, const char* TargetFile, std::uint32_t Win32ErrorCode, std::uint32_t Style) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(hwndParent);
    static_cast<void>(DialogTitle);
    static_cast<void>(SourceFile);
    static_cast<void>(TargetFile);
    static_cast<void>(Win32ErrorCode);
    static_cast<void>(Style);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_SetupBackupErrorW(void* hwndParent, const char16_t* DialogTitle, const char16_t* SourceFile, const char16_t* TargetFile, std::uint32_t Win32ErrorCode, std::uint32_t Style) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(hwndParent);
    static_cast<void>(DialogTitle);
    static_cast<void>(SourceFile);
    static_cast<void>(TargetFile);
    static_cast<void>(Win32ErrorCode);
    static_cast<void>(Style);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupCancelTemporarySourceList() noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupCloseFileQueue(std::uint64_t QueueHandle) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(QueueHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void ksetupapiG_SetupCloseInfFile(std::uint64_t InfHandle) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void ksetupapiG_SetupCloseLog() noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupCommitFileQueueA(void* Owner, std::uint64_t QueueHandle, void* MsgHandler, void* Context) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Owner);
    static_cast<void>(QueueHandle);
    static_cast<void>(MsgHandler);
    static_cast<void>(Context);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupCommitFileQueueW(void* Owner, std::uint64_t QueueHandle, void* MsgHandler, void* Context) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Owner);
    static_cast<void>(QueueHandle);
    static_cast<void>(MsgHandler);
    static_cast<void>(Context);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupConfigureWmiFromInfSectionA(std::uint64_t InfHandle, const char* SectionName, std::uint32_t Flags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(SectionName);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupConfigureWmiFromInfSectionW(std::uint64_t InfHandle, const char16_t* SectionName, std::uint32_t Flags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(SectionName);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_SetupCopyErrorA(void* hwndParent, const char* DialogTitle, const char* DiskName, const char* PathToSource, const char* SourceFile, const char* TargetPathFile, std::uint32_t Win32ErrorCode, std::uint32_t Style, char* PathBuffer, std::uint32_t PathBufferSize, std::uint32_t* PathRequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(hwndParent);
    static_cast<void>(DialogTitle);
    static_cast<void>(DiskName);
    static_cast<void>(PathToSource);
    static_cast<void>(SourceFile);
    static_cast<void>(TargetPathFile);
    static_cast<void>(Win32ErrorCode);
    static_cast<void>(Style);
    static_cast<void>(PathBuffer);
    static_cast<void>(PathBufferSize);
    static_cast<void>(PathRequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_SetupCopyErrorW(void* hwndParent, const char16_t* DialogTitle, const char16_t* DiskName, const char16_t* PathToSource, const char16_t* SourceFile, const char16_t* TargetPathFile, std::uint32_t Win32ErrorCode, std::uint32_t Style, char16_t* PathBuffer, std::uint32_t PathBufferSize, std::uint32_t* PathRequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(hwndParent);
    static_cast<void>(DialogTitle);
    static_cast<void>(DiskName);
    static_cast<void>(PathToSource);
    static_cast<void>(SourceFile);
    static_cast<void>(TargetPathFile);
    static_cast<void>(Win32ErrorCode);
    static_cast<void>(Style);
    static_cast<void>(PathBuffer);
    static_cast<void>(PathBufferSize);
    static_cast<void>(PathRequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupCopyOEMInfA(const char* SourceInfFileName, const char* OEMSourceMediaLocation, std::uint32_t OEMSourceMediaType, std::uint32_t CopyStyle, char* DestinationInfFileName, std::uint32_t DestinationInfFileNameSize, std::uint32_t* RequiredSize, char** DestinationInfFileNameComponent) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(SourceInfFileName);
    static_cast<void>(OEMSourceMediaLocation);
    static_cast<void>(OEMSourceMediaType);
    static_cast<void>(CopyStyle);
    static_cast<void>(DestinationInfFileName);
    static_cast<void>(DestinationInfFileNameSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(DestinationInfFileNameComponent);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupCopyOEMInfW(const char16_t* SourceInfFileName, const char16_t* OEMSourceMediaLocation, std::uint32_t OEMSourceMediaType, std::uint32_t CopyStyle, char16_t* DestinationInfFileName, std::uint32_t DestinationInfFileNameSize, std::uint32_t* RequiredSize, char16_t** DestinationInfFileNameComponent) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(SourceInfFileName);
    static_cast<void>(OEMSourceMediaLocation);
    static_cast<void>(OEMSourceMediaType);
    static_cast<void>(CopyStyle);
    static_cast<void>(DestinationInfFileName);
    static_cast<void>(DestinationInfFileNameSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(DestinationInfFileNameComponent);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t ksetupapiG_SetupCreateDiskSpaceListA(void* Reserved1, std::uint32_t Reserved2, std::uint32_t Flags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t ksetupapiG_SetupCreateDiskSpaceListW(void* Reserved1, std::uint32_t Reserved2, std::uint32_t Flags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_SetupDecompressOrCopyFileA(const char* SourceFileName, const char* TargetFileName, std::uint32_t* CompressionType) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(SourceFileName);
    static_cast<void>(TargetFileName);
    static_cast<void>(CompressionType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_SetupDecompressOrCopyFileW(const char16_t* SourceFileName, const char16_t* TargetFileName, std::uint32_t* CompressionType) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(SourceFileName);
    static_cast<void>(TargetFileName);
    static_cast<void>(CompressionType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_SetupDefaultQueueCallbackA(void* Context, std::uint32_t Notification, std::uint64_t Param1, std::uint64_t Param2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Context);
    static_cast<void>(Notification);
    static_cast<void>(Param1);
    static_cast<void>(Param2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_SetupDefaultQueueCallbackW(void* Context, std::uint32_t Notification, std::uint64_t Param1, std::uint64_t Param2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Context);
    static_cast<void>(Notification);
    static_cast<void>(Param1);
    static_cast<void>(Param2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_SetupDeleteErrorA(void* hwndParent, const char* DialogTitle, const char* File, std::uint32_t Win32ErrorCode, std::uint32_t Style) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(hwndParent);
    static_cast<void>(DialogTitle);
    static_cast<void>(File);
    static_cast<void>(Win32ErrorCode);
    static_cast<void>(Style);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_SetupDeleteErrorW(void* hwndParent, const char16_t* DialogTitle, const char16_t* File, std::uint32_t Win32ErrorCode, std::uint32_t Style) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(hwndParent);
    static_cast<void>(DialogTitle);
    static_cast<void>(File);
    static_cast<void>(Win32ErrorCode);
    static_cast<void>(Style);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDestroyDiskSpaceList(std::uint64_t DiskSpace) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DiskSpace);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiAskForOEMDisk(std::uint64_t DeviceInfoSet, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiBuildClassInfoList(std::uint32_t Flags, void* ClassGuidList, std::uint32_t ClassGuidListSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Flags);
    static_cast<void>(ClassGuidList);
    static_cast<void>(ClassGuidListSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiBuildClassInfoListExA(std::uint32_t Flags, void* ClassGuidList, std::uint32_t ClassGuidListSize, std::uint32_t* RequiredSize, const char* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Flags);
    static_cast<void>(ClassGuidList);
    static_cast<void>(ClassGuidListSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiBuildClassInfoListExW(std::uint32_t Flags, void* ClassGuidList, std::uint32_t ClassGuidListSize, std::uint32_t* RequiredSize, const char16_t* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Flags);
    static_cast<void>(ClassGuidList);
    static_cast<void>(ClassGuidListSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiBuildDriverInfoList(std::uint64_t DeviceInfoSet, void* DeviceInfoData, std::uint32_t DriverType) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(DriverType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiCallClassInstaller(std::uint64_t InstallFunction, std::uint64_t DeviceInfoSet, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InstallFunction);
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiCancelDriverInfoSearch(std::uint64_t DeviceInfoSet) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiChangeState(std::uint64_t DeviceInfoSet, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiClassGuidsFromNameA(const char* ClassName, void* ClassGuidList, std::uint32_t ClassGuidListSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassName);
    static_cast<void>(ClassGuidList);
    static_cast<void>(ClassGuidListSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiClassGuidsFromNameExA(const char* ClassName, void* ClassGuidList, std::uint32_t ClassGuidListSize, std::uint32_t* RequiredSize, const char* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassName);
    static_cast<void>(ClassGuidList);
    static_cast<void>(ClassGuidListSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiClassGuidsFromNameExW(const char16_t* ClassName, void* ClassGuidList, std::uint32_t ClassGuidListSize, std::uint32_t* RequiredSize, const char16_t* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassName);
    static_cast<void>(ClassGuidList);
    static_cast<void>(ClassGuidListSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiClassGuidsFromNameW(const char16_t* ClassName, void* ClassGuidList, std::uint32_t ClassGuidListSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassName);
    static_cast<void>(ClassGuidList);
    static_cast<void>(ClassGuidListSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiClassNameFromGuidA(const void* ClassGuid, char* ClassName, std::uint32_t ClassNameSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(ClassName);
    static_cast<void>(ClassNameSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiClassNameFromGuidExA(const void* ClassGuid, char* ClassName, std::uint32_t ClassNameSize, std::uint32_t* RequiredSize, const char* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(ClassName);
    static_cast<void>(ClassNameSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiClassNameFromGuidExW(const void* ClassGuid, char16_t* ClassName, std::uint32_t ClassNameSize, std::uint32_t* RequiredSize, const char16_t* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(ClassName);
    static_cast<void>(ClassNameSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiClassNameFromGuidW(const void* ClassGuid, char16_t* ClassName, std::uint32_t ClassNameSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(ClassName);
    static_cast<void>(ClassNameSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* ksetupapiG_SetupDiCreateDevRegKeyA(std::uint64_t DeviceInfoSet, void* DeviceInfoData, std::uint32_t Scope, std::uint32_t HwProfile, std::uint32_t KeyType, std::uint64_t InfHandle, const char* InfSectionName) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(Scope);
    static_cast<void>(HwProfile);
    static_cast<void>(KeyType);
    static_cast<void>(InfHandle);
    static_cast<void>(InfSectionName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* ksetupapiG_SetupDiCreateDevRegKeyW(std::uint64_t DeviceInfoSet, void* DeviceInfoData, std::uint32_t Scope, std::uint32_t HwProfile, std::uint32_t KeyType, std::uint64_t InfHandle, const char16_t* InfSectionName) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(Scope);
    static_cast<void>(HwProfile);
    static_cast<void>(KeyType);
    static_cast<void>(InfHandle);
    static_cast<void>(InfSectionName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiCreateDeviceInfoA(std::uint64_t DeviceInfoSet, const char* DeviceName, const void* ClassGuid, const char* DeviceDescription, void* hwndParent, std::uint32_t CreationFlags, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceName);
    static_cast<void>(ClassGuid);
    static_cast<void>(DeviceDescription);
    static_cast<void>(hwndParent);
    static_cast<void>(CreationFlags);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t ksetupapiG_SetupDiCreateDeviceInfoList(const void* ClassGuid, void* hwndParent) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(hwndParent);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t ksetupapiG_SetupDiCreateDeviceInfoListExA(const void* ClassGuid, void* hwndParent, const char* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(hwndParent);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t ksetupapiG_SetupDiCreateDeviceInfoListExW(const void* ClassGuid, void* hwndParent, const char16_t* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(hwndParent);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiCreateDeviceInfoW(std::uint64_t DeviceInfoSet, const char16_t* DeviceName, const void* ClassGuid, const char16_t* DeviceDescription, void* hwndParent, std::uint32_t CreationFlags, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceName);
    static_cast<void>(ClassGuid);
    static_cast<void>(DeviceDescription);
    static_cast<void>(hwndParent);
    static_cast<void>(CreationFlags);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiCreateDeviceInterfaceA(std::uint64_t DeviceInfoSet, void* DeviceInfoData, const void* InterfaceClassGuid, const char* ReferenceString, std::uint32_t CreationFlags, void* DeviceInterfaceData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(InterfaceClassGuid);
    static_cast<void>(ReferenceString);
    static_cast<void>(CreationFlags);
    static_cast<void>(DeviceInterfaceData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* ksetupapiG_SetupDiCreateDeviceInterfaceRegKeyA(std::uint64_t DeviceInfoSet, void* DeviceInterfaceData, std::uint32_t Reserved, std::uint32_t samDesired, std::uint64_t InfHandle, const char* InfSectionName) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInterfaceData);
    static_cast<void>(Reserved);
    static_cast<void>(samDesired);
    static_cast<void>(InfHandle);
    static_cast<void>(InfSectionName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* ksetupapiG_SetupDiCreateDeviceInterfaceRegKeyW(std::uint64_t DeviceInfoSet, void* DeviceInterfaceData, std::uint32_t Reserved, std::uint32_t samDesired, std::uint64_t InfHandle, const char16_t* InfSectionName) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInterfaceData);
    static_cast<void>(Reserved);
    static_cast<void>(samDesired);
    static_cast<void>(InfHandle);
    static_cast<void>(InfSectionName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiCreateDeviceInterfaceW(std::uint64_t DeviceInfoSet, void* DeviceInfoData, const void* InterfaceClassGuid, const char16_t* ReferenceString, std::uint32_t CreationFlags, void* DeviceInterfaceData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(InterfaceClassGuid);
    static_cast<void>(ReferenceString);
    static_cast<void>(CreationFlags);
    static_cast<void>(DeviceInterfaceData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiDeleteDevRegKey(std::uint64_t DeviceInfoSet, void* DeviceInfoData, std::uint32_t Scope, std::uint32_t HwProfile, std::uint32_t KeyType) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(Scope);
    static_cast<void>(HwProfile);
    static_cast<void>(KeyType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiDeleteDeviceInfo(std::uint64_t DeviceInfoSet, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiDeleteDeviceInterfaceData(std::uint64_t DeviceInfoSet, void* DeviceInterfaceData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInterfaceData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiDeleteDeviceInterfaceRegKey(std::uint64_t DeviceInfoSet, void* DeviceInterfaceData, std::uint32_t Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInterfaceData);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiDestroyClassImageList(void* ClassImageListData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassImageListData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiDestroyDriverInfoList(std::uint64_t DeviceInfoSet, void* DeviceInfoData, std::uint32_t DriverType) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(DriverType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiDrawMiniIcon(void* hdc, std::uint64_t rc, std::int32_t MiniIconIndex, std::uint32_t Flags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(hdc);
    static_cast<void>(rc);
    static_cast<void>(MiniIconIndex);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiEnumDeviceInterfaces(std::uint64_t DeviceInfoSet, void* DeviceInfoData, const void* InterfaceClassGuid, std::uint32_t MemberIndex, void* DeviceInterfaceData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(InterfaceClassGuid);
    static_cast<void>(MemberIndex);
    static_cast<void>(DeviceInterfaceData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiEnumDriverInfoA(std::uint64_t DeviceInfoSet, void* DeviceInfoData, std::uint32_t DriverType, std::uint32_t MemberIndex, void* DriverInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(DriverType);
    static_cast<void>(MemberIndex);
    static_cast<void>(DriverInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiEnumDriverInfoW(std::uint64_t DeviceInfoSet, void* DeviceInfoData, std::uint32_t DriverType, std::uint32_t MemberIndex, void* DriverInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(DriverType);
    static_cast<void>(MemberIndex);
    static_cast<void>(DriverInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetActualModelsSectionA(void* Context, void* AlternatePlatformInfo, char* InfSectionWithExt, std::uint32_t InfSectionWithExtSize, std::uint32_t* RequiredSize, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Context);
    static_cast<void>(AlternatePlatformInfo);
    static_cast<void>(InfSectionWithExt);
    static_cast<void>(InfSectionWithExtSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetActualModelsSectionW(void* Context, void* AlternatePlatformInfo, char16_t* InfSectionWithExt, std::uint32_t InfSectionWithExtSize, std::uint32_t* RequiredSize, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Context);
    static_cast<void>(AlternatePlatformInfo);
    static_cast<void>(InfSectionWithExt);
    static_cast<void>(InfSectionWithExtSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetActualSectionToInstallA(std::uint64_t InfHandle, const char* InfSectionName, char* InfSectionWithExt, std::uint32_t InfSectionWithExtSize, std::uint32_t* RequiredSize, char** Extension) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(InfSectionName);
    static_cast<void>(InfSectionWithExt);
    static_cast<void>(InfSectionWithExtSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(Extension);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetActualSectionToInstallExA(std::uint64_t InfHandle, const char* InfSectionName, void* AlternatePlatformInfo, char* InfSectionWithExt, std::uint32_t InfSectionWithExtSize, std::uint32_t* RequiredSize, char** Extension, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(InfSectionName);
    static_cast<void>(AlternatePlatformInfo);
    static_cast<void>(InfSectionWithExt);
    static_cast<void>(InfSectionWithExtSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(Extension);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetActualSectionToInstallExW(std::uint64_t InfHandle, const char16_t* InfSectionName, void* AlternatePlatformInfo, char16_t* InfSectionWithExt, std::uint32_t InfSectionWithExtSize, std::uint32_t* RequiredSize, char16_t** Extension, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(InfSectionName);
    static_cast<void>(AlternatePlatformInfo);
    static_cast<void>(InfSectionWithExt);
    static_cast<void>(InfSectionWithExtSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(Extension);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetActualSectionToInstallW(std::uint64_t InfHandle, const char16_t* InfSectionName, char16_t* InfSectionWithExt, std::uint32_t InfSectionWithExtSize, std::uint32_t* RequiredSize, char16_t** Extension) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(InfSectionName);
    static_cast<void>(InfSectionWithExt);
    static_cast<void>(InfSectionWithExtSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(Extension);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetClassBitmapIndex(const void* ClassGuid, std::int32_t* MiniIconIndex) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(MiniIconIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetClassDescriptionA(const void* ClassGuid, char* ClassDescription, std::uint32_t ClassDescriptionSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(ClassDescription);
    static_cast<void>(ClassDescriptionSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetClassDescriptionExA(const void* ClassGuid, char* ClassDescription, std::uint32_t ClassDescriptionSize, std::uint32_t* RequiredSize, const char* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(ClassDescription);
    static_cast<void>(ClassDescriptionSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetClassDescriptionExW(const void* ClassGuid, char16_t* ClassDescription, std::uint32_t ClassDescriptionSize, std::uint32_t* RequiredSize, const char16_t* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(ClassDescription);
    static_cast<void>(ClassDescriptionSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetClassDescriptionW(const void* ClassGuid, char16_t* ClassDescription, std::uint32_t ClassDescriptionSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(ClassDescription);
    static_cast<void>(ClassDescriptionSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetClassDevPropertySheetsA(std::uint64_t DeviceInfoSet, void* DeviceInfoData, std::uint64_t PropertySheetHeader, std::uint32_t PropertySheetHeaderPageListSize, std::uint32_t* RequiredSize, std::uint32_t PropertySheetType) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(PropertySheetHeader);
    static_cast<void>(PropertySheetHeaderPageListSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(PropertySheetType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetClassDevPropertySheetsW(std::uint64_t DeviceInfoSet, void* DeviceInfoData, std::uint64_t PropertySheetHeader, std::uint32_t PropertySheetHeaderPageListSize, std::uint32_t* RequiredSize, std::uint32_t PropertySheetType) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(PropertySheetHeader);
    static_cast<void>(PropertySheetHeaderPageListSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(PropertySheetType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t ksetupapiG_SetupDiGetClassDevsExA(const void* ClassGuid, const char* Enumerator, void* hwndParent, std::uint32_t Flags, std::uint64_t DeviceInfoSet, const char* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(Enumerator);
    static_cast<void>(hwndParent);
    static_cast<void>(Flags);
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t ksetupapiG_SetupDiGetClassDevsExW(const void* ClassGuid, const char16_t* Enumerator, void* hwndParent, std::uint32_t Flags, std::uint64_t DeviceInfoSet, const char16_t* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(Enumerator);
    static_cast<void>(hwndParent);
    static_cast<void>(Flags);
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetClassImageIndex(void* ClassImageListData, const void* ClassGuid, std::int32_t* ImageIndex) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassImageListData);
    static_cast<void>(ClassGuid);
    static_cast<void>(ImageIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetClassImageList(void* ClassImageListData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassImageListData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetClassImageListExA(void* ClassImageListData, const char* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassImageListData);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetClassImageListExW(void* ClassImageListData, const char16_t* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassImageListData);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetClassInstallParamsA(std::uint64_t DeviceInfoSet, void* DeviceInfoData, void* ClassInstallParams, std::uint32_t ClassInstallParamsSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(ClassInstallParams);
    static_cast<void>(ClassInstallParamsSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetClassInstallParamsW(std::uint64_t DeviceInfoSet, void* DeviceInfoData, void* ClassInstallParams, std::uint32_t ClassInstallParamsSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(ClassInstallParams);
    static_cast<void>(ClassInstallParamsSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetClassRegistryPropertyA(const void* ClassGuid, std::uint32_t Property, std::uint32_t* PropertyRegDataType, std::uint8_t* PropertyBuffer, std::uint32_t PropertyBufferSize, std::uint32_t* RequiredSize, const char* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(Property);
    static_cast<void>(PropertyRegDataType);
    static_cast<void>(PropertyBuffer);
    static_cast<void>(PropertyBufferSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetClassRegistryPropertyW(const void* ClassGuid, std::uint32_t Property, std::uint32_t* PropertyRegDataType, std::uint8_t* PropertyBuffer, std::uint32_t PropertyBufferSize, std::uint32_t* RequiredSize, const char16_t* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(Property);
    static_cast<void>(PropertyRegDataType);
    static_cast<void>(PropertyBuffer);
    static_cast<void>(PropertyBufferSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetCustomDevicePropertyA(std::uint64_t DeviceInfoSet, void* DeviceInfoData, const char* CustomPropertyName, std::uint32_t Flags, std::uint32_t* PropertyRegDataType, std::uint8_t* PropertyBuffer, std::uint32_t PropertyBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(CustomPropertyName);
    static_cast<void>(Flags);
    static_cast<void>(PropertyRegDataType);
    static_cast<void>(PropertyBuffer);
    static_cast<void>(PropertyBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetCustomDevicePropertyW(std::uint64_t DeviceInfoSet, void* DeviceInfoData, const char16_t* CustomPropertyName, std::uint32_t Flags, std::uint32_t* PropertyRegDataType, std::uint8_t* PropertyBuffer, std::uint32_t PropertyBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(CustomPropertyName);
    static_cast<void>(Flags);
    static_cast<void>(PropertyRegDataType);
    static_cast<void>(PropertyBuffer);
    static_cast<void>(PropertyBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetDeviceInfoListClass(std::uint64_t DeviceInfoSet, void* ClassGuid) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(ClassGuid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetDeviceInfoListDetailA(std::uint64_t DeviceInfoSet, std::uint64_t DeviceInfoSetDetailData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoSetDetailData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetDeviceInfoListDetailW(std::uint64_t DeviceInfoSet, std::uint64_t DeviceInfoSetDetailData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoSetDetailData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetDeviceInstallParamsA(std::uint64_t DeviceInfoSet, void* DeviceInfoData, void* DeviceInstallParams) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(DeviceInstallParams);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetDeviceInstallParamsW(std::uint64_t DeviceInfoSet, void* DeviceInfoData, void* DeviceInstallParams) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(DeviceInstallParams);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetDeviceInstanceIdA(std::uint64_t DeviceInfoSet, void* DeviceInfoData, char* DeviceInstanceId, std::uint32_t DeviceInstanceIdSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(DeviceInstanceId);
    static_cast<void>(DeviceInstanceIdSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetDeviceInstanceIdW(std::uint64_t DeviceInfoSet, void* DeviceInfoData, char16_t* DeviceInstanceId, std::uint32_t DeviceInstanceIdSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(DeviceInstanceId);
    static_cast<void>(DeviceInstanceIdSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetDeviceInterfaceAlias(std::uint64_t DeviceInfoSet, void* DeviceInterfaceData, const void* AliasInterfaceClassGuid, void* AliasDeviceInterfaceData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInterfaceData);
    static_cast<void>(AliasInterfaceClassGuid);
    static_cast<void>(AliasDeviceInterfaceData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetDeviceInterfaceDetailA(std::uint64_t DeviceInfoSet, void* DeviceInterfaceData, void* DeviceInterfaceDetailData, std::uint32_t DeviceInterfaceDetailDataSize, std::uint32_t* RequiredSize, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInterfaceData);
    static_cast<void>(DeviceInterfaceDetailData);
    static_cast<void>(DeviceInterfaceDetailDataSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetDeviceInterfaceDetailW(std::uint64_t DeviceInfoSet, void* DeviceInterfaceData, void* DeviceInterfaceDetailData, std::uint32_t DeviceInterfaceDetailDataSize, std::uint32_t* RequiredSize, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInterfaceData);
    static_cast<void>(DeviceInterfaceDetailData);
    static_cast<void>(DeviceInterfaceDetailDataSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetDeviceRegistryPropertyA(std::uint64_t DeviceInfoSet, void* DeviceInfoData, std::uint32_t Property, std::uint32_t* PropertyRegDataType, std::uint8_t* PropertyBuffer, std::uint32_t PropertyBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(Property);
    static_cast<void>(PropertyRegDataType);
    static_cast<void>(PropertyBuffer);
    static_cast<void>(PropertyBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetDeviceRegistryPropertyW(std::uint64_t DeviceInfoSet, void* DeviceInfoData, std::uint32_t Property, std::uint32_t* PropertyRegDataType, std::uint8_t* PropertyBuffer, std::uint32_t PropertyBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(Property);
    static_cast<void>(PropertyRegDataType);
    static_cast<void>(PropertyBuffer);
    static_cast<void>(PropertyBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetDriverInfoDetailA(std::uint64_t DeviceInfoSet, void* DeviceInfoData, void* DriverInfoData, void* DriverInfoDetailData, std::uint32_t DriverInfoDetailDataSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(DriverInfoData);
    static_cast<void>(DriverInfoDetailData);
    static_cast<void>(DriverInfoDetailDataSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetDriverInfoDetailW(std::uint64_t DeviceInfoSet, void* DeviceInfoData, void* DriverInfoData, void* DriverInfoDetailData, std::uint32_t DriverInfoDetailDataSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(DriverInfoData);
    static_cast<void>(DriverInfoDetailData);
    static_cast<void>(DriverInfoDetailDataSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetDriverInstallParamsA(std::uint64_t DeviceInfoSet, void* DeviceInfoData, void* DriverInfoData, void* DriverInstallParams) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(DriverInfoData);
    static_cast<void>(DriverInstallParams);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetDriverInstallParamsW(std::uint64_t DeviceInfoSet, void* DeviceInfoData, void* DriverInfoData, void* DriverInstallParams) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(DriverInfoData);
    static_cast<void>(DriverInstallParams);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetHwProfileFriendlyNameA(std::uint32_t HwProfile, char* FriendlyName, std::uint32_t FriendlyNameSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(HwProfile);
    static_cast<void>(FriendlyName);
    static_cast<void>(FriendlyNameSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetHwProfileFriendlyNameExA(std::uint32_t HwProfile, char* FriendlyName, std::uint32_t FriendlyNameSize, std::uint32_t* RequiredSize, const char* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(HwProfile);
    static_cast<void>(FriendlyName);
    static_cast<void>(FriendlyNameSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetHwProfileFriendlyNameExW(std::uint32_t HwProfile, char16_t* FriendlyName, std::uint32_t FriendlyNameSize, std::uint32_t* RequiredSize, const char16_t* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(HwProfile);
    static_cast<void>(FriendlyName);
    static_cast<void>(FriendlyNameSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetHwProfileFriendlyNameW(std::uint32_t HwProfile, char16_t* FriendlyName, std::uint32_t FriendlyNameSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(HwProfile);
    static_cast<void>(FriendlyName);
    static_cast<void>(FriendlyNameSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetHwProfileList(std::uint32_t* HwProfileList, std::uint32_t HwProfileListSize, std::uint32_t* RequiredSize, std::uint32_t* CurrentlyActiveIndex) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(HwProfileList);
    static_cast<void>(HwProfileListSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(CurrentlyActiveIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetHwProfileListExA(std::uint32_t* HwProfileList, std::uint32_t HwProfileListSize, std::uint32_t* RequiredSize, std::uint32_t* CurrentlyActiveIndex, const char* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(HwProfileList);
    static_cast<void>(HwProfileListSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(CurrentlyActiveIndex);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetHwProfileListExW(std::uint32_t* HwProfileList, std::uint32_t HwProfileListSize, std::uint32_t* RequiredSize, std::uint32_t* CurrentlyActiveIndex, const char16_t* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(HwProfileList);
    static_cast<void>(HwProfileListSize);
    static_cast<void>(RequiredSize);
    static_cast<void>(CurrentlyActiveIndex);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetINFClassA(const char* InfName, void* ClassGuid, char* ClassName, std::uint32_t ClassNameSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfName);
    static_cast<void>(ClassGuid);
    static_cast<void>(ClassName);
    static_cast<void>(ClassNameSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetINFClassW(const char16_t* InfName, void* ClassGuid, char16_t* ClassName, std::uint32_t ClassNameSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfName);
    static_cast<void>(ClassGuid);
    static_cast<void>(ClassName);
    static_cast<void>(ClassNameSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetSelectedDevice(std::uint64_t DeviceInfoSet, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetSelectedDriverA(std::uint64_t DeviceInfoSet, void* DeviceInfoData, void* DriverInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(DriverInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiGetSelectedDriverW(std::uint64_t DeviceInfoSet, void* DeviceInfoData, void* DriverInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(DriverInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* ksetupapiG_SetupDiGetWizardPage(std::uint64_t DeviceInfoSet, void* DeviceInfoData, std::uint64_t InstallWizardData, std::uint32_t PageType, std::uint32_t Flags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(InstallWizardData);
    static_cast<void>(PageType);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiInstallClassA(void* hwndParent, const char* InfFileName, std::uint32_t Flags, std::uint64_t FileQueue) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(hwndParent);
    static_cast<void>(InfFileName);
    static_cast<void>(Flags);
    static_cast<void>(FileQueue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiInstallClassExA(void* hwndParent, const char* InfFileName, std::uint32_t Flags, std::uint64_t FileQueue, const void* InterfaceClassGuid, void* Reserved1, void* Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(hwndParent);
    static_cast<void>(InfFileName);
    static_cast<void>(Flags);
    static_cast<void>(FileQueue);
    static_cast<void>(InterfaceClassGuid);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiInstallClassExW(void* hwndParent, const char16_t* InfFileName, std::uint32_t Flags, std::uint64_t FileQueue, const void* InterfaceClassGuid, void* Reserved1, void* Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(hwndParent);
    static_cast<void>(InfFileName);
    static_cast<void>(Flags);
    static_cast<void>(FileQueue);
    static_cast<void>(InterfaceClassGuid);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiInstallClassW(void* hwndParent, const char16_t* InfFileName, std::uint32_t Flags, std::uint64_t FileQueue) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(hwndParent);
    static_cast<void>(InfFileName);
    static_cast<void>(Flags);
    static_cast<void>(FileQueue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiInstallDevice(std::uint64_t DeviceInfoSet, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiInstallDeviceInterfaces(std::uint64_t DeviceInfoSet, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiInstallDriverFiles(std::uint64_t DeviceInfoSet, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiLoadClassIcon(const void* ClassGuid, void* LargeIcon, std::int32_t* MiniIconIndex) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(LargeIcon);
    static_cast<void>(MiniIconIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* ksetupapiG_SetupDiOpenClassRegKey(const void* ClassGuid, std::uint32_t samDesired) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(samDesired);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* ksetupapiG_SetupDiOpenClassRegKeyExA(const void* ClassGuid, std::uint32_t samDesired, std::uint32_t Flags, const char* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(samDesired);
    static_cast<void>(Flags);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* ksetupapiG_SetupDiOpenClassRegKeyExW(const void* ClassGuid, std::uint32_t samDesired, std::uint32_t Flags, const char16_t* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(samDesired);
    static_cast<void>(Flags);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* ksetupapiG_SetupDiOpenDevRegKey(std::uint64_t DeviceInfoSet, void* DeviceInfoData, std::uint32_t Scope, std::uint32_t HwProfile, std::uint32_t KeyType, std::uint32_t samDesired) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(Scope);
    static_cast<void>(HwProfile);
    static_cast<void>(KeyType);
    static_cast<void>(samDesired);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiOpenDeviceInfoA(std::uint64_t DeviceInfoSet, const char* DeviceInstanceId, void* hwndParent, std::uint32_t OpenFlags, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInstanceId);
    static_cast<void>(hwndParent);
    static_cast<void>(OpenFlags);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiOpenDeviceInfoW(std::uint64_t DeviceInfoSet, const char16_t* DeviceInstanceId, void* hwndParent, std::uint32_t OpenFlags, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInstanceId);
    static_cast<void>(hwndParent);
    static_cast<void>(OpenFlags);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiOpenDeviceInterfaceA(std::uint64_t DeviceInfoSet, const char* DevicePath, std::uint32_t OpenFlags, void* DeviceInterfaceData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DevicePath);
    static_cast<void>(OpenFlags);
    static_cast<void>(DeviceInterfaceData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* ksetupapiG_SetupDiOpenDeviceInterfaceRegKey(std::uint64_t DeviceInfoSet, void* DeviceInterfaceData, std::uint32_t Reserved, std::uint32_t samDesired) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInterfaceData);
    static_cast<void>(Reserved);
    static_cast<void>(samDesired);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiOpenDeviceInterfaceW(std::uint64_t DeviceInfoSet, const char16_t* DevicePath, std::uint32_t OpenFlags, void* DeviceInterfaceData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DevicePath);
    static_cast<void>(OpenFlags);
    static_cast<void>(DeviceInterfaceData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiRegisterCoDeviceInstallers(std::uint64_t DeviceInfoSet, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiRegisterDeviceInfo(std::uint64_t DeviceInfoSet, void* DeviceInfoData, std::uint32_t Flags, std::uint64_t CompareProc, void* CompareContext, void* DupDeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(Flags);
    static_cast<void>(CompareProc);
    static_cast<void>(CompareContext);
    static_cast<void>(DupDeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiRemoveDevice(std::uint64_t DeviceInfoSet, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiRemoveDeviceInterface(std::uint64_t DeviceInfoSet, void* DeviceInterfaceData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInterfaceData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiRestartDevices(std::uint64_t DeviceInfoSet, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiSelectBestCompatDrv(std::uint64_t DeviceInfoSet, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiSelectDevice(std::uint64_t DeviceInfoSet, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiSelectOEMDrv(void* hwndParent, std::uint64_t DeviceInfoSet, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(hwndParent);
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiSetClassInstallParamsA(std::uint64_t DeviceInfoSet, void* DeviceInfoData, void* ClassInstallParams, std::uint32_t ClassInstallParamsSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(ClassInstallParams);
    static_cast<void>(ClassInstallParamsSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiSetClassInstallParamsW(std::uint64_t DeviceInfoSet, void* DeviceInfoData, void* ClassInstallParams, std::uint32_t ClassInstallParamsSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(ClassInstallParams);
    static_cast<void>(ClassInstallParamsSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiSetClassRegistryPropertyA(const void* ClassGuid, std::uint32_t Property, const std::uint8_t* PropertyBuffer, std::uint32_t PropertyBufferSize, const char* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(Property);
    static_cast<void>(PropertyBuffer);
    static_cast<void>(PropertyBufferSize);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiSetClassRegistryPropertyW(const void* ClassGuid, std::uint32_t Property, const std::uint8_t* PropertyBuffer, std::uint32_t PropertyBufferSize, const char16_t* MachineName, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ClassGuid);
    static_cast<void>(Property);
    static_cast<void>(PropertyBuffer);
    static_cast<void>(PropertyBufferSize);
    static_cast<void>(MachineName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiSetDeviceInstallParamsA(std::uint64_t DeviceInfoSet, void* DeviceInfoData, void* DeviceInstallParams) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(DeviceInstallParams);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiSetDeviceInstallParamsW(std::uint64_t DeviceInfoSet, void* DeviceInfoData, void* DeviceInstallParams) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(DeviceInstallParams);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiSetDeviceInterfaceDefault(std::uint64_t DeviceInfoSet, void* DeviceInterfaceData, std::uint32_t Flags, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInterfaceData);
    static_cast<void>(Flags);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiSetDeviceRegistryPropertyA(std::uint64_t DeviceInfoSet, void* DeviceInfoData, std::uint32_t Property, const std::uint8_t* PropertyBuffer, std::uint32_t PropertyBufferSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(Property);
    static_cast<void>(PropertyBuffer);
    static_cast<void>(PropertyBufferSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiSetDeviceRegistryPropertyW(std::uint64_t DeviceInfoSet, void* DeviceInfoData, std::uint32_t Property, const std::uint8_t* PropertyBuffer, std::uint32_t PropertyBufferSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(Property);
    static_cast<void>(PropertyBuffer);
    static_cast<void>(PropertyBufferSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiSetDriverInstallParamsA(std::uint64_t DeviceInfoSet, void* DeviceInfoData, void* DriverInfoData, void* DriverInstallParams) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(DriverInfoData);
    static_cast<void>(DriverInstallParams);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiSetDriverInstallParamsW(std::uint64_t DeviceInfoSet, void* DeviceInfoData, void* DriverInfoData, void* DriverInstallParams) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(DriverInfoData);
    static_cast<void>(DriverInstallParams);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiSetSelectedDevice(std::uint64_t DeviceInfoSet, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiSetSelectedDriverA(std::uint64_t DeviceInfoSet, void* DeviceInfoData, void* DriverInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(DriverInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiSetSelectedDriverW(std::uint64_t DeviceInfoSet, void* DeviceInfoData, void* DriverInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(DriverInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupDiUnremoveDevice(std::uint64_t DeviceInfoSet, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t ksetupapiG_SetupDuplicateDiskSpaceListA(std::uint64_t DiskSpace, void* Reserved1, std::uint32_t Reserved2, std::uint32_t Flags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DiskSpace);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t ksetupapiG_SetupDuplicateDiskSpaceListW(std::uint64_t DiskSpace, void* Reserved1, std::uint32_t Reserved2, std::uint32_t Flags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DiskSpace);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupEnumInfSectionsA(std::uint64_t InfHandle, std::uint32_t Index, char* Buffer, std::uint32_t Size, std::uint32_t* SizeNeeded) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(Index);
    static_cast<void>(Buffer);
    static_cast<void>(Size);
    static_cast<void>(SizeNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupEnumInfSectionsW(std::uint64_t InfHandle, std::uint32_t Index, char16_t* Buffer, std::uint32_t Size, std::uint32_t* SizeNeeded) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(Index);
    static_cast<void>(Buffer);
    static_cast<void>(Size);
    static_cast<void>(SizeNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupFindFirstLineA(std::uint64_t InfHandle, const char* Section, const char* Key, void* Context) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(Section);
    static_cast<void>(Key);
    static_cast<void>(Context);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupFindFirstLineW(std::uint64_t InfHandle, const char16_t* Section, const char16_t* Key, void* Context) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(Section);
    static_cast<void>(Key);
    static_cast<void>(Context);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupFindNextLine(void* ContextIn, void* ContextOut) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ContextIn);
    static_cast<void>(ContextOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupFindNextMatchLineA(void* ContextIn, const char* Key, void* ContextOut) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ContextIn);
    static_cast<void>(Key);
    static_cast<void>(ContextOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupFindNextMatchLineW(void* ContextIn, const char16_t* Key, void* ContextOut) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(ContextIn);
    static_cast<void>(Key);
    static_cast<void>(ContextOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupFreeSourceListA(const char*** List, std::uint32_t Count) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(List);
    static_cast<void>(Count);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupFreeSourceListW(const char16_t*** List, std::uint32_t Count) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(List);
    static_cast<void>(Count);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetBackupInformationA(std::uint64_t QueueHandle, std::uint64_t BackupParams) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(QueueHandle);
    static_cast<void>(BackupParams);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetBackupInformationW(std::uint64_t QueueHandle, std::uint64_t BackupParams) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(QueueHandle);
    static_cast<void>(BackupParams);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetBinaryField(void* Context, std::uint32_t FieldIndex, std::uint8_t* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Context);
    static_cast<void>(FieldIndex);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_SetupGetFieldCount(void* Context) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Context);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_SetupGetFileCompressionInfoA(const char* SourceFileName, char** ActualSourceFileName, std::uint32_t* SourceFileSize, std::uint32_t* TargetFileSize, std::uint32_t* CompressionType) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(SourceFileName);
    static_cast<void>(ActualSourceFileName);
    static_cast<void>(SourceFileSize);
    static_cast<void>(TargetFileSize);
    static_cast<void>(CompressionType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetFileCompressionInfoExA(const char* SourceFileName, char* ActualSourceFileNameBuffer, std::uint32_t ActualSourceFileNameBufferLen, std::uint32_t* RequiredBufferLen, std::uint32_t* SourceFileSize, std::uint32_t* TargetFileSize, std::uint32_t* CompressionType) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(SourceFileName);
    static_cast<void>(ActualSourceFileNameBuffer);
    static_cast<void>(ActualSourceFileNameBufferLen);
    static_cast<void>(RequiredBufferLen);
    static_cast<void>(SourceFileSize);
    static_cast<void>(TargetFileSize);
    static_cast<void>(CompressionType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetFileCompressionInfoExW(const char16_t* SourceFileName, char16_t* ActualSourceFileNameBuffer, std::uint32_t ActualSourceFileNameBufferLen, std::uint32_t* RequiredBufferLen, std::uint32_t* SourceFileSize, std::uint32_t* TargetFileSize, std::uint32_t* CompressionType) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(SourceFileName);
    static_cast<void>(ActualSourceFileNameBuffer);
    static_cast<void>(ActualSourceFileNameBufferLen);
    static_cast<void>(RequiredBufferLen);
    static_cast<void>(SourceFileSize);
    static_cast<void>(TargetFileSize);
    static_cast<void>(CompressionType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_SetupGetFileCompressionInfoW(const char16_t* SourceFileName, char16_t** ActualSourceFileName, std::uint32_t* SourceFileSize, std::uint32_t* TargetFileSize, std::uint32_t* CompressionType) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(SourceFileName);
    static_cast<void>(ActualSourceFileName);
    static_cast<void>(SourceFileSize);
    static_cast<void>(TargetFileSize);
    static_cast<void>(CompressionType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetFileQueueCount(std::uint64_t FileQueue, std::uint32_t SubQueueFileOp, std::uint32_t* NumOperations) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(FileQueue);
    static_cast<void>(SubQueueFileOp);
    static_cast<void>(NumOperations);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetFileQueueFlags(std::uint64_t FileQueue, std::uint32_t* Flags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(FileQueue);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetInfFileListA(const char* DirectoryPath, std::uint32_t InfStyle, char* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DirectoryPath);
    static_cast<void>(InfStyle);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetInfFileListW(const char16_t* DirectoryPath, std::uint32_t InfStyle, char16_t* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DirectoryPath);
    static_cast<void>(InfStyle);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetInfInformationA(const void* InfSpec, std::uint32_t SearchControl, void* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfSpec);
    static_cast<void>(SearchControl);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetInfInformationW(const void* InfSpec, std::uint32_t SearchControl, void* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfSpec);
    static_cast<void>(SearchControl);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetIntField(void* Context, std::uint32_t FieldIndex, std::int32_t* IntegerValue) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Context);
    static_cast<void>(FieldIndex);
    static_cast<void>(IntegerValue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetLineByIndexA(std::uint64_t InfHandle, const char* Section, std::uint32_t Index, void* Context) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(Section);
    static_cast<void>(Index);
    static_cast<void>(Context);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetLineByIndexW(std::uint64_t InfHandle, const char16_t* Section, std::uint32_t Index, void* Context) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(Section);
    static_cast<void>(Index);
    static_cast<void>(Context);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetLineCountA(std::uint64_t InfHandle, const char* Section) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(Section);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetLineCountW(std::uint64_t InfHandle, const char16_t* Section) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(Section);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetLineTextA(void* Context, std::uint64_t InfHandle, const char* Section, const char* Key, char* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Context);
    static_cast<void>(InfHandle);
    static_cast<void>(Section);
    static_cast<void>(Key);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetLineTextW(void* Context, std::uint64_t InfHandle, const char16_t* Section, const char16_t* Key, char16_t* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Context);
    static_cast<void>(InfHandle);
    static_cast<void>(Section);
    static_cast<void>(Key);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetMultiSzFieldA(void* Context, std::uint32_t FieldIndex, char* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Context);
    static_cast<void>(FieldIndex);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetMultiSzFieldW(void* Context, std::uint32_t FieldIndex, char16_t* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Context);
    static_cast<void>(FieldIndex);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetNonInteractiveMode() noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetSourceFileLocationA(std::uint64_t InfHandle, void* InfContext, const char* FileName, std::uint32_t* SourceId, char* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(InfContext);
    static_cast<void>(FileName);
    static_cast<void>(SourceId);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetSourceFileLocationW(std::uint64_t InfHandle, void* InfContext, const char16_t* FileName, std::uint32_t* SourceId, char16_t* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(InfContext);
    static_cast<void>(FileName);
    static_cast<void>(SourceId);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetSourceFileSizeA(std::uint64_t InfHandle, void* InfContext, const char* FileName, const char* Section, std::uint32_t* FileSize, std::uint32_t RoundingFactor) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(InfContext);
    static_cast<void>(FileName);
    static_cast<void>(Section);
    static_cast<void>(FileSize);
    static_cast<void>(RoundingFactor);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetSourceFileSizeW(std::uint64_t InfHandle, void* InfContext, const char16_t* FileName, const char16_t* Section, std::uint32_t* FileSize, std::uint32_t RoundingFactor) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(InfContext);
    static_cast<void>(FileName);
    static_cast<void>(Section);
    static_cast<void>(FileSize);
    static_cast<void>(RoundingFactor);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetSourceInfoA(std::uint64_t InfHandle, std::uint32_t SourceId, std::uint32_t InfoDesired, char* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(SourceId);
    static_cast<void>(InfoDesired);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetSourceInfoW(std::uint64_t InfHandle, std::uint32_t SourceId, std::uint32_t InfoDesired, char16_t* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(SourceId);
    static_cast<void>(InfoDesired);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetStringFieldA(void* Context, std::uint32_t FieldIndex, char* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Context);
    static_cast<void>(FieldIndex);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetStringFieldW(void* Context, std::uint32_t FieldIndex, char16_t* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Context);
    static_cast<void>(FieldIndex);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetTargetPathA(std::uint64_t InfHandle, void* InfContext, const char* Section, char* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(InfContext);
    static_cast<void>(Section);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupGetTargetPathW(std::uint64_t InfHandle, void* InfContext, const char16_t* Section, char16_t* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(InfContext);
    static_cast<void>(Section);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* ksetupapiG_SetupInitDefaultQueueCallback(void* OwnerWindow) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(OwnerWindow);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* ksetupapiG_SetupInitDefaultQueueCallbackEx(void* OwnerWindow, void* AlternateProgressWindow, std::uint32_t ProgressMessage, std::uint32_t Reserved1, void* Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(OwnerWindow);
    static_cast<void>(AlternateProgressWindow);
    static_cast<void>(ProgressMessage);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint64_t ksetupapiG_SetupInitializeFileLogA(const char* LogFileName, std::uint32_t Flags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(LogFileName);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t ksetupapiG_SetupInitializeFileLogW(const char16_t* LogFileName, std::uint32_t Flags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(LogFileName);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupInstallFileA(std::uint64_t InfHandle, void* InfContext, const char* SourceFile, const char* SourcePathRoot, const char* DestinationName, std::uint32_t CopyStyle, void* CopyMsgHandler, void* Context) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(InfContext);
    static_cast<void>(SourceFile);
    static_cast<void>(SourcePathRoot);
    static_cast<void>(DestinationName);
    static_cast<void>(CopyStyle);
    static_cast<void>(CopyMsgHandler);
    static_cast<void>(Context);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupInstallFileExA(std::uint64_t InfHandle, void* InfContext, const char* SourceFile, const char* SourcePathRoot, const char* DestinationName, std::uint32_t CopyStyle, void* CopyMsgHandler, void* Context, std::int32_t* FileWasInUse) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(InfContext);
    static_cast<void>(SourceFile);
    static_cast<void>(SourcePathRoot);
    static_cast<void>(DestinationName);
    static_cast<void>(CopyStyle);
    static_cast<void>(CopyMsgHandler);
    static_cast<void>(Context);
    static_cast<void>(FileWasInUse);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupInstallFileExW(std::uint64_t InfHandle, void* InfContext, const char16_t* SourceFile, const char16_t* SourcePathRoot, const char16_t* DestinationName, std::uint32_t CopyStyle, void* CopyMsgHandler, void* Context, std::int32_t* FileWasInUse) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(InfContext);
    static_cast<void>(SourceFile);
    static_cast<void>(SourcePathRoot);
    static_cast<void>(DestinationName);
    static_cast<void>(CopyStyle);
    static_cast<void>(CopyMsgHandler);
    static_cast<void>(Context);
    static_cast<void>(FileWasInUse);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupInstallFileW(std::uint64_t InfHandle, void* InfContext, const char16_t* SourceFile, const char16_t* SourcePathRoot, const char16_t* DestinationName, std::uint32_t CopyStyle, void* CopyMsgHandler, void* Context) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(InfContext);
    static_cast<void>(SourceFile);
    static_cast<void>(SourcePathRoot);
    static_cast<void>(DestinationName);
    static_cast<void>(CopyStyle);
    static_cast<void>(CopyMsgHandler);
    static_cast<void>(Context);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupInstallFilesFromInfSectionA(std::uint64_t InfHandle, std::uint64_t LayoutInfHandle, std::uint64_t FileQueue, const char* SectionName, const char* SourceRootPath, std::uint32_t CopyFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(LayoutInfHandle);
    static_cast<void>(FileQueue);
    static_cast<void>(SectionName);
    static_cast<void>(SourceRootPath);
    static_cast<void>(CopyFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupInstallFilesFromInfSectionW(std::uint64_t InfHandle, std::uint64_t LayoutInfHandle, std::uint64_t FileQueue, const char16_t* SectionName, const char16_t* SourceRootPath, std::uint32_t CopyFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(LayoutInfHandle);
    static_cast<void>(FileQueue);
    static_cast<void>(SectionName);
    static_cast<void>(SourceRootPath);
    static_cast<void>(CopyFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupInstallFromInfSectionA(void* Owner, std::uint64_t InfHandle, const char* SectionName, std::uint32_t Flags, void* RelativeKeyRoot, const char* SourceRootPath, std::uint32_t CopyFlags, void* MsgHandler, void* Context, std::uint64_t DeviceInfoSet, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Owner);
    static_cast<void>(InfHandle);
    static_cast<void>(SectionName);
    static_cast<void>(Flags);
    static_cast<void>(RelativeKeyRoot);
    static_cast<void>(SourceRootPath);
    static_cast<void>(CopyFlags);
    static_cast<void>(MsgHandler);
    static_cast<void>(Context);
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupInstallFromInfSectionW(void* Owner, std::uint64_t InfHandle, const char16_t* SectionName, std::uint32_t Flags, void* RelativeKeyRoot, const char16_t* SourceRootPath, std::uint32_t CopyFlags, void* MsgHandler, void* Context, std::uint64_t DeviceInfoSet, void* DeviceInfoData) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Owner);
    static_cast<void>(InfHandle);
    static_cast<void>(SectionName);
    static_cast<void>(Flags);
    static_cast<void>(RelativeKeyRoot);
    static_cast<void>(SourceRootPath);
    static_cast<void>(CopyFlags);
    static_cast<void>(MsgHandler);
    static_cast<void>(Context);
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupInstallServicesFromInfSectionA(std::uint64_t InfHandle, const char* SectionName, std::uint32_t Flags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(SectionName);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupInstallServicesFromInfSectionExA(std::uint64_t InfHandle, const char* SectionName, std::uint32_t Flags, std::uint64_t DeviceInfoSet, void* DeviceInfoData, void* Reserved1, void* Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(SectionName);
    static_cast<void>(Flags);
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupInstallServicesFromInfSectionExW(std::uint64_t InfHandle, const char16_t* SectionName, std::uint32_t Flags, std::uint64_t DeviceInfoSet, void* DeviceInfoData, void* Reserved1, void* Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(SectionName);
    static_cast<void>(Flags);
    static_cast<void>(DeviceInfoSet);
    static_cast<void>(DeviceInfoData);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupInstallServicesFromInfSectionW(std::uint64_t InfHandle, const char16_t* SectionName, std::uint32_t Flags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(SectionName);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupIterateCabinetA(const char* CabinetFile, std::uint32_t Reserved, void* MsgHandler, void* Context) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(CabinetFile);
    static_cast<void>(Reserved);
    static_cast<void>(MsgHandler);
    static_cast<void>(Context);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupIterateCabinetW(const char16_t* CabinetFile, std::uint32_t Reserved, void* MsgHandler, void* Context) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(CabinetFile);
    static_cast<void>(Reserved);
    static_cast<void>(MsgHandler);
    static_cast<void>(Context);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupLogErrorA(const char* MessageString, std::uint32_t Severity) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(MessageString);
    static_cast<void>(Severity);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupLogErrorW(const char16_t* MessageString, std::uint32_t Severity) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(MessageString);
    static_cast<void>(Severity);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupLogFileA(std::uint64_t FileLogHandle, const char* LogSectionName, const char* SourceFilename, const char* TargetFilename, std::uint32_t Checksum, const char* DiskTagfile, const char* DiskDescription, const char* OtherInfo, std::uint32_t Flags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(FileLogHandle);
    static_cast<void>(LogSectionName);
    static_cast<void>(SourceFilename);
    static_cast<void>(TargetFilename);
    static_cast<void>(Checksum);
    static_cast<void>(DiskTagfile);
    static_cast<void>(DiskDescription);
    static_cast<void>(OtherInfo);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupLogFileW(std::uint64_t FileLogHandle, const char16_t* LogSectionName, const char16_t* SourceFilename, const char16_t* TargetFilename, std::uint32_t Checksum, const char16_t* DiskTagfile, const char16_t* DiskDescription, const char16_t* OtherInfo, std::uint32_t Flags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(FileLogHandle);
    static_cast<void>(LogSectionName);
    static_cast<void>(SourceFilename);
    static_cast<void>(TargetFilename);
    static_cast<void>(Checksum);
    static_cast<void>(DiskTagfile);
    static_cast<void>(DiskDescription);
    static_cast<void>(OtherInfo);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupOpenAppendInfFileA(const char* FileName, std::uint64_t InfHandle, std::uint32_t* ErrorLine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(FileName);
    static_cast<void>(InfHandle);
    static_cast<void>(ErrorLine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupOpenAppendInfFileW(const char16_t* FileName, std::uint64_t InfHandle, std::uint32_t* ErrorLine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(FileName);
    static_cast<void>(InfHandle);
    static_cast<void>(ErrorLine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t ksetupapiG_SetupOpenFileQueue() noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t ksetupapiG_SetupOpenInfFileA(const char* FileName, const char* InfClass, std::uint32_t InfStyle, std::uint32_t* ErrorLine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(FileName);
    static_cast<void>(InfClass);
    static_cast<void>(InfStyle);
    static_cast<void>(ErrorLine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t ksetupapiG_SetupOpenInfFileW(const char16_t* FileName, const char16_t* InfClass, std::uint32_t InfStyle, std::uint32_t* ErrorLine) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(FileName);
    static_cast<void>(InfClass);
    static_cast<void>(InfStyle);
    static_cast<void>(ErrorLine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupOpenLog(std::int32_t Erase) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Erase);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t ksetupapiG_SetupOpenMasterInf() noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupPrepareQueueForRestoreA(std::uint64_t QueueHandle, const char* BackupPath, std::uint32_t RestoreFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(QueueHandle);
    static_cast<void>(BackupPath);
    static_cast<void>(RestoreFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupPrepareQueueForRestoreW(std::uint64_t QueueHandle, const char16_t* BackupPath, std::uint32_t RestoreFlags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(QueueHandle);
    static_cast<void>(BackupPath);
    static_cast<void>(RestoreFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_SetupPromptForDiskA(void* hwndParent, const char* DialogTitle, const char* DiskName, const char* PathToSource, const char* FileSought, const char* TagFile, std::uint32_t DiskPromptStyle, char* PathBuffer, std::uint32_t PathBufferSize, std::uint32_t* PathRequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(hwndParent);
    static_cast<void>(DialogTitle);
    static_cast<void>(DiskName);
    static_cast<void>(PathToSource);
    static_cast<void>(FileSought);
    static_cast<void>(TagFile);
    static_cast<void>(DiskPromptStyle);
    static_cast<void>(PathBuffer);
    static_cast<void>(PathBufferSize);
    static_cast<void>(PathRequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_SetupPromptForDiskW(void* hwndParent, const char16_t* DialogTitle, const char16_t* DiskName, const char16_t* PathToSource, const char16_t* FileSought, const char16_t* TagFile, std::uint32_t DiskPromptStyle, char16_t* PathBuffer, std::uint32_t PathBufferSize, std::uint32_t* PathRequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(hwndParent);
    static_cast<void>(DialogTitle);
    static_cast<void>(DiskName);
    static_cast<void>(PathToSource);
    static_cast<void>(FileSought);
    static_cast<void>(TagFile);
    static_cast<void>(DiskPromptStyle);
    static_cast<void>(PathBuffer);
    static_cast<void>(PathBufferSize);
    static_cast<void>(PathRequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupPromptReboot(std::uint64_t FileQueue, void* Owner, std::int32_t ScanOnly) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(FileQueue);
    static_cast<void>(Owner);
    static_cast<void>(ScanOnly);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueryDrivesInDiskSpaceListA(std::uint64_t DiskSpace, char* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DiskSpace);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueryDrivesInDiskSpaceListW(std::uint64_t DiskSpace, char16_t* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DiskSpace);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueryFileLogA(std::uint64_t FileLogHandle, const char* LogSectionName, const char* TargetFilename, std::uint64_t DesiredInfo, char* DataOut, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(FileLogHandle);
    static_cast<void>(LogSectionName);
    static_cast<void>(TargetFilename);
    static_cast<void>(DesiredInfo);
    static_cast<void>(DataOut);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueryFileLogW(std::uint64_t FileLogHandle, const char16_t* LogSectionName, const char16_t* TargetFilename, std::uint64_t DesiredInfo, char16_t* DataOut, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(FileLogHandle);
    static_cast<void>(LogSectionName);
    static_cast<void>(TargetFilename);
    static_cast<void>(DesiredInfo);
    static_cast<void>(DataOut);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueryInfFileInformationA(void* InfInformation, std::uint32_t InfIndex, char* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfInformation);
    static_cast<void>(InfIndex);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueryInfFileInformationW(void* InfInformation, std::uint32_t InfIndex, char16_t* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfInformation);
    static_cast<void>(InfIndex);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueryInfOriginalFileInformationA(void* InfInformation, std::uint32_t InfIndex, void* AlternatePlatformInfo, void* OriginalFileInfo) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfInformation);
    static_cast<void>(InfIndex);
    static_cast<void>(AlternatePlatformInfo);
    static_cast<void>(OriginalFileInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueryInfOriginalFileInformationW(void* InfInformation, std::uint32_t InfIndex, void* AlternatePlatformInfo, void* OriginalFileInfo) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfInformation);
    static_cast<void>(InfIndex);
    static_cast<void>(AlternatePlatformInfo);
    static_cast<void>(OriginalFileInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueryInfVersionInformationA(void* InfInformation, std::uint32_t InfIndex, const char* Key, char* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfInformation);
    static_cast<void>(InfIndex);
    static_cast<void>(Key);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueryInfVersionInformationW(void* InfInformation, std::uint32_t InfIndex, const char16_t* Key, char16_t* ReturnBuffer, std::uint32_t ReturnBufferSize, std::uint32_t* RequiredSize) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfInformation);
    static_cast<void>(InfIndex);
    static_cast<void>(Key);
    static_cast<void>(ReturnBuffer);
    static_cast<void>(ReturnBufferSize);
    static_cast<void>(RequiredSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQuerySourceListA(std::uint32_t Flags, const char*** List, std::uint32_t* Count) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Flags);
    static_cast<void>(List);
    static_cast<void>(Count);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQuerySourceListW(std::uint32_t Flags, const char16_t*** List, std::uint32_t* Count) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Flags);
    static_cast<void>(List);
    static_cast<void>(Count);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQuerySpaceRequiredOnDriveA(std::uint64_t DiskSpace, const char* DriveSpec, std::int64_t* SpaceRequired, void* Reserved1, std::uint32_t Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DiskSpace);
    static_cast<void>(DriveSpec);
    static_cast<void>(SpaceRequired);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQuerySpaceRequiredOnDriveW(std::uint64_t DiskSpace, const char16_t* DriveSpec, std::int64_t* SpaceRequired, void* Reserved1, std::uint32_t Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DiskSpace);
    static_cast<void>(DriveSpec);
    static_cast<void>(SpaceRequired);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueueCopyA(std::uint64_t QueueHandle, const char* SourceRootPath, const char* SourcePath, const char* SourceFilename, const char* SourceDescription, const char* SourceTagfile, const char* TargetDirectory, const char* TargetFilename, std::uint32_t CopyStyle) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(QueueHandle);
    static_cast<void>(SourceRootPath);
    static_cast<void>(SourcePath);
    static_cast<void>(SourceFilename);
    static_cast<void>(SourceDescription);
    static_cast<void>(SourceTagfile);
    static_cast<void>(TargetDirectory);
    static_cast<void>(TargetFilename);
    static_cast<void>(CopyStyle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueueCopyIndirectA(std::uint64_t CopyParams) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(CopyParams);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueueCopyIndirectW(std::uint64_t CopyParams) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(CopyParams);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueueCopySectionA(std::uint64_t QueueHandle, const char* SourceRootPath, std::uint64_t InfHandle, std::uint64_t ListInfHandle, const char* Section, std::uint32_t CopyStyle) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(QueueHandle);
    static_cast<void>(SourceRootPath);
    static_cast<void>(InfHandle);
    static_cast<void>(ListInfHandle);
    static_cast<void>(Section);
    static_cast<void>(CopyStyle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueueCopySectionW(std::uint64_t QueueHandle, const char16_t* SourceRootPath, std::uint64_t InfHandle, std::uint64_t ListInfHandle, const char16_t* Section, std::uint32_t CopyStyle) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(QueueHandle);
    static_cast<void>(SourceRootPath);
    static_cast<void>(InfHandle);
    static_cast<void>(ListInfHandle);
    static_cast<void>(Section);
    static_cast<void>(CopyStyle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueueCopyW(std::uint64_t QueueHandle, const char16_t* SourceRootPath, const char16_t* SourcePath, const char16_t* SourceFilename, const char16_t* SourceDescription, const char16_t* SourceTagfile, const char16_t* TargetDirectory, const char16_t* TargetFilename, std::uint32_t CopyStyle) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(QueueHandle);
    static_cast<void>(SourceRootPath);
    static_cast<void>(SourcePath);
    static_cast<void>(SourceFilename);
    static_cast<void>(SourceDescription);
    static_cast<void>(SourceTagfile);
    static_cast<void>(TargetDirectory);
    static_cast<void>(TargetFilename);
    static_cast<void>(CopyStyle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueueDefaultCopyA(std::uint64_t QueueHandle, std::uint64_t InfHandle, const char* SourceRootPath, const char* SourceFilename, const char* TargetFilename, std::uint32_t CopyStyle) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(QueueHandle);
    static_cast<void>(InfHandle);
    static_cast<void>(SourceRootPath);
    static_cast<void>(SourceFilename);
    static_cast<void>(TargetFilename);
    static_cast<void>(CopyStyle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueueDefaultCopyW(std::uint64_t QueueHandle, std::uint64_t InfHandle, const char16_t* SourceRootPath, const char16_t* SourceFilename, const char16_t* TargetFilename, std::uint32_t CopyStyle) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(QueueHandle);
    static_cast<void>(InfHandle);
    static_cast<void>(SourceRootPath);
    static_cast<void>(SourceFilename);
    static_cast<void>(TargetFilename);
    static_cast<void>(CopyStyle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueueDeleteA(std::uint64_t QueueHandle, const char* PathPart1, const char* PathPart2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(QueueHandle);
    static_cast<void>(PathPart1);
    static_cast<void>(PathPart2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueueDeleteSectionA(std::uint64_t QueueHandle, std::uint64_t InfHandle, std::uint64_t ListInfHandle, const char* Section) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(QueueHandle);
    static_cast<void>(InfHandle);
    static_cast<void>(ListInfHandle);
    static_cast<void>(Section);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueueDeleteSectionW(std::uint64_t QueueHandle, std::uint64_t InfHandle, std::uint64_t ListInfHandle, const char16_t* Section) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(QueueHandle);
    static_cast<void>(InfHandle);
    static_cast<void>(ListInfHandle);
    static_cast<void>(Section);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueueDeleteW(std::uint64_t QueueHandle, const char16_t* PathPart1, const char16_t* PathPart2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(QueueHandle);
    static_cast<void>(PathPart1);
    static_cast<void>(PathPart2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueueRenameA(std::uint64_t QueueHandle, const char* SourcePath, const char* SourceFilename, const char* TargetPath, const char* TargetFilename) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(QueueHandle);
    static_cast<void>(SourcePath);
    static_cast<void>(SourceFilename);
    static_cast<void>(TargetPath);
    static_cast<void>(TargetFilename);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueueRenameSectionA(std::uint64_t QueueHandle, std::uint64_t InfHandle, std::uint64_t ListInfHandle, const char* Section) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(QueueHandle);
    static_cast<void>(InfHandle);
    static_cast<void>(ListInfHandle);
    static_cast<void>(Section);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueueRenameSectionW(std::uint64_t QueueHandle, std::uint64_t InfHandle, std::uint64_t ListInfHandle, const char16_t* Section) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(QueueHandle);
    static_cast<void>(InfHandle);
    static_cast<void>(ListInfHandle);
    static_cast<void>(Section);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupQueueRenameW(std::uint64_t QueueHandle, const char16_t* SourcePath, const char16_t* SourceFilename, const char16_t* TargetPath, const char16_t* TargetFilename) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(QueueHandle);
    static_cast<void>(SourcePath);
    static_cast<void>(SourceFilename);
    static_cast<void>(TargetPath);
    static_cast<void>(TargetFilename);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupRemoveFileLogEntryA(std::uint64_t FileLogHandle, const char* LogSectionName, const char* TargetFilename) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(FileLogHandle);
    static_cast<void>(LogSectionName);
    static_cast<void>(TargetFilename);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupRemoveFileLogEntryW(std::uint64_t FileLogHandle, const char16_t* LogSectionName, const char16_t* TargetFilename) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(FileLogHandle);
    static_cast<void>(LogSectionName);
    static_cast<void>(TargetFilename);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupRemoveFromDiskSpaceListA(std::uint64_t DiskSpace, const char* TargetFilespec, std::uint32_t Operation, void* Reserved1, std::uint32_t Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DiskSpace);
    static_cast<void>(TargetFilespec);
    static_cast<void>(Operation);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupRemoveFromDiskSpaceListW(std::uint64_t DiskSpace, const char16_t* TargetFilespec, std::uint32_t Operation, void* Reserved1, std::uint32_t Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DiskSpace);
    static_cast<void>(TargetFilespec);
    static_cast<void>(Operation);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupRemoveFromSourceListA(std::uint32_t Flags, const char* Source) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Flags);
    static_cast<void>(Source);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupRemoveFromSourceListW(std::uint32_t Flags, const char16_t* Source) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Flags);
    static_cast<void>(Source);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupRemoveInstallSectionFromDiskSpaceListA(std::uint64_t DiskSpace, std::uint64_t InfHandle, std::uint64_t LayoutInfHandle, const char* SectionName, void* Reserved1, std::uint32_t Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DiskSpace);
    static_cast<void>(InfHandle);
    static_cast<void>(LayoutInfHandle);
    static_cast<void>(SectionName);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupRemoveInstallSectionFromDiskSpaceListW(std::uint64_t DiskSpace, std::uint64_t InfHandle, std::uint64_t LayoutInfHandle, const char16_t* SectionName, void* Reserved1, std::uint32_t Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DiskSpace);
    static_cast<void>(InfHandle);
    static_cast<void>(LayoutInfHandle);
    static_cast<void>(SectionName);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupRemoveSectionFromDiskSpaceListA(std::uint64_t DiskSpace, std::uint64_t InfHandle, std::uint64_t ListInfHandle, const char* SectionName, std::uint32_t Operation, void* Reserved1, std::uint32_t Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DiskSpace);
    static_cast<void>(InfHandle);
    static_cast<void>(ListInfHandle);
    static_cast<void>(SectionName);
    static_cast<void>(Operation);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupRemoveSectionFromDiskSpaceListW(std::uint64_t DiskSpace, std::uint64_t InfHandle, std::uint64_t ListInfHandle, const char16_t* SectionName, std::uint32_t Operation, void* Reserved1, std::uint32_t Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(DiskSpace);
    static_cast<void>(InfHandle);
    static_cast<void>(ListInfHandle);
    static_cast<void>(SectionName);
    static_cast<void>(Operation);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_SetupRenameErrorA(void* hwndParent, const char* DialogTitle, const char* SourceFile, const char* TargetFile, std::uint32_t Win32ErrorCode, std::uint32_t Style) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(hwndParent);
    static_cast<void>(DialogTitle);
    static_cast<void>(SourceFile);
    static_cast<void>(TargetFile);
    static_cast<void>(Win32ErrorCode);
    static_cast<void>(Style);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t ksetupapiG_SetupRenameErrorW(void* hwndParent, const char16_t* DialogTitle, const char16_t* SourceFile, const char16_t* TargetFile, std::uint32_t Win32ErrorCode, std::uint32_t Style) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(hwndParent);
    static_cast<void>(DialogTitle);
    static_cast<void>(SourceFile);
    static_cast<void>(TargetFile);
    static_cast<void>(Win32ErrorCode);
    static_cast<void>(Style);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupScanFileQueueA(std::uint64_t FileQueue, std::uint32_t Flags, void* Window, void* CallbackRoutine, void* CallbackContext, std::uint32_t* Result) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(FileQueue);
    static_cast<void>(Flags);
    static_cast<void>(Window);
    static_cast<void>(CallbackRoutine);
    static_cast<void>(CallbackContext);
    static_cast<void>(Result);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupScanFileQueueW(std::uint64_t FileQueue, std::uint32_t Flags, void* Window, void* CallbackRoutine, void* CallbackContext, std::uint32_t* Result) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(FileQueue);
    static_cast<void>(Flags);
    static_cast<void>(Window);
    static_cast<void>(CallbackRoutine);
    static_cast<void>(CallbackContext);
    static_cast<void>(Result);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupSetDirectoryIdA(std::uint64_t InfHandle, std::uint32_t Id, const char* Directory) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(Id);
    static_cast<void>(Directory);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupSetDirectoryIdExA(std::uint64_t InfHandle, std::uint32_t Id, const char* Directory, std::uint32_t Flags, std::uint32_t Reserved1, void* Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(Id);
    static_cast<void>(Directory);
    static_cast<void>(Flags);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupSetDirectoryIdExW(std::uint64_t InfHandle, std::uint32_t Id, const char16_t* Directory, std::uint32_t Flags, std::uint32_t Reserved1, void* Reserved2) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(Id);
    static_cast<void>(Directory);
    static_cast<void>(Flags);
    static_cast<void>(Reserved1);
    static_cast<void>(Reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupSetDirectoryIdW(std::uint64_t InfHandle, std::uint32_t Id, const char16_t* Directory) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfHandle);
    static_cast<void>(Id);
    static_cast<void>(Directory);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupSetFileQueueAlternatePlatformA(std::uint64_t QueueHandle, void* AlternatePlatformInfo, const char* AlternateDefaultCatalogFile) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(QueueHandle);
    static_cast<void>(AlternatePlatformInfo);
    static_cast<void>(AlternateDefaultCatalogFile);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupSetFileQueueAlternatePlatformW(std::uint64_t QueueHandle, void* AlternatePlatformInfo, const char16_t* AlternateDefaultCatalogFile) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(QueueHandle);
    static_cast<void>(AlternatePlatformInfo);
    static_cast<void>(AlternateDefaultCatalogFile);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupSetFileQueueFlags(std::uint64_t FileQueue, std::uint32_t FlagMask, std::uint32_t Flags) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(FileQueue);
    static_cast<void>(FlagMask);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupSetNonInteractiveMode(std::int32_t NonInteractiveFlag) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(NonInteractiveFlag);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupSetPlatformPathOverrideA(const char* Override) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Override);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupSetPlatformPathOverrideW(const char16_t* Override) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Override);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupSetSourceListA(std::uint32_t Flags, const char** SourceList, std::uint32_t SourceCount) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Flags);
    static_cast<void>(SourceList);
    static_cast<void>(SourceCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupSetSourceListW(std::uint32_t Flags, const char16_t** SourceList, std::uint32_t SourceCount) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Flags);
    static_cast<void>(SourceList);
    static_cast<void>(SourceCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void ksetupapiG_SetupTermDefaultQueueCallback(void* Context) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(Context);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupTerminateFileLog(std::uint64_t FileLogHandle) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(FileLogHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupUninstallNewlyCopiedInfs(std::uint64_t FileQueue, std::uint32_t Flags, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(FileQueue);
    static_cast<void>(Flags);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupUninstallOEMInfA(const char* InfFileName, std::uint32_t Flags, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfFileName);
    static_cast<void>(Flags);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupUninstallOEMInfW(const char16_t* InfFileName, std::uint32_t Flags, void* Reserved) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfFileName);
    static_cast<void>(Flags);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupVerifyInfFileA(const char* InfName, void* AltPlatformInfo, std::uint64_t InfSignerInfo) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfName);
    static_cast<void>(AltPlatformInfo);
    static_cast<void>(InfSignerInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksetupapiG_SetupVerifyInfFileW(const char16_t* InfName, void* AltPlatformInfo, std::uint64_t InfSignerInfo) noexcept {
    // Refused: the device installation API.
    //
    // the device tree belongs to the kernel and is presented through the Plug
    // and Play manager; this runtime has no device tree to walk and no driver
    // store to install from
    static_cast<void>(InfName);
    static_cast<void>(AltPlatformInfo);
    static_cast<void>(InfSignerInfo);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_setupapi(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("CMP_WaitNoPendingInstallEvents", reinterpret_cast<void*>(&ksetupapiG_CMP_WaitNoPendingInstallEvents));
    e("CM_Add_Empty_Log_Conf", reinterpret_cast<void*>(&ksetupapiG_CM_Add_Empty_Log_Conf));
    e("CM_Add_Empty_Log_Conf_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Add_Empty_Log_Conf_Ex));
    e("CM_Add_IDA", reinterpret_cast<void*>(&ksetupapiG_CM_Add_IDA));
    e("CM_Add_IDW", reinterpret_cast<void*>(&ksetupapiG_CM_Add_IDW));
    e("CM_Add_ID_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Add_ID_ExA));
    e("CM_Add_ID_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Add_ID_ExW));
    e("CM_Add_Range", reinterpret_cast<void*>(&ksetupapiG_CM_Add_Range));
    e("CM_Add_Res_Des", reinterpret_cast<void*>(&ksetupapiG_CM_Add_Res_Des));
    e("CM_Add_Res_Des_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Add_Res_Des_Ex));
    e("CM_Connect_MachineA", reinterpret_cast<void*>(&ksetupapiG_CM_Connect_MachineA));
    e("CM_Connect_MachineW", reinterpret_cast<void*>(&ksetupapiG_CM_Connect_MachineW));
    e("CM_Create_DevNodeA", reinterpret_cast<void*>(&ksetupapiG_CM_Create_DevNodeA));
    e("CM_Create_DevNodeW", reinterpret_cast<void*>(&ksetupapiG_CM_Create_DevNodeW));
    e("CM_Create_DevNode_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Create_DevNode_ExA));
    e("CM_Create_DevNode_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Create_DevNode_ExW));
    e("CM_Create_Range_List", reinterpret_cast<void*>(&ksetupapiG_CM_Create_Range_List));
    e("CM_Delete_Class_Key", reinterpret_cast<void*>(&ksetupapiG_CM_Delete_Class_Key));
    e("CM_Delete_Class_Key_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Delete_Class_Key_Ex));
    e("CM_Delete_DevNode_Key", reinterpret_cast<void*>(&ksetupapiG_CM_Delete_DevNode_Key));
    e("CM_Delete_DevNode_Key_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Delete_DevNode_Key_Ex));
    e("CM_Delete_Range", reinterpret_cast<void*>(&ksetupapiG_CM_Delete_Range));
    e("CM_Detect_Resource_Conflict", reinterpret_cast<void*>(&ksetupapiG_CM_Detect_Resource_Conflict));
    e("CM_Detect_Resource_Conflict_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Detect_Resource_Conflict_Ex));
    e("CM_Disable_DevNode", reinterpret_cast<void*>(&ksetupapiG_CM_Disable_DevNode));
    e("CM_Disable_DevNode_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Disable_DevNode_Ex));
    e("CM_Disconnect_Machine", reinterpret_cast<void*>(&ksetupapiG_CM_Disconnect_Machine));
    e("CM_Dup_Range_List", reinterpret_cast<void*>(&ksetupapiG_CM_Dup_Range_List));
    e("CM_Enable_DevNode", reinterpret_cast<void*>(&ksetupapiG_CM_Enable_DevNode));
    e("CM_Enable_DevNode_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Enable_DevNode_Ex));
    e("CM_Enumerate_Classes", reinterpret_cast<void*>(&ksetupapiG_CM_Enumerate_Classes));
    e("CM_Enumerate_Classes_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Enumerate_Classes_Ex));
    e("CM_Enumerate_EnumeratorsA", reinterpret_cast<void*>(&ksetupapiG_CM_Enumerate_EnumeratorsA));
    e("CM_Enumerate_EnumeratorsW", reinterpret_cast<void*>(&ksetupapiG_CM_Enumerate_EnumeratorsW));
    e("CM_Enumerate_Enumerators_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Enumerate_Enumerators_ExA));
    e("CM_Enumerate_Enumerators_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Enumerate_Enumerators_ExW));
    e("CM_Find_Range", reinterpret_cast<void*>(&ksetupapiG_CM_Find_Range));
    e("CM_First_Range", reinterpret_cast<void*>(&ksetupapiG_CM_First_Range));
    e("CM_Free_Log_Conf", reinterpret_cast<void*>(&ksetupapiG_CM_Free_Log_Conf));
    e("CM_Free_Log_Conf_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Free_Log_Conf_Ex));
    e("CM_Free_Log_Conf_Handle", reinterpret_cast<void*>(&ksetupapiG_CM_Free_Log_Conf_Handle));
    e("CM_Free_Range_List", reinterpret_cast<void*>(&ksetupapiG_CM_Free_Range_List));
    e("CM_Free_Res_Des", reinterpret_cast<void*>(&ksetupapiG_CM_Free_Res_Des));
    e("CM_Free_Res_Des_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Free_Res_Des_Ex));
    e("CM_Free_Res_Des_Handle", reinterpret_cast<void*>(&ksetupapiG_CM_Free_Res_Des_Handle));
    e("CM_Free_Resource_Conflict_Handle", reinterpret_cast<void*>(&ksetupapiG_CM_Free_Resource_Conflict_Handle));
    e("CM_Get_Child", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Child));
    e("CM_Get_Child_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Child_Ex));
    e("CM_Get_Class_Key_NameA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Class_Key_NameA));
    e("CM_Get_Class_Key_NameW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Class_Key_NameW));
    e("CM_Get_Class_Key_Name_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Class_Key_Name_ExA));
    e("CM_Get_Class_Key_Name_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Class_Key_Name_ExW));
    e("CM_Get_Class_NameA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Class_NameA));
    e("CM_Get_Class_NameW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Class_NameW));
    e("CM_Get_Class_Name_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Class_Name_ExA));
    e("CM_Get_Class_Name_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Class_Name_ExW));
    e("CM_Get_Class_Registry_PropertyA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Class_Registry_PropertyA));
    e("CM_Get_Class_Registry_PropertyW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Class_Registry_PropertyW));
    e("CM_Get_Depth", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Depth));
    e("CM_Get_Depth_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Depth_Ex));
    e("CM_Get_DevNode_Custom_PropertyA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_DevNode_Custom_PropertyA));
    e("CM_Get_DevNode_Custom_PropertyW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_DevNode_Custom_PropertyW));
    e("CM_Get_DevNode_Custom_Property_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_DevNode_Custom_Property_ExA));
    e("CM_Get_DevNode_Custom_Property_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_DevNode_Custom_Property_ExW));
    e("CM_Get_DevNode_Registry_PropertyA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_DevNode_Registry_PropertyA));
    e("CM_Get_DevNode_Registry_PropertyW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_DevNode_Registry_PropertyW));
    e("CM_Get_DevNode_Registry_Property_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_DevNode_Registry_Property_ExA));
    e("CM_Get_DevNode_Registry_Property_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_DevNode_Registry_Property_ExW));
    e("CM_Get_DevNode_Status", reinterpret_cast<void*>(&ksetupapiG_CM_Get_DevNode_Status));
    e("CM_Get_DevNode_Status_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Get_DevNode_Status_Ex));
    e("CM_Get_Device_IDA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_IDA));
    e("CM_Get_Device_IDW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_IDW));
    e("CM_Get_Device_ID_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_ID_ExA));
    e("CM_Get_Device_ID_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_ID_ExW));
    e("CM_Get_Device_ID_ListA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_ID_ListA));
    e("CM_Get_Device_ID_ListW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_ID_ListW));
    e("CM_Get_Device_ID_List_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_ID_List_ExA));
    e("CM_Get_Device_ID_List_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_ID_List_ExW));
    e("CM_Get_Device_ID_List_SizeA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_ID_List_SizeA));
    e("CM_Get_Device_ID_List_SizeW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_ID_List_SizeW));
    e("CM_Get_Device_ID_List_Size_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_ID_List_Size_ExA));
    e("CM_Get_Device_ID_List_Size_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_ID_List_Size_ExW));
    e("CM_Get_Device_ID_Size", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_ID_Size));
    e("CM_Get_Device_ID_Size_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_ID_Size_Ex));
    e("CM_Get_Device_Interface_AliasA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_Interface_AliasA));
    e("CM_Get_Device_Interface_AliasW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_Interface_AliasW));
    e("CM_Get_Device_Interface_Alias_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_Interface_Alias_ExA));
    e("CM_Get_Device_Interface_Alias_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_Interface_Alias_ExW));
    e("CM_Get_Device_Interface_ListA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_Interface_ListA));
    e("CM_Get_Device_Interface_ListW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_Interface_ListW));
    e("CM_Get_Device_Interface_List_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_Interface_List_ExA));
    e("CM_Get_Device_Interface_List_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_Interface_List_ExW));
    e("CM_Get_Device_Interface_List_SizeA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_Interface_List_SizeA));
    e("CM_Get_Device_Interface_List_SizeW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_Interface_List_SizeW));
    e("CM_Get_Device_Interface_List_Size_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_Interface_List_Size_ExA));
    e("CM_Get_Device_Interface_List_Size_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Device_Interface_List_Size_ExW));
    e("CM_Get_First_Log_Conf", reinterpret_cast<void*>(&ksetupapiG_CM_Get_First_Log_Conf));
    e("CM_Get_First_Log_Conf_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Get_First_Log_Conf_Ex));
    e("CM_Get_Global_State", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Global_State));
    e("CM_Get_Global_State_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Global_State_Ex));
    e("CM_Get_HW_Prof_FlagsA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_HW_Prof_FlagsA));
    e("CM_Get_HW_Prof_FlagsW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_HW_Prof_FlagsW));
    e("CM_Get_HW_Prof_Flags_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_HW_Prof_Flags_ExA));
    e("CM_Get_HW_Prof_Flags_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_HW_Prof_Flags_ExW));
    e("CM_Get_Hardware_Profile_InfoA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Hardware_Profile_InfoA));
    e("CM_Get_Hardware_Profile_InfoW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Hardware_Profile_InfoW));
    e("CM_Get_Hardware_Profile_Info_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Hardware_Profile_Info_ExA));
    e("CM_Get_Hardware_Profile_Info_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Hardware_Profile_Info_ExW));
    e("CM_Get_Log_Conf_Priority", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Log_Conf_Priority));
    e("CM_Get_Log_Conf_Priority_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Log_Conf_Priority_Ex));
    e("CM_Get_Next_Log_Conf", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Next_Log_Conf));
    e("CM_Get_Next_Log_Conf_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Next_Log_Conf_Ex));
    e("CM_Get_Next_Res_Des", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Next_Res_Des));
    e("CM_Get_Next_Res_Des_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Next_Res_Des_Ex));
    e("CM_Get_Parent", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Parent));
    e("CM_Get_Parent_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Parent_Ex));
    e("CM_Get_Res_Des_Data", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Res_Des_Data));
    e("CM_Get_Res_Des_Data_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Res_Des_Data_Ex));
    e("CM_Get_Res_Des_Data_Size", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Res_Des_Data_Size));
    e("CM_Get_Res_Des_Data_Size_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Res_Des_Data_Size_Ex));
    e("CM_Get_Resource_Conflict_Count", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Resource_Conflict_Count));
    e("CM_Get_Resource_Conflict_DetailsA", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Resource_Conflict_DetailsA));
    e("CM_Get_Resource_Conflict_DetailsW", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Resource_Conflict_DetailsW));
    e("CM_Get_Sibling", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Sibling));
    e("CM_Get_Sibling_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Sibling_Ex));
    e("CM_Get_Version", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Version));
    e("CM_Get_Version_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Get_Version_Ex));
    e("CM_Intersect_Range_List", reinterpret_cast<void*>(&ksetupapiG_CM_Intersect_Range_List));
    e("CM_Invert_Range_List", reinterpret_cast<void*>(&ksetupapiG_CM_Invert_Range_List));
    e("CM_Is_Dock_Station_Present", reinterpret_cast<void*>(&ksetupapiG_CM_Is_Dock_Station_Present));
    e("CM_Is_Dock_Station_Present_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Is_Dock_Station_Present_Ex));
    e("CM_Is_Version_Available", reinterpret_cast<void*>(&ksetupapiG_CM_Is_Version_Available));
    e("CM_Is_Version_Available_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Is_Version_Available_Ex));
    e("CM_Locate_DevNodeA", reinterpret_cast<void*>(&ksetupapiG_CM_Locate_DevNodeA));
    e("CM_Locate_DevNodeW", reinterpret_cast<void*>(&ksetupapiG_CM_Locate_DevNodeW));
    e("CM_Locate_DevNode_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Locate_DevNode_ExA));
    e("CM_Locate_DevNode_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Locate_DevNode_ExW));
    e("CM_Merge_Range_List", reinterpret_cast<void*>(&ksetupapiG_CM_Merge_Range_List));
    e("CM_Modify_Res_Des", reinterpret_cast<void*>(&ksetupapiG_CM_Modify_Res_Des));
    e("CM_Modify_Res_Des_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Modify_Res_Des_Ex));
    e("CM_Move_DevNode", reinterpret_cast<void*>(&ksetupapiG_CM_Move_DevNode));
    e("CM_Move_DevNode_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Move_DevNode_Ex));
    e("CM_Next_Range", reinterpret_cast<void*>(&ksetupapiG_CM_Next_Range));
    e("CM_Open_Class_KeyA", reinterpret_cast<void*>(&ksetupapiG_CM_Open_Class_KeyA));
    e("CM_Open_Class_KeyW", reinterpret_cast<void*>(&ksetupapiG_CM_Open_Class_KeyW));
    e("CM_Open_Class_Key_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Open_Class_Key_ExA));
    e("CM_Open_Class_Key_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Open_Class_Key_ExW));
    e("CM_Open_DevNode_Key", reinterpret_cast<void*>(&ksetupapiG_CM_Open_DevNode_Key));
    e("CM_Open_DevNode_Key_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Open_DevNode_Key_Ex));
    e("CM_Query_And_Remove_SubTreeA", reinterpret_cast<void*>(&ksetupapiG_CM_Query_And_Remove_SubTreeA));
    e("CM_Query_And_Remove_SubTreeW", reinterpret_cast<void*>(&ksetupapiG_CM_Query_And_Remove_SubTreeW));
    e("CM_Query_And_Remove_SubTree_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Query_And_Remove_SubTree_ExA));
    e("CM_Query_And_Remove_SubTree_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Query_And_Remove_SubTree_ExW));
    e("CM_Query_Arbitrator_Free_Data", reinterpret_cast<void*>(&ksetupapiG_CM_Query_Arbitrator_Free_Data));
    e("CM_Query_Arbitrator_Free_Data_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Query_Arbitrator_Free_Data_Ex));
    e("CM_Query_Arbitrator_Free_Size", reinterpret_cast<void*>(&ksetupapiG_CM_Query_Arbitrator_Free_Size));
    e("CM_Query_Arbitrator_Free_Size_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Query_Arbitrator_Free_Size_Ex));
    e("CM_Query_Remove_SubTree", reinterpret_cast<void*>(&ksetupapiG_CM_Query_Remove_SubTree));
    e("CM_Query_Remove_SubTree_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Query_Remove_SubTree_Ex));
    e("CM_Query_Resource_Conflict_List", reinterpret_cast<void*>(&ksetupapiG_CM_Query_Resource_Conflict_List));
    e("CM_Reenumerate_DevNode", reinterpret_cast<void*>(&ksetupapiG_CM_Reenumerate_DevNode));
    e("CM_Reenumerate_DevNode_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Reenumerate_DevNode_Ex));
    e("CM_Register_Device_Driver", reinterpret_cast<void*>(&ksetupapiG_CM_Register_Device_Driver));
    e("CM_Register_Device_Driver_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Register_Device_Driver_Ex));
    e("CM_Register_Device_InterfaceA", reinterpret_cast<void*>(&ksetupapiG_CM_Register_Device_InterfaceA));
    e("CM_Register_Device_InterfaceW", reinterpret_cast<void*>(&ksetupapiG_CM_Register_Device_InterfaceW));
    e("CM_Register_Device_Interface_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Register_Device_Interface_ExA));
    e("CM_Register_Device_Interface_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Register_Device_Interface_ExW));
    e("CM_Remove_SubTree", reinterpret_cast<void*>(&ksetupapiG_CM_Remove_SubTree));
    e("CM_Remove_SubTree_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Remove_SubTree_Ex));
    e("CM_Request_Device_EjectA", reinterpret_cast<void*>(&ksetupapiG_CM_Request_Device_EjectA));
    e("CM_Request_Device_EjectW", reinterpret_cast<void*>(&ksetupapiG_CM_Request_Device_EjectW));
    e("CM_Request_Device_Eject_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Request_Device_Eject_ExA));
    e("CM_Request_Device_Eject_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Request_Device_Eject_ExW));
    e("CM_Request_Eject_PC", reinterpret_cast<void*>(&ksetupapiG_CM_Request_Eject_PC));
    e("CM_Request_Eject_PC_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Request_Eject_PC_Ex));
    e("CM_Run_Detection", reinterpret_cast<void*>(&ksetupapiG_CM_Run_Detection));
    e("CM_Run_Detection_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Run_Detection_Ex));
    e("CM_Set_Class_Registry_PropertyA", reinterpret_cast<void*>(&ksetupapiG_CM_Set_Class_Registry_PropertyA));
    e("CM_Set_Class_Registry_PropertyW", reinterpret_cast<void*>(&ksetupapiG_CM_Set_Class_Registry_PropertyW));
    e("CM_Set_DevNode_Problem", reinterpret_cast<void*>(&ksetupapiG_CM_Set_DevNode_Problem));
    e("CM_Set_DevNode_Problem_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Set_DevNode_Problem_Ex));
    e("CM_Set_DevNode_Registry_PropertyA", reinterpret_cast<void*>(&ksetupapiG_CM_Set_DevNode_Registry_PropertyA));
    e("CM_Set_DevNode_Registry_PropertyW", reinterpret_cast<void*>(&ksetupapiG_CM_Set_DevNode_Registry_PropertyW));
    e("CM_Set_DevNode_Registry_Property_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Set_DevNode_Registry_Property_ExA));
    e("CM_Set_DevNode_Registry_Property_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Set_DevNode_Registry_Property_ExW));
    e("CM_Set_HW_Prof", reinterpret_cast<void*>(&ksetupapiG_CM_Set_HW_Prof));
    e("CM_Set_HW_Prof_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Set_HW_Prof_Ex));
    e("CM_Set_HW_Prof_FlagsA", reinterpret_cast<void*>(&ksetupapiG_CM_Set_HW_Prof_FlagsA));
    e("CM_Set_HW_Prof_FlagsW", reinterpret_cast<void*>(&ksetupapiG_CM_Set_HW_Prof_FlagsW));
    e("CM_Set_HW_Prof_Flags_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Set_HW_Prof_Flags_ExA));
    e("CM_Set_HW_Prof_Flags_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Set_HW_Prof_Flags_ExW));
    e("CM_Setup_DevNode", reinterpret_cast<void*>(&ksetupapiG_CM_Setup_DevNode));
    e("CM_Setup_DevNode_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Setup_DevNode_Ex));
    e("CM_Test_Range_Available", reinterpret_cast<void*>(&ksetupapiG_CM_Test_Range_Available));
    e("CM_Uninstall_DevNode", reinterpret_cast<void*>(&ksetupapiG_CM_Uninstall_DevNode));
    e("CM_Uninstall_DevNode_Ex", reinterpret_cast<void*>(&ksetupapiG_CM_Uninstall_DevNode_Ex));
    e("CM_Unregister_Device_InterfaceA", reinterpret_cast<void*>(&ksetupapiG_CM_Unregister_Device_InterfaceA));
    e("CM_Unregister_Device_InterfaceW", reinterpret_cast<void*>(&ksetupapiG_CM_Unregister_Device_InterfaceW));
    e("CM_Unregister_Device_Interface_ExA", reinterpret_cast<void*>(&ksetupapiG_CM_Unregister_Device_Interface_ExA));
    e("CM_Unregister_Device_Interface_ExW", reinterpret_cast<void*>(&ksetupapiG_CM_Unregister_Device_Interface_ExW));
    e("InstallHinfSectionA", reinterpret_cast<void*>(&ksetupapiG_InstallHinfSectionA));
    e("InstallHinfSectionW", reinterpret_cast<void*>(&ksetupapiG_InstallHinfSectionW));
    e("SetupAddInstallSectionToDiskSpaceListA", reinterpret_cast<void*>(&ksetupapiG_SetupAddInstallSectionToDiskSpaceListA));
    e("SetupAddInstallSectionToDiskSpaceListW", reinterpret_cast<void*>(&ksetupapiG_SetupAddInstallSectionToDiskSpaceListW));
    e("SetupAddSectionToDiskSpaceListA", reinterpret_cast<void*>(&ksetupapiG_SetupAddSectionToDiskSpaceListA));
    e("SetupAddSectionToDiskSpaceListW", reinterpret_cast<void*>(&ksetupapiG_SetupAddSectionToDiskSpaceListW));
    e("SetupAddToDiskSpaceListA", reinterpret_cast<void*>(&ksetupapiG_SetupAddToDiskSpaceListA));
    e("SetupAddToDiskSpaceListW", reinterpret_cast<void*>(&ksetupapiG_SetupAddToDiskSpaceListW));
    e("SetupAddToSourceListA", reinterpret_cast<void*>(&ksetupapiG_SetupAddToSourceListA));
    e("SetupAddToSourceListW", reinterpret_cast<void*>(&ksetupapiG_SetupAddToSourceListW));
    e("SetupAdjustDiskSpaceListA", reinterpret_cast<void*>(&ksetupapiG_SetupAdjustDiskSpaceListA));
    e("SetupAdjustDiskSpaceListW", reinterpret_cast<void*>(&ksetupapiG_SetupAdjustDiskSpaceListW));
    e("SetupBackupErrorA", reinterpret_cast<void*>(&ksetupapiG_SetupBackupErrorA));
    e("SetupBackupErrorW", reinterpret_cast<void*>(&ksetupapiG_SetupBackupErrorW));
    e("SetupCancelTemporarySourceList", reinterpret_cast<void*>(&ksetupapiG_SetupCancelTemporarySourceList));
    e("SetupCloseFileQueue", reinterpret_cast<void*>(&ksetupapiG_SetupCloseFileQueue));
    e("SetupCloseInfFile", reinterpret_cast<void*>(&ksetupapiG_SetupCloseInfFile));
    e("SetupCloseLog", reinterpret_cast<void*>(&ksetupapiG_SetupCloseLog));
    e("SetupCommitFileQueueA", reinterpret_cast<void*>(&ksetupapiG_SetupCommitFileQueueA));
    e("SetupCommitFileQueueW", reinterpret_cast<void*>(&ksetupapiG_SetupCommitFileQueueW));
    e("SetupConfigureWmiFromInfSectionA", reinterpret_cast<void*>(&ksetupapiG_SetupConfigureWmiFromInfSectionA));
    e("SetupConfigureWmiFromInfSectionW", reinterpret_cast<void*>(&ksetupapiG_SetupConfigureWmiFromInfSectionW));
    e("SetupCopyErrorA", reinterpret_cast<void*>(&ksetupapiG_SetupCopyErrorA));
    e("SetupCopyErrorW", reinterpret_cast<void*>(&ksetupapiG_SetupCopyErrorW));
    e("SetupCopyOEMInfA", reinterpret_cast<void*>(&ksetupapiG_SetupCopyOEMInfA));
    e("SetupCopyOEMInfW", reinterpret_cast<void*>(&ksetupapiG_SetupCopyOEMInfW));
    e("SetupCreateDiskSpaceListA", reinterpret_cast<void*>(&ksetupapiG_SetupCreateDiskSpaceListA));
    e("SetupCreateDiskSpaceListW", reinterpret_cast<void*>(&ksetupapiG_SetupCreateDiskSpaceListW));
    e("SetupDecompressOrCopyFileA", reinterpret_cast<void*>(&ksetupapiG_SetupDecompressOrCopyFileA));
    e("SetupDecompressOrCopyFileW", reinterpret_cast<void*>(&ksetupapiG_SetupDecompressOrCopyFileW));
    e("SetupDefaultQueueCallbackA", reinterpret_cast<void*>(&ksetupapiG_SetupDefaultQueueCallbackA));
    e("SetupDefaultQueueCallbackW", reinterpret_cast<void*>(&ksetupapiG_SetupDefaultQueueCallbackW));
    e("SetupDeleteErrorA", reinterpret_cast<void*>(&ksetupapiG_SetupDeleteErrorA));
    e("SetupDeleteErrorW", reinterpret_cast<void*>(&ksetupapiG_SetupDeleteErrorW));
    e("SetupDestroyDiskSpaceList", reinterpret_cast<void*>(&ksetupapiG_SetupDestroyDiskSpaceList));
    e("SetupDiAskForOEMDisk", reinterpret_cast<void*>(&ksetupapiG_SetupDiAskForOEMDisk));
    e("SetupDiBuildClassInfoList", reinterpret_cast<void*>(&ksetupapiG_SetupDiBuildClassInfoList));
    e("SetupDiBuildClassInfoListExA", reinterpret_cast<void*>(&ksetupapiG_SetupDiBuildClassInfoListExA));
    e("SetupDiBuildClassInfoListExW", reinterpret_cast<void*>(&ksetupapiG_SetupDiBuildClassInfoListExW));
    e("SetupDiBuildDriverInfoList", reinterpret_cast<void*>(&ksetupapiG_SetupDiBuildDriverInfoList));
    e("SetupDiCallClassInstaller", reinterpret_cast<void*>(&ksetupapiG_SetupDiCallClassInstaller));
    e("SetupDiCancelDriverInfoSearch", reinterpret_cast<void*>(&ksetupapiG_SetupDiCancelDriverInfoSearch));
    e("SetupDiChangeState", reinterpret_cast<void*>(&ksetupapiG_SetupDiChangeState));
    e("SetupDiClassGuidsFromNameA", reinterpret_cast<void*>(&ksetupapiG_SetupDiClassGuidsFromNameA));
    e("SetupDiClassGuidsFromNameExA", reinterpret_cast<void*>(&ksetupapiG_SetupDiClassGuidsFromNameExA));
    e("SetupDiClassGuidsFromNameExW", reinterpret_cast<void*>(&ksetupapiG_SetupDiClassGuidsFromNameExW));
    e("SetupDiClassGuidsFromNameW", reinterpret_cast<void*>(&ksetupapiG_SetupDiClassGuidsFromNameW));
    e("SetupDiClassNameFromGuidA", reinterpret_cast<void*>(&ksetupapiG_SetupDiClassNameFromGuidA));
    e("SetupDiClassNameFromGuidExA", reinterpret_cast<void*>(&ksetupapiG_SetupDiClassNameFromGuidExA));
    e("SetupDiClassNameFromGuidExW", reinterpret_cast<void*>(&ksetupapiG_SetupDiClassNameFromGuidExW));
    e("SetupDiClassNameFromGuidW", reinterpret_cast<void*>(&ksetupapiG_SetupDiClassNameFromGuidW));
    e("SetupDiCreateDevRegKeyA", reinterpret_cast<void*>(&ksetupapiG_SetupDiCreateDevRegKeyA));
    e("SetupDiCreateDevRegKeyW", reinterpret_cast<void*>(&ksetupapiG_SetupDiCreateDevRegKeyW));
    e("SetupDiCreateDeviceInfoA", reinterpret_cast<void*>(&ksetupapiG_SetupDiCreateDeviceInfoA));
    e("SetupDiCreateDeviceInfoList", reinterpret_cast<void*>(&ksetupapiG_SetupDiCreateDeviceInfoList));
    e("SetupDiCreateDeviceInfoListExA", reinterpret_cast<void*>(&ksetupapiG_SetupDiCreateDeviceInfoListExA));
    e("SetupDiCreateDeviceInfoListExW", reinterpret_cast<void*>(&ksetupapiG_SetupDiCreateDeviceInfoListExW));
    e("SetupDiCreateDeviceInfoW", reinterpret_cast<void*>(&ksetupapiG_SetupDiCreateDeviceInfoW));
    e("SetupDiCreateDeviceInterfaceA", reinterpret_cast<void*>(&ksetupapiG_SetupDiCreateDeviceInterfaceA));
    e("SetupDiCreateDeviceInterfaceRegKeyA", reinterpret_cast<void*>(&ksetupapiG_SetupDiCreateDeviceInterfaceRegKeyA));
    e("SetupDiCreateDeviceInterfaceRegKeyW", reinterpret_cast<void*>(&ksetupapiG_SetupDiCreateDeviceInterfaceRegKeyW));
    e("SetupDiCreateDeviceInterfaceW", reinterpret_cast<void*>(&ksetupapiG_SetupDiCreateDeviceInterfaceW));
    e("SetupDiDeleteDevRegKey", reinterpret_cast<void*>(&ksetupapiG_SetupDiDeleteDevRegKey));
    e("SetupDiDeleteDeviceInfo", reinterpret_cast<void*>(&ksetupapiG_SetupDiDeleteDeviceInfo));
    e("SetupDiDeleteDeviceInterfaceData", reinterpret_cast<void*>(&ksetupapiG_SetupDiDeleteDeviceInterfaceData));
    e("SetupDiDeleteDeviceInterfaceRegKey", reinterpret_cast<void*>(&ksetupapiG_SetupDiDeleteDeviceInterfaceRegKey));
    e("SetupDiDestroyClassImageList", reinterpret_cast<void*>(&ksetupapiG_SetupDiDestroyClassImageList));
    e("SetupDiDestroyDriverInfoList", reinterpret_cast<void*>(&ksetupapiG_SetupDiDestroyDriverInfoList));
    e("SetupDiDrawMiniIcon", reinterpret_cast<void*>(&ksetupapiG_SetupDiDrawMiniIcon));
    e("SetupDiEnumDeviceInterfaces", reinterpret_cast<void*>(&ksetupapiG_SetupDiEnumDeviceInterfaces));
    e("SetupDiEnumDriverInfoA", reinterpret_cast<void*>(&ksetupapiG_SetupDiEnumDriverInfoA));
    e("SetupDiEnumDriverInfoW", reinterpret_cast<void*>(&ksetupapiG_SetupDiEnumDriverInfoW));
    e("SetupDiGetActualModelsSectionA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetActualModelsSectionA));
    e("SetupDiGetActualModelsSectionW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetActualModelsSectionW));
    e("SetupDiGetActualSectionToInstallA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetActualSectionToInstallA));
    e("SetupDiGetActualSectionToInstallExA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetActualSectionToInstallExA));
    e("SetupDiGetActualSectionToInstallExW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetActualSectionToInstallExW));
    e("SetupDiGetActualSectionToInstallW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetActualSectionToInstallW));
    e("SetupDiGetClassBitmapIndex", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetClassBitmapIndex));
    e("SetupDiGetClassDescriptionA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetClassDescriptionA));
    e("SetupDiGetClassDescriptionExA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetClassDescriptionExA));
    e("SetupDiGetClassDescriptionExW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetClassDescriptionExW));
    e("SetupDiGetClassDescriptionW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetClassDescriptionW));
    e("SetupDiGetClassDevPropertySheetsA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetClassDevPropertySheetsA));
    e("SetupDiGetClassDevPropertySheetsW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetClassDevPropertySheetsW));
    e("SetupDiGetClassDevsExA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetClassDevsExA));
    e("SetupDiGetClassDevsExW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetClassDevsExW));
    e("SetupDiGetClassImageIndex", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetClassImageIndex));
    e("SetupDiGetClassImageList", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetClassImageList));
    e("SetupDiGetClassImageListExA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetClassImageListExA));
    e("SetupDiGetClassImageListExW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetClassImageListExW));
    e("SetupDiGetClassInstallParamsA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetClassInstallParamsA));
    e("SetupDiGetClassInstallParamsW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetClassInstallParamsW));
    e("SetupDiGetClassRegistryPropertyA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetClassRegistryPropertyA));
    e("SetupDiGetClassRegistryPropertyW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetClassRegistryPropertyW));
    e("SetupDiGetCustomDevicePropertyA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetCustomDevicePropertyA));
    e("SetupDiGetCustomDevicePropertyW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetCustomDevicePropertyW));
    e("SetupDiGetDeviceInfoListClass", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetDeviceInfoListClass));
    e("SetupDiGetDeviceInfoListDetailA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetDeviceInfoListDetailA));
    e("SetupDiGetDeviceInfoListDetailW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetDeviceInfoListDetailW));
    e("SetupDiGetDeviceInstallParamsA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetDeviceInstallParamsA));
    e("SetupDiGetDeviceInstallParamsW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetDeviceInstallParamsW));
    e("SetupDiGetDeviceInstanceIdA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetDeviceInstanceIdA));
    e("SetupDiGetDeviceInstanceIdW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetDeviceInstanceIdW));
    e("SetupDiGetDeviceInterfaceAlias", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetDeviceInterfaceAlias));
    e("SetupDiGetDeviceInterfaceDetailA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetDeviceInterfaceDetailA));
    e("SetupDiGetDeviceInterfaceDetailW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetDeviceInterfaceDetailW));
    e("SetupDiGetDeviceRegistryPropertyA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetDeviceRegistryPropertyA));
    e("SetupDiGetDeviceRegistryPropertyW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetDeviceRegistryPropertyW));
    e("SetupDiGetDriverInfoDetailA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetDriverInfoDetailA));
    e("SetupDiGetDriverInfoDetailW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetDriverInfoDetailW));
    e("SetupDiGetDriverInstallParamsA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetDriverInstallParamsA));
    e("SetupDiGetDriverInstallParamsW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetDriverInstallParamsW));
    e("SetupDiGetHwProfileFriendlyNameA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetHwProfileFriendlyNameA));
    e("SetupDiGetHwProfileFriendlyNameExA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetHwProfileFriendlyNameExA));
    e("SetupDiGetHwProfileFriendlyNameExW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetHwProfileFriendlyNameExW));
    e("SetupDiGetHwProfileFriendlyNameW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetHwProfileFriendlyNameW));
    e("SetupDiGetHwProfileList", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetHwProfileList));
    e("SetupDiGetHwProfileListExA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetHwProfileListExA));
    e("SetupDiGetHwProfileListExW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetHwProfileListExW));
    e("SetupDiGetINFClassA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetINFClassA));
    e("SetupDiGetINFClassW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetINFClassW));
    e("SetupDiGetSelectedDevice", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetSelectedDevice));
    e("SetupDiGetSelectedDriverA", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetSelectedDriverA));
    e("SetupDiGetSelectedDriverW", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetSelectedDriverW));
    e("SetupDiGetWizardPage", reinterpret_cast<void*>(&ksetupapiG_SetupDiGetWizardPage));
    e("SetupDiInstallClassA", reinterpret_cast<void*>(&ksetupapiG_SetupDiInstallClassA));
    e("SetupDiInstallClassExA", reinterpret_cast<void*>(&ksetupapiG_SetupDiInstallClassExA));
    e("SetupDiInstallClassExW", reinterpret_cast<void*>(&ksetupapiG_SetupDiInstallClassExW));
    e("SetupDiInstallClassW", reinterpret_cast<void*>(&ksetupapiG_SetupDiInstallClassW));
    e("SetupDiInstallDevice", reinterpret_cast<void*>(&ksetupapiG_SetupDiInstallDevice));
    e("SetupDiInstallDeviceInterfaces", reinterpret_cast<void*>(&ksetupapiG_SetupDiInstallDeviceInterfaces));
    e("SetupDiInstallDriverFiles", reinterpret_cast<void*>(&ksetupapiG_SetupDiInstallDriverFiles));
    e("SetupDiLoadClassIcon", reinterpret_cast<void*>(&ksetupapiG_SetupDiLoadClassIcon));
    e("SetupDiOpenClassRegKey", reinterpret_cast<void*>(&ksetupapiG_SetupDiOpenClassRegKey));
    e("SetupDiOpenClassRegKeyExA", reinterpret_cast<void*>(&ksetupapiG_SetupDiOpenClassRegKeyExA));
    e("SetupDiOpenClassRegKeyExW", reinterpret_cast<void*>(&ksetupapiG_SetupDiOpenClassRegKeyExW));
    e("SetupDiOpenDevRegKey", reinterpret_cast<void*>(&ksetupapiG_SetupDiOpenDevRegKey));
    e("SetupDiOpenDeviceInfoA", reinterpret_cast<void*>(&ksetupapiG_SetupDiOpenDeviceInfoA));
    e("SetupDiOpenDeviceInfoW", reinterpret_cast<void*>(&ksetupapiG_SetupDiOpenDeviceInfoW));
    e("SetupDiOpenDeviceInterfaceA", reinterpret_cast<void*>(&ksetupapiG_SetupDiOpenDeviceInterfaceA));
    e("SetupDiOpenDeviceInterfaceRegKey", reinterpret_cast<void*>(&ksetupapiG_SetupDiOpenDeviceInterfaceRegKey));
    e("SetupDiOpenDeviceInterfaceW", reinterpret_cast<void*>(&ksetupapiG_SetupDiOpenDeviceInterfaceW));
    e("SetupDiRegisterCoDeviceInstallers", reinterpret_cast<void*>(&ksetupapiG_SetupDiRegisterCoDeviceInstallers));
    e("SetupDiRegisterDeviceInfo", reinterpret_cast<void*>(&ksetupapiG_SetupDiRegisterDeviceInfo));
    e("SetupDiRemoveDevice", reinterpret_cast<void*>(&ksetupapiG_SetupDiRemoveDevice));
    e("SetupDiRemoveDeviceInterface", reinterpret_cast<void*>(&ksetupapiG_SetupDiRemoveDeviceInterface));
    e("SetupDiRestartDevices", reinterpret_cast<void*>(&ksetupapiG_SetupDiRestartDevices));
    e("SetupDiSelectBestCompatDrv", reinterpret_cast<void*>(&ksetupapiG_SetupDiSelectBestCompatDrv));
    e("SetupDiSelectDevice", reinterpret_cast<void*>(&ksetupapiG_SetupDiSelectDevice));
    e("SetupDiSelectOEMDrv", reinterpret_cast<void*>(&ksetupapiG_SetupDiSelectOEMDrv));
    e("SetupDiSetClassInstallParamsA", reinterpret_cast<void*>(&ksetupapiG_SetupDiSetClassInstallParamsA));
    e("SetupDiSetClassInstallParamsW", reinterpret_cast<void*>(&ksetupapiG_SetupDiSetClassInstallParamsW));
    e("SetupDiSetClassRegistryPropertyA", reinterpret_cast<void*>(&ksetupapiG_SetupDiSetClassRegistryPropertyA));
    e("SetupDiSetClassRegistryPropertyW", reinterpret_cast<void*>(&ksetupapiG_SetupDiSetClassRegistryPropertyW));
    e("SetupDiSetDeviceInstallParamsA", reinterpret_cast<void*>(&ksetupapiG_SetupDiSetDeviceInstallParamsA));
    e("SetupDiSetDeviceInstallParamsW", reinterpret_cast<void*>(&ksetupapiG_SetupDiSetDeviceInstallParamsW));
    e("SetupDiSetDeviceInterfaceDefault", reinterpret_cast<void*>(&ksetupapiG_SetupDiSetDeviceInterfaceDefault));
    e("SetupDiSetDeviceRegistryPropertyA", reinterpret_cast<void*>(&ksetupapiG_SetupDiSetDeviceRegistryPropertyA));
    e("SetupDiSetDeviceRegistryPropertyW", reinterpret_cast<void*>(&ksetupapiG_SetupDiSetDeviceRegistryPropertyW));
    e("SetupDiSetDriverInstallParamsA", reinterpret_cast<void*>(&ksetupapiG_SetupDiSetDriverInstallParamsA));
    e("SetupDiSetDriverInstallParamsW", reinterpret_cast<void*>(&ksetupapiG_SetupDiSetDriverInstallParamsW));
    e("SetupDiSetSelectedDevice", reinterpret_cast<void*>(&ksetupapiG_SetupDiSetSelectedDevice));
    e("SetupDiSetSelectedDriverA", reinterpret_cast<void*>(&ksetupapiG_SetupDiSetSelectedDriverA));
    e("SetupDiSetSelectedDriverW", reinterpret_cast<void*>(&ksetupapiG_SetupDiSetSelectedDriverW));
    e("SetupDiUnremoveDevice", reinterpret_cast<void*>(&ksetupapiG_SetupDiUnremoveDevice));
    e("SetupDuplicateDiskSpaceListA", reinterpret_cast<void*>(&ksetupapiG_SetupDuplicateDiskSpaceListA));
    e("SetupDuplicateDiskSpaceListW", reinterpret_cast<void*>(&ksetupapiG_SetupDuplicateDiskSpaceListW));
    e("SetupEnumInfSectionsA", reinterpret_cast<void*>(&ksetupapiG_SetupEnumInfSectionsA));
    e("SetupEnumInfSectionsW", reinterpret_cast<void*>(&ksetupapiG_SetupEnumInfSectionsW));
    e("SetupFindFirstLineA", reinterpret_cast<void*>(&ksetupapiG_SetupFindFirstLineA));
    e("SetupFindFirstLineW", reinterpret_cast<void*>(&ksetupapiG_SetupFindFirstLineW));
    e("SetupFindNextLine", reinterpret_cast<void*>(&ksetupapiG_SetupFindNextLine));
    e("SetupFindNextMatchLineA", reinterpret_cast<void*>(&ksetupapiG_SetupFindNextMatchLineA));
    e("SetupFindNextMatchLineW", reinterpret_cast<void*>(&ksetupapiG_SetupFindNextMatchLineW));
    e("SetupFreeSourceListA", reinterpret_cast<void*>(&ksetupapiG_SetupFreeSourceListA));
    e("SetupFreeSourceListW", reinterpret_cast<void*>(&ksetupapiG_SetupFreeSourceListW));
    e("SetupGetBackupInformationA", reinterpret_cast<void*>(&ksetupapiG_SetupGetBackupInformationA));
    e("SetupGetBackupInformationW", reinterpret_cast<void*>(&ksetupapiG_SetupGetBackupInformationW));
    e("SetupGetBinaryField", reinterpret_cast<void*>(&ksetupapiG_SetupGetBinaryField));
    e("SetupGetFieldCount", reinterpret_cast<void*>(&ksetupapiG_SetupGetFieldCount));
    e("SetupGetFileCompressionInfoA", reinterpret_cast<void*>(&ksetupapiG_SetupGetFileCompressionInfoA));
    e("SetupGetFileCompressionInfoExA", reinterpret_cast<void*>(&ksetupapiG_SetupGetFileCompressionInfoExA));
    e("SetupGetFileCompressionInfoExW", reinterpret_cast<void*>(&ksetupapiG_SetupGetFileCompressionInfoExW));
    e("SetupGetFileCompressionInfoW", reinterpret_cast<void*>(&ksetupapiG_SetupGetFileCompressionInfoW));
    e("SetupGetFileQueueCount", reinterpret_cast<void*>(&ksetupapiG_SetupGetFileQueueCount));
    e("SetupGetFileQueueFlags", reinterpret_cast<void*>(&ksetupapiG_SetupGetFileQueueFlags));
    e("SetupGetInfFileListA", reinterpret_cast<void*>(&ksetupapiG_SetupGetInfFileListA));
    e("SetupGetInfFileListW", reinterpret_cast<void*>(&ksetupapiG_SetupGetInfFileListW));
    e("SetupGetInfInformationA", reinterpret_cast<void*>(&ksetupapiG_SetupGetInfInformationA));
    e("SetupGetInfInformationW", reinterpret_cast<void*>(&ksetupapiG_SetupGetInfInformationW));
    e("SetupGetIntField", reinterpret_cast<void*>(&ksetupapiG_SetupGetIntField));
    e("SetupGetLineByIndexA", reinterpret_cast<void*>(&ksetupapiG_SetupGetLineByIndexA));
    e("SetupGetLineByIndexW", reinterpret_cast<void*>(&ksetupapiG_SetupGetLineByIndexW));
    e("SetupGetLineCountA", reinterpret_cast<void*>(&ksetupapiG_SetupGetLineCountA));
    e("SetupGetLineCountW", reinterpret_cast<void*>(&ksetupapiG_SetupGetLineCountW));
    e("SetupGetLineTextA", reinterpret_cast<void*>(&ksetupapiG_SetupGetLineTextA));
    e("SetupGetLineTextW", reinterpret_cast<void*>(&ksetupapiG_SetupGetLineTextW));
    e("SetupGetMultiSzFieldA", reinterpret_cast<void*>(&ksetupapiG_SetupGetMultiSzFieldA));
    e("SetupGetMultiSzFieldW", reinterpret_cast<void*>(&ksetupapiG_SetupGetMultiSzFieldW));
    e("SetupGetNonInteractiveMode", reinterpret_cast<void*>(&ksetupapiG_SetupGetNonInteractiveMode));
    e("SetupGetSourceFileLocationA", reinterpret_cast<void*>(&ksetupapiG_SetupGetSourceFileLocationA));
    e("SetupGetSourceFileLocationW", reinterpret_cast<void*>(&ksetupapiG_SetupGetSourceFileLocationW));
    e("SetupGetSourceFileSizeA", reinterpret_cast<void*>(&ksetupapiG_SetupGetSourceFileSizeA));
    e("SetupGetSourceFileSizeW", reinterpret_cast<void*>(&ksetupapiG_SetupGetSourceFileSizeW));
    e("SetupGetSourceInfoA", reinterpret_cast<void*>(&ksetupapiG_SetupGetSourceInfoA));
    e("SetupGetSourceInfoW", reinterpret_cast<void*>(&ksetupapiG_SetupGetSourceInfoW));
    e("SetupGetStringFieldA", reinterpret_cast<void*>(&ksetupapiG_SetupGetStringFieldA));
    e("SetupGetStringFieldW", reinterpret_cast<void*>(&ksetupapiG_SetupGetStringFieldW));
    e("SetupGetTargetPathA", reinterpret_cast<void*>(&ksetupapiG_SetupGetTargetPathA));
    e("SetupGetTargetPathW", reinterpret_cast<void*>(&ksetupapiG_SetupGetTargetPathW));
    e("SetupInitDefaultQueueCallback", reinterpret_cast<void*>(&ksetupapiG_SetupInitDefaultQueueCallback));
    e("SetupInitDefaultQueueCallbackEx", reinterpret_cast<void*>(&ksetupapiG_SetupInitDefaultQueueCallbackEx));
    e("SetupInitializeFileLogA", reinterpret_cast<void*>(&ksetupapiG_SetupInitializeFileLogA));
    e("SetupInitializeFileLogW", reinterpret_cast<void*>(&ksetupapiG_SetupInitializeFileLogW));
    e("SetupInstallFileA", reinterpret_cast<void*>(&ksetupapiG_SetupInstallFileA));
    e("SetupInstallFileExA", reinterpret_cast<void*>(&ksetupapiG_SetupInstallFileExA));
    e("SetupInstallFileExW", reinterpret_cast<void*>(&ksetupapiG_SetupInstallFileExW));
    e("SetupInstallFileW", reinterpret_cast<void*>(&ksetupapiG_SetupInstallFileW));
    e("SetupInstallFilesFromInfSectionA", reinterpret_cast<void*>(&ksetupapiG_SetupInstallFilesFromInfSectionA));
    e("SetupInstallFilesFromInfSectionW", reinterpret_cast<void*>(&ksetupapiG_SetupInstallFilesFromInfSectionW));
    e("SetupInstallFromInfSectionA", reinterpret_cast<void*>(&ksetupapiG_SetupInstallFromInfSectionA));
    e("SetupInstallFromInfSectionW", reinterpret_cast<void*>(&ksetupapiG_SetupInstallFromInfSectionW));
    e("SetupInstallServicesFromInfSectionA", reinterpret_cast<void*>(&ksetupapiG_SetupInstallServicesFromInfSectionA));
    e("SetupInstallServicesFromInfSectionExA", reinterpret_cast<void*>(&ksetupapiG_SetupInstallServicesFromInfSectionExA));
    e("SetupInstallServicesFromInfSectionExW", reinterpret_cast<void*>(&ksetupapiG_SetupInstallServicesFromInfSectionExW));
    e("SetupInstallServicesFromInfSectionW", reinterpret_cast<void*>(&ksetupapiG_SetupInstallServicesFromInfSectionW));
    e("SetupIterateCabinetA", reinterpret_cast<void*>(&ksetupapiG_SetupIterateCabinetA));
    e("SetupIterateCabinetW", reinterpret_cast<void*>(&ksetupapiG_SetupIterateCabinetW));
    e("SetupLogErrorA", reinterpret_cast<void*>(&ksetupapiG_SetupLogErrorA));
    e("SetupLogErrorW", reinterpret_cast<void*>(&ksetupapiG_SetupLogErrorW));
    e("SetupLogFileA", reinterpret_cast<void*>(&ksetupapiG_SetupLogFileA));
    e("SetupLogFileW", reinterpret_cast<void*>(&ksetupapiG_SetupLogFileW));
    e("SetupOpenAppendInfFileA", reinterpret_cast<void*>(&ksetupapiG_SetupOpenAppendInfFileA));
    e("SetupOpenAppendInfFileW", reinterpret_cast<void*>(&ksetupapiG_SetupOpenAppendInfFileW));
    e("SetupOpenFileQueue", reinterpret_cast<void*>(&ksetupapiG_SetupOpenFileQueue));
    e("SetupOpenInfFileA", reinterpret_cast<void*>(&ksetupapiG_SetupOpenInfFileA));
    e("SetupOpenInfFileW", reinterpret_cast<void*>(&ksetupapiG_SetupOpenInfFileW));
    e("SetupOpenLog", reinterpret_cast<void*>(&ksetupapiG_SetupOpenLog));
    e("SetupOpenMasterInf", reinterpret_cast<void*>(&ksetupapiG_SetupOpenMasterInf));
    e("SetupPrepareQueueForRestoreA", reinterpret_cast<void*>(&ksetupapiG_SetupPrepareQueueForRestoreA));
    e("SetupPrepareQueueForRestoreW", reinterpret_cast<void*>(&ksetupapiG_SetupPrepareQueueForRestoreW));
    e("SetupPromptForDiskA", reinterpret_cast<void*>(&ksetupapiG_SetupPromptForDiskA));
    e("SetupPromptForDiskW", reinterpret_cast<void*>(&ksetupapiG_SetupPromptForDiskW));
    e("SetupPromptReboot", reinterpret_cast<void*>(&ksetupapiG_SetupPromptReboot));
    e("SetupQueryDrivesInDiskSpaceListA", reinterpret_cast<void*>(&ksetupapiG_SetupQueryDrivesInDiskSpaceListA));
    e("SetupQueryDrivesInDiskSpaceListW", reinterpret_cast<void*>(&ksetupapiG_SetupQueryDrivesInDiskSpaceListW));
    e("SetupQueryFileLogA", reinterpret_cast<void*>(&ksetupapiG_SetupQueryFileLogA));
    e("SetupQueryFileLogW", reinterpret_cast<void*>(&ksetupapiG_SetupQueryFileLogW));
    e("SetupQueryInfFileInformationA", reinterpret_cast<void*>(&ksetupapiG_SetupQueryInfFileInformationA));
    e("SetupQueryInfFileInformationW", reinterpret_cast<void*>(&ksetupapiG_SetupQueryInfFileInformationW));
    e("SetupQueryInfOriginalFileInformationA", reinterpret_cast<void*>(&ksetupapiG_SetupQueryInfOriginalFileInformationA));
    e("SetupQueryInfOriginalFileInformationW", reinterpret_cast<void*>(&ksetupapiG_SetupQueryInfOriginalFileInformationW));
    e("SetupQueryInfVersionInformationA", reinterpret_cast<void*>(&ksetupapiG_SetupQueryInfVersionInformationA));
    e("SetupQueryInfVersionInformationW", reinterpret_cast<void*>(&ksetupapiG_SetupQueryInfVersionInformationW));
    e("SetupQuerySourceListA", reinterpret_cast<void*>(&ksetupapiG_SetupQuerySourceListA));
    e("SetupQuerySourceListW", reinterpret_cast<void*>(&ksetupapiG_SetupQuerySourceListW));
    e("SetupQuerySpaceRequiredOnDriveA", reinterpret_cast<void*>(&ksetupapiG_SetupQuerySpaceRequiredOnDriveA));
    e("SetupQuerySpaceRequiredOnDriveW", reinterpret_cast<void*>(&ksetupapiG_SetupQuerySpaceRequiredOnDriveW));
    e("SetupQueueCopyA", reinterpret_cast<void*>(&ksetupapiG_SetupQueueCopyA));
    e("SetupQueueCopyIndirectA", reinterpret_cast<void*>(&ksetupapiG_SetupQueueCopyIndirectA));
    e("SetupQueueCopyIndirectW", reinterpret_cast<void*>(&ksetupapiG_SetupQueueCopyIndirectW));
    e("SetupQueueCopySectionA", reinterpret_cast<void*>(&ksetupapiG_SetupQueueCopySectionA));
    e("SetupQueueCopySectionW", reinterpret_cast<void*>(&ksetupapiG_SetupQueueCopySectionW));
    e("SetupQueueCopyW", reinterpret_cast<void*>(&ksetupapiG_SetupQueueCopyW));
    e("SetupQueueDefaultCopyA", reinterpret_cast<void*>(&ksetupapiG_SetupQueueDefaultCopyA));
    e("SetupQueueDefaultCopyW", reinterpret_cast<void*>(&ksetupapiG_SetupQueueDefaultCopyW));
    e("SetupQueueDeleteA", reinterpret_cast<void*>(&ksetupapiG_SetupQueueDeleteA));
    e("SetupQueueDeleteSectionA", reinterpret_cast<void*>(&ksetupapiG_SetupQueueDeleteSectionA));
    e("SetupQueueDeleteSectionW", reinterpret_cast<void*>(&ksetupapiG_SetupQueueDeleteSectionW));
    e("SetupQueueDeleteW", reinterpret_cast<void*>(&ksetupapiG_SetupQueueDeleteW));
    e("SetupQueueRenameA", reinterpret_cast<void*>(&ksetupapiG_SetupQueueRenameA));
    e("SetupQueueRenameSectionA", reinterpret_cast<void*>(&ksetupapiG_SetupQueueRenameSectionA));
    e("SetupQueueRenameSectionW", reinterpret_cast<void*>(&ksetupapiG_SetupQueueRenameSectionW));
    e("SetupQueueRenameW", reinterpret_cast<void*>(&ksetupapiG_SetupQueueRenameW));
    e("SetupRemoveFileLogEntryA", reinterpret_cast<void*>(&ksetupapiG_SetupRemoveFileLogEntryA));
    e("SetupRemoveFileLogEntryW", reinterpret_cast<void*>(&ksetupapiG_SetupRemoveFileLogEntryW));
    e("SetupRemoveFromDiskSpaceListA", reinterpret_cast<void*>(&ksetupapiG_SetupRemoveFromDiskSpaceListA));
    e("SetupRemoveFromDiskSpaceListW", reinterpret_cast<void*>(&ksetupapiG_SetupRemoveFromDiskSpaceListW));
    e("SetupRemoveFromSourceListA", reinterpret_cast<void*>(&ksetupapiG_SetupRemoveFromSourceListA));
    e("SetupRemoveFromSourceListW", reinterpret_cast<void*>(&ksetupapiG_SetupRemoveFromSourceListW));
    e("SetupRemoveInstallSectionFromDiskSpaceListA", reinterpret_cast<void*>(&ksetupapiG_SetupRemoveInstallSectionFromDiskSpaceListA));
    e("SetupRemoveInstallSectionFromDiskSpaceListW", reinterpret_cast<void*>(&ksetupapiG_SetupRemoveInstallSectionFromDiskSpaceListW));
    e("SetupRemoveSectionFromDiskSpaceListA", reinterpret_cast<void*>(&ksetupapiG_SetupRemoveSectionFromDiskSpaceListA));
    e("SetupRemoveSectionFromDiskSpaceListW", reinterpret_cast<void*>(&ksetupapiG_SetupRemoveSectionFromDiskSpaceListW));
    e("SetupRenameErrorA", reinterpret_cast<void*>(&ksetupapiG_SetupRenameErrorA));
    e("SetupRenameErrorW", reinterpret_cast<void*>(&ksetupapiG_SetupRenameErrorW));
    e("SetupScanFileQueueA", reinterpret_cast<void*>(&ksetupapiG_SetupScanFileQueueA));
    e("SetupScanFileQueueW", reinterpret_cast<void*>(&ksetupapiG_SetupScanFileQueueW));
    e("SetupSetDirectoryIdA", reinterpret_cast<void*>(&ksetupapiG_SetupSetDirectoryIdA));
    e("SetupSetDirectoryIdExA", reinterpret_cast<void*>(&ksetupapiG_SetupSetDirectoryIdExA));
    e("SetupSetDirectoryIdExW", reinterpret_cast<void*>(&ksetupapiG_SetupSetDirectoryIdExW));
    e("SetupSetDirectoryIdW", reinterpret_cast<void*>(&ksetupapiG_SetupSetDirectoryIdW));
    e("SetupSetFileQueueAlternatePlatformA", reinterpret_cast<void*>(&ksetupapiG_SetupSetFileQueueAlternatePlatformA));
    e("SetupSetFileQueueAlternatePlatformW", reinterpret_cast<void*>(&ksetupapiG_SetupSetFileQueueAlternatePlatformW));
    e("SetupSetFileQueueFlags", reinterpret_cast<void*>(&ksetupapiG_SetupSetFileQueueFlags));
    e("SetupSetNonInteractiveMode", reinterpret_cast<void*>(&ksetupapiG_SetupSetNonInteractiveMode));
    e("SetupSetPlatformPathOverrideA", reinterpret_cast<void*>(&ksetupapiG_SetupSetPlatformPathOverrideA));
    e("SetupSetPlatformPathOverrideW", reinterpret_cast<void*>(&ksetupapiG_SetupSetPlatformPathOverrideW));
    e("SetupSetSourceListA", reinterpret_cast<void*>(&ksetupapiG_SetupSetSourceListA));
    e("SetupSetSourceListW", reinterpret_cast<void*>(&ksetupapiG_SetupSetSourceListW));
    e("SetupTermDefaultQueueCallback", reinterpret_cast<void*>(&ksetupapiG_SetupTermDefaultQueueCallback));
    e("SetupTerminateFileLog", reinterpret_cast<void*>(&ksetupapiG_SetupTerminateFileLog));
    e("SetupUninstallNewlyCopiedInfs", reinterpret_cast<void*>(&ksetupapiG_SetupUninstallNewlyCopiedInfs));
    e("SetupUninstallOEMInfA", reinterpret_cast<void*>(&ksetupapiG_SetupUninstallOEMInfA));
    e("SetupUninstallOEMInfW", reinterpret_cast<void*>(&ksetupapiG_SetupUninstallOEMInfW));
    e("SetupVerifyInfFileA", reinterpret_cast<void*>(&ksetupapiG_SetupVerifyInfFileA));
    e("SetupVerifyInfFileW", reinterpret_cast<void*>(&ksetupapiG_SetupVerifyInfFileW));
}
}  // namespace occ::runtime::winabi

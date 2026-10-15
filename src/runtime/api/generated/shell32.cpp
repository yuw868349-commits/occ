// The SHELL32 surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_AssocCreateForClasses(const void* rgClasses, std::uint32_t cClasses, const void* riid, void** ppv) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(rgClasses);
    static_cast<void>(cClasses);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_AssocGetDetailsOfPropKey(void* psf, void* pidl, const void* pkey, void* pv, std::int32_t* pfFoundPropKey) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(psf);
    static_cast<void>(pidl);
    static_cast<void>(pkey);
    static_cast<void>(pv);
    static_cast<void>(pfFoundPropKey);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_CDefFolderMenu_Create2(void* pidlFolder, void* hwnd, std::uint32_t cidl, void* apidl, void* psf, std::uint64_t pfn, std::uint32_t nKeys, const void* ahkeys, void** ppcm) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pidlFolder);
    static_cast<void>(hwnd);
    static_cast<void>(cidl);
    static_cast<void>(apidl);
    static_cast<void>(psf);
    static_cast<void>(pfn);
    static_cast<void>(nKeys);
    static_cast<void>(ahkeys);
    static_cast<void>(ppcm);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_CIDLData_CreateFromIDArray(void* pidlFolder, std::uint32_t cidl, void* apidl, void** ppdtobj) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pidlFolder);
    static_cast<void>(cidl);
    static_cast<void>(apidl);
    static_cast<void>(ppdtobj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) char16_t** kshell32G_CommandLineToArgvW(const char16_t* lpCmdLine, std::int32_t* pNumArgs) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(lpCmdLine);
    static_cast<void>(pNumArgs);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_DAD_AutoScroll(void* hwnd, void* pad, const std::uint64_t* pptNow) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hwnd);
    static_cast<void>(pad);
    static_cast<void>(pptNow);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_DAD_DragEnterEx(void* hwndTarget, std::uint64_t ptStart) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hwndTarget);
    static_cast<void>(ptStart);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_DAD_DragEnterEx2(void* hwndTarget, std::uint64_t ptStart, void* pdtObject) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hwndTarget);
    static_cast<void>(ptStart);
    static_cast<void>(pdtObject);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_DAD_DragLeave() noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_DAD_DragMove(std::uint64_t pt) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pt);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_DAD_SetDragImage(void* him, std::uint64_t* pptOffset) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(him);
    static_cast<void>(pptOffset);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_DAD_ShowDragImage(std::int32_t fShow) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(fShow);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshell32G_DoEnvironmentSubstA(char* pszSrc, std::uint32_t cchSrc) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszSrc);
    static_cast<void>(cchSrc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshell32G_DoEnvironmentSubstW(char16_t* pszSrc, std::uint32_t cchSrc) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszSrc);
    static_cast<void>(cchSrc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kshell32G_DragAcceptFiles(void* hWnd, std::int32_t fAccept) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hWnd);
    static_cast<void>(fAccept);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kshell32G_DragFinish(std::uint64_t hDrop) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hDrop);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshell32G_DragQueryFileA(std::uint64_t hDrop, std::uint32_t iFile, char* lpszFile, std::uint32_t cch) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hDrop);
    static_cast<void>(iFile);
    static_cast<void>(lpszFile);
    static_cast<void>(cch);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshell32G_DragQueryFileW(std::uint64_t hDrop, std::uint32_t iFile, char16_t* lpszFile, std::uint32_t cch) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hDrop);
    static_cast<void>(iFile);
    static_cast<void>(lpszFile);
    static_cast<void>(cch);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_DragQueryPoint(std::uint64_t hDrop, std::uint64_t* ppt) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hDrop);
    static_cast<void>(ppt);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_DriveType(std::int32_t iDrive) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(iDrive);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_DuplicateIcon(void* hInst, void* hIcon) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hInst);
    static_cast<void>(hIcon);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_ExtractAssociatedIconA(void* hInst, char* pszIconPath, std::uint16_t* piIcon) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(hInst);
    static_cast<void>(pszIconPath);
    static_cast<void>(piIcon);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_ExtractAssociatedIconExA(void* hInst, char* pszIconPath, std::uint16_t* piIconIndex, std::uint16_t* piIconId) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(hInst);
    static_cast<void>(pszIconPath);
    static_cast<void>(piIconIndex);
    static_cast<void>(piIconId);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_ExtractAssociatedIconExW(void* hInst, char16_t* pszIconPath, std::uint16_t* piIconIndex, std::uint16_t* piIconId) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(hInst);
    static_cast<void>(pszIconPath);
    static_cast<void>(piIconIndex);
    static_cast<void>(piIconId);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_ExtractAssociatedIconW(void* hInst, char16_t* pszIconPath, std::uint16_t* piIcon) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(hInst);
    static_cast<void>(pszIconPath);
    static_cast<void>(piIcon);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_ExtractIconA(void* hInst, const char* pszExeFileName, std::uint32_t nIconIndex) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hInst);
    static_cast<void>(pszExeFileName);
    static_cast<void>(nIconIndex);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshell32G_ExtractIconExA(const char* lpszFile, std::int32_t nIconIndex, void* phiconLarge, void* phiconSmall, std::uint32_t nIcons) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(lpszFile);
    static_cast<void>(nIconIndex);
    static_cast<void>(phiconLarge);
    static_cast<void>(phiconSmall);
    static_cast<void>(nIcons);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshell32G_ExtractIconExW(const char16_t* lpszFile, std::int32_t nIconIndex, void* phiconLarge, void* phiconSmall, std::uint32_t nIcons) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(lpszFile);
    static_cast<void>(nIconIndex);
    static_cast<void>(phiconLarge);
    static_cast<void>(phiconSmall);
    static_cast<void>(nIcons);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_ExtractIconW(void* hInst, const char16_t* pszExeFileName, std::uint32_t nIconIndex) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hInst);
    static_cast<void>(pszExeFileName);
    static_cast<void>(nIconIndex);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_FindExecutableA(const char* lpFile, const char* lpDirectory, char* lpResult) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(lpFile);
    static_cast<void>(lpDirectory);
    static_cast<void>(lpResult);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_FindExecutableW(const char16_t* lpFile, const char16_t* lpDirectory, char16_t* lpResult) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(lpFile);
    static_cast<void>(lpDirectory);
    static_cast<void>(lpResult);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_GetCurrentProcessExplicitAppUserModelID(char16_t** AppID) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(AppID);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_GetFileNameFromBrowse(void* hwnd, char16_t* pszFilePath, std::uint32_t cchFilePath, const char16_t* pszWorkingDir, const char16_t* pszDefExt, const char16_t* pszFilters, const char16_t* pszTitle) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hwnd);
    static_cast<void>(pszFilePath);
    static_cast<void>(cchFilePath);
    static_cast<void>(pszWorkingDir);
    static_cast<void>(pszDefExt);
    static_cast<void>(pszFilters);
    static_cast<void>(pszTitle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_ILAppendID(void* pidl, std::uint64_t pmkid, std::int32_t fAppend) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pidl);
    static_cast<void>(pmkid);
    static_cast<void>(fAppend);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_ILClone(void* pidl) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pidl);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_ILCloneFirst(void* pidl) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pidl);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_ILCombine(void* pidl1, void* pidl2) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pidl1);
    static_cast<void>(pidl2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_ILCreateFromPathA(const char* pszPath) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszPath);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_ILCreateFromPathW(const char16_t* pszPath) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszPath);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_ILFindChild(void* pidlParent, void* pidlChild) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pidlParent);
    static_cast<void>(pidlChild);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_ILFindLastID(void* pidl) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pidl);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void kshell32G_ILFree(void* pidl) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pidl);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void* kshell32G_ILGetNext(void* pidl) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pidl);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshell32G_ILGetSize(void* pidl) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pidl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_ILIsEqual(void* pidl1, void* pidl2) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pidl1);
    static_cast<void>(pidl2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_ILIsParent(void* pidl1, void* pidl2, std::int32_t fImmediate) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pidl1);
    static_cast<void>(pidl2);
    static_cast<void>(fImmediate);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_ILLoadFromStream(void* pstm, void* pidl) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pstm);
    static_cast<void>(pidl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_ILLoadFromStreamEx(void* pstm, void* pidl) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pstm);
    static_cast<void>(pidl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_ILRemoveLastID(void* pidl) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pidl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_ILSaveToStream(void* pstm, void* pidl) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pstm);
    static_cast<void>(pidl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_InitNetworkAddressControl() noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_IsLFNDriveA(const char* pszPath) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(pszPath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_IsLFNDriveW(const char16_t* pszPath) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(pszPath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_IsNetDrive(std::int32_t iDrive) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(iDrive);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_IsUserAnAdmin() noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_OpenRegStream(void* hkey, const char16_t* pszSubkey, const char16_t* pszValue, std::uint32_t grfMode) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hkey);
    static_cast<void>(pszSubkey);
    static_cast<void>(pszValue);
    static_cast<void>(grfMode);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_PathCleanupSpec(const char16_t* pszDir, char16_t* pszSpec) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszDir);
    static_cast<void>(pszSpec);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kshell32G_PathGetShortPath(char16_t* pszLongPath) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszLongPath);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_PathIsExe(const char16_t* pszPath) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszPath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_PathIsSlowA(const char* pszFile, std::uint32_t dwAttr) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszFile);
    static_cast<void>(dwAttr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_PathIsSlowW(const char16_t* pszFile, std::uint32_t dwAttr) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszFile);
    static_cast<void>(dwAttr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_PathMakeUniqueName(char16_t* pszUniqueName, std::uint32_t cchMax, const char16_t* pszTemplate, const char16_t* pszLongPlate, const char16_t* pszDir) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszUniqueName);
    static_cast<void>(cchMax);
    static_cast<void>(pszTemplate);
    static_cast<void>(pszLongPlate);
    static_cast<void>(pszDir);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kshell32G_PathQualify(char16_t* psz) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(psz);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_PathResolve(char16_t* pszPath, std::uint64_t dirs, std::uint32_t fFlags) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszPath);
    static_cast<void>(dirs);
    static_cast<void>(fFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_PathYetAnotherMakeUniqueName(char16_t* pszUniqueName, const char16_t* pszPath, const char16_t* pszShort, const char16_t* pszFileSpec) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszUniqueName);
    static_cast<void>(pszPath);
    static_cast<void>(pszShort);
    static_cast<void>(pszFileSpec);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_PickIconDlg(void* hwnd, char16_t* pszIconPath, std::uint32_t cchIconPath, std::int32_t* piIconIndex) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hwnd);
    static_cast<void>(pszIconPath);
    static_cast<void>(cchIconPath);
    static_cast<void>(piIconIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_PifMgr_CloseProperties(void* hProps, std::uint32_t flOpt) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hProps);
    static_cast<void>(flOpt);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_PifMgr_GetProperties(void* hProps, const char* pszGroup, void* lpProps, std::int32_t cbProps, std::uint32_t flOpt) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hProps);
    static_cast<void>(pszGroup);
    static_cast<void>(lpProps);
    static_cast<void>(cbProps);
    static_cast<void>(flOpt);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_PifMgr_OpenProperties(const char16_t* pszApp, const char16_t* pszPIF, std::uint32_t hInf, std::uint32_t flOpt) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszApp);
    static_cast<void>(pszPIF);
    static_cast<void>(hInf);
    static_cast<void>(flOpt);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_PifMgr_SetProperties(void* hProps, const char* pszGroup, const void* lpProps, std::int32_t cbProps, std::uint32_t flOpt) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hProps);
    static_cast<void>(pszGroup);
    static_cast<void>(lpProps);
    static_cast<void>(cbProps);
    static_cast<void>(flOpt);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_ReadCabinetState(void* pcs, std::int32_t cLength) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pcs);
    static_cast<void>(cLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_RealDriveType(std::int32_t iDrive, std::int32_t fOKToHitNet) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(iDrive);
    static_cast<void>(fOKToHitNet);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_RestartDialog(void* hwnd, const char16_t* pszPrompt, std::uint32_t dwReturn) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hwnd);
    static_cast<void>(pszPrompt);
    static_cast<void>(dwReturn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_RestartDialogEx(void* hwnd, const char16_t* pszPrompt, std::uint32_t dwReturn, std::uint32_t dwReasonCode) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hwnd);
    static_cast<void>(pszPrompt);
    static_cast<void>(dwReturn);
    static_cast<void>(dwReasonCode);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHAddDefaultPropertiesByExt(const char16_t* pszExt, void* pPropStore) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszExt);
    static_cast<void>(pPropStore);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshell32G_SHAddFromPropSheetExtArray(std::uint64_t hpsxa, std::uint64_t lpfnAddPage, std::int64_t lParam) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hpsxa);
    static_cast<void>(lpfnAddPage);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kshell32G_SHAddToRecentDocs(std::uint32_t uFlags, const void* pv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(uFlags);
    static_cast<void>(pv);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void* kshell32G_SHAlloc(std::uint64_t cb) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(cb);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kshell32G_SHAppBarMessage(std::uint32_t dwMessage, std::uint64_t pData) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(dwMessage);
    static_cast<void>(pData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHAssocEnumHandlers(const char16_t* pszExtra, std::uint64_t afFilter, void** ppEnumHandler) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(pszExtra);
    static_cast<void>(afFilter);
    static_cast<void>(ppEnumHandler);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHAssocEnumHandlersForProtocolByApplication(const char16_t* protocol, const void* riid, void** enumHandlers) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(protocol);
    static_cast<void>(riid);
    static_cast<void>(enumHandlers);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHBindToFolderIDListParent(void* psfRoot, void* pidl, const void* riid, void** ppv, void* ppidlLast) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(psfRoot);
    static_cast<void>(pidl);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    static_cast<void>(ppidlLast);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHBindToFolderIDListParentEx(void* psfRoot, void* pidl, void* ppbc, const void* riid, void** ppv, void* ppidlLast) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(psfRoot);
    static_cast<void>(pidl);
    static_cast<void>(ppbc);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    static_cast<void>(ppidlLast);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHBindToObject(void* psf, void* pidl, void* pbc, const void* riid, void** ppv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(psf);
    static_cast<void>(pidl);
    static_cast<void>(pbc);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHBindToParent(void* pidl, const void* riid, void** ppv, void* ppidlLast) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pidl);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    static_cast<void>(ppidlLast);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_SHBrowseForFolderA(std::uint64_t lpbi) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(lpbi);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_SHBrowseForFolderW(std::uint64_t lpbi) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(lpbi);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCLSIDFromString(const char16_t* psz, void* pclsid) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(psz);
    static_cast<void>(pclsid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_SHChangeNotification_Lock(void* hChange, std::uint32_t dwProcId, void** pppidl, std::int32_t* plEvent) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hChange);
    static_cast<void>(dwProcId);
    static_cast<void>(pppidl);
    static_cast<void>(plEvent);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHChangeNotification_Unlock(void* hLock) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hLock);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kshell32G_SHChangeNotify(std::int32_t wEventId, std::uint32_t uFlags, const void* dwItem1, const void* dwItem2) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(wEventId);
    static_cast<void>(uFlags);
    static_cast<void>(dwItem1);
    static_cast<void>(dwItem2);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHChangeNotifyDeregister(std::uint32_t ulID) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(ulID);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshell32G_SHChangeNotifyRegister(void* hwnd, std::int32_t fSources, std::int32_t fEvents, std::uint32_t wMsg, std::int32_t cEntries, const void* pshcne) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hwnd);
    static_cast<void>(fSources);
    static_cast<void>(fEvents);
    static_cast<void>(wMsg);
    static_cast<void>(cEntries);
    static_cast<void>(pshcne);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kshell32G_SHChangeNotifyRegisterThread(std::uint64_t status) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(status);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void* kshell32G_SHCloneSpecialIDList(void* hwnd, std::int32_t csidl, std::int32_t fCreate) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hwnd);
    static_cast<void>(csidl);
    static_cast<void>(fCreate);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCoCreateInstance(const char16_t* pszCLSID, const void* pclsid, void* pUnkOuter, const void* riid, void** ppv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszCLSID);
    static_cast<void>(pclsid);
    static_cast<void>(pUnkOuter);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateAssociationRegistration(const void* riid, void** ppv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateDataObject(void* pidlFolder, std::uint32_t cidl, void* apidl, void* pdtInner, const void* riid, void** ppv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pidlFolder);
    static_cast<void>(cidl);
    static_cast<void>(apidl);
    static_cast<void>(pdtInner);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateDefaultContextMenu(const void* pdcm, const void* riid, void** ppv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pdcm);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateDefaultExtractIcon(const void* riid, void** ppv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateDefaultPropertiesOp(void* psi, void** ppFileOp) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(psi);
    static_cast<void>(ppFileOp);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateDirectory(void* hwnd, const char16_t* pszPath) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hwnd);
    static_cast<void>(pszPath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateDirectoryExA(void* hwnd, const char* pszPath, const void* psa) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hwnd);
    static_cast<void>(pszPath);
    static_cast<void>(psa);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateDirectoryExW(void* hwnd, const char16_t* pszPath, const void* psa) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hwnd);
    static_cast<void>(pszPath);
    static_cast<void>(psa);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateFileExtractIconW(const char16_t* pszFile, std::uint32_t dwFileAttributes, const void* riid, void** ppv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pszFile);
    static_cast<void>(dwFileAttributes);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateItemFromIDList(void* pidl, const void* riid, void** ppv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pidl);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateItemFromParsingName(const char16_t* pszPath, void* pbc, const void* riid, void** ppv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pszPath);
    static_cast<void>(pbc);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateItemFromRelativeName(void* psiParent, const char16_t* pszName, void* pbc, const void* riid, void** ppv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(psiParent);
    static_cast<void>(pszName);
    static_cast<void>(pbc);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateItemInKnownFolder(const void* kfid, std::uint32_t dwKFFlags, const char16_t* pszItem, const void* riid, void** ppv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(kfid);
    static_cast<void>(dwKFFlags);
    static_cast<void>(pszItem);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateItemWithParent(void* pidlParent, void* psfParent, void* pidl, const void* riid, void** ppvItem) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pidlParent);
    static_cast<void>(psfParent);
    static_cast<void>(pidl);
    static_cast<void>(riid);
    static_cast<void>(ppvItem);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateProcessAsUserW(std::uint64_t pscpi) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pscpi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kshell32G_SHCreatePropSheetExtArray(void* hKey, const char16_t* pszSubKey, std::uint32_t max_iface) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hKey);
    static_cast<void>(pszSubKey);
    static_cast<void>(max_iface);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateQueryCancelAutoPlayMoniker(void** ppmoniker) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(ppmoniker);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateShellFolderView(const void* pcsfv, void** ppsv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pcsfv);
    static_cast<void>(ppsv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateShellFolderViewEx(void* pcsfv, void** ppsv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pcsfv);
    static_cast<void>(ppsv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateShellItem(void* pidlParent, void* psfParent, void* pidl, void** ppsi) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pidlParent);
    static_cast<void>(psfParent);
    static_cast<void>(pidl);
    static_cast<void>(ppsi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateShellItemArray(void* pidlParent, void* psf, std::uint32_t cidl, void* ppidl, void** ppsiItemArray) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pidlParent);
    static_cast<void>(psf);
    static_cast<void>(cidl);
    static_cast<void>(ppidl);
    static_cast<void>(ppsiItemArray);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateShellItemArrayFromDataObject(void* pdo, const void* riid, void** ppv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pdo);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateShellItemArrayFromIDLists(std::uint32_t cidl, void* rgpidl, void** ppsiItemArray) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(cidl);
    static_cast<void>(rgpidl);
    static_cast<void>(ppsiItemArray);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateShellItemArrayFromShellItem(void* psi, const void* riid, void** ppv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(psi);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHCreateStdEnumFmtEtc(std::uint32_t cfmt, const void* afmt, void** ppenumFormatEtc) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(cfmt);
    static_cast<void>(afmt);
    static_cast<void>(ppenumFormatEtc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHDefExtractIconA(const char* pszIconFile, std::int32_t iIndex, std::uint32_t uFlags, void* phiconLarge, void* phiconSmall, std::uint32_t nIconSize) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszIconFile);
    static_cast<void>(iIndex);
    static_cast<void>(uFlags);
    static_cast<void>(phiconLarge);
    static_cast<void>(phiconSmall);
    static_cast<void>(nIconSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHDefExtractIconW(const char16_t* pszIconFile, std::int32_t iIndex, std::uint32_t uFlags, void* phiconLarge, void* phiconSmall, std::uint32_t nIconSize) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszIconFile);
    static_cast<void>(iIndex);
    static_cast<void>(uFlags);
    static_cast<void>(phiconLarge);
    static_cast<void>(phiconSmall);
    static_cast<void>(nIconSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kshell32G_SHDestroyPropSheetExtArray(std::uint64_t hpsxa) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hpsxa);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHDoDragDrop(void* hwnd, void* pdata, void* pdsrc, std::uint32_t dwEffect, std::uint32_t* pdwEffect) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hwnd);
    static_cast<void>(pdata);
    static_cast<void>(pdsrc);
    static_cast<void>(dwEffect);
    static_cast<void>(pdwEffect);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHEmptyRecycleBinA(void* hwnd, const char* pszRootPath, std::uint32_t dwFlags) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hwnd);
    static_cast<void>(pszRootPath);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHEmptyRecycleBinW(void* hwnd, const char16_t* pszRootPath, std::uint32_t dwFlags) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hwnd);
    static_cast<void>(pszRootPath);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHEnumerateUnreadMailAccountsW(void* hKeyUser, std::uint32_t dwIndex, char16_t* pszMailAddress, std::int32_t cchMailAddress) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hKeyUser);
    static_cast<void>(dwIndex);
    static_cast<void>(pszMailAddress);
    static_cast<void>(cchMailAddress);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHEvaluateSystemCommandTemplate(const char16_t* pszCmdTemplate, char16_t** ppszApplication, char16_t** ppszCommandLine, char16_t** ppszParameters) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(pszCmdTemplate);
    static_cast<void>(ppszApplication);
    static_cast<void>(ppszCommandLine);
    static_cast<void>(ppszParameters);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHFileOperationA(std::uint64_t lpFileOp) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(lpFileOp);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHFileOperationW(std::uint64_t lpFileOp) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(lpFileOp);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHFindFiles(void* pidlFolder, void* pidlSaveFile) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pidlFolder);
    static_cast<void>(pidlSaveFile);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_SHFind_InitMenuPopup(void* hmenu, void* hwndOwner, std::uint32_t idCmdFirst, std::uint32_t idCmdLast) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hmenu);
    static_cast<void>(hwndOwner);
    static_cast<void>(idCmdFirst);
    static_cast<void>(idCmdLast);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void kshell32G_SHFlushSFCache() noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshell32G_SHFormatDrive(void* hwnd, std::uint32_t drive, std::uint32_t fmtID, std::uint32_t options) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(hwnd);
    static_cast<void>(drive);
    static_cast<void>(fmtID);
    static_cast<void>(options);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kshell32G_SHFree(void* pv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pv);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kshell32G_SHFreeNameMappings(void* hNameMappings) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hNameMappings);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetAttributesFromDataObject(void* pdo, std::uint32_t dwAttributeMask, std::uint32_t* pdwAttributes, std::uint32_t* pcItems) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pdo);
    static_cast<void>(dwAttributeMask);
    static_cast<void>(pdwAttributes);
    static_cast<void>(pcItems);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetDataFromIDListA(void* psf, void* pidl, std::int32_t nFormat, void* pv, std::int32_t cb) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(psf);
    static_cast<void>(pidl);
    static_cast<void>(nFormat);
    static_cast<void>(pv);
    static_cast<void>(cb);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetDataFromIDListW(void* psf, void* pidl, std::int32_t nFormat, void* pv, std::int32_t cb) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(psf);
    static_cast<void>(pidl);
    static_cast<void>(nFormat);
    static_cast<void>(pv);
    static_cast<void>(cb);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetDesktopFolder(void** ppshf) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(ppshf);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetDiskFreeSpaceExA(const char* pszDirectoryName, std::uint64_t* pulFreeBytesAvailableToCaller, std::uint64_t* pulTotalNumberOfBytes, std::uint64_t* pulTotalNumberOfFreeBytes) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(pszDirectoryName);
    static_cast<void>(pulFreeBytesAvailableToCaller);
    static_cast<void>(pulTotalNumberOfBytes);
    static_cast<void>(pulTotalNumberOfFreeBytes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetDiskFreeSpaceExW(const char16_t* pszDirectoryName, std::uint64_t* pulFreeBytesAvailableToCaller, std::uint64_t* pulTotalNumberOfBytes, std::uint64_t* pulTotalNumberOfFreeBytes) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(pszDirectoryName);
    static_cast<void>(pulFreeBytesAvailableToCaller);
    static_cast<void>(pulTotalNumberOfBytes);
    static_cast<void>(pulTotalNumberOfFreeBytes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetDriveMedia(const char16_t* pszDrive, std::uint32_t* pdwMediaContent) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(pszDrive);
    static_cast<void>(pdwMediaContent);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kshell32G_SHGetFileInfoA(const char* pszPath, std::uint32_t dwFileAttributes, void* psfi, std::uint32_t cbFileInfo, std::uint32_t uFlags) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pszPath);
    static_cast<void>(dwFileAttributes);
    static_cast<void>(psfi);
    static_cast<void>(cbFileInfo);
    static_cast<void>(uFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kshell32G_SHGetFileInfoW(const char16_t* pszPath, std::uint32_t dwFileAttributes, void* psfi, std::uint32_t cbFileInfo, std::uint32_t uFlags) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pszPath);
    static_cast<void>(dwFileAttributes);
    static_cast<void>(psfi);
    static_cast<void>(cbFileInfo);
    static_cast<void>(uFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetFolderLocation(void* hwnd, std::int32_t csidl, void* hToken, std::uint32_t dwFlags, void* ppidl) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hwnd);
    static_cast<void>(csidl);
    static_cast<void>(hToken);
    static_cast<void>(dwFlags);
    static_cast<void>(ppidl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetFolderPathAndSubDirA(void* hwnd, std::int32_t csidl, void* hToken, std::uint32_t dwFlags, const char* pszSubDir, char* pszPath) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hwnd);
    static_cast<void>(csidl);
    static_cast<void>(hToken);
    static_cast<void>(dwFlags);
    static_cast<void>(pszSubDir);
    static_cast<void>(pszPath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetFolderPathAndSubDirW(void* hwnd, std::int32_t csidl, void* hToken, std::uint32_t dwFlags, const char16_t* pszSubDir, char16_t* pszPath) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hwnd);
    static_cast<void>(csidl);
    static_cast<void>(hToken);
    static_cast<void>(dwFlags);
    static_cast<void>(pszSubDir);
    static_cast<void>(pszPath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetIDListFromObject(void* punk, void* ppidl) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(punk);
    static_cast<void>(ppidl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetIconOverlayIndexA(const char* pszIconPath, std::int32_t iIconIndex) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pszIconPath);
    static_cast<void>(iIconIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetIconOverlayIndexW(const char16_t* pszIconPath, std::int32_t iIconIndex) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pszIconPath);
    static_cast<void>(iIconIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetImageList(std::int32_t iImageList, const void* riid, void** ppvObj) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(iImageList);
    static_cast<void>(riid);
    static_cast<void>(ppvObj);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetInstanceExplorer(void** ppunk) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(ppunk);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetItemFromDataObject(void* pdtobj, std::uint64_t dwFlags, const void* riid, void** ppv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pdtobj);
    static_cast<void>(dwFlags);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetItemFromObject(void* punk, const void* riid, void** ppv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(punk);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetKnownFolderIDList(const void* rfid, std::uint32_t dwFlags, void* hToken, void* ppidl) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(rfid);
    static_cast<void>(dwFlags);
    static_cast<void>(hToken);
    static_cast<void>(ppidl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetKnownFolderItem(const void* rfid, std::uint64_t flags, void* hToken, const void* riid, void** ppv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(rfid);
    static_cast<void>(flags);
    static_cast<void>(hToken);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetKnownFolderPath(const void* rfid, std::uint32_t dwFlags, void* hToken, char16_t** ppszPath) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(rfid);
    static_cast<void>(dwFlags);
    static_cast<void>(hToken);
    static_cast<void>(ppszPath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetLocalizedName(const char16_t* pszPath, char16_t* pszResModule, std::uint32_t cch, std::int32_t* pidsRes) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pszPath);
    static_cast<void>(pszResModule);
    static_cast<void>(cch);
    static_cast<void>(pidsRes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetMalloc(void** ppMalloc) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(ppMalloc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetNameFromIDList(void* pidl, std::uint64_t sigdnName, char16_t** ppszName) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pidl);
    static_cast<void>(sigdnName);
    static_cast<void>(ppszName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetNewLinkInfoA(const char* pszLinkTo, const char* pszDir, char* pszName, std::int32_t* pfMustCopy, std::uint32_t uFlags) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pszLinkTo);
    static_cast<void>(pszDir);
    static_cast<void>(pszName);
    static_cast<void>(pfMustCopy);
    static_cast<void>(uFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetNewLinkInfoW(const char16_t* pszLinkTo, const char16_t* pszDir, char16_t* pszName, std::int32_t* pfMustCopy, std::uint32_t uFlags) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pszLinkTo);
    static_cast<void>(pszDir);
    static_cast<void>(pszName);
    static_cast<void>(pfMustCopy);
    static_cast<void>(uFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetPathFromIDListA(void* pidl, char* pszPath) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pidl);
    static_cast<void>(pszPath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetPathFromIDListEx(void* pidl, char16_t* pszPath, std::uint32_t cchPath, std::uint64_t uOpts) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pidl);
    static_cast<void>(pszPath);
    static_cast<void>(cchPath);
    static_cast<void>(uOpts);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetPathFromIDListW(void* pidl, char16_t* pszPath) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pidl);
    static_cast<void>(pszPath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetPropertyStoreForWindow(void* hwnd, const void* riid, void** ppv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hwnd);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetPropertyStoreFromIDList(void* pidl, std::uint64_t flags, const void* riid, void** ppv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pidl);
    static_cast<void>(flags);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetPropertyStoreFromParsingName(const char16_t* pszPath, void* pbc, std::uint64_t flags, const void* riid, void** ppv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pszPath);
    static_cast<void>(pbc);
    static_cast<void>(flags);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetRealIDL(void* psf, void* pidlSimple, void* ppidlReal) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(psf);
    static_cast<void>(pidlSimple);
    static_cast<void>(ppidlReal);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetSetFolderCustomSettings(std::uint64_t pfcs, const char16_t* pszPath, std::uint32_t dwReadWrite) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pfcs);
    static_cast<void>(pszPath);
    static_cast<void>(dwReadWrite);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kshell32G_SHGetSetSettings(std::uint64_t lpss, std::uint32_t dwMask, std::int32_t bSet) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(lpss);
    static_cast<void>(dwMask);
    static_cast<void>(bSet);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kshell32G_SHGetSettings(void* psfs, std::uint32_t dwMask) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(psfs);
    static_cast<void>(dwMask);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetSpecialFolderLocation(void* hwnd, std::int32_t csidl, void* ppidl) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hwnd);
    static_cast<void>(csidl);
    static_cast<void>(ppidl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetStockIconInfo(std::uint64_t siid, std::uint32_t uFlags, void* psii) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(siid);
    static_cast<void>(uFlags);
    static_cast<void>(psii);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetTemporaryPropertyForItem(void* psi, const void* propkey, void* ppropvar) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(psi);
    static_cast<void>(propkey);
    static_cast<void>(ppropvar);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHGetUnreadMailCountW(void* hKeyUser, const char16_t* pszMailAddress, std::uint32_t* pdwCount, std::uint64_t* pFileTime, char16_t* pszShellExecuteCommand, std::int32_t cchShellExecuteCommand) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hKeyUser);
    static_cast<void>(pszMailAddress);
    static_cast<void>(pdwCount);
    static_cast<void>(pFileTime);
    static_cast<void>(pszShellExecuteCommand);
    static_cast<void>(cchShellExecuteCommand);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHHandleUpdateImage(void* pidlExtra) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pidlExtra);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHILCreateFromPath(const char16_t* pszPath, void* ppidl, std::uint32_t* rgfInOut) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszPath);
    static_cast<void>(ppidl);
    static_cast<void>(rgfInOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHInvokePrinterCommandA(void* hwnd, std::uint32_t uAction, const char* lpBuf1, const char* lpBuf2, std::int32_t fModal) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(hwnd);
    static_cast<void>(uAction);
    static_cast<void>(lpBuf1);
    static_cast<void>(lpBuf2);
    static_cast<void>(fModal);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHInvokePrinterCommandW(void* hwnd, std::uint32_t uAction, const char16_t* lpBuf1, const char16_t* lpBuf2, std::int32_t fModal) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(hwnd);
    static_cast<void>(uAction);
    static_cast<void>(lpBuf1);
    static_cast<void>(lpBuf2);
    static_cast<void>(fModal);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHIsFileAvailableOffline(const char16_t* pwszPath, std::uint32_t* pdwStatus) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pwszPath);
    static_cast<void>(pdwStatus);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHLimitInputEdit(void* hwndEdit, void* psf) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hwndEdit);
    static_cast<void>(psf);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHLoadInProc(const void* rclsid) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(rclsid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHLoadNonloadedIconOverlayIdentifiers() noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHMapPIDLToSystemImageListIndex(void* pshf, void* pidl, std::int32_t* piIndexSel) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pshf);
    static_cast<void>(pidl);
    static_cast<void>(piIndexSel);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHMultiFileProperties(void* pdtobj, std::uint32_t dwFlags) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pdtobj);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHObjectProperties(void* hwnd, std::uint32_t shopObjectType, const char16_t* pszObjectName, const char16_t* pszPropertyPage) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hwnd);
    static_cast<void>(shopObjectType);
    static_cast<void>(pszObjectName);
    static_cast<void>(pszPropertyPage);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHOpenFolderAndSelectItems(void* pidlFolder, std::uint32_t cidl, void* apidl, std::uint32_t dwFlags) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pidlFolder);
    static_cast<void>(cidl);
    static_cast<void>(apidl);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHOpenPropSheetW(const char16_t* pszCaption, void* ahkeys, std::uint32_t ckeys, const void* pclsidDefault, void* pdtobj, void* psb, const char16_t* pStartPage) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszCaption);
    static_cast<void>(ahkeys);
    static_cast<void>(ckeys);
    static_cast<void>(pclsidDefault);
    static_cast<void>(pdtobj);
    static_cast<void>(psb);
    static_cast<void>(pStartPage);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHOpenWithDialog(void* hwndParent, const void* poainfo) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hwndParent);
    static_cast<void>(poainfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHParseDisplayName(const char16_t* pszName, void* pbc, void* ppidl, std::uint64_t sfgaoIn, void* psfgaoOut) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszName);
    static_cast<void>(pbc);
    static_cast<void>(ppidl);
    static_cast<void>(sfgaoIn);
    static_cast<void>(psfgaoOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHPathPrepareForWriteA(void* hwnd, void* punkEnableModless, const char* pszPath, std::uint32_t dwFlags) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hwnd);
    static_cast<void>(punkEnableModless);
    static_cast<void>(pszPath);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHPathPrepareForWriteW(void* hwnd, void* punkEnableModless, const char16_t* pszPath, std::uint32_t dwFlags) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hwnd);
    static_cast<void>(punkEnableModless);
    static_cast<void>(pszPath);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHPropStgCreate(void* psstg, const void* fmtid, const void* pclsid, std::uint32_t grfFlags, std::uint32_t grfMode, std::uint32_t dwDisposition, void** ppstg, std::uint32_t* puCodePage) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(psstg);
    static_cast<void>(fmtid);
    static_cast<void>(pclsid);
    static_cast<void>(grfFlags);
    static_cast<void>(grfMode);
    static_cast<void>(dwDisposition);
    static_cast<void>(ppstg);
    static_cast<void>(puCodePage);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHPropStgReadMultiple(void* pps, std::uint32_t uCodePage, std::uint32_t cpspec, void* rgpspec, void* rgvar) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pps);
    static_cast<void>(uCodePage);
    static_cast<void>(cpspec);
    static_cast<void>(rgpspec);
    static_cast<void>(rgvar);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHPropStgWriteMultiple(void* pps, std::uint32_t* puCodePage, std::uint32_t cpspec, void* rgpspec, void* rgvar, std::uint64_t propidNameFirst) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pps);
    static_cast<void>(puCodePage);
    static_cast<void>(cpspec);
    static_cast<void>(rgpspec);
    static_cast<void>(rgvar);
    static_cast<void>(propidNameFirst);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHQueryRecycleBinA(const char* pszRootPath, std::uint64_t pSHQueryRBInfo) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszRootPath);
    static_cast<void>(pSHQueryRBInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHQueryRecycleBinW(const char16_t* pszRootPath, std::uint64_t pSHQueryRBInfo) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszRootPath);
    static_cast<void>(pSHQueryRBInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHQueryUserNotificationState(void* pquns) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pquns);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHRemoveLocalizedName(const char16_t* pszPath) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszPath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshell32G_SHReplaceFromPropSheetExtArray(std::uint64_t hpsxa, std::uint32_t uPageID, std::uint64_t lpfnReplaceWith, std::int64_t lParam) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hpsxa);
    static_cast<void>(uPageID);
    static_cast<void>(lpfnReplaceWith);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHResolveLibrary(void* psiLibrary) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(psiLibrary);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshell32G_SHRestricted(std::uint64_t rest) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(rest);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHRunControlPanel(const char16_t* lpcszCmdLine, void* hwndMsgParent) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(lpcszCmdLine);
    static_cast<void>(hwndMsgParent);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHSetDefaultProperties(void* hwnd, void* psi, std::uint32_t dwFileOpFlags, void* pfops) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hwnd);
    static_cast<void>(psi);
    static_cast<void>(dwFileOpFlags);
    static_cast<void>(pfops);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHSetFolderPathA(std::int32_t csidl, void* hToken, std::uint32_t dwFlags, const char* pszPath) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(csidl);
    static_cast<void>(hToken);
    static_cast<void>(dwFlags);
    static_cast<void>(pszPath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHSetFolderPathW(std::int32_t csidl, void* hToken, std::uint32_t dwFlags, const char16_t* pszPath) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(csidl);
    static_cast<void>(hToken);
    static_cast<void>(dwFlags);
    static_cast<void>(pszPath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kshell32G_SHSetInstanceExplorer(void* punk) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(punk);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHSetKnownFolderPath(const void* rfid, std::uint32_t dwFlags, void* hToken, const char16_t* pszPath) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(rfid);
    static_cast<void>(dwFlags);
    static_cast<void>(hToken);
    static_cast<void>(pszPath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHSetLocalizedName(const char16_t* pszPath, const char16_t* pszResModule, std::int32_t idsRes) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pszPath);
    static_cast<void>(pszResModule);
    static_cast<void>(idsRes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHSetTemporaryPropertyForItem(void* psi, const void* propkey, const void* propvar) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(psi);
    static_cast<void>(propkey);
    static_cast<void>(propvar);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHSetUnreadMailCountW(const char16_t* pszMailAddress, std::uint32_t dwCount, const char16_t* pszShellExecuteCommand) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pszMailAddress);
    static_cast<void>(dwCount);
    static_cast<void>(pszShellExecuteCommand);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kshell32G_SHShellFolderView_Message(void* hwndMain, std::uint32_t uMsg, std::int64_t lParam) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hwndMain);
    static_cast<void>(uMsg);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHShowManageLibraryUI(void* psiLibrary, void* hwndOwner, const char16_t* pszTitle, const char16_t* pszInstruction, std::uint64_t lmdOptions) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(psiLibrary);
    static_cast<void>(hwndOwner);
    static_cast<void>(pszTitle);
    static_cast<void>(pszInstruction);
    static_cast<void>(lmdOptions);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kshell32G_SHSimpleIDListFromPath(const char16_t* pszPath) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszPath);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHStartNetConnectionDialogW(void* hwnd, const char16_t* pszRemoteName, std::uint32_t dwType) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(hwnd);
    static_cast<void>(pszRemoteName);
    static_cast<void>(dwType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHTestTokenMembership(void* hToken, std::uint32_t ulRID) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(hToken);
    static_cast<void>(ulRID);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kshell32G_SHUpdateImageA(const char* pszHashItem, std::int32_t iIndex, std::uint32_t uFlags, std::int32_t iImageIndex) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszHashItem);
    static_cast<void>(iIndex);
    static_cast<void>(uFlags);
    static_cast<void>(iImageIndex);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kshell32G_SHUpdateImageW(const char16_t* pszHashItem, std::int32_t iIndex, std::uint32_t uFlags, std::int32_t iImageIndex) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszHashItem);
    static_cast<void>(iIndex);
    static_cast<void>(uFlags);
    static_cast<void>(iImageIndex);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SHValidateUNC(void* hwndOwner, char16_t* pszFile, std::uint32_t fConnect) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(hwndOwner);
    static_cast<void>(pszFile);
    static_cast<void>(fConnect);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SetCurrentProcessExplicitAppUserModelID(const char16_t* AppID) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(AppID);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_ShellAboutA(void* hWnd, const char* szApp, const char* szOtherStuff, void* hIcon) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hWnd);
    static_cast<void>(szApp);
    static_cast<void>(szOtherStuff);
    static_cast<void>(hIcon);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_ShellAboutW(void* hWnd, const char16_t* szApp, const char16_t* szOtherStuff, void* hIcon) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hWnd);
    static_cast<void>(szApp);
    static_cast<void>(szOtherStuff);
    static_cast<void>(hIcon);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_ShellExecuteExA(void* pExecInfo) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pExecInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_ShellExecuteExW(void* pExecInfo) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pExecInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kshell32G_ShellMessageBoxA(void* hAppInst, void* hWnd, const char* lpcText, const char* lpcTitle, std::uint32_t fuStyle, ...) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hAppInst);
    static_cast<void>(hWnd);
    static_cast<void>(lpcText);
    static_cast<void>(lpcTitle);
    static_cast<void>(fuStyle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kshell32G_ShellMessageBoxW(void* hAppInst, void* hWnd, const char16_t* lpcText, const char16_t* lpcTitle, std::uint32_t fuStyle, ...) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hAppInst);
    static_cast<void>(hWnd);
    static_cast<void>(lpcText);
    static_cast<void>(lpcTitle);
    static_cast<void>(fuStyle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_Shell_GetCachedImageIndex(const char16_t* pwszIconPath, std::int32_t iIconIndex, std::uint32_t uIconFlags) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pwszIconPath);
    static_cast<void>(iIconIndex);
    static_cast<void>(uIconFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_Shell_GetCachedImageIndexA(const char* pszIconPath, std::int32_t iIconIndex, std::uint32_t uIconFlags) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pszIconPath);
    static_cast<void>(iIconIndex);
    static_cast<void>(uIconFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_Shell_GetCachedImageIndexW(const char16_t* pszIconPath, std::int32_t iIconIndex, std::uint32_t uIconFlags) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pszIconPath);
    static_cast<void>(iIconIndex);
    static_cast<void>(uIconFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_Shell_GetImageLists(void* phiml, void* phimlSmall) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(phiml);
    static_cast<void>(phimlSmall);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshell32G_Shell_MergeMenus(void* hmDst, void* hmSrc, std::uint32_t uInsert, std::uint32_t uIDAdjust, std::uint32_t uIDAdjustMax, std::uint32_t uFlags) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hmDst);
    static_cast<void>(hmSrc);
    static_cast<void>(uInsert);
    static_cast<void>(uIDAdjust);
    static_cast<void>(uIDAdjustMax);
    static_cast<void>(uFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_Shell_NotifyIconA(std::uint32_t dwMessage, std::uint64_t lpData) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(dwMessage);
    static_cast<void>(lpData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_Shell_NotifyIconGetRect(const void* identifier, void* iconLocation) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(identifier);
    static_cast<void>(iconLocation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_Shell_NotifyIconW(std::uint32_t dwMessage, std::uint64_t lpData) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(dwMessage);
    static_cast<void>(lpData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_SignalFileOpen(void* pidl) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pidl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_StgMakeUniqueName(void* pstgParent, const char16_t* pszFileSpec, std::uint32_t grfMode, const void* riid, void** ppv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pstgParent);
    static_cast<void>(pszFileSpec);
    static_cast<void>(grfMode);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_Win32DeleteFile(const char16_t* pszPath) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pszPath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshell32G_WriteCabinetState(void* pcs) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of COM folders, and there is no shell here
    static_cast<void>(pcs);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_shell32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("AssocCreateForClasses", reinterpret_cast<void*>(&kshell32G_AssocCreateForClasses));
    e("AssocGetDetailsOfPropKey", reinterpret_cast<void*>(&kshell32G_AssocGetDetailsOfPropKey));
    e("CDefFolderMenu_Create2", reinterpret_cast<void*>(&kshell32G_CDefFolderMenu_Create2));
    e("CIDLData_CreateFromIDArray", reinterpret_cast<void*>(&kshell32G_CIDLData_CreateFromIDArray));
    e("CommandLineToArgvW", reinterpret_cast<void*>(&kshell32G_CommandLineToArgvW));
    e("DAD_AutoScroll", reinterpret_cast<void*>(&kshell32G_DAD_AutoScroll));
    e("DAD_DragEnterEx", reinterpret_cast<void*>(&kshell32G_DAD_DragEnterEx));
    e("DAD_DragEnterEx2", reinterpret_cast<void*>(&kshell32G_DAD_DragEnterEx2));
    e("DAD_DragLeave", reinterpret_cast<void*>(&kshell32G_DAD_DragLeave));
    e("DAD_DragMove", reinterpret_cast<void*>(&kshell32G_DAD_DragMove));
    e("DAD_SetDragImage", reinterpret_cast<void*>(&kshell32G_DAD_SetDragImage));
    e("DAD_ShowDragImage", reinterpret_cast<void*>(&kshell32G_DAD_ShowDragImage));
    e("DoEnvironmentSubstA", reinterpret_cast<void*>(&kshell32G_DoEnvironmentSubstA));
    e("DoEnvironmentSubstW", reinterpret_cast<void*>(&kshell32G_DoEnvironmentSubstW));
    e("DragAcceptFiles", reinterpret_cast<void*>(&kshell32G_DragAcceptFiles));
    e("DragFinish", reinterpret_cast<void*>(&kshell32G_DragFinish));
    e("DragQueryFileA", reinterpret_cast<void*>(&kshell32G_DragQueryFileA));
    e("DragQueryFileW", reinterpret_cast<void*>(&kshell32G_DragQueryFileW));
    e("DragQueryPoint", reinterpret_cast<void*>(&kshell32G_DragQueryPoint));
    e("DriveType", reinterpret_cast<void*>(&kshell32G_DriveType));
    e("DuplicateIcon", reinterpret_cast<void*>(&kshell32G_DuplicateIcon));
    e("ExtractAssociatedIconA", reinterpret_cast<void*>(&kshell32G_ExtractAssociatedIconA));
    e("ExtractAssociatedIconExA", reinterpret_cast<void*>(&kshell32G_ExtractAssociatedIconExA));
    e("ExtractAssociatedIconExW", reinterpret_cast<void*>(&kshell32G_ExtractAssociatedIconExW));
    e("ExtractAssociatedIconW", reinterpret_cast<void*>(&kshell32G_ExtractAssociatedIconW));
    e("ExtractIconA", reinterpret_cast<void*>(&kshell32G_ExtractIconA));
    e("ExtractIconExA", reinterpret_cast<void*>(&kshell32G_ExtractIconExA));
    e("ExtractIconExW", reinterpret_cast<void*>(&kshell32G_ExtractIconExW));
    e("ExtractIconW", reinterpret_cast<void*>(&kshell32G_ExtractIconW));
    e("FindExecutableA", reinterpret_cast<void*>(&kshell32G_FindExecutableA));
    e("FindExecutableW", reinterpret_cast<void*>(&kshell32G_FindExecutableW));
    e("GetCurrentProcessExplicitAppUserModelID", reinterpret_cast<void*>(&kshell32G_GetCurrentProcessExplicitAppUserModelID));
    e("GetFileNameFromBrowse", reinterpret_cast<void*>(&kshell32G_GetFileNameFromBrowse));
    e("ILAppendID", reinterpret_cast<void*>(&kshell32G_ILAppendID));
    e("ILClone", reinterpret_cast<void*>(&kshell32G_ILClone));
    e("ILCloneFirst", reinterpret_cast<void*>(&kshell32G_ILCloneFirst));
    e("ILCombine", reinterpret_cast<void*>(&kshell32G_ILCombine));
    e("ILCreateFromPathA", reinterpret_cast<void*>(&kshell32G_ILCreateFromPathA));
    e("ILCreateFromPathW", reinterpret_cast<void*>(&kshell32G_ILCreateFromPathW));
    e("ILFindChild", reinterpret_cast<void*>(&kshell32G_ILFindChild));
    e("ILFindLastID", reinterpret_cast<void*>(&kshell32G_ILFindLastID));
    e("ILFree", reinterpret_cast<void*>(&kshell32G_ILFree));
    e("ILGetNext", reinterpret_cast<void*>(&kshell32G_ILGetNext));
    e("ILGetSize", reinterpret_cast<void*>(&kshell32G_ILGetSize));
    e("ILIsEqual", reinterpret_cast<void*>(&kshell32G_ILIsEqual));
    e("ILIsParent", reinterpret_cast<void*>(&kshell32G_ILIsParent));
    e("ILLoadFromStream", reinterpret_cast<void*>(&kshell32G_ILLoadFromStream));
    e("ILLoadFromStreamEx", reinterpret_cast<void*>(&kshell32G_ILLoadFromStreamEx));
    e("ILRemoveLastID", reinterpret_cast<void*>(&kshell32G_ILRemoveLastID));
    e("ILSaveToStream", reinterpret_cast<void*>(&kshell32G_ILSaveToStream));
    e("InitNetworkAddressControl", reinterpret_cast<void*>(&kshell32G_InitNetworkAddressControl));
    e("IsLFNDriveA", reinterpret_cast<void*>(&kshell32G_IsLFNDriveA));
    e("IsLFNDriveW", reinterpret_cast<void*>(&kshell32G_IsLFNDriveW));
    e("IsNetDrive", reinterpret_cast<void*>(&kshell32G_IsNetDrive));
    e("IsUserAnAdmin", reinterpret_cast<void*>(&kshell32G_IsUserAnAdmin));
    e("OpenRegStream", reinterpret_cast<void*>(&kshell32G_OpenRegStream));
    e("PathCleanupSpec", reinterpret_cast<void*>(&kshell32G_PathCleanupSpec));
    e("PathGetShortPath", reinterpret_cast<void*>(&kshell32G_PathGetShortPath));
    e("PathIsExe", reinterpret_cast<void*>(&kshell32G_PathIsExe));
    e("PathIsSlowA", reinterpret_cast<void*>(&kshell32G_PathIsSlowA));
    e("PathIsSlowW", reinterpret_cast<void*>(&kshell32G_PathIsSlowW));
    e("PathMakeUniqueName", reinterpret_cast<void*>(&kshell32G_PathMakeUniqueName));
    e("PathQualify", reinterpret_cast<void*>(&kshell32G_PathQualify));
    e("PathResolve", reinterpret_cast<void*>(&kshell32G_PathResolve));
    e("PathYetAnotherMakeUniqueName", reinterpret_cast<void*>(&kshell32G_PathYetAnotherMakeUniqueName));
    e("PickIconDlg", reinterpret_cast<void*>(&kshell32G_PickIconDlg));
    e("PifMgr_CloseProperties", reinterpret_cast<void*>(&kshell32G_PifMgr_CloseProperties));
    e("PifMgr_GetProperties", reinterpret_cast<void*>(&kshell32G_PifMgr_GetProperties));
    e("PifMgr_OpenProperties", reinterpret_cast<void*>(&kshell32G_PifMgr_OpenProperties));
    e("PifMgr_SetProperties", reinterpret_cast<void*>(&kshell32G_PifMgr_SetProperties));
    e("ReadCabinetState", reinterpret_cast<void*>(&kshell32G_ReadCabinetState));
    e("RealDriveType", reinterpret_cast<void*>(&kshell32G_RealDriveType));
    e("RestartDialog", reinterpret_cast<void*>(&kshell32G_RestartDialog));
    e("RestartDialogEx", reinterpret_cast<void*>(&kshell32G_RestartDialogEx));
    e("SHAddDefaultPropertiesByExt", reinterpret_cast<void*>(&kshell32G_SHAddDefaultPropertiesByExt));
    e("SHAddFromPropSheetExtArray", reinterpret_cast<void*>(&kshell32G_SHAddFromPropSheetExtArray));
    e("SHAddToRecentDocs", reinterpret_cast<void*>(&kshell32G_SHAddToRecentDocs));
    e("SHAlloc", reinterpret_cast<void*>(&kshell32G_SHAlloc));
    e("SHAppBarMessage", reinterpret_cast<void*>(&kshell32G_SHAppBarMessage));
    e("SHAssocEnumHandlers", reinterpret_cast<void*>(&kshell32G_SHAssocEnumHandlers));
    e("SHAssocEnumHandlersForProtocolByApplication", reinterpret_cast<void*>(&kshell32G_SHAssocEnumHandlersForProtocolByApplication));
    e("SHBindToFolderIDListParent", reinterpret_cast<void*>(&kshell32G_SHBindToFolderIDListParent));
    e("SHBindToFolderIDListParentEx", reinterpret_cast<void*>(&kshell32G_SHBindToFolderIDListParentEx));
    e("SHBindToObject", reinterpret_cast<void*>(&kshell32G_SHBindToObject));
    e("SHBindToParent", reinterpret_cast<void*>(&kshell32G_SHBindToParent));
    e("SHBrowseForFolderA", reinterpret_cast<void*>(&kshell32G_SHBrowseForFolderA));
    e("SHBrowseForFolderW", reinterpret_cast<void*>(&kshell32G_SHBrowseForFolderW));
    e("SHCLSIDFromString", reinterpret_cast<void*>(&kshell32G_SHCLSIDFromString));
    e("SHChangeNotification_Lock", reinterpret_cast<void*>(&kshell32G_SHChangeNotification_Lock));
    e("SHChangeNotification_Unlock", reinterpret_cast<void*>(&kshell32G_SHChangeNotification_Unlock));
    e("SHChangeNotify", reinterpret_cast<void*>(&kshell32G_SHChangeNotify));
    e("SHChangeNotifyDeregister", reinterpret_cast<void*>(&kshell32G_SHChangeNotifyDeregister));
    e("SHChangeNotifyRegister", reinterpret_cast<void*>(&kshell32G_SHChangeNotifyRegister));
    e("SHChangeNotifyRegisterThread", reinterpret_cast<void*>(&kshell32G_SHChangeNotifyRegisterThread));
    e("SHCloneSpecialIDList", reinterpret_cast<void*>(&kshell32G_SHCloneSpecialIDList));
    e("SHCoCreateInstance", reinterpret_cast<void*>(&kshell32G_SHCoCreateInstance));
    e("SHCreateAssociationRegistration", reinterpret_cast<void*>(&kshell32G_SHCreateAssociationRegistration));
    e("SHCreateDataObject", reinterpret_cast<void*>(&kshell32G_SHCreateDataObject));
    e("SHCreateDefaultContextMenu", reinterpret_cast<void*>(&kshell32G_SHCreateDefaultContextMenu));
    e("SHCreateDefaultExtractIcon", reinterpret_cast<void*>(&kshell32G_SHCreateDefaultExtractIcon));
    e("SHCreateDefaultPropertiesOp", reinterpret_cast<void*>(&kshell32G_SHCreateDefaultPropertiesOp));
    e("SHCreateDirectory", reinterpret_cast<void*>(&kshell32G_SHCreateDirectory));
    e("SHCreateDirectoryExA", reinterpret_cast<void*>(&kshell32G_SHCreateDirectoryExA));
    e("SHCreateDirectoryExW", reinterpret_cast<void*>(&kshell32G_SHCreateDirectoryExW));
    e("SHCreateFileExtractIconW", reinterpret_cast<void*>(&kshell32G_SHCreateFileExtractIconW));
    e("SHCreateItemFromIDList", reinterpret_cast<void*>(&kshell32G_SHCreateItemFromIDList));
    e("SHCreateItemFromParsingName", reinterpret_cast<void*>(&kshell32G_SHCreateItemFromParsingName));
    e("SHCreateItemFromRelativeName", reinterpret_cast<void*>(&kshell32G_SHCreateItemFromRelativeName));
    e("SHCreateItemInKnownFolder", reinterpret_cast<void*>(&kshell32G_SHCreateItemInKnownFolder));
    e("SHCreateItemWithParent", reinterpret_cast<void*>(&kshell32G_SHCreateItemWithParent));
    e("SHCreateProcessAsUserW", reinterpret_cast<void*>(&kshell32G_SHCreateProcessAsUserW));
    e("SHCreatePropSheetExtArray", reinterpret_cast<void*>(&kshell32G_SHCreatePropSheetExtArray));
    e("SHCreateQueryCancelAutoPlayMoniker", reinterpret_cast<void*>(&kshell32G_SHCreateQueryCancelAutoPlayMoniker));
    e("SHCreateShellFolderView", reinterpret_cast<void*>(&kshell32G_SHCreateShellFolderView));
    e("SHCreateShellFolderViewEx", reinterpret_cast<void*>(&kshell32G_SHCreateShellFolderViewEx));
    e("SHCreateShellItem", reinterpret_cast<void*>(&kshell32G_SHCreateShellItem));
    e("SHCreateShellItemArray", reinterpret_cast<void*>(&kshell32G_SHCreateShellItemArray));
    e("SHCreateShellItemArrayFromDataObject", reinterpret_cast<void*>(&kshell32G_SHCreateShellItemArrayFromDataObject));
    e("SHCreateShellItemArrayFromIDLists", reinterpret_cast<void*>(&kshell32G_SHCreateShellItemArrayFromIDLists));
    e("SHCreateShellItemArrayFromShellItem", reinterpret_cast<void*>(&kshell32G_SHCreateShellItemArrayFromShellItem));
    e("SHCreateStdEnumFmtEtc", reinterpret_cast<void*>(&kshell32G_SHCreateStdEnumFmtEtc));
    e("SHDefExtractIconA", reinterpret_cast<void*>(&kshell32G_SHDefExtractIconA));
    e("SHDefExtractIconW", reinterpret_cast<void*>(&kshell32G_SHDefExtractIconW));
    e("SHDestroyPropSheetExtArray", reinterpret_cast<void*>(&kshell32G_SHDestroyPropSheetExtArray));
    e("SHDoDragDrop", reinterpret_cast<void*>(&kshell32G_SHDoDragDrop));
    e("SHEmptyRecycleBinA", reinterpret_cast<void*>(&kshell32G_SHEmptyRecycleBinA));
    e("SHEmptyRecycleBinW", reinterpret_cast<void*>(&kshell32G_SHEmptyRecycleBinW));
    e("SHEnumerateUnreadMailAccountsW", reinterpret_cast<void*>(&kshell32G_SHEnumerateUnreadMailAccountsW));
    e("SHEvaluateSystemCommandTemplate", reinterpret_cast<void*>(&kshell32G_SHEvaluateSystemCommandTemplate));
    e("SHFileOperationA", reinterpret_cast<void*>(&kshell32G_SHFileOperationA));
    e("SHFileOperationW", reinterpret_cast<void*>(&kshell32G_SHFileOperationW));
    e("SHFindFiles", reinterpret_cast<void*>(&kshell32G_SHFindFiles));
    e("SHFind_InitMenuPopup", reinterpret_cast<void*>(&kshell32G_SHFind_InitMenuPopup));
    e("SHFlushSFCache", reinterpret_cast<void*>(&kshell32G_SHFlushSFCache));
    e("SHFormatDrive", reinterpret_cast<void*>(&kshell32G_SHFormatDrive));
    e("SHFree", reinterpret_cast<void*>(&kshell32G_SHFree));
    e("SHFreeNameMappings", reinterpret_cast<void*>(&kshell32G_SHFreeNameMappings));
    e("SHGetAttributesFromDataObject", reinterpret_cast<void*>(&kshell32G_SHGetAttributesFromDataObject));
    e("SHGetDataFromIDListA", reinterpret_cast<void*>(&kshell32G_SHGetDataFromIDListA));
    e("SHGetDataFromIDListW", reinterpret_cast<void*>(&kshell32G_SHGetDataFromIDListW));
    e("SHGetDesktopFolder", reinterpret_cast<void*>(&kshell32G_SHGetDesktopFolder));
    e("SHGetDiskFreeSpaceExA", reinterpret_cast<void*>(&kshell32G_SHGetDiskFreeSpaceExA));
    e("SHGetDiskFreeSpaceExW", reinterpret_cast<void*>(&kshell32G_SHGetDiskFreeSpaceExW));
    e("SHGetDriveMedia", reinterpret_cast<void*>(&kshell32G_SHGetDriveMedia));
    e("SHGetFileInfoA", reinterpret_cast<void*>(&kshell32G_SHGetFileInfoA));
    e("SHGetFileInfoW", reinterpret_cast<void*>(&kshell32G_SHGetFileInfoW));
    e("SHGetFolderLocation", reinterpret_cast<void*>(&kshell32G_SHGetFolderLocation));
    e("SHGetFolderPathAndSubDirA", reinterpret_cast<void*>(&kshell32G_SHGetFolderPathAndSubDirA));
    e("SHGetFolderPathAndSubDirW", reinterpret_cast<void*>(&kshell32G_SHGetFolderPathAndSubDirW));
    e("SHGetIDListFromObject", reinterpret_cast<void*>(&kshell32G_SHGetIDListFromObject));
    e("SHGetIconOverlayIndexA", reinterpret_cast<void*>(&kshell32G_SHGetIconOverlayIndexA));
    e("SHGetIconOverlayIndexW", reinterpret_cast<void*>(&kshell32G_SHGetIconOverlayIndexW));
    e("SHGetImageList", reinterpret_cast<void*>(&kshell32G_SHGetImageList));
    e("SHGetInstanceExplorer", reinterpret_cast<void*>(&kshell32G_SHGetInstanceExplorer));
    e("SHGetItemFromDataObject", reinterpret_cast<void*>(&kshell32G_SHGetItemFromDataObject));
    e("SHGetItemFromObject", reinterpret_cast<void*>(&kshell32G_SHGetItemFromObject));
    e("SHGetKnownFolderIDList", reinterpret_cast<void*>(&kshell32G_SHGetKnownFolderIDList));
    e("SHGetKnownFolderItem", reinterpret_cast<void*>(&kshell32G_SHGetKnownFolderItem));
    e("SHGetKnownFolderPath", reinterpret_cast<void*>(&kshell32G_SHGetKnownFolderPath));
    e("SHGetLocalizedName", reinterpret_cast<void*>(&kshell32G_SHGetLocalizedName));
    e("SHGetMalloc", reinterpret_cast<void*>(&kshell32G_SHGetMalloc));
    e("SHGetNameFromIDList", reinterpret_cast<void*>(&kshell32G_SHGetNameFromIDList));
    e("SHGetNewLinkInfoA", reinterpret_cast<void*>(&kshell32G_SHGetNewLinkInfoA));
    e("SHGetNewLinkInfoW", reinterpret_cast<void*>(&kshell32G_SHGetNewLinkInfoW));
    e("SHGetPathFromIDListA", reinterpret_cast<void*>(&kshell32G_SHGetPathFromIDListA));
    e("SHGetPathFromIDListEx", reinterpret_cast<void*>(&kshell32G_SHGetPathFromIDListEx));
    e("SHGetPathFromIDListW", reinterpret_cast<void*>(&kshell32G_SHGetPathFromIDListW));
    e("SHGetPropertyStoreForWindow", reinterpret_cast<void*>(&kshell32G_SHGetPropertyStoreForWindow));
    e("SHGetPropertyStoreFromIDList", reinterpret_cast<void*>(&kshell32G_SHGetPropertyStoreFromIDList));
    e("SHGetPropertyStoreFromParsingName", reinterpret_cast<void*>(&kshell32G_SHGetPropertyStoreFromParsingName));
    e("SHGetRealIDL", reinterpret_cast<void*>(&kshell32G_SHGetRealIDL));
    e("SHGetSetFolderCustomSettings", reinterpret_cast<void*>(&kshell32G_SHGetSetFolderCustomSettings));
    e("SHGetSetSettings", reinterpret_cast<void*>(&kshell32G_SHGetSetSettings));
    e("SHGetSettings", reinterpret_cast<void*>(&kshell32G_SHGetSettings));
    e("SHGetSpecialFolderLocation", reinterpret_cast<void*>(&kshell32G_SHGetSpecialFolderLocation));
    e("SHGetStockIconInfo", reinterpret_cast<void*>(&kshell32G_SHGetStockIconInfo));
    e("SHGetTemporaryPropertyForItem", reinterpret_cast<void*>(&kshell32G_SHGetTemporaryPropertyForItem));
    e("SHGetUnreadMailCountW", reinterpret_cast<void*>(&kshell32G_SHGetUnreadMailCountW));
    e("SHHandleUpdateImage", reinterpret_cast<void*>(&kshell32G_SHHandleUpdateImage));
    e("SHILCreateFromPath", reinterpret_cast<void*>(&kshell32G_SHILCreateFromPath));
    e("SHInvokePrinterCommandA", reinterpret_cast<void*>(&kshell32G_SHInvokePrinterCommandA));
    e("SHInvokePrinterCommandW", reinterpret_cast<void*>(&kshell32G_SHInvokePrinterCommandW));
    e("SHIsFileAvailableOffline", reinterpret_cast<void*>(&kshell32G_SHIsFileAvailableOffline));
    e("SHLimitInputEdit", reinterpret_cast<void*>(&kshell32G_SHLimitInputEdit));
    e("SHLoadInProc", reinterpret_cast<void*>(&kshell32G_SHLoadInProc));
    e("SHLoadNonloadedIconOverlayIdentifiers", reinterpret_cast<void*>(&kshell32G_SHLoadNonloadedIconOverlayIdentifiers));
    e("SHMapPIDLToSystemImageListIndex", reinterpret_cast<void*>(&kshell32G_SHMapPIDLToSystemImageListIndex));
    e("SHMultiFileProperties", reinterpret_cast<void*>(&kshell32G_SHMultiFileProperties));
    e("SHObjectProperties", reinterpret_cast<void*>(&kshell32G_SHObjectProperties));
    e("SHOpenFolderAndSelectItems", reinterpret_cast<void*>(&kshell32G_SHOpenFolderAndSelectItems));
    e("SHOpenPropSheetW", reinterpret_cast<void*>(&kshell32G_SHOpenPropSheetW));
    e("SHOpenWithDialog", reinterpret_cast<void*>(&kshell32G_SHOpenWithDialog));
    e("SHParseDisplayName", reinterpret_cast<void*>(&kshell32G_SHParseDisplayName));
    e("SHPathPrepareForWriteA", reinterpret_cast<void*>(&kshell32G_SHPathPrepareForWriteA));
    e("SHPathPrepareForWriteW", reinterpret_cast<void*>(&kshell32G_SHPathPrepareForWriteW));
    e("SHPropStgCreate", reinterpret_cast<void*>(&kshell32G_SHPropStgCreate));
    e("SHPropStgReadMultiple", reinterpret_cast<void*>(&kshell32G_SHPropStgReadMultiple));
    e("SHPropStgWriteMultiple", reinterpret_cast<void*>(&kshell32G_SHPropStgWriteMultiple));
    e("SHQueryRecycleBinA", reinterpret_cast<void*>(&kshell32G_SHQueryRecycleBinA));
    e("SHQueryRecycleBinW", reinterpret_cast<void*>(&kshell32G_SHQueryRecycleBinW));
    e("SHQueryUserNotificationState", reinterpret_cast<void*>(&kshell32G_SHQueryUserNotificationState));
    e("SHRemoveLocalizedName", reinterpret_cast<void*>(&kshell32G_SHRemoveLocalizedName));
    e("SHReplaceFromPropSheetExtArray", reinterpret_cast<void*>(&kshell32G_SHReplaceFromPropSheetExtArray));
    e("SHResolveLibrary", reinterpret_cast<void*>(&kshell32G_SHResolveLibrary));
    e("SHRestricted", reinterpret_cast<void*>(&kshell32G_SHRestricted));
    e("SHRunControlPanel", reinterpret_cast<void*>(&kshell32G_SHRunControlPanel));
    e("SHSetDefaultProperties", reinterpret_cast<void*>(&kshell32G_SHSetDefaultProperties));
    e("SHSetFolderPathA", reinterpret_cast<void*>(&kshell32G_SHSetFolderPathA));
    e("SHSetFolderPathW", reinterpret_cast<void*>(&kshell32G_SHSetFolderPathW));
    e("SHSetInstanceExplorer", reinterpret_cast<void*>(&kshell32G_SHSetInstanceExplorer));
    e("SHSetKnownFolderPath", reinterpret_cast<void*>(&kshell32G_SHSetKnownFolderPath));
    e("SHSetLocalizedName", reinterpret_cast<void*>(&kshell32G_SHSetLocalizedName));
    e("SHSetTemporaryPropertyForItem", reinterpret_cast<void*>(&kshell32G_SHSetTemporaryPropertyForItem));
    e("SHSetUnreadMailCountW", reinterpret_cast<void*>(&kshell32G_SHSetUnreadMailCountW));
    e("SHShellFolderView_Message", reinterpret_cast<void*>(&kshell32G_SHShellFolderView_Message));
    e("SHShowManageLibraryUI", reinterpret_cast<void*>(&kshell32G_SHShowManageLibraryUI));
    e("SHSimpleIDListFromPath", reinterpret_cast<void*>(&kshell32G_SHSimpleIDListFromPath));
    e("SHStartNetConnectionDialogW", reinterpret_cast<void*>(&kshell32G_SHStartNetConnectionDialogW));
    e("SHTestTokenMembership", reinterpret_cast<void*>(&kshell32G_SHTestTokenMembership));
    e("SHUpdateImageA", reinterpret_cast<void*>(&kshell32G_SHUpdateImageA));
    e("SHUpdateImageW", reinterpret_cast<void*>(&kshell32G_SHUpdateImageW));
    e("SHValidateUNC", reinterpret_cast<void*>(&kshell32G_SHValidateUNC));
    e("SetCurrentProcessExplicitAppUserModelID", reinterpret_cast<void*>(&kshell32G_SetCurrentProcessExplicitAppUserModelID));
    e("ShellAboutA", reinterpret_cast<void*>(&kshell32G_ShellAboutA));
    e("ShellAboutW", reinterpret_cast<void*>(&kshell32G_ShellAboutW));
    e("ShellExecuteExA", reinterpret_cast<void*>(&kshell32G_ShellExecuteExA));
    e("ShellExecuteExW", reinterpret_cast<void*>(&kshell32G_ShellExecuteExW));
    e("ShellMessageBoxA", reinterpret_cast<void*>(&kshell32G_ShellMessageBoxA));
    e("ShellMessageBoxW", reinterpret_cast<void*>(&kshell32G_ShellMessageBoxW));
    e("Shell_GetCachedImageIndex", reinterpret_cast<void*>(&kshell32G_Shell_GetCachedImageIndex));
    e("Shell_GetCachedImageIndexA", reinterpret_cast<void*>(&kshell32G_Shell_GetCachedImageIndexA));
    e("Shell_GetCachedImageIndexW", reinterpret_cast<void*>(&kshell32G_Shell_GetCachedImageIndexW));
    e("Shell_GetImageLists", reinterpret_cast<void*>(&kshell32G_Shell_GetImageLists));
    e("Shell_MergeMenus", reinterpret_cast<void*>(&kshell32G_Shell_MergeMenus));
    e("Shell_NotifyIconA", reinterpret_cast<void*>(&kshell32G_Shell_NotifyIconA));
    e("Shell_NotifyIconGetRect", reinterpret_cast<void*>(&kshell32G_Shell_NotifyIconGetRect));
    e("Shell_NotifyIconW", reinterpret_cast<void*>(&kshell32G_Shell_NotifyIconW));
    e("SignalFileOpen", reinterpret_cast<void*>(&kshell32G_SignalFileOpen));
    e("StgMakeUniqueName", reinterpret_cast<void*>(&kshell32G_StgMakeUniqueName));
    e("Win32DeleteFile", reinterpret_cast<void*>(&kshell32G_Win32DeleteFile));
    e("WriteCabinetState", reinterpret_cast<void*>(&kshell32G_WriteCabinetState));
}
}  // namespace occ::runtime::winabi

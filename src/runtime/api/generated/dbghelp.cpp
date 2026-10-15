// The DBGHELP surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_DbgHelpCreateUserDump(const char* FileName, std::uint64_t Callback, void* UserData) noexcept {
    // Refused: the symbol handler.
    //
    // symbols come from a symbol store reached over the network or from debug
    // information this runtime does not parse; a symbol handler that answered
    // with invented names is worse than one that declines
    static_cast<void>(FileName);
    static_cast<void>(Callback);
    static_cast<void>(UserData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_DbgHelpCreateUserDumpW(const char16_t* FileName, std::uint64_t Callback, void* UserData) noexcept {
    // Refused: the symbol handler.
    //
    // symbols come from a symbol store reached over the network or from debug
    // information this runtime does not parse; a symbol handler that answered
    // with invented names is worse than one that declines
    static_cast<void>(FileName);
    static_cast<void>(Callback);
    static_cast<void>(UserData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_EnumDirTree(void* hProcess, char* RootPath, char* InputPathName, char* OutputPathBuffer, std::uint64_t Callback, void* CallbackData) noexcept {
    // Refused: the symbol handler.
    //
    // symbols come from a symbol store reached over the network or from debug
    // information this runtime does not parse; a symbol handler that answered
    // with invented names is worse than one that declines
    static_cast<void>(hProcess);
    static_cast<void>(RootPath);
    static_cast<void>(InputPathName);
    static_cast<void>(OutputPathBuffer);
    static_cast<void>(Callback);
    static_cast<void>(CallbackData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_EnumerateLoadedModulesEx(void* hProcess, std::uint64_t EnumLoadedModulesCallback, void* UserContext) noexcept {
    // Refused: the symbol handler.
    //
    // symbols come from a symbol store reached over the network or from debug
    // information this runtime does not parse; a symbol handler that answered
    // with invented names is worse than one that declines
    static_cast<void>(hProcess);
    static_cast<void>(EnumLoadedModulesCallback);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_EnumerateLoadedModulesExW(void* hProcess, std::uint64_t EnumLoadedModulesCallback, void* UserContext) noexcept {
    // Refused: the symbol handler.
    //
    // symbols come from a symbol store reached over the network or from debug
    // information this runtime does not parse; a symbol handler that answered
    // with invented names is worse than one that declines
    static_cast<void>(hProcess);
    static_cast<void>(EnumLoadedModulesCallback);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_EnumerateLoadedModulesW64(void* hProcess, std::uint64_t EnumLoadedModulesCallback, void* UserContext) noexcept {
    // Refused: the symbol handler.
    //
    // symbols come from a symbol store reached over the network or from debug
    // information this runtime does not parse; a symbol handler that answered
    // with invented names is worse than one that declines
    static_cast<void>(hProcess);
    static_cast<void>(EnumLoadedModulesCallback);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kdbghelpG_FindDebugInfoFile(const char* FileName, const char* SymbolPath, char* DebugFilePath) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(FileName);
    static_cast<void>(SymbolPath);
    static_cast<void>(DebugFilePath);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kdbghelpG_FindDebugInfoFileEx(const char* FileName, const char* SymbolPath, char* DebugFilePath, std::uint64_t Callback, void* CallerData) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(FileName);
    static_cast<void>(SymbolPath);
    static_cast<void>(DebugFilePath);
    static_cast<void>(Callback);
    static_cast<void>(CallerData);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kdbghelpG_FindDebugInfoFileExW(const char16_t* FileName, const char16_t* SymbolPath, char16_t* DebugFilePath, std::uint64_t Callback, void* CallerData) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(FileName);
    static_cast<void>(SymbolPath);
    static_cast<void>(DebugFilePath);
    static_cast<void>(Callback);
    static_cast<void>(CallerData);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kdbghelpG_FindExecutableImage(const char* FileName, const char* SymbolPath, char* ImageFilePath) noexcept {
    // Refused: the symbol handler.
    //
    // symbols come from a symbol store reached over the network or from debug
    // information this runtime does not parse; a symbol handler that answered
    // with invented names is worse than one that declines
    static_cast<void>(FileName);
    static_cast<void>(SymbolPath);
    static_cast<void>(ImageFilePath);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kdbghelpG_FindExecutableImageEx(const char* FileName, const char* SymbolPath, char* ImageFilePath, std::uint64_t Callback, void* CallerData) noexcept {
    // Refused: the symbol handler.
    //
    // symbols come from a symbol store reached over the network or from debug
    // information this runtime does not parse; a symbol handler that answered
    // with invented names is worse than one that declines
    static_cast<void>(FileName);
    static_cast<void>(SymbolPath);
    static_cast<void>(ImageFilePath);
    static_cast<void>(Callback);
    static_cast<void>(CallerData);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kdbghelpG_FindExecutableImageExW(const char16_t* FileName, const char16_t* SymbolPath, char16_t* ImageFilePath, std::uint64_t Callback, void* CallerData) noexcept {
    // Refused: the symbol handler.
    //
    // symbols come from a symbol store reached over the network or from debug
    // information this runtime does not parse; a symbol handler that answered
    // with invented names is worse than one that declines
    static_cast<void>(FileName);
    static_cast<void>(SymbolPath);
    static_cast<void>(ImageFilePath);
    static_cast<void>(Callback);
    static_cast<void>(CallerData);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_FindFileInPath(void* hprocess, const char* SearchPath, const char* FileName, void* id, std::uint32_t two, std::uint32_t three, std::uint32_t flags, char* FilePath) noexcept {
    // Refused: the symbol handler.
    //
    // symbols come from a symbol store reached over the network or from debug
    // information this runtime does not parse; a symbol handler that answered
    // with invented names is worse than one that declines
    static_cast<void>(hprocess);
    static_cast<void>(SearchPath);
    static_cast<void>(FileName);
    static_cast<void>(id);
    static_cast<void>(two);
    static_cast<void>(three);
    static_cast<void>(flags);
    static_cast<void>(FilePath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_FindFileInSearchPath(void* hprocess, const char* SearchPath, const char* FileName, std::uint32_t one, std::uint32_t two, std::uint32_t three, char* FilePath) noexcept {
    // Refused: the symbol handler.
    //
    // symbols come from a symbol store reached over the network or from debug
    // information this runtime does not parse; a symbol handler that answered
    // with invented names is worse than one that declines
    static_cast<void>(hprocess);
    static_cast<void>(SearchPath);
    static_cast<void>(FileName);
    static_cast<void>(one);
    static_cast<void>(two);
    static_cast<void>(three);
    static_cast<void>(FilePath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymAddSourceStream(void* hProcess, std::uint64_t Base, const char* StreamFile, std::uint8_t* Buffer, std::uint64_t Size) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Base);
    static_cast<void>(StreamFile);
    static_cast<void>(Buffer);
    static_cast<void>(Size);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymAddSourceStreamW(void* hProcess, std::uint64_t Base, const char16_t* StreamFile, std::uint8_t* Buffer, std::uint64_t Size) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Base);
    static_cast<void>(StreamFile);
    static_cast<void>(Buffer);
    static_cast<void>(Size);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymAddSymbol(void* hProcess, std::uint64_t BaseOfDll, const char* Name, std::uint64_t Address, std::uint32_t Size, std::uint32_t Flags) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(BaseOfDll);
    static_cast<void>(Name);
    static_cast<void>(Address);
    static_cast<void>(Size);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymAddSymbolW(void* hProcess, std::uint64_t BaseOfDll, const char16_t* Name, std::uint64_t Address, std::uint32_t Size, std::uint32_t Flags) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(BaseOfDll);
    static_cast<void>(Name);
    static_cast<void>(Address);
    static_cast<void>(Size);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymDeleteSymbol(void* hProcess, std::uint64_t BaseOfDll, const char* Name, std::uint64_t Address, std::uint32_t Flags) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(BaseOfDll);
    static_cast<void>(Name);
    static_cast<void>(Address);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymDeleteSymbolW(void* hProcess, std::uint64_t BaseOfDll, const char16_t* Name, std::uint64_t Address, std::uint32_t Flags) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(BaseOfDll);
    static_cast<void>(Name);
    static_cast<void>(Address);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymEnumLines(void* hProcess, std::uint64_t Base, const char* Obj, const char* File, std::uint64_t EnumLinesCallback, void* UserContext) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Base);
    static_cast<void>(Obj);
    static_cast<void>(File);
    static_cast<void>(EnumLinesCallback);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymEnumLinesW(void* hProcess, std::uint64_t Base, const char16_t* Obj, const char* File, std::uint64_t EnumLinesCallback, void* UserContext) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Base);
    static_cast<void>(Obj);
    static_cast<void>(File);
    static_cast<void>(EnumLinesCallback);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymEnumSourceFiles(void* hProcess, std::uint64_t ModBase, const char* Mask, std::uint64_t cbSrcFiles, void* UserContext) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(ModBase);
    static_cast<void>(Mask);
    static_cast<void>(cbSrcFiles);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymEnumSourceFilesW(void* hProcess, std::uint64_t ModBase, const char16_t* Mask, std::uint64_t cbSrcFiles, void* UserContext) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(ModBase);
    static_cast<void>(Mask);
    static_cast<void>(cbSrcFiles);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymEnumSourceLines(void* hProcess, std::uint64_t Base, const char* Obj, const char* File, std::uint32_t Line, std::uint32_t Flags, std::uint64_t EnumLinesCallback, void* UserContext) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Base);
    static_cast<void>(Obj);
    static_cast<void>(File);
    static_cast<void>(Line);
    static_cast<void>(Flags);
    static_cast<void>(EnumLinesCallback);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymEnumSourceLinesW(void* hProcess, std::uint64_t Base, const char16_t* Obj, const char16_t* File, std::uint32_t Line, std::uint32_t Flags, std::uint64_t EnumLinesCallback, void* UserContext) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Base);
    static_cast<void>(Obj);
    static_cast<void>(File);
    static_cast<void>(Line);
    static_cast<void>(Flags);
    static_cast<void>(EnumLinesCallback);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymEnumSym(void* hProcess, std::uint64_t BaseOfDll, void* EnumSymbolsCallback, void* UserContext) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(BaseOfDll);
    static_cast<void>(EnumSymbolsCallback);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymEnumSymbolsForAddr(void* hProcess, std::uint64_t Address, void* EnumSymbolsCallback, void* UserContext) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Address);
    static_cast<void>(EnumSymbolsCallback);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymEnumSymbolsForAddrW(void* hProcess, std::uint64_t Address, std::uint64_t EnumSymbolsCallback, void* UserContext) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Address);
    static_cast<void>(EnumSymbolsCallback);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymEnumTypes(void* hProcess, std::uint64_t BaseOfDll, void* EnumSymbolsCallback, void* UserContext) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(BaseOfDll);
    static_cast<void>(EnumSymbolsCallback);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymEnumTypesByName(void* hProcess, std::uint64_t BaseOfDll, const char* mask, void* EnumSymbolsCallback, void* UserContext) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(BaseOfDll);
    static_cast<void>(mask);
    static_cast<void>(EnumSymbolsCallback);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymEnumTypesByNameW(void* hProcess, std::uint64_t BaseOfDll, const char* mask, std::uint64_t EnumSymbolsCallback, void* UserContext) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(BaseOfDll);
    static_cast<void>(mask);
    static_cast<void>(EnumSymbolsCallback);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymEnumTypesW(void* hProcess, std::uint64_t BaseOfDll, std::uint64_t EnumSymbolsCallback, void* UserContext) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(BaseOfDll);
    static_cast<void>(EnumSymbolsCallback);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymEnumerateModulesW64(void* hProcess, std::uint64_t EnumModulesCallback, void* UserContext) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(EnumModulesCallback);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymEnumerateSymbols64(void* hProcess, std::uint64_t BaseOfDll, std::uint64_t EnumSymbolsCallback, void* UserContext) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(BaseOfDll);
    static_cast<void>(EnumSymbolsCallback);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymEnumerateSymbolsW64(void* hProcess, std::uint64_t BaseOfDll, std::uint64_t EnumSymbolsCallback, void* UserContext) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(BaseOfDll);
    static_cast<void>(EnumSymbolsCallback);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kdbghelpG_SymFindDebugInfoFile(void* hProcess, const char* FileName, char* DebugFilePath, std::uint64_t Callback, void* CallerData) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(FileName);
    static_cast<void>(DebugFilePath);
    static_cast<void>(Callback);
    static_cast<void>(CallerData);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kdbghelpG_SymFindDebugInfoFileW(void* hProcess, const char16_t* FileName, char16_t* DebugFilePath, std::uint64_t Callback, void* CallerData) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(FileName);
    static_cast<void>(DebugFilePath);
    static_cast<void>(Callback);
    static_cast<void>(CallerData);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kdbghelpG_SymFindExecutableImage(void* hProcess, const char* FileName, char* ImageFilePath, std::uint64_t Callback, void* CallerData) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(FileName);
    static_cast<void>(ImageFilePath);
    static_cast<void>(Callback);
    static_cast<void>(CallerData);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kdbghelpG_SymFindExecutableImageW(void* hProcess, const char16_t* FileName, char16_t* ImageFilePath, std::uint64_t Callback, void* CallerData) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(FileName);
    static_cast<void>(ImageFilePath);
    static_cast<void>(Callback);
    static_cast<void>(CallerData);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymFindFileInPath(void* hprocess, const char* SearchPath, const char* FileName, void* id, std::uint32_t two, std::uint32_t three, std::uint32_t flags, char* FoundFile, std::uint64_t callback, void* context) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hprocess);
    static_cast<void>(SearchPath);
    static_cast<void>(FileName);
    static_cast<void>(id);
    static_cast<void>(two);
    static_cast<void>(three);
    static_cast<void>(flags);
    static_cast<void>(FoundFile);
    static_cast<void>(callback);
    static_cast<void>(context);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymFindFileInPathW(void* hprocess, const char16_t* SearchPath, const char16_t* FileName, void* id, std::uint32_t two, std::uint32_t three, std::uint32_t flags, char* FoundFile, std::uint64_t callback, void* context) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hprocess);
    static_cast<void>(SearchPath);
    static_cast<void>(FileName);
    static_cast<void>(id);
    static_cast<void>(two);
    static_cast<void>(three);
    static_cast<void>(flags);
    static_cast<void>(FoundFile);
    static_cast<void>(callback);
    static_cast<void>(context);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymFromIndex(void* hProcess, std::uint64_t BaseOfDll, std::uint32_t Index, void* Symbol) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(BaseOfDll);
    static_cast<void>(Index);
    static_cast<void>(Symbol);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymFromIndexW(void* hProcess, std::uint64_t BaseOfDll, std::uint32_t Index, void* Symbol) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(BaseOfDll);
    static_cast<void>(Index);
    static_cast<void>(Symbol);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymFromName(void* hProcess, const char* Name, void* Symbol) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Name);
    static_cast<void>(Symbol);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymFromNameW(void* hProcess, const char16_t* Name, void* Symbol) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Name);
    static_cast<void>(Symbol);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymFromToken(void* hProcess, std::uint64_t Base, std::uint32_t Token, void* Symbol) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(hProcess);
    static_cast<void>(Base);
    static_cast<void>(Token);
    static_cast<void>(Symbol);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymFromTokenW(void* hProcess, std::uint64_t Base, std::uint32_t Token, void* Symbol) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(hProcess);
    static_cast<void>(Base);
    static_cast<void>(Token);
    static_cast<void>(Symbol);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kdbghelpG_SymFunctionTableAccess64(void* hProcess, std::uint64_t AddrBase) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(AddrBase);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char16_t* kdbghelpG_SymGetHomeDirectoryW(std::uint32_t type, char16_t* dir, std::uint64_t size) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(type);
    static_cast<void>(dir);
    static_cast<void>(size);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetLineFromName64(void* hProcess, const char* ModuleName, const char* FileName, std::uint32_t dwLineNumber, std::int32_t* plDisplacement, std::uint64_t Line) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(ModuleName);
    static_cast<void>(FileName);
    static_cast<void>(dwLineNumber);
    static_cast<void>(plDisplacement);
    static_cast<void>(Line);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetLineFromNameW64(void* hProcess, const char16_t* ModuleName, const char16_t* FileName, std::uint32_t dwLineNumber, std::int32_t* plDisplacement, std::uint64_t Line) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(ModuleName);
    static_cast<void>(FileName);
    static_cast<void>(dwLineNumber);
    static_cast<void>(plDisplacement);
    static_cast<void>(Line);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetLineNext64(void* hProcess, std::uint64_t Line) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Line);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetLineNextW64(void* hProcess, std::uint64_t Line) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Line);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetLinePrev64(void* hProcess, std::uint64_t Line) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Line);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetLinePrevW64(void* hProcess, std::uint64_t Line) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Line);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetScope(void* hProcess, std::uint64_t BaseOfDll, std::uint32_t Index, void* Symbol) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(BaseOfDll);
    static_cast<void>(Index);
    static_cast<void>(Symbol);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetScopeW(void* hProcess, std::uint64_t BaseOfDll, std::uint32_t Index, void* Symbol) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(BaseOfDll);
    static_cast<void>(Index);
    static_cast<void>(Symbol);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetSourceFile(void* hProcess, std::uint64_t Base, const char* Params, const char* FileSpec, char* FilePath, std::uint32_t Size) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Base);
    static_cast<void>(Params);
    static_cast<void>(FileSpec);
    static_cast<void>(FilePath);
    static_cast<void>(Size);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetSourceFileFromToken(void* hProcess, void* Token, const char* Params, char* FilePath, std::uint32_t Size) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(hProcess);
    static_cast<void>(Token);
    static_cast<void>(Params);
    static_cast<void>(FilePath);
    static_cast<void>(Size);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetSourceFileFromTokenW(void* hProcess, void* Token, const char16_t* Params, char16_t* FilePath, std::uint32_t Size) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(hProcess);
    static_cast<void>(Token);
    static_cast<void>(Params);
    static_cast<void>(FilePath);
    static_cast<void>(Size);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetSourceFileToken(void* hProcess, std::uint64_t Base, const char* FileSpec, void** Token, std::uint32_t* Size) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(hProcess);
    static_cast<void>(Base);
    static_cast<void>(FileSpec);
    static_cast<void>(Token);
    static_cast<void>(Size);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetSourceFileTokenW(void* hProcess, std::uint64_t Base, const char16_t* FileSpec, void** Token, std::uint32_t* Size) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(hProcess);
    static_cast<void>(Base);
    static_cast<void>(FileSpec);
    static_cast<void>(Token);
    static_cast<void>(Size);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetSourceFileW(void* hProcess, std::uint64_t Base, const char16_t* Params, const char16_t* FileSpec, char16_t* FilePath, std::uint32_t Size) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Base);
    static_cast<void>(Params);
    static_cast<void>(FileSpec);
    static_cast<void>(FilePath);
    static_cast<void>(Size);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetSourceVarFromToken(void* hProcess, void* Token, const char* Params, const char* VarName, char* Value, std::uint32_t Size) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(hProcess);
    static_cast<void>(Token);
    static_cast<void>(Params);
    static_cast<void>(VarName);
    static_cast<void>(Value);
    static_cast<void>(Size);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetSourceVarFromTokenW(void* hProcess, void* Token, const char16_t* Params, const char16_t* VarName, char16_t* Value, std::uint32_t Size) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(hProcess);
    static_cast<void>(Token);
    static_cast<void>(Params);
    static_cast<void>(VarName);
    static_cast<void>(Value);
    static_cast<void>(Size);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetSymFromName64(void* hProcess, const char* Name, std::uint64_t Symbol) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Name);
    static_cast<void>(Symbol);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetSymNext64(void* hProcess, std::uint64_t Symbol) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Symbol);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetSymPrev64(void* hProcess, std::uint64_t Symbol) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Symbol);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetSymbolFile(void* hProcess, const char* SymPath, const char* ImageFile, std::uint32_t Type, char* SymbolFile, std::uint64_t cSymbolFile, char* DbgFile, std::uint64_t cDbgFile) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(SymPath);
    static_cast<void>(ImageFile);
    static_cast<void>(Type);
    static_cast<void>(SymbolFile);
    static_cast<void>(cSymbolFile);
    static_cast<void>(DbgFile);
    static_cast<void>(cDbgFile);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetSymbolFileW(void* hProcess, const char16_t* SymPath, const char16_t* ImageFile, std::uint32_t Type, char16_t* SymbolFile, std::uint64_t cSymbolFile, char16_t* DbgFile, std::uint64_t cDbgFile) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(SymPath);
    static_cast<void>(ImageFile);
    static_cast<void>(Type);
    static_cast<void>(SymbolFile);
    static_cast<void>(cSymbolFile);
    static_cast<void>(DbgFile);
    static_cast<void>(cDbgFile);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetTypeFromName(void* hProcess, std::uint64_t BaseOfDll, const char* Name, void* Symbol) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(BaseOfDll);
    static_cast<void>(Name);
    static_cast<void>(Symbol);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymGetTypeFromNameW(void* hProcess, std::uint64_t BaseOfDll, const char16_t* Name, void* Symbol) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(BaseOfDll);
    static_cast<void>(Name);
    static_cast<void>(Symbol);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymMatchFileName(const char* FileName, const char* Match, char** FileNameStop, char** MatchStop) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(FileName);
    static_cast<void>(Match);
    static_cast<void>(FileNameStop);
    static_cast<void>(MatchStop);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymMatchFileNameW(const char16_t* FileName, const char16_t* Match, char16_t** FileNameStop, char16_t** MatchStop) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(FileName);
    static_cast<void>(Match);
    static_cast<void>(FileNameStop);
    static_cast<void>(MatchStop);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymMatchString(const char* string, const char* expression, std::int32_t fCase) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(string);
    static_cast<void>(expression);
    static_cast<void>(fCase);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymMatchStringW(const char16_t* string, const char16_t* expression, std::int32_t fCase) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(string);
    static_cast<void>(expression);
    static_cast<void>(fCase);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymNext(void* hProcess, void* Symbol) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Symbol);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymNextW(void* hProcess, void* Symbol) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Symbol);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymPrev(void* hProcess, void* Symbol) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Symbol);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymPrevW(void* hProcess, void* Symbol) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(Symbol);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymRefreshModuleList(void* hProcess) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymRegisterFunctionEntryCallback64(void* hProcess, std::uint64_t CallbackFunction, std::uint64_t UserContext) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(CallbackFunction);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymSearch(void* hProcess, std::uint64_t BaseOfDll, std::uint32_t Index, std::uint32_t SymTag, const char* Mask, std::uint64_t Address, void* EnumSymbolsCallback, void* UserContext, std::uint32_t Options) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(BaseOfDll);
    static_cast<void>(Index);
    static_cast<void>(SymTag);
    static_cast<void>(Mask);
    static_cast<void>(Address);
    static_cast<void>(EnumSymbolsCallback);
    static_cast<void>(UserContext);
    static_cast<void>(Options);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymSearchW(void* hProcess, std::uint64_t BaseOfDll, std::uint32_t Index, std::uint32_t SymTag, const char16_t* Mask, std::uint64_t Address, std::uint64_t EnumSymbolsCallback, void* UserContext, std::uint32_t Options) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(BaseOfDll);
    static_cast<void>(Index);
    static_cast<void>(SymTag);
    static_cast<void>(Mask);
    static_cast<void>(Address);
    static_cast<void>(EnumSymbolsCallback);
    static_cast<void>(UserContext);
    static_cast<void>(Options);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) char* kdbghelpG_SymSetHomeDirectory(void* hProcess, const char* dir) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(dir);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char* kdbghelpG_SymSetHomeDirectoryW(void* hProcess, const char16_t* dir) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(dir);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymSetParentWindow(void* hwnd) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hwnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) const char* kdbghelpG_SymSrvDeltaName(void* hProcess, const char* SymPath, const char* Type, const char* File1, const char* File2) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(SymPath);
    static_cast<void>(Type);
    static_cast<void>(File1);
    static_cast<void>(File2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) const char16_t* kdbghelpG_SymSrvDeltaNameW(void* hProcess, const char16_t* SymPath, const char16_t* Type, const char16_t* File1, const char16_t* File2) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(SymPath);
    static_cast<void>(Type);
    static_cast<void>(File1);
    static_cast<void>(File2);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymSrvGetFileIndexInfo(const char* File, std::uint64_t Info, std::uint32_t Flags) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(File);
    static_cast<void>(Info);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymSrvGetFileIndexInfoW(const char16_t* File, std::uint64_t Info, std::uint32_t Flags) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(File);
    static_cast<void>(Info);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymSrvGetFileIndexString(void* hProcess, const char* SrvPath, const char* File, char* Index, std::uint64_t Size, std::uint32_t Flags) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(SrvPath);
    static_cast<void>(File);
    static_cast<void>(Index);
    static_cast<void>(Size);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymSrvGetFileIndexStringW(void* hProcess, const char16_t* SrvPath, const char16_t* File, char16_t* Index, std::uint64_t Size, std::uint32_t Flags) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(SrvPath);
    static_cast<void>(File);
    static_cast<void>(Index);
    static_cast<void>(Size);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymSrvGetFileIndexes(std::uint64_t File, void* Id, std::uint32_t* Val1, std::uint32_t* Val2, std::uint32_t Flags) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(File);
    static_cast<void>(Id);
    static_cast<void>(Val1);
    static_cast<void>(Val2);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymSrvGetFileIndexesW(const char16_t* File, void* Id, std::uint32_t* Val1, std::uint32_t* Val2, std::uint32_t Flags) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(File);
    static_cast<void>(Id);
    static_cast<void>(Val1);
    static_cast<void>(Val2);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) const char* kdbghelpG_SymSrvGetSupplement(void* hProcess, const char* SymPath, const char* Node, const char* File) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(SymPath);
    static_cast<void>(Node);
    static_cast<void>(File);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) const char16_t* kdbghelpG_SymSrvGetSupplementW(void* hProcess, const char16_t* SymPath, const char16_t* Node, const char16_t* File) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(SymPath);
    static_cast<void>(Node);
    static_cast<void>(File);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymSrvIsStore(void* hProcess, const char* path) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(path);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymSrvIsStoreW(void* hProcess, const char16_t* path) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(path);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) const char* kdbghelpG_SymSrvStoreFile(void* hProcess, const char* SrvPath, const char* File, std::uint32_t Flags) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(SrvPath);
    static_cast<void>(File);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) const char16_t* kdbghelpG_SymSrvStoreFileW(void* hProcess, const char16_t* SrvPath, const char16_t* File, std::uint32_t Flags) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(SrvPath);
    static_cast<void>(File);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) const char* kdbghelpG_SymSrvStoreSupplement(void* hProcess, std::uint64_t SymPath, const char* Node, const char* File, std::uint32_t Flags) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(SymPath);
    static_cast<void>(Node);
    static_cast<void>(File);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) const char16_t* kdbghelpG_SymSrvStoreSupplementW(void* hProcess, const char16_t* SymPath, const char16_t* Node, const char16_t* File, std::uint32_t Flags) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(hProcess);
    static_cast<void>(SymPath);
    static_cast<void>(Node);
    static_cast<void>(File);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdbghelpG_SymUnDName64(std::uint64_t sym, char* UnDecName, std::uint32_t UnDecNameLength) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(sym);
    static_cast<void>(UnDecName);
    static_cast<void>(UnDecNameLength);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_dbghelp(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("DbgHelpCreateUserDump", reinterpret_cast<void*>(&kdbghelpG_DbgHelpCreateUserDump));
    e("DbgHelpCreateUserDumpW", reinterpret_cast<void*>(&kdbghelpG_DbgHelpCreateUserDumpW));
    e("EnumDirTree", reinterpret_cast<void*>(&kdbghelpG_EnumDirTree));
    e("EnumerateLoadedModulesEx", reinterpret_cast<void*>(&kdbghelpG_EnumerateLoadedModulesEx));
    e("EnumerateLoadedModulesExW", reinterpret_cast<void*>(&kdbghelpG_EnumerateLoadedModulesExW));
    e("EnumerateLoadedModulesW64", reinterpret_cast<void*>(&kdbghelpG_EnumerateLoadedModulesW64));
    e("FindDebugInfoFile", reinterpret_cast<void*>(&kdbghelpG_FindDebugInfoFile));
    e("FindDebugInfoFileEx", reinterpret_cast<void*>(&kdbghelpG_FindDebugInfoFileEx));
    e("FindDebugInfoFileExW", reinterpret_cast<void*>(&kdbghelpG_FindDebugInfoFileExW));
    e("FindExecutableImage", reinterpret_cast<void*>(&kdbghelpG_FindExecutableImage));
    e("FindExecutableImageEx", reinterpret_cast<void*>(&kdbghelpG_FindExecutableImageEx));
    e("FindExecutableImageExW", reinterpret_cast<void*>(&kdbghelpG_FindExecutableImageExW));
    e("FindFileInPath", reinterpret_cast<void*>(&kdbghelpG_FindFileInPath));
    e("FindFileInSearchPath", reinterpret_cast<void*>(&kdbghelpG_FindFileInSearchPath));
    e("SymAddSourceStream", reinterpret_cast<void*>(&kdbghelpG_SymAddSourceStream));
    e("SymAddSourceStreamW", reinterpret_cast<void*>(&kdbghelpG_SymAddSourceStreamW));
    e("SymAddSymbol", reinterpret_cast<void*>(&kdbghelpG_SymAddSymbol));
    e("SymAddSymbolW", reinterpret_cast<void*>(&kdbghelpG_SymAddSymbolW));
    e("SymDeleteSymbol", reinterpret_cast<void*>(&kdbghelpG_SymDeleteSymbol));
    e("SymDeleteSymbolW", reinterpret_cast<void*>(&kdbghelpG_SymDeleteSymbolW));
    e("SymEnumLines", reinterpret_cast<void*>(&kdbghelpG_SymEnumLines));
    e("SymEnumLinesW", reinterpret_cast<void*>(&kdbghelpG_SymEnumLinesW));
    e("SymEnumSourceFiles", reinterpret_cast<void*>(&kdbghelpG_SymEnumSourceFiles));
    e("SymEnumSourceFilesW", reinterpret_cast<void*>(&kdbghelpG_SymEnumSourceFilesW));
    e("SymEnumSourceLines", reinterpret_cast<void*>(&kdbghelpG_SymEnumSourceLines));
    e("SymEnumSourceLinesW", reinterpret_cast<void*>(&kdbghelpG_SymEnumSourceLinesW));
    e("SymEnumSym", reinterpret_cast<void*>(&kdbghelpG_SymEnumSym));
    e("SymEnumSymbolsForAddr", reinterpret_cast<void*>(&kdbghelpG_SymEnumSymbolsForAddr));
    e("SymEnumSymbolsForAddrW", reinterpret_cast<void*>(&kdbghelpG_SymEnumSymbolsForAddrW));
    e("SymEnumTypes", reinterpret_cast<void*>(&kdbghelpG_SymEnumTypes));
    e("SymEnumTypesByName", reinterpret_cast<void*>(&kdbghelpG_SymEnumTypesByName));
    e("SymEnumTypesByNameW", reinterpret_cast<void*>(&kdbghelpG_SymEnumTypesByNameW));
    e("SymEnumTypesW", reinterpret_cast<void*>(&kdbghelpG_SymEnumTypesW));
    e("SymEnumerateModulesW64", reinterpret_cast<void*>(&kdbghelpG_SymEnumerateModulesW64));
    e("SymEnumerateSymbols64", reinterpret_cast<void*>(&kdbghelpG_SymEnumerateSymbols64));
    e("SymEnumerateSymbolsW64", reinterpret_cast<void*>(&kdbghelpG_SymEnumerateSymbolsW64));
    e("SymFindDebugInfoFile", reinterpret_cast<void*>(&kdbghelpG_SymFindDebugInfoFile));
    e("SymFindDebugInfoFileW", reinterpret_cast<void*>(&kdbghelpG_SymFindDebugInfoFileW));
    e("SymFindExecutableImage", reinterpret_cast<void*>(&kdbghelpG_SymFindExecutableImage));
    e("SymFindExecutableImageW", reinterpret_cast<void*>(&kdbghelpG_SymFindExecutableImageW));
    e("SymFindFileInPath", reinterpret_cast<void*>(&kdbghelpG_SymFindFileInPath));
    e("SymFindFileInPathW", reinterpret_cast<void*>(&kdbghelpG_SymFindFileInPathW));
    e("SymFromIndex", reinterpret_cast<void*>(&kdbghelpG_SymFromIndex));
    e("SymFromIndexW", reinterpret_cast<void*>(&kdbghelpG_SymFromIndexW));
    e("SymFromName", reinterpret_cast<void*>(&kdbghelpG_SymFromName));
    e("SymFromNameW", reinterpret_cast<void*>(&kdbghelpG_SymFromNameW));
    e("SymFromToken", reinterpret_cast<void*>(&kdbghelpG_SymFromToken));
    e("SymFromTokenW", reinterpret_cast<void*>(&kdbghelpG_SymFromTokenW));
    e("SymFunctionTableAccess64", reinterpret_cast<void*>(&kdbghelpG_SymFunctionTableAccess64));
    e("SymGetHomeDirectoryW", reinterpret_cast<void*>(&kdbghelpG_SymGetHomeDirectoryW));
    e("SymGetLineFromName64", reinterpret_cast<void*>(&kdbghelpG_SymGetLineFromName64));
    e("SymGetLineFromNameW64", reinterpret_cast<void*>(&kdbghelpG_SymGetLineFromNameW64));
    e("SymGetLineNext64", reinterpret_cast<void*>(&kdbghelpG_SymGetLineNext64));
    e("SymGetLineNextW64", reinterpret_cast<void*>(&kdbghelpG_SymGetLineNextW64));
    e("SymGetLinePrev64", reinterpret_cast<void*>(&kdbghelpG_SymGetLinePrev64));
    e("SymGetLinePrevW64", reinterpret_cast<void*>(&kdbghelpG_SymGetLinePrevW64));
    e("SymGetScope", reinterpret_cast<void*>(&kdbghelpG_SymGetScope));
    e("SymGetScopeW", reinterpret_cast<void*>(&kdbghelpG_SymGetScopeW));
    e("SymGetSourceFile", reinterpret_cast<void*>(&kdbghelpG_SymGetSourceFile));
    e("SymGetSourceFileFromToken", reinterpret_cast<void*>(&kdbghelpG_SymGetSourceFileFromToken));
    e("SymGetSourceFileFromTokenW", reinterpret_cast<void*>(&kdbghelpG_SymGetSourceFileFromTokenW));
    e("SymGetSourceFileToken", reinterpret_cast<void*>(&kdbghelpG_SymGetSourceFileToken));
    e("SymGetSourceFileTokenW", reinterpret_cast<void*>(&kdbghelpG_SymGetSourceFileTokenW));
    e("SymGetSourceFileW", reinterpret_cast<void*>(&kdbghelpG_SymGetSourceFileW));
    e("SymGetSourceVarFromToken", reinterpret_cast<void*>(&kdbghelpG_SymGetSourceVarFromToken));
    e("SymGetSourceVarFromTokenW", reinterpret_cast<void*>(&kdbghelpG_SymGetSourceVarFromTokenW));
    e("SymGetSymFromName64", reinterpret_cast<void*>(&kdbghelpG_SymGetSymFromName64));
    e("SymGetSymNext64", reinterpret_cast<void*>(&kdbghelpG_SymGetSymNext64));
    e("SymGetSymPrev64", reinterpret_cast<void*>(&kdbghelpG_SymGetSymPrev64));
    e("SymGetSymbolFile", reinterpret_cast<void*>(&kdbghelpG_SymGetSymbolFile));
    e("SymGetSymbolFileW", reinterpret_cast<void*>(&kdbghelpG_SymGetSymbolFileW));
    e("SymGetTypeFromName", reinterpret_cast<void*>(&kdbghelpG_SymGetTypeFromName));
    e("SymGetTypeFromNameW", reinterpret_cast<void*>(&kdbghelpG_SymGetTypeFromNameW));
    e("SymMatchFileName", reinterpret_cast<void*>(&kdbghelpG_SymMatchFileName));
    e("SymMatchFileNameW", reinterpret_cast<void*>(&kdbghelpG_SymMatchFileNameW));
    e("SymMatchString", reinterpret_cast<void*>(&kdbghelpG_SymMatchString));
    e("SymMatchStringW", reinterpret_cast<void*>(&kdbghelpG_SymMatchStringW));
    e("SymNext", reinterpret_cast<void*>(&kdbghelpG_SymNext));
    e("SymNextW", reinterpret_cast<void*>(&kdbghelpG_SymNextW));
    e("SymPrev", reinterpret_cast<void*>(&kdbghelpG_SymPrev));
    e("SymPrevW", reinterpret_cast<void*>(&kdbghelpG_SymPrevW));
    e("SymRefreshModuleList", reinterpret_cast<void*>(&kdbghelpG_SymRefreshModuleList));
    e("SymRegisterFunctionEntryCallback64", reinterpret_cast<void*>(&kdbghelpG_SymRegisterFunctionEntryCallback64));
    e("SymSearch", reinterpret_cast<void*>(&kdbghelpG_SymSearch));
    e("SymSearchW", reinterpret_cast<void*>(&kdbghelpG_SymSearchW));
    e("SymSetHomeDirectory", reinterpret_cast<void*>(&kdbghelpG_SymSetHomeDirectory));
    e("SymSetHomeDirectoryW", reinterpret_cast<void*>(&kdbghelpG_SymSetHomeDirectoryW));
    e("SymSetParentWindow", reinterpret_cast<void*>(&kdbghelpG_SymSetParentWindow));
    e("SymSrvDeltaName", reinterpret_cast<void*>(&kdbghelpG_SymSrvDeltaName));
    e("SymSrvDeltaNameW", reinterpret_cast<void*>(&kdbghelpG_SymSrvDeltaNameW));
    e("SymSrvGetFileIndexInfo", reinterpret_cast<void*>(&kdbghelpG_SymSrvGetFileIndexInfo));
    e("SymSrvGetFileIndexInfoW", reinterpret_cast<void*>(&kdbghelpG_SymSrvGetFileIndexInfoW));
    e("SymSrvGetFileIndexString", reinterpret_cast<void*>(&kdbghelpG_SymSrvGetFileIndexString));
    e("SymSrvGetFileIndexStringW", reinterpret_cast<void*>(&kdbghelpG_SymSrvGetFileIndexStringW));
    e("SymSrvGetFileIndexes", reinterpret_cast<void*>(&kdbghelpG_SymSrvGetFileIndexes));
    e("SymSrvGetFileIndexesW", reinterpret_cast<void*>(&kdbghelpG_SymSrvGetFileIndexesW));
    e("SymSrvGetSupplement", reinterpret_cast<void*>(&kdbghelpG_SymSrvGetSupplement));
    e("SymSrvGetSupplementW", reinterpret_cast<void*>(&kdbghelpG_SymSrvGetSupplementW));
    e("SymSrvIsStore", reinterpret_cast<void*>(&kdbghelpG_SymSrvIsStore));
    e("SymSrvIsStoreW", reinterpret_cast<void*>(&kdbghelpG_SymSrvIsStoreW));
    e("SymSrvStoreFile", reinterpret_cast<void*>(&kdbghelpG_SymSrvStoreFile));
    e("SymSrvStoreFileW", reinterpret_cast<void*>(&kdbghelpG_SymSrvStoreFileW));
    e("SymSrvStoreSupplement", reinterpret_cast<void*>(&kdbghelpG_SymSrvStoreSupplement));
    e("SymSrvStoreSupplementW", reinterpret_cast<void*>(&kdbghelpG_SymSrvStoreSupplementW));
    e("SymUnDName64", reinterpret_cast<void*>(&kdbghelpG_SymUnDName64));
}
}  // namespace occ::runtime::winabi

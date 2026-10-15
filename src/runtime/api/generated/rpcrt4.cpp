// The RPCRT4 surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_DceErrorInqTextA(std::int32_t RpcStatus, char* ErrorText) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(RpcStatus);
    static_cast<void>(ErrorText);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_DceErrorInqTextW(std::int32_t RpcStatus, char16_t* ErrorText) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(RpcStatus);
    static_cast<void>(ErrorText);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_DllGetClassObject(const void* rclsid, const void* riid, void** ppv) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(rclsid);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t krpcrt4G_IUnknown_AddRef_Proxy(void* This) noexcept {
    // Refused: the COM marshalling and storage layer.
    //
    // this call reaches a COM interface by vtable, and the vtable that would
    // answer it belongs to an object nobody here created: COM needs a class
    // registry, an apartment and a marshaller
    static_cast<void>(This);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_IUnknown_QueryInterface_Proxy(void* This, const void* riid, void** ppvObject) noexcept {
    // Refused: the COM marshalling and storage layer.
    //
    // this call reaches a COM interface by vtable, and the vtable that would
    // answer it belongs to an object nobody here created: COM needs a class
    // registry, an apartment and a marshaller
    static_cast<void>(This);
    static_cast<void>(riid);
    static_cast<void>(ppvObject);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t krpcrt4G_IUnknown_Release_Proxy(void* This) noexcept {
    // Refused: the COM marshalling and storage layer.
    //
    // this call reaches a COM interface by vtable, and the vtable that would
    // answer it belongs to an object nobody here created: COM needs a class
    // registry, an apartment and a marshaller
    static_cast<void>(This);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* krpcrt4G_I_RpcAllocate(std::uint32_t Size) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Size);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcAsyncAbortCall(void* pAsync, std::uint32_t ExceptionCode) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(pAsync);
    static_cast<void>(ExceptionCode);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcAsyncSetHandle(std::uint64_t Message, void* pAsync) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Message);
    static_cast<void>(pAsync);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcBindingCopy(void* SourceBinding, void** DestinationBinding) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(SourceBinding);
    static_cast<void>(DestinationBinding);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcBindingHandleToAsyncHandle(void* Binding, void** AsyncHandle) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(AsyncHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcBindingInqConnId(void* Binding, void** ConnId, std::int32_t* pfFirstCall) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(ConnId);
    static_cast<void>(pfFirstCall);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcBindingInqDynamicEndpointA(void* Binding, char** DynamicEndpoint) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(DynamicEndpoint);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcBindingInqDynamicEndpointW(void* Binding, char16_t** DynamicEndpoint) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(DynamicEndpoint);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcBindingInqLocalClientPID(void* Binding, std::uint32_t* Pid) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(Pid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcBindingInqMarshalledTargetInfo(void* Binding, std::uint32_t* MarshalledTargetInfoLength, char** MarshalledTargetInfo) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(MarshalledTargetInfoLength);
    static_cast<void>(MarshalledTargetInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcBindingInqSecurityContext(void* Binding, void** SecurityContextHandle) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(SecurityContextHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcBindingInqTransportType(void* Binding, std::uint32_t* Type) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(Type);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcBindingInqWireIdForSnego(void* Binding, char* WireId) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(WireId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcBindingIsClientLocal(void* BindingHandle, std::uint32_t* ClientLocalFlag) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(BindingHandle);
    static_cast<void>(ClientLocalFlag);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcBindingToStaticStringBindingW(void* Binding, std::uint16_t** StringBinding) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(StringBinding);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_I_RpcClearMutex(std::uint64_t Mutex) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Mutex);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcConnectionInqSockBuffSize(std::uint32_t* RecvBuffSize, std::uint32_t* SendBuffSize) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(RecvBuffSize);
    static_cast<void>(SendBuffSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcConnectionSetSockBuffSize(std::uint32_t RecvBuffSize, std::uint32_t SendBuffSize) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(RecvBuffSize);
    static_cast<void>(SendBuffSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_I_RpcDeleteMutex(std::uint64_t Mutex) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Mutex);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcExceptionFilter(std::uint32_t ExceptionCode) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ExceptionCode);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_I_RpcFree(void* Object) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Object);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcFreeBuffer(void* Message) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Message);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcFreePipeBuffer(void* Message) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(Message);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcGetBuffer(void* Message) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Message);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcGetBufferWithObject(void* Message, void* ObjectUuid) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Message);
    static_cast<void>(ObjectUuid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* krpcrt4G_I_RpcGetCurrentCallHandle() noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcGetExtendedError() noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcIfInqTransferSyntaxes(void* RpcIfHandle, void* TransferSyntaxes, std::uint32_t TransferSyntaxSize, std::uint32_t* TransferSyntaxCount) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(RpcIfHandle);
    static_cast<void>(TransferSyntaxes);
    static_cast<void>(TransferSyntaxSize);
    static_cast<void>(TransferSyntaxCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcMapWin32Status(std::int32_t Status) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Status);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcNegotiateTransferSyntax(void* Message) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Message);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcNsBindingSetEntryNameA(void* Binding, std::uint32_t EntryNameSyntax, char* EntryName) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(EntryNameSyntax);
    static_cast<void>(EntryName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcNsBindingSetEntryNameW(void* Binding, std::uint32_t EntryNameSyntax, char16_t* EntryName) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(EntryNameSyntax);
    static_cast<void>(EntryName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcNsInterfaceExported(std::uint32_t EntryNameSyntax, std::uint16_t* EntryName, void* RpcInterfaceInformation) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(EntryNameSyntax);
    static_cast<void>(EntryName);
    static_cast<void>(RpcInterfaceInformation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcNsInterfaceUnexported(std::uint32_t EntryNameSyntax, std::uint16_t* EntryName, void* RpcInterfaceInformation) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(EntryNameSyntax);
    static_cast<void>(EntryName);
    static_cast<void>(RpcInterfaceInformation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_I_RpcPauseExecution(std::uint32_t Milliseconds) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Milliseconds);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcProxyNewConnection(std::uint32_t ConnectionType, std::uint16_t* ServerAddress, std::uint16_t* ServerPort, std::uint16_t* MinConnTimeout, void* ConnectionParameter, void* CallOutState, void* ProxyCallbackInterface) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ConnectionType);
    static_cast<void>(ServerAddress);
    static_cast<void>(ServerPort);
    static_cast<void>(MinConnTimeout);
    static_cast<void>(ConnectionParameter);
    static_cast<void>(CallOutState);
    static_cast<void>(ProxyCallbackInterface);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcReallocPipeBuffer(std::uint64_t Message, std::uint32_t NewSize) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(Message);
    static_cast<void>(NewSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcReceive(std::uint64_t Message, std::uint32_t Size) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Message);
    static_cast<void>(Size);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_I_RpcRecordCalloutFailure(std::int32_t RpcStatus, void* CallOutState, std::uint16_t* DllName) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(RpcStatus);
    static_cast<void>(CallOutState);
    static_cast<void>(DllName);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcReplyToClientWithStatus(void* ConnectionParameter, std::int32_t RpcStatus) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ConnectionParameter);
    static_cast<void>(RpcStatus);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_I_RpcRequestMutex(void* Mutex) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Mutex);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcSend(std::uint64_t Message) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Message);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcSendReceive(void* Message) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Message);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcServerCheckClientRestriction(void* Context) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Context);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* krpcrt4G_I_RpcServerInqAddressChangeFn() noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcServerInqLocalConnAddress(void* Binding, void* Buffer, std::uint32_t* BufferSize, std::uint32_t* AddressFormat) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(Buffer);
    static_cast<void>(BufferSize);
    static_cast<void>(AddressFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcServerInqTransportType(std::uint32_t* Type) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Type);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcServerRegisterForwardFunction(void* pForwardFunction) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(pForwardFunction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcServerSetAddressChangeFn(void* pAddressChangeFn) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(pAddressChangeFn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcServerUseProtseq2A(char* NetworkAddress, char* Protseq, std::uint32_t MaxCalls, void* SecurityDescriptor, void* Policy) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(NetworkAddress);
    static_cast<void>(Protseq);
    static_cast<void>(MaxCalls);
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(Policy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcServerUseProtseq2W(char16_t* NetworkAddress, char16_t* Protseq, std::uint32_t MaxCalls, void* SecurityDescriptor, void* Policy) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(NetworkAddress);
    static_cast<void>(Protseq);
    static_cast<void>(MaxCalls);
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(Policy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcServerUseProtseqEp2A(char* NetworkAddress, char* Protseq, std::uint32_t MaxCalls, char* Endpoint, void* SecurityDescriptor, void* Policy) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(NetworkAddress);
    static_cast<void>(Protseq);
    static_cast<void>(MaxCalls);
    static_cast<void>(Endpoint);
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(Policy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcServerUseProtseqEp2W(char16_t* NetworkAddress, char16_t* Protseq, std::uint32_t MaxCalls, char16_t* Endpoint, void* SecurityDescriptor, void* Policy) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(NetworkAddress);
    static_cast<void>(Protseq);
    static_cast<void>(MaxCalls);
    static_cast<void>(Endpoint);
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(Policy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_I_RpcSessionStrictContextHandle() noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_I_RpcSsDontSerializeContext() noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_RpcTurnOnEEInfoPropagation() noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_I_UuidCreate(void* Uuid) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Uuid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* krpcrt4G_NDRCContextBinding(std::uint64_t CContext) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(CContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NDRCContextMarshall(std::uint64_t CContext, void* pBuff) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(CContext);
    static_cast<void>(pBuff);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NDRCContextUnmarshall(void* pCContext, void* hBinding, void* pBuff, std::uint32_t DataRepresentation) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(pCContext);
    static_cast<void>(hBinding);
    static_cast<void>(pBuff);
    static_cast<void>(DataRepresentation);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NDRSContextMarshall(std::uint64_t CContext, void* pBuff, void* userRunDownIn) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(CContext);
    static_cast<void>(pBuff);
    static_cast<void>(userRunDownIn);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NDRSContextMarshall2(void* BindingHandle, std::uint64_t CContext, void* pBuff, void* userRunDownIn, void* CtxGuard, std::uint32_t Flags) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(BindingHandle);
    static_cast<void>(CContext);
    static_cast<void>(pBuff);
    static_cast<void>(userRunDownIn);
    static_cast<void>(CtxGuard);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NDRSContextMarshallEx(void* BindingHandle, std::uint64_t CContext, void* pBuff, void* userRunDownIn) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(BindingHandle);
    static_cast<void>(CContext);
    static_cast<void>(pBuff);
    static_cast<void>(userRunDownIn);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint64_t krpcrt4G_NDRSContextUnmarshall(void* pBuff, std::uint32_t DataRepresentation) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(pBuff);
    static_cast<void>(DataRepresentation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t krpcrt4G_NDRSContextUnmarshall2(void* BindingHandle, void* pBuff, std::uint32_t DataRepresentation, void* CtxGuard, std::uint32_t Flags) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(BindingHandle);
    static_cast<void>(pBuff);
    static_cast<void>(DataRepresentation);
    static_cast<void>(CtxGuard);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t krpcrt4G_NDRSContextUnmarshallEx(void* BindingHandle, void* pBuff, std::uint32_t DataRepresentation) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(BindingHandle);
    static_cast<void>(pBuff);
    static_cast<void>(DataRepresentation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t krpcrt4G_Ndr64AsyncClientCall(void* pProxyInfo, std::uint32_t nProcNum, void* pReturnValue, ...) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pProxyInfo);
    static_cast<void>(nProcNum);
    static_cast<void>(pReturnValue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_Ndr64AsyncServerCall64(std::uint64_t pRpcMsg) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pRpcMsg);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_Ndr64AsyncServerCallAll(std::uint64_t pRpcMsg) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pRpcMsg);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint64_t krpcrt4G_Ndr64DcomAsyncClientCall(void* pProxyInfo, std::uint32_t nProcNum, void* pReturnValue, ...) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pProxyInfo);
    static_cast<void>(nProcNum);
    static_cast<void>(pReturnValue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_Ndr64DcomAsyncStubCall(void* pThis, void* pChannel, std::uint64_t pRpcMsg, std::uint32_t* pdwStubPhase) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pThis);
    static_cast<void>(pChannel);
    static_cast<void>(pRpcMsg);
    static_cast<void>(pdwStubPhase);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* krpcrt4G_NdrAllocate(void* pStubMsg, std::uint64_t Len) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(Len);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrAsyncServerCall(std::uint64_t pRpcMsg) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pRpcMsg);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrByteCountPointerBufferSize(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrByteCountPointerFree(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrByteCountPointerMarshall(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrByteCountPointerUnmarshall(void* pStubMsg, std::uint8_t** ppMemory, void* pFormat, std::uint8_t fMustAlloc) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ppMemory);
    static_cast<void>(pFormat);
    static_cast<void>(fMustAlloc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrClearOutParameters(void* pStubMsg, void* pFormat, void* ArgAddr) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    static_cast<void>(ArgAddr);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrClientContextMarshall(void* pStubMsg, std::uint64_t ContextHandle, std::int32_t fCheck) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ContextHandle);
    static_cast<void>(fCheck);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrClientContextUnmarshall(void* pStubMsg, void* pContextHandle, void* BindHandle) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pContextHandle);
    static_cast<void>(BindHandle);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrClientInitialize(std::uint64_t pRpcMsg, void* pStubMsg, void* pStubDescriptor, std::uint32_t ProcNum) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pRpcMsg);
    static_cast<void>(pStubMsg);
    static_cast<void>(pStubDescriptor);
    static_cast<void>(ProcNum);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrClientInitializeNew(std::uint64_t pRpcMsg, void* pStubMsg, void* pStubDescriptor, std::uint32_t ProcNum) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pRpcMsg);
    static_cast<void>(pStubMsg);
    static_cast<void>(pStubDescriptor);
    static_cast<void>(ProcNum);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrComplexArrayBufferSize(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrComplexArrayFree(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrComplexArrayMarshall(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t krpcrt4G_NdrComplexArrayMemorySize(void* pStubMsg, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrComplexArrayUnmarshall(void* pStubMsg, std::uint8_t** ppMemory, void* pFormat, std::uint8_t fMustAlloc) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ppMemory);
    static_cast<void>(pFormat);
    static_cast<void>(fMustAlloc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrComplexStructBufferSize(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrComplexStructFree(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrComplexStructMarshall(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t krpcrt4G_NdrComplexStructMemorySize(void* pStubMsg, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrComplexStructUnmarshall(void* pStubMsg, std::uint8_t** ppMemory, void* pFormat, std::uint8_t fMustAlloc) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ppMemory);
    static_cast<void>(pFormat);
    static_cast<void>(fMustAlloc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrConformantArrayBufferSize(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrConformantArrayFree(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrConformantArrayMarshall(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t krpcrt4G_NdrConformantArrayMemorySize(void* pStubMsg, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrConformantArrayUnmarshall(void* pStubMsg, std::uint8_t** ppMemory, void* pFormat, std::uint8_t fMustAlloc) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ppMemory);
    static_cast<void>(pFormat);
    static_cast<void>(fMustAlloc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrConformantStringBufferSize(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrConformantStringMarshall(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t krpcrt4G_NdrConformantStringMemorySize(void* pStubMsg, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrConformantStringUnmarshall(void* pStubMsg, std::uint8_t** ppMemory, void* pFormat, std::uint8_t fMustAlloc) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ppMemory);
    static_cast<void>(pFormat);
    static_cast<void>(fMustAlloc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrConformantStructBufferSize(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrConformantStructFree(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrConformantStructMarshall(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t krpcrt4G_NdrConformantStructMemorySize(void* pStubMsg, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrConformantStructUnmarshall(void* pStubMsg, std::uint8_t** ppMemory, void* pFormat, std::uint8_t fMustAlloc) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ppMemory);
    static_cast<void>(pFormat);
    static_cast<void>(fMustAlloc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrConformantVaryingArrayBufferSize(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrConformantVaryingArrayFree(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrConformantVaryingArrayMarshall(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t krpcrt4G_NdrConformantVaryingArrayMemorySize(void* pStubMsg, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrConformantVaryingArrayUnmarshall(void* pStubMsg, std::uint8_t** ppMemory, void* pFormat, std::uint8_t fMustAlloc) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ppMemory);
    static_cast<void>(pFormat);
    static_cast<void>(fMustAlloc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrConformantVaryingStructBufferSize(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrConformantVaryingStructFree(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrConformantVaryingStructMarshall(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t krpcrt4G_NdrConformantVaryingStructMemorySize(void* pStubMsg, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrConformantVaryingStructUnmarshall(void* pStubMsg, std::uint8_t** ppMemory, void* pFormat, std::uint8_t fMustAlloc) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ppMemory);
    static_cast<void>(pFormat);
    static_cast<void>(fMustAlloc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint64_t krpcrt4G_NdrContextHandleInitialize(void* pStubMsg, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrContextHandleSize(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrConvert(void* pStubMsg, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrConvert2(void* pStubMsg, void* pFormat, std::int32_t NumberParams) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    static_cast<void>(NumberParams);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrCorrelationFree(void* pStubMsg) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrCorrelationInitialize(void* pStubMsg, void* pMemory, std::uint32_t CacheSize, std::uint32_t flags) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(CacheSize);
    static_cast<void>(flags);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrCorrelationPass(void* pStubMsg) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_NdrCreateServerInterfaceFromStub(void* pStub, void* pServerIf) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStub);
    static_cast<void>(pServerIf);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t krpcrt4G_NdrDcomAsyncClientCall(void* pStubDescriptor, void* pFormat, ...) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubDescriptor);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_NdrDcomAsyncStubCall(void* pThis, void* pChannel, std::uint64_t pRpcMsg, std::uint32_t* pdwStubPhase) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pThis);
    static_cast<void>(pChannel);
    static_cast<void>(pRpcMsg);
    static_cast<void>(pdwStubPhase);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrEncapsulatedUnionBufferSize(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrEncapsulatedUnionFree(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrEncapsulatedUnionMarshall(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t krpcrt4G_NdrEncapsulatedUnionMemorySize(void* pStubMsg, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrEncapsulatedUnionUnmarshall(void* pStubMsg, std::uint8_t** ppMemory, void* pFormat, std::uint8_t fMustAlloc) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ppMemory);
    static_cast<void>(pFormat);
    static_cast<void>(fMustAlloc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrFixedArrayBufferSize(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrFixedArrayFree(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrFixedArrayMarshall(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t krpcrt4G_NdrFixedArrayMemorySize(void* pStubMsg, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrFixedArrayUnmarshall(void* pStubMsg, std::uint8_t** ppMemory, void* pFormat, std::uint8_t fMustAlloc) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ppMemory);
    static_cast<void>(pFormat);
    static_cast<void>(fMustAlloc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_NdrFullPointerFree(void* pXlatTables, void* Pointer) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pXlatTables);
    static_cast<void>(Pointer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrFullPointerInsertRefId(void* pXlatTables, std::uint32_t RefId, void* pPointer) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pXlatTables);
    static_cast<void>(RefId);
    static_cast<void>(pPointer);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_NdrFullPointerQueryPointer(void* pXlatTables, void* pPointer, std::uint8_t QueryType, std::uint32_t* pRefId) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pXlatTables);
    static_cast<void>(pPointer);
    static_cast<void>(QueryType);
    static_cast<void>(pRefId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_NdrFullPointerQueryRefId(void* pXlatTables, std::uint32_t RefId, std::uint8_t QueryType, void** ppPointer) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pXlatTables);
    static_cast<void>(RefId);
    static_cast<void>(QueryType);
    static_cast<void>(ppPointer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrFullPointerXlatFree(void* pXlatTables) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pXlatTables);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void* krpcrt4G_NdrFullPointerXlatInit(std::uint32_t NumberOfPointers, std::uint64_t XlatSide) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(NumberOfPointers);
    static_cast<void>(XlatSide);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_NdrGetDcomProtocolVersion(void* pStubMsg, void* pVersion) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pVersion);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_NdrGetUserMarshalInfo(std::uint32_t* pFlags, std::uint32_t InformationLevel, void* pMarshalInfo) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pFlags);
    static_cast<void>(InformationLevel);
    static_cast<void>(pMarshalInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrInterfacePointerBufferSize(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrInterfacePointerFree(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrInterfacePointerMarshall(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t krpcrt4G_NdrInterfacePointerMemorySize(void* pStubMsg, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrInterfacePointerUnmarshall(void* pStubMsg, std::uint8_t** ppMemory, void* pFormat, std::uint8_t fMustAlloc) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ppMemory);
    static_cast<void>(pFormat);
    static_cast<void>(fMustAlloc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_NdrMapCommAndFaultStatus(void* pStubMsg, std::uint32_t* pCommStatus, std::uint32_t* pFaultStatus, std::int32_t Status) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(pStubMsg);
    static_cast<void>(pCommStatus);
    static_cast<void>(pFaultStatus);
    static_cast<void>(Status);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrNonConformantStringBufferSize(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrNonConformantStringMarshall(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t krpcrt4G_NdrNonConformantStringMemorySize(void* pStubMsg, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrNonConformantStringUnmarshall(void* pStubMsg, std::uint8_t** ppMemory, void* pFormat, std::uint8_t fMustAlloc) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ppMemory);
    static_cast<void>(pFormat);
    static_cast<void>(fMustAlloc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrNonEncapsulatedUnionBufferSize(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrNonEncapsulatedUnionFree(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrNonEncapsulatedUnionMarshall(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t krpcrt4G_NdrNonEncapsulatedUnionMemorySize(void* pStubMsg, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrNonEncapsulatedUnionUnmarshall(void* pStubMsg, std::uint8_t** ppMemory, void* pFormat, std::uint8_t fMustAlloc) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ppMemory);
    static_cast<void>(pFormat);
    static_cast<void>(fMustAlloc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrNsGetBuffer(void* pStubMsg, std::uint32_t BufferLength, void* Handle) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(BufferLength);
    static_cast<void>(Handle);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrNsSendReceive(void* pStubMsg, std::uint8_t* pBufferEnd, void** pAutoHandle) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pBufferEnd);
    static_cast<void>(pAutoHandle);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrPartialIgnoreClientBufferSize(void* pStubMsg, void* pMemory) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrPartialIgnoreClientMarshall(void* pStubMsg, void* pMemory) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrPartialIgnoreServerInitialize(void* pStubMsg, void** ppMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ppMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrPartialIgnoreServerUnmarshall(void* pStubMsg, void** ppMemory) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ppMemory);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrPointerBufferSize(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrPointerFree(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrPointerMarshall(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t krpcrt4G_NdrPointerMemorySize(void* pStubMsg, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrPointerUnmarshall(void* pStubMsg, std::uint8_t** ppMemory, void* pFormat, std::uint8_t fMustAlloc) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ppMemory);
    static_cast<void>(pFormat);
    static_cast<void>(fMustAlloc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrRangeUnmarshall(void* pStubMsg, std::uint8_t** ppMemory, void* pFormat, std::uint8_t fMustAlloc) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ppMemory);
    static_cast<void>(pFormat);
    static_cast<void>(fMustAlloc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* krpcrt4G_NdrRpcSmClientAllocate(std::uint64_t Size) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(Size);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrRpcSmClientFree(void* NodeToFree) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(NodeToFree);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrRpcSmSetClientToOsf(void* pMessage) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pMessage);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void* krpcrt4G_NdrRpcSsDefaultAllocate(std::uint64_t Size) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(Size);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrRpcSsDefaultFree(void* NodeToFree) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(NodeToFree);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrRpcSsDisableAllocate(void* pMessage) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pMessage);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrRpcSsEnableAllocate(void* pMessage) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pMessage);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrServerCall2(std::uint64_t pRpcMsg) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pRpcMsg);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrServerCallAll(std::uint64_t pRpcMsg) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pRpcMsg);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrServerCallNdr64(std::uint64_t pRpcMsg) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pRpcMsg);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrServerContextMarshall(void* pStubMsg, std::uint64_t ContextHandle, void* RundownRoutine) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ContextHandle);
    static_cast<void>(RundownRoutine);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrServerContextNewMarshall(void* pStubMsg, std::uint64_t ContextHandle, void* RundownRoutine, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ContextHandle);
    static_cast<void>(RundownRoutine);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint64_t krpcrt4G_NdrServerContextNewUnmarshall(void* pStubMsg, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t krpcrt4G_NdrServerContextUnmarshall(void* pStubMsg) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrServerInitialize(std::uint64_t pRpcMsg, void* pStubMsg, void* pStubDescriptor) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pRpcMsg);
    static_cast<void>(pStubMsg);
    static_cast<void>(pStubDescriptor);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrServerInitializeMarshall(std::uint64_t pRpcMsg, void* pStubMsg) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pRpcMsg);
    static_cast<void>(pStubMsg);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrServerInitializeNew(std::uint64_t pRpcMsg, void* pStubMsg, void* pStubDescriptor) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pRpcMsg);
    static_cast<void>(pStubMsg);
    static_cast<void>(pStubDescriptor);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrServerInitializePartial(std::uint64_t pRpcMsg, void* pStubMsg, void* pStubDescriptor, std::uint32_t RequestedBufferSize) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pRpcMsg);
    static_cast<void>(pStubMsg);
    static_cast<void>(pStubDescriptor);
    static_cast<void>(RequestedBufferSize);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrServerInitializeUnmarshall(void* pStubMsg, void* pStubDescriptor, std::uint64_t pRpcMsg) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pStubDescriptor);
    static_cast<void>(pRpcMsg);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrSimpleStructBufferSize(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrSimpleStructFree(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrSimpleStructMarshall(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t krpcrt4G_NdrSimpleStructMemorySize(void* pStubMsg, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrSimpleStructUnmarshall(void* pStubMsg, std::uint8_t** ppMemory, void* pFormat, std::uint8_t fMustAlloc) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ppMemory);
    static_cast<void>(pFormat);
    static_cast<void>(fMustAlloc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrSimpleTypeMarshall(void* pStubMsg, std::uint8_t* pMemory, std::uint8_t FormatChar) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(FormatChar);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrSimpleTypeUnmarshall(void* pStubMsg, std::uint8_t* pMemory, std::uint8_t FormatChar) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(FormatChar);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_NdrStubCall2(void* pThis, void* pChannel, std::uint64_t pRpcMsg, std::uint32_t* pdwStubPhase) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pThis);
    static_cast<void>(pChannel);
    static_cast<void>(pRpcMsg);
    static_cast<void>(pdwStubPhase);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_NdrStubCall3(void* pThis, void* pChannel, std::uint64_t pRpcMsg, std::uint32_t* pdwStubPhase) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pThis);
    static_cast<void>(pChannel);
    static_cast<void>(pRpcMsg);
    static_cast<void>(pdwStubPhase);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrUserMarshalBufferSize(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrUserMarshalFree(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrUserMarshalMarshall(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t krpcrt4G_NdrUserMarshalMemorySize(void* pStubMsg, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrUserMarshalSimpleTypeConvert(std::uint32_t* pFlags, std::uint8_t* pBuffer, std::uint8_t FormatChar) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pFlags);
    static_cast<void>(pBuffer);
    static_cast<void>(FormatChar);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrUserMarshalUnmarshall(void* pStubMsg, std::uint8_t** ppMemory, void* pFormat, std::uint8_t fMustAlloc) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ppMemory);
    static_cast<void>(pFormat);
    static_cast<void>(fMustAlloc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrVaryingArrayBufferSize(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrVaryingArrayFree(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrVaryingArrayMarshall(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t krpcrt4G_NdrVaryingArrayMemorySize(void* pStubMsg, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrVaryingArrayUnmarshall(void* pStubMsg, std::uint8_t** ppMemory, void* pFormat, std::uint8_t fMustAlloc) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ppMemory);
    static_cast<void>(pFormat);
    static_cast<void>(fMustAlloc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrXmitOrRepAsBufferSize(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_NdrXmitOrRepAsFree(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrXmitOrRepAsMarshall(void* pStubMsg, std::uint8_t* pMemory, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pMemory);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t krpcrt4G_NdrXmitOrRepAsMemorySize(void* pStubMsg, void* pFormat) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(pFormat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t* krpcrt4G_NdrXmitOrRepAsUnmarshall(void* pStubMsg, std::uint8_t** ppMemory, void* pFormat, std::uint8_t fMustAlloc) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(pStubMsg);
    static_cast<void>(ppMemory);
    static_cast<void>(pFormat);
    static_cast<void>(fMustAlloc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcAsyncAbortCall(void* pAsync, std::uint32_t ExceptionCode) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(pAsync);
    static_cast<void>(ExceptionCode);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcAsyncCancelCall(void* pAsync, std::int32_t fAbort) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(pAsync);
    static_cast<void>(fAbort);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcAsyncCompleteCall(void* pAsync, void* Reply) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(pAsync);
    static_cast<void>(Reply);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcAsyncRegisterInfo(void* pAsync) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(pAsync);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingBind(void* pAsync, void* Binding, void* IfSpec) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(pAsync);
    static_cast<void>(Binding);
    static_cast<void>(IfSpec);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingCopy(void* SourceBinding, void** DestinationBinding) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(SourceBinding);
    static_cast<void>(DestinationBinding);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingCreateA(void* Template, void* Security, void* Options, void** Binding) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Template);
    static_cast<void>(Security);
    static_cast<void>(Options);
    static_cast<void>(Binding);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingCreateW(void* Template, void* Security, void* Options, void** Binding) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Template);
    static_cast<void>(Security);
    static_cast<void>(Options);
    static_cast<void>(Binding);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingInqAuthClientA(void* ClientBinding, void** Privs, char** ServerPrincName, std::uint32_t* AuthnLevel, std::uint32_t* AuthnSvc, std::uint32_t* AuthzSvc) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ClientBinding);
    static_cast<void>(Privs);
    static_cast<void>(ServerPrincName);
    static_cast<void>(AuthnLevel);
    static_cast<void>(AuthnSvc);
    static_cast<void>(AuthzSvc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingInqAuthClientExA(void* ClientBinding, void** Privs, char** ServerPrincName, std::uint32_t* AuthnLevel, std::uint32_t* AuthnSvc, std::uint32_t* AuthzSvc, std::uint32_t Flags) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ClientBinding);
    static_cast<void>(Privs);
    static_cast<void>(ServerPrincName);
    static_cast<void>(AuthnLevel);
    static_cast<void>(AuthnSvc);
    static_cast<void>(AuthzSvc);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingInqAuthClientExW(void* ClientBinding, void** Privs, char16_t** ServerPrincName, std::uint32_t* AuthnLevel, std::uint32_t* AuthnSvc, std::uint32_t* AuthzSvc, std::uint32_t Flags) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ClientBinding);
    static_cast<void>(Privs);
    static_cast<void>(ServerPrincName);
    static_cast<void>(AuthnLevel);
    static_cast<void>(AuthnSvc);
    static_cast<void>(AuthzSvc);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingInqAuthClientW(void* ClientBinding, void** Privs, char16_t** ServerPrincName, std::uint32_t* AuthnLevel, std::uint32_t* AuthnSvc, std::uint32_t* AuthzSvc) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ClientBinding);
    static_cast<void>(Privs);
    static_cast<void>(ServerPrincName);
    static_cast<void>(AuthnLevel);
    static_cast<void>(AuthnSvc);
    static_cast<void>(AuthzSvc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingInqAuthInfoA(void* Binding, char** ServerPrincName, std::uint32_t* AuthnLevel, std::uint32_t* AuthnSvc, void** AuthIdentity, std::uint32_t* AuthzSvc) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(ServerPrincName);
    static_cast<void>(AuthnLevel);
    static_cast<void>(AuthnSvc);
    static_cast<void>(AuthIdentity);
    static_cast<void>(AuthzSvc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingInqAuthInfoExA(void* Binding, char** ServerPrincName, std::uint32_t* AuthnLevel, std::uint32_t* AuthnSvc, void** AuthIdentity, std::uint32_t* AuthzSvc, std::uint32_t RpcQosVersion, void* SecurityQOS) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(ServerPrincName);
    static_cast<void>(AuthnLevel);
    static_cast<void>(AuthnSvc);
    static_cast<void>(AuthIdentity);
    static_cast<void>(AuthzSvc);
    static_cast<void>(RpcQosVersion);
    static_cast<void>(SecurityQOS);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingInqAuthInfoExW(void* Binding, char16_t** ServerPrincName, std::uint32_t* AuthnLevel, std::uint32_t* AuthnSvc, void** AuthIdentity, std::uint32_t* AuthzSvc, std::uint32_t RpcQosVersion, void* SecurityQOS) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(ServerPrincName);
    static_cast<void>(AuthnLevel);
    static_cast<void>(AuthnSvc);
    static_cast<void>(AuthIdentity);
    static_cast<void>(AuthzSvc);
    static_cast<void>(RpcQosVersion);
    static_cast<void>(SecurityQOS);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingInqAuthInfoW(void* Binding, char16_t** ServerPrincName, std::uint32_t* AuthnLevel, std::uint32_t* AuthnSvc, void** AuthIdentity, std::uint32_t* AuthzSvc) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(ServerPrincName);
    static_cast<void>(AuthnLevel);
    static_cast<void>(AuthnSvc);
    static_cast<void>(AuthIdentity);
    static_cast<void>(AuthzSvc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingInqOption(void* hBinding, std::uint32_t option, std::uint64_t* pOptionValue) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(hBinding);
    static_cast<void>(option);
    static_cast<void>(pOptionValue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingReset(void* Binding) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingServerFromClient(void* ClientBinding, void** ServerBinding) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ClientBinding);
    static_cast<void>(ServerBinding);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingSetAuthInfoA(void* Binding, char* ServerPrincName, std::uint32_t AuthnLevel, std::uint32_t AuthnSvc, void* AuthIdentity, std::uint32_t AuthzSvc) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(ServerPrincName);
    static_cast<void>(AuthnLevel);
    static_cast<void>(AuthnSvc);
    static_cast<void>(AuthIdentity);
    static_cast<void>(AuthzSvc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingSetAuthInfoExA(void* Binding, char* ServerPrincName, std::uint32_t AuthnLevel, std::uint32_t AuthnSvc, void* AuthIdentity, std::uint32_t AuthzSvc, void* SecurityQos) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(ServerPrincName);
    static_cast<void>(AuthnLevel);
    static_cast<void>(AuthnSvc);
    static_cast<void>(AuthIdentity);
    static_cast<void>(AuthzSvc);
    static_cast<void>(SecurityQos);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingSetAuthInfoExW(void* Binding, char16_t* ServerPrincName, std::uint32_t AuthnLevel, std::uint32_t AuthnSvc, void* AuthIdentity, std::uint32_t AuthzSvc, void* SecurityQOS) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(ServerPrincName);
    static_cast<void>(AuthnLevel);
    static_cast<void>(AuthnSvc);
    static_cast<void>(AuthIdentity);
    static_cast<void>(AuthzSvc);
    static_cast<void>(SecurityQOS);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingSetAuthInfoW(void* Binding, char16_t* ServerPrincName, std::uint32_t AuthnLevel, std::uint32_t AuthnSvc, void* AuthIdentity, std::uint32_t AuthzSvc) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(ServerPrincName);
    static_cast<void>(AuthnLevel);
    static_cast<void>(AuthnSvc);
    static_cast<void>(AuthIdentity);
    static_cast<void>(AuthzSvc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingSetObject(void* Binding, void* ObjectUuid) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(ObjectUuid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingSetOption(void* hBinding, std::uint32_t option, std::uint64_t optionValue) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(hBinding);
    static_cast<void>(option);
    static_cast<void>(optionValue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingToStringBindingA(void* Binding, char** StringBinding) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(StringBinding);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingToStringBindingW(void* Binding, char16_t** StringBinding) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(StringBinding);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingUnbind(void* Binding) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcBindingVectorFree(void** BindingVector) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(BindingVector);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcCancelThread(void* Thread) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Thread);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcCancelThreadEx(void* Thread, std::int32_t Timeout) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Thread);
    static_cast<void>(Timeout);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcEpRegisterA(void* IfSpec, void* BindingVector, void* UuidVector, char* Annotation) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(IfSpec);
    static_cast<void>(BindingVector);
    static_cast<void>(UuidVector);
    static_cast<void>(Annotation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcEpRegisterNoReplaceA(void* IfSpec, void* BindingVector, void* UuidVector, char* Annotation) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(IfSpec);
    static_cast<void>(BindingVector);
    static_cast<void>(UuidVector);
    static_cast<void>(Annotation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcEpRegisterNoReplaceW(void* IfSpec, void* BindingVector, void* UuidVector, char16_t* Annotation) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(IfSpec);
    static_cast<void>(BindingVector);
    static_cast<void>(UuidVector);
    static_cast<void>(Annotation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcEpRegisterW(void* IfSpec, void* BindingVector, void* UuidVector, char16_t* Annotation) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(IfSpec);
    static_cast<void>(BindingVector);
    static_cast<void>(UuidVector);
    static_cast<void>(Annotation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcEpResolveBinding(void* Binding, void* IfSpec) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(IfSpec);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcEpUnregister(void* IfSpec, void* BindingVector, void* UuidVector) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(IfSpec);
    static_cast<void>(BindingVector);
    static_cast<void>(UuidVector);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcErrorAddRecord(void* ErrorInfo) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ErrorInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_RpcErrorClearInformation() noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcErrorEndEnumeration(void* EnumHandle) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(EnumHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcErrorGetNextRecord(void* EnumHandle, std::int32_t CopyStrings, void* ErrorInfo) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(EnumHandle);
    static_cast<void>(CopyStrings);
    static_cast<void>(ErrorInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcErrorGetNumberOfRecords(void* EnumHandle, std::int32_t* Records) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(EnumHandle);
    static_cast<void>(Records);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcErrorLoadErrorInfo(void* ErrorBlob, std::uint64_t BlobSize, void* EnumHandle) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ErrorBlob);
    static_cast<void>(BlobSize);
    static_cast<void>(EnumHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcErrorResetEnumeration(void* EnumHandle) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(EnumHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcErrorSaveErrorInfo(void* EnumHandle, void** ErrorBlob, std::uint64_t* BlobSize) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(EnumHandle);
    static_cast<void>(ErrorBlob);
    static_cast<void>(BlobSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcErrorStartEnumeration(void* EnumHandle) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(EnumHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcFreeAuthorizationContext(void** pAuthzClientContext) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(pAuthzClientContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcGetAuthorizationContextForClient(void* ClientBinding, std::int32_t ImpersonateOnReturn, void* Reserved1, void* pExpirationTime, std::uint64_t Reserved2, std::uint32_t Reserved3, void* Reserved4, void** pAuthzClientContext) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ClientBinding);
    static_cast<void>(ImpersonateOnReturn);
    static_cast<void>(Reserved1);
    static_cast<void>(pExpirationTime);
    static_cast<void>(Reserved2);
    static_cast<void>(Reserved3);
    static_cast<void>(Reserved4);
    static_cast<void>(pAuthzClientContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcIfInqId(void* RpcIfHandle, void* RpcIfId) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(RpcIfHandle);
    static_cast<void>(RpcIfId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcMgmtEpEltInqBegin(void* EpBinding, std::uint32_t InquiryType, void* IfId, std::uint32_t VersOption, void* ObjectUuid, void* InquiryContext) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(EpBinding);
    static_cast<void>(InquiryType);
    static_cast<void>(IfId);
    static_cast<void>(VersOption);
    static_cast<void>(ObjectUuid);
    static_cast<void>(InquiryContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcMgmtEpEltInqDone(void* InquiryContext) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(InquiryContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcMgmtEpEltInqNextA(std::uint64_t InquiryContext, void* IfId, void** Binding, void* ObjectUuid, char** Annotation) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(InquiryContext);
    static_cast<void>(IfId);
    static_cast<void>(Binding);
    static_cast<void>(ObjectUuid);
    static_cast<void>(Annotation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcMgmtEpEltInqNextW(std::uint64_t InquiryContext, void* IfId, void** Binding, void* ObjectUuid, char16_t** Annotation) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(InquiryContext);
    static_cast<void>(IfId);
    static_cast<void>(Binding);
    static_cast<void>(ObjectUuid);
    static_cast<void>(Annotation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcMgmtEpUnregister(void* EpBinding, void* IfId, void* Binding, void* ObjectUuid) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(EpBinding);
    static_cast<void>(IfId);
    static_cast<void>(Binding);
    static_cast<void>(ObjectUuid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcMgmtInqComTimeout(void* Binding, std::uint32_t* Timeout) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(Timeout);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcMgmtInqDefaultProtectLevel(std::uint32_t AuthnSvc, std::uint32_t* AuthnLevel) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(AuthnSvc);
    static_cast<void>(AuthnLevel);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcMgmtInqServerPrincNameA(void* Binding, std::uint32_t AuthnSvc, char** ServerPrincName) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(AuthnSvc);
    static_cast<void>(ServerPrincName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcMgmtInqServerPrincNameW(void* Binding, std::uint32_t AuthnSvc, char16_t** ServerPrincName) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(AuthnSvc);
    static_cast<void>(ServerPrincName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcMgmtInqStats(void* Binding, void** Statistics) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(Statistics);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcMgmtSetAuthorizationFn(std::uint64_t AuthorizationFn) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(AuthorizationFn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcMgmtSetComTimeout(void* Binding, std::uint32_t Timeout) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(Timeout);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcMgmtSetServerStackSize(std::uint32_t ThreadStackSize) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ThreadStackSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcMgmtStatsVectorFree(void** StatsVector) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(StatsVector);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcNetworkInqProtseqsA(void** ProtseqVector) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(ProtseqVector);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcNetworkInqProtseqsW(void** ProtseqVector) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(ProtseqVector);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcNetworkIsProtseqValidA(char* Protseq) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(Protseq);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcNetworkIsProtseqValidW(char16_t* Protseq) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(Protseq);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcNsBindingInqEntryNameA(void* Binding, std::uint32_t EntryNameSyntax, char** EntryName) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(EntryNameSyntax);
    static_cast<void>(EntryName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcNsBindingInqEntryNameW(void* Binding, std::uint32_t EntryNameSyntax, char16_t** EntryName) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(EntryNameSyntax);
    static_cast<void>(EntryName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcObjectInqType(void* ObjUuid, void* TypeUuid) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ObjUuid);
    static_cast<void>(TypeUuid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcObjectSetInqFn(void* InquiryFn) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(InquiryFn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcObjectSetType(void* ObjUuid, void* TypeUuid) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ObjUuid);
    static_cast<void>(TypeUuid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcProtseqVectorFreeA(void** ProtseqVector) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ProtseqVector);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcProtseqVectorFreeW(void** ProtseqVector) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ProtseqVector);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcRevertToSelfEx(void* BindingHandle) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(BindingHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerInqBindingHandle(void** Binding) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerInqBindings(void** BindingVector) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(BindingVector);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerInqCallAttributesA(void* ClientBinding, void* RpcCallAttributes) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ClientBinding);
    static_cast<void>(RpcCallAttributes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerInqCallAttributesW(void* ClientBinding, void* RpcCallAttributes) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ClientBinding);
    static_cast<void>(RpcCallAttributes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerInqDefaultPrincNameA(std::uint32_t AuthnSvc, char** PrincName) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(AuthnSvc);
    static_cast<void>(PrincName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerInqDefaultPrincNameW(std::uint32_t AuthnSvc, char16_t** PrincName) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(AuthnSvc);
    static_cast<void>(PrincName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerInqIf(void* IfSpec, void* MgrTypeUuid, void** MgrEpv) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(IfSpec);
    static_cast<void>(MgrTypeUuid);
    static_cast<void>(MgrEpv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerRegisterAuthInfoA(char* ServerPrincName, std::uint32_t AuthnSvc, std::uint64_t GetKeyFn, void* Arg) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ServerPrincName);
    static_cast<void>(AuthnSvc);
    static_cast<void>(GetKeyFn);
    static_cast<void>(Arg);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerRegisterAuthInfoW(char16_t* ServerPrincName, std::uint32_t AuthnSvc, std::uint64_t GetKeyFn, void* Arg) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ServerPrincName);
    static_cast<void>(AuthnSvc);
    static_cast<void>(GetKeyFn);
    static_cast<void>(Arg);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerSubscribeForNotification(void* Binding, std::uint32_t Notification, std::uint64_t NotificationType, void* NotificationInfo) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(Notification);
    static_cast<void>(NotificationType);
    static_cast<void>(NotificationInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerTestCancel(void* BindingHandle) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(BindingHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerUnregisterIfEx(void* IfSpec, void* MgrTypeUuid, std::int32_t RundownContextHandles) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(IfSpec);
    static_cast<void>(MgrTypeUuid);
    static_cast<void>(RundownContextHandles);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerUnsubscribeForNotification(void* Binding, std::uint64_t Notification, std::uint32_t* NotificationsQueued) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Binding);
    static_cast<void>(Notification);
    static_cast<void>(NotificationsQueued);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerUseAllProtseqs(std::uint32_t MaxCalls, void* SecurityDescriptor) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(MaxCalls);
    static_cast<void>(SecurityDescriptor);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerUseAllProtseqsEx(std::uint32_t MaxCalls, void* SecurityDescriptor, void* Policy) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(MaxCalls);
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(Policy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerUseAllProtseqsIf(std::uint32_t MaxCalls, void* IfSpec, void* SecurityDescriptor) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(MaxCalls);
    static_cast<void>(IfSpec);
    static_cast<void>(SecurityDescriptor);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerUseAllProtseqsIfEx(std::uint32_t MaxCalls, void* IfSpec, void* SecurityDescriptor, void* Policy) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(MaxCalls);
    static_cast<void>(IfSpec);
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(Policy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerUseProtseqA(char* Protseq, std::uint32_t MaxCalls, void* SecurityDescriptor) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Protseq);
    static_cast<void>(MaxCalls);
    static_cast<void>(SecurityDescriptor);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerUseProtseqEpExA(char* Protseq, std::uint32_t MaxCalls, char* Endpoint, void* SecurityDescriptor, void* Policy) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Protseq);
    static_cast<void>(MaxCalls);
    static_cast<void>(Endpoint);
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(Policy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerUseProtseqEpExW(char16_t* Protseq, std::uint32_t MaxCalls, char16_t* Endpoint, void* SecurityDescriptor, void* Policy) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Protseq);
    static_cast<void>(MaxCalls);
    static_cast<void>(Endpoint);
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(Policy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerUseProtseqExA(char* Protseq, std::uint32_t MaxCalls, void* SecurityDescriptor, void* Policy) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Protseq);
    static_cast<void>(MaxCalls);
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(Policy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerUseProtseqExW(char16_t* Protseq, std::uint32_t MaxCalls, void* SecurityDescriptor, void* Policy) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Protseq);
    static_cast<void>(MaxCalls);
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(Policy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerUseProtseqIfA(char* Protseq, std::uint32_t MaxCalls, void* IfSpec, void* SecurityDescriptor) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Protseq);
    static_cast<void>(MaxCalls);
    static_cast<void>(IfSpec);
    static_cast<void>(SecurityDescriptor);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerUseProtseqIfExA(char* Protseq, std::uint32_t MaxCalls, void* IfSpec, void* SecurityDescriptor, void* Policy) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Protseq);
    static_cast<void>(MaxCalls);
    static_cast<void>(IfSpec);
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(Policy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerUseProtseqIfExW(char16_t* Protseq, std::uint32_t MaxCalls, void* IfSpec, void* SecurityDescriptor, void* Policy) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Protseq);
    static_cast<void>(MaxCalls);
    static_cast<void>(IfSpec);
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(Policy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerUseProtseqIfW(char16_t* Protseq, std::uint32_t MaxCalls, void* IfSpec, void* SecurityDescriptor) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Protseq);
    static_cast<void>(MaxCalls);
    static_cast<void>(IfSpec);
    static_cast<void>(SecurityDescriptor);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcServerUseProtseqW(char16_t* Protseq, std::uint32_t MaxCalls, void* SecurityDescriptor) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Protseq);
    static_cast<void>(MaxCalls);
    static_cast<void>(SecurityDescriptor);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_RpcServerYield() noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void* krpcrt4G_RpcSmAllocate(std::uint64_t Size, std::int32_t* pStatus) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Size);
    static_cast<void>(pStatus);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcSmClientFree(void* pNodeToFree) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(pNodeToFree);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcSmDestroyClientContext(void** ContextHandle) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ContextHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcSmDisableAllocate() noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcSmEnableAllocate() noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcSmFree(void* NodeToFree) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(NodeToFree);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t krpcrt4G_RpcSmGetThreadHandle(std::int32_t* pStatus) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(pStatus);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcSmSetClientAllocFree(void** ClientAlloc, void** ClientFree) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ClientAlloc);
    static_cast<void>(ClientFree);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcSmSetThreadHandle(std::uint64_t Id) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Id);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcSmSwapClientAllocFree(void** ClientAlloc, void** ClientFree, void*** OldClientAlloc, void*** OldClientFree) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ClientAlloc);
    static_cast<void>(ClientFree);
    static_cast<void>(OldClientAlloc);
    static_cast<void>(OldClientFree);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcSsContextLockExclusive(void* ServerBindingHandle, void* UserContext) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ServerBindingHandle);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcSsContextLockShared(void* ServerBindingHandle, void* UserContext) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ServerBindingHandle);
    static_cast<void>(UserContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_RpcSsDestroyClientContext(void** ContextHandle) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ContextHandle);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_RpcSsDisableAllocate() noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_RpcSsDontSerializeContext() noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_RpcSsEnableAllocate() noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcSsGetContextBinding(void* ContextHandle, void** Binding) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ContextHandle);
    static_cast<void>(Binding);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t krpcrt4G_RpcSsGetThreadHandle() noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_RpcSsSetClientAllocFree(void** ClientAlloc, void** ClientFree) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ClientAlloc);
    static_cast<void>(ClientFree);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_RpcSsSetThreadHandle(std::uint64_t Id) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(Id);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_RpcSsSwapClientAllocFree(void** ClientAlloc, void** ClientFree, void*** OldClientAlloc, void*** OldClientFree) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(ClientAlloc);
    static_cast<void>(ClientFree);
    static_cast<void>(OldClientAlloc);
    static_cast<void>(OldClientFree);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t krpcrt4G_RpcTestCancel() noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void krpcrt4G_RpcUserFree(std::uint64_t AsyncHandle, void* pBuffer) noexcept {
    // Refused: the RPC runtime.
    //
    // an RPC call is marshalled through a stub the MIDL compiler generated and
    // a format string it emitted; a runtime that answered one without a
    // transport and a binding would be answering from nowhere
    static_cast<void>(AsyncHandle);
    static_cast<void>(pBuffer);
    set_last_error(kNotImplemented);
}

}  // namespace

void add_generated_rpcrt4(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("DceErrorInqTextA", reinterpret_cast<void*>(&krpcrt4G_DceErrorInqTextA));
    e("DceErrorInqTextW", reinterpret_cast<void*>(&krpcrt4G_DceErrorInqTextW));
    e("DllGetClassObject", reinterpret_cast<void*>(&krpcrt4G_DllGetClassObject));
    e("IUnknown_AddRef_Proxy", reinterpret_cast<void*>(&krpcrt4G_IUnknown_AddRef_Proxy));
    e("IUnknown_QueryInterface_Proxy", reinterpret_cast<void*>(&krpcrt4G_IUnknown_QueryInterface_Proxy));
    e("IUnknown_Release_Proxy", reinterpret_cast<void*>(&krpcrt4G_IUnknown_Release_Proxy));
    e("I_RpcAllocate", reinterpret_cast<void*>(&krpcrt4G_I_RpcAllocate));
    e("I_RpcAsyncAbortCall", reinterpret_cast<void*>(&krpcrt4G_I_RpcAsyncAbortCall));
    e("I_RpcAsyncSetHandle", reinterpret_cast<void*>(&krpcrt4G_I_RpcAsyncSetHandle));
    e("I_RpcBindingCopy", reinterpret_cast<void*>(&krpcrt4G_I_RpcBindingCopy));
    e("I_RpcBindingHandleToAsyncHandle", reinterpret_cast<void*>(&krpcrt4G_I_RpcBindingHandleToAsyncHandle));
    e("I_RpcBindingInqConnId", reinterpret_cast<void*>(&krpcrt4G_I_RpcBindingInqConnId));
    e("I_RpcBindingInqDynamicEndpointA", reinterpret_cast<void*>(&krpcrt4G_I_RpcBindingInqDynamicEndpointA));
    e("I_RpcBindingInqDynamicEndpointW", reinterpret_cast<void*>(&krpcrt4G_I_RpcBindingInqDynamicEndpointW));
    e("I_RpcBindingInqLocalClientPID", reinterpret_cast<void*>(&krpcrt4G_I_RpcBindingInqLocalClientPID));
    e("I_RpcBindingInqMarshalledTargetInfo", reinterpret_cast<void*>(&krpcrt4G_I_RpcBindingInqMarshalledTargetInfo));
    e("I_RpcBindingInqSecurityContext", reinterpret_cast<void*>(&krpcrt4G_I_RpcBindingInqSecurityContext));
    e("I_RpcBindingInqTransportType", reinterpret_cast<void*>(&krpcrt4G_I_RpcBindingInqTransportType));
    e("I_RpcBindingInqWireIdForSnego", reinterpret_cast<void*>(&krpcrt4G_I_RpcBindingInqWireIdForSnego));
    e("I_RpcBindingIsClientLocal", reinterpret_cast<void*>(&krpcrt4G_I_RpcBindingIsClientLocal));
    e("I_RpcBindingToStaticStringBindingW", reinterpret_cast<void*>(&krpcrt4G_I_RpcBindingToStaticStringBindingW));
    e("I_RpcClearMutex", reinterpret_cast<void*>(&krpcrt4G_I_RpcClearMutex));
    e("I_RpcConnectionInqSockBuffSize", reinterpret_cast<void*>(&krpcrt4G_I_RpcConnectionInqSockBuffSize));
    e("I_RpcConnectionSetSockBuffSize", reinterpret_cast<void*>(&krpcrt4G_I_RpcConnectionSetSockBuffSize));
    e("I_RpcDeleteMutex", reinterpret_cast<void*>(&krpcrt4G_I_RpcDeleteMutex));
    e("I_RpcExceptionFilter", reinterpret_cast<void*>(&krpcrt4G_I_RpcExceptionFilter));
    e("I_RpcFree", reinterpret_cast<void*>(&krpcrt4G_I_RpcFree));
    e("I_RpcFreeBuffer", reinterpret_cast<void*>(&krpcrt4G_I_RpcFreeBuffer));
    e("I_RpcFreePipeBuffer", reinterpret_cast<void*>(&krpcrt4G_I_RpcFreePipeBuffer));
    e("I_RpcGetBuffer", reinterpret_cast<void*>(&krpcrt4G_I_RpcGetBuffer));
    e("I_RpcGetBufferWithObject", reinterpret_cast<void*>(&krpcrt4G_I_RpcGetBufferWithObject));
    e("I_RpcGetCurrentCallHandle", reinterpret_cast<void*>(&krpcrt4G_I_RpcGetCurrentCallHandle));
    e("I_RpcGetExtendedError", reinterpret_cast<void*>(&krpcrt4G_I_RpcGetExtendedError));
    e("I_RpcIfInqTransferSyntaxes", reinterpret_cast<void*>(&krpcrt4G_I_RpcIfInqTransferSyntaxes));
    e("I_RpcMapWin32Status", reinterpret_cast<void*>(&krpcrt4G_I_RpcMapWin32Status));
    e("I_RpcNegotiateTransferSyntax", reinterpret_cast<void*>(&krpcrt4G_I_RpcNegotiateTransferSyntax));
    e("I_RpcNsBindingSetEntryNameA", reinterpret_cast<void*>(&krpcrt4G_I_RpcNsBindingSetEntryNameA));
    e("I_RpcNsBindingSetEntryNameW", reinterpret_cast<void*>(&krpcrt4G_I_RpcNsBindingSetEntryNameW));
    e("I_RpcNsInterfaceExported", reinterpret_cast<void*>(&krpcrt4G_I_RpcNsInterfaceExported));
    e("I_RpcNsInterfaceUnexported", reinterpret_cast<void*>(&krpcrt4G_I_RpcNsInterfaceUnexported));
    e("I_RpcPauseExecution", reinterpret_cast<void*>(&krpcrt4G_I_RpcPauseExecution));
    e("I_RpcProxyNewConnection", reinterpret_cast<void*>(&krpcrt4G_I_RpcProxyNewConnection));
    e("I_RpcReallocPipeBuffer", reinterpret_cast<void*>(&krpcrt4G_I_RpcReallocPipeBuffer));
    e("I_RpcReceive", reinterpret_cast<void*>(&krpcrt4G_I_RpcReceive));
    e("I_RpcRecordCalloutFailure", reinterpret_cast<void*>(&krpcrt4G_I_RpcRecordCalloutFailure));
    e("I_RpcReplyToClientWithStatus", reinterpret_cast<void*>(&krpcrt4G_I_RpcReplyToClientWithStatus));
    e("I_RpcRequestMutex", reinterpret_cast<void*>(&krpcrt4G_I_RpcRequestMutex));
    e("I_RpcSend", reinterpret_cast<void*>(&krpcrt4G_I_RpcSend));
    e("I_RpcSendReceive", reinterpret_cast<void*>(&krpcrt4G_I_RpcSendReceive));
    e("I_RpcServerCheckClientRestriction", reinterpret_cast<void*>(&krpcrt4G_I_RpcServerCheckClientRestriction));
    e("I_RpcServerInqAddressChangeFn", reinterpret_cast<void*>(&krpcrt4G_I_RpcServerInqAddressChangeFn));
    e("I_RpcServerInqLocalConnAddress", reinterpret_cast<void*>(&krpcrt4G_I_RpcServerInqLocalConnAddress));
    e("I_RpcServerInqTransportType", reinterpret_cast<void*>(&krpcrt4G_I_RpcServerInqTransportType));
    e("I_RpcServerRegisterForwardFunction", reinterpret_cast<void*>(&krpcrt4G_I_RpcServerRegisterForwardFunction));
    e("I_RpcServerSetAddressChangeFn", reinterpret_cast<void*>(&krpcrt4G_I_RpcServerSetAddressChangeFn));
    e("I_RpcServerUseProtseq2A", reinterpret_cast<void*>(&krpcrt4G_I_RpcServerUseProtseq2A));
    e("I_RpcServerUseProtseq2W", reinterpret_cast<void*>(&krpcrt4G_I_RpcServerUseProtseq2W));
    e("I_RpcServerUseProtseqEp2A", reinterpret_cast<void*>(&krpcrt4G_I_RpcServerUseProtseqEp2A));
    e("I_RpcServerUseProtseqEp2W", reinterpret_cast<void*>(&krpcrt4G_I_RpcServerUseProtseqEp2W));
    e("I_RpcSessionStrictContextHandle", reinterpret_cast<void*>(&krpcrt4G_I_RpcSessionStrictContextHandle));
    e("I_RpcSsDontSerializeContext", reinterpret_cast<void*>(&krpcrt4G_I_RpcSsDontSerializeContext));
    e("I_RpcTurnOnEEInfoPropagation", reinterpret_cast<void*>(&krpcrt4G_I_RpcTurnOnEEInfoPropagation));
    e("I_UuidCreate", reinterpret_cast<void*>(&krpcrt4G_I_UuidCreate));
    e("NDRCContextBinding", reinterpret_cast<void*>(&krpcrt4G_NDRCContextBinding));
    e("NDRCContextMarshall", reinterpret_cast<void*>(&krpcrt4G_NDRCContextMarshall));
    e("NDRCContextUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NDRCContextUnmarshall));
    e("NDRSContextMarshall", reinterpret_cast<void*>(&krpcrt4G_NDRSContextMarshall));
    e("NDRSContextMarshall2", reinterpret_cast<void*>(&krpcrt4G_NDRSContextMarshall2));
    e("NDRSContextMarshallEx", reinterpret_cast<void*>(&krpcrt4G_NDRSContextMarshallEx));
    e("NDRSContextUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NDRSContextUnmarshall));
    e("NDRSContextUnmarshall2", reinterpret_cast<void*>(&krpcrt4G_NDRSContextUnmarshall2));
    e("NDRSContextUnmarshallEx", reinterpret_cast<void*>(&krpcrt4G_NDRSContextUnmarshallEx));
    e("Ndr64AsyncClientCall", reinterpret_cast<void*>(&krpcrt4G_Ndr64AsyncClientCall));
    e("Ndr64AsyncServerCall64", reinterpret_cast<void*>(&krpcrt4G_Ndr64AsyncServerCall64));
    e("Ndr64AsyncServerCallAll", reinterpret_cast<void*>(&krpcrt4G_Ndr64AsyncServerCallAll));
    e("Ndr64DcomAsyncClientCall", reinterpret_cast<void*>(&krpcrt4G_Ndr64DcomAsyncClientCall));
    e("Ndr64DcomAsyncStubCall", reinterpret_cast<void*>(&krpcrt4G_Ndr64DcomAsyncStubCall));
    e("NdrAllocate", reinterpret_cast<void*>(&krpcrt4G_NdrAllocate));
    e("NdrAsyncServerCall", reinterpret_cast<void*>(&krpcrt4G_NdrAsyncServerCall));
    e("NdrByteCountPointerBufferSize", reinterpret_cast<void*>(&krpcrt4G_NdrByteCountPointerBufferSize));
    e("NdrByteCountPointerFree", reinterpret_cast<void*>(&krpcrt4G_NdrByteCountPointerFree));
    e("NdrByteCountPointerMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrByteCountPointerMarshall));
    e("NdrByteCountPointerUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrByteCountPointerUnmarshall));
    e("NdrClearOutParameters", reinterpret_cast<void*>(&krpcrt4G_NdrClearOutParameters));
    e("NdrClientContextMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrClientContextMarshall));
    e("NdrClientContextUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrClientContextUnmarshall));
    e("NdrClientInitialize", reinterpret_cast<void*>(&krpcrt4G_NdrClientInitialize));
    e("NdrClientInitializeNew", reinterpret_cast<void*>(&krpcrt4G_NdrClientInitializeNew));
    e("NdrComplexArrayBufferSize", reinterpret_cast<void*>(&krpcrt4G_NdrComplexArrayBufferSize));
    e("NdrComplexArrayFree", reinterpret_cast<void*>(&krpcrt4G_NdrComplexArrayFree));
    e("NdrComplexArrayMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrComplexArrayMarshall));
    e("NdrComplexArrayMemorySize", reinterpret_cast<void*>(&krpcrt4G_NdrComplexArrayMemorySize));
    e("NdrComplexArrayUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrComplexArrayUnmarshall));
    e("NdrComplexStructBufferSize", reinterpret_cast<void*>(&krpcrt4G_NdrComplexStructBufferSize));
    e("NdrComplexStructFree", reinterpret_cast<void*>(&krpcrt4G_NdrComplexStructFree));
    e("NdrComplexStructMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrComplexStructMarshall));
    e("NdrComplexStructMemorySize", reinterpret_cast<void*>(&krpcrt4G_NdrComplexStructMemorySize));
    e("NdrComplexStructUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrComplexStructUnmarshall));
    e("NdrConformantArrayBufferSize", reinterpret_cast<void*>(&krpcrt4G_NdrConformantArrayBufferSize));
    e("NdrConformantArrayFree", reinterpret_cast<void*>(&krpcrt4G_NdrConformantArrayFree));
    e("NdrConformantArrayMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrConformantArrayMarshall));
    e("NdrConformantArrayMemorySize", reinterpret_cast<void*>(&krpcrt4G_NdrConformantArrayMemorySize));
    e("NdrConformantArrayUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrConformantArrayUnmarshall));
    e("NdrConformantStringBufferSize", reinterpret_cast<void*>(&krpcrt4G_NdrConformantStringBufferSize));
    e("NdrConformantStringMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrConformantStringMarshall));
    e("NdrConformantStringMemorySize", reinterpret_cast<void*>(&krpcrt4G_NdrConformantStringMemorySize));
    e("NdrConformantStringUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrConformantStringUnmarshall));
    e("NdrConformantStructBufferSize", reinterpret_cast<void*>(&krpcrt4G_NdrConformantStructBufferSize));
    e("NdrConformantStructFree", reinterpret_cast<void*>(&krpcrt4G_NdrConformantStructFree));
    e("NdrConformantStructMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrConformantStructMarshall));
    e("NdrConformantStructMemorySize", reinterpret_cast<void*>(&krpcrt4G_NdrConformantStructMemorySize));
    e("NdrConformantStructUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrConformantStructUnmarshall));
    e("NdrConformantVaryingArrayBufferSize", reinterpret_cast<void*>(&krpcrt4G_NdrConformantVaryingArrayBufferSize));
    e("NdrConformantVaryingArrayFree", reinterpret_cast<void*>(&krpcrt4G_NdrConformantVaryingArrayFree));
    e("NdrConformantVaryingArrayMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrConformantVaryingArrayMarshall));
    e("NdrConformantVaryingArrayMemorySize", reinterpret_cast<void*>(&krpcrt4G_NdrConformantVaryingArrayMemorySize));
    e("NdrConformantVaryingArrayUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrConformantVaryingArrayUnmarshall));
    e("NdrConformantVaryingStructBufferSize", reinterpret_cast<void*>(&krpcrt4G_NdrConformantVaryingStructBufferSize));
    e("NdrConformantVaryingStructFree", reinterpret_cast<void*>(&krpcrt4G_NdrConformantVaryingStructFree));
    e("NdrConformantVaryingStructMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrConformantVaryingStructMarshall));
    e("NdrConformantVaryingStructMemorySize", reinterpret_cast<void*>(&krpcrt4G_NdrConformantVaryingStructMemorySize));
    e("NdrConformantVaryingStructUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrConformantVaryingStructUnmarshall));
    e("NdrContextHandleInitialize", reinterpret_cast<void*>(&krpcrt4G_NdrContextHandleInitialize));
    e("NdrContextHandleSize", reinterpret_cast<void*>(&krpcrt4G_NdrContextHandleSize));
    e("NdrConvert", reinterpret_cast<void*>(&krpcrt4G_NdrConvert));
    e("NdrConvert2", reinterpret_cast<void*>(&krpcrt4G_NdrConvert2));
    e("NdrCorrelationFree", reinterpret_cast<void*>(&krpcrt4G_NdrCorrelationFree));
    e("NdrCorrelationInitialize", reinterpret_cast<void*>(&krpcrt4G_NdrCorrelationInitialize));
    e("NdrCorrelationPass", reinterpret_cast<void*>(&krpcrt4G_NdrCorrelationPass));
    e("NdrCreateServerInterfaceFromStub", reinterpret_cast<void*>(&krpcrt4G_NdrCreateServerInterfaceFromStub));
    e("NdrDcomAsyncClientCall", reinterpret_cast<void*>(&krpcrt4G_NdrDcomAsyncClientCall));
    e("NdrDcomAsyncStubCall", reinterpret_cast<void*>(&krpcrt4G_NdrDcomAsyncStubCall));
    e("NdrEncapsulatedUnionBufferSize", reinterpret_cast<void*>(&krpcrt4G_NdrEncapsulatedUnionBufferSize));
    e("NdrEncapsulatedUnionFree", reinterpret_cast<void*>(&krpcrt4G_NdrEncapsulatedUnionFree));
    e("NdrEncapsulatedUnionMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrEncapsulatedUnionMarshall));
    e("NdrEncapsulatedUnionMemorySize", reinterpret_cast<void*>(&krpcrt4G_NdrEncapsulatedUnionMemorySize));
    e("NdrEncapsulatedUnionUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrEncapsulatedUnionUnmarshall));
    e("NdrFixedArrayBufferSize", reinterpret_cast<void*>(&krpcrt4G_NdrFixedArrayBufferSize));
    e("NdrFixedArrayFree", reinterpret_cast<void*>(&krpcrt4G_NdrFixedArrayFree));
    e("NdrFixedArrayMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrFixedArrayMarshall));
    e("NdrFixedArrayMemorySize", reinterpret_cast<void*>(&krpcrt4G_NdrFixedArrayMemorySize));
    e("NdrFixedArrayUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrFixedArrayUnmarshall));
    e("NdrFullPointerFree", reinterpret_cast<void*>(&krpcrt4G_NdrFullPointerFree));
    e("NdrFullPointerInsertRefId", reinterpret_cast<void*>(&krpcrt4G_NdrFullPointerInsertRefId));
    e("NdrFullPointerQueryPointer", reinterpret_cast<void*>(&krpcrt4G_NdrFullPointerQueryPointer));
    e("NdrFullPointerQueryRefId", reinterpret_cast<void*>(&krpcrt4G_NdrFullPointerQueryRefId));
    e("NdrFullPointerXlatFree", reinterpret_cast<void*>(&krpcrt4G_NdrFullPointerXlatFree));
    e("NdrFullPointerXlatInit", reinterpret_cast<void*>(&krpcrt4G_NdrFullPointerXlatInit));
    e("NdrGetDcomProtocolVersion", reinterpret_cast<void*>(&krpcrt4G_NdrGetDcomProtocolVersion));
    e("NdrGetUserMarshalInfo", reinterpret_cast<void*>(&krpcrt4G_NdrGetUserMarshalInfo));
    e("NdrInterfacePointerBufferSize", reinterpret_cast<void*>(&krpcrt4G_NdrInterfacePointerBufferSize));
    e("NdrInterfacePointerFree", reinterpret_cast<void*>(&krpcrt4G_NdrInterfacePointerFree));
    e("NdrInterfacePointerMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrInterfacePointerMarshall));
    e("NdrInterfacePointerMemorySize", reinterpret_cast<void*>(&krpcrt4G_NdrInterfacePointerMemorySize));
    e("NdrInterfacePointerUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrInterfacePointerUnmarshall));
    e("NdrMapCommAndFaultStatus", reinterpret_cast<void*>(&krpcrt4G_NdrMapCommAndFaultStatus));
    e("NdrNonConformantStringBufferSize", reinterpret_cast<void*>(&krpcrt4G_NdrNonConformantStringBufferSize));
    e("NdrNonConformantStringMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrNonConformantStringMarshall));
    e("NdrNonConformantStringMemorySize", reinterpret_cast<void*>(&krpcrt4G_NdrNonConformantStringMemorySize));
    e("NdrNonConformantStringUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrNonConformantStringUnmarshall));
    e("NdrNonEncapsulatedUnionBufferSize", reinterpret_cast<void*>(&krpcrt4G_NdrNonEncapsulatedUnionBufferSize));
    e("NdrNonEncapsulatedUnionFree", reinterpret_cast<void*>(&krpcrt4G_NdrNonEncapsulatedUnionFree));
    e("NdrNonEncapsulatedUnionMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrNonEncapsulatedUnionMarshall));
    e("NdrNonEncapsulatedUnionMemorySize", reinterpret_cast<void*>(&krpcrt4G_NdrNonEncapsulatedUnionMemorySize));
    e("NdrNonEncapsulatedUnionUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrNonEncapsulatedUnionUnmarshall));
    e("NdrNsGetBuffer", reinterpret_cast<void*>(&krpcrt4G_NdrNsGetBuffer));
    e("NdrNsSendReceive", reinterpret_cast<void*>(&krpcrt4G_NdrNsSendReceive));
    e("NdrPartialIgnoreClientBufferSize", reinterpret_cast<void*>(&krpcrt4G_NdrPartialIgnoreClientBufferSize));
    e("NdrPartialIgnoreClientMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrPartialIgnoreClientMarshall));
    e("NdrPartialIgnoreServerInitialize", reinterpret_cast<void*>(&krpcrt4G_NdrPartialIgnoreServerInitialize));
    e("NdrPartialIgnoreServerUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrPartialIgnoreServerUnmarshall));
    e("NdrPointerBufferSize", reinterpret_cast<void*>(&krpcrt4G_NdrPointerBufferSize));
    e("NdrPointerFree", reinterpret_cast<void*>(&krpcrt4G_NdrPointerFree));
    e("NdrPointerMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrPointerMarshall));
    e("NdrPointerMemorySize", reinterpret_cast<void*>(&krpcrt4G_NdrPointerMemorySize));
    e("NdrPointerUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrPointerUnmarshall));
    e("NdrRangeUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrRangeUnmarshall));
    e("NdrRpcSmClientAllocate", reinterpret_cast<void*>(&krpcrt4G_NdrRpcSmClientAllocate));
    e("NdrRpcSmClientFree", reinterpret_cast<void*>(&krpcrt4G_NdrRpcSmClientFree));
    e("NdrRpcSmSetClientToOsf", reinterpret_cast<void*>(&krpcrt4G_NdrRpcSmSetClientToOsf));
    e("NdrRpcSsDefaultAllocate", reinterpret_cast<void*>(&krpcrt4G_NdrRpcSsDefaultAllocate));
    e("NdrRpcSsDefaultFree", reinterpret_cast<void*>(&krpcrt4G_NdrRpcSsDefaultFree));
    e("NdrRpcSsDisableAllocate", reinterpret_cast<void*>(&krpcrt4G_NdrRpcSsDisableAllocate));
    e("NdrRpcSsEnableAllocate", reinterpret_cast<void*>(&krpcrt4G_NdrRpcSsEnableAllocate));
    e("NdrServerCall2", reinterpret_cast<void*>(&krpcrt4G_NdrServerCall2));
    e("NdrServerCallAll", reinterpret_cast<void*>(&krpcrt4G_NdrServerCallAll));
    e("NdrServerCallNdr64", reinterpret_cast<void*>(&krpcrt4G_NdrServerCallNdr64));
    e("NdrServerContextMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrServerContextMarshall));
    e("NdrServerContextNewMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrServerContextNewMarshall));
    e("NdrServerContextNewUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrServerContextNewUnmarshall));
    e("NdrServerContextUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrServerContextUnmarshall));
    e("NdrServerInitialize", reinterpret_cast<void*>(&krpcrt4G_NdrServerInitialize));
    e("NdrServerInitializeMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrServerInitializeMarshall));
    e("NdrServerInitializeNew", reinterpret_cast<void*>(&krpcrt4G_NdrServerInitializeNew));
    e("NdrServerInitializePartial", reinterpret_cast<void*>(&krpcrt4G_NdrServerInitializePartial));
    e("NdrServerInitializeUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrServerInitializeUnmarshall));
    e("NdrSimpleStructBufferSize", reinterpret_cast<void*>(&krpcrt4G_NdrSimpleStructBufferSize));
    e("NdrSimpleStructFree", reinterpret_cast<void*>(&krpcrt4G_NdrSimpleStructFree));
    e("NdrSimpleStructMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrSimpleStructMarshall));
    e("NdrSimpleStructMemorySize", reinterpret_cast<void*>(&krpcrt4G_NdrSimpleStructMemorySize));
    e("NdrSimpleStructUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrSimpleStructUnmarshall));
    e("NdrSimpleTypeMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrSimpleTypeMarshall));
    e("NdrSimpleTypeUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrSimpleTypeUnmarshall));
    e("NdrStubCall2", reinterpret_cast<void*>(&krpcrt4G_NdrStubCall2));
    e("NdrStubCall3", reinterpret_cast<void*>(&krpcrt4G_NdrStubCall3));
    e("NdrUserMarshalBufferSize", reinterpret_cast<void*>(&krpcrt4G_NdrUserMarshalBufferSize));
    e("NdrUserMarshalFree", reinterpret_cast<void*>(&krpcrt4G_NdrUserMarshalFree));
    e("NdrUserMarshalMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrUserMarshalMarshall));
    e("NdrUserMarshalMemorySize", reinterpret_cast<void*>(&krpcrt4G_NdrUserMarshalMemorySize));
    e("NdrUserMarshalSimpleTypeConvert", reinterpret_cast<void*>(&krpcrt4G_NdrUserMarshalSimpleTypeConvert));
    e("NdrUserMarshalUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrUserMarshalUnmarshall));
    e("NdrVaryingArrayBufferSize", reinterpret_cast<void*>(&krpcrt4G_NdrVaryingArrayBufferSize));
    e("NdrVaryingArrayFree", reinterpret_cast<void*>(&krpcrt4G_NdrVaryingArrayFree));
    e("NdrVaryingArrayMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrVaryingArrayMarshall));
    e("NdrVaryingArrayMemorySize", reinterpret_cast<void*>(&krpcrt4G_NdrVaryingArrayMemorySize));
    e("NdrVaryingArrayUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrVaryingArrayUnmarshall));
    e("NdrXmitOrRepAsBufferSize", reinterpret_cast<void*>(&krpcrt4G_NdrXmitOrRepAsBufferSize));
    e("NdrXmitOrRepAsFree", reinterpret_cast<void*>(&krpcrt4G_NdrXmitOrRepAsFree));
    e("NdrXmitOrRepAsMarshall", reinterpret_cast<void*>(&krpcrt4G_NdrXmitOrRepAsMarshall));
    e("NdrXmitOrRepAsMemorySize", reinterpret_cast<void*>(&krpcrt4G_NdrXmitOrRepAsMemorySize));
    e("NdrXmitOrRepAsUnmarshall", reinterpret_cast<void*>(&krpcrt4G_NdrXmitOrRepAsUnmarshall));
    e("RpcAsyncAbortCall", reinterpret_cast<void*>(&krpcrt4G_RpcAsyncAbortCall));
    e("RpcAsyncCancelCall", reinterpret_cast<void*>(&krpcrt4G_RpcAsyncCancelCall));
    e("RpcAsyncCompleteCall", reinterpret_cast<void*>(&krpcrt4G_RpcAsyncCompleteCall));
    e("RpcAsyncRegisterInfo", reinterpret_cast<void*>(&krpcrt4G_RpcAsyncRegisterInfo));
    e("RpcBindingBind", reinterpret_cast<void*>(&krpcrt4G_RpcBindingBind));
    e("RpcBindingCopy", reinterpret_cast<void*>(&krpcrt4G_RpcBindingCopy));
    e("RpcBindingCreateA", reinterpret_cast<void*>(&krpcrt4G_RpcBindingCreateA));
    e("RpcBindingCreateW", reinterpret_cast<void*>(&krpcrt4G_RpcBindingCreateW));
    e("RpcBindingInqAuthClientA", reinterpret_cast<void*>(&krpcrt4G_RpcBindingInqAuthClientA));
    e("RpcBindingInqAuthClientExA", reinterpret_cast<void*>(&krpcrt4G_RpcBindingInqAuthClientExA));
    e("RpcBindingInqAuthClientExW", reinterpret_cast<void*>(&krpcrt4G_RpcBindingInqAuthClientExW));
    e("RpcBindingInqAuthClientW", reinterpret_cast<void*>(&krpcrt4G_RpcBindingInqAuthClientW));
    e("RpcBindingInqAuthInfoA", reinterpret_cast<void*>(&krpcrt4G_RpcBindingInqAuthInfoA));
    e("RpcBindingInqAuthInfoExA", reinterpret_cast<void*>(&krpcrt4G_RpcBindingInqAuthInfoExA));
    e("RpcBindingInqAuthInfoExW", reinterpret_cast<void*>(&krpcrt4G_RpcBindingInqAuthInfoExW));
    e("RpcBindingInqAuthInfoW", reinterpret_cast<void*>(&krpcrt4G_RpcBindingInqAuthInfoW));
    e("RpcBindingInqOption", reinterpret_cast<void*>(&krpcrt4G_RpcBindingInqOption));
    e("RpcBindingReset", reinterpret_cast<void*>(&krpcrt4G_RpcBindingReset));
    e("RpcBindingServerFromClient", reinterpret_cast<void*>(&krpcrt4G_RpcBindingServerFromClient));
    e("RpcBindingSetAuthInfoA", reinterpret_cast<void*>(&krpcrt4G_RpcBindingSetAuthInfoA));
    e("RpcBindingSetAuthInfoExA", reinterpret_cast<void*>(&krpcrt4G_RpcBindingSetAuthInfoExA));
    e("RpcBindingSetAuthInfoExW", reinterpret_cast<void*>(&krpcrt4G_RpcBindingSetAuthInfoExW));
    e("RpcBindingSetAuthInfoW", reinterpret_cast<void*>(&krpcrt4G_RpcBindingSetAuthInfoW));
    e("RpcBindingSetObject", reinterpret_cast<void*>(&krpcrt4G_RpcBindingSetObject));
    e("RpcBindingSetOption", reinterpret_cast<void*>(&krpcrt4G_RpcBindingSetOption));
    e("RpcBindingToStringBindingA", reinterpret_cast<void*>(&krpcrt4G_RpcBindingToStringBindingA));
    e("RpcBindingToStringBindingW", reinterpret_cast<void*>(&krpcrt4G_RpcBindingToStringBindingW));
    e("RpcBindingUnbind", reinterpret_cast<void*>(&krpcrt4G_RpcBindingUnbind));
    e("RpcBindingVectorFree", reinterpret_cast<void*>(&krpcrt4G_RpcBindingVectorFree));
    e("RpcCancelThread", reinterpret_cast<void*>(&krpcrt4G_RpcCancelThread));
    e("RpcCancelThreadEx", reinterpret_cast<void*>(&krpcrt4G_RpcCancelThreadEx));
    e("RpcEpRegisterA", reinterpret_cast<void*>(&krpcrt4G_RpcEpRegisterA));
    e("RpcEpRegisterNoReplaceA", reinterpret_cast<void*>(&krpcrt4G_RpcEpRegisterNoReplaceA));
    e("RpcEpRegisterNoReplaceW", reinterpret_cast<void*>(&krpcrt4G_RpcEpRegisterNoReplaceW));
    e("RpcEpRegisterW", reinterpret_cast<void*>(&krpcrt4G_RpcEpRegisterW));
    e("RpcEpResolveBinding", reinterpret_cast<void*>(&krpcrt4G_RpcEpResolveBinding));
    e("RpcEpUnregister", reinterpret_cast<void*>(&krpcrt4G_RpcEpUnregister));
    e("RpcErrorAddRecord", reinterpret_cast<void*>(&krpcrt4G_RpcErrorAddRecord));
    e("RpcErrorClearInformation", reinterpret_cast<void*>(&krpcrt4G_RpcErrorClearInformation));
    e("RpcErrorEndEnumeration", reinterpret_cast<void*>(&krpcrt4G_RpcErrorEndEnumeration));
    e("RpcErrorGetNextRecord", reinterpret_cast<void*>(&krpcrt4G_RpcErrorGetNextRecord));
    e("RpcErrorGetNumberOfRecords", reinterpret_cast<void*>(&krpcrt4G_RpcErrorGetNumberOfRecords));
    e("RpcErrorLoadErrorInfo", reinterpret_cast<void*>(&krpcrt4G_RpcErrorLoadErrorInfo));
    e("RpcErrorResetEnumeration", reinterpret_cast<void*>(&krpcrt4G_RpcErrorResetEnumeration));
    e("RpcErrorSaveErrorInfo", reinterpret_cast<void*>(&krpcrt4G_RpcErrorSaveErrorInfo));
    e("RpcErrorStartEnumeration", reinterpret_cast<void*>(&krpcrt4G_RpcErrorStartEnumeration));
    e("RpcFreeAuthorizationContext", reinterpret_cast<void*>(&krpcrt4G_RpcFreeAuthorizationContext));
    e("RpcGetAuthorizationContextForClient", reinterpret_cast<void*>(&krpcrt4G_RpcGetAuthorizationContextForClient));
    e("RpcIfInqId", reinterpret_cast<void*>(&krpcrt4G_RpcIfInqId));
    e("RpcMgmtEpEltInqBegin", reinterpret_cast<void*>(&krpcrt4G_RpcMgmtEpEltInqBegin));
    e("RpcMgmtEpEltInqDone", reinterpret_cast<void*>(&krpcrt4G_RpcMgmtEpEltInqDone));
    e("RpcMgmtEpEltInqNextA", reinterpret_cast<void*>(&krpcrt4G_RpcMgmtEpEltInqNextA));
    e("RpcMgmtEpEltInqNextW", reinterpret_cast<void*>(&krpcrt4G_RpcMgmtEpEltInqNextW));
    e("RpcMgmtEpUnregister", reinterpret_cast<void*>(&krpcrt4G_RpcMgmtEpUnregister));
    e("RpcMgmtInqComTimeout", reinterpret_cast<void*>(&krpcrt4G_RpcMgmtInqComTimeout));
    e("RpcMgmtInqDefaultProtectLevel", reinterpret_cast<void*>(&krpcrt4G_RpcMgmtInqDefaultProtectLevel));
    e("RpcMgmtInqServerPrincNameA", reinterpret_cast<void*>(&krpcrt4G_RpcMgmtInqServerPrincNameA));
    e("RpcMgmtInqServerPrincNameW", reinterpret_cast<void*>(&krpcrt4G_RpcMgmtInqServerPrincNameW));
    e("RpcMgmtInqStats", reinterpret_cast<void*>(&krpcrt4G_RpcMgmtInqStats));
    e("RpcMgmtSetAuthorizationFn", reinterpret_cast<void*>(&krpcrt4G_RpcMgmtSetAuthorizationFn));
    e("RpcMgmtSetComTimeout", reinterpret_cast<void*>(&krpcrt4G_RpcMgmtSetComTimeout));
    e("RpcMgmtSetServerStackSize", reinterpret_cast<void*>(&krpcrt4G_RpcMgmtSetServerStackSize));
    e("RpcMgmtStatsVectorFree", reinterpret_cast<void*>(&krpcrt4G_RpcMgmtStatsVectorFree));
    e("RpcNetworkInqProtseqsA", reinterpret_cast<void*>(&krpcrt4G_RpcNetworkInqProtseqsA));
    e("RpcNetworkInqProtseqsW", reinterpret_cast<void*>(&krpcrt4G_RpcNetworkInqProtseqsW));
    e("RpcNetworkIsProtseqValidA", reinterpret_cast<void*>(&krpcrt4G_RpcNetworkIsProtseqValidA));
    e("RpcNetworkIsProtseqValidW", reinterpret_cast<void*>(&krpcrt4G_RpcNetworkIsProtseqValidW));
    e("RpcNsBindingInqEntryNameA", reinterpret_cast<void*>(&krpcrt4G_RpcNsBindingInqEntryNameA));
    e("RpcNsBindingInqEntryNameW", reinterpret_cast<void*>(&krpcrt4G_RpcNsBindingInqEntryNameW));
    e("RpcObjectInqType", reinterpret_cast<void*>(&krpcrt4G_RpcObjectInqType));
    e("RpcObjectSetInqFn", reinterpret_cast<void*>(&krpcrt4G_RpcObjectSetInqFn));
    e("RpcObjectSetType", reinterpret_cast<void*>(&krpcrt4G_RpcObjectSetType));
    e("RpcProtseqVectorFreeA", reinterpret_cast<void*>(&krpcrt4G_RpcProtseqVectorFreeA));
    e("RpcProtseqVectorFreeW", reinterpret_cast<void*>(&krpcrt4G_RpcProtseqVectorFreeW));
    e("RpcRevertToSelfEx", reinterpret_cast<void*>(&krpcrt4G_RpcRevertToSelfEx));
    e("RpcServerInqBindingHandle", reinterpret_cast<void*>(&krpcrt4G_RpcServerInqBindingHandle));
    e("RpcServerInqBindings", reinterpret_cast<void*>(&krpcrt4G_RpcServerInqBindings));
    e("RpcServerInqCallAttributesA", reinterpret_cast<void*>(&krpcrt4G_RpcServerInqCallAttributesA));
    e("RpcServerInqCallAttributesW", reinterpret_cast<void*>(&krpcrt4G_RpcServerInqCallAttributesW));
    e("RpcServerInqDefaultPrincNameA", reinterpret_cast<void*>(&krpcrt4G_RpcServerInqDefaultPrincNameA));
    e("RpcServerInqDefaultPrincNameW", reinterpret_cast<void*>(&krpcrt4G_RpcServerInqDefaultPrincNameW));
    e("RpcServerInqIf", reinterpret_cast<void*>(&krpcrt4G_RpcServerInqIf));
    e("RpcServerRegisterAuthInfoA", reinterpret_cast<void*>(&krpcrt4G_RpcServerRegisterAuthInfoA));
    e("RpcServerRegisterAuthInfoW", reinterpret_cast<void*>(&krpcrt4G_RpcServerRegisterAuthInfoW));
    e("RpcServerSubscribeForNotification", reinterpret_cast<void*>(&krpcrt4G_RpcServerSubscribeForNotification));
    e("RpcServerTestCancel", reinterpret_cast<void*>(&krpcrt4G_RpcServerTestCancel));
    e("RpcServerUnregisterIfEx", reinterpret_cast<void*>(&krpcrt4G_RpcServerUnregisterIfEx));
    e("RpcServerUnsubscribeForNotification", reinterpret_cast<void*>(&krpcrt4G_RpcServerUnsubscribeForNotification));
    e("RpcServerUseAllProtseqs", reinterpret_cast<void*>(&krpcrt4G_RpcServerUseAllProtseqs));
    e("RpcServerUseAllProtseqsEx", reinterpret_cast<void*>(&krpcrt4G_RpcServerUseAllProtseqsEx));
    e("RpcServerUseAllProtseqsIf", reinterpret_cast<void*>(&krpcrt4G_RpcServerUseAllProtseqsIf));
    e("RpcServerUseAllProtseqsIfEx", reinterpret_cast<void*>(&krpcrt4G_RpcServerUseAllProtseqsIfEx));
    e("RpcServerUseProtseqA", reinterpret_cast<void*>(&krpcrt4G_RpcServerUseProtseqA));
    e("RpcServerUseProtseqEpExA", reinterpret_cast<void*>(&krpcrt4G_RpcServerUseProtseqEpExA));
    e("RpcServerUseProtseqEpExW", reinterpret_cast<void*>(&krpcrt4G_RpcServerUseProtseqEpExW));
    e("RpcServerUseProtseqExA", reinterpret_cast<void*>(&krpcrt4G_RpcServerUseProtseqExA));
    e("RpcServerUseProtseqExW", reinterpret_cast<void*>(&krpcrt4G_RpcServerUseProtseqExW));
    e("RpcServerUseProtseqIfA", reinterpret_cast<void*>(&krpcrt4G_RpcServerUseProtseqIfA));
    e("RpcServerUseProtseqIfExA", reinterpret_cast<void*>(&krpcrt4G_RpcServerUseProtseqIfExA));
    e("RpcServerUseProtseqIfExW", reinterpret_cast<void*>(&krpcrt4G_RpcServerUseProtseqIfExW));
    e("RpcServerUseProtseqIfW", reinterpret_cast<void*>(&krpcrt4G_RpcServerUseProtseqIfW));
    e("RpcServerUseProtseqW", reinterpret_cast<void*>(&krpcrt4G_RpcServerUseProtseqW));
    e("RpcServerYield", reinterpret_cast<void*>(&krpcrt4G_RpcServerYield));
    e("RpcSmAllocate", reinterpret_cast<void*>(&krpcrt4G_RpcSmAllocate));
    e("RpcSmClientFree", reinterpret_cast<void*>(&krpcrt4G_RpcSmClientFree));
    e("RpcSmDestroyClientContext", reinterpret_cast<void*>(&krpcrt4G_RpcSmDestroyClientContext));
    e("RpcSmDisableAllocate", reinterpret_cast<void*>(&krpcrt4G_RpcSmDisableAllocate));
    e("RpcSmEnableAllocate", reinterpret_cast<void*>(&krpcrt4G_RpcSmEnableAllocate));
    e("RpcSmFree", reinterpret_cast<void*>(&krpcrt4G_RpcSmFree));
    e("RpcSmGetThreadHandle", reinterpret_cast<void*>(&krpcrt4G_RpcSmGetThreadHandle));
    e("RpcSmSetClientAllocFree", reinterpret_cast<void*>(&krpcrt4G_RpcSmSetClientAllocFree));
    e("RpcSmSetThreadHandle", reinterpret_cast<void*>(&krpcrt4G_RpcSmSetThreadHandle));
    e("RpcSmSwapClientAllocFree", reinterpret_cast<void*>(&krpcrt4G_RpcSmSwapClientAllocFree));
    e("RpcSsContextLockExclusive", reinterpret_cast<void*>(&krpcrt4G_RpcSsContextLockExclusive));
    e("RpcSsContextLockShared", reinterpret_cast<void*>(&krpcrt4G_RpcSsContextLockShared));
    e("RpcSsDestroyClientContext", reinterpret_cast<void*>(&krpcrt4G_RpcSsDestroyClientContext));
    e("RpcSsDisableAllocate", reinterpret_cast<void*>(&krpcrt4G_RpcSsDisableAllocate));
    e("RpcSsDontSerializeContext", reinterpret_cast<void*>(&krpcrt4G_RpcSsDontSerializeContext));
    e("RpcSsEnableAllocate", reinterpret_cast<void*>(&krpcrt4G_RpcSsEnableAllocate));
    e("RpcSsGetContextBinding", reinterpret_cast<void*>(&krpcrt4G_RpcSsGetContextBinding));
    e("RpcSsGetThreadHandle", reinterpret_cast<void*>(&krpcrt4G_RpcSsGetThreadHandle));
    e("RpcSsSetClientAllocFree", reinterpret_cast<void*>(&krpcrt4G_RpcSsSetClientAllocFree));
    e("RpcSsSetThreadHandle", reinterpret_cast<void*>(&krpcrt4G_RpcSsSetThreadHandle));
    e("RpcSsSwapClientAllocFree", reinterpret_cast<void*>(&krpcrt4G_RpcSsSwapClientAllocFree));
    e("RpcTestCancel", reinterpret_cast<void*>(&krpcrt4G_RpcTestCancel));
    e("RpcUserFree", reinterpret_cast<void*>(&krpcrt4G_RpcUserFree));
}
}  // namespace occ::runtime::winabi

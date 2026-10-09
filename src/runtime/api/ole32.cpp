// The OLE32 surface: the apartment the process runs in.
//
// COM's apartment is a threading contract. A thread that calls
// `CoInitializeEx` declares which model it will follow, and every call the
// thread makes afterwards is marshalled according to that declaration. This
// runtime runs one guest thread, so the model is a single-threaded apartment
// -- the model a one-threaded program must use, and the only one that needs
// no marshalling, because there is nobody to marshal to.
//
// Three of the four calls below are therefore about a piece of state that
// has exactly one interesting value, and each answers it rather than
// refusing: a program that initialises COM and then asks which apartment it
// got expects to be told, and "single-threaded" is the true answer for a
// program with one thread.
//
// The fourth, `CoWaitForMultipleHandles`, is not bookkeeping: it is a wait,
// and it waits on this runtime's own objects -- the same objects
// `WaitForMultipleObjects` waits on, through the same implementation. A
// second wait built on the host's descriptors would not see an event this
// runtime signalled, and the two spellings of "wait for these handles" have
// to agree about what a handle is.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstdint>

namespace occ::runtime::winabi {

// The wait this file reuses. It is the same wait the synchronization domain
// provides, reached by name so that both spellings of the operation are one
// operation.
extern "C" __attribute__((ms_abi)) std::uint32_t k32s_WaitForMultipleObjects(
    std::uint32_t count, const std::uint64_t* handles, std::int32_t wait_all,
    std::uint32_t milliseconds) noexcept;

namespace {

// The apartment types and the qualifier that goes with them. A
// single-threaded apartment is the main one when it is the process's first,
// which this runtime's is.
constexpr std::uint32_t kApartmentMainSta = 3;
constexpr std::uint32_t kApartmentSta = 0;
constexpr std::uint32_t kApartmentQualifierNone = 0;

// The initialisation flags a caller may pass. Only the apartment model bits
// matter here; the rest select behaviours this runtime does not vary.
constexpr std::uint32_t kApartmentModelMask = 0x7FFu;
constexpr std::uint32_t kApartmentThreaded = 0x0u;
constexpr std::uint32_t kApartmentSingleThreaded = 0x2u;

// The HRESULTs the calls answer. `RPC_E_CHANGED_MODE` is the one a caller
// acts on: it means the thread was already in an apartment of the other
// model, and the caller has to keep using the one it has.
// The three this surface adds to the shared set. `kSOk`, `kSFalse`,
// `kEFail` and `kEInvalidArg` are the support layer's, and are not repeated
// here: two definitions of one status is two values a caller could compare
// against and get different answers from.
constexpr Hresult kRpcChangedMode = static_cast<Hresult>(0x80010106u);
constexpr Hresult kRpcCallPending = static_cast<Hresult>(0x80010115u);
constexpr Hresult kCoNotInitialized = static_cast<Hresult>(0x800401F0u);

// How many times COM has been initialised on this thread, and in which
// model. The count is what makes a second initialisation cheap and an
// unmatched uninitialise harmless, which is what a library that initialises
// COM for its own use relies on.
std::uint32_t g_initialize_count = 0;
std::uint32_t g_apartment_model = kApartmentSingleThreaded;

}  // namespace

extern "C" __attribute__((ms_abi)) Hresult k32ole_CoInitializeEx(
    void* reserved, std::uint32_t model) noexcept {
    // The reserved pointer must be null, and it is not decoration: a
    // non-null value is a caller that built its arguments from a different
    // version of the contract, and accepting it would carry on with a
    // layout neither side agrees on.
    if (reserved != nullptr) {
        return kEInvalidArg;
    }
    const std::uint32_t wanted = model & kApartmentModelMask;
    if (wanted == kApartmentThreaded) {
        // A multi-threaded apartment is a threading model this runtime
        // cannot honour: an object entered from another thread would need
        // the marshalling the model exists to avoid, and there is no second
        // thread here to do it.
        return kRpcChangedMode;
    }
    if (wanted != kApartmentSingleThreaded) {
        return kEInvalidArg;
    }
    if (g_initialize_count != 0 && wanted != g_apartment_model) {
        // The thread is already in an apartment of the other model. The
        // caller is told to keep using what it has rather than being moved:
        // switching under it would invalidate every object it already holds.
        return kRpcChangedMode;
    }
    ++g_initialize_count;
    g_apartment_model = wanted;
    // A success that is not `S_OK` says the call did something other than
    // initialise: `S_FALSE` is what a second call answers, and a caller that
    // matches on `S_OK` uses it to decide whether to uninitialise.
    return g_initialize_count == 1 ? kSOk : kSFalse;
}

extern "C" __attribute__((ms_abi)) void k32ole_CoUninitialize(void) noexcept {
    if (g_initialize_count != 0) {
        --g_initialize_count;
    }
    // The model is left as it was rather than cleared: an unmatched
    // uninitialise must not be able to change what the thread declared, and
    // the next initialise is what sets it again.
}

extern "C" __attribute__((ms_abi)) Hresult k32ole_CoGetApartmentType(
    std::uint32_t* type, std::uint32_t* qualifier) noexcept {
    if (type == nullptr || qualifier == nullptr) {
        return kEInvalidArg;
    }
    if (g_initialize_count == 0) {
        // COM was never initialised on this thread, so there is no apartment
        // to describe. `CO_E_NOTINITIALIZED` is what the call answers, and a
        // caller that checks it learns it forgot to initialise rather than
        // being handed a type it never asked for.
        return kCoNotInitialized;
    }
    *type = g_apartment_model == kApartmentSingleThreaded ? kApartmentMainSta
                                                          : kApartmentSta;
    *qualifier = kApartmentQualifierNone;
    return kSOk;
}

extern "C" __attribute__((ms_abi)) Hresult k32ole_CoWaitForMultipleHandles(
    std::uint32_t flags, std::uint32_t timeout, std::uint32_t count,
    const std::uint64_t* handles, std::uint32_t* index) noexcept {
    static_cast<void>(flags);
    if (handles == nullptr || index == nullptr) {
        return kEInvalidArg;
    }
    *index = 0;
    const std::uint32_t waited =
        k32s_WaitForMultipleObjects(count, handles, 0, timeout);
    // The wait's own answers, translated into the HRESULT this call
    // promises. `WAIT_OBJECT_0` and up name the handle that was signalled,
    // which is an index into the caller's array; the two failures are
    // distinguished because a caller retries one and reports the other.
    constexpr std::uint32_t kWaitTimeout = 258;
    constexpr std::uint32_t kWaitFailed = 0xFFFFFFFFu;
    if (waited == kWaitFailed) {
        return kEFail;
    }
    if (waited == kWaitTimeout) {
        // Nothing was signalled in time. `RPC_S_CALLPENDING` is the
        // documented answer for this call, and a caller distinguishes it
        // from a failure by testing the HRESULT rather than the wait code.
        return kRpcCallPending;
    }
    // The successful answer is `WAIT_OBJECT_0 + i`, so the index is the
    // answer minus the base. The comparison is written as a range test so
    // that an answer outside it -- which only a broken wait could produce --
    // is caught here rather than becoming a wild index in the caller.
    if (waited >= count) {
        return kEFail;
    }
    *index = waited;
    return kSOk;
}

// ------------------------------------------------------------- registration

void add_ole32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("CoGetApartmentType",
      reinterpret_cast<void*>(&k32ole_CoGetApartmentType));
    e("CoInitializeEx", reinterpret_cast<void*>(&k32ole_CoInitializeEx));
    e("CoUninitialize", reinterpret_cast<void*>(&k32ole_CoUninitialize));
    e("CoWaitForMultipleHandles",
      reinterpret_cast<void*>(&k32ole_CoWaitForMultipleHandles));
}

}  // namespace occ::runtime::winabi

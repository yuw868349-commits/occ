// The shapes the API domains share, so that a domain writes its decision
// rather than its marshalling.
//
// The entries under `src/runtime/api/` are one area each: a family of
// functions with one behaviour between them, its own file and its own test.
// What that split buys is independence, and what it costs is repetition --
// every family needs the same four things, and writing them again in each
// file is how two families end up disagreeing about what an `INVALID_HANDLE`
// is or how a `W` entry point marshals its `A` counterpart.
//
// This file is the answer to that repetition. It holds:
//
//   * the error codes, as named constants rather than literals. A family
//     that writes `87` is a family whose failure a reader has to look up;
//     one that writes `kErrorInvalidParameter` states it.
//   * the narrow/Wide string bridge, so an `A` entry point is written once
//     as a marshalling wrapper over the `W` answer rather than as a second
//     implementation that can disagree with it.
//   * the buffer conventions: Windows reports the size it needs rather than
//     failing, and which of the two spellings of "too small" a family uses
//     is a property of the family, not of the author.
//   * the structure layouts, as byte offsets. The guest's structures are
//     the Windows ones, and this host's compiler will not lay them out the
//     way the Windows headers do, so every writer lays them out by hand
//     against offsets declared here.
//
// Nothing here decides anything a caller could observe as behaviour. These
// are the names, the conversions and the layouts; the decisions stay in the
// domain that owns them, where its test can reach them.

#ifndef OCC_RUNTIME_API_COMMON_H
#define OCC_RUNTIME_API_COMMON_H

#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace occ::runtime::winabi {

// ---------------------------------------------------------------- error codes
//
// The subset the API families set and read. These are the values
// `GetLastError` answers, so a wrong one here is a wrong answer to a guest
// rather than a wrong number in a log.

// The success sentinel, and the value `GetLastError` is defined to leave
// alone: a guest that reads it before any call has failed must not be told
// that something did.
constexpr std::uint32_t kErrorSuccess = 0;

constexpr std::uint32_t kErrorInvalidFunction = 1;
constexpr std::uint32_t kErrorFileNotFound = 2;
constexpr std::uint32_t kErrorPathNotFound = 3;
constexpr std::uint32_t kErrorTooManyOpenFiles = 4;
constexpr std::uint32_t kErrorAccessDenied = 5;
constexpr std::uint32_t kErrorInvalidHandle = 6;
constexpr std::uint32_t kErrorNotEnoughMemory = 8;
constexpr std::uint32_t kErrorInvalidParameter = 87;
constexpr std::uint32_t kErrorNoMoreFiles = 18;
constexpr std::uint32_t kErrorAlreadyExists = 183;
constexpr std::uint32_t kErrorDirectoryNotEmpty = 145;
constexpr std::uint32_t kErrorNotSupported = 50;
constexpr std::uint32_t kErrorInsufficientBuffer = 122;
constexpr std::uint32_t kErrorNoMoreItems = 259;
constexpr std::uint32_t kErrorNotFound = 1168;
constexpr std::uint32_t kErrorCallNotImplemented = 120;
constexpr std::uint32_t kErrorInvalidAddress = 487;
constexpr std::uint32_t kErrorBadExeFormat = 193;
constexpr std::uint32_t kErrorBusy = 170;

// `HRESULT` as the guest sees it: a signed 32-bit code where the high bit
// says failure. `S_OK` is zero, `S_FALSE` is one, `E_FAIL` is
// `0x80004005`, and `E_INVALIDARG` is `0x80070057`. Naming them as the
// hexadecimal they are on the wire is what keeps a reader from having to
// know the encoding.
using Hresult = std::int32_t;

constexpr Hresult kSOk = 0;
constexpr Hresult kSFalse = 1;
constexpr Hresult kEFail = static_cast<Hresult>(0x80004005u);
constexpr Hresult kEInvalidArg = static_cast<Hresult>(0x80070057u);
constexpr Hresult kEOutOfMemory = static_cast<Hresult>(0x8007000Eu);
constexpr Hresult kENoInterface = static_cast<Hresult>(0x80004002u);
constexpr Hresult kEHandle = static_cast<Hresult>(0x80070006u);
constexpr Hresult kEUnexpected = static_cast<Hresult>(0x8000FFFFu);
constexpr Hresult kEInvalidState = static_cast<Hresult>(0x80001313u);
constexpr Hresult kEBufferTooSmall = static_cast<Hresult>(0x8007007Au);
constexpr Hresult kEAccessDenied = static_cast<Hresult>(0x80070005u);
constexpr Hresult kEAbi = static_cast<Hresult>(0x80000001u);
constexpr Hresult kEClassNotAvailable = static_cast<Hresult>(0x80040111u);
constexpr Hresult kERegistry = static_cast<Hresult>(0x800401FEu);
constexpr Hresult kEPathNotFound = static_cast<Hresult>(0x80070003u);
constexpr Hresult kEFileNotFound = static_cast<Hresult>(0x80070002u);
constexpr Hresult kEFileExists = static_cast<Hresult>(0x80070050u);
constexpr Hresult kEDataError = static_cast<Hresult>(0x80080003u);

[[nodiscard]] constexpr bool failed(Hresult value) noexcept {
    return value < 0;
}

// ----------------------------------------------------------------- the bridge
//
// The Windows string pair. An `A` entry point and a `W` entry point are the
// same function with different spellings of the text, so they are written
// that way here: the `W` form carries the decision, and the `A` form
// converts in and out and delegates. A family that implements both
// separately has two implementations to keep in agreement and no test that
// can tell when they disagree.

// The Narrow side of a family: what an `A` entry point needs from a `W` one.
// A function answers whether it could do the work at all, which is
// `false` when the input was not valid text in this encoding -- and that is
// a different answer from a failure of the underlying call, because the
// caller's buffer was never touched.
struct AnsiResult {
    bool converted = false;
    Hresult status = kSOk;
};

// Narrow to Wide, for the direction an `A` entry point marshals its input.
[[nodiscard]] AnsiResult narrow_in(std::string_view text,
                                   std::u16string& out) noexcept;

// Wide to Narrow, for the direction one marshals an output back. A `W` entry
// point that returns a buffer writes it in UTF-16 and the `A` form has to
// hand the caller back bytes, which is this conversion and nothing else.
[[nodiscard]] AnsiResult narrow_out(std::u16string_view text,
                                    std::string& out) noexcept;

// The same two directions for a string the caller owns and the entry point
// fills. Windows spells this "the buffer, the size, and how much went in",
// and the count is the number of characters written, terminator included --
// so these return what the caller has to report rather than a bool.
[[nodiscard]] std::size_t narrow_length(std::u16string_view text) noexcept;

// ------------------------------------------------------------------ buffers
//
// Windows has two ways to answer "your buffer is too small" and a family
// picks one: return the size it needs and touch nothing, or fail and set
// the error. `GetFullPathName` returns the size; `GetModuleFileName`
// truncates. These helpers name the difference so that the choice in a
// family is visible in the family rather than implied by it.

// Copies `text` into `buffer` when it fits and reports the length the
// caller should have provided.
//
// The count returned includes the terminator, because that is what the
// Windows spellings return and a caller that adds one itself gets the
// answer off by one exactly once, in the case that is hardest to see.
[[nodiscard]] std::size_t required_capacity(std::u16string_view text) noexcept;

// True when `capacity` elements are enough for `text`, terminator included.
[[nodiscard]] bool fits(std::u16string_view text,
                        std::size_t capacity) noexcept;

// The narrow form of the same question.
[[nodiscard]] std::size_t required_capacity(std::string_view text) noexcept;
[[nodiscard]] bool fits(std::string_view text,
                        std::size_t capacity) noexcept;

// ------------------------------------------------------- structure layouts
//
// The guest's structures, by byte offset.
//
// This host's compiler lays a structure out by this platform's rules, and
// the guest's are the Windows ones. For most of the names below the two
// agree, which is why only the ones that disagree appear. A writer that
// used this host's `sizeof` for a guest structure would be wrong on any
// field after a padding difference, and the difference is invisible in the
// host's debugger, which is what makes it worth naming.

// SYSTEMTIME, 16 bytes on the 64-bit ABI: five 16-bit calendar fields, then
// three 32-bit ones. No padding is involved and no host type matches it, so
// every field is placed by hand.
struct SystemTimeLayout {
    static constexpr std::size_t kYear = 0;          // uint16
    static constexpr std::size_t kMonth = 2;         // uint16
    static constexpr std::size_t kDayOfWeek = 4;     // uint16
    static constexpr std::size_t kDay = 6;           // uint16
    static constexpr std::size_t kHour = 8;          // uint16
    static constexpr std::size_t kMinute = 10;       // uint16
    static constexpr std::size_t kSecond = 12;       // uint16
    static constexpr std::size_t kMilliseconds = 14; // uint16
    static constexpr std::size_t kBytes = 16;
};

// FILETIME, 8 bytes: two 32-bit halves of one 64-bit count from 1601.
struct FileTimeLayout {
    static constexpr std::size_t kLow = 0;
    static constexpr std::size_t kHigh = 4;
    static constexpr std::size_t kBytes = 8;
};

// The `OVERLAPPED` the asynchronous calls take, 32 bytes on the 64-bit ABI:
// four pointer-sized fields, then a pointer to the event. A host `bool`
// where the guest has a `BOOL` is the difference this list exists to stop.
struct OverlappedLayout {
    static constexpr std::size_t kInternal = 0;
    static constexpr std::size_t kInternalHigh = 8;
    static constexpr std::size_t kOffset = 16;
    static constexpr std::size_t kOffsetHigh = 24;
    static constexpr std::size_t kEvent = 32;
    static constexpr std::size_t kBytes = 40;
};

// ------------------------------------------------------------ small writers
//
// Structure fields are read and written through these, so that one
// mistake -- a host `bool` where the guest has a 32-bit `BOOL`, an offset
// taken as a `char*` -- is made once rather than once per family.

// Reads a `DWORD` out of a guest structure.
[[nodiscard]] std::uint32_t read_u32(const void* base,
                                     std::size_t offset) noexcept;
void write_u32(void* base, std::size_t offset,
               std::uint32_t value) noexcept;

// Reads and writes a pointer-width field.
[[nodiscard]] std::uint64_t read_ptr(const void* base,
                                     std::size_t offset) noexcept;
void write_ptr(void* base, std::size_t offset,
               std::uint64_t value) noexcept;

// Reads and writes a `WORD`.
[[nodiscard]] std::uint16_t read_u16(const void* base,
                                     std::size_t offset) noexcept;
void write_u16(void* base, std::size_t offset,
               std::uint16_t value) noexcept;

// ----------------------------------------------------------------- handle
//
// The handle a family hands out and recognises. `INVALID_HANDLE_VALUE` is
// the all-ones pointer, which is neither null nor any index -- the choice
// is what makes a zero handle mean "no handle" the way Windows means it, and
// getting it wrong makes every `if (handle)` in a guest mean the opposite
// of what it says.
constexpr std::uint64_t kInvalidHandleValue = ~std::uint64_t(0);
constexpr std::uint64_t kInvalidHandle = 0;

}  // namespace occ::runtime::winabi

#endif  // OCC_RUNTIME_API_COMMON_H
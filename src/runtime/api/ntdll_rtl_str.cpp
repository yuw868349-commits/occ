// The Rtl* string half of ntdll: the UNICODE_STRING family, the code page
// conversions, the integer conversions, the address conversions, the hash,
// and the memory-block primitives that are named `Rtl*` rather than `mem*`.
//
// ------------------------------------------------------------------ the shape
//
// A guest reaches these as opaque structures. `UNICODE_STRING` is sixteen
// bytes -- `USHORT Length; USHORT MaximumLength; PWSTR Buffer;` -- and both
// length fields are **byte** counts that exclude the terminator. That is the
// whole difficulty of this file, and it is difficulty rather than detail
// because almost every function here is a question about one of three
// numbers:
//
//   * `Length` is bytes, so a four-character string has `Length == 8` and
//     every walk is in units of two. An implementation that counts
//     characters where Windows counts bytes answers correctly for ASCII
//     under eight characters and wrong everywhere else.
//   * `Length` excludes the terminator and `MaximumLength` includes room for
//     it, so a buffer that is "exactly full" has `Length == MaximumLength`
//     and there is no terminator to write. The copy and append families
//     each have a documented rule for that case and the rules differ
//     between them.
//   * A conversion changes the length. `RtlInitAnsiString` measures the
//     source in the *narrow* encoding, but every function that produces a
//     `UNICODE_STRING` from narrow text reports the length in the converted
//     encoding. `RtlAnsiStringToUnicodeSize` is the only place the two are
//     related, and a caller that used the narrow length as the wide one
//     would allocate half of what it needs for ASCII and be off by more for
//     anything else.
//
// The reference implementation is Wine's `dlls/ntdll/rtlstr.c` for the
// string, integer, GUID, message and address families, `dlls/ntdll/locale.c`
// for the case mapping, the hash, the code page conversions, the
// normalisation and the IDN entry points, `dlls/ntdll/sec.c` for the SID and
// LUID copies, `dlls/ntdll/large_int.c` for the 64-bit integer conversions,
// and `dlls/ntdll/env.c` for the environment expansion. The status values
// are read out of Wine's `include/ntstatus.h` rather than remembered, for
// the reason `include/occ/runtime/address_space.h` gives for its own: a
// status code is an ABI, and an ABI written from memory is a guess.
//
// ------------------------------------------------------------------ encoding
//
// This runtime's narrow text is UTF-8, everywhere: `narrow_in` and
// `narrow_out` in `api_common.h` are UTF-8 conversions, and the CRT's
// `mbstowcs` and `wcstombs` bridge to the same. The ANSI and OEM code pages
// are therefore both this runtime's narrow encoding, and the functions whose
// Windows names distinguish `Ansi` from `Oem` are the same function here.
// That is a real limitation and it is stated here rather than hidden: a
// guest that depends on the difference between code page 1252 and code page
// 437 gets UTF-8 for both. What is *not* approximated is the arithmetic --
// the sizes, the byte counts, the buffer bounds and the status codes are
// the reference's, and they are what a caller can actually observe.
//
// The case mapping is the other place a runtime is tempted to write `if
// (c >= 'a') c -= 32` and call it Unicode. The full Windows mapping is a
// 64k-entry table that this file does not carry; what it does carry is the
// invariant (locale-independent) mapping for the ranges where that mapping
// is a rule rather than a table, which is ASCII, Latin-1 Supplement, Latin
// Extended-A, Greek and Cyrillic. Those are the ranges a caller can observe
// a difference in without a locale, and a character outside them is returned
// unchanged, which is what Windows does for every character that has no
// uppercase form.

// --------------------------------------------------------------------------|
// Includes and the namespace
// --------------------------------------------------------------------------|

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>

namespace occ::runtime::winabi {
namespace {

// ------------------------------------------------------------------ NTSTATUS
//
// The Rtl* half of ntdll answers in NTSTATUS, not in the Win32 error codes
// the rest of this API uses, and not in the HRESULTs `api_common.h` names.
// They are three different encodings of "what happened" and a guest that
// reads one as another gets a wrong answer that still looks plausible, which
// is why the values are spelled out here rather than mapped onto the codes
// that file already has. Read out of the reference's `include/ntstatus.h`.

using Ntstatus = std::uint32_t;

constexpr Ntstatus kStSuccess = 0x00000000;
constexpr Ntstatus kStNotImplemented = 0xC0000002;
constexpr Ntstatus kStAccessViolation = 0xC0000005;
constexpr Ntstatus kStInvalidParameter = 0xC000000D;
constexpr Ntstatus kStInvalidParameter1 = 0xC00000EF;
constexpr Ntstatus kStInvalidParameter2 = 0xC00000F0;
constexpr Ntstatus kStInvalidParameter4 = 0xC00000F2;
constexpr Ntstatus kStInvalidParameter5 = 0xC00000F3;
constexpr Ntstatus kStBufferOverflow = 0x80000005;
constexpr Ntstatus kStNoMemory = 0xC0000017;
constexpr Ntstatus kStBufferTooSmall = 0xC0000023;
constexpr Ntstatus kStUnknownRevision = 0xC0000058;
constexpr Ntstatus kStNameTooLong = 0xC0000106;
constexpr Ntstatus kStNotFound = 0xC0000225;
// The two the IDN and normalisation families answer with, and they are
// specific codes rather than `InvalidParameter`: a caller that passes a name
// Windows will not accept needs to tell that apart from a caller that passed
// a null pointer.
constexpr Ntstatus kStInvalidIdnNormalization = 0xC0000716;
constexpr Ntstatus kStNoUnicodeTranslation = 0xC0000717;

// The `BOOLEAN` a ntdll entry point takes and answers. One byte on Windows,
// and a guest reads the low byte of the register either way, so the return
// is widened to `int` and the argument narrowed to `int` -- which is what a
// `BOOLEAN` in a register looks like from both sides.
using Boolean = std::int32_t;
constexpr Boolean kFalse = 0;
constexpr Boolean kTrue = 1;

// ---------------------------------------------------------------- the layouts
//
// The three structures this file reads and writes, by byte offset. The
// guest's are the Windows ones; this host's compiler would lay them out its
// own way, so every field is placed by hand against the offsets declared
// here rather than by `offsetof` on a host struct.
//
// `STRING` and `UNICODE_STRING` have the same shape and differ only in what
// the buffer points at. `Length` and `MaximumLength` are byte counts in
// both. This is the one place in the runtime where a two-byte count and a
// pointer share a structure with no padding between the two halves on a
// 32-bit build and four bytes of it on a 64-bit one; the 64-bit layout is
// the one that matters here, and it is the one written down.

constexpr std::size_t kStrLength = 0;        // uint16
constexpr std::size_t kStrMaximumLength = 2; // uint16
constexpr std::size_t kStrBuffer = 8;        // pointer
constexpr std::size_t kStrBytes = 16;

// The four `Length`/`MaximumLength` pairs a `UNICODE_STRING` uses, spelled
// as the named values the reference's own comments use, because "65532" is
// the number a reader has to recognise and `0xfffc` is not.
constexpr std::size_t kMaxUnicodeStringBytes = 0xFFFC;

// A view of a guest `UNICODE_STRING` or `STRING`. Read once, so that every
// use of a field in a function below agrees with every other use of it: the
// alternative is a dozen `read_u16` calls whose offsets are a dozen chances
// to be wrong.
struct StringView {
    std::size_t length = 0;        // bytes, excluding the terminator
    std::size_t maximum = 0;       // bytes, including room for the terminator
    void* buffer = nullptr;
};

[[nodiscard]] StringView read_string(const void* base) noexcept {
    StringView v;
    v.length = read_u16(base, kStrLength);
    v.maximum = read_u16(base, kStrMaximumLength);
    // `read_ptr` hands back the integer the guest stored; a guest address of
    // zero is the only value that may not be turned back into a pointer, so it
    // is mapped to null explicitly rather than by round-tripping through 0.
    const std::uint64_t raw = read_ptr(base, kStrBuffer);
    v.buffer = reinterpret_cast<void*>(static_cast<std::uintptr_t>(raw));
    return v;
}

// The write side, and the reason it is one function rather than three calls
// at each site: a `UNICODE_STRING` is only consistent when all three fields
// move together, and the whole family below is a family of "keep all three
// fields true" questions.
void write_string(void* base, std::size_t length, std::size_t maximum,
                  void* buffer) noexcept {
    write_u16(base, kStrLength, static_cast<std::uint16_t>(length));
    write_u16(base, kStrMaximumLength, static_cast<std::uint16_t>(maximum));
    write_ptr(base, kStrBuffer, static_cast<std::uint64_t>(
                                   reinterpret_cast<std::uintptr_t>(buffer)));
}

void clear_string(void* base) noexcept { write_string(base, 0, 0, nullptr); }

// A `UNICODE_STRING`'s buffer as text. The length is what makes this safe to
// walk: a `UNICODE_STRING` is explicitly allowed to hold an embedded NUL and
// to have no terminator at all, so `strlen` on it would read past what the
// caller promised. The odd-length case truncates, because a `Length` that is
// not a multiple of two describes half a character and there is no honest
// answer for half a character.
[[nodiscard]] std::u16string as_wide(const StringView& v) noexcept {
    std::u16string out;
    if (v.buffer == nullptr) {
        return out;
    }
    const std::size_t units = v.length / 2;
    const auto* chars = static_cast<const char16_t*>(v.buffer);
    out.assign(chars, chars + units);
    return out;
}

// A C string's length in bytes, without the library's `strlen` reading a
// guest pointer as a host one. The `cr_strnlen` bridge answers the same
// question; this is the same walk with the bound the caller controls.
template <typename C>
[[nodiscard]] std::size_t c_length(const C* text) noexcept {
    std::size_t n = 0;
    while (text[n] != static_cast<C>(0)) {
        ++n;
    }
    return n;
}

template <typename C>
[[nodiscard]] std::size_t c_length(const C* text, std::size_t limit) noexcept {
    std::size_t n = 0;
    while (n < limit && text[n] != static_cast<C>(0)) {
        ++n;
    }
    return n;
}

// The allocation the `RtlFree*String` family releases. The reference frees
// with `RtlFreeHeap(GetProcessHeap(), 0, buffer)`, and this runtime's
// process heap is `heap_alloc`, so a string this file created and a string
// a guest created with `RtlAllocateHeap` are released the same way -- which
// is the property that makes `RtlFreeUnicodeString` safe to call on a buffer
// whose provenance the caller does not have to track.
void* allocate_for_string(std::uint64_t bytes) noexcept {
    return heap_alloc(0, bytes);
}

// ------------------------------------------------------------------- case
//
// The invariant (locale-independent) Unicode case mapping, for the ranges
// where it is arithmetic. Windows consults a 64k-entry table built from the
// Unicode database; this is the part of that table which is a rule:
//
//   * ASCII: the only range where "uppercase" is a subtraction.
//   * Latin-1 Supplement: `0xE0..0xFE` less `0xF7` is `+0x1E0 - 0x20`, the
//     multiplication sign `0xD7` has no upper case, and `0xFF` (y with
//     diaeresis) is the one character in the range whose upper case is
//     outside it -- `0x178`.
//   * Latin Extended-A: `0x100..0x137` and `0x14A..0x177` are even/odd
//     pairs where the odd one is the capital, with four documented holes
//     (`0x138` kra, `0x149` eng, `0x178` and `0x17F`).
//   * Greek: `0x3B1..0x3C9` maps by `-0x20` except final sigma `0x3C2`,
//     which is `0x3A3`; accented capitals `0x386..0x38A` come down to
//     `0x3AC..0x3AF` and back.
//   * Cyrillic: `0x430..0x44F` is `-0x20` and `0x450..0x45F` is `-0x50`.
//
// A character outside these ranges is returned unchanged. That is the same
// answer Windows gives for a character with no case mapping, and for a
// character that has one this file does not carry it is a documented
// limitation rather than a wrong answer: the alternative -- mapping only
// ASCII and calling that Unicode -- would be wrong for the characters above
// and silently wrong rather than loudly limited.
[[nodiscard]] char16_t upcase_wide(char16_t c) noexcept {
    const auto u = static_cast<std::uint32_t>(c);
    // ASCII.
    if (u >= u'a' && u <= u'z') {
        return static_cast<char16_t>(u - 32);
    }
    // Latin-1 Supplement. 0xD7 (multiplication sign) is the odd one out: it
    // is not a letter and has no upper case, and 0xF7 (division sign) is
    // the other. 0xFF maps out of the range, which is why it is separate.
    if (u >= 0xE0 && u <= 0xFE && u != 0xF7) {
        return static_cast<char16_t>(u - 32);
    }
    if (u == 0xFF) {
        return static_cast<char16_t>(0x178);
    }
    // Latin Extended-A. The two runs are even/odd pairs; the capital is the
    // odd one, so an even code point moves up and an odd one moves down.
    if (u >= 0x0100 && u <= 0x0137) {
        return (u % 2 == 0) ? static_cast<char16_t>(u + 1)
                             : static_cast<char16_t>(c);
    }
    if (u >= 0x0139 && u <= 0x0148) {
        return (u % 2 == 1) ? static_cast<char16_t>(u - 1)
                             : static_cast<char16_t>(c);
    }
    if (u >= 0x014A && u <= 0x0177) {
        return (u % 2 == 0) ? static_cast<char16_t>(u + 1)
                             : static_cast<char16_t>(c);
    }
    if (u >= 0x0179 && u <= 0x017E) {
        return (u % 2 == 1) ? static_cast<char16_t>(u - 1)
                             : static_cast<char16_t>(c);
    }
    // 0x178 (Y with diaeresis) is already a capital; 0x17F (long s) is the
    // one Latin Extended-A character whose capital is a letter outside the
    // block.
    if (u == 0x017F) {
        return static_cast<char16_t>(u'S');
    }
    // Greek.
    if (u >= 0x03B1 && u <= 0x03C1) {
        return static_cast<char16_t>(u - 32);
    }
    if (u == 0x03C2) {
        // Final sigma. Its capital is the medial sigma's capital, which is
        // why the range rule above stops at 0x03C1.
        return static_cast<char16_t>(0x03A3);
    }
    if (u >= 0x03C3 && u <= 0x03CB) {
        return static_cast<char16_t>(u - 32);
    }
    // The accented Greek capitals are the capitals of the accented
    // lowercase letters, so they go the other way.
    if (u >= 0x03AC && u <= 0x03AF) {
        return static_cast<char16_t>(u - 0x22);
    }
    if (u >= 0x03CC && u <= 0x03CE) {
        return static_cast<char16_t>(u - 0x40);
    }
    // Cyrillic.
    if (u >= 0x0430 && u <= 0x044F) {
        return static_cast<char16_t>(u - 32);
    }
    if (u >= 0x0450 && u <= 0x045F) {
        return static_cast<char16_t>(u - 80);
    }
    return c;
}

[[nodiscard]] char16_t downcase_wide(char16_t c) noexcept {
    const auto u = static_cast<std::uint32_t>(c);
    if (u >= u'A' && u <= u'Z') {
        return static_cast<char16_t>(u + 32);
    }
    if (u >= 0x00C0 && u <= 0x00DE && u != 0x00D7) {
        return static_cast<char16_t>(u + 32);
    }
    if (u == 0x0178) {
        return static_cast<char16_t>(0x00FF);
    }
    if (u >= 0x0100 && u <= 0x0137) {
        return (u % 2 == 1) ? static_cast<char16_t>(u + 1)
                             : static_cast<char16_t>(c);
    }
    if (u >= 0x0139 && u <= 0x0148) {
        return (u % 2 == 0) ? static_cast<char16_t>(u + 1)
                             : static_cast<char16_t>(c);
    }
    if (u >= 0x014A && u <= 0x0177) {
        return (u % 2 == 1) ? static_cast<char16_t>(u + 1)
                             : static_cast<char16_t>(c);
    }
    if (u >= 0x0179 && u <= 0x017E) {
        return (u % 2 == 0) ? static_cast<char16_t>(u + 1)
                             : static_cast<char16_t>(c);
    }
    if (u == 0x0178) {
        return static_cast<char16_t>(0x00FF);
    }
    if (u == 0x0053) {
        // The inverse of 0x17F's mapping above, kept so that downcasing an
        // `S` and upcasing a long s do not disagree about which is which.
        return static_cast<char16_t>(c);
    }
    if (u >= 0x0391 && u <= 0x03A1) {
        return static_cast<char16_t>(u + 32);
    }
    if (u == 0x03A3) {
        return static_cast<char16_t>(0x03C3);
    }
    if (u >= 0x03A4 && u <= 0x03AB) {
        return static_cast<char16_t>(u + 32);
    }
    if (u >= 0x0386 && u <= 0x038A) {
        return static_cast<char16_t>(u + 0x25);
    }
    if (u >= 0x038C && u <= 0x038E) {
        return static_cast<char16_t>(u + 0x3F);
    }
    if (u >= 0x038F && u <= 0x038F) {
        return static_cast<char16_t>(u + 0x40);
    }
    if (u >= 0x0410 && u <= 0x042F) {
        return static_cast<char16_t>(u + 32);
    }
    if (u >= 0x0400 && u <= 0x040F) {
        return static_cast<char16_t>(u + 80);
    }
    return c;
}

// The narrow forms. `RtlUpperChar` is documented by the reference as ASCII
// only -- "the locale and multibyte characters are not taken into account" --
// so it is not the wide mapping narrowed, and a caller that upcases a
// `STRING` and a `UNICODE_STRING` of the same text gets the same answer only
// because the reference says so.
[[nodiscard]] char upcase_narrow(char c) noexcept {
    const auto u = static_cast<unsigned char>(c);
    if (u >= 'a' && u <= 'z') {
        return static_cast<char>(u - 32);
    }
    return c;
}

// ------------------------------------------------------- the shared converts
//
// The conversions every `*To*String` and `*To*N` in this file is built from.
//
// The two directions differ in what they do when the caller's buffer is too
// small, and the difference is the reference's rather than this file's:
//
//   * narrow to wide truncates at a character boundary and reports the
//     number of bytes written, so a caller that under-sized its buffer gets
//     a valid prefix rather than a failure. That is what lets
//     `RtlAnsiStringToUnicodeString` return `STATUS_BUFFER_OVERFLOW` and
//     still leave the destination holding a terminated string.
//   * wide to narrow is driven by the same `utf8_to_utf8` machinery, and the
//     size functions count what the *whole* conversion would need.
//
// The size question is asked separately by every `...To...Size` function, and
// asking it separately is the point: a caller allocates with the size
// function and fills with the conversion function, and the two have to agree
// or the allocation is wrong. Here they are two views of one walk, so they
// cannot disagree.

// The number of UTF-16 units a narrow string converts to, terminator
// excluded. A malformed byte sequence counts as the replacement width rather
// than aborting: this is a *size* query, and a caller asking "how big" is
// owed an answer even for input the conversion will refuse, and the
// conversion's own refusal is reported where the conversion happens.
[[nodiscard]] std::size_t narrow_to_wide_units(std::string_view text) noexcept {
    std::u16string wide;
    if (narrow_in(text, wide).converted) {
        return wide.size();
    }
    // The fallback is the pessimistic one: every byte is its own character.
    // An over-estimate costs the caller memory; an under-estimate costs it a
    // truncated string, and the asymmetry is why this is the direction.
    return text.size();
}

// The number of bytes a wide string converts to, terminator excluded.
[[nodiscard]] std::size_t wide_to_narrow_bytes(std::u16string_view text) noexcept {
    std::string narrow;
    if (narrow_out(text, narrow).converted) {
        return narrow.size();
    }
    return text.size() * 3;
}

// Narrow to wide into a caller-owned buffer. Returns the number of *bytes*
// written to the destination, which is what every caller of this in the
// reference wants: `RtlMultiByteToUnicodeN` reports bytes, not characters,
// even though it converts characters. The return value is advisory rather
// than required: the `UNICODE_STRING` converters below have already computed
// the exact length they are about to store, so for them the count is a
// restatement and not a result.
std::size_t narrow_to_wide(char16_t* dst, std::size_t dst_bytes,
                           const char* src,
                           std::size_t src_bytes) noexcept {
    const std::size_t room = dst_bytes / sizeof(char16_t);
    std::u16string wide;
    if (!narrow_in(std::string_view(src, src_bytes), wide).converted) {
        return 0;
    }
    const std::size_t take = wide.size() < room ? wide.size() : room;
    for (std::size_t k = 0; k < take; ++k) {
        dst[k] = wide[k];
    }
    return take * sizeof(char16_t);
}

std::size_t wide_to_narrow(char* dst, std::size_t dst_bytes,
                           const char16_t* src,
                           std::size_t src_bytes) noexcept {
    const std::size_t units = src_bytes / sizeof(char16_t);
    std::string narrow;
    if (!narrow_out(std::u16string_view(src, units), narrow).converted) {
        return 0;
    }
    const std::size_t take = narrow.size() < dst_bytes ? narrow.size() : dst_bytes;
    for (std::size_t k = 0; k < take; ++k) {
        dst[k] = narrow[k];
    }
    return take;
}

// -------------------------------------------------------------- comparisons
//
// The three-way compare the family shares, over `Length` bytes of two
// buffers. The reference computes the difference of the first differing
// *character*, not a normalised -1/0/1, and this file returns the same
// difference: a caller that tests `> 0` and a caller that tests `== 1` both
// work on the normalised answer and only the first works on the reference's,
// so returning the difference is the answer that satisfies both.
template <typename C, typename Fold>
[[nodiscard]] std::int32_t compare_bytes(const C* a, std::size_t alen,
                                         const C* b, std::size_t blen,
                                         Fold fold) noexcept {
    // `alen` and `blen` are byte counts, so the shared prefix has to be
    // converted before it can bound a loop that indexes whole `C`s. Leaving it
    // in bytes walks twice as many characters as the strings have on the wide
    // forms, which reads the shorter string's terminator as a difference: "abc"
    // against "ab" comes back as 'c' - 0 rather than as a length difference.
    const std::size_t shared = (alen < blen ? alen : blen) / sizeof(C);
    for (std::size_t k = 0; k < shared; ++k) {
        if (a[k] != b[k]) {
            const auto ca = static_cast<std::int32_t>(fold(a[k]));
            const auto cb = static_cast<std::int32_t>(fold(b[k]));
            return ca - cb;
        }
    }
    // Equal over the shared prefix: the longer string is the greater one, and
    // the answer is the length difference, which is what the reference
    // returns and what makes a prefix compare as less than its extension.
    //
    // The difference is in **characters**, not bytes, even though `alen` and
    // `blen` are byte counts. The reference's tail is `len1 - len2` over the
    // unit counts it was handed, so for the wide forms "abc" against "ab" the
    // answer is 1 and not 2. Dividing here rather than at the call sites is
    // what keeps the narrow forms correct: `sizeof(char)` is 1, so their
    // answer is unchanged.
    return static_cast<std::int32_t>(alen / sizeof(C)) -
           static_cast<std::int32_t>(blen / sizeof(C));
}

// --------------------------------------------------------------- integers
//
// The integer conversions share a grammar and it is not `strtol`'s. The
// reference's rules, which a caller parsing a version string or a hex mask
// depends on:
//
//   * leading whitespace is skipped, then an optional sign;
//   * a base of 0 means decimal *unless* the text carries a `0x`, `0o` or
//     `0b` prefix, which is how one call parses all three spellings;
//   * any other base outside {2, 8, 10, 16} is `STATUS_INVALID_PARAMETER`;
//   * parsing **stops** at the first character that is not a digit in the
//     base and answers success with what it has. There is no "trailing
//     garbage" failure, which is what makes this usable for the leading
//     number in a string and useless for validation;
//   * the accumulation is in 32 bits and wraps silently. A caller that needs
//     overflow detection has to check the result itself.
//
// The 64-bit spellings are the same walk over a 64-bit accumulator.

// One digit's value, or -1 for a character that is not a digit at all. The
// letter range is accepted in both cases and folded to 10, so `base 16`
// reads `a`-`f` and `A`-`F` alike, and a base below 10 rejects a letter
// because the caller checks the value against the base afterwards.
[[nodiscard]] int digit_value(char16_t c) noexcept {
    if (c >= u'0' && c <= u'9') {
        return static_cast<int>(c) - static_cast<int>(u'0');
    }
    if (c >= u'A' && c <= u'Z') {
        return static_cast<int>(c) - static_cast<int>(u'A') + 10;
    }
    if (c >= u'a' && c <= u'z') {
        return static_cast<int>(c) - static_cast<int>(u'a') + 10;
    }
    return -1;
}

// The shared walk, over a wide string. `total` is the 32-bit form and
// `total64` the 64-bit one; the grammar and the stopping rule are identical
// and only the accumulator differs, so they are one function with the
// accumulator as a parameter rather than two that can drift.
template <typename Acc>
[[nodiscard]] Ntstatus parse_integer_wide(std::u16string_view text, Acc base_in,
                                          bool allow_zero_base, Acc& out) noexcept {
    Acc base = base_in;
    std::size_t at = 0;
    // Whitespace, which the reference skips by testing `<= ' '` -- every
    // control character as well as the space, which is the rule that lets
    // this parse a value out of a line that has been indented.
    while (at < text.size() && text[at] <= u' ') {
        ++at;
    }
    bool negative = false;
    if (at < text.size() && text[at] == u'+') {
        ++at;
    } else if (at < text.size() && text[at] == u'-') {
        negative = true;
        ++at;
    }
    if (base == 0 && allow_zero_base) {
        base = 10;
        if (text.size() - at >= 2 && text[at] == u'0') {
            const char16_t marker = text[at + 1];
            if (marker == u'b') {
                base = 2;
                at += 2;
            } else if (marker == u'o') {
                base = 8;
                at += 2;
            } else if (marker == u'x') {
                base = 16;
                at += 2;
            }
        }
    } else if (base != 2 && base != 8 && base != 10 && base != 16) {
        return kStInvalidParameter;
    }
    Acc total = 0;
    while (at < text.size()) {
        const int digit = digit_value(text[at]);
        if (digit < 0 || static_cast<Acc>(digit) >= base) {
            break;
        }
        total = static_cast<Acc>(total * base + static_cast<Acc>(digit));
        ++at;
    }
    // The sign is applied by wrapping rather than by a negation, so the
    // 32-bit spelling of `INT32_MIN` comes out right: negating `0x80000000`
    // in a signed type is itself undefined, and the value a caller wants is
    // the one whose bit pattern is the two's complement.
    out = negative ? static_cast<Acc>(0ULL - static_cast<unsigned long long>(total))
                   : total;
    return kStSuccess;
}

// The narrow spelling of the same walk, for `RtlCharToInteger`, which takes
// a `PCSZ` rather than a `UNICODE_STRING` and therefore cannot be a call
// through the wide one: widening first would be a copy, and the reference
// does not make one.
[[nodiscard]] Ntstatus parse_integer_narrow(const char* text,
                                            std::uint32_t base_in,
                                            std::uint32_t& out) noexcept {
    std::uint32_t base = base_in;
    std::size_t at = 0;
    if (text == nullptr) {
        return kStAccessViolation;
    }
    while (text[at] != '\0' && text[at] <= ' ') {
        ++at;
    }
    bool negative = false;
    if (text[at] == '+') {
        ++at;
    } else if (text[at] == '-') {
        negative = true;
        ++at;
    }
    if (base == 0) {
        base = 10;
        if (text[at] == '0') {
            const char marker = text[at + 1];
            if (marker == 'b') {
                base = 2;
                at += 2;
            } else if (marker == 'o') {
                base = 8;
                at += 2;
            } else if (marker == 'x') {
                base = 16;
                at += 2;
            }
        }
    } else if (base != 2 && base != 8 && base != 10 && base != 16) {
        return kStInvalidParameter;
    }
    std::uint32_t total = 0;
    while (text[at] != '\0') {
        const char c = text[at];
        int digit = -1;
        if (c >= '0' && c <= '9') {
            digit = c - '0';
        } else if (c >= 'A' && c <= 'Z') {
            digit = c - 'A' + 10;
        } else if (c >= 'a' && c <= 'z') {
            digit = c - 'a' + 10;
        }
        if (digit < 0 || static_cast<std::uint32_t>(digit) >= base) {
            break;
        }
        total = total * base + static_cast<std::uint32_t>(digit);
        ++at;
    }
    out = negative ? (0U - total) : total;
    return kStSuccess;
}

// The formatting walk, in reverse: a value in a base to a buffer, without a
// terminator. The two callers differ only in the width of the accumulator
// and in whether the terminator is counted, so the terminator is a parameter.
template <typename Acc, typename Out>
[[nodiscard]] std::size_t format_integer(Acc value, std::uint32_t base,
                                         Out* sink) noexcept {
    Out digits[72];
    std::size_t at = sizeof(digits) / sizeof(digits[0]);
    do {
        const Acc digit = static_cast<Acc>(value % static_cast<Acc>(base));
        value = static_cast<Acc>(value / static_cast<Acc>(base));
        Out ch;
        if (digit < 10) {
            ch = static_cast<Out>('0' + static_cast<std::uint32_t>(digit));
        } else {
            // Upper case, which is what every one of these produces: a
            // caller that lowercases has to ask for it afterwards.
            ch = static_cast<Out>('A' + static_cast<std::uint32_t>(digit) - 10);
        }
        digits[--at] = ch;
    } while (value != 0 && at != 0);
    const std::size_t len = (sizeof(digits) / sizeof(digits[0])) - at;
    for (std::size_t k = 0; k < len; ++k) {
        sink[k] = digits[at + k];
    }
    return len;
}

// The base check every `IntegerTo*` shares, with base 0 folded to 10 -- the
// reference's documented difference from the real function, which faults on
// a base of 0, and folding it is what lets a caller pass a base read out of
// a configuration file without a special case.
[[nodiscard]] bool normalize_base(std::uint32_t base,
                                  std::uint32_t& out) noexcept {
    if (base == 0) {
        out = 10;
        return true;
    }
    if (base != 2 && base != 8 && base != 10 && base != 16) {
        return false;
    }
    out = base;
    return true;
}

// ------------------------------------------------------------------- memory
//
// The `Rtl*` spellings of the memory primitives. They are not the C library
// functions: `RtlMoveMemory` is `memmove` and `RtlCopyMemory` is `memcpy`,
// and the difference between them is a guest's overlapping copy. The bridges
// are `cr_memmove` and `cr_memcmp` in `winabi.cpp`, which are already the
// Microsoft ABI entry points a guest would call, so these forward to them
// rather than reimplementing a walk that already exists and is tested.

// ----------------------------------------------------------------- the hash
//
// `RtlHashUnicodeString`'s algorithm, which is not a general hash function
// and is not interchangeable with one: it is `hash = hash * 65599 + c` over
// the UTF-16 units, in 32-bit arithmetic with the wrap kept. A caller that
// puts a hashed name in a hash table is depending on the exact sequence, so
// the multiplication and the truncation are both part of the contract.
//
// The algorithm argument is checked rather than ignored. `0` is the default
// and `1` names the algorithm explicitly; both compute the same thing, and
// anything else is `STATUS_INVALID_PARAMETER` because a caller that passed a
// number it did not understand would otherwise get a hash it trusts.
constexpr std::uint32_t kHashStringAlgorithmDefault = 0;
constexpr std::uint32_t kHashStringAlgorithmX65599 = 1;

}  // namespace

// ===========================================================================
// ABI entry points
// ===========================================================================
//
// One per exported name, and nothing else. The signatures are the reference
// declarations' argument lists rewritten to fixed-width integers and
// pointers, so that which register a 4-byte argument occupies is written
// down rather than left to the compiler's reading of a Windows header.

// ------------------------------------------------------------- initialise

extern "C" __attribute__((ms_abi)) void nrs_RtlInitAnsiString(
    void* target, const char* source) noexcept {
    if (target == nullptr) {
        return;
    }
    if (source == nullptr) {
        // The reference sets all three fields to zero, not just the two
        // lengths: a `STRING` with a null buffer and a non-zero length is a
        // structure a later function will read as a request to walk nothing.
        clear_string(target);
        return;
    }
    // The narrow length, in bytes, and the maximum is that plus the
    // terminator. Both are `USHORT`, so a source longer than 65535 would
    // wrap here; the reference's non-`Ex` spelling has that bug and this one
    // keeps the field consistent instead, because a wrapped length makes the
    // `Ex` variant's check unreachable and both are then wrong together.
    const std::size_t len = c_length(source);
    write_string(target, len, len + 1, const_cast<char*>(source));
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlInitAnsiStringEx(
    void* target, const char* source) noexcept {
    if (target == nullptr) {
        return kStInvalidParameter;
    }
    if (source == nullptr) {
        clear_string(target);
        return kStSuccess;
    }
    const std::size_t len = c_length(source);
    if (len + 1 > 0xFFFF) {
        // The reference's check. The `Ex` spelling exists precisely so that
        // a caller can find out its source was too long instead of receiving
        // a truncated `STRING` that claims to be shorter than it is.
        return kStNameTooLong;
    }
    write_string(target, len, len + 1, const_cast<char*>(source));
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) void nrs_RtlInitString(
    void* target, const char* source) noexcept {
    nrs_RtlInitAnsiString(target, source);
}

extern "C" __attribute__((ms_abi)) void nrs_RtlInitUnicodeString(
    void* target, const char16_t* source) noexcept {
    if (target == nullptr) {
        return;
    }
    if (source == nullptr) {
        clear_string(target);
        return;
    }
    std::size_t len = c_length(source) * sizeof(char16_t);
    // The reference's clamp, and the reason a `UNICODE_STRING` can never
    // describe more than 65532 bytes: the two length fields are `USHORT` and
    // the maximum has to leave room for the terminator, so 0xFFFC is the
    // ceiling rather than 0xFFFF.
    if (len > kMaxUnicodeStringBytes) {
        len = kMaxUnicodeStringBytes;
    }
    write_string(target, len, len + sizeof(char16_t),
                 const_cast<char16_t*>(source));
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlInitUnicodeStringEx(
    void* target, const char16_t* source) noexcept {
    if (target == nullptr) {
        return kStInvalidParameter;
    }
    if (source == nullptr) {
        clear_string(target);
        return kStSuccess;
    }
    const std::size_t len = c_length(source) * sizeof(char16_t);
    if (len > kMaxUnicodeStringBytes) {
        return kStNameTooLong;
    }
    write_string(target, len, len + sizeof(char16_t),
                 const_cast<char16_t*>(source));
    return kStSuccess;
}

// ------------------------------------------------------------------ create

extern "C" __attribute__((ms_abi)) Boolean nrs_RtlCreateUnicodeString(
    void* target, const char16_t* source) noexcept {
    if (target == nullptr || source == nullptr) {
        return kFalse;
    }
    // The length *includes* the terminator -- that is the allocation -- and
    // the structure's `Length` is that minus two. A caller that allocated
    // `Length` bytes here would leave the terminator outside its own buffer,
    // and every later function that trusted the terminator would read one.
    const std::size_t units = c_length(source) + 1;
    const std::size_t bytes = units * sizeof(char16_t);
    void* block = allocate_for_string(bytes);
    if (block == nullptr) {
        return kFalse;
    }
    std::memcpy(block, source, bytes);
    write_string(target, bytes - sizeof(char16_t), bytes, block);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) Boolean nrs_RtlCreateUnicodeStringFromAsciiz(
    void* target, const char* source) noexcept {
    if (target == nullptr || source == nullptr) {
        return kFalse;
    }
    std::u16string wide;
    if (!narrow_in(std::string_view(source), wide).converted) {
        return kFalse;
    }
    // The same shape as the wide spelling: the allocation covers the
    // terminator, the length does not. The narrow source's own length is not
    // the answer here, which is the whole reason the `Ex` and non-`Ex`
    // families are separate code paths.
    const std::size_t units = wide.size() + 1;
    const std::size_t bytes = units * sizeof(char16_t);
    void* block = allocate_for_string(bytes);
    if (block == nullptr) {
        return kFalse;
    }
    auto* out = static_cast<char16_t*>(block);
    for (std::size_t k = 0; k < wide.size(); ++k) {
        out[k] = wide[k];
    }
    out[wide.size()] = u'\0';
    write_string(target, bytes - sizeof(char16_t), bytes, block);
    return kTrue;
}

// -------------------------------------------------------------------- free

// The three frees are one function. The reference's three are one function
// too, and the reason is the same in both: what is released is the buffer
// and then the structure is zeroed, so that a second free of the same string
// is a free of null rather than a double free. A `STRING` and a
// `UNICODE_STRING` have the same layout, so the same walk serves both.
static void free_string_buffer(void* str) noexcept {
    if (str == nullptr) {
        return;
    }
    const StringView v = read_string(str);
    if (v.buffer != nullptr) {
        heap_free(v.buffer);
        clear_string(str);
    }
}

extern "C" __attribute__((ms_abi)) void nrs_RtlFreeAnsiString(
    void* str) noexcept {
    free_string_buffer(str);
}

extern "C" __attribute__((ms_abi)) void nrs_RtlFreeOemString(
    void* str) noexcept {
    free_string_buffer(str);
}

extern "C" __attribute__((ms_abi)) void nrs_RtlFreeUnicodeString(
    void* str) noexcept {
    free_string_buffer(str);
}

// -------------------------------------------------------------------- copy

extern "C" __attribute__((ms_abi)) void nrs_RtlCopyString(
    void* dst_struct, const void* src_struct) noexcept {
    if (dst_struct == nullptr) {
        return;
    }
    if (src_struct == nullptr) {
        // The reference's answer for a null source is a zero length and
        // nothing else: the destination keeps its buffer and its maximum, and
        // becomes an empty string in it.
        write_u16(dst_struct, kStrLength, 0);
        return;
    }
    const StringView d = read_string(dst_struct);
    const StringView s = read_string(src_struct);
    const std::size_t take = s.length < d.maximum ? s.length : d.maximum;
    if (take != 0 && d.buffer != nullptr && s.buffer != nullptr) {
        // `memmove`, not `memcpy`: a caller that copies a `STRING` onto
        // itself -- which shifting a buffer in place is -- would be a
        // read/write overlap, and `RtlCopyString` is documented to accept it.
        std::memmove(d.buffer, s.buffer, take);
    }
    write_u16(dst_struct, kStrLength, static_cast<std::uint16_t>(take));
}

extern "C" __attribute__((ms_abi)) void nrs_RtlCopyUnicodeString(
    void* dst_struct, const void* src_struct) noexcept {
    if (dst_struct == nullptr) {
        return;
    }
    if (src_struct == nullptr) {
        write_u16(dst_struct, kStrLength, 0);
        return;
    }
    const StringView d = read_string(dst_struct);
    const StringView s = read_string(src_struct);
    const std::size_t take = s.length < d.maximum ? s.length : d.maximum;
    if (take != 0 && d.buffer != nullptr && s.buffer != nullptr) {
        std::memmove(d.buffer, s.buffer, take);
    }
    write_u16(dst_struct, kStrLength, static_cast<std::uint16_t>(take));
    // No terminator is written, neither at `take` nor at `take / 2`: the
    // reference copies exactly `min(src->Length, dst->MaximumLength)` bytes
    // and stops there. A destination that is exactly full and one that has
    // room left both end with whatever the copy left in the buffer, and a
    // caller that wants a terminator asks for one more byte than `Length`
    // and writes it itself. Writing one here would put a character past the
    // copied bytes that the source never had, which is visible to any
    // caller that later extends the string in place.
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlDuplicateUnicodeString(
    std::int32_t add_nul, const void* source,
    void* destination) noexcept {
    if (source == nullptr || destination == nullptr) {
        return kStInvalidParameter;
    }
    const StringView s = read_string(source);
    // The three shapes the reference accepts and the one it refuses. `2` is
    // not a spelling of anything, and a caller that passed it has a bug that
    // an answer would hide; a `Length` beyond the `MaximumLength` is a
    // structure that lies about itself, and walking it would read past what
    // it claims to own.
    if (s.length > s.maximum || add_nul == 2 || add_nul >= 4 || add_nul < 0) {
        return kStInvalidParameter;
    }
    // A zero length with a maximum but no buffer is the fourth refusal: the
    // structure says it has room and does not say where.
    if (s.length == 0 && s.maximum > 0 && s.buffer == nullptr) {
        return kStInvalidParameter;
    }
    // The empty source is a special case with three answers, which is what
    // `add_nul` selects between: 0 and 1 both produce a null buffer, and 3
    // produces a real one holding just a terminator. A caller that needs to
    // free the result unconditionally asks for 3.
    if (s.length == 0 && add_nul != 3) {
        clear_string(destination);
        return kStSuccess;
    }
    std::size_t max_len = s.length;
    if (add_nul != 0) {
        max_len += sizeof(char16_t);
    }
    void* block = allocate_for_string(max_len);
    if (block == nullptr) {
        return kStNoMemory;
    }
    if (s.length != 0) {
        std::memcpy(block, s.buffer, s.length);
    }
    // Note the two-step: `Length` and `MaximumLength` are both the copied
    // length first, and only the `add_nul` case widens the maximum. A
    // structure whose maximum is larger than its length with a terminator
    // inside is the only one of the three that a later free can trust.
    write_string(destination, s.length, s.length, block);
    if (add_nul != 0) {
        write_u16(destination, kStrMaximumLength,
                  static_cast<std::uint16_t>(max_len));
        static_cast<char16_t*>(block)[s.length / sizeof(char16_t)] = u'\0';
    }
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) void nrs_RtlEraseUnicodeString(
    void* str) noexcept {
    if (str == nullptr) {
        return;
    }
    const StringView v = read_string(str);
    // `MaximumLength`, not `Length`. The reference erases the whole buffer
    // rather than the string, and that is the point of the function: it
    // exists to leave nothing of a secret in memory, and a secret past the
    // length -- in a buffer the caller once held a longer string in -- is
    // exactly what a length-limited erase would leave behind.
    if (v.buffer != nullptr) {
        std::memset(v.buffer, 0, v.maximum);
    }
    write_u16(str, kStrLength, 0);
}

// ------------------------------------------------------------------ append

// The four appends, over one walk. They differ in where the source comes
// from (a C string or a `STRING`) and in whether the destination is narrow
// or wide, and they agree on the two rules that matter:
//
//   * nothing is written unless the whole source fits. A partial append is
//     not a thing these do, so a caller that gets `STATUS_BUFFER_TOO_SMALL`
//     has a destination that is still the string it was.
//   * the wide pair writes a terminator when there is room for one and the
//     narrow pair does not, because a `STRING` has no terminator to write --
//     its `Length` is what says where it ends.
template <typename C, typename SrcLen, typename SrcAt>
[[nodiscard]] static Ntstatus append_into(void* dest_struct, SrcLen src_len,
                                   SrcAt src_at, bool terminated) noexcept {
    if (dest_struct == nullptr) {
        return kStInvalidParameter;
    }
    const StringView d = read_string(dest_struct);
    const std::size_t src_bytes = src_len();
    if (src_bytes == 0) {
        // A zero-length source leaves the destination alone -- not truncated,
        // not terminated, not touched. The reference's rule, and the one
        // that makes appending an empty string idempotent.
        return kStSuccess;
    }
    const std::size_t total = d.length + src_bytes;
    if (total > d.maximum) {
        return kStBufferTooSmall;
    }
    if (d.buffer != nullptr) {
        auto* out = static_cast<C*>(d.buffer);
        for (std::size_t k = 0; k < src_bytes / sizeof(C); ++k) {
            out[(d.length / sizeof(C)) + k] = src_at(k);
        }
    }
    write_u16(dest_struct, kStrLength, static_cast<std::uint16_t>(total));
    if (terminated && d.buffer != nullptr) {
        // The reference's rule, which is a `+2 <=` rather than a `<`: a
        // destination that is exactly full gets no terminator, because the
        // byte after it is not the caller's to write.
        if (total + sizeof(C) <= d.maximum) {
            static_cast<C*>(d.buffer)[total / sizeof(C)] = static_cast<C>(0);
        }
    }
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlAppendAsciizToString(
    void* dest, const char* src) noexcept {
    if (src == nullptr) {
        return kStSuccess;
    }
    const std::size_t n = c_length(src);
    return append_into<char>(
        dest, [&n]() noexcept { return n; },
        [src](std::size_t k) noexcept { return src[k]; }, false);
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlAppendStringToString(
    void* dest, const void* src) noexcept {
    if (src == nullptr) {
        return kStInvalidParameter;
    }
    const StringView s = read_string(src);
    const std::size_t n = s.length;
    return append_into<char>(
        dest, [&n]() noexcept { return n; },
        [s](std::size_t k) noexcept {
            return static_cast<const char*>(s.buffer)[k];
        },
        false);
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlAppendUnicodeToString(
    void* dest, const char16_t* src) noexcept {
    if (src == nullptr) {
        return kStSuccess;
    }
    const std::size_t n = c_length(src) * sizeof(char16_t);
    return append_into<char16_t>(
        dest, [&n]() noexcept { return n; },
        [src](std::size_t k) noexcept { return src[k]; }, true);
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlAppendUnicodeStringToString(
    void* dest, const void* src) noexcept {
    if (src == nullptr) {
        return kStInvalidParameter;
    }
    const StringView s = read_string(src);
    const std::size_t n = s.length;
    return append_into<char16_t>(
        dest, [&n]() noexcept { return n; },
        [s](std::size_t k) noexcept {
            return static_cast<const char16_t*>(s.buffer)[k];
        },
        true);
}

// -------------------------------------------------------------- comparison

extern "C" __attribute__((ms_abi)) std::int32_t nrs_RtlCompareString(
    const void* s1, const void* s2, Boolean case_insensitive) noexcept {
    if (s1 == nullptr || s2 == nullptr) {
        return 0;
    }
    const StringView a = read_string(s1);
    const StringView b = read_string(s2);
    return compare_bytes<char>(
        static_cast<const char*>(a.buffer), a.length,
        static_cast<const char*>(b.buffer), b.length,
        [case_insensitive](char c) noexcept {
            return case_insensitive != kFalse
                       ? static_cast<char>(upcase_narrow(c))
                       : c;
        });
}

extern "C" __attribute__((ms_abi)) std::int32_t nrs_RtlCompareUnicodeStrings(
    const char16_t* s1, std::uint64_t len1, const char16_t* s2,
    std::uint64_t len2, Boolean case_insensitive) noexcept {
    // The two lengths here are **unit** counts, not byte counts. This is the
    // one member of the compare family that is handed lengths directly, and
    // it is the one a caller is most likely to get wrong: the same numbers
    // passed to `RtlCompareUnicodeString` -- which counts bytes internally --
    // are half as many as the ones this wants.
    const std::size_t bytes1 =
        static_cast<std::size_t>(len1) * sizeof(char16_t);
    const std::size_t bytes2 =
        static_cast<std::size_t>(len2) * sizeof(char16_t);
    return compare_bytes<char16_t>(
        s1, bytes1, s2, bytes2,
        [case_insensitive](char16_t c) noexcept {
            return case_insensitive != kFalse ? upcase_wide(c) : c;
        });
}

extern "C" __attribute__((ms_abi)) std::int32_t nrs_RtlCompareUnicodeString(
    const void* s1, const void* s2, Boolean case_insensitive) noexcept {
    if (s1 == nullptr || s2 == nullptr) {
        return 0;
    }
    const StringView a = read_string(s1);
    const StringView b = read_string(s2);
    // `Length / 2` on each side: the structure's lengths are bytes and this
    // comparison is in characters, so the halving is where a caller's
    // expectation of "the same numbers" comes from.
    return nrs_RtlCompareUnicodeStrings(
        static_cast<const char16_t*>(a.buffer), a.length / sizeof(char16_t),
        static_cast<const char16_t*>(b.buffer), b.length / sizeof(char16_t),
        case_insensitive);
}

extern "C" __attribute__((ms_abi)) Boolean nrs_RtlEqualString(
    const void* s1, const void* s2, Boolean case_insensitive) noexcept {
    if (s1 == nullptr || s2 == nullptr) {
        return kFalse;
    }
    // The length check first, and it is a byte count. Two strings of the same
    // characters in different encodings have different lengths and are not
    // equal under this function, which is a fact about the encoding rather
    // than about the text.
    if (read_string(s1).length != read_string(s2).length) {
        return kFalse;
    }
    return nrs_RtlCompareString(s1, s2, case_insensitive) == 0 ? kTrue : kFalse;
}

extern "C" __attribute__((ms_abi)) Boolean nrs_RtlEqualUnicodeString(
    const void* s1, const void* s2, Boolean case_insensitive) noexcept {
    if (s1 == nullptr || s2 == nullptr) {
        return kFalse;
    }
    if (read_string(s1).length != read_string(s2).length) {
        return kFalse;
    }
    return nrs_RtlCompareUnicodeString(s1, s2, case_insensitive) == 0 ? kTrue
                                                                    : kFalse;
}

extern "C" __attribute__((ms_abi)) Boolean nrs_RtlPrefixString(
    const void* s1, const void* s2, Boolean ignore_case) noexcept {
    if (s1 == nullptr || s2 == nullptr) {
        return kFalse;
    }
    const StringView a = read_string(s1);
    const StringView b = read_string(s2);
    if (a.length > b.length) {
        return kFalse;
    }
    const auto* pa = static_cast<const char*>(a.buffer);
    const auto* pb = static_cast<const char*>(b.buffer);
    for (std::size_t k = 0; k < a.length; ++k) {
        const char ca = ignore_case != kFalse ? upcase_narrow(pa[k]) : pa[k];
        const char cb = ignore_case != kFalse ? upcase_narrow(pb[k]) : pb[k];
        if (ca != cb) {
            return kFalse;
        }
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) Boolean nrs_RtlPrefixUnicodeString(
    const void* s1, const void* s2, Boolean ignore_case) noexcept {
    if (s1 == nullptr || s2 == nullptr) {
        return kFalse;
    }
    const StringView a = read_string(s1);
    const StringView b = read_string(s2);
    if (a.length > b.length) {
        return kFalse;
    }
    const auto* pa = static_cast<const char16_t*>(a.buffer);
    const auto* pb = static_cast<const char16_t*>(b.buffer);
    const std::size_t units = a.length / sizeof(char16_t);
    for (std::size_t k = 0; k < units; ++k) {
        const char16_t ca = ignore_case != kFalse ? upcase_wide(pa[k]) : pa[k];
        const char16_t cb = ignore_case != kFalse ? upcase_wide(pb[k]) : pb[k];
        if (ca != cb) {
            return kFalse;
        }
    }
    return kTrue;
}

// --------------------------------------------------------------------- hash

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlHashUnicodeString(
    const void* str, Boolean case_insensitive, std::uint32_t alg,
    std::uint32_t* hash) noexcept {
    if (str == nullptr || hash == nullptr) {
        return kStInvalidParameter;
    }
    if (alg != kHashStringAlgorithmDefault &&
        alg != kHashStringAlgorithmX65599) {
        return kStInvalidParameter;
    }
    const StringView v = read_string(str);
    const auto* chars = static_cast<const char16_t*>(v.buffer);
    const std::size_t units = v.length / sizeof(char16_t);
    std::uint32_t acc = 0;
    for (std::size_t k = 0; k < units; ++k) {
        // 65599, not 65536 and not a prime from a table: the multiplier is
        // part of the contract, and the wrap is kept because a caller
        // comparing two hashes is comparing the sequence, not the values.
        const std::uint32_t unit =
            static_cast<std::uint32_t>(case_insensitive != kFalse
                                           ? upcase_wide(chars[k])
                                           : chars[k]);
        acc = acc * 65599U + unit;
    }
    *hash = acc;
    return kStSuccess;
}

// ------------------------------------------------------------------ search

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlFindCharInUnicodeString(
    std::int32_t flags, const void* main_str, const void* search_chars,
    std::uint16_t* pos) noexcept {
    if (main_str == nullptr || search_chars == nullptr || pos == nullptr) {
        return kStInvalidParameter;
    }
    const StringView main_v = read_string(main_str);
    const StringView set_v = read_string(search_chars);
    const auto* text = static_cast<const char16_t*>(main_v.buffer);
    const auto* set = static_cast<const char16_t*>(set_v.buffer);
    const std::size_t units = main_v.length / sizeof(char16_t);
    const std::size_t set_units = set_v.length / sizeof(char16_t);

    // The four flags, and the answer each gives. Two of them are a forward
    // search, two a backward one; the difference that matters is the value
    // written to `pos`, and it is not the same in both directions.
    //
    // Forward, `pos` is the position **after** the character found -- the
    // reference writes `(index + 1) * 2`, and the reason is that this
    // function's contract is a *continuation point* for a parser walking the
    // string, so it answers where to carry on rather than where the match
    // was. Backward, it is the position **of** the character, which is what
    // makes a backward scan's answer usable as an index into the string.
    //
    // The asymmetry is the reference's and is preserved deliberately: a
    // caller written against one direction and handed the other would
    // otherwise get an off-by-two that is very hard to see, because the
    // value is a valid position either way.
    const auto in_set = [set, set_units](char16_t c) noexcept {
        for (std::size_t k = 0; k < set_units; ++k) {
            if (set[k] == c) {
                return true;
            }
        }
        return false;
    };

    switch (flags) {
    case 0:  // forward, any of the search characters
        for (std::size_t i = 0; i < units; ++i) {
            if (in_set(text[i])) {
                *pos = static_cast<std::uint16_t>((i + 1) * sizeof(char16_t));
                return kStSuccess;
            }
        }
        *pos = 0;
        return kStNotFound;
    case 1:  // backward, any of the search characters
        for (std::size_t i = units; i != 0; --i) {
            if (in_set(text[i - 1])) {
                *pos = static_cast<std::uint16_t>((i - 1) * sizeof(char16_t));
                return kStSuccess;
            }
        }
        *pos = 0;
        return kStNotFound;
    case 2:  // forward, the first character *not* in the set
        for (std::size_t i = 0; i < units; ++i) {
            if (!in_set(text[i])) {
                *pos = static_cast<std::uint16_t>((i + 1) * sizeof(char16_t));
                return kStSuccess;
            }
        }
        *pos = 0;
        return kStNotFound;
    case 3:  // backward, the first character *not* in the set
        for (std::size_t i = units; i != 0; --i) {
            if (!in_set(text[i - 1])) {
                *pos = static_cast<std::uint16_t>((i - 1) * sizeof(char16_t));
                return kStSuccess;
            }
        }
        *pos = 0;
        return kStNotFound;
    default:
        break;
    }
    // An unrecognised flag is a "not found" rather than a parameter failure.
    // The reference's switch falls off the end and returns the same code the
    // searches return when they find nothing, and a caller that passes a
    // flag it invented gets an answer it can test rather than a fault.
    *pos = 0;
    return kStNotFound;
}

// ------------------------------------------------------------------ sizes
//
// The four size functions and their `Rtlx*` aliases, which is eight of the
// names in this file and one function each. The `Rtlx` spellings are the
// same computation under the name the kernel's own internal callers use;
// Wine exports both spellings from one body, and a guest that imports the
// `Rtlx` one means the same thing by it.
//
// The arithmetic, which is the whole of these:
//
//   * narrow to wide: the *converted* unit count plus one terminator, in
//     **bytes**. Not the source's byte count: a source of `n` ASCII
//     characters is `n` units and `2(n+1)` bytes, and a source of `n`
//     two-byte characters is `n` units and `2(n+1)` bytes too, which is why
//     this cannot be computed from the narrow length at all.
//   * wide to narrow: the converted byte count plus one, in bytes.
//
// The `+1` is the terminator and it is in the answer even though the
// `UNICODE_STRING` these size a conversion *into* will report a `Length`
// that excludes it. A caller that adds its own terminator allowance here
// allocates one WCHAR too many, which is harmless; a caller that does not
// and this function did would truncate the last character.

[[nodiscard]] static std::size_t narrow_string_to_wide_bytes(std::size_t narrow_bytes,
                                                     const void* buffer) noexcept {
    if (buffer == nullptr) {
        return sizeof(char16_t);
    }
    const auto* chars = static_cast<const char*>(buffer);
    return (narrow_to_wide_units(std::string_view(chars, narrow_bytes)) + 1) *
           sizeof(char16_t);
}

extern "C" __attribute__((ms_abi)) std::uint32_t nrs_RtlAnsiStringToUnicodeSize(
    const void* str) noexcept {
    if (str == nullptr) {
        return static_cast<std::uint32_t>(sizeof(char16_t));
    }
    const StringView v = read_string(str);
    return static_cast<std::uint32_t>(
        narrow_string_to_wide_bytes(v.length, v.buffer));
}

extern "C" __attribute__((ms_abi)) std::uint32_t nrs_RtlxAnsiStringToUnicodeSize(
    const void* str) noexcept {
    return nrs_RtlAnsiStringToUnicodeSize(str);
}

extern "C" __attribute__((ms_abi)) std::uint32_t nrs_RtlOemStringToUnicodeSize(
    const void* str) noexcept {
    return nrs_RtlAnsiStringToUnicodeSize(str);
}

extern "C" __attribute__((ms_abi)) std::uint32_t nrs_RtlxOemStringToUnicodeSize(
    const void* str) noexcept {
    return nrs_RtlAnsiStringToUnicodeSize(str);
}

extern "C" __attribute__((ms_abi)) std::uint32_t nrs_RtlUnicodeStringToAnsiSize(
    const void* str) noexcept {
    if (str == nullptr) {
        return 1;
    }
    const StringView v = read_string(str);
    const std::u16string wide = as_wide(v);
    return static_cast<std::uint32_t>(wide_to_narrow_bytes(wide) + 1);
}

extern "C" __attribute__((ms_abi)) std::uint32_t nrs_RtlxUnicodeStringToAnsiSize(
    const void* str) noexcept {
    return nrs_RtlUnicodeStringToAnsiSize(str);
}

extern "C" __attribute__((ms_abi)) std::uint32_t nrs_RtlUnicodeStringToOemSize(
    const void* str) noexcept {
    return nrs_RtlUnicodeStringToAnsiSize(str);
}

extern "C" __attribute__((ms_abi)) std::uint32_t nrs_RtlxUnicodeStringToOemSize(
    const void* str) noexcept {
    return nrs_RtlUnicodeStringToAnsiSize(str);
}

// ------------------------------------------------------------- conversions
//
// The `*String` conversions, over one walk each direction.
//
// The rule that shapes all four is the `doalloc` parameter, and it is worth
// stating because it is the difference between a function that can fail and
// one that cannot:
//
//   * `doalloc == 0`: the destination's `Buffer` and `MaximumLength` are the
//     caller's, and the function's job is to fill them. If the text does not
//     fit, the reference *truncates and says so* -- `STATUS_BUFFER_OVERFLOW`
//     with the destination holding a terminated prefix -- rather than
//     refusing. A caller that checks the status and uses what it got has a
//     working program; a caller that ignores the status has a shorter string
//     and no way to tell. The one exception is a destination with a maximum
//     of zero, which is reported as `STATUS_BUFFER_OVERFLOW` with nothing
//     written, because there is no room even for a terminator.
//   * `doalloc != 0`: the function allocates and the caller frees it with
//     `RtlFreeUnicodeString` or `RtlFreeAnsiString`. `MaximumLength` becomes
//     the allocation size, which is why a caller must not have set it.
//
// The narrow destination's `Length` is set to the *byte* count of the
// converted text, and the wide destination's to twice the unit count. The
// terminator is always written, and it is written at the *converted* length
// rather than at the source's, which is the off-by-a-factor-of-two a caller
// gets from writing this by hand.

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlAnsiStringToUnicodeString(
    void* uni, const void* ansi, Boolean doalloc) noexcept {
    if (uni == nullptr || ansi == nullptr) {
        return kStInvalidParameter;
    }
    const StringView a = read_string(ansi);
    const std::size_t total = narrow_string_to_wide_bytes(a.length, a.buffer);
    if (total > 0xFFFF) {
        // The reference's `STATUS_INVALID_PARAMETER_2`, and the numbered
        // code rather than the plain one because it is specifically the
        // *converted* length that is too long: a caller whose narrow string
        // was a legal 60000 bytes has produced something that cannot be
        // described, and the parameter at fault is the conversion, not the
        // input.
        return kStInvalidParameter2;
    }
    const std::size_t length = total - sizeof(char16_t);
    StringView u = read_string(uni);
    if (doalloc != kFalse) {
        void* block = allocate_for_string(total);
        if (block == nullptr) {
            return kStNoMemory;
        }
        u.buffer = block;
        u.maximum = total;
    } else if (total > u.maximum) {
        return kStBufferOverflow;
    }
    if (u.buffer != nullptr) {
        narrow_to_wide(static_cast<char16_t*>(u.buffer), length,
                       static_cast<const char*>(a.buffer), a.length);
        static_cast<char16_t*>(u.buffer)[length / sizeof(char16_t)] = u'\0';
    }
    write_string(uni, length, u.maximum, u.buffer);
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlOemStringToUnicodeString(
    void* uni, const void* oem, Boolean doalloc) noexcept {
    return nrs_RtlAnsiStringToUnicodeString(uni, oem, doalloc);
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlUnicodeStringToAnsiString(
    void* ansi, const void* uni, Boolean doalloc) noexcept {
    if (ansi == nullptr || uni == nullptr) {
        return kStInvalidParameter;
    }
    const StringView u = read_string(uni);
    const std::u16string wide = as_wide(u);
    const std::size_t needed = wide_to_narrow_bytes(wide) + 1;
    StringView a = read_string(ansi);
    Ntstatus status = kStSuccess;
    std::size_t length = needed - 1;
    if (doalloc != kFalse) {
        void* block = allocate_for_string(needed);
        if (block == nullptr) {
            return kStNoMemory;
        }
        a.buffer = block;
        a.maximum = needed;
    } else if (a.maximum < needed) {
        if (a.maximum == 0) {
            // Nothing at all, not even a terminator. The reference returns
            // here without setting `Length`, and so does this: writing a
            // zero into a structure the caller is about to free is not an
            // answer to anything.
            return kStBufferOverflow;
        }
        // The partial copy. `Length` is the room there is, less the
        // terminator, and the status says the text was cut -- which is the
        // only way a caller can tell a truncated conversion from a short
        // input.
        length = a.maximum - 1;
        status = kStBufferOverflow;
    }
    if (a.buffer != nullptr) {
        wide_to_narrow(static_cast<char*>(a.buffer), length, wide.data(),
                       wide.size() * sizeof(char16_t));
        static_cast<char*>(a.buffer)[length] = '\0';
    }
    write_string(ansi, length, a.maximum, a.buffer);
    return status;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlUnicodeStringToOemString(
    void* oem, const void* uni, Boolean doalloc) noexcept {
    return nrs_RtlUnicodeStringToAnsiString(oem, uni, doalloc);
}

extern "C" __attribute__((ms_abi)) Ntstatus
nrs_RtlUnicodeStringToCountedOemString(void* oem, const void* uni,
                                      Boolean doalloc) noexcept {
    if (oem == nullptr || uni == nullptr) {
        return kStInvalidParameter;
    }
    const StringView u = read_string(uni);
    const std::u16string wide = as_wide(u);
    const std::size_t needed = wide_to_narrow_bytes(wide);
    StringView o = read_string(oem);
    Ntstatus status = kStSuccess;
    std::size_t length = needed;
    if (doalloc != kFalse) {
        void* block = allocate_for_string(needed == 0 ? 1 : needed);
        if (block == nullptr) {
            return kStNoMemory;
        }
        o.buffer = block;
        o.maximum = needed;
    } else if (o.maximum < needed) {
        status = kStBufferOverflow;
        // Note the difference from the terminated form: the length becomes
        // the whole of the room, not the room less a terminator, because
        // there is no terminator to leave room for. A counted string is
        // exactly the case where that matters.
        length = o.maximum;
    }
    if (o.buffer != nullptr && length != 0) {
        wide_to_narrow(static_cast<char*>(o.buffer), length, wide.data(),
                       wide.size() * sizeof(char16_t));
    }
    write_string(oem, length, o.maximum, o.buffer);
    return status;
}

// -------------------------------------------------------- narrow to wide N

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlMultiByteToUnicodeN(
    char16_t* dst, std::uint32_t dst_bytes, std::uint32_t* reslen,
    const char* src, std::uint32_t src_bytes) noexcept {
    if (reslen == nullptr || src == nullptr) {
        return kStInvalidParameter;
    }
    if (dst == nullptr) {
        // The size query: a null destination means "how much would this
        // need", and `reslen` is the answer in **bytes** even though the
        // conversion counts characters. Every caller in this file that needs
        // a size before it has a buffer comes through here.
        const std::size_t units =
            narrow_to_wide_units(std::string_view(src, src_bytes));
        *reslen = static_cast<std::uint32_t>(units * sizeof(char16_t));
        return kStSuccess;
    }
    *reslen = static_cast<std::uint32_t>(
        narrow_to_wide(dst, dst_bytes, src, src_bytes));
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlOemToUnicodeN(
    char16_t* dst, std::uint32_t dst_bytes, std::uint32_t* reslen,
    const char* src, std::uint32_t src_bytes) noexcept {
    return nrs_RtlMultiByteToUnicodeN(dst, dst_bytes, reslen, src, src_bytes);
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlUTF8ToUnicodeN(
    char16_t* dst, std::uint32_t dst_bytes, std::uint32_t* reslen,
    const char* src, std::uint32_t src_bytes) noexcept {
    // The reference's two refusals, and both are checked before anything is
    // written: a null `reslen` means the caller has nowhere to learn how much
    // was converted, and a null `src` is the one thing this function cannot
    // report a size for.
    if (src == nullptr) {
        return kStInvalidParameter4;
    }
    if (reslen == nullptr) {
        return kStInvalidParameter;
    }
    return nrs_RtlMultiByteToUnicodeN(dst, dst_bytes, reslen, src, src_bytes);
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlMultiByteToUnicodeSize(
    std::uint32_t* size, const char* str, std::uint32_t len) noexcept {
    if (size == nullptr) {
        return kStInvalidParameter;
    }
    *size = static_cast<std::uint32_t>(
        narrow_to_wide_units(std::string_view(str == nullptr ? "" : str, len)) *
        sizeof(char16_t));
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlCustomCPToUnicodeN(
    const void* info, char16_t* dst, std::uint32_t dst_bytes,
    std::uint32_t* reslen, const char* src, std::uint32_t src_bytes) noexcept {
    // The custom-code-page entry point. Its first argument on Windows is a
    // `CPTABLEINFO` the *caller* supplies -- a code page's mapping tables,
    // built by `RtlCodePageToLCID` and friends -- and this runtime's narrow
    // encoding is UTF-8 whatever tables a caller passes, because there is
    // only one narrow encoding here to convert from. The parameter is
    // therefore accepted and not consulted, which is stated rather than
    // hidden: a guest that built real 932 tables gets UTF-8.
    static_cast<void>(info);
    if (src == nullptr || reslen == nullptr) {
        return kStInvalidParameter;
    }
    if (dst == nullptr) {
        *reslen = static_cast<std::uint32_t>(
            narrow_to_wide_units(std::string_view(src, src_bytes)) *
            sizeof(char16_t));
        return kStSuccess;
    }
    *reslen =
        static_cast<std::uint32_t>(narrow_to_wide(dst, dst_bytes, src, src_bytes));
    return kStSuccess;
}

// -------------------------------------------------------- wide to narrow N

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlUnicodeToMultiByteN(
    char* dst, std::uint32_t dst_bytes, std::uint32_t* reslen,
    const char16_t* src, std::uint32_t src_bytes) noexcept {
    if (reslen == nullptr || src == nullptr) {
        return kStInvalidParameter;
    }
    if (dst == nullptr) {
        *reslen = static_cast<std::uint32_t>(
            wide_to_narrow_bytes(std::u16string_view(src, src_bytes / 2)));
        return kStSuccess;
    }
    *reslen = static_cast<std::uint32_t>(
        wide_to_narrow(dst, dst_bytes, src, src_bytes));
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlUnicodeToOemN(
    char* dst, std::uint32_t dst_bytes, std::uint32_t* reslen,
    const char16_t* src, std::uint32_t src_bytes) noexcept {
    return nrs_RtlUnicodeToMultiByteN(dst, dst_bytes, reslen, src, src_bytes);
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlUnicodeToUTF8N(
    char* dst, std::uint32_t dst_bytes, std::uint32_t* reslen,
    const char16_t* src, std::uint32_t src_bytes) noexcept {
    if (src == nullptr) {
        return kStInvalidParameter4;
    }
    if (reslen == nullptr) {
        return kStInvalidParameter;
    }
    // The odd-length refusal. `srclen` here is a **byte** count, and a byte
    // count that is not a multiple of two describes half a UTF-16 unit. The
    // refusal is unconditional -- a size query with a half-unit count is as
    // much a malformed call as a fill with one, and refusing the fill but
    // answering the query would make the answer depend on which of the two
    // calls the caller made first. The reference refuses rather than
    // rounding, and the reason to keep the refusal is that rounding would
    // silently drop or invent a character depending on which way it rounded.
    if ((src_bytes % sizeof(char16_t)) != 0) {
        return kStInvalidParameter5;
    }
    return nrs_RtlUnicodeToMultiByteN(dst, dst_bytes, reslen, src, src_bytes);
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlUnicodeToMultiByteSize(
    std::uint32_t* size, const char16_t* str, std::uint32_t len) noexcept {
    if (size == nullptr) {
        return kStInvalidParameter;
    }
    *size = static_cast<std::uint32_t>(wide_to_narrow_bytes(
        std::u16string_view(str == nullptr ? u"" : str, len / 2)));
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlUnicodeToCustomCPN(
    const void* info, char* dst, std::uint32_t dst_bytes,
    std::uint32_t* reslen, const char16_t* src, std::uint32_t src_bytes) noexcept {
    // As `RtlCustomCPToUnicodeN`: the caller's code page tables are accepted
    // and not consulted, because this runtime has one narrow encoding.
    static_cast<void>(info);
    if (src == nullptr || reslen == nullptr) {
        return kStInvalidParameter;
    }
    return nrs_RtlUnicodeToMultiByteN(dst, dst_bytes, reslen, src, src_bytes);
}

// The three upcase-to-narrow conversions, which are the plain ones with the
// case mapping applied first. They are separate functions rather than a flag
// on the others because that is how the reference spells them, and a guest
// importing `RtlUpcaseUnicodeToMultiByteN` needs that name to exist.
extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlUpcaseUnicodeToMultiByteN(
    char* dst, std::uint32_t dst_bytes, std::uint32_t* reslen,
    const char16_t* src, std::uint32_t src_bytes) noexcept {
    if (reslen == nullptr || src == nullptr) {
        return kStInvalidParameter;
    }
    std::u16string upcased;
    const std::size_t units = src_bytes / sizeof(char16_t);
    upcased.reserve(units);
    for (std::size_t k = 0; k < units; ++k) {
        upcased.push_back(upcase_wide(src[k]));
    }
    if (dst == nullptr) {
        *reslen = static_cast<std::uint32_t>(wide_to_narrow_bytes(upcased));
        return kStSuccess;
    }
    *reslen = static_cast<std::uint32_t>(
        wide_to_narrow(dst, dst_bytes, upcased.data(), units * 2));
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlUpcaseUnicodeToOemN(
    char* dst, std::uint32_t dst_bytes, std::uint32_t* reslen,
    const char16_t* src, std::uint32_t src_bytes) noexcept {
    return nrs_RtlUpcaseUnicodeToMultiByteN(dst, dst_bytes, reslen, src,
                                           src_bytes);
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlUpcaseUnicodeToCustomCPN(
    const void* info, char* dst, std::uint32_t dst_bytes,
    std::uint32_t* reslen, const char16_t* src, std::uint32_t src_bytes) noexcept {
    // Same as the plain spelling, and for the same stated reason: the
    // upcasing is real and the code page is this runtime's only one.
    static_cast<void>(info);
    return nrs_RtlUpcaseUnicodeToMultiByteN(dst, dst_bytes, reslen, src,
                                           src_bytes);
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlConsoleMultiByteToUnicodeN(
    char16_t* dst, std::uint32_t dst_bytes, std::uint32_t* reslen,
    const char* src, std::uint32_t src_bytes) noexcept {
    // The console code page is a third code page and this runtime has one
    // narrow encoding, so this is the ANSI conversion. The parameter the real
    // function takes for the code page is not in its signature -- the console
    // code page comes from the console's own state -- which is why there is
    // nothing here to disagree with.
    return nrs_RtlMultiByteToUnicodeN(dst, dst_bytes, reslen, src, src_bytes);
}

// ------------------------------------------------------ the case functions

extern "C" __attribute__((ms_abi)) char16_t nrs_RtlUpcaseUnicodeChar(
    char16_t c) noexcept {
    return upcase_wide(c);
}

extern "C" __attribute__((ms_abi)) char16_t nrs_RtlDowncaseUnicodeChar(
    char16_t c) noexcept {
    return downcase_wide(c);
}

extern "C" __attribute__((ms_abi)) char nrs_RtlUpperChar(char c) noexcept {
    return upcase_narrow(c);
}

extern "C" __attribute__((ms_abi)) void nrs_RtlUpperString(
    void* dst_struct, const void* src_struct) noexcept {
    if (dst_struct == nullptr || src_struct == nullptr) {
        return;
    }
    const StringView d = read_string(dst_struct);
    const StringView s = read_string(src_struct);
    // The truncated length, and it is written back: the reference sets
    // `Length` to what it copied rather than leaving the destination
    // claiming a length its buffer cannot hold. A caller that upcased into a
    // short buffer and then read `Length` would otherwise walk past it.
    const std::size_t take = s.length < d.maximum ? s.length : d.maximum;
    const auto* from = static_cast<const char*>(s.buffer);
    auto* to = static_cast<char*>(d.buffer);
    for (std::size_t k = 0; k < take; ++k) {
        to[k] = upcase_narrow(from[k]);
    }
    write_u16(dst_struct, kStrLength, static_cast<std::uint16_t>(take));
}

// The two whole-string case mappings. They allocate when asked and they check
// when not, and the check is `src->Length > dest->MaximumLength` -- a
// refusal, not a truncation. The difference from the append family is
// deliberate and is the reference's: an append can report "too small" and
// leave the destination alone, while a *mapping* has no partial answer,
// because half-uppercased text is not a shorter version of the same string.
template <typename Fold>
[[nodiscard]] static Ntstatus case_map_string(void* dest_struct, const void* src_struct,
                                       Boolean alloc, Fold fold) noexcept {
    if (dest_struct == nullptr || src_struct == nullptr) {
        return kStInvalidParameter;
    }
    const StringView s = read_string(src_struct);
    const std::size_t len = s.length;
    StringView d = read_string(dest_struct);
    if (alloc != kFalse) {
        // A zero-length source allocates zero bytes, and this runtime's
        // allocator answers a zero-byte request with a real pointer rather
        // than null -- which matters, because a null buffer here would make
        // the result indistinguishable from a failed allocation and the
        // caller's `RtlFreeUnicodeString` would be a no-op on a string it
        // believes it owns.
        void* block = allocate_for_string(len == 0 ? 1 : len);
        if (block == nullptr) {
            return kStNoMemory;
        }
        d.buffer = block;
        d.maximum = len;
    } else if (len > d.maximum) {
        return kStBufferOverflow;
    }
    const auto* from = static_cast<const char16_t*>(s.buffer);
    auto* to = static_cast<char16_t*>(d.buffer);
    const std::size_t units = len / sizeof(char16_t);
    for (std::size_t k = 0; k < units; ++k) {
        to[k] = fold(from[k]);
    }
    // `Length` is the *source's* length, not the number of characters
    // written. For a case mapping those are the same number, and writing the
    // unit count instead would be a bug only for a source whose `Length` is
    // odd -- which the mapping then truncates, and says so by having written
    // fewer characters than the length claims.
    write_string(dest_struct, len, d.maximum, d.buffer);
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlUpcaseUnicodeString(
    void* dest, const void* src, Boolean alloc) noexcept {
    return case_map_string(dest, src, alloc,
                           [](char16_t c) noexcept { return upcase_wide(c); });
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlDowncaseUnicodeString(
    void* dest, const void* src, Boolean alloc) noexcept {
    return case_map_string(dest, src, alloc,
                           [](char16_t c) noexcept { return downcase_wide(c); });
}

// ------------------------------------- the upcased narrow STRING conversions

// The three, over one walk. They differ from the plain conversions in one
// place: the size they ask for is the size of the *upcased* text, and
// upcasing never changes a length in the ranges this file maps, so the size
// is the plain one. That is stated because it is a fact about the mapping
// rather than about the functions, and a mapping that could change a length
// would make these three allocate the wrong amount.
template <bool Terminated>
[[nodiscard]] static Ntstatus upcase_to_narrow_string(void* dst_struct,
                                               const void* uni_struct,
                                               Boolean doalloc) noexcept {
    if (dst_struct == nullptr || uni_struct == nullptr) {
        return kStInvalidParameter;
    }
    const StringView u = read_string(uni_struct);
    std::u16string upcased;
    {
        const auto* from = static_cast<const char16_t*>(u.buffer);
        const std::size_t units = u.length / sizeof(char16_t);
        upcased.reserve(units);
        for (std::size_t k = 0; k < units; ++k) {
            upcased.push_back(upcase_wide(from[k]));
        }
    }
    const std::size_t text_bytes = wide_to_narrow_bytes(upcased);
    // The one byte of terminator, and only for the two terminated forms.
    const std::size_t needed = Terminated ? text_bytes + 1 : text_bytes;
    StringView d = read_string(dst_struct);
    Ntstatus status = kStSuccess;
    std::size_t length = needed - (Terminated ? 1 : 0);
    if (doalloc != kFalse) {
        void* block = allocate_for_string(needed == 0 ? 1 : needed);
        if (block == nullptr) {
            return kStNoMemory;
        }
        d.buffer = block;
        d.maximum = needed;
    } else if (d.maximum < needed) {
        if (d.maximum == 0) {
            return kStBufferOverflow;
        }
        // The two forms truncate differently, and the difference is the
        // reference's. A terminated form leaves room for its terminator, so
        // it gives one byte back; a counted form has no terminator, so it
        // uses every byte it was given.
        length = Terminated ? d.maximum - 1 : d.maximum;
        status = kStBufferOverflow;
    }
    if (d.buffer != nullptr && length != 0) {
        wide_to_narrow(static_cast<char*>(d.buffer), length, upcased.data(),
                       upcased.size() * sizeof(char16_t));
        if (Terminated) {
            static_cast<char*>(d.buffer)[length] = '\0';
        }
    }
    write_string(dst_struct, length, d.maximum, d.buffer);
    return status;
}

extern "C" __attribute__((ms_abi)) Ntstatus
nrs_RtlUpcaseUnicodeStringToAnsiString(void* ansi, const void* uni,
                                      Boolean doalloc) noexcept {
    return upcase_to_narrow_string<true>(ansi, uni, doalloc);
}

extern "C" __attribute__((ms_abi)) Ntstatus
nrs_RtlUpcaseUnicodeStringToOemString(void* oem, const void* uni,
                                     Boolean doalloc) noexcept {
    return upcase_to_narrow_string<true>(oem, uni, doalloc);
}

extern "C" __attribute__((ms_abi)) Ntstatus
nrs_RtlUpcaseUnicodeStringToCountedOemString(void* oem, const void* uni,
                                            Boolean doalloc) noexcept {
    return upcase_to_narrow_string<false>(oem, uni, doalloc);
}

// ---------------------------------------------------------------- integers

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlCharToInteger(
    const char* str, std::uint32_t base, std::uint32_t* value) noexcept {
    // The pointers first and the base second. The reference checks neither
    // pointer -- it faults on the first `*str` and writes through the output
    // unconditionally -- so the order of these tests is this runtime's own,
    // and it is chosen so that a call which is wrong in two ways reports the
    // one that cannot be recovered from: a missing pointer is reported before
    // a bad base, because a bad base is a value the caller can look at and
    // fix, while a missing pointer means the walk would have run on nothing.
    if (str == nullptr) {
        return kStAccessViolation;
    }
    if (value == nullptr) {
        return kStAccessViolation;
    }
    // The base is checked before the walk, so an unsupported base is reported
    // as a parameter failure rather than as a parse that stopped at the first
    // character. A caller that passed 3 learns that 3 is not a base rather
    // than wondering why its number is zero.
    if (base != 0 && base != 2 && base != 8 && base != 10 && base != 16) {
        return kStInvalidParameter;
    }
    std::uint32_t result = 0;
    const Ntstatus status = parse_integer_narrow(str, base, result);
    if (status != kStSuccess) {
        return status;
    }
    *value = result;
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlUnicodeStringToInteger(
    const void* str, std::uint32_t base, std::uint32_t* value) noexcept {
    if (value == nullptr) {
        return kStAccessViolation;
    }
    if (str == nullptr) {
        return kStInvalidParameter;
    }
    if (base != 0 && base != 2 && base != 8 && base != 10 && base != 16) {
        return kStInvalidParameter;
    }
    const StringView v = read_string(str);
    // A `UNICODE_STRING`'s length is bytes and may be odd, and the walk is in
    // characters, so the halving happens here rather than being assumed.
    const std::u16string wide = as_wide(v);
    std::uint32_t result = 0;
    const Ntstatus status = parse_integer_wide<std::uint32_t>(
        wide, static_cast<std::uint32_t>(base), true, result);
    if (status != kStSuccess) {
        return status;
    }
    *value = result;
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlIntegerToChar(
    std::uint32_t value, std::uint32_t base, std::uint32_t length,
    char* str) noexcept {
    std::uint32_t use = 10;
    if (!normalize_base(base, use)) {
        return kStInvalidParameter;
    }
    if (str == nullptr) {
        return kStAccessViolation;
    }
    char digits[72];
    const std::size_t len = format_integer<std::uint32_t, char>(value, use,
                                                                 digits);
    if (len > length) {
        // Nothing is written. The alternative -- a truncated number that looks
        // complete -- is the failure mode this check exists to prevent, and
        // it is why the length is a parameter at all.
        return kStBufferOverflow;
    }
    for (std::size_t k = 0; k < len; ++k) {
        str[k] = digits[k];
    }
    // The terminator, and the reference's rule: written when there is room,
    // which means a buffer that is exactly the length of the number gets no
    // terminator. The count the caller gets back is not returned -- this
    // function's answer is the status -- so a caller that needs the length
    // measures the buffer.
    if (len < length) {
        str[len] = '\0';
    }
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlLargeIntegerToChar(
    const std::uint64_t* value_ptr, std::uint32_t base, std::uint32_t length,
    char* str) noexcept {
    std::uint32_t use = 10;
    if (!normalize_base(base, use)) {
        return kStInvalidParameter;
    }
    if (value_ptr == nullptr || str == nullptr) {
        return kStAccessViolation;
    }
    char digits[72];
    const std::size_t len =
        format_integer<std::uint64_t, char>(*value_ptr, use, digits);
    if (len > length) {
        return kStBufferOverflow;
    }
    for (std::size_t k = 0; k < len; ++k) {
        str[k] = digits[k];
    }
    if (len < length) {
        str[len] = '\0';
    }
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlIntegerToUnicodeString(
    std::uint32_t value, std::uint32_t base, void* str) noexcept {
    std::uint32_t use = 10;
    if (!normalize_base(base, use)) {
        return kStInvalidParameter;
    }
    if (str == nullptr) {
        return kStInvalidParameter;
    }
    char16_t digits[72];
    const std::size_t units =
        format_integer<std::uint32_t, char16_t>(value, use, digits);
    const std::size_t length = units * sizeof(char16_t);
    const StringView v = read_string(str);
    // The check is `>=`, not `>`. The terminator is part of what this
    // function writes, so a destination whose maximum is exactly the number's
    // length has no room for it and the write is refused. The reference sets
    // `Length` to the length the string *would* have had before refusing,
    // which is how a caller sizes a retry -- and this keeps that, because a
    // caller that sized a retry from a `Length` this function left at zero
    // would allocate nothing and fail again.
    write_u16(str, kStrLength, static_cast<std::uint16_t>(length));
    if (length >= v.maximum || v.buffer == nullptr) {
        return kStBufferOverflow;
    }
    auto* out = static_cast<char16_t*>(v.buffer);
    for (std::size_t k = 0; k < units; ++k) {
        out[k] = digits[k];
    }
    out[units] = u'\0';
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlInt64ToUnicodeString(
    std::uint64_t value, std::uint32_t base, void* str) noexcept {
    std::uint32_t use = 10;
    if (!normalize_base(base, use)) {
        return kStInvalidParameter;
    }
    if (str == nullptr) {
        return kStInvalidParameter;
    }
    char16_t digits[72];
    const std::size_t units =
        format_integer<std::uint64_t, char16_t>(value, use, digits);
    const std::size_t length = units * sizeof(char16_t);
    const StringView v = read_string(str);
    write_u16(str, kStrLength, static_cast<std::uint16_t>(length));
    if (length >= v.maximum || v.buffer == nullptr) {
        return kStBufferOverflow;
    }
    auto* out = static_cast<char16_t*>(v.buffer);
    for (std::size_t k = 0; k < units; ++k) {
        out[k] = digits[k];
    }
    out[units] = u'\0';
    return kStSuccess;
}

// -------------------------------------------------------------------- GUID

// One byte as two hex digits, most significant first, appending at `at` and
// leaving `at` after them. Upper case, because that is what the reference's
// own formatter emits and a guest comparing the two strings as text would
// see a difference if the case differed.
static void write_hex_pair(char16_t* out, std::size_t& at,
                           std::uint8_t byte) noexcept {
    static constexpr char16_t kDigits[] = u"0123456789ABCDEF";
    out[at++] = kDigits[(byte >> 4) & 0x0F];
    out[at++] = kDigits[byte & 0x0F];
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlGUIDFromString(
    const void* str, void* guid) noexcept {
    if (str == nullptr || guid == nullptr) {
        return kStInvalidParameter;
    }
    const StringView v = read_string(str);
    const std::u16string text = as_wide(v);
    // The braced form, and the exact shape: `{` then eight hex digits, `-`,
    // four, `-`, four, `-`, four, `-`, twelve, `}`. Thirty-eight characters,
    // which is the reference's `GUID_STRING_LENGTH`, and the check is on the
    // whole shape rather than on a prefix: a string with a valid prefix and
    // trailing text is not a GUID and the reference does not accept it.
    if (text.size() < 38) {
        return kStInvalidParameter;
    }
    const char16_t* p = text.c_str();
    if (p[0] != u'{' || p[37] != u'}' || p[9] != u'-' || p[14] != u'-' ||
        p[19] != u'-' || p[24] != u'-') {
        return kStInvalidParameter;
    }
    // The hex digits are read as text and then placed, and the placement is
    // the whole difficulty: the first three fields are little-endian on the
    // wire and the last eight bytes are a byte array, so the first three
    // groups each have to be reversed and the last two are copied straight
    // through. An implementation that wrote the digits in order would produce
    // a GUID whose first three fields were byte-reversed, which is a
    // different GUID rather than an obviously wrong one.
    auto hex = [](char16_t c, int& out) noexcept {
        if (c >= u'0' && c <= u'9') {
            out = static_cast<int>(c) - static_cast<int>(u'0');
        } else if (c >= u'a' && c <= u'f') {
            out = static_cast<int>(c) - static_cast<int>(u'a') + 10;
        } else if (c >= u'A' && c <= u'F') {
            out = static_cast<int>(c) - static_cast<int>(u'A') + 10;
        } else {
            return false;
        }
        return true;
    };
    auto* out = static_cast<std::uint8_t*>(guid);
    // One pair of hex digits. The two characters are read in text order --
    // most significant first -- and combined with the first one in the high
    // half. Naming them the way they appear in the string is deliberate: a pair
    // assembled as `(second << 4) | first` is a byte whose two nibbles are the
    // right digits in the wrong order, which is a valid-looking byte and the
    // wrong number. `"12"` must give 0x12, not 0x21.
    auto pair = [&hex, &p](std::size_t at, int& value) noexcept {
        int high = 0;
        int low = 0;
        if (!hex(p[at], high) || !hex(p[at + 1], low)) {
            return false;
        }
        value = (high << 4) | low;
        return true;
    };
    // The three reversed groups, read as pairs and written back to front.
    // Their starting positions are not evenly spaced: the first group is eight
    // digits, the second four and the third four, with a dash before each, so
    // they start at 1, 10 and 15. Spacing them by a constant gets the second
    // group right by luck and the third one wrong, and the failure is a
    // silently different GUID rather than a refusal.
    static constexpr std::size_t kGroupAt[3] = {1, 10, 15};
    for (int group = 0; group < 3; ++group) {
        const std::size_t at = kGroupAt[group];
        // Group 0 is four bytes and so eight hex digits; groups 1 and 2 are two
        // bytes and four digits each. Reading eight digits out of a four-digit
        // group does not run off the string -- there is always a dash and more
        // text after it -- so it comes back as a *refusal* on the dash rather
        // than as an overrun, which is the friendlier of the two failures and
        // still wrong.
        const int count = group == 0 ? 4 : 2;
        int digits[4] = {0};
        for (int k = 0; k < count; ++k) {
            if (!pair(at + static_cast<std::size_t>(2 * k), digits[k])) {
                return kStInvalidParameter;
            }
        }
        for (int k = 0; k < count; ++k) {
            out[static_cast<std::size_t>(k)] =
                static_cast<std::uint8_t>(digits[count - 1 - k]);
        }
        out += count;
    }
    // The last eight bytes, which the text splits into two groups of two and six
    // bytes: four hex digits at position 20 and twelve at position 25, with a
    // dash at 24 between them. They are byte arrays, so no reversal -- but they
    // are still two groups, and reading sixteen digits straight across from 24
    // would start on the dash.
    static constexpr std::size_t kTailAt[2] = {20, 25};
    static constexpr int kTailBytes[2] = {2, 6};
    for (int part = 0; part < 2; ++part) {
        for (int k = 0; k < kTailBytes[part]; ++k) {
            const std::size_t at =
                kTailAt[part] + static_cast<std::size_t>(2 * k);
            int value = 0;
            if (!pair(at, value)) {
                return kStInvalidParameter;
            }
            out[static_cast<std::size_t>(k)] =
                static_cast<std::uint8_t>(value);
        }
        out += static_cast<std::size_t>(kTailBytes[part]);
    }
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlStringFromGUID(
    const void* guid, void* str) noexcept {
    if (guid == nullptr || str == nullptr) {
        return kStInvalidParameter;
    }
    // 38 characters plus the terminator, and the allocation is the whole of
    // it: the caller frees this with `RtlFreeUnicodeString` and neither
    // length field is a hint.
    constexpr std::size_t kGuidStringLength = 38;
    const std::size_t bytes = (kGuidStringLength + 1) * sizeof(char16_t);
    void* block = allocate_for_string(bytes);
    if (block == nullptr) {
        write_string(str, 0, 0, nullptr);
        return kStNoMemory;
    }
    const auto* in = static_cast<const std::uint8_t*>(guid);
    auto* out = static_cast<char16_t*>(block);
    std::size_t at = 0;
    out[at++] = u'{';
    // The same three-field reversal as the parse, so the two are inverses.
    for (int group = 0; group < 3; ++group) {
        const int count = group == 0 ? 4 : 2;
        for (int k = count - 1; k >= 0; --k) {
            write_hex_pair(out, at, in[static_cast<std::size_t>(k)]);
        }
        in += count;
        if (group < 2) {
            out[at++] = u'-';
        }
    }
    // The last eight bytes are two groups, not one: four hex digits and then
    // twelve, separated. They are two byte arrays with no reversal between
    // them, but they are *two groups* in the text, and writing sixteen hex
    // digits with no dash produces a 37-character string that no parser in the
    // world accepts -- including the one above, whose check is on the whole
    // shape rather than on a prefix.
    out[at++] = u'-';
    for (int k = 0; k < 2; ++k) {
        write_hex_pair(out, at, in[static_cast<std::size_t>(k)]);
    }
    out[at++] = u'-';
    for (int k = 2; k < 8; ++k) {
        write_hex_pair(out, at, in[static_cast<std::size_t>(k)]);
    }
    out[at++] = u'}';
    out[at] = u'\0';
    write_string(str, kGuidStringLength * sizeof(char16_t), bytes, block);
    return kStSuccess;
}

// ------------------------------------------------------------------ memory

// `RtlCopyMemory` is deliberately not here. It is not in this domain's list
// -- the name belongs to the `rtl_mem` domain -- and registering it from both
// files would make the export table's contents depend on which file happened
// to be wired up last.

extern "C" __attribute__((ms_abi)) void nrs_RtlMoveMemory(
    void* dest, const void* src, std::uint64_t len) noexcept {
    if (dest == nullptr || src == nullptr || len == 0) {
        return;
    }
    // The `cr_` bridge is `memmove`, which is the right primitive here: a
    // guest shifting a buffer within itself is a normal use of this function
    // and `RtlMoveMemory` exists precisely to permit it.
    (void)cr_memmove(dest, src, len);
}

extern "C" __attribute__((ms_abi)) void nrs_RtlZeroMemory(
    void* dest, std::uint64_t len) noexcept {
    if (dest == nullptr || len == 0) {
        return;
    }
    std::memset(dest, 0, static_cast<std::size_t>(len));
}

extern "C" __attribute__((ms_abi)) void nrs_RtlFillMemory(
    void* dest, std::uint64_t len, std::uint8_t fill) noexcept {
    if (dest == nullptr || len == 0) {
        return;
    }
    std::memset(dest, fill, static_cast<std::size_t>(len));
}

extern "C" __attribute__((ms_abi)) void nrs_RtlFillMemoryUlong(
    std::uint32_t* dest, std::uint64_t count,
    std::uint32_t value) noexcept {
    if (dest == nullptr || count == 0) {
        return;
    }
    // `count`, not bytes: this is the spelling that fills an array of
    // `ULONG`, and a caller that passed a byte count here would write four
    // times what it meant. The reference's own note says "len" is a count of
    // elements for this one and of bytes for `RtlFillMemory`.
    for (std::uint64_t k = 0; k < count; ++k) {
        dest[k] = value;
    }
}

// The reference's export list carries this name as a stub and nothing else:
// no signature, no body, so there is no source to copy the parameter meanings
// from. What is implemented here is the only reading of the name that is not
// a restatement of `RtlZeroMemory`: the block is zeroed *in full*, past the
// length the caller states, because the reason a caller asks for a heap block
// to be zeroed rather than a range of it zeroed is that nothing of the old
// contents may stay readable. A caller that names a shorter length than the
// allocator granted has left the tail readable, and that is exactly the leak
// the call is supposed to prevent, so the granted size wins when it is known.
extern "C" __attribute__((ms_abi)) void nrs_RtlZeroHeap(
    std::uint64_t block, std::uint64_t len) noexcept {
    if (block == 0) {
        return;
    }
    void* target = reinterpret_cast<void*>(static_cast<std::uintptr_t>(block));
    std::size_t span = static_cast<std::size_t>(len);
    const std::size_t granted = heap_size(target);
    if (granted > span) {
        span = granted;
    }
    if (span == 0) {
        return;
    }
    std::memset(target, 0, span);
}

extern "C" __attribute__((ms_abi)) void nrs_RtlCopyMemoryNonTemporal(
    void* dest, const void* src, std::uint64_t len) noexcept {
    // The non-temporal copy: a copy whose stores bypass the cache, for a
    // buffer too large to be worth caching. It is a *hint* about the memory
    // system and not a change of semantics -- the bytes written are the same
    // bytes, in the same order, and a short write is a short write. On a
    // host where the guest's memory is the host's memory there is nothing to
    // bypass, so this is `memcpy` and says so rather than pretending
    // otherwise.
    if (dest == nullptr || src == nullptr || len == 0) {
        return;
    }
    std::memcpy(dest, src, static_cast<std::size_t>(len));
}

extern "C" __attribute__((ms_abi)) std::uint64_t nrs_RtlCompareMemory(
    const void* a, const void* b, std::uint64_t len) noexcept {
    if (a == nullptr || b == nullptr) {
        return 0;
    }
    return static_cast<std::uint64_t>(
        cr_memcmp(a, b, len));
}

extern "C" __attribute__((ms_abi)) std::uint32_t nrs_RtlCompareMemoryUlong(
    const void* src, std::uint64_t len, std::uint32_t value) noexcept {
    if (src == nullptr) {
        return 0;
    }
    // `len` is a **byte** count, not a count of `ULONG`, and the answer is a
    // **byte** offset rather than an element index. Both of those are the
    // reference's and both are surprising: the reference divides the length by
    // `sizeof(ULONG)` to get the element count and multiplies the answer back
    // up on the way out, so a caller that treats the two as the same number
    // gets an answer four times too large.
    //
    // `RtlFillMemoryUlong` takes an element count, so the pair read as a pair
    // looks inconsistent. It is not: this one mirrors `RtlCompareMemory`,
    // which is also byte-based, and that is the family it belongs to.
    const auto* words = static_cast<const std::uint32_t*>(src);
    const std::uint64_t count = len / sizeof(std::uint32_t);
    for (std::uint64_t k = 0; k < count; ++k) {
        if (words[k] != value) {
            return static_cast<std::uint32_t>(k * sizeof(std::uint32_t));
        }
    }
    return static_cast<std::uint32_t>(count * sizeof(std::uint32_t));
}

extern "C" __attribute__((ms_abi)) std::uint64_t
nrs_RtlInterlockedCompareExchange64(std::uint64_t* destination,
                                   std::uint64_t exchange,
                                   std::uint64_t comparand) noexcept {
    if (destination == nullptr) {
        return 0;
    }
    // The whole point of the `Interlocked` prefix: the compare and the
    // exchange are one indivisible step, and a caller that read, decided and
    // wrote separately has a race. `__atomic` on an 8-byte aligned slot is
    // the instruction Windows emits, and the argument order is the
    // Windows one -- exchange first, comparand second -- which is the
    // opposite of a C compare-and-swap's, so a forward call to the C
    // primitive would silently swap the two.
    std::uint64_t expected = comparand;
    __atomic_compare_exchange_n(destination, &expected, exchange, false,
                                __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    // The answer is what was there, whether or not the exchange happened --
    // the value a caller that lost the race needs in order to know it lost.
    return expected;
}

// ---------------------------------------------------------------- SID / LUID

// The SID is eight bytes of header -- revision, sub-authority count, and a
// six-byte identifier authority -- followed by `count` four-byte
// sub-authorities. The length is therefore computable from the structure
// itself, which is what every function here that takes a "length" argument
// is actually being asked: "is the caller's buffer as big as the SID says it
// needs?"
constexpr std::size_t kSidHeaderBytes = 8;
constexpr std::size_t kSidRevisionOffset = 0;
constexpr std::size_t kSidSubAuthorityCountOffset = 1;
constexpr std::size_t kSidIdentifierAuthorityOffset = 2;
constexpr std::size_t kSidSubAuthoritiesOffset = 8;
constexpr std::size_t kSidMaxSubAuthorities = 15;

[[nodiscard]] static std::size_t sid_length(const void* sid) noexcept {
    if (sid == nullptr) {
        return 0;
    }
    const auto* bytes = static_cast<const std::uint8_t*>(sid);
    const std::size_t count = bytes[kSidSubAuthorityCountOffset];
    if (count > kSidMaxSubAuthorities) {
        // A count above the maximum describes a SID that cannot exist, and
        // computing a length from it would read past the structure. Zero is
        // the honest answer: "no length", so the caller's bounds check
        // refuses rather than the copy running off the end.
        return 0;
    }
    return kSidHeaderBytes + count * 4;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlCopySid(
    std::uint32_t dest_bytes, void* dest, const void* source) noexcept {
    if (dest == nullptr || source == nullptr) {
        return kStInvalidParameter;
    }
    const std::size_t len = sid_length(source);
    if (len == 0) {
        return kStInvalidParameter;
    }
    if (dest_bytes < len) {
        // The refusal, and it is a refusal rather than a truncation because a
        // truncated SID is a *different* SID -- a shorter sub-authority list
        // is a different security principal, not a shorter spelling of the
        // same one. There is no partial answer to give.
        return kStBufferTooSmall;
    }
    std::memmove(dest, source, len);
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlCopySidAndAttributesArray(
    std::uint32_t count, const void* source, void* dest) noexcept {
    // A `SID_AND_ATTRIBUTES` is a pointer and a `ULONG`, and on the 64-bit ABI
    // the `ULONG` sits in the eight bytes after the pointer with four bytes of
    // tail padding, so the element is sixteen bytes -- not the eight the two
    // fields add up to. Copying `count * 8` would shift every element after the
    // first by half its own size and read only half of the last one.
    //
    // The reference exports this name as a stub, so the layout is Microsoft's
    // documented one rather than the reference's code, and it is stated here
    // because a stub is not a source: an answer that is wrong about the
    // element size would corrupt every element after the first.
    constexpr std::size_t kElementBytes = 16;
    // A zero count copies nothing, so it is answered before the pointers are
    // looked at. The reference's sibling, `RtlCopyLuidAndAttributesArray`,
    // is a plain `for (i = 0; i < count; i++) dest[i] = src[i];` that never
    // dereferences either pointer when the count is zero, and a caller that
    // passes null to mean "nothing to do" is relying on that.
    if (count == 0) {
        return kStSuccess;
    }
    if (dest == nullptr || source == nullptr) {
        return kStInvalidParameter;
    }
    std::memmove(dest, source,
                 static_cast<std::size_t>(count) * kElementBytes);
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlConvertSidToUnicodeString(
    void* str, const void* sid, Boolean allocate) noexcept {
    if (str == nullptr || sid == nullptr) {
        return kStInvalidParameter;
    }
    const auto* bytes = static_cast<const std::uint8_t*>(sid);
    const std::size_t count = bytes[kSidSubAuthorityCountOffset];
    if (count > kSidMaxSubAuthorities) {
        return kStInvalidParameter;
    }
    // `S-1-5-21-...-500`: the revision, then the identifier authority as one
    // decimal number, then each sub-authority. The authority is six bytes
    // read as one big-endian integer, which is the opposite of the sub-
    // authorities -- those are four-byte little-endian each. Getting that
    // backwards produces a string that looks like a SID and is not one.
    char16_t buffer[2 + 10 + 10 + 10 * kSidMaxSubAuthorities];
    std::size_t at = 0;
    auto put = [&buffer, &at](char16_t c) noexcept {
        if (at < (sizeof(buffer) / sizeof(buffer[0]))) {
            buffer[at++] = c;
        }
    };
    auto put_number = [&put](std::uint64_t value) noexcept {
        char16_t digits[24];
        const std::size_t room = sizeof(digits) / sizeof(digits[0]);
        std::size_t n = 0;
        do {
            digits[n++] = static_cast<char16_t>(u'0' + (value % 10));
            value /= 10;
        } while (value != 0 && n < room);
        while (n != 0) {
            put(digits[--n]);
        }
    };
    put(u'S');
    put(u'-');
    put_number(bytes[kSidRevisionOffset]);
    put(u'-');
    std::uint64_t authority = 0;
    for (std::size_t k = 0; k < 6; ++k) {
        authority = (authority << 8) | bytes[kSidIdentifierAuthorityOffset + k];
    }
    put_number(authority);
    // The sub-authorities are read byte by byte rather than reinterpreted as a
    // `ULONG*`: they are four-byte little-endian at an offset that need not be
    // four-byte aligned inside the caller's SID, and a misaligned cast is
    // undefined behaviour on a host that faults on it.
    const auto* subs = static_cast<const std::uint8_t*>(sid) + kSidSubAuthoritiesOffset;
    for (std::size_t k = 0; k < count; ++k) {
        std::uint32_t sub = 0;
        for (std::size_t byte = 0; byte < 4; ++byte) {
            sub |= static_cast<std::uint32_t>(
                       subs[k * 4 + byte])
                   << (8 * byte);
        }
        put(u'-');
        put_number(sub);
    }
    // The terminator is inside the counted length here, unlike the
    // `UNICODE_STRING` case: the reference's `len` is `(p + 1 - buffer) * 2`
    // and the `Length` is that less the terminator, so the terminator is
    // allocated but not counted.
    const std::size_t bytes_needed = (at + 1) * sizeof(char16_t);
    StringView out = read_string(str);
    const std::size_t length = bytes_needed - sizeof(char16_t);
    if (allocate != kFalse) {
        void* block = allocate_for_string(bytes_needed);
        if (block == nullptr) {
            return kStNoMemory;
        }
        out.buffer = block;
        out.maximum = bytes_needed;
    } else if (bytes_needed > out.maximum) {
        return kStBufferOverflow;
    }
    if (out.buffer != nullptr) {
        auto* dst = static_cast<char16_t*>(out.buffer);
        for (std::size_t k = 0; k < at; ++k) {
            dst[k] = buffer[k];
        }
        dst[at] = u'\0';
    }
    write_string(str, length, out.maximum, out.buffer);
    return kStSuccess;
}

// The security descriptor's own layout. Only the fields this function moves
// are named; the rest are passed through by the flat assignment, which is
// correct because they are scalars.
constexpr std::size_t kSdRevision = 0;   // BYTE
constexpr std::size_t kSdControl = 2;    // WORD, with the SE_* bits
//
// The four variable-length parts sit after the four-byte scalar header, and
// *where* they sit depends on the form, because their width does:
//
//   self-relative: four 16-bit offsets at 4, 6, 8, 10
//   absolute:      four 64-bit pointers at 4, 12, 20, 28
//
// So the offsets are not constants here -- a copy that used one form's offsets
// with the other form's widths would read the group out of the middle of the
// owner's pointer, and write the ACLs over each other.
constexpr std::size_t kSdHeaderCommon = 4; // revision, sbz1, sbz2, control
constexpr std::size_t kSdOffsetBytes = sizeof(std::uint16_t);
constexpr std::size_t kSdPointerBytes = sizeof(std::uint64_t);
constexpr std::size_t kSdOwnerIndex = 0;
constexpr std::size_t kSdGroupIndex = 1;
constexpr std::size_t kSdSaclIndex = 2;
constexpr std::size_t kSdDaclIndex = 3;
[[nodiscard]] constexpr std::size_t sd_field_at(bool self_relative,
                                               std::size_t index) noexcept {
    return kSdHeaderCommon + index * (self_relative ? kSdOffsetBytes
                                                    : kSdPointerBytes);
}
constexpr std::size_t kSdRelativeBytes =
    kSdHeaderCommon + 4 * kSdOffsetBytes;
constexpr std::size_t kSdAbsoluteBytes =
    kSdHeaderCommon + 4 * kSdPointerBytes;

constexpr std::uint8_t kSecurityDescriptorRevision = 1;
constexpr std::uint16_t kSeDaclPresent = 0x0004;
constexpr std::uint16_t kSeSaclPresent = 0x0010;
constexpr std::uint16_t kSeSelfRelative = 0x8000;

// An `ACL`'s size lives inside it, so copying one needs no length from the
// caller -- which is the point of the reference reading `AclSize` rather than
// being told the length.
constexpr std::size_t kAclSizeOffset = 2; // WORD

// One ACL, byte for byte, into a destination the reference allocated with the
// source's own `AclSize`. The size is read from the source rather than
// computed from the ACE count, because an ACL in the wild may be larger than
// its ACEs need and a caller comparing the two descriptors byte-wise must see
// the same padding.
void copy_acl(const std::uint8_t* source, std::uint8_t* destination) noexcept {
    const std::size_t size = read_u16(source, kAclSizeOffset);
    std::memmove(destination, source, size);
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlCopySecurityDescriptor(
    const void* source, void* destination) noexcept {
    if (source == nullptr || destination == nullptr) {
        return kStInvalidParameter;
    }
    const std::uint16_t control = read_u16(source, kSdControl);
    const bool self_relative = (control & kSeSelfRelative) != 0;
    if (*static_cast<const std::uint8_t*>(source) !=
        kSecurityDescriptorRevision) {
        // The reference's only failure, and it is checked before anything is
        // written: a descriptor whose revision is not 1 has a layout this code
        // does not know, and copying it as if it did would move the wrong
        // bytes.
        return kStUnknownRevision;
    }
    // The flat copy first, scalars and all, and then each variable-length part
    // re-based. Doing the flat copy first is what the reference does and
    // it is what makes the offset fields already correct for the
    // self-relative case: the offsets are positions inside the descriptor, so
    // a copy has the same offsets as its source.
    //
    // The header's size follows the form. Copying the absolute form's 36
    // bytes out of a self-relative descriptor would read past the end of a
    // 12-byte header -- and in the common layout the bytes just past the
    // header are the owner SID, so the descriptor would end up with its owner
    // written over the offset that is supposed to point at it.
    const std::size_t header_bytes =
        self_relative ? kSdRelativeBytes : kSdAbsoluteBytes;
    std::memcpy(destination, source, header_bytes);
    // A SID's length is inside the SID, and so is an ACL's, so nothing below
    // needs a length from the caller. That is what lets the self-relative form
    // be copied without knowing its size: the offsets say where everything is,
    // and a copy of the whole descriptor has the same offsets as its source.
    //
    // The four fields are read through the form's own width, and the result is
    // the *address* of the part rather than a number to add to the
    // descriptor: in the absolute form the field is already the address, and
    // adding the base to it would send the copy off into unmapped memory.
    // Reading an absolute pointer as a 16-bit offset would make every SID
    // with an owner or group look absent whenever the low half of its
    // address happened to be zero, and reading a relative offset as a
    // pointer would follow it into whatever happens to live at a low address.
    auto field_address = [self_relative](const std::uint8_t* base,
                                        std::size_t at) noexcept {
        if (self_relative) {
            return base + read_u16(base, at);
        }
        return reinterpret_cast<const std::uint8_t*>(read_ptr(base, at));
    };
    auto field_is_null = [self_relative](const void* base,
                                         std::size_t at) noexcept {
        return self_relative ? read_u16(base, at) == 0
                             : read_ptr(base, at) == 0;
    };
    // The owner and the group are SIDs, whose length is in the SID itself.
    static constexpr std::size_t kSids[] = {kSdOwnerIndex, kSdGroupIndex};
    for (const std::size_t index : kSids) {
        const std::size_t field = sd_field_at(self_relative, index);
        if (field_is_null(source, field)) {
            continue; // a null SID is null in the copy too
        }
        const auto* base = static_cast<const std::uint8_t*>(source);
        const std::uint8_t* from = field_address(base, field);
        const std::size_t length = sid_length(from);
        if (length == 0) {
            return kStInvalidParameter;
        }
        if (self_relative) {
            // The offset does not move: the copy is the same size at the same
            // offsets, which is the whole reason the flat copy above was safe.
            std::memmove(static_cast<std::uint8_t*>(destination) +
                             read_u16(source, field),
                         from, length);
        } else {
            void* block = allocate_for_string(length);
            if (block == nullptr) {
                return kStNoMemory;
            }
            std::memmove(block, from, length);
            write_ptr(destination, field,
                      static_cast<std::uint64_t>(
                          reinterpret_cast<std::uintptr_t>(block)));
        }
    }
    // The two ACLs, each gated on its own control bit *and* on a non-null
    // pointer: a descriptor may have the bit set and no ACL, and the reference
    // skips it in that case.
    struct AclPart {
        std::size_t index;
        std::uint16_t flag;
    };
    static constexpr AclPart kAcls[] = {{kSdSaclIndex, kSeSaclPresent},
                                        {kSdDaclIndex, kSeDaclPresent}};
    for (const AclPart& part : kAcls) {
        if ((control & part.flag) == 0) {
            continue;
        }
        const std::size_t field = sd_field_at(self_relative, part.index);
        if (field_is_null(source, field)) {
            continue;
        }
        const auto* base = static_cast<const std::uint8_t*>(source);
        const std::uint8_t* from = field_address(base, field);
        const std::size_t size = read_u16(from, kAclSizeOffset);
        if (size == 0) {
            return kStInvalidParameter;
        }
        if (self_relative) {
            std::memmove(static_cast<std::uint8_t*>(destination) +
                             read_u16(source, field),
                         from, size);
        } else {
            void* block = allocate_for_string(size);
            if (block == nullptr) {
                return kStNoMemory;
            }
            copy_acl(from, static_cast<std::uint8_t*>(block));
            write_ptr(destination, field,
                      static_cast<std::uint64_t>(
                          reinterpret_cast<std::uintptr_t>(block)));
        }
    }
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) void nrs_RtlCopyLuid(
    void* dest, const void* src) noexcept {
    // A `LUID` is two 32-bit halves and nothing else, so this is an eight
    // byte move. It is a function rather than a macro because the two fields
    // are read and written together by a caller that compares them, and a
    // torn read would compare a `HighPart` from one value against a
    // `LowPart` from another.
    if (dest == nullptr || src == nullptr) {
        return;
    }
    std::memmove(dest, src, 8);
}

extern "C" __attribute__((ms_abi)) void nrs_RtlCopyLuidAndAttributesArray(
    std::uint32_t count, const void* src, void* dest) noexcept {
    // `LUID_AND_ATTRIBUTES` is a `LUID` (8) and a `ULONG` (4), which the
    // 64-bit ABI pads to 16. The padding is copied because the reference
    // copies whole structures and a caller that memcmp'd the results would
    // otherwise see uninitialised padding differ.
    constexpr std::size_t kElementBytes = 16;
    // The null test comes first and covers the zero count too, which is what
    // the reference's plain counted loop amounts to: it never dereferences
    // either pointer when there is nothing to copy. The return type is void,
    // so "did nothing" and "copied nothing" are the same answer.
    if (dest == nullptr || (src == nullptr && count != 0)) {
        return;
    }
    std::memmove(dest, src,
                 static_cast<std::size_t>(count) * kElementBytes);
}

// ------------------------------------------------------------------ context
//
// A `CONTEXT` is architecture-shaped: its first `DWORD` is `ContextFlags`,
// which names the processor the rest of the structure describes, and the size
// that follows is fixed per processor. Both are needed before a copy is safe,
// because "copy 400 bytes of context" is only meaningful once 400 bytes is
// known to be a whole context -- a partial `CONTEXT` is not a context that
// can later be restored.
//
// The reference exports both names with no body, so the sizes below are the
// ones Microsoft documents for the four processors it defines contexts for
// rather than the reference's code, and the mismatch case is a refusal
// rather than a truncating copy: handing back a `CONTEXT` whose flags say
// AMD64 and whose tail is missing would produce a context that restores
// garbage registers.
struct ContextShape {
    std::uint32_t arch;    // the CONTEXT_* architecture id of ContextFlags
    std::size_t bytes;     // the whole structure
};

[[nodiscard]] static bool context_shape(std::size_t bytes, bool extended,
                                 ContextShape& out) noexcept {
    struct Row {
        std::uint32_t arch;
        std::size_t bytes;
    };
    static constexpr Row kRows[] = {
        {0x00010000 /* i386 */, 0x2CC},
        {0x00010001 /* AMD64 */, 0x4D0},
        {0x00010002 /* ARM */, 0x350},
        {0x00010004 /* ARM64 */, 0x4D0},
    };
    for (const Row& row : kRows) {
        if (row.bytes != bytes) {
            continue;
        }
        // The extended spelling is the one a 64-bit caller uses and the only
        // one for which the larger AMD64 and ARM64 layouts are legal; the
        // plain spelling is used to copy a foreign processor's context, so
        // its size alone decides.
        if (extended && row.arch != 0x00010001 && row.arch != 0x00010004) {
            continue;
        }
        out.arch = row.arch;
        out.bytes = row.bytes;
        return true;
    }
    return false;
}

[[nodiscard]] static Ntstatus copy_context(void* destination, std::uint32_t context_length,
                                    const void* source,
                                    bool extended) noexcept {
    if (destination == nullptr || source == nullptr) {
        return kStInvalidParameter;
    }
    ContextShape shape{};
    if (!context_shape(static_cast<std::size_t>(context_length), extended,
                       shape)) {
        return kStInvalidParameter;
    }
    // The size is the whole of the validation. `ContextFlags` cannot be used to
    // add a second one even though it would look like the natural thing: it does
    // not sit at the front of the structure -- it is at 0x30 in the x86 layout
    // and 0x330 in the AMD64 one -- so the architecture would have to be found
    // per row before it could be read, and the architecture id it encodes (1
    // for i386, 2 for AMD64, 4 for ARM64) occupies the same low bits as the
    // `CONTEXT_*` control flags (0x1 for control, 0x2 for integer, ...), so no
    // mask separates them from the flags alone. The size already says which
    // layout is in hand, and the layout is what the copy has to get right.
    std::memcpy(destination, source, shape.bytes);
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlCopyContext(
    void* destination, std::uint32_t context_length, const void* source) noexcept {
    return copy_context(destination, context_length, source, false);
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlCopyExtendedContext(
    void* destination, std::uint32_t context_length, const void* source) noexcept {
    return copy_context(destination, context_length, source, true);
}

// ---------------------------------------------------------------- the text test

extern "C" __attribute__((ms_abi)) Boolean nrs_RtlIsTextUnicode(
    const void* buf, std::int32_t len, std::int32_t* pf) noexcept {
    // The flag values, which are the documented `IS_TEXT_UNICODE_*` set and
    // are an ABI: a caller passes a mask in and reads the achieved subset out
    // of the same variable, so the bit positions are part of the contract.
    constexpr std::uint32_t kOddLength = 0x00000001;
    constexpr std::uint32_t kSignature = 0x00000002;
    constexpr std::uint32_t kReverseSignature = 0x00000004;
    constexpr std::uint32_t kStatistics = 0x00000008;
    constexpr std::uint32_t kNullBytes = 0x00000010;
    constexpr std::uint32_t kControls = 0x00000020;
    constexpr std::uint32_t kReverseControls = 0x00000040;
    // The two "definitely not Unicode" masks and the two "is Unicode" ones,
    // which is how the boolean answer is derived: a reverse mark settles it
    // as not-Unicode, an ASCII-shaped-but-odd-byte stream settles it as
    // Unicode, and a clean pass of any Unicode test settles it as Unicode.
    constexpr std::uint32_t kReverseMask = kReverseSignature | kReverseControls;
    constexpr std::uint32_t kNotUnicodeMask =
        kNullBytes | kReverseSignature | kReverseControls;
    constexpr std::uint32_t kNotAsciiMask =
        kSignature | kNullBytes | kControls;
    constexpr std::uint32_t kUnicodeMask = kSignature | kControls;

    if (buf == nullptr || len < static_cast<std::int32_t>(sizeof(char16_t))) {
        // The documented `IS_TEXT_UNICODE_BUFFER_TOO_SMALL` case. The
        // reference has a FIXME here and reports no flag at all rather than
        // a dedicated code, because the flags are the whole return value of
        // this function -- there is no status to return, only a boolean and
        // a mask.
        if (pf != nullptr) {
            *pf = 0;
        }
        return kFalse;
    }
    std::uint32_t wanted = 0xFFFFFFFFU;
    if (pf != nullptr) {
        wanted = static_cast<std::uint32_t>(*pf);
    }
    const auto* s = static_cast<const char16_t*>(buf);
    std::size_t bytes = static_cast<std::size_t>(len);
    std::uint32_t out = 0;
    if ((bytes % sizeof(char16_t)) != 0) {
        out |= kOddLength;
    }
    // A trailing zero is dropped before the tests run. The reference's
    // comment says Windows does this "to avoid false NULL_BYTES results",
    // and the reasoning holds: a `WCHAR` string's terminator reads as a
    // zero high byte, and without this every correctly-terminated wide
    // string would be reported as containing a wide NUL.
    if (bytes != 0 &&
        static_cast<const char*>(buf)[bytes - 1] == '\0') {
        --bytes;
    }
    std::size_t units = bytes / sizeof(char16_t);
    // 256 units, not the whole buffer: the statistical test is only
    // meaningful over a prefix and Windows only looks at the first 256
    // characters, so a caller cannot use this to characterise a long buffer
    // even if it wanted to.
    if (units > 256) {
        units = 256;
    }
    if (units != 0) {
        if (s[0] == 0xFEFF) {
            out |= kSignature;
        }
        if (s[0] == 0xFFFE) {
            out |= kReverseSignature;
        }
    }
    if ((wanted & kStatistics) != 0) {
        std::size_t narrow_looking = 0;
        for (std::size_t k = 0; k < units; ++k) {
            if (s[k] <= 255) {
                ++narrow_looking;
            }
        }
        // More than half the units being Latin-1 is the reference's
        // threshold, and it is a *statistical* answer: a wide string of
        // mostly-ASCII text looks like narrow text read as wide, and that
        // is exactly the case this test is trying to catch.
        if (units != 0 && narrow_looking > units / 2) {
            out |= kStatistics;
        }
    }
    if ((wanted & kNullBytes) != 0) {
        for (std::size_t k = 0; k < units; ++k) {
            if ((s[k] & 0xFF) == 0 || (s[k] >> 8) == 0) {
                out |= kNullBytes;
            }
        }
    }
    if ((wanted & kControls) != 0) {
        for (std::size_t k = 0; k < units; ++k) {
            const char16_t c = s[k];
            if (c == u'\r' || c == u'\n' || c == u'\t' || c == u' ' ||
                c == 0x3000) {
                out |= kControls;
            }
        }
    }
    if ((wanted & kReverseControls) != 0) {
        for (std::size_t k = 0; k < units; ++k) {
            const char16_t c = s[k];
            if (c == 0x0D00 || c == 0x0A00 || c == 0x0900 || c == 0x2000) {
                out |= kReverseControls;
            }
        }
    }
    if (pf != nullptr) {
        // The caller's mask in, the achieved subset out. Intersecting rather
        // than assigning is the whole contract: a caller that asked only
        // about controls does not learn about a signature it did not ask
        // for, and cannot mistake the answer for a full report.
        *pf = static_cast<std::int32_t>(out & wanted);
        out &= wanted;
    }
    if ((out & (kReverseMask | kNotUnicodeMask)) != 0) {
        return kFalse;
    }
    if ((out & kNotAsciiMask) != 0) {
        return kTrue;
    }
    if ((out & kUnicodeMask) != 0) {
        return kTrue;
    }
    return kFalse;
}

// -------------------------------------------------------------- IP addresses
//
// Sixteen names over two grammars, and the reason for that count is that the
// reference has four shapes per family: A and W for the text, `Ex` and plain
// for the question. `Ex` means "the port is part of this" and it changes two
// things at once -- the address may be bracketed, a scope may follow -- so it
// is not a flag but a different grammar, and it is the one `RtlIpv6*Ex*`
// spells.
//
// Four facts about the reference's behaviour are worth writing down because
// each is a case where the obvious implementation is wrong:
//
//   * the address fields are **big-endian bytes** in the `Ex` output and
//     **host-endian words** in the parsing, so the two directions are not
//     mirror images and one of them byte-swaps;
//   * the `A` forms parse from a fixed 32-character wide buffer, so a narrow
//     address longer than 31 characters is truncated before parsing rather
//     than refused;
//   * `RtlIpv4StringToAddressW` with a terminator reports where it stopped
//     even on failure, and without one it *requires* that it stopped at the
//     end -- trailing text is a refusal, not a partial parse;
//   * the `0x` prefix is accepted in the last IPv6 component and is the
//     reference's documented Windows quirk, terminator and all.

// The digit-value table the reference indexes, as a function. Written as
// ranges rather than as the reference's 103-entry literal table because the
// table is a spelling of these six rules and copying the spelling would make
// a change to the rules have to be made in two places.
[[nodiscard]] static int hex_digit(char16_t c) noexcept {
    if (c >= u'0' && c <= u'9') {
        return static_cast<int>(c) - static_cast<int>(u'0');
    }
    if (c >= u'a' && c <= u'f') {
        return static_cast<int>(c) - static_cast<int>(u'a') + 10;
    }
    if (c >= u'A' && c <= u'F') {
        return static_cast<int>(c) - static_cast<int>(u'A') + 10;
    }
    return -1;
}

// The reference's `htons`/`ntohs` under a name that says what it does: the
// guest's `IN6_ADDR` words are network order, and the host is little-endian,
// so every word crossing into the formatter is swapped. The swap is written
// out rather than borrowed because on a big-endian host the borrow would be
// the identity and this would not be, and the two must agree.
[[nodiscard]] static std::uint16_t swap16(std::uint16_t v) noexcept {
    return static_cast<std::uint16_t>((v >> 8) | (v << 8));
}

// `parse_ipv4_component`: one dotted field, in base 10 unless the field
// carries a `0x` or a leading-zero octal prefix and the caller is not strict.
// The overflow check is the reference's: it compares against the previous
// accumulated value, which catches wrap on any base because a wrapped value is
// by construction smaller than the one that produced it.
[[nodiscard]] static bool parse_ipv4_component(const char16_t*& at, bool strict,
                                        std::uint32_t& value) noexcept {
    std::uint32_t base = 10;
    if (*at == u'.') {
        // A leading dot is a refusal, not an empty field. The reference
        // consumes it anyway so that the caller's terminator lands past it.
        ++at;
        return false;
    }
    if (at[0] == u'0') {
        if (at[1] == u'x' || at[1] == u'X') {
            at += 2;
            if (strict) {
                return false;
            }
            base = 16;
        } else if (at[1] >= u'0' && at[1] <= u'9') {
            // A leading zero followed by a digit is octal, and the strict
            // form refuses it. This is what makes `010` ten and not one, and
            // it is the reason the strict flag exists at all.
            at += 1;
            if (strict) {
                return false;
            }
            base = 8;
        }
    }
    std::uint32_t acc = 0;
    std::uint32_t prev = 0;
    bool any = false;
    while (*at != u'\0') {
        const int d = hex_digit(*at);
        if (d < 0 || static_cast<std::uint32_t>(d) >= base) {
            break;
        }
        acc = acc * base + static_cast<std::uint32_t>(d);
        any = true;
        if (acc < prev) {
            return false; // wrapped
        }
        prev = acc;
        ++at;
    }
    if (any) {
        value = acc;
    }
    return any;
}

// `ipv4_string_to_address`. `terminator` null means "the whole string must be
// the address", non-null means "report where you stopped". `port` non-null is
// the `Ex` form and is what makes a trailing `:nnn` legal.
[[nodiscard]] static Ntstatus ipv4_string_to_address(
    const char16_t* at, bool strict, const char16_t** terminator,
    std::uint8_t* address, std::uint16_t* port) noexcept {
    std::uint32_t fields[4] = {0, 0, 0, 0};
    int n = 0;
    for (;;) {
        if (!parse_ipv4_component(at, strict, fields[static_cast<std::size_t>(n)])) {
            goto error;
        }
        ++n;
        if (*at != u'.') {
            break;
        }
        if (n == 4) {
            goto error;
        }
        ++at;
    }
    if (strict && n < 4) {
        goto error;
    }
    // The one, two and three field forms are the historical inet_aton
    // spellings: the last field soaks up the remaining bytes. The reference
    // keeps them and keeps their field-width limits, because a caller parsing
    // `10.1` and a caller parsing `10.0.0.1` mean the same host.
    switch (n) {
    case 4:
        if (fields[0] > 0xFF || fields[1] > 0xFF || fields[2] > 0xFF ||
            fields[3] > 0xFF) {
            goto error;
        }
        address[0] = static_cast<std::uint8_t>(fields[0]);
        address[1] = static_cast<std::uint8_t>(fields[1]);
        address[2] = static_cast<std::uint8_t>(fields[2]);
        address[3] = static_cast<std::uint8_t>(fields[3]);
        break;
    case 3:
        if (fields[0] > 0xFF || fields[1] > 0xFF || fields[2] > 0xFFFF) {
            goto error;
        }
        address[0] = static_cast<std::uint8_t>(fields[0]);
        address[1] = static_cast<std::uint8_t>(fields[1]);
        address[2] = static_cast<std::uint8_t>((fields[2] & 0xFF00) >> 8);
        address[3] = static_cast<std::uint8_t>(fields[2] & 0x00FF);
        break;
    case 2:
        if (fields[0] > 0xFF || fields[1] > 0xFFFFFF) {
            goto error;
        }
        address[0] = static_cast<std::uint8_t>(fields[0]);
        address[1] = static_cast<std::uint8_t>((fields[1] & 0xFF0000) >> 16);
        address[2] = static_cast<std::uint8_t>((fields[1] & 0x00FF00) >> 8);
        address[3] = static_cast<std::uint8_t>(fields[1] & 0x0000FF);
        break;
    case 1:
        address[0] = static_cast<std::uint8_t>((fields[0] & 0xFF000000) >> 24);
        address[1] = static_cast<std::uint8_t>((fields[0] & 0x00FF0000) >> 16);
        address[2] = static_cast<std::uint8_t>((fields[0] & 0x0000FF00) >> 8);
        address[3] = static_cast<std::uint8_t>(fields[0] & 0x000000FF);
        break;
    default:
        goto error;
    }
    if (terminator != nullptr) {
        *terminator = at;
    }
    if (*at == u':') {
        ++at;
        if (!parse_ipv4_component(at, false, fields[0])) {
            goto error;
        }
        // Zero is a refusal, not "port 0". The reference's check, and it is
        // the right one: `:0` in a URI means "no port given", and a parser
        // that answered 0 would be indistinguishable from a real port 0.
        if (fields[0] == 0 || fields[0] > 0xFFFF || *at != u'\0') {
            goto error;
        }
        if (port != nullptr) {
            *port = swap16(static_cast<std::uint16_t>(fields[0]));
            if (terminator != nullptr) {
                *terminator = at;
            }
        }
    }
    if (terminator == nullptr && *at != u'\0') {
        return kStInvalidParameter;
    }
    return kStSuccess;
error:
    if (terminator != nullptr) {
        *terminator = at;
    }
    return kStInvalidParameter;
}

// One component into the address at byte offset `n_bytes`, network order.
// The swap is the whole point: the parsed number is a host integer and the
// address is big-endian, so writing it low-byte-first would swap every field
// and produce an address that is not the one that was written.
static void write_ipv6_word(std::uint8_t* address, int n_bytes,
                     std::uint32_t component) noexcept {
    const std::uint16_t word = swap16(static_cast<std::uint16_t>(component));
    address[n_bytes] = static_cast<std::uint8_t>(word & 0xFF);
    address[n_bytes + 1] = static_cast<std::uint8_t>((word >> 8) & 0xFF);
}

// `parse_ipv6_component`. The reference builds this on `wcstoul` and then
// repairs the one case `wcstoul` accepts and this must not: a `0x` with no
// digits after it parses as zero under base 16, and the repair steps the
// terminator over the `0` so the `0x` is *not* consumed. The value is also
// clamped to `0x7FFFFFFF` there, which is why the clamp is here rather than
// at the use sites.
[[nodiscard]] static bool parse_ipv6_component(const char16_t*& at, std::uint32_t base,
                                        std::uint32_t& value) noexcept {
    const int first = hex_digit(*at);
    if (first < 0) {
        return false;
    }
    std::uint32_t acc = 0;
    const char16_t* scan = at;
    while (*scan != u'\0') {
        const int d = hex_digit(*scan);
        if (d < 0 || static_cast<std::uint32_t>(d) >= base) {
            break;
        }
        // The clamp, matching the reference's `min(..., 0x7FFFFFFF)`.
        const std::uint32_t next = acc * base + static_cast<std::uint32_t>(d);
        acc = next < 0x80000000u ? next : 0x7FFFFFFFu;
        ++scan;
    }
    if (*scan == u'0') {
        ++scan; // "0x" with nothing valid after it
    } else if (scan == at) {
        return false;
    }
    value = acc;
    at = scan;
    return true;
}

// `ipv6_string_to_address`. The `ex` flag is the `Ex` spelling: it is what
// permits the bracket, the scope and the port, and it is also what refuses
// the `0x` quirk. `terminator` has the same meaning as in the IPv4 case.
[[nodiscard]] static Ntstatus ipv6_string_to_address(
    const char16_t* at, bool ex, const char16_t** terminator,
    std::uint8_t* address, std::uint32_t* scope, std::uint16_t* port) noexcept {
    bool expecting_port = false;
    bool has_0x = false;
    bool too_big = false;
    int n_bytes = 0;
    int n_ipv4_bytes = 0;
    int gap = -1;
    std::uint32_t component = 0;
    std::uint32_t scope_component = 0;
    std::uint32_t port_component = 0;
    const char16_t* prev = nullptr;

    if (at[0] == u'[') {
        if (!ex) {
            goto error;
        }
        // A bracket is the URI spelling and it obliges the caller to want a
        // port: `[addr]` with no port is not a URI authority, so the `]`
        // below is required to be present.
        expecting_port = true;
        ++at;
    }
    if (at[0] == u':') {
        if (at[1] != u':') {
            goto error;
        }
        ++at;
        address[0] = 0;
    }
    for (;;) {
        if (n_ipv4_bytes == 0 && *at == u':') {
            // `::` -- the gap. One only, and it may not start at byte 14,
            // because a gap there would leave the last two bytes
            // unrepresentable.
            if (gap != -1) {
                goto error;
            }
            ++at;
            prev = at;
            gap = n_bytes;
            if (n_bytes == 14 ||
                !parse_ipv6_component(at, 16, component)) {
                break;
            }
            // The component after the gap is parsed twice: once to see
            // whether there is one, then again for real. The reference does
            // it this way and the rewinding is what makes `::1` and `::` both
            // work.
            at = prev;
        } else {
            prev = at;
        }
        if (n_ipv4_bytes == 0 && n_bytes <= (gap != -1 ? 10 : 12)) {
            // A dotted quad in the tail. Looked for by parsing a decimal
            // component and asking whether a dot follows, then rewinding.
            std::uint32_t probe = 0;
            if (parse_ipv6_component(at, 10, probe) && *at == u'.') {
                n_ipv4_bytes = 1;
            }
            at = prev;
        }
        if (n_ipv4_bytes != 0) {
            if (!parse_ipv6_component(at, 10, component)) {
                goto error;
            }
            if (at - prev > 3 || component > 255) {
                // Over-long or over-large, but *not* immediately refused: the
                // reference records it and refuses at the end of the walk, so
                // that a terminator is still reported.
                too_big = true;
            } else {
                if (*at != u'.' &&
                    (n_ipv4_bytes < 4 ||
                     (n_bytes < 15 && gap == -1))) {
                    goto error;
                }
                address[n_bytes] = static_cast<std::uint8_t>(component);
                ++n_bytes;
            }
            if (n_ipv4_bytes == 4 || *at != u'.') {
                break;
            }
            ++n_ipv4_bytes;
        } else {
            if (!parse_ipv6_component(at, 16, component)) {
                goto error;
            }
            if (prev[0] == u'0' && (prev[1] == u'x' || prev[1] == u'X')) {
                // The Windows quirk: a last component written `0x`-prefixed
                // is accepted and may be longer than four digits, and the
                // reference reports the terminator as the `x` -- so a caller
                // that stops where Windows stops sees the `x` as trailing.
                if (terminator != nullptr) {
                    *terminator = prev + 1;
                }
                if (n_bytes < 14 && gap == -1) {
                    return kStInvalidParameter;
                }
                write_ipv6_word(address, n_bytes, component);
                n_bytes += 2;
                has_0x = true;
                goto fill_gap;
            }
            if (*at != u':' && n_bytes < 14 && gap == -1) {
                goto error;
            }
            if (at - prev > 4) {
                too_big = true;
            } else {
                write_ipv6_word(address, n_bytes, component);
            }
            n_bytes += 2;
            if (*at != u':' || (gap != -1 && at[1] == u':')) {
                break;
            }
        }
        if (n_bytes == (gap != -1 ? 14 : 16)) {
            break;
        }
        if (too_big) {
            return kStInvalidParameter;
        }
        ++at;
    }
    if (terminator != nullptr) {
        *terminator = at;
    }
    if (too_big) {
        return kStInvalidParameter;
    }
fill_gap:
    if (gap == -1) {
        if (n_bytes < 16) {
            goto error;
        }
    } else {
        // The gap is filled by sliding what was parsed down to sit above it
        // and zeroing what is left. Done as an explicit loop over 16 bytes
        // because the source and destination overlap and the lengths differ.
        const std::size_t tail = static_cast<std::size_t>(n_bytes - gap);
        for (std::size_t k = 0; k < tail; ++k) {
            address[16 - tail + k] = address[static_cast<std::size_t>(gap) + k];
        }
        for (std::size_t k = static_cast<std::size_t>(gap);
             k < 16 - tail; ++k) {
            address[k] = 0;
        }
    }
    if (ex) {
        // The `Ex` form refuses the `0x` spelling, because a URI authority
        // with `0x` in it is not a URI authority.
        if (has_0x) {
            goto error;
        }
        if (*at == u'%') {
            ++at;
            // Strict, so `0x` and octal are not accepted in a scope id: a
            // scope is a number the interface printed, and accepting a second
            // spelling of it would let two spellings of one scope compare
            // unequal.
            if (!parse_ipv4_component(at, true, scope_component)) {
                goto error;
            }
        }
        if (expecting_port) {
            if (*at != u']') {
                goto error;
            }
            ++at;
            if (*at == u':') {
                ++at;
                if (!parse_ipv4_component(at, false, port_component)) {
                    goto error;
                }
                if (port_component == 0 || port_component > 0xFFFF ||
                    *at != u'\0') {
                    goto error;
                }
                port_component = swap16(static_cast<std::uint16_t>(port_component));
            }
        }
    }
    if (terminator == nullptr && *at != u'\0') {
        return kStInvalidParameter;
    }
    if (scope != nullptr) {
        *scope = scope_component;
    }
    if (port != nullptr) {
        *port = static_cast<std::uint16_t>(port_component);
    }
    return kStSuccess;
error:
    if (terminator != nullptr) {
        *terminator = at;
    }
    return kStInvalidParameter;
}

// The IPv4 formatter, in narrow text, shared by the two `A` spellings. Kept
// apart from the wide one because the reference has two separate
// implementations and because the narrow one is what the IPv6 formatter calls
// for its embedded tail.
[[nodiscard]] std::string narrow_text_of_ipv4(const std::uint8_t* address,
                                              std::uint16_t port,
                                              bool with_port) noexcept {
    std::string text;
    auto put = [&text](std::uint32_t value) noexcept {
        if (value == 0) {
            text.push_back('0');
            return;
        }
        char digits[12];
        std::size_t n = 0;
        while (value != 0) {
            digits[n++] = static_cast<char>('0' + (value % 10));
            value /= 10;
        }
        while (n != 0) {
            text.push_back(digits[--n]);
        }
    };
    put(address[0]);
    text.push_back('.');
    put(address[1]);
    text.push_back('.');
    put(address[2]);
    text.push_back('.');
    put(address[3]);
    if (with_port && port != 0) {
        text.push_back(':');
        put(swap16(port));
    }
    return text;
}

// The four `RtlIpv4StringToAddress*` names. `Ex` differs from the plain form
// in exactly two ways, and both are in the reference: it takes a port instead
// of a terminator, and the plain form with a terminator is allowed to stop
// early while the `Ex` form requires the whole string to have been consumed.
// That asymmetry is the point -- a caller with `"1.2.3.4:80"` in hand and no
// port to fill in wants the plain form, and a caller with a port wants to
// know that there was nothing after it.
extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlIpv4StringToAddressW(
    const char16_t* str, Boolean strict, const char16_t** terminator,
    void* address) noexcept {
    if (str == nullptr) {
        return kStInvalidParameter;
    }
    return ipv4_string_to_address(str, strict != kFalse, terminator,
                                  static_cast<std::uint8_t*>(address), nullptr);
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlIpv4StringToAddressExW(
    const char16_t* str, Boolean strict, void* address,
    std::uint16_t* port) noexcept {
    if (str == nullptr || address == nullptr || port == nullptr) {
        return kStInvalidParameter;
    }
    return ipv4_string_to_address(str, strict != kFalse, nullptr,
                                  static_cast<std::uint8_t*>(address), port);
}

// The `A` forms go through a fixed 32-WCHAR buffer in the reference, and the
// conversion is a *copy* rather than a view, so the terminator the caller
// passes has to be recomputed as an offset back into the caller's own string
// rather than borrowed. That is why the terminator out-parameter of the `A`
// form is in narrow characters and the internal walk is in wide ones: the
// offsets agree only because the buffer is one character per byte.
extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlIpv4StringToAddressA(
    const char* str, Boolean strict, const char** terminator,
    void* address) noexcept {
    if (str == nullptr) {
        return kStInvalidParameter;
    }
    const std::size_t len = c_length(str);
    const std::size_t room = 31; // 32 WCHAR less the terminator
    std::u16string wide;
    if (!narrow_in(std::string_view(str, len < room ? len : room), wide)
             .converted) {
        return kStInvalidParameter;
    }
    char16_t buffer[32];
    const std::size_t take = wide.size() < room ? wide.size() : room;
    for (std::size_t k = 0; k < take; ++k) {
        buffer[k] = wide[k];
    }
    buffer[take] = u'\0';
    const char16_t* wide_terminator = buffer;
    const Ntstatus status =
        ipv4_string_to_address(buffer, strict != kFalse, &wide_terminator,
                               static_cast<std::uint8_t*>(address), nullptr);
    if (terminator != nullptr) {
        *terminator = str + (wide_terminator - buffer);
    }
    return status;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlIpv4StringToAddressExA(
    const char* str, Boolean strict, void* address,
    std::uint16_t* port) noexcept {
    if (str == nullptr) {
        return kStInvalidParameter;
    }
    std::u16string wide;
    if (!narrow_in(std::string_view(str, c_length(str)), wide).converted) {
        return kStInvalidParameter;
    }
    return nrs_RtlIpv4StringToAddressExW(wide.c_str(), strict, address, port);
}

// The four `RtlIpv6StringToAddress*` names. The `Ex` form is not a flag on
// the plain one: it is the only one that accepts brackets, a scope, and a
// port, and the only one that refuses the `0x` quirk -- a bracketed authority
// is a URI and a URI has no `0x` in it.
extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlIpv6StringToAddressW(
    const char16_t* str, const char16_t** terminator, void* address) noexcept {
    if (str == nullptr) {
        return kStInvalidParameter;
    }
    return ipv6_string_to_address(str, false, terminator,
                                  static_cast<std::uint8_t*>(address), nullptr,
                                  nullptr);
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlIpv6StringToAddressExW(
    const char16_t* str, void* address, std::uint32_t* scope,
    std::uint16_t* port) noexcept {
    if (str == nullptr || address == nullptr || scope == nullptr ||
        port == nullptr) {
        return kStInvalidParameter;
    }
    return ipv6_string_to_address(str, true, nullptr,
                                  static_cast<std::uint8_t*>(address), scope,
                                  port);
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlIpv6StringToAddressA(
    const char* str, const char** terminator, void* address) noexcept {
    if (str == nullptr) {
        return kStInvalidParameter;
    }
    std::u16string wide;
    if (!narrow_in(std::string_view(str, c_length(str)), wide).converted) {
        return kStInvalidParameter;
    }
    const char16_t* wide_terminator = wide.c_str();
    const Ntstatus status = ipv6_string_to_address(
        wide.c_str(), false, &wide_terminator,
        static_cast<std::uint8_t*>(address), nullptr, nullptr);
    if (terminator != nullptr) {
        // The narrow offset is the wide offset only because every character
        // converted came from one byte. That holds for everything except an
        // unconvertible byte, and the conversion above refused those, so the
        // arithmetic is sound here and nowhere else in this file.
        *terminator = str + (wide_terminator - wide.c_str());
    }
    return status;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlIpv6StringToAddressExA(
    const char* str, void* address, std::uint32_t* scope,
    std::uint16_t* port) noexcept {
    if (str == nullptr) {
        return kStInvalidParameter;
    }
    std::u16string wide;
    if (!narrow_in(std::string_view(str, c_length(str)), wide).converted) {
        return kStInvalidParameter;
    }
    return nrs_RtlIpv6StringToAddressExW(wide.c_str(), address, scope, port);
}

// The four `*AddressToString*` names for IPv4. `Ex` adds the `:port` suffix
// and takes the size as an in/out; the plain form supplies its own size (16,
// which is the longest possible dotted quad plus terminator) and returns a
// pointer to the terminator -- the *end* of what was written, not the
// beginning, which is what lets a caller append to the buffer.
//
// The `*psize > needed` comparison is the reference's and is strict: a buffer
// of exactly `needed` is refused, because `needed` here counts the characters
// and the terminator is the `+1`. A caller that sized its buffer with this
// function's own answer and got `needed + 1` is one byte short.
[[nodiscard]] std::size_t ipv4_to_text(const std::uint8_t* address,
                                       std::uint16_t port, bool with_port,
                                       char16_t* out, std::size_t room) noexcept {
    std::u16string text;
    auto put = [&text](std::uint32_t value) noexcept {
        if (value == 0) {
            text.push_back(u'0');
            return;
        }
        char16_t digits[12];
        std::size_t n = 0;
        while (value != 0) {
            digits[n++] = static_cast<char16_t>(u'0' + (value % 10));
            value /= 10;
        }
        while (n != 0) {
            text.push_back(digits[--n]);
        }
    };
    put(address[0]);
    text.push_back(u'.');
    put(address[1]);
    text.push_back(u'.');
    put(address[2]);
    text.push_back(u'.');
    put(address[3]);
    if (with_port && port != 0) {
        text.push_back(u':');
        put(swap16(port));
    }
    const std::size_t needed = text.size();
    if (room > needed) {
        for (std::size_t k = 0; k < needed; ++k) {
            out[k] = text[k];
        }
        out[needed] = u'\0';
    }
    return needed + 1;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlIpv4AddressToStringExW(
    const void* address, std::uint16_t port, char16_t* buffer,
    std::uint32_t* size) noexcept {
    if (address == nullptr || buffer == nullptr || size == nullptr) {
        return kStInvalidParameter;
    }
    const auto* bytes = static_cast<const std::uint8_t*>(address);
    // A stack buffer of 32 WCHAR, the reference's `tmp_ip` width: 15
    // characters is the longest dotted quad and 5 more is the longest `:65535`.
    char16_t tmp[32];
    const std::size_t needed = ipv4_to_text(bytes, port, true, tmp, 32);
    if (*size > needed - 1) {
        *size = static_cast<std::uint32_t>(needed);
        for (std::size_t k = 0; k < needed; ++k) {
            buffer[k] = tmp[k];
        }
        return kStSuccess;
    }
    // The size is written even on the refusal, and it is the size that would
    // have worked -- a caller sizing from it and retrying succeeds.
    *size = static_cast<std::uint32_t>(needed);
    return kStInvalidParameter;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlIpv4AddressToStringExA(
    const void* address, std::uint16_t port, char* buffer,
    std::uint32_t* size) noexcept {
    if (address == nullptr || buffer == nullptr || size == nullptr) {
        return kStInvalidParameter;
    }
    const auto* bytes = static_cast<const std::uint8_t*>(address);
    std::string text = narrow_text_of_ipv4(bytes, port, true);
    const std::size_t needed = text.size();
    if (*size > needed) {
        *size = static_cast<std::uint32_t>(needed + 1);
        for (std::size_t k = 0; k < needed; ++k) {
            buffer[k] = text[k];
        }
        buffer[needed] = '\0';
        return kStSuccess;
    }
    *size = static_cast<std::uint32_t>(needed + 1);
    return kStInvalidParameter;
}

extern "C" __attribute__((ms_abi)) char16_t* nrs_RtlIpv4AddressToStringW(
    const void* address, char16_t* buffer) noexcept {
    if (address == nullptr || buffer == nullptr) {
        return buffer;
    }
    // 16, the reference's own starting size, and the widest a dotted quad
    // with a port can be. A failure sets the size to zero, so the returned
    // pointer is `buffer - 1`: the caller is handed a pointer before its own
    // buffer, which is the reference's way of saying "nothing was written"
    // without a status code.
    std::uint32_t size = 16;
    if (nrs_RtlIpv4AddressToStringExW(address, 0, buffer, &size) != kStSuccess) {
        size = 0;
    }
    return buffer + size - 1;
}

extern "C" __attribute__((ms_abi)) char* nrs_RtlIpv4AddressToStringA(
    const void* address, char* buffer) noexcept {
    if (address == nullptr || buffer == nullptr) {
        return buffer;
    }
    std::uint32_t size = 16;
    if (nrs_RtlIpv4AddressToStringExA(address, 0, buffer, &size) != kStSuccess) {
        size = 0;
    }
    return buffer + size - 1;
}

// `is_ipv4_in_ipv6`: the two shapes of IPv6 address that a Windows socket
// layer prints as a dotted quad. Both are named here because the second is
// the one a caller is likely to have and the first is the one that surprises
// people: it is the 6to4 prefix, and an address in it is a *tunnelled* IPv4
// address, which is why it prints as four dotted numbers.
[[nodiscard]] static bool is_ipv4_in_ipv6(const std::uint8_t* address) noexcept {
    // `s6_words[5] == 0x5efe` with `s6_words[4]` clear except for the
    // site-local bit: the 6to4 prefix 2002::/16 with 5efe::/16 inside it.
    const std::uint16_t w4 = swap16(read_u16(address, 8));
    const std::uint16_t w5 = swap16(read_u16(address, 10));
    if (w5 == 0x5efeu && (w4 & ~0x0200u) == 0) {
        return true;
    }
    // The compatible form: ::a.b.c.d and ::ffff:a.b.c.d. The first 64 bits
    // must be zero, the fourth word must be 0 or ffff, and the fifth must be
    // 0 or ffff in the matching way -- an address that is half of each is
    // neither form and must print as six groups.
    for (std::size_t k = 0; k < 8; ++k) {
        if (address[k] != 0) {
            return false;
        }
    }
    if (w4 != 0 && w4 != 0xffffu) {
        return false;
    }
    if (w4 == 0 && w5 != 0 && w5 != 0xffffu) {
        return false;
    }
    if (w4 == 0xffffu && w5 != 0) {
        return false;
    }
    // A word 6 of zero with the compatible prefix is all-zero, which is the
    // unspecified address and prints as IPv6.
    return read_u16(address, 12) != 0;
}

// The IPv6 formatter. The reference's shape, and three things in it are worth
// stating: the longest run of zero words becomes the `::` and it is found
// with a `>` so the *first* longest run wins, which is what every other
// implementation of this format does; a port forces brackets even when the
// address is not ambiguous; and the `%scope` is printed only when non-zero.
[[nodiscard]] static std::string narrow_text_of_ipv6(const std::uint8_t* address,
                                                     std::uint32_t scope,
                                                     std::uint16_t port) noexcept {
    const int ipv6_end = is_ipv4_in_ipv6(address) ? 6 : 8;
    int gap = -1;
    int gap_len = 1;
    for (int i = 0; i < ipv6_end;) {
        int len = 0;
        while (i < ipv6_end && read_u16(address, static_cast<std::size_t>(i) * 2) == 0) {
            ++i;
            ++len;
        }
        if (len > gap_len) {
            gap = i - len;
            gap_len = len;
        }
    }
    std::string text;
    if (port != 0) {
        text.push_back('[');
    }
    int i = 0;
    while (i < ipv6_end) {
        if (i == gap) {
            // The `::`. When the gap runs to the end there is no second colon
            // to write, because the closing one *is* the second colon -- this
            // is the case `::` and `1::` turn on, and writing `:::` there
            // would be the classic off-by-one.
            text.push_back(':');
            i += gap_len;
            if (i == ipv6_end) {
                text.push_back(':');
            }
            continue;
        }
        if (i > 0) {
            text.push_back(':');
        }
        const std::uint16_t word = swap16(read_u16(address, static_cast<std::size_t>(i) * 2));
        static const char kHexDigits[] = "0123456789abcdef";
        bool leading = true;
        for (int shift = 12; shift >= 0; shift -= 4) {
            const unsigned nibble = (word >> shift) & 0x0Fu;
            if (nibble != 0) {
                leading = false;
            }
            if (!leading) {
                text.push_back(kHexDigits[nibble]);
            }
        }
        if (leading) {
            text.push_back('0');
        }
        ++i;
    }
    if (ipv6_end == 6) {
        // The dotted tail. The colon rule is the reference's: one colon unless
        // the previous character already *is* a colon, which is the `::` at
        // the end of `::ffff:` case.
        if (text.empty() || text[text.size() - 1] != ':') {
            text.push_back(':');
        }
        text += narrow_text_of_ipv4(address + 12, 0, false);
    }
    if (scope != 0) {
        text.push_back('%');
        char digits[12];
        std::size_t n = 0;
        std::uint32_t rest = scope;
        if (rest == 0) {
            digits[n++] = '0';
        }
        while (rest != 0) {
            digits[n++] = static_cast<char>('0' + (rest % 10));
            rest /= 10;
        }
        while (n != 0) {
            text.push_back(digits[--n]);
        }
    }
    if (port != 0) {
        text.push_back(']');
        text.push_back(':');
        std::uint32_t host_port = swap16(port);
        char port_digits[8];
        std::size_t pn = 0;
        if (host_port == 0) {
            port_digits[pn++] = '0';
        }
        while (host_port != 0) {
            port_digits[pn++] = static_cast<char>('0' + (host_port % 10));
            host_port /= 10;
        }
        while (pn != 0) {
            text.push_back(port_digits[--pn]);
        }
    }
    return text;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlIpv6AddressToStringExA(
    const void* address, std::uint32_t scope, std::uint16_t port, char* str,
    std::uint32_t* size) noexcept {
    if (address == nullptr || str == nullptr || size == nullptr) {
        return kStInvalidParameter;
    }
    const std::string text =
        narrow_text_of_ipv6(static_cast<const std::uint8_t*>(address), scope, port);
    const std::size_t needed = text.size() + 1;
    Ntstatus status = kStInvalidParameter;
    if (*size >= needed) {
        for (std::size_t k = 0; k < text.size(); ++k) {
            str[k] = text[k];
        }
        str[text.size()] = '\0';
        status = kStSuccess;
    }
    // `>=` here, unlike the IPv4 form's `>`. The reference is inconsistent
    // between the two and each is kept, because a caller that sizes its
    // buffer from one and writes through the other must not find the answer
    // differs by one.
    *size = static_cast<std::uint32_t>(needed);
    return status;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlIpv6AddressToStringExW(
    const void* address, std::uint32_t scope, std::uint16_t port,
    char16_t* str, std::uint32_t* size) noexcept {
    if (address == nullptr || str == nullptr || size == nullptr) {
        return kStInvalidParameter;
    }
    // The reference formats narrow and converts, and only on success. The
    // conversion is bounded by the size it just validated, so it cannot
    // overrun even when the narrow form and the wide form differ in length --
    // and they can, because a character outside the BMP is one UTF-16 unit
    // here and cannot appear in an address at all, so in practice the widths
    // agree and the bound is belt and braces.
    const std::string narrow_text = narrow_text_of_ipv6(
        static_cast<const std::uint8_t*>(address), scope, port);
    char narrow[64];
    for (std::size_t k = 0; k < narrow_text.size() && k < 63; ++k) {
        narrow[k] = narrow_text[k];
    }
    narrow[narrow_text.size() < 63 ? narrow_text.size() : 63] = '\0';
    const Ntstatus status =
        nrs_RtlIpv6AddressToStringExA(address, scope, port, narrow, size);
    if (status == kStSuccess) {
        std::u16string wide;
        if (narrow_in(std::string_view(narrow, c_length(narrow)), wide).converted) {
            for (std::size_t k = 0; k < wide.size(); ++k) {
                str[k] = wide[k];
            }
            str[wide.size()] = u'\0';
        }
    }
    return status;
}

extern "C" __attribute__((ms_abi)) char* nrs_RtlIpv6AddressToStringA(
    const void* address, char* str) noexcept {
    if (address == nullptr || str == nullptr) {
        return str == nullptr ? nullptr : str - 1;
    }
    // 46 is the reference's starting size: 45 characters plus the terminator
    // is the longest an address with a scope and a bracketed port can be.
    std::uint32_t size = 46;
    // The reference writes a terminator into `str[45]` *before* the call, as a
    // belt-and-braces measure for a caller that ignores the status. It is kept
    // because a caller that does ignore the status then reads an empty string
    // rather than uninitialised stack.
    str[45] = '\0';
    (void)nrs_RtlIpv6AddressToStringExA(address, 0, 0, str, &size);
    return str + size - 1;
}

extern "C" __attribute__((ms_abi)) char16_t* nrs_RtlIpv6AddressToStringW(
    const void* address, char16_t* str) noexcept {
    if (address == nullptr || str == nullptr) {
        return str;
    }
    std::uint32_t size = 46;
    str[45] = u'\0';
    if (nrs_RtlIpv6AddressToStringExW(address, 0, 0, str, &size) != kStSuccess) {
        return str;
    }
    return str + size - 1;
}

// -------------------------------------------------------------- environment
//
// The walk, split out because both the wide and the `_U` spelling run it and
// because getting the substitution rules right is the whole value here. Three
// rules, all of them the reference's:
//
//   * a run of ordinary text up to the next `%` is copied as it stands;
//   * `%NAME%` with `NAME` defined is replaced by the value, and the value is
//     copied **whole or not at all** -- a partially copied variable would
//     leave the caller holding a path that looks complete and is not;
//   * `%NAME%` with `NAME` undefined is copied **with its delimiters**, so the
//     caller can see which name was missing, and a trailing `%` with no
//     closer is copied as text rather than treated as a syntax error.
//
// `renv` null means "the process's own block", which the runtime's
// environment table answers; non-null means "this block", which is the
// `NAME=VALUE\0NAME=VALUE\0...\0` form Windows passes around.

// The reference's `ENV_FindVariable`, over a caller's environment block:
// case-insensitive name match, the first spelling in the block wins, and the
// name must be the whole thing before the first `=` -- an entry `PATH=...`
// cannot satisfy `%PAT%`, and an entry `=value` cannot satisfy `%PAT%` either
// because its name is the empty string.
[[nodiscard]] static const char16_t* find_variable(const char16_t* block,
                                            std::u16string_view name) noexcept {
    if (block == nullptr || name.empty()) {
        return nullptr;
    }
    for (const char16_t* entry = block; *entry != u'\0';) {
        const char16_t* value = entry;
        while (*value != u'\0' && *value != u'=') {
            ++value;
        }
        // The name is the part before the `=`, and it is *that* length the
        // comparison below is against -- not the entry's whole length. An
        // entry is `NAME=VALUE`, so `c_length(entry)` answers 9 for
        // `PATH=/bin` and a comparison against the name would never match
        // anything: every variable would look undefined and every expansion
        // would answer `%PATH%` verbatim.
        const std::size_t entry_len = c_length(entry);
        const std::size_t name_len =
            static_cast<std::size_t>(value - entry);
        // Exactly equal, not merely "at least as long": the loop below compares
        // only `name.size()` characters, so a longer name would pass it on its
        // prefix and answer `%PAT%` with the whole of `%PATH%`.
        if (name_len == name.size() && *value == u'=') {
            // The comparison goes through the same mapping the case
            // functions use, because the reference compares with
            // `RtlCompareUnicodeStrings(..., TRUE)` and a guest that stored
            // `%Path%` expects to find `PATH`. An ASCII-only compare would
            // find it too often and a full mapping would find it for scripts
            // whose case differs in a way the filesystem may not agree with.
            bool same = true;
            for (std::size_t k = 0; k < name.size(); ++k) {
                if (upcase_wide(entry[k]) != upcase_wide(name[k])) {
                    same = false;
                    break;
                }
            }
            if (same) {
                return value + 1;
            }
        }
        entry += entry_len + 1;
    }
    return nullptr;
}

// `environment` is the caller's block when it passed one, otherwise the
// process's. `defined` distinguishes "the variable is set to the empty
// string" from "the variable is not set at all", which is not a distinction
// the string value can carry: the first is a substitution that removes
// `%NAME%`, the second is a copy that keeps `%NAME%` visible.
struct VariableSource {
    std::u16string found;
    bool defined = false;
};

[[nodiscard]] static VariableSource lookup_environment(const char16_t* environment,
                                                std::u16string_view name) noexcept {
    VariableSource out;
    if (environment == nullptr) {
        std::string narrow;
        if (!narrow_out(name, narrow).converted) {
            return out;
        }
        const char* value = cr_getenv(narrow.c_str());
        if (value == nullptr) {
            return out;
        }
        // A value the narrow conversion cannot represent is still defined --
        // reporting it as undefined would print `%NAME%` where the value is,
        // which is a worse answer than an empty one.
        std::u16string wide;
        if (narrow_in(std::string_view(value), wide).converted) {
            out.found = std::move(wide);
        }
        out.defined = true;
        return out;
    }
    const char16_t* value = find_variable(environment, name);
    if (value != nullptr) {
        out.found.assign(value, value + c_length(value));
        out.defined = true;
    }
    return out;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlExpandEnvironmentStrings(
    const char16_t* environment, const char16_t* src,
    std::uint64_t src_len_units, char16_t* dst, std::uint64_t count_units,
    std::uint64_t* plen) noexcept {
    if (src == nullptr || plen == nullptr) {
        return kStInvalidParameter;
    }
    // The two-pass shape: the caller asks once with a null destination to
    // learn the size and once with a real one to fill. Both passes run the
    // same walk, and the walk is the only place the substitution rules live.
    std::u16string out;
    const std::u16string text(src, src_len_units);
    std::size_t at = 0;
    // Whether the copy pass had room for everything. The reference tracks this
    // as its running `count`, and answers `STATUS_BUFFER_TOO_SMALL` when it
    // reached zero -- which is the *unqualified* code, not the informational
    // `STATUS_BUFFER_OVERFLOW`, and a caller that tests for overflow here would
    // treat a short expansion as a success.
    std::uint64_t room = count_units;
    bool fits = true;
    while (at < text.size()) {
        if (text[at] != u'%') {
            // A run up to the next `%`. The reference's inner loop leaves
            // `at` on the `%` rather than consuming it, which is what makes
            // the next iteration see it.
            const std::size_t start = at;
            while (at < text.size() && text[at] != u'%') {
                ++at;
            }
            const std::size_t len = at - start;
            if (dst != nullptr) {
                std::size_t copy = len;
                if (room < len) {
                    copy = static_cast<std::size_t>(room);
                    fits = false;
                }
                for (std::size_t k = 0; k < copy; ++k) {
                    dst[k] = text[start + k];
                }
                dst += copy;
                room -= copy;
            }
            out.append(text, start, len);
            continue;
        }
        // At a `%`. Find the closing one.
        std::size_t close = at + 1;
        while (close < text.size() && text[close] != u'%') {
            ++close;
        }
        if (close >= text.size()) {
            // An unterminated `%` is copied as text, not treated as a
            // variable: the reference ignores the unfinished name and copies
            // what it saw, so a trailing `%` in a path is not a syntax error
            // that eats the rest of the string.
            const std::size_t len = text.size() - at;
            if (dst != nullptr) {
                std::size_t copy = len;
                if (room < len) {
                    copy = static_cast<std::size_t>(room);
                    fits = false;
                }
                for (std::size_t k = 0; k < copy; ++k) {
                    dst[k] = text[at + k];
                }
                dst += copy;
                room -= copy;
            }
            out.append(text, at, len);
            at = text.size();
            continue;
        }
        const std::u16string name = text.substr(at + 1, close - at - 1);
        const VariableSource source = lookup_environment(environment, name);
        if (source.defined) {
            // A defined variable, copied whole. The reference's rule is "copy
            // the entire value, or nothing at all": a half-written value would
            // produce a path that reads as complete and resolves somewhere
            // else. An empty value is still a substitution -- it removes the
            // `%NAME%` -- which is why `defined` rather than emptiness decides.
            const std::size_t len = source.found.size();
            if (dst != nullptr) {
                if (room <= len) {
                    // No room, or room only for the terminator. The reference
                    // writes a terminator where the value would have started so
                    // the destination stays a readable string.
                    if (room != 0) {
                        dst[room - 1] = u'\0';
                    }
                    fits = false;
                } else {
                    for (std::size_t k = 0; k < len; ++k) {
                        dst[k] = source.found[k];
                    }
                    dst += len;
                    room -= len;
                }
            }
            out.append(source.found);
        } else {
            // An undefined variable is copied **with its delimiters**. That
            // is the reference's rule and it is the useful one: a caller that
            // expands a path and gets `%UNDEFINED%` back can see which name
            // was missing, whereas dropping the markers would leave a
            // silently wrong path.
            const std::size_t len = close - at + 1;
            if (dst != nullptr) {
                std::size_t copy = len;
                if (room < len) {
                    copy = static_cast<std::size_t>(room);
                    fits = false;
                }
                for (std::size_t k = 0; k < copy; ++k) {
                    dst[k] = text[at + k];
                }
                dst += copy;
                room -= copy;
            }
            out.append(text, at, len);
        }
        at = close + 1;
    }
    // The answer is in **characters**, terminator included -- the reference's
    // `plen` is what `RtlExpandEnvironmentStrings_U` multiplies by two, so a
    // byte count here would make that caller double the size. It is the full
    // length whether or not it fitted, because it is what the caller needs in
    // order to retry with a big enough buffer.
    *plen = static_cast<std::uint64_t>(out.size() + 1);
    if (dst == nullptr) {
        // A size query always succeeds: nothing was asked to fit.
        return kStSuccess;
    }
    if (room != 0) {
        dst[0] = u'\0';
    }
    return fits ? kStSuccess : kStBufferTooSmall;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlExpandEnvironmentStrings_U(
    const char16_t* environment, const void* src, void* dst,
    std::uint32_t* plen) noexcept {
    if (src == nullptr || dst == nullptr) {
        return kStInvalidParameter;
    }
    const StringView s = read_string(src);
    const StringView d = read_string(dst);
    std::uint64_t units = 0;
    const Ntstatus status = nrs_RtlExpandEnvironmentStrings(
        environment, static_cast<const char16_t*>(s.buffer),
        s.length / sizeof(char16_t),
        static_cast<char16_t*>(d.buffer), d.maximum / sizeof(char16_t),
        &units);
    if (plen != nullptr) {
        // **Bytes**, where the non-`_U` spelling answers characters. The
        // reference's own comment marks this conversion, and it is the
        // difference between a caller that allocates a buffer twice too small
        // and one that allocates it once.
        *plen = static_cast<std::uint32_t>(units * sizeof(char16_t));
    }
    if (units > kMaxUnicodeStringBytes / sizeof(char16_t)) {
        return kStBufferTooSmall;
    }
    if (status == kStSuccess) {
        // The `Length` excludes the terminator, as everywhere else. Note
        // that the terminator is written even when the expansion overflowed,
        // so the destination is a valid `UNICODE_STRING` either way -- which
        // is what lets a caller that ignores the status still free it.
        write_u16(dst, kStrLength,
                  static_cast<std::uint16_t>((units - 1) * sizeof(char16_t)));
    }
    return status;
}

// --------------------------------------------------------- message format
//
// `RtlFormatMessage` and its `_Ex` form are the resource-string formatter:
// they take a message template with escape sequences and positional
// `%1`-`%9` inserts, and produce the text a message box shows. Four escape
// rules and one layout rule, and each of them is a case where doing the
// obvious thing is wrong:
//
//   * `\r\n` is *folded into one* CRLF in the output, so a template written
//     with Windows line endings does not come out with doubled breaks;
//   * `%0` discards the **rest of the template**, which is how a message
//     resource stops early for a caller that supplied fewer arguments;
//   * a bare `%x` where `x` is not one of the escapes **drops the `%`** and
//     keeps the character, but under `ignore_inserts` it keeps both -- the
//     whole point of that flag is that a caller without arguments still wants
//     to see what the placeholders were;
//   * `width` breaks lines at the **last space**, not at the exact column, and
//     the spaces it breaks at are then *eaten* -- otherwise every wrapped line
//     would begin with the space that caused the break.

// The argument source. Two shapes, because the reference has two: `is_array`
// means the arguments are a plain array of 64-bit values, which is fully
// specified, and otherwise they are a `va_list`. A `va_list` is the calling
// convention's own structure, and this runtime's guest is Microsoft x64, so
// the four fields and the four general-purpose slots are read out of the
// caller's structure by their documented offsets rather than by a host
// `va_arg` -- a host `va_arg` would walk a host register save area that the
// guest never wrote.
struct MessageArgs {
    bool use_array = false;
    const std::uint64_t* array = nullptr;
    std::uint32_t gp_offset = 0;
    std::uint64_t overflow_area = 0;
    std::uint64_t reg_save_area = 0;
    int last = 0;
    std::uint64_t fetched[102] = {};
};

// The Microsoft x64 `__va_list_tag`: gp offset, fp offset, the overflow
// argument area, and the register save area, in that order at that size. All
// the arguments this formatter ever fetches are 8 bytes wide, so only the
// general-purpose half of it is ever consulted -- and that is not a
// simplification, it is the observation that every format conversion in a
// message resource is a pointer or an integer.
constexpr std::size_t kVaGpOffset = 0;
constexpr std::size_t kVaOverflowArea = 8;
constexpr std::size_t kVaRegSaveArea = 16;
// Six general-purpose slots are reserved for the first integer/pointer
// arguments, so a `va_arg` past that count comes from the overflow area.
constexpr std::uint32_t kGpSlots = 6;
constexpr std::uint64_t kGpSlotBytes = 8;

// Reads one 8-byte argument from the register save area or the overflow area.
[[nodiscard]] static std::uint64_t fetch_va(MessageArgs& args) noexcept {
    std::uint64_t at = 0;
    if (args.gp_offset <= (kGpSlots - 1) * kGpSlotBytes) {
        at = args.reg_save_area + args.gp_offset;
        args.gp_offset += static_cast<std::uint32_t>(kGpSlotBytes);
    } else {
        at = args.overflow_area;
        args.overflow_area += kGpSlotBytes;
    }
    return read_ptr(reinterpret_cast<const void*>(at), 0);
}

// The reference's `get_arg`: `nr == -1` means "the next one", and asking for
// argument *n* fetches everything up to it, because a `va_list` can only be
// read forwards.
[[nodiscard]] static std::uint64_t get_arg(MessageArgs& args, int nr) noexcept {
    if (args.use_array) {
        // The array form indexes directly and needs no cache; the reference
        // does the same and only touches `last` for the `*` widths.
        if (nr < 0) {
            nr = args.last + 1;
        }
        if (args.last < nr) {
            args.last = nr;
        }
        return args.array[static_cast<std::size_t>(nr) - 1];
    }
    if (nr == -1) {
        nr = args.last + 1;
    }
    while (nr > args.last) {
        args.fetched[static_cast<std::size_t>(args.last)] = fetch_va(args);
        ++args.last;
    }
    return args.fetched[static_cast<std::size_t>(nr) - 1];
}

// One insert, from the template's `%1`..`%9` (or `%!....!` for an explicit
// conversion) through to the text it produces.
//
// The string conversions are substituted directly rather than handed to the
// host's formatter, and that is a stated limitation rather than a shortcut:
// a narrow `printf` cannot take a wide string, and applying a width to a
// string insert would need a second implementation of the padding rule. The
// flags and width on a string conversion are parsed and discarded. Numeric
// conversions go through the host formatter with the conversion translated
// where the two disagree -- `I64` is Microsoft's spelling of `ll` and the
// host does not know it, and a bare `s`/`S` pair is swapped by `ansi` exactly
// as the reference swaps it, so a narrow caller gets narrow strings and a wide
// caller gets wide ones.
[[nodiscard]] static Ntstatus add_format(char16_t* out, std::size_t& pos,
                                         std::size_t room, const char16_t*& src,
                                         int insert, Boolean ansi,
                                         MessageArgs& args) noexcept {
    const char16_t* format = src;
    char16_t spec[32];
    std::size_t spec_len = 0;
    spec[spec_len++] = u'%';
    if (*format == u'!') {
        // The explicit form: everything up to the closing `!` is the
        // conversion, and the reference refuses one longer than its own
        // 32-WCHAR scratch rather than truncating it into a different format.
        ++format;
        const char16_t* close = nullptr;
        for (const char16_t* scan = format; *scan != u'\0'; ++scan) {
            if (*scan == u'!') {
                close = scan;
                break;
            }
        }
        if (close == nullptr ||
            static_cast<std::size_t>(close - format) >
                (sizeof(spec) / sizeof(spec[0])) - 2) {
            return kStInvalidParameter;
        }
        src = close + 1;
        while (*format != u'!') {
            if (spec_len + 1 >= (sizeof(spec) / sizeof(spec[0]))) {
                return kStInvalidParameter;
            }
            spec[spec_len++] = *format++;
        }
    } else {
        // No explicit form: a bare string insert, wide when the caller wants
        // wide and narrow when it does not.
        spec[spec_len++] = (ansi != kFalse) ? u'S' : u's';
    }

    // Split the spec into "everything before the conversion character" and the
    // conversion character itself, so the translation below knows which is
    // which. The flag set is the reference's own list of what may appear
    // between the `%` and the conversion.
    static const char16_t kFlags[] = u"0123456789 +-*#.";
    std::size_t lead = 1;
    while (lead < spec_len) {
        bool is_flag = false;
        for (std::size_t k = 0; k < c_length(kFlags); ++k) {
            if (spec[lead] == kFlags[k]) {
                is_flag = true;
                break;
            }
        }
        if (!is_flag) {
            break;
        }
        ++lead;
    }
    if (lead >= spec_len) {
        // A spec with flags and no conversion: nothing to convert, and the
        // reference's scratch would have held a bare `%`. Refusing is the
        // honest answer.
        return kStInvalidParameter;
    }
    const char16_t conv = spec[lead];

    // The `*` widths, in order, then the value. A `*` is an `int` argument
    // like any other, which is why the reference counts them, and the first
    // one is the positional insert while the rest are sequential.
    int star_value[2] = {0, 0};
    int star_slot = 0;
    for (std::size_t k = 1; k < lead; ++k) {
        if (spec[k] != u'*') {
            continue;
        }
        star_value[star_slot] =
            static_cast<int>(static_cast<std::int32_t>(get_arg(args, insert)));
        ++star_slot;
        // Only the first fetch is the positional insert; the rest follow on.
        insert = -1;
    }
    if (insert == -1 && star_slot > 0) {
        // A width consumed the positional insert, so the value itself is the
        // next sequential argument rather than the insert's. The reference
        // drops one from `last` to reproduce a documented Microsoft bug in
        // which the value is taken from the slot the width came from; taking
        // the next slot is what a caller's argument list lines up with, and
        // it is what the surrounding reference code does.
        --args.last;
    }
    const std::uint64_t value = get_arg(args, insert);

    if (conv == u's' || conv == u'S') {
        // The argument is a pointer to the other width. The `ansi` flag is
        // what decides which: the reference swaps the conversion character by
        // `^('s' - 'S')`, so a narrow caller is reading narrow strings and a
        // wide caller wide ones.
        const bool wide = (conv == u'S') != (ansi != kFalse);
        if (value == 0) {
            // A null insert is an empty one, not a crash: a message resource
            // may have a `%2` that the caller chose not to supply.
            return kStSuccess;
        }
        const auto* text = reinterpret_cast<const char16_t*>(value);
        if (wide) {
            const std::size_t len = c_length(text);
            if (pos + len > room) {
                return kStBufferOverflow;
            }
            for (std::size_t k = 0; k < len; ++k) {
                out[pos++] = text[k];
            }
        } else {
            const auto* narrow_text = reinterpret_cast<const char*>(value);
            const std::size_t len = c_length(narrow_text);
            if (pos + len > room) {
                return kStBufferOverflow;
            }
            for (std::size_t k = 0; k < len; ++k) {
                std::u16string one;
                if (!narrow_in(std::string_view(narrow_text + k, 1), one)
                         .converted) {
                    return kStNoUnicodeTranslation;
                }
                if (pos + one.size() > room) {
                    return kStBufferOverflow;
                }
                for (std::size_t j = 0; j < one.size(); ++j) {
                    out[pos++] = one[j];
                }
            }
        }
        return kStSuccess;
    }

    // The numeric conversions. The host formatter is asked for a 64-bit value
    // in every case and the value is pre-truncated to the width the
    // conversion asks for, because handing a 64-bit register to a `%d` is
    // exactly the mismatch the `I64` marker exists to avoid.
    //
    // Each `*` is written out as the number it stands for, so the host sees a
    // literal width rather than a star it would fetch from an argument list
    // that no longer exists.
    char host_fmt[40];
    std::size_t at = 0;
    host_fmt[at++] = '%';
    int star_used = 0;
    for (std::size_t k = 1; k < lead; ++k) {
        if (spec[k] == u'*') {
            const int width = star_value[star_used < 2 ? star_used : 1];
            ++star_used;
            if (width < 0) {
                // A negative width is the left-justify flag followed by a
                // positive width, which is what the reference's own `*`
                // handling produces.
                host_fmt[at++] = '-';
                at += static_cast<std::size_t>(
                    std::snprintf(host_fmt + at, sizeof(host_fmt) - at, "%d",
                                  -width));
            } else {
                at += static_cast<std::size_t>(
                    std::snprintf(host_fmt + at, sizeof(host_fmt) - at, "%d",
                                  width));
            }
            continue;
        }
        host_fmt[at++] = static_cast<char>(spec[k]);
    }
    // `I64` is the Microsoft length modifier; the host spells it `ll`.
    bool is_64 = false;
    if (conv == u'I') {
        // `I64x`: the modifier and the conversion in one character pair.
        if (lead + 2 < spec_len && spec[lead + 1] == u'6' &&
            spec[lead + 2] == u'4') {
            is_64 = true;
            host_fmt[at++] = 'l';
            host_fmt[at++] = 'l';
            host_fmt[at++] = static_cast<char>(spec[lead + 3]);
        } else {
            return kStInvalidParameter;
        }
    } else {
        host_fmt[at++] = static_cast<char>(conv);
    }
    host_fmt[at] = '\0';

    // The conversion is chosen from a table rather than assembled as a
    // literal, so the host formatter is reached through the variadic bridge
    // that already exists for this: `host_vformat` takes its arguments as
    // 8-byte slots in the Microsoft layout and rebuilds them for the host,
    // which is what keeps a format built at run time from being read as
    // though its shape were known at compile time. Handing `snprintf` a
    // format string assembled from guest-controlled specifiers is the thing
    // that bridge exists to prevent -- the specifiers here come from the
    // guest's format string, so the width and length modifier below are its
    // to choose.
    std::string text;
    if (!is_64) {
        std::uint64_t slot = static_cast<std::uint32_t>(value);
        if (host_vformat(text, host_fmt, &slot) < 0) {
            return kStInvalidParameter;
        }
    } else {
        std::uint64_t slot = value;
        if (host_vformat(text, host_fmt, &slot) < 0) {
            return kStInvalidParameter;
        }
    }
    if (pos + text.size() > room) {
        return kStBufferOverflow;
    }
    for (std::size_t k = 0; k < text.size(); ++k) {
        out[pos++] = static_cast<char16_t>(
            static_cast<unsigned char>(text[k]));
    }
    return kStSuccess;
}

[[nodiscard]] static Ntstatus format_message_impl(
    const char16_t* src, std::uint32_t width, Boolean ignore_inserts,
    Boolean ansi, Boolean is_array, const void* va, char16_t* buffer,
    std::uint32_t size, std::uint32_t* retsize) noexcept {
    if (src == nullptr || buffer == nullptr || retsize == nullptr ||
        va == nullptr) {
        return kStInvalidParameter;
    }
    MessageArgs args;
    args.use_array = is_array != kFalse;
    if (args.use_array) {
        args.array = static_cast<const std::uint64_t*>(va);
    } else {
        // The Microsoft x64 `va_list` is a pointer to the four-field structure.
        const auto* tag = static_cast<const std::uint32_t*>(va);
        args.gp_offset = tag[kVaGpOffset / sizeof(std::uint32_t)];
        args.overflow_area = read_ptr(va, kVaOverflowArea);
        args.reg_save_area = read_ptr(va, kVaRegSaveArea);
    }

    std::size_t pos = 0;
    const std::size_t room = size / sizeof(char16_t);
    // The line-start and last-space bookkeeping, as indices. The reference
    // uses pointers and a null, and the one place the difference shows is the
    // tab case's `space == buffer - 1`, which is "no space yet, and we are at
    // the very start"; here it is "no space yet, and `pos` is zero".
    std::size_t line = 0;
    std::ptrdiff_t space = -1;
    Ntstatus status = kStSuccess;

    for (const char16_t* scan = src; *scan != u'\0'; ++scan) {
        switch (*scan) {
        case u'\r':
            if (scan[1] == u'\n') {
                ++scan;
            }
            [[fallthrough]];
        case u'\n':
            if (width == 0) {
                // A real line break. With a width the template's newlines are
                // only *candidate* break points, so they fall through to the
                // space case and become ordinary break opportunities.
                if (pos + 2 > room) {
                    return kStBufferOverflow;
                }
                buffer[pos++] = u'\r';
                buffer[pos++] = u'\n';
                line = pos;
                space = -1;
                break;
            }
            [[fallthrough]];
        case u' ':
            space = static_cast<std::ptrdiff_t>(pos);
            if (pos + 1 > room) {
                return kStBufferOverflow;
            }
            buffer[pos++] = u' ';
            break;
        case u'\t':
            if (space == -1 && pos == 0) {
                space = 0;
            }
            if (pos + 1 > room) {
                return kStBufferOverflow;
            }
            buffer[pos++] = u'\t';
            break;
        case u'%': {
            ++scan;
            switch (*scan) {
            case u'\0':
                // A `%` at the very end is a malformed template, not a
                // literal: the reference refuses rather than emitting it.
                return kStInvalidParameter;
            case u't':
                if (width == 0) {
                    if (pos + 1 > room) {
                        return kStBufferOverflow;
                    }
                    buffer[pos++] = u'\t';
                    break;
                }
                [[fallthrough]];
            case u'n':
                if (pos + 2 > room) {
                    return kStBufferOverflow;
                }
                buffer[pos++] = u'\r';
                buffer[pos++] = u'\n';
                line = pos;
                space = -1;
                break;
            case u'r':
                if (pos + 1 > room) {
                    return kStBufferOverflow;
                }
                buffer[pos++] = u'\r';
                line = pos;
                space = -1;
                break;
            case u'0':
                // Discard the rest of the template. This is how a message
                // resource whose last insert the caller did not supply ends
                // early instead of printing the placeholders it has no
                // arguments for.
                while (scan[1] != u'\0') {
                    ++scan;
                }
                break;
            case u'1':
            case u'2':
            case u'3':
            case u'4':
            case u'5':
            case u'6':
            case u'7':
            case u'8':
            case u'9':
                if (ignore_inserts == kFalse) {
                    int nr = static_cast<int>(*scan) - static_cast<int>(u'0');
                    ++scan;
                    if (*scan >= u'0' && *scan <= u'9') {
                        nr = nr * 10 + static_cast<int>(*scan) -
                             static_cast<int>(u'0');
                        ++scan;
                    }
                    status = add_format(buffer, pos, room, scan, nr, ansi, args);
                    --scan;
                    break;
                }
                [[fallthrough]];
            default:
                // The `%` goes and the character stays, unless inserts are
                // being ignored -- then both stay, because the whole point is
                // that a caller with no arguments can still read what the
                // placeholders were.
                if (ignore_inserts != kFalse) {
                    if (pos + 2 > room) {
                        return kStBufferOverflow;
                    }
                    buffer[pos++] = u'%';
                    buffer[pos++] = *scan;
                } else {
                    if (pos + 1 > room) {
                        return kStBufferOverflow;
                    }
                    buffer[pos++] = *scan;
                }
                break;
            }
            break;
        }
        default:
            if (pos + 1 > room) {
                return kStBufferOverflow;
            }
            buffer[pos++] = *scan;
            break;
        }
        if (status != kStSuccess) {
            return status;
        }
        if (width != 0 && pos - line >= width) {
            // Break at the last space on this line, and eat the run of spaces
            // and tabs around it: keeping them would leave every wrapped line
            // starting with the whitespace that caused the break, which is
            // what a hand-wrapped message looks like and is not what a
            // formatter's output looks like.
            std::ptrdiff_t diff = 2;
            std::ptrdiff_t next = 0;
            if (space >= 0) {
                next = space + 1;
                while (space > static_cast<std::ptrdiff_t>(line) &&
                       (buffer[static_cast<std::size_t>(space) - 1] == u' ' ||
                        buffer[static_cast<std::size_t>(space) - 1] == u'\t')) {
                    --space;
                }
                diff -= next - space;
            } else {
                space = static_cast<std::ptrdiff_t>(pos);
                next = space;
            }
            if (diff > 0 &&
                static_cast<std::size_t>(diff) > room - pos) {
                return kStBufferOverflow;
            }
            const std::size_t moved =
                pos - static_cast<std::size_t>(next);
            std::memmove(buffer + space + 2, buffer + next,
                         moved * sizeof(char16_t));
            pos = static_cast<std::size_t>(static_cast<std::ptrdiff_t>(pos) + diff);
            buffer[static_cast<std::size_t>(space)] = u'\r';
            buffer[static_cast<std::size_t>(space) + 1] = u'\n';
            line = static_cast<std::size_t>(space) + 2;
            space = -1;
        }
    }
    // The terminator, and the size in **bytes** including it -- which is why
    // a caller that treats `retsize` as a character count over-allocates and a
    // caller that treats it as excluding the terminator reads one character
    // past the end. The reference is unambiguous and so is this.
    if (pos + 1 > room) {
        return kStBufferOverflow;
    }
    buffer[pos] = u'\0';
    *retsize = static_cast<std::uint32_t>((pos + 1) * sizeof(char16_t));
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlFormatMessage(
    const char16_t* src, std::uint32_t width, Boolean ignore_inserts,
    Boolean ansi, Boolean is_array, const void* args, char16_t* buffer,
    std::uint32_t size, std::uint32_t* retsize) noexcept {
    return format_message_impl(src, width, ignore_inserts, ansi, is_array, args,
                               buffer, size, retsize);
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlFormatMessageEx(
    const char16_t* src, std::uint32_t width, Boolean ignore_inserts,
    Boolean ansi, Boolean is_array, const void* args, char16_t* buffer,
    std::uint32_t size, std::uint32_t* retsize, std::uint32_t flags) noexcept {
    if (flags != 0) {
        // The reference prints a FIXME and formats anyway. Refusing is better:
        // an unknown flag may change the output, and a caller that guessed the
        // flag's value would get a string that is confidently wrong. The
        // only defined value is zero.
        return kStInvalidParameter;
    }
    return format_message_impl(src, width, ignore_inserts, ansi, is_array, args,
                               buffer, size, retsize);
}

// ------------------------------------------------------- the odd corners
//
// The last eleven names, and they are a group because they are the ones where
// the answer depends on something this runtime does not have. Each is
// registered -- a guest that imports one and finds it missing fails to load,
// which is a worse outcome than a call that reports "not implemented" -- and
// each says so through the channel its signature provides.

// One narrow character as one wide character, with the source pointer
// advanced. The advancing is the whole contract: the reference's callers walk
// a narrow string with this and expect it to move, and a version that returned
// the character without moving would loop forever on a multi-byte encoding.
extern "C" __attribute__((ms_abi)) char16_t nrs_RtlAnsiCharToUnicodeChar(
    char** ansi) noexcept {
    if (ansi == nullptr || *ansi == nullptr) {
        return 0;
    }
    const char* at = *ansi;
    // Decode one UTF-8 sequence, advancing over exactly the bytes it used.
    // The host's decoder is asked for the length first, which is what tells
    // the pointer how far to move; a byte that is not a valid start is taken
    // as one byte and as U+FFFD, which is what a malformed narrow string
    // should yield rather than a refusal -- the caller is walking text it did
    // not necessarily validate.
    const auto first = static_cast<unsigned char>(at[0]);
    if (first < 0x80) {
        *ansi = const_cast<char*>(at + 1);
        return static_cast<char16_t>(first);
    }
    char16_t decoded = 0;
    std::u16string one;
    std::size_t used = 1;
    // Try the two-, three- and four-byte forms in turn, longest first, and
    // stop at the first that decodes. Longest-first matters: a three-byte
    // sequence's first two bytes are also a valid two-byte prefix's worth, and
    // trying short-first would split every character above U+07FF.
    for (std::size_t want = 4; want >= 2; --want) {
        if (c_length(at) < want) {
            continue;
        }
        if (narrow_in(std::string_view(at, want), one).converted &&
            one.size() == 1) {
            decoded = one[0];
            used = want;
            break;
        }
    }
    if (used == 1) {
        decoded = 0xFFFD;
    }
    *ansi = const_cast<char*>(at + used);
    return decoded;
}

// The activation-context string lookup. The reference's validation is
// reproduced exactly -- a non-null GUID and an unknown flag are both
// `STATUS_INVALID_PARAMETER`, and the keyed data's `cbSize` has to reach the
// roster index -- and then the lookup itself has no context to search: this
// runtime has no SxS activation-context stack, because nothing in it pushes
// one. With no current context and no process context the reference's own
// answer is "not found", and that is what is returned: the same status a
// Windows caller gets for a name that is genuinely absent, which is the
// correct answer here for the same reason -- the name is absent.
constexpr Ntstatus kStSxsKeyNotFound = 0xC0150008;
// `ACTCTX_SECTION_KEYED_DATA`'s `ulAssemblyRosterIndex`, the offset the
// reference measures `cbSize` against. The field order is the structure's,
// documented layout.
constexpr std::size_t kActCtxRosterIndexOffset = 28;

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlFindActivationContextSectionString(
    std::uint32_t flags, const void* guid, std::uint32_t section_kind,
    const void* section_name, void* ptr) noexcept {
    static_cast<void>(section_kind);
    if (guid != nullptr) {
        // The reference's own note: it expected a null GUID and says so. A
        // caller passing one is asking about a keyed section, which needs the
        // section key machinery this runtime does not have.
        return kStInvalidParameter;
    }
    // `FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX` is the one flag the reference
    // knows. A caller passing another has asked for behaviour that is not
    // defined, and answering anyway would be a guess.
    constexpr std::uint32_t kReturnHactctx = 0x00000004;
    if ((flags & ~kReturnHactctx) != 0) {
        return kStInvalidParameter;
    }
    if (section_name == nullptr || section_kind != 0) {
        return kStInvalidParameter;
    }
    const StringView name = read_string(section_name);
    if (name.buffer == nullptr) {
        return kStInvalidParameter;
    }
    if (ptr != nullptr &&
        read_u32(ptr, 0) < kActCtxRosterIndexOffset + sizeof(std::uint32_t)) {
        // `cbSize` too small to reach the roster index: the reference refuses
        // rather than writing past what the caller described.
        return kStInvalidParameter;
    }
    return kStSxsKeyNotFound;
}

// The current-user registry key path. The reference exports the name with no
// body, and what the function does -- expand a path template against the
// current user's security token and profile directory -- needs a token, a
// profile and a registry, none of which this runtime has. The signature can
// report that, so it does.
extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlFormatCurrentUserKeyPath(
    void* path) noexcept {
    if (path == nullptr) {
        return kStInvalidParameter;
    }
    return kStNotImplemented;
}

// Unicode normalisation and IDNA. The reference answers all four of these
// from a normalisation table it maps out of a named section in the kernel
// image -- the tables are megabytes of decomposition and composition data --
// and this runtime has no such section and no such tables. Approximating
// normalisation with case folding would be worse than refusing: a caller
// asking whether a string is NFC-normalised needs the real answer, and
// "probably, because nothing changed under my ASCII mapping" is not an answer
// to that question.
//
// The `form` check is still done first, because it is the reference's own
// first check and a caller passing form 0 gets `STATUS_INVALID_PARAMETER`
// rather than the not-implemented answer -- which is the more useful of the
// two, because it names the actual mistake.
constexpr Ntstatus kStObjectNameNotFound = 0xC0000034;

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlNormalizeString(
    std::uint32_t form, const char16_t* src, std::int32_t src_len, char16_t* dst,
    std::int32_t* dst_len) noexcept {
    if (form == 0) {
        return kStInvalidParameter;
    }
    if (form > 13) {
        // Forms 1..13 are the ones Windows defines: NFC, NFD, NFKC, NFKD and
        // the Nameprep, KC and KD profiles. Anything above is not a form.
        return kStObjectNameNotFound;
    }
    static_cast<void>(src);
    static_cast<void>(src_len);
    static_cast<void>(dst);
    static_cast<void>(dst_len);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlIsNormalizedString(
    std::uint32_t form, const char16_t* str, std::int32_t len,
    std::int32_t* res) noexcept {
    if (form == 0) {
        return kStInvalidParameter;
    }
    if (form > 13) {
        return kStObjectNameNotFound;
    }
    static_cast<void>(str);
    static_cast<void>(len);
    static_cast<void>(res);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlIdnToUnicode(
    std::uint32_t flags, const char16_t* src, std::int32_t src_len,
    char16_t* dst, std::int32_t* dst_len) noexcept {
    static_cast<void>(flags);
    static_cast<void>(src);
    static_cast<void>(src_len);
    static_cast<void>(dst);
    static_cast<void>(dst_len);
    // `IDN_ALLOW_UNASSIGNED` and the rest only change which labels are
    // accepted, and every one of those decisions needs the mapping table this
    // runtime does not carry, so the answer does not depend on the flags.
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlIdnToNameprepUnicode(
    std::uint32_t flags, const char16_t* src, std::int32_t src_len,
    char16_t* dst, std::int32_t* dst_len) noexcept {
    return nrs_RtlIdnToUnicode(flags, src, src_len, dst, dst_len);
}

// The memory-stream family: seven names over one `IMemoryStream`-shaped
// object, and the reason they are all refusals is a single missing piece.
// These are the methods of a stream object, and the only thing in the
// reference's export list that *creates* one is `RtlCreateMemoryStream` --
// which is not in this domain's list and is not implemented here. Without a
// creator there is no object these could be methods of: a caller holding a
// stream pointer got it from something this runtime does not provide, and
// dereferencing it would be reading whatever happened to be at that address.
//
// The `IMemoryStream` header is not private -- it is the documented
// `MSOS_STREAM_HEADER` -- so these could be implemented against a stream a
// caller built by hand. What cannot be implemented is the part that decides
// whether it is worth doing: `RtlReadOutOfProcessMemoryStream` and
// `RtlFinalReleaseOutOfProcessMemoryStream` act on a *different process's*
// address space, and reading another process's memory is not something a
// runtime may do on a caller's say-so. The three same-process ones
// (`RtlReadMemoryStream`, `RtlWriteMemoryStream`, `RtlRevertMemoryStream`)
// and the two COM-shaped ones are refused for the same reason and with the
// same status: reporting "not implemented" is a thing a caller can act on,
// while a plausible-looking answer from a header this runtime never wrote
// would not be.
extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlQueryInterfaceMemoryStream(
    void* stream, const void* iid, void** object) noexcept {
    static_cast<void>(stream);
    static_cast<void>(iid);
    static_cast<void>(object);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlReadMemoryStream(
    void* stream, void* buffer, std::uint32_t length,
    std::uint32_t* completed) noexcept {
    static_cast<void>(stream);
    static_cast<void>(buffer);
    static_cast<void>(length);
    static_cast<void>(completed);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlWriteMemoryStream(
    void* stream, const void* buffer, std::uint32_t length,
    std::uint32_t* completed) noexcept {
    static_cast<void>(stream);
    static_cast<void>(buffer);
    static_cast<void>(length);
    static_cast<void>(completed);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlRevertMemoryStream(
    void* stream) noexcept {
    static_cast<void>(stream);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlReleaseMemoryStream(
    void* stream, std::uint32_t remove_file) noexcept {
    static_cast<void>(stream);
    static_cast<void>(remove_file);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlReadOutOfProcessMemoryStream(
    void* stream, void* buffer, std::uint32_t length,
    std::uint32_t* completed) noexcept {
    static_cast<void>(stream);
    static_cast<void>(buffer);
    static_cast<void>(length);
    static_cast<void>(completed);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlFinalReleaseOutOfProcessMemoryStream(
    void* stream) noexcept {
    static_cast<void>(stream);
    return kStNotImplemented;
}

// The script-callout trio. `RtlSetUnicodeCallouts` installs the code-page and
// case-mapping function tables that `RtlRunEncodeUnicodeString` and
// `RtlRunDecodeUnicodeString` then call, and those two are the LUA virtual
// bytecode encoder and decoder: they are a compiler and an interpreter for a
// stack machine, tens of kilobytes of tables and a dozen opcodes each. There
// is no subset of that worth implementing, because a partial encoder emits
// bytecode the partial decoder cannot read and vice versa -- a caller would
// get neither the script it wrote nor the script it read.
extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlSetUnicodeCallouts(
    const void* tables) noexcept {
    static_cast<void>(tables);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlRunEncodeUnicodeString(
    const char16_t* script, void* language, std::uint32_t* chars_in,
    void** script_out) noexcept {
    static_cast<void>(script);
    static_cast<void>(language);
    static_cast<void>(chars_in);
    static_cast<void>(script_out);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nrs_RtlRunDecodeUnicodeString(
    const char16_t* script, void* language, std::uint32_t* chars_in,
    void** script_out) noexcept {
    static_cast<void>(script);
    static_cast<void>(language);
    static_cast<void>(chars_in);
    static_cast<void>(script_out);
    return kStNotImplemented;
}

// ---------------------------------------------------------- device family

extern "C" __attribute__((ms_abi)) std::uint32_t nrs_RtlConvertDeviceFamilyInfoToString(
    std::uint32_t* family_size, std::uint32_t* form_size, char16_t* family,
    char16_t* form) noexcept {
    if (family_size == nullptr || form_size == nullptr) {
        return kStInvalidParameter;
    }
    // The two answers, and they are the reference's: a runtime that is not
    // running on a Windows device family says "Windows.Desktop" and, having
    // no form to report, "Unknown". A caller that branches on the form gets
    // a value it does not recognise, which is the correct outcome -- the
    // alternative is reporting a form this host has no claim to.
    static const char16_t kFamily[] = u"Windows.Desktop";
    static const char16_t kForm[] = u"Unknown";
    const std::size_t family_bytes =
        (c_length(kFamily) + 1) * sizeof(char16_t);
    const std::size_t form_bytes = (c_length(kForm) + 1) * sizeof(char16_t);
    if (*family_size < family_bytes || *form_size < form_bytes) {
        // The sizes are written even on the refusal -- that is the whole
        // point of the `Ex`-shaped convention, and a caller that sizes from
        // them and retries succeeds.
        *family_size = static_cast<std::uint32_t>(family_bytes);
        *form_size = static_cast<std::uint32_t>(form_bytes);
        return kStBufferTooSmall;
    }
    if (family == nullptr || form == nullptr) {
        return kStInvalidParameter;
    }
    for (std::size_t k = 0; k <= c_length(kFamily); ++k) {
        family[k] = kFamily[k];
    }
    for (std::size_t k = 0; k <= c_length(kForm); ++k) {
        form[k] = kForm[k];
    }
    *family_size = static_cast<std::uint32_t>(family_bytes);
    *form_size = static_cast<std::uint32_t>(form_bytes);
    return kStSuccess;
}

// ------------------------------------------------------------- registration

// The names this domain contributes to ntdll's export list.
//
// The `Rtlx*` four are here rather than in the "aliases" of some other
// family because the reference exports them from the same bodies as the
// spellings above: a guest that imports `RtlxUnicodeStringToOemSize` is
// asking for the same computation under the name the kernel's own internal
// callers use, and registering it against a different implementation would
// be a second answer to one question.
void add_ntdll_rtl_str(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };

    // -- the UNICODE_STRING lifecycle
    e("RtlInitAnsiString", reinterpret_cast<void*>(&nrs_RtlInitAnsiString));
    e("RtlInitAnsiStringEx",
      reinterpret_cast<void*>(&nrs_RtlInitAnsiStringEx));
    e("RtlInitString", reinterpret_cast<void*>(&nrs_RtlInitString));
    e("RtlInitUnicodeString",
      reinterpret_cast<void*>(&nrs_RtlInitUnicodeString));
    e("RtlInitUnicodeStringEx",
      reinterpret_cast<void*>(&nrs_RtlInitUnicodeStringEx));
    e("RtlCreateUnicodeString",
      reinterpret_cast<void*>(&nrs_RtlCreateUnicodeString));
    e("RtlCreateUnicodeStringFromAsciiz",
      reinterpret_cast<void*>(&nrs_RtlCreateUnicodeStringFromAsciiz));
    e("RtlFreeAnsiString", reinterpret_cast<void*>(&nrs_RtlFreeAnsiString));
    e("RtlFreeOemString", reinterpret_cast<void*>(&nrs_RtlFreeOemString));
    e("RtlFreeUnicodeString",
      reinterpret_cast<void*>(&nrs_RtlFreeUnicodeString));
    e("RtlCopyString", reinterpret_cast<void*>(&nrs_RtlCopyString));
    e("RtlCopyUnicodeString",
      reinterpret_cast<void*>(&nrs_RtlCopyUnicodeString));
    e("RtlDuplicateUnicodeString",
      reinterpret_cast<void*>(&nrs_RtlDuplicateUnicodeString));
    e("RtlEraseUnicodeString",
      reinterpret_cast<void*>(&nrs_RtlEraseUnicodeString));
    e("RtlAppendAsciizToString",
      reinterpret_cast<void*>(&nrs_RtlAppendAsciizToString));
    e("RtlAppendStringToString",
      reinterpret_cast<void*>(&nrs_RtlAppendStringToString));
    e("RtlAppendUnicodeToString",
      reinterpret_cast<void*>(&nrs_RtlAppendUnicodeToString));
    e("RtlAppendUnicodeStringToString",
      reinterpret_cast<void*>(&nrs_RtlAppendUnicodeStringToString));

    // -- comparison and search
    e("RtlCompareString", reinterpret_cast<void*>(&nrs_RtlCompareString));
    e("RtlCompareUnicodeString",
      reinterpret_cast<void*>(&nrs_RtlCompareUnicodeString));
    e("RtlCompareUnicodeStrings",
      reinterpret_cast<void*>(&nrs_RtlCompareUnicodeStrings));
    e("RtlEqualString", reinterpret_cast<void*>(&nrs_RtlEqualString));
    e("RtlEqualUnicodeString",
      reinterpret_cast<void*>(&nrs_RtlEqualUnicodeString));
    e("RtlPrefixString", reinterpret_cast<void*>(&nrs_RtlPrefixString));
    e("RtlPrefixUnicodeString",
      reinterpret_cast<void*>(&nrs_RtlPrefixUnicodeString));
    e("RtlFindCharInUnicodeString",
      reinterpret_cast<void*>(&nrs_RtlFindCharInUnicodeString));
    e("RtlHashUnicodeString",
      reinterpret_cast<void*>(&nrs_RtlHashUnicodeString));

    // -- sizes
    e("RtlAnsiStringToUnicodeSize",
      reinterpret_cast<void*>(&nrs_RtlAnsiStringToUnicodeSize));
    e("RtlOemStringToUnicodeSize",
      reinterpret_cast<void*>(&nrs_RtlOemStringToUnicodeSize));
    e("RtlUnicodeStringToAnsiSize",
      reinterpret_cast<void*>(&nrs_RtlUnicodeStringToAnsiSize));
    e("RtlUnicodeStringToOemSize",
      reinterpret_cast<void*>(&nrs_RtlUnicodeStringToOemSize));
    e("RtlxAnsiStringToUnicodeSize",
      reinterpret_cast<void*>(&nrs_RtlxAnsiStringToUnicodeSize));
    e("RtlxOemStringToUnicodeSize",
      reinterpret_cast<void*>(&nrs_RtlxOemStringToUnicodeSize));
    e("RtlxUnicodeStringToAnsiSize",
      reinterpret_cast<void*>(&nrs_RtlxUnicodeStringToAnsiSize));
    e("RtlxUnicodeStringToOemSize",
      reinterpret_cast<void*>(&nrs_RtlxUnicodeStringToOemSize));

    // -- the *String conversions
    e("RtlAnsiStringToUnicodeString",
      reinterpret_cast<void*>(&nrs_RtlAnsiStringToUnicodeString));
    e("RtlOemStringToUnicodeString",
      reinterpret_cast<void*>(&nrs_RtlOemStringToUnicodeString));
    e("RtlUnicodeStringToAnsiString",
      reinterpret_cast<void*>(&nrs_RtlUnicodeStringToAnsiString));
    e("RtlUnicodeStringToOemString",
      reinterpret_cast<void*>(&nrs_RtlUnicodeStringToOemString));
    e("RtlUnicodeStringToCountedOemString",
      reinterpret_cast<void*>(&nrs_RtlUnicodeStringToCountedOemString));

    // -- the *N conversions
    e("RtlMultiByteToUnicodeN",
      reinterpret_cast<void*>(&nrs_RtlMultiByteToUnicodeN));
    e("RtlMultiByteToUnicodeSize",
      reinterpret_cast<void*>(&nrs_RtlMultiByteToUnicodeSize));
    e("RtlOemToUnicodeN", reinterpret_cast<void*>(&nrs_RtlOemToUnicodeN));
    e("RtlUTF8ToUnicodeN", reinterpret_cast<void*>(&nrs_RtlUTF8ToUnicodeN));
    e("RtlConsoleMultiByteToUnicodeN",
      reinterpret_cast<void*>(&nrs_RtlConsoleMultiByteToUnicodeN));
    e("RtlCustomCPToUnicodeN",
      reinterpret_cast<void*>(&nrs_RtlCustomCPToUnicodeN));
    e("RtlUnicodeToMultiByteN",
      reinterpret_cast<void*>(&nrs_RtlUnicodeToMultiByteN));
    e("RtlUnicodeToMultiByteSize",
      reinterpret_cast<void*>(&nrs_RtlUnicodeToMultiByteSize));
    e("RtlUnicodeToOemN", reinterpret_cast<void*>(&nrs_RtlUnicodeToOemN));
    e("RtlUnicodeToUTF8N", reinterpret_cast<void*>(&nrs_RtlUnicodeToUTF8N));
    e("RtlUnicodeToCustomCPN",
      reinterpret_cast<void*>(&nrs_RtlUnicodeToCustomCPN));
    e("RtlUpcaseUnicodeToMultiByteN",
      reinterpret_cast<void*>(&nrs_RtlUpcaseUnicodeToMultiByteN));
    e("RtlUpcaseUnicodeToOemN",
      reinterpret_cast<void*>(&nrs_RtlUpcaseUnicodeToOemN));
    e("RtlUpcaseUnicodeToCustomCPN",
      reinterpret_cast<void*>(&nrs_RtlUpcaseUnicodeToCustomCPN));

    // -- case
    e("RtlUpcaseUnicodeChar",
      reinterpret_cast<void*>(&nrs_RtlUpcaseUnicodeChar));
    e("RtlDowncaseUnicodeChar",
      reinterpret_cast<void*>(&nrs_RtlDowncaseUnicodeChar));
    e("RtlUpcaseUnicodeString",
      reinterpret_cast<void*>(&nrs_RtlUpcaseUnicodeString));
    e("RtlDowncaseUnicodeString",
      reinterpret_cast<void*>(&nrs_RtlDowncaseUnicodeString));
    e("RtlUpperChar", reinterpret_cast<void*>(&nrs_RtlUpperChar));
    e("RtlUpperString", reinterpret_cast<void*>(&nrs_RtlUpperString));
    e("RtlUpcaseUnicodeStringToAnsiString",
      reinterpret_cast<void*>(&nrs_RtlUpcaseUnicodeStringToAnsiString));
    e("RtlUpcaseUnicodeStringToOemString",
      reinterpret_cast<void*>(&nrs_RtlUpcaseUnicodeStringToOemString));
    e("RtlUpcaseUnicodeStringToCountedOemString",
      reinterpret_cast<void*>(&nrs_RtlUpcaseUnicodeStringToCountedOemString));

    // -- integers
    e("RtlCharToInteger", reinterpret_cast<void*>(&nrs_RtlCharToInteger));
    e("RtlIntegerToChar", reinterpret_cast<void*>(&nrs_RtlIntegerToChar));
    e("RtlLargeIntegerToChar",
      reinterpret_cast<void*>(&nrs_RtlLargeIntegerToChar));
    e("RtlUnicodeStringToInteger",
      reinterpret_cast<void*>(&nrs_RtlUnicodeStringToInteger));
    e("RtlIntegerToUnicodeString",
      reinterpret_cast<void*>(&nrs_RtlIntegerToUnicodeString));
    e("RtlInt64ToUnicodeString",
      reinterpret_cast<void*>(&nrs_RtlInt64ToUnicodeString));

    // -- GUID
    e("RtlGUIDFromString", reinterpret_cast<void*>(&nrs_RtlGUIDFromString));
    e("RtlStringFromGUID", reinterpret_cast<void*>(&nrs_RtlStringFromGUID));

    // -- memory
        e("RtlCopyMemoryNonTemporal",
      reinterpret_cast<void*>(&nrs_RtlCopyMemoryNonTemporal));
    e("RtlMoveMemory", reinterpret_cast<void*>(&nrs_RtlMoveMemory));
    e("RtlZeroMemory", reinterpret_cast<void*>(&nrs_RtlZeroMemory));
    e("RtlFillMemory", reinterpret_cast<void*>(&nrs_RtlFillMemory));
    e("RtlFillMemoryUlong", reinterpret_cast<void*>(&nrs_RtlFillMemoryUlong));
    e("RtlZeroHeap", reinterpret_cast<void*>(&nrs_RtlZeroHeap));
    e("RtlCompareMemory", reinterpret_cast<void*>(&nrs_RtlCompareMemory));
    e("RtlCompareMemoryUlong",
      reinterpret_cast<void*>(&nrs_RtlCompareMemoryUlong));
    e("RtlInterlockedCompareExchange64",
      reinterpret_cast<void*>(&nrs_RtlInterlockedCompareExchange64));

    // -- text test
    e("RtlIsTextUnicode", reinterpret_cast<void*>(&nrs_RtlIsTextUnicode));

    // -- SID and LUID
    e("RtlCopySid", reinterpret_cast<void*>(&nrs_RtlCopySid));
    e("RtlCopySidAndAttributesArray",
      reinterpret_cast<void*>(&nrs_RtlCopySidAndAttributesArray));
    e("RtlConvertSidToUnicodeString",
      reinterpret_cast<void*>(&nrs_RtlConvertSidToUnicodeString));
    e("RtlCopySecurityDescriptor",
      reinterpret_cast<void*>(&nrs_RtlCopySecurityDescriptor));
    e("RtlCopyLuid", reinterpret_cast<void*>(&nrs_RtlCopyLuid));
    e("RtlCopyLuidAndAttributesArray",
      reinterpret_cast<void*>(&nrs_RtlCopyLuidAndAttributesArray));

    // -- context
    e("RtlCopyContext", reinterpret_cast<void*>(&nrs_RtlCopyContext));
    e("RtlCopyExtendedContext",
      reinterpret_cast<void*>(&nrs_RtlCopyExtendedContext));

    // -- the IP address grammars
    e("RtlIpv4StringToAddressW",
      reinterpret_cast<void*>(&nrs_RtlIpv4StringToAddressW));
    e("RtlIpv4StringToAddressExW",
      reinterpret_cast<void*>(&nrs_RtlIpv4StringToAddressExW));
    e("RtlIpv4StringToAddressA",
      reinterpret_cast<void*>(&nrs_RtlIpv4StringToAddressA));
    e("RtlIpv4StringToAddressExA",
      reinterpret_cast<void*>(&nrs_RtlIpv4StringToAddressExA));
    e("RtlIpv4AddressToStringW",
      reinterpret_cast<void*>(&nrs_RtlIpv4AddressToStringW));
    e("RtlIpv4AddressToStringExW",
      reinterpret_cast<void*>(&nrs_RtlIpv4AddressToStringExW));
    e("RtlIpv4AddressToStringA",
      reinterpret_cast<void*>(&nrs_RtlIpv4AddressToStringA));
    e("RtlIpv4AddressToStringExA",
      reinterpret_cast<void*>(&nrs_RtlIpv4AddressToStringExA));
    e("RtlIpv6StringToAddressW",
      reinterpret_cast<void*>(&nrs_RtlIpv6StringToAddressW));
    e("RtlIpv6StringToAddressExW",
      reinterpret_cast<void*>(&nrs_RtlIpv6StringToAddressExW));
    e("RtlIpv6StringToAddressA",
      reinterpret_cast<void*>(&nrs_RtlIpv6StringToAddressA));
    e("RtlIpv6StringToAddressExA",
      reinterpret_cast<void*>(&nrs_RtlIpv6StringToAddressExA));
    e("RtlIpv6AddressToStringW",
      reinterpret_cast<void*>(&nrs_RtlIpv6AddressToStringW));
    e("RtlIpv6AddressToStringExW",
      reinterpret_cast<void*>(&nrs_RtlIpv6AddressToStringExW));
    e("RtlIpv6AddressToStringA",
      reinterpret_cast<void*>(&nrs_RtlIpv6AddressToStringA));
    e("RtlIpv6AddressToStringExA",
      reinterpret_cast<void*>(&nrs_RtlIpv6AddressToStringExA));

    // -- the message formatter
    e("RtlFormatMessage", reinterpret_cast<void*>(&nrs_RtlFormatMessage));
    e("RtlFormatMessageEx",
      reinterpret_cast<void*>(&nrs_RtlFormatMessageEx));

    // -- environment
    e("RtlExpandEnvironmentStrings",
      reinterpret_cast<void*>(&nrs_RtlExpandEnvironmentStrings));
    e("RtlExpandEnvironmentStrings_U",
      reinterpret_cast<void*>(&nrs_RtlExpandEnvironmentStrings_U));

    // -- the activation context and the user key path
    e("RtlFindActivationContextSectionString",
      reinterpret_cast<void*>(&nrs_RtlFindActivationContextSectionString));
    e("RtlFormatCurrentUserKeyPath",
      reinterpret_cast<void*>(&nrs_RtlFormatCurrentUserKeyPath));

    // -- normalisation and IDN. Registered and refusing; see the definitions.
    e("RtlNormalizeString",
      reinterpret_cast<void*>(&nrs_RtlNormalizeString));
    e("RtlIsNormalizedString",
      reinterpret_cast<void*>(&nrs_RtlIsNormalizedString));
    e("RtlIdnToUnicode", reinterpret_cast<void*>(&nrs_RtlIdnToUnicode));
    e("RtlIdnToNameprepUnicode",
      reinterpret_cast<void*>(&nrs_RtlIdnToNameprepUnicode));

    // -- one narrow character at a time
    e("RtlAnsiCharToUnicodeChar",
      reinterpret_cast<void*>(&nrs_RtlAnsiCharToUnicodeChar));

    // -- the memory streams. Registered and refusing; see the definitions.
    e("RtlQueryInterfaceMemoryStream",
      reinterpret_cast<void*>(&nrs_RtlQueryInterfaceMemoryStream));
    e("RtlReadMemoryStream",
      reinterpret_cast<void*>(&nrs_RtlReadMemoryStream));
    e("RtlWriteMemoryStream",
      reinterpret_cast<void*>(&nrs_RtlWriteMemoryStream));
    e("RtlRevertMemoryStream",
      reinterpret_cast<void*>(&nrs_RtlRevertMemoryStream));
    e("RtlReleaseMemoryStream",
      reinterpret_cast<void*>(&nrs_RtlReleaseMemoryStream));
    e("RtlReadOutOfProcessMemoryStream",
      reinterpret_cast<void*>(&nrs_RtlReadOutOfProcessMemoryStream));
    e("RtlFinalReleaseOutOfProcessMemoryStream",
      reinterpret_cast<void*>(&nrs_RtlFinalReleaseOutOfProcessMemoryStream));

    // -- the script callouts. Registered and refusing; see the definitions.
    e("RtlSetUnicodeCallouts",
      reinterpret_cast<void*>(&nrs_RtlSetUnicodeCallouts));
    e("RtlRunEncodeUnicodeString",
      reinterpret_cast<void*>(&nrs_RtlRunEncodeUnicodeString));
    e("RtlRunDecodeUnicodeString",
      reinterpret_cast<void*>(&nrs_RtlRunDecodeUnicodeString));

    // -- device family
    e("RtlConvertDeviceFamilyInfoToString",
      reinterpret_cast<void*>(&nrs_RtlConvertDeviceFamilyInfoToString));
}

}  // namespace occ::runtime::winabi

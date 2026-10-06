#include "occ/runtime/loader.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace occ::runtime {

namespace {

// ---------------------------------------------------------------- constants

// IMAGE_DIRECTORY_ENTRY_* indices into the data directories array.
//
// Only the entries this loader reads from the raw header are named. The
// exception directory and the IAT directory are not among them: an index
// constant that no code uses is a claim that the corresponding directory is
// handled, and neither is at this layer. The exception directory belongs to
// the layer that dispatches structured exceptions, and the IAT is located
// through each import descriptor's own fields rather than through the
// directory entry.
//
// The base relocation directory is read through the parser's accessor for
// the same reason: the parser already resolved it, and reading it again
// from the raw header would be a second place for the offset arithmetic to
// be wrong.
constexpr unsigned kDirImport = 1;
constexpr unsigned kDirTls = 9;

// The relocation types this runtime applies.
//
// ABSOLUTE is not a relocation, it is padding between blocks, and applying
// it would write zeros over a section. Typing it and then ignoring it is
// how the padding is handled without a special case in the loop that reads
// entries.
constexpr std::uint16_t kRelBasedAbsolute = 0;
constexpr std::uint16_t kRelBasedHigh = 1;
constexpr std::uint16_t kRelBasedLow = 2;
constexpr std::uint16_t kRelBasedHighLow = 3;
constexpr std::uint16_t kRelBasedHighAdj = 4;
constexpr std::uint16_t kRelBasedDir64 = 10;

// The offset of the data directories inside the optional header, from the
// start of the optional header. The optional header is a fixed prefix
// followed by the directory array, and the array's position differs between
// PE32 and PE32+ only because the fixed prefix does.
constexpr std::size_t kDirsOffset32 = 96;
constexpr std::size_t kDirsOffset64 = 112;

// ------------------------------------------------------------------ reading

// A little-endian read at a byte offset, with the bound checked as a
// subtraction.
//
// The subtraction matters: `off + 4 > size` wraps when both operands come
// from the file, and a wrapped comparison passes while the read after it
// goes out of bounds. `off > size - 4` cannot wrap because the guard above
// it has already established that size is at least 4.
[[nodiscard]] bool read_u16(ByteSpan b, std::size_t off,
                            std::uint16_t& out) noexcept {
    if (b.size() < 2 || off > b.size() - 2) {
        return false;
    }
    out = static_cast<std::uint16_t>(b.data()[off]) |
          static_cast<std::uint16_t>(static_cast<std::uint16_t>(b.data()[off + 1])
                                     << 8);
    return true;
}

[[nodiscard]] bool read_u32(ByteSpan b, std::size_t off,
                            std::uint32_t& out) noexcept {
    if (b.size() < 4 || off > b.size() - 4) {
        return false;
    }
    out = static_cast<std::uint32_t>(b.data()[off]) |
          (static_cast<std::uint32_t>(b.data()[off + 1]) << 8) |
          (static_cast<std::uint32_t>(b.data()[off + 2]) << 16) |
          (static_cast<std::uint32_t>(b.data()[off + 3]) << 24);
    return true;
}

[[nodiscard]] bool read_u64(ByteSpan b, std::size_t off,
                            std::uint64_t& out) noexcept {
    std::uint32_t lo = 0;
    std::uint32_t hi = 0;
    if (!read_u32(b, off, lo) || !read_u32(b, off + 4, hi)) {
        return false;
    }
    out = static_cast<std::uint64_t>(lo) |
          (static_cast<std::uint64_t>(hi) << 32);
    return true;
}

// Reads a NUL-terminated ASCII string at an RVA, bounded by the file.
//
// A name that does not terminate inside the file is refused rather than
// returned as a fragment. An import named "CreateFileW" and one named
// "CreateFileW" followed by garbage are different programs' requests and a
// reader that silently truncates cannot tell the person which one it saw.
[[nodiscard]] bool read_rva_name(const parser::PeImage& image, ByteSpan bytes,
                                 std::uint64_t rva,
                                 std::string& out) noexcept {
    std::uint64_t off = 0;
    if (!image.to_file_offset(rva, off)) {
        return false;
    }
    if (off >= bytes.size()) {
        return false;
    }
    out.clear();
    // A cap rather than a scan to the end of the file: an export name
    // longer than this is not a name, and a corrupted pointer into a large
    // section would otherwise be walked in full.
    constexpr std::size_t kMaxName = 4096;
    for (std::size_t i = static_cast<std::size_t>(off); i < bytes.size(); ++i) {
        const char c = static_cast<char>(bytes.data()[i]);
        if (c == '\0') {
            return !out.empty();
        }
        if (out.size() >= kMaxName) {
            return false;
        }
        out.push_back(c);
    }
    return false;
}

// -------------------------------------------------------------------- events

void emit_mapping(obs::Writer* w, const Region& r) noexcept {
    if (w == nullptr) {
        return;
    }
    auto& e = w->begin(obs::EventKind::Mapping);
    e.add_hex("base", r.base);
    e.add_hex("size", r.size);
    e.add("protection", protection_name(r.protection));
    e.add("kind", region_kind_name(r.kind));
    if (!r.section.empty()) {
        e.add("section", r.section);
    }
    w->commit();
}

void emit_note(obs::Writer* w, std::string_view text) noexcept {
    if (w != nullptr) {
        w->note(text);
    }
}

// An address as the "0x" + minimal lowercase-hex form the details below use.
//
// It mirrors the helper detect.cpp defines for its own refusals, and it is
// duplicated rather than shared for the same reason the two parsers do not
// share theirs: a formatting decision made for one refusal should not change
// another. The width is the value's own, so 0x0 is spelled 0x0 and not
// 0x0000000000000000, which is what a reader comparing two refusals needs.
[[nodiscard]] std::string hex_of(std::uint64_t v) {
    if (v == 0) {
        return "0x0";
    }
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    while (v != 0) {
        out.push_back(digits[v & 0xf]);
        v >>= 4;
    }
    out.push_back('x');
    out.push_back('0');
    std::reverse(out.begin(), out.end());
    return out;
}

// ------------------------------------------------------- writing the memory

// Little-endian stores at an address in mapped memory.
//
// These have no bounds check, which is the thing a reader is most likely to
// object to, so the reason is worth one paragraph. The address is derived
// from an RVA that the placement plan already checked is inside the image,
// and the image's regions are the only things this process can make, so the
// store lands in one of them. A check here would be a second place where the
// same question is answered, and it would answer it with less information:
// the caller's check is against the map, which is the authority, while a
// check here would be against the arithmetic.
//
// The value is written through a byte pointer rather than a reinterpret_cast
// to a wider type because the address is only 4-byte or 8-byte aligned if
// the relocation says so, and a store through a misaligned wide pointer is
// undefined even on x86 where it works. The byte loop has no such
// requirement and the cost is four or eight stores on a path that runs tens
// of thousands of times per image.
void store_u16(std::uint64_t va, std::uint16_t v) noexcept {
    auto* p = reinterpret_cast<std::uint8_t*>(va);
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
}

void store_u32(std::uint64_t va, std::uint32_t v) noexcept {
    auto* p = reinterpret_cast<std::uint8_t*>(va);
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
    p[2] = static_cast<std::uint8_t>(v >> 16);
    p[3] = static_cast<std::uint8_t>(v >> 24);
}

void store_u64(std::uint64_t va, std::uint64_t v) noexcept {
    store_u32(va, static_cast<std::uint32_t>(v));
    store_u32(va + 4, static_cast<std::uint32_t>(v >> 32));
}

// A load at an address in mapped memory, with the answer the caller needs to
// tell "the address held this" from "the address was not readable".
//
// The counterpart to the stores above, and it exists for the same reason they
// do and with the same caveat: no bounds check, because the caller checked
// the address against the space. The difference is that a store cannot
// report -- writing to an unmapped address kills the process, which is a
// perfectly clear way of finding out -- while a load can come back as
// anything at all, and a caller that treats that as data produces an answer
// from whatever the kernel left there.
//
// `space` is the authority rather than a size, because a TLS template is
// read from an image that was placed rather than from the file, and "inside
// the image" and "inside a region this process mapped" are different
// questions: the first is a fact about the file's arithmetic and the second
// is a fact about the process.
[[nodiscard]] bool load_from(const AddressSpace& space, std::uint64_t va,
                             void* dst, std::size_t bytes) noexcept {
    const Region* r = space.find(va);
    if (r == nullptr || r->end() < va + bytes) {
        return false;
    }
    std::memcpy(dst, reinterpret_cast<const void*>(va), bytes);
    return true;
}

[[nodiscard]] bool load_u32_from(const AddressSpace& space, std::uint64_t va,
                                 std::uint32_t& out) noexcept {
    return load_from(space, va, &out, sizeof out);
}

[[nodiscard]] bool load_u64_from(const AddressSpace& space, std::uint64_t va,
                                 std::uint64_t& out) noexcept {
    return load_from(space, va, &out, sizeof out);
}

// The width, in bytes, of the field a relocation of this type writes.
//
// The switch in `apply_one` below is the authority on what each type does, and
// this is the same mapping kept where a caller can read it before the write:
// a caller that has to know how many bytes will land needs the answer before
// it calls, not after. The two are kept in step by the fact that every arm of
// `apply_one` writes exactly one of the widths below, and a type that falls
// off the end here is one `apply_one` refuses as well.
//
// Absolute has no field -- it is padding -- and its width is zero, which is
// the value that makes the containment test in `region_for_write` succeed for
// any mapped address. That is correct: nothing is written, so nothing has to
// fit. The caller skips Absolute before reading this, so the zero is a
// fallback rather than a case in the walk.
[[nodiscard]] constexpr std::uint64_t relocation_width(
    std::uint16_t type) noexcept {
    switch (type) {
    case kRelBasedHigh:
    case kRelBasedLow:
    case kRelBasedHighAdj:
        return 2;
    case kRelBasedHighLow:
        return 4;
    case kRelBasedDir64:
        return 8;
    default:
        return 0;
    }
}

// The region a field of `bytes` width at `va` fits in entirely, or null.
//
// The stores below take an address and a width and write that many bytes, and
// every one of them is reached from a file's arithmetic rather than from
// anything this process decided. `find(va)` is the check they used to lean on,
// and it answers a narrower question than the one that matters: it says the
// first byte is mapped, not that the field is. A DIR64 relocation whose RVA
// lands one byte before the end of the last mapped region passes `find` and
// then writes seven bytes past it.
//
// This is the store-side twin of `load_from` above, and it exists for the same
// reason: both operations take an address and a width, and the containment
// test has to be made against the width. `load_from` can report the overrun to
// its caller; a store cannot, for the reason given above its definition, so
// the caller has to ask first.
//
// `r->end()` is exclusive, and the sum is written as a subtraction from the
// end rather than as `va + bytes <= r->end()` so that a `bytes` that would
// overflow past the top of the address space cannot wrap into the test and
// pass it.
[[nodiscard]] const Region* region_for_write(const AddressSpace& space,
                                             std::uint64_t va,
                                             std::uint64_t bytes) noexcept {
    const Region* r = space.find(va);
    if (r == nullptr) {
        return nullptr;
    }
    if (bytes > r->size || va - r->base > r->size - bytes) {
        return nullptr;
    }
    return r;
}

// What went wrong when a relocation could not be written.
struct RelocFailure {
    bool failed = false;
    std::uint64_t rva = 0;
    const char* what = "";
};

// Reads a 16-bit field out of mapped memory.
//
// Byte at a time for the reason the loaders below do their arithmetic in a
// wider type and store back narrow: the address is only guaranteed to be
// aligned to whatever the linker emitted, and a narrow load at an odd address
// is a fault on some architectures and undefined on all of them.
[[nodiscard]] std::uint16_t load_u16_at(std::uint64_t va) noexcept {
    const auto* p = reinterpret_cast<const std::uint8_t*>(va);
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(p[0]) |
                                   static_cast<std::uint16_t>(
                                       static_cast<std::uint16_t>(p[1]) << 8)));
}

// Applies one relocation of the given type at `va`.
//
// The five types the format defines, each writing the form the linker emitted
// rather than a normalized 64-bit form. A runtime that wrote all of them as
// DIR64 would corrupt every 32-bit field in the image, and one that wrote them
// all as 32-bit would truncate a real pointer; the type is the whole of what
// distinguishes them.
//
// The 16-bit types -- HIGH, LOW and HIGHADJ -- are 16-bit types. They
// relocate a *half* of an address, on the machines whose instructions could
// not hold a 32-bit absolute address in one operand (MIPS, Alpha, IA64's
// predecessors). Reading and writing 32 bits at those addresses corrupts the
// neighbouring field, and the arithmetic below is the Windows Research
// Kernel's, which is the authority: the format description in the PE
// specification is a sentence long and does not say what the arithmetic is.
//
// `adjustment` carries HIGHADJ's second value, which lives in the *next
// relocation entry* rather than in the image. The caller reads it and passes
// it here because the entry walk is where the file is being read; see
// HIGHADJ below for why it cannot come from the image.
[[nodiscard]] RelocFailure apply_one(std::uint64_t va, std::uint16_t type,
                                     std::uint64_t delta,
                                     std::int16_t adjustment) noexcept {
    RelocFailure f;
    switch (type) {
    case kRelBasedHigh: {
        // The 16-bit field is the high half of a 32-bit address. The low half
        // is not in this entry, so the arithmetic has to pretend the field is
        // the whole address, shift the field up to where it belongs, add the
        // delta, and shift back down -- which discards exactly the delta's
        // low 16 bits and keeps the field's own low half out of the result.
        //
        // The shifts are on a signed 32-bit value because the sum is meant to
        // be interpreted as one: a field of 0xFFFF shifted up is negative,
        // and an unsigned shift would bring zeros into the top half and make
        // the addition wrap differently. This is `LONG Temp` in the kernel's
        // LdrProcessRelocationBlock.
        std::int32_t temp = static_cast<std::int32_t>(
                                static_cast<std::uint32_t>(load_u16_at(va))
                                << 16);
        temp += static_cast<std::int32_t>(static_cast<std::uint32_t>(delta));
        store_u16(va, static_cast<std::uint16_t>(temp >> 16));
        return f;
    }
    case kRelBasedLow: {
        // The 16-bit field is the low half of an address. It moves by the
        // whole delta and wraps within its own 16 bits, which is what the
        // field's width means -- the machine reading it sign-extends, so the
        // wrap is not an accident but the encoding.
        //
        // Wine skips this in 64-bit builds. That is a defensible reading of
        // "no amd64 linker emits LOW", and this runtime does not emit relocs
        // either -- but skipping it here would be a claim about what a file
        // may contain rather than about what the type means, and a loader
        // that refuses a file it could place is not more faithful than one
        // that places it wrong. The kernel applies it unconditionally, and so
        // does this.
        const std::uint16_t field = load_u16_at(va);
        store_u16(va, static_cast<std::uint16_t>(
                           static_cast<std::uint32_t>(field) +
                           static_cast<std::uint32_t>(delta)));
        return f;
    }
    case kRelBasedHighLow: {
        // A 32-bit field moves by the whole delta, with wraparound. The delta
        // is truncated to 32 bits first because the field is 32 bits: adding a
        // 64-bit delta to a 32-bit field would be a different operation, and
        // a linker that emitted a HIGHLOW in a 64-bit image emitted it
        // against an address it knew would stay in the low 4 GiB.
        std::uint32_t v = 0;
        const auto* p = reinterpret_cast<const std::uint8_t*>(va);
        v = static_cast<std::uint32_t>(p[0]) |
            (static_cast<std::uint32_t>(p[1]) << 8) |
            (static_cast<std::uint32_t>(p[2]) << 16) |
            (static_cast<std::uint32_t>(p[3]) << 24);
        v += static_cast<std::uint32_t>(delta);
        store_u32(va, v);
        return f;
    }
    case kRelBasedHighAdj: {
        // The one relocation that is not a relocation of the address it
        // names, and the only one whose correctness depends on a value that
        // is not in the image at all.
        //
        // A MIPS immediate is a signed 16-bit field, and an address assembled
        // from two of them needs the high half adjusted when the low half is
        // negative: 0x0000_7FFF plus a base is 0x0000_8000-ish, and the
        // carry has to go somewhere. HIGHADJ is how the linker says where.
        //
        // The kernel's arithmetic, which is the whole of the specification
        // that matters here:
        //
        //     Temp = field << 16;      // the 16-bit high half, as an address
        //     Temp += adjustment;      // the carry the linker recorded
        //     Temp += Diff;            // this load's delta
        //     Temp += 0x8000;          // rounding
        //     field = Temp >> 16;
        //
        // Three parts of that are load-bearing and none is decoration.
        //
        // The adjustment comes from the *next relocation entry*, not from the
        // image. An entry is 16 bits of type and offset with no room for a
        // value, so the adjustment is stored as a second entry whose own
        // offset field is meaningless and whose 16 bits are the number. That
        // is why this entry consumes two slots and why the caller has to
        // read it -- and it is why an implementation that reads the
        // adjustment out of the bytes *after* the field in the image is
        // reading whatever that code happens to be: on the machines that emit
        // HIGHADJ, the instruction at the relocated address is a pair of
        // immediates, so the bytes after the high half are the low half --
        // the wrong number entirely.
        //
        // The adjustment is signed. The linker emits the carry as a negative
        // number when the low half was negative, and reading it as unsigned
        // turns a subtraction of 8 into an addition of 65528.
        //
        // The 0x8000 is a rounding term and not an offset. The low half is
        // signed, so adding it to the high half alone is ambiguous at the
        // halfway point; the kernel adds half of the low half's range and
        // then discards the low half by shifting, which rounds the total
        // toward the value the assembler's sign extension would have
        // produced. An implementation that omits it is off by one on every
        // field whose low half is in [0x0000, 0x8000) -- a third of them --
        // and only on those, which is the worst possible way to be wrong.
        //
        // There is no second-entry bookkeeping here and no "already applied"
        // flag: the kernel checks a bit in the *offset* field
        // (LDRP_RELOCATION_FINAL) because the Windows loader can be asked to
        // relocate an image twice and the second pass would add the delta
        // again. This loader relocates exactly once per load, from the file's
        // bytes, and places the result at an address the caller was given --
        // there is no second pass to defend against, and adding a bit to an
        // entry would mutate the file's image for a caller that did not ask
        // for that.
        std::int32_t temp = static_cast<std::int32_t>(
                                static_cast<std::uint32_t>(load_u16_at(va))
                                << 16);
        temp += static_cast<std::int32_t>(adjustment);
        temp += static_cast<std::int32_t>(static_cast<std::uint32_t>(delta));
        temp += 0x8000;
        store_u16(va, static_cast<std::uint16_t>(temp >> 16));
        return f;
    }
    case kRelBasedDir64: {
        // The only type this runtime sees in practice on amd64, and the only
        // one whose field is as wide as the address it holds.
        std::uint64_t out = 0;
        for (int i = 7; i >= 0; --i) {
            out = (out << 8) |
                  static_cast<std::uint64_t>(
                      reinterpret_cast<const std::uint8_t*>(va)[i]);
        }
        out += delta;
        store_u64(va, out);
        return f;
    }
    default:
        f.failed = true;
        f.rva = va;
        f.what = "a relocation type this runtime does not apply";
        return f;
    }
}

// Undoes a placement: unmaps every region the batch recorded.
//
// The undo is by base address, from the batch rather than from the space,
// because the space may have been given more regions by a later step of a
// load that is not this one. Reverse order, so that a partial undo leaves
// the regions that were mapped first in the state that a reader would expect
// to still be there -- and because for an image whose sections were adjacent,
// the highest section is the one a reader looks at first.
//
// A failure here is not reported over the failure that caused it. A munmap
// of an address this function just mapped cannot fail on a sane kernel, and
// a caller that was told "the load failed" cannot act differently on the
// second failure, so surfacing it would replace a message that names the
// cause with one that names a consequence.
void rollback_placement(Mapper& m,
                        const std::vector<AddressSpace::Candidate>& batch) noexcept {
    for (auto it = batch.rbegin(); it != batch.rend(); ++it) {
        (void)m.unmap(it->base);
    }
}

// Undoes a placement that was only recorded: the ledger's copy of the image,
// with no kernel mapping behind it.
//
// This is not rollback_placement with a null mapper. That would be a crash,
// and the path that needs this is the one that has no mapper by design --
// `occ check`, which reads a file and reports what it says without placing
// anything. So the two cases are told apart by what the caller has, not by
// whether it happens to be null today.
//
// The reason this exists at all is a bug the fuzzer found, and the bug was
// not in the TLS code that introduced the path that reached it. It was here:
// `record_batch` runs before the relocation walk, the IAT and the TLS
// directory, and every one of those three can refuse. A refusal rolled back
// the kernel mapping when there was one and rolled back *nothing* when there
// was not, so a refused `occ check` left the space describing an image with
// no bytes in it -- which is a state the comment at the record call says a
// reader can recognise, and which a caller has no way to tell from a
// successful load. The loader's own contract says a refused load leaves the
// space unchanged. This is where that is kept.
//
// The allocation count does not go back, and that is `remove`'s rule rather
// than a second decision: it counts allocations and hands out replay sequence
// numbers, and a recorded-then-forgotten region consumed one. What has to go
// back is the map, because the map is what "unchanged" is a statement about.
void rollback_record(AddressSpace& space,
                     const std::vector<AddressSpace::Candidate>& batch) noexcept {
    for (auto it = batch.rbegin(); it != batch.rend(); ++it) {
        (void)space.remove(it->base);
    }
}

// Undoes a placement, whichever kind it was.
void rollback(AddressSpace& space, Mapper* placement,
              const std::vector<AddressSpace::Candidate>& batch) noexcept {
    if (placement != nullptr) {
        rollback_placement(*placement, batch);
    } else {
        rollback_record(space, batch);
    }
}

TlsResult commit_tls_index(const TlsModule& m, AddressSpace& space,
                           TlsTable& table) noexcept {
    TlsResult out;
    if (m.index_va == 0) {
        // A directory with no `AddressOfIndex` is legal -- a module can
        // declare a template and no way to find its slot -- and there is
        // nothing to write. Not a refusal: the module's TLS is still built,
        // and a caller that knows the module's base can still find the
        // block. What it cannot do is look it up by index, which is what
        // the absence of the field means.
        out.ok = true;
        return out;
    }
    // Every refusal below hands the slot back, and the reason is the same
    // in both: a slot consumed by a load that then failed is a slot the
    // reuse search will never offer again, because the entry is not zeroed
    // and a non-zero entry looks occupied. A process that loaded and refused
    // the same broken module in a loop would grow its table by one per
    // attempt and never reuse a single one of them.
    //
    // The high-water mark goes back with it, and only when this module held
    // the last slot. Lowering it unconditionally would renumber nothing --
    // it is a bound, not a length -- but it would report a smaller bound than
    // the table has, and the reuse search stops at the bound.
    auto release = [&]() noexcept {
        if (m.index < table.modules.size()) {
            table.modules[m.index] = TlsModule{};
        }
        if (table.slots_allocated == m.index + 1) {
            table.slots_allocated = m.index;
        }
    };

    // The index is four bytes and the test is against four bytes. The field's
    // address comes from the file's TLS directory, so a directory whose
    // AddressOfIndex names the last byte of a region is a file that can be
    // written one byte and probed for three -- which is what `find` alone
    // would allow, since it answers for the first byte only.
    const Region* r =
        region_for_write(space, m.index_va, sizeof(std::uint32_t));
    if (r == nullptr) {
        release();
        out.error = TlsError::MalformedDirectory;
        out.detail = "the TLS index at " + hex_of(m.index_va) +
                     " has no four bytes in any region this load made";
        return out;
    }
    if ((protection_to_prot(r->protection) & PROT_WRITE) == 0) {
        release();
        out.error = TlsError::MalformedDirectory;
        out.detail = "the TLS index at " + hex_of(m.index_va) +
                     " is in " + (r->section.empty() ? "an unnamed section"
                                                     : r->section) +
                     ", which the file declared read-only, so no slot number "
                     "can ever be written there";
        return out;
    }
    store_u32(m.index_va, m.index);
    out.ok = true;
    return out;
}

} // namespace

const char* load_error_name(LoadError e) noexcept {
    switch (e) {
    case LoadError::None: return "none";
    case LoadError::NotParsable: return "not_parsable";
    case LoadError::UnsupportedMachine: return "unsupported_machine";
    case LoadError::SectionOutOfRange: return "section_out_of_range";
    case LoadError::NoRelocations: return "no_relocations";
    case LoadError::BadRelocation: return "bad_relocation";
    case LoadError::MissingImport: return "missing_import";
    case LoadError::UnimplementedImport: return "unimplemented_import";
    case LoadError::AddressConflict: return "address_conflict";
    case LoadError::MappingRefused: return "mapping_refused";
    case LoadError::RelocationNotWritable: return "relocation_not_writable";
    case LoadError::TlsRefused: return "tls_refused";
    }
    return "unknown";
}

LoadResult load_image(const parser::PeImage& image, ByteSpan bytes,
                      std::uint64_t preferred_base, AddressSpace& space,
                      const LoadContext& context) noexcept {
    LoadResult out;

    if (!image.ok()) {
        out.error = LoadError::NotParsable;
        out.detail = image.error_detail();
        return out;
    }

    // The machine check.
    //
    // Only AMD64 is executed. An ARM64 image is a valid PE and refusing it
    // by name is a different act from refusing a damaged file, which is why
    // the error is its own value. The check is on the parser's named
    // machine rather than on the raw word so that adding a machine to the
    // runtime means adding it in one place.
    if (image.machine() != parser::PeMachine::Amd64) {
        out.error = LoadError::UnsupportedMachine;
        out.detail = std::string("the image is for ") +
                     parser::pe_machine_name(image.machine()) +
                     ", and this runtime executes only amd64";
        return out;
    }

    // Where the image lands.
    //
    // A caller that named a base gets it. A caller that did not gets the
    // image's own preferred base, because that is the address the image was
    // linked for and using it means the relocation pass has nothing to do.
    // This is not an optimisation: an image with no relocation table can
    // only load at its preferred base, so choosing it is what lets those
    // images load at all.
    std::uint64_t base = preferred_base != 0 ? preferred_base : image.image_base();
    if (base == 0) {
        out.error = LoadError::NoRelocations;
        out.detail = "the image names no base and the caller named none";
        return out;
    }

    const std::uint64_t image_size = image.image_size();
    if (image_size == 0) {
        out.error = LoadError::SectionOutOfRange;
        out.detail = "the image declares a size of zero";
        return out;
    }

    const std::uint64_t headers_size = image.headers_size();
    if (headers_size > image_size) {
        out.error = LoadError::SectionOutOfRange;
        out.detail = "the headers are larger than the image";
        return out;
    }

    // The relocation decision is made before anything is mapped, so that an
    // image that cannot be placed is refused without having been placed.
    const bool needs_relocation = base != image.image_base();
    const bool has_relocations = image.reloc_size() != 0;
    if (needs_relocation && !has_relocations) {
        out.error = LoadError::NoRelocations;
        out.detail = "the image asked for base " +
                     hex_of(image.image_base()) +
                     " and has no relocation table, so it cannot be placed "
                     "at " + hex_of(base);
        return out;
    }

    // ------------------------------------------------------- placement plan
    //
    // The plan is built before anything is recorded.
    //
    // The order is the contract: a LoadResult that is not ok leaves the
    // space unchanged, and that is what lets a caller retry at another base
    // without unwinding a half-populated map. Everything below that can
    // refuse -- a section out of the window, a bad relocation -- is
    // therefore decided here, against the file and the plan, and the
    // records at the end happen only once all of it has held. Putting the
    // mapping first reads more naturally and is wrong, because the walk
    // that finds a bad relocation comes after it and by then the sections
    // are in the map.

    // The section table, gathered up front so that the loop below does not
    // re-walk it. The count was bounded by the parser; this is only the
    // copy that makes the iteration cheap.
    struct Placement {
        std::uint32_t index;
        const parser::PeSection* section;
        std::uint64_t va;
        std::uint64_t mem_size;
        std::uint64_t file_size;
        std::uint64_t file_off;
    };
    std::vector<Placement> placements;
    placements.reserve(image.sections().size());

    for (std::uint32_t i = 0; i < image.sections().size(); ++i) {
        const parser::PeSection& s = image.sections()[i];

        // The in-memory size is VirtualSize when it is set and the raw size
        // when it is not. A linker that emits a section with VirtualSize 0
        // means "as large as the file part", and treating the zero as a
        // zero-length section would drop it.
        std::uint64_t mem = s.virtual_size != 0 ? s.virtual_size : s.raw_size;
        // Rounded up to a page: a section whose size is not a multiple of
        // the page is mapped in whole pages, and recording it unrounded
        // would leave the tail of the last page unowned, so a fault there
        // would be reported as unmapped when it is mapped.
        mem = (mem + AddressSpace::kPageSize - 1) &
              ~(AddressSpace::kPageSize - 1);
        if (mem == 0) {
            // A section with no content in either coordinate. Legal, and
            // there is nothing to map.
            continue;
        }

        const std::uint64_t va = base + s.virtual_address;
        // A subtraction again: the section's own address from the file is
        // added to a base from the caller, and the sum is compared against
        // the window rather than added to the size.
        if (va < base || va > AddressSpace::kUserMax ||
            mem > AddressSpace::kUserMax - va) {
            out.error = LoadError::SectionOutOfRange;
            out.detail = "section " + s.name + " would be placed outside the "
                         "address window";
            return out;
        }

        Placement p;
        p.index = i;
        p.section = &s;
        p.va = va;
        p.mem_size = mem;
        // The file part is capped at the memory part. A section whose raw
        // size exceeds its virtual size is a file with a tail that is not
        // mapped, which is a real layout and not an error: the bytes are in
        // the file and the program cannot address them.
        p.file_size = s.raw_size < mem ? s.raw_size : mem;
        if (p.file_size > bytes.size() || s.raw_offset > bytes.size() ||
            p.file_size > bytes.size() - s.raw_offset) {
            // The tail is dropped rather than the section refused. The
            // parser already rejected a raw extent outside the file, so
            // reaching here means the file shrank between the parse and the
            // load -- which cannot happen for a file held open, but the
            // check costs nothing and makes the copy below bounded by
            // construction rather than by an argument.
            p.file_size = 0;
        }
        p.file_off = s.raw_offset;

        placements.push_back(p);
    }

    // The entry point has to be inside the image.
    //
    // This is a check the loader did not have and the fuzzer found: an image
    // whose entry RVA points past the end of every section -- or into the
    // gap between two sections that the linker left -- loads, reports
    // success, and hands the layer above a module whose entry address is not
    // mapped. The first instruction of such a program faults, and nothing
    // above this layer can see it coming, because the loader is the only
    // place that holds both the entry address and the map.
    //
    // A zero entry RVA is not an error and is not checked here: an image
    // that is a pure DLL has no entry point and declares zero, and a runtime
    // that refused it would refuse every resource-only module. The check is
    // therefore on a non-zero entry, which is the only case where the field
    // claims something about an address.
    //
    // The bound is the image, not the window: the entry point of an image is
    // an address the image itself owns, and an image that places it outside
    // its own SizeOfImage is an image whose linker disagreed with its
    // headers. The subtraction is a subtraction rather than an addition
    // because both operands come from the file and a sum can wrap.
    const std::uint64_t image_entry_rva = image.entry_rva();
    if (image_entry_rva != 0) {
        if (image_entry_rva >= image_size) {
            out.error = LoadError::SectionOutOfRange;
            out.detail = "the entry point RVA " + hex_of(image_entry_rva) +
                         " is outside the image, which is " +
                         hex_of(image_size) + " bytes";
            return out;
        }
        // And it has to land in a section that was actually placed, and that
        // section has to be executable.
        //
        // The two questions are asked in one walk because they are about the
        // same section. Coverage alone is not enough: the entry point is
        // where execution starts, and a program whose first instruction is
        // in a read-only page cannot run. Windows enforces the same thing
        // and reports it as a failure to start rather than as a fault at the
        // first instruction; deciding it here means the refusal names the
        // section.
        //
        // The headers are deliberately not accepted as coverage. They are
        // never executable, and a program whose entry point is inside its
        // own headers cannot run, so accepting them for coverage and then
        // rejecting them for executability would be two checks where one
        // answers both questions with the same result.
        bool entry_ok = false;
        for (const Placement& p : placements) {
            const std::uint64_t start = p.section->virtual_address;
            if (image_entry_rva >= start &&
                image_entry_rva - start < p.mem_size) {
                entry_ok = p.section->executable();
                break;
            }
        }
        if (!entry_ok) {
            out.error = LoadError::SectionOutOfRange;
            out.detail = "the entry point RVA " + hex_of(image_entry_rva) +
                         " is not in an executable section";
            return out;
        }
    }

    // No two of the regions this load will record may overlap.
    //
    // The address space refuses overlapping records, but a refusal from
    // there is reported as a conflict with the caller's space and this is a
    // fact about the file: the image's own sections overlap, or a section
    // starts inside the headers. Refusing it here means the message names
    // the file and the header check upstream is not needed, and it also
    // means the batch handed to record_batch() is already known to be
    // internally disjoint.
    //
    // The sections are sorted by address once, so the check is the same
    // adjacent comparison the address space uses rather than a quadratic
    // scan. The sort is on a copy of the indices, so the placements vector
    // keeps the file's order for the report.
    //
    // A section that starts at an address below the headers' end overlaps
    // them, and that is checked by comparing each section's start against
    // headers_size. A section with VirtualAddress 0 -- which a malformed
    // image can declare, and the fuzzer produced one -- lands there and is
    // refused, which is the right answer because the headers occupy that
    // address.
    {
        std::vector<std::size_t> order;
        order.reserve(placements.size());
        for (std::size_t i = 0; i < placements.size(); ++i) {
            order.push_back(i);
        }
        std::sort(order.begin(), order.end(),
                  [&placements](std::size_t a, std::size_t b) {
                      return placements[a].section->virtual_address <
                             placements[b].section->virtual_address;
                  });
        std::uint64_t furthest_end = headers_size;
        for (const std::size_t i : order) {
            const Placement& p = placements[i];
            const std::uint64_t start = p.section->virtual_address;
            if (start < furthest_end) {
                out.error = LoadError::SectionOutOfRange;
                out.detail = "section " + p.section->name +
                             " at RVA " + hex_of(start) +
                             " overlaps the headers or an earlier section";
                return out;
            }
            furthest_end = start + p.mem_size;
        }
    }

    // -------------------------------------------------------- relocations
    //
    // Walked before anything is recorded, for the reason stated above: this
    // is the pass that can refuse an image, and it only reads the file.

    LoadedModule module;
    module.base = base;
    module.size = image_size;
    module.entry_va = base + image.entry_rva();

    if (needs_relocation) {
        const std::uint64_t reloc_end =
            image.reloc_rva() + image.reloc_size();
        std::uint64_t cursor = image.reloc_rva();

        while (cursor + 8 <= reloc_end) {
            // Each block is a page address and a block size, followed by
            // 16-bit entries. The size covers the header, so a block whose
            // size is less than its header is a block that would loop
            // forever; refusing it is what keeps the walk bounded.
            std::uint64_t block_off = 0;
            if (!image.to_file_offset(cursor, block_off) ||
                block_off + 8 > bytes.size()) {
                out.error = LoadError::BadRelocation;
                out.detail = "a relocation block header is outside the file";
                return out;
            }
            std::uint32_t page_rva = 0;
            std::uint32_t block_size = 0;
            (void)read_u32(bytes, static_cast<std::size_t>(block_off),
                           page_rva);
            (void)read_u32(bytes, static_cast<std::size_t>(block_off) + 4,
                           block_size);
            if (block_size < 8) {
                out.error = LoadError::BadRelocation;
                out.detail = "a relocation block declares a size smaller "
                             "than its own header";
                return out;
            }
            ++module.relocation_blocks;

            const std::uint32_t entries = (block_size - 8) / 2;
            for (std::uint32_t i = 0; i < entries; ++i) {
                std::uint16_t entry = 0;
                const std::uint64_t entry_rva = cursor + 8 + 2ULL * i;
                std::uint64_t entry_off = 0;
                if (!image.to_file_offset(entry_rva, entry_off) ||
                    !read_u16(bytes, static_cast<std::size_t>(entry_off),
                              entry)) {
                    out.error = LoadError::BadRelocation;
                    out.detail = "a relocation entry is outside the file";
                    return out;
                }
                const std::uint16_t type = entry >> 12;
                const std::uint16_t offset = entry & 0x0FFFU;
                if (type == kRelBasedAbsolute) {
                    // Padding, not a relocation. Applying it would write
                    // zero over whatever is there.
                    continue;
                }
                const std::uint64_t rva = page_rva + offset;

                // Every relocation type, not just DIR64, and against the width
                // each one writes.
                //
                // The image's size is the bound available here: this pass runs
                // before anything is mapped, so there is no region to test
                // against and the arithmetic is all there is. The write pass
                // checks the map again, and against the region rather than the
                // image, because a relocation into a gap between sections
                // passes this test and has to be caught there.
                //
                // The width matters here for the same reason it matters there.
                // A HIGH relocates two bytes and a HIGHLOW four, and a check
                // that used 8 for all of them would refuse files it could
                // place; one that used 1 would admit a DIR64 whose last seven
                // bytes fall outside the image. `image_size < field_bytes` is
                // tested first so that the subtraction cannot wrap when the
                // image is smaller than the field, which is the case a file
                // with a four-byte SizeOfImage reaches on its first entry.
                const std::uint64_t field_bytes = relocation_width(type);
                if (image_size < field_bytes ||
                    rva > image_size - field_bytes) {
                    out.error = LoadError::BadRelocation;
                    out.detail = "a " + std::to_string(field_bytes * 8) +
                                 "-bit relocation points outside the image";
                    return out;
                }

                // HIGHADJ's adjustment is the next entry, and this entry
                // therefore covers two slots. Skip the second here so that
                // the walk below counts one relocation rather than two -- and
                // so that a block whose HIGHADJ is its last entry, with no
                // adjustment slot after it, is refused here, before anything
                // is mapped. That is the check this pass exists for; the
                // adjustment's *value* is the write pass's business, and
                // reading it here would mean holding a number this pass has
                // no use for.
                //
                // The adjustment is the entry's own 16 bits, not its offset
                // field: the linker spends a whole entry on a number that
                // does not fit in an entry's 12-bit offset, and the type
                // nibble of that second entry says nothing.
                if (type == kRelBasedHighAdj) {
                    if (i + 1 >= entries) {
                        out.error = LoadError::BadRelocation;
                        out.detail = "a HIGHADJ relocation is the last entry "
                                     "in its block and has no adjustment slot";
                        return out;
                    }
                    ++i;
                }

                switch (type) {
                case kRelBasedDir64:
                    module.relocations_applied += 1;
                    break;
                case kRelBasedHigh:
                case kRelBasedLow:
                case kRelBasedHighLow:
                case kRelBasedHighAdj:
                    // The 16- and 32-bit forms. They exist in 64-bit images
                    // for fields the linker knew would stay in the low 4 GiB,
                    // or -- for the 16-bit ones -- on the machines whose
                    // instructions held half an address each. A runtime that
                    // ignored them would leave those fields pointing at the
                    // old base.
                    module.relocations_applied += 1;
                    break;
                default:
                    out.error = LoadError::BadRelocation;
                    out.detail = "relocation type " +
                                 std::to_string(type) +
                                 " is not one this runtime applies";
                    return out;
                }
            }
            cursor += block_size;
        }
    }

    // ------------------------------------------------------------- mapping
    //
    // Reached only when every check above has held. From here on nothing
    // refuses except the address space itself reporting an overlap with a
    // region that was already there before this call, which is a fact about
    // the caller's space rather than about the file.

    // The whole image is recorded in one operation: the headers, then one
    // region per section, in that order.
    //
    // It is one operation and not a loop of record() calls because record()
    // commits as it goes, and this function's contract says a load that is
    // not ok leaves the space unchanged. A file whose fourth section
    // overlaps its first -- or overlaps a region the caller had already
    // mapped -- is refused at the fourth call, by which point the headers
    // and three sections are in the map. The fuzzer found exactly that: the
    // first sample it produced recorded the headers and then refused a
    // section, and the space kept the headers.
    //
    // record_batch() checks every candidate against the existing map and
    // against the others before inserting any of them, so the state after a
    // refusal is the state before the call.
    //
    // The headers go first because the order is what the failure message
    // names when it is the headers that could not be placed, and because a
    // reader of the file reaches them first.
    std::vector<AddressSpace::Candidate> batch;
    batch.reserve(placements.size() + 1);
    {
        // The whole header area is recorded rather than only the parsed
        // part, because a program can read the DOS stub and the section
        // table and a region that stopped at the parsed fields would report
        // a fault in a page that is really there.
        AddressSpace::Candidate h;
        h.base = base;
        h.size = headers_size;
        h.protection = PageProtection::ReadOnly;
        h.kind = RegionKind::Image;
        h.section = ".headers";
        h.section_index = 0;
        batch.push_back(std::move(h));
    }
    for (const Placement& p : placements) {
        AddressSpace::Candidate c;
        c.base = p.va;
        c.size = p.mem_size;
        c.protection = PageProtection::ReadOnly;
        // The order of these tests is Windows' own precedence: write-implies-
        // read and execute-implies-read, and a section that is both
        // executable and writable gets the combined value rather than one
        // of the two. Reading them in the other order produces a
        // read-execute section from a read-write-execute one.
        //
        // The value is computed once and used twice below -- once for the
        // recorded region and once for the final protection after the
        // placement -- because a load that recorded one protection and
        // applied another would be a map that lies about its own memory, and
        // the whole point of computing it from the section's flags is that
        // the two readings cannot disagree.
        const bool w = p.section->writable();
        const bool x = p.section->executable();
        if (w && x) {
            c.protection = PageProtection::ExecuteReadWrite;
        } else if (x) {
            c.protection = PageProtection::ExecuteRead;
        } else if (w) {
            c.protection = PageProtection::ReadWrite;
        }
        c.kind = RegionKind::Image;
        c.section = p.section->name;
        c.section_index = p.index;
        batch.push_back(std::move(c));
    }

    // The two modes diverge here, and the divergence is one line wide.
    //
    // Without a mapper the call is record_batch and nothing else, which is
    // the whole of what this function used to do. With one, the same
    // candidates go through map_batch, which maps and records as one
    // operation, and then the bytes are written.
    //
    // What is *not* different is that the plan above already ran. An image
    // that would be refused by the window check, by the overlap check, by
    // the relocation walk or by the entry-point check is refused before
    // either call, so adding a mapper cannot turn a refusal into a
    // placement. It can only add new failures of its own -- the kernel
    // refusing an address the plan accepted, which is what MappingRefused is
    // for.
    Mapper* placement = context.placement;

    if (placement == nullptr) {
        const auto rec = space.record_batch(batch);
        if (!rec.ok()) {
            // A conflict is a fact about the caller's space and not about
            // the file, which is why it is a different error from the ones
            // the plan above produces. The batch is all-or-nothing, so there
            // is nothing to undo here.
            out.error = LoadError::AddressConflict;
            out.detail = "the image could not be recorded: " +
                         std::string(status_name(rec.status));
            return out;
        }
    } else {
        // The same batch, through the mapper.
        //
        // Every region goes in as read-write, whatever the section's flags
        // say, and the flags are applied afterwards. The alternative --
        // mapping each section with its final protection -- cannot work:
        // a relocation routinely names an address in a read-only section,
        // because a read-only section is full of pointers to the image's own
        // functions and those pointers are exactly what a relocation
        // rewrites. A loader that mapped the final protections first would
        // fault on its own relocation pass, on a perfectly ordinary image.
        //
        // Windows avoids the problem by mapping the whole image committed
        // and read-write, writing the relocations, and then protecting each
        // section, and the order here is that order. The window in which a
        // read-only section is writable is the same window Windows has, and
        // it is why the final protect is a separate step that is checked
        // rather than assumed: an image that is placed and whose protection
        // was never applied is an image whose .text is writable, and a
        // runtime that reports success there is reporting something false.
        std::vector<Mapper::Candidate> to_map;
        to_map.reserve(batch.size());
        for (AddressSpace::Candidate& c : batch) {
            to_map.push_back(Mapper::Candidate{c.base, c.size,
                                                PageProtection::ReadWrite,
                                                c.kind, c.section,
                                                c.section_index});
        }

        const Result<std::uint64_t> mapped = placement->map_batch(to_map);
        if (!mapped.ok()) {
            // map_batch is all-or-nothing in both directions: it unmapped
            // everything it had mapped before reporting this, so there is
            // nothing to undo here and the space is as it was.
            out.error = (mapped.status == Status::ConflictingAddresses)
                            ? LoadError::AddressConflict
                            : LoadError::MappingRefused;
            out.detail = "the image could not be mapped: " +
                         std::string(status_name(mapped.status));
            if (placement->last_failure().error != 0) {
                out.detail += " (errno " +
                              std::to_string(placement->last_failure().error) +
                              ")";
            }
            return out;
        }
    }

    // The image is recorded in the space before the contents are placed, so
    // that the placement is a change to a map that already exists. A caller
    // that abandons the load between the two sees a map describing an image
    // with no bytes in it, which is a state a reader can recognise; the
    // alternative order leaves bytes at addresses the map does not mention.
    emit_note(context.events, "image mapped at " + hex_of(base) +
                                  " with " +
                                  std::to_string(placements.size()) +
                                  " sections");

    for (const Placement& p : placements) {
        const Region* r = space.find(p.va);
        if (r != nullptr) {
            emit_mapping(context.events, *r);
        }
    }

    // ------------------------------------------------------------- contents
    //
    // The file's bytes, into the memory. Below the record, above the
    // relocations, and below the IAT -- the order the header of this file
    // gives and the order the operations require: a relocation rewrites a
    // value that has to be in memory, and the IAT holds addresses that have
    // to be relocated too if the image moved.

    if (placement != nullptr) {
        // The headers.
        //
        // Bounded by both the file and the region, because the region's size
        // is the parsed header size and the file can be shorter -- the
        // loader already handles that case for sections by dropping the
        // uncovered tail, and the headers need the same treatment rather
        // than a memcpy of a length the file may not have.
        {
            const Region* h = space.find(base);
            if (h == nullptr) {
                out.error = LoadError::AddressConflict;
                out.detail = "the header region was not recorded";
                rollback_placement(*placement, batch);
                return out;
            }
            const std::uint64_t copy =
                (headers_size < static_cast<std::uint64_t>(bytes.size()))
                    ? headers_size
                    : static_cast<std::uint64_t>(bytes.size());
            std::memcpy(reinterpret_cast<void*>(base), bytes.data(),
                        static_cast<std::size_t>(copy));
            // The part of the header region the file does not cover. The
            // mapping is anonymous and the kernel zeroes anonymous pages, so
            // this is already zero and the memset is not needed -- which is
            // worth stating because a reader looking for the zero fill will
            // not find one here, and the reason it is safe is that this
            // runtime maps anonymous memory and nothing else.
        }

        // The sections.
        for (const Placement& p : placements) {
            if (p.file_size != 0) {
                // Bounded by construction: the plan clamped file_size to
                // bytes.size() - raw_offset, so the read below is in range
                // by arithmetic rather than by a check here. The subtraction
                // is the reason the plan used that form.
                if (p.file_off > static_cast<std::uint64_t>(bytes.size()) ||
                    p.file_size >
                        static_cast<std::uint64_t>(bytes.size()) - p.file_off) {
                    out.error = LoadError::SectionOutOfRange;
                    out.detail = "section " + p.section->name +
                                 " names bytes outside the file";
                    rollback_placement(*placement, batch);
                    return out;
                }
                std::memcpy(reinterpret_cast<void*>(p.va),
                            bytes.data() + static_cast<std::size_t>(p.file_off),
                            static_cast<std::size_t>(p.file_size));
            }
            // The zero tail: a section whose virtual extent exceeds its raw
            // size. The mapping is anonymous and zero, so again there is
            // nothing to do, and the reason is the same one as above.
        }
    }

    // The delta is base minus preferred base, as a byte offset.
    //
    // It is computed in unsigned arithmetic and reinterpreted, not by casting
    // each address to int64_t and subtracting. Both operands are uint64_t
    // taken from a caller and from the file, and the file's preferred base
    // can be any 64-bit value; the cast of such a value to int64_t is
    // implementation-defined in the negative half, and the subtraction of the
    // two is signed overflow -- undefined behaviour, which UBSan reported on
    // the loader fuzz harness. Unsigned subtraction of two 64-bit values is
    // total: it wraps modulo 2^64, and the two's-complement reinterpretation
    // of that result is precisely the signed byte offset. No branch is
    // needed and none is UB.
    const std::uint64_t delta = base - image.image_base();

    if (needs_relocation && placement != nullptr) {
        // The second walk over the relocations, which writes them.
        //
        // The walk above is the one that can refuse, and it runs before
        // anything is mapped, so a file with a bad relocation never reaches
        // this point. This one therefore does not validate the block
        // structure -- every bound it would check was checked already, from
        // the same bytes, moments ago -- and does only the work that needs
        // memory to exist. Splitting it this way is what keeps the contract
        // that a refused load leaves nothing behind: all of the refusals are
        // in the first walk and none are in this one, so this walk cannot
        // fail halfway and leave a half-relocated image mapped.
        //
        // The one thing it does check is that each entry's address is
        // covered by a region, because the plan's check is against the
        // image's size and the image's size is not the set of addresses that
        // exist: a section's virtual extent is rounded up to a page, the
        // gap between two sections is not mapped at all, and a relocation
        // naming that gap is a file the plan accepted and this walk cannot
        // satisfy. That is what RelocationNotWritable is for.
        const std::uint64_t reloc_end = image.reloc_rva() + image.reloc_size();
        std::uint64_t walk = image.reloc_rva();

        while (walk + 8 <= reloc_end) {
            std::uint64_t block_off = 0;
            if (!image.to_file_offset(walk, block_off) ||
                block_off + 8 > bytes.size()) {
                // Unreachable given the walk above held on the same bytes.
                // Bounded anyway, because "unreachable" is a claim about the
                // past and this is a loop over a file.
                out.error = LoadError::BadRelocation;
                out.detail = "a relocation block header is outside the file";
                rollback_placement(*placement, batch);
                return out;
            }
            std::uint32_t page_rva = 0;
            std::uint32_t block_size = 0;
            (void)read_u32(bytes, static_cast<std::size_t>(block_off),
                           page_rva);
            (void)read_u32(bytes, static_cast<std::size_t>(block_off) + 4,
                           block_size);
            if (block_size < 8) {
                out.error = LoadError::BadRelocation;
                out.detail = "a relocation block declares a size smaller "
                             "than its own header";
                rollback_placement(*placement, batch);
                return out;
            }

            const std::uint32_t entries = (block_size - 8) / 2;
            for (std::uint32_t i = 0; i < entries; ++i) {
                std::uint16_t entry = 0;
                const std::uint64_t entry_rva = walk + 8 + 2ULL * i;
                std::uint64_t entry_off = 0;
                if (!image.to_file_offset(entry_rva, entry_off) ||
                    !read_u16(bytes, static_cast<std::size_t>(entry_off),
                              entry)) {
                    out.error = LoadError::BadRelocation;
                    out.detail = "a relocation entry is outside the file";
                    rollback_placement(*placement, batch);
                    return out;
                }
                const std::uint16_t type = entry >> 12;
                const std::uint16_t offset = entry & 0x0FFFU;
                if (type == kRelBasedAbsolute) {
                    continue;
                }

                // The same two-slot walk as the pass above, and for the same
                // reason: the adjustment is the next entry, and reading it
                // here rather than in the plan would mean reading the file a
                // second time for a value the plan already had in hand. The
                // plan validated that the slot exists, so this cannot fail --
                // and it is still written as a read that reports failure,
                // because a loop over a file bounded by a claim about a past
                // walk is the shape that turns a wrong claim into a fault.
                std::int16_t adjustment = 0;
                if (type == kRelBasedHighAdj) {
                    std::uint64_t adj_off = 0;
                    if (!image.to_file_offset(walk + 8 + 2ULL * (i + 1),
                                             adj_off) ||
                        !read_u16(bytes, static_cast<std::size_t>(adj_off),
                                  entry)) {
                        out.error = LoadError::BadRelocation;
                        out.detail = "a HIGHADJ adjustment slot is outside "
                                     "the file";
                        rollback_placement(*placement, batch);
                        return out;
                    }
                    adjustment = static_cast<std::int16_t>(entry);
                    ++i;
                }

                const std::uint64_t rva = page_rva + offset;
                const std::uint64_t va = base + rva;

                // Coverage and writability, checked against the map rather
                // than against the image's arithmetic.
                //
                // The region's own containment test is the authority, and a
                // relocation into the gap between two sections is the case it
                // exists for: the plan's check is against SizeOfImage, and
                // the image's size includes gaps that were never mapped.
                //
                // The containment test is against the *field*, not against its
                // first byte. `space.find(va)` would answer the narrower
                // question and let a DIR64 at the last mapped byte through,
                // which writes seven bytes past the region. `region_for_write`
                // is the check that takes the width.
                //
                // The writability half cannot fail here -- every region went
                // in as read-write and nothing has protected any of them yet
                // -- and it is checked anyway, because the check costs one
                // comparison and the thing it guards is a write to a page
                // that would fault. A loader that arrived here with a
                // read-only region in its own map has a placement bug, and
                // it should report that rather than fault inside apply_one.
                const std::uint64_t field_bytes = relocation_width(type);
                const Region* target = region_for_write(space, va, field_bytes);
                if (target == nullptr) {
                    out.error = LoadError::RelocationNotWritable;
                    out.detail = "a " + std::to_string(field_bytes * 8) +
                                 "-bit relocation at RVA " + hex_of(rva) +
                                 " names an address the image does not cover "
                                 "for its whole width";
                    rollback_placement(*placement, batch);
                    return out;
                }
                if ((protection_to_prot(target->protection) & PROT_WRITE) ==
                    0) {
                    out.error = LoadError::RelocationNotWritable;
                    out.detail = "a relocation at RVA " + hex_of(rva) +
                                 " names read-only memory";
                    rollback_placement(*placement, batch);
                    return out;
                }
                const RelocFailure applied =
                    apply_one(va, type, delta, adjustment);
                if (applied.failed) {
                    out.error = LoadError::BadRelocation;
                    out.detail = applied.what;
                    rollback_placement(*placement, batch);
                    return out;
                }
            }
            walk += block_size;
        }
    }

    if (needs_relocation) {
        if (context.events != nullptr) {
            auto& e = context.events->begin(obs::EventKind::Note);
            e.add("text", std::string_view{"relocations applied"});
            e.add_hex("delta", delta);
            e.add("blocks", static_cast<std::uint64_t>(module.relocation_blocks));
            e.add("entries", module.relocations_applied);
            e.add("written", placement != nullptr);
            context.events->commit();
        }
    }
    // ------------------------------------------------------ import lookup

    // The import directory.
    //
    // Each descriptor names a DLL, an array of name thunks, and an array of
    // address thunks the loader fills in. The two arrays start out holding
    // the same values -- an RVA to a hint/name entry -- and it is the
    // second one that the program reads at runtime. Keeping them distinct
    // is what makes a second load of the same image idempotent: writing
    // resolved addresses into the name array would make the next reader see
    // an address where it expected a name.
    const auto& sections = image.sections();
    std::uint64_t import_rva = 0;
    std::uint32_t import_size = 0;
    {
        // The directory array is read from the raw optional header, which
        // the parser exposes as a size but not as an offset. The offset is
        // the fixed prefix's length, which differs between the two magic
        // values, so the pointer arithmetic is done here where the constant
        // that names it lives.
        const std::size_t dirs_off =
            image.is_pe32_plus() ? kDirsOffset64 : kDirsOffset32;
        const std::size_t import_entry =
            dirs_off + 8 * static_cast<std::size_t>(kDirImport);
        std::uint64_t opt_off = 0;
        // The optional header's file offset is the COFF header's plus its
        // size, and the parser records the latter. Recovering the former
        // needs e_lfanew, which is at 0x3C of the DOS header, so it is read
        // from the file rather than guessed.
        std::uint32_t lfanew = 0;
        if (read_u32(bytes, 0x3C, lfanew)) {
            opt_off = static_cast<std::uint64_t>(lfanew) + 4U + 20U;
        }
        // The order is an RVA and then a size, which is the opposite of
        // what the field names suggest to a reader who is thinking of the
        // table as (size, address). Reading them the other way round
        // produces an RVA that is really the table's size -- a small
        // number -- and a walk at that address finds zeros and reports no
        // imports, so the file loads and the report is silently empty.
        std::uint32_t rva32 = 0;
        if (opt_off != 0 &&
            read_u32(bytes, static_cast<std::size_t>(opt_off + import_entry),
                     rva32) &&
            read_u32(bytes,
                     static_cast<std::size_t>(opt_off + import_entry + 4),
                     import_size)) {
            import_rva = rva32;
        }
    }

    if (import_rva != 0 && import_size != 0) {
        const std::uint64_t import_end = import_rva + import_size;
        std::uint64_t desc_rva = import_rva;
        // The descriptor array is terminated by an all-zero entry, and the
        // directory's own size is the other bound. Both are honoured: a
        // directory that claims more descriptors than it has is a file that
        // would otherwise be walked into whatever follows.
        while (desc_rva + 20 <= import_end) {
            std::uint64_t desc_off = 0;
            if (!image.to_file_offset(desc_rva, desc_off) ||
                desc_off + 20 > bytes.size()) {
                break;
            }
            std::uint32_t name_rva = 0;
            std::uint32_t iat_rva = 0;
            std::uint32_t thunk_rva = 0;
            (void)read_u32(bytes, static_cast<std::size_t>(desc_off + 12),
                           name_rva);
            (void)read_u32(bytes, static_cast<std::size_t>(desc_off + 16),
                           iat_rva);
            (void)read_u32(bytes, static_cast<std::size_t>(desc_off), thunk_rva);

            if (name_rva == 0 && iat_rva == 0 && thunk_rva == 0) {
                break;
            }

            std::string dll;
            if (!read_rva_name(image, bytes, name_rva, dll)) {
                break;
            }

            // The name thunk array is the one that still holds names. It is
            // absent in an image that was already bound, in which case the
            // IAT array holds the names -- a real and legal layout.
            std::uint64_t names_cursor = thunk_rva != 0 ? thunk_rva : iat_rva;
            std::uint64_t iat_cursor = iat_rva != 0 ? iat_rva : thunk_rva;

            // A bound, because a malformed thunk array has no terminator
            // and the walk would run into the next section. The limit is
            // the size of the image in entries; an image with more imports
            // than it has bytes is not an image.
            const std::uint64_t max_entries = image_size / 8;
            for (std::uint64_t i = 0; i < max_entries; ++i) {
                std::uint64_t entry_off = 0;
                if (!image.to_file_offset(names_cursor + 8 * i,
                                          entry_off) ||
                    entry_off + 8 > bytes.size()) {
                    break;
                }
                std::uint64_t value = 0;
                (void)read_u64(bytes, static_cast<std::size_t>(entry_off),
                               value);
                if (value == 0) {
                    break;
                }

                ResolvedImport imp;
                imp.dll = dll;
                imp.iat_va = base + iat_cursor + 8 * i;

                // The IAT slot has to be inside something this load mapped,
                // and this is the check the loader did not have.
                //
                // The address above is computed from the file's RVA, and the
                // only thing bounded so far is that the *name* array could be
                // read. A malformed directory -- and the corpus has one --
                // therefore produces an IAT at an address nothing covers, and
                // the load reports success while handing the layer above a
                // module that will store its imports into unmapped memory. The
                // program faults on the store, before its first instruction,
                // which is the same shape of failure as an unmapped entry
                // point and is decided here for the same reason: this is the
                // only layer holding both the address and the map.
                //
                // What counts as covered is the batch that was just recorded,
                // not the section list alone. The headers are a mapped
                // region and an import table is allowed to live in them --
                // the parser resolves an RVA below SizeOfHeaders as a file
                // offset precisely because the format puts things there. A
                // check that walked the sections alone would refuse images
                // whose imports are real, and the unit tests hold exactly
                // such an image.
                //
                // An entry that fails this is skipped rather than refused.
                // The failure is local to one import: the other descriptors
                // in the array are real, and a load that refused the whole
                // image because one thunk pointed outside it would refuse
                // images that run. What the caller needs is the ones that
                // are real, with the ones that are not left out.
                bool slot_mapped = imp.iat_va >= base &&
                                   imp.iat_va - base < headers_size;
                for (const Placement& p : placements) {
                    if (slot_mapped) {
                        break;
                    }
                    if (imp.iat_va >= p.va &&
                        imp.iat_va - p.va < p.mem_size) {
                        slot_mapped = true;
                    }
                }
                if (!slot_mapped) {
                    continue;
                }

                constexpr std::uint64_t kOrdinalFlag = 0x8000000000000000ULL;
                if ((value & kOrdinalFlag) != 0) {
                    imp.by_ordinal = true;
                    imp.name = "#" + std::to_string(value & 0xFFFFU);
                } else if (!read_rva_name(image, bytes, value + 2, imp.name)) {
                    // A hint/name entry is a 16-bit hint followed by the
                    // name, so the name starts two bytes in. A name that
                    // will not read ends the array rather than the load:
                    // the entries before it are real imports and dropping
                    // them would understate what the image needs.
                    break;
                }

                if (context.resolve != nullptr) {
                    std::uint16_t ordinal = 0;
                    if (imp.by_ordinal) {
                        ordinal = static_cast<std::uint16_t>(
                            value & 0xFFFFU);
                    }
                    imp.target_va = context.resolve(
                        context.resolver_state, dll, imp.name, ordinal,
                        imp.by_ordinal);
                    imp.resolved = imp.target_va != 0;
                }

                // The IAT store.
                //
                // Written after the relocations and not before, and the order
                // is the whole reason this walk is where it is. The IAT of a
                // relocated image holds RVAs until the relocation pass runs
                // and absolute addresses after it, so an IAT written before
                // the relocations would be rewritten by them into
                // address+delta -- a value that is the address of an import
                // plus a displacement, which points into the middle of
                // whatever it names. The three stores therefore run in the
                // order the header of this file gives: bytes, then
                // relocations, then the IAT.
                //
                // Only when there was a resolver. Without one the slot keeps
                // the RVA the file held, which is what `occ check` wants to
                // see and what a caller that resolved nothing can act on: a
                // program that reads an unresolved IAT reads a small
                // number and faults, where a slot holding zero is a program
                // that reads null and calls it -- which is a different
                // failure with a different cause, and hiding it behind a
                // resolved-looking zero is the thing this avoids.
                if (placement != nullptr && imp.resolved) {
                    // The slot was checked for coverage above, which is the
                    // check that matters: this is a raw store at an address
                    // computed from a file's RVA, and the coverage test is
                    // what makes it safe. The test above walked placements
                    // rather than the space, and the space now holds
                    // exactly those regions plus the headers.
                    // The slot is eight bytes and the test is against eight.
                    // `find(imp.iat_va)` would answer for the first byte, and
                    // a directory whose LastThunk lands three bytes before the
                    // end of a section would then be written past it.
                    const Region* slot = region_for_write(
                        space, imp.iat_va, sizeof(std::uint64_t));
                    if (slot == nullptr) {
                        out.error = LoadError::RelocationNotWritable;
                        out.detail = "the IAT slot for " + dll + "!" +
                                     imp.name +
                                     " has no eight bytes in a region this "
                                     "load made";
                        rollback_placement(*placement, batch);
                        return out;
                    }
                    if ((protection_to_prot(slot->protection) & PROT_WRITE) ==
                        0) {
                        out.error = LoadError::RelocationNotWritable;
                        out.detail = "the IAT slot for " + dll + "!" +
                                     imp.name + " is read-only";
                        rollback_placement(*placement, batch);
                        return out;
                    }
                    store_u64(imp.iat_va, imp.target_va);
                }

                if (context.events != nullptr) {
                    auto& e = context.events->begin(obs::EventKind::Import);
                    e.add("dll", dll);
                    e.add("name", imp.name);
                    e.add_hex("iat", imp.iat_va);
                    e.add_hex("target", imp.target_va);
                    e.add("resolved", imp.resolved);
                    e.add("by_ordinal", imp.by_ordinal);
                    context.events->commit();
                }

                module.imports.push_back(std::move(imp));
            }

            desc_rva += 20;
        }
    }

    // ----------------------------------------------------------------- TLS
    //
    // The directory is read here and the slot is handed out here, and the
    // split between the two is Wine's and worth keeping: `alloc_tls_slot`
    // runs at load time because the index has to be in the image before any
    // thread can read it, and the per-thread copy happens at thread creation
    // because a thread's block belongs to the thread. Doing either at the
    // wrong time is a specific and confusing failure -- an image whose index
    // is written when the first thread attaches is an image whose second
    // thread reads a slot number that was never written.
    //
    // The read is a decision, so it happens whether or not a mapper was
    // given, exactly like the import walk above. What a mapper adds is the
    // one store: the index is written into the image, and there is nowhere
    // to write it without memory.
    // A table for the case where the caller supplied none. A load with no
    // table still reads the directory and still reports it, and the slot it
    // hands out is a slot in a table that goes out of scope -- which is the
    // right outcome, because a slot number written into an image with no
    // process behind it is a number nothing will ever resolve. The
    // alternative, a file-scope table, would be a slot shared by every
    // process in the address space, which is the bug Wine's global
    // `tls_dirs` is.
    //
    // Declared out here rather than inside the block because the final
    // protections below hand a slot back on a TLS refusal, and a slot can
    // only be given back to the table it came from.
    TlsTable detached;
    TlsTable& table = context.tls != nullptr ? *context.tls : detached;
    {
        TlsModule found;
        TlsResult tls =
            load_tls(image, bytes, base, space, context, table, &found);
        if (!tls.ok) {
            // A TLS directory this runtime cannot make sense of refuses the
            // load rather than being ignored, and the refusal names the
            // field. An image whose callbacks cannot be found is an image
            // whose thread entry points at nothing; loading it and saying
            // so later is worse than saying so here, where the file is still
            // the thing being read.
            //
            // The rollback tells the two placements apart rather than
            // guarding on the mapper, because "nothing was mapped" is not the
            // same statement as "nothing was recorded". A load with no mapper
            // still ran record_batch, so it still put the image in the
            // ledger, and a refusal that undid only the kernel mapping would
            // leave the space describing an image with no bytes in it. The
            // fuzzer found this: its invariant is that a refused load leaves
            // the space as it was, and the TLS directory was the first thing
            // in the loader that could refuse *after* the record.
            //
            // A null mapper was never the reason to skip the undo, so nothing
            // is dereferenced here that might be null.
            out.error = LoadError::TlsRefused;
            out.detail = std::move(tls.detail);
            rollback(space, placement, batch);
            return out;
        }
        module.tls = found;
        module.has_tls = found.template_va != 0 || found.zero_fill != 0 ||
                         found.callbacks_va != 0;
    }

    // --------------------------------------------------- final protections
    //
    // The last step of a placement, and the one that makes the image what the
    // file said it is.
    //
    // Everything above ran with every region writable, because a relocation
    // can name an address in any section including a read-only one, and
    // because the IAT is frequently in a section the linker marked
    // read-only. This step is what takes that permission away, and it is
    // separate rather than folded into the mapping for the reason stated at
    // the mapping: a read-only section full of pointers into the image is
    // ordinary, and a loader that applied the final protections first could
    // not write its own relocations.
    //
    // Windows has the same window and closes it the same way. The window is
    // why the result is checked rather than assumed: an image that is placed
    // and never protected is an image whose .text is writable, and a loader
    // that reported success there is reporting something false. The
    // check is the only thing between "the placement finished" and "the
    // image is loaded".
    if (placement != nullptr) {
        // Headers first, then the sections in the order they were placed.
        // The order is the order a failure message names them in, and the
        // headers are read-only in every image so this is the first place a
        // refusal could occur.
        for (const AddressSpace::Candidate& c : batch) {
            const Result<std::uint32_t> applied =
                placement->protect(c.base, c.protection);
            if (!applied.ok()) {
                out.error = LoadError::MappingRefused;
                out.detail = "the protection of " + c.section + " at 0x" +
                             hex_of(c.base) + " could not be set: " +
                             std::string(status_name(applied.status));
                rollback_placement(*placement, batch);
                return out;
            }
            if (context.events != nullptr) {
                const Region* r = space.find(c.base);
                if (r != nullptr) {
                    emit_mapping(context.events, *r);
                }
            }
        }
        // The counter the caller reads is now true of memory rather than of
        // a plan: every entry was written.
        for (ResolvedImport& imp : module.imports) {
            if (!imp.resolved) {
                continue;
            }
            imp.iat_written = true;
        }

        // The TLS slot number goes in last, and it goes in here because this
        // is the first moment the index field's writability is a fact rather
        // than a temporary. See `commit_tls_index`.
        if (module.has_tls) {
            const TlsResult tls = commit_tls_index(module.tls, space, table);
            if (!tls.ok) {
                out.error = LoadError::TlsRefused;
                out.detail = std::move(tls.detail);
                // The placement is already protected, and the undo does not
                // care about that: it is a munmap of what this call mapped.
                rollback_placement(*placement, batch);
                return out;
            }
        }
    }

    // -------------------------------------------------------------- result

    (void)sections;

    out.ok = true;
    out.error = LoadError::None;
    out.module = std::move(module);
    return out;
}

// ------------------------------------------------------- placing with retry

std::uint64_t choose_base_below(void*, const parser::PeImage& image,
                                std::uint64_t failed_base,
                                std::uint32_t) noexcept {
    // The state and the attempt count are named in the header's declaration
    // and left unnamed here: a deterministic scan carries none and has no
    // use for either, since the only thing that stops it is the window.

    // The lowest base this policy will offer.
    //
    // A base is legal when it is at or above the window's floor, and the
    // lowest such base is the window's floor itself -- `kUserMin` already is
    // a whole number of granularies. The image's size does not enter into it.
    // The floor answers "how far down may I step", and the answer does not
    // depend on how big the thing being stepped down towards is; what the
    // size decides is whether the image fits *at all*, which is the second
    // half of this check.
    //
    // This used to be `kUserMin + round_up(size - 1, kGranularity)`, on the
    // reasoning that the floor is "the first base where base + size still
    // fits". That formula is not that base. It adds the image's own size to
    // the window floor, which puts the floor at least one granularity too
    // high for every image smaller than a granularity -- and it did so
    // silently, because a scan that stops one step early still returns a
    // plausible-looking answer. The cost was a policy that reported "no base
    // was free" about a space with a free base in it: the loop stepped down
    // to kUserMin, was refused by this comparison, and told the caller there
    // was nowhere left to try. A case in tests/test_placement.cpp found it,
    // and found it by computing the floor itself rather than by asking this
    // function -- the two disagreed by exactly one granularity.
    const std::uint64_t size = image.image_size();
    if (size == 0) {
        return 0;
    }
    const std::uint64_t lowest =
        AddressSpace::round_up(AddressSpace::kUserMin, AddressSpace::kGranularity);

    // Whether the image fits at that base. It does not for an image larger
    // than the window, and then there is nothing for this policy to offer at
    // any base -- every answer would be a base the loader refuses. Saying so
    // once here is cheaper than handing out sixty-four of them.
    if (size > AddressSpace::kUserMax - lowest) {
        return 0;
    }

    // The scan steps down by the granularity.
    //
    // Two bounds, and the second one is not decoration. `kUserMin` is the
    // bottom of the window a base has to be in, and the subtraction below
    // wraps: a base one granularity under it produces a number at the very
    // top of the address space, and the loop would then walk *up* through
    // the whole window handing out bases it had already tried. The guard is
    // on the *base* rather than on the result, because the two forms agree
    // everywhere except at the bottom -- `kUserMin` is exactly one
    // granularity, so the unguarded step at the floor lands on zero, which
    // is harmless, and only the step below it wraps.
    //
    // The upper guard is the other half of the same problem from the other
    // direction, and it was missing until a case in tests/test_placement.cpp
    // named a base below the window. A caller is entitled to name any
    // address at all, including one this runtime would never have produced,
    // and `failed_base` here is whatever the previous answer was. Once a
    // single unguarded step produces a value above `kUserMax`, every
    // subsequent step stays above it -- the subtraction makes the number
    // smaller, but "smaller" is still astronomically large -- and the policy
    // answered with 0xffffffffffc00000, a base the loader would then try to
    // map and fail on, having spent an attempt to learn what one comparison
    // could have said. A scan that cannot continue says so, whatever the
    // reason.
    if (failed_base < AddressSpace::kUserMin + AddressSpace::kGranularity ||
        failed_base > AddressSpace::kUserMax) {
        return 0;
    }
    const std::uint64_t next = failed_base - AddressSpace::kGranularity;

    if (next < lowest) {
        return 0;
    }
    return next;
}

LoadResult load_image_retrying(const parser::PeImage& image, ByteSpan bytes,
                               std::uint64_t preferred_base,
                               AddressSpace& space,
                               const LoadContext& context,
                               BaseRetry* report) noexcept {
    LoadResult out;
    BaseRetry local{};

    // The attempt cap. It exists so that a caller with a pathological space
    // gets an answer rather than a long wait, and 64 is far above any real
    // process: an image whose preferred base is taken is placed within two
    // or three tries, because the space above a base is not usually full.
    // The number is a constant rather than a field because a caller that
    // wants a different one wants a different policy, and `BaseChooser` is
    // how a caller supplies one.
    constexpr std::uint32_t kMaxAttempts = 64;

    std::uint64_t base = preferred_base;
    std::uint32_t attempts = 0;
    const BaseChooser choose =
        context.base_chooser != nullptr ? context.base_chooser
                                        : ::occ::runtime::choose_base_below;

    while (true) {
        ++attempts;
        const std::uint64_t tried_base =
            base != 0 ? base : image.image_base();
        local.tried.push_back(tried_base);

        out = load_image(image, bytes, base, space, context);

        if (out.ok) {
            local.error = LoadError::None;
            local.detail.clear();
            local.attempts = attempts;
            if (report != nullptr) {
                *report = std::move(local);
            }
            return out;
        }

        // Only a placement conflict is retried. Everything else is a fact
        // about the file or about this runtime, and no other base would
        // change it -- a bad relocation is bad at every address, and an
        // image this machine does not execute is not going to be executed by
        // moving it. Retrying them would replace a refusal that names the
        // problem with a refusal that names the wrong one.
        if (out.error != LoadError::AddressConflict) {
            local.error = out.error;
            local.detail = std::move(out.detail);
            local.attempts = attempts;
            if (report != nullptr) {
                *report = std::move(local);
            }
            return out;
        }

        if (attempts >= kMaxAttempts) {
            // The cap is reached rather than the space being full, and the
            // message says which, because "it tried 64 addresses" and "there
            // was nowhere to put it" call for different responses from the
            // person reading them.
            local.error = out.error;
            local.detail = "the image was still in the way after " +
                           std::to_string(attempts) + " bases";
            local.attempts = attempts;
            if (report != nullptr) {
                *report = std::move(local);
            }
            return out;
        }

        // The next base. A chooser that returns zero has run out, and that
        // is a fact about the space rather than about the image, so the
        // error stays AddressConflict and the detail says the search ended.
        //
        // It says so *in addition to* what the last attempt said, rather
        // than instead of it. Substituting the attempt's own detail here --
        // which is what an earlier version did, falling back to a sentence
        // about the search only when the attempt had nothing to say -- is
        // how a caller ends up reading "that address is taken" as the whole
        // story when the truth is "I have nowhere left to try", and those
        // two call for opposite responses: one looks for the module that
        // took the address, the other for a bigger space. An earlier
        // version of this file had the same defect in the form of four
        // details that spelled an address in decimal after a "0x".
        const std::uint64_t next =
            choose(context.base_chooser_state, image, tried_base, attempts);
        if (next == 0) {
            local.error = out.error;
            local.detail = "no base was free for the image";
            if (!out.detail.empty()) {
                local.detail += ": ";
                local.detail += out.detail;
            }
            local.attempts = attempts;
            if (report != nullptr) {
                *report = std::move(local);
            }
            return out;
        }

        // A chooser that returns a base that was already tried would spin.
        // The cap above would stop it, but the caller would get a report
        // saying it tried 64 addresses when it tried two, and the report is
        // the thing a person reads to decide what went wrong. Checked
        // against the bases actually used, not against a count, because a
        // chooser is free to skip and a count would refuse a legitimate
        // scan.
        bool already = false;
        for (const std::uint64_t b : local.tried) {
            if (b == next) {
                already = true;
                break;
            }
        }
        if (already) {
            local.error = out.error;
            local.detail = "the base chooser returned " +
                           hex_of(next) +
                           ", which had already been tried";
            local.attempts = attempts;
            if (report != nullptr) {
                *report = std::move(local);
            }
            return out;
        }

        base = next;
    }
}

// ------------------------------------------------------------------- TLS
//
// The reference throughout is Wine's `alloc_tls_slot`,
// `free_tls_slot` and `call_tls_callbacks` in `dlls/ntdll/loader.c`, read
// rather than copied. The shape is the format's; what follows is where this
// runtime differs and why.
//
// The one thing that has to be right -- and that a from-the-file
// implementation gets wrong in a way every bounds check agrees with -- is
// that the directory's four address fields are read out of the *mapped*
// image. See the section on TLS in loader.h for the whole argument; the short
// version is that they are pointers, the relocation pass has rewritten them,
// and the file still holds the addresses the image was linked at.

const char* tls_error_name(TlsError e) noexcept {
    switch (e) {
    case TlsError::None: return "none";
    case TlsError::MalformedDirectory: return "malformed_directory";
    case TlsError::TooLarge: return "too_large";
    case TlsError::CallbackFailed: return "callback_failed";
    case TlsError::OutOfMemory: return "out_of_memory";
    }
    return "unknown";
}

const char* tls_reason_name(TlsReason r) noexcept {
    switch (r) {
    case TlsReason::ProcessDetach: return "process_detach";
    case TlsReason::ThreadAttach: return "thread_attach";
    case TlsReason::ThreadDetach: return "thread_detach";
    case TlsReason::ProcessAttach: return "process_attach";
    }
    return "unknown";
}

// The directory, as a structure.
//
// Nine DWORDs on PE32+, five on PE32. The difference is not cosmetic and the
// shorter form is not a subset: the 32-bit structure has no
// `AddressOfCallBacks` field at all, which is to say a PE32 module cannot
// have TLS callbacks, and reading a field that is not there is how a 32-bit
// image would end up with a callback list full of whatever followed it in
// the structure.
//
// Returned as a plain value rather than filled in place, so that a
// half-read directory is never the caller's to look at.
struct RawTlsDirectory {
    std::uint32_t start_raw = 0;
    std::uint32_t end_raw = 0;
    std::uint32_t index_va = 0;
    std::uint32_t callbacks_va = 0;
    std::uint32_t zero_fill = 0;
    std::uint32_t characteristics = 0;
    bool have_callbacks_field = false;
};

// Where the directory is, and whether the file carries one.
//
// The RVA comes from the optional header's data directory, which is an RVA
// in every case and is not relocated -- the directory array is part of the
// headers and describes the file, not the mapping. Only the directory's
// *contents* are addresses that relocation touches.
[[nodiscard]] TlsResult find_tls_directory(const parser::PeImage& image,
                                           ByteSpan bytes,
                                           std::uint32_t& rva_out) noexcept {
    rva_out = 0;
    std::uint32_t lfanew = 0;
    if (!read_u32(bytes, 0x3C, lfanew)) {
        // No e_lfanew means no optional header, so no directory array. That
        // is a parse failure the caller has already refused the file for, and
        // it is reported as a TLS refusal rather than a crash because this
        // function is reachable from `occ check` on any file at all.
        return TlsResult{false, TlsError::MalformedDirectory,
                         "the file has no e_lfanew, so it has no TLS "
                         "directory to read"};
    }
    const std::size_t dirs_off = image.is_pe32_plus() ? kDirsOffset64
                                                      : kDirsOffset32;
    const std::size_t dir_at =
        static_cast<std::size_t>(lfanew) + 4U + 20U + dirs_off +
        8 * static_cast<std::size_t>(kDirTls);
    if (!read_u32(bytes, dir_at, rva_out)) {
        return TlsResult{false, TlsError::MalformedDirectory,
                         "the data directory array stops before the TLS "
                         "entry at " + hex_of(dir_at)};
    }
    return TlsResult{true, TlsError::None, {}};
}

// Reads a directory out of the file, for the case where there is no mapping.
//
// This is the `occ check` path and the only one that reads the file, and it
// is correct there for a reason that is worth stating because it is not
// generally true: an image that was never mapped was never relocated, so the
// file's addresses are the addresses the module has. The moment a module is
// placed anywhere but its linked base, this function is the wrong one, which
// is why `load_tls` prefers the space whenever there is one.
[[nodiscard]] TlsResult read_tls_directory_from_file(const parser::PeImage& image,
                                                     ByteSpan bytes,
                                                     std::uint32_t rva,
                                                     RawTlsDirectory& out) noexcept {
    std::uint64_t off = 0;
    if (!image.to_file_offset(rva, off)) {
        return TlsResult{false, TlsError::MalformedDirectory,
                         "the TLS directory at RVA " + hex_of(rva) +
                             " is outside the file"};
    }
    const std::size_t at = static_cast<std::size_t>(off);
    if (!read_u32(bytes, at, out.start_raw) ||
        !read_u32(bytes, at + 4, out.end_raw) ||
        !read_u32(bytes, at + 8, out.index_va) ||
        !read_u32(bytes, at + 12, out.zero_fill)) {
        return TlsResult{false, TlsError::MalformedDirectory,
                         "the TLS directory at RVA " + hex_of(rva) +
                             " is truncated in the file"};
    }
    // Characteristics is the fifth field on both forms and is read for the
    // same reason Windows reads it: not to act on it, but so that a report
    // can name the whole structure. It is deliberately not branched on -- the
    // alignment bits are the loader's business rather than the program's,
    // and a module that declares unusual ones still has a template that has
    // to be copied.
    (void)read_u32(bytes, at + 16, out.characteristics);

    if (image.is_pe32_plus()) {
        out.have_callbacks_field = true;
        if (!read_u32(bytes, at + 20, out.callbacks_va)) {
            return TlsResult{false, TlsError::MalformedDirectory,
                             "the TLS directory at RVA " + hex_of(rva) +
                                 " is truncated inside the callback field"};
        }
    }
    return TlsResult{true, TlsError::None, {}};
}

// Reads a directory out of the mapped image.
//
// Two things are different from the file read and both matter. The values
// are the *relocated* ones, which is the whole reason this function exists;
// and each field is checked against the space as it is read, so a directory
// pointing at an address no region covers is refused by name instead of
// producing a template address that faults on first use.
//
// The width is 32 bits on both PE32 and PE32+ for a reason the format makes
// unavoidable: these are the fields as the file stores them, and a PE32+
// module's TLS template above 4 GiB is a module whose directory cannot
// describe it. That is a property of the format, not a limit chosen here --
// and it is worth knowing rather than assuming, because the *loaded* image
// routinely lives above 4 GiB while the directory that describes it is a
// 32-bit structure. Wine has the same constraint and the same consequence:
// `RtlImageDirectoryEntryToData` hands out pointers into the mapping while
// the directory's own fields stay 32-bit.
[[nodiscard]] TlsResult read_tls_directory_from_space(
    const AddressSpace& space, std::uint64_t dir_va, bool pe32_plus,
    RawTlsDirectory& out) noexcept {
    // Read by offset, spelled out, because "the four address fields" is the
    // fact the whole structure exists to express and an expression that
    // computed the offsets would hide which field is which.
    std::uint32_t start_raw = 0;
    std::uint32_t end_raw = 0;
    std::uint32_t index_va = 0;
    std::uint32_t zero_fill = 0;
    std::uint32_t characteristics = 0;
    std::uint32_t callbacks_va = 0;

    if (!load_u32_from(space, dir_va + 0, start_raw) ||
        !load_u32_from(space, dir_va + 4, end_raw) ||
        !load_u32_from(space, dir_va + 8, index_va) ||
        !load_u32_from(space, dir_va + 12, zero_fill) ||
        !load_u32_from(space, dir_va + 16, characteristics)) {
        return TlsResult{false, TlsError::MalformedDirectory,
                         "the TLS directory at " + hex_of(dir_va) +
                             " is not five readable DWORDs in memory this "
                             "process mapped"};
    }
    if (pe32_plus) {
        if (!load_u32_from(space, dir_va + 20, callbacks_va)) {
            return TlsResult{false, TlsError::MalformedDirectory,
                             "the TLS directory at " + hex_of(dir_va) +
                                 " is truncated inside the callback field in "
                                 "memory this process mapped"};
        }
    }

    out.start_raw = start_raw;
    out.end_raw = end_raw;
    out.index_va = index_va;
    out.zero_fill = zero_fill;
    out.characteristics = characteristics;
    out.callbacks_va = callbacks_va;
    out.have_callbacks_field = pe32_plus;
    return TlsResult{true, TlsError::None, {}};
}

// Picks the source and reads the directory.
//
// The rule in one place, because it is the rule everything else rests on:
// mapped memory when there is a mapping, the file when there is not. A
// directory read from the file while a mapping exists is not a fallback, it
// is a wrong answer that passes every check.
[[nodiscard]] TlsResult read_tls_directory(const parser::PeImage& image,
                                           ByteSpan bytes,
                                           const AddressSpace& space,
                                           std::uint64_t base,
                                           bool mapped, std::uint32_t rva,
                                           RawTlsDirectory& out) noexcept {
    if (!mapped) {
        return read_tls_directory_from_file(image, bytes, rva, out);
    }
    return read_tls_directory_from_space(space, base + rva,
                                         image.is_pe32_plus(), out);
}

// Whether a directory field, read as a virtual address, names something
// inside the image.
//
// The window is half-open on the right because a field that names the first
// byte past the end is not inside, and a template whose *start* is at the
// end is caught by the size check that follows rather than by this one.
[[nodiscard]] bool field_is_inside(std::uint64_t field, std::uint64_t base,
                                   std::uint64_t image_rva_end) noexcept {
    return field >= base && field - base < image_rva_end;
}

// Turns a directory field into the address it names.
//
// **The format has two answers for this and a loader has to accept both.**
// The field is 32 bits. The image is not. So:
//
//   * Read as a virtual address, the field can only describe an image based
//     below 4 GiB. This is what the specification says the field means and
//     what a linker that targets a low base emits, and it is what Wine
//     assumes without checking -- `alloc_tls_slot` memcpy's from
//     `(void *)dir->StartAddressOfRawData` and never asks whether the value
//     is an RVA. A module based at 0x7fa2a6e30000, which is where a
//     64-bit Windows process puts a DLL, therefore has a TLS directory that
//     Wine cannot use at all.
//
//   * Read as an RVA, the field works at any base -- and this is what
//     modern linkers emit for 64-bit images, because it is the only
//     encoding that survives ASLR. A file that used the VA form would have
//     to be patched whenever it moved, and the relocation pass does not
//     touch the TLS directory: those four fields are not in the relocation
//     table, which is precisely why a VA-form directory is *stale* the
//     moment the image moves and has to be re-read from the mapping.
//
// So: a field that lands inside the image is a VA, and a field that does not
// is an RVA. The disambiguation is unambiguous in practice -- an RVA is
// under `SizeOfImage`, which is a small number, and a VA is not, unless the
// image is based low -- and the ambiguous case is resolved toward the VA
// reading, which is the one the specification names.
//
// The consequence worth stating: reading the file's copy of a VA-form
// directory is *always* wrong, because the file's copy holds the linked
// address and the field is not relocated. Reading the mapped copy is right
// in both forms. That is the whole argument for reading out of memory.
[[nodiscard]] std::uint64_t resolve_tls_address(std::uint64_t field,
                                                std::uint64_t base,
                                                bool is_rva) noexcept {
    return is_rva ? base + field : static_cast<std::uint64_t>(field);
}

// Writes a module's slot number into its image, after the protections are on.
//
// This is the second half of the store `load_tls` deliberately did not do,
// and the reason it is a separate step is that it is the first moment the
// question "is the index field in writable memory?" has an answer worth
// asking. Before the final protections every region is `ReadWrite` -- a
// relocation can name a read-only section and the IAT often is in one -- so a
// check made there is a check of a temporary state.
//
// A file whose `AddressOfIndex` names a read-only section cannot have a
// working TLS, because the program reads the slot number from there and
// nothing will ever write it. Windows refuses such a module at load time
// (`LdrpTlsSlotsUsed` walks the directory and the write in
// `alloc_tls_slot` faults or is guarded), and so does this: the refusal
// names the address, and the slot is given back so a later module can take
// it.
TlsResult load_tls(const parser::PeImage& image, ByteSpan bytes,
                   std::uint64_t base, AddressSpace& space,
                   const LoadContext& context, TlsTable& table,
                   TlsModule* module) noexcept {
    TlsResult out;
    if (module == nullptr) {
        out.error = TlsError::MalformedDirectory;
        out.detail = "no module to report the TLS of";
        return out;
    }
    *module = TlsModule{};

    std::uint32_t rva = 0;
    {
        const TlsResult found = find_tls_directory(image, bytes, rva);
        if (!found.ok) {
            return found;
        }
    }
    if (rva == 0) {
        // No directory. Not a failure, and not the same thing as a directory
        // that is present and empty: a zero RVA is how a linker says "this
        // module has no TLS", and a caller that had to tell the two apart
        // would be asking a question with two useless answers.
        out.ok = true;
        return out;
    }

    // Whether the image is really in memory, which decides where the
    // directory is read from.
    //
    // The test is the *mapper*, not the ledger. An earlier version asked
    // `space.find(base) != nullptr`, on the reasoning that a region covering
    // the base means the image is there. It is not: a load with no mapper
    // still calls `record_batch`, so the ledger describes every section of
    // the image and none of them is backed by anything. The loader then read
    // the directory out of a recorded-but-unmapped address and the test suite
    // died with SIGSEGV inside a memcpy.
    //
    // The distinction is the one the whole `LoadContext::placement` field is
    // about: the ledger is a record of what the load *decided*, the mapping
    // is what the kernel *did*, and only the second one can be read from.
    // A ledger that said "mapped" for an unmapped address would make this
    // function -- and the entry-point check, and every IAT store -- a
    // segfault waiting for an image with no mapper.
    const bool mapped = context.placement != nullptr;

    RawTlsDirectory dir;
    {
        const TlsResult read =
            read_tls_directory(image, bytes, space, base, mapped, rva, dir);
        if (!read.ok) {
            return read;
        }
    }

    // The empty-directory check Wine makes, kept exactly as it is there: a
    // directory whose template, zero fill and callback array are all absent
    // describes nothing, and giving the module a slot would make its
    // `AddressOfIndex` meaningful where the file says nothing about it.
    //
    // Wine's test is `!size && !SizeOfZeroFill && !AddressOfCallBacks` where
    // `size` is `End - Start`. Written here with the same three terms, and
    // the terms are compared as "the derived quantity is zero" rather than
    // "both fields are zero" so that a directory declaring a zero-length
    // template at a non-zero address is treated the same way Wine treats it:
    // as no TLS.
    const std::uint64_t template_size =
        dir.end_raw >= dir.start_raw
            ? static_cast<std::uint64_t>(dir.end_raw) - dir.start_raw
            : 0;
    if (dir.end_raw < dir.start_raw) {
        out.error = TlsError::MalformedDirectory;
        out.detail = "the TLS template ends at " + hex_of(dir.end_raw) +
                     ", before it starts at " + hex_of(dir.start_raw);
        return out;
    }
    if (template_size == 0 && dir.zero_fill == 0 && dir.callbacks_va == 0) {
        out.ok = true;
        return out;
    }

    // The template plus the zero fill is what every thread's block costs, and
    // it is checked here rather than at thread creation for the same reason
    // the placement plan is checked before anything is mapped: a size that
    // cannot be allocated is a fact about the file, and finding it out once
    // at load time is better than once per thread.
    const std::uint64_t block = template_size + dir.zero_fill;
    if (block > std::numeric_limits<std::uint32_t>::max()) {
        // The two fields are 32-bit, so their sum is at most 2^33, and
        // `TlsBlock::size` is 32-bit. Refusing here rather than truncating
        // is the difference between a thread whose block is the size the file
        // asked for and a thread whose block is the size the file asked for
        // modulo four gigabytes.
        out.error = TlsError::TooLarge;
        out.detail = "a thread's TLS block would be " + hex_of(block) +
                     " bytes, which does not fit in the 32-bit size this "
                     "runtime reports it in";
        return out;
    }

    TlsModule m;
    m.directory_va = base + rva;
    m.template_size = static_cast<std::uint32_t>(template_size);
    m.zero_fill = dir.zero_fill;
    m.callbacks_va = dir.have_callbacks_field ? dir.callbacks_va : 0;

    // The image's extent, as an RVA window. Every address in the directory
    // is checked against this and nothing else, because the directory's
    // address fields are 32-bit and the image is not -- see
    // resolve_tls_address, which is where that matters.
    const std::uint64_t image_rva_end = image.image_size();
    const std::uint64_t image_end = base + image_rva_end;

    // How each address field was read out of the directory. Recorded because
    // "the template is at 0x7fa2a6e31100" and "the template is at RVA 0x1100
    // in an image based at 0x7fa2a6e30000" are the same fact said two ways,
    // and a reader of a report needs to know which one produced it.
    const bool template_is_rva =
        !field_is_inside(dir.start_raw, base, image_rva_end);
    const bool index_is_rva =
        !field_is_inside(dir.index_va, base, image_rva_end);
    const bool callbacks_is_rva =
        m.callbacks_va != 0 &&
        !field_is_inside(m.callbacks_va, base, image_rva_end);

    m.template_va = resolve_tls_address(dir.start_raw, base, template_is_rva);
    m.index_va = resolve_tls_address(dir.index_va, base, index_is_rva);
    m.callbacks_va =
        resolve_tls_address(m.callbacks_va, base, callbacks_is_rva);

    // The template has to be inside the image, and "inside" is checked
    // against the image rather than against the space. A TLS directory that
    // points outside its own image is wrong whether or not the image happens
    // to be in memory, and `occ check` has to reach the same verdict as a
    // load -- a checker that accepted a directory a loader would refuse is a
    // checker that says a broken file is fine.
    //
    // Written as a subtraction from `m.template_va - base` rather than as a
    // comparison against `base` first, because the two are not the same
    // check: a field that resolved *below* the base would have wrapped into
    // a huge RVA that passes every `> image_size` test, and the wrap is what
    // the explicit `template_va < base` line below turns into a refusal.
    if (m.template_va < base ||
        m.template_va - base + template_size > image_rva_end) {
        out.error = TlsError::MalformedDirectory;
        out.detail = "the TLS template at " + hex_of(m.template_va) +
                     (m.template_va < base
                          ? " is below the image base " + hex_of(base)
                          : " leaves the image, which ends at " +
                                hex_of(image_end));
        return out;
    }
    if (m.callbacks_va != 0 &&
        (m.callbacks_va < base || m.callbacks_va >= image_end)) {
        out.error = TlsError::MalformedDirectory;
        out.detail = "the TLS callback array at " + hex_of(m.callbacks_va) +
                     " is outside the image, which ends at " +
                     hex_of(image_end);
        return out;
    }
    // The index is a DWORD, so the check is for four bytes ending inside --
    // a field that starts one byte before the end of the image is a field
    // whose three other bytes are in the next section, or past the mapping.
    if (m.index_va != 0 &&
        (m.index_va < base || m.index_va - base + 4 > image_rva_end)) {
        out.error = TlsError::MalformedDirectory;
        out.detail = "the TLS index field at " + hex_of(m.index_va) +
                     " is outside the image, which ends at " +
                     hex_of(image_end);
        return out;
    }

    // The slot. Reuse of a free slot is Wine's behaviour and it is worth
    // having: a process that loads and unloads the same DLL two hundred
    // times in a loop would otherwise need two hundred slots, and the slot
    // number is baked into code the DLL's own author compiled against an
    // earlier load of itself.
    //
    // A free slot is one whose entry has been zeroed, which is exactly what
    // `free_tls_block`'s counterpart does and exactly what Wine's
    // `free_tls_slot` does -- it `memset`s the entry rather than compacting
    // the array, because compacting would renumber the live modules, and a
    // module's slot number is written into its own image where nothing
    // rewrites it.
    std::uint32_t slot = static_cast<std::uint32_t>(table.modules.size());
    for (std::size_t i = 0; i < table.modules.size(); ++i) {
        if (table.modules[i].template_va == 0 &&
            table.modules[i].template_size == 0 &&
            table.modules[i].zero_fill == 0 &&
            table.modules[i].callbacks_va == 0) {
            slot = static_cast<std::uint32_t>(i);
            break;
        }
    }
    m.index = slot;
    if (static_cast<std::size_t>(slot) < table.modules.size()) {
        table.modules[slot] = m;
    } else {
        table.modules.push_back(m);
    }
    if (slot + 1 > table.slots_allocated) {
        table.slots_allocated = slot + 1;
    }

    // Nothing below can fail, and that is a property of the order rather
    // than an accident of this snapshot. Every check that could refuse --
    // the template's bounds, the callback array's, the index field's, the
    // block's size -- ran *above*, before a slot was allocated, so a
    // directory this runtime cannot build never reaches the table and there
    // is nothing here to give back.
    //
    // The one check that happens later is the index field's writability, in
    // `commit_tls_index`, which runs after the final protections because
    // that is the first moment the question has an answer. That one does
    // have to release, and does; see the `release` lambda there.
    //
    // Writing this down matters because the next person to add a check will
    // add it here, below the allocation, and it will have to release -- and
    // the failure mode of forgetting is a table that grows by one per
    // refused load and reuses nothing.

    // The one store, and it does not happen here.
    //
    // The slot number goes into the image at `index_va`, but not from this
    // function, because at this point in the load every region is
    // `ReadWrite` on purpose -- a relocation can name an address in a
    // read-only section, and the IAT is often in one -- so a writability
    // check here would be a check of a temporary state and would always
    // pass. It is `commit_tls_index`, called after the final protections,
    // that finds out whether the index field is in a section the file
    // declared writable, and a file whose is not is refused there.
    //
    // Wine writes it from `alloc_tls_slot`, which also runs after the
    // sections are protected, and for the same reason.

    if (context.events != nullptr) {
        auto& e = context.events->begin(obs::EventKind::Note);
        e.add("text", std::string_view{"tls directory"});
        e.add("source", std::string_view{mapped ? "memory" : "file"});
        e.add_hex("directory", m.directory_va);
        e.add_hex("template", m.template_va);
        e.add("template_size", static_cast<std::uint64_t>(m.template_size));
        e.add("zero_fill", static_cast<std::uint64_t>(m.zero_fill));
        e.add("slot", static_cast<std::uint64_t>(slot));
        e.add_hex("index", m.index_va);
        if (m.callbacks_va != 0) {
            e.add_hex("callbacks", m.callbacks_va);
        }
        context.events->commit();
    }

    *module = m;
    out.ok = true;
    return out;
}

TlsResult build_tls_block(const TlsTable& table, std::uint32_t slot,
                          const AddressSpace& space, Mapper& mapper,
                          TlsBlock* out) noexcept {
    TlsResult result;
    if (out == nullptr) {
        result.error = TlsError::MalformedDirectory;
        result.detail = "no block to report the thread's TLS in";
        return result;
    }
    *out = TlsBlock{};

    if (slot >= table.modules.size()) {
        result.error = TlsError::MalformedDirectory;
        result.detail = "slot " + std::to_string(slot) +
                        " is not in a table of " +
                        std::to_string(table.modules.size()) + " modules";
        return result;
    }
    const TlsModule& m = table.modules[slot];
    const std::uint64_t total =
        static_cast<std::uint64_t>(m.template_size) + m.zero_fill;

    // Everything this function will read is checked *before* it maps
    // anything, and the order is the whole point.
    //
    // The first version of this allocated the block first and read the
    // template into it afterwards, on the reasonable grounds that a block is
    // needed before anything can be copied into it. That order has a failure
    // mode that is invisible until it happens: `mapper.map(0, ...)` asks the
    // kernel where to put the block, and the kernel is free to answer with an
    // address that is the template's own address. The mapping then *covers*
    // the template, `space.find` finds the block, and the copy reads a page
    // of zeros out of the block it just made and reports success. Every
    // thread of that program then has a TLS template full of zeroes where
    // the module's own pointers should be -- which is not a crash, and not a
    // wrong answer this runtime can detect later, but a program whose
    // thread-local variables are all zero for a reason nothing in the report
    // will name.
    //
    // Checking first makes the allocation irrelevant to the answer. A
    // template that is not in the space is refused by name, before there is
    // a block that could be mistaken for one, and the refusal is the same
    // whether or not the kernel would have overlapped them. It also means
    // the block is only ever mapped when there is something to put in it, so
    // the "map then possibly undo" window below shrinks to the copies
    // themselves, which cannot fail.
    if (m.template_size != 0) {
        const Region* home = space.find(m.template_va);
        if (home == nullptr || home->end() < m.template_va + m.template_size) {
            result.error = TlsError::MalformedDirectory;
            result.detail = "the TLS template at " + hex_of(m.template_va) +
                            " is not in memory this process mapped";
            return result;
        }
    }
    if (m.callbacks_va != 0 && space.find(m.callbacks_va) == nullptr) {
        result.error = TlsError::MalformedDirectory;
        result.detail = "the TLS callback array at " + hex_of(m.callbacks_va) +
                        " is not in memory this process mapped";
        return result;
    }

    // The template is copied out of the *space*, and that is the whole
    // reason this function takes a space and not a file. The template holds
    // pointers into the image, and an image placed away from its linked base
    // has had those pointers relocated; a copy taken from the file would hand
    // every thread a block full of addresses that point at the image's
    // preferred base, which is memory nothing is mapped at.
    //
    // Read through the space rather than through a raw pointer for the same
    // reason the stores are: a TLS template can name an address the plan did
    // not cover, and the space is the authority on what was covered.
    if (total != 0) {
        const Result<std::uint64_t> mapped =
            mapper.map(0, total, PageProtection::ReadWrite,
                       RegionKind::Private, ".tls");
        if (!mapped.ok()) {
            result.error = TlsError::OutOfMemory;
            result.detail = "a thread's TLS block of " + hex_of(total) +
                            " bytes could not be mapped";
            return result;
        }
        out->address = mapped.value;
        out->size = static_cast<std::uint32_t>(total);

        // The two reads below cannot fail: the checks above established that
        // both the template and the callback array are inside regions this
        // space holds, and nothing between here and them removes one. They
        // are still written to refuse rather than to assume, because the
        // alternative is a load_from that returns a bool nobody looks at,
        // and a check that cannot fail is either redundant or load-bearing
        // depending on a fact three functions away.
        auto refuse = [&](TlsError e, std::string detail) noexcept -> TlsResult {
            (void)mapper.unmap(out->address);
            *out = TlsBlock{};
            result.ok = false;
            result.error = e;
            result.detail = std::move(detail);
            return result;
        };

        if (m.template_size != 0) {
            if (!load_from(space, m.template_va, reinterpret_cast<void*>(out->address),
                           m.template_size)) {
                return refuse(TlsError::MalformedDirectory,
                              "the TLS template at " + hex_of(m.template_va) +
                                  " stopped being readable between the check "
                                  "and the copy");
            }
        }
        // The zero fill. Written rather than left to the mapping, because a
        // caller may reuse a block address it was given, and then the
        // kernel's zeros are somebody else's leftovers.
        //
        // It is `m.template_size` bytes in, not `total` bytes in: the
        // template is already there and writing zeros over it would destroy
        // the very thing this function exists to copy.
        if (m.zero_fill != 0) {
            std::memset(reinterpret_cast<void*>(out->address + m.template_size),
                        0, m.zero_fill);
        }
    }

    // The callback array, read out of the space for the same reason the
    // template is: the entries are addresses in the image, and an image
    // placed elsewhere has had them relocated.
    if (m.callbacks_va != 0) {
        // Bounded by the region, not trusted. A file whose array has no
        // terminator inside its own image would otherwise walk off the end
        // of every mapping and read whatever the kernel had there, and the
        // resulting "callback" would be called.
        //
        // The null check is not repeated from the one above, but the region
        // is: `find` is a search and this needs the extent, and holding the
        // region from the earlier check across an allocation would be holding
        // a pointer into a vector that the allocation may have reallocated.
        const Region* r = space.find(m.callbacks_va);
        if (r == nullptr) {
            result.error = TlsError::MalformedDirectory;
            result.detail = "the TLS callback array at " +
                            hex_of(m.callbacks_va) +
                            " stopped being mapped between the check and the "
                            "walk";
            return result;
        }
        // The terminator has to fit too: a region that ends exactly at the
        // last entry has no terminator in it, and the loop below would read
        // one past. Bounded by `end() - 8` so the last read is a whole
        // pointer that is inside the region.
        const std::uint64_t region_end = r->end();
        for (std::uint64_t at = m.callbacks_va; at + 8 <= region_end;
             at += 8) {
            std::uint64_t fn = 0;
            if (!load_u64_from(space, at, fn)) {
                break;
            }
            if (fn == 0) {
                // The format's own terminator. Not an absence and not an
                // error: an array whose first entry is null is a module
                // with no callbacks, and a loader that reported an error
                // would be reporting its own expectation as a fact.
                break;
            }
            out->callbacks.push_back(fn);
        }
    }

    result.ok = true;
    return result;
}

void free_tls_block(Mapper& mapper, const TlsBlock& block) noexcept {
    // No address is not an error. A module with neither template nor zero
    // fill has no block, and a caller freeing every module's TLS on thread
    // exit should not have to ask which modules those were.
    if (block.address == 0) {
        return;
    }
    // The result is dropped on purpose, and the reason is worth stating
    // because it looks like an oversight: this function returns void, and a
    // caller that cannot see a failure cannot act on one. What it can do is
    // not carry on believing the block is there, which is why the block is
    // zeroed below whatever the unmap did -- an unmap that failed leaves
    // memory mapped, and a caller that goes on to use the address faults
    // somewhere that has nothing to do with TLS.
    (void)mapper.unmap(block.address);
}

TlsResult call_tls_callbacks(const TlsBlock& block, TlsCallback callback,
                             void* state, std::uint64_t module,
                             TlsReason reason) noexcept {
    TlsResult out;
    if (callback == nullptr) {
        // Not a refusal of the module: a caller with no way to call into the
        // image can still walk the list, and saying "failed" here would make
        // an absence of an invoker indistinguishable from a callback that
        // returned false. Nothing was called, which is what ok means.
        out.ok = true;
        return out;
    }
    for (std::uint64_t fn : block.callbacks) {
        if (!callback(state, fn, module, reason)) {
            out.error = TlsError::CallbackFailed;
            out.detail = "the TLS callback at " + hex_of(fn) +
                         " refused the " + tls_reason_name(reason);
            return out;
        }
    }
    out.ok = true;
    return out;
}

} // namespace occ::runtime

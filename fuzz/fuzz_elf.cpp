// Harness: ELF and format detection over arbitrary bytes.
//
// This is the surface a fuzzer is actually for. Everything else in occ is
// driven by occ itself -- the policy is built in-tree, the GDB peer is
// another process, the target is exec'd -- but a file's first eight bytes
// decide which parser runs, and those bytes come from wherever the user
// pointed occ. A malformed header that reads a program header table out of
// bounds, or that makes the segment arithmetic overflow, is a crash on
// someone else's machine before it is anything else.
//
// The harness therefore does two things rather than one. It calls the parser,
// so ASan and UBSan see whatever the input causes. And it then checks the
// parser's own invariants, because a parser that survives without crashing
// but reports a mapping past the end of the file has still produced a lie,
// and a fuzzer that only watches for crashes will not notice.
//
// Not reached by this harness: the `run` path and everything under it. Those
// need a real process, a real namespace and a real kernel, and a fuzzer that
// forks per input spends all its time in setup. The parser is where untrusted
// bytes enter, so that is where the budget goes.

#include "occ/parser/detect.h"
#include "occ/parser/elf.h"
#include "occ/util/span.h"

#include <cstddef>
#include <cstdint>

namespace {

using occ::ByteSpan;
using occ::parser::ElfImage;
using occ::parser::LoadError;

ByteSpan as_span(const uint8_t* data, std::size_t size) noexcept {
    return ByteSpan{data, size};
}

// The invariants a parsed image has to satisfy whatever the input was.
//
// Each of these is a claim the rest of occ relies on. `occ run` maps what
// this reports, `occ check` prints it, and the W^X tracker watches the
// regions it names -- so a mapping that runs past the end of the file is not
// a cosmetic defect, it is a length the rest of the program will hand to
// mmap.

// A vaddr plus a size is what mmap will be asked for. Two rules hold for
// every one of them: the range does not wrap around the address space, and
// the file-backed part of it is inside the file.
bool invariants_hold(const ElfImage& image, std::size_t file_size) noexcept {
    if (!image.ok()) {
        // A failed parse has no mappings. Reporting some anyway would be the
        // worst outcome, because a caller checks ok() and then trusts the
        // rest.
        return image.mappings().empty();
    }

    for (const auto& m : image.mappings()) {
        const std::uint64_t start = m.vaddr;
        const std::uint64_t size = m.memsz;

        // memsz of zero is a segment that maps nothing. Legal, and the
        // kernel accepts it, so there is nothing to check beyond the file
        // offset being in range below.
        if (size == 0) {
            continue;
        }

        // The range must not wrap. A vaddr near the top of the address space
        // with a large memsz would otherwise produce an end below its start,
        // and a caller doing start + size would get a small number and treat
        // a huge mapping as a small one.
        //
        // Asked without the addition that would overflow it: whether start +
        // size is representable is the same question as whether size fits in
        // what is left above start, and the subtraction form cannot be
        // defeated by the values it is checking.
        if (size > UINT64_MAX - start) {
            return false;
        }

        // Zero-fill is derived from memsz - filesz and must not exceed the
        // memory size, which is what makes it a count rather than a
        // difference that could have been computed wrongly.
        const std::uint64_t zero_fill =
            size > m.filesz ? size - m.filesz : 0;
        if (zero_fill > size) {
            return false;
        }

        // The file-backed extent has to be inside the file. This is the one
        // an overflow in the header arithmetic produces: a filesz read from
        // a crafted table can exceed the file, and the loader would then read
        // past the end of the mapping it just made.
        if (m.filesz > 0) {
            // Both bounds are asked by subtraction. file_offset and filesz
            // come straight out of the program header table, so an addition
            // here would wrap for the same crafted file that made the
            // reader's own bound overflow -- and a check that can be
            // defeated by its input is not a check.
            if (m.file_offset > file_size) {
                return false;
            }
            if (static_cast<std::uint64_t>(file_size) - m.file_offset <
                m.filesz) {
                return false;
            }
        }
    }

    // The interpreter, when present, is a path. A parsed one that is empty
    // has told the loader there is no interpreter while also saying there is
    // one, which is the kind of contradiction that becomes a null deref
    // somewhere else entirely.
    if (image.has_interpreter() && image.interpreter().empty()) {
        return false;
    }

    return true;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data,
                                      std::size_t size) noexcept {
    const ByteSpan bytes = as_span(data, size);

    // Both entry points, on the same bytes. detect_bytes reads a signature
    // near the front; ElfImage::parse reads a header and a table. Running
    // both means a corpus entry that reaches one of them is a seed for the
    // other, which is most of the value of a corpus.
    const auto detection = occ::parser::detect_bytes(bytes);
    (void)occ::parser::format_name(detection.format);

    const ElfImage image = ElfImage::parse(bytes);

    // Touch every accessor even on a failed parse. An accessor that reads
    // uninitialised state is a finding in itself, and a fuzzer that only
    // calls the accessors on success never reaches one.
    (void)image.ok();
    (void)image.error();
    (void)image.error_detail();
    (void)occ::parser::load_error_name(image.error());
    (void)image.type();
    (void)image.machine();
    (void)image.entry();
    (void)image.phnum();
    (void)image.has_interpreter();
    (void)image.has_gnu_relro();
    (void)image.wants_executable_stack();

    if (!invariants_hold(image, size)) {
        // An invariant failure is a bug, not a crash, so it has to abort
        // rather than return: returning would let the fuzzer record the
        // input as uninteresting and move on. __builtin_trap is the portable
        // way to say that from a noexcept function without pulling in the
        // sanitizer runtime's reporting.
        __builtin_trap();
    }

    return 0;
}

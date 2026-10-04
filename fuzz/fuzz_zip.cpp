// Harness: the zip central directory, over arbitrary bytes.
//
// A separate binary from the ELF one for the reason the README gives for
// separating the others: the invariants here are about a different reader,
// and a crash in the archive walk reported as a finding about ELF headers
// sends the next person to the wrong file.
//
// This reader is worth its own harness on its own terms rather than as a
// fifth case folded into the ELF one. It is the only parser in occ whose
// offsets are relative to the *end* of the file rather than the start: the
// end-of-central-directory record is found by scanning backwards, and
// everything else -- the directory's position, its size, the member count --
// comes from that record. A file that controls bytes near its end therefore
// controls every offset the walk uses, which is a different and slightly
// nastier shape than a file that controls bytes near its beginning.
//
// The invariants are the claims the rest of occ relies on. `occ check` prints
// the member list, `occ run` puts one event per member into the stream, and
// the APK engine's refusal tells a caller which library to extract. A name
// read from the wrong offset, or a count that produces members the archive
// does not have, is a lie in all three places at once.

#include "occ/parser/detect.h"
#include "occ/util/span.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace {

using occ::ByteSpan;
using occ::parser::ZipMemberInfo;

ByteSpan as_span(const uint8_t* data, std::size_t size) noexcept {
    return ByteSpan{data, size};
}

// A member's name has to be inside the buffer it was read from.
//
// This is the invariant that a walk with a wrong offset breaks, and it is the
// one that cannot be checked by the reader itself: the reader only ever hands
// back a name it copied, and a copy of the wrong bytes is still a string. So
// it is checked here, against the input, by asking whether the name's bytes
// appear in the file at all.
//
// Appears rather than starts at a computed offset on purpose. The reader
// does not report where it read a name from, and reconstructing the offset
// here would mean reimplementing the walk -- which is the thing under test,
// and a second implementation of it agreeing with the first would prove
// nothing. The substring test is weaker and still catches the failure that
// matters: a name assembled from bytes the file does not contain.
bool name_is_in_file(const ZipMemberInfo& m, ByteSpan file) noexcept {
    if (m.name.empty()) {
        // An empty name is legal in the format and is not this reader's
        // business to refuse. Nothing to look for.
        return true;
    }
    const std::string& n = m.name;
    if (n.size() > file.size()) {
        return false;
    }
    for (std::size_t at = 0; at + n.size() <= file.size(); ++at) {
        bool same = true;
        for (std::size_t i = 0; i < n.size(); ++i) {
            if (file[at + i] != static_cast<uint8_t>(n[i])) {
                same = false;
                break;
            }
        }
        if (same) {
            return true;
        }
    }
    return false;
}

// The claims a member list has to satisfy whatever the input was.
//
// Three of them are about the reader and one is about the report, and the
// fourth is the one a caller of `occ check` would notice first: a reported
// list that is not a subsequence of what was read would mean the report
// invented an entry, which is the failure a bounded report is most able to
// produce.
bool invariants_hold(const std::vector<ZipMemberInfo>& all,
                     const std::vector<ZipMemberInfo>& shown,
                     ByteSpan file) noexcept {
    for (const ZipMemberInfo& m : all) {
        if (!name_is_in_file(m, file)) {
            return false;
        }
        // stored is derived from the method rather than read, so a member
        // claiming method 0 and reporting itself as deflated would mean the
        // two were computed from different fields.
        if (m.stored != (m.compression_method == 0)) {
            return false;
        }
        // Deliberately not asserted: that a stored member's two sizes are
        // equal. They are equal in every archive a writer produces, and a
        // file whose record says otherwise is a file whose record is wrong --
        // but "wrong" is a fact about the file, and this reader's contract is
        // to report what the directory said rather than to decide that the
        // directory is lying. Asserting it here was tried and it traps on
        // inputs that are perfectly well-formed as files: a stored member
        // whose recorded sizes differ is unusual, not unreadable, and the
        // report of it is exactly what a caller needs in order to distrust
        // it. The invariants here are about the reader's own promises -- that
        // a name came from the file, that the report is a subsequence of
        // what was read -- and not about the archive being coherent.
    }

    // The report is drawn from the full list and adds nothing: no member is
    // reported that was not read, and none is reported more often than it
    // was read.
    //
    // Compared as a count per name rather than as a subsequence walk. The
    // walk is the obvious choice and it is wrong: a directory may name the
    // same member twice -- two records with one name is a malformed archive,
    // but it is a well-formed list -- and a walk that consumes one entry per
    // reported member loses its place at the duplicate and then fails to
    // match a name that is genuinely present. That is a false report of a
    // reader defect, found by running this harness, and it is why the
    // comparison is over counts.
    for (const ZipMemberInfo& m : shown) {
        std::size_t in_all = 0;
        for (const ZipMemberInfo& a : all) {
            if (a.name == m.name) {
                ++in_all;
            }
        }
        std::size_t in_shown = 0;
        for (const ZipMemberInfo& s : shown) {
            if (s.name == m.name) {
                ++in_shown;
            }
        }
        if (in_shown > in_all) {
            return false;
        }
    }

    return true;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data,
                                      std::size_t size) noexcept {
    const ByteSpan bytes = as_span(data, size);

    // Both entry points, and they are the two a caller reaches in sequence:
    // detection decides the format and fills the member list, and the reader
    // is public because the APK engine calls it on the same bytes. Running
    // both here means a corpus entry that reaches one is a seed for the
    // other.
    const auto detection = occ::parser::detect_bytes(bytes);

    // Touch the accessors whatever the verdict was, including on a parse that
    // failed. An accessor reading uninitialised state is a finding in itself.
    (void)occ::parser::format_name(detection.format);
    (void)detection.file_size;
    (void)detection.bare_program_header;
    for (const std::string& e : detection.evidence) {
        (void)e.size();
    }
    for (const ZipMemberInfo& m : detection.zip_members) {
        (void)m.name.size();
        (void)m.compression_method;
        (void)m.compressed_size;
        (void)m.uncompressed_size;
        (void)m.stored;
    }

    // Read the directory a second time, into its own vector, so the two can
    // be compared -- but only where the two are supposed to agree.
    //
    // Detection reads the central directory only after the first local file
    // header has identified the file as a zip at all. A file whose first
    // local header has been damaged is not a zip as far as detection is
    // concerned, and it reports no members -- while a direct call to the
    // reader, which starts from the end of the file, still finds the
    // directory. Both answers are correct: they answer different questions.
    // So the comparison is asserted only when detection took the zip path,
    // and the case where it did not is asserted to be a file detection
    // called something other than a zip.
    const bool detection_is_zip = detection.format == occ::parser::Format::Zip ||
                                  detection.format == occ::parser::Format::Apk;

    std::vector<ZipMemberInfo> direct;
    const bool read = occ::parser::read_zip_members(bytes, direct);
    if (read != !direct.empty()) {
        __builtin_trap();
    }

    if (detection_is_zip) {
        if (read != !detection.zip_members.empty()) {
            __builtin_trap();
        }
        if (read && direct.size() != detection.zip_members.size()) {
            __builtin_trap();
        }
    } else if (!detection.zip_members.empty()) {
        // A file detection did not call a zip reported members. There is no
        // path on which that is true, and if one appears it would mean the
        // members came from somewhere other than the directory this harness
        // is about.
        __builtin_trap();
    }

    const std::vector<ZipMemberInfo> shown =
        occ::parser::zip_report_members(detection.zip_members);

    if (!invariants_hold(detection.zip_members, shown, bytes)) {
        // An invariant failure is a bug rather than a crash, so it aborts
        // instead of returning: returning would let the fuzzer record the
        // input as uninteresting and move on.
        __builtin_trap();
    }

    return 0;
}

// The static inspection surface: one command, every structure an image
// carries, read from the file and reported without running it.
//
// Everything here is a *reader*, not a loader: the file is parsed as it
// lies on disk, malformed structures are reported rather than repaired, and
// nothing in this file touches the runtime. The JSON it emits is meant to
// be consumed the way `occ run`'s event stream is -- one document, jq-ready,
// with every offset an analyst would otherwise reach for a second tool to
// find.

#pragma once

#include <cstdint>
#include <string>

#include "occ/parser/pe.h"
#include "occ/util/span.h"

namespace occ::inspect {

// What the report includes beyond the always-present structure sections.
struct InspectOptions {
    // Extract printable ASCII and UTF-16 strings (minimum length 5).
    bool strings = true;
    // Extract the version resource, when the image carries one.
    bool version = true;
    // How many strings to report before the list is capped.
    std::size_t string_limit = 4096;
};

// Produces the full inspection document for one image. The bytes must be
// the whole file; `image` must be its parse. Answers an empty string when
// the parse failed -- the caller reports that through the parse's own
// error, which is the same failure the loader would have named.
[[nodiscard]] std::string inspect_pe_json(const parser::PeImage& image,
                                          ByteSpan bytes,
                                          const InspectOptions& options);

}  // namespace occ::inspect

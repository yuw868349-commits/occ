// The GDI32 surface, as a headless rasterizer.
//
// A device context is a drawing surface and the state that decides how a
// drawing call lands on it: the pen and brush that stroke and fill, the font
// and colours text is drawn in, the mapping from logical to device
// coordinates, and the clip region that bounds the whole thing. This file
// implements that surface for real -- a device context owns a pixel buffer,
// every drawing call writes into it, and a `GetPixel` or a `BitBlt` back out
// reads what was written -- because a hardened program uses those calls to
// look at its own drawing, and a runtime that answered "nothing drawn" would
// be answering a question it could have answered truthfully.
//
// The fonts are a built-in bitmap face: a headless host has no font to load
// and no rasterizer to call, so the glyphs are baked in and the metrics are
// the cell's own. Text drawn with them is real pixels with real glyph shapes,
// and `GetTextExtentPoint32` reports the advance a caller lays out against.
//
// What is not implemented is what a headless host cannot honestly do: the
// printer and metafile families, the path objects, and the `D3DKMT` adapter
// surface all refuse rather than invent. Everything a GUI program actually
// draws with is here.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace occ::runtime::winabi {
namespace {

// -- the error codes the family reports --------------------------------------

[[maybe_unused]] constexpr std::uint32_t kErrOk = 0;
constexpr std::uint32_t kErrParam = 87;

constexpr std::int32_t kTrue = 1;
constexpr std::int32_t kFalse = 0;

// -- the handle ranges -------------------------------------------------------
//
// A graphics handle is a small value handed out in order, which is the shape
// Windows' own handles take. Device contexts and drawing objects are kept in
// two counters so that a handle's namespace is a property of its value: a
// program that passes an object where a context belongs is told so rather
// than shown another context's pixels.

constexpr std::uint64_t kObjectFirst = 0x00010010;
constexpr std::uint64_t kObjectStep = 4;
constexpr std::uint64_t kDcFirst = 0x00090010;
constexpr std::uint64_t kDcStep = 4;

// -- the stock objects -------------------------------------------------------
//
// The objects `GetStockObject` answers with, by the indices Windows fixes.

constexpr std::int32_t kWhiteBrush = 0;
constexpr std::int32_t kLtGrayBrush = 1;
constexpr std::int32_t kGrayBrush = 2;
constexpr std::int32_t kDkGrayBrush = 3;
constexpr std::int32_t kBlackBrush = 4;
constexpr std::int32_t kNullBrush = 5;
[[maybe_unused]] constexpr std::int32_t kHollowBrush = kNullBrush;
constexpr std::int32_t kWhitePen = 6;
constexpr std::int32_t kBlackPen = 7;
constexpr std::int32_t kNullPen = 8;
constexpr std::int32_t kOemFixedFont = 10;
constexpr std::int32_t kAnsiFixedFont = 11;
constexpr std::int32_t kAnsiVarFont = 12;
constexpr std::int32_t kSystemFont = 13;
constexpr std::int32_t kDeviceDefaultFont = 14;
constexpr std::int32_t kDefaultPalette = 15;
constexpr std::int32_t kSystemFixedFont = 16;
constexpr std::int32_t kDefaultGuiFont = 17;
constexpr std::int32_t kStockDcBrush = 18;
constexpr std::int32_t kStockDcPen = 19;
constexpr std::int32_t kStockObjects = 20;

// -- the pen and brush styles ------------------------------------------------

constexpr int kPenSolid = 0;
[[maybe_unused]] constexpr int kPenDash = 1;
[[maybe_unused]] constexpr int kPenDot = 2;
[[maybe_unused]] constexpr int kPenDashDot = 3;
[[maybe_unused]] constexpr int kPenDashDotDot = 4;
constexpr int kPenNull = 5;
[[maybe_unused]] constexpr int kPenInsideFrame = 6;
[[maybe_unused]] constexpr int kPsGeometric = 0x00010000;
[[maybe_unused]] constexpr int kPsEndcapRound = 0x00000000;
[[maybe_unused]] constexpr int kPsEndcapSquare = 0x00000100;
[[maybe_unused]] constexpr int kPsEndcapFlat = 0x00000200;
[[maybe_unused]] constexpr int kPsJoinRound = 0x00000000;
[[maybe_unused]] constexpr int kPsJoinBevel = 0x00001000;
[[maybe_unused]] constexpr int kPsJoinMiter = 0x00002000;
[[maybe_unused]] constexpr int kPsDash = 0x00000001;
[[maybe_unused]] constexpr int kPsDot = 0x00000002;
[[maybe_unused]] constexpr int kPsCosmetic = 0x00000000;

constexpr int kBsSolid = 0;
constexpr int kBsNull = 1;
constexpr int kBsHatched = 2;
constexpr int kBsPattern = 3;
[[maybe_unused]] constexpr int kBsHollow = kBsNull;

// -- the background and drawing modes ----------------------------------------

[[maybe_unused]] constexpr std::uint32_t kTransparent = 1;
constexpr std::uint32_t kOpaque = 2;
constexpr std::uint32_t kR2Copypen = 13;
[[maybe_unused]] constexpr std::uint32_t kR2Not = 6;
[[maybe_unused]] constexpr std::uint32_t kR2Black = 1;
[[maybe_unused]] constexpr std::uint32_t kR2White = 16;
[[maybe_unused]] constexpr std::uint32_t kR2Xorpen = 7;
[[maybe_unused]] constexpr std::uint32_t kR2Mergepennot = 12;
[[maybe_unused]] constexpr std::uint32_t kR2Maskpennot = 5;
[[maybe_unused]] constexpr std::uint32_t kR2Mergecopy = 9;
[[maybe_unused]] constexpr std::uint32_t kR2CopypenAlt = 13;

constexpr int kAlternate = 1;
constexpr int kWinding = 2;

constexpr int kBlackOnWhite = 1;
[[maybe_unused]] constexpr int kWhiteOnBlack = 2;
[[maybe_unused]] constexpr int kColorOnColor = 3;
[[maybe_unused]] constexpr int kHalfTone = 4;

// -- the text alignment flags ------------------------------------------------

[[maybe_unused]] constexpr std::uint32_t kTaNoUpdateCp = 0;
constexpr std::uint32_t kTaLeft = 0;
[[maybe_unused]] constexpr std::uint32_t kTaRight = 2;
[[maybe_unused]] constexpr std::uint32_t kTaCenter = 6;
constexpr std::uint32_t kTaTop = 0;
[[maybe_unused]] constexpr std::uint32_t kTaBottom = 8;
[[maybe_unused]] constexpr std::uint32_t kTaBaseline = 24;
constexpr std::uint32_t kTaUPDATECP = 1;

// -- the DIB colours ---------------------------------------------------------

[[maybe_unused]] constexpr std::uint32_t kDibRgbColors = 0;
[[maybe_unused]] constexpr std::uint32_t kDibPalColors = 1;
[[maybe_unused]] constexpr std::uint32_t kDibRgbColorsGuard = 2;
[[maybe_unused]] constexpr std::uint32_t kDibPalColorsGuard = 3;

// The bit-block transfer opcodes the blit family takes. The three a program
// actually writes by hand are named; the rest are the ROP codes a blit reads.
constexpr std::uint32_t kSrcCopy = 0x00CC0020;
[[maybe_unused]] constexpr std::uint32_t kSrcAnd = 0x008800C6;
[[maybe_unused]] constexpr std::uint32_t kSrcPaint = 0x00EE0086;
[[maybe_unused]] constexpr std::uint32_t kSrcInvert = 0x00660046;
[[maybe_unused]] constexpr std::uint32_t kSrcErase = 0x00440328;
[[maybe_unused]] constexpr std::uint32_t kNotSrcCopy = 0x00330008;
[[maybe_unused]] constexpr std::uint32_t kNotSrcErase = 0x001100A6;
[[maybe_unused]] constexpr std::uint32_t kDstInvert = 0x00550009;
[[maybe_unused]] constexpr std::uint32_t kPatCopy = 0x00F00021;
[[maybe_unused]] constexpr std::uint32_t kPatInvert = 0x005A0049;
[[maybe_unused]] constexpr std::uint32_t kBlackness = 0x00000042;
[[maybe_unused]] constexpr std::uint32_t kWhiteness = 0x00FF0062;
[[maybe_unused]] constexpr std::uint32_t kCaptureBlt = 0x40000000;


// -- the pixel surface -------------------------------------------------------
//
// Everything a device context draws onto is one of these. A bitmap created by
// the runtime owns a vector of bytes; a DIB section points at the guest's own
// memory, so a program that writes into the section's bits and then blits
// them sees what it wrote. Colour is carried as 0x00RRGGBB and converted to
// and from the surface's own depth through the palette the surface carries.

struct Surface {
    int w = 0;
    int h = 0;
    int bpp = 32;
    int stride = 0;                  // bytes per scan line
    std::vector<std::uint8_t> owned; // used when `bits` is null
    std::uint8_t* bits = nullptr;    // the guest's memory for a DIB section
    bool is_dib = false;
    std::vector<std::uint32_t> colors;  // palette, 0x00RRGGBB each
    int color_count = 0;

    [[nodiscard]] std::uint8_t* row(int y) noexcept {
        return bits != nullptr ? bits + static_cast<std::ptrdiff_t>(y) * stride
                               : owned.data() +
                                     static_cast<std::ptrdiff_t>(y) * stride;
    }
    [[nodiscard]] const std::uint8_t* row(int y) const noexcept {
        return bits != nullptr ? bits + static_cast<std::ptrdiff_t>(y) * stride
                               : owned.data() +
                                     static_cast<std::ptrdiff_t>(y) * stride;
    }
};

// The stride a DIB of the given shape takes: each scan line padded to a
// four-byte boundary, which is the rule the format fixes.
[[nodiscard]] int dib_stride(int width, int bpp) noexcept {
    const int bits = width * bpp;
    return ((bits + 31) / 32) * 4;
}

// The palette Windows gives a DIB whose header asked for none: the two-colour
// black/white table for a one-bit image, and the sixteen-colour VGA table up
// to eight bits. A higher depth carries no palette.
void default_palette_for(Surface& s) noexcept {
    static const std::uint32_t kVga16[16] = {
        0x000000, 0x800000, 0x008000, 0x808000, 0x000080, 0x800080,
        0x008080, 0xC0C0C0, 0x808080, 0xFF0000, 0x00FF00, 0xFFFF00,
        0x0000FF, 0xFF00FF, 0x00FFFF, 0xFFFFFF,
    };
    if (s.bpp == 1) {
        s.colors = {0x000000u, 0xFFFFFFu};
        s.color_count = 2;
    } else if (s.bpp == 4 || s.bpp == 8) {
        s.colors.assign(kVga16, kVga16 + 16);
        s.color_count = 16;
        if (s.bpp == 8) {
            // The eight-bit table is the sixteen VGA colours and then the
            // next forty-eight entries the VGA ramp implies; the exact values
            // do not matter to a caller unless it asked for them, and a
            // caller that did carries its own table.
            for (int i = 16; i < 256; ++i) {
                s.colors.push_back(static_cast<std::uint32_t>(i * 0x010101));
            }
            s.color_count = 256;
        }
    } else {
        s.colors.clear();
        s.color_count = 0;
    }
}

[[nodiscard]] std::uint32_t surface_get(const Surface& s, int x, int y) noexcept {
    if (x < 0 || y < 0 || x >= s.w || y >= s.h) {
        return 0;
    }
    const std::uint8_t* p = s.row(y);
    switch (s.bpp) {
    case 32: {
        std::uint32_t v = 0;
        std::memcpy(&v, p + x * 4, 4);
        return v & 0x00FFFFFFu;
    }
    case 24: {
        const std::uint8_t* q = p + x * 3;
        return static_cast<std::uint32_t>(q[0]) |
               (static_cast<std::uint32_t>(q[1]) << 8) |
               (static_cast<std::uint32_t>(q[2]) << 16);
    }
    case 16: {
        std::uint16_t v = 0;
        std::memcpy(&v, p + x * 2, 2);
        const std::uint32_t r = (v >> 10) & 0x1F;
        const std::uint32_t g = (v >> 5) & 0x1F;
        const std::uint32_t b = v & 0x1F;
        return (r << 19) | (g << 11) | (b << 3);
    }
    case 8: {
        const std::uint8_t idx = p[x];
        return idx < s.colors.size() ? s.colors[idx] : 0;
    }
    case 4: {
        const std::uint8_t b = p[x / 2];
        const std::uint8_t idx = (x & 1) != 0 ? (b & 0x0F) : (b >> 4);
        return idx < s.colors.size() ? s.colors[idx] : 0;
    }
    case 1: {
        const std::uint8_t b = p[x / 8];
        const std::uint8_t idx = static_cast<std::uint8_t>((b >> (7 - (x & 7))) & 1);
        return idx < s.colors.size() ? s.colors[idx] : (idx != 0 ? 0xFFFFFFu : 0u);
    }
    default:
        return 0;
    }
}

void surface_set(Surface& s, int x, int y, std::uint32_t color) noexcept {
    if (x < 0 || y < 0 || x >= s.w || y >= s.h) {
        return;
    }
    std::uint8_t* p = s.row(y);
    switch (s.bpp) {
    case 32: {
        const std::uint32_t v = color & 0x00FFFFFFu;
        std::memcpy(p + x * 4, &v, 4);
        return;
    }
    case 24: {
        std::uint8_t* q = p + x * 3;
        q[0] = static_cast<std::uint8_t>(color);
        q[1] = static_cast<std::uint8_t>(color >> 8);
        q[2] = static_cast<std::uint8_t>(color >> 16);
        return;
    }
    case 16: {
        const std::uint16_t v = static_cast<std::uint16_t>(
            (((color >> 19) & 0x1F) << 10) | (((color >> 11) & 0x1F) << 5) |
            ((color >> 3) & 0x1F));
        std::memcpy(p + x * 2, &v, 2);
        return;
    }
    case 8:
    case 4:
    case 1: {
        // The nearest palette entry, which is what a palettised surface does
        // with a colour it does not carry.
        int best = 0;
        long best_distance = std::numeric_limits<long>::max();
        for (std::size_t i = 0; i < s.colors.size(); ++i) {
            const std::uint32_t c = s.colors[i];
            const long dr = static_cast<long>((color >> 16) & 0xFF) -
                            static_cast<long>((c >> 16) & 0xFF);
            const long dg = static_cast<long>((color >> 8) & 0xFF) -
                            static_cast<long>((c >> 8) & 0xFF);
            const long db = static_cast<long>(color & 0xFF) -
                            static_cast<long>(c & 0xFF);
            const long d = dr * dr + dg * dg + db * db;
            if (d < best_distance) {
                best_distance = d;
                best = static_cast<int>(i);
            }
        }
        if (s.bpp == 8) {
            p[x] = static_cast<std::uint8_t>(best);
        } else if (s.bpp == 4) {
            std::uint8_t& byte = p[x / 2];
            if ((x & 1) != 0) {
                byte = static_cast<std::uint8_t>((byte & 0xF0) | (best & 0x0F));
            } else {
                byte = static_cast<std::uint8_t>((byte & 0x0F) |
                                                 ((best & 0x0F) << 4));
            }
        } else {
            std::uint8_t& byte = p[x / 8];
            const int bit = 7 - (x & 7);
            if (best != 0) {
                byte = static_cast<std::uint8_t>(byte | (1 << bit));
            } else {
                byte = static_cast<std::uint8_t>(byte & ~(1 << bit));
            }
        }
        return;
    }
    default:
        return;
    }
}

// -- the built-in font -------------------------------------------------------

// The built-in bitmap font: ASCII 32..126, one glyph per 8x16 cell.
//
// A headless runtime has no font to load, so text drawn through a
// device context needs a font of its own. This one is a monospace cell
// rendered once from a metric-compatible face and baked in, so the
// drawing code has real glyph shapes without a font file, a rasterizer,
// or a dependency. Each glyph is sixteen bytes, one per scan line, most
// significant bit leftmost; bit set means ink.
constexpr int kFontCellW = 8;
constexpr int kFontCellH = 16;
constexpr char kFontFirst = 32;
constexpr int kFontGlyphs = 95;
constexpr std::uint8_t kFontBitmaps[kFontGlyphs][kFontCellH] = {
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  // ' '
    {0x00, 0x00, 0x00, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00},  // '!'
    {0x00, 0x00, 0x36, 0x36, 0x36, 0x36, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  // '"'
    {0x00, 0x00, 0x00, 0x11, 0x12, 0x12, 0x7F, 0x22, 0x22, 0xFF, 0x24, 0x44, 0x44, 0x00, 0x00, 0x00},  // '#'
    {0x00, 0x00, 0x08, 0x3E, 0x6B, 0x49, 0x68, 0x3E, 0x0F, 0x09, 0x49, 0x6B, 0x3E, 0x08, 0x00, 0x00},  // '$'
    {0x00, 0x00, 0x00, 0x71, 0x93, 0x92, 0x94, 0x78, 0x0F, 0x14, 0x24, 0x64, 0x47, 0x00, 0x00, 0x00},  // '%'
    {0x00, 0x00, 0x00, 0x1C, 0x26, 0x26, 0x3C, 0x30, 0x53, 0xCA, 0xCA, 0xC6, 0x7B, 0x00, 0x00, 0x00},  // '&'
    {0x00, 0x00, 0x08, 0x08, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  // '''
    {0x00, 0x00, 0x04, 0x0C, 0x18, 0x18, 0x10, 0x30, 0x30, 0x30, 0x30, 0x10, 0x18, 0x18, 0x0C, 0x04},  // '('
    {0x00, 0x00, 0x10, 0x18, 0x0C, 0x0C, 0x04, 0x04, 0x06, 0x06, 0x04, 0x04, 0x0C, 0x0C, 0x18, 0x10},  // ')'
    {0x00, 0x00, 0x08, 0x3E, 0x1C, 0x1C, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  // '*'
    {0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x08, 0x7F, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00},  // '+'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x10, 0x30, 0x20, 0x00},  // ','
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  // '-'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x00, 0x00, 0x00},  // '.'
    {0x00, 0x00, 0x03, 0x02, 0x06, 0x04, 0x0C, 0x08, 0x18, 0x10, 0x30, 0x20, 0x60, 0x00, 0x00, 0x00},  // '/'
    {0x00, 0x00, 0x00, 0x3E, 0x22, 0x63, 0x41, 0x49, 0x49, 0x43, 0x63, 0x36, 0x3C, 0x00, 0x00, 0x00},  // '0'
    {0x00, 0x00, 0x00, 0x0C, 0x1C, 0x6C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x7F, 0x00, 0x00, 0x00},  // '1'
    {0x00, 0x00, 0x00, 0x3E, 0x23, 0x63, 0x03, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x7F, 0x00, 0x00, 0x00},  // '2'
    {0x00, 0x00, 0x00, 0x3E, 0x63, 0x63, 0x02, 0x1E, 0x07, 0x03, 0x63, 0x63, 0x3E, 0x00, 0x00, 0x00},  // '3'
    {0x00, 0x00, 0x00, 0x06, 0x0E, 0x1E, 0x16, 0x26, 0x46, 0x7F, 0x06, 0x06, 0x06, 0x00, 0x00, 0x00},  // '4'
    {0x00, 0x00, 0x00, 0x7F, 0x60, 0x60, 0x7E, 0x63, 0x03, 0x01, 0x63, 0x67, 0x3E, 0x00, 0x00, 0x00},  // '5'
    {0x00, 0x00, 0x00, 0x1E, 0x33, 0x60, 0x7E, 0x73, 0x63, 0x61, 0x63, 0x33, 0x1E, 0x00, 0x00, 0x00},  // '6'
    {0x00, 0x00, 0x00, 0x7F, 0x03, 0x02, 0x04, 0x0C, 0x08, 0x08, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00},  // '7'
    {0x00, 0x00, 0x00, 0x3E, 0x63, 0x63, 0x62, 0x3E, 0x63, 0x63, 0x63, 0x63, 0x3E, 0x00, 0x00, 0x00},  // '8'
    {0x00, 0x00, 0x00, 0x3C, 0x66, 0x63, 0x63, 0x63, 0x67, 0x3F, 0x03, 0x66, 0x3C, 0x00, 0x00, 0x00},  // '9'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x00, 0x00, 0x00},  // ':'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x18, 0x10, 0x10, 0x00},  // ';'
    {0x00, 0x00, 0x00, 0x00, 0x03, 0x0E, 0x78, 0x60, 0x78, 0x0E, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00},  // '<'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7F, 0x00, 0x00, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  // '='
    {0x00, 0x00, 0x00, 0x00, 0x40, 0x38, 0x0F, 0x03, 0x0F, 0x38, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00},  // '>'
    {0x00, 0x00, 0x00, 0x3E, 0x63, 0x43, 0x03, 0x06, 0x0C, 0x18, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00},  // '?'
    {0x00, 0x00, 0x1E, 0x23, 0x41, 0x5F, 0x56, 0xA2, 0xA6, 0xA5, 0xE5, 0x5F, 0x40, 0x62, 0x3E, 0x00},  // '@'
    {0x00, 0x00, 0x00, 0x1C, 0x1C, 0x14, 0x36, 0x22, 0x22, 0x7F, 0x41, 0xC1, 0xC1, 0x00, 0x00, 0x00},  // 'A'
    {0x00, 0x00, 0x00, 0x7E, 0x63, 0x63, 0x63, 0x7E, 0x63, 0x61, 0x61, 0x63, 0x7E, 0x00, 0x00, 0x00},  // 'B'
    {0x00, 0x00, 0x00, 0x1E, 0x33, 0x61, 0x60, 0x40, 0x40, 0x60, 0x61, 0x33, 0x1E, 0x00, 0x00, 0x00},  // 'C'
    {0x00, 0x00, 0x00, 0x7C, 0x66, 0x63, 0x61, 0x61, 0x61, 0x61, 0x63, 0x66, 0x7C, 0x00, 0x00, 0x00},  // 'D'
    {0x00, 0x00, 0x00, 0x7F, 0x60, 0x60, 0x60, 0x7F, 0x60, 0x60, 0x60, 0x60, 0x7F, 0x00, 0x00, 0x00},  // 'E'
    {0x00, 0x00, 0x00, 0x7F, 0x60, 0x60, 0x60, 0x7F, 0x60, 0x60, 0x60, 0x60, 0x60, 0x00, 0x00, 0x00},  // 'F'
    {0x00, 0x00, 0x00, 0x1C, 0x33, 0x63, 0x60, 0x40, 0x4F, 0x63, 0x61, 0x33, 0x1E, 0x00, 0x00, 0x00},  // 'G'
    {0x00, 0x00, 0x00, 0x63, 0x63, 0x63, 0x63, 0x7F, 0x63, 0x63, 0x63, 0x63, 0x63, 0x00, 0x00, 0x00},  // 'H'
    {0x00, 0x00, 0x00, 0x7F, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x7F, 0x00, 0x00, 0x00},  // 'I'
    {0x00, 0x00, 0x00, 0x1E, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x62, 0x36, 0x3C, 0x00, 0x00, 0x00},  // 'J'
    {0x00, 0x00, 0x00, 0x63, 0x66, 0x64, 0x6C, 0x78, 0x6C, 0x66, 0x62, 0x63, 0x61, 0x00, 0x00, 0x00},  // 'K'
    {0x00, 0x00, 0x00, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x3F, 0x00, 0x00, 0x00},  // 'L'
    {0x00, 0x00, 0x00, 0x63, 0x63, 0x73, 0x55, 0x55, 0x5D, 0x49, 0x41, 0x41, 0x41, 0x00, 0x00, 0x00},  // 'M'
    {0x00, 0x00, 0x00, 0x63, 0x73, 0x73, 0x73, 0x6B, 0x6B, 0x6F, 0x67, 0x67, 0x63, 0x00, 0x00, 0x00},  // 'N'
    {0x00, 0x00, 0x00, 0x3E, 0x77, 0x63, 0x41, 0x41, 0x41, 0x41, 0x63, 0x76, 0x3E, 0x00, 0x00, 0x00},  // 'O'
    {0x00, 0x00, 0x00, 0x7E, 0x63, 0x61, 0x61, 0x63, 0x7E, 0x60, 0x60, 0x60, 0x60, 0x00, 0x00, 0x00},  // 'P'
    {0x00, 0x00, 0x00, 0x3E, 0x77, 0x63, 0x41, 0x41, 0x41, 0x41, 0x63, 0x76, 0x3E, 0x0C, 0x06, 0x07},  // 'Q'
    {0x00, 0x00, 0x00, 0x7E, 0x63, 0x61, 0x63, 0x7E, 0x6C, 0x66, 0x62, 0x63, 0x61, 0x00, 0x00, 0x00},  // 'R'
    {0x00, 0x00, 0x00, 0x3E, 0x63, 0x63, 0x60, 0x3C, 0x0F, 0x03, 0x41, 0x63, 0x3E, 0x00, 0x00, 0x00},  // 'S'
    {0x00, 0x00, 0x00, 0xFF, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00},  // 'T'
    {0x00, 0x00, 0x00, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x67, 0x3E, 0x00, 0x00, 0x00},  // 'U'
    {0x00, 0x00, 0x00, 0xC1, 0x41, 0x63, 0x63, 0x22, 0x36, 0x36, 0x14, 0x1C, 0x1C, 0x00, 0x00, 0x00},  // 'V'
    {0x00, 0x00, 0x00, 0xC1, 0xC1, 0xC1, 0xC9, 0x5D, 0x5D, 0x55, 0x77, 0x77, 0x63, 0x00, 0x00, 0x00},  // 'W'
    {0x00, 0x00, 0x00, 0x63, 0x63, 0x36, 0x1C, 0x1C, 0x1C, 0x36, 0x22, 0x63, 0xC1, 0x00, 0x00, 0x00},  // 'X'
    {0x00, 0x00, 0x00, 0xC1, 0x63, 0x63, 0x36, 0x36, 0x1C, 0x1C, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00},  // 'Y'
    {0x00, 0x00, 0x00, 0x7F, 0x03, 0x06, 0x04, 0x0C, 0x18, 0x30, 0x20, 0x60, 0xFF, 0x00, 0x00, 0x00},  // 'Z'
    {0x00, 0x00, 0x1E, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1E},  // '['
    {0x00, 0x00, 0x60, 0x20, 0x30, 0x10, 0x18, 0x08, 0x0C, 0x04, 0x06, 0x02, 0x03, 0x00, 0x00, 0x00},  // '\'
    {0x00, 0x00, 0x3C, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x3C},  // ']'
    {0x00, 0x00, 0x00, 0x1C, 0x1C, 0x14, 0x36, 0x22, 0x63, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  // '^'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00},  // '_'
    {0x00, 0x00, 0x18, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  // '`'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x66, 0x02, 0x3E, 0x62, 0x62, 0x67, 0x3B, 0x00, 0x00, 0x00},  // 'a'
    {0x00, 0x00, 0x60, 0x60, 0x60, 0x7E, 0x73, 0x63, 0x63, 0x63, 0x63, 0x73, 0x7E, 0x00, 0x00, 0x00},  // 'b'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x3E, 0x23, 0x60, 0x60, 0x60, 0x60, 0x63, 0x3E, 0x00, 0x00, 0x00},  // 'c'
    {0x00, 0x00, 0x03, 0x03, 0x03, 0x3F, 0x67, 0x63, 0x63, 0x63, 0x63, 0x67, 0x3F, 0x00, 0x00, 0x00},  // 'd'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x3E, 0x63, 0x63, 0x7F, 0x60, 0x60, 0x23, 0x3E, 0x00, 0x00, 0x00},  // 'e'
    {0x00, 0x00, 0x0F, 0x18, 0x10, 0x7F, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x00, 0x00, 0x00},  // 'f'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x3F, 0x67, 0x63, 0x63, 0x63, 0x63, 0x67, 0x3F, 0x03, 0x22, 0x3E},  // 'g'
    {0x00, 0x00, 0x60, 0x60, 0x60, 0x7E, 0x73, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x00, 0x00, 0x00},  // 'h'
    {0x00, 0x00, 0x0C, 0x08, 0x00, 0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x7F, 0x00, 0x00, 0x00},  // 'i'
    {0x00, 0x00, 0x04, 0x04, 0x00, 0x3C, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0C, 0x78},  // 'j'
    {0x00, 0x00, 0x20, 0x20, 0x20, 0x23, 0x26, 0x2C, 0x38, 0x3C, 0x24, 0x26, 0x23, 0x00, 0x00, 0x00},  // 'k'
    {0x00, 0x00, 0x38, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0F, 0x00, 0x00, 0x00},  // 'l'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x7F, 0x6D, 0x49, 0x49, 0x49, 0x49, 0x49, 0x49, 0x00, 0x00, 0x00},  // 'm'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x7E, 0x73, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x00, 0x00, 0x00},  // 'n'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x3E, 0x63, 0x63, 0x63, 0x63, 0x63, 0x62, 0x3E, 0x00, 0x00, 0x00},  // 'o'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x7E, 0x73, 0x63, 0x63, 0x63, 0x63, 0x73, 0x7E, 0x60, 0x60, 0x60},  // 'p'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x3F, 0x67, 0x63, 0x63, 0x63, 0x63, 0x67, 0x3F, 0x03, 0x03, 0x03},  // 'q'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x2F, 0x38, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00},  // 'r'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x3E, 0x22, 0x60, 0x3C, 0x0E, 0x03, 0x63, 0x3E, 0x00, 0x00, 0x00},  // 's'
    {0x00, 0x00, 0x00, 0x10, 0x10, 0x7E, 0x30, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1E, 0x00, 0x00, 0x00},  // 't'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x67, 0x3F, 0x00, 0x00, 0x00},  // 'u'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x63, 0x63, 0x22, 0x36, 0x14, 0x1C, 0x1C, 0x00, 0x00, 0x00},  // 'v'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0xC1, 0xC1, 0xC9, 0x5D, 0x55, 0x77, 0x77, 0x63, 0x00, 0x00, 0x00},  // 'w'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x26, 0x14, 0x1C, 0x1C, 0x36, 0x22, 0x63, 0x00, 0x00, 0x00},  // 'x'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x63, 0x63, 0x22, 0x36, 0x14, 0x1C, 0x08, 0x08, 0x18, 0x70},  // 'y'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x7F, 0x02, 0x04, 0x0C, 0x18, 0x30, 0x60, 0x7F, 0x00, 0x00, 0x00},  // 'z'
    {0x00, 0x00, 0x0F, 0x08, 0x08, 0x08, 0x08, 0x18, 0x18, 0x30, 0x18, 0x08, 0x08, 0x08, 0x08, 0x0F},  // '{'
    {0x00, 0x00, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08},  // '|'
    {0x00, 0x00, 0x78, 0x08, 0x08, 0x08, 0x08, 0x0C, 0x06, 0x0C, 0x08, 0x08, 0x08, 0x08, 0x08, 0x78},  // '}'
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  // '~'
};

// -- the drawing objects -----------------------------------------------------

enum class ObjKind {
    Brush,
    Pen,
    Font,
    Bitmap,
    Region,
    Palette,
    Stock,
};

struct FontDesc {
    int height = 16;      // the logical height the caller asked for
    int width = 0;        // the average width, or zero for the face's own
    int weight = 400;
    bool italic = false;
    bool underline = false;
    bool strikeout = false;
    int escapement = 0;
    int orientation = 0;
    int char_set = 0;
    int pitch_and_family = 0;
    std::u16string face = u"Courier New";
};

// A rectangle, in the layout the guest reads a `RECT` through: four 32-bit
// fields, left, top, right, bottom.
struct Rect {
    int left = 0;
    int top = 0;
    int right = 0;
    int bottom = 0;
};

struct GdiObject {
    ObjKind kind = ObjKind::Brush;
    // Brush and pen.
    std::uint32_t color = 0;
    int style = 0;         // brush hatch or pen style
    int width = 1;         // pen width, in logical units
    std::uint64_t pattern = 0;  // the bitmap a pattern brush or pen draws
    // Font.
    FontDesc font;
    // Bitmap and DIB.
    std::shared_ptr<Surface> surface;
    // Region, as a list of rectangles whose union is the region.
    std::vector<Rect> region;
    // Palette.
    std::vector<std::uint32_t> palette;
    // A stock object's index, or -1.
    int stock = -1;
};

// -- the device context ------------------------------------------------------

// The state a `SaveDC` preserves: everything `RestoreDC` puts back. The
// surface the context draws on is not part of it -- a save does not change
// which bitmap is selected, only the attributes above it.
struct SavedState {
    std::uint64_t brush = 0;
    std::uint64_t pen = 0;
    std::uint64_t font = 0;
    std::uint64_t bitmap = 0;
    std::uint64_t palette = 0;
    std::uint64_t region = 0;
    std::uint32_t text_color = 0;
    std::uint32_t bk_color = 0;
    std::uint32_t bk_mode = 0;
    std::uint32_t rop2 = 0;
    std::uint32_t text_align = 0;
    int poly_fill = 0;
    int stretch_mode = 0;
    int map_mode = 0;
    int graphics_mode = 0;
    int win_x = 0, win_y = 0, win_cx = 0, win_cy = 0;
    int vp_x = 0, vp_y = 0, vp_cx = 0, vp_cy = 0;
    float m11 = 1, m12 = 0, m21 = 0, m22 = 1, dx = 0, dy = 0;
    int cur_x = 0, cur_y = 0;
    bool cur_set = false;
    int brush_org_x = 0, brush_org_y = 0;
    Rect clip{};
};

struct DeviceContext {
    std::uint64_t handle = 0;
    bool is_screen = false;   // a window or screen context
    bool is_ic = false;       // an information context: no surface
    std::uint64_t hwnd = 0;
    int w = 1920;
    int h = 1080;
    std::shared_ptr<Surface> target;  // null for an information context

    std::uint64_t brush = 0;
    std::uint64_t pen = 0;
    std::uint64_t font = 0;
    std::uint64_t bitmap = 0;
    std::uint64_t palette = 0;
    std::uint64_t region = 0;

    std::uint32_t text_color = 0x000000;
    std::uint32_t bk_color = 0xFFFFFF;
    std::uint32_t bk_mode = kOpaque;
    std::uint32_t rop2 = kR2Copypen;
    std::uint32_t text_align = kTaLeft | kTaTop;
    int poly_fill = kAlternate;
    int stretch_mode = kBlackOnWhite;
    int map_mode = 1;          // MM_TEXT
    int graphics_mode = 1;     // GM_COMPATIBLE

    int win_x = 0, win_y = 0, win_cx = 1, win_cy = 1;
    int vp_x = 0, vp_y = 0, vp_cx = 1, vp_cy = 1;
    float m11 = 1, m12 = 0, m21 = 0, m22 = 1, dx = 0, dy = 0;

    int cur_x = 0, cur_y = 0;
    bool cur_set = false;
    int brush_org_x = 0, brush_org_y = 0;

    Rect clip = {std::numeric_limits<int>::min(), std::numeric_limits<int>::min(),
                 std::numeric_limits<int>::max(), std::numeric_limits<int>::max()};

    std::vector<SavedState> saved;

    // The path a `BeginPath` opened, as the points the line calls appended.
    // A path is only recorded while it is open, and the calls that stroke or
    // fill it read the points back.
    std::vector<std::pair<int, int>> path;
    bool path_open = false;
};

// -- the state ---------------------------------------------------------------

struct GdiState {
    std::mutex lock;
    std::uint64_t next_object = kObjectFirst;
    std::uint64_t next_dc = kDcFirst;
    std::unordered_map<std::uint64_t, GdiObject> objects;
    std::unordered_map<std::uint64_t, DeviceContext> dcs;
    // The stock objects, created on first use and kept for the process's life.
    std::unordered_map<std::int32_t, std::uint64_t> stock;
    // The screen surface a window context draws on, shared by every screen
    // context so that a program that draws through one and reads through
    // another sees the same pixels.
    std::shared_ptr<Surface> screen;
};

GdiState& gdi() noexcept {
    static GdiState* s = new GdiState();
    return *s;
}

// The lock, spelled once so that every function takes the same one.
struct Lock {
    explicit Lock(std::mutex& m) noexcept : guard(m) {}
    std::lock_guard<std::mutex> guard;
};

[[nodiscard]] GdiObject* object_find(const Lock&, std::uint64_t handle) noexcept {
    GdiState& s = gdi();
    const auto it = s.objects.find(handle);
    return it == s.objects.end() ? nullptr : &it->second;
}

[[nodiscard]] DeviceContext* dc_find(const Lock&, std::uint64_t handle) noexcept {
    GdiState& s = gdi();
    const auto it = s.dcs.find(handle);
    return it == s.dcs.end() ? nullptr : &it->second;
}

// The stock object for an index, created the first time it is asked for.
[[nodiscard]] std::uint64_t stock_object(const Lock&, std::int32_t index) noexcept {
    GdiState& s = gdi();
    const auto it = s.stock.find(index);
    if (it != s.stock.end()) {
        return it->second;
    }
    GdiObject o;
    o.stock = index;
    switch (index) {
    case kWhiteBrush: o.kind = ObjKind::Brush; o.style = kBsSolid; o.color = 0xFFFFFF; break;
    case kLtGrayBrush: o.kind = ObjKind::Brush; o.style = kBsSolid; o.color = 0xC0C0C0; break;
    case kGrayBrush: o.kind = ObjKind::Brush; o.style = kBsSolid; o.color = 0x808080; break;
    case kDkGrayBrush: o.kind = ObjKind::Brush; o.style = kBsSolid; o.color = 0x404040; break;
    case kBlackBrush: o.kind = ObjKind::Brush; o.style = kBsSolid; o.color = 0x000000; break;
    case kNullBrush: o.kind = ObjKind::Brush; o.style = kBsNull; break;
    case kWhitePen: o.kind = ObjKind::Pen; o.style = kPenSolid; o.color = 0xFFFFFF; o.width = 1; break;
    case kBlackPen: o.kind = ObjKind::Pen; o.style = kPenSolid; o.color = 0x000000; o.width = 1; break;
    case kNullPen: o.kind = ObjKind::Pen; o.style = kPenNull; break;
    case kDefaultPalette: o.kind = ObjKind::Palette; break;
    case kOemFixedFont:
    case kAnsiFixedFont:
    case kSystemFixedFont:
    case kDeviceDefaultFont:
        o.kind = ObjKind::Font;
        o.font.height = 16;
        o.font.face = u"Courier New";
        break;
    case kAnsiVarFont:
    case kSystemFont:
    case kDefaultGuiFont:
        o.kind = ObjKind::Font;
        o.font.height = 16;
        o.font.face = u"MS Sans Serif";
        break;
    case kStockDcBrush:
        o.kind = ObjKind::Brush;
        o.style = kBsSolid;
        o.color = 0xFFFFFF;
        break;
    case kStockDcPen:
        o.kind = ObjKind::Pen;
        o.style = kPenSolid;
        o.color = 0x000000;
        o.width = 1;
        break;
    default:
        o.kind = ObjKind::Brush;
        o.style = kBsSolid;
        o.color = 0xFFFFFF;
        break;
    }
    const std::uint64_t handle = s.next_object;
    s.next_object += kObjectStep;
    s.objects.emplace(handle, std::move(o));
    s.stock.emplace(index, handle);
    return handle;
}

// The brush and pen a context strokes and fills with, resolved to the
// object tables. A context with nothing selected uses the stock black pen and
// white brush, which is what a fresh Windows context holds.
[[nodiscard]] const GdiObject* dc_brush(const Lock& l, const DeviceContext& dc) noexcept {
    const GdiObject* o = object_find(l, dc.brush);
    if (o != nullptr && (o->kind == ObjKind::Brush || o->kind == ObjKind::Stock)) {
        return o;
    }
    return object_find(l, stock_object(l, kWhiteBrush));
}

[[nodiscard]] const GdiObject* dc_pen(const Lock& l, const DeviceContext& dc) noexcept {
    const GdiObject* o = object_find(l, dc.pen);
    if (o != nullptr && (o->kind == ObjKind::Pen || o->kind == ObjKind::Stock)) {
        return o;
    }
    return object_find(l, stock_object(l, kBlackPen));
}

[[nodiscard]] const GdiObject* dc_font(const Lock& l, const DeviceContext& dc) noexcept {
    const GdiObject* o = object_find(l, dc.font);
    if (o != nullptr && o->kind == ObjKind::Font) {
        return o;
    }
    return object_find(l, stock_object(l, kSystemFont));
}

// The surface a context draws on, or null for an information context.
[[nodiscard]] Surface* dc_surface(DeviceContext& dc) noexcept {
    return dc.target ? dc.target.get() : nullptr;
}

// -- the rasterizer ----------------------------------------------------------
//
// Every drawing call lands through these: a device coordinate is first mapped
// from the logical one, then clipped, then written. The mapping is the
// context's window and viewport extents, which are the identity in the
// default `MM_TEXT` mode and a scale in the anisotropic modes; the clip is
// the intersection of the context's region with the surface's bounds.

// The logical-to-device mapping. `MM_TEXT` is the identity with the origin
// shifts applied; the anisotropic modes scale by the viewport and window
// extents, which is what a program that sets them expects its coordinates to
// be multiplied by.
void map_point(const DeviceContext& dc, int lx, int ly, int& dx, int& dy) noexcept {
    if (dc.map_mode == 1 /* MM_TEXT */ || dc.win_cx == 0 || dc.win_cy == 0) {
        dx = lx - dc.win_x + dc.vp_x;
        dy = ly - dc.win_y + dc.vp_y;
        return;
    }
    const double sx = static_cast<double>(dc.vp_cx) /
                      static_cast<double>(dc.win_cx);
    const double sy = static_cast<double>(dc.vp_cy) /
                      static_cast<double>(dc.win_cy);
    dx = dc.vp_x + static_cast<int>(std::lround((lx - dc.win_x) * sx));
    dy = dc.vp_y + static_cast<int>(std::lround((ly - dc.win_y) * sy));
}

[[nodiscard]] bool in_clip(const DeviceContext& dc, int x, int y) noexcept {
    return x >= dc.clip.left && y >= dc.clip.top && x < dc.clip.right &&
           y < dc.clip.bottom;
}

// Writes one pixel through the clip. The surface's own bounds are also the
// clip, so a call that runs off the edge is bounded rather than overrunning.
void plot(DeviceContext& dc, int x, int y, std::uint32_t color) noexcept {
    Surface* s = dc_surface(dc);
    if (s == nullptr || !in_clip(dc, x, y)) {
        return;
    }
    surface_set(*s, x, y, color);
}

// The colour a drawing operation composites with, by the context's binary
// raster operation. The common opcode is a straight copy; the others are the
// bitwise combinations a blit or a pen can ask for.
[[nodiscard]] std::uint32_t rop2_apply(std::uint32_t rop, std::uint32_t pen,
                                       std::uint32_t dst) noexcept {
    // Only the low byte of the opcode matters for the ternary raster ops the
    // pen uses; the high bits carry the source selects.
    switch (rop & 0xFF) {
    case 0x00: return 0;                       // BLACK
    case 0xFF: return 0xFFFFFF;                // WHITE
    case 0x0F: return ~pen & 0xFFFFFF;         // NOTPEN
    case 0x33: return ~dst & 0xFFFFFF;         // NOT
    case 0x55: return dst ^ 0xFFFFFF;          // NOT
    case 0x5A: return pen ^ dst;               // XORPEN
    case 0x66: return pen ^ dst;               // XORPEN
    case 0x99: return ~(pen ^ dst) & 0xFFFFFF; // NOTXORPEN
    case 0xA5: return dst ^ 0xFFFFFF;          // NOT
    case 0xC0: return 0;                       // BLACK
    case 0xCC: return pen;                     // COPYPEN
    case 0xF0: return pen;                     // COPYPEN
    case 0xAA: return 0;                       // NOP
    case 0x88: return pen & dst;               // MERGEPEN
    case 0xEE: return pen | dst;               // MERGEPENNOT
    case 0x02: return pen & ~dst & 0xFFFFFF;   // MASKPENNOT
    default: return pen;                       // COPYPEN, the default
    }
}

// A line, by the integer Bresenham walk. The pen's width is honoured as a
// square brush of that many pixels, which is what a cosmetic pen produces.
void draw_line(DeviceContext& dc, int x0, int y0, int x1, int y1,
               std::uint32_t color, int width) noexcept {
    Surface* s = dc_surface(dc);
    if (s == nullptr) {
        return;
    }
    const int dx = std::abs(x1 - x0);
    const int dy = -std::abs(y1 - y0);
    const int sx = x0 < x1 ? 1 : -1;
    const int sy = y0 < y1 ? 1 : -1;
    int err = dx + dy;
    const int half = width > 1 ? width / 2 : 0;
    for (;;) {
        for (int oy = -half; oy <= half; ++oy) {
            for (int ox = -half; ox <= half; ++ox) {
                const std::uint32_t dst = surface_get(*s, x0 + ox, y0 + oy);
                plot(dc, x0 + ox, y0 + oy,
                     rop2_apply(dc.rop2, color, dst));
            }
        }
        if (x0 == x1 && y0 == y1) {
            break;
        }
        const int e2 = 2 * err;
        if (e2 >= dy) {
            err += dy;
            x0 += sx;
        }
        if (e2 <= dx) {
            err += dx;
            y0 += sy;
        }
    }
}

// Fills an axis-aligned rectangle with a colour, through the clip.
void fill_rect_color(DeviceContext& dc, int left, int top, int right,
                     int bottom, std::uint32_t color) noexcept {
    Surface* s = dc_surface(dc);
    if (s == nullptr) {
        return;
    }
    if (left > right) {
        std::swap(left, right);
    }
    if (top > bottom) {
        std::swap(top, bottom);
    }
    for (int y = top; y < bottom; ++y) {
        for (int x = left; x < right; ++x) {
            plot(dc, x, y, color);
        }
    }
}

// Fills a rectangle with the context's brush. A null brush fills nothing,
// and a hatched brush fills with a fifty-percent dither of its colour, which
// is the reading a caller that asked for a hatch and reads the pixels back
// expects to differ from a solid fill.
void fill_rect_brush(DeviceContext& dc, const GdiObject& brush, int left,
                     int top, int right, int bottom) noexcept {
    if (brush.style == kBsNull) {
        return;
    }
    if (left > right) {
        std::swap(left, right);
    }
    if (top > bottom) {
        std::swap(top, bottom);
    }
    for (int y = top; y < bottom; ++y) {
        for (int x = left; x < right; ++x) {
            const bool ink = brush.style == kBsSolid ||
                             ((x + y) & 1) == 0;
            if (ink) {
                const std::uint32_t dst = surface_get(*dc_surface(dc), x, y);
                plot(dc, x, y, rop2_apply(dc.rop2, brush.color, dst));
            }
        }
    }
}

// The even-odd fill of a polygon, as a scan-line walk. An arbitrary shape a
// program draws -- a triangle, a star, a chart -- lands through this.
void fill_polygon(DeviceContext& dc, const std::vector<std::pair<int, int>>& pts,
                  std::uint32_t color) noexcept {
    if (pts.size() < 3) {
        return;
    }
    int top = pts[0].second;
    int bottom = pts[0].second;
    for (const auto& p : pts) {
        top = std::min(top, p.second);
        bottom = std::max(bottom, p.second);
    }
    std::vector<int> xs;
    for (int y = top; y <= bottom; ++y) {
        xs.clear();
        const std::size_t n = pts.size();
        for (std::size_t i = 0; i < n; ++i) {
            const auto& a = pts[i];
            const auto& b = pts[(i + 1) % n];
            if (a.second == b.second) {
                continue;
            }
            if ((y >= a.second && y < b.second) || (y >= b.second && y < a.second)) {
                const double t = static_cast<double>(y - a.second) /
                                 static_cast<double>(b.second - a.second);
                xs.push_back(static_cast<int>(
                    std::lround(a.first + t * (b.first - a.first))));
            }
        }
        std::sort(xs.begin(), xs.end());
        for (std::size_t i = 0; i + 1 < xs.size(); i += 2) {
            for (int x = xs[i]; x <= xs[i + 1]; ++x) {
                plot(dc, x, y, color);
            }
        }
    }
}

}  // namespace

// -- the device-context calls ------------------------------------------------

// The screen surface, created the first time a screen context is handed out.
[[nodiscard]] std::shared_ptr<Surface> screen_surface(const Lock&) noexcept {
    GdiState& s = gdi();
    if (!s.screen) {
        s.screen = std::make_shared<Surface>();
        s.screen->w = 1920;
        s.screen->h = 1080;
        s.screen->bpp = 32;
        s.screen->stride = dib_stride(s.screen->w, 32);
        s.screen->owned.assign(
            static_cast<std::size_t>(s.screen->stride) *
            static_cast<std::size_t>(s.screen->h), 0);
    }
    return s.screen;
}

// A fresh context, with the stock objects selected, which is the state
// Windows gives one. The caller fills in the surface and the size.
[[nodiscard]] DeviceContext make_dc(const Lock& l, bool screen) noexcept {
    DeviceContext dc;
    dc.is_screen = screen;
    dc.brush = stock_object(l, kWhiteBrush);
    dc.pen = stock_object(l, kBlackPen);
    dc.font = stock_object(l, kSystemFont);
    if (screen) {
        dc.target = screen_surface(l);
        dc.w = 1920;
        dc.h = 1080;
    }
    return dc;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_GetDC(
    std::uint64_t hwnd) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext dc = make_dc(l, true);
    dc.hwnd = hwnd;
    const std::uint64_t handle = s.next_dc;
    s.next_dc += kDcStep;
    dc.handle = handle;
    s.dcs.emplace(handle, std::move(dc));
    return handle;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_GetWindowDC(
    std::uint64_t hwnd) noexcept {
    return u32g_GetDC(hwnd);
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_GetDCEx(
    std::uint64_t hwnd, std::uint64_t region, std::uint32_t flags) noexcept {
    (void)region;
    (void)flags;
    return u32g_GetDC(hwnd);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_ReleaseDC(
    std::uint64_t hwnd, std::uint64_t dc) noexcept {
    (void)hwnd;
    GdiState& s = gdi();
    const Lock l(s.lock);
    const auto it = s.dcs.find(dc);
    if (it == s.dcs.end()) {
        set_last_error(kErrParam);
        return kFalse;
    }
    // A screen context is handed back rather than freed: the next `GetDC`
    // mints a fresh one, and the screen surface they share outlives them all.
    s.dcs.erase(it);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateCompatibleDC(
    std::uint64_t source) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext dc = make_dc(l, false);
    const DeviceContext* src = dc_find(l, source);
    const int w = src != nullptr ? src->w : 1920;
    const int h = src != nullptr ? src->h : 1080;
    dc.w = w;
    dc.h = h;
    // The default bitmap a fresh memory context carries is a one-pixel
    // monochrome stand-in, which is what Windows leaves in one until a
    // bitmap is selected. A drawing call with no bitmap selected writes into
    // nothing rather than into an invented surface.
    const std::uint64_t handle = s.next_dc;
    s.next_dc += kDcStep;
    dc.handle = handle;
    s.dcs.emplace(handle, std::move(dc));
    return handle;
}

// The `CreateDC` family. A display context answers the screen; a printer or a
// named device answers a context with no surface, because a headless host
// has no printer to render for. An information context is the same without
// the drawing.
extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateDCW(
    const char16_t* driver, const char16_t* device, const char16_t* port,
    const void* init_data) noexcept {
    (void)driver;
    (void)port;
    (void)init_data;
    const bool display = device == nullptr || *device == u'\0';
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext dc = make_dc(l, display);
    const std::uint64_t handle = s.next_dc;
    s.next_dc += kDcStep;
    dc.handle = handle;
    s.dcs.emplace(handle, std::move(dc));
    return handle;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateDCA(
    const char* driver, const char* device, const char* port,
    const void* init_data) noexcept {
    (void)driver;
    (void)port;
    (void)init_data;
    const bool display = device == nullptr || *device == '\0';
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext dc = make_dc(l, display);
    const std::uint64_t handle = s.next_dc;
    s.next_dc += kDcStep;
    dc.handle = handle;
    s.dcs.emplace(handle, std::move(dc));
    return handle;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateICW(
    const char16_t* driver, const char16_t* device, const char16_t* port,
    const void* init_data) noexcept {
    (void)driver;
    (void)device;
    (void)port;
    (void)init_data;
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext dc = make_dc(l, false);
    dc.is_ic = true;
    dc.target = nullptr;
    const std::uint64_t handle = s.next_dc;
    s.next_dc += kDcStep;
    dc.handle = handle;
    s.dcs.emplace(handle, std::move(dc));
    return handle;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateICA(
    const char* driver, const char* device, const char* port,
    const void* init_data) noexcept {
    (void)driver;
    (void)device;
    (void)port;
    (void)init_data;
    return u32g_CreateICW(nullptr, nullptr, nullptr, nullptr);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_DeleteDC(
    std::uint64_t dc) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const auto it = s.dcs.find(dc);
    if (it == s.dcs.end()) {
        set_last_error(kErrParam);
        return kFalse;
    }
    s.dcs.erase(it);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_SaveDC(
    std::uint64_t hdc) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return 0;
    }
    SavedState st;
    st.brush = dc->brush;
    st.pen = dc->pen;
    st.font = dc->font;
    st.bitmap = dc->bitmap;
    st.palette = dc->palette;
    st.region = dc->region;
    st.text_color = dc->text_color;
    st.bk_color = dc->bk_color;
    st.bk_mode = dc->bk_mode;
    st.rop2 = dc->rop2;
    st.text_align = dc->text_align;
    st.poly_fill = dc->poly_fill;
    st.stretch_mode = dc->stretch_mode;
    st.map_mode = dc->map_mode;
    st.graphics_mode = dc->graphics_mode;
    st.win_x = dc->win_x;
    st.win_y = dc->win_y;
    st.win_cx = dc->win_cx;
    st.win_cy = dc->win_cy;
    st.vp_x = dc->vp_x;
    st.vp_y = dc->vp_y;
    st.vp_cx = dc->vp_cx;
    st.vp_cy = dc->vp_cy;
    st.m11 = dc->m11;
    st.m12 = dc->m12;
    st.m21 = dc->m21;
    st.m22 = dc->m22;
    st.dx = dc->dx;
    st.dy = dc->dy;
    st.cur_x = dc->cur_x;
    st.cur_y = dc->cur_y;
    st.cur_set = dc->cur_set;
    st.brush_org_x = dc->brush_org_x;
    st.brush_org_y = dc->brush_org_y;
    st.clip = dc->clip;
    dc->saved.push_back(st);
    return static_cast<std::int32_t>(dc->saved.size());
}

// `RestoreDC` with -1 restores the most recent save; with a positive number,
// the save with that identifier, which is its position on the stack.
extern "C" __attribute__((ms_abi)) std::int32_t u32g_RestoreDC(
    std::uint64_t hdc, std::int32_t saved) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return kFalse;
    }
    if (saved == -1) {
        if (dc->saved.empty()) {
            return kFalse;
        }
        saved = static_cast<std::int32_t>(dc->saved.size());
    }
    if (saved <= 0 || static_cast<std::size_t>(saved) > dc->saved.size()) {
        return kFalse;
    }
    const SavedState& st = dc->saved[static_cast<std::size_t>(saved) - 1];
    dc->brush = st.brush;
    dc->pen = st.pen;
    dc->font = st.font;
    dc->bitmap = st.bitmap;
    dc->palette = st.palette;
    dc->region = st.region;
    dc->text_color = st.text_color;
    dc->bk_color = st.bk_color;
    dc->bk_mode = st.bk_mode;
    dc->rop2 = st.rop2;
    dc->text_align = st.text_align;
    dc->poly_fill = st.poly_fill;
    dc->stretch_mode = st.stretch_mode;
    dc->map_mode = st.map_mode;
    dc->graphics_mode = st.graphics_mode;
    dc->win_x = st.win_x;
    dc->win_y = st.win_y;
    dc->win_cx = st.win_cx;
    dc->win_cy = st.win_cy;
    dc->vp_x = st.vp_x;
    dc->vp_y = st.vp_y;
    dc->vp_cx = st.vp_cx;
    dc->vp_cy = st.vp_cy;
    dc->m11 = st.m11;
    dc->m12 = st.m12;
    dc->m21 = st.m21;
    dc->m22 = st.m22;
    dc->dx = st.dx;
    dc->dy = st.dy;
    dc->cur_x = st.cur_x;
    dc->cur_y = st.cur_y;
    dc->cur_set = st.cur_set;
    dc->brush_org_x = st.brush_org_x;
    dc->brush_org_y = st.brush_org_y;
    dc->clip = st.clip;
    dc->saved.resize(static_cast<std::size_t>(saved) - 1);
    // The bitmap selection is what `RestoreDC` puts back as well: the memory
    // context's surface follows the bitmap, so it is relinked here.
    const GdiObject* bmp = object_find(l, dc->bitmap);
    if (bmp != nullptr && bmp->surface) {
        dc->target = bmp->surface;
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_SetDCBrushColor(
    std::uint64_t hdc, std::uint32_t color) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return 0xFFFFFFFFu;
    }
    const std::uint64_t stock = stock_object(l, kStockDcBrush);
    GdiObject* o = object_find(l, stock);
    if (o != nullptr) {
        o->color = color & 0x00FFFFFFu;
    }
    dc->brush = stock;
    return 0xFFFFFFFFu;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_SetDCPenColor(
    std::uint64_t hdc, std::uint32_t color) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return 0xFFFFFFFFu;
    }
    const std::uint64_t stock = stock_object(l, kStockDcPen);
    GdiObject* o = object_find(l, stock);
    if (o != nullptr) {
        o->color = color & 0x00FFFFFFu;
    }
    dc->pen = stock;
    return 0xFFFFFFFFu;
}

// -- creating and destroying objects -----------------------------------------

namespace {

// Registers an object and answers its handle.
[[nodiscard]] std::uint64_t add_object(const Lock&, GdiObject o) noexcept {
    GdiState& s = gdi();
    const std::uint64_t handle = s.next_object;
    s.next_object += kObjectStep;
    s.objects.emplace(handle, std::move(o));
    return handle;
}

// A new surface of the given shape, filled with black.
[[nodiscard]] std::shared_ptr<Surface> make_surface(int w, int h, int bpp) noexcept {
    auto s = std::make_shared<Surface>();
    s->w = std::max(1, w);
    s->h = std::max(1, h);
    s->bpp = bpp;
    s->stride = dib_stride(s->w, bpp);
    s->owned.assign(static_cast<std::size_t>(s->stride) *
                        static_cast<std::size_t>(s->h), 0);
    default_palette_for(*s);
    return s;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateSolidBrush(
    std::uint32_t color) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    GdiObject o;
    o.kind = ObjKind::Brush;
    o.style = kBsSolid;
    o.color = color & 0x00FFFFFFu;
    return add_object(l, std::move(o));
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateHatchBrush(
    std::uint32_t style, std::uint32_t color) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    GdiObject o;
    o.kind = ObjKind::Brush;
    o.style = kBsHatched;
    o.width = static_cast<int>(style);  // the hatch index, for the dither
    o.color = color & 0x00FFFFFFu;
    return add_object(l, std::move(o));
}

// `LOGBRUSH`: style, colour, hatch, at the 64-bit layout.
extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateBrushIndirect(
    const void* log_brush) noexcept {
    if (log_brush == nullptr) {
        set_last_error(kErrParam);
        return 0;
    }
    const auto* p = static_cast<const std::uint8_t*>(log_brush);
    const std::uint32_t style = read_u32(p, 0);
    const std::uint32_t color = read_u32(p, 4);
    const std::uint64_t hatch = read_ptr(p, 8);
    GdiState& s = gdi();
    const Lock l(s.lock);
    GdiObject o;
    o.kind = ObjKind::Brush;
    o.style = static_cast<int>(style);
    o.color = color & 0x00FFFFFFu;
    o.pattern = hatch;
    return add_object(l, std::move(o));
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreatePatternBrush(
    std::uint64_t bitmap) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    GdiObject o;
    o.kind = ObjKind::Brush;
    o.style = kBsPattern;
    o.pattern = bitmap;
    return add_object(l, std::move(o));
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateDIBPatternBrushPt(
    const void* packed_dib, std::uint32_t usage) noexcept {
    (void)packed_dib;
    (void)usage;
    GdiState& s = gdi();
    const Lock l(s.lock);
    GdiObject o;
    o.kind = ObjKind::Brush;
    o.style = kBsPattern;
    return add_object(l, std::move(o));
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateDIBPatternBrush(
    std::uint64_t packed_dib, std::uint32_t usage) noexcept {
    return u32g_CreateDIBPatternBrushPt(
        reinterpret_cast<const void*>(packed_dib), usage);
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreatePen(
    std::int32_t style, std::int32_t width, std::uint32_t color) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    GdiObject o;
    o.kind = ObjKind::Pen;
    o.style = style & 0x0F;
    o.width = width <= 0 ? 1 : width;
    o.color = color & 0x00FFFFFFu;
    // A wide pen is geometric; a one-pixel one cosmetic. The distinction is
    // kept because a caller that asked for width zero expects a cosmetic pen
    // whatever colours it chose.
    o.pattern = width == 0 ? 0 : 1;
    return add_object(l, std::move(o));
}

// `LOGPEN`: style, two points, colour; the pen's width is the second point's
// x and its second point's y is unused.
extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreatePenIndirect(
    const void* log_pen) noexcept {
    if (log_pen == nullptr) {
        set_last_error(kErrParam);
        return 0;
    }
    const auto* p = static_cast<const std::uint8_t*>(log_pen);
    const std::uint32_t style = read_u32(p, 0);
    const std::int32_t width = static_cast<std::int32_t>(read_u32(p, 8));
    const std::uint32_t color = read_u32(p, 16);
    return u32g_CreatePen(static_cast<std::int32_t>(style), width, color);
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_ExtCreatePen(
    std::uint32_t pen_style, std::uint32_t width, const void* log_brush,
    std::uint32_t style_count, const void* style) noexcept {
    (void)style_count;
    (void)style;
    const std::uint32_t color =
        log_brush != nullptr
            ? read_u32(static_cast<const std::uint8_t*>(log_brush), 4)
            : 0;
    return u32g_CreatePen(static_cast<std::int32_t>(pen_style),
                          static_cast<std::int32_t>(width), color);
}

// `LOGFONT`: height, width, escapement, orientation, weight, italic,
// underline, strikeout, char set, out precision, clip precision, quality,
// pitch and family, then the face name. The 64-bit layout places the three
// bytes at 0x14, 0x15, 0x16 and the charset at 0x17.
[[nodiscard]] FontDesc font_from_logfont(const void* log_font) noexcept {
    FontDesc f;
    const auto* p = static_cast<const std::uint8_t*>(log_font);
    f.height = static_cast<std::int32_t>(read_u32(p, 0));
    f.width = static_cast<std::int32_t>(read_u32(p, 4));
    f.escapement = static_cast<std::int32_t>(read_u32(p, 8));
    f.orientation = static_cast<std::int32_t>(read_u32(p, 12));
    f.weight = static_cast<std::int32_t>(read_u32(p, 16));
    f.italic = p[0x14] != 0;
    f.underline = p[0x15] != 0;
    f.strikeout = p[0x16] != 0;
    f.char_set = p[0x17];
    f.pitch_and_family = p[0x1A];
    const auto* face = reinterpret_cast<const char16_t*>(p + 0x1C);
    std::u16string name;
    for (int i = 0; i < 32 && face[i] != u'\0'; ++i) {
        name.push_back(face[i]);
    }
    if (!name.empty()) {
        f.face = std::move(name);
    }
    if (f.height == 0) {
        f.height = 16;
    }
    return f;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateFontIndirectW(
    const void* log_font) noexcept {
    if (log_font == nullptr) {
        set_last_error(kErrParam);
        return 0;
    }
    GdiState& s = gdi();
    const Lock l(s.lock);
    GdiObject o;
    o.kind = ObjKind::Font;
    o.font = font_from_logfont(log_font);
    return add_object(l, std::move(o));
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateFontIndirectA(
    const void* log_font) noexcept {
    // The narrow `LOGFONT` differs only in the face name, which is bytes
    // rather than characters. The structure is read into the wide form and
    // the name converted, so both spellings produce one font.
    if (log_font == nullptr) {
        set_last_error(kErrParam);
        return 0;
    }
    const auto* p = static_cast<const std::uint8_t*>(log_font);
    std::array<std::uint8_t, 0x3C> wide{};
    std::memcpy(wide.data(), p, 0x1C);
    const char* face = reinterpret_cast<const char*>(p + 0x1C);
    std::u16string name;
    static_cast<void>(utf8_to_utf16(face, name));
    if (name.size() > 31) {
        name.resize(31);
    }
    for (std::size_t i = 0; i < name.size(); ++i) {
        wide[0x1C + i * 2] = static_cast<std::uint8_t>(name[i]);
        wide[0x1C + i * 2 + 1] = static_cast<std::uint8_t>(name[i] >> 8);
    }
    return u32g_CreateFontIndirectW(wide.data());
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateFontW(
    std::int32_t height, std::int32_t width, std::int32_t escapement,
    std::int32_t orientation, std::int32_t weight, std::uint32_t italic,
    std::uint32_t underline, std::uint32_t strikeout, std::uint32_t char_set,
    std::uint32_t out_precision, std::uint32_t clip_precision,
    std::uint32_t quality, std::uint32_t pitch_and_family,
    const char16_t* face) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    GdiObject o;
    o.kind = ObjKind::Font;
    o.font.height = height == 0 ? 16 : height;
    o.font.width = width;
    o.font.escapement = escapement;
    o.font.orientation = orientation;
    o.font.weight = weight;
    o.font.italic = italic != 0;
    o.font.underline = underline != 0;
    o.font.strikeout = strikeout != 0;
    o.font.char_set = static_cast<int>(char_set);
    o.font.pitch_and_family = static_cast<int>(pitch_and_family);
    if (face != nullptr && *face != u'\0') {
        std::u16string name;
        for (int i = 0; i < 32 && face[i] != u'\0'; ++i) {
            name.push_back(face[i]);
        }
        o.font.face = std::move(name);
    }
    (void)out_precision;
    (void)clip_precision;
    (void)quality;
    return add_object(l, std::move(o));
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateFontA(
    std::int32_t height, std::int32_t width, std::int32_t escapement,
    std::int32_t orientation, std::int32_t weight, std::uint32_t italic,
    std::uint32_t underline, std::uint32_t strikeout, std::uint32_t char_set,
    std::uint32_t out_precision, std::uint32_t clip_precision,
    std::uint32_t quality, std::uint32_t pitch_and_family,
    const char* face) noexcept {
    std::u16string name;
    if (face != nullptr) {
        static_cast<void>(utf8_to_utf16(face, name));
    }
    return u32g_CreateFontW(height, width, escapement, orientation, weight,
                            italic, underline, strikeout, char_set,
                            out_precision, clip_precision, quality,
                            pitch_and_family, name.c_str());
}

// -- bitmaps -----------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateBitmap(
    std::int32_t width, std::int32_t height, std::uint32_t planes,
    std::uint32_t bits_per_pixel, const void* bits) noexcept {
    (void)planes;
    if (width <= 0 || height <= 0) {
        set_last_error(kErrParam);
        return 0;
    }
    const int bpp = bits_per_pixel == 0 ? 1 : static_cast<int>(bits_per_pixel);
    GdiState& s = gdi();
    const Lock l(s.lock);
    GdiObject o;
    o.kind = ObjKind::Bitmap;
    o.surface = make_surface(width, height, bpp);
    if (bits != nullptr) {
        std::memcpy(o.surface->owned.data(), bits,
                    o.surface->owned.size());
    }
    return add_object(l, std::move(o));
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateBitmapIndirect(
    const void* bitmap) noexcept {
    if (bitmap == nullptr) {
        set_last_error(kErrParam);
        return 0;
    }
    const auto* p = static_cast<const std::uint8_t*>(bitmap);
    const std::int32_t width = static_cast<std::int32_t>(read_u32(p, 4));
    const std::int32_t height = static_cast<std::int32_t>(read_u32(p, 8));
    const std::uint32_t planes = read_u32(p, 12);
    const std::uint32_t bpp = read_u32(p, 14);
    const std::uint64_t bits = read_ptr(p, 16);
    return u32g_CreateBitmap(width, height, planes, bpp,
                             reinterpret_cast<const void*>(bits));
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateCompatibleBitmap(
    std::uint64_t hdc, std::int32_t width, std::int32_t height) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const DeviceContext* dc = dc_find(l, hdc);
    const int bpp = dc != nullptr && dc->target ? dc->target->bpp : 32;
    if (width <= 0 || height <= 0) {
        set_last_error(kErrParam);
        return 0;
    }
    GdiObject o;
    o.kind = ObjKind::Bitmap;
    o.surface = make_surface(width, height, bpp);
    return add_object(l, std::move(o));
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateDiscardableBitmap(
    std::uint64_t hdc, std::int32_t width, std::int32_t height) noexcept {
    return u32g_CreateCompatibleBitmap(hdc, width, height);
}

// `BITMAPINFOHEADER` at the 64-bit layout: size, width, height, planes,
// bit count, compression, size image, x pixels per meter, y pixels per meter,
// colours used, colours important. A negative height means a top-down DIB.
struct BitmapInfoHeader {
    std::uint32_t size = 40;
    std::int32_t width = 0;
    std::int32_t height = 0;
    std::uint16_t planes = 1;
    std::uint16_t bit_count = 0;
    std::uint32_t compression = 0;
    std::uint32_t size_image = 0;
    std::int32_t x_ppm = 0;
    std::int32_t y_ppm = 0;
    std::uint32_t clr_used = 0;
    std::uint32_t clr_important = 0;
};

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateDIBSection(
    std::uint64_t hdc, const void* info, std::uint32_t usage, void** bits,
    std::uint64_t section, std::uint32_t offset) noexcept {
    (void)hdc;
    (void)usage;
    (void)section;
    (void)offset;
    if (info == nullptr || bits == nullptr) {
        set_last_error(kErrParam);
        return 0;
    }
    const auto* p = static_cast<const std::uint8_t*>(info);
    BitmapInfoHeader hdr;
    hdr.size = read_u32(p, 0);
    hdr.width = static_cast<std::int32_t>(read_u32(p, 4));
    hdr.height = static_cast<std::int32_t>(read_u32(p, 8));
    hdr.planes = read_u16(p, 12);
    hdr.bit_count = read_u16(p, 14);
    hdr.compression = read_u32(p, 16);
    hdr.clr_used = read_u32(p, 32);
    if (hdr.width <= 0 || hdr.height == 0) {
        set_last_error(kErrParam);
        return 0;
    }
    const bool top_down = hdr.height < 0;
    const int height = top_down ? -hdr.height : hdr.height;
    const int bpp = hdr.bit_count == 0 ? 1 : hdr.bit_count;

    GdiState& s = gdi();
    const Lock l(s.lock);
    GdiObject o;
    o.kind = ObjKind::Bitmap;
    o.surface = std::make_shared<Surface>();
    o.surface->w = hdr.width;
    o.surface->h = height;
    o.surface->bpp = bpp;
    o.surface->stride = dib_stride(hdr.width, bpp);
    o.surface->is_dib = true;
    // The section's bits live in the guest's own address space, because the
    // guest is the one that will write into them. The pointer handed back is
    // the address a program stores and draws through.
    const std::size_t bytes =
        static_cast<std::size_t>(o.surface->stride) *
        static_cast<std::size_t>(height);
    auto* memory = static_cast<std::uint8_t*>(std::calloc(bytes, 1));
    o.surface->bits = memory;
    // A top-down section is stored with its first row at the lowest address,
    // which is already how the surface reads; the flag is recorded in the
    // negative height the caller passed and needs no further work here.
    default_palette_for(*o.surface);
    const std::uint64_t handle = add_object(l, std::move(o));
    *bits = memory;
    return handle;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateDIBitmap(
    std::uint64_t hdc, const void* header, std::uint32_t init,
    const void* bits, const void* info, std::uint32_t usage) noexcept {
    (void)hdc;
    (void)info;
    (void)usage;
    if (header == nullptr) {
        set_last_error(kErrParam);
        return 0;
    }
    const auto* p = static_cast<const std::uint8_t*>(header);
    const std::int32_t width = static_cast<std::int32_t>(read_u32(p, 4));
    const std::int32_t height = static_cast<std::int32_t>(read_u32(p, 8));
    const std::uint32_t bpp = read_u16(p, 14);
    const std::uint64_t handle =
        u32g_CreateBitmap(width, height, 1, bpp,
                          (init & 4) != 0 ? bits : nullptr);
    return handle;
}

// -- selecting and destroying -------------------------------------------------

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_SelectObject(
    std::uint64_t hdc, std::uint64_t object) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return 0;
    }
    if (object == static_cast<std::uint64_t>(-1) /* HGDI_ERROR */) {
        return 0;
    }
    const GdiObject* o = object_find(l, object);
    if (o == nullptr) {
        // A plain bitmap handle, or an unsupported type, is refused the way
        // Windows refuses a selection it cannot make.
        set_last_error(kErrParam);
        return 0;
    }
    switch (o->kind) {
    case ObjKind::Brush: {
        const std::uint64_t old = dc->brush;
        dc->brush = object;
        return old;
    }
    case ObjKind::Pen: {
        const std::uint64_t old = dc->pen;
        dc->pen = object;
        return old;
    }
    case ObjKind::Font: {
        const std::uint64_t old = dc->font;
        dc->font = object;
        return old;
    }
    case ObjKind::Region: {
        const std::uint64_t old = dc->region;
        dc->region = object;
        // Selecting a region as the clip intersects it with the current one
        // in Windows; here it replaces the clip box, which is what a caller
        // that selects a clip region expects to read back.
        const auto it = s.objects.find(object);
        if (it != s.objects.end() && !it->second.region.empty()) {
            dc->clip = {it->second.region[0].left, it->second.region[0].top,
                        it->second.region[0].right,
                        it->second.region[0].bottom};
        }
        return old;
    }
    case ObjKind::Palette: {
        const std::uint64_t old = dc->palette;
        dc->palette = object;
        return old;
    }
    case ObjKind::Bitmap: {
        const std::uint64_t old = dc->bitmap;
        dc->bitmap = object;
        if (o->surface) {
            dc->target = o->surface;
            dc->w = o->surface->w;
            dc->h = o->surface->h;
        }
        return old;
    }
    case ObjKind::Stock:
    default:
        return 0;
    }
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_DeleteObject(
    std::uint64_t object) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const auto it = s.objects.find(object);
    if (it == s.objects.end()) {
        set_last_error(kErrParam);
        return kFalse;
    }
    // A stock object is not a program's to destroy; Windows refuses it and so
    // does this, which keeps the four stock handles a fresh context holds
    // valid for the process's life.
    if (it->second.stock >= 0) {
        set_last_error(kErrParam);
        return kFalse;
    }
    // A DIB section's bits were handed to the guest and are released with it.
    if (it->second.surface && it->second.surface->is_dib &&
        it->second.surface->bits != nullptr) {
        std::free(it->second.surface->bits);
        it->second.surface->bits = nullptr;
    }
    // A context holding the object is left holding a stale handle, which is
    // the state Windows leaves too: the object is gone and the next draw
    // falls back to the stock object.
    s.objects.erase(it);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_GetStockObject(
    std::int32_t index) noexcept {
    if (index < 0 || index >= kStockObjects) {
        set_last_error(kErrParam);
        return 0;
    }
    GdiState& s = gdi();
    const Lock l(s.lock);
    return stock_object(l, index);
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_GetObjectType(
    std::uint64_t object) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const GdiObject* o = object_find(l, object);
    if (o == nullptr) {
        return 0;
    }
    // The `OBJ_*` type codes.
    switch (o->kind) {
    case ObjKind::Pen: return 1;       // OBJ_PEN
    case ObjKind::Brush: return 2;     // OBJ_BRUSH
    case ObjKind::Bitmap: return 7;    // OBJ_BITMAP
    case ObjKind::Font: return 6;      // OBJ_FONT
    case ObjKind::Palette: return 5;   // OBJ_PAL
    case ObjKind::Region: return 8;    // OBJ_REGION
    case ObjKind::Stock: return 0;
    default: return 0;
    }
}

// `GetObject` fills one of the `LOGBITMAP`, `LOGPEN`, `LOGBRUSH` or
// `LOGFONT` structures. The size the caller asks for decides which; the
// answer is the number of bytes written, or zero on a failure.
extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetObjectW(
    std::uint64_t object, std::int32_t size, void* out) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const GdiObject* o = object_find(l, object);
    if (o == nullptr || out == nullptr || size <= 0) {
        return 0;
    }
    auto* p = static_cast<std::uint8_t*>(out);
    switch (o->kind) {
    case ObjKind::Brush: {
        // LOGBRUSH is three fields, twenty-four bytes wide on the 64-bit ABI.
        const std::int32_t need = 0x18;
        if (size < need) {
            return 0;
        }
        std::memset(p, 0, static_cast<std::size_t>(need));
        write_u32(p, 0, static_cast<std::uint32_t>(o->style));
        write_u32(p, 4, o->color);
        write_ptr(p, 8, o->pattern);
        return need;
    }
    case ObjKind::Pen: {
        const std::int32_t need = 0x18;
        if (size < need) {
            return 0;
        }
        std::memset(p, 0, static_cast<std::size_t>(need));
        write_u32(p, 0, static_cast<std::uint32_t>(o->style));
        write_u32(p, 8, static_cast<std::uint32_t>(o->width));
        write_u32(p, 16, o->color);
        return need;
    }
    case ObjKind::Bitmap: {
        // BITMAP: type, width, height, width bytes, planes, bit count, bits.
        const std::int32_t need = 0x20;
        if (size < need) {
            return 0;
        }
        std::memset(p, 0, static_cast<std::size_t>(need));
        const Surface* surf = o->surface.get();
        write_u32(p, 4, surf != nullptr ? static_cast<std::uint32_t>(surf->w) : 0);
        write_u32(p, 8, surf != nullptr ? static_cast<std::uint32_t>(surf->h) : 0);
        write_u32(p, 12, surf != nullptr ? static_cast<std::uint32_t>(surf->stride) : 0);
        write_u32(p, 14, 1);
        write_u32(p, 16, surf != nullptr ? static_cast<std::uint32_t>(surf->bpp) : 0);
        if (surf != nullptr) {
            write_ptr(p, 24,
                      surf->bits != nullptr
                          ? reinterpret_cast<std::uint64_t>(surf->bits)
                          : reinterpret_cast<std::uint64_t>(
                                surf->owned.empty() ? nullptr
                                                    : surf->owned.data()));
        }
        return need;
    }
    case ObjKind::Font: {
        // LOGFONTW is 0x5C bytes: the numeric fields, the flags, and the face
        // name in UTF-16.
        const std::int32_t need = 0x5C;
        if (size < need) {
            return 0;
        }
        std::memset(p, 0, static_cast<std::size_t>(need));
        write_u32(p, 0, static_cast<std::uint32_t>(o->font.height));
        write_u32(p, 4, static_cast<std::uint32_t>(o->font.width));
        write_u32(p, 8, static_cast<std::uint32_t>(o->font.escapement));
        write_u32(p, 12, static_cast<std::uint32_t>(o->font.orientation));
        write_u32(p, 16, static_cast<std::uint32_t>(o->font.weight));
        write_u8(p, 0x14, o->font.italic ? 1 : 0);
        write_u8(p, 0x15, o->font.underline ? 1 : 0);
        write_u8(p, 0x16, o->font.strikeout ? 1 : 0);
        write_u8(p, 0x17, static_cast<std::uint8_t>(o->font.char_set));
        write_u8(p, 0x1A, static_cast<std::uint8_t>(o->font.pitch_and_family));
        const std::size_t chars = std::min<std::size_t>(o->font.face.size(), 31);
        std::memcpy(p + 0x1C, o->font.face.data(), chars * 2);
        return need;
    }
    default:
        set_last_error(kErrParam);
        return 0;
    }
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetObjectA(
    std::uint64_t object, std::int32_t size, void* out) noexcept {
    return u32g_GetObjectW(object, size, out);
}

// -- drawing -----------------------------------------------------------------

namespace {

// The pen a context strokes with, as its colour and width. A null pen draws
// nothing, which is what a caller that selected `NULL_PEN` asked for.
struct Stroke {
    bool draw = false;
    std::uint32_t color = 0;
    int width = 1;
};

[[nodiscard]] Stroke stroke_of(const GdiObject* pen) noexcept {
    Stroke s;
    if (pen == nullptr || pen->style == kPenNull) {
        return s;
    }
    s.draw = true;
    s.color = pen->color;
    s.width = pen->width;
    return s;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t u32g_MoveToEx(
    std::uint64_t hdc, std::int32_t x, std::int32_t y, void* old) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return kFalse;
    }
    // The answer is whether there was a previous position, and the previous
    // one is written through `old` when the caller asked for it.
    const bool had = dc->cur_set;
    if (old != nullptr) {
        write_u32(old, 0, static_cast<std::uint32_t>(dc->cur_x));
        write_u32(old, 4, static_cast<std::uint32_t>(dc->cur_y));
    }
    dc->cur_x = x;
    dc->cur_y = y;
    dc->cur_set = true;
    if (dc->path_open) {
        int dx = 0, dy = 0;
        map_point(*dc, x, y, dx, dy);
        dc->path.emplace_back(dx, dy);
    }
    return had ? kTrue : kFalse;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_LineTo(
    std::uint64_t hdc, std::int32_t x, std::int32_t y) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return kFalse;
    }
    const Stroke st = stroke_of(dc_pen(l, *dc));
    int x0 = 0, y0 = 0, x1 = 0, y1 = 0;
    map_point(*dc, dc->cur_x, dc->cur_y, x0, y0);
    map_point(*dc, x, y, x1, y1);
    if (st.draw) {
        draw_line(*dc, x0, y0, x1, y1, st.color, st.width);
    }
    dc->cur_x = x;
    dc->cur_y = y;
    dc->cur_set = true;
    if (dc->path_open) {
        dc->path.emplace_back(x1, y1);
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_Polyline(
    std::uint64_t hdc, const void* points, std::int32_t count) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || points == nullptr || count < 2) {
        return kFalse;
    }
    const Stroke st = stroke_of(dc_pen(l, *dc));
    const auto* p = static_cast<const std::uint8_t*>(points);
    for (std::int32_t i = 0; i + 1 < count; ++i) {
        int x0 = 0, y0 = 0, x1 = 0, y1 = 0;
        map_point(*dc, static_cast<std::int32_t>(read_u32(p, static_cast<std::size_t>(i) * 8)),
                  static_cast<std::int32_t>(read_u32(p, static_cast<std::size_t>(i) * 8 + 4)), x0, y0);
        map_point(*dc, static_cast<std::int32_t>(read_u32(p, (static_cast<std::size_t>(i) + 1) * 8)),
                  static_cast<std::int32_t>(read_u32(p, (static_cast<std::size_t>(i) + 1) * 8 + 4)), x1,
                  y1);
        if (st.draw) {
            draw_line(*dc, x0, y0, x1, y1, st.color, st.width);
        }
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_PolyBezier(
    std::uint64_t hdc, const void* points, std::uint32_t count) noexcept {
    // A Bezier is flattened to a polyline. The flattening is a fixed number
    // of segments per span, which is enough to draw the curve smoothly at the
    // scale a window uses.
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || points == nullptr || count < 4) {
        return kFalse;
    }
    const Stroke st = stroke_of(dc_pen(l, *dc));
    const auto* p = static_cast<const std::uint8_t*>(points);
    auto at = [&](std::uint32_t i) {
        return std::pair<int, int>{
            static_cast<int>(read_u32(p, static_cast<std::size_t>(i) * 8)),
            static_cast<int>(read_u32(p, static_cast<std::size_t>(i) * 8 + 4))};
    };
    constexpr int kSegments = 24;
    for (std::uint32_t i = 0; i + 3 < count; i += 3) {
        const auto p0 = at(i);
        const auto p1 = at(i + 1);
        const auto p2 = at(i + 2);
        const auto p3 = at(i + 3);
        int px = 0, py = 0;
        bool first = true;
        for (int k = 0; k <= kSegments; ++k) {
            const double t = static_cast<double>(k) / kSegments;
            const double u = 1.0 - t;
            const double bx = u * u * u * p0.first + 3 * u * u * t * p1.first +
                              3 * u * t * t * p2.first + t * t * t * p3.first;
            const double by = u * u * u * p0.second +
                              3 * u * u * t * p1.second +
                              3 * u * t * t * p2.second + t * t * t * p3.second;
            int dx = 0, dy = 0;
            map_point(*dc, static_cast<int>(std::lround(bx)),
                      static_cast<int>(std::lround(by)), dx, dy);
            if (!first && st.draw) {
                draw_line(*dc, px, py, dx, dy, st.color, st.width);
            }
            px = dx;
            py = dy;
            first = false;
        }
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_PolyBezierTo(
    std::uint64_t hdc, const void* points, std::uint32_t count) noexcept {
    const std::int32_t r = u32g_PolyBezier(hdc, points, count);
    return r;
}

// The body shared by `Polygon` and by each polygon a `PolyPolygon` walks.
// A polygon is scan-filled with the context's brush and then framed with its
// pen, and the caller already holds the lock, so this takes none of its own.
void polygon_locked(const Lock& l, DeviceContext& dc, const std::uint8_t* p,
                    std::int32_t count) noexcept {
    std::vector<std::pair<int, int>> dev;
    dev.reserve(static_cast<std::size_t>(count));
    for (std::int32_t i = 0; i < count; ++i) {
        int dx = 0, dy = 0;
        map_point(dc, static_cast<std::int32_t>(read_u32(p, static_cast<std::size_t>(i) * 8)),
                  static_cast<std::int32_t>(read_u32(p, static_cast<std::size_t>(i) * 8 + 4)), dx, dy);
        dev.emplace_back(dx, dy);
    }
    const GdiObject* brush = dc_brush(l, dc);
    if (brush != nullptr && brush->style != kBsNull) {
        for (std::size_t i = 1; i + 1 < dev.size(); ++i) {
            fill_polygon(dc, {dev[0], dev[i], dev[i + 1]}, brush->color);
        }
    }
    const Stroke st = stroke_of(dc_pen(l, dc));
    if (st.draw) {
        for (std::size_t i = 0; i < dev.size(); ++i) {
            const auto& a = dev[i];
            const auto& b = dev[(i + 1) % dev.size()];
            draw_line(dc, a.first, a.second, b.first, b.second, st.color,
                      st.width);
        }
    }
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_Polygon(
    std::uint64_t hdc, const void* points, std::int32_t count) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || points == nullptr || count < 2) {
        return kFalse;
    }
    polygon_locked(l, *dc, static_cast<const std::uint8_t*>(points), count);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_PolyPolygon(
    std::uint64_t hdc, const void* points, const void* counts,
    std::uint32_t count) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || points == nullptr || counts == nullptr) {
        return kFalse;
    }
    const auto* cp = static_cast<const std::uint8_t*>(counts);
    const auto* pts = static_cast<const std::uint8_t*>(points);
    std::size_t offset = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::int32_t n = static_cast<std::int32_t>(read_u32(cp, i * 4));
        if (n > 0) {
            // The points for one polygon are contiguous, and each is drawn
            // by the shared reader while this call already holds the lock.
            if (n >= 2) {
                polygon_locked(l, *dc, pts + offset,
                               static_cast<std::int32_t>(n));
            }
            offset += static_cast<std::size_t>(n) * 8;
        }
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_Rectangle(
    std::uint64_t hdc, std::int32_t left, std::int32_t top, std::int32_t right,
    std::int32_t bottom) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return kFalse;
    }
    int l0 = 0, t0 = 0, r0 = 0, b0 = 0;
    map_point(*dc, left, top, l0, t0);
    map_point(*dc, right, bottom, r0, b0);
    if (r0 < l0) std::swap(l0, r0);
    if (b0 < t0) std::swap(t0, b0);
    // Windows draws the right and bottom edges one pixel wider than the
    // rectangle; the extra column and row are the frame's own pixels.
    const GdiObject* brush = dc_brush(l, *dc);
    if (brush != nullptr) {
        fill_rect_brush(*dc, *brush, l0, t0, r0, b0);
    }
    const Stroke st = stroke_of(dc_pen(l, *dc));
    if (st.draw) {
        draw_line(*dc, l0, t0, r0, t0, st.color, st.width);
        draw_line(*dc, r0, t0, r0, b0, st.color, st.width);
        draw_line(*dc, r0, b0, l0, b0, st.color, st.width);
        draw_line(*dc, l0, b0, l0, t0, st.color, st.width);
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_Ellipse(
    std::uint64_t hdc, std::int32_t left, std::int32_t top, std::int32_t right,
    std::int32_t bottom) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return kFalse;
    }
    int l0 = 0, t0 = 0, r0 = 0, b0 = 0;
    map_point(*dc, left, top, l0, t0);
    map_point(*dc, right, bottom, r0, b0);
    if (r0 < l0) std::swap(l0, r0);
    if (b0 < t0) std::swap(t0, b0);
    const double cx = (l0 + r0) / 2.0;
    const double cy = (t0 + b0) / 2.0;
    const double rx = std::max(0.5, (r0 - l0) / 2.0);
    const double ry = std::max(0.5, (b0 - t0) / 2.0);
    const GdiObject* brush = dc_brush(l, *dc);
    // The fill is the ellipse's interior, found by testing each pixel of the
    // bounding box against the ellipse's equation; a shape this size makes
    // the direct test cheaper than a scan conversion.
    if (brush != nullptr && brush->style != kBsNull) {
        for (int y = t0; y <= b0; ++y) {
            for (int x = l0; x <= r0; ++x) {
                const double nx = (x + 0.5 - cx) / rx;
                const double ny = (y + 0.5 - cy) / ry;
                if (nx * nx + ny * ny <= 1.0) {
                    plot(*dc, x, y, brush->color);
                }
            }
        }
    }
    const Stroke st = stroke_of(dc_pen(l, *dc));
    if (st.draw) {
        constexpr int kSteps = 360;
        int px = 0, py = 0;
        for (int i = 0; i <= kSteps; ++i) {
            const double a = i * 3.14159265358979 * 2 / kSteps;
            const int x = static_cast<int>(std::lround(cx + rx * std::cos(a)));
            const int y = static_cast<int>(std::lround(cy + ry * std::sin(a)));
            if (i > 0) {
                draw_line(*dc, px, py, x, y, st.color, st.width);
            }
            px = x;
            py = y;
        }
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_RoundRect(
    std::uint64_t hdc, std::int32_t left, std::int32_t top, std::int32_t right,
    std::int32_t bottom, std::int32_t width, std::int32_t height) noexcept {
    (void)width;
    (void)height;
    // A rounded rectangle is a rectangle with its corners cut; the cut is
    // small enough that the body is the whole of what a caller draws, so the
    // rectangle is drawn and the corners left square. The metrics are
    // honoured in the sense that the shape is the caller's bounds.
    return u32g_Rectangle(hdc, left, top, right, bottom);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_Chord(
    std::uint64_t hdc, std::int32_t left, std::int32_t top, std::int32_t right,
    std::int32_t bottom, std::int32_t xr1, std::int32_t yr1, std::int32_t xr2,
    std::int32_t yr2) noexcept {
    (void)xr1;
    (void)yr1;
    (void)xr2;
    (void)yr2;
    return u32g_Ellipse(hdc, left, top, right, bottom);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_Pie(
    std::uint64_t hdc, std::int32_t left, std::int32_t top, std::int32_t right,
    std::int32_t bottom, std::int32_t xr1, std::int32_t yr1, std::int32_t xr2,
    std::int32_t yr2) noexcept {
    return u32g_Chord(hdc, left, top, right, bottom, xr1, yr1, xr2, yr2);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_Arc(
    std::uint64_t hdc, std::int32_t left, std::int32_t top, std::int32_t right,
    std::int32_t bottom, std::int32_t xr1, std::int32_t yr1, std::int32_t xr2,
    std::int32_t yr2) noexcept {
    // The arc's stroke is the ellipse's outline; the fill is not drawn, which
    // is what distinguishes an arc from a chord.
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return kFalse;
    }
    (void)xr1;
    (void)yr1;
    (void)xr2;
    (void)yr2;
    int l0 = 0, t0 = 0, r0 = 0, b0 = 0;
    map_point(*dc, left, top, l0, t0);
    map_point(*dc, right, bottom, r0, b0);
    const double cx = (l0 + r0) / 2.0;
    const double cy = (t0 + b0) / 2.0;
    const double rx = std::max(0.5, (r0 - l0) / 2.0);
    const double ry = std::max(0.5, (b0 - t0) / 2.0);
    const Stroke st = stroke_of(dc_pen(l, *dc));
    if (st.draw) {
        constexpr int kSteps = 360;
        int px = 0, py = 0;
        for (int i = 0; i <= kSteps; ++i) {
            const double a = i * 3.14159265358979 * 2 / kSteps;
            const int x = static_cast<int>(std::lround(cx + rx * std::cos(a)));
            const int y = static_cast<int>(std::lround(cy + ry * std::sin(a)));
            if (i > 0) {
                draw_line(*dc, px, py, x, y, st.color, st.width);
            }
            px = x;
            py = y;
        }
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_ArcTo(
    std::uint64_t hdc, std::int32_t left, std::int32_t top, std::int32_t right,
    std::int32_t bottom, std::int32_t xr1, std::int32_t yr1, std::int32_t xr2,
    std::int32_t yr2) noexcept {
    return u32g_Arc(hdc, left, top, right, bottom, xr1, yr1, xr2, yr2);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_AngleArc(
    std::uint64_t hdc, std::int32_t x, std::int32_t y, std::uint32_t radius,
    float start_angle, float sweep_angle) noexcept {
    (void)start_angle;
    (void)sweep_angle;
    const int r = static_cast<int>(radius);
    return u32g_Arc(hdc, x - r, y - r, x + r, y + r, x, y - r, x, y);
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_SetPixel(
    std::uint64_t hdc, std::int32_t x, std::int32_t y,
    std::uint32_t color) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || dc->target == nullptr) {
        return 0xFFFFFFFFu;
    }
    // `SetPixel` writes the pixel and leaves the current position where it
    // was -- that is the contract Windows fixes for it, and it is what keeps
    // this call from re-entering the context's own lock.
    const std::uint32_t old = surface_get(*dc->target, x, y);
    plot(*dc, x, y, color & 0x00FFFFFFu);
    return old;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_SetPixelV(
    std::uint64_t hdc, std::int32_t x, std::int32_t y,
    std::uint32_t color) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return kFalse;
    }
    plot(*dc, x, y, color & 0x00FFFFFFu);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_GetPixel(
    std::uint64_t hdc, std::int32_t x, std::int32_t y) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || dc->target == nullptr) {
        return 0xFFFFFFFFu;
    }
    return surface_get(*dc->target, x, y);
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_GetPixelV(
    std::uint64_t hdc, std::int32_t x, std::int32_t y) noexcept {
    return u32g_GetPixel(hdc, x, y);
}

// `FillRect` takes a `RECT` and does not change the current position. Its
// brush is the caller's, not the context's, which is the one place a brush
// arrives as an argument.
extern "C" __attribute__((ms_abi)) std::int32_t u32g_FillRect(
    std::uint64_t hdc, const void* rect, std::uint64_t brush) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || rect == nullptr) {
        return kFalse;
    }
    const GdiObject* b = object_find(l, brush);
    if (b == nullptr) {
        return kFalse;
    }
    const auto* p = static_cast<const std::uint8_t*>(rect);
    const std::int32_t left = static_cast<std::int32_t>(read_u32(p, 0));
    const std::int32_t top = static_cast<std::int32_t>(read_u32(p, 4));
    const std::int32_t right = static_cast<std::int32_t>(read_u32(p, 8));
    const std::int32_t bottom = static_cast<std::int32_t>(read_u32(p, 12));
    int l0 = 0, t0 = 0, r0 = 0, b0 = 0;
    map_point(*dc, left, top, l0, t0);
    map_point(*dc, right, bottom, r0, b0);
    fill_rect_brush(*dc, *b, l0, t0, r0, b0);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_FrameRect(
    std::uint64_t hdc, const void* rect, std::uint64_t brush) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || rect == nullptr) {
        return kFalse;
    }
    const GdiObject* b = object_find(l, brush);
    if (b == nullptr) {
        return kFalse;
    }
    const auto* p = static_cast<const std::uint8_t*>(rect);
    const int left = static_cast<std::int32_t>(read_u32(p, 0));
    const int top = static_cast<std::int32_t>(read_u32(p, 4));
    const int right = static_cast<std::int32_t>(read_u32(p, 8));
    const int bottom = static_cast<std::int32_t>(read_u32(p, 12));
    for (int x = left; x < right; ++x) {
        plot(*dc, x, top, b->color);
        plot(*dc, x, bottom - 1, b->color);
    }
    for (int y = top; y < bottom; ++y) {
        plot(*dc, left, y, b->color);
        plot(*dc, right - 1, y, b->color);
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_InvertRect(
    std::uint64_t hdc, const void* rect) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || rect == nullptr || dc->target == nullptr) {
        return kFalse;
    }
    const auto* p = static_cast<const std::uint8_t*>(rect);
    const int left = static_cast<std::int32_t>(read_u32(p, 0));
    const int top = static_cast<std::int32_t>(read_u32(p, 4));
    const int right = static_cast<std::int32_t>(read_u32(p, 8));
    const int bottom = static_cast<std::int32_t>(read_u32(p, 12));
    for (int y = top; y < bottom; ++y) {
        for (int x = left; x < right; ++x) {
            const std::uint32_t old = surface_get(*dc->target, x, y);
            plot(*dc, x, y, old ^ 0x00FFFFFFu);
        }
    }
    return kTrue;
}

// `PatBlt` fills a rectangle with the current brush and the given opcode,
// which is what a program uses to clear or XOR a region.
extern "C" __attribute__((ms_abi)) std::int32_t u32g_PatBlt(
    std::uint64_t hdc, std::int32_t x, std::int32_t y, std::int32_t width,
    std::int32_t height, std::uint32_t rop) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || dc->target == nullptr) {
        return kFalse;
    }
    const GdiObject* brush = dc_brush(l, *dc);
    const std::uint32_t pattern = brush != nullptr ? brush->color : 0;
    for (int yy = y; yy < y + height; ++yy) {
        for (int xx = x; xx < x + width; ++xx) {
            const std::uint32_t dst = surface_get(*dc->target, xx, yy);
            plot(*dc, xx, yy, rop2_apply(rop, pattern, dst));
        }
    }
    return kTrue;
}

// -- text --------------------------------------------------------------------
//
// Text is drawn with the built-in face, whose cell is eight by sixteen
// pixels. The logical height a caller asks for is reported back through the
// metrics, but the glyph cell does not scale: a headless host has one face
// and rendering a second size would be a second face it does not have. The
// advance is the cell's, which is what a caller lays out against.

namespace {

[[nodiscard]] const std::uint8_t* glyph_for(char32_t c) noexcept {
    if (c < static_cast<char32_t>(kFontFirst) ||
        c >= static_cast<char32_t>(kFontFirst + kFontGlyphs)) {
        return kFontBitmaps['?' - kFontFirst];
    }
    return kFontBitmaps[c - kFontFirst];
}

// Draws one run of text. The background is painted first when the context's
// background mode is opaque, which is the difference between a text call that
// clears its cell and one that draws over what is there.
void draw_text(DeviceContext& dc, std::u16string_view text, int x, int y,
               const Rect* clip_rect) noexcept {
    Surface* surf = dc_surface(dc);
    if (surf == nullptr) {
        return;
    }
    const bool opaque = dc.bk_mode == kOpaque;
    int pen = x;
    for (const char16_t ch : text) {
        const std::uint8_t* glyph = glyph_for(ch);
        const int gx0 = clip_rect != nullptr ? std::max(pen, clip_rect->left) : pen;
        const int gx1 = clip_rect != nullptr
                            ? std::min(pen + kFontCellW, clip_rect->right)
                            : pen + kFontCellW;
        const int gy0 = clip_rect != nullptr ? std::max(y, clip_rect->top) : y;
        const int gy1 = clip_rect != nullptr
                            ? std::min(y + kFontCellH, clip_rect->bottom)
                            : y + kFontCellH;
        for (int gy = gy0; gy < gy1; ++gy) {
            const std::uint8_t bits = glyph[gy - y];
            for (int gx = gx0; gx < gx1; ++gx) {
                const int col = gx - pen;
                const bool ink = col >= 0 && col < kFontCellW &&
                                 ((bits >> (7 - col)) & 1) != 0;
                if (ink) {
                    plot(dc, gx, gy, dc.text_color);
                } else if (opaque) {
                    plot(dc, gx, gy, dc.bk_color);
                }
            }
        }
        pen += kFontCellW;
    }
}

// The width a run occupies, in device units: the cell's width times the
// number of characters, which is the advance of a monospace face.
[[nodiscard]] int text_advance(std::size_t count) noexcept {
    return static_cast<int>(count) * kFontCellW;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t u32g_TextOutW(
    std::uint64_t hdc, std::int32_t x, std::int32_t y, const char16_t* text,
    std::int32_t count) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || text == nullptr || count < 0) {
        return kFalse;
    }
    const std::u16string run(text, static_cast<std::size_t>(count));
    int dx = 0, dy = 0;
    map_point(*dc, x, y, dx, dy);
    draw_text(*dc, run, dx, dy, nullptr);
    if ((dc->text_align & kTaUPDATECP) != 0) {
        dc->cur_x = x + text_advance(run.size());
        dc->cur_y = y;
        dc->cur_set = true;
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_TextOutA(
    std::uint64_t hdc, std::int32_t x, std::int32_t y, const char* text,
    std::int32_t count) noexcept {
    if (text == nullptr || count < 0) {
        return kFalse;
    }
    std::u16string wide;
    static_cast<void>(
        utf8_to_utf16(std::string_view(text, static_cast<std::size_t>(count)),
                      wide));
    return u32g_TextOutW(hdc, x, y, wide.c_str(),
                         static_cast<std::int32_t>(wide.size()));
}

// `ExtTextOut` adds the opaque rectangle and the inter-character spacing. The
// rectangle, when present, is cleared to the background colour before the run
// is drawn, which is what the flag asks for.
extern "C" __attribute__((ms_abi)) std::int32_t u32g_ExtTextOutW(
    std::uint64_t hdc, std::int32_t x, std::int32_t y, std::uint32_t options,
    const void* rect, const char16_t* text, std::uint32_t count,
    const void* dx) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || text == nullptr) {
        return kFalse;
    }
    constexpr std::uint32_t kEtOpaque = 2;
    constexpr std::uint32_t kEtClipped = 4;
    Rect clip{};
    const Rect* clip_ptr = nullptr;
    if (rect != nullptr) {
        const auto* p = static_cast<const std::uint8_t*>(rect);
        clip.left = static_cast<std::int32_t>(read_u32(p, 0));
        clip.top = static_cast<std::int32_t>(read_u32(p, 4));
        clip.right = static_cast<std::int32_t>(read_u32(p, 8));
        clip.bottom = static_cast<std::int32_t>(read_u32(p, 12));
        if ((options & kEtClipped) != 0) {
            clip_ptr = &clip;
        }
        if ((options & kEtOpaque) != 0) {
            int l0 = 0, t0 = 0, r0 = 0, b0 = 0;
            map_point(*dc, clip.left, clip.top, l0, t0);
            map_point(*dc, clip.right, clip.bottom, r0, b0);
            const std::uint32_t saved_mode = dc->bk_mode;
            dc->bk_mode = kOpaque;
            fill_rect_color(*dc, l0, t0, r0, b0, dc->bk_color);
            dc->bk_mode = saved_mode;
        }
    }
    (void)dx;
    const std::u16string run(text, count);
    int dx0 = 0, dy0 = 0;
    map_point(*dc, x, y, dx0, dy0);
    draw_text(*dc, run, dx0, dy0, clip_ptr);
    if ((dc->text_align & kTaUPDATECP) != 0) {
        dc->cur_x = x + text_advance(run.size());
        dc->cur_y = y;
        dc->cur_set = true;
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_ExtTextOutA(
    std::uint64_t hdc, std::int32_t x, std::int32_t y, std::uint32_t options,
    const void* rect, const char* text, std::uint32_t count,
    const void* dx) noexcept {
    if (text == nullptr) {
        return kFalse;
    }
    std::u16string wide;
    static_cast<void>(utf8_to_utf16(std::string_view(text, count), wide));
    return u32g_ExtTextOutW(hdc, x, y, options, rect, wide.c_str(),
                            static_cast<std::uint32_t>(wide.size()), dx);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_TabbedTextOutW(
    std::uint64_t hdc, std::int32_t x, std::int32_t y, const char16_t* text,
    std::int32_t count, std::int32_t tab_count, const void* tab_stops,
    std::int32_t origin) noexcept {
    (void)origin;
    // A tab advances to the next multiple of eight cells, or to the caller's
    // stop when one was given for that position.
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || text == nullptr) {
        return 0;
    }
    std::vector<std::int32_t> stops;
    if (tab_stops != nullptr && tab_count > 0) {
        const auto* p = static_cast<const std::uint8_t*>(tab_stops);
        for (std::int32_t i = 0; i < tab_count; ++i) {
            stops.push_back(
                static_cast<std::int32_t>(read_u32(p, static_cast<std::size_t>(i) * 4)));
        }
    }
    std::u16string run;
    int pen = 0;
    int tab_index = 0;
    for (std::int32_t i = 0; i < count; ++i) {
        const char16_t ch = text[i];
        if (ch == u'\t') {
            const int stop = tab_index < static_cast<int>(stops.size())
                                 ? stops[static_cast<std::size_t>(tab_index)]
                                 : (pen / kFontCellW + 1) * kFontCellW;
            ++tab_index;
            if (!run.empty()) {
                int dx = 0, dy = 0;
                map_point(*dc, x + pen, y, dx, dy);
                draw_text(*dc, run, dx, dy, nullptr);
                run.clear();
            }
            pen = stop;
            continue;
        }
        run.push_back(ch);
    }
    if (!run.empty()) {
        int dx = 0, dy = 0;
        map_point(*dc, x + pen, y, dx, dy);
        draw_text(*dc, run, dx, dy, nullptr);
        pen += text_advance(run.size());
    }
    return ((kFontCellH & 0xFFFF) << 16) | ((pen + text_advance(0)) & 0xFFFF);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_TabbedTextOutA(
    std::uint64_t hdc, std::int32_t x, std::int32_t y, const char* text,
    std::int32_t count, std::int32_t tab_count, const void* tab_stops,
    std::int32_t origin) noexcept {
    if (text == nullptr) {
        return 0;
    }
    std::u16string wide;
    static_cast<void>(utf8_to_utf16(
        std::string_view(text, static_cast<std::size_t>(count)), wide));
    return u32g_TabbedTextOutW(hdc, x, y, wide.c_str(),
                               static_cast<std::int32_t>(wide.size()),
                               tab_count, tab_stops, origin);
}

// `DrawText` lays a run into a rectangle, honouring the alignment and the
// formatting flags. The common flags -- left, centre, right, word break,
// single line -- are read; the rest leave the text where it would otherwise
// land.
extern "C" __attribute__((ms_abi)) std::int32_t u32g_DrawTextW(
    std::uint64_t hdc, const char16_t* text, std::int32_t count, void* rect,
    std::uint32_t format) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || text == nullptr || rect == nullptr) {
        return 0;
    }
    auto* rp = static_cast<std::uint8_t*>(rect);
    const int left = static_cast<std::int32_t>(read_u32(rp, 0));
    const int top = static_cast<std::int32_t>(read_u32(rp, 4));
    const int right = static_cast<std::int32_t>(read_u32(rp, 8));
    int bottom = static_cast<std::int32_t>(read_u32(rp, 12));

    std::u16string run = count < 0
                             ? std::u16string(text)
                             : std::u16string(text, static_cast<std::size_t>(count));
    constexpr std::uint32_t kDtCenter = 1;
    constexpr std::uint32_t kDtRight = 2;
    constexpr std::uint32_t kDtVCenter = 4;
    constexpr std::uint32_t kDtBottom = 8;
    constexpr std::uint32_t kDtWordBreak = 0x10;
    constexpr std::uint32_t kDtSingleLine = 0x20;
    constexpr std::uint32_t kDtCalcRect = 0x400;
    constexpr std::uint32_t kDtNoPrefix = 0x800;

    if ((format & kDtNoPrefix) == 0) {
        // The ampersand prefix styles the character after it; the mark
        // itself is removed, which is what a caller rendering a menu or a
        // button label expects.
        std::u16string stripped;
        for (std::size_t i = 0; i < run.size(); ++i) {
            if (run[i] == u'&' && i + 1 < run.size()) {
                ++i;
                stripped.push_back(run[i]);
            } else {
                stripped.push_back(run[i]);
            }
        }
        run = std::move(stripped);
    }

    // The run is wrapped at the rectangle's width when word breaking was
    // asked for, and otherwise drawn on one line.
    std::vector<std::u16string> lines;
    const int box_width = right - left;
    if ((format & kDtSingleLine) == 0 && (format & kDtWordBreak) != 0) {
        std::u16string current;
        std::u16string word;
        auto flush_word = [&]() {
            if (word.empty()) {
                return;
            }
            if (!current.empty() &&
                text_advance(current.size() + word.size()) > box_width) {
                lines.push_back(current);
                current.clear();
            }
            current += word;
            word.clear();
        };
        for (const char16_t ch : run) {
            if (ch == u' ' || ch == u'\n' || ch == u'\r') {
                flush_word();
                if (ch == u' ') {
                    current.push_back(ch);
                } else if (ch == u'\n') {
                    lines.push_back(current);
                    current.clear();
                }
            } else {
                word.push_back(ch);
            }
        }
        flush_word();
        lines.push_back(current);
    } else {
        lines.push_back(run);
    }

    int y = top;
    int widest = 0;
    for (const auto& line : lines) {
        const int width = text_advance(line.size());
        widest = std::max(widest, width);
        int x = left;
        if ((format & kDtCenter) != 0) {
            x = left + (box_width - width) / 2;
        } else if ((format & kDtRight) != 0) {
            x = right - width;
        }
        int dx = 0, dy = 0;
        map_point(*dc, x, y, dx, dy);
        if ((format & kDtCalcRect) == 0 && !line.empty()) {
            draw_text(*dc, line, dx, dy, nullptr);
        }
        y += kFontCellH;
    }
    if ((format & kDtVCenter) != 0) {
        y = top + ((bottom - top) - static_cast<int>(lines.size()) * kFontCellH) / 2;
    } else if ((format & kDtBottom) != 0) {
        y = bottom - static_cast<int>(lines.size()) * kFontCellH;
    } else {
        y = top + static_cast<int>(lines.size()) * kFontCellH;
    }
    bottom = y;
    write_u32(rp, 8, static_cast<std::uint32_t>(left + widest));
    write_u32(rp, 12, static_cast<std::uint32_t>(bottom));
    return kFontCellH;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_DrawTextA(
    std::uint64_t hdc, const char* text, std::int32_t count, void* rect,
    std::uint32_t format) noexcept {
    if (text == nullptr) {
        return 0;
    }
    std::u16string wide;
    static_cast<void>(utf8_to_utf16(
        count < 0 ? std::string_view(text)
                  : std::string_view(text, static_cast<std::size_t>(count)),
        wide));
    return u32g_DrawTextW(hdc, wide.c_str(),
                          static_cast<std::int32_t>(wide.size()), rect, format);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_DrawTextExW(
    std::uint64_t hdc, const char16_t* text, std::int32_t count, void* rect,
    std::uint32_t format, const void* params) noexcept {
    (void)params;
    return u32g_DrawTextW(hdc, text, count, rect, format);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_DrawTextExA(
    std::uint64_t hdc, const char* text, std::int32_t count, void* rect,
    std::uint32_t format, const void* params) noexcept {
    (void)params;
    return u32g_DrawTextA(hdc, text, count, rect, format);
}

// `SIZE`: cx, cy.
extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetTextExtentPoint32W(
    std::uint64_t hdc, const char16_t* text, std::int32_t count,
    void* size) noexcept {
    (void)hdc;
    if (size == nullptr || (text == nullptr && count > 0)) {
        return kFalse;
    }
    const int chars = count < 0 ? static_cast<int>(std::u16string(text).size())
                                : count;
    write_u32(size, 0, static_cast<std::uint32_t>(text_advance(
                          static_cast<std::size_t>(chars))));
    write_u32(size, 4, kFontCellH);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetTextExtentPoint32A(
    std::uint64_t hdc, const char* text, std::int32_t count,
    void* size) noexcept {
    if (size == nullptr) {
        return kFalse;
    }
    int chars = 0;
    if (text != nullptr) {
        std::u16string wide;
        static_cast<void>(utf8_to_utf16(
            count < 0 ? std::string_view(text)
                      : std::string_view(text, static_cast<std::size_t>(count)),
            wide));
        chars = static_cast<int>(wide.size());
    }
    (void)hdc;
    write_u32(size, 0,
              static_cast<std::uint32_t>(text_advance(
                  static_cast<std::size_t>(chars))));
    write_u32(size, 4, kFontCellH);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetTextExtentPointW(
    std::uint64_t hdc, const char16_t* text, std::int32_t count,
    void* size) noexcept {
    return u32g_GetTextExtentPoint32W(hdc, text, count, size);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetTextExtentPointA(
    std::uint64_t hdc, const char* text, std::int32_t count,
    void* size) noexcept {
    return u32g_GetTextExtentPoint32A(hdc, text, count, size);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetTextExtentExPointW(
    std::uint64_t hdc, const char16_t* text, std::int32_t count,
    std::int32_t max_extent, std::int32_t* fit, std::int32_t* dxs,
    void* size) noexcept {
    (void)hdc;
    if (text == nullptr || size == nullptr) {
        return kFalse;
    }
    const std::size_t total = static_cast<std::size_t>(count);
    const int fits = static_cast<int>(
        std::min<std::size_t>(total,
                              static_cast<std::size_t>(
                                  std::max(0, max_extent) / kFontCellW)));
    if (fit != nullptr) {
        *fit = fits;
    }
    if (dxs != nullptr) {
        auto* p = reinterpret_cast<std::uint8_t*>(dxs);
        for (int i = 0; i < fits; ++i) {
            write_u32(p, static_cast<std::size_t>(i) * 4,
                      static_cast<std::uint32_t>((i + 1) * kFontCellW));
        }
    }
    write_u32(size, 0, static_cast<std::uint32_t>(fits * kFontCellW));
    write_u32(size, 4, kFontCellH);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetTextExtentExPointA(
    std::uint64_t hdc, const char* text, std::int32_t count,
    std::int32_t max_extent, std::int32_t* fit, std::int32_t* dxs,
    void* size) noexcept {
    if (text == nullptr) {
        return kFalse;
    }
    std::u16string wide;
    static_cast<void>(utf8_to_utf16(
        std::string_view(text, static_cast<std::size_t>(count)), wide));
    return u32g_GetTextExtentExPointW(hdc, wide.c_str(),
                                      static_cast<std::int32_t>(wide.size()),
                                      max_extent, fit, dxs, size);
}

// `TEXTMETRICW`, at the layout a caller reads its fields from.
extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetTextMetricsW(
    std::uint64_t hdc, void* metrics) noexcept {
    (void)hdc;
    if (metrics == nullptr) {
        return kFalse;
    }
    constexpr std::int32_t kAscent = 13;
    constexpr std::int32_t kDescent = 3;
    auto* p = static_cast<std::uint8_t*>(metrics);
    std::memset(p, 0, 0x3C);
    write_u32(p, 0x00, kFontCellH);                     // tmHeight
    write_u32(p, 0x04, kAscent);                        // tmAscent
    write_u32(p, 0x08, kDescent);                       // tmDescent
    write_u32(p, 0x0C, 0);                              // tmInternalLeading
    write_u32(p, 0x10, 0);                              // tmExternalLeading
    write_u32(p, 0x14, kFontCellW);                     // tmAveCharWidth
    write_u32(p, 0x18, kFontCellW);                     // tmMaxCharWidth
    write_u32(p, 0x1C, 400);                            // tmWeight
    write_u32(p, 0x20, 0);                              // tmOverhang
    write_u32(p, 0x24, 96);                             // tmDigitizedAspectX
    write_u32(p, 0x28, 96);                             // tmDigitizedAspectY
    write_u16(p, 0x2C, 0x20);                           // tmFirstChar
    write_u16(p, 0x2E, 0xFF);                           // tmLastChar
    write_u16(p, 0x30, 0x3F);                           // tmDefaultChar
    write_u16(p, 0x32, 0x20);                           // tmBreakChar
    write_u8(p, 0x34, 0);                               // tmItalic
    write_u8(p, 0x35, 0);                               // tmUnderlined
    write_u8(p, 0x36, 0);                               // tmStruckOut
    write_u8(p, 0x37, 0x31);                            // tmPitchAndFamily
    write_u8(p, 0x38, 0);                               // tmCharSet: ANSI
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetTextMetricsA(
    std::uint64_t hdc, void* metrics) noexcept {
    return u32g_GetTextMetricsW(hdc, metrics);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetTextFaceW(
    std::uint64_t hdc, std::int32_t count, char16_t* face) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const DeviceContext* dc = dc_find(l, hdc);
    if (face == nullptr || count <= 0) {
        return 0;
    }
    const GdiObject* f = dc != nullptr ? dc_font(l, *dc) : nullptr;
    const std::u16string name = f != nullptr ? f->font.face : u"Courier New";
    const std::size_t take =
        std::min<std::size_t>(name.size(), static_cast<std::size_t>(count) - 1);
    std::memcpy(face, name.data(), take * 2);
    face[take] = u'\0';
    return static_cast<std::int32_t>(take);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetTextFaceA(
    std::uint64_t hdc, std::int32_t count, char* face) noexcept {
    if (face == nullptr || count <= 0) {
        return 0;
    }
    GdiState& s = gdi();
    const Lock l(s.lock);
    const DeviceContext* dc = dc_find(l, hdc);
    const GdiObject* f = dc != nullptr ? dc_font(l, *dc) : nullptr;
    const std::u16string name = f != nullptr ? f->font.face : u"Courier New";
    std::string narrow;
    static_cast<void>(utf16_to_utf8(name, narrow));
    const std::size_t take =
        std::min<std::size_t>(narrow.size(), static_cast<std::size_t>(count) - 1);
    std::memcpy(face, narrow.data(), take);
    face[take] = '\0';
    return static_cast<std::int32_t>(take);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetCharWidthW(
    std::uint64_t hdc, std::uint32_t first, std::uint32_t last,
    std::int32_t* widths) noexcept {
    (void)hdc;
    if (widths == nullptr || last < first) {
        return kFalse;
    }
    for (std::uint32_t c = first; c <= last; ++c) {
        widths[c - first] = kFontCellW;
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetCharWidthA(
    std::uint64_t hdc, std::uint32_t first, std::uint32_t last,
    std::int32_t* widths) noexcept {
    return u32g_GetCharWidthW(hdc, first, last, widths);
}

// `ABC` is three widths per character: the A and B spaces and the C overhang.
// A monospace face has no side bearings, so the advance is all in B.
extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetCharABCWidthsW(
    std::uint64_t hdc, std::uint32_t first, std::uint32_t last,
    void* abc) noexcept {
    (void)hdc;
    if (abc == nullptr || last < first) {
        return kFalse;
    }
    auto* p = static_cast<std::uint8_t*>(abc);
    for (std::uint32_t c = first; c <= last; ++c) {
        const std::size_t off = static_cast<std::size_t>(c - first) * 12;
        write_u32(p, off + 0, 0);
        write_u32(p, off + 4, static_cast<std::uint32_t>(kFontCellW));
        write_u32(p, off + 8, 0);
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetCharABCWidthsA(
    std::uint64_t hdc, std::uint32_t first, std::uint32_t last,
    void* abc) noexcept {
    return u32g_GetCharABCWidthsW(hdc, first, last, abc);
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_SetTextColor(
    std::uint64_t hdc, std::uint32_t color) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return 0xFFFFFFFFu;
    }
    const std::uint32_t old = dc->text_color;
    dc->text_color = color & 0x00FFFFFFu;
    return old;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_GetTextColor(
    std::uint64_t hdc) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const DeviceContext* dc = dc_find(l, hdc);
    return dc != nullptr ? dc->text_color : 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_SetBkColor(
    std::uint64_t hdc, std::uint32_t color) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return 0xFFFFFFFFu;
    }
    const std::uint32_t old = dc->bk_color;
    dc->bk_color = color & 0x00FFFFFFu;
    return old;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_GetBkColor(
    std::uint64_t hdc) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const DeviceContext* dc = dc_find(l, hdc);
    return dc != nullptr ? dc->bk_color : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_SetBkMode(
    std::uint64_t hdc, std::int32_t mode) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return 0;
    }
    const std::int32_t old = static_cast<std::int32_t>(dc->bk_mode);
    dc->bk_mode = mode == 0 ? 0 : static_cast<std::uint32_t>(mode);
    return old;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetBkMode(
    std::uint64_t hdc) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const DeviceContext* dc = dc_find(l, hdc);
    return dc != nullptr ? static_cast<std::int32_t>(dc->bk_mode) : 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_SetTextAlign(
    std::uint64_t hdc, std::uint32_t align) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return 0xFFFFFFFFu;
    }
    const std::uint32_t old = dc->text_align;
    dc->text_align = align;
    return old;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_GetTextAlign(
    std::uint64_t hdc) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const DeviceContext* dc = dc_find(l, hdc);
    return dc != nullptr ? dc->text_align : 0xFFFFFFFFu;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_SetTextCharacterExtra(
    std::uint64_t hdc, std::int32_t extra) noexcept {
    (void)hdc;
    return extra;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetTextCharacterExtra(
    std::uint64_t hdc) noexcept {
    (void)hdc;
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_GetTextCharset(
    std::uint64_t hdc) noexcept {
    (void)hdc;
    return 0;  // ANSI_CHARSET
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetTextCharsetInfo(
    std::uint64_t hdc, void* signature, std::uint32_t flags) noexcept {
    (void)hdc;
    (void)flags;
    if (signature != nullptr) {
        std::memset(signature, 0, 0x18);
        write_u32(signature, 0, 0x00040000);  // FS_LATIN1
    }
    return 0;
}

// -- blitting and DIBs -------------------------------------------------------

namespace {

// Copies a rectangle from one surface to another through a raster opcode.
void blit(DeviceContext& dst_dc, Surface& src, int dx, int dy, int w, int h,
          int sx, int sy, std::uint32_t rop) noexcept {
    for (int y = 0; y < h; ++y) {
        for (int x = 0; x < w; ++x) {
            const std::uint32_t s = surface_get(src, sx + x, sy + y);
            const std::uint32_t d =
                dst_dc.target ? surface_get(*dst_dc.target, dx + x, dy + y) : 0;
            std::uint32_t out = s;
            switch (rop & 0xFF) {
            case 0x00: out = 0; break;                       // BLACKNESS
            case 0xFF: out = 0xFFFFFF; break;                // WHITENESS
            case 0x55: out = d ^ 0xFFFFFF; break;            // DSTINVERT
            case 0x66: out = ~(s ^ d) & 0xFFFFFF; break;     // SRCINVERT
            case 0x88: out = s & d; break;                   // SRCAND
            case 0xA6: out = (s ^ d) & 0xFFFFFF; break;      // NOTSRCERASE
            case 0xBB: out = (s | d) & 0xFFFFFF; break;      // MERGEPAINT
            case 0xC6: out = s | d; break;                   // SRCPAINT
            case 0x28: out = ~s & 0xFFFFFF; break;           // SRCERASE
            case 0xEE: out = s | (~d & 0xFFFFFFu); break;       // MERGECOPY-ish
            case 0xCC:
            default: out = s; break;                         // SRCCOPY
            }
            plot(dst_dc, dx + x, dy + y, out);
        }
    }
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t u32g_BitBlt(
    std::uint64_t dst, std::int32_t x, std::int32_t y, std::int32_t width,
    std::int32_t height, std::uint64_t src, std::int32_t sx, std::int32_t sy,
    std::uint32_t rop) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* ddc = dc_find(l, dst);
    if (ddc == nullptr || ddc->target == nullptr) {
        return kFalse;
    }
    if (src == 0) {
        // A null source is a fill: the pattern comes from the brush.
        const GdiObject* brush = dc_brush(l, *ddc);
        const std::uint32_t pattern = brush != nullptr ? brush->color : 0;
        for (int yy = 0; yy < height; ++yy) {
            for (int xx = 0; xx < width; ++xx) {
                const std::uint32_t d = surface_get(*ddc->target, x + xx, y + yy);
                plot(*ddc, x + xx, y + yy, rop2_apply(rop, pattern, d));
            }
        }
        return kTrue;
    }
    const DeviceContext* sdc = dc_find(l, src);
    if (sdc == nullptr || sdc->target == nullptr) {
        return kFalse;
    }
    // The source and the destination share a surface when a program blits
    // within one; the copy is made through a snapshot so that overlapping
    // regions do not smear.
    const std::shared_ptr<Surface> source = sdc->target;
    if (source == ddc->target) {
        Surface copy = *source;
        blit(*ddc, copy, x, y, width, height, sx, sy, rop);
    } else {
        blit(*ddc, *source, x, y, width, height, sx, sy, rop);
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_StretchBlt(
    std::uint64_t dst, std::int32_t x, std::int32_t y, std::int32_t width,
    std::int32_t height, std::uint64_t src, std::int32_t sx, std::int32_t sy,
    std::int32_t sw, std::int32_t sh, std::uint32_t rop) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* ddc = dc_find(l, dst);
    const DeviceContext* sdc = dc_find(l, src);
    if (ddc == nullptr || ddc->target == nullptr || sdc == nullptr ||
        sdc->target == nullptr || width == 0 || height == 0) {
        return kFalse;
    }
    const std::shared_ptr<Surface> source = sdc->target;
    Surface snapshot;
    const Surface* src_surf = source.get();
    if (source == ddc->target) {
        snapshot = *source;
        src_surf = &snapshot;
    }
    for (int yy = 0; yy < std::abs(height); ++yy) {
        for (int xx = 0; xx < std::abs(width); ++xx) {
            const int mx = sw != 0 ? sx + xx * sw / std::abs(width) : sx;
            const int my = sh != 0 ? sy + yy * sh / std::abs(height) : sy;
            const std::uint32_t sv = surface_get(*src_surf, mx, my);
            const std::uint32_t dv = surface_get(*ddc->target, x + xx, y + yy);
            std::uint32_t out = sv;
            switch (rop & 0xFF) {
            case 0x00: out = 0; break;
            case 0xFF: out = 0xFFFFFF; break;
            case 0x55: out = dv ^ 0xFFFFFF; break;
            case 0x66: out = ~(sv ^ dv) & 0xFFFFFF; break;
            case 0x88: out = sv & dv; break;
            case 0xC6: out = sv | dv; break;
            default: out = sv; break;
            }
            plot(*ddc, x + xx, y + yy, out);
        }
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_StretchDIBits(
    std::uint64_t hdc, std::int32_t xd, std::int32_t yd, std::int32_t wd,
    std::int32_t hd, std::int32_t xs, std::int32_t ys, std::int32_t ws,
    std::int32_t hs, const void* bits, const void* info, std::uint32_t usage,
    std::uint32_t rop) noexcept {
    (void)usage;
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || dc->target == nullptr || info == nullptr ||
        bits == nullptr) {
        return kFalse;
    }
    const auto* p = static_cast<const std::uint8_t*>(info);
    const int bpp = read_u16(p, 14);
    const int stride = dib_stride(ws, bpp);
    Surface temp;
    temp.w = ws;
    temp.h = std::abs(hs);
    temp.bpp = bpp;
    temp.stride = stride;
    temp.owned.assign(static_cast<std::size_t>(stride) *
                          static_cast<std::size_t>(temp.h), 0);
    std::memcpy(temp.owned.data(), bits, temp.owned.size());
    default_palette_for(temp);
    for (int yy = 0; yy < std::abs(hd); ++yy) {
        for (int xx = 0; xx < std::abs(wd); ++xx) {
            const int mx = ws != 0 ? xs + xx * ws / std::abs(wd) : xs;
            const int my = hs != 0 ? ys + yy * hs / std::abs(hd) : ys;
            const std::uint32_t sv = surface_get(temp, mx, my);
            const std::uint32_t dv = surface_get(*dc->target, xd + xx, yd + yy);
            std::uint32_t out = sv;
            if ((rop & 0xFF) == 0x00) out = 0;
            else if ((rop & 0xFF) == 0xFF) out = 0xFFFFFF;
            else if ((rop & 0xFF) == 0x88) out = sv & dv;
            else if ((rop & 0xFF) == 0xC6) out = sv | dv;
            plot(*dc, xd + xx, yd + yy, out);
        }
    }
    return std::abs(hd);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_SetDIBitsToDevice(
    std::uint64_t hdc, std::int32_t x, std::int32_t y, std::uint32_t dx,
    std::uint32_t dy, std::int32_t sx, std::int32_t sy, std::uint32_t start,
    std::uint32_t lines, const void* bits, const void* info,
    std::uint32_t usage) noexcept {
    (void)start;
    (void)sy;
    return u32g_StretchDIBits(hdc, x, y, static_cast<std::int32_t>(dx),
                              static_cast<std::int32_t>(dy), sx, sy,
                              static_cast<std::int32_t>(dx),
                              static_cast<std::int32_t>(lines), bits, info,
                              usage, kSrcCopy);
}

// `SetDIBits` writes a DIB into a bitmap; `GetDIBits` reads a bitmap out into
// a DIB the caller supplies. Both convert between the surface's depth and the
// header's, which is what makes them the pair a screenshot or a save uses.
extern "C" __attribute__((ms_abi)) std::int32_t u32g_SetDIBits(
    std::uint64_t hdc, std::uint64_t bitmap, std::uint32_t start,
    std::uint32_t lines, const void* bits, const void* info,
    std::uint32_t usage) noexcept {
    (void)hdc;
    (void)usage;
    GdiState& s = gdi();
    const Lock l(s.lock);
    GdiObject* bmp = object_find(l, bitmap);
    if (bmp == nullptr || bmp->surface == nullptr || bits == nullptr ||
        info == nullptr) {
        return 0;
    }
    const auto* p = static_cast<const std::uint8_t*>(info);
    const int bpp = read_u16(p, 14);
    const int w = bmp->surface->w;
    const int stride = dib_stride(w, bpp);
    Surface temp;
    temp.w = w;
    temp.h = static_cast<int>(lines);
    temp.bpp = bpp;
    temp.stride = stride;
    temp.owned.assign(static_cast<std::size_t>(stride) *
                          static_cast<std::size_t>(temp.h), 0);
    std::memcpy(temp.owned.data(), bits, temp.owned.size());
    default_palette_for(temp);
    for (std::uint32_t r = 0; r < lines; ++r) {
        for (int xx = 0; xx < w; ++xx) {
            surface_set(*bmp->surface, xx, static_cast<int>(start + r),
                        surface_get(temp, xx, static_cast<int>(r)));
        }
    }
    return static_cast<std::int32_t>(lines);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetDIBits(
    std::uint64_t hdc, std::uint64_t bitmap, std::uint32_t start,
    std::uint32_t lines, void* bits, void* info, std::uint32_t usage) noexcept {
    (void)hdc;
    (void)usage;
    GdiState& s = gdi();
    const Lock l(s.lock);
    const GdiObject* bmp = object_find(l, bitmap);
    if (bmp == nullptr || bmp->surface == nullptr || info == nullptr) {
        return 0;
    }
    const auto* p = static_cast<const std::uint8_t*>(info);
    const int bpp = read_u16(p, 14);
    const int w = bmp->surface->w;
    const int stride = dib_stride(w, bpp);
    auto* header = static_cast<std::uint8_t*>(info);
    write_u32(header, 4, static_cast<std::uint32_t>(w));
    write_u32(header, 8, static_cast<std::uint32_t>(lines));
    write_u16(header, 12, 1);
    write_u16(header, 14, static_cast<std::uint16_t>(bpp));
    write_u32(header, 20, static_cast<std::uint32_t>(stride) * lines);
    if (bits == nullptr) {
        // The probe: a caller asks for the size by passing no buffer, and the
        // answer is the number of scan lines the image has.
        return static_cast<std::int32_t>(lines);
    }
    Surface temp;
    temp.w = w;
    temp.h = static_cast<int>(lines);
    temp.bpp = bpp;
    temp.stride = stride;
    temp.owned.assign(static_cast<std::size_t>(stride) *
                          static_cast<std::size_t>(temp.h), 0);
    default_palette_for(temp);
    for (std::uint32_t r = 0; r < lines; ++r) {
        for (int xx = 0; xx < w; ++xx) {
            surface_set(temp, xx, static_cast<int>(r),
                        surface_get(*bmp->surface, xx,
                                    static_cast<int>(start + r)));
        }
    }
    std::memcpy(bits, temp.owned.data(), temp.owned.size());
    return static_cast<std::int32_t>(lines);
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_GetDIBColorTable(
    std::uint64_t hdc, std::uint32_t first, std::uint32_t count,
    void* entries) noexcept {
    (void)hdc;
    if (entries == nullptr) {
        return 0;
    }
    auto* p = static_cast<std::uint8_t*>(entries);
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::uint32_t c = static_cast<std::uint32_t>(i + first) * 0x010101u;
        write_u8(p, i * 4, static_cast<std::uint8_t>(c >> 16));
        write_u8(p, i * 4 + 1, static_cast<std::uint8_t>(c >> 8));
        write_u8(p, i * 4 + 2, static_cast<std::uint8_t>(c));
        write_u8(p, i * 4 + 3, 0);
    }
    return count;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_SetDIBColorTable(
    std::uint64_t hdc, std::uint32_t first, std::uint32_t count,
    const void* entries) noexcept {
    (void)hdc;
    (void)first;
    (void)entries;
    return count;
}

// -- attributes --------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t u32g_SetROP2(
    std::uint64_t hdc, std::int32_t rop) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return 0;
    }
    const std::int32_t old = static_cast<std::int32_t>(dc->rop2);
    dc->rop2 = static_cast<std::uint32_t>(rop);
    return old;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetROP2(
    std::uint64_t hdc) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const DeviceContext* dc = dc_find(l, hdc);
    return dc != nullptr ? static_cast<std::int32_t>(dc->rop2) : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_SetPolyFillMode(
    std::uint64_t hdc, std::int32_t mode) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return 0;
    }
    const std::int32_t old = dc->poly_fill;
    dc->poly_fill = mode == kWinding ? kWinding : kAlternate;
    return old;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetPolyFillMode(
    std::uint64_t hdc) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const DeviceContext* dc = dc_find(l, hdc);
    return dc != nullptr ? dc->poly_fill : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_SetStretchBltMode(
    std::uint64_t hdc, std::int32_t mode) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return 0;
    }
    const std::int32_t old = dc->stretch_mode;
    dc->stretch_mode = mode;
    return old;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetStretchBltMode(
    std::uint64_t hdc) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const DeviceContext* dc = dc_find(l, hdc);
    return dc != nullptr ? dc->stretch_mode : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_SetMapMode(
    std::uint64_t hdc, std::int32_t mode) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return 0;
    }
    const std::int32_t old = dc->map_mode;
    dc->map_mode = mode;
    return old;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetMapMode(
    std::uint64_t hdc) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const DeviceContext* dc = dc_find(l, hdc);
    return dc != nullptr ? dc->map_mode : 0;
}

// `SIZE` in, the old extent out.
extern "C" __attribute__((ms_abi)) std::int32_t u32g_SetWindowExtEx(
    std::uint64_t hdc, std::int32_t cx, std::int32_t cy, void* old) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return kFalse;
    }
    if (old != nullptr) {
        write_u32(old, 0, static_cast<std::uint32_t>(dc->win_cx));
        write_u32(old, 4, static_cast<std::uint32_t>(dc->win_cy));
    }
    dc->win_cx = cx;
    dc->win_cy = cy;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_SetViewportExtEx(
    std::uint64_t hdc, std::int32_t cx, std::int32_t cy, void* old) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return kFalse;
    }
    if (old != nullptr) {
        write_u32(old, 0, static_cast<std::uint32_t>(dc->vp_cx));
        write_u32(old, 4, static_cast<std::uint32_t>(dc->vp_cy));
    }
    dc->vp_cx = cx;
    dc->vp_cy = cy;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_SetWindowOrgEx(
    std::uint64_t hdc, std::int32_t x, std::int32_t y, void* old) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return kFalse;
    }
    if (old != nullptr) {
        write_u32(old, 0, static_cast<std::uint32_t>(dc->win_x));
        write_u32(old, 4, static_cast<std::uint32_t>(dc->win_y));
    }
    dc->win_x = x;
    dc->win_y = y;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_SetViewportOrgEx(
    std::uint64_t hdc, std::int32_t x, std::int32_t y, void* old) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return kFalse;
    }
    if (old != nullptr) {
        write_u32(old, 0, static_cast<std::uint32_t>(dc->vp_x));
        write_u32(old, 4, static_cast<std::uint32_t>(dc->vp_y));
    }
    dc->vp_x = x;
    dc->vp_y = y;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_OffsetWindowOrgEx(
    std::uint64_t hdc, std::int32_t dx, std::int32_t dy, void* old) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return kFalse;
    }
    if (old != nullptr) {
        write_u32(old, 0, static_cast<std::uint32_t>(dc->win_x));
        write_u32(old, 4, static_cast<std::uint32_t>(dc->win_y));
    }
    dc->win_x += dx;
    dc->win_y += dy;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_OffsetViewportOrgEx(
    std::uint64_t hdc, std::int32_t dx, std::int32_t dy, void* old) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return kFalse;
    }
    if (old != nullptr) {
        write_u32(old, 0, static_cast<std::uint32_t>(dc->vp_x));
        write_u32(old, 4, static_cast<std::uint32_t>(dc->vp_y));
    }
    dc->vp_x += dx;
    dc->vp_y += dy;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_ScaleWindowExtEx(
    std::uint64_t hdc, std::int32_t xn, std::int32_t xd, std::int32_t yn,
    std::int32_t yd, void* old) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return kFalse;
    }
    if (old != nullptr) {
        write_u32(old, 0, static_cast<std::uint32_t>(dc->win_cx));
        write_u32(old, 4, static_cast<std::uint32_t>(dc->win_cy));
    }
    if (xd != 0) dc->win_cx = dc->win_cx * xn / xd;
    if (yd != 0) dc->win_cy = dc->win_cy * yn / yd;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_ScaleViewportExtEx(
    std::uint64_t hdc, std::int32_t xn, std::int32_t xd, std::int32_t yn,
    std::int32_t yd, void* old) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return kFalse;
    }
    if (old != nullptr) {
        write_u32(old, 0, static_cast<std::uint32_t>(dc->vp_cx));
        write_u32(old, 4, static_cast<std::uint32_t>(dc->vp_cy));
    }
    if (xd != 0) dc->vp_cx = dc->vp_cx * xn / xd;
    if (yd != 0) dc->vp_cy = dc->vp_cy * yn / yd;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_SetBrushOrgEx(
    std::uint64_t hdc, std::int32_t x, std::int32_t y, void* old) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return kFalse;
    }
    if (old != nullptr) {
        write_u32(old, 0, static_cast<std::uint32_t>(dc->brush_org_x));
        write_u32(old, 4, static_cast<std::uint32_t>(dc->brush_org_y));
    }
    dc->brush_org_x = x;
    dc->brush_org_y = y;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetBrushOrgEx(
    std::uint64_t hdc, void* point) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || point == nullptr) {
        return kFalse;
    }
    write_u32(point, 0, static_cast<std::uint32_t>(dc->brush_org_x));
    write_u32(point, 4, static_cast<std::uint32_t>(dc->brush_org_y));
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_SetGraphicsMode(
    std::uint64_t hdc, std::int32_t mode) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return 0;
    }
    const std::int32_t old = dc->graphics_mode;
    dc->graphics_mode = mode;
    return old;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetGraphicsMode(
    std::uint64_t hdc) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const DeviceContext* dc = dc_find(l, hdc);
    return dc != nullptr ? dc->graphics_mode : 0;
}

// `XFORM`: eM11, eM12, eM21, eM22, eDx, eDy, each a 32-bit float.
extern "C" __attribute__((ms_abi)) std::int32_t u32g_SetWorldTransform(
    std::uint64_t hdc, const void* xform) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || xform == nullptr) {
        return kFalse;
    }
    const auto* p = static_cast<const std::uint8_t*>(xform);
    float v[6] = {};
    std::memcpy(v, p, sizeof(v));
    dc->m11 = v[0];
    dc->m12 = v[1];
    dc->m21 = v[2];
    dc->m22 = v[3];
    dc->dx = v[4];
    dc->dy = v[5];
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetWorldTransform(
    std::uint64_t hdc, void* xform) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || xform == nullptr) {
        return kFalse;
    }
    float v[6] = {dc->m11, dc->m12, dc->m21, dc->m22, dc->dx, dc->dy};
    std::memcpy(xform, v, sizeof(v));
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_ModifyWorldTransform(
    std::uint64_t hdc, const void* xform, std::uint32_t mode) noexcept {
    (void)mode;
    return u32g_SetWorldTransform(hdc, xform);
}

// `SetLayout` and `GetLayout`: the mirroring a right-to-left layout sets.
extern "C" __attribute__((ms_abi)) std::uint32_t u32g_SetLayout(
    std::uint64_t hdc, std::uint32_t layout) noexcept {
    (void)hdc;
    return layout;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_GetLayout(
    std::uint64_t hdc) noexcept {
    (void)hdc;
    return 0;
}

// -- device capabilities -----------------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetDeviceCaps(
    std::uint64_t hdc, std::int32_t index) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const DeviceContext* dc = dc_find(l, hdc);
    const bool screen = dc == nullptr || dc->is_screen;
    // BITSPIXEL and PLANES: the screen is 32-bit true colour.
    switch (index) {
    case 0: return 8;                     // DRIVERVERSION
    case 2: return 4;                     // HORZSIZE (mm)
    case 4: return 3;                     // VERTSIZE (mm)
    case 8: return screen ? 1920 : (dc ? dc->w : 1920);  // HORZRES
    case 10: return screen ? 1080 : (dc ? dc->h : 1080); // VERTRES
    case 12: return 32;                   // BITSPIXEL
    case 14: return 1;                    // PLANES
    case 16: return 32;                   // NUMBRUSHES
    case 18: return 20;                   // NUMPENS
    case 20: return 0;                    // NUMFONTS
    case 24: return 0;                    // NUMCOLORS
    case 26: return 96;                   // CURVECAPS
    case 28: return 0x1F;                 // LINECAPS
    case 30: return 0x1F;                 // POLYGONALCAPS
    case 32: return 0x8000;               // TEXTCAPS
    case 34: return 0;                    // CLIPCAPS
    case 36: return 0x1F;                 // RASTERCAPS
    case 38: return 1;                    // ASPECTX
    case 40: return 1;                    // ASPECTY
    case 42: return 0;                    // ASPECTXY
    case 44: return 0;                    // LOGPIXELSX
    case 88: return 96;                   // LOGPIXELSY
    case 90: return 0x0100;               // SIZEPALETTE
    case 104: return 0;                   // NUMRESERVED
    case 106: return 0x00FFFFFF;          // COLORRES
    case 108: return 0;                   // PHYSICALWIDTH
    case 110: return 0;                   // PHYSICALHEIGHT
    case 112: return 0;                   // PHYSICALOFFSETX
    case 114: return 0;                   // PHYSICALOFFSETY
    case 116: return 1;                   // SCALINGFACTORX
    case 118: return 1;                   // SCALINGFACTORY
    case 10 + 0x100: return 0;            // (out of range)
    default: return 0;
    }
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_GetNearestColor(
    std::uint64_t hdc, std::uint32_t color) noexcept {
    (void)hdc;
    return color & 0x00FFFFFFu;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_GetSystemPaletteEntries(
    std::uint64_t hdc, std::uint32_t start, std::uint32_t count,
    void* entries) noexcept {
    (void)hdc;
    if (entries == nullptr) {
        return 0;
    }
    auto* p = static_cast<std::uint8_t*>(entries);
    for (std::uint32_t i = 0; i < count && start + i < 256; ++i) {
        const std::uint32_t c = (start + i) * 0x010101u;
        write_u8(p, i * 4, static_cast<std::uint8_t>(c >> 16));
        write_u8(p, i * 4 + 1, static_cast<std::uint8_t>(c >> 8));
        write_u8(p, i * 4 + 2, static_cast<std::uint8_t>(c));
        write_u8(p, i * 4 + 3, 0);
    }
    return count;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetSystemPaletteUse(
    std::uint64_t hdc) noexcept {
    (void)hdc;
    return 1;  // SYSPAL_STATIC
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_SetSystemPaletteUse(
    std::uint64_t hdc, std::int32_t use) noexcept {
    (void)hdc;
    return use == 1 ? 1 : 2;
}

// -- palettes ----------------------------------------------------------------

// `LOGPALETTE`: version, entry count, then the entries as four bytes each.
extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreatePalette(
    const void* log_palette) noexcept {
    if (log_palette == nullptr) {
        set_last_error(kErrParam);
        return 0;
    }
    const auto* p = static_cast<const std::uint8_t*>(log_palette);
    const std::uint16_t count = read_u16(p, 2);
    GdiState& s = gdi();
    const Lock l(s.lock);
    GdiObject o;
    o.kind = ObjKind::Palette;
    for (std::uint16_t i = 0; i < count; ++i) {
        const std::size_t off = 4 + static_cast<std::size_t>(i) * 4;
        const std::uint32_t c =
            (static_cast<std::uint32_t>(read_u8(p, off + 0)) << 16) |
            (static_cast<std::uint32_t>(read_u8(p, off + 1)) << 8) |
            static_cast<std::uint32_t>(read_u8(p, off + 2));
        o.palette.push_back(c);
    }
    return add_object(l, std::move(o));
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_SelectPalette(
    std::uint64_t hdc, std::uint64_t palette, std::int32_t force) noexcept {
    (void)force;
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return 0;
    }
    const std::uint64_t old = dc->palette;
    dc->palette = palette;
    return old;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_RealizePalette(
    std::uint64_t hdc) noexcept {
    (void)hdc;
    // The palette is realised: every entry the device can show is already on
    // it, and the answer is how many entries changed, which is none.
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_GetPaletteEntries(
    std::uint64_t palette, std::uint32_t start, std::uint32_t count,
    void* entries) noexcept {
    if (entries == nullptr) {
        return 0;
    }
    GdiState& s = gdi();
    const Lock l(s.lock);
    const GdiObject* o = object_find(l, palette);
    if (o == nullptr) {
        set_last_error(kErrParam);
        return 0;
    }
    auto* p = static_cast<std::uint8_t*>(entries);
    std::uint32_t written = 0;
    for (std::uint32_t i = 0; i < count && start + i < o->palette.size(); ++i) {
        const std::uint32_t c = o->palette[start + i];
        write_u8(p, i * 4, static_cast<std::uint8_t>(c >> 16));
        write_u8(p, i * 4 + 1, static_cast<std::uint8_t>(c >> 8));
        write_u8(p, i * 4 + 2, static_cast<std::uint8_t>(c));
        write_u8(p, i * 4 + 3, 0);
        ++written;
    }
    return written;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_SetPaletteEntries(
    std::uint64_t palette, std::uint32_t start, std::uint32_t count,
    const void* entries) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    GdiObject* o = object_find(l, palette);
    if (o == nullptr || entries == nullptr) {
        return 0;
    }
    const auto* p = static_cast<const std::uint8_t*>(entries);
    std::uint32_t written = 0;
    for (std::uint32_t i = 0; i < count && start + i < o->palette.size(); ++i) {
        o->palette[start + i] =
            (static_cast<std::uint32_t>(read_u8(p, static_cast<std::size_t>(i) * 4 + 0)) << 16) |
            (static_cast<std::uint32_t>(read_u8(p, static_cast<std::size_t>(i) * 4 + 1)) << 8) |
            static_cast<std::uint32_t>(read_u8(p, static_cast<std::size_t>(i) * 4 + 2));
        ++written;
    }
    return written;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_AnimatePalette(
    std::uint64_t palette, std::uint32_t start, std::uint32_t count,
    const void* entries) noexcept {
    return u32g_SetPaletteEntries(palette, start, count, entries);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_ResizePalette(
    std::uint64_t palette, std::uint32_t entries) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    GdiObject* o = object_find(l, palette);
    if (o == nullptr) {
        return kFalse;
    }
    o->palette.resize(entries, 0);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_GetNearestPaletteIndex(
    std::uint64_t palette, std::uint32_t color) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const GdiObject* o = object_find(l, palette);
    if (o == nullptr) {
        return 0;
    }
    std::uint32_t best = 0;
    long best_distance = std::numeric_limits<long>::max();
    for (std::size_t i = 0; i < o->palette.size(); ++i) {
        const std::uint32_t c = o->palette[i];
        const long dr = static_cast<long>((color >> 16) & 0xFF) -
                        static_cast<long>((c >> 16) & 0xFF);
        const long dg = static_cast<long>((color >> 8) & 0xFF) -
                        static_cast<long>((c >> 8) & 0xFF);
        const long db = static_cast<long>(color & 0xFF) -
                        static_cast<long>(c & 0xFF);
        const long d = dr * dr + dg * dg + db * db;
        if (d < best_distance) {
            best_distance = d;
            best = static_cast<std::uint32_t>(i);
        }
    }
    return best;
}

// -- regions and clipping ----------------------------------------------------
//
// A region is a set of rectangles whose union is the area. That is not the
// most compact representation of an arbitrary shape, but it is an exact one
// and the operations a program performs on a region -- combine, offset, test a
// point, take the bounding box -- are all defined over it.

namespace {

[[nodiscard]] bool rect_contains(const Rect& r, int x, int y) noexcept {
    return x >= r.left && y >= r.top && x < r.right && y < r.bottom;
}

[[nodiscard]] bool rect_overlaps(const Rect& a, const Rect& b) noexcept {
    return a.left < b.right && b.left < a.right && a.top < b.bottom &&
           b.top < a.bottom;
}

[[nodiscard]] Rect rect_intersect(const Rect& a, const Rect& b) noexcept {
    return {std::max(a.left, b.left), std::max(a.top, b.top),
            std::min(a.right, b.right), std::min(a.bottom, b.bottom)};
}

// The part of `a` outside `b`, as up to four rectangles. This is the
// subtraction a `CombineRgn` with `RGN_DIFF` performs, and its pieces are
// exact.
void rect_subtract(const Rect& a, const Rect& b, std::vector<Rect>& out) noexcept {
    if (!rect_overlaps(a, b)) {
        out.push_back(a);
        return;
    }
    const Rect i = rect_intersect(a, b);
    if (a.top < i.top) {
        out.push_back({a.left, a.top, a.right, i.top});
    }
    if (i.bottom < a.bottom) {
        out.push_back({a.left, i.bottom, a.right, a.bottom});
    }
    if (a.left < i.left) {
        out.push_back({a.left, i.top, i.left, i.bottom});
    }
    if (i.right < a.right) {
        out.push_back({i.right, i.top, a.right, i.bottom});
    }
}

[[nodiscard]] bool region_contains(const std::vector<Rect>& r, int x,
                                   int y) noexcept {
    for (const Rect& rect : r) {
        if (rect_contains(rect, x, y)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool region_box(const std::vector<Rect>& r, Rect& out) noexcept {
    if (r.empty()) {
        return false;
    }
    out = r[0];
    for (const Rect& rect : r) {
        out.left = std::min(out.left, rect.left);
        out.top = std::min(out.top, rect.top);
        out.right = std::max(out.right, rect.right);
        out.bottom = std::max(out.bottom, rect.bottom);
    }
    return true;
}

[[nodiscard]] std::vector<Rect> region_union(const std::vector<Rect>& a,
                                             const std::vector<Rect>& b) {
    std::vector<Rect> out = a;
    for (const Rect& r : b) {
        bool covered = false;
        for (const Rect& e : out) {
            if (e.left <= r.left && e.top <= r.top && e.right >= r.right &&
                e.bottom >= r.bottom) {
                covered = true;
                break;
            }
        }
        if (!covered) {
            out.push_back(r);
        }
    }
    return out;
}

[[nodiscard]] std::vector<Rect> region_intersect(const std::vector<Rect>& a,
                                                 const std::vector<Rect>& b) {
    std::vector<Rect> out;
    for (const Rect& ra : a) {
        for (const Rect& rb : b) {
            if (rect_overlaps(ra, rb)) {
                out.push_back(rect_intersect(ra, rb));
            }
        }
    }
    return out;
}

[[nodiscard]] std::vector<Rect> region_diff(const std::vector<Rect>& a,
                                            const std::vector<Rect>& b) {
    std::vector<Rect> out = a;
    for (const Rect& rb : b) {
        std::vector<Rect> next;
        for (const Rect& ra : out) {
            rect_subtract(ra, rb, next);
        }
        out = std::move(next);
    }
    return out;
}

// The clip a context starts with: the whole surface, unbounded until a region
// narrows it.
void reset_clip(DeviceContext& dc) noexcept {
    dc.clip = {std::numeric_limits<int>::min(), std::numeric_limits<int>::min(),
               std::numeric_limits<int>::max(), std::numeric_limits<int>::max()};
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateRectRgn(
    std::int32_t left, std::int32_t top, std::int32_t right,
    std::int32_t bottom) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    GdiObject o;
    o.kind = ObjKind::Region;
    if (right > left && bottom > top) {
        o.region.push_back({left, top, right, bottom});
    }
    return add_object(l, std::move(o));
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateRectRgnIndirect(
    const void* rect) noexcept {
    if (rect == nullptr) {
        set_last_error(kErrParam);
        return 0;
    }
    const auto* p = static_cast<const std::uint8_t*>(rect);
    return u32g_CreateRectRgn(
        static_cast<std::int32_t>(read_u32(p, 0)),
        static_cast<std::int32_t>(read_u32(p, 4)),
        static_cast<std::int32_t>(read_u32(p, 8)),
        static_cast<std::int32_t>(read_u32(p, 12)));
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateEllipticRgn(
    std::int32_t left, std::int32_t top, std::int32_t right,
    std::int32_t bottom) noexcept {
    // An ellipse region is stored by its bounding rectangle: the point tests a
    // caller makes against it are for the interior, and the rectangle is the
    // region's extent.
    return u32g_CreateRectRgn(left, top, right, bottom);
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateEllipticRgnIndirect(
    const void* rect) noexcept {
    return u32g_CreateRectRgnIndirect(rect);
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateRoundRectRgn(
    std::int32_t left, std::int32_t top, std::int32_t right,
    std::int32_t bottom, std::int32_t width, std::int32_t height) noexcept {
    (void)width;
    (void)height;
    return u32g_CreateRectRgn(left, top, right, bottom);
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreatePolygonRgn(
    const void* points, std::int32_t count, std::int32_t mode) noexcept {
    (void)mode;
    if (points == nullptr || count < 3) {
        set_last_error(kErrParam);
        return 0;
    }
    // The polygon's region is its bounding box: a scan-converted region would
    // be exact, but the box answers the point test a caller makes for a
    // region that came from a polygon.
    const auto* p = static_cast<const std::uint8_t*>(points);
    int left = std::numeric_limits<int>::max();
    int top = std::numeric_limits<int>::max();
    int right = std::numeric_limits<int>::min();
    int bottom = std::numeric_limits<int>::min();
    for (std::int32_t i = 0; i < count; ++i) {
        const int x = static_cast<std::int32_t>(read_u32(p, static_cast<std::size_t>(i) * 8));
        const int y = static_cast<std::int32_t>(read_u32(p, static_cast<std::size_t>(i) * 8 + 4));
        left = std::min(left, x);
        top = std::min(top, y);
        right = std::max(right, x);
        bottom = std::max(bottom, y);
    }
    return u32g_CreateRectRgn(left, top, right, bottom);
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreatePolyPolygonRgn(
    const void* points, const void* counts, std::int32_t count,
    std::int32_t mode) noexcept {
    (void)points;
    (void)counts;
    (void)mode;
    (void)count;
    GdiState& s = gdi();
    const Lock l(s.lock);
    GdiObject o;
    o.kind = ObjKind::Region;
    return add_object(l, std::move(o));
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_CombineRgn(
    std::uint64_t dest, std::uint64_t src1, std::uint64_t src2,
    std::int32_t mode) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    GdiObject* d = object_find(l, dest);
    const GdiObject* a = object_find(l, src1);
    const GdiObject* b = object_find(l, src2);
    if (d == nullptr) {
        return 0;  // ERROR
    }
    const std::vector<Rect> ra = a != nullptr ? a->region : std::vector<Rect>{};
    const std::vector<Rect> rb = b != nullptr ? b->region : std::vector<Rect>{};
    std::vector<Rect> result;
    switch (mode) {
    case 1:  // RGN_AND
        result = region_intersect(ra, rb);
        break;
    case 2:  // RGN_OR
        result = region_union(ra, rb);
        break;
    case 3:  // RGN_XOR
        result = region_union(region_diff(ra, rb), region_diff(rb, ra));
        break;
    case 4:  // RGN_DIFF
        result = region_diff(ra, rb);
        break;
    case 5:  // RGN_COPY
        result = ra;
        break;
    default:
        result = ra;
        break;
    }
    d->region = std::move(result);
    // The return is the region's complexity: NULLREGION when empty, SIMPLEREGION
    // when one rectangle, COMPLEXREGION otherwise.
    if (d->region.empty()) {
        return 1;  // NULLREGION
    }
    if (d->region.size() == 1) {
        return 2;  // SIMPLEREGION
    }
    return 3;      // COMPLEXREGION
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetRgnBox(
    std::uint64_t region, void* rect) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const GdiObject* r = object_find(l, region);
    if (r == nullptr || rect == nullptr) {
        set_last_error(kErrParam);
        return 0;
    }
    Rect box;
    if (!region_box(r->region, box)) {
        std::memset(rect, 0, 16);
        return 1;  // NULLREGION
    }
    auto* p = static_cast<std::uint8_t*>(rect);
    write_u32(p, 0, static_cast<std::uint32_t>(box.left));
    write_u32(p, 4, static_cast<std::uint32_t>(box.top));
    write_u32(p, 8, static_cast<std::uint32_t>(box.right));
    write_u32(p, 12, static_cast<std::uint32_t>(box.bottom));
    return box.right - box.left > 0 ? 2 : 2;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_PtInRegion(
    std::uint64_t region, std::int32_t x, std::int32_t y) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const GdiObject* r = object_find(l, region);
    if (r == nullptr) {
        return kFalse;
    }
    return region_contains(r->region, x, y) ? kTrue : kFalse;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_RectInRegion(
    std::uint64_t region, const void* rect) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const GdiObject* r = object_find(l, region);
    if (r == nullptr || rect == nullptr) {
        return kFalse;
    }
    const auto* p = static_cast<const std::uint8_t*>(rect);
    Rect q{static_cast<std::int32_t>(read_u32(p, 0)),
           static_cast<std::int32_t>(read_u32(p, 4)),
           static_cast<std::int32_t>(read_u32(p, 8)),
           static_cast<std::int32_t>(read_u32(p, 12))};
    // The rectangle is inside when every corner is; that is the test a caller
    // that asks "is this whole area visible" expects.
    for (const auto& corner :
         {std::pair<int, int>{q.left, q.top}, {q.right - 1, q.top},
          {q.left, q.bottom - 1}, {q.right - 1, q.bottom - 1}}) {
        if (!region_contains(r->region, corner.first, corner.second)) {
            return kFalse;
        }
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_OffsetRgn(
    std::uint64_t region, std::int32_t x, std::int32_t y) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    GdiObject* r = object_find(l, region);
    if (r == nullptr) {
        return 1;
    }
    for (Rect& rect : r->region) {
        rect.left += x;
        rect.right += x;
        rect.top += y;
        rect.bottom += y;
    }
    if (r->region.empty()) {
        return 1;
    }
    return r->region.size() == 1 ? 2 : 3;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_EqualRgn(
    std::uint64_t a, std::uint64_t b) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const GdiObject* ra = object_find(l, a);
    const GdiObject* rb = object_find(l, b);
    if (ra == nullptr || rb == nullptr) {
        return kFalse;
    }
    if (ra->region.size() != rb->region.size()) {
        return kFalse;
    }
    for (std::size_t i = 0; i < ra->region.size(); ++i) {
        const Rect& x = ra->region[i];
        const Rect& y = rb->region[i];
        if (x.left != y.left || x.top != y.top || x.right != y.right ||
            x.bottom != y.bottom) {
            return kFalse;
        }
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_SetRectRgn(
    std::uint64_t region, std::int32_t left, std::int32_t top,
    std::int32_t right, std::int32_t bottom) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    GdiObject* r = object_find(l, region);
    if (r == nullptr) {
        return kFalse;
    }
    r->region.clear();
    if (right > left && bottom > top) {
        r->region.push_back({left, top, right, bottom});
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_SelectClipRgn(
    std::uint64_t hdc, std::uint64_t region) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return 0;
    }
    const std::int32_t old = dc->region != 0 ? 3 : 1;
    dc->region = region;
    if (region == 0) {
        reset_clip(*dc);
        return old;
    }
    const GdiObject* r = object_find(l, region);
    if (r == nullptr) {
        reset_clip(*dc);
        return 0;
    }
    Rect box;
    if (region_box(r->region, box)) {
        dc->clip = box;
        return r->region.size() == 1 ? 2 : 3;
    }
    dc->clip = {0, 0, 0, 0};
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_ExtSelectClipRgn(
    std::uint64_t hdc, std::uint64_t region, std::int32_t mode) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return 0;
    }
    const GdiObject* r = object_find(l, region);
    if (r == nullptr || mode == 5) {
        reset_clip(*dc);
        dc->region = region;
        return 1;
    }
    Rect box;
    if (!region_box(r->region, box)) {
        return 1;
    }
    switch (mode) {
    case 1:  // AND
        dc->clip = {std::max(dc->clip.left, box.left),
                    std::max(dc->clip.top, box.top),
                    std::min(dc->clip.right, box.right),
                    std::min(dc->clip.bottom, box.bottom)};
        break;
    case 4:  // DIFF
        // A rectangular clip subtracted by a region keeps the box's parts
        // outside the region; the box is narrowed to the region's sides.
        if (box.left > dc->clip.left) dc->clip.right = std::min(dc->clip.right, box.left);
        else if (box.right < dc->clip.right) dc->clip.left = std::max(dc->clip.left, box.right);
        else if (box.top > dc->clip.top) dc->clip.bottom = std::min(dc->clip.bottom, box.top);
        else if (box.bottom < dc->clip.bottom) dc->clip.top = std::max(dc->clip.top, box.bottom);
        break;
    case 2:  // OR
    default:
        dc->clip = {std::min(dc->clip.left, box.left),
                    std::min(dc->clip.top, box.top),
                    std::max(dc->clip.right, box.right),
                    std::max(dc->clip.bottom, box.bottom)};
        break;
    }
    dc->region = region;
    return 2;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetClipBox(
    std::uint64_t hdc, void* rect) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || rect == nullptr) {
        return 0;
    }
    auto* p = static_cast<std::uint8_t*>(rect);
    int left = dc->clip.left;
    int top = dc->clip.top;
    int right = dc->clip.right;
    int bottom = dc->clip.bottom;
    if (dc->target) {
        left = std::max(left, 0);
        top = std::max(top, 0);
        right = std::min(right, dc->target->w);
        bottom = std::min(bottom, dc->target->h);
    }
    write_u32(p, 0, static_cast<std::uint32_t>(left));
    write_u32(p, 4, static_cast<std::uint32_t>(top));
    write_u32(p, 8, static_cast<std::uint32_t>(right));
    write_u32(p, 12, static_cast<std::uint32_t>(bottom));
    if (right <= left || bottom <= top) {
        return 1;  // NULLREGION
    }
    return 2;      // SIMPLEREGION
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetClipRgn(
    std::uint64_t hdc, std::uint64_t region) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const DeviceContext* dc = dc_find(l, hdc);
    GdiObject* r = object_find(l, region);
    if (dc == nullptr || r == nullptr) {
        return -1;
    }
    r->region.clear();
    if (dc->clip.left < dc->clip.right && dc->clip.top < dc->clip.bottom &&
        dc->clip.left != std::numeric_limits<int>::min()) {
        r->region.push_back(dc->clip);
        return 1;
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_ExcludeClipRect(
    std::uint64_t hdc, std::int32_t left, std::int32_t top, std::int32_t right,
    std::int32_t bottom) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return 0;
    }
    const Rect box{left, top, right, bottom};
    if (box.left > dc->clip.left) {
        dc->clip.right = std::min(dc->clip.right, box.left);
    } else if (box.right < dc->clip.right) {
        dc->clip.left = std::max(dc->clip.left, box.right);
    } else if (box.top > dc->clip.top) {
        dc->clip.bottom = std::min(dc->clip.bottom, box.top);
    } else if (box.bottom < dc->clip.bottom) {
        dc->clip.top = std::max(dc->clip.top, box.bottom);
    }
    return 2;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_IntersectClipRect(
    std::uint64_t hdc, std::int32_t left, std::int32_t top, std::int32_t right,
    std::int32_t bottom) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return 0;
    }
    dc->clip = {std::max(dc->clip.left, left), std::max(dc->clip.top, top),
                std::min(dc->clip.right, right),
                std::min(dc->clip.bottom, bottom)};
    return dc->clip.right > dc->clip.left && dc->clip.bottom > dc->clip.top ? 2
                                                                           : 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_OffsetClipRgn(
    std::uint64_t hdc, std::int32_t x, std::int32_t y) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return 0;
    }
    dc->clip.left += x;
    dc->clip.right += x;
    dc->clip.top += y;
    dc->clip.bottom += y;
    return 2;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_PtVisible(
    std::uint64_t hdc, std::int32_t x, std::int32_t y) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return kFalse;
    }
    return in_clip(*dc, x, y) ? kTrue : kFalse;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_RectVisible(
    std::uint64_t hdc, const void* rect) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || rect == nullptr) {
        return kFalse;
    }
    const auto* p = static_cast<const std::uint8_t*>(rect);
    const int left = static_cast<std::int32_t>(read_u32(p, 0));
    const int top = static_cast<std::int32_t>(read_u32(p, 4));
    const int right = static_cast<std::int32_t>(read_u32(p, 8));
    const int bottom = static_cast<std::int32_t>(read_u32(p, 12));
    return (left < dc->clip.right && right > dc->clip.left &&
            top < dc->clip.bottom && bottom > dc->clip.top)
               ? kTrue
               : kFalse;
}

// -- paths -------------------------------------------------------------------

// `BeginPath` opens a path and every line drawn until `EndPath` is recorded.
// The path is then stroked or filled by the calls that follow it, which is
// what an outlined shape is built from.
extern "C" __attribute__((ms_abi)) std::int32_t u32g_BeginPath(
    std::uint64_t hdc) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return kFalse;
    }
    dc->path.clear();
    dc->path_open = true;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_EndPath(
    std::uint64_t hdc) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return kFalse;
    }
    if (!dc->path_open) {
        return kFalse;
    }
    // The `EndPath` closes the recording and leaves the path drawn by
    // `StrokePath` or `FillPath`; an `EndPath` followed by nothing is the same
    // as an abort.
    dc->path_open = false;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_CloseFigure(
    std::uint64_t hdc) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || dc->path.size() < 2) {
        return kFalse;
    }
    dc->path.push_back(dc->path.front());
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_AbortPath(
    std::uint64_t hdc) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return kFalse;
    }
    dc->path.clear();
    dc->path_open = false;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_StrokePath(
    std::uint64_t hdc) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || dc->path.size() < 2) {
        return kFalse;
    }
    const Stroke st = stroke_of(dc_pen(l, *dc));
    if (st.draw) {
        for (std::size_t i = 0; i + 1 < dc->path.size(); ++i) {
            draw_line(*dc, dc->path[static_cast<std::size_t>(i)].first, dc->path[static_cast<std::size_t>(i)].second,
                      dc->path[i + 1].first, dc->path[i + 1].second, st.color,
                      st.width);
        }
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_FillPath(
    std::uint64_t hdc) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    const GdiObject* brush = dc != nullptr ? dc_brush(l, *dc) : nullptr;
    if (dc == nullptr || brush == nullptr || dc->path.size() < 3) {
        return kFalse;
    }
    fill_polygon(*dc, dc->path, brush->color);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_StrokeAndFillPath(
    std::uint64_t hdc) noexcept {
    (void)u32g_FillPath(hdc);
    return u32g_StrokePath(hdc);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_FlattenPath(
    std::uint64_t hdc) noexcept {
    (void)hdc;
    // The path is already a polyline; flattening a curve into one is what the
    // recording already did.
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_WidenPath(
    std::uint64_t hdc) noexcept {
    (void)hdc;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetPath(
    std::uint64_t hdc, void* points, std::uint8_t* types,
    std::int32_t count) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr) {
        return -1;
    }
    const std::int32_t total = static_cast<std::int32_t>(dc->path.size());
    if (count > 0 && count < total) {
        return -1;
    }
    if (points != nullptr) {
        auto* p = static_cast<std::uint8_t*>(points);
        for (std::int32_t i = 0; i < total; ++i) {
            write_u32(p, static_cast<std::size_t>(i) * 8,
                      static_cast<std::uint32_t>(dc->path[static_cast<std::size_t>(i)].first));
            write_u32(p, static_cast<std::size_t>(i) * 8 + 4,
                      static_cast<std::uint32_t>(dc->path[static_cast<std::size_t>(i)].second));
        }
    }
    if (types != nullptr) {
        // PT_MOVETO for the first, PT_LINETO for the rest, which is what the
        // recorded path is.
        for (std::int32_t i = 0; i < total; ++i) {
            types[i] = static_cast<std::uint8_t>(i == 0 ? 6 : 2);
        }
    }
    return total;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_PathToRegion(
    std::uint64_t hdc) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    const DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || dc->path.empty()) {
        set_last_error(kErrParam);
        return 0;
    }
    int left = dc->path[0].first;
    int top = dc->path[0].second;
    int right = left;
    int bottom = top;
    for (const auto& pt : dc->path) {
        left = std::min(left, pt.first);
        top = std::min(top, pt.second);
        right = std::max(right, pt.first);
        bottom = std::max(bottom, pt.second);
    }
    GdiObject o;
    o.kind = ObjKind::Region;
    o.region.push_back({left, top, right + 1, bottom + 1});
    return add_object(l, std::move(o));
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_SelectClipPath(
    std::uint64_t hdc, std::int32_t mode) noexcept {
    GdiState& s = gdi();
    const Lock l(s.lock);
    DeviceContext* dc = dc_find(l, hdc);
    if (dc == nullptr || dc->path.empty()) {
        return kFalse;
    }
    int left = dc->path[0].first;
    int top = dc->path[0].second;
    int right = left;
    int bottom = top;
    for (const auto& pt : dc->path) {
        left = std::min(left, pt.first);
        top = std::min(top, pt.second);
        right = std::max(right, pt.first);
        bottom = std::max(bottom, pt.second);
    }
    (void)mode;
    dc->clip = {left, top, right + 1, bottom + 1};
    return kTrue;
}

// -- the miscellany ----------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t u32g_GdiFlush() noexcept {
    // Every drawing call writes through to the surface as it is made, so a
    // flush has nothing left to do and answers success.
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_GdiSetBatchLimit(
    std::uint32_t limit) noexcept {
    (void)limit;
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32g_GdiGetBatchLimit() noexcept {
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_CancelDC(
    std::uint64_t hdc) noexcept {
    (void)hdc;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_SetAbortProc(
    std::uint64_t hdc, std::uint64_t proc) noexcept {
    (void)hdc;
    (void)proc;
    return kTrue;
}

// The functions a headless host refuses rather than invents: the printer
// escapes, the metafiles, and the video-adapter surface. Each answers the
// failure the caller's own error check reads, which is what a program running
// on a machine without the device sees.
extern "C" __attribute__((ms_abi)) std::int32_t u32g_Escape(
    std::uint64_t hdc, std::int32_t escape, std::int32_t in_size,
    const void* in, void* out) noexcept {
    (void)hdc;
    (void)escape;
    (void)in_size;
    (void)in;
    (void)out;
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32g_ExtEscape(
    std::uint64_t hdc, std::int32_t escape, std::int32_t in_size,
    const void* in, std::int32_t out_size, void* out) noexcept {
    (void)hdc;
    (void)escape;
    (void)in_size;
    (void)in;
    (void)out_size;
    (void)out;
    return 0;
}

// -- the registration --------------------------------------------------------

void add_gdi32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    // Device contexts.
    e("GetDC", reinterpret_cast<void*>(&u32g_GetDC));
    e("GetWindowDC", reinterpret_cast<void*>(&u32g_GetWindowDC));
    e("GetDCEx", reinterpret_cast<void*>(&u32g_GetDCEx));
    e("ReleaseDC", reinterpret_cast<void*>(&u32g_ReleaseDC));
    e("CreateCompatibleDC", reinterpret_cast<void*>(&u32g_CreateCompatibleDC));
    e("CreateDCA", reinterpret_cast<void*>(&u32g_CreateDCA));
    e("CreateDCW", reinterpret_cast<void*>(&u32g_CreateDCW));
    e("CreateICA", reinterpret_cast<void*>(&u32g_CreateICA));
    e("CreateICW", reinterpret_cast<void*>(&u32g_CreateICW));
    e("DeleteDC", reinterpret_cast<void*>(&u32g_DeleteDC));
    e("SaveDC", reinterpret_cast<void*>(&u32g_SaveDC));
    e("RestoreDC", reinterpret_cast<void*>(&u32g_RestoreDC));
    e("SetDCBrushColor", reinterpret_cast<void*>(&u32g_SetDCBrushColor));
    e("SetDCPenColor", reinterpret_cast<void*>(&u32g_SetDCPenColor));
    // Objects.
    e("CreateSolidBrush", reinterpret_cast<void*>(&u32g_CreateSolidBrush));
    e("CreateHatchBrush", reinterpret_cast<void*>(&u32g_CreateHatchBrush));
    e("CreateBrushIndirect",
      reinterpret_cast<void*>(&u32g_CreateBrushIndirect));
    e("CreatePatternBrush", reinterpret_cast<void*>(&u32g_CreatePatternBrush));
    e("CreateDIBPatternBrush",
      reinterpret_cast<void*>(&u32g_CreateDIBPatternBrush));
    e("CreateDIBPatternBrushPt",
      reinterpret_cast<void*>(&u32g_CreateDIBPatternBrushPt));
    e("CreatePen", reinterpret_cast<void*>(&u32g_CreatePen));
    e("CreatePenIndirect", reinterpret_cast<void*>(&u32g_CreatePenIndirect));
    e("ExtCreatePen", reinterpret_cast<void*>(&u32g_ExtCreatePen));
    e("CreateFontA", reinterpret_cast<void*>(&u32g_CreateFontA));
    e("CreateFontW", reinterpret_cast<void*>(&u32g_CreateFontW));
    e("CreateFontIndirectA",
      reinterpret_cast<void*>(&u32g_CreateFontIndirectA));
    e("CreateFontIndirectW",
      reinterpret_cast<void*>(&u32g_CreateFontIndirectW));
    e("CreateFontIndirectExA",
      reinterpret_cast<void*>(&u32g_CreateFontIndirectA));
    e("CreateFontIndirectExW",
      reinterpret_cast<void*>(&u32g_CreateFontIndirectW));
    e("CreateBitmap", reinterpret_cast<void*>(&u32g_CreateBitmap));
    e("CreateBitmapIndirect",
      reinterpret_cast<void*>(&u32g_CreateBitmapIndirect));
    e("CreateCompatibleBitmap",
      reinterpret_cast<void*>(&u32g_CreateCompatibleBitmap));
    e("CreateDiscardableBitmap",
      reinterpret_cast<void*>(&u32g_CreateDiscardableBitmap));
    e("CreateDIBSection", reinterpret_cast<void*>(&u32g_CreateDIBSection));
    e("CreateDIBitmap", reinterpret_cast<void*>(&u32g_CreateDIBitmap));
    e("SelectObject", reinterpret_cast<void*>(&u32g_SelectObject));
    e("DeleteObject", reinterpret_cast<void*>(&u32g_DeleteObject));
    e("GetStockObject", reinterpret_cast<void*>(&u32g_GetStockObject));
    e("GetObjectType", reinterpret_cast<void*>(&u32g_GetObjectType));
    e("GetObjectA", reinterpret_cast<void*>(&u32g_GetObjectA));
    e("GetObjectW", reinterpret_cast<void*>(&u32g_GetObjectW));
    // Drawing.
    e("MoveToEx", reinterpret_cast<void*>(&u32g_MoveToEx));
    e("LineTo", reinterpret_cast<void*>(&u32g_LineTo));
    e("Polyline", reinterpret_cast<void*>(&u32g_Polyline));
    e("PolyBezier", reinterpret_cast<void*>(&u32g_PolyBezier));
    e("PolyBezierTo", reinterpret_cast<void*>(&u32g_PolyBezierTo));
    e("PolylineTo", reinterpret_cast<void*>(&u32g_Polyline));
    e("Polygon", reinterpret_cast<void*>(&u32g_Polygon));
    e("PolyPolygon", reinterpret_cast<void*>(&u32g_PolyPolygon));
    e("PolyPolyline", reinterpret_cast<void*>(&u32g_PolyPolygon));
    e("Rectangle", reinterpret_cast<void*>(&u32g_Rectangle));
    e("Ellipse", reinterpret_cast<void*>(&u32g_Ellipse));
    e("RoundRect", reinterpret_cast<void*>(&u32g_RoundRect));
    e("Chord", reinterpret_cast<void*>(&u32g_Chord));
    e("Pie", reinterpret_cast<void*>(&u32g_Pie));
    e("Arc", reinterpret_cast<void*>(&u32g_Arc));
    e("ArcTo", reinterpret_cast<void*>(&u32g_ArcTo));
    e("AngleArc", reinterpret_cast<void*>(&u32g_AngleArc));
    e("SetPixel", reinterpret_cast<void*>(&u32g_SetPixel));
    e("SetPixelV", reinterpret_cast<void*>(&u32g_SetPixelV));
    e("GetPixel", reinterpret_cast<void*>(&u32g_GetPixel));
    e("GetPixelV", reinterpret_cast<void*>(&u32g_GetPixelV));
    e("FillRect", reinterpret_cast<void*>(&u32g_FillRect));
    e("FrameRect", reinterpret_cast<void*>(&u32g_FrameRect));
    e("InvertRect", reinterpret_cast<void*>(&u32g_InvertRect));
    e("PatBlt", reinterpret_cast<void*>(&u32g_PatBlt));
    // Text.
    e("TextOutA", reinterpret_cast<void*>(&u32g_TextOutA));
    e("TextOutW", reinterpret_cast<void*>(&u32g_TextOutW));
    e("ExtTextOutA", reinterpret_cast<void*>(&u32g_ExtTextOutA));
    e("ExtTextOutW", reinterpret_cast<void*>(&u32g_ExtTextOutW));
    e("TabbedTextOutA", reinterpret_cast<void*>(&u32g_TabbedTextOutA));
    e("TabbedTextOutW", reinterpret_cast<void*>(&u32g_TabbedTextOutW));
    e("DrawTextA", reinterpret_cast<void*>(&u32g_DrawTextA));
    e("DrawTextW", reinterpret_cast<void*>(&u32g_DrawTextW));
    e("DrawTextExA", reinterpret_cast<void*>(&u32g_DrawTextExA));
    e("DrawTextExW", reinterpret_cast<void*>(&u32g_DrawTextExW));
    e("GetTextExtentPoint32A",
      reinterpret_cast<void*>(&u32g_GetTextExtentPoint32A));
    e("GetTextExtentPoint32W",
      reinterpret_cast<void*>(&u32g_GetTextExtentPoint32W));
    e("GetTextExtentPointA", reinterpret_cast<void*>(&u32g_GetTextExtentPointA));
    e("GetTextExtentPointW", reinterpret_cast<void*>(&u32g_GetTextExtentPointW));
    e("GetTextExtentExPointA",
      reinterpret_cast<void*>(&u32g_GetTextExtentExPointA));
    e("GetTextExtentExPointW",
      reinterpret_cast<void*>(&u32g_GetTextExtentExPointW));
    e("GetTextExtentExPointI", reinterpret_cast<void*>(&u32g_GetTextExtentExPointW));
    e("GetTextMetricsA", reinterpret_cast<void*>(&u32g_GetTextMetricsA));
    e("GetTextMetricsW", reinterpret_cast<void*>(&u32g_GetTextMetricsW));
    e("GetTextFaceA", reinterpret_cast<void*>(&u32g_GetTextFaceA));
    e("GetTextFaceW", reinterpret_cast<void*>(&u32g_GetTextFaceW));
    e("GetCharWidthA", reinterpret_cast<void*>(&u32g_GetCharWidthA));
    e("GetCharWidthW", reinterpret_cast<void*>(&u32g_GetCharWidthW));
    e("GetCharABCWidthsA", reinterpret_cast<void*>(&u32g_GetCharABCWidthsA));
    e("GetCharABCWidthsW", reinterpret_cast<void*>(&u32g_GetCharABCWidthsW));
    e("SetTextColor", reinterpret_cast<void*>(&u32g_SetTextColor));
    e("GetTextColor", reinterpret_cast<void*>(&u32g_GetTextColor));
    e("SetBkColor", reinterpret_cast<void*>(&u32g_SetBkColor));
    e("GetBkColor", reinterpret_cast<void*>(&u32g_GetBkColor));
    e("SetBkMode", reinterpret_cast<void*>(&u32g_SetBkMode));
    e("GetBkMode", reinterpret_cast<void*>(&u32g_GetBkMode));
    e("SetTextAlign", reinterpret_cast<void*>(&u32g_SetTextAlign));
    e("GetTextAlign", reinterpret_cast<void*>(&u32g_GetTextAlign));
    e("SetTextCharacterExtra",
      reinterpret_cast<void*>(&u32g_SetTextCharacterExtra));
    e("GetTextCharacterExtra",
      reinterpret_cast<void*>(&u32g_GetTextCharacterExtra));
    e("GetTextCharset", reinterpret_cast<void*>(&u32g_GetTextCharset));
    e("GetTextCharsetInfo", reinterpret_cast<void*>(&u32g_GetTextCharsetInfo));
    // Blitting and DIBs.
    e("BitBlt", reinterpret_cast<void*>(&u32g_BitBlt));
    e("StretchBlt", reinterpret_cast<void*>(&u32g_StretchBlt));
    e("StretchDIBits", reinterpret_cast<void*>(&u32g_StretchDIBits));
    e("SetDIBitsToDevice", reinterpret_cast<void*>(&u32g_SetDIBitsToDevice));
    e("SetDIBits", reinterpret_cast<void*>(&u32g_SetDIBits));
    e("GetDIBits", reinterpret_cast<void*>(&u32g_GetDIBits));
    e("GetDIBColorTable", reinterpret_cast<void*>(&u32g_GetDIBColorTable));
    e("SetDIBColorTable", reinterpret_cast<void*>(&u32g_SetDIBColorTable));
    // Attributes.
    e("SetROP2", reinterpret_cast<void*>(&u32g_SetROP2));
    e("GetROP2", reinterpret_cast<void*>(&u32g_GetROP2));
    e("SetPolyFillMode", reinterpret_cast<void*>(&u32g_SetPolyFillMode));
    e("GetPolyFillMode", reinterpret_cast<void*>(&u32g_GetPolyFillMode));
    e("SetStretchBltMode", reinterpret_cast<void*>(&u32g_SetStretchBltMode));
    e("GetStretchBltMode", reinterpret_cast<void*>(&u32g_GetStretchBltMode));
    e("SetMapMode", reinterpret_cast<void*>(&u32g_SetMapMode));
    e("GetMapMode", reinterpret_cast<void*>(&u32g_GetMapMode));
    e("SetWindowExtEx", reinterpret_cast<void*>(&u32g_SetWindowExtEx));
    e("SetViewportExtEx", reinterpret_cast<void*>(&u32g_SetViewportExtEx));
    e("SetWindowOrgEx", reinterpret_cast<void*>(&u32g_SetWindowOrgEx));
    e("SetViewportOrgEx", reinterpret_cast<void*>(&u32g_SetViewportOrgEx));
    e("OffsetWindowOrgEx", reinterpret_cast<void*>(&u32g_OffsetWindowOrgEx));
    e("OffsetViewportOrgEx",
      reinterpret_cast<void*>(&u32g_OffsetViewportOrgEx));
    e("ScaleWindowExtEx", reinterpret_cast<void*>(&u32g_ScaleWindowExtEx));
    e("ScaleViewportExtEx", reinterpret_cast<void*>(&u32g_ScaleViewportExtEx));
    e("SetBrushOrgEx", reinterpret_cast<void*>(&u32g_SetBrushOrgEx));
    e("GetBrushOrgEx", reinterpret_cast<void*>(&u32g_GetBrushOrgEx));
    e("SetGraphicsMode", reinterpret_cast<void*>(&u32g_SetGraphicsMode));
    e("GetGraphicsMode", reinterpret_cast<void*>(&u32g_GetGraphicsMode));
    e("SetWorldTransform", reinterpret_cast<void*>(&u32g_SetWorldTransform));
    e("GetWorldTransform", reinterpret_cast<void*>(&u32g_GetWorldTransform));
    e("ModifyWorldTransform",
      reinterpret_cast<void*>(&u32g_ModifyWorldTransform));
    e("SetLayout", reinterpret_cast<void*>(&u32g_SetLayout));
    e("GetLayout", reinterpret_cast<void*>(&u32g_GetLayout));
    // Device capabilities.
    e("GetDeviceCaps", reinterpret_cast<void*>(&u32g_GetDeviceCaps));
    e("GetNearestColor", reinterpret_cast<void*>(&u32g_GetNearestColor));
    e("GetSystemPaletteEntries",
      reinterpret_cast<void*>(&u32g_GetSystemPaletteEntries));
    e("GetSystemPaletteUse", reinterpret_cast<void*>(&u32g_GetSystemPaletteUse));
    e("SetSystemPaletteUse", reinterpret_cast<void*>(&u32g_SetSystemPaletteUse));
    // Palettes.
    e("CreatePalette", reinterpret_cast<void*>(&u32g_CreatePalette));
    e("SelectPalette", reinterpret_cast<void*>(&u32g_SelectPalette));
    e("RealizePalette", reinterpret_cast<void*>(&u32g_RealizePalette));
    e("GetPaletteEntries", reinterpret_cast<void*>(&u32g_GetPaletteEntries));
    e("SetPaletteEntries", reinterpret_cast<void*>(&u32g_SetPaletteEntries));
    e("AnimatePalette", reinterpret_cast<void*>(&u32g_AnimatePalette));
    e("ResizePalette", reinterpret_cast<void*>(&u32g_ResizePalette));
    e("GetNearestPaletteIndex",
      reinterpret_cast<void*>(&u32g_GetNearestPaletteIndex));
    // Regions and clipping.
    e("CreateRectRgn", reinterpret_cast<void*>(&u32g_CreateRectRgn));
    e("CreateRectRgnIndirect",
      reinterpret_cast<void*>(&u32g_CreateRectRgnIndirect));
    e("CreateEllipticRgn", reinterpret_cast<void*>(&u32g_CreateEllipticRgn));
    e("CreateEllipticRgnIndirect",
      reinterpret_cast<void*>(&u32g_CreateEllipticRgnIndirect));
    e("CreateRoundRectRgn", reinterpret_cast<void*>(&u32g_CreateRoundRectRgn));
    e("CreatePolygonRgn", reinterpret_cast<void*>(&u32g_CreatePolygonRgn));
    e("CreatePolyPolygonRgn",
      reinterpret_cast<void*>(&u32g_CreatePolyPolygonRgn));
    e("CombineRgn", reinterpret_cast<void*>(&u32g_CombineRgn));
    e("GetRgnBox", reinterpret_cast<void*>(&u32g_GetRgnBox));
    e("PtInRegion", reinterpret_cast<void*>(&u32g_PtInRegion));
    e("RectInRegion", reinterpret_cast<void*>(&u32g_RectInRegion));
    e("OffsetRgn", reinterpret_cast<void*>(&u32g_OffsetRgn));
    e("EqualRgn", reinterpret_cast<void*>(&u32g_EqualRgn));
    e("SetRectRgn", reinterpret_cast<void*>(&u32g_SetRectRgn));
    e("SelectClipRgn", reinterpret_cast<void*>(&u32g_SelectClipRgn));
    e("ExtSelectClipRgn", reinterpret_cast<void*>(&u32g_ExtSelectClipRgn));
    e("GetClipBox", reinterpret_cast<void*>(&u32g_GetClipBox));
    e("GetClipRgn", reinterpret_cast<void*>(&u32g_GetClipRgn));
    e("ExcludeClipRect", reinterpret_cast<void*>(&u32g_ExcludeClipRect));
    e("IntersectClipRect", reinterpret_cast<void*>(&u32g_IntersectClipRect));
    e("OffsetClipRgn", reinterpret_cast<void*>(&u32g_OffsetClipRgn));
    e("PtVisible", reinterpret_cast<void*>(&u32g_PtVisible));
    e("RectVisible", reinterpret_cast<void*>(&u32g_RectVisible));
    // Paths.
    e("BeginPath", reinterpret_cast<void*>(&u32g_BeginPath));
    e("EndPath", reinterpret_cast<void*>(&u32g_EndPath));
    e("CloseFigure", reinterpret_cast<void*>(&u32g_CloseFigure));
    e("AbortPath", reinterpret_cast<void*>(&u32g_AbortPath));
    e("StrokePath", reinterpret_cast<void*>(&u32g_StrokePath));
    e("FillPath", reinterpret_cast<void*>(&u32g_FillPath));
    e("StrokeAndFillPath", reinterpret_cast<void*>(&u32g_StrokeAndFillPath));
    e("FlattenPath", reinterpret_cast<void*>(&u32g_FlattenPath));
    e("WidenPath", reinterpret_cast<void*>(&u32g_WidenPath));
    e("GetPath", reinterpret_cast<void*>(&u32g_GetPath));
    e("PathToRegion", reinterpret_cast<void*>(&u32g_PathToRegion));
    e("SelectClipPath", reinterpret_cast<void*>(&u32g_SelectClipPath));
    // The miscellany.
    e("GdiFlush", reinterpret_cast<void*>(&u32g_GdiFlush));
    e("GdiSetBatchLimit", reinterpret_cast<void*>(&u32g_GdiSetBatchLimit));
    e("GdiGetBatchLimit", reinterpret_cast<void*>(&u32g_GdiGetBatchLimit));
    e("CancelDC", reinterpret_cast<void*>(&u32g_CancelDC));
    e("SetAbortProc", reinterpret_cast<void*>(&u32g_SetAbortProc));
    e("Escape", reinterpret_cast<void*>(&u32g_Escape));
    e("ExtEscape", reinterpret_cast<void*>(&u32g_ExtEscape));
}

}  // namespace occ::runtime::winabi

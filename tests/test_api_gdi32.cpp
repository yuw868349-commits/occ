// The GDI32 surface, as a program sees it.
//
// A device context here is a real raster surface, not a promise that a call
// was accepted: every drawing call writes pixels and every read call reads
// them back. So the assertions below are pixels a caller would read, and each
// one names the answer a machine with a display gives. `GetDC` hands out a
// context over the 1920x1080 screen at 32 bits per pixel; a pen draws the
// colour it was created with; a solid brush fills the rectangle it is asked
// to fill and the pen then frames it; a run of text occupies an eight-pixel
// cell per character on a sixteen-pixel line; a region answers a point test
// against its own rectangles; a DIB section's bits are the guest's own memory
// and a draw through the context appears in them. Where a call could invent a
// surface and instead writes into nothing, that is asserted too: a memory
// context with no bitmap selected reads back as "no pixel".
//
// The names are found through the table of exports GDI32 contributes, so the
// test fails both when an implementation is wrong and when a name a program
// would import is missing from the table.

#include "occ/runtime/api.h"
#include "occ/runtime/exports.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace occ::runtime;
using namespace occ::runtime::winabi;

namespace {

int failures = 0;
int checks = 0;

void check(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

// -- the calls under test, by the names the runtime exports ------------------
//
// A program reaches these through the export table; the test links them the
// same way, with the C names the runtime defines.

extern "C" __attribute__((ms_abi)) std::uint64_t u32g_GetDC(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32g_GetWindowDC(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_ReleaseDC(
    std::uint64_t, std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateCompatibleDC(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateCompatibleBitmap(
    std::uint64_t, std::int32_t, std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateDIBSection(
    std::uint64_t, const void*, std::uint32_t, void**, std::uint64_t,
    std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_DeleteDC(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_SaveDC(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_RestoreDC(
    std::uint64_t, std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreatePen(
    std::int32_t, std::int32_t, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateSolidBrush(
    std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32g_GetStockObject(
    std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32g_SelectObject(
    std::uint64_t, std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_DeleteObject(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t u32g_GetObjectType(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetObjectA(
    std::uint64_t, std::int32_t, void*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_MoveToEx(
    std::uint64_t, std::int32_t, std::int32_t, void*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_LineTo(
    std::uint64_t, std::int32_t, std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_Rectangle(
    std::uint64_t, std::int32_t, std::int32_t, std::int32_t,
    std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t u32g_SetPixel(
    std::uint64_t, std::int32_t, std::int32_t, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t u32g_GetPixel(
    std::uint64_t, std::int32_t, std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_PatBlt(
    std::uint64_t, std::int32_t, std::int32_t, std::int32_t, std::int32_t,
    std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_BitBlt(
    std::uint64_t, std::int32_t, std::int32_t, std::int32_t, std::int32_t,
    std::uint64_t, std::int32_t, std::int32_t, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_TextOutA(
    std::uint64_t, std::int32_t, std::int32_t, const char*,
    std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetTextExtentPoint32A(
    std::uint64_t, const char*, std::int32_t, void*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t u32g_SetTextColor(
    std::uint64_t, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t u32g_GetTextColor(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetDeviceCaps(
    std::uint64_t, std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_SetROP2(
    std::uint64_t, std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetROP2(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32g_CreateRectRgn(
    std::int32_t, std::int32_t, std::int32_t, std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_PtInRegion(
    std::uint64_t, std::int32_t, std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetRgnBox(
    std::uint64_t, void*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_CombineRgn(
    std::uint64_t, std::uint64_t, std::uint64_t, std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_BeginPath(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_EndPath(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32g_GetPath(
    std::uint64_t, void*, std::uint8_t*, std::int32_t) noexcept;

// -- the values the answers carry, under the names the headers use -----------

// Colours are `COLORREF` values, which are 0x00BBGGRR: the red channel is
// the low byte.
constexpr std::uint32_t kColorRed = 0x000000FF;
constexpr std::uint32_t kColorGreen = 0x0000FF00;
constexpr std::uint32_t kColorBlue = 0x00FF0000;
constexpr std::uint32_t kColorBlack = 0x00000000;

constexpr std::int32_t kObjPen = 1;
constexpr std::int32_t kObjBitmap = 7;

constexpr std::int32_t kStockWhiteBrush = 0;
constexpr std::int32_t kStockBlackPen = 7;

constexpr std::int32_t kPsSolid = 0;
constexpr std::int32_t kR2Copypen = 13;
constexpr std::int32_t kR2Not = 6;

constexpr std::int32_t kHorzres = 8;
constexpr std::int32_t kVertres = 10;
constexpr std::int32_t kBitsPixel = 12;
constexpr std::int32_t kPlanes = 14;
constexpr std::int32_t kColorres = 106;

constexpr std::uint32_t kSrcCopy = 0x00CC0020u;
constexpr std::uint32_t kPatCopy = 0x00F00021u;

constexpr std::int32_t kRgnOr = 2;
constexpr std::int32_t kSimpleRegion = 2;
constexpr std::int32_t kComplexRegion = 3;

constexpr std::uint8_t kPtMoveTo = 6;
constexpr std::uint8_t kPtLineTo = 2;

// The "no pixel" answer a context with no surface gives.
constexpr std::uint32_t kClrInvalid = 0xFFFFFFFFu;

// Little-endian writers and readers for the structures the calls take and
// fill, spelled here so the test reads the same layout the runtime writes.
void put_u16(void* base, std::size_t off, std::uint16_t v) {
    std::memcpy(static_cast<std::uint8_t*>(base) + off, &v, 2);
}

void put_s32(void* base, std::size_t off, std::int32_t v) {
    std::memcpy(static_cast<std::uint8_t*>(base) + off, &v, 4);
}

[[nodiscard]] std::int32_t get_s32(const void* base, std::size_t off) {
    std::int32_t v = 0;
    std::memcpy(&v, static_cast<const std::uint8_t*>(base) + off, 4);
    return v;
}

// -- the table ---------------------------------------------------------------

void test_table_lists_the_names_a_shell_imports() {
    ExportList list;
    add_gdi32(list);

    bool addressed = true;
    for (const HostExport& entry : list) {
        if (entry.name.empty() || entry.address == 0) {
            addressed = false;
        }
    }
    check(addressed, "gdi32: every entry has a name and an address");

    // The names a packed program reaches for while it paints a window, a
    // splash screen or a licence dialog. Each has to be in the table or the
    // import it belongs to would fail to bind.
    const char* const wanted[] = {
        "GetDC",           "ReleaseDC",        "CreateCompatibleDC",
        "CreateCompatibleBitmap", "SelectObject", "DeleteObject",
        "CreatePen",       "CreateSolidBrush", "GetStockObject",
        "MoveToEx",        "LineTo",           "Rectangle",
        "SetPixel",        "GetPixel",         "PatBlt",
        "BitBlt",          "StretchBlt",       "CreateDIBSection",
        "TextOutA",        "TextOutW",         "DrawTextA",
        "GetTextExtentPoint32A", "SetTextColor", "GetTextColor",
        "SetBkMode",       "GetDeviceCaps",    "CreateRectRgn",
        "PtInRegion",      "CombineRgn",       "BeginPath",
        "EndPath",         "GetPath",          "SaveDC",
        "RestoreDC",
    };
    for (const char* name : wanted) {
        bool found = false;
        for (const HostExport& entry : list) {
            if (entry.name == name) {
                found = true;
                break;
            }
        }
        check(found, (std::string("gdi32: exports ") + name).c_str());
    }
}

// -- the screen context ------------------------------------------------------

void test_screen_context_reports_the_display() {
    const std::uint64_t dc = u32g_GetDC(0);
    check(dc != 0, "gdi32: GetDC(0) hands out a context");

    check(u32g_GetDeviceCaps(dc, kBitsPixel) == 32,
          "gdi32: the screen is 32 bits per pixel");
    check(u32g_GetDeviceCaps(dc, kPlanes) == 1,
          "gdi32: the screen has one plane");
    check(u32g_GetDeviceCaps(dc, kHorzres) == 1920,
          "gdi32: the screen is 1920 pixels wide");
    check(u32g_GetDeviceCaps(dc, kVertres) == 1080,
          "gdi32: the screen is 1080 pixels tall");
    check(u32g_GetDeviceCaps(dc, kColorres) == 0x00FFFFFF,
          "gdi32: the screen carries 24 colour bits");

    // A window context is the same screen.
    const std::uint64_t wdc = u32g_GetWindowDC(0);
    check(u32g_GetDeviceCaps(wdc, kHorzres) == 1920,
          "gdi32: a window context is over the screen");
    check(u32g_ReleaseDC(0, wdc) == 1, "gdi32: ReleaseDC accepts its own");

    // A pixel written is a pixel read, and the write reports what it covered.
    const std::uint32_t old = u32g_SetPixel(dc, 5, 5, kColorBlue);
    check(u32g_GetPixel(dc, 5, 5) == kColorBlue,
          "gdi32: a pixel written reads back the colour it was given");
    (void)old;

    check(u32g_ReleaseDC(0, dc) == 1,
          "gdi32: ReleaseDC accepts a screen context");
    check(u32g_DeleteDC(dc) == 0,
          "gdi32: a context already released is gone");

    // Handles that name nothing are refused rather than answered.
    check(u32g_GetPixel(0xDEAD0000, 0, 0) == kClrInvalid,
          "gdi32: GetPixel on an unknown context reports no pixel");
    check(u32g_DeleteDC(0xDEAD0000) == 0,
          "gdi32: DeleteDC on an unknown context fails");
    check(u32g_ReleaseDC(0, 0xDEAD0000) == 0,
          "gdi32: ReleaseDC on an unknown context fails");
}

// -- objects and a memory context --------------------------------------------

void test_memory_context_draws_through_its_objects() {
    const std::uint64_t dc = u32g_CreateCompatibleDC(0);
    check(dc != 0, "gdi32: CreateCompatibleDC hands out a context");

    // A fresh memory context carries no bitmap, so there is nothing to read.
    check(u32g_GetPixel(dc, 0, 0) == kClrInvalid,
          "gdi32: a memory context with no bitmap reads back no pixel");

    const std::uint64_t bmp =
        u32g_CreateCompatibleBitmap(dc, 32, 32);
    check(bmp != 0, "gdi32: CreateCompatibleBitmap hands out a bitmap");
    check(u32g_GetObjectType(bmp) == kObjBitmap,
          "gdi32: a bitmap reports itself as a bitmap");

    std::uint8_t info[0x20];
    std::memset(info, 0, sizeof(info));
    check(u32g_GetObjectA(bmp, 0x20, info) == 0x20,
          "gdi32: GetObject fills a BITMAP");
    check(get_s32(info, 4) == 32 && get_s32(info, 8) == 32,
          "gdi32: the bitmap remembers the size it was made");

    check(u32g_SelectObject(dc, bmp) == 0,
          "gdi32: a fresh memory context held no bitmap to displace");
    check(u32g_GetDeviceCaps(dc, kHorzres) == 32,
          "gdi32: the context takes the bitmap's size");

    // A pen draws what it was created with.
    const std::uint64_t pen = u32g_CreatePen(kPsSolid, 1, kColorGreen);
    check(pen != 0, "gdi32: CreatePen hands out a pen");
    check(u32g_GetObjectType(pen) == kObjPen,
          "gdi32: a pen reports itself as a pen");
    check(u32g_SelectObject(dc, pen) != 0,
          "gdi32: selecting a pen answers the one it displaced");
    check(u32g_MoveToEx(dc, 0, 0, nullptr) == 0,
          "gdi32: the first MoveToEx has no previous position");
    check(u32g_LineTo(dc, 16, 0) == 1, "gdi32: LineTo draws a line");
    check(u32g_GetPixel(dc, 8, 0) == kColorGreen,
          "gdi32: a line lands in the pen's colour");
    check(u32g_GetPixel(dc, 8, 4) == 0x00000000,
          "gdi32: a line only lands where it was drawn");

    // A solid brush fills the rectangle; the pen frames it.
    const std::uint64_t brush = u32g_CreateSolidBrush(kColorBlue);
    check(brush != 0, "gdi32: CreateSolidBrush hands out a brush");
    check(u32g_SelectObject(dc, brush) != 0,
          "gdi32: selecting a brush answers the one it displaced");
    check(u32g_Rectangle(dc, 8, 8, 24, 24) == 1,
          "gdi32: Rectangle draws");
    check(u32g_GetPixel(dc, 16, 16) == kColorBlue,
          "gdi32: a rectangle's interior is the brush's colour");
    check(u32g_GetPixel(dc, 8, 8) == kColorGreen,
          "gdi32: a rectangle's frame is the pen's colour");

    // The context state is saved and put back.
    check(u32g_SetTextColor(dc, kColorBlue) == kColorBlack,
          "gdi32: SetTextColor answers the colour it displaced");
    check(u32g_GetTextColor(dc) == kColorBlue,
          "gdi32: the text colour is the one that was set");
    check(u32g_SaveDC(dc) == 1, "gdi32: SaveDC answers the saved state's id");
    check(u32g_SetTextColor(dc, kColorGreen) == kColorBlue,
          "gdi32: the text colour changed after the save");
    check(u32g_RestoreDC(dc, -1) == 1,
          "gdi32: RestoreDC(-1) puts the last save back");
    check(u32g_GetTextColor(dc) == kColorBlue,
          "gdi32: RestoreDC brought the saved text colour back");

    // The raster operation is read and set.
    check(u32g_GetROP2(dc) == kR2Copypen,
          "gdi32: a fresh context copies the pen");
    check(u32g_SetROP2(dc, kR2Not) == kR2Copypen,
          "gdi32: SetROP2 answers the mode it displaced");
    check(u32g_GetROP2(dc) == kR2Not, "gdi32: the new raster mode is in force");
    check(u32g_SetROP2(dc, kR2Copypen) == kR2Not,
          "gdi32: the raster mode can be put back");

    // A pattern blit fills with the brush, not the pen.
    check(u32g_PatBlt(dc, 0, 28, 32, 4, kPatCopy) == 1,
          "gdi32: PatBlt fills");
    check(u32g_GetPixel(dc, 4, 29) == kColorBlue,
          "gdi32: PatBlt fills with the context's brush");

    // A stock object belongs to the runtime; a made one belongs to the caller.
    const std::uint64_t stock = u32g_GetStockObject(kStockWhiteBrush);
    check(stock != 0, "gdi32: GetStockObject hands out the stock brush");
    check(u32g_DeleteObject(stock) == 0,
          "gdi32: a stock object is not the caller's to destroy");
    check(u32g_GetStockObject(kStockBlackPen) != 0,
          "gdi32: the stock black pen exists");
    check(u32g_DeleteObject(brush) == 1,
          "gdi32: a caller's brush is the caller's to destroy");

    check(u32g_DeleteDC(dc) == 1, "gdi32: DeleteDC frees the memory context");
}

// -- the DIB section ---------------------------------------------------------

void test_dib_section_bits_are_the_guests() {
    // A 4x4, 32-bit, bottom-up section. The header is a BITMAPINFOHEADER at
    // its 64-bit layout: size, width, height, planes, bit count.
    std::uint8_t header[40];
    std::memset(header, 0, sizeof(header));
    put_s32(header, 0, 40);
    put_s32(header, 4, 4);
    put_s32(header, 8, 4);
    put_u16(header, 12, 1);
    put_u16(header, 14, 32);
    put_s32(header, 16, 0);

    void* bits = nullptr;
    const std::uint64_t dib =
        u32g_CreateDIBSection(0, header, 0, &bits, 0, 0);
    check(dib != 0, "gdi32: CreateDIBSection hands out a bitmap");
    check(bits != nullptr, "gdi32: the section's bits are handed back");
    check(u32g_GetObjectType(dib) == kObjBitmap,
          "gdi32: a DIB section is a bitmap");

    const std::uint64_t dc = u32g_CreateCompatibleDC(0);
    check(u32g_SelectObject(dc, dib) == 0,
          "gdi32: the fresh context held no bitmap to displace");
    check(u32g_GetDeviceCaps(dc, kHorzres) == 4,
          "gdi32: the context took the section's width");

    // A draw through the context lands in the guest's own memory, which is
    // what a program that hands the bits to another API relies on.
    check(u32g_SetPixel(dc, 1, 1, kColorGreen) == 0,
          "gdi32: the section started all zero");
    check(u32g_GetPixel(dc, 1, 1) == kColorGreen,
          "gdi32: the pixel reads back through the context");

    // At 4 bytes a pixel the channel order is blue, green, red, unused.
    const auto* p = static_cast<const std::uint8_t*>(bits);
    const std::size_t stride = 4 * 4;  // a 32-bit row of four pixels
    check(p[1 * stride + 1 * 4 + 1] == 0xFF,
          "gdi32: the green channel is in the section's own memory");
    check(p[1 * stride + 1 * 4 + 0] == 0x00,
          "gdi32: the blue channel is clear where only green was drawn");

    check(u32g_DeleteObject(dib) == 1,
          "gdi32: the section is the caller's to destroy");
    check(u32g_DeleteDC(dc) == 1, "gdi32: the context is freed");
}

// -- a blit between two contexts ---------------------------------------------

void test_bitblt_copies_pixels() {
    const std::uint64_t screen = u32g_GetDC(0);
    // A mark at the source corner, so the copy can be told from a fill.
    check(u32g_SetPixel(screen, 60, 60, kColorBlue) == 0,
          "gdi32: the source pixel started clear");

    const std::uint64_t mem = u32g_CreateCompatibleDC(screen);
    const std::uint64_t bmp = u32g_CreateCompatibleBitmap(screen, 16, 16);
    check(u32g_SelectObject(mem, bmp) == 0,
          "gdi32: the fresh destination held no bitmap to displace");

    check(u32g_BitBlt(mem, 0, 0, 16, 16, screen, 60, 60, kSrcCopy) == 1,
          "gdi32: BitBlt copies");
    check(u32g_GetPixel(mem, 0, 0) == kColorBlue,
          "gdi32: the copied pixel is the source's colour");
    check(u32g_GetDeviceCaps(mem, kHorzres) == 16,
          "gdi32: the destination is the bitmap's own size");

    check(u32g_ReleaseDC(0, screen) == 1, "gdi32: the screen context is freed");
    check(u32g_DeleteDC(mem) == 1, "gdi32: the memory context is freed");
}

// -- text --------------------------------------------------------------------

void test_text_reports_its_cell_and_draws_ink() {
    const std::uint64_t dc = u32g_GetDC(0);

    // The built-in face is a monospace cell: eight pixels per character on a
    // sixteen-pixel line.
    std::uint8_t size[8];
    std::memset(size, 0, sizeof(size));
    check(u32g_GetTextExtentPoint32A(dc, "AB", 2, size) == 1,
          "gdi32: GetTextExtentPoint32 measures a run");
    check(get_s32(size, 0) == 16,
          "gdi32: two characters advance sixteen pixels");
    check(get_s32(size, 4) == 16, "gdi32: the line is sixteen pixels tall");

    // Text drawn in a chosen colour leaves that colour on the surface. The
    // run is placed clear of the pixels the other cases drew.
    check(u32g_SetTextColor(dc, kColorRed) == 0,
          "gdi32: the text colour was the default black");
    check(u32g_TextOutA(dc, 0, 800, "I", 1) == 1,
          "gdi32: TextOut draws a run");

    // The glyph is a vertical stroke, so the chosen colour is present.
    bool ink = false;
    for (std::int32_t y = 800; y < 816 && !ink; ++y) {
        for (std::int32_t x = 0; x < 8; ++x) {
            if (u32g_GetPixel(dc, x, y) == kColorRed) {
                ink = true;
                break;
            }
        }
    }
    check(ink, "gdi32: the drawn text is the text colour");

    // Outside the run's box the surface is untouched by it.
    check(u32g_GetPixel(dc, 40, 800) != kColorRed,
          "gdi32: text stays within its advance");

    check(u32g_ReleaseDC(0, dc) == 1, "gdi32: the screen context is freed");
}

// -- regions -----------------------------------------------------------------

void test_regions_answer_point_tests() {
    const std::uint64_t a = u32g_CreateRectRgn(10, 10, 20, 20);
    check(a != 0, "gdi32: CreateRectRgn hands out a region");
    check(u32g_PtInRegion(a, 15, 15) == 1,
          "gdi32: an interior point is in the region");
    check(u32g_PtInRegion(a, 5, 5) == 0,
          "gdi32: a point before the region is not in it");
    check(u32g_PtInRegion(a, 20, 20) == 0,
          "gdi32: the right and bottom edges are outside");

    std::uint8_t box[16];
    std::memset(box, 0, sizeof(box));
    check(u32g_GetRgnBox(a, box) == kSimpleRegion,
          "gdi32: a rectangle region is simple");
    check(get_s32(box, 0) == 10 && get_s32(box, 4) == 10 &&
              get_s32(box, 8) == 20 && get_s32(box, 12) == 20,
          "gdi32: the region's box is the rectangle it was made from");

    // Two separated rectangles unioned into one region stay two rectangles,
    // which is what a complex region is.
    const std::uint64_t b = u32g_CreateRectRgn(30, 30, 40, 40);
    const std::uint64_t dst = u32g_CreateRectRgn(0, 0, 0, 0);
    check(u32g_CombineRgn(dst, a, b, kRgnOr) == kComplexRegion,
          "gdi32: a union of separated rectangles is complex");
    check(u32g_PtInRegion(dst, 15, 15) == 1,
          "gdi32: the union holds the first rectangle");
    check(u32g_PtInRegion(dst, 35, 35) == 1,
          "gdi32: the union holds the second rectangle");
    check(u32g_PtInRegion(dst, 25, 25) == 0,
          "gdi32: the union does not hold the gap between them");

    std::memset(box, 0, sizeof(box));
    check(u32g_GetRgnBox(dst, box) == kSimpleRegion,
          "gdi32: the union's box answers");
    check(get_s32(box, 0) == 10 && get_s32(box, 8) == 40,
          "gdi32: the union's box spans both rectangles");
}

// -- paths -------------------------------------------------------------------

void test_paths_record_the_line_calls() {
    const std::uint64_t dc = u32g_CreateCompatibleDC(0);
    const std::uint64_t bmp = u32g_CreateCompatibleBitmap(dc, 32, 32);
    check(u32g_SelectObject(dc, bmp) == 0,
          "gdi32: the fresh context held no bitmap to displace");

    check(u32g_BeginPath(dc) == 1, "gdi32: BeginPath opens a path");
    (void)u32g_MoveToEx(dc, 0, 0, nullptr);
    check(u32g_LineTo(dc, 16, 0) == 1, "gdi32: a line is added to the path");
    check(u32g_EndPath(dc) == 1, "gdi32: EndPath closes the path");

    const std::int32_t total = u32g_GetPath(dc, nullptr, nullptr, 0);
    check(total == 2, "gdi32: the path holds the move and the line");

    std::uint8_t points[2 * 8];
    std::uint8_t types[2];
    std::memset(points, 0, sizeof(points));
    std::memset(types, 0, sizeof(types));
    check(u32g_GetPath(dc, points, types, 2) == 2,
          "gdi32: GetPath fills the points and types");
    check(get_s32(points, 0) == 0 && get_s32(points, 4) == 0,
          "gdi32: the first point is the move's");
    check(get_s32(points, 8) == 16 && get_s32(points, 12) == 0,
          "gdi32: the second point is the line's end");
    check(types[0] == kPtMoveTo, "gdi32: the first type is PT_MOVETO");
    check(types[1] == kPtLineTo, "gdi32: the second type is PT_LINETO");

    check(u32g_DeleteDC(dc) == 1, "gdi32: the context is freed");
}

}  // namespace

int main() {
    test_table_lists_the_names_a_shell_imports();
    test_screen_context_reports_the_display();
    test_memory_context_draws_through_its_objects();
    test_dib_section_bits_are_the_guests();
    test_bitblt_copies_pixels();
    test_text_reports_its_cell_and_draws_ink();
    test_regions_answer_point_tests();
    test_paths_record_the_line_calls();

    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks, 0 failures\n", checks);
    return 0;
}

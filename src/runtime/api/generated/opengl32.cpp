// The OPENGL32 surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) void kopengl32G_glAccum(std::uint32_t op, float value) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(op);
    static_cast<void>(value);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glAlphaFunc(std::uint32_t func, float ref) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(func);
    static_cast<void>(ref);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t kopengl32G_glAreTexturesResident(std::int32_t n, const std::uint32_t* textures, std::uint8_t* residences) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(n);
    static_cast<void>(textures);
    static_cast<void>(residences);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glArrayElement(std::int32_t i) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(i);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glBegin(std::uint32_t mode) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(mode);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glBindTexture(std::uint32_t target, std::uint32_t texture) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(texture);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glBitmap(std::int32_t width, std::int32_t height, float xorig, float yorig, float xmove, float ymove, const std::uint8_t* bitmap) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(width);
    static_cast<void>(height);
    static_cast<void>(xorig);
    static_cast<void>(yorig);
    static_cast<void>(xmove);
    static_cast<void>(ymove);
    static_cast<void>(bitmap);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glBlendFunc(std::uint32_t sfactor, std::uint32_t dfactor) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(sfactor);
    static_cast<void>(dfactor);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glCallList(std::uint32_t list) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(list);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glCallLists(std::int32_t n, std::uint32_t type, const void* lists) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(n);
    static_cast<void>(type);
    static_cast<void>(lists);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glClear(std::uint32_t mask) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(mask);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glClearAccum(float red, float green, float blue, float alpha) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(red);
    static_cast<void>(green);
    static_cast<void>(blue);
    static_cast<void>(alpha);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glClearColor(float red, float green, float blue, float alpha) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(red);
    static_cast<void>(green);
    static_cast<void>(blue);
    static_cast<void>(alpha);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glClearDepth(double depth) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(depth);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glClearIndex(float c) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(c);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glClearStencil(std::int32_t s) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(s);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glClipPlane(std::uint32_t plane, const double* equation) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(plane);
    static_cast<void>(equation);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor3b(std::int8_t red, std::int8_t green, std::int8_t blue) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(red);
    static_cast<void>(green);
    static_cast<void>(blue);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor3bv(const std::int8_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor3d(double red, double green, double blue) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(red);
    static_cast<void>(green);
    static_cast<void>(blue);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor3dv(const double* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor3f(float red, float green, float blue) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(red);
    static_cast<void>(green);
    static_cast<void>(blue);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor3fv(const float* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor3i(std::int32_t red, std::int32_t green, std::int32_t blue) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(red);
    static_cast<void>(green);
    static_cast<void>(blue);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor3iv(const std::int32_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor3s(std::int16_t red, std::int16_t green, std::int16_t blue) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(red);
    static_cast<void>(green);
    static_cast<void>(blue);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor3sv(const std::int16_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor3ub(std::uint8_t red, std::uint8_t green, std::uint8_t blue) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(red);
    static_cast<void>(green);
    static_cast<void>(blue);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor3ubv(const std::uint8_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor3ui(std::uint32_t red, std::uint32_t green, std::uint32_t blue) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(red);
    static_cast<void>(green);
    static_cast<void>(blue);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor3uiv(const std::uint32_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor3us(std::uint16_t red, std::uint16_t green, std::uint16_t blue) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(red);
    static_cast<void>(green);
    static_cast<void>(blue);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor3usv(const std::uint16_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor4b(std::int8_t red, std::int8_t green, std::int8_t blue, std::int8_t alpha) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(red);
    static_cast<void>(green);
    static_cast<void>(blue);
    static_cast<void>(alpha);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor4bv(const std::int8_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor4d(double red, double green, double blue, double alpha) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(red);
    static_cast<void>(green);
    static_cast<void>(blue);
    static_cast<void>(alpha);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor4dv(const double* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor4f(float red, float green, float blue, float alpha) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(red);
    static_cast<void>(green);
    static_cast<void>(blue);
    static_cast<void>(alpha);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor4fv(const float* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor4i(std::int32_t red, std::int32_t green, std::int32_t blue, std::int32_t alpha) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(red);
    static_cast<void>(green);
    static_cast<void>(blue);
    static_cast<void>(alpha);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor4iv(const std::int32_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor4s(std::int16_t red, std::int16_t green, std::int16_t blue, std::int16_t alpha) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(red);
    static_cast<void>(green);
    static_cast<void>(blue);
    static_cast<void>(alpha);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor4sv(const std::int16_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor4ub(std::uint8_t red, std::uint8_t green, std::uint8_t blue, std::uint8_t alpha) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(red);
    static_cast<void>(green);
    static_cast<void>(blue);
    static_cast<void>(alpha);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor4ubv(const std::uint8_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor4ui(std::uint32_t red, std::uint32_t green, std::uint32_t blue, std::uint32_t alpha) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(red);
    static_cast<void>(green);
    static_cast<void>(blue);
    static_cast<void>(alpha);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor4uiv(const std::uint32_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor4us(std::uint16_t red, std::uint16_t green, std::uint16_t blue, std::uint16_t alpha) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(red);
    static_cast<void>(green);
    static_cast<void>(blue);
    static_cast<void>(alpha);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColor4usv(const std::uint16_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColorMask(std::uint8_t red, std::uint8_t green, std::uint8_t blue, std::uint8_t alpha) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(red);
    static_cast<void>(green);
    static_cast<void>(blue);
    static_cast<void>(alpha);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColorMaterial(std::uint32_t face, std::uint32_t mode) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(face);
    static_cast<void>(mode);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glColorPointer(std::int32_t size, std::uint32_t type, std::int32_t stride, const void* pointer) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(size);
    static_cast<void>(type);
    static_cast<void>(stride);
    static_cast<void>(pointer);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glCopyPixels(std::int32_t x, std::int32_t y, std::int32_t width, std::int32_t height, std::uint32_t type) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(width);
    static_cast<void>(height);
    static_cast<void>(type);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glCopyTexImage1D(std::uint32_t target, std::int32_t level, std::uint32_t internalFormat, std::int32_t x, std::int32_t y, std::int32_t width, std::int32_t border) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(level);
    static_cast<void>(internalFormat);
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(width);
    static_cast<void>(border);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glCopyTexImage2D(std::uint32_t target, std::int32_t level, std::uint32_t internalFormat, std::int32_t x, std::int32_t y, std::int32_t width, std::int32_t height, std::int32_t border) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(level);
    static_cast<void>(internalFormat);
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(width);
    static_cast<void>(height);
    static_cast<void>(border);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glCopyTexSubImage1D(std::uint32_t target, std::int32_t level, std::int32_t xoffset, std::int32_t x, std::int32_t y, std::int32_t width) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(level);
    static_cast<void>(xoffset);
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(width);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glCopyTexSubImage2D(std::uint32_t target, std::int32_t level, std::int32_t xoffset, std::int32_t yoffset, std::int32_t x, std::int32_t y, std::int32_t width, std::int32_t height) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(level);
    static_cast<void>(xoffset);
    static_cast<void>(yoffset);
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(width);
    static_cast<void>(height);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glCullFace(std::uint32_t mode) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(mode);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glDeleteLists(std::uint32_t list, std::int32_t range) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(list);
    static_cast<void>(range);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glDeleteTextures(std::int32_t n, const std::uint32_t* textures) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(n);
    static_cast<void>(textures);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glDepthFunc(std::uint32_t func) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(func);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glDepthMask(std::uint8_t flag) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(flag);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glDepthRange(double zNear, double zFar) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(zNear);
    static_cast<void>(zFar);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glDisable(std::uint32_t cap) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(cap);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glDisableClientState(std::uint32_t array) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(array);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glDrawArrays(std::uint32_t mode, std::int32_t first, std::int32_t count) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(mode);
    static_cast<void>(first);
    static_cast<void>(count);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glDrawBuffer(std::uint32_t mode) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(mode);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glDrawElements(std::uint32_t mode, std::int32_t count, std::uint32_t type, const void* indices) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(mode);
    static_cast<void>(count);
    static_cast<void>(type);
    static_cast<void>(indices);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glDrawPixels(std::int32_t width, std::int32_t height, std::uint32_t format, std::uint32_t type, const void* pixels) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(width);
    static_cast<void>(height);
    static_cast<void>(format);
    static_cast<void>(type);
    static_cast<void>(pixels);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glEdgeFlag(std::uint8_t flag) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(flag);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glEdgeFlagPointer(std::int32_t stride, const void* pointer) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(stride);
    static_cast<void>(pointer);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glEdgeFlagv(const std::uint8_t* flag) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(flag);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glEnable(std::uint32_t cap) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(cap);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glEnableClientState(std::uint32_t array) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(array);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glEnd() noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glEndList() noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glEvalCoord1d(double u) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(u);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glEvalCoord1dv(const double* u) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(u);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glEvalCoord1f(float u) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(u);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glEvalCoord1fv(const float* u) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(u);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glEvalCoord2d(double u, double v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(u);
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glEvalCoord2dv(const double* u) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(u);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glEvalCoord2f(float u, float v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(u);
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glEvalCoord2fv(const float* u) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(u);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glEvalMesh1(std::uint32_t mode, std::int32_t i1, std::int32_t i2) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(mode);
    static_cast<void>(i1);
    static_cast<void>(i2);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glEvalMesh2(std::uint32_t mode, std::int32_t i1, std::int32_t i2, std::int32_t j1, std::int32_t j2) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(mode);
    static_cast<void>(i1);
    static_cast<void>(i2);
    static_cast<void>(j1);
    static_cast<void>(j2);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glEvalPoint1(std::int32_t i) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(i);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glEvalPoint2(std::int32_t i, std::int32_t j) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(i);
    static_cast<void>(j);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glFeedbackBuffer(std::int32_t size, std::uint32_t type, float* buffer) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(size);
    static_cast<void>(type);
    static_cast<void>(buffer);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glFinish() noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glFlush() noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glFogf(std::uint32_t pname, float param) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(pname);
    static_cast<void>(param);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glFogfv(std::uint32_t pname, const float* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glFogi(std::uint32_t pname, std::int32_t param) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(pname);
    static_cast<void>(param);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glFogiv(std::uint32_t pname, const std::int32_t* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glFrontFace(std::uint32_t mode) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(mode);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glFrustum(double left, double right, double bottom, double top, double zNear, double zFar) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(left);
    static_cast<void>(right);
    static_cast<void>(bottom);
    static_cast<void>(top);
    static_cast<void>(zNear);
    static_cast<void>(zFar);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kopengl32G_glGenLists(std::int32_t range) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(range);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGenTextures(std::int32_t n, std::uint32_t* textures) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(n);
    static_cast<void>(textures);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetBooleanv(std::uint32_t pname, std::uint8_t* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetClipPlane(std::uint32_t plane, double* equation) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(plane);
    static_cast<void>(equation);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetDoublev(std::uint32_t pname, double* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kopengl32G_glGetError() noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetFloatv(std::uint32_t pname, float* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetIntegerv(std::uint32_t pname, std::int32_t* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetLightfv(std::uint32_t light, std::uint32_t pname, float* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(light);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetLightiv(std::uint32_t light, std::uint32_t pname, std::int32_t* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(light);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetMapdv(std::uint32_t target, std::uint32_t query, double* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(query);
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetMapfv(std::uint32_t target, std::uint32_t query, float* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(query);
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetMapiv(std::uint32_t target, std::uint32_t query, std::int32_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(query);
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetMaterialfv(std::uint32_t face, std::uint32_t pname, float* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(face);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetMaterialiv(std::uint32_t face, std::uint32_t pname, std::int32_t* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(face);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetPixelMapfv(std::uint32_t map, float* values) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(map);
    static_cast<void>(values);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetPixelMapuiv(std::uint32_t map, std::uint32_t* values) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(map);
    static_cast<void>(values);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetPixelMapusv(std::uint32_t map, std::uint16_t* values) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(map);
    static_cast<void>(values);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetPointerv(std::uint32_t pname, void** params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetPolygonStipple(std::uint8_t* mask) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(mask);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t* kopengl32G_glGetString(std::uint32_t name) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(name);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetTexEnvfv(std::uint32_t target, std::uint32_t pname, float* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetTexEnviv(std::uint32_t target, std::uint32_t pname, std::int32_t* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetTexGendv(std::uint32_t coord, std::uint32_t pname, double* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(coord);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetTexGenfv(std::uint32_t coord, std::uint32_t pname, float* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(coord);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetTexGeniv(std::uint32_t coord, std::uint32_t pname, std::int32_t* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(coord);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetTexImage(std::uint32_t target, std::int32_t level, std::uint32_t format, std::uint32_t type, void* pixels) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(level);
    static_cast<void>(format);
    static_cast<void>(type);
    static_cast<void>(pixels);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetTexLevelParameterfv(std::uint32_t target, std::int32_t level, std::uint32_t pname, float* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(level);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetTexLevelParameteriv(std::uint32_t target, std::int32_t level, std::uint32_t pname, std::int32_t* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(level);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetTexParameterfv(std::uint32_t target, std::uint32_t pname, float* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glGetTexParameteriv(std::uint32_t target, std::uint32_t pname, std::int32_t* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glHint(std::uint32_t target, std::uint32_t mode) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(mode);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glIndexMask(std::uint32_t mask) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(mask);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glIndexPointer(std::uint32_t type, std::int32_t stride, const void* pointer) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(type);
    static_cast<void>(stride);
    static_cast<void>(pointer);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glIndexd(double c) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(c);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glIndexdv(const double* c) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(c);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glIndexf(float c) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(c);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glIndexfv(const float* c) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(c);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glIndexi(std::int32_t c) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(c);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glIndexiv(const std::int32_t* c) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(c);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glIndexs(std::int16_t c) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(c);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glIndexsv(const std::int16_t* c) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(c);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glIndexub(std::uint8_t c) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(c);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glIndexubv(const std::uint8_t* c) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(c);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glInitNames() noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glInterleavedArrays(std::uint32_t format, std::int32_t stride, const void* pointer) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(format);
    static_cast<void>(stride);
    static_cast<void>(pointer);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t kopengl32G_glIsEnabled(std::uint32_t cap) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(cap);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kopengl32G_glIsList(std::uint32_t list) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(list);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kopengl32G_glIsTexture(std::uint32_t texture) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(texture);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glLightModelf(std::uint32_t pname, float param) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(pname);
    static_cast<void>(param);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glLightModelfv(std::uint32_t pname, const float* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glLightModeli(std::uint32_t pname, std::int32_t param) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(pname);
    static_cast<void>(param);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glLightModeliv(std::uint32_t pname, const std::int32_t* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glLightf(std::uint32_t light, std::uint32_t pname, float param) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(light);
    static_cast<void>(pname);
    static_cast<void>(param);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glLightfv(std::uint32_t light, std::uint32_t pname, const float* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(light);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glLighti(std::uint32_t light, std::uint32_t pname, std::int32_t param) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(light);
    static_cast<void>(pname);
    static_cast<void>(param);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glLightiv(std::uint32_t light, std::uint32_t pname, const std::int32_t* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(light);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glLineStipple(std::int32_t factor, std::uint16_t pattern) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(factor);
    static_cast<void>(pattern);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glLineWidth(float width) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(width);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glListBase(std::uint32_t base) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(base);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glLoadIdentity() noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glLoadMatrixd(const double* m) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(m);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glLoadMatrixf(const float* m) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(m);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glLoadName(std::uint32_t name) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(name);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glLogicOp(std::uint32_t opcode) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(opcode);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glMap1d(std::uint32_t target, double u1, double u2, std::int32_t stride, std::int32_t order, const double* points) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(u1);
    static_cast<void>(u2);
    static_cast<void>(stride);
    static_cast<void>(order);
    static_cast<void>(points);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glMap1f(std::uint32_t target, float u1, float u2, std::int32_t stride, std::int32_t order, const float* points) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(u1);
    static_cast<void>(u2);
    static_cast<void>(stride);
    static_cast<void>(order);
    static_cast<void>(points);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glMap2d(std::uint32_t target, double u1, double u2, std::int32_t ustride, std::int32_t uorder, double v1, double v2, std::int32_t vstride, std::int32_t vorder, const double* points) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(u1);
    static_cast<void>(u2);
    static_cast<void>(ustride);
    static_cast<void>(uorder);
    static_cast<void>(v1);
    static_cast<void>(v2);
    static_cast<void>(vstride);
    static_cast<void>(vorder);
    static_cast<void>(points);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glMap2f(std::uint32_t target, float u1, float u2, std::int32_t ustride, std::int32_t uorder, float v1, float v2, std::int32_t vstride, std::int32_t vorder, const float* points) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(u1);
    static_cast<void>(u2);
    static_cast<void>(ustride);
    static_cast<void>(uorder);
    static_cast<void>(v1);
    static_cast<void>(v2);
    static_cast<void>(vstride);
    static_cast<void>(vorder);
    static_cast<void>(points);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glMapGrid1d(std::int32_t un, double u1, double u2) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(un);
    static_cast<void>(u1);
    static_cast<void>(u2);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glMapGrid1f(std::int32_t un, float u1, float u2) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(un);
    static_cast<void>(u1);
    static_cast<void>(u2);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glMapGrid2d(std::int32_t un, double u1, double u2, std::int32_t vn, double v1, double v2) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(un);
    static_cast<void>(u1);
    static_cast<void>(u2);
    static_cast<void>(vn);
    static_cast<void>(v1);
    static_cast<void>(v2);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glMapGrid2f(std::int32_t un, float u1, float u2, std::int32_t vn, float v1, float v2) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(un);
    static_cast<void>(u1);
    static_cast<void>(u2);
    static_cast<void>(vn);
    static_cast<void>(v1);
    static_cast<void>(v2);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glMaterialf(std::uint32_t face, std::uint32_t pname, float param) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(face);
    static_cast<void>(pname);
    static_cast<void>(param);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glMaterialfv(std::uint32_t face, std::uint32_t pname, const float* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(face);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glMateriali(std::uint32_t face, std::uint32_t pname, std::int32_t param) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(face);
    static_cast<void>(pname);
    static_cast<void>(param);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glMaterialiv(std::uint32_t face, std::uint32_t pname, const std::int32_t* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(face);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glMatrixMode(std::uint32_t mode) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(mode);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glMultMatrixd(const double* m) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(m);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glMultMatrixf(const float* m) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(m);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glNewList(std::uint32_t list, std::uint32_t mode) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(list);
    static_cast<void>(mode);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glNormal3b(std::int8_t nx, std::int8_t ny, std::int8_t nz) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(nx);
    static_cast<void>(ny);
    static_cast<void>(nz);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glNormal3bv(const std::int8_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glNormal3d(double nx, double ny, double nz) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(nx);
    static_cast<void>(ny);
    static_cast<void>(nz);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glNormal3dv(const double* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glNormal3f(float nx, float ny, float nz) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(nx);
    static_cast<void>(ny);
    static_cast<void>(nz);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glNormal3fv(const float* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glNormal3i(std::int32_t nx, std::int32_t ny, std::int32_t nz) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(nx);
    static_cast<void>(ny);
    static_cast<void>(nz);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glNormal3iv(const std::int32_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glNormal3s(std::int16_t nx, std::int16_t ny, std::int16_t nz) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(nx);
    static_cast<void>(ny);
    static_cast<void>(nz);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glNormal3sv(const std::int16_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glNormalPointer(std::uint32_t type, std::int32_t stride, const void* pointer) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(type);
    static_cast<void>(stride);
    static_cast<void>(pointer);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glOrtho(double left, double right, double bottom, double top, double zNear, double zFar) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(left);
    static_cast<void>(right);
    static_cast<void>(bottom);
    static_cast<void>(top);
    static_cast<void>(zNear);
    static_cast<void>(zFar);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPassThrough(float token) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(token);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPixelMapfv(std::uint32_t map, std::int32_t mapsize, const float* values) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(map);
    static_cast<void>(mapsize);
    static_cast<void>(values);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPixelMapuiv(std::uint32_t map, std::int32_t mapsize, const std::uint32_t* values) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(map);
    static_cast<void>(mapsize);
    static_cast<void>(values);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPixelMapusv(std::uint32_t map, std::int32_t mapsize, const std::uint16_t* values) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(map);
    static_cast<void>(mapsize);
    static_cast<void>(values);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPixelStoref(std::uint32_t pname, float param) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(pname);
    static_cast<void>(param);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPixelStorei(std::uint32_t pname, std::int32_t param) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(pname);
    static_cast<void>(param);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPixelTransferf(std::uint32_t pname, float param) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(pname);
    static_cast<void>(param);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPixelTransferi(std::uint32_t pname, std::int32_t param) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(pname);
    static_cast<void>(param);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPixelZoom(float xfactor, float yfactor) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(xfactor);
    static_cast<void>(yfactor);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPointSize(float size) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(size);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPolygonMode(std::uint32_t face, std::uint32_t mode) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(face);
    static_cast<void>(mode);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPolygonOffset(float factor, float units) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(factor);
    static_cast<void>(units);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPolygonStipple(const std::uint8_t* mask) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(mask);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPopAttrib() noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPopClientAttrib() noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPopMatrix() noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPopName() noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPrioritizeTextures(std::int32_t n, const std::uint32_t* textures, const float* priorities) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(n);
    static_cast<void>(textures);
    static_cast<void>(priorities);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPushAttrib(std::uint32_t mask) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(mask);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPushClientAttrib(std::uint32_t mask) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(mask);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPushMatrix() noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glPushName(std::uint32_t name) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(name);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos2d(double x, double y) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos2dv(const double* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos2f(float x, float y) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos2fv(const float* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos2i(std::int32_t x, std::int32_t y) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos2iv(const std::int32_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos2s(std::int16_t x, std::int16_t y) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos2sv(const std::int16_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos3d(double x, double y, double z) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos3dv(const double* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos3f(float x, float y, float z) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos3fv(const float* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos3i(std::int32_t x, std::int32_t y, std::int32_t z) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos3iv(const std::int32_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos3s(std::int16_t x, std::int16_t y, std::int16_t z) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos3sv(const std::int16_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos4d(double x, double y, double z, double w) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    static_cast<void>(w);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos4dv(const double* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos4f(float x, float y, float z, float w) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    static_cast<void>(w);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos4fv(const float* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos4i(std::int32_t x, std::int32_t y, std::int32_t z, std::int32_t w) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    static_cast<void>(w);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos4iv(const std::int32_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos4s(std::int16_t x, std::int16_t y, std::int16_t z, std::int16_t w) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    static_cast<void>(w);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRasterPos4sv(const std::int16_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glReadBuffer(std::uint32_t mode) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(mode);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glReadPixels(std::int32_t x, std::int32_t y, std::int32_t width, std::int32_t height, std::uint32_t format, std::uint32_t type, void* pixels) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(width);
    static_cast<void>(height);
    static_cast<void>(format);
    static_cast<void>(type);
    static_cast<void>(pixels);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRectd(double x1, double y1, double x2, double y2) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x1);
    static_cast<void>(y1);
    static_cast<void>(x2);
    static_cast<void>(y2);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRectdv(const double* v1, const double* v2) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v1);
    static_cast<void>(v2);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRectf(float x1, float y1, float x2, float y2) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x1);
    static_cast<void>(y1);
    static_cast<void>(x2);
    static_cast<void>(y2);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRectfv(const float* v1, const float* v2) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v1);
    static_cast<void>(v2);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRecti(std::int32_t x1, std::int32_t y1, std::int32_t x2, std::int32_t y2) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x1);
    static_cast<void>(y1);
    static_cast<void>(x2);
    static_cast<void>(y2);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRectiv(const std::int32_t* v1, const std::int32_t* v2) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v1);
    static_cast<void>(v2);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRects(std::int16_t x1, std::int16_t y1, std::int16_t x2, std::int16_t y2) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x1);
    static_cast<void>(y1);
    static_cast<void>(x2);
    static_cast<void>(y2);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRectsv(const std::int16_t* v1, const std::int16_t* v2) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v1);
    static_cast<void>(v2);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kopengl32G_glRenderMode(std::uint32_t mode) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(mode);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRotated(double angle, double x, double y, double z) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(angle);
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glRotatef(float angle, float x, float y, float z) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(angle);
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glScaled(double x, double y, double z) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glScalef(float x, float y, float z) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glScissor(std::int32_t x, std::int32_t y, std::int32_t width, std::int32_t height) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(width);
    static_cast<void>(height);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glSelectBuffer(std::int32_t size, std::uint32_t* buffer) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(size);
    static_cast<void>(buffer);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glShadeModel(std::uint32_t mode) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(mode);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glStencilFunc(std::uint32_t func, std::int32_t ref, std::uint32_t mask) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(func);
    static_cast<void>(ref);
    static_cast<void>(mask);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glStencilMask(std::uint32_t mask) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(mask);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glStencilOp(std::uint32_t fail, std::uint32_t zfail, std::uint32_t zpass) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(fail);
    static_cast<void>(zfail);
    static_cast<void>(zpass);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord1d(double s) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(s);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord1dv(const double* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord1f(float s) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(s);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord1fv(const float* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord1i(std::int32_t s) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(s);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord1iv(const std::int32_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord1s(std::int16_t s) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(s);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord1sv(const std::int16_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord2d(double s, double t) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(s);
    static_cast<void>(t);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord2dv(const double* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord2f(float s, float t) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(s);
    static_cast<void>(t);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord2fv(const float* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord2i(std::int32_t s, std::int32_t t) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(s);
    static_cast<void>(t);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord2iv(const std::int32_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord2s(std::int16_t s, std::int16_t t) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(s);
    static_cast<void>(t);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord2sv(const std::int16_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord3d(double s, double t, double r) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(s);
    static_cast<void>(t);
    static_cast<void>(r);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord3dv(const double* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord3f(float s, float t, float r) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(s);
    static_cast<void>(t);
    static_cast<void>(r);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord3fv(const float* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord3i(std::int32_t s, std::int32_t t, std::int32_t r) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(s);
    static_cast<void>(t);
    static_cast<void>(r);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord3iv(const std::int32_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord3s(std::int16_t s, std::int16_t t, std::int16_t r) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(s);
    static_cast<void>(t);
    static_cast<void>(r);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord3sv(const std::int16_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord4d(double s, double t, double r, double q) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(s);
    static_cast<void>(t);
    static_cast<void>(r);
    static_cast<void>(q);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord4dv(const double* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord4f(float s, float t, float r, float q) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(s);
    static_cast<void>(t);
    static_cast<void>(r);
    static_cast<void>(q);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord4fv(const float* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord4i(std::int32_t s, std::int32_t t, std::int32_t r, std::int32_t q) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(s);
    static_cast<void>(t);
    static_cast<void>(r);
    static_cast<void>(q);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord4iv(const std::int32_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord4s(std::int16_t s, std::int16_t t, std::int16_t r, std::int16_t q) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(s);
    static_cast<void>(t);
    static_cast<void>(r);
    static_cast<void>(q);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoord4sv(const std::int16_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexCoordPointer(std::int32_t size, std::uint32_t type, std::int32_t stride, const void* pointer) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(size);
    static_cast<void>(type);
    static_cast<void>(stride);
    static_cast<void>(pointer);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexEnvf(std::uint32_t target, std::uint32_t pname, float param) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(pname);
    static_cast<void>(param);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexEnvfv(std::uint32_t target, std::uint32_t pname, const float* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexEnvi(std::uint32_t target, std::uint32_t pname, std::int32_t param) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(pname);
    static_cast<void>(param);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexEnviv(std::uint32_t target, std::uint32_t pname, const std::int32_t* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexGend(std::uint32_t coord, std::uint32_t pname, double param) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(coord);
    static_cast<void>(pname);
    static_cast<void>(param);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexGendv(std::uint32_t coord, std::uint32_t pname, const double* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(coord);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexGenf(std::uint32_t coord, std::uint32_t pname, float param) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(coord);
    static_cast<void>(pname);
    static_cast<void>(param);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexGenfv(std::uint32_t coord, std::uint32_t pname, const float* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(coord);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexGeni(std::uint32_t coord, std::uint32_t pname, std::int32_t param) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(coord);
    static_cast<void>(pname);
    static_cast<void>(param);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexGeniv(std::uint32_t coord, std::uint32_t pname, const std::int32_t* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(coord);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexImage1D(std::uint32_t target, std::int32_t level, std::int32_t internalformat, std::int32_t width, std::int32_t border, std::uint32_t format, std::uint32_t type, const void* pixels) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(level);
    static_cast<void>(internalformat);
    static_cast<void>(width);
    static_cast<void>(border);
    static_cast<void>(format);
    static_cast<void>(type);
    static_cast<void>(pixels);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexImage2D(std::uint32_t target, std::int32_t level, std::int32_t internalformat, std::int32_t width, std::int32_t height, std::int32_t border, std::uint32_t format, std::uint32_t type, const void* pixels) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(level);
    static_cast<void>(internalformat);
    static_cast<void>(width);
    static_cast<void>(height);
    static_cast<void>(border);
    static_cast<void>(format);
    static_cast<void>(type);
    static_cast<void>(pixels);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexParameterf(std::uint32_t target, std::uint32_t pname, float param) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(pname);
    static_cast<void>(param);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexParameterfv(std::uint32_t target, std::uint32_t pname, const float* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexParameteri(std::uint32_t target, std::uint32_t pname, std::int32_t param) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(pname);
    static_cast<void>(param);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexParameteriv(std::uint32_t target, std::uint32_t pname, const std::int32_t* params) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(pname);
    static_cast<void>(params);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexSubImage1D(std::uint32_t target, std::int32_t level, std::int32_t xoffset, std::int32_t width, std::uint32_t format, std::uint32_t type, const void* pixels) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(level);
    static_cast<void>(xoffset);
    static_cast<void>(width);
    static_cast<void>(format);
    static_cast<void>(type);
    static_cast<void>(pixels);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTexSubImage2D(std::uint32_t target, std::int32_t level, std::int32_t xoffset, std::int32_t yoffset, std::int32_t width, std::int32_t height, std::uint32_t format, std::uint32_t type, const void* pixels) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(target);
    static_cast<void>(level);
    static_cast<void>(xoffset);
    static_cast<void>(yoffset);
    static_cast<void>(width);
    static_cast<void>(height);
    static_cast<void>(format);
    static_cast<void>(type);
    static_cast<void>(pixels);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTranslated(double x, double y, double z) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glTranslatef(float x, float y, float z) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex2d(double x, double y) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex2dv(const double* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex2f(float x, float y) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex2fv(const float* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex2i(std::int32_t x, std::int32_t y) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex2iv(const std::int32_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex2s(std::int16_t x, std::int16_t y) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex2sv(const std::int16_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex3d(double x, double y, double z) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex3dv(const double* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex3f(float x, float y, float z) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex3fv(const float* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex3i(std::int32_t x, std::int32_t y, std::int32_t z) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex3iv(const std::int32_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex3s(std::int16_t x, std::int16_t y, std::int16_t z) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex3sv(const std::int16_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex4d(double x, double y, double z, double w) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    static_cast<void>(w);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex4dv(const double* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex4f(float x, float y, float z, float w) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    static_cast<void>(w);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex4fv(const float* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex4i(std::int32_t x, std::int32_t y, std::int32_t z, std::int32_t w) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    static_cast<void>(w);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex4iv(const std::int32_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex4s(std::int16_t x, std::int16_t y, std::int16_t z, std::int16_t w) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(z);
    static_cast<void>(w);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertex4sv(const std::int16_t* v) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(v);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glVertexPointer(std::int32_t size, std::uint32_t type, std::int32_t stride, const void* pointer) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(size);
    static_cast<void>(type);
    static_cast<void>(stride);
    static_cast<void>(pointer);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kopengl32G_glViewport(std::int32_t x, std::int32_t y, std::int32_t width, std::int32_t height) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(width);
    static_cast<void>(height);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kopengl32G_wglCopyContext(void* arg0, void* arg1, std::uint32_t arg2) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kopengl32G_wglCreateContext(void* arg0) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kopengl32G_wglCreateLayerContext(void* arg0, std::int32_t arg1) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kopengl32G_wglDeleteContext(void* arg0) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kopengl32G_wglDescribeLayerPlane(void* arg0, std::int32_t arg1, std::int32_t arg2, std::uint32_t arg3, std::uint64_t arg4) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    static_cast<void>(arg4);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kopengl32G_wglGetCurrentContext() noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kopengl32G_wglGetCurrentDC() noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kopengl32G_wglGetLayerPaletteEntries(void* arg0, std::int32_t arg1, std::int32_t arg2, std::int32_t arg3, std::uint32_t* arg4) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    static_cast<void>(arg4);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kopengl32G_wglGetProcAddress(const char* arg0) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kopengl32G_wglMakeCurrent(void* arg0, void* arg1) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kopengl32G_wglRealizeLayerPalette(void* arg0, std::int32_t arg1, std::int32_t arg2) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kopengl32G_wglSetLayerPaletteEntries(void* arg0, std::int32_t arg1, std::int32_t arg2, std::int32_t arg3, const std::uint32_t* arg4) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    static_cast<void>(arg4);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kopengl32G_wglShareLists(void* arg0, void* arg1) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kopengl32G_wglSwapLayerBuffers(void* arg0, std::uint32_t arg1) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kopengl32G_wglSwapMultipleBuffers(std::uint32_t arg0, const void* arg1) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kopengl32G_wglUseFontBitmapsA(void* arg0, std::uint32_t arg1, std::uint32_t arg2, std::uint32_t arg3) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kopengl32G_wglUseFontBitmapsW(void* arg0, std::uint32_t arg1, std::uint32_t arg2, std::uint32_t arg3) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kopengl32G_wglUseFontOutlinesA(void* arg0, std::uint32_t arg1, std::uint32_t arg2, std::uint32_t arg3, float arg4, float arg5, std::int32_t arg6, std::uint64_t arg7) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    static_cast<void>(arg4);
    static_cast<void>(arg5);
    static_cast<void>(arg6);
    static_cast<void>(arg7);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kopengl32G_wglUseFontOutlinesW(void* arg0, std::uint32_t arg1, std::uint32_t arg2, std::uint32_t arg3, float arg4, float arg5, std::int32_t arg6, std::uint64_t arg7) noexcept {
    // Refused: the OpenGL client library.
    //
    // an OpenGL context is a driver object attached to a device context, and
    // both the driver and the device context would have to exist
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    static_cast<void>(arg4);
    static_cast<void>(arg5);
    static_cast<void>(arg6);
    static_cast<void>(arg7);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_opengl32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("glAccum", reinterpret_cast<void*>(&kopengl32G_glAccum));
    e("glAlphaFunc", reinterpret_cast<void*>(&kopengl32G_glAlphaFunc));
    e("glAreTexturesResident", reinterpret_cast<void*>(&kopengl32G_glAreTexturesResident));
    e("glArrayElement", reinterpret_cast<void*>(&kopengl32G_glArrayElement));
    e("glBegin", reinterpret_cast<void*>(&kopengl32G_glBegin));
    e("glBindTexture", reinterpret_cast<void*>(&kopengl32G_glBindTexture));
    e("glBitmap", reinterpret_cast<void*>(&kopengl32G_glBitmap));
    e("glBlendFunc", reinterpret_cast<void*>(&kopengl32G_glBlendFunc));
    e("glCallList", reinterpret_cast<void*>(&kopengl32G_glCallList));
    e("glCallLists", reinterpret_cast<void*>(&kopengl32G_glCallLists));
    e("glClear", reinterpret_cast<void*>(&kopengl32G_glClear));
    e("glClearAccum", reinterpret_cast<void*>(&kopengl32G_glClearAccum));
    e("glClearColor", reinterpret_cast<void*>(&kopengl32G_glClearColor));
    e("glClearDepth", reinterpret_cast<void*>(&kopengl32G_glClearDepth));
    e("glClearIndex", reinterpret_cast<void*>(&kopengl32G_glClearIndex));
    e("glClearStencil", reinterpret_cast<void*>(&kopengl32G_glClearStencil));
    e("glClipPlane", reinterpret_cast<void*>(&kopengl32G_glClipPlane));
    e("glColor3b", reinterpret_cast<void*>(&kopengl32G_glColor3b));
    e("glColor3bv", reinterpret_cast<void*>(&kopengl32G_glColor3bv));
    e("glColor3d", reinterpret_cast<void*>(&kopengl32G_glColor3d));
    e("glColor3dv", reinterpret_cast<void*>(&kopengl32G_glColor3dv));
    e("glColor3f", reinterpret_cast<void*>(&kopengl32G_glColor3f));
    e("glColor3fv", reinterpret_cast<void*>(&kopengl32G_glColor3fv));
    e("glColor3i", reinterpret_cast<void*>(&kopengl32G_glColor3i));
    e("glColor3iv", reinterpret_cast<void*>(&kopengl32G_glColor3iv));
    e("glColor3s", reinterpret_cast<void*>(&kopengl32G_glColor3s));
    e("glColor3sv", reinterpret_cast<void*>(&kopengl32G_glColor3sv));
    e("glColor3ub", reinterpret_cast<void*>(&kopengl32G_glColor3ub));
    e("glColor3ubv", reinterpret_cast<void*>(&kopengl32G_glColor3ubv));
    e("glColor3ui", reinterpret_cast<void*>(&kopengl32G_glColor3ui));
    e("glColor3uiv", reinterpret_cast<void*>(&kopengl32G_glColor3uiv));
    e("glColor3us", reinterpret_cast<void*>(&kopengl32G_glColor3us));
    e("glColor3usv", reinterpret_cast<void*>(&kopengl32G_glColor3usv));
    e("glColor4b", reinterpret_cast<void*>(&kopengl32G_glColor4b));
    e("glColor4bv", reinterpret_cast<void*>(&kopengl32G_glColor4bv));
    e("glColor4d", reinterpret_cast<void*>(&kopengl32G_glColor4d));
    e("glColor4dv", reinterpret_cast<void*>(&kopengl32G_glColor4dv));
    e("glColor4f", reinterpret_cast<void*>(&kopengl32G_glColor4f));
    e("glColor4fv", reinterpret_cast<void*>(&kopengl32G_glColor4fv));
    e("glColor4i", reinterpret_cast<void*>(&kopengl32G_glColor4i));
    e("glColor4iv", reinterpret_cast<void*>(&kopengl32G_glColor4iv));
    e("glColor4s", reinterpret_cast<void*>(&kopengl32G_glColor4s));
    e("glColor4sv", reinterpret_cast<void*>(&kopengl32G_glColor4sv));
    e("glColor4ub", reinterpret_cast<void*>(&kopengl32G_glColor4ub));
    e("glColor4ubv", reinterpret_cast<void*>(&kopengl32G_glColor4ubv));
    e("glColor4ui", reinterpret_cast<void*>(&kopengl32G_glColor4ui));
    e("glColor4uiv", reinterpret_cast<void*>(&kopengl32G_glColor4uiv));
    e("glColor4us", reinterpret_cast<void*>(&kopengl32G_glColor4us));
    e("glColor4usv", reinterpret_cast<void*>(&kopengl32G_glColor4usv));
    e("glColorMask", reinterpret_cast<void*>(&kopengl32G_glColorMask));
    e("glColorMaterial", reinterpret_cast<void*>(&kopengl32G_glColorMaterial));
    e("glColorPointer", reinterpret_cast<void*>(&kopengl32G_glColorPointer));
    e("glCopyPixels", reinterpret_cast<void*>(&kopengl32G_glCopyPixels));
    e("glCopyTexImage1D", reinterpret_cast<void*>(&kopengl32G_glCopyTexImage1D));
    e("glCopyTexImage2D", reinterpret_cast<void*>(&kopengl32G_glCopyTexImage2D));
    e("glCopyTexSubImage1D", reinterpret_cast<void*>(&kopengl32G_glCopyTexSubImage1D));
    e("glCopyTexSubImage2D", reinterpret_cast<void*>(&kopengl32G_glCopyTexSubImage2D));
    e("glCullFace", reinterpret_cast<void*>(&kopengl32G_glCullFace));
    e("glDeleteLists", reinterpret_cast<void*>(&kopengl32G_glDeleteLists));
    e("glDeleteTextures", reinterpret_cast<void*>(&kopengl32G_glDeleteTextures));
    e("glDepthFunc", reinterpret_cast<void*>(&kopengl32G_glDepthFunc));
    e("glDepthMask", reinterpret_cast<void*>(&kopengl32G_glDepthMask));
    e("glDepthRange", reinterpret_cast<void*>(&kopengl32G_glDepthRange));
    e("glDisable", reinterpret_cast<void*>(&kopengl32G_glDisable));
    e("glDisableClientState", reinterpret_cast<void*>(&kopengl32G_glDisableClientState));
    e("glDrawArrays", reinterpret_cast<void*>(&kopengl32G_glDrawArrays));
    e("glDrawBuffer", reinterpret_cast<void*>(&kopengl32G_glDrawBuffer));
    e("glDrawElements", reinterpret_cast<void*>(&kopengl32G_glDrawElements));
    e("glDrawPixels", reinterpret_cast<void*>(&kopengl32G_glDrawPixels));
    e("glEdgeFlag", reinterpret_cast<void*>(&kopengl32G_glEdgeFlag));
    e("glEdgeFlagPointer", reinterpret_cast<void*>(&kopengl32G_glEdgeFlagPointer));
    e("glEdgeFlagv", reinterpret_cast<void*>(&kopengl32G_glEdgeFlagv));
    e("glEnable", reinterpret_cast<void*>(&kopengl32G_glEnable));
    e("glEnableClientState", reinterpret_cast<void*>(&kopengl32G_glEnableClientState));
    e("glEnd", reinterpret_cast<void*>(&kopengl32G_glEnd));
    e("glEndList", reinterpret_cast<void*>(&kopengl32G_glEndList));
    e("glEvalCoord1d", reinterpret_cast<void*>(&kopengl32G_glEvalCoord1d));
    e("glEvalCoord1dv", reinterpret_cast<void*>(&kopengl32G_glEvalCoord1dv));
    e("glEvalCoord1f", reinterpret_cast<void*>(&kopengl32G_glEvalCoord1f));
    e("glEvalCoord1fv", reinterpret_cast<void*>(&kopengl32G_glEvalCoord1fv));
    e("glEvalCoord2d", reinterpret_cast<void*>(&kopengl32G_glEvalCoord2d));
    e("glEvalCoord2dv", reinterpret_cast<void*>(&kopengl32G_glEvalCoord2dv));
    e("glEvalCoord2f", reinterpret_cast<void*>(&kopengl32G_glEvalCoord2f));
    e("glEvalCoord2fv", reinterpret_cast<void*>(&kopengl32G_glEvalCoord2fv));
    e("glEvalMesh1", reinterpret_cast<void*>(&kopengl32G_glEvalMesh1));
    e("glEvalMesh2", reinterpret_cast<void*>(&kopengl32G_glEvalMesh2));
    e("glEvalPoint1", reinterpret_cast<void*>(&kopengl32G_glEvalPoint1));
    e("glEvalPoint2", reinterpret_cast<void*>(&kopengl32G_glEvalPoint2));
    e("glFeedbackBuffer", reinterpret_cast<void*>(&kopengl32G_glFeedbackBuffer));
    e("glFinish", reinterpret_cast<void*>(&kopengl32G_glFinish));
    e("glFlush", reinterpret_cast<void*>(&kopengl32G_glFlush));
    e("glFogf", reinterpret_cast<void*>(&kopengl32G_glFogf));
    e("glFogfv", reinterpret_cast<void*>(&kopengl32G_glFogfv));
    e("glFogi", reinterpret_cast<void*>(&kopengl32G_glFogi));
    e("glFogiv", reinterpret_cast<void*>(&kopengl32G_glFogiv));
    e("glFrontFace", reinterpret_cast<void*>(&kopengl32G_glFrontFace));
    e("glFrustum", reinterpret_cast<void*>(&kopengl32G_glFrustum));
    e("glGenLists", reinterpret_cast<void*>(&kopengl32G_glGenLists));
    e("glGenTextures", reinterpret_cast<void*>(&kopengl32G_glGenTextures));
    e("glGetBooleanv", reinterpret_cast<void*>(&kopengl32G_glGetBooleanv));
    e("glGetClipPlane", reinterpret_cast<void*>(&kopengl32G_glGetClipPlane));
    e("glGetDoublev", reinterpret_cast<void*>(&kopengl32G_glGetDoublev));
    e("glGetError", reinterpret_cast<void*>(&kopengl32G_glGetError));
    e("glGetFloatv", reinterpret_cast<void*>(&kopengl32G_glGetFloatv));
    e("glGetIntegerv", reinterpret_cast<void*>(&kopengl32G_glGetIntegerv));
    e("glGetLightfv", reinterpret_cast<void*>(&kopengl32G_glGetLightfv));
    e("glGetLightiv", reinterpret_cast<void*>(&kopengl32G_glGetLightiv));
    e("glGetMapdv", reinterpret_cast<void*>(&kopengl32G_glGetMapdv));
    e("glGetMapfv", reinterpret_cast<void*>(&kopengl32G_glGetMapfv));
    e("glGetMapiv", reinterpret_cast<void*>(&kopengl32G_glGetMapiv));
    e("glGetMaterialfv", reinterpret_cast<void*>(&kopengl32G_glGetMaterialfv));
    e("glGetMaterialiv", reinterpret_cast<void*>(&kopengl32G_glGetMaterialiv));
    e("glGetPixelMapfv", reinterpret_cast<void*>(&kopengl32G_glGetPixelMapfv));
    e("glGetPixelMapuiv", reinterpret_cast<void*>(&kopengl32G_glGetPixelMapuiv));
    e("glGetPixelMapusv", reinterpret_cast<void*>(&kopengl32G_glGetPixelMapusv));
    e("glGetPointerv", reinterpret_cast<void*>(&kopengl32G_glGetPointerv));
    e("glGetPolygonStipple", reinterpret_cast<void*>(&kopengl32G_glGetPolygonStipple));
    e("glGetString", reinterpret_cast<void*>(&kopengl32G_glGetString));
    e("glGetTexEnvfv", reinterpret_cast<void*>(&kopengl32G_glGetTexEnvfv));
    e("glGetTexEnviv", reinterpret_cast<void*>(&kopengl32G_glGetTexEnviv));
    e("glGetTexGendv", reinterpret_cast<void*>(&kopengl32G_glGetTexGendv));
    e("glGetTexGenfv", reinterpret_cast<void*>(&kopengl32G_glGetTexGenfv));
    e("glGetTexGeniv", reinterpret_cast<void*>(&kopengl32G_glGetTexGeniv));
    e("glGetTexImage", reinterpret_cast<void*>(&kopengl32G_glGetTexImage));
    e("glGetTexLevelParameterfv", reinterpret_cast<void*>(&kopengl32G_glGetTexLevelParameterfv));
    e("glGetTexLevelParameteriv", reinterpret_cast<void*>(&kopengl32G_glGetTexLevelParameteriv));
    e("glGetTexParameterfv", reinterpret_cast<void*>(&kopengl32G_glGetTexParameterfv));
    e("glGetTexParameteriv", reinterpret_cast<void*>(&kopengl32G_glGetTexParameteriv));
    e("glHint", reinterpret_cast<void*>(&kopengl32G_glHint));
    e("glIndexMask", reinterpret_cast<void*>(&kopengl32G_glIndexMask));
    e("glIndexPointer", reinterpret_cast<void*>(&kopengl32G_glIndexPointer));
    e("glIndexd", reinterpret_cast<void*>(&kopengl32G_glIndexd));
    e("glIndexdv", reinterpret_cast<void*>(&kopengl32G_glIndexdv));
    e("glIndexf", reinterpret_cast<void*>(&kopengl32G_glIndexf));
    e("glIndexfv", reinterpret_cast<void*>(&kopengl32G_glIndexfv));
    e("glIndexi", reinterpret_cast<void*>(&kopengl32G_glIndexi));
    e("glIndexiv", reinterpret_cast<void*>(&kopengl32G_glIndexiv));
    e("glIndexs", reinterpret_cast<void*>(&kopengl32G_glIndexs));
    e("glIndexsv", reinterpret_cast<void*>(&kopengl32G_glIndexsv));
    e("glIndexub", reinterpret_cast<void*>(&kopengl32G_glIndexub));
    e("glIndexubv", reinterpret_cast<void*>(&kopengl32G_glIndexubv));
    e("glInitNames", reinterpret_cast<void*>(&kopengl32G_glInitNames));
    e("glInterleavedArrays", reinterpret_cast<void*>(&kopengl32G_glInterleavedArrays));
    e("glIsEnabled", reinterpret_cast<void*>(&kopengl32G_glIsEnabled));
    e("glIsList", reinterpret_cast<void*>(&kopengl32G_glIsList));
    e("glIsTexture", reinterpret_cast<void*>(&kopengl32G_glIsTexture));
    e("glLightModelf", reinterpret_cast<void*>(&kopengl32G_glLightModelf));
    e("glLightModelfv", reinterpret_cast<void*>(&kopengl32G_glLightModelfv));
    e("glLightModeli", reinterpret_cast<void*>(&kopengl32G_glLightModeli));
    e("glLightModeliv", reinterpret_cast<void*>(&kopengl32G_glLightModeliv));
    e("glLightf", reinterpret_cast<void*>(&kopengl32G_glLightf));
    e("glLightfv", reinterpret_cast<void*>(&kopengl32G_glLightfv));
    e("glLighti", reinterpret_cast<void*>(&kopengl32G_glLighti));
    e("glLightiv", reinterpret_cast<void*>(&kopengl32G_glLightiv));
    e("glLineStipple", reinterpret_cast<void*>(&kopengl32G_glLineStipple));
    e("glLineWidth", reinterpret_cast<void*>(&kopengl32G_glLineWidth));
    e("glListBase", reinterpret_cast<void*>(&kopengl32G_glListBase));
    e("glLoadIdentity", reinterpret_cast<void*>(&kopengl32G_glLoadIdentity));
    e("glLoadMatrixd", reinterpret_cast<void*>(&kopengl32G_glLoadMatrixd));
    e("glLoadMatrixf", reinterpret_cast<void*>(&kopengl32G_glLoadMatrixf));
    e("glLoadName", reinterpret_cast<void*>(&kopengl32G_glLoadName));
    e("glLogicOp", reinterpret_cast<void*>(&kopengl32G_glLogicOp));
    e("glMap1d", reinterpret_cast<void*>(&kopengl32G_glMap1d));
    e("glMap1f", reinterpret_cast<void*>(&kopengl32G_glMap1f));
    e("glMap2d", reinterpret_cast<void*>(&kopengl32G_glMap2d));
    e("glMap2f", reinterpret_cast<void*>(&kopengl32G_glMap2f));
    e("glMapGrid1d", reinterpret_cast<void*>(&kopengl32G_glMapGrid1d));
    e("glMapGrid1f", reinterpret_cast<void*>(&kopengl32G_glMapGrid1f));
    e("glMapGrid2d", reinterpret_cast<void*>(&kopengl32G_glMapGrid2d));
    e("glMapGrid2f", reinterpret_cast<void*>(&kopengl32G_glMapGrid2f));
    e("glMaterialf", reinterpret_cast<void*>(&kopengl32G_glMaterialf));
    e("glMaterialfv", reinterpret_cast<void*>(&kopengl32G_glMaterialfv));
    e("glMateriali", reinterpret_cast<void*>(&kopengl32G_glMateriali));
    e("glMaterialiv", reinterpret_cast<void*>(&kopengl32G_glMaterialiv));
    e("glMatrixMode", reinterpret_cast<void*>(&kopengl32G_glMatrixMode));
    e("glMultMatrixd", reinterpret_cast<void*>(&kopengl32G_glMultMatrixd));
    e("glMultMatrixf", reinterpret_cast<void*>(&kopengl32G_glMultMatrixf));
    e("glNewList", reinterpret_cast<void*>(&kopengl32G_glNewList));
    e("glNormal3b", reinterpret_cast<void*>(&kopengl32G_glNormal3b));
    e("glNormal3bv", reinterpret_cast<void*>(&kopengl32G_glNormal3bv));
    e("glNormal3d", reinterpret_cast<void*>(&kopengl32G_glNormal3d));
    e("glNormal3dv", reinterpret_cast<void*>(&kopengl32G_glNormal3dv));
    e("glNormal3f", reinterpret_cast<void*>(&kopengl32G_glNormal3f));
    e("glNormal3fv", reinterpret_cast<void*>(&kopengl32G_glNormal3fv));
    e("glNormal3i", reinterpret_cast<void*>(&kopengl32G_glNormal3i));
    e("glNormal3iv", reinterpret_cast<void*>(&kopengl32G_glNormal3iv));
    e("glNormal3s", reinterpret_cast<void*>(&kopengl32G_glNormal3s));
    e("glNormal3sv", reinterpret_cast<void*>(&kopengl32G_glNormal3sv));
    e("glNormalPointer", reinterpret_cast<void*>(&kopengl32G_glNormalPointer));
    e("glOrtho", reinterpret_cast<void*>(&kopengl32G_glOrtho));
    e("glPassThrough", reinterpret_cast<void*>(&kopengl32G_glPassThrough));
    e("glPixelMapfv", reinterpret_cast<void*>(&kopengl32G_glPixelMapfv));
    e("glPixelMapuiv", reinterpret_cast<void*>(&kopengl32G_glPixelMapuiv));
    e("glPixelMapusv", reinterpret_cast<void*>(&kopengl32G_glPixelMapusv));
    e("glPixelStoref", reinterpret_cast<void*>(&kopengl32G_glPixelStoref));
    e("glPixelStorei", reinterpret_cast<void*>(&kopengl32G_glPixelStorei));
    e("glPixelTransferf", reinterpret_cast<void*>(&kopengl32G_glPixelTransferf));
    e("glPixelTransferi", reinterpret_cast<void*>(&kopengl32G_glPixelTransferi));
    e("glPixelZoom", reinterpret_cast<void*>(&kopengl32G_glPixelZoom));
    e("glPointSize", reinterpret_cast<void*>(&kopengl32G_glPointSize));
    e("glPolygonMode", reinterpret_cast<void*>(&kopengl32G_glPolygonMode));
    e("glPolygonOffset", reinterpret_cast<void*>(&kopengl32G_glPolygonOffset));
    e("glPolygonStipple", reinterpret_cast<void*>(&kopengl32G_glPolygonStipple));
    e("glPopAttrib", reinterpret_cast<void*>(&kopengl32G_glPopAttrib));
    e("glPopClientAttrib", reinterpret_cast<void*>(&kopengl32G_glPopClientAttrib));
    e("glPopMatrix", reinterpret_cast<void*>(&kopengl32G_glPopMatrix));
    e("glPopName", reinterpret_cast<void*>(&kopengl32G_glPopName));
    e("glPrioritizeTextures", reinterpret_cast<void*>(&kopengl32G_glPrioritizeTextures));
    e("glPushAttrib", reinterpret_cast<void*>(&kopengl32G_glPushAttrib));
    e("glPushClientAttrib", reinterpret_cast<void*>(&kopengl32G_glPushClientAttrib));
    e("glPushMatrix", reinterpret_cast<void*>(&kopengl32G_glPushMatrix));
    e("glPushName", reinterpret_cast<void*>(&kopengl32G_glPushName));
    e("glRasterPos2d", reinterpret_cast<void*>(&kopengl32G_glRasterPos2d));
    e("glRasterPos2dv", reinterpret_cast<void*>(&kopengl32G_glRasterPos2dv));
    e("glRasterPos2f", reinterpret_cast<void*>(&kopengl32G_glRasterPos2f));
    e("glRasterPos2fv", reinterpret_cast<void*>(&kopengl32G_glRasterPos2fv));
    e("glRasterPos2i", reinterpret_cast<void*>(&kopengl32G_glRasterPos2i));
    e("glRasterPos2iv", reinterpret_cast<void*>(&kopengl32G_glRasterPos2iv));
    e("glRasterPos2s", reinterpret_cast<void*>(&kopengl32G_glRasterPos2s));
    e("glRasterPos2sv", reinterpret_cast<void*>(&kopengl32G_glRasterPos2sv));
    e("glRasterPos3d", reinterpret_cast<void*>(&kopengl32G_glRasterPos3d));
    e("glRasterPos3dv", reinterpret_cast<void*>(&kopengl32G_glRasterPos3dv));
    e("glRasterPos3f", reinterpret_cast<void*>(&kopengl32G_glRasterPos3f));
    e("glRasterPos3fv", reinterpret_cast<void*>(&kopengl32G_glRasterPos3fv));
    e("glRasterPos3i", reinterpret_cast<void*>(&kopengl32G_glRasterPos3i));
    e("glRasterPos3iv", reinterpret_cast<void*>(&kopengl32G_glRasterPos3iv));
    e("glRasterPos3s", reinterpret_cast<void*>(&kopengl32G_glRasterPos3s));
    e("glRasterPos3sv", reinterpret_cast<void*>(&kopengl32G_glRasterPos3sv));
    e("glRasterPos4d", reinterpret_cast<void*>(&kopengl32G_glRasterPos4d));
    e("glRasterPos4dv", reinterpret_cast<void*>(&kopengl32G_glRasterPos4dv));
    e("glRasterPos4f", reinterpret_cast<void*>(&kopengl32G_glRasterPos4f));
    e("glRasterPos4fv", reinterpret_cast<void*>(&kopengl32G_glRasterPos4fv));
    e("glRasterPos4i", reinterpret_cast<void*>(&kopengl32G_glRasterPos4i));
    e("glRasterPos4iv", reinterpret_cast<void*>(&kopengl32G_glRasterPos4iv));
    e("glRasterPos4s", reinterpret_cast<void*>(&kopengl32G_glRasterPos4s));
    e("glRasterPos4sv", reinterpret_cast<void*>(&kopengl32G_glRasterPos4sv));
    e("glReadBuffer", reinterpret_cast<void*>(&kopengl32G_glReadBuffer));
    e("glReadPixels", reinterpret_cast<void*>(&kopengl32G_glReadPixels));
    e("glRectd", reinterpret_cast<void*>(&kopengl32G_glRectd));
    e("glRectdv", reinterpret_cast<void*>(&kopengl32G_glRectdv));
    e("glRectf", reinterpret_cast<void*>(&kopengl32G_glRectf));
    e("glRectfv", reinterpret_cast<void*>(&kopengl32G_glRectfv));
    e("glRecti", reinterpret_cast<void*>(&kopengl32G_glRecti));
    e("glRectiv", reinterpret_cast<void*>(&kopengl32G_glRectiv));
    e("glRects", reinterpret_cast<void*>(&kopengl32G_glRects));
    e("glRectsv", reinterpret_cast<void*>(&kopengl32G_glRectsv));
    e("glRenderMode", reinterpret_cast<void*>(&kopengl32G_glRenderMode));
    e("glRotated", reinterpret_cast<void*>(&kopengl32G_glRotated));
    e("glRotatef", reinterpret_cast<void*>(&kopengl32G_glRotatef));
    e("glScaled", reinterpret_cast<void*>(&kopengl32G_glScaled));
    e("glScalef", reinterpret_cast<void*>(&kopengl32G_glScalef));
    e("glScissor", reinterpret_cast<void*>(&kopengl32G_glScissor));
    e("glSelectBuffer", reinterpret_cast<void*>(&kopengl32G_glSelectBuffer));
    e("glShadeModel", reinterpret_cast<void*>(&kopengl32G_glShadeModel));
    e("glStencilFunc", reinterpret_cast<void*>(&kopengl32G_glStencilFunc));
    e("glStencilMask", reinterpret_cast<void*>(&kopengl32G_glStencilMask));
    e("glStencilOp", reinterpret_cast<void*>(&kopengl32G_glStencilOp));
    e("glTexCoord1d", reinterpret_cast<void*>(&kopengl32G_glTexCoord1d));
    e("glTexCoord1dv", reinterpret_cast<void*>(&kopengl32G_glTexCoord1dv));
    e("glTexCoord1f", reinterpret_cast<void*>(&kopengl32G_glTexCoord1f));
    e("glTexCoord1fv", reinterpret_cast<void*>(&kopengl32G_glTexCoord1fv));
    e("glTexCoord1i", reinterpret_cast<void*>(&kopengl32G_glTexCoord1i));
    e("glTexCoord1iv", reinterpret_cast<void*>(&kopengl32G_glTexCoord1iv));
    e("glTexCoord1s", reinterpret_cast<void*>(&kopengl32G_glTexCoord1s));
    e("glTexCoord1sv", reinterpret_cast<void*>(&kopengl32G_glTexCoord1sv));
    e("glTexCoord2d", reinterpret_cast<void*>(&kopengl32G_glTexCoord2d));
    e("glTexCoord2dv", reinterpret_cast<void*>(&kopengl32G_glTexCoord2dv));
    e("glTexCoord2f", reinterpret_cast<void*>(&kopengl32G_glTexCoord2f));
    e("glTexCoord2fv", reinterpret_cast<void*>(&kopengl32G_glTexCoord2fv));
    e("glTexCoord2i", reinterpret_cast<void*>(&kopengl32G_glTexCoord2i));
    e("glTexCoord2iv", reinterpret_cast<void*>(&kopengl32G_glTexCoord2iv));
    e("glTexCoord2s", reinterpret_cast<void*>(&kopengl32G_glTexCoord2s));
    e("glTexCoord2sv", reinterpret_cast<void*>(&kopengl32G_glTexCoord2sv));
    e("glTexCoord3d", reinterpret_cast<void*>(&kopengl32G_glTexCoord3d));
    e("glTexCoord3dv", reinterpret_cast<void*>(&kopengl32G_glTexCoord3dv));
    e("glTexCoord3f", reinterpret_cast<void*>(&kopengl32G_glTexCoord3f));
    e("glTexCoord3fv", reinterpret_cast<void*>(&kopengl32G_glTexCoord3fv));
    e("glTexCoord3i", reinterpret_cast<void*>(&kopengl32G_glTexCoord3i));
    e("glTexCoord3iv", reinterpret_cast<void*>(&kopengl32G_glTexCoord3iv));
    e("glTexCoord3s", reinterpret_cast<void*>(&kopengl32G_glTexCoord3s));
    e("glTexCoord3sv", reinterpret_cast<void*>(&kopengl32G_glTexCoord3sv));
    e("glTexCoord4d", reinterpret_cast<void*>(&kopengl32G_glTexCoord4d));
    e("glTexCoord4dv", reinterpret_cast<void*>(&kopengl32G_glTexCoord4dv));
    e("glTexCoord4f", reinterpret_cast<void*>(&kopengl32G_glTexCoord4f));
    e("glTexCoord4fv", reinterpret_cast<void*>(&kopengl32G_glTexCoord4fv));
    e("glTexCoord4i", reinterpret_cast<void*>(&kopengl32G_glTexCoord4i));
    e("glTexCoord4iv", reinterpret_cast<void*>(&kopengl32G_glTexCoord4iv));
    e("glTexCoord4s", reinterpret_cast<void*>(&kopengl32G_glTexCoord4s));
    e("glTexCoord4sv", reinterpret_cast<void*>(&kopengl32G_glTexCoord4sv));
    e("glTexCoordPointer", reinterpret_cast<void*>(&kopengl32G_glTexCoordPointer));
    e("glTexEnvf", reinterpret_cast<void*>(&kopengl32G_glTexEnvf));
    e("glTexEnvfv", reinterpret_cast<void*>(&kopengl32G_glTexEnvfv));
    e("glTexEnvi", reinterpret_cast<void*>(&kopengl32G_glTexEnvi));
    e("glTexEnviv", reinterpret_cast<void*>(&kopengl32G_glTexEnviv));
    e("glTexGend", reinterpret_cast<void*>(&kopengl32G_glTexGend));
    e("glTexGendv", reinterpret_cast<void*>(&kopengl32G_glTexGendv));
    e("glTexGenf", reinterpret_cast<void*>(&kopengl32G_glTexGenf));
    e("glTexGenfv", reinterpret_cast<void*>(&kopengl32G_glTexGenfv));
    e("glTexGeni", reinterpret_cast<void*>(&kopengl32G_glTexGeni));
    e("glTexGeniv", reinterpret_cast<void*>(&kopengl32G_glTexGeniv));
    e("glTexImage1D", reinterpret_cast<void*>(&kopengl32G_glTexImage1D));
    e("glTexImage2D", reinterpret_cast<void*>(&kopengl32G_glTexImage2D));
    e("glTexParameterf", reinterpret_cast<void*>(&kopengl32G_glTexParameterf));
    e("glTexParameterfv", reinterpret_cast<void*>(&kopengl32G_glTexParameterfv));
    e("glTexParameteri", reinterpret_cast<void*>(&kopengl32G_glTexParameteri));
    e("glTexParameteriv", reinterpret_cast<void*>(&kopengl32G_glTexParameteriv));
    e("glTexSubImage1D", reinterpret_cast<void*>(&kopengl32G_glTexSubImage1D));
    e("glTexSubImage2D", reinterpret_cast<void*>(&kopengl32G_glTexSubImage2D));
    e("glTranslated", reinterpret_cast<void*>(&kopengl32G_glTranslated));
    e("glTranslatef", reinterpret_cast<void*>(&kopengl32G_glTranslatef));
    e("glVertex2d", reinterpret_cast<void*>(&kopengl32G_glVertex2d));
    e("glVertex2dv", reinterpret_cast<void*>(&kopengl32G_glVertex2dv));
    e("glVertex2f", reinterpret_cast<void*>(&kopengl32G_glVertex2f));
    e("glVertex2fv", reinterpret_cast<void*>(&kopengl32G_glVertex2fv));
    e("glVertex2i", reinterpret_cast<void*>(&kopengl32G_glVertex2i));
    e("glVertex2iv", reinterpret_cast<void*>(&kopengl32G_glVertex2iv));
    e("glVertex2s", reinterpret_cast<void*>(&kopengl32G_glVertex2s));
    e("glVertex2sv", reinterpret_cast<void*>(&kopengl32G_glVertex2sv));
    e("glVertex3d", reinterpret_cast<void*>(&kopengl32G_glVertex3d));
    e("glVertex3dv", reinterpret_cast<void*>(&kopengl32G_glVertex3dv));
    e("glVertex3f", reinterpret_cast<void*>(&kopengl32G_glVertex3f));
    e("glVertex3fv", reinterpret_cast<void*>(&kopengl32G_glVertex3fv));
    e("glVertex3i", reinterpret_cast<void*>(&kopengl32G_glVertex3i));
    e("glVertex3iv", reinterpret_cast<void*>(&kopengl32G_glVertex3iv));
    e("glVertex3s", reinterpret_cast<void*>(&kopengl32G_glVertex3s));
    e("glVertex3sv", reinterpret_cast<void*>(&kopengl32G_glVertex3sv));
    e("glVertex4d", reinterpret_cast<void*>(&kopengl32G_glVertex4d));
    e("glVertex4dv", reinterpret_cast<void*>(&kopengl32G_glVertex4dv));
    e("glVertex4f", reinterpret_cast<void*>(&kopengl32G_glVertex4f));
    e("glVertex4fv", reinterpret_cast<void*>(&kopengl32G_glVertex4fv));
    e("glVertex4i", reinterpret_cast<void*>(&kopengl32G_glVertex4i));
    e("glVertex4iv", reinterpret_cast<void*>(&kopengl32G_glVertex4iv));
    e("glVertex4s", reinterpret_cast<void*>(&kopengl32G_glVertex4s));
    e("glVertex4sv", reinterpret_cast<void*>(&kopengl32G_glVertex4sv));
    e("glVertexPointer", reinterpret_cast<void*>(&kopengl32G_glVertexPointer));
    e("glViewport", reinterpret_cast<void*>(&kopengl32G_glViewport));
    e("wglCopyContext", reinterpret_cast<void*>(&kopengl32G_wglCopyContext));
    e("wglCreateContext", reinterpret_cast<void*>(&kopengl32G_wglCreateContext));
    e("wglCreateLayerContext", reinterpret_cast<void*>(&kopengl32G_wglCreateLayerContext));
    e("wglDeleteContext", reinterpret_cast<void*>(&kopengl32G_wglDeleteContext));
    e("wglDescribeLayerPlane", reinterpret_cast<void*>(&kopengl32G_wglDescribeLayerPlane));
    e("wglGetCurrentContext", reinterpret_cast<void*>(&kopengl32G_wglGetCurrentContext));
    e("wglGetCurrentDC", reinterpret_cast<void*>(&kopengl32G_wglGetCurrentDC));
    e("wglGetLayerPaletteEntries", reinterpret_cast<void*>(&kopengl32G_wglGetLayerPaletteEntries));
    e("wglGetProcAddress", reinterpret_cast<void*>(&kopengl32G_wglGetProcAddress));
    e("wglMakeCurrent", reinterpret_cast<void*>(&kopengl32G_wglMakeCurrent));
    e("wglRealizeLayerPalette", reinterpret_cast<void*>(&kopengl32G_wglRealizeLayerPalette));
    e("wglSetLayerPaletteEntries", reinterpret_cast<void*>(&kopengl32G_wglSetLayerPaletteEntries));
    e("wglShareLists", reinterpret_cast<void*>(&kopengl32G_wglShareLists));
    e("wglSwapLayerBuffers", reinterpret_cast<void*>(&kopengl32G_wglSwapLayerBuffers));
    e("wglSwapMultipleBuffers", reinterpret_cast<void*>(&kopengl32G_wglSwapMultipleBuffers));
    e("wglUseFontBitmapsA", reinterpret_cast<void*>(&kopengl32G_wglUseFontBitmapsA));
    e("wglUseFontBitmapsW", reinterpret_cast<void*>(&kopengl32G_wglUseFontBitmapsW));
    e("wglUseFontOutlinesA", reinterpret_cast<void*>(&kopengl32G_wglUseFontOutlinesA));
    e("wglUseFontOutlinesW", reinterpret_cast<void*>(&kopengl32G_wglUseFontOutlinesW));
}
}  // namespace occ::runtime::winabi

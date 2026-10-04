cmake_minimum_required(VERSION 3.20)

# The compiler check has to already know which standard library this build
# uses, and it runs before project() gets a chance to look at the toolchain
# below. A Clang installed from a release tarball carries no libstdc++ at all,
# so the probe program CMake compiles to test the compiler fails to link with
# "cannot find -lstdc++" and configuration stops -- before any of this file's
# own configuration is read, and regardless of whether the flags further down
# are correct. Setting the default here, ahead of project(), is what makes the
# probe link.
#
# This only sets a default. Passing -DCMAKE_CXX_FLAGS on the command line
# still wins, because an explicit choice by whoever is building should not be
# overridden by a guess made on their behalf.

# Every layout known to hold a libc++, most specific first. A root is only
# usable when it carries both the headers and the libraries, which is what
# occ_libcxx_root_is_complete below checks.
set(OCC_LIBCXX_CANDIDATES
    /usr/lib/llvm-23 /usr/lib/llvm-22 /usr/lib/llvm-21
    /usr/lib/llvm-20 /usr/lib/llvm-19 /usr/lib/llvm-18
    /usr/lib/llvm-17 /opt/LLVM-23.1.2-Linux-X64)

# A libc++ is usable only if the same tree supplies its headers and its
# libraries. Accepting a root on the strength of its headers alone is what
# lets a half-populated directory -- one a package installed next to an
# unrelated compiler -- be chosen over a complete toolchain sitting further
# down the list.
macro(occ_libcxx_root_is_complete root out)
    set(_occ_has_headers FALSE)
    if(EXISTS "${root}/include/c++/v1/print" OR
       EXISTS "${root}/include/x86_64-unknown-linux-gnu/c++/v1/print")
        set(_occ_has_headers TRUE)
    endif()

    set(_occ_has_libs FALSE)
    foreach(_occ_libdir /lib/x86_64-unknown-linux-gnu /lib)
        if(EXISTS "${root}${_occ_libdir}/libc++.a" OR
           EXISTS "${root}${_occ_libdir}/libc++.so")
            set(_occ_has_libs TRUE)
        endif()
    endforeach()

    if(_occ_has_headers AND _occ_has_libs)
        set(${out} TRUE)
    else()
        set(${out} FALSE)
    endif()
endmacro()

# Whether a directory is an LLVM tool tree in its own right, rather than a
# sysroot that merely happens to have a clang two levels down. A release
# tarball unpacks to a directory with its own bin/clang; a distribution
# compiler sits in a bin directory whose parent is /usr, and /usr owns no
# clang of its own. The two are told apart here rather than by special-casing
# paths, because the question is a property of the layout and the layouts are
# not ours to enumerate.
macro(occ_libcxx_root_is_llvm_tree root out)
    if(EXISTS "${root}/bin/clang" OR EXISTS "${root}/bin/clang++")
        set(${out} TRUE)
    else()
        set(${out} FALSE)
    endif()
endmacro()

# -stdlib=libc++ is a Clang option. Handing it to GCC does not degrade the
# build, it ends it: "unrecognized command-line option", and the compiler
# check fails before project() runs, so nothing below can recover. The
# compiler's identity is what decides, and ahead of project() the only thing
# worth reading is the name whoever pointed at: $CXX, or the compiler CMake
# would pick on its own. Anything not named clang* is left to the list below,
# which adds no Clang-only flag of its own.
set(_occ_cxx_name "")
if(DEFINED ENV{CXX})
    get_filename_component(_occ_cxx_name "$ENV{CXX}" NAME)
endif()
if(_occ_cxx_name STREQUAL "")
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        set(_occ_cxx_name clang++)
    endif()
endif()

if(_occ_cxx_name MATCHES "^clang")
    # The libc++ that belongs to the compiler actually driving this build is
    # the one shipped beside it, so that root is tried before anything else.
    # This is what keeps a release-tarball Clang from being handed a
    # distribution's libc++ headers: the two are separate installs, and mixing
    # them does not fail at the point of mixing but much later, inside a
    # header, as an unresolved "using ::strncmp" for a C library function that
    # is obviously present.
    #
    # A distribution clang has no tool tree of its own to contribute, so the
    # fixed list stands in for it. Letting /usr qualify would be actively
    # harmful: it would pull the newest libc++ headers on the machine into a
    # build driven by an older clang, and that pairing stops at the first
    # header with "Libc++ only supports Clang 21 and later" -- fatal here,
    # because this build treats warnings as errors.
    if(DEFINED ENV{CXX})
        get_filename_component(_occ_cxx_bin "$ENV{CXX}" DIRECTORY)
        get_filename_component(_occ_cxx_root "${_occ_cxx_bin}" DIRECTORY)
        occ_libcxx_root_is_llvm_tree("${_occ_cxx_root}" _occ_cxx_is_tree)
        if(_occ_cxx_is_tree)
            list(INSERT OCC_LIBCXX_CANDIDATES 0 "${_occ_cxx_root}")
        endif()
    endif()

    foreach(_occ_candidate IN LISTS OCC_LIBCXX_CANDIDATES)
        occ_libcxx_root_is_complete("${_occ_candidate}" _occ_usable)
        if(_occ_usable)
            set(CMAKE_CXX_FLAGS_INIT "-stdlib=libc++")
            break()
        endif()
    endforeach()
endif()

project(occ LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# ---------------------------------------------------------------- toolchain
#
# The reference build uses Clang with libc++ from an LLVM release tree and
# links fully static. The search is done in the toolchain, not nailed to one
# filesystem layout, so a distribution-packaged libc++ works too.

if(NOT DEFINED OCC_LIBCXX_ROOT)
    # The compiler in use gets first refusal, ahead of the fixed list, so a
    # Clang unpacked from a release tarball builds against the libc++ that
    # shipped in the very same tarball. Without this, a libc++ installed
    # from a distribution package can be chosen first -- it sits at
    # /usr/lib/llvm-23 and holds perfectly good headers -- and the two sets of
    # headers then disagree about the C library. The failure is a wall of
    # "reference to unresolved using declaration" for strncmp and friends,
    # raised from inside <cstring>, on a machine where strncmp is obviously
    # present. Same version number, different install, incompatible headers.
    #
    # Only a compiler that lives in an LLVM tool tree of its own gets this
    # priority. A distribution clang sits above a sysroot, not above a
    # toolchain, and a sysroot is not a libc++ root however complete it looks.
    # Only a Clang that lives in an LLVM tool tree of its own gets this
    # priority. A distribution clang sits above a sysroot rather than above a
    # toolchain, and a sysroot is not a libc++ root however complete it looks.
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        get_filename_component(_occ_compiler_bin "${CMAKE_CXX_COMPILER}" DIRECTORY)
        get_filename_component(_occ_compiler_root "${_occ_compiler_bin}" DIRECTORY)

        occ_libcxx_root_is_llvm_tree("${_occ_compiler_root}" _occ_compiler_is_tree)
        if(_occ_compiler_is_tree)
            list(INSERT OCC_LIBCXX_CANDIDATES 0 "${_occ_compiler_root}")
        endif()
    endif()

    foreach(candidate IN LISTS OCC_LIBCXX_CANDIDATES)
        occ_libcxx_root_is_complete("${candidate}" _occ_usable)
        if(_occ_usable)
            set(OCC_LIBCXX_ROOT "${candidate}" CACHE PATH "libc++ root")
            break()
        endif()
    endforeach()
endif()

set(OCC_USE_LIBCXX ON CACHE BOOL "Build against libc++ instead of libstdc++")
set(OCC_STATIC_LINK ON CACHE BOOL "Link the main binary statically")

if(OCC_USE_LIBCXX AND OCC_LIBCXX_ROOT)
    message(STATUS "occ: libc++ root ${OCC_LIBCXX_ROOT}")

    # Exactly one include directory and one library directory, chosen as the
    # first that matches. A tree can hold both layouts, and adding both would
    # leave the search order to decide which copy of the headers wins -- so
    # the build would depend on an accident of ordering rather than on
    # anything the tree intended.
    foreach(suffix /include/x86_64-unknown-linux-gnu/c++/v1
                   /include/c++/v1)
        if(EXISTS "${OCC_LIBCXX_ROOT}${suffix}/print")
            include_directories(SYSTEM "${OCC_LIBCXX_ROOT}${suffix}")
            set(OCC_LIBCXX_INCLUDE "${OCC_LIBCXX_ROOT}${suffix}")
            break()
        endif()
    endforeach()

    foreach(suffix /lib/x86_64-unknown-linux-gnu /lib)
        if(EXISTS "${OCC_LIBCXX_ROOT}${suffix}/libc++.a" OR
           EXISTS "${OCC_LIBCXX_ROOT}${suffix}/libc++.so")
            link_directories("${OCC_LIBCXX_ROOT}${suffix}")
            set(OCC_LIBCXX_LIBDIR "${OCC_LIBCXX_ROOT}${suffix}")
            break()
        endif()
    endforeach()

    # -stdlib is a clang and Apple-clang option. GCC has never heard of it and
    # rejects the command line outright, so a machine that has libc++ headers
    # installed but a GCC default compiler cannot build at all. That
    # combination is easy to hit: installing a libc++ package is enough to
    # create it, and the failure is a wall of "unrecognized command-line
    # option" that says nothing about which compiler is at fault.
    #
    # So the flag goes only to a compiler that understands it. GCC does not
    # need it because the headers are already on the include path above and it
    # will link what it is told to link.
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        add_compile_options(-stdlib=libc++)
        add_link_options(-stdlib=libc++)
    else()
        message(STATUS
            "occ: compiler is ${CMAKE_CXX_COMPILER_ID}, not adding -stdlib=libc++")
    endif()
    set(OCC_CXX_LIBS c++ c++abi)
else()
    message(STATUS "occ: libc++ not found, falling back to libstdc++")
    set(OCC_CXX_LIBS)
endif()

# The flags below are all Clang options. GCC rejects each of them by name, and
# it rejects them before reading a single source file, so a build that reaches
# this point with GCC as the compiler cannot start at all. Every Clang-specific
# option is therefore gated on the compiler, not on libc++ being present: the
# two are independent, and a machine can easily have libc++ headers installed
# and a GCC default compiler.
set(OCC_COMPILER_IS_CLANG OFF)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(OCC_COMPILER_IS_CLANG ON)
endif()

# When several GCC installations are present, Clang 19 and later warn that a
# future release will change which one it prefers. The warning is informative
# but it fires on every translation unit, and this build treats warnings as
# errors. Naming the directory makes the choice explicit and the build quiet.
if(OCC_COMPILER_IS_CLANG AND OCC_USE_LIBCXX)
    foreach(ver 15 14)
        if(EXISTS "/usr/lib/gcc/x86_64-linux-gnu/${ver}")
            add_compile_options(
                "--gcc-install-dir=/usr/lib/gcc/x86_64-linux-gnu/${ver}")
            set(OCC_GCC_LIB_DIR "/usr/lib/gcc/x86_64-linux-gnu/${ver}")
            break()
        endif()
    endforeach()
endif()

# libc++abi needs _Unwind_*. Both LLVM's libunwind and GCC's libgcc_eh
# provide it. Linking both produces duplicate-symbol errors that do not name
# the cause, so exactly one is chosen. libgcc is chosen where a GCC runtime
# is present, which it is wherever a C++ toolchain is installed.
if(OCC_USE_LIBCXX AND OCC_STATIC_LINK)
    if(OCC_COMPILER_IS_CLANG)
        add_link_options(--unwindlib=libgcc)
    else()
        # GCC has no such option and does not need one: it links libgcc_eh
        # itself when it sees an exception-handling call.
    endif()
endif()

if(OCC_STATIC_LINK)
    add_link_options(-static)
endif()

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion
                    -Wsign-conversion -Wcast-qual -Wdouble-promotion
                    -Wformat=2 -Wundef -Wnull-dereference -Wimplicit-fallthrough)

# ---------------------------------------------------------------- options

option(OCC_ENABLE_TESTS "Build unit tests" ON)
option(OCC_ENABLE_FUZZ "Build libFuzzer harnesses" OFF)
option(OCC_WERROR "Treat warnings as errors" ON)

if(OCC_WERROR)
    add_compile_options(-Werror)
endif()

if(OCC_ENABLE_FUZZ)
    add_compile_options(-fsanitize=fuzzer-no-link,address,undefined
                        -fno-omit-frame-pointer)
    add_link_options(-fsanitize=fuzzer,address,undefined)
    # A sanitized build cannot be a static build; libFuzzer supplies main().
    set(OCC_STATIC_LINK OFF)
endif()

# ---------------------------------------------------------------- core

add_library(occ_core STATIC
    src/syscall/syscall.cpp
    src/syscall/capability.cpp
    src/util/log.cpp
    src/util/string.cpp
    src/util/errno.cpp
    src/util/fs.cpp
    src/probe/doctor.cpp
    src/parser/detect.cpp
    src/parser/elf.cpp
    src/isolation/seccomp.cpp
    src/isolation/container.cpp
    src/observer/event.cpp
    src/observer/ptrace.cpp
    src/observer/watchpoint.cpp
    src/observer/wx.cpp
    src/observer/rsp.cpp
    src/observer/session.cpp
    src/observer/transport.cpp
    src/observer/registry.cpp
    src/runner/run.cpp
)

target_include_directories(occ_core PUBLIC include)
target_compile_options(occ_core PRIVATE -fno-exceptions -fno-rtti)

# ---------------------------------------------------------------- binary

add_executable(occ
    src/main.cpp
    src/cmd_check.cpp
    src/cmd_doctor.cpp
    src/cmd_run.cpp
    src/cmd_attach.cpp
    src/cmd_stop.cpp
)

target_link_libraries(occ PRIVATE occ_core)
if(OCC_CXX_LIBS)
    target_link_libraries(occ PRIVATE ${OCC_CXX_LIBS})
endif()

# ---------------------------------------------------------------- tests

if(OCC_ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(OCC_ENABLE_FUZZ)
    add_subdirectory(fuzz)
endif()

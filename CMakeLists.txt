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
    # /usr/lib/llvm-23 and holds perfectly good headers -- and headers from
    # one install then meet a compiler from another. The failure is a wall of
    # "reference to unresolved using declaration" for strncmp and friends,
    # raised from inside <cstring>, on a machine where strncmp is obviously
    # present.
    #
    # The version number does not tell the two apart, which is what makes this
    # worth the preference below. Both installs report the same libc++
    # version; they differ in the configuration their headers were built
    # with, so what meets the compiler is a header set the compiler was never
    # tested against. The mismatch is therefore invisible in anything a build
    # log would name, and the error it produces describes a C library function
    # rather than the pair of installs that caused it.
    #
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

# Declared here rather than with the other options at the bottom of the file,
# because it has to be known before the standard library is chosen below.
option(OCC_ENABLE_FUZZ "Build libFuzzer harnesses" OFF)

set(OCC_USE_LIBCXX ON CACHE BOOL "Build against libc++ instead of libstdc++")

# libFuzzer ships as a prebuilt archive linked into the harness, and it was
# compiled against libstdc++. Its C++ symbols carry libstdc++'s ABI --
# std::__cxx11::basic_string, std::thread::hardware_concurrency -- none of
# which libc++ defines, because libc++ puts the same names in std::__1. A
# fuzz build against libc++ therefore fails to link, and the errors name
# symbols from the fuzzer archive rather than anything in this tree, so they
# read as a broken toolchain rather than a mismatched standard library.
#
# Linking libstdc++ alongside libc++ to satisfy those symbols is worse than
# the link error. The two runtimes implement operator new and operator delete
# separately, so a std::string allocated inside libFuzzer and destroyed by
# code in this tree -- or the reverse -- calls free() on memory the other
# library's allocator owns. That is heap corruption a sanitizer run may not
# catch, and it would live in the fuzz build only, where it would make the
# harness itself the thing under suspicion.
#
# So a fuzz build uses libstdc++ throughout. Nothing is lost: the harnesses
# parse untrusted bytes, and the parsers they drive use no standard library
# behaviour that differs between the two. A fuzz build is not shipped, and a
# crash found under libstdc++ is a crash in the same code.
#
# Written to the cache rather than as a normal variable so that the value a
# reconfigure reads back is the value this build used. A normal variable would
# shadow the cache for this run and leave the cache claiming ON, so the next
# configure would look at a build that never existed.
if(OCC_ENABLE_FUZZ AND OCC_USE_LIBCXX)
    set(OCC_USE_LIBCXX OFF CACHE BOOL "Build against libc++ instead of libstdc++" FORCE)
    message(STATUS
        "occ: fuzzing needs libstdc++ (libFuzzer's ABI); building against libstdc++")
endif()
set(OCC_STATIC_LINK ON CACHE BOOL "Link the main binary statically")

# A libc++ that is present is not a libc++ this compiler can use. The pairing
# has a floor -- libc++ 23 asks for Clang 21 or GCC 15 and says so in a
# #warning the moment it is included -- and a machine below that floor has a
# perfectly complete libc++ installed that it cannot compile a single line
# with. Guessing cannot detect this: the directory holds the headers and the
# libraries, so every check above it passes.
#
# So the compiler is asked directly, once, with the include path this build
# would really use. The question is answered by a compile rather than by
# parsing a version, because the version in the directory name is the
# distribution's and not necessarily the one whose floor applies.
#
# The probe includes what this project includes, not a token sample. A probe
# that reaches only for <string> and <vector> passes on a combination that
# cannot build: GCC with libc++ takes <string> cleanly and only fails on
# <cstdlib>, where libstdc++'s stdlib.h and libc++'s cstdlib each expect the
# other to have gone first. A probe narrower than the real sources is worse
# than no probe, because it turns a build that cannot start into one that
# fails three thousand lines later. So the headers below are the ones the
# sources actually open, and adding to them costs one line.
if(OCC_USE_LIBCXX AND OCC_LIBCXX_ROOT)
    set(_occ_probe_dir "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/occ_libcxx_probe")
    file(MAKE_DIRECTORY "${_occ_probe_dir}")
    file(WRITE "${_occ_probe_dir}/probe.cpp"
         "#include <cstdlib>\n#include <cstring>\n#include <string>\n"
         "#include <vector>\n#include <map>\n#include <span>\n"
         "#include <optional>\n#include <algorithm>\n"
         "int main() {\n"
         "  std::vector<std::string> v;\n  v.push_back(\"probe\");\n"
         "  std::map<int, std::string> m;\n  m.emplace(1, v[0]);\n"
         "  std::span<const int> s;\n  (void)s;\n"
         "  std::optional<int> o = 1;\n"
         "  (void)std::strncmp(v[0].c_str(), \"p\", 1);\n"
         "  (void)std::max(0, o.value_or(0));\n"
         "  return static_cast<int>(m.size() + v[0].size());\n}\n")

    set(_occ_probe_ok TRUE)
    set(_occ_probe_include "")
    set(_occ_probe_reason "")
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        set(_occ_probe_flags "-stdlib=libc++")
    else()
        # GCC has no -stdlib, but it will still compile against libc++ headers
        # put on its include path, which is exactly what has to be tested.
        set(_occ_probe_flags "")
    endif()

    foreach(suffix /include/x86_64-unknown-linux-gnu/c++/v1 /include/c++/v1)
        if(EXISTS "${OCC_LIBCXX_ROOT}${suffix}/print")
            set(_occ_probe_include "${OCC_LIBCXX_ROOT}${suffix}")
            break()
        endif()
    endforeach()

    set(_occ_probe_link_flags "")
    foreach(suffix /lib/x86_64-unknown-linux-gnu /lib)
        if(EXISTS "${OCC_LIBCXX_ROOT}${suffix}/libc++.a" OR
           EXISTS "${OCC_LIBCXX_ROOT}${suffix}/libc++.so")
            set(_occ_probe_link_flags "-L${OCC_LIBCXX_ROOT}${suffix}")
            break()
        endif()
    endforeach()
    if(_occ_probe_link_flags)
        list(APPEND _occ_probe_link_flags -lc++ -lc++abi)
    endif()

    if(NOT _occ_probe_include)
        set(_occ_probe_ok FALSE)
        set(_occ_probe_reason "no libc++ include directory under ${OCC_LIBCXX_ROOT}")
    else()
        # The probe links as well as compiles. Headers that compile against a
        # libc++ whose library is missing or built for another ABI are a
        # combination that gets all the way to the end of the build before it
        # is found, and finding it here costs one command instead of a full
        # build. The library directory is the one this file would use, so a
        # root whose libraries are somewhere else is reported as incomplete
        # rather than being linked against whatever happens to be installed.
        execute_process(
            COMMAND "${CMAKE_CXX_COMPILER}" ${_occ_probe_flags}
                    -std=c++23 -isystem "${_occ_probe_include}"
                    "${_occ_probe_dir}/probe.cpp"
                    -o "${_occ_probe_dir}/probe"
                    ${_occ_probe_link_flags}
            RESULT_VARIABLE _occ_probe_result
            OUTPUT_VARIABLE _occ_probe_output
            ERROR_VARIABLE _occ_probe_output)
        if(NOT _occ_probe_result EQUAL 0)
            set(_occ_probe_ok FALSE)
            # The reason is taken from what the compiler actually said, so
            # that the warning names the incompatibility rather than just
            # asserting one exists. Two forms are recognised: a libc++ that
            # states its own floor outright, and any other hard error, which
            # is reported as the first line the compiler marked. Anything
            # more specific than that would be a guess about a message this
            # file does not control.
            string(REGEX MATCH "Libc\\+\\+ only supports[^\"]*"
                   _occ_probe_reason "${_occ_probe_output}")
            if(NOT _occ_probe_reason)
                string(REGEX MATCH "error:[^\n]*" _occ_probe_reason
                       "${_occ_probe_output}")
            endif()
            if(NOT _occ_probe_reason)
                set(_occ_probe_reason "the compiler rejected it")
            endif()
            string(STRIP "${_occ_probe_reason}" _occ_probe_reason)
        endif()
    endif()

    if(NOT _occ_probe_ok)
        # Falling back is the right answer and not a second-class one: the
        # alternative is a build that cannot start. The reason is reported
        # because a build that silently stops using the standard library it
        # was configured with is its own kind of surprise, and because the
        # reason is the only thing that says what to install.
        message(WARNING
            "occ: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION} "
            "cannot use the libc++ at ${OCC_LIBCXX_ROOT} (${_occ_probe_reason}); "
            "falling back to libstdc++. Install a newer compiler, or point "
            "-DOCC_LIBCXX_ROOT at a libc++ this compiler supports.")
        set(OCC_USE_LIBCXX OFF)
    endif()
endif()

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
# future release will change which one it prefers, and name the one they would
# pick over the one in use. The warning is informative, but this build treats
# warnings as errors, so it has to be silenced rather than tolerated.
#
# Naming the directory is what silences it, and it has to reach the link line
# as well as the compile line. The warning is emitted while the driver decides
# which libstdc++ to use, which happens when the link command is assembled --
# not once per translation unit -- so a compile-only option leaves every
# executable in the build printing it. Both are set here for that reason.
if(OCC_COMPILER_IS_CLANG AND OCC_USE_LIBCXX)
    # The version has to be the one the compiler actually is, not merely the
    # newest one on disk. A hardcoded list goes stale: on a machine whose
    # default GCC is 16, a list ending at 15 names a different compiler than
    # the one running, and the warning it silences comes back -- pointing at
    # a directory this build did not choose. So the version is read from the
    # compiler, and the directory is used only if it is the one that reported.
    #
    # -DOCC_GCC_LIB_DIR overrides that, for a machine where the compiler
    # reports a directory that is not the one to use -- a sysroot, or a
    # cross-compilation setup where the answer is right and the path is not.
    if(NOT DEFINED OCC_GCC_LIB_DIR)
        execute_process(
            COMMAND "${CMAKE_CXX_COMPILER}" -print-search-dirs
            OUTPUT_VARIABLE _occ_gcc_search
            ERROR_QUIET)
        # The line is "libraries: =<dir>:<dir>:...", a search path rather
        # than a single directory. The GCC installation is the one under a
        # gcc directory in that list -- the clang resource directory and the
        # system library directories are also on it, and naming any of those
        # as a GCC installation would be wrong.
        string(REGEX MATCH "libraries: *=([^ \n]*)" _occ_gcc_libs
               "${_occ_gcc_search}")
        string(REPLACE ":" ";" _occ_gcc_libs "${_occ_gcc_libs}")
        foreach(_occ_libdir IN LISTS _occ_gcc_libs)
            if(_occ_libdir MATCHES "/gcc/")
                set(OCC_GCC_LIB_DIR "${_occ_libdir}")
                break()
            endif()
        endforeach()
    endif()

    if(OCC_GCC_LIB_DIR AND IS_DIRECTORY "${OCC_GCC_LIB_DIR}")
        set(OCC_GCC_INSTALL_DIR "--gcc-install-dir=${OCC_GCC_LIB_DIR}")
        add_compile_options("${OCC_GCC_INSTALL_DIR}")
        add_link_options("${OCC_GCC_INSTALL_DIR}")
    else()
        # A Clang with no GCC installation behind it has nothing to name, and
        # the warning does not fire in that case either.
        message(STATUS "occ: no GCC installation found for --gcc-install-dir")
    endif()
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

# A sanitized build cannot be a static build either, and a sanitizer build
# is two different things here. libFuzzer supplies main(), and ASan needs the
# dynamic loader's data to install its shadow memory -- linking -static
# against it fails with an undefined reference to _DYNAMIC, which names
# neither the cause nor the flag. The same failure arrives through the other
# door when the sanitizers are configured by hand, because the flags go into
# CMAKE_CXX_FLAGS rather than into any variable this file set: the check
# reads the flags, not a project option, and a build whose own comments
# describe sanitizers as incompatible with -static cannot link -static the
# moment its flags say -fsanitize. OCC_ENABLE_FUZZ is part of the match below
# as well, but stating both is cheaper than proving the overlap is total.
set(OCC_SANITIZED_BUILD OFF)
if(CMAKE_CXX_FLAGS MATCHES "-fsanitize" OR
   CMAKE_CXX_FLAGS_DEBUG MATCHES "-fsanitize" OR
   CMAKE_CXX_FLAGS_RELWITHDEBINFO MATCHES "-fsanitize" OR
   CMAKE_CXX_FLAGS_RELEASE MATCHES "-fsanitize")
    set(OCC_SANITIZED_BUILD ON)
endif()

if(OCC_ENABLE_FUZZ OR OCC_SANITIZED_BUILD)
    # This has to happen before the -static below is turned into a link
    # option. Setting OCC_STATIC_LINK after add_link_options(-static) is too
    # late: the option is already on every target in the directory, so the
    # variable would read OFF while the command line still said -static.
    # A variable that lies about what the build did is worse than one that
    # is merely set in the wrong place, because the next thing that consults
    # it is this kind of check.
    set(OCC_STATIC_LINK OFF)
endif()

if(OCC_STATIC_LINK)
    # Static and position-independent together. The position-independence
    # is not a hardening checkbox: the loader places guest images at the
    # base their headers name, and the base a classic x64 image names is
    # 0x400000 -- the address a static executable occupies by default. A
    # fixed-load-address occ sits on the one address most guests ask for
    # first and then refuses them for having no relocations, a refusal the
    # guest would not have earned anywhere but here. Built as a static PIE,
    # the kernel picks occ's load address out of the mmap region and
    # 0x400000 is free for the guest that wants it, which is most of them.
    add_link_options(-static-pie)
endif()

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion
                    -Wsign-conversion -Wcast-qual -Wdouble-promotion
                    -Wformat=2 -Wundef -Wnull-dereference -Wimplicit-fallthrough)

# GCC's -Wnull-dereference does not mean what Clang's does, and where the two
# share a name only Clang's is worth having. GCC runs the analysis through
# libstdc++ headers, where a small-string-optimized string is built by a
# constructor that branches on capacity, and the branch that is not taken
# looks like a null store. Adding a std::string to a std::vector is enough to
# reach it. The diagnostic is correct about C and unreliable about C++, and
# with warnings as errors that makes the whole build fail on correct code --
# so it is dropped for GCC rather than trusted there.
#
# It stays on for Clang, where it is a real check on this project's own code.
# Nothing else is relaxed: every other warning in the list above applies to
# both compilers and is meant to.
if(NOT OCC_COMPILER_IS_CLANG)
    add_compile_options(-Wno-error=null-dereference)
endif()

# ---------------------------------------------------------------- options

option(OCC_ENABLE_TESTS "Build unit tests" ON)
option(OCC_WERROR "Treat warnings as errors" ON)

if(OCC_WERROR)
    add_compile_options(-Werror)
endif()

if(OCC_ENABLE_FUZZ)
    # Compile options only. The fuzzer and sanitizer *link* options belong to
    # the harnesses and are set per target in fuzz/CMakeLists.txt, because
    # -fsanitize=fuzzer links libFuzzer's main() and this directory also
    # builds the occ binary, which has a main() of its own. A directory-level
    # add_link_options would put two mains in one link.
    add_compile_options(-fsanitize=fuzzer-no-link,address,undefined
                        -fno-omit-frame-pointer)
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
    src/parser/pe.cpp
    src/isolation/seccomp.cpp
    src/isolation/container.cpp
    src/observer/event.cpp
    src/observer/ptrace.cpp
    src/observer/watchpoint.cpp
    src/observer/uprobe.cpp
    src/observer/ntdll_probes.cpp
    src/probe/placer.cpp
    src/observer/wx.cpp
    src/observer/rsp.cpp
    src/observer/session.cpp
    src/observer/transport.cpp
    src/observer/registry.cpp
    src/engine/engine.cpp
    src/engine/exe_engine.cpp
    src/engine/pe_engine.cpp
    src/engine/apk_engine.cpp
    src/runner/run.cpp
    src/runner/pe_runner.cpp
    src/runtime/address_space.cpp
    src/runtime/dos_path.cpp
    src/runtime/mapper.cpp
    src/runtime/loader.cpp
    src/runtime/exports.cpp
    src/runtime/ntdll.cpp
    src/runtime/objects.cpp
    src/runtime/pe_process.cpp
    src/runtime/seh.cpp
    src/runtime/winabi.cpp
    src/runtime/guest_thread.cpp
    src/runtime/guest_tls.cpp
    src/runtime/guest_module.cpp
    src/inspect/inspect.cpp
    src/inspect/disasm.cpp
    src/runtime/api_common.cpp
    src/runtime/api_hook.cpp
    src/runtime/apiset.cpp
    src/runtime/iat_rebuild.cpp
    src/runtime/image_dump.cpp
    src/runtime/memwatch.cpp
    src/runtime/api/path.cpp
    src/runtime/api/string.cpp
    src/runtime/api/file.cpp
    src/runtime/api/time.cpp
    src/runtime/api/memory.cpp
    src/runtime/api/console.cpp
    src/runtime/api/modules.cpp
    src/runtime/api/kernel32_extra.cpp
    src/runtime/api/kernelbase_extra.cpp
    src/runtime/api/user32_extra.cpp
    src/runtime/api/user32_windows.cpp
    src/runtime/api/psapi.cpp
    src/runtime/api/version.cpp
    src/runtime/api/dbghelp.cpp
    src/runtime/api/ucrt_extra.cpp
    src/runtime/api/ntdll_debug.cpp
    src/runtime/api/ntdll_antidebug.cpp
    src/runtime/api/kernel32_debug.cpp
    src/runtime/api/ntdll_rtl.cpp
    src/runtime/api/ntdll_nt.cpp
    src/runtime/api/gdi32.cpp
    src/runtime/api/advapi32.cpp
    src/runtime/api/rpcrt4.cpp
    src/runtime/api/setupapi.cpp
    src/runtime/api/shell32.cpp
    src/runtime/api/crypt32.cpp
    src/runtime/api/secur32.cpp
    src/runtime/api/ole32.cpp
    src/runtime/api/crt.cpp
    src/runtime/api/kernel32_sync.cpp
    src/runtime/api/kernel32_proc.cpp
    src/runtime/api/kernel32_str.cpp
    src/runtime/api/kernel32_err.cpp
    src/runtime/api/kernel32_sys2.cpp
    src/runtime/api/kernel32_file2.cpp
    src/runtime/api/kernel32_state2.cpp
    src/runtime/api/kernel32_ctx2.cpp
    src/runtime/api/kernel32_io2.cpp
    src/runtime/api/bcrypt.cpp
    src/runtime/api/winmm.cpp
    src/runtime/api/mscoree.cpp
    src/runtime/api/ws2_32.cpp
    src/runtime/api/iphlpapi.cpp
    src/runtime/api/advapi32_reg.cpp
    src/runtime/api/advapi32_sec.cpp
    src/runtime/api/ntdll_rtl_str.cpp
    src/runtime/api/ntdll_rtl_mem1.cpp
    src/runtime/api/ntdll_rtl_mem2.cpp
    src/runtime/api/ntdll_rtl_mem3.cpp
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
    src/cmd_inspect.cpp
)

target_link_libraries(occ PRIVATE occ_core)
if(OCC_CXX_LIBS)
    target_link_libraries(occ PRIVATE ${OCC_CXX_LIBS})
endif()

# The sanitizer runtimes, but not libFuzzer's. occ_core is instrumented in a
# sanitized build, so occ needs the runtime to resolve it -- and occ is the
# one binary a sanitized build still produces that is meant to be run by a
# person, which makes it the one worth running under ASan by hand.
if(OCC_ENABLE_FUZZ)
    target_link_options(occ PRIVATE -fsanitize=address,undefined)
endif()

# ---------------------------------------------------------------- tests

if(OCC_ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(OCC_ENABLE_FUZZ)
    add_subdirectory(fuzz)
endif()

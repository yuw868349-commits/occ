# The test binaries link the core library and are built as separate
# executables rather than through a framework. Each one exits non-zero on the
# first failure and prints a line per observation, which is what a developer
# running it by hand wants from a project that has no test dependency.
#
# The sanitizer link flags below are the same ones the fuzz harnesses use, and
# for the same reason they were moved out of directory scope: an instrumented
# occ_core needs the runtime that resolves its instrumentation, so every
# consumer of the library carries the flag too. Leaving it off produces a
# wall of undefined references to __asan_memcpy and
# __ubsan_handle_type_mismatch_v1 that name the library's objects rather than
# anything in the test.
function(occ_add_test name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE occ_core)
    if(OCC_CXX_LIBS)
        target_link_libraries(${name} PRIVATE ${OCC_CXX_LIBS})
    endif()
    if(OCC_ENABLE_FUZZ)
        target_link_options(${name} PRIVATE -fsanitize=address,undefined)
    endif()
    add_test(NAME ${name} COMMAND ${name})
endfunction()

# Two of these install a mechanism in the child process that a sanitizer
# runtime cannot survive, and neither failure is in this project's code.
#
# occ_test_seccomp installs a real seccomp filter. AddressSanitizer allocates
# its shadow memory with mmap on the way out of fork(), and the filter denies
# it -- the runtime's own CHECK fails and the child exits 1 before reaching
# its _exit(0). The test then reports a child that died, which is true and
# says nothing whatever about the filter. A policy that denies mmap would
# break a real program the same way, which is worth knowing and worth
# testing on its own terms rather than through a harness that cannot survive
# it.
#
# occ_test_container ptrace-attaches to a child. ASan depends on its shadow
# memory being where it put it; an attached tracer observes the mmap that
# places it and the runtime faults at an address it never wrote. The target
# dies of a SEGV that the tracer faithfully reports.
#
# Neither can be configured away -- the mmap denial is the behaviour under
# test, and the attach is likewise -- so in a sanitized build these two are
# not built. Skipping them is honest; linking the runtime anyway and watching
# them fail would report this project's code as broken when it is the
# combination that is. The ordinary build still runs all six, which is where
# their assertions are about seccomp and namespaces rather than about a
# sanitizer's shadow memory.
#
# The other five are instrumented in a sanitized build and should stay that
# way: they parse untrusted bytes and build events, which is the work a
# sanitizer is for.
if(NOT OCC_ENABLE_FUZZ)
    occ_add_test(occ_test_seccomp test_seccomp.cpp)
    occ_add_test(occ_test_container test_container.cpp)
endif()
occ_add_test(occ_test_detect test_detect.cpp)
occ_add_test(occ_test_elf test_elf.cpp)
occ_add_test(occ_test_engine test_engine.cpp)
occ_add_test(occ_test_event test_event.cpp)
occ_add_test(occ_test_observer test_observer.cpp)
occ_add_test(occ_test_uprobe test_uprobe.cpp)
occ_add_test(occ_test_ntdll_probes test_ntdll_probes.cpp)
occ_add_test(occ_test_placer test_placer.cpp)
occ_add_test(occ_test_probe_wiring test_probe_wiring.cpp)
occ_add_test(occ_test_pe test_pe.cpp)
occ_add_test(occ_test_runtime_loader test_runtime_loader.cpp)
occ_add_test(occ_test_mapper test_mapper.cpp)
occ_add_test(occ_test_placement test_placement.cpp)
occ_add_test(occ_test_gdb_interop test_gdb_interop.cpp)

# occ_test_check is the one test here that drives a built binary rather than
# the library: it runs "occ check" on a path and reads the exit status and the
# report. The load verdict is a property of the whole command -- the format
# detection, the engine table, the loader and the exit code all have to agree
# -- and calling into any one of them would test the piece instead of the
# answer. The two definitions below are the path to the binary and the
# directory the fuzz seeds live in, both resolved by CMake so the test does
# not guess at build layout.
occ_add_test(occ_test_check test_check.cpp)
target_compile_definitions(occ_test_check PRIVATE
    OCC_BINARY="$<TARGET_FILE:occ>"
    OCC_SEED_DIR="${CMAKE_SOURCE_DIR}/fuzz/seeds")
add_dependencies(occ_test_check occ)

# occ_test_seeds guards the fuzz corpus against the generator that writes it.
#
# The corpus is generated because a checked-in binary says only what it is,
# and that only holds while the files and the generator agree. Nothing else
# would notice a drift: the harnesses read whatever bytes are in the
# directory, so a seed that no longer matches the program describing it would
# still run and still pass while reaching different code than it was written
# to reach.
#
# Both paths are handed in by CMake rather than assembled here, because a
# test that located the repository's own files by relative path would be the
# first thing to break under an out-of-tree build.
#
# It needs python3 and skips cleanly without it -- see the note the test
# prints when it does, which says plainly that a seed can drift unnoticed
# then. Python stays out of the build; this is the only thing that runs it.
occ_add_test(occ_test_seeds test_seeds.cpp)
target_compile_definitions(occ_test_seeds PRIVATE
    OCC_SEED_GENERATOR="${CMAKE_SOURCE_DIR}/tools/make_pe_seeds.py"
    OCC_SEED_DIR="${CMAKE_SOURCE_DIR}/fuzz/seeds")
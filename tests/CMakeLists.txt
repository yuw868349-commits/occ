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
# Fuzz harnesses.
#
# Built only with -DOCC_ENABLE_FUZZ=ON, which turns on the sanitizers and
# turns off the static link -- libFuzzer supplies main(), and a sanitized
# fully static binary is not something the linkers here produce.
#
# Each harness is a separate executable rather than one binary with a
# dispatch on the first byte, because they are run separately and against
# separate corpora. A combined harness would report a crash in the protocol
# codec as a finding about the ELF parser.

# The sanitizer and fuzzer link flags live here rather than in the top-level
# file because they are needed by these two targets and by nothing else.
# libFuzzer's archive contributes main(), and occ_core's own consumers --
# the occ binary, the tests -- have a main() already; applying the flag at
# directory scope would put two of them in one link.
set(OCC_FUZZ_LINK_FLAGS -fsanitize=fuzzer,address,undefined)

add_executable(occ_fuzz_elf fuzz_elf.cpp)
target_link_libraries(occ_fuzz_elf PRIVATE occ_core)
target_link_options(occ_fuzz_elf PRIVATE ${OCC_FUZZ_LINK_FLAGS})

add_executable(occ_fuzz_rsp fuzz_rsp.cpp)
target_link_libraries(occ_fuzz_rsp PRIVATE occ_core)
target_link_options(occ_fuzz_rsp PRIVATE ${OCC_FUZZ_LINK_FLAGS})

# The PE reader is the one parser whose input names a location indirectly:
# a PE gives an RVA, and turning it into a file offset means finding a
# section and comparing against two sizes that are routinely different. The
# harness's invariants are about that conversion, so it gets its own binary
# and its own corpus for the same reason the others do.
add_executable(occ_fuzz_pe fuzz_pe.cpp)
target_link_libraries(occ_fuzz_pe PRIVATE occ_core)
target_link_options(occ_fuzz_pe PRIVATE ${OCC_FUZZ_LINK_FLAGS})

# The loader is a second consumer of the same bytes and a second set of
# walks. It reads the relocation table and the import directory -- both of
# which the parser only reports the location of -- and it records regions in
# an address space. Its harness checks the loader's contract rather than the
# parser's, which is why it is a separate binary against the same corpus:
# the invariants differ even though the inputs do not.
add_executable(occ_fuzz_loader fuzz_loader.cpp)
target_link_libraries(occ_fuzz_loader PRIVATE occ_core)
target_link_options(occ_fuzz_loader PRIVATE ${OCC_FUZZ_LINK_FLAGS})

# The seeds below are real inputs, not noise. A fuzzer starts from a corpus
# and spends its first minutes broadening what it already reaches, so a
# corpus of zeros teaches it nothing about a header parser. These are the
# smallest inputs that get past each parser's first gate.
#
# The PE seeds are generated rather than checked in as binaries. A .bin file
# in a diff is a file nobody can review, and the whole claim of this corpus
# is that each entry gets past a particular gate -- a claim that has to be
# readable to be believable. tools/make_pe_seeds.py writes them, and the
# comments there say which gate each one is for.
#
# The last three are the loader's regressions rather than the parser's
# gates: files the loader used to accept and must refuse, one per shape the
# loader fuzz harness found. They are the seed half of those findings; the
# unit tests are the other half and are the ones that run in a default
# build.
set(OCC_PE_SEEDS
    pe32_min.bin
    pe32plus_min.bin
    pe_dll.bin
    pe_two_sections.bin
    pe_imports.bin
    pe_short_optional.bin
    pe_tiny_optional.bin
    mz_only.bin
    mz_no_signature.bin
    pe_bad_entry_rva.bin
    pe_entry_not_executable.bin
    pe_section_over_headers.bin)

set(OCC_PE_SEED_PATHS)
foreach(_seed IN LISTS OCC_PE_SEEDS)
    list(APPEND OCC_PE_SEED_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/seeds/${_seed})
endforeach()

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/corpus/pe/.stamp
    COMMAND ${CMAKE_COMMAND} -E make_directory
            ${CMAKE_CURRENT_BINARY_DIR}/corpus/pe
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${OCC_PE_SEED_PATHS}
            ${CMAKE_CURRENT_BINARY_DIR}/corpus/pe/
    COMMAND ${CMAKE_COMMAND} -E touch
            ${CMAKE_CURRENT_BINARY_DIR}/corpus/pe/.stamp
    COMMENT "regenerating the PE fuzzing seed corpus"
    VERBATIM)

add_custom_target(occ_fuzz_pe_corpus
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/corpus/pe/.stamp)

add_custom_target(occ_fuzz_corpus
    COMMAND ${CMAKE_COMMAND} -E make_directory
            ${CMAKE_CURRENT_BINARY_DIR}/corpus/elf
    COMMAND ${CMAKE_COMMAND} -E make_directory
            ${CMAKE_CURRENT_BINARY_DIR}/corpus/rsp
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/seeds/elf_min.bin
            ${CMAKE_CURRENT_BINARY_DIR}/corpus/elf/
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/seeds/rsp_g.gdb
            ${CMAKE_CURRENT_BINARY_DIR}/corpus/rsp/
    COMMENT "staging the fuzzing seed corpus")
add_dependencies(occ_fuzz_corpus occ_fuzz_pe_corpus)

# One target that runs each harness for a fixed time, for a caller who wants a
# smoke test rather than a campaign. The times are short enough to finish in
# under a minute and long enough to get past the start-up cost, which for a
# libFuzzer binary is most of what a fifteen-second run would do.
add_custom_target(occ_fuzz_smoke
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/occ_fuzz_elf
            -max_total_time=20
            -max_len=4096
            ${CMAKE_CURRENT_BINARY_DIR}/corpus/elf
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/occ_fuzz_rsp
            -max_total_time=20
            -max_len=256
            ${CMAKE_CURRENT_BINARY_DIR}/corpus/rsp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/occ_fuzz_pe
            -max_total_time=20
            -max_len=4096
            ${CMAKE_CURRENT_BINARY_DIR}/corpus/pe
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/occ_fuzz_loader
            -max_total_time=20
            -max_len=4096
            ${CMAKE_CURRENT_BINARY_DIR}/corpus/pe
    DEPENDS occ_fuzz_elf occ_fuzz_rsp occ_fuzz_pe occ_fuzz_loader
            occ_fuzz_corpus
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "running each harness briefly against its seeds")

# ------------------------------------------------------------------ ctest

# The target above is a convenience and nothing else: ctest never sees a
# custom target, so a harness registered only there is a harness that an
# ordinary `ctest` does not run. That is the whole difference between fuzzing
# that exists and fuzzing that happens, and it is worth the tests below.
#
# What this is not: a campaign. The coverage these harnesses reach from the
# checked-in seeds has converged -- a minute of occ_fuzz_pe moves the edge
# count by two -- so a longer run finds nothing a short one does not. What a
# bounded run catches is a change to the code under test that the seeds
# already reach, which is the regression a person would otherwise find by
# hand. A real campaign is someone running the binary for longer than this,
# and the README says so rather than implying that ctest is one.
#
# The seccomp and container tests are not built in this configuration, and
# the reason is in tests/CMakeLists.txt: a sanitizer cannot survive the
# seccomp filter it installs or the ptrace attach it performs. None of those
# four harnesses does either. They call the library over a buffer -- the ELF,
# PE and loader harnesses parse one, the RSP harness frames one -- with no
# fork, no exec, no filter and no tracer. The incompatibility that removes
# two tests from this build does not apply here, and a reader who has just
# read that it does somewhere else deserves the sentence saying so.
#
# The bound is libFuzzer's own -max_total_time and the ctest TIMEOUT is the
# backstop, four times larger. That order matters and it is not decoration:
# libFuzzer given a malformed -max_total_time value does not fail, it runs
# forever, so a test whose only limit is libFuzzer's has no limit at all. The
# TIMEOUT is what makes a harness that ignores its own bound a reported
# failure rather than a hung suite.
set(OCC_FUZZ_CTEST_SECONDS 30 CACHE STRING
    "Seconds each fuzz harness runs for when ctest invokes it")

function(occ_add_fuzz_run name harness max_len corpus)
    add_test(NAME ${name}
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/${harness}
                -max_total_time=${OCC_FUZZ_CTEST_SECONDS}
                -max_len=${max_len}
                ${CMAKE_CURRENT_BINARY_DIR}/corpus/${corpus})
    set_tests_properties(${name} PROPERTIES
        TIMEOUT 120
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endfunction()

occ_add_fuzz_run(occ_fuzz_run_elf    occ_fuzz_elf    4096 elf)
occ_add_fuzz_run(occ_fuzz_run_rsp    occ_fuzz_rsp    256  rsp)
occ_add_fuzz_run(occ_fuzz_run_pe     occ_fuzz_pe     4096 pe)
occ_add_fuzz_run(occ_fuzz_run_loader occ_fuzz_loader 4096 pe)

# A test that runs a harness against a corpus directory needs that directory
# populated, and the population is the same copy_if_different chain the
# targets above perform. A fixture repeats it as a test so that ctest alone
# -- without anyone having run the corpus targets first -- leaves the seeds
# where the harnesses look for them. An empty corpus directory would make
# every test below pass while fuzzing nothing, which is the failure mode this
# whole arrangement exists to avoid.
#
# One copy command per corpus, not one command with every seed and every
# destination: copy_if_different takes a list of sources and a single
# destination directory, so a command mixing the two would copy each directory
# name as if it were a source file and drop the seeds wherever the last
# argument pointed. The three commands below are what make the claim "the
# corpus is staged" true for all three corpora rather than for one.
add_test(NAME occ_fuzz_corpus_dirs
    COMMAND ${CMAKE_COMMAND} -E make_directory
            ${CMAKE_CURRENT_BINARY_DIR}/corpus/elf
            ${CMAKE_CURRENT_BINARY_DIR}/corpus/rsp
            ${CMAKE_CURRENT_BINARY_DIR}/corpus/pe)
add_test(NAME occ_fuzz_corpus_pe
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${OCC_PE_SEED_PATHS}
            ${CMAKE_CURRENT_BINARY_DIR}/corpus/pe)
add_test(NAME occ_fuzz_corpus_elf
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/seeds/elf_min.bin
            ${CMAKE_CURRENT_BINARY_DIR}/corpus/elf)
add_test(NAME occ_fuzz_corpus_rsp
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/seeds/rsp_g.gdb
            ${CMAKE_CURRENT_BINARY_DIR}/corpus/rsp)

set_tests_properties(occ_fuzz_corpus_dirs PROPERTIES FIXTURES_SETUP fuzz_corpus)
foreach(_s occ_fuzz_corpus_pe occ_fuzz_corpus_elf occ_fuzz_corpus_rsp)
    set_tests_properties(${_s} PROPERTIES
        FIXTURES_SETUP fuzz_corpus
        DEPENDS occ_fuzz_corpus_dirs)
endforeach()

foreach(_t occ_fuzz_run_elf occ_fuzz_run_rsp occ_fuzz_run_pe occ_fuzz_run_loader)
    set_tests_properties(${_t} PROPERTIES FIXTURES_REQUIRED fuzz_corpus)
endforeach()

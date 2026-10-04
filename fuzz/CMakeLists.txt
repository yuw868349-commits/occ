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

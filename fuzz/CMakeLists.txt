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

# The seeds below are real inputs, not noise. A fuzzer starts from a corpus
# and spends its first minutes broadening what it already reaches, so a
# corpus of zeros teaches it nothing about a header parser. These are the
# smallest inputs that get past each parser's first gate.
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
    DEPENDS occ_fuzz_elf occ_fuzz_rsp occ_fuzz_corpus
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "running each harness briefly against its seeds")

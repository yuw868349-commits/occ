#!/usr/bin/env bash
# occ unpack — one-command de-virtualization pipeline for VMProtect-style
# packed samples.
#
#   usage: unpack.sh <sample.exe> [dispatch-va] [prefix]
#
# The pipeline is the whole of the VM trace work, chained:
#   1. `occ run` with the page-trap dispatch trace, dumping the decrypted
#      image at the first dispatch (.vm) and at the fault (.vmf), plus the
#      address-to-name map the report needs (.api).
#   2. `devirt.py` reassembles the virtual stream from the trace and the
#      dump: handler semantics, API calls, control flow, and an
#      assembly-like listing, all in one report file.
#
# Output (default prefix: sample basename):
#   <prefix>.jsonl   the dispatch trace (operand-level)
#   <prefix>.vm      image dump at the first dispatch
#   <prefix>.vmf     image dump at the fault (fully decrypted engine)
#   <prefix>.api     API address->name map (ASLR-independent naming)
#   <prefix>.report.txt  the de-virtualization report
#   unpacked.exe     copy of the .vmf dump, ready for `occ inspect`
#
# Requires the build in ../build and a dispatch address for the packer.
# For the bundled VMProtect 3.x sample the dispatch is 0x140006b2a.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
occ="${root}/build/occ"

sample="${1:?usage: unpack.sh <sample.exe> [dispatch-va] [prefix]}"
dispatch="${2:-0x140006b2a}"
prefix="${3:-${sample%.exe}}"

if [[ ! -x "${occ}" ]]; then
    echo "error: ${occ} is not built; run cmake --build build first" >&2
    exit 2
fi

# The engine runs with the lab fallback (no sandbox) and the dispatch
# trap; the dump is written under the prefix.
(
    cd "$(dirname "${sample}")" || exit 2
    timeout 180 env \
        OCC_VM_TRACE="${prefix}.jsonl" \
        OCC_VM_DISPATCH="${dispatch}" \
        OCC_DUMP_IMAGE="${prefix}" \
        "${occ}" run --no-container "$(basename "${sample}")"
) >/dev/null 2>&1 || true   # the packer faults at the end by design

if [[ ! -s "${prefix}.jsonl" || ! -s "${prefix}.vmf" ]]; then
    echo "error: the trace or the dump is missing (dispatch ${dispatch}?)" >&2
    exit 1
fi

cp "${prefix}.vmf" unpacked.exe

"${occ}" devirt "${prefix}.jsonl" "${prefix}.vmf" \
    -o "${prefix}.report.txt" >/dev/null 2>&1 || true

echo "unpacked:"
echo "  trace       ${prefix}.jsonl ($(grep -c dispatch "${prefix}.jsonl" 2>/dev/null || echo 0) dispatches)"
echo "  dump@first  ${prefix}.vm"
echo "  dump@fault  ${prefix}.vmf (-> unpacked.exe)"
echo "  api map     ${prefix}.api"
echo "  report      ${prefix}.report.txt"

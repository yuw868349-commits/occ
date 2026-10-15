"""Write the missing surface of every DLL out as one C++ file per module.

Run: python3 build.py [<dll> ...]

The inputs are fixed and each has one job:

  * `/tmp/target_api.json` -- the export names this runtime does not answer,
    by module. Built from the mingw import libraries, which are the real
    DLLs' export tables read with `nm`.
  * `/tmp/mingw_prototypes.json` -- the declared signature of each of those
    names, read from the headers by `extract_prototypes.py`.
  * `/tmp/occ_names.txt` -- what the runtime already exports, so that a
    generated file never registers a name twice.

Everything the emitter writes lands under `src/runtime/api/generated/`. The
files are checked in: a generated file that is not in the repository is a
file whose content depends on which version of the toolchain produced it,
and the signatures here are meant to be read.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import emit
import wintypes
import semantic
from refuse import reason_for

PROTOTYPES = json.load(open('/tmp/mingw_prototypes.json'))
TARGET = json.load(open('/tmp/target_api.json'))
ALREADY = set(open('/tmp/occ_names.txt').read().split())

# The output directory is found from this file's own location, so that
# the tool runs from a checkout rather than from the directory it was
# written in.
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
OUT_DIR = os.path.join(ROOT, 'src', 'runtime', 'api', 'generated')

# The modules whose entire surface is generated. Each is a real DLL a guest
# can import from, and each is built by exactly one file below.
MODULE_NAMES = {
    'advapi32': 'ADVAPI32.dll', 'avifil32': 'AVIFIL32.dll',
    'bcrypt': 'BCRYPT.dll', 'comctl32': 'COMCTL32.dll',
    'comdlg32': 'COMDLG32.dll', 'crypt32': 'CRYPT32.dll',
    'dbghelp': 'DBGHELP.dll', 'dhcpcsvc': 'DHCPCSVC.dll',
    'dnsapi': 'DNSAPI.dll', 'gdi32': 'GDI32.dll', 'imm32': 'IMM32.dll',
    'iphlpapi': 'IPHLPAPI.dll', 'kernel32': 'KERNEL32.dll',
    'mpr': 'MPR.dll', 'msacm32': 'MSACM32.dll', 'mswsock': 'MSWSOCK.dll',
    'netapi32': 'NETAPI32.dll', 'ntdll': 'NTDLL.dll', 'ole32': 'OLE32.dll',
    'oleaut32': 'OLEAUT32.dll', 'opengl32': 'OPENGL32.dll',
    'rpcrt4': 'RPCRT4.dll', 'secur32': 'SECUR32.dll',
    'setupapi': 'SETUPAPI.dll', 'shell32': 'SHELL32.dll',
    'shlwapi': 'SHLWAPI.dll', 'user32': 'USER32.dll',
    'userenv': 'USERENV.dll', 'uxtheme': 'UXTHEME.dll',
    'winhttp': 'WINHTTP.dll', 'wininet': 'WININET.dll',
    'winmm': 'WINMM.dll', 'winspool': 'WINSPOOL.DRV', 'wintrust': 'WINTRUST.dll',
    'wldap32': 'WLDAP32.dll', 'ws2_32': 'WS2_32.dll',
    'wtsapi32': 'WTSAPI32.dll',
}

FILE_HEADER = '''// The {dll} surface this runtime did not answer.
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

'''

MIDDLE = '''
}  // namespace

void add_generated_{dll}(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
'''

FOOTER = '''}
}  // namespace occ::runtime::winabi
'''


def signature(dll, name, ret, args, names):
    return (f'extern "C" __attribute__((ms_abi)) {ret} '
            f'{emit.symbol_of(dll, name)}({emit.parameter_list(args, names)}) '
            f'noexcept {{\n')


def refusal_body(name, dll, ret, args, names):
    subsystem, note = reason_for(name, dll)
    lines = [f'    // Refused: {subsystem}.', '    //']
    lines += emit.wrap(note)
    lines += emit.unused_statements(args, names)
    lines.append('    set_last_error(kNotImplemented);')
    zero = emit.zero_of(ret)
    if zero is not None:
        lines.append(f'    return {zero};')
    return lines


def nullary_refusal(dll, name):
    """A refusal for an export whose signature the headers do not state."""
    subsystem, note = reason_for(name, dll)
    lines = [f'    // Refused: {subsystem}.', '    //']
    lines += emit.wrap(note)
    lines += [
        '    //',
        '    // The signature is not in the headers, so this thunk declares no',
        '    // parameters at all. That is safe on this ABI: the caller allocates',
        '    // and releases the shadow space, and a callee that names no',
        '    // parameter reads neither it nor the registers the arguments',
        '    // arrived in. The answer is a zero, which is the answer a refused',
        '    // call already gives.',
        '    set_last_error(kNotImplemented);',
        '    return 0;',
    ]
    head = (f'extern "C" __attribute__((ms_abi)) std::uint32_t '
            f'{emit.symbol_of(dll, name)}() noexcept {{\n')
    return head + '\n'.join(lines) + '\n}\n'


def build(dll):
    names = [n for n in TARGET.get(dll, []) if n not in ALREADY]
    protos = PROTOTYPES.get(dll, {})
    pieces = []
    registrations = []
    skipped = []
    real = 0
    used_domains = set()
    for name in names:
        proto = protos.get(name)
        if proto is None:
            # A name the headers do not declare. The export exists -- the
            # import library lists it -- but its signature is not written
            # down anywhere this runtime can read, and a guessed arity is a
            # call that reads its arguments out of the wrong registers.
            #
            # The platform's convention is what makes a stub safe here: on
            # the 64-bit Microsoft ABI the caller allocates the shadow space
            # and cleans it up, and a callee that declares no parameters
            # touches neither them nor the registers they would arrive in.
            # So this is a refusal with no parameters, and it reads nothing
            # it was not given.
            pieces.append(nullary_refusal(dll, name))
            registrations.append(
                f'    e("{name}", reinterpret_cast<void*>(&'
                f'{emit.symbol_of(dll, name)}));')
            continue
        ret = wintypes.map_return(proto['ret'])
        args = wintypes.split_args(proto['args'])
        if not args and proto['args'].strip() not in ('', 'void', 'VOID'):
            skipped.append(name)
            continue
        names = emit.parameter_names(args)
        head = signature(dll, name, ret, args, names)
        body = semantic.body(dll, name, ret, args, names)
        if body is None:
            lines = refusal_body(name, dll, ret, args, names)
        else:
            lines = body.split('\n')
            real += 1
            used_domains.add(semantic.last_domain())
        pieces.append(head + '\n'.join(lines) + '\n}\n')
        registrations.append(
            f'    e("{name}", reinterpret_cast<void*>(&'
            f'{emit.symbol_of(dll, name)}));')
    if not pieces:
        return 0, 0, real, skipped

    text = FILE_HEADER.replace('{dll}', dll.upper())
    helpers = semantic.helpers_for(dll, used_domains)
    if helpers:
        text += helpers + '\n'
    text += '\n\n'.join(pieces)
    text += MIDDLE.replace('{dll}', dll)
    text += '\n'.join(registrations)
    text += '\n' + FOOTER
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, f'{dll}.cpp'), 'w') as handle:
        handle.write(text)
    return len(pieces), len(registrations), real, skipped


if __name__ == '__main__':
    wanted = sys.argv[1:] or sorted(MODULE_NAMES)
    total = 0
    total_real = 0
    for dll in wanted:
        count, _, real, skipped = build(dll)
        total += count
        total_real += real
        line = f'{dll:12s} {count:5d} functions {real:5d} implemented'
        if skipped:
            line += f'  ({len(skipped)} skipped: {", ".join(skipped[:4])})'
        print(line)
    print(f'total {total} functions, {total_real} implemented')
    unresolved = wintypes.TYPES.unresolved()
    print(f'type names answered by the last resort: {len(unresolved)}')

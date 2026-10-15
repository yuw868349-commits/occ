"""Extract every prototype the mingw headers declare, with its return type.

The earlier pass kept the argument list but read the return type off the
wrong token: a declaration is spelled
`WINBASEAPI BOOL WINAPI AddConsoleAliasA(...)`, and taking the last word of
the prefix answers `WINAPI` -- a calling convention, not a type. That is not
a cosmetic error. The return type decides which register the callee's answer
is read out of, so a wrong one makes every caller of the function read
garbage, and it does it silently.

So the prefix is taken apart properly here: the attributes are removed with
balanced parentheses, the storage and convention macros are dropped by name,
and what is left is the type. The preprocessor does the expansion, because
the declarations are macro-decorated and the raw text cannot be read.
"""
import json
import os
import re
import subprocess

INC = '/usr/x86_64-w64-mingw32/include'

HEADERS = {
 'kernel32': ['winbase.h','winnls.h','wincon.h','processthreadsapi.h','memoryapi.h','synchapi.h',
              'fileapi.h','handleapi.h','ioapiset.h','winreg.h','jobapi.h','libloaderapi.h',
              'namedpipeapi.h','profileapi.h','sysinfoapi.h','timezoneapi.h','errhandlingapi.h',
              'interlockedapi.h','utilapiset.h','wow64apiset.h','debugapi.h','consoleapi.h',
              'realtimeapiset.h','winerror.h'],
 'ntdll': ['winternl.h','ntsecapi.h','ntstatus.h','wdm.h'],
 'advapi32': ['winreg.h','winsvc.h','aclapi.h','securitybaseapi.h','ntsecapi.h','sddl.h',
              'accctrl.h','wincrypt.h'],
 'user32': ['winuser.h','wincon.h','dde.h','winable.h'],
 'gdi32': ['wingdi.h','winnls.h'],
 'ole32': ['objbase.h','objidl.h','objidlbase.h','ole2.h','combaseapi.h','unknwn.h','propidl.h'],
 'oleaut32': ['oleauto.h','oaidl.h'],
 'shell32': ['shellapi.h','shlobj.h'],
 'shlwapi': ['shlwapi.h'],
 'ws2_32': ['winsock2.h','ws2tcpip.h'],
 'wininet': ['wininet.h'],
 'winhttp': ['winhttp.h'],
 'crypt32': ['wincrypt.h','dpapi.h'],
 'bcrypt': ['bcrypt.h'],
 'setupapi': ['setupapi.h','cfgmgr32.h','devpropdef.h'],
 'dbghelp': ['dbghelp.h'],
 'iphlpapi': ['iphlpapi.h','iptypes.h'],
 'dnsapi': ['windns.h'],
 'netapi32': ['lm.h','lmaccess.h'],
 'version': ['winver.h'],
 'psapi': ['psapi.h'],
 'winmm': ['mmsystem.h','timeapi.h','playsoundapi.h','joystickapi.h'],
 'winspool': ['winspool.h'],
 'secur32': ['sspi.h','schannel.h'],
 'wintrust': ['wintrust.h','softpub.h'],
 'imm32': ['imm.h'],
 'comctl32': ['commctrl.h'],
 'uxtheme': ['uxtheme.h'],
 'wtsapi32': ['wtsapi32.h'],
 'userenv': ['userenv.h'],
 'mpr': ['winnetwk.h'],
 'wldap32': ['winldap.h'],
 'dhcpcsvc': ['dhcpcsvc.h'],
 'msacm32': ['msacm.h'],
 'avifil32': ['vfw.h'],
 'opengl32': ['GL/gl.h','GL/glu.h'],
 'comdlg32': ['commdlg.h'],
 'mswsock': ['mswsock.h'],
 'rpcrt4': ['rpcdce.h','rpc.h','rpcndr.h','rpcasync.h'],
}

PROTO = re.compile(
    r'(?m)^[ \t]*'
    r'((?:[A-Za-z_][A-Za-z0-9_]*[ \t]+|\*[ \t]*|__attribute__[ \t]*\(\(.*?\)\)[ \t]*)+?)'
    r'([A-Za-z_][A-Za-z0-9_]*)[ \t]*\(([^;(){}]*)\)[ \t]*;')

# Names that decorate a declaration without being part of its type. The
# list is the calling conventions, the storage classes and the export
# attributes the Windows headers spell their declarations with.
NOISE = {
    'WINBASEAPI', 'WINGDIAPI', 'WINUSERAPI', 'WINADVAPI', 'WINAPI', 'WINAPIV',
    'APIENTRY', 'CALLBACK', 'PASCAL', 'NTAPI', 'NTSYSAPI', 'NTAPI',
    'RPC_ENTRY', 'RPC_USER', 'RPC_STUB', 'STDAPICALLTYPE', 'STDAPI',
    'STDMETHODCALLTYPE', 'STDMETHODIMP', 'DECLSPEC_IMPORT', 'DECLSPEC_EXPORT',
    'DECLSPEC_DEPRECATED', 'EXTERN_C', '__cdecl', '__stdcall', '__fastcall',
    '__RPC_USER', '__RPC_FAR', '__RPC_STUB', '__RPC_API', '__MINGW_NOTHROW',
    '__MINGW_ATTRIB_NORETURN', '__MINGW_ATTRIB_DEPRECATED',
    '__MINGW_ATTRIB_DEPRECATED_MSG', '__MINGW_EXTENSION', 'static', 'inline',
    '__inline__', '__inline', 'extern', '__extension__', '__forceinline',
    '__CRT_INLINE', '__CRTIMP', '_CRTIMP', 'WINBOOL_', 'WINGDIAPI_',
    '__declspec', 'dllimport', 'dllexport', 'noreturn',
}

SKIP = {'pack','pop','if','for','while','switch','return','sizeof','defined','va_arg',
        'va_start','va_end','va_copy','__attribute__','__asm__','__extension__','typedef'}


def _strip_attributes(text):
    """Removes every `__attribute__((...))`, balancing its parentheses."""
    out = []
    index = 0
    while index < len(text):
        found = text.find('__attribute__', index)
        if found < 0:
            out.append(text[index:])
            break
        out.append(text[index:found])
        at = found + len('__attribute__')
        while at < len(text) and text[at] in ' \t':
            at += 1
        if at >= len(text) or text[at] != '(':
            index = at
            continue
        depth = 0
        while at < len(text):
            if text[at] == '(':
                depth += 1
            elif text[at] == ')':
                depth -= 1
                if depth == 0:
                    at += 1
                    break
            at += 1
        index = at
    return ''.join(out)


def _return_type(prefix):
    """The type a declaration's prefix states, with the noise removed."""
    text = _strip_attributes(prefix)
    words = []
    for word in re.split(r'\s+', text.strip()):
        if not word or word in NOISE:
            continue
        if word.startswith('__attribute__') or word.startswith('__declspec'):
            continue
        words.append(word)
    if not words:
        return 'void'
    return ' '.join(words)


def _normalise_args(text):
    """The argument list, with the whitespace collapsed.

    A parameter's own type is kept intact -- `char * p` becomes `char *p` --
    because the argument text is what the signature is built from and a lost
    asterisk is a call that passes an integer where a pointer was meant.
    """
    return ' '.join(text.split())


def prototypes_of(headers):
    out = {}
    for header in headers:
        if not os.path.exists(os.path.join(INC, header)):
            continue
        text = subprocess.run(
            ['x86_64-w64-mingw32-gcc','-E','-P','-xc','-include',header,'-'],
            input='', capture_output=True, text=True).stdout
        for m in PROTO.finditer(text):
            prefix = m.group(1)
            name = m.group(2)
            args = _normalise_args(m.group(3))
            if name in SKIP or name.startswith('__') or len(name) < 2:
                continue
            ret = _return_type(prefix)
            if ret in NOISE or ret.endswith('__'):
                continue
            if name in out:
                continue
            out[name] = {'ret': ret, 'args': args}
    return out


if __name__ == '__main__':
    result = {dll: prototypes_of(h) for dll, h in HEADERS.items()}
    json.dump(result, open('/tmp/mingw_prototypes.json', 'w'))
    total = sum(len(v) for v in result.values())
    print('DLLs:', len(result), ' prototypes:', total)
    for dll, p in sorted(result.items(), key=lambda kv: -len(kv[1]))[:12]:
        print(f'  {dll:12s} {len(p):5d}')
    for probe in ('GetSystemTimeAsFileTime', 'AddConsoleAliasA', 'NdrAllocate'):
        for dll, p in result.items():
            if probe in p:
                print(f'  {probe}: {p[probe]}')
                break

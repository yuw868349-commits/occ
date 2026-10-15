"""Emit the C++ for one DLL's missing surface.

The shape of the output is the shape every other domain in this runtime
has: a file of `ms_abi` entry points and one registration function that
pushes them into an `ExportList`. What is different here is only where the
bodies come from -- a rule table for the ones whose behaviour is stated,
and the refusal for the rest.

Two things are decided here rather than in a rule, because they have to be
true of every function in the file:

  * the symbol name. A guest export can start with an underscore, and a
    symbol that starts with an underscore followed by a capital -- let
    alone two underscores -- is reserved to the implementation, so the
    symbol is built instead of copied: a fixed prefix, the DLL, and the
    export with its leading underscores turned into something an
    identifier may start with.
  * the parameter names. A header is free to name a parameter `type` or
    `class`; C++ is not. The name is kept where it is legal because a
    signature reads better with it, and suffixed where it is not.
"""

import re

CPP_KEYWORDS = {
    'alignas', 'alignof', 'and', 'and_eq', 'asm', 'auto', 'bitand', 'bitor',
    'bool', 'break', 'case', 'catch', 'char', 'char8_t', 'char16_t',
    'char32_t', 'class', 'compl', 'concept', 'const', 'consteval',
    'constexpr', 'constinit', 'const_cast', 'continue', 'co_await',
    'co_return', 'co_yield', 'decltype', 'default', 'delete', 'do', 'double',
    'dynamic_cast', 'else', 'enum', 'explicit', 'export', 'extern', 'false',
    'float', 'for', 'friend', 'goto', 'if', 'inline', 'int', 'long',
    'mutable', 'namespace', 'new', 'noexcept', 'not', 'not_eq', 'nullptr',
    'operator', 'or', 'or_eq', 'private', 'protected', 'public', 'register',
    'reinterpret_cast', 'requires', 'return', 'short', 'signed', 'sizeof',
    'static', 'static_assert', 'static_cast', 'struct', 'switch', 'template',
    'this', 'thread_local', 'throw', 'true', 'try', 'typedef', 'typeid',
    'typename', 'union', 'unsigned', 'using', 'virtual', 'void', 'volatile',
    'wchar_t', 'while', 'xor', 'xor_eq',
    # Not keywords, but the names this file uses for its own machinery.
    'set_last_error', 'kNotImplemented', 'out', 'e', 'entry',
}

# The types a body may not put an argument through `static_cast<void>` and
# still compile: an array or a function parameter has no address to read.
BUILTIN_RESERVED = ('std', 'occ', 'winabi', 'bool', 'char', 'int', 'long')


def symbol_of(dll, name):
    """The C++ identifier for one export's thunk."""
    body = re.sub(r'[^A-Za-z0-9_]', '_', name)
    body = body.lstrip('_')
    if not body or body[0].isdigit():
        body = 'x' + body
    return f'k{dll}G_{body}'


def parameter_of(name, index, used=None):
    """A parameter name that is legal C++ and unique in its list."""
    candidate = name if name and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name) \
        else f'arg{index}'
    if candidate in CPP_KEYWORDS:
        candidate += '_'
    if used is not None:
        seen = used.setdefault(candidate, 0)
        if seen:
            candidate = f'{candidate}{seen}'
        used[candidate] = used.get(candidate, 0) + 1
    return candidate


def parameter_names(args):
    """The names a thunk's parameters are declared with.

    The names come from the header and are kept, because a signature reads
    better with them than with a sequence of `arg0`. A name that is a C++
    keyword, or that appears twice, is adjusted -- and the rule that writes
    the body is handed this list rather than the header's, so that the two
    spell the parameter the same way.
    """
    used = {}
    out = []
    for index, (ctype, name) in enumerate(args):
        out.append(None if ctype == '...' else parameter_of(name, index, used))
    return out


def parameter_list(args, names):
    """The parameter list of one thunk."""
    parts = []
    for ctype, name in zip([a[0] for a in args], names):
        parts.append('...' if ctype == '...' else f'{ctype} {name}')
    return ', '.join(parts)


def unused_statements(args, names):
    """`static_cast<void>` for every parameter the body does not read.

    The runtime builds with `-Werror -Wunused-parameter`, and a function
    that refuses a call is a function that does not read its arguments.
    Naming them silences the warning in the one way that stays honest: the
    parameter is still there, still named, and the body says it is not the
    reason the call failed.
    """
    out = []
    for ctype, name in zip([a[0] for a in args], names):
        if ctype == '...':
            continue
        out.append(f'    static_cast<void>({name});')
    return out


def zero_of(ret):
    """The answer that means "this did not happen" for a return type."""
    if ret == 'void':
        return None
    if ret.endswith('*'):
        return 'nullptr'
    if ret in ('float', 'double'):
        return '0.0'
    return '0'


def wrap(text, width=72, prefix='    // '):
    """A comment, wrapped. The notes are prose and a source line is 80."""
    lines = []
    current = ''
    for word in text.split():
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = (current + ' ' + word).strip()
    if current:
        lines.append(current)
    return [prefix + line for line in lines]

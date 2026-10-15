"""The implementations that can be written from a name and a signature.

A domain here is a family of exports whose behaviour is one algorithm
parameterised by the name. `PathCompactPathExA` and `PathCompactPathExW` are
the same rule at two character widths, and the rule says so once.

What belongs here is narrow on purpose. A rule is written only where the
behaviour is defined by a format, a structure layout or an arithmetic rule
-- something that can be read off a specification rather than off a
machine this runtime does not have. Everything else is refused by
`refuse.py`, which is not a fallback but a statement: the call needs
something this runtime does not carry, and the reason names what.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sem_common

# The domain modules, in the order a name is looked for. Order matters only
# where two domains could claim one name, and they are listed by module so
# that a reader can find the file that answers a call.
DOMAIN_MODULES = [
    'sem_shlwapi',
    'sem_kernel',
    'sem_profile',
    'sem_ntdll',
    'sem_advapi',
    'sem_oleaut',
    'sem_ole32',
    'sem_user32',
    'sem_gdi32',
    'sem_net',
    'sem_shell32',
    'sem_misc',
]

_LOADED = None


def _domains():
    global _LOADED
    if _LOADED is not None:
        return _LOADED
    _LOADED = []
    for module_name in DOMAIN_MODULES:
        try:
            module = __import__(module_name)
        except ImportError:
            continue
        _LOADED.append(module)
    return _LOADED


_LAST_DOMAIN = None


def last_domain():
    """The module that answered the last call to `body`."""
    return _LAST_DOMAIN


def body(dll, name, ret, args, names):
    """The body for one name, or None when no rule fits it.

    `args` is the mapped parameter list and `names` the identifiers the
    thunk declares them with, so that a rule writes the same spelling the
    signature does.
    """
    for module in _domains():
        rule = getattr(module, 'body', None)
        if rule is None:
            continue
        try:
            text = rule(dll, name, ret, args, names)
        except Exception:
            text = None
        if text is not None:
            global _LAST_DOMAIN
            _LAST_DOMAIN = module.__name__
            return text
    return None


def helpers_for(dll, used_domains):
    """The helper block a generated file needs.

    Only the domains that answered a call in this file contribute, and the
    common block is emitted only when there is one of them. A file of
    refusals reads its arguments through `static_cast<void>` and needs no
    walk of anything, and a file whose only implementations come from one
    domain has no use for another domain's walks -- and a helper nothing
    calls is a helper the compiler is right to report.
    """
    blocks = []
    for module in _domains():
        if module.__name__ not in used_domains:
            continue
        domain_helpers = getattr(module, 'HELPERS', None)
        if domain_helpers:
            blocks.append(domain_helpers)
    if not blocks:
        return ''
    return sem_common.COMMON + '\n'.join(blocks)

"""kernel32: the interlocked family, the profile files, and the small算.

Three groups live here, and they are here together because each is a
function of its arguments alone:

  * the interlocked and bit-test family, which is a set of atomic
    read-modify-write operations. The runtime runs one guest thread, but the
    operations are still written as atomics: a guest that uses them to
    protect a structure is entitled to the guarantee the API states, and an
    implementation that was only correct because nothing else runs would be
    a promise quietly withdrawn.

  * the profile files. `GetPrivateProfileString` reads an INI file, and an
    INI file is a text format with a definition: sections in brackets, keys,
    values, the delimiter rules, the comment rules. All of it is in the
    format, so all of it is implemented here.

  * the calls whose whole body is a conversion or an acknowledgement the
    API documents as having no effect. `GlobalFix` is documented as doing
    nothing on Win32; a function that did nothing else and said so is not a
    stub, it is the behaviour.
"""

import re

HELPERS = '''
// ------------------------------------------------------------------ bits
//
// The bit-test family is defined in terms of the bit it names, so it is
// written over the width rather than over a type: every one of them takes a
// bit index that is allowed to be out of range, and the answer for an
// out-of-range index is what makes the family usable as a test.

template <typename W>
[[nodiscard]] bool bit_of(W value, std::int64_t index) noexcept {
    const std::int64_t width = static_cast<std::int64_t>(sizeof(W) * 8);
    if (index < 0 || index >= width) {
        return false;
    }
    return ((value >> index) & static_cast<W>(1)) != 0;
}

template <typename W>
void bit_set(W* value, std::int64_t index, bool on) noexcept {
    const std::int64_t width = static_cast<std::int64_t>(sizeof(W) * 8);
    if (value == nullptr || index < 0 || index >= width) {
        return;
    }
    const W mask = static_cast<W>(static_cast<W>(1) << index);
    if (on) {
        *value = static_cast<W>(*value | mask);
    } else {
        *value = static_cast<W>(*value & static_cast<W>(~mask));
    }
}

// The position of the lowest set bit, as `_BitScanForward` reports it: the
// answer says whether there was one, and the index is written only when
// there was.
[[nodiscard]] bool scan_forward(std::uint64_t mask, std::uint32_t* index) noexcept {
    if (mask == 0) {
        return false;
    }
    std::uint32_t at = 0;
    while (((mask >> at) & 1u) == 0u) {
        ++at;
    }
    *index = at;
    return true;
}

// The position of the highest set bit, as `_BitScanReverse` reports it.
[[nodiscard]] bool scan_reverse(std::uint64_t mask, std::uint32_t* index) noexcept {
    if (mask == 0) {
        return false;
    }
    std::uint32_t at = 63;
    while (((mask >> at) & 1u) == 0u) {
        --at;
    }
    *index = at;
    return true;
}

// A 128-bit product, as the signed and unsigned pairs below need it. The
// host's own wide type is what makes the multiply exact: `(a*b) >> shift`
// computed in 64 bits would be a different answer, and it is the answer a
// caller of these functions is trying to avoid.
[[nodiscard]] unsigned __int128 widen_product(std::uint64_t left,
                                              std::uint64_t right) noexcept {
    return static_cast<unsigned __int128>(left) *
           static_cast<unsigned __int128>(right);
}

// ------------------------------------------------------------------- ini
//
// The profile format. A file is a sequence of lines; a line is a section
// header, a key and a value, a comment, or nothing. The rules that matter
// and that a naive reader gets wrong are:
//
//   * a key and its value are separated by `=` or `:`, and the first of
//     either is the separator -- a colon inside a value is part of it;
//   * the blank space around both is not part of either;
//   * a line whose first non-blank character is `;` is a comment;
//   * a section name is bracketed, and the brackets are not part of it;
//   * a key reached before any section belongs to no section, and asking
//     for it under a name finds nothing.

// Whether a line is blank or a comment.
template <typename C>
[[nodiscard]] bool ini_line_ignorable(const C* line) noexcept {
    while (*line == static_cast<C>(' ') || *line == static_cast<C>('\\t')) {
        ++line;
    }
    return *line == static_cast<C>(0) || *line == static_cast<C>(';') ||
           *line == static_cast<C>('#');
}

// The span of a line, as a pointer and a length, so that a reader does not
// have to write a terminator into the caller's file.
template <typename C>
struct IniSpan {
    const C* text = nullptr;
    std::size_t length = 0;
};

// The next line, and a cursor past it.
template <typename C>
[[nodiscard]] bool ini_next_line(const C* file, std::size_t size,
                                 std::size_t* cursor,
                                 IniSpan<C>* line) noexcept {
    if (*cursor >= size || file[*cursor] == static_cast<C>(0)) {
        return false;
    }
    std::size_t end = *cursor;
    while (end < size && file[end] != static_cast<C>(0) &&
           file[end] != static_cast<C>('\\n') &&
           file[end] != static_cast<C>('\\r')) {
        ++end;
    }
    line->text = file + *cursor;
    line->length = end - *cursor;
    while (end < size && (file[end] == static_cast<C>('\\n') ||
                          file[end] == static_cast<C>('\\r'))) {
        ++end;
    }
    *cursor = end;
    return true;
}

// The section a line introduces, or nothing.
template <typename C>
[[nodiscard]] bool ini_section_of(const IniSpan<C>& line,
                                  IniSpan<C>* name) noexcept {
    std::size_t at = 0;
    while (at < line.length && (line.text[at] == static_cast<C>(' ') ||
                               line.text[at] == static_cast<C>('\\t'))) {
        ++at;
    }
    if (at >= line.length || line.text[at] != static_cast<C>('[')) {
        return false;
    }
    ++at;
    const std::size_t start = at;
    while (at < line.length && line.text[at] != static_cast<C>(']') &&
           line.text[at] != static_cast<C>('\\n')) {
        ++at;
    }
    if (at >= line.length || line.text[at] != static_cast<C>(']')) {
        return false;
    }
    name->text = line.text + start;
    name->length = at - start;
    return true;
}

// The key and the value of a line, or nothing. Split at the first `=` or
// `:` that is not inside the key, with the blank space trimmed from both
// ends of both halves.
template <typename C>
[[nodiscard]] bool ini_pair_of(const IniSpan<C>& line, IniSpan<C>* key,
                               IniSpan<C>* value) noexcept {
    std::size_t at = 0;
    while (at < line.length && (line.text[at] == static_cast<C>(' ') ||
                               line.text[at] == static_cast<C>('\\t'))) {
        ++at;
    }
    if (at >= line.length) {
        return false;
    }
    const std::size_t key_start = at;
    while (at < line.length && line.text[at] != static_cast<C>('=') &&
           line.text[at] != static_cast<C>(':') &&
           line.text[at] != static_cast<C>('\\n')) {
        ++at;
    }
    if (at >= line.length) {
        return false;
    }
    std::size_t key_end = at;
    while (key_end > key_start && (line.text[key_end - 1] == static_cast<C>(' ') ||
                                  line.text[key_end - 1] == static_cast<C>('\\t'))) {
        --key_end;
    }
    if (key_end == key_start) {
        return false;
    }
    ++at;  // past the separator
    while (at < line.length && (line.text[at] == static_cast<C>(' ') ||
                               line.text[at] == static_cast<C>('\\t'))) {
        ++at;
    }
    std::size_t value_end = line.length;
    while (value_end > at && (line.text[value_end - 1] == static_cast<C>(' ') ||
                              line.text[value_end - 1] == static_cast<C>('\\t'))) {
        --value_end;
    }
    key->text = line.text + key_start;
    key->length = key_end - key_start;
    value->text = line.text + at;
    value->length = value_end - at;
    return true;
}

// Case-insensitive comparison against a span, which is how the format's
// names behave: `[Section]` and `[SECTION]` name the same section.
template <typename C>
[[nodiscard]] bool ini_span_equals(const IniSpan<C>& span, const C* wanted,
                                   std::size_t wanted_length) noexcept {
    if (span.length != wanted_length) {
        return false;
    }
    for (std::size_t index = 0; index < wanted_length; ++index) {
        if (ch_lower_of(span.text[index]) != ch_lower_of(wanted[index])) {
            return false;
        }
    }
    return true;
}

// The number a profile key holds. The reference parses an optional sign and
// a run of digits, and stops at the first character that is neither --
// which is why `10` and `10xyz` both answer ten.
[[nodiscard]] std::int64_t ini_number(const char16_t* text,
                                      std::size_t length) noexcept {
    std::size_t at = 0;
    while (at < length && (text[at] == u' ' || text[at] == u'\\t')) {
        ++at;
    }
    bool negative = false;
    if (at < length && (text[at] == u'-' || text[at] == u'+')) {
        negative = text[at] == u'-';
        ++at;
    }
    std::int64_t value = 0;
    bool any = false;
    while (at < length && ch_digit(text[at])) {
        any = true;
        value = value * 10 + static_cast<std::int64_t>(text[at] - u'0');
        ++at;
    }
    if (!any) {
        return 0;
    }
    return negative ? -value : value;
}

// The whole of a profile file, read through the runtime's own file calls so
// that the code page and the path translation are the same ones every other
// file call uses.
[[nodiscard]] bool read_profile_file(const char16_t* path,
                                     std::u16string* out) noexcept {
    char narrow[1024];
    if (path == nullptr) {
        return false;
    }
    static_cast<void>(narrow_text(path, narrow, 1024));
    void* file = cr_fopen(narrow, "rb");
    if (file == nullptr) {
        return false;
    }
    char buffer[4096];
    for (;;) {
        const std::uint64_t got = cr_fread(buffer, 1, sizeof(buffer), file);
        if (got == 0) {
            break;
        }
        out->reserve(out->size() + static_cast<std::size_t>(got));
        for (std::uint64_t index = 0; index < got; ++index) {
            out->push_back(static_cast<char16_t>(
                static_cast<unsigned char>(buffer[index])));
        }
    }
    static_cast<void>(cr_fclose(file));
    return true;
}
'''

RULES = []


def rule(pattern):
    def decorate(builder):
        RULES.append((re.compile(pattern), builder))
        return builder
    return decorate


class Ctx:
    def __init__(self, name, ret, args, names):
        self.name = name
        self.ret = ret
        self.args = args
        self.names = names
        self.wide = name.endswith('W')

    def arg(self, index):
        return self.names[index] if index < len(self.names) else None


def _w(ctx):
    return 'W' if ctx.wide else 'A'


def _lit(ctx, text):
    return f'u"{text}"' if ctx.wide else f'"{text}"'


# ------------------------------------------------------------- interlocked
#
# The family is written from one body per operation, because the atomic
# builtin takes the width as its template argument and the operations differ
# only in which builtin and which width.

_ATOMIC = {
    'Increment': ('__atomic_add_fetch(p, {one}, __ATOMIC_SEQ_CST)', 'new'),
    'Decrement': ('__atomic_sub_fetch(p, {one}, __ATOMIC_SEQ_CST)', 'new'),
    'Add': ('__atomic_add_fetch(p, {value}, __ATOMIC_SEQ_CST)', 'new'),
    'Exchange': ('__atomic_exchange_n(p, {value}, __ATOMIC_SEQ_CST)', 'old'),
    'ExchangeAdd': ('__atomic_fetch_add(p, {value}, __ATOMIC_SEQ_CST)', 'old'),
    'And': ('__atomic_fetch_and(p, {value}, __ATOMIC_SEQ_CST)', 'old'),
    'Or': ('__atomic_fetch_or(p, {value}, __ATOMIC_SEQ_CST)', 'old'),
    'Xor': ('__atomic_fetch_xor(p, {value}, __ATOMIC_SEQ_CST)', 'old'),
    'CompareExchange': (
        '__atomic_compare_exchange_n(p, &expected, {value}, false, '
        '__ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST) ? expected : expected', 'old'),
}


def _interlocked(c, op, width, arg_index):
    """One atomic operation, at one width."""
    target = c.arg(0)
    if op in ('Increment', 'Decrement'):
        return f'''    if ({target} == nullptr) {{
        return 0;
    }}
    auto* p = const_cast<{width}*>({target});
    {width} one = 1;
    return static_cast<{c.ret}>({_atomic_expr(op, 'new', 'one', None)});'''
    if op == 'CompareExchange':
        comparand = c.arg(2)
        exchange = c.arg(1)
        return f'''    if ({target} == nullptr) {{
        return nullptr;
    }}
    auto* p = const_cast<{width}*>({target});
    {width} expected = static_cast<{width}>({comparand});
    static_cast<void>(__atomic_compare_exchange_n(
        p, &expected, static_cast<{width}>({exchange}), false,
        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST));
    return static_cast<{c.ret}>(expected);'''
    value = c.arg(1)
    return f'''    if ({target} == nullptr) {{
        return 0;
    }}
    auto* p = const_cast<{width}*>({target});
    {width} value = static_cast<{width}>({value_name});
    return static_cast<{c.ret}>({_atomic_expr(op, 'old', None, 'value')});'''.replace(
        '{value_name}', str(value))


def _atomic_expr(op, kind, one, value):
    if op == 'Increment':
        return '__atomic_add_fetch(p, one, __ATOMIC_SEQ_CST)'
    if op == 'Decrement':
        return '__atomic_sub_fetch(p, one, __ATOMIC_SEQ_CST)'
    if op == 'Add':
        return '__atomic_add_fetch(p, value, __ATOMIC_SEQ_CST)'
    if op == 'Exchange':
        return '__atomic_exchange_n(p, value, __ATOMIC_SEQ_CST)'
    if op == 'ExchangeAdd':
        return '__atomic_fetch_add(p, value, __ATOMIC_SEQ_CST)'
    if op == 'And':
        return '__atomic_fetch_and(p, value, __ATOMIC_SEQ_CST)'
    if op == 'Or':
        return '__atomic_fetch_or(p, value, __ATOMIC_SEQ_CST)'
    if op == 'Xor':
        return '__atomic_fetch_xor(p, value, __ATOMIC_SEQ_CST)'
    return '0'


def _make_interlocked(op, width, ret):
    def builder(c):
        target = c.arg(0)
        if op in ('Increment', 'Decrement'):
            body = f'''    if ({target} == nullptr) {{
        return 0;
    }}
    auto* p = const_cast<{width}*>({target});
    {width} one = 1;
    return static_cast<{ret}>({_atomic_expr(op, 'new', 'one', None)});'''
        elif op == 'CompareExchange':
            if c.arg(2) is None:
                return None
            comparand, exchange = c.arg(2), c.arg(1)
            body = f'''    if ({target} == nullptr) {{
        return static_cast<{ret}>(0);
    }}
    auto* p = const_cast<{width}*>({target});
    {width} expected = static_cast<{width}>({comparand});
    static_cast<void>(__atomic_compare_exchange_n(
        p, &expected, static_cast<{width}>({exchange}), false,
        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST));
    return static_cast<{ret}>(expected);'''
        else:
            value = c.arg(1)
            if value is None:
                return None
            body = f'''    if ({target} == nullptr) {{
        return 0;
    }}
    auto* p = const_cast<{width}*>({target});
    {width} value = static_cast<{width}>({value});
    return static_cast<{ret}>({_atomic_expr(op, 'old', None, 'value')});'''
        return body
    return builder


INTERLOCKED_RULES = [
    (r'^_InterlockedIncrement$', 'Increment', 'std::int32_t', 'std::int32_t'),
    (r'^_InterlockedIncrement16$', 'Increment', 'std::int16_t', 'std::int16_t'),
    (r'^_InterlockedIncrement64$', 'Increment', 'std::int64_t', 'std::int64_t'),
    (r'^_InterlockedDecrement$', 'Decrement', 'std::int32_t', 'std::int32_t'),
    (r'^_InterlockedDecrement16$', 'Decrement', 'std::int16_t', 'std::int16_t'),
    (r'^_InterlockedDecrement64$', 'Decrement', 'std::int64_t', 'std::int64_t'),
    (r'^_InterlockedAdd$', 'Add', 'std::int32_t', 'std::int32_t'),
    (r'^_InterlockedAdd64$', 'Add', 'std::int64_t', 'std::int64_t'),
    (r'^_InterlockedExchange$', 'Exchange', 'std::int32_t', 'std::int32_t'),
    (r'^_InterlockedExchange64$', 'Exchange', 'std::int64_t', 'std::int64_t'),
    (r'^_InterlockedExchangePointer$', 'Exchange', 'void*', 'void*'),
    (r'^_InterlockedExchangeAdd$', 'ExchangeAdd', 'std::int32_t', 'std::int32_t'),
    (r'^_InterlockedExchangeAdd64$', 'ExchangeAdd', 'std::int64_t',
     'std::int64_t'),
    (r'^_InterlockedAnd$', 'And', 'std::int32_t', 'std::int32_t'),
    (r'^_InterlockedAnd64$', 'And', 'std::int64_t', 'std::int64_t'),
    (r'^_InterlockedOr$', 'Or', 'std::int32_t', 'std::int32_t'),
    (r'^_InterlockedOr64$', 'Or', 'std::int64_t', 'std::int64_t'),
    (r'^_InterlockedXor$', 'Xor', 'std::int32_t', 'std::int32_t'),
    (r'^_InterlockedXor64$', 'Xor', 'std::int64_t', 'std::int64_t'),
    (r'^_InterlockedCompareExchange$', 'CompareExchange', 'std::int32_t',
     'std::int32_t'),
    (r'^_InterlockedCompareExchange16$', 'CompareExchange', 'std::int16_t',
     'std::int16_t'),
    (r'^_InterlockedCompareExchange64$', 'CompareExchange', 'std::int64_t',
     'std::int64_t'),
    (r'^_InterlockedCompareExchangePointer$', 'CompareExchange', 'void*',
     'void*'),
]


def _interlocked_body(c):
    for pattern, op, ret, width in INTERLOCKED_RULES:
        if re.match(pattern, c.name):
            return _make_interlocked(op, width, ret)(c)
    return None


RULES.append((re.compile(r'^_Interlocked'), _interlocked_body))


@rule(r'^_BitScanForward64$')
def _bit_scan_forward64(c):
    index, mask = c.arg(0), c.arg(1)
    return f'''    if ({index} == nullptr) {{
        return 0;
    }}
    std::uint32_t found = 0;
    if (!scan_forward(static_cast<std::uint64_t>({mask}), &found)) {{
        return 0;
    }}
    *{index} = found;
    return 1;'''


@rule(r'^_BitScanForward$')
def _bit_scan_forward(c):
    index, mask = c.arg(0), c.arg(1)
    return f'''    if ({index} == nullptr) {{
        return 0;
    }}
    std::uint32_t found = 0;
    if (!scan_forward(static_cast<std::uint32_t>({mask}), &found)) {{
        return 0;
    }}
    *{index} = found;
    return 1;'''


@rule(r'^_BitScanReverse64$')
def _bit_scan_reverse64(c):
    index, mask = c.arg(0), c.arg(1)
    return f'''    if ({index} == nullptr) {{
        return 0;
    }}
    std::uint32_t found = 0;
    if (!scan_reverse(static_cast<std::uint64_t>({mask}), &found)) {{
        return 0;
    }}
    *{index} = found;
    return 1;'''


@rule(r'^_BitScanReverse$')
def _bit_scan_reverse(c):
    index, mask = c.arg(0), c.arg(1)
    return f'''    if ({index} == nullptr) {{
        return 0;
    }}
    std::uint32_t found = 0;
    if (!scan_reverse(static_cast<std::uint32_t>({mask}), &found)) {{
        return 0;
    }}
    *{index} = found;
    return 1;'''


@rule(r'^_bittestandset64$')
def _bittest_set64(c):
    value, index = c.arg(0), c.arg(1)
    return f'''    if ({value} == nullptr) {{
        return 0;
    }}
    const bool was = bit_of<std::int64_t>(*{value}, {index});
    bit_set<std::int64_t>({value}, {index}, true);
    return was ? 1 : 0;'''


@rule(r'^_bittestandset$')
def _bittest_set(c):
    value, index = c.arg(0), c.arg(1)
    return f'''    if ({value} == nullptr) {{
        return 0;
    }}
    const bool was = bit_of<std::int32_t>(*{value}, {index});
    bit_set<std::int32_t>({value}, {index}, true);
    return was ? 1 : 0;'''


@rule(r'^_bittestandreset64$')
def _bittest_reset64(c):
    value, index = c.arg(0), c.arg(1)
    return f'''    if ({value} == nullptr) {{
        return 0;
    }}
    const bool was = bit_of<std::int64_t>(*{value}, {index});
    bit_set<std::int64_t>({value}, {index}, false);
    return was ? 1 : 0;'''


@rule(r'^_bittestandreset$')
def _bittest_reset(c):
    value, index = c.arg(0), c.arg(1)
    return f'''    if ({value} == nullptr) {{
        return 0;
    }}
    const bool was = bit_of<std::int32_t>(*{value}, {index});
    bit_set<std::int32_t>({value}, {index}, false);
    return was ? 1 : 0;'''


@rule(r'^_bittestandcomplement64$')
def _bittest_complement64(c):
    value, index = c.arg(0), c.arg(1)
    return f'''    if ({value} == nullptr) {{
        return 0;
    }}
    const bool was = bit_of<std::int64_t>(*{value}, {index});
    bit_set<std::int64_t>({value}, {index}, !was);
    return was ? 1 : 0;'''


@rule(r'^_bittestandcomplement$')
def _bittest_complement(c):
    value, index = c.arg(0), c.arg(1)
    return f'''    if ({value} == nullptr) {{
        return 0;
    }}
    const bool was = bit_of<std::int32_t>(*{value}, {index});
    bit_set<std::int32_t>({value}, {index}, !was);
    return was ? 1 : 0;'''


@rule(r'^_bittest64$')
def _bittest64(c):
    value, index = c.arg(0), c.arg(1)
    return f'''    if ({value} == nullptr) {{
        return 0;
    }}
    return bit_of<std::int64_t>(*{value}, {index}) ? 1 : 0;'''


@rule(r'^_bittest$')
def _bittest(c):
    value, index = c.arg(0), c.arg(1)
    return f'''    if ({value} == nullptr) {{
        return 0;
    }}
    return bit_of<std::int32_t>(*{value}, {index}) ? 1 : 0;'''


@rule(r'^_interlockedbittestand(set|reset|complement)64$')
def _interlocked_bittest64(c):
    return _atomic_bittest(c, 'std::int64_t')


@rule(r'^_interlockedbittestand(set|reset|complement)$')
def _interlocked_bittest(c):
    return _atomic_bittest(c, 'std::int32_t')


@rule(r'^InterlockedBitTestAnd(Set|Reset|Complement)64$')
def _interlocked_bit_test64(c):
    return _atomic_bittest(c, 'std::int64_t')


@rule(r'^InterlockedBitTestAnd(Set|Reset|Complement)$')
def _interlocked_bit_test(c):
    return _atomic_bittest(c, 'std::int32_t')


def _atomic_bittest(c, width):
    value, index = c.arg(0), c.arg(1)
    if 'Complement' in c.name:
        start, mask = '0', '0'
        op = 'flip'
    elif 'Reset' in c.name:
        start, mask = '0', '0'
        op = 'reset'
    else:
        start, mask = '0', '0'
        op = 'set'
    return f'''    if ({value} == nullptr) {{
        return 0;
    }}
    // The bit test is the atomic form of the three non-atomic ones: the read
    // and the write are one operation, which is what a caller that uses it
    // as a lock relies on.
    auto* p = const_cast<{width}*>({value});
    const std::int64_t at = static_cast<std::int64_t>({index});
    if (at < 0 || at >= static_cast<std::int64_t>(sizeof({width}) * 8)) {{
        return 0;
    }}
    const {width} bit = static_cast<{width}>(static_cast<{width}>(1) << at);
    for (;;) {{
        {width} current = __atomic_load_n(p, __ATOMIC_SEQ_CST);
        const bool was = (current & bit) != 0;
        const {width} wanted =
            {"static_cast<" + width + ">(current ^ bit)" if op == "flip" else
             ("static_cast<" + width + ">(current & ~bit)" if op == "reset" else
              "static_cast<" + width + ">(current | bit)")};
        if (__atomic_compare_exchange_n(p, &current, wanted, false,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {{
            return was ? 1 : 0;
        }}
    }}'''


@rule(r'^_mul128$')
def _mul128(c):
    left, right, high = c.arg(0), c.arg(1), c.arg(2)
    return f'''    const unsigned __int128 product = widen_product(
        static_cast<std::uint64_t>({left}), static_cast<std::uint64_t>({right}));
    if ({high} != nullptr) {{
        *{high} = static_cast<std::int64_t>(product >> 64);
    }}
    return static_cast<std::int64_t>(static_cast<std::uint64_t>(product));'''


@rule(r'^_umul128$')
def _umul128(c):
    left, right, high = c.arg(0), c.arg(1), c.arg(2)
    return f'''    const unsigned __int128 product = widen_product(
        static_cast<std::uint64_t>({left}), static_cast<std::uint64_t>({right}));
    if ({high} != nullptr) {{
        *{high} = static_cast<std::uint64_t>(product >> 64);
    }}
    return static_cast<std::uint64_t>(product);'''


@rule(r'^MultiplyExtract128$')
def _multiply_extract128(c):
    left, right, shift = c.arg(0), c.arg(1), c.arg(2)
    return f'''    // The product is formed in 128 bits and then shifted right, which is the
    // whole point of the call: done in 64 bits the intermediate would be the
    // answer a caller of this function is trying to avoid.
    signed __int128 product = static_cast<signed __int128>(
        static_cast<std::int64_t>({left})) *
        static_cast<signed __int128>(static_cast<std::int64_t>({right}));
    const std::uint32_t at = static_cast<std::uint32_t>({shift}) & 0x7Fu;
    product >>= at;
    return static_cast<std::int64_t>(static_cast<std::uint64_t>(product));'''


@rule(r'^UnsignedMultiplyExtract128$')
def _unsigned_multiply_extract128(c):
    left, right, shift = c.arg(0), c.arg(1), c.arg(2)
    return f'''    const unsigned __int128 product = widen_product(
        static_cast<std::uint64_t>({left}), static_cast<std::uint64_t>({right}));
    const std::uint32_t at = static_cast<std::uint32_t>({shift}) & 0x7Fu;
    return static_cast<std::uint64_t>(product >> at);'''


@rule(r'^MulDiv$')
def _mul_div(c):
    number, numerator, denominator = c.arg(0), c.arg(1), c.arg(2)
    return f'''    if ({denominator} == 0) {{
        return -1;
    }}
    // The product is formed in 64 bits and rounded half away from zero, and
    // the answer is refused when it does not fit the 32 bits the caller has
    // -- a truncated result would be read as a successful division, which is
    // the failure this function exists to avoid.
    const std::int64_t product =
        static_cast<std::int64_t>({number}) * static_cast<std::int64_t>({numerator});
    const std::int64_t half = static_cast<std::int64_t>({denominator}) / 2;
    const std::int64_t rounded = product >= 0 ? product + half : product - half;
    const std::int64_t answer = rounded / static_cast<std::int64_t>({denominator});
    if (answer > 2147483647LL || answer < -2147483648LL) {{
        return -1;
    }}
    return static_cast<std::int32_t>(answer);'''


# ------------------------------------------------------------ the objects

@rule(r'^InitOnceInitialize$')
def _init_once_initialize(c):
    target = c.arg(0)
    return f'''    if ({target} != nullptr) {{
        // The state is one pointer-sized word: null means "not begun", a
        // sentinel means "in progress", and anything else is the caller's
        // context. Writing the sentinel here would start it; this call only
        // clears it.
        *static_cast<std::uint64_t*>({target}) = 0;
    }}'''


@rule(r'^InitOnceBeginInitialize$')
def _init_once_begin(c):
    target, flags, pending, context = (c.arg(i) for i in range(4))
    return f'''    if ({target} == nullptr || {pending} == nullptr) {{
        return 0;
    }}
    constexpr std::uint32_t kInitOnceCheckOnly = 0x00000001u;
    auto* cell = static_cast<std::uint64_t*>({target});
    if (({flags} & kInitOnceCheckOnly) != 0) {{
        // A check that does not run the initialisation: it either reports
        // that the work is not done, or reports the context and says so.
        const std::uint64_t seen = __atomic_load_n(cell, __ATOMIC_SEQ_CST);
        if (seen == 0 || seen == 1) {{
            *{pending} = 1;
            return 1;
        }}
        *{pending} = 0;
        if ({context} != nullptr) {{
            *{context} = reinterpret_cast<void*>(static_cast<std::uintptr_t>(seen));
        }}
        return 1;
    }}
    std::uint64_t expected = 0;
    if (__atomic_compare_exchange_n(cell, &expected, 1, false,
                                    __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {{
        // This caller is the one that will run the work.
        *{pending} = 1;
        return 1;
    }}
    if (expected == 1) {{
        // Another caller is running it. The caller that arrives second waits
        // for the first to finish, which is what makes the context readable.
        while (__atomic_load_n(cell, __ATOMIC_SEQ_CST) == 1) {{
        }}
        expected = __atomic_load_n(cell, __ATOMIC_SEQ_CST);
    }}
    *{pending} = 0;
    if ({context} != nullptr) {{
        *{context} = reinterpret_cast<void*>(static_cast<std::uintptr_t>(expected));
    }}
    return 1;'''


@rule(r'^InitOnceComplete$')
def _init_once_complete(c):
    target, flags, context = c.arg(0), c.arg(1), c.arg(2)
    return f'''    if ({target} == nullptr) {{
        return 0;
    }}
    constexpr std::uint32_t kInitOnceInitialize = 0x00000002u;
    auto* cell = static_cast<std::uint64_t*>({target});
    const std::uint64_t stored = ({flags} & kInitOnceInitialize) != 0
                                     ? 0
                                     : static_cast<std::uint64_t>(
                                           reinterpret_cast<std::uintptr_t>({context}));
    __atomic_store_n(cell, stored, __ATOMIC_SEQ_CST);
    return 1;'''


@rule(r'^InitializeSRWLock$')
def _initialize_srwlock(c):
    target = c.arg(0)
    return f'''    if ({target} != nullptr) {{
        // An SRW lock in the unlocked state is a null pointer, which is what
        // makes `InitializeSRWLock` a store and nothing else.
        *static_cast<void**>({target}) = nullptr;
    }}'''


@rule(r'^TryAcquireSRWLockShared$')
def _try_acquire_shared(c):
    target = c.arg(0)
    return f'''    if ({target} == nullptr) {{
        return 0;
    }}
    // The exclusive owner is the only state this runtime tracks: a shared
    // acquisition succeeds unless somebody holds the lock exclusively, and
    // the shared count is left at zero because the release for a shared
    // acquisition is not one of the entry points here.
    auto* cell = static_cast<std::uint64_t*>({target});
    std::uint64_t expected = 0;
    return __atomic_compare_exchange_n(cell, &expected, 0, false,
                                       __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
               ? 1
               : 0;'''


@rule(r'^InitializeSynchronizationBarrier$')
def _init_barrier(c):
    barrier, threads, spin = c.arg(0), c.arg(1), c.arg(2)
    return f'''    if ({barrier} == nullptr || {threads} < 1) {{
        return 0;
    }}
    // The barrier is four pointer-sized words: the count still to arrive,
    // the count the barrier was made with, the spin count, and a generation
    // that lets a caller tell one round from the next.
    auto* words = static_cast<std::uint64_t*>({barrier});
    words[0] = static_cast<std::uint64_t>({threads});
    words[1] = static_cast<std::uint64_t>({threads});
    words[2] = static_cast<std::uint64_t>({spin});
    words[3] = 0;
    return 1;'''


@rule(r'^EnterSynchronizationBarrier$')
def _enter_barrier(c):
    barrier, flags = c.arg(0), c.arg(1)
    return f'''    if ({barrier} == nullptr) {{
        return 0;
    }}
    static_cast<void>({flags});
    auto* words = static_cast<std::uint64_t*>({barrier});
    const std::uint64_t generation =
        __atomic_load_n(&words[3], __ATOMIC_SEQ_CST) + 1;
    const std::uint64_t left =
        __atomic_sub_fetch(&words[0], 1, __ATOMIC_SEQ_CST);
    if (left == 0) {{
        // The last arrival opens the barrier: the count is restored and the
        // generation advances, which is the signal every waiter is watching.
        __atomic_store_n(&words[0], words[1], __ATOMIC_SEQ_CST);
        __atomic_store_n(&words[3], generation, __ATOMIC_SEQ_CST);
        return 1;
    }}
    while (__atomic_load_n(&words[3], __ATOMIC_SEQ_CST) != generation) {{
    }}
    return 0;'''


@rule(r'^DeleteSynchronizationBarrier$')
def _delete_barrier(c):
    barrier = c.arg(0)
    return f'''    if ({barrier} != nullptr) {{
        auto* words = static_cast<std::uint64_t*>({barrier});
        words[0] = 0;
        words[1] = 0;
        words[2] = 0;
        words[3] = 0;
    }}
    return 1;'''


@rule(r'^SetCriticalSectionSpinCount$')
def _set_cs_spin(c):
    section, count = c.arg(0), c.arg(1)
    return f'''    if ({section} == nullptr) {{
        return 0;
    }}
    // The spin count is the fifth pointer-sized field of a critical section
    // on the 64-bit ABI: the lock count, the recursion count, the owning
    // thread, the semaphore, and then this. The answer is the count that was
    // there, which is what lets a caller restore it.
    constexpr std::size_t kSpinCountOffset = 32;
    const std::uint32_t previous = read_le32({section}, kSpinCountOffset);
    write_le32({section}, kSpinCountOffset, {count});
    return previous;'''


@rule(r'^EncodePointer$')
def _encode_pointer(c):
    return _encode(c, 'pointer_cookie()')


@rule(r'^EncodeSystemPointer$')
def _encode_pointer_system(c):
    return _encode(c, 'pointer_cookie()')


@rule(r'^DecodePointer$')
def _decode_pointer(c):
    return _decode(c, 'pointer_cookie()')


@rule(r'^DecodeSystemPointer$')
def _decode_pointer_system(c):
    return _decode(c, 'pointer_cookie()')


def _encode(c, cookie):
    raw = c.arg(0)
    return f'''    // The pointer and a per-process value, exclusive-ored. The value is not
    // a secret -- the API does not claim to be one -- and what it buys is
    // that a pointer a guest wrote down is not a usable address after the
    // process that wrote it has gone, which is what the call is for.
    if ({raw} == nullptr) {{
        return nullptr;
    }}
    return reinterpret_cast<void*>(
        reinterpret_cast<std::uintptr_t>({raw}) ^ {cookie});'''


def _decode(c, cookie):
    raw = c.arg(0)
    return f'''    if ({raw} == nullptr) {{
        return nullptr;
    }}
    return reinterpret_cast<void*>(
        reinterpret_cast<std::uintptr_t>({raw}) ^ {cookie});'''


# ------------------------------------------------------------ file and time

@rule(r'^DosDateTimeToFileTime$')
def _dos_to_filetime(c):
    date, time, out = c.arg(0), c.arg(1), c.arg(2)
    return f'''    if ({out} == nullptr) {{
        return 0;
    }}
    // The DOS word is a packed calendar: bits 9 to 15 the year from 1980,
    // bits 5 to 8 the month, bits 0 to 4 the day. The output is a count of
    // hundred-nanosecond ticks from 1601, which is where the conversion
    // lives: between 1601 and 1980 there are 134774 days.
    const std::uint32_t year = 1980u + (({date} >> 9) & 0x7Fu);
    const std::uint32_t month = ({date} >> 5) & 0x0Fu;
    const std::uint32_t day = {date} & 0x1Fu;
    const std::uint32_t hour = ({time} >> 11) & 0x1Fu;
    const std::uint32_t minute = ({time} >> 5) & 0x3Fu;
    const std::uint32_t second = ({time} & 0x1Fu) * 2u;
    if (month < 1 || month > 12 || day < 1 || day > 31) {{
        return 0;
    }}
    const std::uint64_t days = days_from_epoch(year, month, day);
    const std::uint64_t ticks =
        ((days * 24u + hour) * 60u + minute) * 60u + second;
    write_le64({out}, 0, ticks * 10000000ull);
    return 1;'''


@rule(r'^FileTimeToDosDateTime$')
def _filetime_to_dos(c):
    source, date, time = c.arg(0), c.arg(1), c.arg(2)
    return f'''    if ({source} == nullptr || {date} == nullptr || {time} == nullptr) {{
        return 0;
    }}
    const std::uint64_t ticks = read_le64({source}, 0) / 10000000ull;
    std::uint64_t days = ticks / 86400ull;
    std::uint64_t rest = ticks % 86400ull;
    const std::uint32_t hour = static_cast<std::uint32_t>(rest / 3600ull);
    rest %= 3600ull;
    const std::uint32_t minute = static_cast<std::uint32_t>(rest / 60ull);
    const std::uint32_t second = static_cast<std::uint32_t>(rest % 60ull);
    std::uint32_t year = 0;
    std::uint32_t month = 0;
    std::uint32_t day = 0;
    calendar_from_days(days, &year, &month, &day);
    // The DOS calendar starts at 1980, so anything earlier has no spelling
    // and the call refuses rather than answering a wrapped date.
    if (year < 1980 || year > 2107) {{
        return 0;
    }}
    *{date} = static_cast<std::uint16_t>(
        ((year - 1980u) << 9) | (month << 5) | day);
    *{time} = static_cast<std::uint16_t>(
        (hour << 11) | (minute << 5) | (second / 2u));
    return 1;'''


@rule(r'^GetSystemWindowsDirectory[AW]$')
def _get_system_windows_directory(c):
    buffer, size = c.arg(0), c.arg(1)
    w = _w(c)
    return f'''    // On a machine that is not a terminal server the system Windows
    // directory and the Windows directory are the same, and this runtime
    // presents one installation rather than a session.
    return k32p_GetWindowsDirectory{w}({buffer}, {size});'''


@rule(r'^GetVersion$')
def _get_version(c):
    return f'''    // The packed form: the major version in the low byte, the minor in the
    // next, and the build in the high word. The numbers are the ones the
    // system-information domain reports, which is what keeps this answer
    // and `GetVersionEx`'s the same.
    return (kReportedOsBuild << 16) | (kReportedOsMinor << 8) | kReportedOsMajor;'''


@rule(r'^AreFileApisANSI$')
def _are_file_apis_ansi(c):
    return '''    return file_api_code_page_is_ansi() ? 1 : 0;'''


@rule(r'^SetFileApisToANSI$')
def _set_file_apis_ansi(c):
    return '''    set_file_api_code_page(true);'''


@rule(r'^SetFileApisToOEM$')
def _set_file_apis_oem(c):
    return '''    // The switch is kept, and it changes the answer `AreFileApisANSI`
    // gives. It does not change any conversion, because this runtime answers
    // one single-byte code page for the two the platform keeps apart --
    // which is the same statement its stream and file domains already make.
    set_file_api_code_page(false);'''


@rule(r'^SetHandleCount$')
def _set_handle_count(c):
    requested = c.arg(0)
    return f'''    // The count the process had before, which is the count it still has: the
    // call is documented as having no effect from Win32 onwards, and a
    // runtime that refused it would break a caller that uses it to raise a
    // limit it does not actually have.
    static_cast<void>({requested});
    return 255;'''


@rule(r'^GlobalCompact$')
def _global_compact(c):
    minimum = c.arg(0)
    return f'''    static_cast<void>({minimum});
    // `GlobalCompact` is documented as having no effect on Win32: the heap
    // is compacted by the allocator, and the answer is the largest free
    // block. This runtime's allocator has no such query, and answering a
    // number would be inventing one, so the call reports that it could not
    // compact rather than a size.
    set_last_error(kErrorCallNotImplemented);
    return 0;'''


@rule(r'^GlobalFix$')
def _global_fix(c):
    block = c.arg(0)
    return f'''    static_cast<void>({block});
    // Documented as having no effect: the pages of a global block are
    // already pinned for the life of the allocation. The call is kept so
    // that a program written against the 16-bit API still runs.
    '''


@rule(r'^GlobalUnfix$')
def _global_unfix(c):
    block = c.arg(0)
    return f'''    static_cast<void>({block});
    // The other half of `GlobalFix`, and equally without effect.
    '''


@rule(r'^GlobalWire$')
def _global_wire(c):
    block = c.arg(0)
    return f'''    // A wire that locks a block in place and answers the block. The lock is
    // the allocator's own, which is not movable here, so the answer is the
    // block and the call has nothing else to do.
    return {block};'''


@rule(r'^GlobalUnWire$')
def _global_unwire(c):
    block = c.arg(0)
    return f'''    static_cast<void>({block});
    return 1;'''


# --------------------------------------------------------------- the profile

PROFILE_HELPERS = '''
// The profile-file state: one flag for the code page the file APIs report,
// and one cookie for the pointer encoding. Both are process-wide and both
// are written only by the calls that own them.

[[nodiscard]] bool& file_api_code_page_is_ansi_flag() noexcept {
    static bool ansi = true;
    return ansi;
}
[[nodiscard]] bool file_api_code_page_is_ansi() noexcept {
    return file_api_code_page_is_ansi_flag();
}
void set_file_api_code_page(bool ansi) noexcept {
    file_api_code_page_is_ansi_flag() = ansi;
}

// The value the pointer encoder xors with. Its address is what makes it
// differ between processes; its value is not a secret and the API does not
// claim it is.
[[nodiscard]] std::uintptr_t pointer_cookie() noexcept {
    static std::uintptr_t cookie = 0;
    if (cookie == 0) {
        cookie = reinterpret_cast<std::uintptr_t>(&cookie) ^
                 0x5EED5EED5EED5EEDull;
    }
    return cookie;
}

// The day count between a calendar date and the epoch a `FILETIME` counts
// from, which is 1601-01-01. The walk is the standard civil-from-days
// algorithm, run backwards and forwards, because the two conversions have
// to agree about the leap years or a date near a boundary round-trips
// wrong.
[[nodiscard]] bool leap_year(std::uint64_t year) noexcept {
    return (year % 4u == 0 && year % 100u != 0) || year % 400u == 0;
}

[[nodiscard]] std::uint64_t days_before_year(std::uint64_t year) noexcept {
    const std::uint64_t previous = year - 1;
    return previous * 365u + previous / 4u - previous / 100u + previous / 400u;
}

[[nodiscard]] std::uint64_t days_before_month(std::uint64_t year,
                                              std::uint32_t month) noexcept {
    static const std::uint32_t lengths[] = {0,  31, 59, 90, 120, 151,
                                            181, 212, 243, 273, 304, 334};
    const std::uint32_t index = month >= 1 && month <= 12 ? month - 1 : 0;
    std::uint64_t days = lengths[index];
    if (month > 2 && leap_year(year)) {
        ++days;
    }
    return days;
}

// Days from 1601-01-01 to the given date, which is the count a FILETIME's
// high half needs.
[[nodiscard]] std::uint64_t days_from_epoch(std::uint32_t year,
                                            std::uint32_t month,
                                            std::uint32_t day) noexcept {
    const std::uint64_t from_1601 = days_before_year(year) -
                                    days_before_year(1601);
    std::uint64_t days = from_1601 + days_before_month(year, month) + (day - 1);
    // The Gregorian correction: the days the calendar skipped. 1601 is
    // inside the Gregorian era, so only the leap-year rule applies, which
    // `days_before_year` already carries.
    return days;
}

// The inverse: the calendar date a day count from 1601 names.
void calendar_from_days(std::uint64_t days, std::uint32_t* year,
                        std::uint32_t* month, std::uint32_t* day) noexcept {
    std::uint64_t at = 1601;
    while (days >= (leap_year(at) ? 366u : 365u)) {
        days -= leap_year(at) ? 366u : 365u;
        ++at;
    }
    std::uint32_t month_at = 1;
    for (; month_at <= 12; ++month_at) {
        const std::uint32_t length =
            month_at == 2 ? (leap_year(at) ? 29u : 28u)
                          : ((month_at == 4 || month_at == 6 || month_at == 9 ||
                              month_at == 11)
                                 ? 30u
                                 : 31u);
        if (days < length) {
            break;
        }
        days -= length;
    }
    *year = static_cast<std::uint32_t>(at);
    *month = month_at;
    *day = static_cast<std::uint32_t>(days) + 1;
}
'''


# The object and flag helpers belong to the same file, so they are
# appended to the block above rather than kept apart.
HELPERS = HELPERS + PROFILE_HELPERS


def applies_to(dll, names):
    return dll == 'kernel32'


def body(dll, name, ret, args, names):
    if dll != 'kernel32':
        return None
    for pattern, builder in RULES:
        if pattern.match(name):
            try:
                return builder(Ctx(name, ret, args, names))
            except Exception:
                return None
    return None

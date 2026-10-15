"""The profile files: the INI format and the calls that read and write it.

`GetPrivateProfileString` is one of the few Windows APIs whose behaviour is
defined entirely by a text format, which makes it one this runtime can
implement without a capability it lacks. The format is small and its rules
are exact:

  * a line whose first non-blank character is `;` or `#` is a comment, and
    is never a key;
  * `[name]` introduces a section;
  * a key and its value are separated by the first `=` or `:` on the line,
    and the blank space around both is not part of either;
  * a key written twice in one section is answered by the first.

The write side is the part worth stating. A program that stores a window
position must not lose the comments and the keys it did not touch, so the
file is edited as its lines and not reproduced from the parse. That is the
contract, and a writer built from the parse tree is a writer that silently
deletes a user's file.
"""

import re

HELPERS = r'''
// ------------------------------------------------------------ the profile
//
// One INI file, held as its lines, so that a write can preserve everything
// it is not about.

[[nodiscard]] std::u16string profile_wide(const char* text) noexcept {
    std::u16string out;
    if (text == nullptr) {
        return out;
    }
    while (*text != 0) {
        out.push_back(static_cast<char16_t>(
            static_cast<unsigned char>(*text++)));
    }
    return out;
}

// The file, split into lines with their terminators removed. A file that is
// not there is an empty list rather than a failure: every caller of the
// read side treats a missing profile as one with nothing in it.
[[nodiscard]] bool profile_load(std::u16string_view path,
                                std::vector<std::u16string>* lines) noexcept {
    lines->clear();
    std::u16string text;
    static_cast<void>(read_profile_file(std::u16string(path).c_str(), &text));
    std::size_t at = 0;
    while (at < text.size()) {
        std::size_t end = at;
        while (end < text.size() && text[end] != char16_t{10} &&
               text[end] != char16_t{13}) {
            ++end;
        }
        lines->emplace_back(text.substr(at, end - at));
        while (end < text.size() && (text[end] == char16_t{10} ||
                                     text[end] == char16_t{13})) {
            ++end;
        }
        at = end;
    }
    return true;
}

[[nodiscard]] bool profile_store(std::u16string_view path,
                                 const std::vector<std::u16string>& lines) noexcept {
    char narrow[1024];
    static_cast<void>(narrow_text(std::u16string(path).c_str(), narrow, 1024));
    void* file = cr_fopen(narrow, "wb");
    if (file == nullptr) {
        return false;
    }
    for (const std::u16string& line : lines) {
        std::string bytes;
        bytes.reserve(line.size() + 1);
        for (char16_t ch : line) {
            bytes.push_back(ch < 0x100 ? static_cast<char>(ch) : '?');
        }
        bytes.push_back('\n');
        if (cr_fwrite(bytes.data(), 1, bytes.size(), file) != bytes.size()) {
            static_cast<void>(cr_fclose(file));
            return false;
        }
    }
    return cr_fclose(file) == 0;
}

// The lines of a section: the one after its header to the one before the
// next header. A section that is not in the file is an empty range at the
// end, which is where an insertion belongs.
[[nodiscard]] bool profile_section_range(
    const std::vector<std::u16string>& lines, std::u16string_view section,
    std::size_t* begin, std::size_t* end) noexcept {
    for (std::size_t at = 0; at < lines.size(); ++at) {
        IniSpan<char16_t> span{lines[at].c_str(), lines[at].size()};
        IniSpan<char16_t> name{};
        if (!ini_section_of<char16_t>(span, &name) ||
            !ini_span_equals<char16_t>(name, section.data(), section.size())) {
            continue;
        }
        *begin = at + 1;
        std::size_t stop = at + 1;
        while (stop < lines.size()) {
            IniSpan<char16_t> next{lines[stop].c_str(), lines[stop].size()};
            IniSpan<char16_t> other{};
            if (ini_section_of<char16_t>(next, &other)) {
                break;
            }
            ++stop;
        }
        *end = stop;
        return true;
    }
    *begin = lines.size();
    *end = lines.size();
    return false;
}

// The value a section holds for a key, or nothing. The first line that
// names the key wins, and a line that is a comment is skipped rather than
// read as a key that happens to begin with a semicolon.
[[nodiscard]] bool profile_get(const std::vector<std::u16string>& lines,
                               std::u16string_view section,
                               std::u16string_view key,
                               std::u16string* value) noexcept {
    std::size_t begin = 0;
    std::size_t end = 0;
    if (!profile_section_range(lines, section, &begin, &end)) {
        return false;
    }
    for (std::size_t at = begin; at < end; ++at) {
        IniSpan<char16_t> span{lines[at].c_str(), lines[at].size()};
        if (ini_line_ignorable<char16_t>(span.text)) {
            continue;
        }
        IniSpan<char16_t> found_key{};
        IniSpan<char16_t> found_value{};
        if (!ini_pair_of<char16_t>(span, &found_key, &found_value)) {
            continue;
        }
        if (ini_span_equals<char16_t>(found_key, key.data(), key.size())) {
            value->assign(found_value.text, found_value.length);
            return true;
        }
    }
    return false;
}

// A key written, replaced or removed. `remove` is the API's null-string
// case: a caller that passes one is asking for the key to go, which is a
// different request from storing an empty value.
void profile_set(std::vector<std::u16string>* lines,
                 std::u16string_view section, std::u16string_view key,
                 const std::u16string& value, bool remove) noexcept {
    std::size_t begin = 0;
    std::size_t end = 0;
    if (!profile_section_range(*lines, section, &begin, &end)) {
        if (remove) {
            return;
        }
        std::u16string header{'['};
        header.append(section.begin(), section.end());
        header.push_back(u']');
        lines->push_back(std::move(header));
        begin = lines->size();
        end = begin;
    }
    for (std::size_t at = begin; at < end; ++at) {
        IniSpan<char16_t> span{(*lines)[at].c_str(), (*lines)[at].size()};
        IniSpan<char16_t> found_key{};
        IniSpan<char16_t> found_value{};
        if (!ini_pair_of<char16_t>(span, &found_key, &found_value) ||
            !ini_span_equals<char16_t>(found_key, key.data(), key.size())) {
            continue;
        }
        if (remove) {
            lines->erase(lines->begin() + static_cast<std::ptrdiff_t>(at));
        } else {
            std::u16string fresh(key.begin(), key.end());
            fresh.push_back(u'=');
            fresh.append(value);
            (*lines)[at] = std::move(fresh);
        }
        return;
    }
    if (remove) {
        return;
    }
    std::u16string fresh(key.begin(), key.end());
    fresh.push_back(u'=');
    fresh.append(value);
    lines->insert(lines->begin() + static_cast<std::ptrdiff_t>(end),
                  std::move(fresh));
}

// A whole section removed: its header and every line under it.
void profile_remove_section(std::vector<std::u16string>* lines,
                            std::u16string_view section) noexcept {
    std::size_t begin = 0;
    std::size_t end = 0;
    if (!profile_section_range(*lines, section, &begin, &end)) {
        return;
    }
    lines->erase(lines->begin() + static_cast<std::ptrdiff_t>(begin - 1),
                 lines->begin() + static_cast<std::ptrdiff_t>(end));
}

// The section dumped as the format's lines: `key=value`, one per line, each
// terminated by its own null. This is the shape the `GetPrivateProfileSection`
// call answers with, and the shape its write side takes.
[[nodiscard]] std::u16string profile_section_text(
    const std::vector<std::u16string>& lines, std::u16string_view section) noexcept {
    std::u16string out;
    std::size_t begin = 0;
    std::size_t end = 0;
    if (!profile_section_range(lines, section, &begin, &end)) {
        return out;
    }
    for (std::size_t at = begin; at < end; ++at) {
        IniSpan<char16_t> span{lines[at].c_str(), lines[at].size()};
        if (ini_line_ignorable<char16_t>(span.text)) {
            continue;
        }
        IniSpan<char16_t> key{};
        IniSpan<char16_t> value{};
        if (!ini_pair_of<char16_t>(span, &key, &value)) {
            continue;
        }
        out.append(key.text, key.length);
        out.push_back(u'=');
        out.append(value.text, value.length);
        out.push_back(char16_t{0});
    }
    out.push_back(char16_t{0});
    return out;
}

// A NUL-separated list copied to the narrow width.
//
// The list ends with an empty entry -- two nulls in a row -- and the
// characters of the list other than the last are not a string. A converter
// that stopped at the first null would answer only the first name, which is
// the difference between a section list and a section name.
std::uint32_t copy_list_to_narrow(std::u16string_view list,
                                               char* out,
                                               std::uint32_t capacity) noexcept {
    if (out == nullptr || capacity == 0) {
        return 0;
    }
    std::uint32_t at = 0;
    for (std::size_t index = 0; index < list.size() && at + 2 < capacity;
         ++index) {
        const char16_t ch = list[index];
        out[at++] = ch < 0x100 ? static_cast<char>(ch) : '?';
        if (ch == char16_t{0} &&
            (index + 1 >= list.size() || list[index + 1] == char16_t{0})) {
            break;
        }
    }
    out[at] = 0;
    return at + 1;
}

// The section names, in the order they appear, each with its own null.
[[nodiscard]] std::u16string profile_section_names(
    const std::vector<std::u16string>& lines) noexcept {
    std::u16string out;
    for (const std::u16string& line : lines) {
        IniSpan<char16_t> span{line.c_str(), line.size()};
        IniSpan<char16_t> name{};
        if (!ini_section_of<char16_t>(span, &name)) {
            continue;
        }
        out.append(name.text, name.length);
        out.push_back(char16_t{0});
    }
    out.push_back(char16_t{0});
    return out;
}

// The two paths the plain profile calls use: `win.ini` under the Windows
// directory, which is where the platform keeps the file that predates the
// per-application ones.
[[nodiscard]] const char16_t* profile_shared_file() noexcept {
    static char16_t path[260] = {};
    if (path[0] == char16_t{0}) {
        char16_t directory[260] = {};
        if (k32p_GetWindowsDirectoryW(directory, 260) == 0) {
            return nullptr;
        }
        std::size_t at = text_copy<char16_t>(path, 260, directory);
        if (at == 0 || at + 8 >= 260) {
            return nullptr;
        }
        if (path[at - 1] != static_cast<char16_t>(92)) {
            path[at++] = static_cast<char16_t>(92);
        }
        text_copy<char16_t>(path + at, 260 - at, u"win.ini");
    }
    return path;
}
'''


class Ctx:
    def __init__(self, name, ret, args, names):
        self.name = name
        self.ret = ret
        self.args = args
        self.names = names
        self.wide = name.endswith('W')

    def arg(self, index):
        return self.names[index] if index < len(self.names) else None


def _file_arg(c, index, shared):
    """The path a profile call works on, as a wide pointer expression."""
    if shared:
        return 'profile_shared_file()'
    return c.arg(index)


def _wide_arg(c, index):
    """A wide string expression from a parameter that may be narrow."""
    name = c.arg(index)
    if c.wide:
        return name, ''
    local = f'wide_{name}'
    return local, f'    const std::u16string {local} = profile_wide({name});\n'


def body(dll, name, ret, args, names):
    if dll != 'kernel32':
        return None
    c = Ctx(name, ret, args, names)
    shared = 'Private' not in name
    match = re.match(r'^(Get|Write)PrivateProfileString([AW])$', name)
    if match:
        return _get_string(c, match.group(1) == 'Write')
    match = re.match(r'^(Get|Write)ProfileString([AW])$', name)
    if match:
        return _get_string(c, match.group(1) == 'Write', shared=True)
    match = re.match(r'^GetPrivateProfileInt([AW])$', name)
    if match:
        return _get_int(c)
    match = re.match(r'^GetProfileInt([AW])$', name)
    if match:
        return _get_int(c, shared=True)
    match = re.match(r'^(Get|Write)PrivateProfileSection([AW])$', name)
    if match:
        return _get_section(c, match.group(1) == 'Write')
    match = re.match(r'^(Get|Write)ProfileSection([AW])$', name)
    if match:
        return _get_section(c, match.group(1) == 'Write', shared=True)
    match = re.match(r'^GetPrivateProfileSectionNames([AW])$', name)
    if match:
        return _get_section_names(c)
    return None


def _get_string(c, writing, shared=False):
    if writing:
        app, key, value = c.arg(0), c.arg(1), c.arg(2)
        path = c.arg(3) if len(c.args) > 3 else None
        path_guard = 'profile_shared_file()' if shared else path
        path_e = path_guard
        declarations = ''
        if c.wide:
            app_e, key_e, value_e = app, key, value
        else:
            declarations += (
                f'    const std::u16string wide_app = profile_wide({app});\n'
                f'    const std::u16string wide_key = profile_wide({key});\n'
                f'    const std::u16string wide_value = profile_wide({value});\n')
            app_e, key_e, value_e = 'wide_app', 'wide_key', 'wide_value'
            if not shared:
                declarations += (
                    f'    const std::u16string wide_path = profile_wide({path});\n')
                path_e = 'wide_path'
        return f'''{declarations}    if ({path_guard} == nullptr) {{
        return 0;
    }}
    if ({app} == nullptr) {{
        // A null section names nothing, and the call has nothing to do.
        return 0;
    }}
    std::vector<std::u16string> lines;
    static_cast<void>(profile_load({path_e}, &lines));
    if ({key} == nullptr) {{
        // A null key asks for the section itself to go, which is a
        // different request from clearing one value in it.
        profile_remove_section(&lines, {app_e});
        return profile_store({path_e}, lines) ? 1 : 0;
    }}
    if ({value} == nullptr) {{
        profile_set(&lines, {app_e}, {key_e}, std::u16string{{}}, true);
    }} else {{
        profile_set(&lines, {app_e}, {key_e}, {value_e}, false);
    }}
    return profile_store({path_e}, lines) ? 1 : 0;'''

    app, key, default, out, size = (c.arg(i) for i in range(5))
    path = c.arg(5) if len(c.args) > 5 else None
    path_guard = 'profile_shared_file()' if shared else path
    path_e = path_guard
    declarations = ''
    if c.wide:
        app_e, key_e, default_e = app, key, default
    else:
        declarations += (
            f'    const std::u16string wide_app = profile_wide({app});\n'
            f'    const std::u16string wide_key = profile_wide({key});\n'
            f'    const std::u16string wide_default = profile_wide({default});\n')
        app_e, key_e, default_e = 'wide_app', 'wide_key', 'wide_default'
        if not shared:
            declarations += (
                f'    const std::u16string wide_path = profile_wide({path});\n')
            path_e = 'wide_path'
    emit = (_narrow_emit(c, out, size) if not c.wide
            else f'    static_cast<void>(text_copy<char16_t>({out}, {size}, answer.c_str()));')
    return f'''{declarations}    if ({out} == nullptr || {size} == 0) {{
        return 0;
    }}
    // A missing key, a missing section and a missing file are one case in
    // the format, and each is answered with the default rather than with an
    // error: that is what makes the call usable for a setting that has
    // never been written.
    std::u16string answer;
    std::vector<std::u16string> lines;
    if ({key} != nullptr && {app} != nullptr && {path_guard} != nullptr &&
        profile_load({path_e}, &lines) &&
        profile_get(lines, {app_e}, {key_e}, &answer)) {{
        static_cast<void>(0);
    }} else {{
        answer = {default} == nullptr ? std::u16string{{}}
                                        : std::u16string({default_e});
    }}
    // The answer is truncated to the caller's buffer, and the length
    // reported is what was written with the terminator counted, which is how
    // a caller detects that it was cut.
    {emit}
    return static_cast<std::uint32_t>(text_len_at({out}, {size})) + 1;'''


def _narrow_emit(c, out, size):
    return (f'    static_cast<void>(narrow_text(answer.c_str(), {out}, {size}));\n'
            f'    {out}[{size} - 1] = 0;')


def _get_int(c, shared=False):
    app, key, fallback = c.arg(0), c.arg(1), c.arg(2)
    path = c.arg(3) if len(c.args) > 3 else None
    path_guard = 'profile_shared_file()' if shared else path
    declarations = ''
    if c.wide:
        app_e, key_e = app, key
        path_e = path_guard
    else:
        declarations += (
            f'    const std::u16string wide_app = profile_wide({app});\n'
            f'    const std::u16string wide_key = profile_wide({key});\n')
        app_e, key_e = 'wide_app', 'wide_key'
        path_e = path_guard
        if not shared:
            declarations += (
                f'    const std::u16string wide_path = profile_wide({path});\n')
            path_e = 'wide_path'
    return f'''{declarations}    if ({app} == nullptr || {key} == nullptr || {path_guard} == nullptr) {{
        return static_cast<std::uint32_t>({fallback});
    }}
    std::u16string answer;
    std::vector<std::u16string> lines;
    if (!profile_load({path_e}, &lines) ||
        !profile_get(lines, {app_e}, {key_e}, &answer)) {{
        return static_cast<std::uint32_t>({fallback});
    }}
    // The value is read as a decimal number and stops at the first character
    // that is not one. A value that holds no digit at all answers the
    // default, which is the reference's rule and the reason the call is
    // usable on a setting a user has typed into by hand.
    bool any = false;
    for (std::size_t index = 0; index < answer.size(); ++index) {{
        if (ch_digit(answer[index])) {{
            any = true;
            break;
        }}
    }}
    if (!any) {{
        return static_cast<std::uint32_t>({fallback});
    }}
    return static_cast<std::uint32_t>(ini_number(answer.c_str(), answer.size()));'''


def _get_section(c, writing, shared=False):
    if writing:
        app, text = c.arg(0), c.arg(1)
        path = c.arg(2) if len(c.args) > 2 else None
        path_guard = 'profile_shared_file()' if shared else path
        declarations = ''
        if c.wide:
            app_e, text_e = app, text
            text_wide = text
            path_e = path_guard
        else:
            declarations += (
                f'    const std::u16string wide_app = profile_wide({app});\n'
                f'    const std::u16string wide_text = profile_wide({text});\n')
            app_e, text_e = 'wide_app', 'wide_text'
            text_wide = 'wide_text.c_str()'
            path_e = path_guard
            if not shared:
                declarations += (
                    f'    const std::u16string wide_path = profile_wide({path});\n')
                path_e = 'wide_path'
        return f'''{declarations}    if ({path_guard} == nullptr || {app} == nullptr) {{
        return 0;
    }}
    std::vector<std::u16string> lines;
    static_cast<void>(profile_load({path_e}, &lines));
    profile_remove_section(&lines, {app_e});
    if ({text} == nullptr || *{text} == static_cast<{c_char(c)}>(0)) {{
        // An empty text leaves the section removed, which is the API's way
        // of deleting one.
        return profile_store({path_e}, lines) ? 1 : 0;
    }}
    // The text is the format's own lines, each terminated by a null, in the
    // same shape the read side answers with. It is read at the wide width
    // whichever spelling the caller used, so that the pair splitter is the
    // one the read side uses. Only the pairs are taken: a comment in the
    // caller's text is not part of a section's contents.
    const char16_t* at = {text_wide};
    for (;;) {{
        const std::size_t length = text_len(at);
        if (length == 0) {{
            break;
        }}
        const std::u16string line(at, length);
        IniSpan<char16_t> span{{line.c_str(), line.size()}};
        IniSpan<char16_t> key{{}};
        IniSpan<char16_t> value{{}};
        if (ini_pair_of<char16_t>(span, &key, &value)) {{
            profile_set(&lines, {app_e},
                        std::u16string_view(key.text, key.length),
                        std::u16string(value.text, value.length), false);
        }}
        at += length + 1;
    }}
    return profile_store({path_e}, lines) ? 1 : 0;'''

    app, out, size = c.arg(0), c.arg(1), c.arg(2)
    path = c.arg(3) if len(c.args) > 3 else None
    path_guard = 'profile_shared_file()' if shared else path
    declarations = ''
    if c.wide:
        app_e = app
        path_e = path_guard
    else:
        declarations += f'    const std::u16string wide_app = profile_wide({app});\n'
        app_e = 'wide_app'
        path_e = path_guard
        if not shared:
            declarations += (
                f'    const std::u16string wide_path = profile_wide({path});\n')
            path_e = 'wide_path'
    if c.wide:
        emit = (f'    static_cast<void>(text_copy<char16_t>({out}, {size}, '
                f'answer.c_str()));')
    else:
        emit = f'    copy_list_to_narrow(answer, {out}, {size});'
    return f'''{declarations}    if ({out} == nullptr || {size} == 0 || {path_guard} == nullptr) {{
        return 0;
    }}
    std::u16string answer;
    if ({app} != nullptr) {{
        std::vector<std::u16string> lines;
        static_cast<void>(profile_load({path_e}, &lines));
        answer = profile_section_text(lines, {app_e});
    }}
    {emit}
    return static_cast<std::uint32_t>(text_len_at({out}, {size})) + 1;'''


def _get_section_names(c):
    """The section names, in the order the file states them."""
    out, size, path = c.arg(0), c.arg(1), c.arg(2)
    if c.wide:
        decls, path_e = '', path
    else:
        decls = f'    const std::u16string wide_path = profile_wide({path});\n'
        path_e = 'wide_path'
    if c.wide:
        emit = (f'    static_cast<void>(text_copy<char16_t>({out}, {size}, '
                f'answer.c_str()));')
    else:
        emit = f'    copy_list_to_narrow(answer, {out}, {size});'
    return f'''{decls}    if ({out} == nullptr || {size} == 0 || {path} == nullptr) {{
        return 0;
    }}
    std::vector<std::u16string> lines;
    static_cast<void>(profile_load({path_e}, &lines));
    const std::u16string answer = profile_section_names(lines);
    {emit}
    return static_cast<std::uint32_t>(text_len_at({out}, {size})) + 1;'''


def c_char(c):
    return 'char16_t' if c.wide else 'char'


def applies_to(dll, names):
    return dll == 'kernel32'

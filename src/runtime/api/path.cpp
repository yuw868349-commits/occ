// The path grammar, as Windows defines it.
//
// A Windows path is not a POSIX path and the difference is not cosmetic. The
// root of `C:\a` is `C:\`, the root of `\a` is `\`, the root of `\\s\sh\a`
// is `\\s\sh\`, and `a` has no root at all; a runtime that hands these
// strings to the host and reads back what `realpath` makes of them reports
// the wrong answer for every one of them. So the strings are walked here.
//
// Both separators are accepted on input -- Windows has taken `/` since DOS
// and a guest that was written with forward slashes expects it -- and only
// `\` is written, which is what the operating system does. Every function
// below that returns a pointer returns one into the string it was given,
// which is the contract the header states and the reason the returns are
// not copies.
//
// The rules are Microsoft's. Wine implements the same ones in
// `dlls/shlwapi/path.c`; where the two differ this file says so, and where
// Wine carries a FIXME this file states what the Windows behaviour is
// instead of copying the gap.
//
// The body of each function is a template over the character type so that
// the A and W forms cannot drift: there is one walk, instantiated twice.

#include "occ/runtime/api.h"

#include <cstddef>
#include <cstdint>
#include <utility>

namespace occ::runtime::winabi {
namespace {

// ------------------------------------------------------------------ alphabet

// Both separators are separators for the searches; only the backslash is one
// for the predicates.
//
// This is not an oversight and it is the first thing the reference answers
// made obvious: `PathIsRoot("C:/")` is false and `PathIsRoot("C:/")` in the
// reference answers the same, because the functions that decide what a path
// *is* accept the backslash alone. The functions that walk a string looking
// for a component accept either, because a caller that wrote forward slashes
// still wrote a path. The two sets are kept apart below rather than
// unified, because unifying them is exactly the mistake that makes
// `PathIsRoot("C:/")` claim a drive root that the rest of the family would
// then fail to agree with.
template <typename C>
[[nodiscard]] constexpr bool is_sep(C c) noexcept {
    return c == static_cast<C>('\\') || c == static_cast<C>('/');
}

template <typename C>
[[nodiscard]] constexpr bool is_backslash(C c) noexcept {
    return c == static_cast<C>('\\');
}

template <typename C>
[[nodiscard]] constexpr C backslash() noexcept {
    return static_cast<C>('\\');
}

template <typename C>
[[nodiscard]] constexpr C dot() noexcept {
    return static_cast<C>('.');
}

template <typename C>
[[nodiscard]] constexpr C colon() noexcept {
    return static_cast<C>(':');
}

template <typename C>
[[nodiscard]] constexpr bool is_alpha(C c) noexcept {
    return (c >= static_cast<C>('A') && c <= static_cast<C>('Z')) ||
           (c >= static_cast<C>('a') && c <= static_cast<C>('z'));
}

template <typename C>
[[nodiscard]] std::size_t length_of(const C* text) noexcept {
    std::size_t n = 0;
    while (text[n] != static_cast<C>(0)) {
        ++n;
    }
    return n;
}

// --------------------------------------------------------------- the roots

// A drive letter followed by a colon. `C:` qualifies whether or not a
// separator follows; `C:\` is a root and `C:x` is a drive-relative path,
// which is a real thing Windows has and no other system does. The root of
// both is `C:\`, and `PathIsRoot` is the function that tells them apart.
template <typename C>
[[nodiscard]] bool has_drive(const C* path) noexcept {
    return path[0] != static_cast<C>(0) && path[1] == colon<C>() &&
           is_alpha(path[0]);
}

// `\\server\share` and its descendants. A UNC path is recognised by two
// leading backslashes -- and only backslashes: the reference answers false
// for `//server/share`, so a forward-slash form is not a UNC path to any of
// the predicates below even though the searches would happily walk it.
template <typename C>
[[nodiscard]] bool is_unc(const C* path) noexcept {
    return is_backslash(path[0]) && is_backslash(path[1]);
}

// The end of the server component of a UNC path: the backslash after the
// server name. Null when the path is not a UNC path or has no server.
template <typename C>
[[nodiscard]] const C* unc_server_end(const C* path) noexcept {
    if (!is_unc(path)) {
        return nullptr;
    }
    const C* p = path + 2;
    while (*p != static_cast<C>(0) && !is_backslash(*p)) {
        ++p;
    }
    return p;
}

// The end of the share component, which is where a UNC root really stops.
template <typename C>
[[nodiscard]] const C* unc_share_end(const C* path) noexcept {
    const C* server = unc_server_end(path);
    if (server == nullptr || !is_backslash(*server)) {
        return nullptr;
    }
    const C* p = server + 1;
    while (*p != static_cast<C>(0) && !is_backslash(*p)) {
        ++p;
    }
    return p;
}


// ---------------------------------------------------------------- searching

// The last component of a path: what follows the last separator, or the
// whole string when there is none. `C:\a\b` answers `b`, `C:\a\` answers
// the empty string at the end, and `a\b` answers `b`. This is the shape
// every one of the searches below is built out of.
template <typename C>
[[nodiscard]] const C* tail_component(const C* path) noexcept {
    const C* last = path;
    for (const C* p = path; *p != static_cast<C>(0); ++p) {
        if (is_sep(*p)) {
            last = p + 1;
        }
    }
    return last;
}

}  // namespace

// Two of the walks below are used before they are defined, because the
// function that asks the question reads better than a reordering would. They
// are declared here rather than moved, so that each definition keeps the
// comment that explains its rules.
template <typename C>
[[nodiscard]] bool is_root(const C* path) noexcept;
template <typename C>
[[nodiscard]] const C* find_file_name(const C* path) noexcept;

// ---------------------------------------------------------------------------
// PathAddBackslash
// ---------------------------------------------------------------------------
//
// Appends a separator if the string does not already end in one, and answers
// where the separator is. Windows does not append to a path that is already
// terminated -- a caller that does it twice gets one separator, not two --
// and it does not append to an empty string.
//
// The return is the pointer the caller is meant to keep: it points at the
// separator, so that a caller building `dir` + `name` in place can write at
// it. A caller that ignores the return value still gets the string mutated.
template <typename C>
[[nodiscard]] const C* add_backslash(const C* path) noexcept {
    C* end = const_cast<C*>(path) + length_of(path);
    if (end == path) {
        // Nothing to terminate. Windows answers the string unchanged rather
        // than producing a path of one separator, which would name the root
        // of the current drive.
        return path;
    }
    if (!is_sep(end[-1])) {
        end[0] = backslash<C>();
        end[1] = static_cast<C>(0);
    }
    return end;
}

// ---------------------------------------------------------------------------
// PathRemoveBackslash
// ---------------------------------------------------------------------------
//
// Removes the trailing separator, except when the path is a root: `C:\`
// stays `C:\`, because a root with its separator removed names a
// drive-relative path instead. The predicate is this family's own `is_root`
// rather than a separate scan, which is what makes `\\server\share\` lose
// its separator -- the reference does not call that a root, and the two
// functions agreeing here is what keeps a caller from seeing one of them
// undo the other.
template <typename C>
[[nodiscard]] const C* remove_backslash(const C* path) noexcept {
    const std::size_t n = length_of(path);
    if (n == 0 || !is_sep(path[n - 1])) {
        return path + n;
    }
    if (is_root(path)) {
        return path + n;
    }
    const_cast<C*>(path)[n - 1] = static_cast<C>(0);
    return path + n - 1;
}

// ---------------------------------------------------------------------------
// PathRemoveFileSpec
// ---------------------------------------------------------------------------
//
// Strips the last component and the separator before it: `C:\dir\file.txt`
// becomes `C:\dir`, `C:\dir\` becomes `C:\dir`, and `C:\a` becomes `C:\`.
//
// The search steps over a trailing separator first, which is what makes
// `C:\dir\` lose its last component and not the empty one after it.
//
// Three cases are worth stating because each one is where a plausible
// implementation differs from what the reference does, and all three were
// found by running the reference rather than by reading the documentation.
//
// A path with no separator at all loses its only component and becomes the
// empty string. A UNC share name is not protected -- `\\server\share`
// becomes `\\server`, because the share is a component to this function
// like any other. And a root is left alone and answers false, which is what
// makes `while (PathRemoveFileSpec(path))` a loop that climbs to the root
// and stops there instead of looping forever on the empty string.
template <typename C>
[[nodiscard]] bool remove_file_spec(const C* path) noexcept {
    // A drive root and a bare separator are roots with nothing to remove,
    // and emptying either would name something else. The answer is false,
    // which is what a caller climbing toward the root reads as "this is the
    // root".
    //
    // A UNC root is not protected, and the reference is why: `\\server\share`
    // becomes `\\server`. The share is a component to this function like any
    // other, and the asymmetry with the drive root is the reference's rather
    // than a reading of the documentation.
    if (path[0] == static_cast<C>(0)) {
        return false;
    }
    if (is_backslash(path[0]) && path[1] == static_cast<C>(0)) {
        return false;
    }
    if (has_drive(path) && is_backslash(path[2]) &&
        path[3] == static_cast<C>(0)) {
        return false;
    }
    C* text = const_cast<C*>(path);
    std::size_t cut = length_of(text);
    while (cut != 0 && !is_sep(text[cut - 1])) {
        --cut;
    }
    if (cut == 0) {
        // No separator anywhere, so the only component went. The reference
        // does the same and answers true.
        text[0] = static_cast<C>(0);
        return true;
    }
    // The separator found is dropped, unless dropping it would leave a path
    // that names something else. `C:\a` has to become `C:\` rather than
    // `C:`, because the second is a drive-relative path, and `\a` has to
    // become `\` rather than the empty string, because a path has to start
    // somewhere.
    if (cut == 1 && is_sep(text[0])) {
        text[1] = static_cast<C>(0);
        return true;
    }
    if (cut == 3 && has_drive(text) && is_backslash(text[2])) {
        text[3] = static_cast<C>(0);
        return true;
    }
    text[cut - 1] = static_cast<C>(0);
    return true;
}

// ---------------------------------------------------------------------------
// PathStripPath
// ---------------------------------------------------------------------------
//
// Moves the last component to the front of the buffer, so that the string a
// caller holds becomes the file name. This is the one function in the family
// whose result is not a pointer into the caller's buffer; it rewrites the
// buffer because the point is to hand the whole string to something that
// wants a file name.
//
// It shares `find_file_name` with the function of that name, so `C:\dir\`
// strips to `dir\` rather than to nothing: whatever the search calls the
// name is what this leaves.
template <typename C>
void strip_path(const C* path) noexcept {
    const C* name = find_file_name(path);
    if (name == path) {
        return;
    }
    C* out = const_cast<C*>(path);
    while (*name != static_cast<C>(0)) {
        *out++ = *name++;
    }
    *out = static_cast<C>(0);
}

// ---------------------------------------------------------------------------
// PathFindExtension
// ---------------------------------------------------------------------------
//
// The extension starts at the last dot in the last component. A dot earlier
// in the path belongs to a directory name -- `C:\a.b\c` has no extension --
// which is why the search starts from the file name rather than the whole
// string. With no extension the answer is the end of the string, not null,
// so that a caller can test `*p == 0` without a null check.
//
// `file.` answers the dot and not the end. The reference answers the same,
// and the reading is that the name has an extension which happens to be
// empty; a caller that tested "no extension" by looking at the character
// would otherwise treat `file.` and `file` alike, and Windows does not.
template <typename C>
[[nodiscard]] const C* find_extension(const C* path) noexcept {
    const C* name = tail_component(path);
    const C* last_dot = nullptr;
    for (const C* p = name; *p != static_cast<C>(0); ++p) {
        if (*p == dot<C>()) {
            last_dot = p;
        }
    }
    return last_dot != nullptr ? last_dot : name + length_of(name);
}

// ---------------------------------------------------------------------------
// PathFindFileName
// ---------------------------------------------------------------------------
//
// The last component. A trailing separator is stepped over before the search
// starts, which is what makes `C:\dir\` answer `dir\` and not the empty
// string; the reference answers the same, and the alternative reads a
// directory path as naming nothing.
template <typename C>
[[nodiscard]] const C* find_file_name(const C* path) noexcept {
    const C* end = path + length_of(path);
    while (end != path && is_sep(end[-1])) {
        --end;
    }
    const C* name = path;
    for (const C* p = path; p != end; ++p) {
        if (is_sep(*p)) {
            name = p + 1;
        }
    }
    return name;
}

// ---------------------------------------------------------------------------
// PathFindNextComponent
// ---------------------------------------------------------------------------
//
// Walks to the component after the one at the front: `a\b\c` answers `b\c`.
// Leading separators are skipped first, so `\a\b` answers `a\b`. A string
// with no separator left answers the empty string at the end.
template <typename C>
[[nodiscard]] const C* find_next_component(const C* path) noexcept {
    const C* p = path;
    while (*p != static_cast<C>(0) && !is_sep(*p)) {
        ++p;
    }
    while (is_sep(*p)) {
        ++p;
    }
    return p;
}

// ---------------------------------------------------------------------------
// PathGetDriveNumber
// ---------------------------------------------------------------------------
//
// The zero-based drive index, or -1 for a path with no drive. `C:` is 2 and
// `a:` is 0.
//
// A UNC path answers -1 in this runtime. Windows documents the answer as the
// index of the drive the share is mapped to, but which drive that is depends
// on a mapping this process does not have and cannot invent; -1 is the
// answer for "no drive letter", which is the true one here. A caller that
// branches on the value sees a share as having no drive, which is what it
// has.
template <typename C>
[[nodiscard]] std::int32_t get_drive_number(const C* path) noexcept {
    if (has_drive(path)) {
        const C c = path[0];
        if (c >= static_cast<C>('A') && c <= static_cast<C>('Z')) {
            return static_cast<std::int32_t>(c - static_cast<C>('A'));
        }
        return static_cast<std::int32_t>(c - static_cast<C>('a'));
    }
    return -1;
}

// ---------------------------------------------------------------------------
// PathGetArgs
// ---------------------------------------------------------------------------
//
// Everything after the first unquoted space. Windows hands a command line
// around as one string and this is how a program splits the program name
// from its arguments without a parser: the answer points at the first
// argument, or at the terminator when there is none.
template <typename C>
[[nodiscard]] const C* get_args(const C* path) noexcept {
    bool quoted = false;
    for (const C* p = path; *p != static_cast<C>(0); ++p) {
        if (*p == static_cast<C>('"')) {
            quoted = !quoted;
        } else if (*p == static_cast<C>(' ') && !quoted) {
            return p + 1;
        }
    }
    return path + length_of(path);
}

// ---------------------------------------------------------------------------
// PathSkipRoot
// ---------------------------------------------------------------------------
//
// Where the root ends and the rest of the path starts: `C:\a\b` answers
// `a\b` and `\\server\share\a` answers `a`.
//
// A null answer is the reference's for three inputs that a caller will meet:
// a relative path, which has no root, a path that is nothing but a root, and
// a UNC path with no member after the share. `C:\` answers its own end
// rather than null, because the drive root is a root with something after
// it -- nothing -- and the caller that walks from here gets the terminator
// rather than a null to check.
template <typename C>
[[nodiscard]] const C* skip_root(const C* path) noexcept {
    if (is_unc(path)) {
        const C* share = unc_share_end(path);
        if (share == nullptr || *share == static_cast<C>(0)) {
            return nullptr;
        }
        return share + 1;
    }
    if (has_drive(path) && is_backslash(path[2])) {
        return path + 3;
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// PathIsRoot
// ---------------------------------------------------------------------------
//
// True for `C:\`, `\`, `\\server` and `\\server\share`. False for `C:`,
// which is a drive-relative path and not a root even though it has a drive.
//
// Two of these are the reference's answers rather than a reading of the
// documentation, and both are worth naming because they decide how the rest
// of the family behaves. `C:/` is not a root: the predicate accepts the
// backslash alone, so a caller that wrote forward slashes gets a false here
// even though the searches would walk the same string. And `\\server` is a
// root while `\\server\share\` is not, so what makes a UNC root is where the
// string stops rather than how many separators it has.
template <typename C>
[[nodiscard]] bool is_root(const C* path) noexcept {
    if (path[0] == static_cast<C>(0)) {
        return false;
    }
    if (is_unc(path)) {
        const C* server = unc_server_end(path);
        if (*server == static_cast<C>(0)) {
            return true;  // `\\server`
        }
        const C* share = server + 1;
        while (*share != static_cast<C>(0) && !is_backslash(*share)) {
            ++share;
        }
        return *share == static_cast<C>(0);  // `\\server\share`
    }
    if (is_sep(path[0])) {
        // A forward slash is a separator to the searches and not a root to
        // this predicate.
        return is_backslash(path[0]) && path[1] == static_cast<C>(0);
    }
    if (has_drive(path) && is_backslash(path[2])) {
        return path[3] == static_cast<C>(0);
    }
    return false;
}

// ---------------------------------------------------------------------------
// PathIsRelative
// ---------------------------------------------------------------------------
//
// A path is relative unless it is rooted. `\a` is not relative, because a
// leading separator roots it at the current drive.
//
// A drive letter makes a path absolute whatever follows it, including
// nothing: the reference answers false for `C:` as well as for `C:a`. That
// is worth stating because the documentation describes `C:` as relative, and
// a caller that believed it would build a path relative to something the
// string does not name. Following the reference here means the two answers
// agree about which paths a caller must qualify.
template <typename C>
[[nodiscard]] bool is_relative(const C* path) noexcept {
    if (path[0] == static_cast<C>(0)) {
        return true;
    }
    if (is_backslash(path[0])) {
        return false;
    }
    if (has_drive(path)) {
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// PathCommonPrefix
// ---------------------------------------------------------------------------
//
// The number of characters two paths share, counted on a component boundary.
// The count is what the caller uses to build a relative path, so the
// boundary matters: `C:\a` and `C:\ab` share four characters and no
// component, and the answer is three -- the reference agrees -- which is
// what keeps a caller from building a path that walks out of the directory.
//
// The two strings ending together is the one case that does not back up. A
// path compared against itself shares all of itself and no part of it is
// partial, so `C:\a` against `C:\a` answers four while `C:\a` against
// `C:\ab` answers three.
//
// The output buffer is optional: Windows documents it as such and a caller
// that only wants the count passes null.
template <typename C>
[[nodiscard]] std::int32_t common_prefix(const C* a, const C* b,
                                         C* out) noexcept {
    std::size_t i = 0;
    while (a[i] != static_cast<C>(0) && b[i] != static_cast<C>(0)) {
        const bool same = a[i] == b[i] || (is_sep(a[i]) && is_sep(b[i]));
        if (!same) {
            break;
        }
        ++i;
    }
    if (a[i] != static_cast<C>(0) || b[i] != static_cast<C>(0)) {
        if (i != 0) {
            if (is_sep(a[i - 1])) {
                --i;
            } else {
                while (i != 0 && !is_sep(a[i - 1])) {
                    --i;
                }
            }
        }
    }
    if (out != nullptr) {
        for (std::size_t k = 0; k < i; ++k) {
            out[k] = a[k];
        }
        out[i] = static_cast<C>(0);
    }
    return static_cast<std::int32_t>(i);
}

// ---------------------------------------------------------------------------
// PathAppend
// ---------------------------------------------------------------------------
//
// Joins a path and a component, resolving `..` and keeping `.`. This is not
// string concatenation: a component of `..` shortens the path, which is why
// a caller that wants a join uses this and not `strcat`.
//
// Three of the reference's answers decide the shape, and each one is the
// opposite of the tempting reading.
//
// A component with its own drive **replaces** the path: `C:\dir` plus
// `D:\other` answers `D:\other`. There is nothing to join when the component
// names a root of its own, and refusing would leave the caller with a
// failure it has no way to act on.
//
// A component that starts with a separator is **joined anyway**, with the
// separator dropped: `C:\dir` plus `\absolute` answers `C:\dir\absolute`.
// Windows reads the leading separator as "a path that starts here", and the
// here is the path being appended to.
//
// A `.` component is **kept**: `C:\dir` plus `.` answers `C:\dir\.`. The
// reference leaves it, and a caller comparing the result against a
// precomputed string would see a difference if this dropped it.
template <typename C>
[[nodiscard]] bool append(const C* base, const C* more) noexcept {
    if (more[0] == static_cast<C>(0)) {
        return true;
    }
    C* out = const_cast<C*>(base);
    if (has_drive(more) && is_sep(more[2])) {
        std::size_t k = 0;
        while (more[k] != static_cast<C>(0)) {
            out[k] = more[k];
            ++k;
        }
        out[k] = static_cast<C>(0);
        return true;
    }
    std::size_t n = length_of(base);
    const C* p = more;
    while (is_sep(*p)) {
        ++p;
    }
    while (*p != static_cast<C>(0)) {
        const C* piece = p;
        while (*p != static_cast<C>(0) && !is_sep(*p)) {
            ++p;
        }
        const std::size_t piece_len = static_cast<std::size_t>(p - piece);
        const bool is_dotdot =
            piece_len == 2 && piece[0] == dot<C>() && piece[1] == dot<C>();
        if (is_dotdot) {
            // Step back over the last component, and over the separator that
            // introduced it. A path with nothing left to step over keeps its
            // root: `C:\` plus `..` stays `C:\`.
            while (n != 0 && !is_sep(out[n - 1])) {
                --n;
            }
            if (n != 0) {
                --n;
            }
            if (n == 0) {
                // Nothing was stepped over; the walk starts again from the
                // root's separator so the result is still a path.
                if (is_sep(base[0])) {
                    out[n++] = backslash<C>();
                }
            }
        } else {
            if (n != 0 && !is_sep(out[n - 1])) {
                out[n++] = backslash<C>();
            }
            for (std::size_t k = 0; k < piece_len; ++k) {
                out[n++] = piece[k];
            }
        }
        while (is_sep(*p)) {
            ++p;
        }
    }
    out[n] = static_cast<C>(0);
    return true;
}

// ---------------------------------------------------------------------------
// PathCombine
// ---------------------------------------------------------------------------
//
// Concatenates a directory and a file name. A file with its own root replaces
// the directory instead of being joined to it, which is what makes it safe
// to pass a guest-supplied name through this.
//
// A file that starts with a separator and has no drive is the case worth
// stating: `C:\dir` plus `\rooted` answers `C:\rooted`. The reference keeps
// the directory's root and takes the file's rest, rather than answering
// `\rooted`, which would name a path on no drive and lose the one the caller
// supplied.
//
// The result goes to `out`, not back into either input, because the two
// inputs are often the same buffer and a join that wrote into one while
// reading the other would corrupt it.
template <typename C>
[[nodiscard]] bool combine(C* out, const C* dir, const C* file) noexcept {
    // A null half is an empty one, which is what Windows does:
    // `PathCombineA(out, NULL, file)` produces the file and
    // `PathCombineA(out, dir, NULL)` produces the directory.
    static const C kEmpty[1] = {static_cast<C>(0)};
    if (dir == nullptr) {
        dir = kEmpty;
    }
    if (file == nullptr) {
        file = kEmpty;
    }
    const auto copy_out = [out](const C* from) {
        std::size_t k = 0;
        while (from[k] != static_cast<C>(0)) {
            out[k] = from[k];
            ++k;
        }
        out[k] = static_cast<C>(0);
    };
    if (file[0] == static_cast<C>(0) || dir[0] == static_cast<C>(0) ||
        has_drive(file)) {
        copy_out(file[0] == static_cast<C>(0) ? dir : file);
        return true;
    }
    if (is_sep(file[0])) {
        if (is_backslash(file[0]) && is_backslash(file[1])) {
            // A UNC file is its own root; nothing of the directory survives.
            copy_out(file);
            return true;
        }
        // Keep the directory's root, then the file without its separator.
        std::size_t root = 0;
        if (has_drive(dir) && is_backslash(dir[2])) {
            root = 3;
        } else if (is_unc(dir)) {
            const C* share = unc_share_end(dir);
            root = share != nullptr ? static_cast<std::size_t>(share - dir) + 1
                                    : 0;
        } else if (is_sep(dir[0])) {
            root = 1;
        }
        for (std::size_t k = 0; k < root; ++k) {
            out[k] = dir[k];
        }
        const C* rest = file;
        while (is_sep(*rest)) {
            ++rest;
        }
        std::size_t n = root;
        while (*rest != static_cast<C>(0)) {
            out[n++] = *rest++;
        }
        out[n] = static_cast<C>(0);
        return true;
    }
    copy_out(dir);
    return append(out, file);
}

// ---------------------------------------------------------------------------
// ABI entry points
// ---------------------------------------------------------------------------
//
// One pair per function above, and nothing else: the bodies are the
// templates, instantiated for the two character types. A handler that did
// anything more would be a second implementation of the walk.

extern "C" __attribute__((ms_abi)) char* sw_PathAddBackslashA(
    char* path) noexcept {
    return const_cast<char*>(add_backslash(path));
}

extern "C" __attribute__((ms_abi)) char16_t* sw_PathAddBackslashW(
    char16_t* path) noexcept {
    return const_cast<char16_t*>(add_backslash(path));
}

extern "C" __attribute__((ms_abi)) char* sw_PathRemoveBackslashA(
    char* path) noexcept {
    return const_cast<char*>(remove_backslash(path));
}

extern "C" __attribute__((ms_abi)) char16_t* sw_PathRemoveBackslashW(
    char16_t* path) noexcept {
    return const_cast<char16_t*>(remove_backslash(path));
}

extern "C" __attribute__((ms_abi)) std::int32_t sw_PathRemoveFileSpecA(
    char* path) noexcept {
    return remove_file_spec(path) ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t sw_PathRemoveFileSpecW(
    char16_t* path) noexcept {
    return remove_file_spec(path) ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) void sw_PathStripPathA(char* path) noexcept {
    strip_path(path);
}

extern "C" __attribute__((ms_abi)) void sw_PathStripPathW(
    char16_t* path) noexcept {
    strip_path(path);
}

extern "C" __attribute__((ms_abi)) char* sw_PathFindExtensionA(
    const char* path) noexcept {
    return const_cast<char*>(find_extension(path));
}

extern "C" __attribute__((ms_abi)) char16_t* sw_PathFindExtensionW(
    const char16_t* path) noexcept {
    return const_cast<char16_t*>(find_extension(path));
}

extern "C" __attribute__((ms_abi)) char* sw_PathFindFileNameA(
    const char* path) noexcept {
    return const_cast<char*>(find_file_name(path));
}

extern "C" __attribute__((ms_abi)) char16_t* sw_PathFindFileNameW(
    const char16_t* path) noexcept {
    return const_cast<char16_t*>(find_file_name(path));
}

extern "C" __attribute__((ms_abi)) char* sw_PathFindNextComponentA(
    const char* path) noexcept {
    return const_cast<char*>(find_next_component(path));
}

extern "C" __attribute__((ms_abi)) char16_t* sw_PathFindNextComponentW(
    const char16_t* path) noexcept {
    return const_cast<char16_t*>(find_next_component(path));
}

extern "C" __attribute__((ms_abi)) std::int32_t sw_PathGetDriveNumberA(
    const char* path) noexcept {
    return get_drive_number(path);
}

extern "C" __attribute__((ms_abi)) std::int32_t sw_PathGetDriveNumberW(
    const char16_t* path) noexcept {
    return get_drive_number(path);
}

extern "C" __attribute__((ms_abi)) char* sw_PathGetArgsA(
    const char* path) noexcept {
    return const_cast<char*>(get_args(path));
}

extern "C" __attribute__((ms_abi)) char16_t* sw_PathGetArgsW(
    const char16_t* path) noexcept {
    return const_cast<char16_t*>(get_args(path));
}

extern "C" __attribute__((ms_abi)) char* sw_PathSkipRootA(
    const char* path) noexcept {
    return const_cast<char*>(skip_root(path));
}

extern "C" __attribute__((ms_abi)) char16_t* sw_PathSkipRootW(
    const char16_t* path) noexcept {
    return const_cast<char16_t*>(skip_root(path));
}

extern "C" __attribute__((ms_abi)) std::int32_t sw_PathIsRootA(
    const char* path) noexcept {
    return is_root(path) ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t sw_PathIsRootW(
    const char16_t* path) noexcept {
    return is_root(path) ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t sw_PathIsRelativeA(
    const char* path) noexcept {
    return is_relative(path) ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t sw_PathIsRelativeW(
    const char16_t* path) noexcept {
    return is_relative(path) ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t sw_PathCommonPrefixA(
    const char* a, const char* b, char* out) noexcept {
    return common_prefix(a, b, out);
}

extern "C" __attribute__((ms_abi)) std::int32_t sw_PathCommonPrefixW(
    const char16_t* a, const char16_t* b, char16_t* out) noexcept {
    return common_prefix(a, b, out);
}

extern "C" __attribute__((ms_abi)) std::int32_t sw_PathAppendA(
    char* base, const char* more) noexcept {
    return append(base, more) ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t sw_PathAppendW(
    char16_t* base, const char16_t* more) noexcept {
    return append(base, more) ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) char* sw_PathCombineA(char* out,
                                                         const char* dir,
                                                         const char* file)
    noexcept {
    return combine(out, dir, file) ? out : nullptr;
}

extern "C" __attribute__((ms_abi)) char16_t* sw_PathCombineW(
    char16_t* out, const char16_t* dir, const char16_t* file) noexcept {
    return combine(out, dir, file) ? out : nullptr;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void add_path_shlwapi(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("PathAddBackslashA", reinterpret_cast<void*>(&sw_PathAddBackslashA));
    e("PathAddBackslashW", reinterpret_cast<void*>(&sw_PathAddBackslashW));
    e("PathAppendA", reinterpret_cast<void*>(&sw_PathAppendA));
    e("PathAppendW", reinterpret_cast<void*>(&sw_PathAppendW));
    e("PathCombineA", reinterpret_cast<void*>(&sw_PathCombineA));
    e("PathCombineW", reinterpret_cast<void*>(&sw_PathCombineW));
    e("PathCommonPrefixA", reinterpret_cast<void*>(&sw_PathCommonPrefixA));
    e("PathCommonPrefixW", reinterpret_cast<void*>(&sw_PathCommonPrefixW));
    e("PathFindExtensionA", reinterpret_cast<void*>(&sw_PathFindExtensionA));
    e("PathFindExtensionW", reinterpret_cast<void*>(&sw_PathFindExtensionW));
    e("PathFindFileNameA", reinterpret_cast<void*>(&sw_PathFindFileNameA));
    e("PathFindFileNameW", reinterpret_cast<void*>(&sw_PathFindFileNameW));
    e("PathFindNextComponentA",
      reinterpret_cast<void*>(&sw_PathFindNextComponentA));
    e("PathFindNextComponentW",
      reinterpret_cast<void*>(&sw_PathFindNextComponentW));
    e("PathGetArgsA", reinterpret_cast<void*>(&sw_PathGetArgsA));
    e("PathGetArgsW", reinterpret_cast<void*>(&sw_PathGetArgsW));
    e("PathGetDriveNumberA", reinterpret_cast<void*>(&sw_PathGetDriveNumberA));
    e("PathGetDriveNumberW", reinterpret_cast<void*>(&sw_PathGetDriveNumberW));
    e("PathIsRelativeA", reinterpret_cast<void*>(&sw_PathIsRelativeA));
    e("PathIsRelativeW", reinterpret_cast<void*>(&sw_PathIsRelativeW));
    e("PathIsRootA", reinterpret_cast<void*>(&sw_PathIsRootA));
    e("PathIsRootW", reinterpret_cast<void*>(&sw_PathIsRootW));
    e("PathRemoveBackslashA", reinterpret_cast<void*>(&sw_PathRemoveBackslashA));
    e("PathRemoveBackslashW", reinterpret_cast<void*>(&sw_PathRemoveBackslashW));
    e("PathRemoveFileSpecA", reinterpret_cast<void*>(&sw_PathRemoveFileSpecA));
    e("PathRemoveFileSpecW", reinterpret_cast<void*>(&sw_PathRemoveFileSpecW));
    e("PathSkipRootA", reinterpret_cast<void*>(&sw_PathSkipRootA));
    e("PathSkipRootW", reinterpret_cast<void*>(&sw_PathSkipRootW));
    e("PathStripPathA", reinterpret_cast<void*>(&sw_PathStripPathA));
    e("PathStripPathW", reinterpret_cast<void*>(&sw_PathStripPathW));
}

}  // namespace occ::runtime::winabi

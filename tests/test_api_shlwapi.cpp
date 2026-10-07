// The SHLWAPI path and string families.
//
// These are pure functions over text, which makes them the one part of the
// API a unit test can exercise completely: there is no handle, no host file
// and no process, so every answer below is a fact about the grammar rather
// than about what a machine happened to have. The cases are the ones where a
// plausible implementation is wrong:
//
//   * `PathIsRoot("C:")` is false. A drive with no separator is a
//     drive-relative path, and a caller that treats it as a root builds a
//     path that means something else;
//   * `PathIsRelative("\\a")` is false, because a leading separator roots
//     the path at the current drive;
//   * `PathRemoveFileSpec("C:\\a")` leaves `C:\` and not `C:`, because the
//     second is a drive-relative path;
//   * `PathCommonPrefix` counts on a separator boundary, so `C:\a` and
//     `C:\ab` share three characters and no component;
//   * `PathAppend` resolves `..` instead of concatenating it, and refuses an
//     absolute component rather than letting it discard the base;
//   * `StrChr` takes a 16-bit character and `StrRChr` takes the end of its
//     range, both of which a handler written from a guess gets wrong;
//   * `StrTrim` takes the set of characters to remove and not a flag;
//   * `StrToInt` reads a leading number without validating the tail, and
//     `StrToIntEx` accepts `0x` only when the caller asked for it;
//   * `StrCmpLogicalW` orders `file2` before `file10`, which is the one
//     answer in this file that no C library gives.

#include "occ/runtime/api.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

using namespace occ::runtime;
using namespace occ::runtime::winabi;

namespace {

int failures = 0;
int checks = 0;

void check(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

// ---------------------------------------------------------------------- paths
//
// The expected values below are not a reading of the documentation. Every
// one of them was taken from a program built for Windows and run under the
// reference implementation, because the first version of this file was
// written from the documentation and got nine of them wrong. The cases worth
// reading twice are the ones where a reasonable reading of the prose
// disagrees with what the functions do, and each of those says so where it
// appears.

void test_path_roots() {
    check(sw_PathIsRootA("C:\\") == 1, "path: C:\\ is a root");
    check(sw_PathIsRootA("\\") == 1, "path: \\ is a root");
    check(sw_PathIsRootA("\\\\server\\share") == 1,
          "path: a UNC path is a root");
    // `\\server` is a root even though it names no share: the reference
    // answers true, so what makes a UNC root is where the string stops
    // rather than how many components it has.
    check(sw_PathIsRootA("\\\\server") == 1,
          "path: a server with no share is a root");

    // The reference accepts the backslash alone as a separator for the
    // predicates, so a forward-slash root is not one. A caller that wrote
    // forward slashes gets a false here even though the searches would walk
    // the same string.
    check(sw_PathIsRootA("C:/") == 0,
          "path: C:/ is not a root, because only the backslash counts");
    check(sw_PathIsRootA("/") == 0, "path: / is not a root");
    check(sw_PathIsRootA("\\\\server\\share\\") == 0,
          "path: a UNC path with a trailing separator is not a root");

    check(sw_PathIsRootA("C:") == 0,
          "path: C: is drive-relative and not a root");
    check(sw_PathIsRootA("C:\\a") == 0, "path: C:\\a is not a root");
    check(sw_PathIsRootA("\\\\server\\share\\a") == 0,
          "path: a share with a member is not a root");
    check(sw_PathIsRootA("") == 0, "path: the empty string is not a root");
    check(sw_PathIsRootA("a") == 0, "path: a bare name is not a root");
    check(sw_PathIsRootW(u"C:\\") == 1, "path: the wide form agrees on C:\\");
    check(sw_PathIsRootW(u"C:") == 0,
          "path: the wide form agrees that C: is not a root");
}

void test_path_relative() {
    check(sw_PathIsRelativeA("a\\b") == 1, "path: a\\b is relative");
    check(sw_PathIsRelativeA("") == 1, "path: the empty string is relative");

    // A drive letter makes a path absolute whatever follows it, including
    // nothing. The documentation describes `C:` as relative; the reference
    // does not, and a caller that believed the prose would build a path
    // relative to something the string does not name.
    check(sw_PathIsRelativeA("C:") == 0,
          "path: a bare drive is not relative");
    check(sw_PathIsRelativeA("C:a") == 0,
          "path: a drive with a member is not relative");

    check(sw_PathIsRelativeA("C:\\a") == 0,
          "path: a drive root is absolute");
    check(sw_PathIsRelativeA("\\a") == 0,
          "path: a leading separator is absolute");
    check(sw_PathIsRelativeA("\\\\s\\sh") == 0, "path: a UNC path is absolute");
    check(sw_PathIsRelativeW(u"\\a") == 0,
          "path: the wide form agrees a leading separator is absolute");
}

void test_path_extension() {
    const char* e1 = sw_PathFindExtensionA("C:\\dir\\file.txt");
    check(std::strcmp(e1, ".txt") == 0, "path: the extension is found");

    // A dot in a directory name is not the file's extension, which is why the
    // search starts at the file name rather than at the string.
    const char* e2 = sw_PathFindExtensionA("C:\\a.b\\file");
    check(*e2 == '\0', "path: a dot in a directory is not an extension");

    // A trailing dot is an extension which happens to be empty, so the answer
    // is the dot. A caller that tested for "no extension" by looking at the
    // character would otherwise treat `file.` and `file` alike.
    const char* e3 = sw_PathFindExtensionA("C:\\dir\\file.");
    check(*e3 == '.', "path: a trailing dot is the extension");

    const char* e4 = sw_PathFindExtensionA("file.tar.gz");
    check(std::strcmp(e4, ".gz") == 0,
          "path: the last dot names the extension");

    const char* e5 = sw_PathFindExtensionA("noext");
    check(*e5 == '\0',
          "path: no extension answers the end of the string, not null");

    const char16_t* w1 = sw_PathFindExtensionW(u"C:\\a.b\\file.txt");
    check(std::char_traits<char16_t>::compare(w1, u".txt", 4) == 0,
          "path: the wide form finds the extension");
}

void test_path_file_name() {
    const char* n1 = sw_PathFindFileNameA("C:\\dir\\file.txt");
    check(std::strcmp(n1, "file.txt") == 0, "path: the file name is the tail");

    // A trailing separator is stepped over, so a directory path answers the
    // directory's own name rather than the empty string.
    const char* n2 = sw_PathFindFileNameA("C:\\dir\\");
    check(std::strcmp(n2, "dir\\") == 0,
          "path: a trailing separator is stepped over");

    const char* n3 = sw_PathFindFileNameA("plain");
    check(std::strcmp(n3, "plain") == 0,
          "path: a name with no directory is itself");

    const char* n4 = sw_PathFindFileNameA("C:/fwd/slash.txt");
    check(std::strcmp(n4, "slash.txt") == 0,
          "path: a forward slash separates too");
}

void test_path_next_component() {
    const char* c1 = sw_PathFindNextComponentA("a\\b\\c");
    check(std::strcmp(c1, "b\\c") == 0,
          "path: the next component is what follows the first");

    const char* c2 = sw_PathFindNextComponentA("\\a\\b");
    check(std::strcmp(c2, "a\\b") == 0,
          "path: leading separators are skipped");

    const char* c3 = sw_PathFindNextComponentA("last");
    check(*c3 == '\0', "path: a single component has no next one");
}

void test_path_drive_number() {
    check(sw_PathGetDriveNumberA("C:\\a") == 2, "path: C is drive 2");
    check(sw_PathGetDriveNumberA("a:\\x") == 0, "path: a is drive 0");
    check(sw_PathGetDriveNumberA("Z:\\") == 25, "path: Z is drive 25");
    check(sw_PathGetDriveNumberA("\\a") == -1,
          "path: a path with no drive answers -1");
    check(sw_PathGetDriveNumberA("a\\b") == -1,
          "path: a relative path with no drive answers -1");
    // Which drive a share is mapped to is a property of a mapping this
    // process does not have, so the answer is "no drive letter" rather than
    // an invented index.
    check(sw_PathGetDriveNumberA("\\\\s\\sh") == -1,
          "path: a share has no drive letter here");
}

void test_path_args() {
    const char* a1 = sw_PathGetArgsA("prog.exe arg1 arg2");
    check(std::strcmp(a1, "arg1 arg2") == 0,
          "path: the arguments follow the first space");

    // A space inside quotes does not separate, which is the whole reason the
    // function tracks the quote state rather than looking for a space.
    const char* a2 = sw_PathGetArgsA("prog.exe \"a b\" c");
    check(std::strcmp(a2, "\"a b\" c") == 0,
          "path: a quoted space does not separate");

    const char* a3 = sw_PathGetArgsA("prog.exe");
    check(*a3 == '\0', "path: no arguments answers the terminator");
}

void test_path_skip_root() {
    const char* s1 = sw_PathSkipRootA("C:\\a\\b");
    check(s1 != nullptr && std::strcmp(s1, "a\\b") == 0,
          "path: skipping C:\\ leaves the rest");

    const char* s3 = sw_PathSkipRootA("\\\\srv\\shr\\a");
    check(s3 != nullptr && std::strcmp(s3, "a") == 0,
          "path: skipping a UNC root leaves the member");

    // A drive root is a root with something after it -- nothing -- so the
    // answer is the terminator rather than a null a caller has to check.
    const char* s2 = sw_PathSkipRootA("C:\\");
    check(s2 != nullptr && *s2 == '\0',
          "path: a drive root answers its own end");

    // Three inputs answer null, and a caller walking a path has to expect
    // all three: a relative path has no root, a single leading separator is
    // not a root this function names, and a UNC path with nothing after the
    // share has nothing to skip to.
    check(sw_PathSkipRootA("a\\b") == nullptr,
          "path: a relative path has no root and answers null");
    check(sw_PathSkipRootA("\\a\\b") == nullptr,
          "path: a rooted path with no drive answers null");
    check(sw_PathSkipRootA("\\\\srv\\shr") == nullptr,
          "path: a UNC path with nothing after the share answers null");
}

void test_path_common_prefix() {
    char out[64];
    const std::int32_t n1 = sw_PathCommonPrefixA("C:\\a\\b", "C:\\a\\c", out);
    check(n1 == 4, "path: the common prefix drops the trailing separator");
    check(std::strcmp(out, "C:\\a") == 0, "path: the prefix is copied out");

    // The two share four characters and no component. Counting the characters
    // is what a naive implementation does and what makes a caller build a
    // path that walks out of the directory; the reference answers three.
    const std::int32_t n2 = sw_PathCommonPrefixA("C:\\a", "C:\\ab", nullptr);
    check(n2 == 3, "path: a partial component is not a component prefix");

    const std::int32_t n3 = sw_PathCommonPrefixA("C:\\x", "D:\\x", nullptr);
    check(n3 == 0, "path: paths on different drives share nothing");

    // The one case that does not back up: the two ended together, so no part
    // of what they share is partial.
    const std::int32_t n4 = sw_PathCommonPrefixA("C:\\a", "C:\\a", nullptr);
    check(n4 == 4, "path: a path shares all of itself");
}

// The mutating functions rewrite in place, so every case below drives a
// fixed array rather than a string whose capacity is whatever the
// implementation chose.
static char* seed(char* buf, const char* text) {
    std::strcpy(buf, text);
    return buf;
}

void test_path_add_and_remove_backslash() {
    char a[64];
    seed(a, "C:\\dir");
    sw_PathAddBackslashA(a);
    check(std::strcmp(a, "C:\\dir\\") == 0, "path: a separator is added");

    seed(a, "C:\\dir\\");
    sw_PathAddBackslashA(a);
    check(std::strcmp(a, "C:\\dir\\") == 0,
          "path: a separator is not doubled");

    seed(a, "C:\\dir\\");
    sw_PathRemoveBackslashA(a);
    check(std::strcmp(a, "C:\\dir") == 0, "path: a separator is removed");

    // A root's separator belongs to the root.
    seed(a, "C:\\");
    sw_PathRemoveBackslashA(a);
    check(std::strcmp(a, "C:\\") == 0,
          "path: a drive root keeps its separator");

    // A UNC path ending in a separator is not a root to this family, so the
    // separator goes. The two functions agreeing about what a root is is the
    // point of sharing the predicate.
    seed(a, "\\\\srv\\shr\\");
    sw_PathRemoveBackslashA(a);
    check(std::strcmp(a, "\\\\srv\\shr") == 0,
          "path: a UNC path that is not a root loses its separator");

    seed(a, "C:\\dir\\sub\\");
    sw_PathRemoveBackslashA(a);
    check(std::strcmp(a, "C:\\dir\\sub") == 0,
          "path: a non-root separator is removed");
}

void test_path_remove_file_spec() {
    char a[64];
    seed(a, "C:\\dir\\file.txt");
    check(sw_PathRemoveFileSpecA(a) == 1,
          "path: removing a file spec reports that it removed one");
    check(std::strcmp(a, "C:\\dir") == 0, "path: the file name is removed");

    // The directory shorthand: the trailing separator belongs to the path
    // rather than to the component being removed.
    seed(a, "C:\\dir\\");
    sw_PathRemoveFileSpecA(a);
    check(std::strcmp(a, "C:\\dir") == 0, "path: a trailing separator goes too");

    // `C:\a` leaves `C:\` and not `C:`, because the second names a
    // drive-relative path rather than a root.
    seed(a, "C:\\a");
    sw_PathRemoveFileSpecA(a);
    check(std::strcmp(a, "C:\\") == 0, "path: C:\\a leaves C:\\ and not C:");

    seed(a, "\\a");
    sw_PathRemoveFileSpecA(a);
    check(std::strcmp(a, "\\") == 0, "path: \\a leaves the root");

    // A path with no separator loses its only component. The reference does
    // the same and still answers true, which is what keeps a caller's
    // climb-to-root loop from stopping early.
    seed(a, "plain");
    check(sw_PathRemoveFileSpecA(a) == 1,
          "path: a path with no separator still reports a removal");
    check(std::strcmp(a, "") == 0, "path: and it becomes empty");

    // A UNC share name is a component to this function like any other, even
    // though the rest of the family calls `\\srv\shr` a root.
    seed(a, "\\\\srv\\shr");
    sw_PathRemoveFileSpecA(a);
    check(std::strcmp(a, "\\\\srv") == 0,
          "path: a UNC share name is removed like a component");
    seed(a, "\\\\srv\\shr\\a");
    sw_PathRemoveFileSpecA(a);
    check(std::strcmp(a, "\\\\srv\\shr") == 0,
          "path: and only the component below it is removed");

    // A drive root and a bare separator are left alone and answer false.
    // That answer is what makes a climb-to-root loop stop, so a version that
    // emptied them would loop instead of returning.
    seed(a, "C:\\");
    check(sw_PathRemoveFileSpecA(a) == 0,
          "path: a drive root reports that nothing was removed");
    check(std::strcmp(a, "C:\\") == 0, "path: and is left alone");

    seed(a, "\\");
    check(sw_PathRemoveFileSpecA(a) == 0,
          "path: a bare separator reports that nothing was removed");
    check(std::strcmp(a, "\\") == 0, "path: and is left alone");

    seed(a, "");
    check(sw_PathRemoveFileSpecA(a) == 0,
          "path: the empty string reports that nothing was removed");
}

void test_path_strip_path() {
    char a[64];
    seed(a, "C:\\dir\\file.txt");
    sw_PathStripPathA(a);
    check(std::strcmp(a, "file.txt") == 0, "path: stripping leaves the name");

    seed(a, "plain");
    sw_PathStripPathA(a);
    check(std::strcmp(a, "plain") == 0, "path: a bare name is unchanged");

    // Whatever `PathFindFileName` calls the name is what this leaves, so a
    // directory path strips to the directory's own name.
    seed(a, "C:\\dir\\");
    sw_PathStripPathA(a);
    check(std::strcmp(a, "dir\\") == 0,
          "path: a directory path strips to the directory name");

    char16_t w[64];
    std::char_traits<char16_t>::copy(w, u"C:\\dir\\file.txt", 15);
    sw_PathStripPathW(w);
    check(std::char_traits<char16_t>::compare(w, u"file.txt", 8) == 0,
          "path: the wide form strips to the name");
}

void test_path_append() {
    char a[64];
    seed(a, "C:\\dir");
    check(sw_PathAppendA(a, "sub") == 1, "path: append succeeds");
    check(std::strcmp(a, "C:\\dir\\sub") == 0, "path: the component is joined");

    // `..` is resolved, not concatenated: the result is a shorter path.
    seed(a, "C:\\dir\\sub");
    sw_PathAppendA(a, "..");
    check(std::strcmp(a, "C:\\dir") == 0, "path: .. steps back a component");

    // `.` is kept. A caller comparing the result against a precomputed
    // string would see a difference if this dropped it.
    seed(a, "C:\\dir");
    sw_PathAppendA(a, ".");
    check(std::strcmp(a, "C:\\dir\\.") == 0,
          "path: . is kept rather than resolved");

    seed(a, "C:\\dir\\sub");
    sw_PathAppendA(a, "..\\other");
    check(std::strcmp(a, "C:\\dir\\other") == 0,
          "path: a .. inside a component walk is resolved");

    // A leading separator is dropped and the component joined anyway. A
    // caller that passed an absolute-looking component still gets a path
    // rooted where it started.
    seed(a, "C:\\dir");
    check(sw_PathAppendA(a, "\\absolute") == 1,
          "path: a component with a leading separator is accepted");
    check(std::strcmp(a, "C:\\dir\\absolute") == 0,
          "path: and is joined with the separator dropped");

    // A component with its own drive replaces the path: there is nothing
    // left to join when the component names a root of its own.
    seed(a, "C:\\dir");
    check(sw_PathAppendA(a, "D:\\other") == 1,
          "path: a component with a drive is accepted");
    check(std::strcmp(a, "D:\\other") == 0,
          "path: and replaces the path");
}

void test_path_combine() {
    char out[64];
    sw_PathCombineA(out, "C:\\dir", "file.txt");
    check(std::strcmp(out, "C:\\dir\\file.txt") == 0,
          "path: a directory and a name are joined");

    // An absolute name replaces the directory rather than being joined to it,
    // which is what makes this safe to call with a caller-supplied name.
    sw_PathCombineA(out, "C:\\dir", "D:\\other\\file");
    check(std::strcmp(out, "D:\\other\\file") == 0,
          "path: an absolute name replaces the directory");

    // A rooted name keeps the directory's root and takes the name's rest,
    // rather than answering a path that names no drive.
    sw_PathCombineA(out, "C:\\dir", "\\rooted");
    check(std::strcmp(out, "C:\\rooted") == 0,
          "path: a rooted name keeps the directory's root");

    sw_PathCombineA(out, nullptr, "file");
    check(std::strcmp(out, "file") == 0,
          "path: a null directory is an empty one");

    sw_PathCombineA(out, "C:\\dir", nullptr);
    check(std::strcmp(out, "C:\\dir") == 0,
          "path: a null name leaves the directory");
}

// -------------------------------------------------------------------- strings

void test_string_compares() {
    check(sw_StrCmpCA("abc", "abc") == 0, "str: equal strings compare equal");
    check(sw_StrCmpCA("abc", "abd") < 0, "str: a smaller string compares less");
    check(sw_StrCmpCA("abd", "abc") > 0,
          "str: a larger string compares greater");
    check(sw_StrCmpCA("ABC", "abc") < 0,
          "str: the case-sensitive compare distinguishes case");

    check(sw_StrCmpICA("ABC", "abc") == 0,
          "str: the case-insensitive compare folds");
    check(sw_StrCmpIW(u"AbC", u"aBc") == 0,
          "str: the wide case-insensitive compare folds");

    // A bound of zero compares nothing, which is what makes a caller free to
    // pass a size it has not checked. A negative bound is not zero: it means
    // no limit, which is what a caller that passes -1 for "the whole string"
    // expects.
    check(sw_StrCmpNCA("abc", "abd", 2) == 0,
          "str: a bound stops the compare before the difference");
    check(sw_StrCmpNCA("abc", "abd", 3) < 0,
          "str: the bound reaches the difference");
    check(sw_StrCmpNCA("abc", "xyz", 0) == 0,
          "str: a zero bound compares nothing");
    check(sw_StrCmpNCA("abc", "xyz", -1) != 0,
          "str: a negative bound compares the whole string");

    check(sw_StrIsIntlEqualA(1, "ABC", "abc", -1) != 0,
          "str: case matters when the caller says so");
    check(sw_StrIsIntlEqualA(0, "ABC", "abc", -1) == 0,
          "str: and not when the caller says not");
}

void test_string_logical_order() {
    // The whole reason this function exists: a character compare puts "10"
    // before "2" and Explorer does not.
    check(sw_StrCmpLogicalW(u"file2", u"file10") < 0,
          "str: an embedded number is compared by value");
    check(sw_StrCmpLogicalW(u"a2b", u"a10b") < 0,
          "str: a number in the middle is compared by value");
    check(sw_StrCmpLogicalW(u"2", u"10") < 0,
          "str: two numbers compare by value");
    check(sw_StrCmpLogicalW(u"10", u"2") > 0,
          "str: and in the other direction");

    // Leading zeros do not order the two apart: `01` and `1` compare equal.
    // The reference says so, and a caller that needed the two ordered would
    // need a tie-break this function does not provide.
    check(sw_StrCmpLogicalW(u"01", u"1") == 0,
          "str: a leading zero does not order the two apart");
    check(sw_StrCmpLogicalW(u"0", u"00") == 0,
          "str: two runs of zeros compare equal");
    check(sw_StrCmpLogicalW(u"a01b", u"a1b") == 0,
          "str: and in the middle of a string");

    check(sw_StrCmpLogicalW(u"abc", u"ABC") == 0,
          "str: the text part is compared without case");
    check(sw_StrCmpLogicalW(u"abc", u"abd") < 0,
          "str: the text part is compared by code unit");
    check(sw_StrCmpLogicalW(u"a", u"a") == 0, "str: a string equals itself");
}

void test_string_searches() {
    check(sw_StrChrA("abc", 'b') != nullptr &&
              *sw_StrChrA("abc", 'b') == 'b',
          "str: a character is found");
    check(sw_StrChrA("abc", 'z') == nullptr,
          "str: a missing character answers null");
    check(sw_StrChrIA("aBc", 'b') != nullptr,
          "str: the case-insensitive search folds");
    check(*sw_StrChrNW(u"abcdef", u'c', 3) == u'c',
          "str: a bounded search finds inside the bound");
    check(sw_StrChrNW(u"abcdef", u'd', 3) == nullptr,
          "str: and does not find outside it");

    check(*sw_StrRChrA("a/b/c", nullptr, '/') == '/',
          "str: the backward search finds the last one");
    check(std::strcmp(sw_StrRChrA("a/b/c", nullptr, '/'), "/c") == 0,
          "str: and it is the last one");
    check(sw_StrRChrA("abc", nullptr, 'z') == nullptr,
          "str: a missing character answers null");

    check(*sw_StrPBrkA("hello world", "aeiou") == 'e',
          "str: the first character in a set is found");
    check(sw_StrPBrkA("xyz", "aeiou") == nullptr,
          "str: a set with no member present answers null");

    check(sw_StrStrA("hello world", "world") != nullptr,
          "str: a substring is found");
    check(sw_StrStrA("hello", "xyz") == nullptr,
          "str: a missing substring answers null");
    check(sw_StrStrIA("Hello World", "world") != nullptr,
          "str: the case-insensitive substring search folds");
    check(sw_StrStrIA("hello", "L") != nullptr,
          "str: and finds a single character in either case");
    check(sw_StrStrNW(u"abcdef", u"cd", 3) != nullptr,
          "str: a bounded substring search respects the bound");
    // The bound is on the needle, not on the haystack: a needle shorter than
    // the bound is found wherever it is.
    check(sw_StrStrNW(u"abcdef", u"de", 3) != nullptr,
          "str: the bound is the needle's length, not the haystack's");

    check(*sw_StrRStrIA("a.b.c.d", nullptr, ".c") == '.',
          "str: the last substring is found");
    check(std::strcmp(sw_StrRStrIA("a.b.c.d", nullptr, ".c"), ".c.d") == 0,
          "str: and it is the last one");

    check(sw_StrSpnA("aaabbb", "a") == 3, "str: the span counts the prefix");
    check(sw_StrCSpnA("aaabbb", "b") == 3,
          "str: the complement span counts up to the set");
    check(sw_StrSpnA("abcdef", "xyz") == 0,
          "str: a span with no member present is zero");
}

void test_string_copies() {
    char a[8];
    std::memset(a, 0x7F, sizeof(a));
    sw_StrCpyNXA(a, "abcdefghij", 8);
    check(std::strcmp(a, "abcdefg") == 0,
          "str: the bounded copy stops one short and terminates");

    char b[4];
    std::memset(b, 0x7F, sizeof(b));
    sw_StrCpyNXA(b, "abcdef", 4);
    check(std::strcmp(b, "abc") == 0,
          "str: a small buffer takes what fits");
    check(b[3] == '\0', "str: and is terminated");

    // A capacity of zero is the caller saying there is no room, which is not
    // the same as a request to write at offset zero.
    char c[4] = {'x', 'y', 'z', '\0'};
    sw_StrCpyNXA(c, "abc", 0);
    check(std::strcmp(c, "xyz") == 0,
          "str: a zero capacity leaves the buffer alone");

    char d[12] = "abc";
    sw_StrCatBuffA(d, "def", 12);
    check(std::strcmp(d, "abcdef") == 0, "str: the bounded append joins");

    char e[6] = "abc";
    sw_StrCatBuffA(e, "defgh", 6);
    check(std::strcmp(e, "abcde") == 0,
          "str: and stops at the buffer's end");

    char16_t f[8] = u"ab";
    const std::uint32_t at = sw_StrCatChainW(f, 8, 2, u"cd");
    check(std::char_traits<char16_t>::compare(f, u"abcd", 4) == 0,
          "str: the chained append writes at the offset");
    check(at == 4, "str: and answers the new offset");
    sw_StrCatChainW(f, 8, at, u"ef");
    check(std::char_traits<char16_t>::compare(f, u"abcdef", 6) == 0,
          "str: the offset carries to the next call");
}

void test_string_trim() {
    char a[] = "  padded  ";
    sw_StrTrimA(a, " ");
    check(std::strcmp(a, "padded") == 0, "str: both ends are trimmed");

    char b[] = "\t\tpadded\r\n";
    sw_StrTrimA(b, " \t\r\n");
    check(std::strcmp(b, "padded") == 0,
          "str: the set is what is trimmed, not always whitespace");

    // Trimming a character that is not in the set changes nothing, which is
    // the check that the second argument is really the set.
    char c[] = "  padded  ";
    sw_StrTrimA(c, "x");
    check(std::strcmp(c, "  padded  ") == 0,
          "str: a set that does not match leaves the text alone");

    char d[] = "xxxx";
    sw_StrTrimA(d, "x");
    check(std::strcmp(d, "") == 0, "str: a fully trimmed string is empty");

    char e[] = "";
    sw_StrTrimA(e, " ");
    check(std::strcmp(e, "") == 0, "str: an empty string stays empty");
}

void test_string_parses() {
    check(sw_StrToIntA("123") == 123, "str: a decimal number parses");
    check(sw_StrToIntA("12abc") == 12, "str: the trailing text is ignored");
    check(sw_StrToIntA("-45") == -45, "str: a leading sign is read");

    // Leading whitespace is not skipped, so a value a caller did not trim is
    // not a number. The answer is zero rather than a silently wrong number,
    // and the reference answers the same.
    check(sw_StrToIntA("  -45") == 0,
          "str: leading whitespace is not skipped");

    // `StrToInt` reads the decimal `0` and stops at the `x`, so the answer is
    // zero. A caller that wants the hex form asks for it through
    // `StrToIntEx`.
    check(sw_StrToIntA("0x1F") == 0,
          "str: StrToInt reads no hex prefix");
    check(sw_StrToIntA("notanumber") == 0,
          "str: text parses as zero, as documented");
    check(sw_StrToIntA("") == 0, "str: an empty string parses as zero");
    check(sw_StrToIntA("-") == 0, "str: a bare sign is not a number");

    std::int32_t out = 0;
    check(sw_StrToIntExA("0x20", 1, &out) == 1 && out == 32,
          "str: the hex form parses when the caller asks for it");

    // Without the flag the call still succeeds: it read the decimal zero and
    // stopped. A caller cannot tell "parsed zero" from "parsed nothing" by
    // the return value, which is why the documentation says not to use this
    // to validate input.
    out = 7;
    check(sw_StrToIntExA("0x20", 0, &out) == 1 && out == 0,
          "str: and reads the leading zero without it");

    std::int64_t wide = 0;
    check(sw_StrToInt64ExA("123456789012", 0, &wide) == 1 &&
              wide == 123456789012LL,
          "str: the 64-bit form reads past 32 bits");
}

// The table itself: every name this domain registers has to be reachable by
// the registry, and a name registered twice would make one of the two
// unreachable without anything saying so.
void test_registration() {
    ExportList list;
    add_path_shlwapi(list);
    const std::size_t path_count = list.size();
    add_string_shlwapi(list);

    bool duplicate = false;
    for (std::size_t i = 0; i < list.size() && !duplicate; ++i) {
        for (std::size_t k = i + 1; k < list.size(); ++k) {
            if (list[i].name == list[k].name) {
                duplicate = true;
                break;
            }
        }
    }
    check(!duplicate, "api: no name is registered twice");

    bool all_named = true;
    bool all_addressed = true;
    for (const HostExport& entry : list) {
        if (entry.name.empty()) {
            all_named = false;
        }
        if (entry.address == 0) {
            all_addressed = false;
        }
    }
    check(all_named, "api: every entry has a name");
    check(all_addressed, "api: every entry has an address");
    check(path_count == 30, "api: the path domain contributes thirty names");
    check(list.size() == 78, "api: the shlwapi path and string domains contribute seventy-eight");
}

}  // namespace

int main() {
    test_path_roots();
    test_path_relative();
    test_path_extension();
    test_path_file_name();
    test_path_next_component();
    test_path_drive_number();
    test_path_args();
    test_path_skip_root();
    test_path_common_prefix();
    test_path_add_and_remove_backslash();
    test_path_remove_file_spec();
    test_path_strip_path();
    test_path_append();
    test_path_combine();
    test_string_compares();
    test_string_logical_order();
    test_string_searches();
    test_string_copies();
    test_string_trim();
    test_string_parses();
    test_registration();

    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks, 0 failures\n", checks);
    return 0;
}

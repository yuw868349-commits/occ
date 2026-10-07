// The file and directory family.
//
// These functions answer through the host's file system, so the tests drive a
// real directory and check what comes back. The expected values are the
// reference's, not a reading of the documentation: each one below was taken
// from a Windows program run under the reference implementation, and several
// are cases where the documentation would lead a reader the other way.
//
// The directory is under the host's `/tmp` and is named for this file, so a
// run leaves the tree as it found it and two runs do not collide.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

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

// The host side of the tree the guest side drives, and the DOS spelling of
// it. `Z:` is mapped at the host's root, so one path is the other with the
// separators turned round.
constexpr const char* kHostDir = "/tmp/occ_api_file_test";
constexpr const char* kHostFile = "/tmp/occ_api_file_test/a.txt";
constexpr const char* kHostCopy = "/tmp/occ_api_file_test/b.txt";
constexpr const char* kHostMoved = "/tmp/occ_api_file_test/c.txt";

const std::uint32_t kInvalidAttributes = 0xFFFFFFFFu;
const std::uint32_t kAttributeReadOnly = 0x01;
const std::uint32_t kAttributeDirectory = 0x10;
const std::uint32_t kAttributeArchive = 0x20;
const std::uint32_t kAttributeNormal = 0x80;
const std::uint32_t kErrorFileNotFound = 2;
const std::uint32_t kErrorAlreadyExists = 183;

// The tree is built on the host side rather than through the functions under
// test, so that a failure in setup is not reported as a failure of the thing
// being set up.
void reset_tree() {
    // The working directory cannot be the one being removed: a process whose
    // current directory is a directory it deletes gets an error from the
    // host, the directory survives, and every case after this one then runs
    // against a tree the previous case left behind. That is not a
    // hypothetical -- it made three different mutations fail the same five
    // assertions, which is the shape a state leak makes.
    char here[512];
    if (::getcwd(here, sizeof(here)) != nullptr &&
        std::strcmp(here, kHostDir) == 0) {
        ::chdir("/tmp");
    }
    ::unlink(kHostFile);
    ::unlink(kHostCopy);
    ::unlink(kHostMoved);
    ::rmdir(kHostDir);
    ::mkdir(kHostDir, 0777);
}

void write_fixture(const char* path, const char* text) {
    const int fd = ::open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) {
        ::write(fd, text, std::strlen(text));
        ::close(fd);
    }
}

void test_attributes() {
    reset_tree();
    set_last_error(0);

    // The sentinel a failure answers is all ones, which is what makes it
    // distinguishable from a file that exists and carries no attributes.
    const std::uint32_t missing =
        k32b_GetFileAttributesA("Z:\\tmp\\occ_api_file_test\\nope.txt");
    check(missing == kInvalidAttributes,
          "file: a failed attribute query answers the invalid sentinel");
    check(k32_GetLastError() == kErrorFileNotFound,
          "file: and reports file-not-found");

    // A directory carries the directory bit and no archive bit.
    const std::uint32_t dir =
        k32b_GetFileAttributesA("Z:\\tmp\\occ_api_file_test");
    check((dir & kAttributeDirectory) != 0,
          "file: a directory carries the directory attribute");

    write_fixture(kHostFile, "hello");
    const std::uint32_t file =
        k32b_GetFileAttributesA("Z:\\tmp\\occ_api_file_test\\a.txt");
    check((file & kAttributeArchive) != 0,
          "file: an ordinary file carries the archive attribute");
    // The reference does not set NORMAL on a file that has another
    // attribute: NORMAL means "none of the others".
    check((file & kAttributeNormal) == 0,
          "file: and does not carry the normal attribute");

    const std::uint32_t wide =
        k32b_GetFileAttributesW(u"Z:\\tmp\\occ_api_file_test\\a.txt");
    check(wide == file, "file: the wide form agrees with the narrow one");

    // A query on a name too long for the guest's buffer is the caller's
    // problem, not a failure of the query: what this checks is that a path
    // the runtime does not mount is reported rather than invented.
    const std::uint32_t other =
        k32b_GetFileAttributesA("Q:\\nowhere\\x.txt");
    check(other == kInvalidAttributes,
          "file: a volume the runtime does not mount is a failure");
}

void test_attributes_ex() {
    reset_tree();
    write_fixture(kHostFile, "hello");

    // WIN32_FILE_ATTRIBUTE_DATA: the attribute word, three FILETIMEs and the
    // two halves of the size, which is 36 bytes.
    std::uint8_t block[36];
    std::memset(block, 0, sizeof(block));
    const std::int32_t ok = k32b_GetFileAttributesExA(
        "Z:\\tmp\\occ_api_file_test\\a.txt", 0, block);
    check(ok == 1, "file: the extended query succeeds");

    std::uint32_t attributes = 0;
    std::uint32_t size_low = 0;
    std::uint32_t size_high = 0;
    std::memcpy(&attributes, block + 0, 4);
    std::memcpy(&size_low, block + 32, 4);
    std::memcpy(&size_high, block + 28, 4);
    check((attributes & kAttributeArchive) != 0,
          "file: the extended query reports the attributes");
    check(size_low == 5 && size_high == 0,
          "file: and the size, split across its two halves");

    // The write time is a Windows time: ticks from the start of 1601. A
    // value that fits in the low half alone would mean the epoch offset was
    // left out, which shifts every timestamp by four centuries.
    std::uint32_t write_low = 0;
    std::uint32_t write_high = 0;
    std::memcpy(&write_low, block + 20, 4);
    std::memcpy(&write_high, block + 24, 4);
    check(write_high != 0,
          "file: the write time carries the epoch offset it should");

    check(k32b_GetFileAttributesExA("Z:\\tmp\\occ_api_file_test\\nope.txt", 0,
                                    block) == 0,
          "file: the extended query fails for a missing name");
}

void test_directories() {
    reset_tree();
    ::rmdir(kHostDir);

    check(k32b_CreateDirectoryA("Z:\\tmp\\occ_api_file_test", nullptr) == 1,
          "file: a directory is created");
    // The second attempt fails, and with the error a caller branches on:
    // "already exists" is not a failure the caller has to report.
    set_last_error(0);
    check(k32b_CreateDirectoryA("Z:\\tmp\\occ_api_file_test", nullptr) == 0,
          "file: creating it twice fails");
    check(k32_GetLastError() == kErrorAlreadyExists,
          "file: and reports that the name already exists");

    check(k32b_RemoveDirectoryA("Z:\\tmp\\occ_api_file_test") == 1,
          "file: an empty directory is removed");
    check(k32b_RemoveDirectoryA("Z:\\tmp\\occ_api_file_test") == 0,
          "file: removing it twice fails");
}

void test_current_directory() {
    reset_tree();

    char cwd[512];
    std::memset(cwd, 0, sizeof(cwd));
    const std::uint32_t got = k32b_GetCurrentDirectoryA(sizeof(cwd), cwd);
    // The answer is the length without the terminator, which is what makes
    // it comparable against `strlen`.
    check(got == std::strlen(cwd),
          "file: the current directory answers its length, no terminator");

    // A buffer that cannot hold it is not a failure: the call answers the
    // size the caller needs, terminator included, and writes nothing.
    char tiny[2];
    tiny[0] = 'x';
    tiny[1] = '\0';
    const std::uint32_t needed = k32b_GetCurrentDirectoryA(2, tiny);
    check(needed > 2, "file: a small buffer answers the size needed");
    check(tiny[0] == 'x', "file: and leaves the buffer alone");

    // Changing it changes the process's, which is what a caller that
    // changes directory and then opens a relative path depends on.
    check(k32b_SetCurrentDirectoryA("Z:\\tmp") == 1,
          "file: the current directory is changed");
    char after[512];
    std::memset(after, 0, sizeof(after));
    k32b_GetCurrentDirectoryA(sizeof(after), after);
    check(std::strcmp(after, "Z:\\tmp") == 0,
          "file: and the change is visible");

    // The wide form reads the same directory, which is the check that the
    // two entry points share one implementation rather than two.
    char16_t wide[512];
    const std::uint32_t wide_got = k32b_GetCurrentDirectoryW(512, wide);
    check(wide_got == 6, "file: the wide form answers the same length");
    check(std::char_traits<char16_t>::compare(wide, u"Z:\\tmp", 6) == 0,
          "file: and the same path");

    k32b_SetCurrentDirectoryA("Z:\\tmp\\occ_api_file_test");
}

void test_full_path() {
    reset_tree();
    k32b_SetCurrentDirectoryA("Z:\\tmp\\occ_api_file_test");

    char out[512];
    std::memset(out, 0, sizeof(out));
    const std::uint32_t got = k32b_GetFullPathNameA("a.txt", sizeof(out), out,
                                                    nullptr);
    check(got == std::strlen(out),
          "file: the full path answers its length, no terminator");
    check(std::strcmp(out, "Z:\\tmp\\occ_api_file_test\\a.txt") == 0,
          "file: a relative name is qualified against the directory");

    // A name that is not there is answered rather than refused: what the
    // caller wants is a path to compare, not a path that exists.
    const std::uint32_t absent = k32b_GetFullPathNameA(
        "not-there.txt", sizeof(out), out, nullptr);
    check(absent == std::strlen(out),
          "file: a missing name is still qualified");

    // The output pointer receives the position of the file name.
    char* part = nullptr;
    k32b_GetFullPathNameA("a.txt", sizeof(out), out, &part);
    check(part != nullptr && std::strcmp(part, "a.txt") == 0,
          "file: the file-name pointer points at the name");
}

void test_copies_and_moves() {
    reset_tree();
    write_fixture(kHostFile, "hello");

    check(k32b_CopyFileA("Z:\\tmp\\occ_api_file_test\\a.txt",
                         "Z:\\tmp\\occ_api_file_test\\b.txt", 0) == 1,
          "file: a file is copied");
    check(k32b_CopyFileA("Z:\\tmp\\occ_api_file_test\\a.txt",
                         "Z:\\tmp\\occ_api_file_test\\b.txt", 1) == 0,
          "file: and refuses when the destination exists and it was told to");

    // The copy carries the contents, which is the whole point.
    char body[16];
    std::memset(body, 0, sizeof(body));
    const int fd = ::open(kHostCopy, O_RDONLY);
    if (fd >= 0) {
        ::read(fd, body, sizeof(body) - 1);
        ::close(fd);
    }
    check(std::strcmp(body, "hello") == 0, "file: and the contents arrive");

    check(k32b_MoveFileA("Z:\\tmp\\occ_api_file_test\\b.txt",
                         "Z:\\tmp\\occ_api_file_test\\c.txt") == 1,
          "file: a file is moved");
    check(k32b_GetFileAttributesA("Z:\\tmp\\occ_api_file_test\\b.txt") ==
              kInvalidAttributes,
          "file: and the source is gone");

    // A move onto an existing name is refused unless the caller asked for
    // the replacement, which is what makes the plain form safe to call with
    // a destination nothing checked.
    set_last_error(0);
    check(k32b_MoveFileA("Z:\\tmp\\occ_api_file_test\\c.txt",
                         "Z:\\tmp\\occ_api_file_test\\a.txt") == 0,
          "file: a move onto an existing name is refused");
    check(k32_GetLastError() == kErrorAlreadyExists,
          "file: and reports that the destination exists");

    check(k32b_MoveFileExA("Z:\\tmp\\occ_api_file_test\\c.txt",
                           "Z:\\tmp\\occ_api_file_test\\a.txt", 1) == 1,
          "file: and is allowed when the caller asks to replace");
    check(k32b_GetFileAttributesA("Z:\\tmp\\occ_api_file_test\\c.txt") ==
              kInvalidAttributes,
          "file: the moved name is gone from where it was");
}

void test_deletes() {
    reset_tree();
    write_fixture(kHostFile, "hello");

    check(k32b_GetFileAttributesExA("Z:\\tmp\\occ_api_file_test\\a.txt", 0,
                                    nullptr) == 0,
          "file: the extended query refuses a null output");

    // The removal itself is `DeleteFileA`, which this domain does not own;
    // what it owns is that a query on the name afterwards says the name is
    // gone, which is the state the next section needs.
    ::unlink(kHostFile);
    reset_tree();
    write_fixture(kHostFile, "hello");
    check(k32b_SetFileAttributesA("Z:\\tmp\\occ_api_file_test\\a.txt",
                                  kAttributeReadOnly) == 1,
          "file: the read-only attribute is set");
    const std::uint32_t after =
        k32b_GetFileAttributesA("Z:\\tmp\\occ_api_file_test\\a.txt");
    check((after & kAttributeReadOnly) != 0,
          "file: and a query reports it back");

    check(k32b_SetFileAttributesA("Z:\\tmp\\occ_api_file_test\\a.txt", 0) == 1,
          "file: and is cleared again");
    const std::uint32_t cleared =
        k32b_GetFileAttributesA("Z:\\tmp\\occ_api_file_test\\a.txt");
    check((cleared & kAttributeReadOnly) == 0,
          "file: so the file is writable again");
}

void test_temp_path() {
    char out[512];
    std::memset(out, 0, sizeof(out));
    const std::uint32_t got = k32b_GetTempPathA(sizeof(out), out);
    check(got == std::strlen(out),
          "file: the temporary path answers its length, no terminator");
    // Windows documents the answer as ending in a separator, and a caller
    // concatenates onto it on that understanding.
    check(got != 0 && out[got - 1] == '\\',
          "file: the temporary path ends in a separator");

    char16_t wide[512];
    const std::uint32_t wide_got = k32b_GetTempPathW(512, wide);
    check(wide_got == got, "file: and the wide form agrees");
}

void test_arguments() {
    // A null path is an argument error rather than a missing file, and every
    // function in the domain says so rather than opening something.
    set_last_error(0);
    check(k32b_GetFileAttributesA(nullptr) == kInvalidAttributes,
          "file: a null path is refused");
    check(k32_GetLastError() == 87, "file: as an invalid parameter");
    check(k32b_CreateDirectoryA(nullptr, nullptr) == 0,
          "file: creating a null directory is refused");
    check(k32b_RemoveDirectoryA("") == 0,
          "file: removing the empty path is refused");
    check(k32b_SetCurrentDirectoryA(nullptr) == 0,
          "file: setting a null directory is refused");
    check(k32b_GetFullPathNameA(nullptr, 8, nullptr, nullptr) == 0,
          "file: qualifying a null path is refused");
    check(k32b_CopyFileA(nullptr, nullptr, 0) == 0,
          "file: copying from a null path is refused");
    check(k32b_MoveFileExA(nullptr, nullptr, 0) == 0,
          "file: moving a null path is refused");
}

// The table itself: every name this domain registers has to be reachable and
// no name may appear twice.
void test_registration() {
    ExportList list;
    add_file_kernel32(list);

    bool duplicate = false;
    for (std::size_t i = 0; i < list.size() && !duplicate; ++i) {
        for (std::size_t k = i + 1; k < list.size(); ++k) {
            if (list[i].name == list[k].name) {
                duplicate = true;
                break;
            }
        }
    }
    check(!duplicate, "file: no name is registered twice");

    bool all_addressed = true;
    for (const HostExport& entry : list) {
        if (entry.name.empty() || entry.address == 0) {
            all_addressed = false;
        }
    }
    check(all_addressed, "file: every entry has a name and an address");
    check(list.size() == 24, "file: the domain contributes twenty-four names");
}

}  // namespace

int main() {
    test_attributes();
    test_attributes_ex();
    test_directories();
    test_current_directory();
    test_full_path();
    test_copies_and_moves();
    test_deletes();
    test_temp_path();
    test_arguments();
    test_registration();

    reset_tree();
    ::unlink(kHostFile);
    ::unlink(kHostCopy);
    ::unlink(kHostMoved);
    ::rmdir(kHostDir);

    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks, 0 failures\n", checks);
    return 0;
}

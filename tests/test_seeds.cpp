// The fuzz seed corpus is what the generator says it is.
//
// Every seed under fuzz/seeds/ was written by tools/make_pe_seeds.py, and
// the reason they are generated rather than checked in by hand is that a
// binary with no generator says only what it is. That reason only holds
// while the generator and the checked-in files agree, and nothing else in
// the tree would notice when they stopped: the harnesses read whatever bytes
// are in the directory, so a seed that had drifted would still be run, would
// still pass, and would no longer reach the code it was written to reach.
//
// So this test runs the generator and compares. Two directions, because they
// fail differently:
//
//   * A seed whose bytes differ from the generated ones means the file was
//     edited, or the generator was changed without regenerating. Either way
//     the file and the program that describes it now say different things
//     about the same corpus.
//
//   * A file in the directory that the generator does not produce means a
//     seed was added by hand, which is the case the generator exists to end.
//     Comparing only the generated names would pass here, because every name
//     the generator knows would still match.
//
// Both report the file by name. A failure that says "a seed differs" without
// saying which one leaves the reader to diff two directories by hand.
//
// Python is not a build dependency. This test needs it and skips cleanly
// without it, because a corpus that cannot be regenerated is still a corpus
// the harnesses can run, and a build that failed for want of an interpreter
// would be a worse answer than an unchecked one. What the skip costs is
// stated in the message it prints, so nobody reads a green run here as more
// than it was.

#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

// Both arrive from CMake. The generator is a script and the seeds are data,
// and neither has a business being located by a test that guesses at the
// repository's layout.
#ifndef OCC_SEED_GENERATOR
#error "OCC_SEED_GENERATOR must name tools/make_pe_seeds.py"
#endif
#ifndef OCC_SEED_DIR
#error "OCC_SEED_DIR must name the directory holding the seeds"
#endif

namespace {

int failures = 0;
int checks = 0;
int skipped = 0;

// Set when the generator could not be run at all, so that a second test
// asking the same question does not report it a second time -- as a failure,
// which is what happened before this existed: the corpus comparison skipped
// cleanly and the reproducibility check then failed for the same missing
// interpreter, so a host without python3 got one skip and one failure and the
// pair said two contradictory things about the same condition.
bool generator_unavailable = false;

void check(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

void note(const char* what) {
    std::fprintf(stderr, "SKIP %s\n", what);
    ++skipped;
}

bool is_file(const std::string& path) {
    struct stat st {};
    return ::stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

// Reads a whole file. Returns false when it cannot be opened, which is
// different from opening it and finding it empty: an unreadable seed is a
// failure to report and an empty one is a mismatch.
bool read_file(const std::string& path, std::string& out) {
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (f == nullptr) {
        return false;
    }
    out.clear();
    char buf[4096];
    std::size_t n = 0;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) {
        out.append(buf, n);
    }
    const bool bad = std::ferror(f) != 0;
    std::fclose(f);
    return !bad;
}

// The names in one directory, sorted, so that a failure lists the same two
// names in the same order on every machine. readdir's order is a function of
// the filesystem, and a test whose output reorders itself between runs is a
// test people stop reading.
std::vector<std::string> list_dir(const std::string& path) {
    std::vector<std::string> names;
    DIR* d = ::opendir(path.c_str());
    if (d == nullptr) {
        return names;
    }
    while (const struct dirent* e = ::readdir(d)) {
        const std::string n = e->d_name;
        if (n == "." || n == "..") {
            continue;
        }
        names.push_back(n);
    }
    ::closedir(d);
    std::sort(names.begin(), names.end());
    return names;
}

struct Generated {
    bool ran = false;
    int status = -1;
    std::string out;
    std::string dir;
    // Why it did not run, when it did not. The caller prints this instead of
    // a bare "skipped", because "python3 is missing" and "the generator
    // failed" call for different responses from whoever reads the log.
    std::string why;
};

// Runs the generator into a fresh directory under TMPDIR and returns what it
// printed, which is one line per seed with its size.
//
// The generator is run as "python3 <script> <dir>" rather than as "<script>
// <dir>", and the difference is not a style choice. execv does not read a
// shebang: only the exec family that goes through PATH does, so a test that
// exec'd the script directly would fail to run it on every machine and
// report the same skip every time. Worse, it would fail silently -- the
// script has never carried the executable bit, because the documented way to
// run it is "python3 tools/make_pe_seeds.py", so making the test depend on
// that bit would have meant changing the file to fit the test.
//
// Naming the interpreter also means this test reports "python3 is not
// installed" when that is the truth, instead of reporting a missing file
// that is present.
//
// The three file descriptors are wired before the exec because a child that
// inherited this test's stdout would interleave its output with the failure
// messages above and make both unreadable.
Generated run_generator(const std::string& dest) {
    Generated g;
    g.dir = dest;

    int fds[2] = {-1, -1};
    if (::pipe(fds) != 0) {
        g.why = "a pipe could not be created";
        return g;
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        ::close(fds[0]);
        ::close(fds[1]);
        g.why = "fork failed";
        return g;
    }

    if (pid == 0) {
        ::close(fds[0]);
        if (::dup2(fds[1], 1) < 0) {
            ::_exit(126);
        }
        ::close(fds[1]);
        const std::string script = OCC_SEED_GENERATOR;
        const std::string arg = dest;
        char* argv[] = {const_cast<char*>("python3"),
                        const_cast<char*>(script.c_str()),
                        const_cast<char*>(arg.c_str()), nullptr};
        ::execvp("python3", argv);
        ::_exit(127);
    }

    ::close(fds[1]);
    char buf[4096];
    ssize_t n = 0;
    while ((n = ::read(fds[0], buf, sizeof(buf))) > 0) {
        g.out.append(buf, static_cast<std::size_t>(n));
    }
    ::close(fds[0]);

    int st = 0;
    while (::waitpid(pid, &st, 0) < 0) {
        // EINTR is the only retryable failure here, and retrying on anything
        // else would loop on a condition retrying cannot fix.
    }
    g.status = st;
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
        g.ran = true;
    } else if (WIFEXITED(st) && WEXITSTATUS(st) == 127) {
        g.why = "python3 is not on PATH";
    } else if (WIFEXITED(st)) {
        g.why = "the generator exited " + std::to_string(WEXITSTATUS(st));
    } else {
        g.why = "the generator did not exit normally";
    }
    return g;
}

// Removes a directory tree, so a run that fails partway does not leave seeds
// behind for the next one to trip over. Only ever called on a path this test
// created under TMPDIR.
void remove_tree(const std::string& path) {
    DIR* d = ::opendir(path.c_str());
    if (d != nullptr) {
        while (const struct dirent* e = ::readdir(d)) {
            const std::string n = e->d_name;
            if (n == "." || n == "..") {
                continue;
            }
            remove_tree(path + "/" + n);
        }
        ::closedir(d);
        ::rmdir(path.c_str());
        return;
    }
    ::unlink(path.c_str());
}

std::string unique_dir() {
    const char* tmp = std::getenv("TMPDIR");
    std::string base = (tmp != nullptr && tmp[0] != '\0') ? tmp : "/tmp";
    return base + "/occ-test-seeds-XXXXXX";
}

void test_seeds_match_the_generator() {
    if (!is_file(OCC_SEED_GENERATOR)) {
        // The path came from CMake, so this should not happen. Reporting it
        // as a failure rather than a skip is the point: a misconfigured
        // generator must not be mistaken for an absent interpreter.
        check(false, "seeds: the generator named by the build exists");
        return;
    }

    std::string tmpl = unique_dir();
    // mkdtemp edits its argument, so the buffer has to outlive it and the
    // template has to be writable rather than const.
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    if (::mkdtemp(buf.data()) == nullptr) {
        check(false, "seeds: a temporary directory could be created");
        return;
    }
    const std::string tmp = buf.data();

    const Generated g = run_generator(tmp);
    if (!g.ran) {
        // An interpreter that is not installed is a skip and not a failure:
        // the corpus still exists and the harnesses still run it, and a build
        // machine without Python is a supported thing to be. A generator
        // that ran and failed is neither -- that is a real fault, in the
        // script or in what this test passed it, and it must not be allowed
        // to hide behind the same message.
        remove_tree(tmp);
        if (g.why == "python3 is not on PATH") {
            generator_unavailable = true;
            note("seeds: python3 is not installed, so the corpus was not "
                 "checked against the generator; a seed can drift without "
                 "this test noticing");
            return;
        }
        std::fprintf(stderr, "FAIL seeds: the generator did not run (%s)\n",
                     g.why.c_str());
        ++failures;
        return;
    }
    check(true, "seeds: the generator ran");

    // One direction: every generated file is present and byte-identical.
    const std::vector<std::string> generated = list_dir(tmp);
    check(!generated.empty(), "seeds: the generator produced something");

    for (const std::string& name : generated) {
        std::string want;
        std::string got;
        const bool read_want = read_file(tmp + "/" + name, want);
        const bool read_got = read_file(std::string(OCC_SEED_DIR) + "/" + name,
                                        got);
        if (!read_want || !read_got) {
            std::fprintf(stderr,
                         "FAIL seeds: %s could not be read (generated=%d "
                         "checked in=%d)\n",
                         name.c_str(), static_cast<int>(read_want),
                         static_cast<int>(read_got));
            ++failures;
            continue;
        }
        if (want != got) {
            // Report where, not just that: a length plus the offset of the
            // first difference is enough to tell an off-by-one header field
            // from a wholly different file, which are different mistakes.
            std::size_t i = 0;
            while (i < want.size() && i < got.size() && want[i] == got[i]) {
                ++i;
            }
            std::fprintf(stderr,
                         "FAIL seeds: %s differs at byte %zu (generated %zu "
                         "bytes, checked in %zu bytes)\n",
                         name.c_str(), i, want.size(), got.size());
            ++failures;
            ++checks;
            continue;
        }
        ++checks;
    }

    // The other direction: nothing in the directory the generator does not
    // know about. A hand-added seed is the case this file exists to end, and
    // a test that only walked the generated names could not see one.
    const std::vector<std::string> present = list_dir(OCC_SEED_DIR);
    for (const std::string& name : present) {
        bool known = false;
        for (const std::string& n : generated) {
            if (n == name) {
                known = true;
                break;
            }
        }
        if (!known) {
            std::fprintf(stderr,
                         "FAIL seeds: %s is in the seed directory but the "
                         "generator does not produce it\n",
                         name.c_str());
            ++failures;
        }
    }
    ++checks;

    remove_tree(tmp);
}

// The lines the generator prints, with the directory prefix removed.
//
// It prints one line per seed as "<path>  <size> bytes", and the path
// necessarily contains the directory it was told to write to. Comparing two
// runs' output verbatim would therefore compare two temporary directory
// names, and would fail on a generator that is perfectly deterministic --
// which is the failure this test had on its first run, and the reason the
// comparison below strips the prefix instead of asserting on the whole line.
//
// What is left is "name  size", and that is the claim worth making: the same
// names with the same sizes, which for a generator that writes what it names
// means the same bytes.
std::string listing_without_paths(const std::string& out,
                                  const std::string& dir) {
    std::vector<std::string> lines;
    std::size_t pos = 0;
    while (pos < out.size()) {
        std::size_t nl = out.find('\n', pos);
        if (nl == std::string::npos) {
            nl = out.size();
        }
        std::string line = out.substr(pos, nl - pos);
        pos = nl + 1;

        const std::string prefix = dir + "/";
        if (line.rfind(prefix, 0) == 0) {
            line.erase(0, prefix.size());
        }
        if (!line.empty()) {
            lines.push_back(line);
        }
    }
    std::sort(lines.begin(), lines.end());
    std::string joined;
    for (const std::string& l : lines) {
        joined += l;
        joined.push_back('\n');
    }
    return joined;
}

// The generator has to be usable as a program, not only importable, and this
// is the one thing about it a byte comparison cannot see: that running it
// twice writes the same thing. A generator whose output depended on dict
// ordering or on the clock would pass the comparison above on a machine
// where nothing had changed yet.
void test_the_generator_is_reproducible() {
    std::vector<std::string> dirs;
    bool made = true;
    for (int i = 0; i < 2; ++i) {
        std::string tmpl = unique_dir();
        std::vector<char> buf(tmpl.begin(), tmpl.end());
        buf.push_back('\0');
        if (::mkdtemp(buf.data()) == nullptr) {
            made = false;
            break;
        }
        dirs.emplace_back(buf.data());
    }
    if (!made) {
        check(false, "seeds: two temporary directories could be created");
        return;
    }

    const Generated a = run_generator(dirs[0]);
    const Generated b = run_generator(dirs[1]);
    if (!a.ran || !b.ran) {
        // The corpus comparison already reported a missing interpreter and
        // set this flag; asking again would report the same condition as a
        // failure. Reaching here with the flag unset means the interpreter was
        // there and the generator still did not run, which is a fault.
        for (const std::string& d : dirs) {
            remove_tree(d);
        }
        if (generator_unavailable) {
            return;
        }
        check(false, "seeds: the generator ran twice");
        return;
    }
    check(true, "seeds: the generator ran twice");

    const std::string la = listing_without_paths(a.out, dirs[0]);
    const std::string lb = listing_without_paths(b.out, dirs[1]);
    if (la != lb) {
        std::fprintf(stderr,
                     "FAIL seeds: two runs produced different listings\n"
                     "  first run:\n%s  second run:\n%s",
                     la.c_str(), lb.c_str());
    }
    check(la == lb,
          "seeds: two runs of the generator produce the same names and sizes");

    for (const std::string& d : dirs) {
        remove_tree(d);
    }
}

} // namespace

int main() {
    test_seeds_match_the_generator();
    test_the_generator_is_reproducible();

    std::printf("%d checks, %d failures", checks, failures);
    if (skipped > 0) {
        std::printf(", %d skipped", skipped);
    }
    std::printf("\n");
    return failures == 0 ? 0 : 1;
}

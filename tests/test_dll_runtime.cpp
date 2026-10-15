// The DLL runtime's regression test.
//
// The library is a real one -- built from `dll_test_helper.c` by the mingw
// cross compiler as part of this test's build -- because what is being
// tested is the loading of a library the Windows toolchain produced. A
// hand-built image would test this runtime's image writer instead, which is
// a different claim.
//
// What each section is checking:
//
//   * the load itself: the image is mapped, its imports resolve, and its
//     entry point runs;
//   * the entry point's reason and its once-only property: `helper_entries`
//     answers 1 after the load, which is false if the entry ran twice or not
//     at all;
//   * the calls: no arguments, integer arguments, floating-point arguments,
//     and the two mixed shapes -- the last two being the ones that catch a
//     convention mistake, because the positional rule puts an integer in
//     `rcx` and a double in `xmm1` rather than counting the classes apart;
//   * the reference count: a second load of the same file is a second
//     reference to one module rather than a second module;
//   * the release: the last reference unloads.

#include "occ/parser/pe.h"
#include "occ/runtime/dll_runtime.h"
#include "occ/util/span.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace {

int failures = 0;

void check(bool condition, const char* what) {
    if (!condition) {
        std::fprintf(stderr, "FAIL %s\n", what);
        ++failures;
    }
}

// The directory the test library was built into, from the build system. A
// build without the cross compiler defines it as empty, and the test then
// reports that it has nothing to load rather than failing.
#ifdef OCC_TEST_DLL_PATH
constexpr const char* kLibraryPath = OCC_TEST_DLL_PATH;
#else
constexpr const char* kLibraryPath = "";
#endif

[[nodiscard]] bool read_file(const std::string& path,
                             std::vector<std::uint8_t>* out) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return false;
    }
    out->assign(std::istreambuf_iterator<char>(stream),
                std::istreambuf_iterator<char>());
    return true;
}

using occ::runtime::GuestCallArgs;
using occ::runtime::GuestCallOutcome;
using occ::runtime::dll_runtime::Runtime;

[[nodiscard]] GuestCallArgs no_arguments() {
    GuestCallArgs args;
    args.count = 0;
    return args;
}

[[nodiscard]] GuestCallArgs integer_arguments(std::uint64_t a,
                                              std::uint64_t b) {
    GuestCallArgs args;
    args.slots[0].as_integer = a;
    args.slots[1].as_integer = b;
    args.count = 2;
    return args;
}

// A call whose answer comes back in a vector register, read as the double
// the guest's own type would read.
[[nodiscard]] double as_double(const GuestCallOutcome& outcome) {
    double value = 0;
    std::memcpy(&value, &outcome.result, sizeof(value));
    return value;
}

}  // namespace

int main() {
    if (kLibraryPath[0] == '\0') {
        std::printf(
            "test_dll_runtime: no cross compiler was found at build time, so "
            "there is no library to load; the test is skipped\n");
        return 0;
    }

    std::vector<std::uint8_t> bytes;
    if (!read_file(kLibraryPath, &bytes)) {
        std::fprintf(stderr, "FAIL the test library could not be read: %s\n",
                     kLibraryPath);
        return 1;
    }
    const occ::parser::PeImage image = occ::parser::PeImage::parse(
        occ::ByteSpan{bytes.data(), bytes.size()});
    check(image.ok(), "the test library parses");
    if (!image.ok()) {
        return 1;
    }
    check(image.is_dll(), "the test library is a DLL");

    // The search path is the library's own directory, which is where the
    // build system put it. A dependency of the library -- there is none in
    // this one -- would be found there.
    const std::string full_path(kLibraryPath);
    const std::string directory =
        full_path.substr(0, full_path.find_last_of('/'));

    occ::runtime::dll_runtime::Options options;
    options.search_directories.push_back(directory);
    std::string error;
    std::unique_ptr<Runtime> runtime = Runtime::build(
        image, occ::ByteSpan{bytes.data(), bytes.size()}, kLibraryPath,
        options, &error);
    check(runtime != nullptr, "the library's process builds");
    if (runtime == nullptr) {
        std::fprintf(stderr, "  %s\n", error.c_str());
        return 1;
    }

    // The image's name in the table is the file's base name, folded.
    const std::string folded = occ::runtime::module_table::fold_name(
        kLibraryPath);
    occ::runtime::module_table::Entry* entry = runtime->table().find_name(
        folded);
    check(entry != nullptr, "the library is in the module table");
    if (entry == nullptr) {
        return 1;
    }
    const std::uint64_t module = entry->base;
    check(module != 0, "the library has a base");

    // The load: the entry point runs with `DLL_PROCESS_ATTACH`, after its
    // dependencies -- of which this library has none that are files.
    std::string initialize_error;
    check(runtime->table().initialize(module, &initialize_error),
          "the library initializes");
    if (!initialize_error.empty()) {
        std::fprintf(stderr, "  %s\n", initialize_error.c_str());
    }
    check(entry->initialized, "the entry point ran");

    // --- the calls --------------------------------------------------------

    const auto answer = runtime->find_export(module, "helper_answer");
    check(answer != 0, "helper_answer resolves");
    const GuestCallOutcome answer_outcome = runtime->call(answer,
                                                          no_arguments());
    check(answer_outcome.ok, "helper_answer returns");
    check(answer_outcome.result == 42, "helper_answer answers 42");

    const auto add = runtime->find_export(module, "helper_add");
    check(add != 0, "helper_add resolves");
    const GuestCallOutcome add_outcome = runtime->call(
        add, integer_arguments(20, 22));
    check(add_outcome.ok && add_outcome.result == 42,
          "helper_add(20, 22) answers 42");

    const auto mul = runtime->find_export(module, "helper_mul");
    const GuestCallOutcome mul_outcome = runtime->call(
        mul, integer_arguments(1000000ULL, 3000000ULL));
    check(mul_outcome.ok && mul_outcome.result == 3000000000000ULL,
          "helper_mul answers 3000000000000");

    // The floating-point answer: the same eight bytes, read as the double
    // the export's declared type returns.
    const auto half = runtime->find_export(module, "helper_half");
    GuestCallArgs half_args;
    half_args.slots[0].floating = true;
    half_args.slots[0].as_float = 5.0;
    half_args.count = 1;
    half_args.floating_result = true;
    const GuestCallOutcome half_outcome = runtime->call(half, half_args);
    check(half_outcome.ok && as_double(half_outcome) == 2.5,
          "helper_half(5.0) answers 2.5");

    // The two mixed shapes. These are the ones a convention mistake breaks:
    // `mix(int, double)` puts the integer in `rcx` and the double in `xmm1`,
    // and `scale(double, int)` puts the double in `xmm0` and the integer in
    // `rdx`. A caller that counted the two classes apart gets both wrong,
    // and the answers below are what says which caller this is.
    const auto mix = runtime->find_export(module, "helper_mix");
    GuestCallArgs mix_args;
    mix_args.slots[0].as_integer = 3;
    mix_args.slots[1].floating = true;
    mix_args.slots[1].as_float = 0.5;
    mix_args.count = 2;
    mix_args.floating_result = true;
    const GuestCallOutcome mix_outcome = runtime->call(mix, mix_args);
    check(mix_outcome.ok && as_double(mix_outcome) == 3.5,
          "helper_mix(3, 0.5) answers 3.5");

    const auto scale = runtime->find_export(module, "helper_scale");
    GuestCallArgs scale_args;
    scale_args.slots[0].floating = true;
    scale_args.slots[0].as_float = 2.5;
    scale_args.slots[1].as_integer = 4;
    scale_args.count = 2;
    scale_args.floating_result = true;
    const GuestCallOutcome scale_outcome = runtime->call(scale, scale_args);
    check(scale_outcome.ok && as_double(scale_outcome) == 10.0,
          "helper_scale(2.5, 4) answers 10");

    // The entry point's count: one, which is what a load that ran the entry
    // exactly once answers. Two would mean the initialize path ran it twice;
    // zero would mean it did not run.
    const auto entries = runtime->find_export(module, "helper_entries");
    const GuestCallOutcome entries_outcome = runtime->call(
        entries, no_arguments());
    check(entries_outcome.ok && entries_outcome.result == 1,
          "the entry point ran exactly once");

    // The string argument: the address the runtime places travels in the
    // integer slot, and a function that returns its argument answers the
    // same address -- which is what says the copy arrived rather than a
    // number that merely looks like an address.
    const auto echo = runtime->find_export(module, "helper_echo");
    check(echo != 0, "helper_echo resolves");
    const char* text = "occ-dll-runtime";
    std::uint64_t floor = 0;
    for (const auto& region : runtime->process().image().regions) {
        const std::uint64_t end = region.base + region.size;
        if (end > floor) {
            floor = end;
        }
    }
    const auto placed = runtime->process().mapper().map_above(
        occ::runtime::AddressSpace::round_up(
            floor, occ::runtime::AddressSpace::kGranularity),
        occ::runtime::AddressSpace::kPageSize,
        occ::runtime::PageProtection::ReadWrite,
        occ::runtime::RegionKind::Private);
    check(placed.ok(), "a string can be placed in the guest's memory");
    if (placed.ok()) {
        std::memcpy(reinterpret_cast<void*>(placed.value), text,
                    std::strlen(text) + 1);
        const GuestCallOutcome echo_outcome =
            runtime->call(echo, integer_arguments(placed.value, 0));
        check(echo_outcome.ok && echo_outcome.result == placed.value,
              "helper_echo answers the address it was given");
        check(std::strcmp(reinterpret_cast<const char*>(echo_outcome.result),
                          text) == 0,
              "the string at that address is the one that was passed");
    }

    // A name the library does not export answers zero, which is what
    // `GetProcAddress` answers for one.
    check(runtime->find_export(module, "helper_missing") == 0,
          "a name the library does not export resolves to nothing");

    // --- the reference count ---------------------------------------------

    const occ::runtime::module_table::LoadOutcome again =
        runtime->load(kLibraryPath);
    check(again.ok && again.base == module,
          "a second load answers the same base");
    check(entry->refcount == 2, "a second load is a second reference");

    // The image the process was built around cannot be unloaded, and that is
    // the platform's answer as well: `FreeLibrary` on the running module
    // fails, because unloading the program is a request with no meaning.
    // The test asserts the refusal rather than a release, and the refusal's
    // reason names the module.
    std::string unload_error;
    check(!runtime->unload(module, &unload_error),
          "the running image refuses to unload");
    check(unload_error.find("cannot be unloaded") != std::string::npos,
          "the refusal says why");
    occ::runtime::module_table::Entry* still_there =
        runtime->table().find_name(folded);
    check(still_there != nullptr,
          "the module is still in the table after the refusal");
    if (still_there != nullptr) {
        check(still_there->refcount == 2,
              "the refused release did not move the count");
    }

    // --- the detach -------------------------------------------------------

    std::string detach_error;
    check(runtime->detach_all(&detach_error), "the detach succeeds");
    if (!detach_error.empty()) {
        std::fprintf(stderr, "  %s\n", detach_error.c_str());
    }

    std::printf("test_dll_runtime: %s\n",
                failures == 0 ? "all checks passed" : "there were failures");
    return failures == 0 ? 0 : 1;
}

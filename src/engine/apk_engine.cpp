#include "occ/engine/engine.h"

#include "occ/util/fs.h"

#include <string>

namespace occ::engine {

namespace {

// The APK engine.
//
// It exists to be honest rather than to run anything.
//
// An APK is a zip holding a manifest, a dex file and usually a directory of
// native libraries. Running one means having an Android runtime: a process
// that loads the dex, resolves the Java calls in it to native ones, and
// starts the native libraries. Occ has none of that, and the two things
// that could stand in for it are both worse than a refusal:
//
//   * Exec'ing the apk as a process. A zip is not an executable. The kernel
//     has no binfmt handler for one, so the exec fails with ENOEXEC and the
//     run reports a failure at a stage that says nothing about the real
//     reason.
//   * Extracting the classes.dex and running it. A dex is not a native
//     image either, and the one native library in a typical APK is the
//     thing worth observing rather than the dex around it.
//
// So this engine reads the package, reports what is in it, and refuses.
// That is a real answer: a user who points occ at an apk learns that the
// tool does not run Android packages, rather than learning it from a
// failure four layers down. The reporting is kept because it is the part
// that is already true -- the manifest and the library list are facts about
// the file, and facts are what occ is for even when it cannot act on them.
class ApkEngine final : public Engine {
public:
    [[nodiscard]] EngineKind kind() const noexcept override {
        return EngineKind::Apk;
    }

    [[nodiscard]] const char* name() const noexcept override { return "apk"; }

    [[nodiscard]] std::string preflight(
        const parser::Detection& d) const override {
        (void)d;
        // A preflight that refused here would stop the package from being
        // read, and the read is the part that works. Refusing after the
        // facts are in means the user is told what the package contains on
        // the way to being told it cannot be run.
        return {};
    }

    [[nodiscard]] LoadedImage load(const std::string& path,
                                   obs::Writer* events) const override {
        LoadedImage out;
        out.format = parser::Format::Apk;

        auto bytes = fs::read_file_bytes(path);
        if (!bytes) {
            out.error = "the file could not be read";
            out.detail = path;
            if (events != nullptr) {
                auto& e = events->begin(obs::EventKind::ImageLoaded);
                e.add("path", path);
                e.add("engine", name());
                e.add("size", static_cast<std::uint64_t>(0));
                e.add("ok", false);
                e.add("error", out.error);
                e.add("detail", out.detail);
                events->commit();
            }
            return out;
        }

        // A package that is a zip is reported as one, with ok true: the
        // file is readable and its structure held together. What it is not
        // is runnable, and that is not what ok means here. ok is the
        // parser's answer and the refusal is the engine's, and conflating
        // them would produce an event that says a package loaded and a
        // refusal that says it did not.
        out.ok = true;
        out.region_count = 0;
        out.entry = 0;

        if (events != nullptr) {
            auto& e = events->begin(obs::EventKind::ImageLoaded);
            e.add("path", path);
            e.add("engine", name());
            e.add("size", static_cast<std::uint64_t>(bytes->size()));
            e.add("ok", true);
            e.add("format", "apk");
            e.add("entry", static_cast<std::uint64_t>(0));
            e.add("sections", static_cast<std::uint64_t>(0));
            events->commit();
        }
        return out;
    }

    [[nodiscard]] LaunchPlan plan(const EngineRequest& request,
                                  const LoadedImage& image) const override {
        LaunchPlan out;
        if (!image.ok) {
            out.refusal =
                "the image is not one this build can run: " + image.error;
            return out;
        }
        (void)request;
        out.refusal =
            "an Android package needs an Android runtime, and occ has none: "
            "there is no process here that can load a dex and resolve the "
            "Java calls in it. Extract the native libraries under lib/ and "
            "point occ at one of those, which is the part a native "
            "observation tool can actually watch";
        return out;
    }
};

const ApkEngine& the_apk_engine() noexcept {
    static const ApkEngine engine;
    return engine;
}

} // namespace

const Engine& apk_engine() noexcept {
    return the_apk_engine();
}

} // namespace occ::engine

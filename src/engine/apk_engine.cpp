#include "occ/engine/engine.h"

#include "occ/util/fs.h"

#include <cstdint>
#include <string>
#include <vector>

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
// that is already true -- the member list is a fact about the file, and
// facts are what occ is for even when it cannot act on them.
//
// The reporting is not a formality. The refusal below tells a caller to
// extract the native libraries under lib/ and point occ at one of them, and
// a package whose lib/ directory occ did not name would make that a guess;
// the list is what turns the advice into something the caller can act on
// without opening the archive by hand.
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

        // The members, from the bytes already read.
        //
        // This is the reporting the comment above promises, and it is a
        // re-parse of the buffer in hand rather than a second read of the
        // file: read_zip_members is the same function detection used, so the
        // list here and the list `occ check` prints come from one reading and
        // cannot disagree. Reading the file again to get it would be the
        // alternative, and it would be a second answer to a question already
        // answered.
        std::vector<parser::ZipMemberInfo> members;
        (void)parser::read_zip_members(
            ByteSpan{bytes->data(), bytes->size()}, members);

        if (events != nullptr) {
            {
                auto& e = events->begin(obs::EventKind::ImageLoaded);
                e.add("path", path);
                e.add("engine", name());
                e.add("size", static_cast<std::uint64_t>(bytes->size()));
                e.add("ok", true);
                e.add("format", "apk");
                e.add("entry", static_cast<std::uint64_t>(0));
                e.add("sections", static_cast<std::uint64_t>(0));
                e.add("members", static_cast<std::uint64_t>(members.size()));
                events->commit();
            }

            // The manifest on its own event, then one per native library.
            //
            // Separate events rather than an array on the load, because the
            // stream is line-oriented and a consumer tailing a run can act on
            // a member as it arrives; an array would arrive whole or not at
            // all, which is the property that makes an array the wrong shape
            // for a stream that exists to be watched while it is written.
            //
            // The load is committed before this loop rather than after it
            // because Writer::begin resets the event being built: a loop that
            // began its own events before the load was committed would
            // overwrite the load's body and the run would report a package
            // with no image_loaded event at all. Every other engine commits
            // one event per load, so this is the first place the writer's
            // single-slot shape has to be respected by hand.
            //
            // Bounded by zip_report_members, so a package with thousands of
            // entries does not turn one load into thousands of lines. The
            // count on the load event is the archive's real member count
            // rather than the reported one, so a consumer can tell a short
            // package from a truncated report without comparing against
            // anything.
            const std::vector<parser::ZipMemberInfo> shown =
                parser::zip_report_members(members);
            for (const parser::ZipMemberInfo& m : shown) {
                auto& me = events->begin(obs::EventKind::Note);
                me.add("package_member", m.name);
                me.add("stored", m.stored);
                me.add("uncompressed_size", m.uncompressed_size);
                me.add("compressed_size", m.compressed_size);
                me.add("method", static_cast<std::uint64_t>(
                                     m.compression_method));
                events->commit();
            }

            if (shown.size() < members.size()) {
                auto& ne = events->begin(obs::EventKind::Note);
                ne.add("package_members_omitted",
                       static_cast<std::uint64_t>(members.size() -
                                                  shown.size()));
                ne.add("note",
                       "members that are neither AndroidManifest.xml nor "
                       "under lib/ are not reported; read the archive with a "
                       "zip tool for the full list");
                events->commit();
            }
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

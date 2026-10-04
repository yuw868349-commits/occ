#pragma once

// Engine dispatch.
//
// A parser says what a file is. An engine says what to do about it, and the
// two are separate because they change for different reasons and must not be
// allowed to change together.
//
// The separation also decides where the format-specific knowledge stops.
// An ELF is exec'd directly, so the program is the target and the arguments
// are the caller's. A PE is not exec'd directly: the program is Wine and the
// target becomes the first argument, with a prefix directory and a loader
// path that have to exist before anything runs. An APK is a zip, so running
// one means running something that reads it. Each of those is a different
// answer to "what is the argv of the process this run is about", and the
// honest place to put the answer is a data structure the runner already
// knows how to execute -- not a branch inside the spawn path that has to be
// re-decided for every option the caller can pass.
//
// So an engine produces a LaunchPlan and the runner executes it. Everything
// after the plan is format-independent: the same container, the same
// observer, the same event stream. A format with no engine is refused by
// name rather than attempted, because a run that exec's a file no engine
// understood is a run whose isolation nobody reasoned about.
//
// The division is also what keeps `occ check` and `occ run` from drifting.
// Both go through engine_for(); there is no second table of which format
// goes where, because a second table is a second thing to forget to update.

#include <cstdint>
#include <string>
#include <vector>

#include "occ/isolation/container.h"
#include "occ/observer/event.h"
#include "occ/parser/detect.h"

namespace occ::engine {

// Which engine handles a format. Every ELF goes to the exe engine including
// the ones it will refuse: a target an engine names a reason for is more
// useful than one routed nowhere, and an engine that never sees a file it
// cannot run never gets the chance to explain why.
enum class EngineKind : std::uint8_t {
    Elf, // A Linux executable or shared object, exec'd by the kernel.
    Pe,  // A Windows image, run under Wine.
    Apk, // An Android package.
};

[[nodiscard]] const char* engine_kind_name(EngineKind k) noexcept;

// What an engine learned about a target, in the terms the runner uses.
//
// The reader's own error type is deliberately not carried here. An ELF
// reports parser::LoadError and a PE reports parser::PeError, and a struct
// that held both would be a tagged union pretending to be a flat value.
// What the runner actually needs is the name and the sentence, because that
// is what goes into the event stream and into a refusal a person reads.
struct LoadedImage {
    bool ok = false;
    parser::Format format = parser::Format::Unknown;

    // The reader's name for the failure, and its explanation. Both empty
    // when ok. Named rather than enumerated so that adding a reader does
    // not mean changing this struct, and so that a failure is reportable
    // without every consumer having been taught the new enum.
    std::string error;
    std::string detail;

    // Where execution starts, and how many separately-mapped regions the
    // image asks to be mapped. For an ELF that is e_entry and the PT_LOAD
    // count; for a PE it is the entry's virtual address and the section
    // count. Both are "where the image says to start" and "how many pieces
    // the image is made of", which is the most the runner can use either
    // for.
    std::uint64_t entry = 0;
    std::uint64_t region_count = 0;

    // The address width the image is for, as a bit count: 64 for an ELF64
    // or a PE32+, 32 for the others, and 0 when the reader did not get far
    // enough to know.
    //
    // This is here because an engine cannot recover it later. The choice of
    // loader for a PE depends on it -- a 32-bit image under a 64-bit-only
    // loader fails in the dynamic linker with a message that does not
    // mention bitness -- and re-reading the file to get it would be a
    // second parse whose answer could disagree with the first.
    std::uint32_t address_bits = 0;
};

// One function the engine wants probed, named by symbol rather than by
// address.
//
// By symbol and not by address because the engine cannot resolve an address:
// the library the symbol lives in has not been loaded yet when the plan is
// made, and its load address is a decision the dynamic linker makes per run.
// The engine knows which file the symbol should be in and which symbol it is,
// and the step that turns that into an offset happens after the file is found
// on disk -- which is the same file the loader will map.
struct ProbeRequest {
    // The file the symbol is expected to live in. A bare file name is a
    // search of the loader's path; a path with a slash in it is used as
    // given. The distinction is deliberate and is the caller's to make: a
    // caller that knows the file names it, and a caller that only knows the
    // library names the library.
    std::string module;

    // The symbol to look up in that module's dynamic symbol table.
    std::string symbol;

    // The name the probe is reported under. Distinct from the symbol because
    // a report is read by a person and because the same symbol may be probed
    // at two offsets under two labels.
    std::string label;

    // Why this probe is worth having, for the event that reports it. Empty
    // is allowed.
    std::string note;
};

// What the runner is going to execute.
//
// This is the whole of an engine's effect on the process. The runner builds
// a container from the caller's options plus what the plan adds, and execs
// `program` with `argv`. An engine that wanted a different isolation
// primitive would have to add it here, which is the point: there is one
// place where "what runs" is decided, and it is a value rather than a
// branch.
struct LaunchPlan {
    // The program to exec, and the arguments with argv[0] first. For a
    // direct run these are the target and the caller's argv; for a PE they
    // are the loader and the target among its arguments.
    std::string program;
    std::vector<std::string> argv;

    // Environment entries this engine needs that the caller's options do
    // not produce. Added to the caller's environment rather than replacing
    // it, so a caller who set WINEPREFIX deliberately keeps theirs.
    std::vector<std::string> env;

    // Binds the engine needs mounted into the container. A PE needs the
    // loader's libraries; without them the exec succeeds and the target
    // dies in the dynamic linker, which is a worse report than a refusal.
    std::vector<isolation::ContainerConfig::BindMount> binds;

    // The functions the engine wants observed from inside the target.
    //
    // This is a request rather than an action for the reason the whole plan
    // is: placing a probe means resolving a symbol in a file and writing to
    // tracefs, and both of those can fail in ways that produce a degradation
    // rather than a refusal. The runner places them after the target is
    // running, so that a host without tracefs loses the probes and keeps the
    // syscall-level observation, which is the trade SECURITY.md describes.
    //
    // Empty for an engine whose format needs none, which is every format
    // that runs as itself.
    std::vector<ProbeRequest> probes;

    // The root this run needs, empty when the caller's is right. A PE
    // engine that builds a prefix needs somewhere the prefix can be
    // written, which a read-only bind of the host's root is not.
    std::string root_dir;

    // A directory the engine created that the runner must remove when the
    // run ends. Named rather than left for the engine to clean up, because
    // the engine's plan is made before the run and has no callback into its
    // end: a prefix that outlives its run holds a wineserver's state and
    // the target's own writes, and the next run would inherit both.
    std::string scratch_dir;

    // What the engine could not do, in a form a person reads. Not a
    // failure: a PE engine that found a Wine with no dynamic symbols
    // reports that here and the run continues at a lower resolution. An
    // empty string means the engine did everything it knows how to do.
    std::vector<std::string> degradations;

    // Set when the engine will not proceed. Non-empty means the run stops
    // here and this is the sentence the user gets, so it is a string
    // rather than an error code: a code would have to be translated, and
    // the translation is where the useful part is usually lost.
    std::string refusal;
};

// What an engine is asked to plan. A struct rather than three parameters
// because the third one did not exist when the first two did: an engine
// that keeps state on disk -- a Wine prefix, a directory unpacked into --
// needs somewhere to put it, and the only place that is correct is the
// directory the runner made for this run. Threading a path in is how that
// dependency gets expressed without the engine having to know what a
// session is.
struct EngineRequest {
    // The target, as the caller named it. Not resolved: an engine that
    // wants the resolved path asks fs::absolute_path, so that the fact
    // that resolution happens is visible at the call site rather than
    // assumed.
    std::string path;

    // The caller's argv with the target as argv[0]. An engine that runs
    // something other than the target rewrites this rather than passing it
    // through.
    std::vector<std::string> argv;

    // A directory this run owns, already created, writable, and removed
    // when the run ends. Empty when the caller asked for no scratch space,
    // which an engine that needs some has to refuse rather than invent a
    // location outside the run's own lifetime.
    std::string scratch_dir;
};

// An engine.
//
// Three responsibilities, deliberately separate because they fail
// differently: preflight is a judgement about the detection and costs
// nothing, load reads the file and can fail on its contents, and plan
// decides the process. A caller that wants to know whether a target is
// runnable does not have to read it to find out.
class Engine {
public:
    virtual ~Engine() = default;

    // Identity. `name` is the word that appears in a refusal and in
    // `occ check`'s engine column, so it is a stable lowercase token
    // rather than something derived from the class name.
    [[nodiscard]] virtual EngineKind kind() const noexcept = 0;
    [[nodiscard]] virtual const char* name() const noexcept = 0;

    // Why this engine will not run this target, from the detection alone,
    // or an empty string meaning it will try. Empty is not "yes": it means
    // the detection raised nothing, and reading the file may still find
    // something. The distinction is why a refusal can be reported before
    // the file is read.
    [[nodiscard]] virtual std::string preflight(
        const parser::Detection& d) const = 0;

    // Reads the target and reports it. Writes the image_loaded event and
    // whatever the format's own geometry produces -- mapping events for an
    // ELF, section events for a PE -- in the order a reader would learn
    // them. A file that cannot be read is reported the same way a file that
    // cannot be parsed is, with ok false and a reason.
    //
    // Const because an engine has no state to change: everything it learns
    // comes back in the LoadedImage, which is what makes one engine usable
    // from two places in the same run -- a caller that inspects and then
    // runs gets two independent reads rather than a cached one that could
    // be stale.
    [[nodiscard]] virtual LoadedImage load(const std::string& path,
                                           obs::Writer* events) const = 0;

    // Decides the process. Called only after a successful load, and free to
    // refuse anyway: a target can parse and still be unrunnable, which is
    // the normal case for a PE on a host with no Wine.
    [[nodiscard]] virtual LaunchPlan plan(const EngineRequest& request,
                                          const LoadedImage& image) const = 0;
};

// The engine for a format, or nullptr when nothing in this build handles
// it. Never returns an engine for a format the engine would only refuse
// without reading -- preflight exists to answer that, and routing those
// away here would make the refusal generic.
[[nodiscard]] const Engine* engine_for(parser::Format f) noexcept;

// The engine for a detection, by the same rule. A convenience for the
// callers that already have one.
[[nodiscard]] const Engine* engine_for(const parser::Detection& d) noexcept;

// The engines, for a caller that wants to enumerate rather than dispatch --
// `occ check` reporting what this build can run is the case. The order is
// the declaration order and is stable.
[[nodiscard]] const std::vector<const Engine*>& engines() noexcept;

[[nodiscard]] const Engine& elf_engine() noexcept;
[[nodiscard]] const Engine& pe_engine() noexcept;
[[nodiscard]] const Engine& apk_engine() noexcept;

} // namespace occ::engine

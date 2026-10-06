#pragma once

// The runner for Windows images, in-process.
//
// `occ run` of a PE does not fork a loader somebody else wrote. The engine's
// plan names this binary -- `/proc/self/exe`, found without a PATH search --
// with `__pe-runner` as the first argument, and the container exec's it. What
// comes up on the other side of the exec is occ again, inside the container's
// namespaces, dispatching here: it builds an `ExportRegistry` whose modules
// are the host implementations in `runtime/winabi`, builds a `PeProcess`
// whose imports resolve through that registry, and jumps into the image with
// `run_pe_process`. The process that returns from that call is the guest's
// exit, and the runner ends with it.
//
// The re-exec is what buys the isolation and the exit, in one move. The
// container can seal the filesystem and enter the namespaces around a process
// it exec's, which it cannot do around a jump inside its own; and a guest
// that trashes its own stack, registers or GS base trashes a process that
// was started for it, rather than the process the caller is sitting in. The
// exec is the boundary between "the tool" and "the thing the tool runs", and
// everything about the design depends on it being a real one.

namespace occ::runner {

// The token argv[1] carries when occ re-execs itself to run a PE. Leading
// underscores because it must never collide with a real command a caller
// could type, and because `occ __pe-runner ...` is not a command anyone is
// meant to run by hand.
inline constexpr char kPeRunnerCommand[] = "__pe-runner";

// The program exec'd with it: this binary itself, named without a PATH
// search. A PATH search would find a different `occ` if one was installed,
// and a runner that is a different binary than the planner is a runner whose
// registry nobody audited.
inline constexpr char kPeRunnerProgram[] = "/proc/self/exe";

// Runs the image named by `argv[1]` with `argv[2..]` as its arguments, and
// ends the process with the image's own exit code. Diagnostics go to stderr;
// nothing here writes the event stream, because the parent's observer owns
// that.
[[nodiscard]] int run_pe_runner(int argc, char** argv) noexcept;

} // namespace occ::runner

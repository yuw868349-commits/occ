// Writing a minidump of the guest, and reading one back.
//
// The dump is a real MDMP file -- the format Windows' own debuggers, the
// WER pipeline and every crash-analysis tool read -- built by hand in this
// file: the header, the stream directory, the module list, the thread list
// with a CONTEXT at a stop, the exception record when the stop was a
// fault, the memory ranges, and the system information. No library stands
// behind it, which is the rule everything in this runtime keeps.
//
// The reader is the same file's other half, and it is deliberately more
// than a convenience: a writer whose only check is its own writer's
// opinion cannot distinguish "wrote a dump" from "wrote bytes that look
// like a dump to the code that wrote them". Reading the file back through
// an independent parse -- header to directory to stream to field -- is
// the round trip that makes the write mean something, and `summarize` is
// the command form of that check.

#ifndef OCC_RUNTIME_MINIDUMP_H_
#define OCC_RUNTIME_MINIDUMP_H_

#include <cstdint>
#include <string>

namespace occ::runtime::minidump {

// Whether the run asks for a dump, and where. `OCC_MINIDUMP` names the
// file; like the other switches it reaches the runner through the
// environment the command passes on.
[[nodiscard]] bool enabled() noexcept;
[[nodiscard]] std::string path() noexcept;

// The registers a dump's CONTEXT carries, as the caller saw them. Either
// a fault handler's ucontext copy or a debugger stop's snapshot -- the
// indices are the gregs order in both.
struct Context {
    std::uint64_t regs[23] = {};
    bool valid = false;
};

// Writes the dump. `image_base` and `image_size` name the guest's module;
// `stack_base`/`stack_bytes` name the region of the guest's stack to
// carry (the context's rsp answers at a fault); `exception_code` and
// `exception_address` are the Windows-side exception when the dump is
// taken at a fault, and `code == 0` writes a dump with no exception
// stream -- a live-state dump rather than a crash dump.
[[nodiscard]] bool write(const std::string& out_path,
                         std::uint64_t image_base, std::uint64_t image_size,
                         const Context& context, std::uint32_t exception_code,
                         std::uint64_t exception_address,
                         const char* module_path) noexcept;

// Reads a dump back and prints what it holds: the header's fields, each
// stream, the module list, the exception record, and the memory ranges.
// False when the file is not a dump this reader accepts, with the reason
// printed -- the same honesty the writer's caller gets.
[[nodiscard]] bool summarize(const std::string& in_path) noexcept;

}  // namespace occ::runtime::minidump

#endif  // OCC_RUNTIME_MINIDUMP_H_

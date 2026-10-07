// The x64 structured-exception machinery the guest's own runtime expects.
//
// A throw inside the guest is not an emulation problem: the guest is native
// code in this address space, and its `RaiseException` call arrives as an
// ordinary host call with the guest's real frames below it on the real
// stack. What Windows would then do -- find each caller's unwind
// information in the image's own `.pdata`, ask each language handler
// whether it will handle the exception, and eventually resume in the frame
// that said yes -- is what this file does, against the guest's tables and
// with the guest's handlers as calls back into guest code.
//
// The CONTEXT layout is the Windows x64 one, written as offsets into a
// 1232-byte buffer exactly as `pe_process` writes one. The unwinding
// follows the format the ABI documents: the `.pdata` entries are sorted,
// the unwind codes within an `UNWIND_INFO` are sorted by prolog offset in
// descending order, and unwinding reverses each code the control point
// actually reached -- the pops restoring what the pushes saved, the
// allocations added back, and the return address read from where the
// caller's `call` left it.
//
// The three semantics this file must not improvise are the ones every
// debugger, every runtime and every personality routine agrees on:
// `EstablisherFrame` is the RSP of the frame whose handler is called, the
// language handler that decides to handle the exception initiates its own
// `RtlUnwindEx` and does not return, and the unwind walk ends by restoring
// the saved context with `Rip` at the handler's chosen target.

#ifndef OCC_RUNTIME_SEH_H_
#define OCC_RUNTIME_SEH_H_

#include <cstddef>
#include <cstdint>

namespace occ::runtime::seh {

// The Windows x64 CONTEXT, as offsets into a 1232-byte buffer. Shared with
// `pe_process`, which writes one from the kernel's ucontext on the fault
// path; this layer writes and reads them on the raise-and-unwind path.
constexpr std::size_t kContextSize = 0x4D0;  // 1232 bytes
static_assert(kContextSize % 16 == 0,
              "the CONTEXT must fill whole 16-byte rows");

constexpr std::uint32_t kContextAmd64 = 0x100000u;
// The flag set `RtlCaptureContext` writes: the architecture bit plus the
// control, integer, floating-point and xstate sections.
constexpr std::uint32_t kContextFull =
    kContextAmd64 | 0x1u | 0x2u | 0x4u | 0x8u;

constexpr std::size_t kContextFlags = 0x30;
constexpr std::size_t kContextMxCsr = 0x34;
constexpr std::size_t kContextSegCs = 0x38;
constexpr std::size_t kContextSegDs = 0x3A;
constexpr std::size_t kContextSegEs = 0x3C;
constexpr std::size_t kContextSegFs = 0x3E;
constexpr std::size_t kContextSegGs = 0x40;
constexpr std::size_t kContextSegSs = 0x42;
constexpr std::size_t kContextEFlags = 0x44;
constexpr std::size_t kContextRax = 0x78;
constexpr std::size_t kContextRcx = 0x80;
constexpr std::size_t kContextRdx = 0x88;
constexpr std::size_t kContextRbx = 0x90;
constexpr std::size_t kContextRsp = 0x98;
constexpr std::size_t kContextRbp = 0xA0;
constexpr std::size_t kContextRsi = 0xA8;
constexpr std::size_t kContextRdi = 0xB0;
constexpr std::size_t kContextR8 = 0xB8;
constexpr std::size_t kContextR9 = 0xC0;
constexpr std::size_t kContextR10 = 0xC8;
constexpr std::size_t kContextR11 = 0xD0;
constexpr std::size_t kContextR12 = 0xD8;
constexpr std::size_t kContextR13 = 0xE0;
constexpr std::size_t kContextR14 = 0xE8;
constexpr std::size_t kContextR15 = 0xF0;
constexpr std::size_t kContextRip = 0xF8;
constexpr std::size_t kContextFltSave = 0x100;  // XSAVE_FORMAT, 512 bytes

// The two EXCEPTION_RECORD fields the walk itself reads or writes: the
// flags at 0x04, which the unwind pass raises, and the code at 0x00, which
// a filter-driven unwind passes on as the landing pad's return value.
constexpr std::size_t kRecordCode = 0x00;
constexpr std::size_t kRecordFlags = 0x04;
// The record is 152 bytes: four u32 fields, a pointer, and fifteen
// parameter slots. Only `c_specific_handler`'s callers need the whole
// shape; the walk touches the two fields above.
constexpr std::size_t kRecordSize = 152;

// The unwind flags an UNWIND_INFO or a walk type can carry. The walk type
// says which handlers the walk wants: the search pass asks the exception
// handlers, the unwind pass asks the termination handlers.
constexpr std::uint32_t kUnwFlagNHandler = 0x0u;
constexpr std::uint32_t kUnwFlagEHandler = 0x1u;
constexpr std::uint32_t kUnwFlagUHandler = 0x2u;
constexpr std::uint32_t kUnwFlagChainInfo = 0x4u;

// The EXCEPTION_RECORD flags the two passes distinguish by.
constexpr std::uint32_t kExceptionNoncontinuable = 0x1u;
constexpr std::uint32_t kExceptionUnwinding = 0x2u;
constexpr std::uint32_t kExceptionExitUnwind = 0x4u;
constexpr std::uint32_t kExceptionTargetUnwind = 0x20u;

// The EXCEPTION_DISPOSITION values a language handler returns.
constexpr std::uint64_t kExceptionContinueExecution = 0;
constexpr std::uint64_t kExceptionContinueSearch = 1;
constexpr std::uint64_t kExceptionNestedException = 2;
constexpr std::uint64_t kExceptionCollidedUnwind = 3;

// The filter verdicts __C_specific_handler's scopes carry and return.
constexpr std::int32_t kExceptionContinueSearchFilter = 0;
constexpr std::int32_t kExceptionExecuteHandler = 1;
constexpr std::int32_t kExceptionContinueExecutionFilter = -1;

// The DISPATCHER_CONTEXT fields a handler writes back: the scope index,
// which `__C_specific_handler` advances so a `__finally` that itself
// raises is not run twice.
constexpr std::size_t kDispatcherScopeIndex = 0x48;

// The .pdata entry: the code range and the RVA of its UNWIND_INFO. The
// layout is the format's own, and a pointer to one is handed to guest
// handlers inside the dispatcher context, so the fields are laid out
// exactly and not accessed through offsets.
struct FunctionEntry {
    std::uint32_t begin_rva = 0;
    std::uint32_t end_rva = 0;
    std::uint32_t unwind_rva = 0;
};
static_assert(sizeof(FunctionEntry) == 12,
              "RUNTIME_FUNCTION layout drifted");

// The dispatcher context a language handler reads. Field for field the
// Windows shape -- ControlPc, ImageBase, FunctionEntry, EstablisherFrame,
// TargetIp, ContextRecord, LanguageHandler, HandlerData, HistoryTable,
// ScopeIndex, FillResult -- because the guest's personality routines walk
// these fields by their own definitions, so the layout is the interface
// and the static_asserts are the proof.
struct DispatcherContext {
    std::uint64_t control_pc = 0;
    std::uint64_t image_base = 0;
    const FunctionEntry* function_entry = nullptr;
    std::uint64_t establisher_frame = 0;
    std::uint64_t target_ip = 0;
    const void* context_record = nullptr;
    std::uint64_t language_handler = 0;
    const void* handler_data = nullptr;
    const void* history_table = nullptr;
    std::uint32_t scope_index = 0;
    std::uint32_t fill_result = 0;
};
static_assert(offsetof(DispatcherContext, target_ip) == 0x20,
              "DISPATCHER_CONTEXT layout drifted");
static_assert(offsetof(DispatcherContext, context_record) == 0x28,
              "DISPATCHER_CONTEXT layout drifted");
static_assert(offsetof(DispatcherContext, scope_index) == 0x48,
              "DISPATCHER_CONTEXT layout drifted");
static_assert(sizeof(DispatcherContext) == 0x50,
              "DISPATCHER_CONTEXT layout drifted");

// Looks a control point up in the image's `.pdata` table. The table holds
// RUNTIME_FUNCTIONs sorted by begin RVA; the answer is the table's own row
// for the pc -- chains not followed, which is the `RtlLookupFunctionEntry`
// contract -- or nullptr when the pc is in no entry: a leaf function, or a
// pc outside the image.
const FunctionEntry* find_function_entry(std::uint64_t image_base,
                                         const std::uint8_t* pdata,
                                         std::size_t pdata_bytes,
                                         std::uint64_t pc) noexcept;

// The same lookup with chained entries followed to their destination: the
// row the unwind walk itself needs, since a chain names the entry whose
// codes describe the prolog the pc belongs to. A chain that cycles is a
// corrupt table and gets nullptr rather than a loop.
const FunctionEntry* lookup_function_entry(std::uint64_t image_base,
                                           const std::uint8_t* pdata,
                                           std::size_t pdata_bytes,
                                           std::uint64_t pc) noexcept;

// Reverses one frame. The context comes in as the state at the control
// point and goes out as the state the caller of that frame would have seen
// -- the registers the prolog saved restored from their slots, the stack
// pointer past the return address, and `Rip` on the return address itself.
//
// `type` selects which handlers count: a search pass asks for
// `kUnwFlagEHandler`, an unwind pass for `kUnwFlagUHandler`. `frame_out`
// answers the establisher frame -- the RSP the frame runs its body with,
// which is what a handler's locals are addressed relative to.
// `data_out` answers the handler's own data (the scope table a language
// handler reads), and `handler_out` the handler's address, zero when the
// frame carries none this pass should call -- which includes a control
// point inside the prolog, where the format answers no handler.
//
// False means the table was bad in a way the format does not allow; the
// caller treats that as a frame with no handler rather than as a reason to
// guess.
bool virtual_unwind(std::uint32_t type, std::uint64_t image_base,
                    std::uint64_t pc, const FunctionEntry* entry,
                    std::uint8_t* context, const void** data_out,
                    std::uint64_t* frame_out,
                    std::uint64_t* handler_out) noexcept;

// The search pass. Walks the frames from the control point upward, calling
// each frame's language handler the way Windows calls it -- the original
// context as the handler's `context` argument, the frame's own state
// described by the dispatcher context -- and returns true when one of them
// answered EXCEPTION_CONTINUE_EXECUTION: the caller resumes the walk's
// original context. A handler that decides to handle initiates its own
// unwind and never returns at all, so the only other way out is every
// frame declining or the walk leaving the stack, and that is the false
// this function returns -- the shape an unhandled exception takes.
bool dispatch(std::uint8_t* record, const std::uint8_t* context,
              const std::uint8_t* pdata, std::size_t pdata_bytes,
              std::uint64_t image_base, std::uint64_t image_end,
              std::uint64_t stack_low, std::uint64_t stack_high) noexcept;

// The unwind pass. Runs the termination handlers from the frame the
// context names up to `end_frame`, marking the record with the target
// flag as it arrives, and then restores `context` with `Rip` at
// `target_ip` and `Rax` at `retval`. Does not return. The context is the
// state at the exception point -- what the dispatcher context's context
// record holds -- and the walk stays on the guest's frames between it and
// the target. A zero `end_frame` marks an exit unwind, which has no
// target flag to raise; zero stack bounds ask the walk to run unbounded,
// which is what the handler-initiated unwinds inside `c_specific_handler`
// do, the frames they cross having been vetted by the pass that found
// them.
[[noreturn]] void unwind_ex(std::uint64_t end_frame, std::uint64_t target_ip,
                            std::uint8_t* record, std::uint64_t retval,
                            std::uint8_t* context, std::uint64_t image_base,
                            std::uint64_t image_end,
                            const std::uint8_t* pdata,
                            std::size_t pdata_bytes, std::uint64_t stack_low,
                            std::uint64_t stack_high) noexcept;

// Captures the caller's registers into a CONTEXT, exactly as the Windows
// call captures the caller of itself: `Rsp` pointing at the return address
// and `Rip` holding it. The buffer must be 16-byte aligned -- the
// `fxsave` the Windows call performs requires it, and so does ours.
// `extern "C"` because the raise stub reaches it through its own `call`,
// which names the symbol the way the assembler spells it.
extern "C" __attribute__((ms_abi)) void seh_capture_context(
    std::uint8_t* out) noexcept;

// Restores a captured CONTEXT and resumes at its `Rip`. Does not return.
extern "C" __attribute__((ms_abi, noreturn)) void seh_restore_context(
    const std::uint8_t* context) noexcept;

// The guest-facing `RtlUnwindEx`, the call a guest's own language handler
// makes once it has decided to handle: the walk from the caller's frame to
// `end_frame`, the termination handlers on the way, and the restore at
// `target_ip`. The bounds and the table come from the guest state this
// runtime keeps, so the arguments are the Windows call's own six.
extern "C" __attribute__((ms_abi, noreturn)) void seh_RtlUnwindEx(
    void* end_frame, void* target_ip, void* record, void* retval,
    void* context, void* history_table) noexcept;

// `__C_specific_handler`, the scope-table walker a guest compiled with
// `__try` reaches through msvcrt. Field for field Wine's reading of the
// Microsoft contract: the search pass runs each scope's filter and starts
// the unwind to the scope whose filter accepted; the unwind pass runs each
// `__finally` whose range held the control point, advancing the
// dispatcher's scope index so a `__finally` that itself raises is not run
// twice, and stops before the `__finally` the target ip lands in.
extern "C" __attribute__((ms_abi)) std::uint64_t seh_C_specific_handler(
    const void* record, void* establisher_frame, const void* context,
    void* dispatcher) noexcept;

}  // namespace occ::runtime::seh

#endif  // OCC_RUNTIME_SEH_H_

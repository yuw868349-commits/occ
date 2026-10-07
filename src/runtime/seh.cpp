// The structured-exception walk, written against the guest's tables.
//
// The reference for every decision here is the ABI's own contract plus the
// behaviour all implementations of this format agree on. The `.pdata`
// lookup is a binary search over sorted entries; the unwind reverses the
// prolog's stack effects in the order the codes are stored -- descending
// by prolog offset, so the last effect the prolog produced is the first
// undone -- and the two passes of dispatch are as every language handler
// assumes them: the search pass calls each handler with the original
// context, a handler that decides to handle initiates its own unwind and
// never returns, and the unwind walk ends by restoring the saved context
// with `Rip` at the handler's own chosen landing point.
//
// What is deliberately not here: epilogue interpretation. A control point
// inside an epilogue is a pc whose prolog the format says was fully
// executed, and reversing the recorded prolog still answers the right
// caller for it. The guest code this runtime runs raises and faults in
// function bodies; if that changes, the epilogue shape test belongs
// beside the prolog test, not in place of it.

#include "occ/runtime/seh.h"

#include <cstring>

#include <cstdlib>
#include <signal.h>

#include "occ/runtime/winabi.h"

namespace occ::runtime::seh {

namespace {

// The first four bytes of an UNWIND_INFO: the version (low three bits),
// the flags (next five), the prolog length in bytes, and the code count in
// *slots* -- an odd count carries one padding slot before the handler
// data.
struct UnwindHeader {
    std::uint8_t byte0;
    std::uint8_t prolog;
    std::uint8_t count;
    std::uint8_t frame_bits;  // low 4: frame register, high 4: offset / 16
};

constexpr std::uint8_t kVersionMask = 0x07;
constexpr std::uint8_t kFlagsMask = 0xF8;
constexpr std::uint8_t kFlagsShift = 3;
constexpr std::uint8_t kFrameRegMask = 0x0F;
constexpr std::uint8_t kFrameOffsetShift = 4;

// The opcodes, and the encoding size of each in slots -- the step the code
// walk takes after reading one.
constexpr std::uint8_t kUwopPushNonvol = 0;
constexpr std::uint8_t kUwopAllocLarge = 1;
constexpr std::uint8_t kUwopAllocSmall = 2;
constexpr std::uint8_t kUwopSetFpreg = 3;
constexpr std::uint8_t kUwopSaveNonvol = 4;
constexpr std::uint8_t kUwopSaveNonvolFar = 5;
constexpr std::uint8_t kUwopEpilog = 6;
constexpr std::uint8_t kUwopSaveXmm128 = 8;
constexpr std::uint8_t kUwopSaveXmm128Far = 9;
constexpr std::uint8_t kUwopPushMachframe = 10;

std::uint8_t opcode_code(std::uint8_t slot) noexcept {
    return static_cast<std::uint8_t>(slot & 0x0F);
}

std::uint8_t opcode_info(std::uint8_t slot) noexcept {
    return static_cast<std::uint8_t>(slot >> 4);
}

std::size_t opcode_size(std::uint8_t slot) noexcept {
    switch (opcode_code(slot)) {
    case kUwopAllocLarge:
        return opcode_info(slot) != 0 ? 3 : 2;
    case kUwopSaveNonvol:
    case kUwopSaveXmm128:
        return 2;
    case kUwopSaveNonvolFar:
    case kUwopSaveXmm128Far:
        return 3;
    default:
        return 1;
    }
}

// A code's payload, read from the slot pair that follows the pair the code
// itself occupies: the pair at slot `i` holds the prolog offset and the
// opcode, and the payload starts at slot `i + 1`.
std::uint16_t payload_u16(const std::uint8_t* codes, std::size_t i) noexcept {
    std::uint16_t value = 0;
    std::memcpy(&value, codes + (i + 1) * 2, sizeof(value));
    return value;
}

std::uint32_t payload_u32(const std::uint8_t* codes, std::size_t i) noexcept {
    std::uint32_t value = 0;
    std::memcpy(&value, codes + (i + 1) * 2, sizeof(value));
    return value;
}

void set_int_reg(std::uint8_t* context, std::size_t offset,
                 std::uint64_t value) noexcept {
    std::memcpy(context + offset, &value, sizeof(value));
}

std::uint64_t get_int_reg(const std::uint8_t* context,
                          std::size_t offset) noexcept {
    std::uint64_t value = 0;
    std::memcpy(&value, context + offset, sizeof(value));
    return value;
}

void set_xmm_reg(std::uint8_t* context, int reg, const void* source) noexcept {
    std::memcpy(context + kContextFltSave + 0xA0 +
                    static_cast<std::size_t>(reg) * 16,
                source, 16);
}

std::uint64_t load_u64(const void* address) noexcept {
    std::uint64_t value = 0;
    std::memcpy(&value, address, sizeof(value));
    return value;
}

std::uint32_t get_u32(const std::uint8_t* base, std::size_t offset) noexcept {
    std::uint32_t value = 0;
    std::memcpy(&value, base + offset, sizeof(value));
    return value;
}

void put_u32(std::uint8_t* base, std::size_t offset,
             std::uint32_t value) noexcept {
    std::memcpy(base + offset, &value, sizeof(value));
}

void put_u64(std::uint8_t* base, std::size_t offset,
             std::uint64_t value) noexcept {
    std::memcpy(base + offset, &value, sizeof(value));
}

std::size_t int_reg_offset(std::uint8_t reg) noexcept {
    return kContextRax + static_cast<std::size_t>(reg) * 8;
}

// The handler data that follows the code slots: a chained entry, or the
// handler RVA with the bytes the handler reads after it.
const std::uint8_t* handler_data_slot(const std::uint8_t* info,
                                      std::size_t count) noexcept {
    return info + 4 + ((count + 1) & ~static_cast<std::size_t>(1)) * 2;
}

// The dispatcher context, as the guest's handlers read it. Built fresh for
// each frame the walk calls into; the field order is the one the mingw
// headers spell, with the image base second, and the scope index reset --
// the index a handler writes back belongs to the frame that wrote it.
void fill_dispatcher(std::uint8_t* dc, std::uint64_t control_pc,
                     std::uint64_t image_base, const FunctionEntry* entry,
                     std::uint64_t frame, std::uint64_t target_ip,
                     const void* context_record, std::uint64_t handler,
                     const void* handler_data) noexcept {
    std::memcpy(dc + 0x00, &control_pc, sizeof(control_pc));
    std::memcpy(dc + 0x08, &image_base, sizeof(image_base));
    std::memcpy(dc + 0x10, &entry, sizeof(entry));
    std::memcpy(dc + 0x18, &frame, sizeof(frame));
    std::memcpy(dc + 0x20, &target_ip, sizeof(target_ip));
    std::memcpy(dc + 0x28, &context_record, sizeof(context_record));
    std::memcpy(dc + 0x30, &handler, sizeof(handler));
    std::memcpy(dc + 0x38, &handler_data, sizeof(handler_data));
    static const void* kNoHistory = nullptr;
    std::memcpy(dc + 0x40, &kNoHistory, sizeof(kNoHistory));
    static const std::uint32_t kZeroScope = 0;
    std::memcpy(dc + 0x48, &kZeroScope, sizeof(kZeroScope));
    static const std::uint32_t kZeroFill = 0;
    std::memcpy(dc + 0x4C, &kZeroFill, sizeof(kZeroFill));
}

using GuestHandlerFn = std::uint64_t(__attribute__((ms_abi))*)(
    const void* record, std::uint64_t frame, const void* context,
    const void* dispatcher);

}  // namespace

// The table's own row for the pc, chains left alone: the contract
// `RtlLookupFunctionEntry` documents, and the shape a caller that wants
// to read a row's chain flag for itself needs.
const FunctionEntry* find_function_entry(std::uint64_t image_base,
                                         const std::uint8_t* pdata,
                                         std::size_t pdata_bytes,
                                         std::uint64_t pc) noexcept {
    if (pdata == nullptr || pdata_bytes < sizeof(FunctionEntry)) {
        return nullptr;
    }
    if (pc < image_base || pc - image_base > 0xFFFFFFFFULL) {
        return nullptr;
    }
    const std::uint32_t rva = static_cast<std::uint32_t>(pc - image_base);
    const auto* table = reinterpret_cast<const FunctionEntry*>(pdata);
    std::size_t low = 0;
    std::size_t high = pdata_bytes / sizeof(FunctionEntry);
    while (low < high) {
        const std::size_t mid = low + (high - low) / 2;
        if (rva < table[mid].begin_rva) {
            high = mid;
        } else if (rva >= table[mid].end_rva) {
            low = mid + 1;
        } else {
            return &table[mid];
        }
    }
    return nullptr;
}

const FunctionEntry* lookup_function_entry(std::uint64_t image_base,
                                           const std::uint8_t* pdata,
                                           std::size_t pdata_bytes,
                                           std::uint64_t pc) noexcept {
    const FunctionEntry* found =
        find_function_entry(image_base, pdata, pdata_bytes, pc);
    // A chained entry carries the chain flag in the low bit of its unwind
    // RVA and names another entry by byte offset. The format keeps this
    // for functions the assembler split into pieces; the walk follows it
    // at most a bounded number of times, because a chain that cycles is a
    // corrupt table and a corrupt table gets no second chance to loop the
    // runtime.
    for (int steps = 0; found != nullptr && (found->unwind_rva & 1) != 0;
         ++steps) {
        if (steps > 8) {
            return nullptr;
        }
        found = reinterpret_cast<const FunctionEntry*>(
            pdata + (found->unwind_rva & ~1u));
    }
    return found;
}

bool virtual_unwind(std::uint32_t type, std::uint64_t image_base,
                    std::uint64_t pc, const FunctionEntry* entry,
                    std::uint8_t* context, const void** data_out,
                    std::uint64_t* frame_out,
                    std::uint64_t* handler_out) noexcept {
    // The establisher frame starts as the RSP the frame runs its body
    // with. A frame register, when the info records one, replaces it: the
    // register holds a fixed anchor, and the recorded offset is the
    // anchor's distance below the value the `lea` saw.
    std::uint64_t frame = get_int_reg(context, kContextRsp);
    *frame_out = frame;
    if (handler_out != nullptr) {
        *handler_out = 0;
    }
    if (data_out != nullptr) {
        *data_out = nullptr;
    }

    if (entry == nullptr) {
        // A leaf function: no prolog, no saves. The caller's state is the
        // return address the `call` pushed and the stack above it.
        const std::uint64_t rsp = get_int_reg(context, kContextRsp);
        set_int_reg(context, kContextRip,
                    load_u64(reinterpret_cast<const void*>(rsp)));
        set_int_reg(context, kContextRsp, rsp + 8);
        return true;
    }

    // A chained entry names the entry whose codes finish describing the
    // prolog; each round of the loop reverses one piece. The step cap is
    // the same defence the lookup applies: a chain that cycles is a
    // corrupt table, and the answer is failure rather than a loop.
    bool mach_frame = false;
    for (int steps = 0;; ++steps) {
        if (steps > 8) {
            return false;
        }
        const std::uint8_t* info =
            reinterpret_cast<const std::uint8_t*>(image_base +
                                                  (entry->unwind_rva & ~1u));
        UnwindHeader header{};
        std::memcpy(&header, info, sizeof(header));
        const std::uint32_t version = header.byte0 & kVersionMask;
        const std::uint32_t flags =
            (header.byte0 & kFlagsMask) >> kFlagsShift;
        if (version != 1 && version != 2) {
            return false;
        }

        if ((header.frame_bits & kFrameRegMask) != 0) {
            frame = get_int_reg(context, int_reg_offset(header.frame_bits &
                                                        kFrameRegMask)) -
                    static_cast<std::uint64_t>(
                        (header.frame_bits & 0xF0) >> kFrameOffsetShift) * 16;
        }

        // How far into the prolog the control point sits. A pc in the body
        // -- the common case -- reverses every code; a pc inside the
        // prolog reverses only the codes the prolog reached, which is the
        // offset comparison the format encodes.
        std::uint32_t prolog_offset = ~0u;
        const std::uint64_t begin = image_base + entry->begin_rva;
        if (pc >= begin && pc < begin + header.prolog) {
            prolog_offset = static_cast<std::uint32_t>(pc - begin);
        }

        const std::uint8_t* codes = info + 4;
        for (std::size_t i = 0; i < header.count;) {
            // The walk counts in slot pairs, the encoding's own unit: the
            // first byte of a pair is the prolog offset, the second is the
            // opcode and its info nibble, and the payload pairs follow.
            const std::uint8_t offset = codes[i * 2];
            const std::uint8_t slot = codes[i * 2 + 1];
            // The codes are stored by prolog offset in descending order,
            // and one whose offset is past the control point names an
            // effect the prolog had not produced yet -- skipped, not
            // reversed.
            if (prolog_offset != ~0u && prolog_offset < offset) {
                i += opcode_size(slot);
                continue;
            }

            switch (opcode_code(slot)) {
            case kUwopPushNonvol: {
                // Undo the push. The value it saved sits where the stack
                // pointer is now, because this is the most recent of the
                // stack effects still to be undone.
                const std::uint64_t rsp = get_int_reg(context, kContextRsp);
                set_int_reg(context, int_reg_offset(opcode_info(slot)),
                            load_u64(reinterpret_cast<const void*>(rsp)));
                set_int_reg(context, kContextRsp, rsp + 8);
                break;
            }
            case kUwopAllocLarge: {
                const std::uint64_t bytes =
                    opcode_info(slot) != 0
                        ? payload_u32(codes, i)
                        : static_cast<std::uint64_t>(payload_u16(codes, i)) *
                              8;
                set_int_reg(context, kContextRsp,
                            get_int_reg(context, kContextRsp) + bytes);
                break;
            }
            case kUwopAllocSmall:
                set_int_reg(context, kContextRsp,
                            get_int_reg(context, kContextRsp) +
                                static_cast<std::uint64_t>(
                                    opcode_info(slot) + 1) * 8);
                break;
            case kUwopSetFpreg: {
                // The `lea` that established the anchor did not move the
                // stack pointer, but undoing it restores the pointer to
                // where the anchor says it was when the anchor was taken.
                set_int_reg(context, kContextRsp, frame);
                *frame_out = frame;
                break;
            }
            case kUwopSaveNonvol: {
                const std::uint64_t slot_va =
                    frame + static_cast<std::uint64_t>(
                                payload_u16(codes, i)) * 8;
                set_int_reg(context, int_reg_offset(opcode_info(slot)),
                            load_u64(reinterpret_cast<const void*>(slot_va)));
                break;
            }
            case kUwopSaveNonvolFar: {
                const std::uint64_t slot_va = frame + payload_u32(codes, i);
                set_int_reg(context, int_reg_offset(opcode_info(slot)),
                            load_u64(reinterpret_cast<const void*>(slot_va)));
                break;
            }
            case kUwopSaveXmm128: {
                const std::uint64_t slot_va =
                    frame + static_cast<std::uint64_t>(
                                payload_u16(codes, i)) * 16;
                set_xmm_reg(context, opcode_info(slot),
                            reinterpret_cast<const void*>(slot_va));
                break;
            }
            case kUwopSaveXmm128Far: {
                const std::uint64_t slot_va = frame + payload_u32(codes, i);
                set_xmm_reg(context, opcode_info(slot),
                            reinterpret_cast<const void*>(slot_va));
                break;
            }
            case kUwopPushMachframe: {
                // The frame a signal delivery pushed, reversed the way the
                // format records it: the error-code slot when the info bit
                // says one was pushed, then the machine frame's own return
                // address and saved state.
                if (opcode_info(slot) != 0) {
                    set_int_reg(context, kContextRsp,
                                get_int_reg(context, kContextRsp) + 8);
                }
                const std::uint64_t rsp = get_int_reg(context, kContextRsp);
                set_int_reg(context, kContextRip,
                            load_u64(reinterpret_cast<const void*>(rsp)));
                set_int_reg(
                    context, kContextRsp,
                    load_u64(reinterpret_cast<const void*>(rsp + 24)));
                mach_frame = true;
                break;
            }
            default:
                // An epilogue marker, or an opcode this runtime has no
                // business reversing: the recorded effects so far stand,
                // and the walk continues with them.
                break;
            }
            i += opcode_size(slot);
        }

        if (!mach_frame) {
            // Every effect is undone; what the stack pointer now points at
            // is the return address the caller's `call` left. A machine
            // frame carried its own return address, and the walk takes it
            // rather than popping again.
            const std::uint64_t rsp = get_int_reg(context, kContextRsp);
            set_int_reg(context, kContextRip,
                        load_u64(reinterpret_cast<const void*>(rsp)));
            set_int_reg(context, kContextRsp, rsp + 8);
        }

        if ((flags & kUnwFlagChainInfo) == 0) {
            if (handler_out != nullptr && (flags & type) != 0 &&
                prolog_offset == ~0u) {
                const std::uint8_t* data =
                    handler_data_slot(info, header.count);
                std::uint32_t handler_rva = 0;
                std::memcpy(&handler_rva, data, sizeof(handler_rva));
                *handler_out = image_base + handler_rva;
                if (data_out != nullptr) {
                    *data_out = data + sizeof(handler_rva);
                }
            }
            return true;
        }

        // A chained entry: the pieces reversed so far belong to the tail
        // of a function whose real prolog is described elsewhere. The
        // chain names the next entry in place, which is the format's own
        // instruction.
        const std::uint8_t* data = handler_data_slot(info, header.count);
        entry = reinterpret_cast<const FunctionEntry*>(data);
    }
}

bool dispatch(std::uint8_t* record, const std::uint8_t* context,
              const std::uint8_t* pdata, std::size_t pdata_bytes,
              std::uint64_t image_base, std::uint64_t image_end,
              std::uint64_t stack_low, std::uint64_t stack_high) noexcept {
    alignas(16) std::uint8_t walked[kContextSize];
    std::memcpy(walked, context, kContextSize);
    alignas(16) std::uint8_t dispatcher[sizeof(DispatcherContext)];

    for (;;) {
        const std::uint64_t pc = get_int_reg(walked, kContextRip);
        const FunctionEntry* entry =
            lookup_function_entry(image_base, pdata, pdata_bytes, pc);
        const void* handler_data = nullptr;
        std::uint64_t frame = 0;
        std::uint64_t handler = 0;
        if (!virtual_unwind(kUnwFlagEHandler, image_base, pc, entry, walked,
                            &handler_data, &frame, &handler)) {
            return false;
        }
        if (frame < stack_low || frame >= stack_high) {
            // A frame outside the stack this run owns is a walked-off
            // table, not a caller; stopping here reports the same thing
            // Windows reports for a stack the walk could not trust.
            return false;
        }
        if (handler != 0) {
            if (handler < image_base || handler >= image_end) {
                // A handler address the image does not hold is a corrupt
                // table's jump, and the walk does not take it.
                return false;
            }
            fill_dispatcher(dispatcher, pc, image_base, entry, frame, 0,
                            context, handler, handler_data);
            const auto tell = reinterpret_cast<GuestHandlerFn>(handler);
            const std::uint64_t verdict =
                tell(record, frame, context, dispatcher);
            if (verdict == kExceptionContinueExecution) {
                // The handler declined to unwind and asked to run on. The
                // caller resumes the context the walk started with, which
                // is why the walk copied it instead of walking it in
                // place.
                return true;
            }
            if (verdict != kExceptionContinueSearch) {
                // A nested exception or a collided unwind asks for
                // machinery this walk does not carry; both arrive as a
                // verdict that cannot be honoured, which leaves the
                // exception as unhandled as a walk that ran off the
                // stack.
                return false;
            }
        }
        if (get_int_reg(walked, kContextRsp) >= stack_high) {
            return false;
        }
    }
}

[[noreturn]] void unwind_ex(std::uint64_t end_frame, std::uint64_t target_ip,
                            std::uint8_t* record, std::uint64_t retval,
                            std::uint8_t* context, std::uint64_t image_base,
                            std::uint64_t image_end,
                            const std::uint8_t* pdata,
                            std::size_t pdata_bytes, std::uint64_t stack_low,
                            std::uint64_t stack_high) noexcept {
    // The walk starts from the context the caller handed in -- the state
    // at the exception point, which is what the dispatcher context's
    // context record holds. Windows' own unwind captures its caller's
    // registers here and walks the whole real stack, host frames included;
    // every frame it crosses carries unwind info there. This walk reads
    // the guest's `.pdata` only, so it stays on the guest's frames from
    // the exception point to the target, and the context is revised frame
    // by frame the way the Windows walk revises its own.
    alignas(16) std::uint8_t walked[kContextSize];
    std::memcpy(walked, context, kContextSize);
    alignas(16) std::uint8_t dispatcher[sizeof(DispatcherContext)];
    alignas(16) std::uint8_t made[kRecordSize];

    if (record == nullptr) {
        // STATUS_UNWIND: the record an unwind without an exception
        // carries, addressed where the unwind itself was called from.
        std::memset(made, 0, sizeof(made));
        put_u32(made, kRecordCode, 0xC0000027u);
        put_u64(made, 0x10, get_int_reg(context, kContextRip));
        record = made;
    }

    // The record is marked unwinding for the whole pass, and a walk that
    // was given no target frame is an exit unwind -- the shape a runtime
    // hands back when the target died before the walk reached it.
    put_u32(record, kRecordFlags,
            get_u32(record, kRecordFlags) | kExceptionUnwinding |
                (end_frame != 0 ? 0u : kExceptionExitUnwind));

    // The bounds the walk trusts. A handler-initiated unwind passes zeros
    // -- the frames it crosses were vetted by the pass that found them --
    // and the checks below stand down for them.
    const bool bounded = stack_high != 0;

    for (;;) {
        const std::uint64_t pc = get_int_reg(walked, kContextRip);
        const FunctionEntry* entry =
            lookup_function_entry(image_base, pdata, pdata_bytes, pc);
        const void* handler_data = nullptr;
        std::uint64_t frame = 0;
        std::uint64_t handler = 0;
        if (!virtual_unwind(kUnwFlagUHandler, image_base, pc, entry, walked,
                            &handler_data, &frame, &handler)) {
            break;
        }
        if (bounded && (frame < stack_low || frame >= stack_high)) {
            break;
        }
        if (end_frame != 0 && frame == end_frame) {
            put_u32(record, kRecordFlags,
                    get_u32(record, kRecordFlags) | kExceptionTargetUnwind);
        }
        if (handler != 0) {
            if (image_end != 0 &&
                (handler < image_base || handler >= image_end)) {
                break;
            }
            fill_dispatcher(dispatcher, pc, image_base, entry, frame,
                            target_ip, context, handler, handler_data);
            const auto tell = reinterpret_cast<GuestHandlerFn>(handler);
            const std::uint64_t verdict =
                tell(record, frame, context, dispatcher);
            // A termination handler answers ExceptionContinueSearch, or
            // it initiates its own unwind and does not return. The
            // collided-unwind handshake this format reserves for nested
            // unwinds is machinery no current guest path reaches, and a
            // verdict this walk does not carry ends it the same way a
            // corrupt table does: at the target.
            (void)verdict;
        }
        if (end_frame != 0 && frame == end_frame) {
            break;
        }
        if (bounded && get_int_reg(walked, kContextRsp) >= stack_high) {
            break;
        }
        std::memcpy(context, walked, kContextSize);
    }

    set_int_reg(context, kContextRax, retval);
    set_int_reg(context, kContextRip, target_ip);
    seh_restore_context(context);
}

// The capture, spelled the way the ABI's own capture is spelled: the
// register file as the *caller* of this function holds it, the stack
// pointer pointing at the return address, and `Rip` holding that address.
// The buffer arrives in %rcx -- the Microsoft ABI's first argument, which
// is the convention the guest's own `RtlCaptureContext` import follows --
// and the routine keeps no prolog of its own, which is what leaves every
// non-volatile register still belonging to the caller.
__attribute__((naked)) void seh_capture_context(
    std::uint8_t*) noexcept {
    __asm__(
        "pushfq\n\t"
        "movl $0x10000f, 0x30(%rcx)\n\t"
        "stmxcsr 0x34(%rcx)\n\t"
        "movw %cs, 0x38(%rcx)\n\t"
        "movw %ds, 0x3a(%rcx)\n\t"
        "movw %es, 0x3c(%rcx)\n\t"
        "movw %fs, 0x3e(%rcx)\n\t"
        "movw %gs, 0x40(%rcx)\n\t"
        "movw %ss, 0x42(%rcx)\n\t"
        "popq 0x44(%rcx)\n\t"
        "movq %rax, 0x78(%rcx)\n\t"
        "movq %rcx, 0x80(%rcx)\n\t"
        "movq %rdx, 0x88(%rcx)\n\t"
        "movq %rbx, 0x90(%rcx)\n\t"
        "leaq 8(%rsp), %rax\n\t"
        "movq %rax, 0x98(%rcx)\n\t"
        "movq %rbp, 0xa0(%rcx)\n\t"
        "movq %rsi, 0xa8(%rcx)\n\t"
        "movq %rdi, 0xb0(%rcx)\n\t"
        "movq %r8, 0xb8(%rcx)\n\t"
        "movq %r9, 0xc0(%rcx)\n\t"
        "movq %r10, 0xc8(%rcx)\n\t"
        "movq %r11, 0xd0(%rcx)\n\t"
        "movq %r12, 0xd8(%rcx)\n\t"
        "movq %r13, 0xe0(%rcx)\n\t"
        "movq %r14, 0xe8(%rcx)\n\t"
        "movq %r15, 0xf0(%rcx)\n\t"
        "movq (%rsp), %rax\n\t"
        "movq %rax, 0xf8(%rcx)\n\t"
        "fxsave 0x100(%rcx)\n\t"
        "ret\n\t");
}

// The restore, which hands the machine back to the buffer's state and
// jumps: every general register comes off the buffer, the rip and rsp
// riding through %xmm0 and %xmm1 because both general registers the jump
// itself needs are restored first, and the jump lands on `Rip` without
// writing so much as a slot of the stack it arrives at. Volatile state
// beyond the xmm file is not restored, which is its contract -- nothing
// after a control transfer may assume it.
__attribute__((naked, noreturn)) void seh_restore_context(
    const std::uint8_t*) noexcept {
    __asm__(
        "ldmxcsr 0x34(%rcx)\n\t"
        "fxrstor 0x100(%rcx)\n\t"
        "movq 0xf8(%rcx), %r10\n\t"
        "movq 0x98(%rcx), %r11\n\t"
        "movq %r10, %xmm0\n\t"
        "movq %r11, %xmm1\n\t"
        "movq 0x78(%rcx), %rax\n\t"
        "movq 0x88(%rcx), %rdx\n\t"
        "movq 0x90(%rcx), %rbx\n\t"
        "movq 0xa0(%rcx), %rbp\n\t"
        "movq 0xa8(%rcx), %rsi\n\t"
        "movq 0xb0(%rcx), %rdi\n\t"
        "movq 0xb8(%rcx), %r8\n\t"
        "movq 0xc0(%rcx), %r9\n\t"
        "movq 0xc8(%rcx), %r10\n\t"
        "movq 0xd0(%rcx), %r11\n\t"
        "movq 0xd8(%rcx), %r12\n\t"
        "movq 0xe0(%rcx), %r13\n\t"
        "movq 0xe8(%rcx), %r14\n\t"
        "movq 0xf0(%rcx), %r15\n\t"
        "movq 0x80(%rcx), %rcx\n\t"
        "movq %xmm0, %r10\n\t"          // the rip comes back off its ferry
        "movq %xmm1, %rsp\n\t"
        "jmp *%r10\n\t");
}

// The scope table the C language handler reads, in the layout its data
// carries: a count, then records of four RVAs each.
struct ScopeTable {
    std::uint32_t count;
    struct Record {
        std::uint32_t begin_rva;
        std::uint32_t end_rva;
        std::uint32_t handler_rva;
        std::uint32_t jump_rva;
    };
    Record record[1];  // the format's own trailing array, count entries long
};

// The C language handler, under the name the guest's own C code imports
// from msvcrt. The search pass asks each enclosing scope's filter; a
// filter that accepts initiates the unwind to that scope's jump target and
// this call never returns. The unwind pass runs the termination handlers
// -- the `__finally` blocks -- in the order the scopes nest, advancing the
// dispatcher's scope index before each call so a `__finally` that itself
// raises does not meet the same scope twice, and stopping before the
// scope the target lands in, which the unwinder's own jump enters.
extern "C" __attribute__((ms_abi)) std::uint64_t seh_C_specific_handler(
    const void* record, void* establisher_frame, const void* context,
    void* dispatcher) noexcept {
    const auto* rec = static_cast<const std::uint8_t*>(record);
    auto* disp = static_cast<std::uint8_t*>(dispatcher);
    if (rec == nullptr || disp == nullptr) {
        return kExceptionContinueSearch;
    }
    const DispatcherContext& dc =
        *reinterpret_cast<const DispatcherContext*>(disp);
    const auto* table = static_cast<const ScopeTable*>(dc.handler_data);
    if (table == nullptr) {
        return kExceptionContinueSearch;
    }

    const std::uint64_t base = dc.image_base;
    const std::uint64_t pc = dc.control_pc;
    const std::uint32_t flags = get_u32(rec, kRecordFlags);
    const std::uint64_t rva = pc - base;
    // The guest state carries the bounds and the table the unwind this
    // handler starts will need; without a guest there is no walk to
    // start, and the search answering "not handled" is the whole of what
    // is left to say.
    winabi::GuestState* guest = winabi::guest_state();

    using FilterFn = std::int32_t(__attribute__((ms_abi))*)(
        const void* pointers, std::uint64_t frame);
    using TerminationFn = void(__attribute__((ms_abi))*)(std::uint8_t flag,
                                                         std::uint64_t frame);

    if ((flags & (kExceptionUnwinding | kExceptionExitUnwind)) != 0) {
        for (std::uint32_t i = dc.scope_index; i < table->count; ++i) {
            const ScopeTable::Record& scope = table->record[i];
            if (rva < scope.begin_rva || rva >= scope.end_rva) {
                continue;
            }
            // A scope with a jump target is an `except`; the unwind pass
            // has no reason to touch it. What the unwind runs is the
            // `finally` -- the scope with no jump target at all.
            if (scope.jump_rva != 0) {
                continue;
            }
            if ((flags & kExceptionTargetUnwind) != 0 && dc.target_ip != 0) {
                const std::uint64_t target_rva = dc.target_ip - base;
                if (target_rva >= scope.begin_rva &&
                    target_rva < scope.end_rva) {
                    break;  // the target scope's own landing: stop calling
                }
            }
            // The index advances before the call, for the reason the pass
            // description gives.
            const std::uint32_t next = i + 1;
            std::memcpy(disp + kDispatcherScopeIndex, &next, sizeof(next));
            const auto termination =
                reinterpret_cast<TerminationFn>(base + scope.handler_rva);
            termination(1, reinterpret_cast<std::uint64_t>(establisher_frame));
        }
        return kExceptionContinueSearch;
    }

    for (std::uint32_t i = dc.scope_index; i < table->count; ++i) {
        const ScopeTable::Record& scope = table->record[i];
        if (rva < scope.begin_rva || rva >= scope.end_rva) {
            continue;
        }
        if (scope.jump_rva == 0) {
            continue;
        }
        if (scope.handler_rva != static_cast<std::uint32_t>(
                                     kExceptionExecuteHandler)) {
            // A real filter. EXCEPTION_EXECUTE_HANDLER as an *address* is
            // the format's own shorthand for "accept unconditionally" --
            // the value 1 is not a callable address, and the format gives
            // it that meaning.
            alignas(8) const void* pointers[2] = {record, context};
            const auto filter =
                reinterpret_cast<FilterFn>(base + scope.handler_rva);
            const std::int32_t verdict =
                filter(pointers, reinterpret_cast<std::uint64_t>(
                                     establisher_frame));
            if (verdict == kExceptionContinueSearchFilter) {
                continue;
            }
            if (verdict != kExceptionExecuteHandler) {
                return kExceptionContinueExecution;
            }
        }
        if (guest == nullptr) {
            return kExceptionContinueSearch;
        }
        // Accepted. The unwind to the jump target runs from inside this
        // call -- the unwind pass calls this handler back for the
        // `finally` scopes -- and does not return here. The value the
        // landing sees is the exception's own code, which is what the
        // format's handler hands its unwind.
        unwind_ex(reinterpret_cast<std::uint64_t>(establisher_frame),
                  base + scope.jump_rva,
                  const_cast<std::uint8_t*>(rec),
                  get_u32(rec, kRecordCode),
                  const_cast<std::uint8_t*>(
                      static_cast<const std::uint8_t*>(dc.context_record)),
                  base, guest->image_end,
                  reinterpret_cast<const std::uint8_t*>(guest->pdata_va),
                  guest->pdata_bytes, guest->stack_low, guest->stack_high);
    }
    return kExceptionContinueSearch;
}

// The guest-facing `RtlUnwindEx`, defined here so the registry and the
// walk share one spelling. The guest's own personality routines call it --
// a language handler that decided to handle starts its unwind from
// inside -- so the bounds come from the guest state, and the signal mask
// a fault blocked is restored first: a guest that catches the exception
// must be able to fault again. Does not return.
extern "C" __attribute__((ms_abi, noreturn)) void seh_RtlUnwindEx(
    void* end_frame, void* target_ip, void* record, void* retval,
    void* context, void* history_table) noexcept {
    (void)history_table;
    winabi::GuestState* guest = winabi::guest_state();
    if (guest == nullptr) {
        // No guest, no walk; a caller that reached here without one has
        // already left the state this runtime keeps, and there is nothing
        // to unwind into.
        ::abort();
    }
    if (guest->resume_mask_valid) {
        ::sigset_t mask;
        std::memcpy(&mask, guest->resume_mask, sizeof(mask));
        ::sigprocmask(SIG_SETMASK, &mask, nullptr);
        guest->resume_mask_valid = false;
    }
    unwind_ex(reinterpret_cast<std::uint64_t>(end_frame),
              reinterpret_cast<std::uint64_t>(target_ip),
              static_cast<std::uint8_t*>(record),
              reinterpret_cast<std::uint64_t>(retval),
              static_cast<std::uint8_t*>(context), guest->image_base,
              guest->image_end,
              reinterpret_cast<const std::uint8_t*>(guest->pdata_va),
              static_cast<std::size_t>(guest->pdata_bytes),
              guest->stack_low, guest->stack_high);
}

}  // namespace occ::runtime::seh

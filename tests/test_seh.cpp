// Structured-exception walk tests.
//
// The walk is a reading of the guest's own tables, so the fixtures below
// are the tables themselves: `.pdata` rows and UNWIND_INFO bytes spelled
// by hand, the way a linker lays them out, and a stack built to match.
// Each case pins one part of the contract a personality routine assumes --
// the binary search, the chained rows, the reversal order of the unwind
// codes, the prolog-offset skip, the frame-register anchoring, the
// handler the dispatcher context carries -- and the round trip of the
// capture and restore that ends every unwind.

#include "occ/runtime/seh.h"

#include "occ/runtime/winabi.h"

#include <csetjmp>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace occ;
using namespace occ::runtime;

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

void put32(std::uint8_t* b, std::size_t off, std::uint32_t v) {
    std::memcpy(b + off, &v, sizeof(v));
}

void put64(std::uint8_t* b, std::size_t off, std::uint64_t v) {
    std::memcpy(b + off, &v, sizeof(v));
}

std::uint64_t get64(const std::uint8_t* b, std::size_t off) {
    std::uint64_t v = 0;
    std::memcpy(&v, b + off, sizeof(v));
    return v;
}

// A UNWIND_INFO under construction: the four header bytes and the code
// slots, in the descending-offset order the format stores them.
struct UnwindInfoBytes {
    std::vector<std::uint8_t> bytes;

    UnwindInfoBytes(std::uint32_t flags, std::uint8_t prolog,
                    std::uint8_t frame_reg, std::uint8_t frame_offset) {
        bytes.push_back(static_cast<std::uint8_t>(0x01 | (flags << 3)));
        bytes.push_back(prolog);
        bytes.push_back(0);  // the count, filled in by the codes below
        bytes.push_back(static_cast<std::uint8_t>((frame_offset << 4) |
                                                  frame_reg));
    }

    // One code: the offset byte, the opcode and info byte, then however
    // many payload slots the opcode carries. The header's count is the
    // slot total, which is what the format counts.
    void code(std::uint8_t offset, std::uint8_t opcode, std::uint8_t info,
              std::uint16_t payload = 0, bool has_payload = false) {
        bytes.push_back(offset);
        bytes.push_back(static_cast<std::uint8_t>((info << 4) | opcode));
        if (has_payload) {
            bytes.push_back(static_cast<std::uint8_t>(payload & 0xFF));
            bytes.push_back(static_cast<std::uint8_t>(payload >> 8));
        }
        bytes[2] = static_cast<std::uint8_t>((bytes.size() - 4) / 2);
    }
};

// The unwind fixtures place their tables in static storage and pick an
// image base just below them, which is what makes the RVAs inside the
// tables real addresses: the walk reads the info through the base, and a
// base the buffers do not belong to would be reading nothing.
struct TableFixture {
    alignas(16) std::uint8_t info[16] = {};
    alignas(8) std::uint8_t pdata[12] = {};
    std::uint64_t base = 0;
    std::uint64_t pc = 0;

    // Rows the pc at 0x1050 into, with the info at 0x1000.
    void place(const std::vector<std::uint8_t>& info_bytes) {
        for (std::size_t i = 0; i < info_bytes.size() && i < sizeof(info);
             ++i) {
            info[i] = info_bytes[i];
        }
        base = reinterpret_cast<std::uint64_t>(info) - 0x1000;
        put32(pdata, 0, 0x1000);
        put32(pdata, 4, 0x1100);
        put32(pdata, 8, 0x1000);
        pc = base + 0x1050;
    }

    // The range the walk bounds its reads by. The fixture's info buffer is
    // where its rows point, so that is the section: the same relationship
    // a real image has between `.pdata` and `.xdata`, spelled with one
    // buffer instead of two sections.
    seh::UnwindRange xdata() const {
        return seh::UnwindRange{reinterpret_cast<std::uint64_t>(info),
                                sizeof(info)};
    }

    // The row the fixture's pc lands in, as the walk looks it up.
    const seh::FunctionEntry* entry() const {
        return seh::lookup_function_entry(base, pdata, sizeof(pdata), pc);
    }
};

// ---------------------------------------------------------------- lookup

void test_lookup_finds_the_row_holding_the_pc() {
    alignas(8) std::uint8_t table[3 * 12];
    put32(table, 0, 0x1000);
    put32(table, 4, 0x1100);
    put32(table, 8, 0x40);
    put32(table, 12, 0x2000);
    put32(table, 16, 0x2100);
    put32(table, 20, 0x50);
    put32(table, 24, 0x3000);
    put32(table, 28, 0x3100);
    put32(table, 32, 0x60);
    const std::uint64_t base = 0x140000000ULL;

    const auto* mid = seh::lookup_function_entry(base, table, sizeof(table),
                                                 base + 0x2050);
    check(mid != nullptr && mid->begin_rva == 0x2000,
          "the binary search lands on the row whose range holds the pc");
    const auto* last = seh::lookup_function_entry(base, table, sizeof(table),
                                                  base + 0x30FF);
    check(last != nullptr && last->begin_rva == 0x3000,
          "the pc just below a row's end belongs to that row");
    check(seh::lookup_function_entry(base, table, sizeof(table),
                                     base + 0x1150) == nullptr,
          "a pc between rows is in no row");
    check(seh::lookup_function_entry(base, table, sizeof(table),
                                     base + 0x3100) == nullptr,
          "a pc at the table's end is outside it");
}

void test_lookup_follows_the_chain() {
    // Row one carries the chain flag in the low bit of its unwind RVA and
    // names row two by byte offset; the answer is row two's own info.
    alignas(8) std::uint8_t table[2 * 12];
    put32(table, 0, 0x1000);
    put32(table, 4, 0x1100);
    put32(table, 8, 12 | 1);  // chained, pointing at the second row
    put32(table, 12, 0x1000);
    put32(table, 16, 0x1100);
    put32(table, 20, 0x776);  // even: the row the chain lands on is plain
    const std::uint64_t base = 0x140000000ULL;
    const auto* chained =
        seh::lookup_function_entry(base, table, sizeof(table), base + 0x1050);
    check(chained != nullptr && chained->unwind_rva == 0x776,
          "a chained row answers with the row it names");
}

void test_lookup_rejects_a_chain_that_leaves_the_table() {
    // A row whose chain offset names a byte past the table's last entry:
    // following it would read whatever this process holds beyond the
    // caller's buffer, so the lookup answers nullptr instead. The offset
    // is the row's own guest byte, and a table crafted to carry one is
    // the case this bound exists for.
    alignas(8) std::uint8_t table[2 * 12];
    put32(table, 0, 0x1000);
    put32(table, 4, 0x1100);
    put32(table, 8, 0x40 | 1);  // chained, 0x40 bytes past a 24-byte table
    put32(table, 12, 0x2000);
    put32(table, 16, 0x2100);
    put32(table, 20, 0x776);
    const std::uint64_t base = 0x140000000ULL;
    check(seh::lookup_function_entry(base, table, sizeof(table),
                                     base + 0x1050) == nullptr,
          "a chain past the end of the table is refused");

    // The offset exactly one entry's worth short of the end is the last
    // row the table holds, and reading it is what the bound must still
    // allow: the check is a range, not a blanket refusal.
    put32(table, 8, 12 | 1);
    const auto* last = seh::lookup_function_entry(
        base, table, sizeof(table), base + 0x1050);
    check(last != nullptr && last->unwind_rva == 0x776,
          "the last row the table holds is still reachable by chain");
}

// --------------------------------------------------------- the reversal

void test_leaf_unwind_pops_the_return_address() {
    alignas(16) std::uint8_t context[seh::kContextSize];
    std::memset(context, 0, sizeof(context));
    alignas(8) std::uint8_t stack[64];
    std::memset(stack, 0, sizeof(stack));
    const std::uint64_t return_address = 0x140001000ULL;
    const std::uint64_t rsp = reinterpret_cast<std::uint64_t>(stack) + 32;
    put64(stack, 32, return_address);
    put64(context, seh::kContextRsp, rsp);

    const void* data = nullptr;
    std::uint64_t frame = 0;
    std::uint64_t handler = 0;
    const bool ok =
        seh::virtual_unwind(seh::kUnwFlagEHandler, 0x140000000ULL,
                            0x140000FFFULL, nullptr, context,
                            seh::UnwindRange{}, 0, 0, &data, &frame,
                            &handler);
    check(ok, "a leaf unwinds without a table row");
    check(get64(context, seh::kContextRip) == return_address,
          "the leaf's caller is the address the call pushed");
    check(get64(context, seh::kContextRsp) == rsp + 8,
          "the leaf's caller's stack pointer is past the return address");
    check(frame == rsp && handler == 0,
          "a leaf carries no handler and frames itself at its own rsp");
}

void test_leaf_unwind_refuses_a_stack_pointer_off_the_stack() {
    // A context whose Rsp the guest set past the top of the stack this run
    // owns. The address is a real one -- the buffer's own memory -- so the
    // bounded reversal refuses it by the range rather than by faulting,
    // while the unbounded shape the handler-initiated unwinds use reads it
    // as it always would.
    alignas(16) std::uint8_t context[seh::kContextSize];
    std::memset(context, 0, sizeof(context));
    alignas(8) std::uint8_t stack[256];
    std::memset(stack, 0, sizeof(stack));
    const std::uint64_t stack_base = reinterpret_cast<std::uint64_t>(stack);
    const std::uint64_t return_address = 0x140001000ULL;
    // The return address sits at +128, inside the buffer but past the
    // 64-byte span the bound below hands the walk.
    put64(stack, 128, return_address);
    put64(context, seh::kContextRsp, stack_base + 128);

    const void* data = nullptr;
    std::uint64_t frame = 0;
    std::uint64_t handler = 0;
    const bool ok =
        seh::virtual_unwind(seh::kUnwFlagEHandler, 0x140000000ULL,
                            0x140000FFFULL, nullptr, context,
                            seh::UnwindRange{}, stack_base, stack_base + 64,
                            &data, &frame, &handler);
    check(!ok, "a leaf whose rsp is past the stack's top is refused");

    // A zero-high range is the handler-initiated shape: no check at all,
    // and the same rsp reads the return address it names.
    std::memset(context, 0, sizeof(context));
    put64(context, seh::kContextRsp, stack_base + 128);
    const bool unbounded =
        seh::virtual_unwind(seh::kUnwFlagEHandler, 0x140000000ULL,
                            0x140000FFFULL, nullptr, context,
                            seh::UnwindRange{}, 0, 0, &data, &frame,
                            &handler);
    check(unbounded && get64(context, seh::kContextRip) == return_address,
          "a zero-high range stands the stack check down");
}

void test_body_unwind_refuses_a_row_pointing_outside_xdata() {
    // A row whose `unwind_rva` names an address the `.xdata` section does
    // not hold. Reading the header there would fault or read a stranger's
    // bytes; the range turns it into the false that ends the walk.
    TableFixture fixture;
    UnwindInfoBytes info(0, 7, 0, 0);
    info.code(0, 0, 5);  // PUSH_NONVOL rbp
    fixture.place(info.bytes);
    // The fixture's row points at 0x1000, inside its info buffer. A row
    // rewritten to point a megabyte further on is the crafted case.
    put32(fixture.pdata, 8, 0x100000);

    alignas(16) std::uint8_t context[seh::kContextSize];
    std::memset(context, 0, sizeof(context));
    put64(context, seh::kContextRsp,
          reinterpret_cast<std::uint64_t>(&context));

    const void* data = nullptr;
    std::uint64_t frame = 0;
    std::uint64_t handler = 0;
    const bool ok = seh::virtual_unwind(
        seh::kUnwFlagEHandler, fixture.base, fixture.pc, fixture.entry(),
        context, fixture.xdata(), 0, 0, &data, &frame, &handler);
    check(!ok, "a row pointing outside .xdata is refused");
}

void test_unwind_stops_when_the_code_count_overruns_the_section() {
    // A header claiming far more code slots than the section holds. The
    // reversal applies what it can read and stops at the edge rather than
    // walking out of the section: the count is one guest byte, and a
    // crafted header sets it to anything.
    TableFixture fixture;
    UnwindInfoBytes info(0, 7, 0, 0);
    info.code(0, 0, 5);   // PUSH_NONVOL rbp, the one real code
    info.code(1, 2, 4);   // ALLOC_SMALL, 0x28
    fixture.place(info.bytes);
    // The place() wrote the header's count as the codes set it; raise it
    // past what the section holds.
    fixture.info[2] = 0x7F;

    alignas(16) std::uint8_t context[seh::kContextSize];
    std::memset(context, 0, sizeof(context));
    alignas(8) std::uint8_t stack[256];
    std::memset(stack, 0, sizeof(stack));
    const std::uint64_t stack_base = reinterpret_cast<std::uint64_t>(stack);
    const std::uint64_t saved_rbp = 0x5555555555555555ULL;
    // The push's own slot: the code below undoes it by reading here.
    put64(stack, 64, saved_rbp);
    put64(context, seh::kContextRsp, stack_base + 64);

    const auto* entry = seh::lookup_function_entry(
        fixture.base, fixture.pdata, sizeof(fixture.pdata), fixture.pc);
    const void* data = nullptr;
    std::uint64_t frame = 0;
    std::uint64_t handler = 0;
    const bool ok = seh::virtual_unwind(seh::kUnwFlagEHandler, fixture.base,
                                        fixture.pc, entry, context,
                                        fixture.xdata(), stack_base,
                                        stack_base + sizeof(stack), &data,
                                        &frame, &handler);
    check(ok, "a table that overruns its section still unwinds");
    check(get64(context, seh::kContextRbp) == saved_rbp,
          "the code inside the section was applied");
    check(get64(context, seh::kContextRsp) > stack_base + 64,
          "the stack moved by the codes that were read");
}

void test_body_unwind_reverses_push_and_alloc() {
    // A prolog that pushes rbx, pushes rbp, then allocates 0x28 bytes.
    // The codes are stored descending by offset: the allocation first,
    // then the pushes, and the walk reverses them in the stored order.
    TableFixture fixture;
    UnwindInfoBytes info(0, 7, 0, 0);
    info.code(2, 2, 4);  // ALLOC_SMALL, 5 units of 8: 0x28 bytes
    info.code(1, 0, 3);  // PUSH_NONVOL rbx
    info.code(0, 0, 5);  // PUSH_NONVOL rbp
    fixture.place(info.bytes);

    alignas(16) std::uint8_t context[seh::kContextSize];
    std::memset(context, 0, sizeof(context));
    alignas(8) std::uint8_t stack[256];
    std::memset(stack, 0, sizeof(stack));
    const std::uint64_t stack_base = reinterpret_cast<std::uint64_t>(stack);
    const std::uint64_t body_rsp = stack_base + 128;
    const std::uint64_t saved_rbx = 0x1111111111111111ULL;
    const std::uint64_t saved_rbp = 0x2222222222222222ULL;
    const std::uint64_t return_address = 0x140002000ULL;
    // The stack the prolog built, above the body's rsp: the allocation's
    // extent, then rbx's slot, rbp's slot, and the return address.
    put64(stack, 128 + 40, saved_rbx);
    put64(stack, 128 + 48, saved_rbp);
    put64(stack, 128 + 56, return_address);
    put64(context, seh::kContextRsp, body_rsp);

    const auto* entry = seh::lookup_function_entry(
        fixture.base, fixture.pdata, sizeof(fixture.pdata), fixture.pc);
    check(entry != nullptr, "the fixture's pc lands in its own row");

    const void* data = nullptr;
    std::uint64_t frame = 0;
    std::uint64_t handler = 0;
    const bool ok = seh::virtual_unwind(seh::kUnwFlagEHandler, fixture.base,
                                        fixture.pc, entry, context,
                                        fixture.xdata(), 0, 0, &data,
                                        &frame, &handler);
    check(ok, "a body control point unwinds");
    check(get64(context, seh::kContextRsp) == body_rsp + 0x28 + 24,
          "the allocation, both pushes and the return address come back");
    check(get64(context, seh::kContextRbx) == saved_rbx,
          "rbx is restored from the slot its push left");
    check(get64(context, seh::kContextRbp) == saved_rbp,
          "rbp is restored from the slot its push left");
    check(get64(context, seh::kContextRip) == return_address,
          "the caller is the address its call pushed");
    check(frame == body_rsp,
          "a frame with no frame register frames itself at the entry rsp");
}

void test_body_unwind_steps_over_an_epilogue_marker() {
    // An epilogue marker in the middle of the code list, with a push behind
    // it in the direction the walk travels. The marker carries a payload
    // pair the walk never reads, and the size it is recorded with is what
    // keeps the cursor on a code boundary: stepped over as one slot instead
    // of two, the cursor lands inside the payload, reads two bytes of it as
    // the next code, and reverses an effect the prolog never produced --
    // which shows up as a stack pointer eight bytes too high and a
    // register restored from a slot nothing was saved in.
    //
    // The marker is stored the way the format stores it, in the order the
    // prolog produced the effects: the allocation first, then the marker,
    // then the push.
    TableFixture fixture;
    UnwindInfoBytes info(0, 7, 0, 0);
    info.code(4, 2, 4);              // ALLOC_SMALL, 5 units of 8: 0x28 bytes
    info.code(2, 6, 0, 0, true);     // UWOP_EPILOG, with a payload to skip
    info.code(0, 0, 3);              // PUSH_NONVOL rbx
    fixture.place(info.bytes);

    alignas(16) std::uint8_t context[seh::kContextSize];
    std::memset(context, 0, sizeof(context));
    alignas(8) std::uint8_t stack[256];
    std::memset(stack, 0, sizeof(stack));
    const std::uint64_t stack_base = reinterpret_cast<std::uint64_t>(stack);
    const std::uint64_t body_rsp = stack_base + 128;
    const std::uint64_t saved_rbx = 0x1111111111111111ULL;
    const std::uint64_t return_address = 0x140002000ULL;
    put64(stack, 128 + 40, saved_rbx);
    put64(stack, 128 + 48, return_address);
    put64(context, seh::kContextRsp, body_rsp);

    const auto* entry = seh::lookup_function_entry(
        fixture.base, fixture.pdata, sizeof(fixture.pdata), fixture.pc);
    check(entry != nullptr, "the fixture's pc lands in its own row");

    const void* data = nullptr;
    std::uint64_t frame = 0;
    std::uint64_t handler = 0;
    const bool ok = seh::virtual_unwind(seh::kUnwFlagEHandler, fixture.base,
                                        fixture.pc, entry, context,
                                        fixture.xdata(), 0, 0, &data,
                                        &frame, &handler);
    check(ok, "a body control point with an epilogue marker unwinds");
    check(get64(context, seh::kContextRsp) == body_rsp + 0x28 + 8 + 8,
          "the marker consumed no stack, and the push behind it was "
          "reversed once");
    check(get64(context, seh::kContextRbx) == saved_rbx,
          "rbx is restored from the slot its push left");
    check(get64(context, seh::kContextRip) == return_address,
          "the caller is the address its call pushed");
    check(get64(context, seh::kContextRax) == 0,
          "the payload was not read as a code and stored into r0");
}

void test_prolog_middle_skips_the_codes_not_reached() {
    // The same prolog, entered three bytes in: the allocation and the
    // push have run, the save has not.
    TableFixture fixture;
    UnwindInfoBytes info(0, 8, 0, 0);
    info.code(6, 4, 3, 4, true);  // SAVE_NONVOL rbx, slot 4
    info.code(2, 2, 4);           // ALLOC_SMALL, 0x28
    info.code(1, 0, 3);           // PUSH_NONVOL rbx
    fixture.place(info.bytes);

    alignas(16) std::uint8_t context[seh::kContextSize];
    std::memset(context, 0, sizeof(context));
    alignas(8) std::uint8_t stack[256];
    std::memset(stack, 0, sizeof(stack));
    const std::uint64_t stack_base = reinterpret_cast<std::uint64_t>(stack);
    const std::uint64_t rsp_at_three = stack_base + 128;
    const std::uint64_t saved_rbx = 0x3333333333333333ULL;
    const std::uint64_t return_address = 0x140003000ULL;
    put64(stack, 128 + 40, saved_rbx);
    put64(stack, 128 + 48, return_address);
    put64(context, seh::kContextRsp, rsp_at_three);

    const auto* entry = seh::lookup_function_entry(
        fixture.base, fixture.pdata, sizeof(fixture.pdata), fixture.pc);
    // The fixture pc sits in the body; the walk is driven here at the
    // prolog offset the case names.
    const std::uint64_t pc_in_prolog = fixture.base + 0x1003;

    const void* data = nullptr;
    std::uint64_t frame = 0;
    std::uint64_t handler = 0;
    const bool ok = seh::virtual_unwind(seh::kUnwFlagEHandler, fixture.base,
                                        pc_in_prolog, entry, context,
                                        fixture.xdata(), 0, 0, &data,
                                        &frame, &handler);
    check(ok, "a prolog control point unwinds");
    check(get64(context, seh::kContextRsp) == rsp_at_three + 0x28 + 16,
          "only the effects the prolog reached are reversed");
    check(get64(context, seh::kContextRbx) == saved_rbx,
          "the push that ran is still undone");
    check(get64(context, seh::kContextRip) == return_address,
          "the walk ends at the caller regardless");
    check(handler == 0 && data == nullptr,
          "a prolog control point reports no handler");
}

void test_frame_register_anchors_the_save_slots() {
    // A frame that keeps an anchor in rbp and saves rbx through it. The
    // anchor sits one 16-byte unit below the value the lea produced, and
    // the save's slot is measured from the anchor.
    TableFixture fixture;
    UnwindInfoBytes info(0, 8, 5, 1);  // frame register rbp, offset 1
    info.code(5, 4, 3, 2, true);       // SAVE_NONVOL rbx, slot 2
    info.code(3, 3, 0);                // SET_FPREG
    fixture.place(info.bytes);

    alignas(16) std::uint8_t context[seh::kContextSize];
    std::memset(context, 0, sizeof(context));
    alignas(8) std::uint8_t stack[256];
    std::memset(stack, 0, sizeof(stack));
    const std::uint64_t stack_base = reinterpret_cast<std::uint64_t>(stack);
    const std::uint64_t anchor = stack_base + 128;
    const std::uint64_t saved_rbx = 0x4444444444444444ULL;
    const std::uint64_t return_address = 0x140004000ULL;
    put64(stack, 128, saved_rbx);       // the anchor's slot 2: anchor + 16
    put64(stack, 112, return_address);  // the anchor, where the rsp returns
    put64(context, seh::kContextRsp, stack_base + 64);
    put64(context, seh::kContextRbp, anchor);

    const auto* entry = seh::lookup_function_entry(
        fixture.base, fixture.pdata, sizeof(fixture.pdata), fixture.pc);

    const void* data = nullptr;
    std::uint64_t frame = 0;
    std::uint64_t handler = 0;
    const bool ok = seh::virtual_unwind(seh::kUnwFlagEHandler, fixture.base,
                                        fixture.pc, entry, context,
                                        fixture.xdata(), 0, 0, &data,
                                        &frame, &handler);
    check(ok, "a frame-registered control point unwinds");
    check(frame == anchor - 16,
          "the establisher frame is the anchor less the recorded units");
    check(get64(context, seh::kContextRbx) == saved_rbx,
          "the save reads its slot through the anchor");
    check(get64(context, seh::kContextRsp) == anchor - 8 &&
              get64(context, seh::kContextRip) == return_address,
          "the frame register hands the stack pointer back to the anchor");
}

// ------------------------------------------------------- the dispatch

__attribute__((ms_abi)) std::uint64_t handler_continues_exec(
    const void*, std::uint64_t, const void*, const void*) noexcept {
    return seh::kExceptionContinueExecution;
}

__attribute__((ms_abi)) std::uint64_t handler_continues_search(
    const void*, std::uint64_t, const void*, const void*) noexcept {
    return seh::kExceptionContinueSearch;
}

// The dispatch fixtures share one shape: a one-row `.pdata` whose info
// carries an exception handler, and a handler that is one of the host
// functions above. Static storage keeps the tables close enough to the
// functions for one image base to hold them both.
struct DispatchFixture {
    alignas(16) std::uint8_t info[16] = {};
    alignas(8) std::uint8_t pdata[12] = {};
    alignas(16) std::uint8_t context[seh::kContextSize] = {};
    std::uint64_t base = 0;
    std::uint64_t image_end = 0;
    std::uint64_t pc = 0;

    void build(std::uint64_t handler_address, std::uint64_t rsp) {
        const std::uint64_t info_va = reinterpret_cast<std::uint64_t>(info);
        base = (info_va < handler_address ? info_va : handler_address) &
               ~0xFFFFULL;
        image_end = base + (1ULL << 32);
        // version 1, UNW_FLAG_EHANDLER, prolog 0, no codes, handler RVA.
        info[0] = static_cast<std::uint8_t>(0x01 | (0x1 << 3));
        info[1] = 0;
        info[2] = 0;
        info[3] = 0;
        put32(info, 4, static_cast<std::uint32_t>(handler_address - base));
        put32(pdata, 0, 0x1000);
        put32(pdata, 4, 0x1100);
        put32(pdata, 8, static_cast<std::uint32_t>(info_va - base));
        pc = base + 0x1050;
        put64(context, seh::kContextRip, pc);
        put64(context, seh::kContextRsp, rsp);
    }

    // The same relationship TableFixture keeps: the rows point at `info`,
    // so `info` is the section the walk bounds its reads by.
    seh::UnwindRange xdata() const {
        return seh::UnwindRange{reinterpret_cast<std::uint64_t>(info),
                                sizeof(info)};
    }
};

void test_dispatch_reports_the_handler_that_will_handle() {
    static DispatchFixture fixture;
    std::uint64_t probe = 0;
    fixture.build(reinterpret_cast<std::uint64_t>(&handler_continues_exec),
                  reinterpret_cast<std::uint64_t>(&probe) - 0x400);
    alignas(16) std::uint8_t record[seh::kRecordSize];
    std::memset(record, 0, sizeof(record));

    // The upper bound stays inside the real stack: the walk climbs frame
    // by frame, and a bound past the stack's own top would have it read
    // unmapped memory before the bound gets to stop it.
    const std::uint64_t low =
        reinterpret_cast<std::uint64_t>(&probe) - 0x100000;
    const std::uint64_t high =
        reinterpret_cast<std::uint64_t>(&probe) + 0x800;
    const bool resume =
        seh::dispatch(record, fixture.context, fixture.pdata,
                      sizeof(fixture.pdata), fixture.xdata(), fixture.base,
                      fixture.image_end, low, high);
    check(resume,
          "a handler that answers continue-execution leaves the run alive");
}

void test_dispatch_walks_off_when_no_one_declines() {
    static DispatchFixture fixture;
    std::uint64_t probe = 0;
    fixture.build(reinterpret_cast<std::uint64_t>(&handler_continues_search),
                  reinterpret_cast<std::uint64_t>(&probe) - 0x400);
    alignas(16) std::uint8_t record[seh::kRecordSize];
    std::memset(record, 0, sizeof(record));

    const std::uint64_t low =
        reinterpret_cast<std::uint64_t>(&probe) - 0x100000;
    const std::uint64_t high =
        reinterpret_cast<std::uint64_t>(&probe) + 0x800;
    const bool resume =
        seh::dispatch(record, fixture.context, fixture.pdata,
                      sizeof(fixture.pdata), fixture.xdata(), fixture.base,
                      fixture.image_end, low, high);
    check(!resume,
          "a search every frame declines ends as an unhandled exception");
}

void test_dispatch_without_a_table_is_unhandled() {
    alignas(16) std::uint8_t context[seh::kContextSize];
    std::memset(context, 0, sizeof(context));
    put64(context, seh::kContextRip, 0x140001000ULL);
    put64(context, seh::kContextRsp,
          reinterpret_cast<std::uint64_t>(&context) - 0x400);
    alignas(16) std::uint8_t record[seh::kRecordSize];
    std::memset(record, 0, sizeof(record));
    std::uint64_t probe = 0;
    const bool resume =
        seh::dispatch(record, context, nullptr, 0, seh::UnwindRange{},
                      0x140000000ULL, 0x150000000ULL,
                      reinterpret_cast<std::uint64_t>(&probe) - 0x100000,
                      reinterpret_cast<std::uint64_t>(&probe) + 0x800);
    check(!resume, "an image with no exception table has nothing to handle");
}

// ------------------------------------------- the C-specific handler

bool g_finally_ran = false;
std::uint8_t g_finally_abnormal = 0;

__attribute__((ms_abi)) std::int32_t filter_continues_search(
    const void*, std::uint64_t) noexcept {
    return seh::kExceptionContinueSearchFilter;
}

__attribute__((ms_abi)) std::int32_t filter_continues_execution(
    const void*, std::uint64_t) noexcept {
    return seh::kExceptionContinueExecutionFilter;
}

__attribute__((ms_abi)) void finally_body(std::uint8_t abnormal,
                                          std::uint64_t) noexcept {
    g_finally_ran = true;
    g_finally_abnormal = abnormal;
}

// The C-specific handler reads its scope table through the dispatcher
// context's handler data, and reaches each filter through the image base:
// `base + handler_rva`. The fixtures below anchor the base on the filter's
// own address -- the low 32 bits then spell the RVA, which is all the slot
// holds -- and hand the table over directly.

void test_c_specific_handler_search_pass_runs_the_filter() {
    // One scope whose filter declines: the search continues, which the
    // handler answers as ExceptionContinueSearch.
    alignas(8) std::uint8_t scope[4 + 16];
    put32(scope, 0, 1);  // one record
    put32(scope, 4, 0x1000);
    put32(scope, 8, 0x1100);
    const std::uint64_t base =
        reinterpret_cast<std::uint64_t>(&filter_continues_search) &
        ~0xFFFFFFFFULL;
    put32(scope, 12,
          static_cast<std::uint32_t>(
              reinterpret_cast<std::uint64_t>(&filter_continues_search) -
              base));
    put32(scope, 16, 0x2000);  // the jump target

    seh::DispatcherContext dc;
    dc.image_base = base;
    dc.control_pc = base + 0x1050;
    dc.handler_data = scope;
    dc.scope_index = 0;

    alignas(16) std::uint8_t record[seh::kRecordSize];
    std::memset(record, 0, sizeof(record));
    alignas(16) std::uint8_t context[seh::kContextSize];
    std::memset(context, 0, sizeof(context));

    const std::uint64_t verdict =
        seh::seh_C_specific_handler(record, nullptr, context, &dc);
    check(verdict == seh::kExceptionContinueSearch,
          "a filter that declines leaves the search continuing");
}

void test_c_specific_handler_reports_continue_execution() {
    alignas(8) std::uint8_t scope[4 + 16];
    put32(scope, 0, 1);
    put32(scope, 4, 0x1000);
    put32(scope, 8, 0x1100);
    const std::uint64_t base =
        reinterpret_cast<std::uint64_t>(&filter_continues_execution) &
        ~0xFFFFFFFFULL;
    put32(scope, 12,
          static_cast<std::uint32_t>(
              reinterpret_cast<std::uint64_t>(&filter_continues_execution) -
              base));
    put32(scope, 16, 0x2000);

    seh::DispatcherContext dc;
    dc.image_base = base;
    dc.control_pc = base + 0x1050;
    dc.handler_data = scope;

    alignas(16) std::uint8_t record[seh::kRecordSize];
    std::memset(record, 0, sizeof(record));
    const std::uint64_t verdict =
        seh::seh_C_specific_handler(record, nullptr, nullptr, &dc);
    check(verdict == seh::kExceptionContinueExecution,
          "a filter that answers continue-execution reports it");
}

void test_c_specific_handler_unwind_pass_runs_the_finally() {
    // The unwind pass over one `__finally` scope: the body runs, marked
    // abnormal, and the dispatcher's scope index moves past the scope it
    // ran.
    alignas(8) std::uint8_t scope[4 + 16];
    put32(scope, 0, 1);
    put32(scope, 4, 0x1000);
    put32(scope, 8, 0x1100);
    const std::uint64_t base =
        reinterpret_cast<std::uint64_t>(&finally_body) & ~0xFFFFFFFFULL;
    put32(scope, 12,
          static_cast<std::uint32_t>(
              reinterpret_cast<std::uint64_t>(&finally_body) - base));
    put32(scope, 16, 0);  // no jump target: a finally

    seh::DispatcherContext dc;
    dc.image_base = base;
    dc.control_pc = base + 0x1050;
    dc.handler_data = scope;

    alignas(16) std::uint8_t record[seh::kRecordSize];
    std::memset(record, 0, sizeof(record));
    put32(record, seh::kRecordFlags, seh::kExceptionUnwinding);

    g_finally_ran = false;
    const std::uint64_t verdict =
        seh::seh_C_specific_handler(record, nullptr, nullptr, &dc);
    check(verdict == seh::kExceptionContinueSearch,
          "the unwind pass answers continue-search when it is done");
    check(g_finally_ran, "the finally body ran");
    check(g_finally_abnormal == 1, "the finally was told it is abnormal");
    check(dc.scope_index == 1,
          "the scope index moved past the finally that ran");
}

// ------------------------------------------ the capture and restore

::jmp_buf g_round_trip;
std::uint64_t g_rbx_seen = 0;

__attribute__((noinline)) void restore_target() noexcept {
    asm volatile("movq %%rbx, %0" : "=r"(g_rbx_seen));
    std::longjmp(g_round_trip, 1);
}

void test_capture_and_restore_round_trip() {
    alignas(16) std::uint8_t context[seh::kContextSize];
    if (::setjmp(g_round_trip) == 0) {
        const std::uint64_t planted = 0x123456789ABCDEF0ULL;
        seh::seh_capture_context(context);
        // The register the round trip certifies is planted straight into
        // the captured context: what the restore must do is bring the
        // buffer's values back into the live registers, and what the
        // compiler does with its own registers between the calls is its
        // business.
        put64(context, seh::kContextRbx, planted);
        const std::uint64_t target =
            reinterpret_cast<std::uint64_t>(&restore_target);
        put64(context, seh::kContextRip, target);
        seh::seh_restore_context(context);
        check(false, "the restore does not return");
        return;
    }
    check(g_rbx_seen == 0x123456789ABCDEF0ULL,
          "the restore brings the non-volatile registers back");
}

}  // namespace

int main() {
    test_lookup_finds_the_row_holding_the_pc();
    test_lookup_follows_the_chain();
    test_lookup_rejects_a_chain_that_leaves_the_table();
    test_leaf_unwind_pops_the_return_address();
    test_leaf_unwind_refuses_a_stack_pointer_off_the_stack();
    test_body_unwind_refuses_a_row_pointing_outside_xdata();
    test_unwind_stops_when_the_code_count_overruns_the_section();
    test_body_unwind_reverses_push_and_alloc();
    test_body_unwind_steps_over_an_epilogue_marker();
    test_prolog_middle_skips_the_codes_not_reached();
    test_frame_register_anchors_the_save_slots();
    test_dispatch_reports_the_handler_that_will_handle();
    test_dispatch_walks_off_when_no_one_declines();
    test_dispatch_without_a_table_is_unhandled();
    test_c_specific_handler_search_pass_runs_the_filter();
    test_c_specific_handler_reports_continue_execution();
    test_c_specific_handler_unwind_pass_runs_the_finally();
    test_capture_and_restore_round_trip();
    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

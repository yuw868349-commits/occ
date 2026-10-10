// The minidump writer and reader. See the header for why both live here:
// the write is the format, the read is the proof.

#include "occ/runtime/minidump.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

namespace occ::runtime::minidump {
namespace {

constexpr std::uint32_t kSignature = 0x504D444D;  // 'MDMP'
constexpr std::uint32_t kVersion = 42899;         // the format's own

// The stream types a dump carries.
constexpr std::uint32_t kStreamThreadList = 3;
constexpr std::uint32_t kStreamModuleList = 4;
constexpr std::uint32_t kStreamMemoryList = 5;
constexpr std::uint32_t kStreamException = 6;
constexpr std::uint32_t kStreamSystemInfo = 7;

constexpr std::uint32_t kProcessorArchitectureAmd64 = 9;
constexpr std::uint32_t kContextAmd64 = 0x100000;
constexpr std::uint32_t kContextFull = 0x10003F;

// The CONTEXT x64, as offsets into the 1232-byte structure -- the fields
// this dump fills and none of the ones it leaves zero.
constexpr std::size_t kContextSize = 0x4D0;
constexpr std::size_t kCtxContextFlags = 0x38;
constexpr std::size_t kCtxMxCsr = 0x3C;
constexpr std::size_t kCtxSegCs = 0x40;
constexpr std::size_t kCtxSegSs = 0x4A;
constexpr std::size_t kCtxEFlags = 0x4C;
constexpr std::size_t kCtxRax = 0x80;   // through R15 at 0xF0, Rip at 0xF8
constexpr std::size_t kCtxRip = 0xF8;

// The gregs indices the caller's array uses, to the CONTEXT's layout.
constexpr std::size_t kGregRax = 13;
constexpr std::size_t kGregRcx = 14;
constexpr std::size_t kGregRdx = 12;
constexpr std::size_t kGregRbx = 11;
constexpr std::size_t kGregRsp = 15;
constexpr std::size_t kGregRbp = 10;
constexpr std::size_t kGregRsi = 9;
constexpr std::size_t kGregRdi = 8;
constexpr std::size_t kGregR8 = 0;   // through R15 at 7
constexpr std::size_t kGregRip = 16;
constexpr std::size_t kGregEfl = 17;

// The stack a dump carries: as much below rsp as the region holds. A
// crash's stack is the memory the backtrace walks, and 64 KB reaches
// further than any honest frame chain this runtime produces.
constexpr std::uint32_t kStackBytes = 0x10000;

[[nodiscard]] std::uint32_t rd32(const std::uint8_t* p, std::size_t at) noexcept {
    return static_cast<std::uint32_t>(p[at]) |
           (static_cast<std::uint32_t>(p[at + 1]) << 8) |
           (static_cast<std::uint32_t>(p[at + 2]) << 16) |
           (static_cast<std::uint32_t>(p[at + 3]) << 24);
}

void put32(std::vector<std::uint8_t>& b, std::size_t at,
           std::uint32_t v) noexcept {
    b[at] = static_cast<std::uint8_t>(v);
    b[at + 1] = static_cast<std::uint8_t>(v >> 8);
    b[at + 2] = static_cast<std::uint8_t>(v >> 16);
    b[at + 3] = static_cast<std::uint8_t>(v >> 24);
}

void put64(std::vector<std::uint8_t>& b, std::size_t at,
           std::uint64_t v) noexcept {
    for (int i = 0; i < 8; ++i) {
        b[at + static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>(v >> (8 * i));
    }
}

void put16(std::vector<std::uint8_t>& b, std::size_t at,
           std::uint16_t v) noexcept {
    b[at] = static_cast<std::uint8_t>(v);
    b[at + 1] = static_cast<std::uint8_t>(v >> 8);
}

void append32(std::vector<std::uint8_t>& b, std::uint32_t v) noexcept {
    const std::size_t at = b.size();
    b.resize(at + 4);
    put32(b, at, v);
}

void append64(std::vector<std::uint8_t>& b, std::uint64_t v) noexcept {
    const std::size_t at = b.size();
    b.resize(at + 8);
    put64(b, at, v);
}

void align8(std::vector<std::uint8_t>& b) noexcept {
    while (b.size() % 8 != 0) {
        b.push_back(0);
    }
}

// A MINIDUMP_STRING: length in bytes, then UTF-16, then the terminator.
void append_string(std::vector<std::uint8_t>& b, const char* text) noexcept {
    std::vector<std::uint16_t> wide;
    for (const char* p = text != nullptr ? text : ""; *p != '\0'; ++p) {
        wide.push_back(static_cast<std::uint16_t>(
            static_cast<unsigned char>(*p)));
    }
    // The helpers below write at an offset they were given; the appends
    // have to grow the vector *first* -- put16 at b.size() is an
    // out-of-bounds store otherwise, undefined and silent, which is
    // exactly what the first version did and exactly why the name was
    // zeros in the file while every reader of the source swore it wrote.
    append32(b, static_cast<std::uint32_t>(wide.size() * 2));
    for (const std::uint16_t w : wide) {
        const std::size_t at = b.size();
        b.resize(at + 2);
        put16(b, at, w);
    }
    const std::size_t null_at = b.size();
    b.resize(null_at + 2);
    put16(b, null_at, 0);
}

// The CONTEXT, filled from the caller's gregs-order snapshot. The vector
// and segment state a fault handler does not carry are zero -- a reader
// treats missing state as missing, and inventing it would be worse.
void build_context(std::vector<std::uint8_t>& out,
                   const Context& context) noexcept {
    out.resize(kContextSize, 0);
    put32(out, kCtxContextFlags, kContextAmd64 | kContextFull);
    put32(out, kCtxMxCsr, 0x1F80);
    put16(out, kCtxSegCs, 0x33);
    put16(out, kCtxSegSs, 0x2B);
    if (!context.valid) {
        return;
    }
    struct Move {
        std::size_t ctx_at;
        std::size_t greg;
    };
    constexpr Move kMoves[] = {
        {kCtxRax, kGregRax},      {kCtxRax + 0x8, kGregRcx},
        {kCtxRax + 0x10, kGregRdx}, {kCtxRax + 0x18, kGregRbx},
        {kCtxRax + 0x20, kGregRsp}, {kCtxRax + 0x28, kGregRbp},
        {kCtxRax + 0x30, kGregRsi}, {kCtxRax + 0x38, kGregRdi},
        {kCtxRax + 0x40, kGregR8},  {kCtxRax + 0x48, kGregR8 + 1},
        {kCtxRax + 0x50, kGregR8 + 2}, {kCtxRax + 0x58, kGregR8 + 3},
        {kCtxRax + 0x60, kGregR8 + 4}, {kCtxRax + 0x68, kGregR8 + 5},
        {kCtxRax + 0x70, kGregR8 + 6}, {kCtxRax + 0x78, kGregR8 + 7},
        {kCtxRip, kGregRip},
    };
    for (const Move& m : kMoves) {
        put64(out, m.ctx_at, context.regs[m.greg]);
    }
    put32(out, kCtxEFlags,
          static_cast<std::uint32_t>(context.regs[kGregEfl]));
}

// The guest's memory, read the way every reader of guest memory in this
// runtime reads it: through the process's own mapping, with a short read
// answering "not all of this is mapped" rather than a fault.
[[nodiscard]] std::size_t read_guest(uint64_t address, void* out,
                                     std::size_t bytes) noexcept {
    static const int fd = ::open("/proc/self/mem", O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    std::size_t done = 0;
    auto* dst = static_cast<std::uint8_t*>(out);
    while (done < bytes) {
        const ssize_t got = ::pread(fd, dst + done, bytes - done,
                                    static_cast<off_t>(address + done));
        if (got <= 0) {
            break;
        }
        done += static_cast<std::size_t>(got);
    }
    return done;
}

}  // namespace

bool enabled() noexcept {
    static const bool on = [] {
        const char* value = ::getenv("OCC_MINIDUMP");
        return value != nullptr && value[0] != '\0';
    }();
    return on;
}

std::string path() noexcept {
    const char* value = ::getenv("OCC_MINIDUMP");
    return value != nullptr ? value : "";
}

bool write(const std::string& out_path, std::uint64_t image_base,
           std::uint64_t image_size, const Context& context,
           std::uint32_t exception_code, std::uint64_t exception_address,
           const char* module_path) noexcept {
    // The file is built whole and written once: a half-written dump on a
    // fault path is worse than none, and the sections the format names
    // know their own offsets, which this builder assigns as it goes.
    std::vector<std::uint8_t> file;
    file.reserve(0x40000);

    // --- header: 32 bytes, then the directory of 8-byte stream entries.
    // The stream RVAs are back-patched, so the directory is laid out here
    // and the streams appended after.
    const std::size_t stream_count = exception_code != 0 ? 5 : 4;
    file.resize(32 + stream_count * 8, 0);
    put32(file, 0, kSignature);
    put32(file, 4, kVersion);
    put32(file, 8, static_cast<std::uint32_t>(stream_count));
    put32(file, 12, 32);  // directory rva
    put32(file, 16, 0);   // checksum: the format's own reader ignores it
    put32(file, 20, static_cast<std::uint32_t>(::time(nullptr)));
    // Flags: with data streams, so a reader knows what it may ask for.
    put64(file, 24, 0x7DE00);  // MiniDumpWithDataSegs | WithFullMemory-ish set

    // The directory entries, as the writer learns them: type and rva in
    // the order appended, patched into the directory before the file is
    // written. An earlier version patched each stream's type into the
    // stream's own leading bytes and left every directory rva at zero --
    // the reader then parsed the header as every stream, which is why
    // this file carries its own reader.
    std::vector<std::pair<std::uint32_t, std::uint32_t>> stream_entries;
    stream_entries.reserve(stream_count);

    // --- thread list -------------------------------------------------------
    const std::size_t threads_at = file.size();
    (void)threads_at;
    stream_entries.emplace_back(kStreamThreadList, 0);
    align8(file);
    file.resize(file.size() + 8, 0);
    stream_entries.back().second = static_cast<std::uint32_t>(file.size());  // patched below
    // one thread: the guest. Count first, then the fixed-size record.
    append32(file, 1);
    const std::size_t thread_record = file.size();
    // MINIDUMP_THREAD: 48 bytes.
    file.resize(file.size() + 48, 0);
    put32(file, thread_record, 1);                    // thread id
    put64(file, thread_record + 16, 0);               // teb: not kept per-run
    // The stack descriptor, at 24: start-of-range, size, rva -- patched
    // after the stack bytes are appended.
    std::uint64_t rsp = 0;
    if (context.valid) {
        rsp = context.regs[kGregRsp];
    }
    const std::uint64_t stack_start =
        rsp > kStackBytes ? rsp - kStackBytes : 0;
    std::vector<std::uint8_t> stack(kStackBytes, 0);
    const std::size_t stack_have =
        rsp != 0 ? read_guest(stack_start, stack.data(), stack.size()) : 0;
    put64(file, thread_record + 24, stack_start);
    put32(file, thread_record + 32, static_cast<std::uint32_t>(stack_have));
    put32(file, thread_record + 36,
          static_cast<std::uint32_t>(file.size()));  // stack rva
    file.insert(file.end(), stack.begin(),
                stack.begin() + static_cast<long>(stack_have));
    // The thread's CONTEXT descriptor, at 40: size and rva.
    std::vector<std::uint8_t> ctx;
    build_context(ctx, context);
    put32(file, thread_record + 40, kContextSize);
    put32(file, thread_record + 44,
          static_cast<std::uint32_t>(file.size()));
    file.insert(file.end(), ctx.begin(), ctx.end());

    // --- module list -------------------------------------------------------
    const std::size_t modules_at = file.size();
    (void)modules_at;
    stream_entries.emplace_back(kStreamModuleList, 0);
    align8(file);
    file.resize(file.size() + 8, 0);
    stream_entries.back().second = static_cast<std::uint32_t>(file.size());
    append32(file, 1);  // one module: the guest image
    const std::size_t module_record = file.size();
    file.resize(file.size() + 108, 0);
    put64(file, module_record, image_base);
    put32(file, module_record + 8, static_cast<std::uint32_t>(image_size));
    const std::uint32_t name_rva = static_cast<std::uint32_t>(file.size());
    append_string(file, module_path != nullptr ? module_path : "");
    // ModuleNameRva sits at 20 -- after the base, the size, the checksum
    // and the timestamp -- and the VersionInfo that follows it at 24 is
    // 52 bytes of VS_FIXEDFILEINFO zeros here, with the Cv and Misc
    // records and the two reserved fields the rest of the record.
    put32(file, module_record + 20, name_rva);

    // --- memory list -------------------------------------------------------
    const std::size_t memory_at = file.size();
    (void)memory_at;
    stream_entries.emplace_back(kStreamMemoryList, 0);
    align8(file);
    file.resize(file.size() + 8, 0);
    stream_entries.back().second = static_cast<std::uint32_t>(file.size());
    // One range: the image itself, the bytes every analysis starts from.
    std::vector<std::uint8_t> image(image_size, 0);
    const std::size_t image_have =
        read_guest(image_base, image.data(), image.size());
    append32(file, 1);
    append64(file, image_base);
    append32(file, static_cast<std::uint32_t>(image_have));
    append32(file, static_cast<std::uint32_t>(file.size()));
    file.insert(file.end(), image.begin(),
                image.begin() + static_cast<long>(image_have));

    // --- exception ---------------------------------------------------------
    if (exception_code != 0) {
        const std::size_t exception_at = file.size();
        (void)exception_at;
        stream_entries.emplace_back(kStreamException, 0);
        align8(file);
        file.resize(file.size() + 8, 0);
        stream_entries.back().second = static_cast<std::uint32_t>(file.size());
        // MINIDUMP_EXCEPTION_STREAM: thread id, alignment, the record
        // (168 bytes), then the context descriptor.
        append32(file, 1);
        append32(file, 0);
        append32(file, exception_code);
        append32(file, 0);  // flags
        append64(file, 0);  // inner record
        append64(file, exception_address);
        append32(file, 0);              // parameter count
        append32(file, 0);              // alignment padding
        file.resize(file.size() + 15 * 8, 0);  // information[15]
        append32(file, kContextSize);
        append32(file, static_cast<std::uint32_t>(file.size()));
        file.insert(file.end(), ctx.begin(), ctx.end());
    }

    // --- system info -------------------------------------------------------
    const std::size_t system_at = file.size();
    (void)system_at;
    stream_entries.emplace_back(kStreamSystemInfo, 0);
    align8(file);
    file.resize(file.size() + 8, 0);
    stream_entries.back().second = static_cast<std::uint32_t>(file.size());
    put16(file, file.size(), kProcessorArchitectureAmd64);
    file.resize(file.size() + 2, 0);        // reserved
    put16(file, file.size(), 0x0F);          // PROCESSOR_LEVEL_X64 family
    file.resize(file.size() + 24, 0);        // revision, counts, versions
    put32(file, file.size(), 0);             // CSD version: none
    file.resize(file.size() + 12, 0);        // suite mask, cpu info

    // --- directory: type and rva, in the order appended ------------------
    for (std::size_t i = 0; i < stream_entries.size(); ++i) {
        put32(file, 32 + i * 8, stream_entries[i].first);
        put32(file, 32 + i * 8 + 4, stream_entries[i].second);
    }

    std::FILE* out = std::fopen(out_path.c_str(), "wb");
    if (out == nullptr) {
        std::fprintf(stderr, "occ minidump: cannot open %s\n",
                     out_path.c_str());
        return false;
    }
    const std::size_t put = std::fwrite(file.data(), 1, file.size(), out);
    std::fclose(out);
    if (put != file.size()) {
        std::fprintf(stderr, "occ minidump: the write came up short\n");
        return false;
    }
    std::fprintf(stderr,
                 "occ minidump: wrote %s (%zu bytes, %zu streams)\n",
                 out_path.c_str(), file.size(), stream_entries.size());
    return true;
}

bool summarize(const std::string& in_path) noexcept {
    std::FILE* in = std::fopen(in_path.c_str(), "rb");
    if (in == nullptr) {
        std::fprintf(stderr, "occ minidump: cannot read %s\n",
                     in_path.c_str());
        return false;
    }
    std::vector<std::uint8_t> bytes;
    std::uint8_t chunk[65536];
    std::size_t got = 0;
    while ((got = std::fread(chunk, 1, sizeof(chunk), in)) > 0) {
        bytes.insert(bytes.end(), chunk, chunk + got);
    }
    std::fclose(in);

    if (bytes.size() < 32) {
        std::fprintf(stderr, "occ minidump: %s is %zu bytes, which cannot "
                             "hold a header\n",
                     in_path.c_str(), bytes.size());
        return false;
    }
    if (rd32(bytes.data(), 0) != kSignature) {
        std::fprintf(stderr, "occ minidump: no MDMP signature\n");
        return false;
    }
    const std::uint32_t count = rd32(bytes.data(), 8);
    const std::uint32_t directory = rd32(bytes.data(), 12);
    std::printf("signature MDMP, version %u, %u streams at rva 0x%x, "
                "%zu bytes\n",
                rd32(bytes.data(), 4), count, directory, bytes.size());
    if (static_cast<std::size_t>(directory) + count * 8 > bytes.size()) {
        std::fprintf(stderr, "occ minidump: the directory runs past the "
                             "file\n");
        return false;
    }
    // Every read past this point is bounds-checked: the file being read
    // is untrusted by definition -- it may not even have been written by
    // this runtime -- and a summary that crashes on a malformed file
    // would fail the one test a reader owes its user.
    const auto at32 = [&bytes](std::size_t at) -> std::uint32_t {
        if (at + 4 > bytes.size()) {
            return 0;
        }
        return rd32(bytes.data(), at);
    };
    bool ok = true;
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::size_t at = directory + static_cast<std::size_t>(i) * 8;
        const std::uint32_t type = at32(at);
        const std::uint32_t rva = at32(at + 4);
        std::printf("  stream %u: type %u at rva 0x%x\n", i, type, rva);
        if (static_cast<std::size_t>(rva) >= bytes.size()) {
            std::fprintf(stderr, "    stream rva is past the file\n");
            ok = false;
        }
        if (type == kStreamModuleList &&
            static_cast<std::size_t>(rva) < bytes.size()) {
            const std::uint32_t modules = at32(rva);
            std::printf("    modules: %u\n", modules);
            if (modules >= 1) {
                // The module array starts directly after the count: the
                // record's address is the count's address plus four, not
                // the value the count's word holds.
                const std::uint32_t record = rva + 4;
                const std::uint64_t base =
                    at32(record) |
                    (static_cast<std::uint64_t>(at32(record + 4)) << 32);
                const std::uint32_t size = at32(record + 8);
                const std::uint32_t name_rva = at32(record + 20);
                if (static_cast<std::size_t>(name_rva) + 4 < bytes.size()) {
                    const std::uint32_t name_bytes = at32(name_rva);
                    std::printf("    module 0: base 0x%llx size 0x%x name "
                                "%u bytes\n",
                                static_cast<unsigned long long>(base), size,
                                name_bytes / 2);
                }
            }
        }
        if (type == kStreamException &&
            static_cast<std::size_t>(rva) < bytes.size()) {
            const std::uint32_t code = at32(rva + 8);
            // ExceptionAddress is the fourth field of the record: after
            // the thread id, the alignment, the code, the flags and the
            // inner-record pointer.
            const std::uint64_t address =
                at32(rva + 24) |
                (static_cast<std::uint64_t>(at32(rva + 28)) << 32);
            std::printf("    exception code 0x%08x at address 0x%llx\n",
                        code, static_cast<unsigned long long>(address));
        }
    }
    return ok;
}

}  // namespace occ::runtime::minidump

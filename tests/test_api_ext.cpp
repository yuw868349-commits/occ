// The families added for the probe, the loader and the downloader, as the
// tests see them.
//
// What is checked here is the contract a guest depends on: the version
// record carries the version this runtime presents everywhere else, the
// OEM conversion round-trips, the temporary name names a file that exists,
// the image checksum is read out of the image, and a handle from the
// WinINet family closes cleanly. What is not checked is what needs a live
// guest -- the loader and the procedure resolution reach the registry
// through `GetProcAddress`, which needs the guest state a real run
// installs -- so those two are checked on their failure contracts, which
// is the part a caller can provoke without a guest.

#include "occ/runtime/api.h"
#include "occ/runtime/exports.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace occ::runtime;
using namespace occ::runtime::winabi;

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

// The functions under test, declared the way the domain files define them.
extern "C" __attribute__((ms_abi)) std::int32_t k32si_GetVersionExA(
    std::uint8_t* info) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32si_CharToOemA(
    const char* source, char* destination) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32si_OemToCharA(
    const char* source, char* destination) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32pe_GetTempFileNameA(
    const char* path, const char* prefix, std::uint32_t unique,
    char* out) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32pe_WinExec(
    const char* command, std::uint32_t show) noexcept;
extern "C" __attribute__((ms_abi)) void* k32ih_CheckSumMappedFile(
    void* base, std::uint32_t length, std::uint32_t* header_sum,
    std::uint32_t* checksum) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32ih_MapFileAndCheckSumA(
    const char* filename, std::uint32_t* header_sum,
    std::uint32_t* checksum) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32ldr_LdrLoadDll(
    std::uint64_t search_path, std::uint64_t flags, const std::uint8_t* name,
    std::uint64_t* base) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32ldr_LdrGetProcedureAddress(
    std::uint64_t module, const std::uint8_t* name, std::uint32_t ordinal,
    std::uint64_t* address) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32te_CreateRemoteThread(
    std::uint64_t process, void* attributes, std::uint64_t stack_size,
    std::uint64_t start, void* parameter, std::uint32_t flags,
    std::uint32_t* thread_id) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32te_QueueUserAPC(
    std::uint64_t routine, std::uint64_t thread, std::uint64_t data) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32dbe_DebugSetProcessKillOnExit(
    std::int32_t flag) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32wi_InternetOpenA(
    const char* agent, std::uint32_t access_type, const char* proxy,
    const char* bypass, std::uint32_t flags) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32wi_InternetCloseHandle(
    std::uint64_t handle) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32um_URLDownloadToFileA(
    std::uint64_t caller, const char* url, const char* filename,
    std::uint32_t reserved, std::uint64_t callback) noexcept;

}  // namespace

int main() {
    // The version record: the size is the caller's, and the numbers are
    // the ones this runtime presents -- a Windows 10 major, the platform
    // id for a Win32 NT build, and the build this runtime answers with.
    {
        std::uint8_t info[148];
        std::memset(info, 0, sizeof(info));
        std::memcpy(info, "\x94\x00\x00\x00", 4);  // dwOSVersionInfoSize = 148
        check(k32si_GetVersionExA(info) == 1, "GetVersionExA succeeds");
        std::uint32_t major = 0;
        std::memcpy(&major, info + 4, 4);
        check(major == 10, "GetVersionExA reports the Windows 10 major");
        std::uint32_t platform = 0;
        std::memcpy(&platform, info + 16, 4);
        check(platform == 2, "GetVersionExA reports VER_PLATFORM_WIN32_NT");
    }

    // The OEM round trip: ASCII survives, and the two directions agree.
    {
        char oem[16];
        char back[16];
        check(k32si_CharToOemA("A", oem) == 1 && oem[0] == 'A' &&
                  oem[1] == '\0',
              "CharToOemA maps ASCII unchanged");
        check(k32si_OemToCharA(oem, back) == 1 && std::strcmp(back, "A") == 0,
              "OemToCharA inverts CharToOemA");
    }

    // The temporary name: a real file is created, named uniquely, and
    // removed by the test so the workspace stays clean.
    {
        char out[260];
        const std::uint32_t unique =
            k32pe_GetTempFileNameA("/tmp", "occ", 0, out);
        check(unique != 0, "GetTempFileNameA chooses a unique number");
        check(::access(out, F_OK) == 0, "GetTempFileNameA created the file");
        ::unlink(out);
        const std::uint32_t again =
            k32pe_GetTempFileNameA("/tmp", "occ", unique, out);
        check(again != 0, "GetTempFileNameA reuses a named number once free");
        ::unlink(out);
    }

    // WinExec's refusal contract, which needs no guest to provoke.
    {
        check(k32pe_WinExec(nullptr, 0) == 0,
              "WinExec refuses a null command line");
    }

    // The image checksum: a minimal PE buffer with a header checksum the
    // call must read back, and a whole-image checksum it must compute.
    {
        std::uint8_t image[0xA0];
        std::memset(image, 0, sizeof(image));
        image[0] = 'M';
        image[1] = 'Z';
        const std::uint32_t lfanew = 0x40;
        std::memcpy(image + 0x3C, &lfanew, 4);
        image[0x40] = 'P';
        image[0x41] = 'E';
        const std::uint32_t header_checksum = 0x12345678;
        std::memcpy(image + 0x40 + 0x18 + 0x40, &header_checksum, 4);
        std::uint32_t hsum = 0;
        std::uint32_t csum = 0;
        void* base =
            k32ih_CheckSumMappedFile(image, sizeof(image), &hsum, &csum);
        check(base == image, "CheckSumMappedFile answers the image base");
        check(hsum == header_checksum,
              "CheckSumMappedFile reads the header checksum field");
        check(csum != 0, "CheckSumMappedFile computes a whole-image checksum");

        // The file spelling reads the same image from disk.
        const char* path = "/tmp/occ_checksum_test.bin";
        const int fd = ::open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
        check(fd >= 0, "checksum test file opens");
        if (fd >= 0) {
            ::write(fd, image, sizeof(image));
            ::close(fd);
            std::uint32_t fhsum = 0;
            std::uint32_t fcsum = 0;
            check(k32ih_MapFileAndCheckSumA(path, &fhsum, &fcsum) == 0,
                  "MapFileAndCheckSumA succeeds on a PE file");
            check(fhsum == header_checksum && fcsum == csum,
                  "MapFileAndCheckSumA agrees with the mapped spelling");
            ::unlink(path);
        }
    }

    // The loader failure contracts: a null name record is refused with the
    // loader's invalid-handle status, without a guest state to reach into.
    {
        std::uint64_t base = 0;
        check(k32ldr_LdrLoadDll(0, 0, nullptr, &base) == 0xC0000008u,
              "LdrLoadDll refuses a null name record");
        std::uint64_t proc = 0;
        check(k32ldr_LdrGetProcedureAddress(0, nullptr, 0, &proc) ==
                  0xC0000008u,
              "LdrGetProcedureAddress refuses a null name record");
    }

    // The remote-thread and APC refusals, which need no guest to provoke:
    // a process handle that is not the pseudo-handle, and a null routine.
    {
        std::uint32_t id = 0;
        check(k32te_CreateRemoteThread(0x1234, nullptr, 0, 0, nullptr, 0,
                                       &id) == 0,
              "CreateRemoteThread refuses a foreign process handle");
        check(k32te_QueueUserAPC(0, 1, 0) == 0,
              "QueueUserAPC refuses a null routine");
    }

    // The kill-on-exit flag round trip.
    {
        check(k32dbe_DebugSetProcessKillOnExit(1) == 1,
              "DebugSetProcessKillOnExit sets the flag");
        check(k32dbe_DebugSetProcessKillOnExit(0) == 1,
              "DebugSetProcessKillOnExit clears the flag");
    }

    // The WinINet handle lifecycle: a session is created and closed, and a
    // close of a value that names nothing is refused.
    {
        const std::uint64_t session = k32wi_InternetOpenA("occ-test", 0,
                                                          nullptr, nullptr, 0);
        check(session != 0, "InternetOpenA creates a session");
        check(k32wi_InternetCloseHandle(session) == 1,
              "InternetCloseHandle closes the session");
        check(k32wi_InternetCloseHandle(0x1234) == 0,
              "InternetCloseHandle refuses a foreign value");
    }

    // The downloader's refusal contract.
    {
        check(k32um_URLDownloadToFileA(0, nullptr, nullptr, 0, 0) != 0,
              "URLDownloadToFileA refuses null arguments");
    }

    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks passed\n", checks);
    return 0;
}

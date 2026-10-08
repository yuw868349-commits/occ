// The API set names, and the module each one stands for.
//
// A modern Windows image rarely imports `kernel32.dll`. It imports a name
// like `api-ms-win-core-file-l1-1-0.dll`, which is not a file on any disk:
// it is a *contract* -- a set of functions the platform promises, kept
// separately from the module that happens to provide them. The loader
// resolves that name to the implementation at load time, which is what lets
// a program link against "the file API" and run on a machine whose file API
// lives in a different DLL than the one it was built against.
//
// A runtime that does not know the contract cannot load such an image at
// all: the import names a DLL that does not exist, and every function in it
// looks missing. The table below is the resolution, one entry per contract
// this runtime can honour. The names and their targets are the platform's
// published arrangement rather than a choice made here -- the same mapping
// appears in the platform's own schema and in the projects that reimplement
// it -- and the table is written out in full rather than derived, because a
// contract that resolves to the wrong module would bind an import to a
// function with a different signature.
//
// Only contracts whose target module this runtime actually presents are
// listed. A contract that resolves to a module with no implementation here
// is left out on purpose: resolving it would move the failure from "this
// image needs a DLL I do not have" to "this image needs a function I do not
// have", and the first names the missing module, which is the more useful
// answer to a person reading it.

#include "occ/runtime/apiset.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <string>
#include <string_view>

namespace occ::runtime {
namespace {

struct ApiSetEntry {
    const char* name;
    const char* target;
};

// Sorted by name so the lookup can be a binary search. The table is the
// resolution table and the sort is checked by a test rather than trusted.
constexpr ApiSetEntry kApiSets[] = {
    {"api-ms-win-appmodel-runtime-internal-l1-1-1", "kernelbase.dll"},
    {"api-ms-win-appmodel-runtime-l1-1-2", "kernelbase.dll"},
    {"api-ms-win-base-bootconfig-l1-1-0", "advapi32.dll"},
    {"api-ms-win-base-util-l1-1-0", "advapi32.dll"},
    {"api-ms-win-core-apiquery-l1-1-0", "ntdll.dll"},
    {"api-ms-win-core-apiquery-l2-1-0", "kernelbase.dll"},
    {"api-ms-win-core-appcompat-l1-1-1", "kernelbase.dll"},
    {"api-ms-win-core-appinit-l1-1-0", "kernel32.dll"},
    {"api-ms-win-core-atoms-l1-1-0", "kernel32.dll"},
    {"api-ms-win-core-backgroundtask-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-calendar-l1-1-0", "kernel32.dll"},
    {"api-ms-win-core-comm-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-commandlinetoargv-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-console-ansi-l2-1-0", "kernel32.dll"},
    {"api-ms-win-core-console-internal-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-console-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-console-l1-2-0", "kernelbase.dll"},
    {"api-ms-win-core-console-l2-1-0", "kernelbase.dll"},
    {"api-ms-win-core-console-l2-2-0", "kernelbase.dll"},
    {"api-ms-win-core-console-l3-1-0", "kernelbase.dll"},
    {"api-ms-win-core-console-l3-2-0", "kernelbase.dll"},
    {"api-ms-win-core-crt-l1-1-0", "msvcrt.dll"},
    {"api-ms-win-core-crt-l2-1-0", "msvcrt.dll"},
    {"api-ms-win-core-datetime-l1-1-1", "kernelbase.dll"},
    {"api-ms-win-core-debug-l1-1-1", "kernelbase.dll"},
    {"api-ms-win-core-delayload-l1-1-1", "kernelbase.dll"},
    {"api-ms-win-core-enclave-l1-1-1", "kernelbase.dll"},
    {"api-ms-win-core-errorhandling-l1-1-3", "kernelbase.dll"},
    {"api-ms-win-core-fibers-l1-1-1", "kernelbase.dll"},
    {"api-ms-win-core-fibers-l2-1-1", "kernelbase.dll"},
    {"api-ms-win-core-file-ansi-l1-1-0", "kernel32.dll"},
    {"api-ms-win-core-file-ansi-l2-1-0", "kernel32.dll"},
    {"api-ms-win-core-file-fromapp-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-file-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-file-l1-2-2", "kernelbase.dll"},
    {"api-ms-win-core-file-l2-1-2", "kernelbase.dll"},
    {"api-ms-win-core-firmware-l1-1-0", "kernel32.dll"},
    {"api-ms-win-core-guard-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-handle-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-heap-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-heap-l1-2-0", "kernelbase.dll"},
    {"api-ms-win-core-heap-l2-1-0", "kernelbase.dll"},
    {"api-ms-win-core-heap-obsolete-l1-1-0", "kernel32.dll"},
    {"api-ms-win-core-interlocked-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-interlocked-l1-2-0", "kernelbase.dll"},
    {"api-ms-win-core-io-l1-1-1", "kernel32.dll"},
    {"api-ms-win-core-ioring-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-job-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-job-l2-1-0", "kernel32.dll"},
    {"api-ms-win-core-kernel32-legacy-ansi-l1-1-0", "kernel32.dll"},
    {"api-ms-win-core-kernel32-legacy-l1-1-5", "kernel32.dll"},
    {"api-ms-win-core-kernel32-private-l1-1-2", "kernel32.dll"},
    {"api-ms-win-core-kernel32-private-l1-2-0", "kernel32.dll"},
    {"api-ms-win-core-largeinteger-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-libraryloader-l1-1-1", "kernelbase.dll"},
    {"api-ms-win-core-libraryloader-l1-2-2", "kernelbase.dll"},
    {"api-ms-win-core-libraryloader-l2-1-0", "kernelbase.dll"},
    {"api-ms-win-core-libraryloader-private-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-localization-ansi-l1-1-0", "kernel32.dll"},
    {"api-ms-win-core-localization-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-localization-l1-2-2", "kernelbase.dll"},
    {"api-ms-win-core-localization-l2-1-0", "kernelbase.dll"},
    {"api-ms-win-core-localization-obsolete-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-localization-obsolete-l1-2-0", "kernelbase.dll"},
    {"api-ms-win-core-localization-obsolete-l1-3-0", "kernelbase.dll"},
    {"api-ms-win-core-localization-private-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-localregistry-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-memory-l1-1-4", "kernelbase.dll"},
    {"api-ms-win-core-misc-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-namedpipe-ansi-l1-1-0", "kernel32.dll"},
    {"api-ms-win-core-namedpipe-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-namedpipe-l1-2-0", "kernelbase.dll"},
    {"api-ms-win-core-namespace-ansi-l1-1-0", "kernel32.dll"},
    {"api-ms-win-core-namespace-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-normalization-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-path-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-pcw-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-perfcounters-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-perfcounters-l1-2-0", "kernelbase.dll"},
    {"api-ms-win-core-perfstm-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-privateprofile-l1-1-1", "kernel32.dll"},
    {"api-ms-win-core-processenvironment-ansi-l1-1-0", "kernel32.dll"},
    {"api-ms-win-core-processenvironment-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-processenvironment-l1-2-0", "kernelbase.dll"},
    {"api-ms-win-core-processsecurity-l1-1-0", "kernel32.dll"},
    {"api-ms-win-core-processsnapshot-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-processthreads-l1-1-3", "kernel32.dll"},
    {"api-ms-win-core-processtopology-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-processtopology-l1-2-0", "kernelbase.dll"},
    {"api-ms-win-core-processtopology-obsolete-l1-1-0", "kernel32.dll"},
    {"api-ms-win-core-processtopology-private-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-profile-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-psapi-ansi-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-psapi-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-psapi-obsolete-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-psapiansi-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-psm-key-l1-1-1", "kernelbase.dll"},
    {"api-ms-win-core-quirks-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-realtime-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-registry-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-registry-l2-1-0", "advapi32.dll"},
    {"api-ms-win-core-registry-l2-2-0", "advapi32.dll"},
    {"api-ms-win-core-registry-l2-3-0", "advapi32.dll"},
    {"api-ms-win-core-registry-private-l1-1-0", "advapi32.dll"},
    {"api-ms-win-core-registryuserspecific-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-rtlsupport-l1-1-0", "ntdll.dll"},
    {"api-ms-win-core-rtlsupport-l1-2-0", "ntdll.dll"},
    {"api-ms-win-core-shlwapi-legacy-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-shlwapi-obsolete-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-shlwapi-obsolete-l1-2-0", "kernelbase.dll"},
    {"api-ms-win-core-shutdown-ansi-l1-1-0", "advapi32.dll"},
    {"api-ms-win-core-shutdown-l1-1-0", "advapi32.dll"},
    {"api-ms-win-core-sidebyside-ansi-l1-1-0", "kernel32.dll"},
    {"api-ms-win-core-sidebyside-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-state-helpers-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-string-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-string-l2-1-0", "kernelbase.dll"},
    {"api-ms-win-core-string-obsolete-l1-1-0", "kernel32.dll"},
    {"api-ms-win-core-stringansi-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-stringloader-l1-1-1", "kernelbase.dll"},
    {"api-ms-win-core-synch-ansi-l1-1-0", "kernel32.dll"},
    {"api-ms-win-core-synch-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-synch-l1-2-1", "kernelbase.dll"},
    {"api-ms-win-core-sysinfo-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-sysinfo-l1-2-1", "kernelbase.dll"},
    {"api-ms-win-core-sysinfo-l2-1-0", "advapi32.dll"},
    {"api-ms-win-core-systemtopology-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-threadpool-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-threadpool-l1-2-0", "kernelbase.dll"},
    {"api-ms-win-core-threadpool-legacy-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-threadpool-private-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-timezone-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-timezone-private-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-toolhelp-l1-1-0", "kernel32.dll"},
    {"api-ms-win-core-ums-l1-1-0", "kernel32.dll"},
    {"api-ms-win-core-url-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-util-l1-1-0", "kernel32.dll"},
    {"api-ms-win-core-version-l1-1-1", "kernelbase.dll"},
    {"api-ms-win-core-version-private-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-versionansi-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-windowsceip-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-core-windowserrorreporting-l1-1-1", "kernelbase.dll"},
    {"api-ms-win-core-wow64-l1-1-1", "kernelbase.dll"},
    {"api-ms-win-core-xstate-l1-1-0", "ntdll.dll"},
    {"api-ms-win-core-xstate-l2-1-0", "kernelbase.dll"},
    {"api-ms-win-crt-conio-l1-1-0", "ucrtbase.dll"},
    {"api-ms-win-crt-convert-l1-1-0", "ucrtbase.dll"},
    {"api-ms-win-crt-environment-l1-1-0", "ucrtbase.dll"},
    {"api-ms-win-crt-filesystem-l1-1-0", "ucrtbase.dll"},
    {"api-ms-win-crt-heap-l1-1-0", "ucrtbase.dll"},
    {"api-ms-win-crt-locale-l1-1-0", "ucrtbase.dll"},
    {"api-ms-win-crt-math-l1-1-0", "ucrtbase.dll"},
    {"api-ms-win-crt-multibyte-l1-1-0", "ucrtbase.dll"},
    {"api-ms-win-crt-private-l1-1-0", "ucrtbase.dll"},
    {"api-ms-win-crt-process-l1-1-0", "ucrtbase.dll"},
    {"api-ms-win-crt-runtime-l1-1-0", "ucrtbase.dll"},
    {"api-ms-win-crt-stdio-l1-1-0", "ucrtbase.dll"},
    {"api-ms-win-crt-string-l1-1-0", "ucrtbase.dll"},
    {"api-ms-win-crt-time-l1-1-0", "ucrtbase.dll"},
    {"api-ms-win-crt-utility-l1-1-0", "ucrtbase.dll"},
    {"api-ms-win-deprecated-apis-obsolete-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-downlevel-advapi32-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-downlevel-advapi32-l4-1-0", "advapi32.dll"},
    {"api-ms-win-downlevel-kernel32-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-downlevel-kernel32-l2-1-0", "kernel32.dll"},
    {"api-ms-win-downlevel-normaliz-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-downlevel-shlwapi-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-downlevel-user32-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-downlevel-version-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-dx-d3dkmt-l1-1-0", "gdi32.dll"},
    {"api-ms-win-eventing-classicprovider-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-eventing-legacy-l1-1-0", "advapi32.dll"},
    {"api-ms-win-eventing-provider-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-eventlog-legacy-l1-1-0", "advapi32.dll"},
    {"api-ms-win-eventlog-private-l1-1-0", "advapi32.dll"},
    {"api-ms-win-gaming-deviceinformation-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-gdi-dpiinfo-l1-1-0", "gdi32.dll"},
    {"api-ms-win-http-time-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-legacy-shlwapi-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-ntuser-dc-access-l1-1-0", "user32.dll"},
    {"api-ms-win-ntuser-ie-message-l1-1-0", "user32.dll"},
    {"api-ms-win-ntuser-ie-window-l1-1-0", "user32.dll"},
    {"api-ms-win-ntuser-ie-wmpointer-l1-1-0", "user32.dll"},
    {"api-ms-win-ntuser-rectangle-l1-1-0", "user32.dll"},
    {"api-ms-win-ntuser-sysparams-l1-1-0", "user32.dll"},
    {"api-ms-win-obsolete-localization-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-obsolete-psapi-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-obsolete-shlwapi-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-ole32-ie-l1-1-0", "ole32.dll"},
    {"api-ms-win-oobe-notification-l1-1-0", "kernel32.dll"},
    {"api-ms-win-perf-legacy-l1-1-0", "advapi32.dll"},
    {"api-ms-win-rtcore-ntuser-clipboard-l1-1-0", "user32.dll"},
    {"api-ms-win-rtcore-ntuser-draw-l1-1-0", "user32.dll"},
    {"api-ms-win-rtcore-ntuser-powermanagement-l1-1-0", "user32.dll"},
    {"api-ms-win-rtcore-ntuser-private-l1-1-0", "user32.dll"},
    {"api-ms-win-rtcore-ntuser-shell-l1-1-0", "user32.dll"},
    {"api-ms-win-rtcore-ntuser-synch-l1-1-0", "user32.dll"},
    {"api-ms-win-rtcore-ntuser-window-l1-1-0", "user32.dll"},
    {"api-ms-win-rtcore-ntuser-winevent-l1-1-0", "user32.dll"},
    {"api-ms-win-rtcore-ntuser-wmpointer-l1-1-0", "user32.dll"},
    {"api-ms-win-rtcore-ntuser-wmpointer-l1-2-0", "user32.dll"},
    {"api-ms-win-rtcore-ole32-clipboard-l1-1-0", "ole32.dll"},
    {"api-ms-win-security-appcontainer-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-security-base-ansi-l1-1-0", "advapi32.dll"},
    {"api-ms-win-security-base-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-security-base-l1-2-0", "kernelbase.dll"},
    {"api-ms-win-security-base-private-l1-1-1", "kernelbase.dll"},
    {"api-ms-win-security-cpwl-l1-1-0", "advapi32.dll"},
    {"api-ms-win-security-grouppolicy-l1-1-0", "kernelbase.dll"},
    {"api-ms-win-security-logon-l1-1-1", "advapi32.dll"},
    {"api-ms-win-security-lsalookup-ansi-l2-1-0", "advapi32.dll"},
    {"api-ms-win-security-lsalookup-l2-1-1", "advapi32.dll"},
    {"api-ms-win-security-provider-ansi-l1-1-0", "advapi32.dll"},
    {"api-ms-win-security-provider-l1-1-0", "advapi32.dll"},
    {"api-ms-win-security-sddl-ansi-l1-1-0", "advapi32.dll"},
    {"api-ms-win-security-systemfunctions-l1-1-0", "advapi32.dll"},
    {"api-ms-win-security-trustee-l1-1-1", "advapi32.dll"},
    {"api-ms-win-service-core-ansi-l1-1-0", "advapi32.dll"},
    {"api-ms-win-service-legacy-l1-1-0", "advapi32.dll"},
    {"api-ms-win-shell-shellcom-l1-1-0", "shell32.dll"},
    {"api-ms-win-shlwapi-ie-l1-1-0", "shlwapi.dll"},
    {"api-ms-win-shlwapi-winrt-storage-l1-1-1", "shlwapi.dll"},
    {"api-ms-win-stateseparation-helpers-l1-1-0", "kernelbase.dll"},
    {"ext-ms-onecore-shlwapi-l1-1-0", "shlwapi.dll"},
    {"ext-ms-win-advapi32-auth-l1-1-0", "advapi32.dll"},
    {"ext-ms-win-advapi32-encryptedfile-l1-1-0", "advapi32.dll"},
    {"ext-ms-win-advapi32-eventingcontroller-l1-1-0", "advapi32.dll"},
    {"ext-ms-win-advapi32-eventlog-ansi-l1-1-0", "advapi32.dll"},
    {"ext-ms-win-advapi32-eventlog-l1-1-1", "advapi32.dll"},
    {"ext-ms-win-advapi32-hwprof-l1-1-0", "advapi32.dll"},
    {"ext-ms-win-advapi32-idletask-l1-1-0", "advapi32.dll"},
    {"ext-ms-win-advapi32-lsa-l1-1-0", "advapi32.dll"},
    {"ext-ms-win-advapi32-msi-l1-1-0", "advapi32.dll"},
    {"ext-ms-win-advapi32-npusername-l1-1-0", "advapi32.dll"},
    {"ext-ms-win-advapi32-ntmarta-l1-1-0", "advapi32.dll"},
    {"ext-ms-win-advapi32-registry-l1-1-0", "advapi32.dll"},
    {"ext-ms-win-advapi32-safer-l1-1-0", "advapi32.dll"},
    {"ext-ms-win-advapi32-shutdown-l1-1-0", "advapi32.dll"},
    {"ext-ms-win-com-ole32-l1-1-3", "ole32.dll"},
    {"ext-ms-win-com-ole32-l1-2-0", "ole32.dll"},
    {"ext-ms-win-com-ole32-l1-3-0", "ole32.dll"},
    {"ext-ms-win-com-ole32-l1-4-0", "ole32.dll"},
    {"ext-ms-win-com-sta-l1-1-0", "ole32.dll"},
    {"ext-ms-win-compositor-hosting-l1-1-0", "user32.dll"},
    {"ext-ms-win-core-marshal-l2-1-0", "ole32.dll"},
    {"ext-ms-win-dx-d3dkmt-gdi-l1-1-0", "gdi32.dll"},
    {"ext-ms-win-gdi-clipping-l1-1-0", "gdi32.dll"},
    {"ext-ms-win-gdi-dc-create-l1-1-1", "gdi32.dll"},
    {"ext-ms-win-gdi-dc-l1-2-0", "gdi32.dll"},
    {"ext-ms-win-gdi-devcaps-l1-1-0", "gdi32.dll"},
    {"ext-ms-win-gdi-draw-l1-1-1", "gdi32.dll"},
    {"ext-ms-win-gdi-font-l1-1-1", "gdi32.dll"},
    {"ext-ms-win-gdi-internal-desktop-l1-1-4", "gdi32.dll"},
    {"ext-ms-win-gdi-internal-uap-init-l1-1-0", "gdi32.dll"},
    {"ext-ms-win-gdi-metafile-l1-1-2", "gdi32.dll"},
    {"ext-ms-win-gdi-path-l1-1-0", "gdi32.dll"},
    {"ext-ms-win-gdi-print-l1-1-0", "gdi32.dll"},
    {"ext-ms-win-gdi-private-l1-1-0", "gdi32.dll"},
    {"ext-ms-win-gdi-render-l1-1-0", "gdi32.dll"},
    {"ext-ms-win-gdi-rgn-l1-1-0", "gdi32.dll"},
    {"ext-ms-win-gdi-wcs-l1-1-0", "gdi32.dll"},
    {"ext-ms-win-kernel32-appcompat-l1-1-0", "kernel32.dll"},
    {"ext-ms-win-kernel32-datetime-l1-1-0", "kernel32.dll"},
    {"ext-ms-win-kernel32-elevation-l1-1-0", "kernel32.dll"},
    {"ext-ms-win-kernel32-errorhandling-l1-1-0", "kernel32.dll"},
    {"ext-ms-win-kernel32-file-l1-1-0", "kernel32.dll"},
    {"ext-ms-win-kernel32-localization-l1-1-0", "kernel32.dll"},
    {"ext-ms-win-kernel32-package-current-l1-1-0", "kernelbase.dll"},
    {"ext-ms-win-kernel32-package-l1-1-1", "kernelbase.dll"},
    {"ext-ms-win-kernel32-process-l1-1-0", "kernel32.dll"},
    {"ext-ms-win-kernel32-quirks-l1-1-1", "kernel32.dll"},
    {"ext-ms-win-kernel32-registry-l1-1-0", "kernel32.dll"},
    {"ext-ms-win-kernel32-sidebyside-l1-1-0", "kernel32.dll"},
    {"ext-ms-win-kernel32-transacted-l1-1-0", "kernel32.dll"},
    {"ext-ms-win-kernel32-updateresource-l1-1-0", "kernel32.dll"},
    {"ext-ms-win-kernel32-windowserrorreporting-l1-1-1", "kernel32.dll"},
    {"ext-ms-win-kernelbase-processthread-l1-1-0", "kernel32.dll"},
    {"ext-ms-win-kernelbase-processthread-l1-2-0", "kernel32.dll"},
    {"ext-ms-win-ntuser-caret-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-chartranslation-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-dc-access-ext-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-dde-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-dialogbox-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-draw-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-gui-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-gui-l1-2-0", "user32.dll"},
    {"ext-ms-win-ntuser-gui-l1-3-0", "user32.dll"},
    {"ext-ms-win-ntuser-keyboard-ansi-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-keyboard-l1-1-1", "user32.dll"},
    {"ext-ms-win-ntuser-keyboard-l1-2-0", "user32.dll"},
    {"ext-ms-win-ntuser-keyboard-l1-3-0", "user32.dll"},
    {"ext-ms-win-ntuser-menu-l1-1-2", "user32.dll"},
    {"ext-ms-win-ntuser-message-l1-1-1", "user32.dll"},
    {"ext-ms-win-ntuser-misc-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-misc-l1-2-0", "user32.dll"},
    {"ext-ms-win-ntuser-misc-l1-3-0", "user32.dll"},
    {"ext-ms-win-ntuser-misc-l1-5-1", "user32.dll"},
    {"ext-ms-win-ntuser-misc-l1-6-0", "user32.dll"},
    {"ext-ms-win-ntuser-misc-l1-7-0", "user32.dll"},
    {"ext-ms-win-ntuser-mit-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-mouse-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-powermanagement-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-private-l1-1-1", "user32.dll"},
    {"ext-ms-win-ntuser-private-l1-2-0", "user32.dll"},
    {"ext-ms-win-ntuser-private-l1-3-3", "user32.dll"},
    {"ext-ms-win-ntuser-private-l1-4-0", "user32.dll"},
    {"ext-ms-win-ntuser-private-l1-5-0", "user32.dll"},
    {"ext-ms-win-ntuser-private-l1-6-0", "user32.dll"},
    {"ext-ms-win-ntuser-rawinput-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-rawinput-l1-2-0", "user32.dll"},
    {"ext-ms-win-ntuser-rectangle-ext-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-rim-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-rim-l1-2-0", "user32.dll"},
    {"ext-ms-win-ntuser-rotationmanager-l1-1-1", "user32.dll"},
    {"ext-ms-win-ntuser-server-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-string-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-synch-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-sysparams-ext-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-touch-hittest-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-uicontext-ext-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-window-l1-1-4", "user32.dll"},
    {"ext-ms-win-ntuser-windowclass-l1-1-1", "user32.dll"},
    {"ext-ms-win-ntuser-windowstation-ansi-l1-1-0", "user32.dll"},
    {"ext-ms-win-ntuser-windowstation-l1-1-1", "user32.dll"},
    {"ext-ms-win-ole32-bindctx-l1-1-0", "ole32.dll"},
    {"ext-ms-win-ole32-ie-ext-l1-1-0", "ole32.dll"},
    {"ext-ms-win-ole32-oleautomation-l1-1-0", "ole32.dll"},
    {"ext-ms-win-rtcore-gdi-devcaps-l1-1-0", "gdi32.dll"},
    {"ext-ms-win-rtcore-gdi-object-l1-1-0", "gdi32.dll"},
    {"ext-ms-win-rtcore-gdi-rgn-l1-1-0", "gdi32.dll"},
    {"ext-ms-win-rtcore-ntuser-cursor-l1-1-0", "user32.dll"},
    {"ext-ms-win-rtcore-ntuser-dc-access-l1-1-0", "user32.dll"},
    {"ext-ms-win-rtcore-ntuser-dpi-l1-1-0", "user32.dll"},
    {"ext-ms-win-rtcore-ntuser-dpi-l1-2-0", "user32.dll"},
    {"ext-ms-win-rtcore-ntuser-iam-l1-1-0", "user32.dll"},
    {"ext-ms-win-rtcore-ntuser-inputintercept-l1-1-0", "user32.dll"},
    {"ext-ms-win-rtcore-ntuser-integration-l1-1-0", "user32.dll"},
    {"ext-ms-win-rtcore-ntuser-keyboard-l1-1-0", "user32.dll"},
    {"ext-ms-win-rtcore-ntuser-message-ansi-l1-1-0", "user32.dll"},
    {"ext-ms-win-rtcore-ntuser-message-l1-1-0", "user32.dll"},
    {"ext-ms-win-rtcore-ntuser-rawinput-l1-1-0", "user32.dll"},
    {"ext-ms-win-rtcore-ntuser-rawinput-l1-2-0", "user32.dll"},
    {"ext-ms-win-rtcore-ntuser-synch-ext-l1-1-0", "user32.dll"},
    {"ext-ms-win-rtcore-ntuser-syscolors-l1-1-0", "user32.dll"},
    {"ext-ms-win-rtcore-ntuser-sysparams-l1-1-0", "user32.dll"},
    {"ext-ms-win-rtcore-ntuser-usersecurity-l1-1-0", "user32.dll"},
    {"ext-ms-win-rtcore-ntuser-window-ansi-l1-1-0", "user32.dll"},
    {"ext-ms-win-rtcore-ntuser-window-ext-l1-1-0", "user32.dll"},
    {"ext-ms-win-rtcore-ntuser-window-l1-1-0", "user32.dll"},
    {"ext-ms-win-rtcore-ntuser-winevent-ext-l1-1-0", "user32.dll"},
    {"ext-ms-win-rtcore-ntuser-wmpointer-l1-1-0", "user32.dll"},
    {"ext-ms-win-rtcore-ole32-dragdrop-l1-1-0", "ole32.dll"},
    {"ext-ms-win-rtcore-ole32-misc-l1-1-0", "ole32.dll"},
    {"ext-ms-win-setupapi-classinstallers-l1-1-2", "setupapi.dll"},
    {"ext-ms-win-setupapi-inf-l1-1-1", "setupapi.dll"},
    {"ext-ms-win-setupapi-logging-l1-1-0", "setupapi.dll"},
    {"ext-ms-win-shell-exports-internal-l1-1-0", "shell32.dll"},
    {"ext-ms-win-shell-shell32-l1-2-0", "shell32.dll"},
    {"ext-ms-win-shell-shell32-l1-3-0", "shell32.dll"},
    {"ext-ms-win-shell-shell32-l1-4-0", "shell32.dll"},
    {"ext-ms-win-shell-shell32-l1-5-0", "shell32.dll"},
    {"ext-ms-win-shell-shlwapi-l1-1-1", "shlwapi.dll"},
    {"ext-ms-win-shell-shlwapi-l1-2-0", "shlwapi.dll"},
    {"ext-ms-win-usp10-l1-1-0", "gdi32.dll"},
};

// The prefix every API set name carries. A name that does not start with it
// is an ordinary module name and is left for the ordinary lookup, because
// resolving an ordinary name through this table would be guessing.
constexpr std::string_view kApiSetPrefix = "api-ms-win-";
constexpr std::string_view kExtensionPrefix = "ext-ms-win-";

// The suffix a module name carries and an API set name does not.
constexpr std::string_view kDllSuffix = ".dll";

[[nodiscard]] std::string lower_of(std::string_view text) {
    std::string out(text);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

}  // namespace

bool is_api_set_name(std::string_view name) noexcept {
    return name.size() > kApiSetPrefix.size() &&
           (name.substr(0, kApiSetPrefix.size()) == kApiSetPrefix ||
            name.substr(0, kExtensionPrefix.size()) == kExtensionPrefix);
}

std::string resolve_api_set(std::string_view name) {
    if (!is_api_set_name(name)) {
        return std::string();
    }
    // The import table spells the name with the extension and the table does
    // not, which is the arrangement both use: the table's left column is the
    // contract's own name and the import adds the extension the loader
    // strips before matching.
    std::string key = lower_of(name);
    if (key.size() > kDllSuffix.size() &&
        key.compare(key.size() - kDllSuffix.size(), kDllSuffix.size(),
                    kDllSuffix) == 0) {
        key.resize(key.size() - kDllSuffix.size());
    }

    const auto* begin = std::begin(kApiSets);
    const auto* end = std::end(kApiSets);
    const auto* found = std::lower_bound(
        begin, end, key, [](const ApiSetEntry& entry, const std::string& what) {
            return std::string_view(entry.name) < what;
        });
    if (found == end || key != found->name) {
        // A contract this runtime does not implement. The empty answer is
        // what the loader turns into a load failure that names the contract,
        // which is more useful than a guess at a module that might have it.
        return std::string();
    }
    return std::string(found->target);
}

std::size_t api_set_count() noexcept {
    return std::size(kApiSets);
}

}  // namespace occ::runtime

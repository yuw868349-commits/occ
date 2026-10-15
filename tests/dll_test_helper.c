/*
 * The test library the DLL runtime's test loads.
 *
 * Built by the test's build rule with the mingw cross compiler, because the
 * point of the test is a *real* library: one the Windows toolchain produced,
 * with the headers it produces, exporting the symbols it exports. A
 * hand-built PE would test this runtime's image writer rather than its
 * loader, and the loader is what this is for.
 *
 * The exports are the four shapes a call can take -- no arguments, integer
 * arguments, floating-point arguments, mixed -- plus one that reports
 * whether the entry point ran, which is how the test checks the load's
 * order and its once-only property.
 */

#include <windows.h>

static int entry_count = 0;

__declspec(dllexport) int helper_answer(void) { return 42; }

__declspec(dllexport) int helper_add(int a, int b) { return a + b; }

__declspec(dllexport) unsigned long long helper_mul(unsigned long long a,
                                                    unsigned long long b) {
    return a * b;
}

__declspec(dllexport) double helper_half(double x) { return x / 2.0; }

__declspec(dllexport) double helper_mix(int a, double b) { return a + b; }

__declspec(dllexport) double helper_scale(double a, int b) { return a * b; }

/* The entry point's count, which the test reads to check that the load ran
 * the entry point exactly once. */
__declspec(dllexport) int helper_entries(void) { return entry_count; }

/* The string is returned, not copied: the test passes an address the
 * runtime placed and checks that the answer is the same address, which is
 * what a function that returns its argument does. */
__declspec(dllexport) const char* helper_echo(const char* text) {
    return text;
}

BOOL WINAPI DllMain(HINSTANCE self, DWORD reason, LPVOID reserved) {
    (void)self;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        entry_count += 1;
    }
    return TRUE;
}

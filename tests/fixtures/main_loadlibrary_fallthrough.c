/* Sibling to main_loadlibrary.c, for the hook's *fallthrough* path
 * (tests/windows/test_pe_hook_runtime.py): with an embedded dependency
 * present (so the LoadLibraryW/LoadLibraryA/GetProcAddress hook is
 * actually installed), ordinary LoadLibrary/GetProcAddress calls
 * against a real, non-embedded system DLL (KERNEL32.dll itself) must
 * still behave exactly like the unhooked real APIs. Resolving
 * GetCurrentProcessId this way and comparing it against a normal,
 * statically-linked call to the same function in the same process is a
 * real, independently-checkable correctness proof -- not just "didn't
 * crash" -- with no observable side effects (unlike e.g. MessageBeep).
 *
 * Statically imports (and calls) lib.dll's own `lib_value` -- unlike
 * main_loadlibrary.c, this one needs the embedder to actually *embed* a
 * dependency (which only happens for something the host's own import
 * table names) so the hook is genuinely installed at all; the point of
 * this test is the fallthrough path for *other*, non-embedded names,
 * not the embedded-match path main_loadlibrary.c already covers.
 */
#include <windows.h>

__declspec(dllimport) int lib_value(void);

typedef DWORD (WINAPI *get_pid_fn)(void);

int main(void) {
    if (lib_value() != 42) {
        return 9;
    }

    HMODULE h = LoadLibraryW(L"KERNEL32.DLL");
    if (!h) {
        return 1;
    }

    get_pid_fn fn = (get_pid_fn)GetProcAddress(h, "GetCurrentProcessId");
    if (!fn) {
        return 2;
    }

    DWORD via_hooked_path = fn();
    DWORD via_direct_call = GetCurrentProcessId();
    if (via_hooked_path != via_direct_call) {
        return 3;
    }

    HMODULE h2 = LoadLibraryA("kernel32.dll");
    if (!h2) {
        return 4;
    }

    return 0;
}

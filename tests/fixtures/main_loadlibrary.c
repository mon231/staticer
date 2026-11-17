/* Host for the LoadLibraryW/LoadLibraryA/GetProcAddress runtime-hook
 * regression test (tests/windows/test_pe_hook_runtime.py).
 *
 * Statically imports (and calls) lib.dll's own `lib_value` -- embed()
 * only ever embeds a DLL the host's own import graph actually names
 * (there's no "force embed this" mechanism, nor should there be), so
 * this is what makes lib.dll an embedded dependency *at all*, exactly
 * the way a real app's own compiled code is what makes a real framework
 * DLL (e.g. Qt6Core.dll) an embedded dependency in the first place.
 *
 * Separately -- and this is the actual thing under test -- it ALSO
 * calls LoadLibraryW/LoadLibraryA + GetProcAddress on that *same* name
 * at runtime, entirely independent of the static import above, mirroring
 * a second, unrelated code path in the same process asking for an
 * already-embedded dependency by name (e.g. a plugin loader's own
 * dynamic resolution) -- exactly the chain the hook is meant to
 * intercept, and prove it resolves against the *same* embedded copy.
 */
#include <windows.h>

__declspec(dllimport) int lib_value(void);

int main(void) {
    if (lib_value() != 42) {
        return 9;
    }

    HMODULE h1 = LoadLibraryW(L"lib.dll");
    if (!h1) {
        return 1;
    }

    typedef int (*lib_value_fn)(void);
    lib_value_fn fn = (lib_value_fn)GetProcAddress(h1, "lib_value");
    if (!fn) {
        return 2;
    }
    if (fn() != 42) {
        return 3;
    }

    /* A second, independent LoadLibraryA call for the same name must
     * resolve to the exact same (embedded) base -- real LoadLibrary
     * is required to do this too (it bumps a refcount rather than
     * mapping a second copy), and our hook's own match table lookup
     * is deterministic, so this should hold either way. */
    HMODULE h2 = LoadLibraryA("lib.dll");
    if (!h2) {
        return 4;
    }
    if (h2 != h1) {
        return 5;
    }

    /* GetProcAddress for a name this module does NOT export must
     * return NULL, not crash and not resolve to something bogus. */
    if (GetProcAddress(h1, "no_such_export_xyz") != NULL) {
        return 6;
    }

    return 0;
}

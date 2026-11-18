/* Host for the LdrRegisterDllNotification-based hook regression test
 * (tests/windows/test_pe_hook_runtime.py) -- the real-world shape being
 * 010 Editor's own qwindows.dll Qt platform plugin.
 *
 * Statically imports lib.dll (same reason as main_loadlibrary.c -- this
 * is what makes it an embedded dependency at all). Separately -- the
 * actual thing under test -- it loads plugin.dll (NOT statically
 * imported by this host, so embed() never embeds it) at runtime via
 * LoadLibraryW, exactly like a plugin loader. plugin.dll ITSELF
 * statically imports lib.dll by name.
 *
 * Unlike main_loadlibrary.c's own test, this does NOT delete lib.dll
 * from disk first: by the time LDR_DLL_NOTIFICATION_REASON_LOADED fires
 * for plugin.dll, the real loader has ALREADY had to recursively, really
 * resolve plugin.dll's own static dependency on lib.dll via the real
 * filesystem (confirmed concretely: deleting lib.dll first makes
 * LoadLibraryW("plugin.dll") itself fail with ERROR_MOD_NOT_FOUND,
 * regardless of whether this hook works correctly at all -- the
 * notification simply never gets a chance to fire for a module whose own
 * dependencies couldn't be resolved in the first place). This is exactly
 * the real 010 Editor shape too: Qt6Core.dll/Qt6Gui.dll's own files stay
 * on disk even once embedded, so the real loader DOES load a real,
 * separate, wasteful-but-successful duplicate copy as a side effect of
 * resolving qwindows.dll's own import table -- the hook's actual job is
 * to redirect plugin.dll's own *calls* through that already-resolved IAT
 * slot to the embedded copy afterward, not to prevent the duplicate load
 * from happening at all.
 *
 * So the real proof here is address-based, not file-presence-based:
 * plugin_get_lib_address() returns the actual address of the lib.dll
 * code that ran (lib_value_self_address() -- not a thunk, not an IAT
 * slot, the real function body). GetModuleHandleExW with
 * GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS maps that address back to
 * whichever module it physically lives in; comparing that against this
 * host's own module handle (GetModuleHandleW(NULL) -- the embedded copy
 * lives INSIDE the host's own image, with no separate module boundary at
 * all, unlike a real duplicate) tells us, unambiguously, whether the
 * call was redirected to the embedded copy or fell through to whatever
 * real, separate copy the loader's own recursive dependency resolution
 * already loaded.
 */
#include <windows.h>

__declspec(dllimport) int lib_value(void);

int main(void) {
    if (lib_value() != 42) {
        return 9;
    }

    HMODULE h = LoadLibraryW(L"plugin.dll");
    if (!h) {
        return 1;
    }

    typedef unsigned long long (*get_addr_fn)(void);
    get_addr_fn fn = (get_addr_fn)GetProcAddress(h, "plugin_get_lib_address");
    if (!fn) {
        return 2;
    }

    unsigned long long called_addr = fn();

    HMODULE called_module = NULL;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            (LPCWSTR)(UINT_PTR)called_addr,
            &called_module)) {
        return 4;
    }

    HMODULE self = GetModuleHandleW(NULL);
    if (called_module != self) {
        /* Resolved against a real, separate (duplicate) module instead
         * of the embedded copy -- exactly the Qt-plugin-duplication gap
         * this hook exists to fix. */
        return 5;
    }

    return 0;
}

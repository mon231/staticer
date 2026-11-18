/* Stand-in for a 010-Editor-style "plugin" DLL (the real-world shape being
 * `qwindows.dll`): loaded dynamically, by name, by the host at runtime
 * (never statically imported by the host itself, so embed() never embeds
 * *this* file) -- but it ITSELF statically imports an embedded dependency
 * (lib.dll) at compile time, the exact shape the LdrRegisterDllNotification
 * hook (tests/windows/test_pe_hook_runtime.py's
 * test_third_party_plugin_statically_importing_embedded_dependency_
 * resolves_against_embedded_copy) exists to fix -- the KERNEL32-level
 * LoadLibraryW/GetProcAddress hook alone does NOT see this import at all,
 * since it's resolved by the OS loader's own internal import-snap
 * machinery while mapping plugin.dll, never through an explicit
 * application-level LoadLibrary/GetProcAddress call.
 */
#include <windows.h>

__declspec(dllimport) int lib_value(void);
__declspec(dllimport) unsigned long long lib_value_self_address(void);

__declspec(dllexport) int plugin_call(void) {
    return lib_value();
}

/* See lib.c's own comment on `lib_value_self_address` -- exposes which
 * PHYSICAL copy of lib.dll's code this plugin's own (real, OS-resolved)
 * static import actually calls through, for the host to inspect. */
__declspec(dllexport) unsigned long long plugin_get_lib_address(void) {
    return lib_value_self_address();
}

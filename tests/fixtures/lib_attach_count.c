// Dependency DLL with a custom DllMain that counts DLL_PROCESS_ATTACH
// notifications -- used by test_dll_as_output_runs_dep_init_once (B6-PE) to
// confirm the generated stub only runs each embedded dependency's own init
// once (at the *output* DLL's own process-attach), not on every subsequent
// thread attach/detach notification the OS also delivers to a loaded DLL's
// entry point.
#include <windows.h>

#if defined(_MSC_VER)
#define STATICER_EXPORT __declspec(dllexport)
#else
#define STATICER_EXPORT
#endif

static volatile long attach_count = 0;

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)hinst;
    (void)reserved;
    if (reason == 1 /* DLL_PROCESS_ATTACH */) {
        attach_count++;
    }
    return TRUE;
}

STATICER_EXPORT long get_attach_count(void) {
    return attach_count;
}

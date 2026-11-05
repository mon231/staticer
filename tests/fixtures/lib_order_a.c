// Part of the init-order pair with lib_order_b.c (see main_order.c and
// test_dependency_initializer_runs_before_dependent). main.exe directly
// imports both this and lib_order_b.dll, with no import edge between the
// two DLLs themselves -- their relative embed/init order is therefore
// whatever order the host's own import table lists them in (which
// `list_pe_imports(main.exe)` empirically returns as this DLL first, for
// this fixture pair, consistently across rebuilds), exactly mirroring how
// `embed_order` walks the dependency graph for two otherwise-unrelated
// top-level dependencies. This DLL's DllMain runs first and sets a
// process-wide marker; lib_order_b.c's DllMain checks for it.
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        SetEnvironmentVariableA("STATICER_ORDER_FLAG", "1");
    }
    return TRUE;
}

__declspec(dllexport) int lib_order_a_marker(void) { return 0; }

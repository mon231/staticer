// See lib_order_a.c's comment. This DLL's DllMain runs second (per
// `embed_order`/the host's own import order) and records whether
// lib_order_a.c's DllMain already ran (set the env-var marker) by the
// time it gets control -- the only way that can be true once both DLLs
// are embedded (removed from the import table entirely) is if the
// generated stub itself called lib_order_a's entry point first, in
// `init_order`'s sequence, exactly as intended.
#include <windows.h>

__declspec(dllexport) int g_b_saw_a_attached = -1;

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        char buf[8] = {0};
        DWORD n = GetEnvironmentVariableA("STATICER_ORDER_FLAG", buf, sizeof(buf));
        g_b_saw_a_attached = (n > 0 && buf[0] == '1') ? 1 : 0;
    }
    return TRUE;
}

__declspec(dllexport) int lib_order_b_marker(void) { return 0; }

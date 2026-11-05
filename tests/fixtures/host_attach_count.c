// Host *DLL* (not EXE) for test_dll_as_output_runs_dep_init_once (B6-PE) --
// imports lib_attach_count.dll and re-exports a thin wrapper so the test
// can read the dependency's own DLL_PROCESS_ATTACH counter via ctypes
// after loading the embedded output.
#if defined(_MSC_VER)
#define STATICER_EXPORT __declspec(dllexport)
#else
#define STATICER_EXPORT
#endif

long get_attach_count(void);

STATICER_EXPORT long host_get_attach_count(void) {
    return get_attach_count();
}

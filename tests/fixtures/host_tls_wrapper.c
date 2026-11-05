// Host DLL for test_pe_tls.py's multi-thread TLS case -- imports
// lib_tls_simple.dll and re-exports a thin wrapper so the test can call
// its TLS-backed counter (via ctypes, from several real OS threads)
// after loading the embedded output.
#if defined(_MSC_VER)
#define STATICER_EXPORT __declspec(dllexport)
#else
#define STATICER_EXPORT
#endif

int lib_tls_bump(void);

STATICER_EXPORT int host_bump(void) {
    return lib_tls_bump();
}

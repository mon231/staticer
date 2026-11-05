// A dependency DLL carrying one simple __declspec(thread)/__thread
// variable (no callbacks, AddressOfCallBacks == 0 -- the synthetic,
// callback-free sub-case of PE TLS-directory merging) -- used by
// test_pe_tls.py to prove the raw-data/index mechanism actually works
// end to end (the embedded, per-thread counter increments and reads back
// correctly after real embed()+run), not just "doesn't crash".
#if defined(_MSC_VER)
#define STATICER_EXPORT __declspec(dllexport)
#define THREAD_LOCAL __declspec(thread)
#else
#define STATICER_EXPORT
#define THREAD_LOCAL __thread
#endif

THREAD_LOCAL int counter = 0;

STATICER_EXPORT int lib_tls_bump(void) {
    counter++;
    return counter;
}

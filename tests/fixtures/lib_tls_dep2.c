// A second, independent TLS-bearing dependency DLL, sibling to
// lib_tls_dep.c -- used together with it by the three-way
// (host-owns-TLS + two TLS-bearing dependencies) merge test, the N-way
// generalization of Task 5's phase-2 mechanism for the
// host-already-has-TLS case. A different global/export name from
// lib_tls_dep.c's own, so aliasing the two onto the same storage is
// detectable.
#if defined(_MSC_VER)
#define STATICER_EXPORT __declspec(dllexport)
#define THREAD_LOCAL __declspec(thread)
#else
#define STATICER_EXPORT
#define THREAD_LOCAL __thread
#endif

THREAD_LOCAL int dep_tls_counter2 = 9;

STATICER_EXPORT int lib_tls_value2(void) {
    return dep_tls_counter2;
}

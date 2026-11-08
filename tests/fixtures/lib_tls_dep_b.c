// See lib_tls_dep_a.c's comment -- this is its independent sibling, used
// together to prove PE TLS merging works for more than one TLS-bearing
// dependency in the same embed() run. Its own counter starts at 0 and is
// bumped by lib_tls_dep_b_bump(); a different global name and export name
// from lib_tls_dep_a.c's, so aliasing the two onto the same storage is
// detectable rather than silently matching by coincidence.
#if defined(_MSC_VER)
#define STATICER_EXPORT __declspec(dllexport)
#define THREAD_LOCAL __declspec(thread)
#else
#define STATICER_EXPORT
#define THREAD_LOCAL __thread
#endif

THREAD_LOCAL int dep_b_counter = 0;

STATICER_EXPORT int lib_tls_dep_b_bump(void) {
    dep_b_counter++;
    return dep_b_counter;
}

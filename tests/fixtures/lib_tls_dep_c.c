// Third sibling to lib_tls_dep_a.c/lib_tls_dep_b.c -- used only by the
// three-TLS-dependency non-aliasing test (a stronger proof than the
// two-dependency case that each dependency's own merged TLS slot really
// is independent, not just pairwise-non-aliased). Its own counter starts
// at 0 and is bumped by lib_tls_dep_c_bump().
#if defined(_MSC_VER)
#define STATICER_EXPORT __declspec(dllexport)
#define THREAD_LOCAL __declspec(thread)
#else
#define STATICER_EXPORT
#define THREAD_LOCAL __thread
#endif

THREAD_LOCAL int dep_c_counter = 0;

STATICER_EXPORT int lib_tls_dep_c_bump(void) {
    dep_c_counter++;
    return dep_c_counter;
}

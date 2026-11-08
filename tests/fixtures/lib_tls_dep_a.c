// One of two independently-TLS-bearing dependency DLLs used to prove PE
// TLS merging works for *more than one* TLS-bearing dependency in the
// same embed() run (the N-way generalization of Task 5's phase-2
// mechanism) -- this one's own counter starts at 0 and is bumped by
// lib_tls_dep_a_bump(). See lib_tls_dep_b.c for its independent sibling;
// the two deliberately use differently-named globals/exports so a merge
// bug that aliases them onto the same storage is detectable rather than
// silently matching by coincidence.
#if defined(_MSC_VER)
#define STATICER_EXPORT __declspec(dllexport)
#define THREAD_LOCAL __declspec(thread)
#else
#define STATICER_EXPORT
#define THREAD_LOCAL __thread
#endif

THREAD_LOCAL int dep_a_counter = 0;

STATICER_EXPORT int lib_tls_dep_a_bump(void) {
    dep_a_counter++;
    return dep_a_counter;
}

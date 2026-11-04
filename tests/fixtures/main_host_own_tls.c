// Host for test_pe_final_review_fixes.py's TLS negative case -- the HOST
// itself already carries a non-empty PE TLS directory (its own
// __declspec(thread)/__thread variable), and also imports lib_tls_dep.dll
// (which carries its own, separate TLS directory). Embedding
// lib_tls_dep.dll into *this* host is the phase-2/Task-5 case
// (two real TLS directories to merge into one) that staticer's PE
// embedder still refuses, unlike the TLS-less-host case Task 2 now
// supports.
#if defined(_MSC_VER)
#define THREAD_LOCAL __declspec(thread)
#else
#define THREAD_LOCAL __thread
#endif

THREAD_LOCAL int host_counter = 7;

int lib_tls_value(void);

int main(void) {
    return host_counter + lib_tls_value();
}

// Host for the N-way TLS-merge generalization's three-way-merge case:
// the HOST itself already carries its own non-empty TLS directory (its
// own host_counter, as in main_host_own_tls.c), and also imports *two*
// separate TLS-bearing dependencies (lib_tls_dep.dll's dep_tls_counter
// and lib_tls_dep2.dll's dep_tls_counter2) -- host + dep1 + dep2, all
// three merged into one combined raw-data range sharing the host's own
// real TLS index slot.
//
// main()'s return value packs all three distinct values into disjoint
// decimal digit ranges (host_counter*1000000 + lib_tls_value()*1000 +
// lib_tls_value2()) rather than a plain sum, so a merge bug that swaps,
// zero-fills, or aliases any of the three values onto the same storage
// changes this result in a way a plain sum could hide.
#if defined(_MSC_VER)
#define THREAD_LOCAL __declspec(thread)
#else
#define THREAD_LOCAL __thread
#endif

THREAD_LOCAL int host_counter = 7;

int lib_tls_value(void);
int lib_tls_value2(void);

int main(void) {
    return host_counter * 1000000 + lib_tls_value() * 1000 + lib_tls_value2();
}

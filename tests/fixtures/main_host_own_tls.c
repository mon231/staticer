// Host for tests/windows/test_pe_tls.py's phase-2 (Task 5) positive case
// and tests/linux/test_elf_tls.py's still-unsupported ELF negative case --
// the HOST itself already carries a non-empty TLS directory (its own
// __declspec(thread)/__thread variable), and also imports lib_tls_dep.dll
// (which carries its own, separate TLS directory). Embedding
// lib_tls_dep.dll into *this* host is the phase-2/Task-5 case (two real
// TLS directories to merge into one): on PE/Windows, staticer's embedder
// now supports this (64-bit hosts); on ELF/Linux it still refuses, unlike
// the TLS-less-host case Task 2/3 already support on both platforms.
//
// main()'s return value is deliberately `host_counter*1000 +
// lib_tls_value()`, not a plain sum -- a merge bug that swaps,
// zero-fills, or aliases the two independent TLS values onto the same
// storage must change this result in a way a plain sum (7+5 either way)
// could hide.
#if defined(_MSC_VER)
#define THREAD_LOCAL __declspec(thread)
#else
#define THREAD_LOCAL __thread
#endif

THREAD_LOCAL int host_counter = 7;

int lib_tls_value(void);

int main(void) {
    return host_counter * 1000 + lib_tls_value();
}

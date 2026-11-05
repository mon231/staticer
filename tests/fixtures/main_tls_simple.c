// Host for test_pe_tls.py's synthetic positive case -- imports
// lib_tls_simple.dll and calls its TLS-backed counter three times,
// returning the final (read-back) value as the process exit code. A
// correct TLS-directory merge must increment and read back the *same*
// per-thread slot across calls -- a wrong merge (e.g. aliasing onto an
// unrelated slot, or never getting a real index at all) would not
// reliably return 3.
int lib_tls_bump(void);

int main(void) {
    lib_tls_bump();
    lib_tls_bump();
    return lib_tls_bump();
}

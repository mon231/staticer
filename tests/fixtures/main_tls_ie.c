// Host for the ELF Initial-Exec TLS merge regression test: imports
// lib_tls_ie.so and calls its Initial-Exec-model TLS-backed counter
// three times, returning the final (read-back) value as the process
// exit code. A correct merge must resolve the R_X86_64_TPOFF64
// relocation to the real, now-single-module static TLS offset -- a
// wrong offset would read/write an unrelated memory location instead of
// the counter, and very likely not return 3.
int lib_tls_ie_bump(void);

int main(void) {
    lib_tls_ie_bump();
    lib_tls_ie_bump();
    return lib_tls_ie_bump();
}

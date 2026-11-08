// A dependency .so carrying a __thread variable compiled under the
// Initial-Exec TLS model (forces the compiler to emit a GOTTPOFF/
// R_X86_64_TPOFF64 relocation instead of the General-Dynamic
// DTPMOD64/DTPOFF64 pair every other TLS fixture in this project uses).
#if defined(__GNUC__)
__attribute__((tls_model("initial-exec")))
#endif
__thread int ie_counter = 0;

int lib_tls_ie_bump(void) {
    ie_counter++;
    return ie_counter;
}

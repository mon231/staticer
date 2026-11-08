// Host for the N-way TLS-merge generalization's first new positive case:
// a TLS-less host importing *two* independently TLS-bearing dependencies
// (lib_tls_dep_a.dll, lib_tls_dep_b.dll) in the same embed() run -- the
// case that used to hit embed()'s "more than one dependency" ValueError.
//
// dep_a's own counter is bumped 3 times, dep_b's own counter is bumped 7
// times; the return value (dep_a_final*1000 + dep_b_final) is
// deliberately not a plain sum of totals -- if the two dependencies'
// TLS slots were ever aliased onto the same storage (a merge bug), the
// first dependency's own bumps would leak into the second's count and
// change this result (e.g. 3010 instead of the correct 3007), not just
// "didn't crash".
int lib_tls_dep_a_bump(void);
int lib_tls_dep_b_bump(void);

int main(void) {
    int a = 0, b = 0;
    for (int i = 0; i < 3; i++) {
        a = lib_tls_dep_a_bump();
    }
    for (int i = 0; i < 7; i++) {
        b = lib_tls_dep_b_bump();
    }
    return a * 1000 + b;
}

// Stronger, three-dependency non-aliasing proof: a TLS-less host
// importing *three* independently TLS-bearing dependencies
// (lib_tls_dep_a.dll, lib_tls_dep_b.dll, lib_tls_dep_c.dll) in the same
// embed() run. Each one's own counter is bumped a different number of
// times (3, 7, 11); the return value encodes all three final counts into
// disjoint decimal digit ranges so any pairwise or three-way aliasing
// bug changes the result rather than merely "didn't crash".
int lib_tls_dep_a_bump(void);
int lib_tls_dep_b_bump(void);
int lib_tls_dep_c_bump(void);

int main(void) {
    int a = 0, b = 0, c = 0;
    for (int i = 0; i < 3; i++) {
        a = lib_tls_dep_a_bump();
    }
    for (int i = 0; i < 7; i++) {
        b = lib_tls_dep_b_bump();
    }
    for (int i = 0; i < 11; i++) {
        c = lib_tls_dep_c_bump();
    }
    return a * 1000000 + b * 1000 + c;
}

/* See lib_ctor_b.c's comment for why this doesn't actually reference
 * anything from lib_ctor_b.c at the symbol level. */
long long a_seq = -1;

__attribute__((constructor))
static void a_ctor(void) {
    a_seq = (long long)__builtin_ia32_rdtsc();
}

long long a_seq_value(void) {
    return a_seq;
}

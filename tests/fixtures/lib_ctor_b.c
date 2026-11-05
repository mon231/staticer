/* Records when its own .init_array constructor ran, via the CPU's cycle
 * counter (a plain `rdtsc`, needing no external call at all -- elf_
 * embedder.py doesn't yet support a dependency that itself calls out
 * through its own PLT/relocations to another module, so this and
 * lib_ctor_a.c deliberately stay fully self-contained; see
 * main_ctor_order.c for how the host compares the two recorded values
 * to prove *order* without either dependency referencing the other's
 * symbols directly).
 *
 * lib_ctor_a.c links against this file (DT_NEEDED only, via
 * `-Wl,--no-as-needed`, with no actual symbol reference) purely so
 * ElfEmbedder's dependency graph records a real A-depends-on-B edge,
 * making embed_order's dependencies-first guarantee -- the thing this
 * test is actually checking -- meaningful. */
long long b_seq = -1;

__attribute__((constructor))
static void b_ctor(void) {
    b_seq = (long long)__builtin_ia32_rdtsc();
}

long long b_seq_value(void) {
    return b_seq;
}

extern long long a_seq_value(void);
extern long long b_seq_value(void);

int main(void) {
    /* lib_ctor_a.c "depends" on lib_ctor_b.c only via DT_NEEDED (see
     * lib_ctor_b.c's comment); embed_order's dependencies-first
     * guarantee means the generated stub must call lib_ctor_b's
     * constructor before lib_ctor_a's, so b's recorded rdtsc value
     * must come out strictly earlier than a's. */
    return (b_seq_value() < a_seq_value()) ? 42 : 1;
}

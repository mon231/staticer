/* Used by tests/linux/test_elf_no_reloc.py to force the host's own
 * extended PT_LOAD segment (`ext`, in elf_embedder.py's embed()) to grow
 * by a large, predictable amount -- large enough that a fixed-base
 * dependency's reservation, checked only against the host's *original*
 * vaddr range at the time it's placed, can still end up virtually
 * overlapping wherever `ext` actually grows to by the time embed() is
 * done. */
int lib_value(void) {
    return 42;
}

char big_buffer[2 * 1024 * 1024];

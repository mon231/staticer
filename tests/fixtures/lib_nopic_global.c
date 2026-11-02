/* Used by tests/linux/test_elf_no_reloc.py to simulate a genuinely
 * fixed-base (non-PIC) ELF dependency: a function that touches its own
 * internal data, so a tool can tell whether the embedder correctly placed
 * it at its own declared fixed address versus somewhere else (see that
 * test file's own comments for why `lib.c`'s constant-returning
 * `lib_value` can't tell the difference on its own). */
static int counter = 10;

int lib_value(void) {
    counter += 1;
    return counter + 31;
}

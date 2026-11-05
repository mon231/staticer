#include <stdio.h>

int lib_value(void);

/* A thread-local variable in the *host* (the executable being embedded
 * into, not the embedded .so) -- this is deliberately in a separate
 * fixture from main.c (which the PE/mingw tests also build) rather than
 * added there, since this exercises PT_TLS specifically: if
 * ElfEmbedder.embed() ever breaks AT_PHDR (e.g. by relocating the
 * program header table into a differently-skewed PT_LOAD segment), glibc's
 * _dl_aux_init walks a bogus phdr array looking for this executable's own
 * PT_TLS entry, silently skipping (or crashing during) static TLS setup --
 * a `lib.c`/`main.c`-only test, with no TLS and no RELRO dependency,
 * can't catch that class of bug at all. */
static __thread int tls_counter = 7;

int main(void) {
    int v = tls_counter + lib_value();
    printf("%d\n", v);
    return v;
}

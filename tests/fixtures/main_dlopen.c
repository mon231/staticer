/* Host for the dlopen/dlsym runtime-hook regression test
 * (tests/linux/test_elf_dlopen_hook.py) -- the ELF counterpart of
 * main_loadlibrary.c on the Windows side.
 *
 * Statically imports (and calls) lib.so's own `lib_value` -- embed() only
 * ever embeds a dependency the host's own DT_NEEDED actually names, so
 * this is what makes lib.so an embedded dependency, and what installs the
 * hook, at all.
 *
 * Separately -- the actual thing under test -- it ALSO calls
 * dlopen()+dlsym() on that *same* name at runtime, entirely independent
 * of the static import above, mirroring a real app's own explicit
 * dlopen of something that happens to already be statically linked in
 * (e.g. a plugin re-requesting a library the host itself also uses).
 */
#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>

extern int lib_value(void);

typedef int (*lib_value_fn)(void);

int main(void) {
    if (lib_value() != 42) {
        return 9;
    }

    void *h1 = dlopen("lib.so", RTLD_NOW);
    if (!h1) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    lib_value_fn fn = (lib_value_fn)dlsym(h1, "lib_value");
    if (!fn) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        return 2;
    }
    if (fn() != 42) {
        return 3;
    }

    /* A second, independent dlopen call for the same name must resolve
     * to the exact same handle -- real dlopen is required to do this
     * too (refcounted, not a second mapping), and our hook's own table
     * lookup is deterministic, so this should hold either way. */
    void *h2 = dlopen("lib.so", RTLD_LAZY);
    if (h2 != h1) {
        return 4;
    }

    /* dlsym for a name this module does NOT export must return NULL,
     * not crash and not resolve to something bogus (see elf_stub.py's
     * own docstring for why this -- not a real dlsym fallback -- is the
     * deliberately safe behavior for a recognized-handle, symbol-not-
     * found miss). */
    if (dlsym(h1, "no_such_export_xyz") != NULL) {
        return 5;
    }

    return 0;
}

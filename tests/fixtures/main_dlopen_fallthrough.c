/* Sibling to main_dlopen.c, for the hook's *fallthrough* path
 * (tests/linux/test_elf_dlopen_hook.py): with an embedded dependency
 * present (so the dlopen/dlsym hook is actually installed), an ordinary
 * dlopen/dlsym call against a real, non-embedded, genuinely-still-on-
 * disk system library (libm.so.6) must still behave exactly like the
 * unhooked real APIs.
 *
 * Resolving `sin` this way and comparing it against a normal, statically
 * linked call to the same function in the same process is a real,
 * independently-checkable correctness proof, not just "didn't crash".
 *
 * Statically imports (and calls) lib.so's own `lib_value` -- unlike
 * main_dlopen.c, this one needs the embedder to actually *embed* a
 * dependency (which only happens for something the host's own import
 * table names) so the hook is genuinely installed at all; the point of
 * this test is the fallthrough path for an *other*, non-embedded name,
 * not the embedded-match path main_dlopen.c already covers.
 */
#include <dlfcn.h>
#include <math.h>

extern int lib_value(void);

typedef double (*sin_fn)(double);

int main(void) {
    if (lib_value() != 42) {
        return 9;
    }

    void *h = dlopen("libm.so.6", RTLD_NOW);
    if (!h) {
        return 1;
    }

    sin_fn fn = (sin_fn)dlsym(h, "sin");
    if (!fn) {
        return 2;
    }

    double via_hooked_path = fn(1.0);
    double via_direct_call = sin(1.0);
    if (via_hooked_path != via_direct_call) {
        return 3;
    }

    return 0;
}

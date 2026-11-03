/* B6-ELF regression test's own throwaway driver program -- NOT built via
   conftest.py's build_exe (that produces a host for ElfEmbedder to
   *embed into*; this program is the opposite: an ordinary, never-
   embedded executable that dlopen()s an ElfEmbedder *output* .so and
   calls into it, to confirm the embedded dependency's constructor
   actually ran). Takes the .so's path as argv[1]. Exits 0 if
   host_seq_value() (see lib_so_host.c) returns anything other than -1
   (lib_ctor_a.c's sentinel, meaning its constructor never ran), non-zero
   otherwise. */
#include <dlfcn.h>
#include <stdio.h>

typedef long long (*seq_fn)(void);

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <path-to-so>\n", argv[0]);
        return 2;
    }
    /* RTLD_LAZY (not RTLD_NOW): matches the default, lazy-binding
       behaviour this fixture's own host .so is built with (no explicit
       -Wl,-z,now) -- RTLD_NOW would force eager resolution of every PLT
       slot regardless of the loaded .so's own BIND_NOW flag, which is a
       separate, real-world dlopen-caller-controlled wrinkle outside
       this regression test's own scope (see B5's test for the
       process-level lazy-binding case). */
    void *handle = dlopen(argv[1], RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 3;
    }
    seq_fn host_seq_value = (seq_fn)dlsym(handle, "host_seq_value");
    if (!host_seq_value) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        return 4;
    }
    long long value = host_seq_value();
    fprintf(stderr, "host_seq_value() = %lld\n", value);
    return value == -1 ? 1 : 0;
}

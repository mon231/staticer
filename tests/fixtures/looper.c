/* Loops forever with a short sleep each iteration (never a busy-spin) --
   a minimal host executable used by real-world-dependency embedding
   tests (see tests/windows/test_pe_frida_gadget.py and
   tests/linux/test_elf_frida_gadget.py) where the embedded dependency
   itself is what's under test, not this host's own logic. The host is
   never expected to actually reach the loop body in those tests: a
   dependency whose own init/constructor calls exit() first (as
   frida-gadget's config-driven script does) terminates the process
   before main() ever runs. */
#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

int main(void) {
    while (1) {
#if defined(_WIN32)
        Sleep(75);
#else
        usleep(75000);
#endif
    }
    return 0;
}

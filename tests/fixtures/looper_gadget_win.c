/* Windows-only variant of looper.c (see its own comment) that also
   references frida-gadget's real `frida_gadget_load` export as an unused
   function-pointer value -- never actually calling it (frida-gadget's
   own embedded DllMain already calls it exactly once on process attach;
   calling it a second time from here would re-run its whole init
   sequence). This exists purely to make the PE linker emit a real
   import-table entry naming the dependency: unlike ELF (where a plain
   `-Wl,--no-as-needed` forces a DT_NEEDED entry with no symbol used at
   all), a PE import descriptor only gets created for a DLL that at least
   one referenced symbol actually resolves against. */
#include <windows.h>

extern void frida_gadget_load(void *range, void *config_data, int *result);

int main(void) {
    volatile void *keep_import = (void *) frida_gadget_load;
    (void) keep_import;
    while (1) {
        Sleep(75);
    }
    return 0;
}

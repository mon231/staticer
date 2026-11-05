#if defined(_MSC_VER)
#define STATICER_EXPORT __declspec(dllexport)
#else
#define STATICER_EXPORT
#endif

/* B2 regression fixture: this .so is the one that gets EMBEDDED into the
   host, but it itself links against lib_further.c's library, which is
   deliberately NOT embedded (kept out of the embedder's lib_dir, so it's
   out-of-scope/unresolved from the dependency graph's point of view) --
   see tests/linux/test_elf_embed.py's
   test_embedded_deps_own_further_dependency_gets_host_dt_needed. */
extern int further_value(void);

STATICER_EXPORT int needs_further_value(void) {
    return further_value() + 1;
}

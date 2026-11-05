#if defined(_MSC_VER)
#define STATICER_EXPORT __declspec(dllexport)
#else
#define STATICER_EXPORT
#endif

/* B2 regression fixture: the real, non-embedded dependency that
   lib_needs_further.c (below) itself links against. Simulates a
   dependency-of-a-dependency that is excluded/out-of-scope from
   embedding -- see tests/linux/test_elf_embed.py's
   test_embedded_deps_own_further_dependency_gets_host_dt_needed. */
STATICER_EXPORT int further_value(void) {
    return 7;
}

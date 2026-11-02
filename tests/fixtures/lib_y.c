// Leaf of the lib_x.c -> lib_y.c DLL-to-DLL import edge used by
// test_transitive_exclusion_overlap (see lib_x.c's comment).
#if defined(_MSC_VER)
#define STATICER_EXPORT __declspec(dllexport)
#else
#define STATICER_EXPORT
#endif

STATICER_EXPORT int lib_y_value(void) {
    return 1;
}

// Leaf of the lib_x.c -> lib_y.c DLL-to-DLL import edge used by
// test_transitive_exclusion_overlap (see lib_x.c's comment).
int lib_y_value(void) {
    return 1;
}

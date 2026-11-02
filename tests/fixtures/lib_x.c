// Imports lib_y_value from lib_y.dll -- a real DLL-to-DLL import edge, not
// just a shared host import -- so that excluding this DLL (lib_x.dll) by
// name exercises the dependency graph's transitive-exclusion cascade (see
// staticer/common/depgraph.py's build_dependency_graph) rather than a
// direct top-level exclusion. Used by
// test_transitive_exclusion_overlap, which also has the host import
// lib_y.dll directly -- Y must stay excluded on account of X's exclusion
// even though it's independently a direct host import too.
int lib_y_value(void);

int lib_x_value(void) {
    return lib_y_value() + 10;
}

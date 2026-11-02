// Directly imports both lib_x.dll and lib_y.dll, where lib_x.dll itself
// also imports lib_y.dll (see lib_x.c's comment) -- used by
// test_transitive_exclusion_overlap.
int lib_x_value(void);
int lib_y_value(void);

int main(void) {
    return lib_x_value() + lib_y_value();
}

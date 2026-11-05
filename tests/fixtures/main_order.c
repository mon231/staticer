// Links both lib_order_a.dll and lib_order_b.dll directly (so both are
// discovered as embeddable top-level dependencies, each individually
// removed from the combined import table by `embed()`) -- see
// lib_order_a.c/lib_order_b.c for how the ordering check works.
int lib_order_a_marker(void);
int lib_order_b_marker(void);
__declspec(dllimport) extern int g_b_saw_a_attached;

int main(void) {
    lib_order_a_marker();
    lib_order_b_marker();
    return g_b_saw_a_attached;
}

// Host for test_tls_dependency_fails_loudly (B3) -- imports lib_tls_dep.dll,
// whose lib_tls_dep.c carries a __declspec(thread)/__thread variable.
int lib_tls_value(void);

int main(void) {
    return lib_tls_value();
}

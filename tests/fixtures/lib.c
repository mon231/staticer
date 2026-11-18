#if defined(_MSC_VER)
#define STATICER_EXPORT __declspec(dllexport)
#else
#define STATICER_EXPORT
#endif

STATICER_EXPORT int lib_value(void) {
    return 42;
}

/* Returns ITS OWN executing code address (not a thunk/IAT-slot address --
 * the actual function body that ran), as a plain integer -- used by
 * tests/windows/test_pe_hook_runtime.py's LdrRegisterDllNotification
 * regression test to tell which PHYSICAL copy of this function actually
 * executed (the embedded one, living inside the host's own image, vs. a
 * real, separately-loaded duplicate module), by comparing this value
 * against the calling process's own module address ranges. Plain
 * `lib_value` can't be used for that: both copies run byte-identical
 * code and would return the same `42` either way. */
STATICER_EXPORT unsigned long long lib_value_self_address(void) {
    return (unsigned long long)(void *)(&lib_value_self_address);
}

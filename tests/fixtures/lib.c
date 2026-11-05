#if defined(_MSC_VER)
#define STATICER_EXPORT __declspec(dllexport)
#else
#define STATICER_EXPORT
#endif

STATICER_EXPORT int lib_value(void) {
    return 42;
}

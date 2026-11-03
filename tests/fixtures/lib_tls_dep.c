// A dependency DLL carrying its own non-empty IMAGE_DIRECTORY_ENTRY_TLS
// (a __declspec(thread)/__thread variable) -- used by
// test_tls_dependency_fails_loudly (B3) to confirm PortableExecutableEmbedder
// refuses to embed it rather than silently corrupting TLS access.
#if defined(_MSC_VER)
#define STATICER_EXPORT __declspec(dllexport)
#define THREAD_LOCAL __declspec(thread)
#else
#define STATICER_EXPORT
#define THREAD_LOCAL __thread
#endif

THREAD_LOCAL int dep_tls_counter = 5;

STATICER_EXPORT int lib_tls_value(void) {
    return dep_tls_counter;
}

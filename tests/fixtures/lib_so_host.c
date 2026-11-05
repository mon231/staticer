#if defined(_MSC_VER)
#define STATICER_EXPORT __declspec(dllexport)
#else
#define STATICER_EXPORT
#endif

/* B6-ELF regression fixture: this .so is itself the ElfEmbedder *input*
   (not a dependency, and not an executable) -- lib_ctor_a.c gets
   embedded into it. ld.so never calls e_entry for a shared object, so
   the embedded dependency's constructor has to run through this host
   .so's own DT_INIT_ARRAY instead -- see
   tests/linux/test_elf_embed.py's
   test_embed_into_so_input_runs_dependency_constructor. */
extern long long a_seq_value(void);

STATICER_EXPORT long long host_seq_value(void) {
    return a_seq_value();
}

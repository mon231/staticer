# Limitations

- Explicit dynamic-loading from the executed code itself (`dlopen`+`dlsym`
  / `LoadLibraryW`+`GetProcAddress`) is not hooked yet; only dependencies
  resolved through the input's own import/dynamic-section table are
  embedded.
- A "full closure" embed on ELF still bottoms out at glibc's own dynamic
  linker/loader internals, which stay dynamically linked rather than
  embedded.
- Process-detach cleanup (`elf-destructor` / `DllMain`
  `DLL_PROCESS_DETACH`) is not invoked for embedded dependencies, and
  thread attach/detach notifications may never be supported.
- `-o`/`--output` silently overwrites an existing file at that path.
- A dependency using PE Thread Local Storage (`__declspec(thread)`) is
  rejected with a clear error rather than embedded incorrectly —
  TLS-directory merging isn't implemented yet.
- A fully self-contained module that both throws *and* catches a C++
  exception entirely within itself can still hit compiler-internal
  personality-routine details beyond the documented unwind ABI — ordinary
  cross-boundary unwinding is unaffected.
- ELF embedding of a dependency whose own further imports aren't
  themselves embedded or excluded (an "in-between" import) isn't
  supported; such a dependency fails loudly rather than silently losing
  that further dependency.
- A COPY-relocated ELF symbol larger than one pointer, containing its own
  interior pointer fields, doesn't get relocation entries for those
  interior pointers — a genuine architectural limit, since ELF carries no
  type/layout metadata for a COPY-relocated symbol beyond a byte count.
- A PLT entry resolved under lazy binding is only handled for the
  ordinary `R_*_JUMP_SLOT` case; an `R_*_GLOB_DAT`/`R_*_IRELATIVE` entry
  inside the PLT relocation table under lazy binding (not seen in any
  real-world binary encountered so far) would take the eager-binding
  code path instead.

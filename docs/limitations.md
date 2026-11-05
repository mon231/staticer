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
- Because `DLL_PROCESS_DETACH` is never delivered to an embedded
  dependency (see above), calling `FreeLibrary` on a staticer-produced
  DLL *before* process exit can crash the process: a dependency built
  against a dynamically-linked CRT registers process-wide TLS/FLS state
  during its (real, CRT-startup) `DLL_PROCESS_ATTACH` that nothing ever
  tears down, and the CRT's own exit-time bookkeeping later dereferences
  it after the freed library's memory is gone. Confirmed reproducible.
  Safe as long as the output DLL stays loaded for the life of the
  process (the common case); avoid `FreeLibrary`-ing it otherwise.
- `-o`/`--output` silently overwrites an existing file at that path.
- A dependency using Thread Local Storage (PE `__declspec(thread)` /
  ELF `__thread`) merges cleanly into a *TLS-less* host on both
  platforms (see [Features](features.md)) — but merging two *separate*
  TLS directories, one from the host itself and one from a dependency,
  into a single combined block isn't implemented; that case is rejected
  with a clear error naming the dependency rather than embedded
  incorrectly.
- ELF General/Local-Dynamic TLS model call-site relaxation
  (`R_X86_64_TLSGD`/`TLSLD`, types 19/20, and the i386 equivalents) is
  deliberately not implemented — not because it was overlooked, but
  because it was investigated and found to be an effectively dead code
  path for any input `embed()` can actually encounter. These relocation
  types exist only as a directive from the compiler to the *static
  linker* inside an unlinked relocatable object file (`.o`); confirmed
  with `readelf -r` that `gcc -c` genuinely emits
  `R_X86_64_TLSGD` there (including when explicitly forced via
  `__attribute__((tls_model("global-dynamic")))` or
  `-ftls-model=global-dynamic`), but every linker tried against the
  resulting *linked* `.so` (GNU `ld`/bfd and `lld`) always resolves it at
  link time into an ordinary `DTPMOD64`/`DTPOFF64` GOT-slot pair (which
  *is* implemented — see above) before it ever reaches a linked output
  file. This held even for the one shape that should structurally defeat
  link-time resolution — an `extern __thread` variable whose definition
  lives in a wholly different, unlinked shared object, so its TLS module
  id genuinely cannot be known until load time — the linked `.so` still
  carried `DTPMOD64`/`DTPOFF64` against the undefined symbol, never
  `TLSGD`/`TLSLD`. Since every dependency `embed()` processes is already
  a linked `.so` (never a raw `.o`), this relocation type cannot appear
  in practice regardless of source code shape, compiler flags, or
  toolchain version. `embed()` still checks for it explicitly, before
  falling into the generic "unsupported relocation type" error, and
  raises a specific `ValueError` naming the relocation type if it's ever
  encountered — see
  `.superpowers/sdd/2026-11-04-tls-support/task-6-report.md` for the full
  investigation.
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

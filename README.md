# staticer
Know it when you create a dynamiclly-linked executable, <br />
And try to execute it on other machines, but it fails to find expected symbols? <br />
Using your linux-executable on other machines with different libc, and can't find expected GLIBC function versions? <br />
Compiling a Windows-program and failing to run it on other machines? Or simply want your project to be published as onefile? <br />
Wait no more as `staticer` is here to the rescue! <br />
No more execution failures or long-taking compilation adaptions, <br />
Just to simply support same-kernel different-OS / OS versioning!

**NOTE** you should use this tool for legit-development / debugging / educational purposes only!

## Installation
Simply run:
> pip install staticer

Make sure to have python scripts folder in your path, <br/>
And use the correct version of pip for python3.

## Usage
```
staticer <input> -o <output> [--exclude NAME[,NAME...]] [--lib-dir PATH]
```

**NOTE** `-o`/`--output` overwrites an existing file at that path without warning or backup.

## Goals & Parctice
We want to get en executable-file and embed its dependencies recursively. <br />
We need to patch the executable-file's import-table and prevent it from loading the dynamic libraries. <br />
We need to patch the executable-file's import-table and have the resolved symbol addresses in it, <br />
And make the loader ignore that import-table in order not to clash, as it is invalidated. <br />
We need to embed the code/data/... sections of each embedded dependency, <br />
Patch their import-table the same way, and call their initializers (i.e. `DllMain` / `Constructor`)

In order to intercept explicit dynamic-loading (from the executed code itself), <br />
We'll have to hook `dlopen`+`dlsym` / `LoadLibraryW`+`GetProcAddress` and make them return addresses to embedded resources, <br />
Or make them call the original functions, if they try to access dynamic-libraries that weren't embedded.

**NOTE** OS-based / C++ `exception` unwinding works across embedded-dependency boundaries (unwind metadata is preserved); a self-contained embedded module that both throws and catches internally may still hit compiler-specific personality-routine details beyond the documented ABI
**NOTE** we currently do NOT support invoking `elf-destructor` / `DllMain` process-detach
**NOTE** we might never support `DllMain` invoking for thread attach/detach reasons

## Features & How They're Implemented

Everything below operates on the real on-disk binary format directly (`pefile`
for PE, `pyelftools` for reading ELF + hand-packed structs for writing it back,
since `pyelftools` is read-only) — no linker, compiler, or native toolchain is
invoked by the installed package itself.

- **Dependency graph & embed order.** `staticer` recursively resolves a
  binary's imports (PE Import Directory / ELF `DT_NEEDED`) into a dependency
  graph, then topologically sorts it so each embedded dependency's own
  initializer runs before anything that depends on it, mirroring normal
  loader behavior. Exclusion (`--exclude`, or a dependency found outside
  `--lib-dir`) propagates *transitively*: anything an excluded dependency
  itself imports is also left dynamic, so the same code never ends up both
  embedded and dynamically loaded as two independent copies. Cycles among
  embeddable dependencies are detected and rejected with a clear error naming
  the cycle, rather than looping forever or silently picking an order.

- **PIC / relocation-bearing dependencies (the common case).** A
  dependency's code/data sections are appended into the host as new
  sections/segments, its relocations (PE `.reloc`, ELF `.rela`/`.rel`) are
  re-applied against the new placement, and the host's import-table entries
  pointing at it are patched to the embedded address and removed from the
  import table / `DT_NEEDED`. On ELF, new content extends the host's own
  existing loadable segment in place rather than adding a new one — adding a
  genuinely new segment and relocating the program-header table into it
  breaks the kernel's `AT_PHDR` calculation (its skew assumption only holds
  for a segment that shares the *original* image's `vaddr - offset` skew),
  silently breaking TLS/RELRO/stack-flag setup. This took three real,
  execution-verified fix rounds to get right.

- **Fixed-base / non-relocatable dependencies.** A dependency with *no*
  usable relocation data (as opposed to one that merely prefers a fixed
  base but still carries relocations — those always take the normal path
  above) is placed at its own declared preferred address instead, with
  every such reservation checked against the host's own image, every other
  reserved dependency, and any bridging filler sections, failing loudly on
  a genuine address conflict rather than producing a silently-malformed
  binary. On PE, embedding any such dependency also clears
  `DYNAMIC_BASE`/`HIGH_ENTROPY_VA` on the output, since a fixed-base
  dependency's untracked absolute references are only valid if the whole
  combined image never gets relocated as a whole. ELF has no equivalent
  per-image flag to clear, so embedding a fixed-base dependency into a PIE
  host fails loudly instead.

- **Exception / unwind metadata.** PE `.pdata`/`.xdata` (the
  `RUNTIME_FUNCTION`/`UNWIND_INFO` exception directory) and ELF
  `.eh_frame`/`.eh_frame_hdr` entries are merged into the host rather than
  discarded, with every RVA/offset they reference patched to the relocated
  address — so a C++ exception, or a Windows structured exception, can
  unwind correctly across the boundary between the host and an embedded
  dependency. A fully self-contained module that both throws *and* catches
  entirely within itself can still hit compiler-internal personality-routine
  details beyond the documented unwind ABI (see the note above) — this is a
  real limit of the public unwind data format, not something this project's
  implementation chose to skip.

- **Generated entrypoint stub.** The output's entrypoint is replaced with a
  small generated stub that calls each embedded dependency's initializer
  (`DllMain` process-attach / ELF constructor) in dependency order, then
  jumps to the original entrypoint. On PE, the stub correctly distinguishes
  real process-attach from thread-attach/detach when the output itself is a
  DLL (so embedded initializers run exactly once, not on every thread
  event). On ELF, a `.so` input can't rely on `e_entry` at all — the
  dynamic linker never calls it for a shared object — so its init sequence
  is injected as an additional `DT_INIT_ARRAY` entry instead, which *does*
  run via the normal constructor-calling mechanism.

- **`--exclude` / `--lib-dir` scoping.** `--exclude NAME[,NAME...]` keeps
  specific dependencies dynamic by name (case-insensitively on PE, matching
  Windows' own case-insensitive filenames; case-sensitively on ELF, matching
  real filesystem semantics on Linux). `--lib-dir PATH` restricts embedding
  to dependencies actually found inside that folder — anything resolved from
  elsewhere (including system directories) stays a normal dynamic import.
  Dependency names come straight from the binary being processed, so they're
  treated as untrusted input: a crafted name with path-traversal components
  or an absolute path is rejected rather than allowed to escape the intended
  search directory.

- **Real-world binaries.** Tested against actual system binaries
  (`cmd.exe`/`hostname.exe` on Windows, `bash`/`grep` on Linux), both as a
  curated subset (via `--lib-dir`/`--exclude`) and as closer-to-full
  transitive closures. A handful of real-world-only bugs only ever
  surfaced against genuine system DLLs/`.so`s — forwarded exports,
  ordinal-only imports, forwarder import cycles, stale `DT_VERNEED`
  entries, `R_*_COPY` relocations for a dependency's own globals, and weak
  symbols from the C runtime's own startup boilerplate — all fixed and
  covered by regression tests built from the same binaries that found them.
  Also tried against a genuine real-world *instrumentation library*
  (Frida's own `frida-gadget`, downloaded for real from its GitHub release
  assets — see `tests/windows/test_pe_frida_gadget.py` /
  `tests/linux/test_elf_frida_gadget.py`): it carries its own TLS
  directory on both PE and ELF (a real `AddressOfCallBacks`-bearing PE
  TLS directory, a real `PT_TLS` segment on ELF), which TLS-directory
  merging (see Features below) now adopts as the TLS-less host's own on
  both platforms. Past that, the gadget's full config-driven-script flow
  — load a `.config` naming a JS file, run it, have the script call
  `exit()` — runs genuinely end-to-end once embedded, on both platforms,
  confirmed by actually executing the embedded binary: frida-gadget's
  own config-path lookup resolves relative to the *host's* own path once
  embedded (since there's no longer a separately-loaded module for it to
  resolve against — confirmed by reading frida-core's own
  config-resolution source), so the config is named after the host
  binary's stem, not the gadget's; the script's own `exit(845)` call
  really executes (PE reports it back as `845` — a full 32-bit exit
  code; ELF reports `77`, since POSIX process exit statuses are
  truncated to 8 bits by the kernel itself, `845 & 0xFF == 77`, nothing
  to do with staticer or frida-gadget).

## Limitations
- Explicit dynamic-loading from the executed code itself (`dlopen`+`dlsym` / `LoadLibraryW`+`GetProcAddress`) is not hooked yet; only dependencies resolved through the input's own import/dynamic-section table are embedded.
- A "full closure" embed on ELF still bottoms out at glibc's own dynamic linker/loader internals, which stay dynamically linked rather than embedded.
- Process-detach cleanup (`elf-destructor` / `DllMain` `DLL_PROCESS_DETACH`) is not invoked for embedded dependencies, and thread attach/detach notifications may never be supported.
- Because `DLL_PROCESS_DETACH` is never delivered to an embedded dependency (see above), calling `FreeLibrary` on a staticer-produced DLL *before* process exit can crash the process: a dependency built against a dynamically-linked CRT registers process-wide TLS/FLS state during its (real, CRT-startup) `DLL_PROCESS_ATTACH` that nothing ever tears down, and the CRT's own exit-time bookkeeping later dereferences it after the freed library's memory is gone. Confirmed reproducible. Safe as long as the output DLL stays loaded for the life of the process (the common case); avoid `FreeLibrary`-ing it otherwise.
- `-o`/`--output` silently overwrites an existing file at that path (see Usage above).
- A dependency using Thread Local Storage (PE `__declspec(thread)` / ELF `__thread`) merges cleanly into a *TLS-less* host on both platforms (see Features above). Merging two separate TLS directories — one from the host itself and one from a dependency — into a single combined block is implemented for a 64-bit PE host; a 32-bit PE host, and ELF on either bit-width, still reject that case with a clear error rather than embed it incorrectly.
- ELF embedding of a dependency whose own further imports aren't themselves embedded or excluded (an "in-between" import) isn't supported; such a dependency fails loudly rather than silently losing that further dependency.
- A COPY-relocated ELF symbol larger than one pointer, containing its own interior pointer fields, doesn't get relocation entries for those interior pointers — a genuine architectural limit, since ELF carries no type/layout metadata for a COPY-relocated symbol beyond a byte count.
- PE's section-header table has no growth mechanism: a host whose header region was packed tight by its own linker (common for real-world commercial binaries, confirmed via local testing) may have too little slack to add even one dependency's new sections, failing loudly rather than embedding anything. Planned, not yet implemented — see [Internals](https://mon231.github.io/staticer/internals/) / [Limitations](https://mon231.github.io/staticer/limitations/) for detail.
- The host-already-has-TLS merge's byte-pattern scanner is verified against this project's own mingw-w64 fixtures but confirmed (via the same local testing) to correctly refuse real MSVC-built third-party DLLs whose compiled TLS-access code it doesn't recognize — safe (fails loudly), but narrower in practice than "works for 64-bit PE" suggests. Planned broadening, not yet implemented.

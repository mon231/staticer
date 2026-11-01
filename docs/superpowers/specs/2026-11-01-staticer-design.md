# staticer — design

## Intent

`staticer` takes a dynamically-linked executable or shared object (PE/ELF,
x86/x64) and produces a new binary with some or all of its DLL/SO
dependencies embedded directly into it, inlining their code/data and
patching out the corresponding import-table entries. The result runs with
fewer runtime dependencies on the target machine (no "missing DLL" /
"wrong GLIBC version" failures from mismatched system libraries), at the
cost of a more unusual binary layout. A secondary target is embedded
devices, where pulling platform-specific objects into one blob matters as
much as dependency count.

This is the existing project skeleton's stated goal (see `README.md`);
this document specifies the rest of it.

## Goals

- Given an input executable or shared object, recursively resolve its
  imported DLLs/SOs, and embed the chosen ones' code/data sections into a
  new output binary.
- Patch the import table (PE Import Directory / ELF `DT_NEEDED` +
  relocations) so the loader no longer looks for embedded dependencies at
  load time, while un-embedded (excluded, or out-of-scope) dependencies
  keep working exactly as they do today, resolved dynamically at runtime.
- Generate a custom entrypoint that runs embedded modules' initializers
  (`DllMain` process-attach / ELF constructors) in a correct dependency
  order (topological order over the resolved dependency graph) before
  handing off to the original entrypoint.
- Support both executables and shared objects/DLLs as the *input* being
  processed (an embedded SO/DLL becomes "more static" too, not just
  top-level EXEs).
- Support Windows (PE) and Linux (ELF), x86 and x64, for both input types.
- Support both PIC and non-PIC (fixed-base) input/dependency binaries.
- Preserve working C++ exception / SEH unwind metadata (PE `.pdata`/
  `.xdata`, ELF `.eh_frame`) across the embedded boundary, rather than
  refusing binaries that carry it (nearly all real-world binaries do).
- Let the user optionally exclude specific DLLs/SOs by name from static
  embedding — excluded deps stay as ordinary dynamic imports, resolved at
  runtime exactly as an unmodified binary would.
- Let the user optionally restrict the dependency search to one folder
  (`--lib-dir`): only dependencies actually found there get embedded;
  anything resolved from system locations (`System32`, `/usr/lib`, `/lib`,
  etc.) outside that folder is left as a normal dynamic import, untouched.
- Pure-Python implementation: no shelling out to a system linker,
  compiler, or `objcopy`; parsing/patching libraries are themselves pure
  Python (pip-installable, no bundled native toolchain dependency).
- Package and release as a normal PyPI package (`pip install staticer`),
  building on the existing `setup.py` skeleton.
- Automated tests for Windows + Linux, exe + dll/so, PIC + non-PIC, x86 +
  x64, running in CI.

## Non-goals

- Invoking ELF destructors / `DllMain` process-detach on unload (carried
  over from the existing README caveat).
- `DllMain` thread-attach/detach notifications for embedded modules (may
  never be supported — existing README caveat).
- Cross-architecture embedding (embedding an ARM `.so` into an x86 host,
  etc.) — out of scope for this iteration; architectures must match.
- A GUI or interactive mode — CLI only.

## Anti-goals

- Silently producing a binary that appears to build successfully but
  crashes or misbehaves at runtime without a clear diagnostic — unsupported
  constructs (e.g. an embed candidate that needs an unsupported feature)
  should fail loudly at embed time, not at the victim's runtime.
- Requiring a compiler, linker, or other native toolchain to be installed
  to *run* `staticer` (install and use must stay pure-`pip install`).
- Mutating/removing import entries for dependencies the user asked to
  exclude or that fall outside `--lib-dir` — those must remain bit-for-bit
  equivalent to how an unmodified binary would resolve them.

## Constraints

- Pure Python only. Parsing libraries: `pefile` for PE, `pyelftools` for
  ELF. No `lief` (compiled C++ bindings) and no shelling out to
  `ld`/`link.exe`/`objcopy`/a compiler at runtime. (This supersedes the
  existing skeleton's `lief` dependency — see "What's decided" below.)
- No bundled native helper binaries ship with the package itself. Test
  *fixtures* may be compiled by a system compiler during test setup (a
  dev/CI-only concern) — this does not apply to the installed package.
- Must work against real-world system binaries as one test case (e.g.
  embedding into a copy of `cmd.exe`), not only synthetic fixtures.

## What's decided

- **Drop `lief`.** The current `staticer/staticer.py`,
  `staticer/pe_embedder.py`, and `staticer/elf_embedder.py` skeleton files
  are rewritten against `pefile` (PE) and `pyelftools` (ELF) instead.
  `setup.py`'s `install_requires` changes from `['lief']` to
  `['pefile', 'pyelftools']`, and `requirements.txt` updates to match.
- **CLI shape:**
  `staticer <input> -o <output> [--exclude NAME[,NAME...]] [--lib-dir PATH]`
  - `<input>` (positional): path to the dynamically-linked executable or
    shared object/DLL to process.
  - `-o/--output`: path to write the resulting binary.
  - `--exclude`: comma-separated dependency names to keep as ordinary
    dynamic imports (never embedded, resolved at runtime as today).
  - `--lib-dir` (optional): a folder to restrict embedding to. When given,
    only dependencies actually found inside it are embedded; dependencies
    resolved from anywhere else (system paths included) are left as
    ordinary dynamic imports. When omitted, every dependency resolvable
    anywhere on disk is a candidate for embedding except `--exclude`d
    ones — including system libraries, if they're found and not excluded.
- **Dependency walk / entrypoint order:** build the full dependency graph
  by recursively resolving imports (respecting `--lib-dir` scoping and
  `--exclude`), then topologically sort it. The generated entrypoint stub
  runs each embedded dependency's initializer in that order (dependencies
  before dependents) before transferring control to the original
  entrypoint — mirroring normal loader behavior.
- **Exclusion propagates transitively.** If dependency X is excluded (by
  `--exclude`, or by falling outside `--lib-dir`), X's own on-disk
  imports are left completely untouched (per the anti-goal) — so anything
  X itself imports must also be treated as excluded, even if the host
  also imports it directly and it would otherwise qualify for embedding.
  Otherwise the same dependency would exist both embedded (with its own
  initializer run once) and dynamically loaded for X's sake, as two
  independent copies of its code/globals/locks in one process. Concretely:
  starting from the host's direct imports, a node is embeddable only if
  it is not itself excluded/out-of-scope AND is not reachable through any
  excluded/out-of-scope node's own (untouched) import edges. This
  propagation happens before the topological sort that drives entrypoint
  ordering.
- **Exception/unwind metadata is preserved, not rejected.** An embedded
  dependency's unwind data (PE `.pdata`/`.xdata`, ELF `.eh_frame`) is kept
  working across the new boundary: sections holding unwind/exception
  tables are merged into the host where their internal offsets still
  resolve correctly post-relocation, or duplicated alongside the
  dependency's relocated code when offsets can't be preserved in place —
  with every pointer/offset the unwinder reads patched to match wherever
  the bytes actually end up. Reference existing open-source static-linking
  implementations' handling of `.pdata`/`.eh_frame` merging where useful,
  rather than re-deriving it from scratch.
- **Non-PIC / fixed-base handling:** a dependency that carries relocation
  data is always relocated normally (whether it's PIC or merely
  "prefers" a fixed base) — this is the common case even for non-PIC
  binaries. Only a dependency with *no* usable relocation data at all
  falls back to base-address reservation: the generated stub reserves
  that dependency's preferred base before anything else maps there. If
  the preferred base is already taken (by the host image, ASLR, or
  another such dependency), that's a conflict and embedding that
  dependency fails loudly rather than silently relocating it incorrectly.
- **Embedding mechanism:** for each embedded dependency, its code/data
  sections are appended into the host binary as new sections, its
  relocations are applied against the new base addresses, and any host
  import-table entries that reference it are patched to point at the
  embedded symbol addresses and then removed from the PE Import Directory
  / ELF `DT_NEEDED`+relocation entries. Excluded/out-of-scope dependencies'
  entries are left completely untouched.
- **Runtime dynamic-loading interception** (`LoadLibraryW`/`GetProcAddress`,
  `dlopen`/`dlsym`): hooked in the generated stub so that explicit runtime
  loading of an embedded module resolves to its embedded address; lookups
  for anything not embedded fall through to the real loader functions
  unchanged. (Already specified in the existing README; carried over
  as-is.)
- **Test matrix:** Windows + Linux × exe + dll/so × x86 + x64 × PIC +
  non-PIC, built from small synthetic C fixtures, plus several real-world
  system binaries as extra (not the only) target cases:
  - Windows: `cmd.exe` and at least one more (e.g. a copy of
    `notepad.exe` or `reg.exe`), each tested BOTH ways: (a) a curated
    subset via `--lib-dir`/`--exclude` (one or two chosen DLLs embedded,
    rest left dynamic) and (b) the full transitive closure embedded
    (including `kernel32.dll`/`ntdll.dll`), relying on the exception/
    unwind-preservation and fixed-base handling above to make the full
    case actually work.
  - Linux: `bash` and at least one more (e.g. `ls` or `cat`), same two
    variants — curated subset via `--lib-dir`/`--exclude`, and full
    transitive closure including `libc`/`ld-linux`.
  - one case per platform proving `--exclude` leaves a named dependency
    dynamically linked and the output still runs correctly;
  - one case per platform proving `--lib-dir` scoping: a dependency placed
    in a temp folder gets embedded, while a system dependency of the same
    binary (found outside that folder) is left dynamically imported.
- **Packaging / project layout:** restructure to match a typical PyPI
  package's tests+CI layout, kept simple:
  ```
  staticer/
    staticer/              # package source
      __init__.py
      staticer.py          # CLI entrypoint (main())
      pe_embedder.py        # PE-specific embedding logic
      elf_embedder.py        # ELF-specific embedding logic
      common/                # shared logic (dep-graph, topo sort, exclude/lib-dir scoping)
      stubs/                 # generated entrypoint-stub templates/trampolines
        windows/              # PE stub bytes/asm, LoadLibraryW/GetProcAddress hook
        linux/                 # ELF stub bytes/asm, dlopen/dlsym hook
    tests/
      fixtures/              # tiny C sources for synthetic exe/dll/so test binaries
      windows/                # Windows-only tests (PE, cmd.exe/notepad.exe cases)
      linux/                  # Linux-only tests (ELF, bash/ls cases)
      test_*.py               # shared/platform-dispatched test modules
    .github/workflows/ci.yml  # Windows + Linux matrix, builds fixtures, runs pytest
    setup.py
    requirements.txt
    README.md
  ```
  CI (GitHub Actions) runs a Windows + Linux matrix, builds the small C
  test fixtures with the platform's available compiler (MSVC/MinGW on
  Windows, gcc/clang on Linux) as a test-setup step — a CI/dev-time
  dependency only, not affecting the installed package's pure-Python
  requirement — then runs the full pytest suite.

## Left to the builder

- Exact internal module layout beyond the existing
  `pe_embedder.py`/`elf_embedder.py` split (e.g. where graph-building,
  relocation-patching, and stub-generation code lives).
- The on-disk format/placement of the generated entrypoint stub and hook
  trampolines (hand-assembled bytes vs. a small embedded data table
  interpreted by a tiny fixed stub) — whichever is simpler to get correct
  per architecture.
- Specific pytest fixture/helper structure for building and running the
  tiny C test binaries per platform/arch/PIC combination.
- Error message wording and exact exit codes for the "loud failure on
  unsupported construct" anti-goal.

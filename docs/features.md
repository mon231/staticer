# Features

Everything below operates on the real on-disk binary format directly
(`pefile` for PE, `pyelftools` for reading ELF plus hand-packed structs for
writing it back, since `pyelftools` is read-only) — no linker, compiler, or
native toolchain is invoked by the installed package itself.

## Dependency graph & embed order

`staticer` recursively resolves a binary's imports (PE Import Directory /
ELF `DT_NEEDED`) into a dependency graph, then topologically sorts it so
each embedded dependency's own initializer runs before anything that
depends on it — mirroring normal loader behavior.

Exclusion (`--exclude`, or a dependency found outside `--lib-dir`)
propagates **transitively**: anything an excluded dependency itself imports
is also left dynamic, so the same code never ends up both embedded and
dynamically loaded as two independent copies in the same process.

On PE, a genuine import cycle among embeddable dependencies (confirmed
real, not hypothetical: e.g. `WS2_32.dll`'s own import table imports
`MSWSOCK.dll`, while `WS2_32.dll` also forwards some exports *to*
`MSWSOCK.dll`) no longer aborts the embed — cross-dependency resolution
is already fully deferred to a finalize pass run after every dependency
is placed, so a strict total order was never a real technical
requirement; cyclic nodes are grouped into strongly-connected components
(Tarjan's algorithm) and embedded together, keeping every component
dependencies-first relative to the rest of the graph. ELF keeps
rejecting a cycle with a clear error naming it, unchanged.

A dependency reachable *only* as another dependency's export-forward
target (e.g. `SHLWAPI.dll` forwards some exports to `SHCORE.dll`, which
its own import table never mentions at all) is also discovered and
embedded like any ordinary one, on PE — not just ordinary import-table
edges.

## PIC / relocation-bearing dependencies

This is the common case: a dependency's code/data sections are appended
into the host as new sections/segments, its relocations (PE `.reloc`,
ELF `.rela`/`.rel`) are re-applied against the new placement, and the
host's import-table entries pointing at it are patched to the embedded
address and removed from the import table / `DT_NEEDED`.

On ELF, new content extends the host's own existing loadable segment in
place rather than adding a new one — adding a genuinely new segment and
relocating the program-header table into it breaks the kernel's
`AT_PHDR` calculation (its skew assumption only holds for a segment that
shares the *original* image's `vaddr - offset` skew), which silently
breaks TLS/RELRO/stack-flag setup for the whole process.

## Fixed-base / non-relocatable dependencies

A dependency with *no* usable relocation data at all (as opposed to one
that merely prefers a fixed base but still carries relocations — those
always take the normal path above) is placed at its own declared
preferred address instead.

Every such reservation is checked against:

- the host's own image range,
- every other reserved fixed-base dependency,
- any bridging filler content needed to keep the section/segment table
  contiguous.

A genuine address conflict fails loudly with a clear error rather than
producing a silently-malformed binary.

On PE, embedding any fixed-base dependency also clears
`DYNAMIC_BASE`/`HIGH_ENTROPY_VA` on the output — a fixed-base
dependency's untracked absolute references are only valid if the whole
combined image never gets relocated as a whole, so the output can no
longer be an ASLR candidate. ELF has no equivalent per-image flag to
clear, so embedding a fixed-base dependency into a PIE host fails loudly
instead of silently corrupting at a random load address.

## Exception / unwind metadata

PE `.pdata`/`.xdata` (the `RUNTIME_FUNCTION`/`UNWIND_INFO` exception
directory) and ELF `.eh_frame`/`.eh_frame_hdr` entries are merged into
the host rather than discarded, with every RVA/offset they reference
patched to the relocated address — so a C++ exception, or a Windows
structured exception, can unwind correctly across the boundary between
the host and an embedded dependency.

!!! note
    A fully self-contained module that both throws *and* catches entirely
    within itself can still hit compiler-internal personality-routine
    details beyond the documented unwind ABI. This is a real limit of the
    public unwind data format, not something skipped for convenience —
    ordinary cross-boundary unwinding (the common case) is fully
    supported and tested.

## Thread Local Storage

A dependency's Thread Local Storage directory (PE `IMAGE_DIRECTORY_ENTRY_TLS`
/ ELF `PT_TLS`) is adopted as a *TLS-less* host's own: the dependency's raw
TLS data template is merged into the host's own TLS block and its
TLS-relative relocations (ELF `R_X86_64_DTPMOD64`/`DTPOFF64`/`TPOFF64`; PE's
raw-data/index patch-up) are resolved against the single combined module, so
each OS thread still gets its own correctly-initialized slot.

On PE, this also handles a dependency's TLS callback array
(`AddressOfCallBacks`) rather than only the callback-free case — verified
against a real-world dependency (frida-gadget, below) whose own TLS
directory carries three real callback entries.

A dependency's TLS directory can also be merged with a *64-bit PE host's own*
pre-existing TLS directory, rather than only adopted by a TLS-less host: both
raw-data ranges are combined, both halves share the one `_tls_index` slot the
loader actually assigns, and the dependency's compiled TLS-access offsets are
patched to their new position within the combined range. This chains to any
number of TLS-bearing dependencies in the same `embed()` call, not just one:
each additional one's own raw data is appended to the end of the
already-combined range, its own compiled TLS-access offset(s) shifted by
however many bytes already precede it, and its own `_tls_index` fixed up to
match whichever module ended up holding the one real, loader-assigned slot.

!!! note
    Merging the host's *own* TLS directory with a dependency's separate one
    (or chaining in more than one TLS-bearing dependency) is not yet
    implemented for a 32-bit PE host, or for ELF on either bit-width (ELF
    still supports only a single TLS-bearing dependency into a TLS-less
    host) — see [Limitations](limitations.md).

ELF additionally supports the Initial-Exec TLS model
(`R_X86_64_TPOFF64`): once a dependency's `PT_TLS` becomes the sole
(module-1) TLS directory after merging into a TLS-less host, its
%fs-relative static offset is a fixed, load-bias-independent constant
per the ELF TLS ABI's variant II layout — confirmed empirically against
a real process's actual %fs-relative address for a single-module
Initial-Exec variable, not just derived from the ABI spec.

## Runtime dynamic-loading interception

A statically-resolved import isn't the only way code ends up needing a
dependency: application code (or an embedded dependency's own later
code) can also ask for one *by name* at runtime. Both platforms
intercept this so a request for one of this run's own embedded
dependencies resolves to the already-initialized embedded copy instead
of triggering a real, separate, duplicate load (which would otherwise
waste memory and, worse, duplicate the dependency's own global/static
state between two independent instances in one process):

- **PE**: `LoadLibraryW`/`LoadLibraryA`/`GetProcAddress` are hooked —
  every discovered real IAT slot for the three is patched to a generated
  trampoline before any embedded dependency's own initializer runs. A
  name/handle that doesn't match one of this run's embedded dependencies
  falls through to the real, saved API unconditionally, so ordinary
  dynamic loading elsewhere is unaffected.
- **PE, additionally**: `LdrRegisterDllNotification` is used to catch
  the case the IAT hook alone can't see — a module *itself* loaded
  dynamically by name (which the IAT hook does see and correctly lets
  through, since that module isn't embedded) whose own,
  compiler-generated static import table references an embedded
  dependency by name. The OS loader resolves that internally while
  mapping the module, never through any IAT slot the IAT hook can reach
  — confirmed against the real-world case this was built for (a Qt
  application's platform plugin, itself `LoadLibraryW`'d by Qt's own
  plugin loader, statically importing the application's own Qt core
  libraries). The registered callback patches the newly-loaded module's
  own already-snapped IAT slots for any matching embedded dependency,
  confirmed via a dedicated empirical investigation (not just read from
  Microsoft's documentation) that this is safe: the loader's own import
  snap for a module has already completed by the time the `LOADED`
  notification fires for it, so there's no race to patch around, and a
  real cross-module `VirtualProtect` call from inside the callback — of
  the kind Microsoft's own docs call unsafe — works without deadlock or
  crash on every Windows build tested so far. This is unsupported,
  undocumented-by-Microsoft behavior, verified empirically rather than
  architecturally guaranteed — see [Limitations](limitations.md).
- **ELF**: `dlopen`/`dlsym` are hooked the same way, adapted for real
  glibc mechanics rather than a blind port of the PE design — a
  bootstrap call through every discovered GOT slot forces real
  resolution to happen once, by `staticer`, before any slot is read or
  overwritten (lazy PLT binding would otherwise let the first real call
  silently uninstall the trampoline), and a slot inside a `PT_GNU_RELRO`
  range gets a real `mprotect`-wrapped write. A `dlsym` against a
  recognized (embedded-module) handle for a symbol that isn't in that
  module's own known export table returns `NULL` (matching a real
  "not found"), not a fallback to a real `dlsym` call — glibc's real
  `dlsym` does no validation at all on its `handle` argument, so handing
  it a fake one risks a wild pointer chase rather than a clean failure.

Both platforms are x64/x86-64 only for this mechanism so far; see
[Limitations](limitations.md) for the exact scope.

## Generated entrypoint stub

The output's entrypoint is replaced with a small generated stub that
calls each embedded dependency's initializer (`DllMain` process-attach /
ELF constructor) in dependency order, then jumps to the original
entrypoint.

- On **PE**, the stub distinguishes real process-attach from
  thread-attach/detach when the output itself is a DLL, so embedded
  initializers run exactly once — not on every thread event.
- On **ELF**, a `.so` input can't rely on `e_entry` at all (the dynamic
  linker never calls it for a shared object), so its init sequence is
  injected as an additional `DT_INIT_ARRAY` entry instead, which *does*
  run via the normal constructor-calling mechanism.

## Scoping: `--exclude` / `--lib-dir`

- `--exclude NAME[,NAME...]` keeps specific dependencies dynamic by name.
- `--lib-dir PATH` restricts embedding to dependencies actually found
  inside that folder; anything resolved elsewhere stays dynamic.

Dependency names come straight from the binary being processed, so
they're treated as untrusted input: a crafted name with path-traversal
components or an absolute path is rejected rather than allowed to escape
the intended search directory.

## Tested against real-world binaries

Beyond synthetic test fixtures, `staticer` is tested against actual
system binaries — `cmd.exe`/`hostname.exe`/`python.exe`+`python313.dll`
on Windows, `bash`/`grep` on Linux — both as a curated subset (via
`--lib-dir`/`--exclude`) and as closer-to-full transitive closures. A
real `python.exe`, embedded down to just `KERNEL32.dll` plus its own
mandatory companions (`KERNELBASE.dll`/`ntdll.dll`/the virtual
`api-ms-win-*` API sets, none of which are real files that could ever
be embedded), runs a real interpreter session correctly after the
embed. A handful of real-world-only bugs only ever surfaced against
genuine system DLLs/`.so`s: forwarded exports, ordinal-only imports,
forwarder import cycles, stale `DT_VERNEED` entries, `R_*_COPY`
relocations for a dependency's own globals, weak symbols from the C
runtime's own startup boilerplate, a `pefile` default export-table
truncation cap silently dropping real exports from a sufficiently
large real DLL, and ordinal-style (`"DLL.#N"`) export-forward targets
never being converted from their literal string form to a real integer
lookup key — all fixed, each covered by a regression test built from
the binary that found it.

Also tried, for real, against a genuine commercial Qt6 GUI application
(010 Editor) — the single most demanding real-world closure attempted
so far, pulling in dozens of real system DLLs and several genuinely
TLS-bearing ones at once. This found real bugs no smaller closure ever
reached: a `/DELAYLOAD` import crash (fixed by generating real lazy
per-function thunks instead of either eagerly resolving or leaving the
compiler's own thunk to run against a module that's no longer
separately loaded), and false-positive matches in the TLS byte-pattern
scanner against real MSVC-compiled system/Qt DLLs (`SHLWAPI.dll`,
`SHELL32.dll`, and — as of this writing, still being worked —
`Qt6Gui.dll`) that would have silently corrupted unrelated code — see
[Limitations](limitations.md) for the current, exact state of this
specific embed (the TLS-scanner and runtime-interception work above
were both driven by it, and it's the most up-to-date record of exactly
how far it currently gets).

Also tried, for real, against a genuine third-party *instrumentation*
library — Frida's own `frida-gadget`, downloaded directly from its GitHub
release assets rather than synthesized (see
`tests/windows/test_pe_frida_gadget.py` /
`tests/linux/test_elf_frida_gadget.py`). It now embeds and runs genuinely
end-to-end on **both** platforms:

- frida-gadget carries its own TLS directory on both PE and ELF (a real
  `AddressOfCallBacks`-bearing PE TLS directory, a real `PT_TLS` segment
  with 14 `R_X86_64_DTPMOD64` relocations on ELF) — handled by the TLS
  merge above rather than rejected.
- Past that, frida-gadget's documented config-file-driven "Script"
  interaction (auto-running a JS file on load, no external Frida client
  needed) runs for real. frida-gadget resolves its own `.config` file by
  asking the OS which loaded module contains its own running code, then
  looking next to that module's path (confirmed by reading frida-core's
  own config-resolution source). Once embedded, that code no longer
  belongs to a separate module at all — it's part of the host — so that
  lookup resolves to the *host binary's own* path rather than the
  gadget's, meaning the config file needs to be named after the host's
  own filename stem, not the gadget's. With the config named that way,
  the embedded gadget loads it, runs the configured script, and the
  script's own `NativeFunction`-wrapped `exit(845)` call genuinely
  executes — confirmed by actually running the embedded binary (and, on
  Linux, by tracing it with `strace`).
- The two platforms report the script's exit code differently, for a
  reason with nothing to do with staticer or frida-gadget: Windows
  process exit codes are a full 32-bit `DWORD`
  (`GetExitCodeProcess`), so the PE test observes `845` directly: POSIX
  process exit statuses are truncated to the low 8 bits by the kernel
  itself (`man 2 wait`), so the ELF test observes `845 & 0xFF == 77`
  instead — both are the same underlying `exit(845)` call, genuinely
  executed.

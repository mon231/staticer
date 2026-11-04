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

Cycles among embeddable dependencies are detected and rejected with a
clear error naming the cycle, rather than looping forever or silently
picking an order.

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
system binaries — `cmd.exe`/`hostname.exe` on Windows, `bash`/`grep` on
Linux — both as a curated subset (via `--lib-dir`/`--exclude`) and as
closer-to-full transitive closures. A handful of real-world-only bugs
only ever surfaced against genuine system DLLs/`.so`s: forwarded
exports, ordinal-only imports, forwarder import cycles, stale
`DT_VERNEED` entries, `R_*_COPY` relocations for a dependency's own
globals, and weak symbols from the C runtime's own startup boilerplate —
all fixed, each covered by a regression test built from the binary that
found it.

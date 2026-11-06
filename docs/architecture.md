# Architecture

```
staticer/
  staticer.py            # CLI entrypoint: parse_args, sniff_format, main
  pe_embedder.py          # PE-specific embedding logic (pefile)
  elf_embedder.py         # ELF-specific embedding logic (pyelftools + hand-packed structs)
  common/
    depgraph.py           # format-agnostic dependency graph, exclusion, topo sort
  stubs/
    windows/pe_stub.py    # generated PE entrypoint stub (init-call sequence)
    linux/elf_stub.py     # generated ELF entrypoint stub / DT_INIT_ARRAY injection
tests/
  fixtures/               # tiny C sources for synthetic exe/dll/so test binaries
  windows/                # Windows-only tests (PE)
  linux/                  # Linux-only tests (ELF)
```

## Pipeline

1. **Sniff** the input's format (`MZ` → PE, `\x7fELF` → ELF).
2. **Build the dependency graph**: recursively resolve imports, respecting
   `--lib-dir` scoping and `--exclude`, with exclusion propagating
   transitively through anything an excluded node itself imports.
3. **Topologically sort** the embeddable subset — dependencies before
   dependents — raising a clear error on any cycle.
4. **For each embeddable dependency, in that order**:
   - partition into the relocation-bearing path or the fixed-base
     (no usable relocation data) path;
   - append its code/data into the host, re-applying relocations or
     reserving its preferred address as appropriate;
   - merge its exception/unwind metadata;
   - patch the host's (and any other embedded dependency's) import-table
     entries that reference it;
   - remove it from the import table / `DT_NEEDED`.
5. **Generate the entrypoint stub**: calls every embedded dependency's
   initializer in dependency order, then jumps to the original entry.
6. **Write the output.**

Everything not embedded (excluded, out-of-scope, or genuinely unresolved)
is left completely untouched — bit-for-bit equivalent to how an
unmodified binary would resolve it at runtime.

## Why no linker is involved

`staticer` never shells out to `ld`, `link.exe`, `objcopy`, or a
compiler — not at install time, not at run time. All of the above is
done by reading and rewriting the binary format directly:

- **PE**: via [`pefile`](https://github.com/erocarrera/pefile) for
  parsing, with direct byte-level patching for everything this project
  writes back (sections, the import directory, the relocation table, the
  exception directory, `DllCharacteristics`).
- **ELF**: via [`pyelftools`](https://github.com/eliben/pyelftools) for
  parsing (it's read-only), with a small set of hand-written struct-pack
  helpers for every ELF32/64 structure this project needs to write back
  (program headers, the dynamic section, relocation entries).

The only place a C compiler is used anywhere in this project is to build
the tiny synthetic test fixtures the test suite compiles on the fly — a
test/CI-time concern, not something the installed package ever invokes.

## The one deliberate exception: `keystone-engine`

Both generated entrypoint stubs (`staticer/stubs/windows/pe_stub.py`,
`staticer/stubs/linux/elf_stub.py`) are assembled from real x86/x86-64
assembly text via [Keystone](https://www.keystone-engine.org/)
(`keystone-engine` on PyPI) rather than hand-encoded as raw opcode byte
literals. This is a deliberate, explicit exception to the "pure Python,
no compiled C extensions" rule above — the same rule that excluded
`lief` early in this project's history — since `keystone-engine` ships a
compiled assembler engine under its Python bindings. It does not,
however, reintroduce the "needs a C toolchain" problem that rule exists
to prevent: `keystone-engine` publishes prebuilt wheels (confirmed:
`manylinux1_x86_64`/`manylinux2014_x86_64` and `win_amd64`, among
others) with the compiled engine already bundled, so installing it —
like `pefile`/`pyelftools` — never requires the end user to have a C
compiler. Its use is scoped narrowly: only for assembling the small,
fixed, generated entrypoint stubs on both the PE and ELF sides, never
for anything else in the embedding pipeline.

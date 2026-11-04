# staticer

Embed a dynamically-linked executable or shared library's dependencies
directly into it — fewer runtime dependencies, no "missing DLL" or
"wrong GLIBC version" failures from mismatched system libraries, at the
cost of a more unusual binary layout.

```
staticer <input> -o <output> [--exclude NAME[,NAME...]] [--lib-dir PATH]
```

- **Pure Python.** No linker, compiler, or native toolchain is invoked by
  the installed package — parsing and patching are done directly on the
  binary format (`pefile` for PE, `pyelftools` + hand-packed structs for
  ELF).
- **Both platforms, both formats.** Windows PE and Linux ELF, x86 and x64,
  executables and shared libraries (DLL/`.so`) as either the input or a
  dependency.
- **Scoped, not all-or-nothing.** Choose exactly which dependencies get
  embedded with `--exclude` and `--lib-dir`; everything else stays an
  ordinary dynamic import, resolved at runtime exactly as before.
- **Fails loudly, not silently.** An unsupported construct (TLS in a
  dependency, a base-address conflict, a crafted/untrusted dependency
  name) raises a clear error at embed time — never a corrupted binary
  that only breaks at the victim's runtime.

Start with [Installation](installation.md), then [Usage](usage.md) for
the CLI, or jump straight to [Examples](examples.md).

!!! warning
    Use this tool for legitimate development, debugging, or educational
    purposes only.

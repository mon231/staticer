# staticer core implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `staticer` end to end: given a PE or ELF executable/shared-object, resolve its dependency graph, embed the chosen dependencies' code/data/unwind-metadata into a new output binary with a generated init-order entrypoint stub, and leave excluded/out-of-scope dependencies untouched — on both Windows and Linux, x86 and x64, PIC and non-PIC.

**Architecture:** A format-agnostic `common/depgraph.py` builds the dependency graph and decides what's embeddable (exclusion propagates transitively; cycles and unresolved names are handled explicitly) and in what init order, driven by format-specific callbacks. `pe_embedder.py` and `elf_embedder.py` each supply those callbacks (import listing, resolution, section-level embedding, relocation/base-reservation, unwind-metadata preservation) and do the actual byte-level rewriting with `pefile`/`pyelftools`. `stubs/windows` and `stubs/linux` hold the generated-entrypoint and dlopen/LoadLibrary-hook trampolines each embedder calls into. `staticer.py` is the thin CLI that sniffs the input format and dispatches.

**Tech Stack:** Python 3, `pefile`, `pyelftools`, `pytest`, GitHub Actions (Windows + Linux matrix).

**Spec:** `docs/superpowers/specs/2026-11-01-staticer-design.md`

## Global Constraints

- Pure Python only: `pefile` for PE, `pyelftools` for ELF. No `lief`. No shelling to a linker, compiler, or `objcopy` at install/run time.
- No native toolchain required to install or run `staticer` itself (test fixtures may use a system compiler at test-setup time only — a CI/dev concern, not a package dependency).
- CLI shape: `staticer <input> -o <output> [--exclude NAME[,NAME...]] [--lib-dir PATH]`.
- Excluded dependencies and anything outside `--lib-dir` (when given) keep their on-disk import entries byte-for-byte untouched — never patched, never removed.
- Exclusion propagates transitively: anything imported (directly or indirectly) only through an excluded/out-of-scope node is itself treated as excluded, even if also directly imported by the host.
- Embedding requires matching architecture between host and dependency; no cross-arch embedding.
- No ELF destructor / `DllMain` process-detach invocation (non-goal, not built).
- A dependency with relocation data is always relocated normally; only a dependency with zero usable relocation data falls back to base-address reservation, which fails loudly on conflict.
- Exception/unwind metadata (`.pdata`/`.xdata`, `.eh_frame`) is preserved across the embedded boundary, not stripped or rejected.

## Review Focus

- An import name that resolves to nothing on disk (not excluded by name, just not found) is left as an ordinary dynamic import rather than erroring — the common case for any dependency outside the scan's reach.
- Two embeddable dependencies that import each other (a cycle) must not hang the topological sort or silently drop one side — it should fail loudly and name the cycle.
- An input file that is neither a valid PE nor a valid ELF (garbage/truncated) must produce a clear CLI error, never an unhandled traceback.
- Running with `--output` pointing at a file that already exists overwrites it (and this is documented), rather than silently refusing or corrupting a partial write.
- A resolved dependency whose architecture doesn't match the host (e.g., an x86 DLL found under the name an x64 host imports) must fail loudly instead of being embedded as corrupt code.

---

## File Structure

```
staticer/
  staticer/
    __init__.py
    staticer.py              # CLI: parse_args, main(), format sniff+dispatch
    pe_embedder.py             # PE-specific import listing/resolution/embedding
    elf_embedder.py             # ELF-specific import listing/resolution/embedding
    common/
      __init__.py
      depgraph.py               # format-agnostic graph build + exclusion + topo order
    stubs/
      windows/
        __init__.py
        pe_stub.py                # entrypoint-stub + LoadLibraryW/GetProcAddress hook bytes
      linux/
        __init__.py
        elf_stub.py                # entrypoint-stub + dlopen/dlsym hook bytes
  tests/
    conftest.py                 # fixture-building helpers (system compiler, skip if absent)
    fixtures/                   # tiny C sources for synthetic exe/dll/so targets
      lib.c
      exc_lib.c
      main.c
    test_depgraph.py            # format-agnostic graph/exclusion/cycle tests
    test_cli.py                  # argument parsing, format sniffing, error paths
    windows/
      test_pe_embed.py            # exe+dll, x86+x64, PIC (reloc-bearing) embedding
      test_pe_no_reloc.py          # base-reservation path + conflict failure
      test_pe_unwind.py             # exception across embedded boundary
      test_pe_scope.py               # --exclude / --lib-dir / transitive-exclusion overlap
      test_pe_real_binaries.py        # cmd.exe / notepad.exe, curated-subset + full-closure
    linux/
      test_elf_embed.py
      test_elf_no_reloc.py
      test_elf_unwind.py
      test_elf_scope.py
      test_elf_real_binaries.py       # bash / ls, curated-subset + full-closure
  .github/workflows/ci.yml
  setup.py                     # modified: install_requires -> pefile, pyelftools
  requirements.txt              # modified: pefile, pyelftools
  README.md                      # modified: new CLI, drop exception non-goal caveat
```

---

### Task 1: Dependency graph — resolution, transitive exclusion, cycle detection, topo order

**Files:**
- Create: `staticer/common/__init__.py`
- Create: `staticer/common/depgraph.py`
- Test: `tests/test_depgraph.py`

**Interfaces:**
- Produces:
  - `@dataclass DependencyNode: name: str; path: Path; embeddable: bool`
  - `class CyclicDependencyError(Exception)` — raised with the cycle's node names in its message.
  - `build_dependency_graph(root_path: Path, list_imports: Callable[[Path], List[str]], resolve: Callable[[str, List[Path]], Optional[Path]], search_dirs: List[Path], lib_dir: Optional[Path], exclude: Set[str]) -> Dict[str, DependencyNode]`
  - `embed_order(graph: Dict[str, DependencyNode]) -> List[DependencyNode]` — raises `CyclicDependencyError` on a cycle among embeddable nodes.
- Consumes: nothing (format-agnostic; `list_imports`/`resolve` are supplied by Tasks 3/4).

- [ ] **Step 1: Write failing tests for `build_dependency_graph`**

```python
def _fake(imports_by_name, resolvable_paths):
    def list_imports(path):
        return imports_by_name[path.name]
    def resolve(name, search_dirs):
        return resolvable_paths.get(name)
    return list_imports, resolve

def test_excludes_by_name():
    # root -> A (excluded by name)
    ...
    graph = build_dependency_graph(root, list_imports, resolve, [], None, {"a.dll"})
    assert graph["a.dll"].embeddable is False

def test_exclusion_propagates_transitively():
    # root -> X (excluded), root -> Y, X -> Y
    # Y must end up NOT embeddable even though root also imports it directly,
    # regardless of which edge to Y is visited first.
    ...
    assert graph["y.dll"].embeddable is False

def test_lib_dir_scopes_embedding():
    # root -> A (path inside lib_dir), root -> B (path outside lib_dir)
    graph = build_dependency_graph(root, list_imports, resolve, [], lib_dir, set())
    assert graph["a.dll"].embeddable is True
    assert graph["b.dll"].embeddable is False

def test_unresolved_import_is_left_dynamic():
    # root imports "missing.dll", resolve() returns None for it
    graph = build_dependency_graph(root, list_imports, resolve, [], None, set())
    assert "missing.dll" not in graph  # never embedded, never an error
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_depgraph.py -v`
Expected: FAIL (`build_dependency_graph` not defined)

- [ ] **Step 3: Implement `build_dependency_graph`**

```python
def build_dependency_graph(root_path, list_imports, resolve, search_dirs, lib_dir, exclude):
    nodes = {}

    def in_scope(path):
        return lib_dir is None or path.is_relative_to(lib_dir)

    def visit(name, path, force_excluded):
        is_excluded = force_excluded or (name in exclude) or not in_scope(path)
        if name in nodes:
            if is_excluded:
                nodes[name].embeddable = False
            return
        nodes[name] = DependencyNode(name=name, path=path, embeddable=not is_excluded)
        for imp_name in list_imports(path):
            resolved = resolve(imp_name, search_dirs)
            if resolved is None:
                continue
            visit(imp_name, resolved, force_excluded=is_excluded)

    for imp_name in list_imports(root_path):
        resolved = resolve(imp_name, search_dirs)
        if resolved is not None:
            visit(imp_name, resolved, force_excluded=False)
    return nodes
```

Exclusion only ever turns `embeddable` from `True` to `False` (never back), so visit order doesn't matter — whichever path discovers the exclusion wins.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_depgraph.py -v`
Expected: PASS

- [ ] **Step 5: Write failing tests for `embed_order` (topo sort + cycle detection)**

```python
def test_embed_order_is_dependencies_first():
    # A embeddable, B embeddable, A imports B -> B must come before A
    order = embed_order(graph)
    assert order.index(graph["b.dll"]) < order.index(graph["a.dll"])

def test_embed_order_skips_non_embeddable_nodes():
    order = embed_order(graph)
    assert graph["excluded.dll"] not in order

def test_embed_order_raises_on_cycle():
    # A imports B, B imports A, both embeddable
    with pytest.raises(CyclicDependencyError):
        embed_order(graph)
```

- [ ] **Step 6: Run tests to verify they fail, then implement `embed_order`**

Standard DFS post-order topological sort restricted to `embeddable` nodes and edges between embeddable nodes; track an in-progress set along the current DFS path and raise `CyclicDependencyError` (with the path's node names) if a node already on that path is revisited.

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_depgraph.py -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add staticer/common tests/test_depgraph.py
git commit -m "feat: dependency graph with transitive exclusion and cycle-checked topo order"
```

---

### Task 2: CLI — argument parsing, format sniffing, error handling

**Files:**
- Modify: `staticer/staticer.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `PortableExecutableEmbedder` from Task 3, `ElfEmbedder` from Task 4 (only their constructor signature and `.embed()`, per those tasks' Interfaces blocks — not implemented yet, so this task's embed-dispatch tests use stub/mock classes).
- Produces:
  - `parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace` with fields `input: Path`, `output: Path`, `exclude: Set[str]`, `lib_dir: Optional[Path]`.
  - `sniff_format(path: Path) -> Literal["pe", "elf"]` — raises `ValueError("unrecognized binary format")` for anything else.
  - `main(argv: Optional[List[str]] = None) -> int` — returns 0 on success, prints a one-line error and returns 1 on any `ValueError`/`CyclicDependencyError` raised below it (no raw traceback).

- [ ] **Step 1: Write failing tests**

```python
def test_parse_args_defaults():
    ns = parse_args(["in.exe", "-o", "out.exe"])
    assert ns.input == Path("in.exe") and ns.output == Path("out.exe")
    assert ns.exclude == set() and ns.lib_dir is None

def test_parse_args_exclude_is_comma_split():
    ns = parse_args(["in.exe", "-o", "out.exe", "--exclude", "a.dll,b.dll"])
    assert ns.exclude == {"a.dll", "b.dll"}

def test_sniff_format_pe(tmp_path):
    p = tmp_path / "x.exe"; p.write_bytes(b"MZ" + b"\x00" * 100)
    assert sniff_format(p) == "pe"

def test_sniff_format_elf(tmp_path):
    p = tmp_path / "x"; p.write_bytes(b"\x7fELF" + b"\x00" * 100)
    assert sniff_format(p) == "elf"

def test_sniff_format_rejects_garbage(tmp_path):
    p = tmp_path / "x"; p.write_bytes(b"not a binary")
    with pytest.raises(ValueError):
        sniff_format(p)

def test_main_reports_clean_error_on_garbage_input(tmp_path, capsys):
    p = tmp_path / "x"; p.write_bytes(b"garbage")
    code = main([str(p), "-o", str(tmp_path / "out")])
    assert code == 1
    assert "unrecognized" in capsys.readouterr().err.lower()

def test_main_overwrites_existing_output(tmp_path):
    out = tmp_path / "out.exe"; out.write_bytes(b"old")
    # ... main() with a real minimal PE input ...
    assert out.read_bytes() != b"old"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cli.py -v`
Expected: FAIL

- [ ] **Step 3: Implement `parse_args`, `sniff_format`, `main`**

`parse_args` uses `argparse` with a positional `input`, `-o/--output` (required), `--exclude` (comma-split into a set, default empty), `--lib-dir` (`Path`, default `None`). `sniff_format` reads the first 4 bytes and checks `b"MZ"` / `b"\x7fELF"` prefixes. `main` calls `sniff_format`, dispatches to `PortableExecutableEmbedder` or `ElfEmbedder` accordingly, and wraps the dispatch in `try/except (ValueError, CyclicDependencyError)` printing `str(e)` to stderr and returning 1; writing `--output` always opens with truncation (overwrite).

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add staticer/staticer.py tests/test_cli.py
git commit -m "feat: staticer CLI with format sniffing and clean error handling"
```

---

### Task 3: PE embedder — reloc-bearing dependency embedding (PIC path)

**Files:**
- Modify: `staticer/pe_embedder.py`
- Create: `tests/conftest.py` (fixture-building helpers, shared by Windows and Linux tests)
- Create: `tests/fixtures/lib.c`, `tests/fixtures/main.c`
- Test: `tests/windows/test_pe_embed.py`

**Interfaces:**
- Consumes: `DependencyNode`, `build_dependency_graph`, `embed_order` from Task 1 (`staticer/common/depgraph.py`).
- Produces:
  - `list_pe_imports(path: Path) -> List[str]`
  - `resolve_pe(name: str, search_dirs: List[Path]) -> Optional[Path]` (scans `search_dirs` in order; appends `System32`/`SysWOW64` only when no `--lib-dir` was given, per Task 2's call site)
  - `class PortableExecutableEmbedder: def __init__(self, input_path: Path, output_path: Path, exclude: Set[str], lib_dir: Optional[Path]); def embed(self) -> None` — raises `ValueError` on architecture mismatch between host and any embeddable dependency.

- [ ] **Step 1: Write `tests/conftest.py` fixture-building helpers**

A session-scoped fixture `c_compiler()` that finds `cl.exe`/`gcc`/`clang` on `PATH` and `pytest.skip()`s dependent tests if none is found; a helper `build_shared_lib(tmp_path, source: Path, name: str, *, pic: bool, bits: int) -> Path` and `build_exe(tmp_path, source: Path, name: str, libs: List[Path], *, pic: bool, bits: int) -> Path` that invoke it with the right flags (`/LD` or `-shared`, `-fPIC`/`-fno-pic`, `-m32`/`-m64` or `/arch`) — used by every per-platform embed test via `pytest.mark.parametrize("bits", [32, 64])` and `pytest.mark.parametrize("pic", [True, False])`.

- [ ] **Step 2: Write `tests/fixtures/lib.c` and `tests/fixtures/main.c`**

`lib.c` exports one function (e.g. `int lib_value(void) { return 42; }`); `main.c`'s `main()` calls it and `printf`s/returns the result, so a test can assert on the embedded output's exit code or stdout.

- [ ] **Step 3: Write failing tests**

```python
def test_embed_pic_dll_into_exe(tmp_path, c_compiler):
    dll = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.dll", pic=True, bits=64)
    exe = build_exe(tmp_path, FIXTURES / "main.c", "main.exe", [dll], pic=True, bits=64)
    out = tmp_path / "static.exe"
    PortableExecutableEmbedder(exe, out, exclude=set(), lib_dir=None).embed()
    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 42

def test_embedded_output_no_longer_imports_embedded_dll(tmp_path, c_compiler):
    # same setup; assert "lib.dll" not in list_pe_imports(out)
    ...

def test_architecture_mismatch_fails_loudly(tmp_path, c_compiler):
    dll32 = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.dll", pic=True, bits=32)
    exe64 = build_exe(tmp_path, FIXTURES / "main.c", "main.exe", [], pic=True, bits=64)
    # manually place dll32 where exe64's import of "lib.dll" would resolve to it
    with pytest.raises(ValueError):
        PortableExecutableEmbedder(exe64, tmp_path / "out.exe", set(), lib_dir=tmp_path).embed()
```

Run equivalents for `bits in (32, 64)` via parametrization.

- [ ] **Step 4: Run tests to verify they fail**

Run: `pytest tests/windows/test_pe_embed.py -v`
Expected: FAIL / SKIP (if no compiler) — confirm FAIL, not error, when a compiler is present

- [ ] **Step 5: Implement `list_pe_imports`, `resolve_pe`, `PortableExecutableEmbedder.embed`**

Use `pefile.PE` to read the `IMPORT_DESCRIPTOR` directory for `list_pe_imports`. `embed()`: build the graph (Task 1) with `list_pe_imports`/`resolve_pe`, get `embed_order`, then for each embeddable node append its sections (page-aligned) into the host, apply its base relocation table (`.reloc`) against the new section addresses, patch the host's `IMPORT_DESCRIPTOR`/IAT entries referencing that node to the embedded symbol's new address, and remove that node's entry from the host's Import Directory. Check `pefile.PE.FILE_HEADER.Machine` equality between host and dependency before embedding each node; raise `ValueError` on mismatch. (Entrypoint-stub wiring and unwind preservation are Task 7 — this task's `embed()` runs the dependency's init path inline via a call stub only for the happy path needed by these tests, which Task 7 replaces with the real generated stub.)

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/windows/test_pe_embed.py -v`
Expected: PASS (or SKIP without a compiler)

- [ ] **Step 7: Commit**

```bash
git add staticer/pe_embedder.py tests/conftest.py tests/fixtures tests/windows/test_pe_embed.py
git commit -m "feat: PE embedding for reloc-bearing (PIC) dependencies"
```

---

### Task 4: ELF embedder — reloc-bearing dependency embedding (PIC path)

**Files:**
- Modify: `staticer/elf_embedder.py`
- Test: `tests/linux/test_elf_embed.py`

**Interfaces:**
- Consumes: Task 1's `depgraph` API; Task 3's `tests/conftest.py` fixture helpers (same `c_compiler`/`build_shared_lib`/`build_exe`, parametrized with `-shared -fPIC`/`-no-pie` instead of PE flags) and `tests/fixtures/lib.c`/`main.c`.
- Produces:
  - `list_elf_imports(path: Path) -> List[str]` (from `DT_NEEDED` entries via `pyelftools`)
  - `resolve_elf(name: str, search_dirs: List[Path]) -> Optional[Path]` (scans `search_dirs`, then `/lib`, `/usr/lib`, `/lib64`, `/usr/lib64` when no `--lib-dir` was given)
  - `class ElfEmbedder: def __init__(self, input_path: Path, output_path: Path, exclude: Set[str], lib_dir: Optional[Path]); def embed(self) -> None` — same architecture-mismatch contract as Task 3.

- [ ] **Step 1: Write failing tests** (mirrors Task 3's three tests, ELF/.so flavored: `test_embed_pic_so_into_exe`, `test_embedded_output_no_longer_needs_embedded_so` checking `DT_NEEDED`, `test_architecture_mismatch_fails_loudly`)

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/linux/test_elf_embed.py -v`
Expected: FAIL / SKIP

- [ ] **Step 3: Implement `list_elf_imports`, `resolve_elf`, `ElfEmbedder.embed`**

Use `pyelftools`'s `ELFFile` dynamic section to read `DT_NEEDED` for `list_elf_imports`. `embed()` mirrors Task 3: append sections, apply `.rela.dyn`/`.rela.plt` relocations against new addresses, patch the host's PLT/GOT entries and symbol table for embedded symbols, remove the corresponding `DT_NEEDED` entry. Check `e_machine` equality for the architecture-mismatch check.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/linux/test_elf_embed.py -v`
Expected: PASS (or SKIP without a compiler)

- [ ] **Step 5: Commit**

```bash
git add staticer/elf_embedder.py tests/linux/test_elf_embed.py
git commit -m "feat: ELF embedding for reloc-bearing (PIC) dependencies"
```

---

### Task 5: PE non-PIC / no-relocation-data path (base-address reservation)

**Files:**
- Modify: `staticer/pe_embedder.py`
- Test: `tests/windows/test_pe_no_reloc.py`

**Interfaces:**
- Consumes: `PortableExecutableEmbedder` from Task 3 (extends `embed()`'s per-node handling).
- Produces: no new public names — `embed()` now also handles a node whose `pefile.PE` has an empty/absent `.reloc` directory by reserving that node's `OPTIONAL_HEADER.ImageBase` in the host's virtual address layout before mapping anything else there, and raises `ValueError` (naming the conflicting address) if that range is already claimed by the host image or another reserved dependency.

- [ ] **Step 1: Write failing tests**

```python
def test_embed_non_pic_dll_without_relocs(tmp_path, c_compiler):
    dll = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.dll", pic=False, bits=64, strip_relocs=True)
    exe = build_exe(tmp_path, FIXTURES / "main.c", "main.exe", [dll], pic=True, bits=64)
    out = tmp_path / "static.exe"
    PortableExecutableEmbedder(exe, out, set(), None).embed()
    assert subprocess.run([str(out)], capture_output=True).returncode == 42

def test_base_address_conflict_fails_loudly(tmp_path, c_compiler):
    # two no-reloc-data DLLs built/forced to the same preferred ImageBase
    with pytest.raises(ValueError):
        PortableExecutableEmbedder(exe, out, set(), None).embed()
```

(`build_shared_lib`'s `strip_relocs` flag, added here, re-saves the compiled DLL via `pefile` with its `IMAGE_DIRECTORY_ENTRY_BASERELOC` zeroed out, so the test doesn't depend on finding a compiler flag that reliably omits relocations.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/windows/test_pe_no_reloc.py -v`
Expected: FAIL

- [ ] **Step 3: Implement the base-reservation branch**

Before embedding any nodes, partition `embed_order()`'s result into reloc-bearing (Task 3 path) and no-reloc nodes; for each no-reloc node, check its `ImageBase` against the host's own load range and every other no-reloc node's claimed range — on overlap, raise `ValueError(f"base address conflict at 0x{addr:x} between {a} and {b}")`; otherwise record the range as reserved and copy its sections in at that fixed address without relocation.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/windows/test_pe_no_reloc.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add staticer/pe_embedder.py tests/windows/test_pe_no_reloc.py
git commit -m "feat: PE base-address reservation for no-relocation-data dependencies"
```

---

### Task 6: ELF non-PIC / no-relocation-data path (base-address reservation)

**Files:**
- Modify: `staticer/elf_embedder.py`
- Test: `tests/linux/test_elf_no_reloc.py`

**Interfaces:**
- Consumes: `ElfEmbedder` from Task 4.
- Produces: no new public names — same base-reservation behavior as Task 5, keyed off a dependency's `ET_EXEC`-style fixed load address (`p_vaddr` of its first `PT_LOAD` segment) when it carries no `.rela`/`.rel` entries.

- [ ] **Step 1: Write failing tests** (mirrors Task 5: `test_embed_non_pic_so_without_relocs`, `test_base_address_conflict_fails_loudly`, using a `strip_relocs` fixture helper that re-saves the `.so` via `pyelftools`/manual section edit with its relocation sections emptied)

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/linux/test_elf_no_reloc.py -v`
Expected: FAIL

- [ ] **Step 3: Implement the base-reservation branch** (mirrors Task 5, using ELF segment/section layout)

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/linux/test_elf_no_reloc.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add staticer/elf_embedder.py tests/linux/test_elf_no_reloc.py
git commit -m "feat: ELF base-address reservation for no-relocation-data dependencies"
```

---

### Task 7: PE unwind-metadata preservation + Windows entrypoint stub

**Files:**
- Modify: `staticer/pe_embedder.py`
- Create: `staticer/stubs/windows/__init__.py`, `staticer/stubs/windows/pe_stub.py`
- Create: `tests/fixtures/exc_lib.c`
- Test: `tests/windows/test_pe_unwind.py`

**Interfaces:**
- Consumes: `PortableExecutableEmbedder` from Tasks 3/5; `embed_order` from Task 1 (drives the stub's init-call sequence).
- Produces:
  - `build_windows_stub(init_order: List[str], hooked_names: Set[str]) -> bytes` in `staticer/stubs/windows/pe_stub.py` — machine code that, in order, calls each embedded module's entry (`DllMain` process-attach convention) for every name in `init_order`, installs the `LoadLibraryW`/`GetProcAddress` IAT hook (falling through to the originals for any name not in `hooked_names`), then jumps to the original entrypoint.
  - `PortableExecutableEmbedder.embed()` now also merges/duplicates `.pdata`/`.xdata` for each embedded node (patching their internal RVAs/offsets to the relocated addresses) and calls `build_windows_stub` to generate the new entrypoint instead of Task 3's placeholder inline call.

- [ ] **Step 1: Write `tests/fixtures/exc_lib.c`**

Exports a function that `throw`s (compiled as C++) or raises a structured exception (compiled as C, via `RaiseException`/`__try`/`__except`) caught by `main.c`'s caller across the embed boundary, returning a distinct exit code (e.g. `7`) only reachable if the catch worked.

- [ ] **Step 2: Write failing tests**

```python
def test_exception_crosses_embedded_boundary(tmp_path, c_compiler):
    dll = build_shared_lib(tmp_path, FIXTURES / "exc_lib.c", "exc.dll", pic=True, bits=64)
    exe = build_exe(tmp_path, FIXTURES / "exc_main.c", "main.exe", [dll], pic=True, bits=64)
    out = tmp_path / "static.exe"
    PortableExecutableEmbedder(exe, out, set(), None).embed()
    assert subprocess.run([str(out)], capture_output=True).returncode == 7

def test_dependency_initializer_runs_before_dependent(tmp_path, c_compiler):
    # lib B sets a global flag in its DllMain attach; lib A (depends on B) reads it in its own attach
    # assert exit code proves B's attach ran first
    ...
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/windows/test_pe_unwind.py -v`
Expected: FAIL

- [ ] **Step 4: Implement `.pdata`/`.xdata` merge and `build_windows_stub`**

Unwind-directory entries (`IMAGE_DIRECTORY_ENTRY_EXCEPTION`) reference function start/end RVAs and unwind-info RVAs; when a node's sections are relocated to new addresses, copy its `.pdata`/`.xdata` alongside and rewrite those RVA fields to match, then append the copied `.pdata` entries into the host's own exception directory (merged, sorted by start RVA, as the ABI requires) rather than discarding them. `build_windows_stub` emits a small fixed prologue (per Task 1's `embed_order` names, called in sequence) plus the hook trampoline bytes, written as a new PE section whose entrypoint RVA replaces the host's original `AddressOfEntryPoint` (saved and jumped to at the stub's end).

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/windows/test_pe_unwind.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add staticer/pe_embedder.py staticer/stubs/windows tests/fixtures/exc_lib.c tests/windows/test_pe_unwind.py
git commit -m "feat: PE unwind-metadata preservation and generated entrypoint stub"
```

---

### Task 8: ELF unwind-metadata preservation + Linux entrypoint stub

**Files:**
- Modify: `staticer/elf_embedder.py`
- Create: `staticer/stubs/linux/__init__.py`, `staticer/stubs/linux/elf_stub.py`
- Test: `tests/linux/test_elf_unwind.py`

**Interfaces:**
- Consumes: `ElfEmbedder` from Tasks 4/6; `embed_order` from Task 1.
- Produces:
  - `build_linux_stub(init_order: List[str], hooked_names: Set[str]) -> bytes` in `staticer/stubs/linux/elf_stub.py` — mirrors Task 7's stub: calls each embedded module's constructors (`.init_array`) in `init_order`, installs the `dlopen`/`dlsym` PLT hook (falling through for anything not in `hooked_names`), then jumps to the original entrypoint.
  - `ElfEmbedder.embed()` now merges `.eh_frame`/`.eh_frame_hdr` for each embedded node (patching the PC-relative offsets its FDEs encode to the relocated addresses) and wires in `build_linux_stub`.

- [ ] **Step 1: Write failing tests** (mirrors Task 7: `test_exception_crosses_embedded_boundary` using a C++ `throw`/`catch` fixture, `test_dependency_initializer_runs_before_dependent` using `.init_array` constructors)

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/linux/test_elf_unwind.py -v`
Expected: FAIL

- [ ] **Step 3: Implement `.eh_frame` merge and `build_linux_stub`**

`.eh_frame` FDEs encode PC-relative offsets to their function and to their CIE; when relocating a node's code, recompute those offsets for the new addresses and append the FDEs into the host's `.eh_frame` (and regenerate/extend `.eh_frame_hdr`'s binary-search table if present) rather than discarding them. `build_linux_stub` mirrors Task 7's structure for ELF: new `PT_LOAD` segment holding the stub code, `e_entry` repointed to it, jumping to the saved original entry at the end.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/linux/test_elf_unwind.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add staticer/elf_embedder.py staticer/stubs/linux tests/linux/test_elf_unwind.py
git commit -m "feat: ELF unwind-metadata preservation and generated entrypoint stub"
```

---

### Task 9: Scope/overlap end-to-end tests (`--exclude`, `--lib-dir`, transitive-exclusion overlap)

**Files:**
- Test: `tests/windows/test_pe_scope.py`
- Test: `tests/linux/test_elf_scope.py`

**Interfaces:**
- Consumes: `PortableExecutableEmbedder`/`ElfEmbedder` (Tasks 3–8, now feature-complete) and `tests/conftest.py` helpers.

- [ ] **Step 1: Write failing tests (Windows)**

```python
def test_exclude_keeps_dependency_dynamic(tmp_path, c_compiler):
    # exclude "lib.dll" by name; assert it's still in the output's import table and the output still runs
    ...

def test_lib_dir_only_embeds_matching_dependency(tmp_path, c_compiler):
    # one dep placed inside a lib_dir, another (same import mechanism) left at a path outside it
    # assert only the in-lib_dir one is gone from the output's import table
    ...

def test_transitive_exclusion_overlap(tmp_path, c_compiler):
    # host imports X (excluded) and Y directly; X itself imports Y
    # assert Y is NOT embedded (stays in output's import table) despite being a direct host import too
    ...
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/windows/test_pe_scope.py -v`
Expected: FAIL

- [ ] **Step 3: These exercise existing `embed()` logic — no new implementation; fix any bug they surface**

If a test fails for a reason other than "not implemented," it has found a real bug in Tasks 1–8; fix it there rather than in this task.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/windows/test_pe_scope.py -v`
Expected: PASS

- [ ] **Step 5: Repeat Steps 1–4 for `tests/linux/test_elf_scope.py`** (same three scenarios, ELF/.so flavored)

- [ ] **Step 6: Commit**

```bash
git add tests/windows/test_pe_scope.py tests/linux/test_elf_scope.py
git commit -m "test: --exclude, --lib-dir, and transitive-exclusion overlap scenarios"
```

---

### Task 10: Real-world system-binary tests (curated-subset + full-closure)

**Files:**
- Test: `tests/windows/test_pe_real_binaries.py`
- Test: `tests/linux/test_elf_real_binaries.py`

**Interfaces:**
- Consumes: `PortableExecutableEmbedder`/`ElfEmbedder`, feature-complete from Tasks 1–9.

- [ ] **Step 1: Write failing tests (Windows)**

```python
def test_cmd_exe_curated_subset(tmp_path):
    cmd = Path(os.environ["WINDIR"]) / "System32" / "cmd.exe"
    # copy one real System32 DLL cmd.exe imports into a lib_dir, exclude everything else by name
    out = tmp_path / "cmd_static.exe"
    PortableExecutableEmbedder(cmd, out, exclude=all_other_names, lib_dir=lib_dir).embed()
    result = subprocess.run([str(out), "/c", "echo hello"], capture_output=True, text=True)
    assert result.stdout.strip() == "hello"

def test_cmd_exe_full_closure(tmp_path):
    cmd = Path(os.environ["WINDIR"]) / "System32" / "cmd.exe"
    out = tmp_path / "cmd_static_full.exe"
    PortableExecutableEmbedder(cmd, out, exclude=set(), lib_dir=None).embed()
    result = subprocess.run([str(out), "/c", "echo hello"], capture_output=True, text=True)
    assert result.stdout.strip() == "hello"

def test_second_real_binary_curated_subset(tmp_path): ...  # reg.exe or notepad.exe, same shape
def test_second_real_binary_full_closure(tmp_path): ...
```

Mark all four `@pytest.mark.slow` and skip if not running as Administrator/with write access needed to copy/read `System32` freely.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/windows/test_pe_real_binaries.py -v`
Expected: FAIL

- [ ] **Step 3: These exercise existing logic end-to-end — fix any real-world edge case they surface** (e.g. a PE construct present in system DLLs but not in the synthetic fixtures) in the owning Task's file (3/5/7), not here

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/windows/test_pe_real_binaries.py -v`
Expected: PASS

- [ ] **Step 5: Repeat Steps 1–4 for `tests/linux/test_elf_real_binaries.py`** using `/bin/bash` and `/bin/ls` (or `/bin/cat`) against real `/lib`/`/usr/lib` shared objects, asserting on `subprocess.run([str(out), "-c", "echo hello"])` / `[str(out), tmp_path]` output respectively

- [ ] **Step 6: Commit**

```bash
git add tests/windows/test_pe_real_binaries.py tests/linux/test_elf_real_binaries.py
git commit -m "test: real-world system binaries (curated-subset and full-closure)"
```

---

### Task 11: Packaging — drop `lief`, update `setup.py`/`requirements.txt`/`README.md`

**Files:**
- Modify: `setup.py`
- Modify: `requirements.txt`
- Modify: `README.md`

**Interfaces:**
- Consumes: nothing (packaging metadata only).

- [ ] **Step 1: Update `requirements.txt`**

Replace `lief` with `pefile` and `pyelftools` (one per line, matching the file's existing style).

- [ ] **Step 2: Update `setup.py`'s `install_requires`**

Change `install_requires = ['lief']` to `install_requires = ['pefile', 'pyelftools']`.

- [ ] **Step 3: Update `README.md`**

Remove the "we currently do NOT support dependencies that use OS-based/C++ `exception`s" caveat (no longer true per Task 7/8); keep the ELF-destructor/`DllMain`-detach caveat; add one line documenting the new CLI shape (`staticer <input> -o <output> [--exclude ...] [--lib-dir ...]`) in place of the old `-i`/`-o`-only description.

- [ ] **Step 4: Verify the package still installs cleanly**

Run: `pip install -e .`
Expected: succeeds, pulling `pefile`/`pyelftools` instead of `lief`

- [ ] **Step 5: Commit**

```bash
git add setup.py requirements.txt README.md
git commit -m "chore: replace lief with pefile+pyelftools, update README for new CLI"
```

---

### Task 12: CI workflow — Windows + Linux matrix

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: nothing (CI config only; must build fixtures via a system compiler as a setup step, per Global Constraints, without that compiler becoming a package dependency).

- [ ] **Step 1: Write `.github/workflows/ci.yml`**

A matrix over `os: [windows-latest, ubuntu-latest]`; steps: checkout, set up Python, `pip install -e .` plus `pytest`, ensure a C compiler is on `PATH` (MSVC is preinstalled on `windows-latest`'s default shell — use the `ilammy/msvc-dev-cmd` action or equivalent to put `cl.exe` on `PATH`; `gcc`/`clang` are preinstalled on `ubuntu-latest`), then `pytest -v`.

- [ ] **Step 2: Verify locally where possible**

Run: `pytest -v` on this machine (Windows) with the current `PATH`'s compiler
Expected: the full suite passes or cleanly skips anything needing a missing tool (e.g. Administrator rights for Task 10's `System32` cases)

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: Windows + Linux test matrix"
```

---

## Self-Review Notes

- **Spec coverage:** every design-doc bullet maps to a task — graph/exclusion (1), CLI/--lib-dir/--exclude surface (2), PE/ELF PIC embedding (3/4), non-PIC base reservation (5/6), unwind preservation + entrypoint/hook stub (7/8), scope-overlap behavior (9), the mandated real-binary curated+full-closure tests (10), packaging/README (11), CI matrix (12).
- **Review Focus coverage:** unresolved import → Task 1; cycle → Task 1; garbage input → Task 2; `--output` overwrite → Task 2; arch mismatch → Tasks 3/4.
- **Type/name consistency checked:** `DependencyNode`, `build_dependency_graph`, `embed_order`, `CyclicDependencyError` are defined once in Task 1 and referenced identically in every later task; `PortableExecutableEmbedder`/`ElfEmbedder` constructor signature (`input_path, output_path, exclude, lib_dir`) is fixed in Tasks 3/4 and unchanged by 5/7/9/10.

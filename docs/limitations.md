# Limitations

- ELF: explicit dynamic-loading from the executed code itself
  (`dlopen`+`dlsym`) against an *embedded* dependency's own name **is**
  now hooked, x64 hosts only (see `elf_stub.py`'s module docstring's "Hook
  mechanism" section for the full design) -- `ElfEmbedder.embed()` finds
  every real GOT slot importing `dlopen`/`dlsym` (the host's own, and/or
  any embedded dependency's own remaining import of either) and, from a
  synthetic, zero-argument entry prepended to the generated init-array
  call sequence (runs before any embedded dependency's own real
  initializer, same ordering guarantee as the PE hook's own install
  step), forces real resolution via a harmless bootstrap call (fixing a
  real ELF-specific hazard the PE hook never has -- a naive "read the GOT
  slot, overwrite it" patch self-clobbers under lazy PLT binding, since
  the first real fallthrough call's own lazy resolution permanently
  overwrites the trampoline right back out), then overwrites every
  discovered slot with a generated trampoline (through a real
  `mprotect`-wrapped read/write when a slot falls inside the host's own
  RELRO-protected range, the ELF analogue of the PE hook's `VirtualProtect`
  dance). A `dlopen` call for one of this run's embedded dependencies'
  own names returns that dependency's own base VA as a fake handle
  (mirroring the PE hook's "HMODULE is the base address" convention); a
  `dlsym` call against that handle resolves against that dependency's own
  already-known export table. Confirmed via a real end-to-end fixture
  (`tests/linux/test_elf_dlopen_hook.py`): after a real `embed()`+run, the
  host's own runtime `dlopen`+`dlsym` call against an embedded
  dependency's name resolves and calls through to the embedded copy
  correctly, including when the real on-disk `.so` is removed first
  (proving no real `dlopen` happened), and an ordinary `dlopen`/`dlsym`
  call against a real, unrelated, still-on-disk system library
  (`libm.so.6`) is completely unaffected by the hook being installed.
  Known, deliberate scope limits:
  - x86-64 only (32-bit hosts get no hook at all), matching the PE hook's
    own x64-only scope.
  - Only `dlopen`/`dlsym` themselves are hooked, not `dlvsym` (the
    explicitly-versioned variant) -- not needed for anything this
    project's own fixtures or the motivating gap actually require.
  - `RTLD_DEFAULT`/`RTLD_NEXT` (dlsym's pseudo-handles) and any genuine
    real handle fall through to the real `dlsym` unconditionally, same as
    every other non-match.
  - A recognized handle whose requested symbol isn't in that
    dependency's own export table returns `NULL` rather than falling
    through to a *real* `dlsym` call with that handle -- deliberately
    narrower than it might seem necessary to be, and for the same reason
    `pe_stub.py`'s own `GetProcAddress` trampoline already makes the
    identical choice for its exact equivalent case: a fake,
    non-loader-tracked handle is never safe to hand to the real API.
    Confirmed concretely *why* for ELF specifically (not just mirrored
    from the PE side without checking): real glibc `dlsym` casts its
    `handle` argument directly to `struct link_map *` and dereferences
    fields on it with no validation at all once it isn't
    `RTLD_DEFAULT`/`RTLD_NEXT` -- since our fake handle (an embedded
    dependency's own base VA) is itself a validly-mapped address, this
    wouldn't even reliably crash; it would chase whatever unrelated bytes
    (that dependency's own ELF header/code, not a real `link_map`) happen
    to sit there as pointers, risking a wild write or a silently wrong
    resolved address rather than a clean, debuggable failure.
- PE (Windows): explicit dynamic-loading (`LoadLibraryW`/`LoadLibraryA`/
  `GetProcAddress`) against an *embedded* dependency's own name **is**
  now hooked, x64 hosts only (see `pe_stub.py`'s module docstring's "Hook
  mechanism" section for the full design) -- this project's own
  generated entrypoint stub installs trampolines over every discovered
  real IAT slot for the three, before any embedded dependency's own
  initializer runs, so anything that later asks to load one of this
  run's embedded dependencies by name gets back its already-initialized
  embedded address instead of triggering a real, separate, duplicate
  load. Two scope limits remain, both deliberate:
  - 32-bit (x86) hosts get no hook at all (the trampolines/install code
    are x64 machine code only, matching every other recently-added stub
    in that module).
  - This intercepts *explicit, application-level* LoadLibrary*/
    GetProcAddress calls, not the OS loader's own *internal* resolution
    of a module's statically-compiled import table while mapping that
    module. A module loaded dynamically by name (which this hook does
    see) that itself statically imports one of this run's embedded
    dependencies by name is NOT thereby redirected to the embedded copy
    -- the loader's own internal import-table walk for that module never
    calls through any IAT slot this hook can see or overwrite. See the
    010 Editor Qt-platform-plugin entry below for the real-world case
    this was confirmed against, and exactly what it does and doesn't fix.
    **Update: this specific gap is now separately fixed** by the
    LdrRegisterDllNotification-based hook described in that same
    010-Editor entry below -- the two hooks are complementary, not
    redundant (this one still covers the explicit-call case the other
    one doesn't, and vice versa).
- A "full closure" embed on ELF still bottoms out at glibc's own dynamic
  linker/loader internals, which stay dynamically linked rather than
  embedded. Root cause confirmed concrete, not a vague "loader internals"
  handwave: glibc (and `ld-linux` itself) use `R_X86_64_IRELATIVE` (GNU
  indirect-function/IFUNC) relocations, which `embed()` doesn't support
  at all — the full-closure case fails loudly with `"unsupported
  relocation type 37"` (confirmed via `test_bash_full_closure`/
  `test_grep_full_closure`, both `xfail`). IFUNC is a general mechanism
  that can appear in other modern-glibc-linked binaries too, not only
  glibc/ld-linux specifically.
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
  platforms (see [Features](features.md)). Merging two *separate* TLS
  directories — one from the host itself and one from a dependency —
  into a single combined block is implemented for a 64-bit PE host
  (see Features). **Update: no longer capped at one TLS-bearing
  dependency per run.** The 64-bit PE merge mechanism now chains any
  number of TLS-bearing dependencies into the same combined raw-data
  range in one `embed()` call (host-has-none-of-its-own + N
  dependencies, host-already-has-its-own + N dependencies, or any mix),
  each one's own compiled TLS-access offset shifted by however many
  bytes already precede it in the chain and each one's own `_tls_index`
  fixed up at process start to match whichever module ended up holding
  the one real, loader-assigned slot — proven via real embed()+run
  fixtures with two and three independently-TLS-bearing dependencies
  (`tests/windows/test_pe_tls.py`), including a three-way host+dep+dep
  merge. Still not implemented: a 32-bit PE host (whether the 32-bit
  limit comes from the host already having its own TLS directory, or
  from a *second* TLS-bearing dependency showing up with a TLS-less
  host — either now rejected with the same 64-bit-only error, since the
  synthesized index-fixup callback is x64 machine code either way), and
  ELF on either bit-width (ELF still rejects at exactly one TLS-bearing
  dependency, and still has no merge-with-host-TLS mechanism at all —
  see the ELF-specific TLS gaps below). Separately, and still real: even
  with the N-way cap gone, a *real* MSVC-compiled dependency DLL (as
  opposed to this project's own mingw-w64 test fixtures) can still fail
  the byte-pattern scanner this merge depends on to find and shift its
  compiled TLS-access instruction(s) — see "The host-already-has-TLS
  merge's byte-pattern scanner... is narrower than its own docstring
  implies" below, which is unaffected by this change and was confirmed
  via the same local 010 Editor testing that originally found the
  one-dependency cap: 8 of its Qt6 modules plus 4 further dependencies
  (`astyle.dll`, `pugixml.dll`, `rapidjson.dll`, `tidy-html.dll`) all
  carry real (non-empty) TLS directories, and all are real MSVC builds.
- **Fixed**: PE's dependency graph previously only discovered a dependency
  via ordinary import-table edges, so a DLL reachable *only* as another
  dependency's export-forward TARGET (e.g. SHLWAPI.dll forwards some
  exports to SHCORE.dll, which SHLWAPI.dll's own import table never
  mentions at all) was never added to the graph at all, and
  `_resolve_raw_export`'s finalize pass hit a hard, unconditional dead
  end resolving it ("isn't an already-embedded dependency"). Fixed by
  having the PE embedder's own `list_imports` callback
  (`_list_pe_import_graph_edges`) also surface forwarder-target DLL
  names as graph edges, so a forward-only dependency gets discovered,
  resolved, and embedded exactly like any ordinary one — found and fixed
  while pushing a real `python.exe`+`python313.dll` full-System32-closure
  embed further; a self-forward (a real shape too, e.g. RPCRT4.dll
  forwards some of its own ANSI exports to its own wide-string ones) is
  explicitly excluded from this to avoid a spurious self-loop in
  `embed_order`'s cycle detector.
  **Fixed**: a genuine import CYCLE among embeddable dependencies
  (confirmed real, not hypothetical: WS2_32.dll's own import table
  imports MSWSOCK.dll, while WS2_32.dll also forwards some exports TO
  MSWSOCK.dll) has no valid single topological order, so
  `embed_order()`'s strict default used to raise `CyclicDependencyError`
  rather than embed either side wrong. Confirmed (by tracing every line
  of `embed()`'s per-dependency loop) that cross-dependency resolution
  is already fully deferred to a finalize pass run after every
  dependency is placed, so a strict total order is not a real technical
  requirement for the embedding mechanism itself — `embed_order` gained
  an additive `allow_cycles=True` opt-in (`common/depgraph.py`) that
  groups mutually-cyclic nodes into strongly-connected components
  (Tarjan's algorithm) instead of raising, keeping every component
  dependencies-first relative to the rest of the graph; `pe_embedder.py`
  opts into it, `elf_embedder.py` keeps calling the strict default
  unchanged. See `tests/windows/test_pe_real_binaries.py`'s
  `test_second_real_binary_full_closure` (still `xfail`, now for a
  *different* reason — this cycle, and its two earlier blockers
  (KERNELBASE.dll's TLS directory and the forwarder-discovery gap), are
  all fixed; the current blocker is msvcrt.dll hitting the already-
  documented TLS byte-pattern-scanner limitation below).
- **Fixed, found via the same 010 Editor testing**: `pefile.PE(path)`
  (`fast_load=False`, the default) already fully parses every data
  directory at construction; `pe_embedder.py` used to call
  `parse_data_directories()` a *second* time on the same already-parsed
  object (in `list_pe_imports`, `embed()`'s host parse, and `embed()`'s
  per-dependency parse). That redundant call is not a no-op: for 010
  Editor's own densely-importing binary (26 real `IMAGE_IMPORT_DESCRIPTOR`
  entries), the second walk silently gave up after too many entries it
  failed to resolve imports for, truncating the parsed import list from
  26 down to 3 — `build_dependency_graph` then saw only the host's first
  3 imports, and the final rebuilt import table was missing the rest,
  producing a real `c0000005` access-violation crash on launch. Fixed by
  removing all three redundant re-parse calls.
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
  encountered.
- Three further ELF TLS gaps, none yet implemented (distinct from the
  already-documented "second TLS-bearing dependency"/GD-LD-relaxation
  cases above):
  - `R_X86_64_TPOFF64` (the Initial-Exec TLS model) is completely
    unimplemented — `embed()` raises a `ValueError` naming it explicitly
    rather than mis-handling it (`elf_embedder.py`).
  - A TLS-bearing dependency that itself references an *external* (not
    embedded, not the host's own) TLS symbol is rejected outright, for
    both the module-ID (`DTPMOD64`) and offset (`DTPOFF64`) relocation
    halves.
  - A fixed-base (non-PIC, `ET_EXEC`) ELF dependency that carries its own
    TLS directory is unconditionally rejected.
- PE's `blob_size` (derived from a dependency's `SizeOfImage`) has no
  upper-bound sanity check, unlike ELF's equivalent `p_memsz`-derived
  size, which is capped at 16 GiB against a malformed/adversarial value
  triggering an unbounded allocation. This asymmetry (PE side missing
  the same guard ELF already has) is a real, currently open gap.
- PE has no dependency-architecture allow-list. ELF explicitly rejects
  any machine type other than x86/x86-64
  (`_SUPPORTED_MACHINES`); PE's `embed()` only checks that the host and
  dependency *agree* with each other (a mismatch guard), never that the
  shared architecture is one staticer has ever actually been exercised
  against (e.g. ARM64 PE would currently be accepted untested).
- No guard against passing the same path as both `--input` and
  `--output`; doing so likely surfaces as a raw, unhelpful Python
  traceback (e.g. a file-handle conflict) rather than a clean CLI error.
- **Real system-DLL `DllMain` invocation has an unresolved, nondeterministic
  crash risk** — the most severe open item in this list, since it's not
  reproducible on demand. Embedding `WS2_32.dll` alone into `hostname.exe`
  (no TLS involved, previously verified working) crashed with
  `STATUS_ACCESS_VIOLATION` on one real Windows build (Server 2025,
  build 26100) while passing reliably across 15/15 runs on a different
  build (26300). No concrete bug has been identified; the leading theory
  is that invoking a real system DLL's own `DllMain` out-of-band (this
  project's whole embedding design, not what the real Windows loader
  does) is sensitive to that exact DLL's build — properly diagnosing or
  fixing this would need either the exact crashing build's `System32`
  image or a substantially more complete PE loader than `embed()`
  implements. Treat embedding real, non-trivial system DLLs as currently
  unreliable, not merely "untested."
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
- Minor, acknowledged-unfixed correctness nitpick in the dependency
  graph (`common/depgraph.py`): in a cycle, `is_excluded` can go stale
  in an already-visited parent DFS frame. Low risk in practice —
  `embed_order` independently raises on any cycle among embeddable
  nodes regardless, so this can't silently produce a wrong embed.
- The ELF unwind-metadata-preservation scan for `_CxxThrowException`
  call sites (`_fh4_scan_for_throw_info_candidates`-equivalent logic in
  the MSVC unwind-fix path) is scoped per-function (each
  `RUNTIME_FUNCTION`/`.pdata` entry's own byte range), not a whole-
  section scan. Reliable for any function with its own `.pdata` entry
  (effectively all x64 functions), but not a complete, generic
  throw-site finder in the abstract. Every candidate is structurally
  validated before any write, so the failure mode is "misses a throw
  site" (then falls back to not patching it), never data corruption.
  Distinct from the already-documented self-contained throw+catch
  personality-routine limitation above.
- A PLT entry resolved under lazy binding is only handled for the
  ordinary `R_*_JUMP_SLOT` case; an `R_*_GLOB_DAT`/`R_*_IRELATIVE` entry
  inside the PLT relocation table under lazy binding (not seen in any
  real-world binary encountered so far) would take the eager-binding
  code path instead.
- **PE's section-header table has no growth mechanism — update: now
  implemented.** Embedding a dependency appends new sections, which
  needs new section-header entries — but if the host's own
  section-header table was packed tight against its first section's
  file data by the original linker (common for modern, real-world
  commercial binaries; found via local testing against a genuine
  Qt6-based application, [010 Editor](https://www.sweetscape.com/010editor/)),
  there may be only a handful of bytes of slack, nowhere near enough for
  even one dependency's worth of new sections. `embed()` used to always
  fail loudly in this case (`"not enough slack in the host's section
  header table to add N new section(s)"`) rather than corrupting the
  output, but couldn't embed *anything* into such a host. ELF had an
  equivalent constraint (growing the program-header array) and already
  solved it; `embed()` now applies the PE-side counterpart of that same
  "grow in place, extend the existing boundary" discipline when the
  existing slack is insufficient: it shifts every section's
  `PointerToRawData` (and the debug directory's own file-offset-based
  `PointerToRawData` entries, if present) forward by enough
  `FileAlignment`-aligned bytes to close the shortfall, grows
  `SizeOfHeaders` to match, and physically widens the output file with
  that many padding bytes right before the first section's raw data.
  Every RVA/VA-based field (imports, relocations, exceptions, TLS, the
  entry point, ...) is untouched by construction, since this only moves
  *file* offsets. When the host already has enough slack (the common
  case), behavior is byte-for-byte unchanged — the growth path only
  activates when the existing check would otherwise have raised. Two
  narrow, theoretical gaps, unreachable with any known real-world
  linker's output but worth knowing about: the legacy COFF
  `FILE_HEADER.PointerToSymbolTable` field is never shifted (always 0 in
  every real linked EXE/DLL this project has seen); and the new
  `SizeOfHeaders` math assumes the host's *original* `SizeOfHeaders`
  equals its original first section's `PointerToRawData`, true for
  every real toolchain observed so far but not asserted in code.
- **The host-already-has-TLS merge's byte-pattern scanner
  (`_patch_dep_tls_access_offsets`) is narrower than its own docstring
  implies.** It was verified correct against this project's own
  mingw-w64-compiled test fixtures, but **confirmed to fail against real
  MSVC-built third-party DLLs** (found via the same local 010 Editor
  test: `embed()` correctly refused to merge Qt6Core.dll/Qt6Widgets.dll/
  etc.'s TLS directories into the host, each failing loudly with "none
  were found matching the expected compiled pattern," rather than
  silently mis-patching). This is the disclosed risk from the original
  implementation materializing on real software, not a new kind of bug —
  but it means the host-already-has-TLS merge path, while safe, is
  currently narrower in practice than "works for 64-bit PE" suggests.
  **Also now confirmed against a real Microsoft-shipped system DLL, not
  just third-party ones**: once `embed_order`'s cycle-tolerance fix (see
  above) stopped `test_second_real_binary_full_closure` from hitting
  `CyclicDependencyError`, the next real dependency reached --
  msvcrt.dll, itself TLS-bearing -- hits this exact same scanner gap,
  now the test's current (still-`xfail`) blocker.
  (A previously-listed "extended x64 register (`r8d`-`r15d`) load" gap
  here was re-reviewed and confirmed NOT a real gap — the anchor match
  only looks at the ModRM reg-field bits, which a preceding REX prefix
  byte doesn't affect — and is now covered by an automated test,
  `tests/test_pe_tls_scanner_unit.py`; it was a stale claim that got
  re-introduced by this file's own 2026-11-08 consolidation pass after
  already being corrected once, on 2026-11-06.)
  **Planned, not yet implemented**: broaden the scanner to recognize the
  compiled-TLS-access idiom across more real compilers/optimization
  levels (at minimum real MSVC-emitted code, not just mingw-w64), or add
  a second, independent verification pass (e.g. checking the matched
  instruction's full surrounding byte context, not just the first
  candidate) so a genuine non-match still fails loudly but a near-miss
  doesn't silently misfire.
  **Update, fixed**: pushing the 010 Editor embed further (adding
  ADVAPI32.dll/SHELL32.dll/COMDLG32.dll/MSVCP140.dll/VCRUNTIME140.dll
  alongside the already-working Qt6Core/Gui/Widgets, 8 real dependencies
  pulling in 57 total once their own transitive imports are included)
  turned up exactly the "near-miss silently misfires" risk the paragraph
  above already flagged as a theoretical concern -- this time for real,
  twice, both causing genuine `c0000005` crashes (one inside
  `010Editor+0x1a9bd24`, a `mov rax, [rax+rcx*8]` reading a bogus
  RVA-sized address; the other inside `010Editor+0x1e50afe`, a RIP-
  relative load whose own disp32 had been corrupted). Root-caused via
  disassembling the exact crash sites and mapping them back to specific
  `.sdepN` sections (`SHLWAPI.dll` and `SHELL32.dll` respectively, both
  real Windows system DLLs, not Qt or MSVC-CRT modules) and comparing the
  live crashing bytes against those same DLLs' own on-disk originals:
  - `_try_patch_msvc_style_tls_access`'s backward ("unoptimized-build")
    window scan could walk *into the anchor's own 6 bytes* (its disp32
    is arbitrary data with no structural meaning as machine code) and
    misread one of those bytes as a `mov r32, imm32` opcode purely by
    coincidence (confirmed: SHLWAPI.dll's real anchor disp32,
    `0x0005bde2`, has `0xbd` as its second byte, squarely in the
    `0xB8-0xBF` range being scanned for) -- corrupting the anchor's own
    `_tls_index` load and the start of the following real instruction.
  - Separately, the same function's forward scan (and the "before"
    window too) could land on a coincidental `0xB8-0xBF` byte inside a
    completely unrelated, genuinely different instruction sitting
    between the anchor and the real offset-load (confirmed: SHELL32.dll
    has an ordinary, unrelated `mov [rip+disp32], eax` store between its
    anchor and its real `mov r9d, 0x10` offset-load, whose own disp32
    byte `0xba` got misread and corrupted the same way) -- a corroboration
    check ("does a `gs:[0x58]` access exist somewhere in the window")
    that's necessary but not remotely sufficient on its own.
  Fixed by replacing the byte-anywhere-in-a-window scan with a much
  narrower, strongly-corroborated match: a `mov r32, imm32` candidate is
  now only accepted when it's immediately (zero-gap) followed by the one
  instruction shape every real compiled access actually observed shares
  right after loading the offset -- a scale-8 SIB-addressed load using
  that register (`REX.W 8B modrm(mod=00,rm=100) sib(scale=11)`, e.g.
  `48 8B 04 C8` / `4C 8B 04 D0`), plus never starting a candidate inside
  the anchor's own 6 bytes at all. Verified against the real SHLWAPI.dll
  and SHELL32.dll bytes (the exact false matches no longer fire, the
  exact real matches still do) and covered by two new hand-crafted
  regression tests in `tests/test_pe_tls_scanner_unit.py`
  (`test_scanner_does_not_misparse_anchor_disp32_as_msvc_immediate`,
  `test_scanner_does_not_misparse_intervening_instruction_as_msvc_immediate`).
  Trading recall for precision this way means a real anchor can now
  legitimately go unmatched (confirmed: patching only 10 of 15 real
  anchors in SHLWAPI.dll and 25 of 26 in SHELL32.dll with real-world
  `shift` values) without the whole merge being treated as unsupported
  -- `_patch_dep_tls_access_offsets` only raises when *none* of a
  dependency's anchors matched, same as before this fix, deliberately
  *not* tightened to "all anchors must match": nearly every real system
  DLL embeds several TLS-bearing access sites, and refusing on any
  partial miss would make real-system-DLL embedding impractical. A
  missed anchor leaves that one specific TLS variable reading/writing a
  stale (but still in-bounds) offset rather than crashing -- a real,
  accepted correctness gap, not a new crash risk, and exactly the kind
  of gap the "second, independent verification pass" note above already
  anticipated.
- **Fixed, found via the same 010 Editor testing (history below --
  CORRECTED twice; the first "fix" here had a real, confirmed
  regression of its own)**: the PE embedder had no handling at all for
  `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT` (the linker's `/DELAYLOAD`
  feature) -- a second, independent real crash source, unrelated to the
  TLS scanner bugs above. Left alone, a delay-imported function's
  compiled thunk, on its first actual use, calls
  `ntdll!LdrResolveDelayLoadedAPI` passing the embedded dependency's own
  placement as if it were a real, separately `LoadLibrary`'d module's
  `HMODULE` -- which it isn't. Confirmed via live single-stepping under
  a debugger (embedding a real `OLEAUT32.dll`) that this leads to an
  indirect call through a null pointer, crashing with RIP becoming
  exactly `0`. 38 of 57 of a real 010 Editor embed's dependencies have a
  non-empty delay-import directory, so refusing to embed any dependency
  with one isn't viable.

  **First fix attempt (shipped, then reverted)**: folded every delay-
  import module into the same merged/combined *ordinary*-import
  mechanism already used for a dependency's own remaining external
  imports, reasoning that the modern delay-import descriptor shape
  (`pINT`/`pIAT`) mirrors an ordinary one closely enough to reuse that
  machinery. This stopped the null-pointer crash, but introduced a
  **real, confirmed regression**: it turns every genuinely *lazy*
  delay-load into an *eager*, process-init-time one, resolved by
  `LdrpInitializeProcess` before any application code -- even the
  host's own entry point -- ever runs. Confirmed via a real full 010
  Editor embed (`staticer 010Editor.exe -o onefile_010editor.exe
  --exclude kernel32.dll,msvcrt.dll,ntdll.dll,USER32.dll,ole32.dll`,
  all 57 transitive dependencies once ADVAPI32/SHELL32/COMDLG32 are
  added) plus `gflags /i <exe> +sls` (Show Loader Snaps): the build no
  longer crashed, but *hung forever* behind a `STATUS_DLL_INIT_FAILED`
  ("this application was unable to start correctly") hard-error dialog
  that generates no WER entry at all (a loader-level hard error, not an
  unhandled exception), with the loader snap log pinpointing the exact
  cause --
  ```
  LdrpPreprocessDllName - ERROR: ... for DLL
  ext-ms-win-security-chambers-l1-1-0.dll failed with status
  0xc0000481 (STATUS_API_SET_NOT_PRESENT)
  LdrpInitializeProcess - ERROR: Walking the import tables of the
  executable and its static imports failed with status 0xc0000481
  ```
  -- i.e. `SECHOST.dll` (itself one of the 57 embedded dependencies
  here, pulled in purely as an export-forward target of ADVAPI32.dll,
  nothing to do with delay imports at all) has its own perfectly
  ordinary, genuine `/DELAYLOAD` import of that API set, which
  independently confirmed has no real host at all on this machine
  (`LoadLibraryW` on it fails with `ERROR_MODULE_NOT_FOUND`/126,
  outside this project entirely). That's fine -- *expected*, even --
  for a real delay import: it's resolved only on an actual first call,
  which evidently never happens during 010 Editor's own normal startup.
  Forced into the *ordinary* import table instead, its mere absence
  became a mandatory, unrecoverable process-startup failure. (This
  wasn't an isolated fluke either: a scan of this same real 010 Editor
  closure found over 100 delay-import entries whose target happens to
  also be one of this run's own embedded dependencies once ADVAPI32/
  SHELL32/COMDLG32/SHLWAPI/SHCORE/NETAPI32/etc. are all embedded --
  contradicting that first fix's own "a delay-import's target is never
  itself one of this run's embedded dependencies" assumption.)

  **Second attempt tried, also empirically falsified**: simply
  reverting to "leave every delay-import descriptor completely
  untouched" (its pre-fix behavior) was tried next and *also* crashes --
  this turns out to be the *same original* null-pointer-at-RIP-0 bug,
  reproduced again and root-caused live under `cdb`:
  ```
  LdrResolveDelayLoadedAPI - ERROR: LdrResolveDelayLoadedAPI:Unable to
  locate DLL based at 0x00000001425B0000. Status = 0xc0000135
  Access violation - code c0000005 (first chance)
  00000000`00000000 ??              ???
  ```
  This is unavoidable for *any* embedded dependency with its own delay
  imports, regardless of the delay-import's target: the compiler's own
  thunk computes `ParentModuleBase` as `&__ImageBase` (correctly
  resolving, via ordinary RIP-relative addressing, to this dependency's
  own placement *within* the host image -- the same property that
  already lets its entry point/export table/TLS directory work
  untouched), but `LdrResolveDelayLoadedAPI` needs that to be a *real,
  separately loaded module's* registered base, which it no longer is
  once embedded -- so the lookup fails and the thunk's own failure
  handling dereferences a null/garbage result.

  **Properly fixed**: the compiler's own delay-load thunk must never
  run at all for *any* delay import belonging to an embedded
  dependency, regardless of its target, while the target DLL's real
  name/optionality must never be forced into eager resolution either.
  Two cases:
  1. Target is itself embedded this run: no live DLL by that name is
     left to delay-load, so each function is resolved directly to the
     target's own final address (mirroring the ordinary-import "B1"
     merge's dependency-to-dependency IAT patch) -- bypassing the
     delay-load thunk entirely, since the IAT slot already holds the
     real address before anything could call through it. A resolution
     failure here (e.g. SHLWAPI.dll's real delay import of SHELL32.dll's
     ordinal 102, `SHCoCreateInstance`, which SHELL32 itself can only
     re-export as a forward to the same unembeddable
     `api-ms-win-shell-shellcom-l1-1-0.dll` virtual API set as the
     next bullet below) falls back to leaving that one IAT slot's
     original compiled bytes untouched rather than failing the whole
     embed -- safe because the target DLL is still a real, loadable
     file on disk even once also embedded.
  2. Target is a real external DLL, not embedded this run (the
     overwhelming majority of cases): a small generated per-function
     "lazy thunk" is installed in its IAT slot instead of the
     compiler's own thunk. On the host's own code's first actual call
     through that slot (never before), it does its own real
     `LoadLibraryA`+`GetProcAddress` (through two freshly added
     KERNEL32.dll IAT slots -- KERNEL32.dll is never embeddable/
     excludable, so this is always safe/eager with no optionality
     concern), self-patches the slot with the resolved address so
     every later call skips straight to it (matching a real delay-
     load's own steady-state-bound behavior), and only then tail-jumps
     -- preserving every x64 argument register (`rcx`/`rdx`/`r8`/`r9`
     and `xmm0`-`xmm3`, matching what MSVC's own real thunks preserve)
     so the resolved function's own `ret` lands directly back at the
     real caller. Nothing runs until that first real call; what runs
     then never touches `LdrResolveDelayLoadedAPI` or any other loader-
     internal mechanism at all.

  Verified against the real, full 010 Editor embed: the build no
  longer hangs behind a hard-error dialog and no longer null-pointer-
  crashes -- it now actually starts, shows a real window, and stays
  alive and responsive. See the next bullet for what it shows once it
  does.
- **Found, confirmed unrelated to the delay-import fix above**: with
  the loader-level hang/crash fixed, the real full 010 Editor embed
  now actually starts and shows a real window for the first time in
  this whole investigation -- but that window is Qt's own
  "This application failed to start because no Qt platform plugin
  could be initialized" error dialog, not 010 Editor's real UI.
  Root-caused, not just observed: `Get-Process -Module` on the running
  process shows `Qt6Core.dll` and `Qt6Gui.dll` both loaded as real,
  separate, disk-resident modules (`C:\Program Files\010
  Editor\Qt6Core.dll`/`Qt6Gui.dll`) *alongside* this run's own embedded
  copies of the exact same two DLLs. Cause: 010 Editor's Qt platform
  plugin (`Plugins\platforms\qwindows.dll`, loaded at runtime via
  `QPluginLoader`/`LoadLibrary`, entirely outside this project's own
  static import-table analysis) has its own ordinary, compile-time
  import of `Qt6Core.dll`/`Qt6Gui.dll` by name; since no module by
  that exact name is registered in the process once they're embedded,
  the real Windows loader dutifully finds and loads a second, fresh,
  genuinely separate copy straight off disk (both files are still
  there -- embedding copies a dependency's code into the host, it
  doesn't remove the original file). The result is two independent
  QtCore/QtGui runtime instances in one process with no shared global
  state (separate `QCoreApplication::instance()`, among everything
  else), which is exactly the shape Qt's own plugin-compatibility
  check is designed to reject.

  This is **not a new gap introduced by this task's fix** -- it's the
  first entry in this very file ("Explicit dynamic-loading from the
  executed code itself ... is not hooked yet") and the
  deliberately-deferred "runtime dynamic-loading interception" hook
  `pe_stub.py`'s own module docstring already describes in detail
  (locate KERNEL32's LoadLibraryW/GetProcAddress IAT slots, redirect a
  request for an embedded module's own name back to its embedded
  address instead of letting a fresh copy load) -- it simply had never
  been *reached* before: every earlier attempt at this real 010 Editor
  embed crashed or hung during process bootstrap, long before Qt ever
  got a chance to load a plugin at all. Fixing the delay-import
  regression was a precondition for discovering this, not its cause.
  Implementing that hook is a substantial, separate undertaking (real,
  non-trivial generated machine code touching every embedded
  dependency's own name resolution, with -- per that same docstring --
  "an outsized blast radius if it's subtly wrong") and is left as
  follow-up work, consistent with this project's existing precedent of
  shipping the tested mechanism now and deferring that specific hook.

  **Update**: that hook is now implemented (the `LoadLibraryW`/
  `LoadLibraryA`/`GetProcAddress` section above) -- it correctly
  redirects any EXPLICIT, application-level LoadLibrary*/GetProcAddress
  call against an embedded dependency's own name, confirmed via a real
  end-to-end fixture. It does **not**, by itself, fix the Qt-plugin
  case described here: `qwindows.dll` is itself loaded via an explicit
  `LoadLibraryW` call (which the hook correctly lets through to a real
  load, since `qwindows.dll` itself isn't embedded), but ITS OWN static
  import table's resolution of `Qt6Core.dll`/`Qt6Gui.dll` happens
  entirely inside `ntdll`'s own `LdrpLoadDll`/import-snap machinery --
  never through any IAT slot the KERNEL32-level hook can see or
  overwrite. Two independent investigations into the next-level fix
  this needs, both real research, neither shipped:

  1. *Is there a simpler fix?* No. A real Qt6 rebuild with static
     plugins (`configure -static` + `Q_IMPORT_PLUGIN`) would eliminate
     `qwindows.dll` as a separate module entirely, but that means
     controlling 010 Editor's own Qt6 build, not something staticer can
     do. An embed-time rewrite of `qwindows.dll`'s own on-disk IAT is
     structurally impossible, not just complex: the embedded
     `Qt6Core.dll`'s real runtime base is only known once the HOST
     process actually loads (ASLR), which is long after `embed()` has
     already finished writing files to disk. No Windows OS-level
     facility (KnownDLLs, SxS/manifest redirection) generalizes to "redirect
     an arbitrary third-party import, per-run, against an already-mapped
     module." Prior art (PyInstaller's onefile mode, Enigma Virtual Box)
     doesn't actually solve this same problem -- both extract every
     embedded file to a real temp location (or virtualize the filesystem)
     and let the ordinary Windows loader do all resolution itself,
     naturally deduplicating by path; neither does true in-memory PE
     embedding with manual import fixups the way staticer does, so
     neither ever hits this failure mode in the first place. This is a
     real structural cost of staticer's own in-memory-embed design,
     not a gap in research.
  2. *Is `LdrRegisterDllNotification` (the natural next mechanism: an
     officially Microsoft-documented, if "may change without notice,"
     ntdll export that fires when ANY module loads, before its own
     dynamic linking runs, with that module's own base/size) the right
     fix?* Investigated, NOT shipped -- two real, unresolved blockers,
     not a complexity judgment call:
     - Microsoft's own documentation states, verbatim, that it is
       *"unsafe for the notification callback to call functions in ANY
       other module other than itself."* The existing `VirtualProtect`
       wrap this project's own hook-install code already needs (a real,
       previously-reproduced crash proved a pre-existing IAT slot can
       live in a read-only page) calls into KERNEL32 -- a different
       module -- so the existing, already-proven-necessary pattern
       can't be reused here without substituting a raw, undocumented
       `ntdll`-internal syscall path instead, which carries its own,
       separate version-fragility risk Microsoft's own text gives no
       carve-out for either.
     - Both "fires before dynamic linking takes place" is documented,
       but whether an IAT write made *at that moment*, for the module
       the notification is ABOUT, survives that same module's own
       subsequent import-snap pass (which the loader still has to run
       for it) is NOT confirmed by any authoritative source found --
       only that import resolution overall happens "before DllMain," a
       different claim. If the snap pass unconditionally overwrites
       every slot regardless of what's already there (plausible, since
       it walks the import-descriptor table by name with no reason to
       skip an already-populated slot), a patch applied at this timing
       would be silently undone moments later, and the real, duplicate
       load would still happen -- meaning the whole mechanism might
       accomplish nothing while still carrying the cross-module-call
       risk above.

     Settling the second point would need its own dedicated,
     instrumented debugging investigation (a minimal notification-DLL
     fixture, traced live under a debugger) before any production code
     against this mechanism is safe to write -- a real sub-task of its
     own, not attempted. A structurally different alternative (inserting
     a synthetic `LDR_DATA_TABLE_ENTRY` for each embedded dependency so
     the loader's OWN by-name resolution finds and reuses it naturally,
     no per-import patching or notification callback needed at all) was
     also considered and not attempted -- that struct's layout beyond a
     small public partial definition is undocumented and has changed
     across Windows versions, trading this problem for an equally real
     version-compatibility one.

     **Previous state: genuinely unresolved, not merely unimplemented.**
     Treat embedding a Qt6 (or any framework with the same "plugin
     loaded by LoadLibrary, plugin statically imports an embedded
     dependency by name" shape) GUI application as capped at "starts
     without crashing/hanging, embeds everything except what a runtime-
     loaded plugin's own import table needs" until one of the two
     research threads above is actually completed, not just scoped.

     **Update: both open questions from thread 2 above are now settled,
     and the mechanism is implemented and shipping.** A dedicated
     empirical investigation (a throwaway C test harness, 3 consistent
     runs plus register-level confirmation under `cdb`, on a real
     Windows 11 build -- not assumed from documentation) checked both
     blockers directly, concretely, rather than relying on Microsoft's
     own documentation (which doesn't settle either one):
     - `LDR_DLL_NOTIFICATION_REASON_LOADED` fires AFTER the newly-loaded
       module's own import-table snap has ALREADY completed -- confirmed
       directly (a watched module's real IAT slot already held its
       correctly-resolved address at notify time, not a pre-snap
       placeholder). There is no race to design around: by the time the
       callback runs, the module's own import resolution already
       happened the normal way; the hook patches a slot back open
       afterward, never before anything has settled.
     - The watched module's IAT-containing page IS read-only at that
       point (confirmed via `VirtualProtect` returning
       `oldProtect = PAGE_READONLY`), same as the already-known KERNEL32
       IAT case the existing hook above already handles with its own
       `VirtualProtect` wrap -- so the identical wrap/write/restore dance
       is reused here rather than inventing a second mechanism.
     - Calling a REAL KERNEL32 function (`VirtualProtect`) from inside
       the notification callback -- against Microsoft's own documented
       "unsafe to call other modules" guidance -- worked with no
       deadlock and no crash in the real test. **This remains
       unsupported/undocumented behavior**: confirmed empirically on the
       tested build, NOT architecturally guaranteed by Microsoft across
       all future Windows versions. Shipped anyway, with the same honest
       framing this project already uses elsewhere for loader-internals-
       adjacent work that's "verified working on tested platforms, not
       guaranteed" (see the real-system-DLL-`DllMain`-nondeterminism
       entry above).
     - A sentinel write made during the callback, after flipping
       protection, was confirmed to survive untouched after
       `LoadLibraryW` returns (no later re-snap undoes it) -- settling
       thread 2's second open question directly.

     Implemented as `build_windows_ldr_notification_callback`/
     `build_windows_ldr_notification_register` in `pe_stub.py` (see that
     module's own docstring's "Ldr notification hook" section for the
     full mechanism) -- registered via a synthetic ntdll.dll import of
     the real `LdrRegisterDllNotification`, spliced into the generated
     init-call stub the same way as the KERNEL32 hook's own
     `__hook_install__` entry, so registration happens before any
     embedded module's own initializer runs. The callback itself walks
     ANY newly-loaded module's own `IMAGE_IMPORT_DESCRIPTOR`/
     `IMAGE_THUNK_DATA64` arrays (pure memory reads against its own
     newly-mapped image) looking for an import whose owning DLL name
     matches one of this run's embedded dependency names, and on a
     match, patches that already-snapped IAT slot to the embedded
     dependency's own resolved address -- reusing the exact same by-name/
     by-ordinal sub-tables the KERNEL32-level GetProcAddress hook already
     builds, not a second, parallel table.

     Confirmed via a real, dedicated end-to-end fixture
     (`tests/windows/test_pe_hook_runtime.py`'s
     `test_third_party_plugin_statically_importing_embedded_dependency_
     resolves_against_embedded_copy`, synthesizing the exact `qwindows.
     dll` shape -- a `plugin.dll` that is never statically imported by the
     host, loaded dynamically via `LoadLibraryW`, and which itself
     statically imports the embedded `lib.dll` by name): after a real
     `embed()`+run, the function the plugin calls through that static
     import correctly resolves to the EMBEDDED copy, not a fresh,
     separate load.

     **A real methodology correction worth recording explicitly**: the
     "delete the real dependency's file from disk first, so a failed
     redirect fails loudly" proof technique that works for the KERNEL32-
     level hook (`test_loadlibrary_getprocaddress_resolve_against_
     embedded_copy`) does NOT work for this hook, and trying it first is
     what surfaced this -- confirmed concretely, live, with `cdb` and
     loader snaps (`gflags +sls`): deleting the embedded dependency's
     real file before loading the third-party plugin makes the PLUGIN's
     own load fail outright with `ERROR_MOD_NOT_FOUND` (126), regardless
     of whether this hook is working correctly at all. This is a direct,
     unavoidable corollary of the already-confirmed "notification fires
     after the watched module's own import snap already completed"
     finding above: that snap can only complete at all if every one of
     the plugin's own dependencies was already resolvable via a real
     file (or an already-loaded module) -- there is no point at which
     this hook could intervene *before* that resolution happens, only
     after. This is also exactly the real 010 Editor shape: `Qt6Core.
     dll`/`Qt6Gui.dll`'s own files stay on disk even once embedded (see
     the entry above), so the real loader DOES load a real, separate,
     wasteful-but-successful duplicate copy as a side effect of resolving
     `qwindows.dll`'s own import table -- this hook's actual job is to
     redirect calls through that already-resolved IAT slot to the
     embedded copy afterward, not to prevent the duplicate load from
     happening at all. The regression test instead proves this by
     address: the dependency exposes a function returning its OWN
     executing code address (not a thunk, not an IAT slot -- the real
     function body, so a real duplicate copy and the embedded copy
     provably return different values despite running byte-identical
     code), and the host maps that address back to its owning module via
     `GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, ...)`
     and compares it against its own module handle (the embedded copy
     lives inside the host's own image with no separate module boundary
     at all). Confirmed this genuinely discriminates, not merely "returns
     0 either way": running the *unembedded* host directly (no hook
     installed) returns a distinct, non-zero code for this exact
     scenario.

     Known, deliberate scope limits for this specific hook (beyond the
     x64-only scope every mechanism in `pe_stub.py` shares): only
     `LDR_DLL_NOTIFICATION_REASON_LOADED` is handled (`_UNLOADED` is a
     no-op); a loaded module's import descriptor with no
     `OriginalFirstThunk` (no unbound import-name table -- old/rare in
     practice) is skipped entirely, since there is no other way to
     recover by-name/by-ordinal import identity once `FirstThunk` has
     already been snapped to resolved addresses; and an import that
     doesn't match any hooked dependency's own by-name/by-ordinal
     sub-table (including an unresolvable forward) is left completely
     untouched -- no patch at all, not even a NULL write, since unlike
     GetProcAddress's own explicit "not found" contract, there's no way
     to signal failure back to the loader's own already-completed snap.

     **The real-world payoff, and a new, genuinely separate blocker found
     while chasing it**: rebuilding the actual 010 Editor installation
     (`staticer "C:\Program Files\010 Editor\010Editor.exe" -o
     "C:\Program Files\010 Editor\onefile_010editor.exe" --exclude
     kernel32.dll,msvcrt.dll,ntdll.dll,USER32.dll,ole32.dll` -- the exact
     command every earlier entry in this file was building toward) now
     gets *past* the Qt-platform-plugin dialog for the first time ever in
     this project's history (confirmed via loader snaps, `gflags +sls`:
     `qwindows.dll` and `qwindowsvistastyle.dll` both load, resolve their
     own static imports of the real, separate, duplicate `Qt6Core.dll`/
     `Qt6Gui.dll`/`Qt6Widgets.dll` copies, run their own init routines,
     and the process goes on to spawn real worker threads and execute
     real Qt widget code) -- but it still doesn't show the real UI: it
     now crashes with a real `STATUS_ACCESS_VIOLATION` (`c0000005`) a
     little further in, reading from an unmapped address.

     **Root-caused, not just observed -- and confirmed NOT caused by this
     task's own hook.** The crash site (`010Editor+0x37263d1`, inside the
     embedded copy of `Qt6Gui.dll`) is a plain `cmp dword ptr
     [rip+disp32], eax` -- ordinary compiler-generated code, nothing this
     project's generated machine code ever executes or writes to.
     Confirmed by three independent, concrete checks:
     1. A write watchpoint (`ba w8`) on the exact faulting address, set
        before the process ever ran, never fired before the crash -- the
        bad bytes were already wrong in the file on disk, not corrupted
        at runtime by anything (this hook's callback included).
     2. The exact same corrupted bytes exist, at the exact same RVA, in a
        build produced with this task's own `LdrRegisterDllNotification`
        registration call replaced by a no-op (via a direct monkeypatch
        of `build_windows_ldr_notification_register`, everything else in
        `embed()` left untouched) -- i.e. a build using nothing this task
        added. That "no-hook" build never reaches this code path at all
        (it still stops at the Qt-plugin dialog, the same as every
        earlier entry in this file describes), but the bug is already
        baked into its output file regardless.
     3. Directly invoking the pre-existing (unmodified by this task)
        `_patch_dep_tls_access_offsets` against the real `Qt6Gui.dll`
        confirms it: the genuine `_tls_index` load anchor at blob offset
        `0x2393bf` (`mov ecx, [rip+disp32]`, correctly resolving to
        `Qt6Gui.dll`'s own real `_tls_index` RVA) is followed, 18 bytes
        later, by this unrelated `cmp dword ptr [rip+disp32], eax`
        instruction at `0x2393d1` -- and `_try_patch_msvc_style_tls_
        access`'s own forward scan accepts *that* instruction's disp32
        as if it were the TLS-variable-specific offset to shift, for any
        shift value tested. It isn't one; it's an ordinary, unrelated
        global-variable comparison that merely happens to sit close
        enough after a genuine anchor, with a `mov r32, imm32`-shaped
        byte sitting where the scanner's corroboration check (described
        above, under "The host-already-has-TLS merge's byte-pattern
        scanner...") looks for one. Shifting its disp32 by the TLS
        merge's own `shift` value corrupts it into pointing far outside
        the dependency's own image (confirmed: the original, unpatched
        instruction's own disp32 resolves to a real, in-bounds offset
        within `Qt6Gui.dll`'s own data; the corrupted one resolves to
        roughly 2.2x the *entire merged image's* own `SizeOfImage`).

     This is a new, concrete instance of exactly the risk category the
     "near-miss silently misfires" paragraph above already flags as
     open (a real anchor can be found correctly while a *different*,
     unrelated nearby instruction is *also* incorrectly treated as the
     offset-bearing one) -- found in `Qt6Gui.dll` specifically, not
     `SHLWAPI.dll`/`SHELL32.dll` (the two instances already fixed), and
     only reachable at all once the LdrRegisterDllNotification hook let
     `qwindows.dll`'s own `Qt6Gui.dll` import actually finish resolving
     and running its own TLS-merged initializer -- every earlier attempt
     at this real 010 Editor embed stopped (at the Qt-plugin dialog, or
     earlier) before this exact code path ever executed. Fixing the
     scanner's corroboration logic further (so it also rules out this
     specific shape) is real, separate, additional work -- the same kind
     of narrow, compiler-codegen-specific analysis the SHLWAPI/SHELL32
     fix already needed, now against a third real-world binary -- and is
     out of scope for this task (which built and verified the
     LdrRegisterDllNotification mechanism itself, confirmed correct by
     its own dedicated end-to-end fixture); left as a concrete, precisely
     located follow-up rather than something this task should force a
     quick patch past.

     **Current state**: the LdrRegisterDllNotification hook is
     implemented, tested, and confirmed working correctly end-to-end on
     its own synthetic fixture. Against the real 010 Editor binary, it
     measurably moves the needle (past the Qt-plugin-duplication dialog,
     for the first time) but does not yet reach the real UI -- blocked
     by this separate, pre-existing, now precisely located TLS-scanner
     false-positive in `Qt6Gui.dll`, not by anything this task built.

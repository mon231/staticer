# Limitations

- Explicit dynamic-loading from the executed code itself (`dlopen`+`dlsym`
  / `LoadLibraryW`+`GetProcAddress`) is not hooked yet; only dependencies
  resolved through the input's own import/dynamic-section table are
  embedded.
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
- **Fixed, found via the same 010 Editor testing**: the PE embedder had
  no handling at all for `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT` (the
  linker's `/DELAYLOAD` feature) -- a second, independent real crash
  source, unrelated to the TLS scanner bugs above. Left alone, a
  delay-imported function's compiled thunk, on its first actual use,
  calls `ntdll!LdrResolveDelayLoadedAPI` passing the embedded
  dependency's own placement as if it were a real, separately
  `LoadLibrary`'d module's `HMODULE` -- which it isn't (it's just
  appended code/data inside the host's own single image, with no
  corresponding entry in the process's real loaded-module list).
  Confirmed via live single-stepping under a debugger (embedding a real
  `OLEAUT32.dll`, which delay-loads several API-set DLLs for COM
  interop, as part of a real 010 Editor build) that this leads to an
  indirect call through a null pointer a few frames further in, with
  the host crashing with RIP becoming exactly `0`. Checked against every
  dependency a real 010 Editor embed pulls in: 38 of 57 have a
  non-empty delay-import directory, so refusing to embed any dependency
  that has one isn't viable -- nearly every real Windows system DLL uses
  `/DELAYLOAD` for at least a handful of imports. An intermediate fix
  attempt (overwriting every delay-import IAT slot with a tiny stub that
  unconditionally "fails") did stop the crash but broke 010 Editor's own
  startup, which treats one specific forced-failed COM call as fatal and
  exits on its own -- confirmed by comparing against the unmodified
  original `010Editor.exe` (even just renamed/run from a different
  location), which starts normally. Properly fixed instead by folding
  each delay-import module into the very same merged/combined
  ordinary-import mechanism already used for a dependency's own
  *remaining* (non-embedded) ordinary imports: the modern (VS2005+)
  delay-import descriptor format already mirrors an ordinary
  `IMAGE_IMPORT_DESCRIPTOR` almost exactly (`pINT` is the same shape as
  `OriginalFirstThunk`, `pIAT` the same shape as `FirstThunk`), so its
  name-table thunk entries get the same `+X` rebase as an ordinary
  import's and it becomes one more merged descriptor entry. The real
  Windows loader then resolves it like any ordinary import, at process
  load, before any application code runs -- so by the time the
  delay-load thunk's own compiled "already resolved?" fast-path check
  runs, the slot already holds the real function's address, and the
  thunk never calls into the delay-load helper (hence never touches the
  dangerous fake-HMODULE path) at all. No dependency-graph change was
  needed: delay-import targets are never themselves one of this run's
  embedded dependencies (nothing currently walks delay imports when
  discovering the graph), so there's no "target is itself embedded" case
  to handle here, unlike the ordinary-import merge.
- **Found, not yet fixed**: with both TLS-scanner false-positives and
  the delay-import gap above fixed, the full real 010 Editor embed (all
  8 originally-requested dependencies, 57 once transitive imports are
  included, excluding only
  `kernel32.dll,msvcrt.dll,ntdll.dll,USER32.dll,ole32.dll`) no longer
  crashes with an access violation, but still doesn't run cleanly: it
  now terminates a few seconds into startup with exit code `0xC0000417`
  (`STATUS_INVALID_CRUNTIME_PARAMETER`) -- the UCRT's own fatal
  invalid-parameter fast-fail path, not an unhandled SEH exception (it
  generates no Windows Error Reporting / Application-Error event log
  entry at all, consistent with a deliberate `__fastfail`-style
  termination rather than a wild crash). Not yet root-caused: it doesn't
  reproduce reliably while single-stepping under a live debugger (cdb
  sessions covering the relevant ~4-10 second real-time window
  consistently failed to hit it at all, even with breakpoints on
  `ntdll!RtlFailFast`/`RtlFailFast2`/`KERNELBASE!RaiseFailFastException`),
  suggesting it's sensitive to real wall-clock timing (e.g. an
  async/worker-thread race) in a way that a debugger's own overhead
  disturbs. Confirmed real progress nonetheless: an earlier, intermediate
  fix attempt (stubbing out delay imports instead of properly resolving
  them, see above) got only as far as a clean, immediate `exit(-1)`
  before even this point was reached, so properly resolving delay
  imports did fix a real, further startup step (likely COM
  initialization) before this next, distinct issue surfaces. Future work:
  reproduce under a lower-overhead instrumentation approach (e.g. a
  logging `DllMain`/CRT-init shim rather than live single-stepping, per
  this project's own established debug-instrumentation precedent) to
  identify which specific CRT call and parameter trips the fast-fail
  check.

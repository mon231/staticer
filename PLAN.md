# staticer — plan status

Full plan: `docs/superpowers/plans/2026-11-01-staticer-core.md`
Spec: `docs/superpowers/specs/2026-11-01-staticer-design.md`
Ledger: `.superpowers/sdd/2026-11-01-staticer-core/progress.md`

## Tasks

| # | Task | Status |
|---|------|--------|
| 1 | Dependency graph (`common/depgraph.py`) | done — 1 fix round (exclusion cascade bug) |
| 2 | CLI (`staticer.py`, format sniff, dispatch) | done — clean review |
| 3 | PE embedder — PIC/reloc-bearing path | done — 1 fix round (no-reloc guard, MSVC bitness skip) |
| 4 | ELF embedder — PIC/reloc-bearing path | done — review closed, 3 fix rounds; verified passing for real on Linux (WSL) |
| 5 | PE non-PIC / no-reloc base-reservation | done — 1 fix round (filler-range conflict gap) |
| 6 | ELF non-PIC / no-reloc base-reservation | done — 2 fix rounds (reservation-growth gap, doc) |
| 7 | PE unwind preservation + Windows stub | done — approved with flagged risk |
| 8 | ELF unwind preservation + Linux stub | done — 1 fix round (stack-realignment overshoot, verified on real WSL twice) (commits `221784a`, `f274e01`) |
| 9a | Scope/overlap tests — PE (`test_pe_scope.py`) | done — clean review (commit `fcb764a`) |
| 9b | Scope/overlap tests — ELF (`test_elf_scope.py`) | done — clean review (commit `1bfc50b`) |
| 10a | Real-world binaries — PE (cmd.exe/hostname.exe, curated+full-closure) | done — approved, 1 moderate + 1 minor finding, both fixed directly (commits `fefc758`, `6f7e58e`) |
| 10b | Real-world binaries — ELF (bash/grep, curated+full-closure) | done — approved, 1 minor finding fixed directly (commits `49f4045`, `e11d8d1`) |
| 11 | Packaging (drop lief, pefile+pyelftools+firstclass, README) | done — approved, 1 low non-blocking note |
| 12 | CI (GitHub Actions, Windows+Linux matrix) | done |

## Done so far

- Dependency graph with transitive exclusion propagation, cycle detection, topo order.
- CLI arg parsing, format sniffing (PE/ELF), clean error handling.
- PE embedder: real section injection, relocation application, IAT patch, import
  directory rebuild, combined reloc table, entrypoint stub (reloc-bearing/PIC
  dependencies only — commit `77e2042`).
- ELF embedder: blob injection as an in-place extension of the host's own
  highest-vaddr PT_LOAD segment (not a new segment — see fix rounds below),
  RELA/REL relocation application against the new placement, GOT/PLT patch for
  embedded exports, DT_NEEDED neutralization (converted to DT_DEBUG in place),
  combined relocation table (reloc-bearing/PIC dependencies only — commit
  `bf545f5`, fixed in `405de22` and `4a00e2b`). Hand-packs every ELF32/64
  struct it writes since pyelftools is read-only.
  Fix round 1 (review): the first version appended new content as a *new*
  PT_LOAD segment and relocated the program header table into it, which
  breaks AT_PHDR (the kernel derives its skew from the *first* PT_LOAD
  segment only, not per-segment) — silently skips or crashes on
  TLS/RELRO/stack-flag setup. Fixed by never touching e_phoff/e_phnum at all:
  extend the host's own last PT_LOAD segment in place instead. Also fixed a
  signed-pack overflow for 32-bit addresses >= 2^31 in the new combined
  relocation table, and corrected a doc comment about init_array argument
  passing. Added `tests/fixtures/main_tls.c` + a TLS regression test
  (`483fa92`) that the trivial `lib.c`/`main.c` fixtures can't exercise.
  Fix round 2 (real Linux verification, WSL Ubuntu + gcc 15.2.0): actually
  building and running the fixtures found 3 more real bugs no amount of
  reasoning-only review caught — (a) `conftest.py`'s compiler picker
  preferred an installed mingw-w64 cross-compiler over native gcc even on
  Linux, silently producing PE binaries instead of ELF (`e8fb00a`); (b) every
  real GCC-built `.so` links in crtstuff's weak undefined GOT references
  (`__cxa_finalize` etc.), which `embed()` wrongly rejected as an unsupported
  external dependency — fixed to zero+skip them, matching ld.so's own "weak
  symbol not found → NULL" behavior; (c) the generated init-call stub (built
  whenever a dependency has a `DT_INIT`/`DT_INIT_ARRAY` entry — again,
  unconditional crtstuff boilerplate, not just real constructors) reliably
  segfaulted on x86-32 (crtstuff's `frame_dummy`/`register_tm_clones` need
  their own GOT-base setup convention the stub's naive `call` didn't
  establish) — removed the stub mechanism entirely rather than ship
  known-unsafe code; the brief's own instructions for this method never
  actually required a stub (unlike Task 3's PE brief), so this is a real
  capability gap left for Task 8, not a regression. Both (b) and (c) in
  `4a00e2b`. All 8 ELF tests now pass for real on Linux, 32- and 64-bit.
  Fix round 3 (review, confirmed by rebuilding fixtures with the real
  toolchain): new content's placement was derived only from the host's
  extended segment rounding its own p_memsz up to a page boundary,
  silently assuming that slack always covers whatever ordinary trailing
  non-segment-covered content the binary has (.comment/.symtab/.strtab/
  .shstrtab/the section header table -- present on any unstripped
  binary). This suite's own 64-bit fixtures cleared the guard by only
  ~240 bytes out of ~4096 of slack with no extra flags; adding plain
  `-g` debug info flipped it negative, spuriously raising "would
  overlap existing file content" on a completely ordinary binary — a
  real Task 10 risk, not an edge case. Fixed by taking
  max(segment's own rounded memsz end, actual EOF + skew) before the
  final page rounding (`4085898`). Added
  `test_embed_handles_trailing_debug_info` (built with `-g`,
  `5c44506`); confirmed on WSL both that it fails without the fix
  (exact "would overlap" error, 64-bit) and passes with it, alongside
  the rest of the suite.
- `firstclass` adopted for `DependencyNode` per explicit direction (pure Python,
  confirmed no compiled backend).
- `docs/firstclass-feedback.md` — upstream suggestions for the library.
- PE base-address reservation (Task 5): dependencies with zero relocation data
  are placed at their declared `ImageBase`, with a zero-file-backed filler
  section bridging any RVA gap to the host's existing sections, and
  `DYNAMIC_BASE`/`HIGH_ENTROPY_VA` cleared in the output's `DllCharacteristics`
  since embedding any fixed-base dependency makes the whole image effectively
  non-ASLR-safe. Conflict detection covers host-vs-dependency,
  dependency-vs-dependency, AND (after a fix round) dependency-vs-filler-range
  overlaps — all fail loudly with `ValueError`. Commits `309ef51`, `9f5d5ec`.
- ELF base-address reservation (Task 6): a dependency is detected as
  fixed-base via `e_type == ET_EXEC` (not "empty .rela", which is ambiguous
  for ELF per Task 4's own docstring — a fully-PIC `.so` can legitimately have
  no self-relocations). Reserved against the host's original PT_LOAD ranges,
  other fixed-base dependencies, AND (after a fix round) the host's extended
  segment's final grown extent. Commits `ced376f`, `5fc9143`, `62b5f1a`.
  Found and fixed 2 more real bugs via live WSL execution: a stale AT_PHDR
  doc claim (corrected across all 4 instances in the file after 2 rounds),
  and confirmed — but explicitly left unfixed as pre-existing/out-of-scope —
  a Task 4 GOT/PLT-patch bug that surfaces for ordinary PIC dependencies on
  non-PIE hosts (`"unexpected PLT reloc type"`), flagged for whoever next
  touches that code path since base-reservation is only sound on a non-PIE
  host in the first place.

## Known problems / open concerns

- Task 3 scoped its tests to `lib_dir=tmp_path` instead of brief's
  `lib_dir=None`, to avoid pulling the full Windows system-DLL closure (that's
  Task 10's job, needs Tasks 5-8 first). Reviewed, approved as a sound call.
- Task 3 stub is flat/unconditional: no LoadLibrary/dlopen hooking yet, only
  HIGHLOW/DIR64 reloc types, no ordinal imports. Deferred to Task 7+.
- Task 12's CI yaml itself is approved but unverified on a real GitHub
  runner (no access from this session) — first real CI run may surface
  issues the local pytest pass can't catch.
- Parked (Task 1 review): cycle-case `is_excluded` staleness in parent DFS
  frames — low risk, `embed_order` independently raises on any cycle.
- Task 4 has now been verified for real on Linux (WSL Ubuntu, gcc 15.2.0,
  both 32- and 64-bit) — all 5 tests (`test_embed_pic_so_into_exe`,
  `test_embedded_output_no_longer_needs_embedded_so`,
  `test_architecture_mismatch_fails_loudly`,
  `test_embedded_output_preserves_host_tls`,
  `test_embed_handles_trailing_debug_info`) pass for real, not just
  collect+skip. This surfaced and fixed 4 bugs reasoning-only review hadn't
  caught (see "Done so far" above) — most notably that the generated
  init-call stub, which looked correct and well-reasoned on paper, reliably
  segfaulted, and that the segment-extension placement logic silently relied
  on a page-rounding-slack coincidence that a plain `-g` build broke. Not
  yet verified: anything beyond this task's own 2-fixture scope
  (`lib.c`/`main.c`/`main_tls.c`) — e.g. a dependency with a *real*
  (non-crtstuff) global constructor, multi-dependency chains, or a host with
  an unusual segment layout (the "highest-vaddr PT_LOAD segment is also last
  in the file" assumption) are all still reasoning-only. Task 12's CI matrix
  will extend coverage once it runs for real.
- Task 4 deliberately diverges from Task 3's "dependency has no relocation
  data -> fail loudly" guard (that PE-specific signal of non-PIC doesn't carry
  over to ELF — see `elf_embedder.py`'s `embed()` docstring) and doesn't merge
  a dependency's own further external imports into the host (out of this
  task's scope per the brief; such dependencies fail loudly instead). Both are
  explicit, documented scope calls, not oversights — flagging for review.

- **Flagged by user for a future task**: a `_tls_index` problem (PE TLS directory
  handling — likely relevant wherever a dependency or host uses
  `__declspec(thread)`/`_tls_index`-based thread-local storage, intersecting
  with Task 7's stub/entrypoint work or Task 10's real-binary embedding).
  Not yet investigated — revisit when Task 7 or Task 10 touches TLS-bearing
  binaries.

- **B5 (fixed, Track B)**: `elf_embedder.py`'s host GOT/PLT patch loop
  zeroed a resolved R_*_JUMP_SLOT entry to R_*_NONE unconditionally,
  aborting any host built with lazy (non-BIND_NOW) PLT binding -- the
  ABI default, and most real-world ELF binaries, though this project's
  own toolchain/distro defaults to `-z now`, which is why this stayed
  hidden through Tasks 4/6/10b. First flagged in Task 6's own review as
  "worth a look for whichever task next touches that patch loop", then
  missed by Task 10b when it touched this exact code for COPY-relocation
  handling. Fixed in the final-review fix wave (see ledger) by detecting
  the host's own binding mode and leaving a lazy-bound host's PLT entries
  untouched instead.
- **ELF COPY-relocated objects larger than pointer-size (known
  architectural limitation, Track B)**: when a host's R_*_COPY
  relocation copies a struct bigger than one pointer (e.g. one with its
  own interior pointer field, not just scalar data) from an embedded
  dependency, only the *whole* copied value gets a new R_*_RELATIVE
  ASLR-safety entry, and only when its size is exactly one pointer
  width. A >ptr_size COPY-relocated object's own interior pointer
  field(s) get no such entry at all, even if they point into the
  dependency's own embedded blob -- those would go stale under ASLR.
  Not fixed: ELF carries no type/layout metadata for a COPY-relocated
  symbol (just `st_size`, a byte count), so there's no way to tell,
  from the raw bytes alone, which sub-offsets of a >ptr_size object are
  even pointers at all without DWARF type info this module doesn't use
  anywhere else. None of this project's own fixtures or the real system
  binaries (bash/libtinfo.so.6) exercised in Task 10b hit this (every
  real COPY-relocated symbol seen so far is pointer-sized or smaller).
- **Final whole-branch review fix wave (2026-11-02 — 2026-11-04): COMPLETE.**
  A final whole-branch reviewer (most capable model) found B1-B6 blocking
  issues plus several moderate/minor findings. Fixed in parallel across 3
  tracks (PE, ELF, packaging/CLI/docs/CI), each independently reviewed and
  approved (Track A: approved; Track B: approved with flagged risk — risk is
  about review METHOD, no Linux execution access in the reviewer's own
  sandbox, not an unresolved code concern; Track C: approved). One finding
  (dependency-name path-traversal hardening, CWE-22) was dropped from both
  track dispatches by mistake — caught and fixed separately afterward,
  reviewed, approved. Full detail lives in the ledger
  (`.superpowers/sdd/2026-11-01-staticer-core/progress.md`).
  Remaining known, honestly-documented limitations (not blocking, see ledger
  for full list): PE arch whitelist, PE no-reloc placement-order deviation,
  unbounded-allocation check, output==input traceback (all deferred from
  Track A); B5's narrow R_GLOB_DAT/R_IRELATIVE-under-lazy-binding gap inside
  JMPREL (never seen in any real binary this project encountered); ELF
  COPY-relocated objects >pointer-size get no RELATIVE entries for interior
  pointers (architectural limit, documented); MSVC half of Task 7's original
  self-contained-throw finding not re-tested after B4 (GCC/MinGW half
  confirmed fixed, MSVC half unconfirmed either way).
- A GitHub Actions PyPI publish workflow was added (`.github/workflows/publish.yml`,
  adapted from the `firstclass` project's own release workflow), triggered on
  `v*` tags. Needs a `PYPI_API_TOKEN` repo secret before a real publish can
  run; not yet exercised end-to-end (no tag pushed).

## What's next

**All 12 tasks complete, all final-review findings resolved or documented.**
Remaining per `subagent-driven-development`'s closing steps:
- Collect every `Ruling:` line from the ledger into a final summary for the user.
- Delete this plan's SDD workspace directory.
- Hand off to `finishing-a-development-branch`.
- Proceed to `superpowers:finishing-a-development-branch`.

Note: `origin/dev` was pushed mid-session at the user's explicit request
while Task 8's fix round was still in progress (commit `8715cd1`, flagged
WIP in its own message) — superseded by the completed fix (`f274e01`).
Current branch has diverged further since (Tasks 9b/10b + fix-round
commits) and has NOT been re-pushed yet.
- CI/CD done (Task 12): GitHub Actions Windows+Linux matrix, MSVC via
  ilammy/msvc-dev-cmd, builds C test fixtures with system compiler at
  test-setup time, runs pytest. `pefile`/`pyelftools` now declared as real
  install requirements (added ahead of Task 11, same precedent as `firstclass`).

## Commit discipline

Small, single-purpose commits per implementer, no amending, no push until
asked. Current HEAD: see `git log -1` (this SHA goes stale immediately
otherwise; as of the final-review fix wave starting, HEAD was `26e2294`).

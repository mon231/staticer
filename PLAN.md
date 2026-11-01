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
| 4 | ELF embedder — PIC/reloc-bearing path | done — untested on real Linux (dev box is Windows; see concerns) |
| 5 | PE non-PIC / no-reloc base-reservation | not started |
| 6 | ELF non-PIC / no-reloc base-reservation | not started |
| 7 | PE unwind preservation + Windows stub | not started |
| 8 | ELF unwind preservation + Linux stub | not started |
| 9 | Scope/overlap end-to-end tests | not started |
| 10 | Real-world system binaries (cmd.exe/notepad, bash/ls) | not started |
| 11 | Packaging (drop lief, pefile+pyelftools+firstclass, README) | not started |
| 12 | CI (GitHub Actions, Windows+Linux matrix) | done |

## Done so far

- Dependency graph with transitive exclusion propagation, cycle detection, topo order.
- CLI arg parsing, format sniffing (PE/ELF), clean error handling.
- PE embedder: real section injection, relocation application, IAT patch, import
  directory rebuild, combined reloc table, entrypoint stub (reloc-bearing/PIC
  dependencies only — commit `77e2042`).
- ELF embedder: PT_LOAD blob injection, RELA/REL relocation application against
  the new placement, GOT/PLT patch for embedded exports, DT_NEEDED neutralization
  (converted to DT_DEBUG in place), combined relocation table, DT_INIT/
  DT_INIT_ARRAY-driven init-call stub, new PT_LOAD segment that also carries the
  relocated program header table (reloc-bearing/PIC dependencies only — commit
  `bf545f5`). Hand-packs every ELF32/64 struct it writes since pyelftools is
  read-only.
- `firstclass` adopted for `DependencyNode` per explicit direction (pure Python,
  confirmed no compiled backend).
- `docs/firstclass-feedback.md` — upstream suggestions for the library.

## Known problems / open concerns

- Task 3 scoped its tests to `lib_dir=tmp_path` instead of brief's
  `lib_dir=None`, to avoid pulling the full Windows system-DLL closure (that's
  Task 10's job, needs Tasks 5-8 first). Reviewed, approved as a sound call.
- Task 3 stub is flat/unconditional: no LoadLibrary/dlopen hooking yet, only
  HIGHLOW/DIR64 reloc types, no ordinal imports. Deferred to Task 7+.
- `setup.py` still lists `lief` pending removal (Task 11).
- Task 12's CI yaml itself is approved but unverified on a real GitHub
  runner (no access from this session) — first real CI run may surface
  issues the local pytest pass can't catch.
- Parked (Task 1 review): cycle-case `is_excluded` staleness in parent DFS
  frames — low risk, `embed_order` independently raises on any cycle.
- **Task 4 is entirely unexercised against a real compiler/runtime**: this dev
  box is Windows, so `tests/linux/test_elf_embed.py` only ever collects+skips
  (platform skip, never even reaches the `c_compiler` fixture). The
  implementation is reasoned from pyelftools' source + ELF spec semantics and
  checked with standalone unit assertions on the hand-written struct-packing
  helpers (Phdr/Ehdr-field/relocation-entry packing), but the actual embed+run
  path (GOT/PLT patch correctness, the new PT_LOAD segment's AT_PHDR-safety,
  the generated stub) needs a real Linux CI run (Task 12's matrix) before it
  can be trusted. First real run may need a fix round.
- Task 4 deliberately diverges from Task 3's "dependency has no relocation
  data -> fail loudly" guard (that PE-specific signal of non-PIC doesn't carry
  over to ELF — see `elf_embedder.py`'s `embed()` docstring) and doesn't merge
  a dependency's own further external imports into the host (out of this
  task's scope per the brief; such dependencies fail loudly instead). Both are
  explicit, documented scope calls, not oversights — flagging for review.

## What's next

- Task 4 (ELF PIC path) done, pending review — see open concerns re: real-Linux
  verification.
- Tasks 5-8 (non-PIC + unwind) depend on 3/4 being settled first (same files) —
  now unblocked for both sides, pending Task 4's review.
- Task 9-11 sequential after 5-8.
- CI/CD done (Task 12): GitHub Actions Windows+Linux matrix, MSVC via
  ilammy/msvc-dev-cmd, builds C test fixtures with system compiler at
  test-setup time, runs pytest. `pefile`/`pyelftools` now declared as real
  install requirements (added ahead of Task 11, same precedent as `firstclass`).

## Commit discipline

Small, single-purpose commits per implementer, no amending, no push until
asked. Current HEAD: `bf545f5`.

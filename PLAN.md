# staticer — plan status

Full plan: `docs/superpowers/plans/2026-11-01-staticer-core.md`
Spec: `docs/superpowers/specs/2026-11-01-staticer-design.md`
Ledger: `.superpowers/sdd/2026-11-01-staticer-core/progress.md`

## Tasks

| # | Task | Status |
|---|------|--------|
| 1 | Dependency graph (`common/depgraph.py`) | done — 1 fix round (exclusion cascade bug) |
| 2 | CLI (`staticer.py`, format sniff, dispatch) | done — clean review |
| 3 | PE embedder — PIC/reloc-bearing path | review in progress |
| 4 | ELF embedder — PIC/reloc-bearing path | not started |
| 5 | PE non-PIC / no-reloc base-reservation | not started |
| 6 | ELF non-PIC / no-reloc base-reservation | not started |
| 7 | PE unwind preservation + Windows stub | not started |
| 8 | ELF unwind preservation + Linux stub | not started |
| 9 | Scope/overlap end-to-end tests | not started |
| 10 | Real-world system binaries (cmd.exe/notepad, bash/ls) | not started |
| 11 | Packaging (drop lief, pefile+pyelftools+firstclass, README) | not started |
| 12 | CI (GitHub Actions, Windows+Linux matrix) | not started |

## Done so far

- Dependency graph with transitive exclusion propagation, cycle detection, topo order.
- CLI arg parsing, format sniffing (PE/ELF), clean error handling.
- PE embedder: real section injection, relocation application, IAT patch, import
  directory rebuild, combined reloc table, entrypoint stub (reloc-bearing/PIC
  dependencies only — commit `77e2042`).
- `firstclass` adopted for `DependencyNode` per explicit direction (pure Python,
  confirmed no compiled backend).
- `docs/firstclass-feedback.md` — upstream suggestions for the library.

## Known problems / open concerns

- Task 3 implementer scoped its tests to `lib_dir=tmp_path` instead of brief's
  `lib_dir=None`, to avoid pulling the full Windows system-DLL closure (that's
  Task 10's job, needs Tasks 5-8 first). Under review now.
- Task 3 stub is flat/unconditional: no LoadLibrary/dlopen hooking yet, only
  HIGHLOW/DIR64 reloc types, no ordinal imports. Deferred to Task 7+.
- `pefile` not yet declared in `requirements.txt`/`setup.py` (Task 11).
- `setup.py` still lists `lief` pending removal (Task 11).
- Parked (Task 1 review): cycle-case `is_excluded` staleness in parent DFS
  frames — low risk, `embed_order` independently raises on any cycle.

## What's next

- Finish Task 3 review (in progress) → fix loop if needed → ledger.
- Task 4 (ELF PIC path) — mirrors Task 3, file-disjoint from it.
- Tasks 5-8 (non-PIC + unwind) depend on 3/4 being settled first (same files).
- Task 12 (CI yaml) is file-disjoint from all embedder work — candidate to run
  in parallel with Task 4 once dispatched.
- CI/CD: GitHub Actions Windows+Linux matrix, builds C test fixtures with
  system compiler at test-setup time, runs pytest. Not started yet (Task 12).

## Commit discipline

Small, single-purpose commits per implementer, no amending, no push until
asked. Current HEAD: `77e2042`.

"""End-to-end tests embedding REAL Windows system binaries (not the small
synthetic ``tests/fixtures`` ones) via ``PortableExecutableEmbedder``, then
actually running the resulting output and asserting on its behavior.

Two binaries, two shapes each:
  * ``cmd.exe``, whose only *resolvable* import is ``ntdll.dll`` (every
    other import it declares is an ``api-ms-win-*`` virtual "API set"
    name -- not a physical file anywhere on disk, resolved by the loader
    at runtime via API Set redirection rather than ``resolve_pe``'s plain
    filesystem scan -- so it's simply never a candidate for embedding at
    all, curated-subset or full-closure alike).
  * ``hostname.exe``, which (via WS2_32.dll/MSWSOCK.dll) has a real,
    multi-DLL resolvable closure -- used here for the "second real
    binary" curated-subset case (embedding WS2_32.dll alone, verified
    working) and, deliberately, to document a genuine discovered gap in
    the full-closure case (see ``test_second_real_binary_full_closure``'s
    xfail).

Real-binary bugs found and fixed in ``staticer/pe_embedder.py`` while
writing these tests (see its own module/inline comments for the full
mechanism):
  * Forwarded exports (pefile's ``sym.forwarder``) were resolved as if
    ``sym.address`` were a callable address -- it's actually just the RVA
    of the forwarder string. Real system DLLs use forwarding heavily
    (e.g. KERNEL32.dll forwards ~200 exports to KERNELBASE.dll); this
    silently produced a bogus call target. Fixed by resolving each
    dependency's raw export table (plain VA, or a pending forward
    marker) and chasing forward chains -- including self-forwards, e.g.
    RPCRT4.dll forwarding one of its own exports back to another of its
    own exports -- in a dedicated resolver.
  * Ordinal-only imports (``imp.import_by_ordinal``) raised unconditionally
    ("not supported"); real system import tables use these (e.g.
    WS2_32.dll's ``WSAStartup`` is imported by ordinal from some real
    binaries). Fixed by resolving against the dependency's export table
    by ordinal, not just by name.
  * A forwarded export's target DLL, and the DLL that forwards to it, can
    have a genuine *import* cycle between them with no valid single
    topological order (observed for real: WS2_32.dll forwards
    ``ProcessSocketNotifications`` to MSWSOCK.dll, while MSWSOCK.dll's
    own import table imports WS2_32.dll back) -- fixed by deferring all
    host-IAT-patch resolution to a finalize pass run after every
    dependency has been placed, rather than resolving inline during the
    dependencies-first embed loop.

Known, NOT fixed, open gap -- see ``test_second_real_binary_full_closure``:
embedding hostname.exe's full resolvable closure pulls in KERNELBASE.dll,
which carries its own non-empty TLS directory (a real
``__declspec(thread)`` variable) -- PortableExecutableEmbedder.embed() now
refuses this loudly (ValueError, see the PE-track final-review fix wave's
B3 item) rather than silently embedding it incorrectly.

UPDATE (final-review fix wave, Track A): this xfail's reason text used to
attribute the failure to manually invoking a real system DLL's own DllMain
out of band (msvcrt.dll specifically). That was this test's *symptom* at
the time, not its root cause -- re-run against the fixed embedder (after
B1's dependency-to-dependency-import fix and B3's TLS guard both landed),
the *actual* blocker surfacing first is KERNELBASE.dll's TLS directory
(confirmed by real execution: embed() now raises ValueError naming
KERNELBASE.dll before the stub/DllMain-invocation code path is ever
reached). It's left xfail (same bottom line: full-closure embedding of
this real system binary doesn't work yet) but for a different, now
correctly-attributed reason -- TLS-directory merging is real future work
(B3's docstring in pe_embedder.py), not stub/entrypoint work. Whether the
DllMain-out-of-band concern is *also* real for some other real binary
without a TLS-carrying dependency is still an open question this fix wave
didn't need to resolve, since this particular xfail no longer reaches that
code path at all.
"""

import os
import platform
import subprocess
from pathlib import Path
from typing import Set

import pytest

from staticer.pe_embedder import PortableExecutableEmbedder, list_pe_imports

pytestmark = [
    pytest.mark.skipif(platform.system() != "Windows", reason="PE embedding is Windows-only"),
    pytest.mark.slow,
]


def _system32() -> Path:
    return Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32"


def _require_readable_system32_file(name: str) -> Path:
    """Returns System32/`name`, skipping cleanly if it can't be read/copied
    (reading System32 for copying doesn't normally need elevation, but skip
    rather than fail if some locked-down environment denies it)."""
    path = _system32() / name
    if not path.is_file():
        pytest.skip(f"{path} not present on this system")
    try:
        path.read_bytes()
    except OSError as exc:
        pytest.skip(f"cannot read {path}: {exc}")
    return path


def _curated_lib_dir(tmp_path: Path, keep_dll: str) -> Path:
    """A lib_dir containing only a copy of `keep_dll` (from the real
    System32), for the "embed exactly one real dependency" shape."""
    import shutil

    libdir = tmp_path / "curated_libs"
    libdir.mkdir()
    src = _require_readable_system32_file(keep_dll)
    shutil.copy(src, libdir / keep_dll)
    return libdir


def _exclude_all_but(host: Path, keep: str) -> Set[str]:
    return {n for n in list_pe_imports(host) if n.lower() != keep.lower()}


def test_cmd_exe_curated_subset(tmp_path):
    cmd = _require_readable_system32_file("cmd.exe")
    lib_dir = _curated_lib_dir(tmp_path, "ntdll.dll")
    exclude = _exclude_all_but(cmd, "ntdll.dll")
    out = tmp_path / "cmd_static.exe"

    PortableExecutableEmbedder(cmd, out, exclude=exclude, lib_dir=lib_dir).embed()

    assert "ntdll.dll" not in list_pe_imports(out)

    result = subprocess.run([str(out), "/c", "echo hello"], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0
    assert result.stdout.strip() == "hello"


def test_cmd_exe_full_closure(tmp_path):
    cmd = _require_readable_system32_file("cmd.exe")
    out = tmp_path / "cmd_static_full.exe"

    # lib_dir=None makes every resolvable import a candidate; in practice
    # cmd.exe's only *resolvable* import is ntdll.dll (every other import
    # it declares is a virtual api-ms-win-* "API set" name with no
    # physical file on disk -- see this module's docstring), so this
    # exercises the lib_dir=None/no-exclude code path distinctly from the
    # curated test above while still only ever embedding ntdll.dll.
    PortableExecutableEmbedder(cmd, out, exclude=set(), lib_dir=None).embed()

    assert "ntdll.dll" not in list_pe_imports(out)

    result = subprocess.run([str(out), "/c", "echo hello"], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0
    assert result.stdout.strip() == "hello"


def test_second_real_binary_curated_subset(tmp_path):
    """hostname.exe with exactly one real dependency (WS2_32.dll, which has
    its own real entry point/DllMain, a forwarded export to MSWSOCK.dll
    that isn't actually called here, and ordinal-only imports from the
    host -- a genuinely different shape than cmd.exe/ntdll.dll's zero-entry-
    point, zero-forwarder case above) statically embedded; everything else
    (msvcrt.dll, MSWSOCK.dll, every api-ms-win-* name) stays an ordinary,
    normally-resolved dynamic import."""
    host = _require_readable_system32_file("hostname.exe")
    lib_dir = _curated_lib_dir(tmp_path, "WS2_32.dll")
    exclude = _exclude_all_but(host, "WS2_32.dll")
    out = tmp_path / "hostname_static.exe"

    PortableExecutableEmbedder(host, out, exclude=exclude, lib_dir=lib_dir).embed()

    assert "WS2_32.dll" not in list_pe_imports(out)

    result = subprocess.run([str(out)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0
    # hostname.exe prints the machine's own (non-empty) NetBIOS hostname.
    assert result.stdout.strip() != ""


@pytest.mark.xfail(
    reason=(
        "Real, discovered gap (not papered over -- see this module's "
        "docstring's UPDATE note): embedding hostname.exe's full "
        "resolvable closure pulls in KERNELBASE.dll, which carries its "
        "own TLS directory (a real __declspec(thread) variable) -- "
        "embed() now correctly refuses this with a loud ValueError (the "
        "PE-track final review's B3 fix) rather than silently embedding "
        "it wrong. TLS-directory merging (a new shared _tls_index slot, "
        "relocating TLS-relative references) is real future work, not "
        "yet implemented, so this stays xfail -- but for this reason now, "
        "not the previously-documented DllMain-out-of-band-invocation "
        "theory, which this test no longer even reaches."
    ),
    strict=True,
)
def test_second_real_binary_full_closure(tmp_path):
    host = _require_readable_system32_file("hostname.exe")
    out = tmp_path / "hostname_static_full.exe"

    PortableExecutableEmbedder(host, out, exclude=set(), lib_dir=None).embed()

    result = subprocess.run([str(out)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0
    assert result.stdout.strip() != ""

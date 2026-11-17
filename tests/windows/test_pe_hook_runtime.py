"""End-to-end regression test for the runtime LoadLibraryW/LoadLibraryA/
GetProcAddress hook (see ``staticer/stubs/windows/pe_stub.py``'s module
docstring's "Hook mechanism" section, and ``build_windows_hook_install``/
``build_windows_loadlibrary_trampoline``/``build_windows_getprocaddress_
trampoline``).

Unlike ``test_pe_hook_trampolines.py`` (direct execution of the generated
machine code in isolation), this exercises the *whole* mechanism through
a real ``embed()`` run and a real, separately launched process: the host
(``main_loadlibrary.c``) never statically imports the dependency DLL at
all -- it calls ``LoadLibraryW``/``LoadLibraryA``/``GetProcAddress`` on it
by name at runtime, exactly the way a plugin loader (e.g. Qt's
``QPluginLoader``) does, entirely outside static import analysis. After
embedding, the dependency's own file is deleted from disk before the
embedded output is ever run -- a *real*, unhooked ``LoadLibraryW`` would
then fail with ``ERROR_MODULE_NOT_FOUND``, so the host process succeeding
anyway is unambiguous proof the hook resolved the call against the
embedded copy, not a fresh load from disk.
"""

import platform
import subprocess

import pytest

from conftest import FIXTURES, build_exe, build_shared_lib

from staticer.pe_embedder import PortableExecutableEmbedder, list_pe_imports

pytestmark = pytest.mark.skipif(platform.system() != "Windows", reason="PE embedding is Windows-only")


def test_loadlibrary_getprocaddress_resolve_against_embedded_copy(tmp_path):
    dll = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.dll", pic=True, bits=64)
    exe = build_exe(tmp_path, FIXTURES / "main_loadlibrary.c", "main.exe", [dll], pic=True, bits=64)
    out = tmp_path / "static.exe"

    # The host statically imports lib.dll (see main_loadlibrary.c's own
    # comment on why -- embed() has no "force embed this" mechanism, so
    # this is what makes it an embedded dependency, and so a hookable
    # name, in the first place).
    assert "lib.dll" in list_pe_imports(exe)

    PortableExecutableEmbedder(exe, out, exclude=set(), lib_dir=tmp_path).embed()

    # That static import is gone from the final output -- confirms the
    # dependency really was embedded (patched directly, not left as a
    # live import), not merely present on disk for the runtime
    # LoadLibraryW/GetProcAddress calls below to coincidentally find.
    assert "lib.dll" not in list_pe_imports(out)

    # The unambiguous proof: delete the real dependency from disk. A
    # real, unhooked LoadLibraryW("lib.dll") would now fail outright.
    dll.unlink()

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 0, (
        f"expected the hook to resolve LoadLibraryW/LoadLibraryA/GetProcAddress "
        f"against the embedded copy (real lib.dll was deleted from disk before "
        f"running), got exit code {result.returncode}, stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )


def test_loadlibrary_hook_falls_through_for_non_embedded_names(tmp_path):
    """A sibling check for the "no match -> real LoadLibrary/
    GetProcAddress still work" half of the contract: with an embedded
    dependency present (so the hook is genuinely installed), resolving
    KERNEL32.dll's own `GetCurrentProcessId` via LoadLibraryW +
    GetProcAddress (neither of which match any embedded dependency's own
    name/base) must return the exact same, real, callable function a
    normal compiled call reaches -- see main_loadlibrary_fallthrough.c's
    own comment for why this is a real, independently-checkable
    correctness proof rather than merely "didn't crash"."""
    dll = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.dll", pic=True, bits=64)
    exe = build_exe(tmp_path, FIXTURES / "main_loadlibrary_fallthrough.c", "main.exe", [dll], pic=True, bits=64)
    out = tmp_path / "static.exe"

    PortableExecutableEmbedder(exe, out, exclude=set(), lib_dir=tmp_path).embed()

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 0, (
        f"expected the hook's fallthrough path to behave exactly like the real "
        f"LoadLibraryW/LoadLibraryA/GetProcAddress APIs for a non-embedded name, "
        f"got exit code {result.returncode}, stdout={result.stdout!r} stderr={result.stderr!r}"
    )

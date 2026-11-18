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


def test_third_party_plugin_statically_importing_embedded_dependency_resolves_against_embedded_copy(tmp_path):
    """Regression test for the LdrRegisterDllNotification-based hook (see
    ``staticer/stubs/windows/pe_stub.py``'s ``build_windows_ldr_
    notification_callback``/``build_windows_ldr_notification_register``,
    and ``docs/limitations.md``) -- the real-world shape being 010
    Editor's own Qt platform plugin, ``qwindows.dll``, which the
    KERNEL32-level LoadLibraryW/LoadLibraryA/GetProcAddress hook above
    does NOT fix (it only intercepts explicit, application-level
    LoadLibrary*/GetProcAddress calls, not the OS loader's own internal
    import-table resolution of a dynamically-loaded module's own static
    imports).

    ``plugin.dll`` (synthesized small, exactly ``qwindows.dll``-shaped):
    never statically imported by the host, so embed() never embeds it --
    it stays a real, genuinely-still-on-disk DLL, loaded dynamically by
    the host via an explicit LoadLibraryW call (which the KERNEL32-level
    hook correctly lets through to a real load, since ``plugin.dll``
    itself isn't embedded). ``plugin.dll`` ITSELF statically imports
    ``lib.dll`` by name -- the dependency this run embeds.

    Deliberately does NOT delete the real lib.dll from disk first (unlike
    ``test_loadlibrary_getprocaddress_resolve_against_embedded_copy``
    above) -- confirmed concretely, by first trying exactly that, that it
    doesn't test what it looks like it tests here: by the time
    `LDR_DLL_NOTIFICATION_REASON_LOADED` fires for `plugin.dll`, the real
    loader has ALREADY had to recursively, really resolve `plugin.dll`'s
    own static dependency on `lib.dll` via the real filesystem (deleting
    `lib.dll` first makes `LoadLibraryW("plugin.dll")` itself fail with
    `ERROR_MOD_NOT_FOUND`/126 regardless of whether this hook works at
    all -- confirmed live with `cdb`/loader snaps -- since the
    notification simply never gets a chance to fire for a module whose
    own dependencies couldn't be resolved in the first place). This is
    exactly the real 010 Editor shape too: `Qt6Core.dll`/`Qt6Gui.dll`'s
    own files stay on disk even once embedded (see
    ``docs/limitations.md``), so the real loader DOES load a real,
    separate, wasteful-but-successful duplicate copy as a side effect of
    resolving `qwindows.dll`'s own import table -- this hook's actual job
    is to redirect `plugin.dll`'s own *calls* through that
    already-resolved IAT slot to the embedded copy afterward, not to
    prevent the duplicate load from happening at all.

    So the real proof is address-based: `plugin_get_lib_address()`
    returns the real address of the `lib.dll` code that actually ran
    (`lib_value_self_address()` -- the function body itself, not a thunk
    or an IAT slot, so both the embedded and a real duplicate copy would
    return a genuinely different value here, unlike plain `lib_value()`,
    which returns the same `42` either way since both copies run
    byte-identical code). ``main_plugin_loader.c`` maps that address back
    to its owning module via `GetModuleHandleExW`
    (`GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS`) and compares it against its
    own module handle -- the embedded copy lives INSIDE the host's own
    image with no separate module boundary at all, unlike a real
    duplicate. Confirmed this actually discriminates (not just "returns
    0 either way"): running the *unembedded* host directly (no hook
    installed at all) returns a distinct, non-zero code (5) for this
    exact reason -- the duplicate-copy gap this hook exists to fix.
    """
    dll = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.dll", pic=True, bits=64)
    plugin = build_shared_lib(tmp_path, FIXTURES / "plugin.c", "plugin.dll", pic=True, bits=64, libs=[dll])
    exe = build_exe(tmp_path, FIXTURES / "main_plugin_loader.c", "main.exe", [dll], pic=True, bits=64)
    out = tmp_path / "static.exe"

    assert "lib.dll" in list_pe_imports(exe)

    PortableExecutableEmbedder(exe, out, exclude=set(), lib_dir=tmp_path).embed()

    assert "lib.dll" not in list_pe_imports(out)
    # plugin.dll itself is untouched -- embed() only ever embeds what the
    # top-level host's own import graph names, and the host here never
    # statically imports plugin.dll at all.
    assert "lib.dll" in list_pe_imports(plugin)

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 0, (
        f"expected the LdrRegisterDllNotification hook to redirect plugin.dll's own "
        f"static import of lib.dll to the embedded copy, got exit code "
        f"{result.returncode} (5 means it resolved against a real, separate "
        f"duplicate module instead), stdout={result.stdout!r} stderr={result.stderr!r}"
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

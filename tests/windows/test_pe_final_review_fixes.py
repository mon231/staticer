"""Tests for the PE-track fixes from the final whole-branch review:
B1 (dependency-to-dependency imports must not stay dynamic), B3 (a
TLS-carrying dependency must fail loudly, not silently corrupt), B4 (a
dependency's own PE header region must be copied into its embedded blob),
B6-PE (a DLL-as-output must not re-run dependency inits on thread
attach/detach), and the --exclude case-sensitivity minor fix.
"""

import ctypes
import platform
import subprocess
import threading

import pefile
import pytest

from conftest import FIXTURES, build_exe, build_shared_lib

from staticer.pe_embedder import PortableExecutableEmbedder, list_pe_imports

pytestmark = pytest.mark.skipif(platform.system() != "Windows", reason="PE embedding is Windows-only")


def test_transitive_embedded_dependency_import_is_patched_not_dynamic(tmp_path, c_compiler):
    """B1: lib_x.dll imports lib_y.dll; both get embedded (no exclusion).
    The combined output must not still dynamically import 'lib_y.dll' --
    lib_x's own IAT slot for it must be patched directly to the embedded
    address instead, and the program must still compute the right result.
    """
    kind, _ = c_compiler

    dll_y = build_shared_lib(tmp_path, FIXTURES / "lib_y.c", "lib_y.dll", pic=True, bits=64)
    link_arg = str(dll_y.with_suffix(".lib")) if kind == "msvc" else str(dll_y)
    dll_x = build_shared_lib(
        tmp_path, FIXTURES / "lib_x.c", "lib_x.dll", pic=True, bits=64, extra_flags=[link_arg],
    )

    exe = build_exe(
        tmp_path, FIXTURES / "main_transitive.c", "main_transitive.exe", [dll_x, dll_y], pic=True, bits=64,
    )
    out = tmp_path / "static_transitive.exe"

    # No exclusion at all -- both lib_x.dll and lib_y.dll are embeddable,
    # and lib_x.dll's own import of lib_y.dll must be resolved internally.
    PortableExecutableEmbedder(exe, out, set(), tmp_path).embed()

    remaining = list_pe_imports(out)
    assert "lib_x.dll" not in remaining
    assert "lib_y.dll" not in remaining

    # Move lib_y.dll out of the way so a surviving (buggy) dynamic import
    # of it can't accidentally still resolve and mask the bug.
    (tmp_path / "lib_y.dll").unlink()

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 12  # lib_x_value() + lib_y_value() == 11 + 1


def test_tls_dependency_fails_loudly(tmp_path, c_compiler):
    """B3: a dependency carrying its own TLS directory must raise
    ValueError (naming it) rather than being silently (and incorrectly)
    embedded."""
    dll = build_shared_lib(tmp_path, FIXTURES / "lib_tls_dep.c", "lib_tls_dep.dll", pic=True, bits=64)
    exe = build_exe(
        tmp_path, FIXTURES / "main_tls_dep.c", "main_tls_dep.exe", [dll], pic=True, bits=64,
    )
    out = tmp_path / "static_tls_dep.exe"

    with pytest.raises(ValueError, match="lib_tls_dep.dll"):
        PortableExecutableEmbedder(exe, out, set(), tmp_path).embed()


def test_dependency_header_region_is_copied_into_blob(tmp_path, c_compiler):
    """B4: the embedded blob for a dependency must carry its own PE header
    bytes (DOS 'MZ' signature at offset 0 of its placement), not zeros --
    otherwise anything reading its own module header via its own HINSTANCE
    once embedded (e.g. mingw's pseudo-relocation check) finds garbage."""
    dll = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.dll", pic=True, bits=64)
    exe = build_exe(tmp_path, FIXTURES / "main.c", "main.exe", [dll], pic=True, bits=64)
    out = tmp_path / "static.exe"

    PortableExecutableEmbedder(exe, out, set(), tmp_path).embed()

    pe = pefile.PE(str(out))
    try:
        # The embedded dependency landed in a new ".sdep0" section -- find
        # it and check its first bytes are a real DOS header ('MZ'), not
        # zeros.
        dep_section = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".sdep0")
        header_bytes = pe.get_data(dep_section.VirtualAddress, 2)
        assert header_bytes == b"MZ"
    finally:
        pe.close()

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 42


def test_dll_as_output_runs_dep_init_once(tmp_path, c_compiler):
    """B6-PE: when the embed() *input* is itself a DLL (not an EXE), the
    generated stub becomes its real entrypoint, called by the OS loader on
    every thread attach/detach too -- the embedded dependency's own
    process-attach-style init must run exactly once (at the output DLL's
    own process attach), not again on every later thread notification."""
    dep = build_shared_lib(tmp_path, FIXTURES / "lib_attach_count.c", "lib_attach_count.dll", pic=True, bits=64)
    kind, _ = c_compiler
    link_arg = str(dep.with_suffix(".lib")) if kind == "msvc" else str(dep)
    host_dll = build_shared_lib(
        tmp_path, FIXTURES / "host_attach_count.c", "host_attach_count.dll", pic=True, bits=64,
        extra_flags=[link_arg],
    )
    out = tmp_path / "static_host_attach_count.dll"

    PortableExecutableEmbedder(host_dll, out, set(), tmp_path).embed()
    assert "lib_attach_count.dll" not in list_pe_imports(out)

    lib = ctypes.WinDLL(str(out))
    try:
        lib.host_get_attach_count.restype = ctypes.c_long
        # LoadLibrary itself already delivered one real DLL_PROCESS_ATTACH.
        assert lib.host_get_attach_count() == 1

        # Starting new OS threads while this DLL is loaded delivers
        # DLL_THREAD_ATTACH (and, on join, DLL_THREAD_DETACH) to its entry
        # point too -- the buggy stub (no fdwReason guard) would re-run the
        # dependency's process-attach-style init on each of these.
        threads = [threading.Thread(target=lambda: None) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert lib.host_get_attach_count() == 1
    finally:
        ctypes.windll.kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
        ctypes.windll.kernel32.FreeLibrary(lib._handle)


def test_exclude_is_case_insensitive(tmp_path, c_compiler):
    """Minor fix: --exclude must match DLL names case-insensitively
    (Windows filenames are case-insensitive) -- excluding 'LIB.DLL' must
    still exclude the actual 'lib.dll' import."""
    dll = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.dll", pic=True, bits=64)
    exe = build_exe(tmp_path, FIXTURES / "main.c", "main.exe", [dll], pic=True, bits=64)
    out = tmp_path / "static.exe"

    PortableExecutableEmbedder(exe, out, {"LIB.DLL"}, tmp_path).embed()

    assert "lib.dll" in list_pe_imports(out)

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 42

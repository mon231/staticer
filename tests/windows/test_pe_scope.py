"""Scope-selection tests for PortableExecutableEmbedder.embed() -- exclude
by name, lib_dir scoping, and transitive-exclusion-vs-direct-import overlap.
These exercise *existing* embed() behaviour (Tasks 3/5/7); no new embedder
logic is added here.
"""

import platform
import subprocess

import pytest

from conftest import FIXTURES, build_exe, build_shared_lib

from staticer.pe_embedder import PortableExecutableEmbedder, list_pe_imports

pytestmark = pytest.mark.skipif(platform.system() != "Windows", reason="PE embedding is Windows-only")

# NOTE on `lib_dir`/bits: same reasoning as tests/windows/test_pe_embed.py's
# own NOTE -- scope embedding to a known directory so only the fixture
# DLL(s) under test are candidates, and (matching test_pe_unwind.py's
# precedent) exercise a single bitness (64) rather than parametrizing,
# since these tests are about *scope selection*, not bitness-dependent
# mechanism.


def test_exclude_keeps_dependency_dynamic(tmp_path, c_compiler):
    """--exclude lib.dll by name: the host's import of it must survive
    untouched (still in the import table, still resolvable at runtime),
    not be embedded."""
    dll = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.dll", pic=True, bits=64)
    exe = build_exe(tmp_path, FIXTURES / "main.c", "main.exe", [dll], pic=True, bits=64)
    out = tmp_path / "static.exe"

    PortableExecutableEmbedder(exe, out, {"lib.dll"}, tmp_path).embed()

    assert "lib.dll" in list_pe_imports(out)

    # lib.dll is left alongside `out` in tmp_path, so the still-dynamic
    # import resolves fine at runtime.
    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 42


def test_lib_dir_only_embeds_matching_dependency(tmp_path, c_compiler):
    """Two direct dependencies, same import mechanism: one placed inside
    lib_dir (embeddable), the other left at a path outside it (out of
    scope, so it must stay an ordinary dynamic import)."""
    lib_dir = tmp_path / "libdir"
    lib_dir.mkdir()

    dll_in = build_shared_lib(lib_dir, FIXTURES / "lib.c", "lib.dll", pic=True, bits=64)
    dll_out = build_shared_lib(tmp_path, FIXTURES / "lib_b.c", "lib_b.dll", pic=True, bits=64)

    exe = build_exe(
        tmp_path, FIXTURES / "main_two_libs.c", "main_two_libs.exe", [dll_in, dll_out], pic=True, bits=64,
    )
    out = tmp_path / "static_two_libs.exe"

    PortableExecutableEmbedder(exe, out, set(), lib_dir).embed()

    remaining = list_pe_imports(out)
    assert "lib.dll" not in remaining  # inside lib_dir -- embedded
    assert "lib_b.dll" in remaining  # outside lib_dir -- stays dynamic

    # `out` and lib_b.dll both live in tmp_path, so the still-dynamic
    # import resolves fine at runtime.
    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 43  # lib_value() + lib_b_value() == 42 + 1


def test_transitive_exclusion_overlap(tmp_path, c_compiler):
    """Host imports lib_x.dll (excluded by name) and lib_y.dll directly;
    lib_x.dll itself also imports lib_y.dll. Excluding X must cascade to Y
    (per build_dependency_graph's transitive-exclusion walk) even though Y
    is independently a direct host import too -- Y must NOT be embedded."""
    kind, _ = c_compiler

    dll_y = build_shared_lib(tmp_path, FIXTURES / "lib_y.c", "lib_y.dll", pic=True, bits=64)
    # mingw's ld can link directly against a DLL; MSVC's link.exe needs the
    # sibling .lib import library instead (see conftest's
    # _msvc_import_lib_for docstring for why a raw .dll can't be passed).
    link_arg = str(dll_y.with_suffix(".lib")) if kind == "msvc" else str(dll_y)
    dll_x = build_shared_lib(
        tmp_path, FIXTURES / "lib_x.c", "lib_x.dll", pic=True, bits=64, extra_flags=[link_arg],
    )

    exe = build_exe(
        tmp_path, FIXTURES / "main_transitive.c", "main_transitive.exe", [dll_x, dll_y], pic=True, bits=64,
    )
    out = tmp_path / "static_transitive.exe"

    PortableExecutableEmbedder(exe, out, {"lib_x.dll"}, tmp_path).embed()

    remaining = list_pe_imports(out)
    assert "lib_x.dll" in remaining  # directly excluded
    assert "lib_y.dll" in remaining  # must stay dynamic despite also being a direct host import

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 12  # lib_x_value() + lib_y_value() == 11 + 1

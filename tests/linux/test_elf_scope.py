"""Scope-selection tests for ElfEmbedder.embed() -- exclude by name,
lib_dir scoping, and transitive-exclusion-vs-direct-import overlap. These
exercise *existing* embed() behaviour (Tasks 1-8); no new embedder logic
is added here.

ELF counterpart of tests/windows/test_pe_scope.py's three scenarios.
"""

import os
import platform
import subprocess

import pytest

from conftest import FIXTURES, build_exe, build_shared_lib

from staticer.elf_embedder import ElfEmbedder, list_elf_imports

pytestmark = pytest.mark.skipif(platform.system() != "Linux", reason="ELF embedding is Linux-only")

# NOTE on lib_dir/bits: same reasoning as test_pe_scope.py's own NOTE --
# scope embedding to a known directory so only the fixture .so(s) under
# test are candidates, and exercise a single bitness (64) rather than
# parametrizing, since these tests are about *scope selection*, not
# bitness-dependent mechanism.
#
# NOTE on runtime resolution: unlike the Windows loader (which searches
# the launched executable's own directory by default), the ELF dynamic
# linker does *not* search the host's directory unless told to (no
# DT_RPATH/DT_RUNPATH is set by these fixture builds). Whenever a test
# below leaves a dependency dynamic on purpose, it runs the output with
# LD_LIBRARY_PATH pointed at the directory holding that still-needed
# .so, rather than relying on any default search path.
#
# NOTE on DT_SONAME: every .so built below passes
# `-Wl,-soname,<basename>`. Without an explicit soname, GNU ld records
# the *literal path string given on its command line* (not the basename)
# as the resulting DT_NEEDED entry -- e.g. linking against an absolute
# path produces a DT_NEEDED of that whole absolute path, not "lib.so".
# Real-world shared objects (including the host's own libc.so.6, which
# shows up fine as a bare name above) always carry a soname; giving the
# fixtures one too keeps DT_NEEDED entries as plain basenames, matching
# both this suite's exclude-by-name/lib_dir API (which matches against
# names like "lib.so") and the PE side's import-table entries (which are
# always bare DLL names).


def test_exclude_keeps_dependency_dynamic(tmp_path, c_compiler):
    """--exclude lib.so by name: the host's import of it must survive
    untouched (still a DT_NEEDED entry, still resolvable at runtime), not
    be embedded."""
    so = build_shared_lib(
        tmp_path, FIXTURES / "lib.c", "lib.so", pic=True, bits=64,
        extra_flags=["-Wl,-soname,lib.so"],
    )
    exe = build_exe(tmp_path, FIXTURES / "main.c", "main", [so], pic=True, bits=64)
    out = tmp_path / "static"

    ElfEmbedder(exe, out, {"lib.so"}, tmp_path).embed()
    out.chmod(0o755)

    assert "lib.so" in list_elf_imports(out)

    # lib.so is left alongside `out` in tmp_path, so the still-dynamic
    # import resolves fine at runtime via LD_LIBRARY_PATH.
    env = dict(os.environ, LD_LIBRARY_PATH=str(tmp_path))
    result = subprocess.run([str(out)], capture_output=True, env=env)
    assert result.returncode == 42


def test_lib_dir_only_embeds_matching_dependency(tmp_path, c_compiler):
    """Two direct dependencies, same import mechanism: one placed inside
    lib_dir (embeddable), the other left at a path outside it (out of
    scope, so it must stay an ordinary dynamic import)."""
    lib_dir = tmp_path / "libdir"
    lib_dir.mkdir()

    so_in = build_shared_lib(
        lib_dir, FIXTURES / "lib.c", "lib.so", pic=True, bits=64,
        extra_flags=["-Wl,-soname,lib.so"],
    )
    so_out = build_shared_lib(
        tmp_path, FIXTURES / "lib_b.c", "lib_b.so", pic=True, bits=64,
        extra_flags=["-Wl,-soname,lib_b.so"],
    )

    exe = build_exe(
        tmp_path, FIXTURES / "main_two_libs.c", "main_two_libs", [so_in, so_out], pic=True, bits=64,
    )
    out = tmp_path / "static_two_libs"

    ElfEmbedder(exe, out, set(), lib_dir).embed()
    out.chmod(0o755)

    remaining = list_elf_imports(out)
    assert "lib.so" not in remaining  # inside lib_dir -- embedded
    assert "lib_b.so" in remaining  # outside lib_dir -- stays dynamic

    # `out` and lib_b.so both live in tmp_path, so the still-dynamic
    # import resolves fine at runtime via LD_LIBRARY_PATH.
    env = dict(os.environ, LD_LIBRARY_PATH=str(tmp_path))
    result = subprocess.run([str(out)], capture_output=True, env=env)
    assert result.returncode == 43  # lib_value() + lib_b_value() == 42 + 1


def test_transitive_exclusion_overlap(tmp_path, c_compiler):
    """Host imports lib_x.so (excluded by name) and lib_y.so directly;
    lib_x.so itself also imports lib_y.so (DT_NEEDS it). Excluding X must
    cascade to Y (per build_dependency_graph's transitive-exclusion walk)
    even though Y is independently a direct host import too -- Y must NOT
    be embedded."""
    so_y = build_shared_lib(
        tmp_path, FIXTURES / "lib_y.c", "lib_y.so", pic=True, bits=64,
        extra_flags=["-Wl,-soname,lib_y.so"],
    )
    so_x = build_shared_lib(
        tmp_path, FIXTURES / "lib_x.c", "lib_x.so", pic=True, bits=64,
        extra_flags=[str(so_y), "-Wl,-soname,lib_x.so"],
    )

    exe = build_exe(
        tmp_path, FIXTURES / "main_transitive.c", "main_transitive", [so_x, so_y], pic=True, bits=64,
    )
    out = tmp_path / "static_transitive"

    ElfEmbedder(exe, out, {"lib_x.so"}, tmp_path).embed()
    out.chmod(0o755)

    remaining = list_elf_imports(out)
    assert "lib_x.so" in remaining  # directly excluded
    assert "lib_y.so" in remaining  # must stay dynamic despite also being a direct host import

    # lib_x.so and lib_y.so both live in tmp_path, so both still-dynamic
    # imports (host's direct one and lib_x.so's own DT_NEEDED on lib_y.so)
    # resolve fine at runtime via LD_LIBRARY_PATH.
    env = dict(os.environ, LD_LIBRARY_PATH=str(tmp_path))
    result = subprocess.run([str(out)], capture_output=True, env=env)
    assert result.returncode == 12  # lib_x_value() + lib_y_value() == 11 + 1

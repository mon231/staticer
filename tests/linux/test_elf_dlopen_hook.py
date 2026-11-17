"""Regression tests for the ELF dlopen/dlsym runtime hook (see
``staticer/stubs/linux/elf_stub.py``'s module docstring for the full
design) -- the ELF counterpart of ``tests/windows/test_pe_hook_runtime.py``.
"""

import platform
import subprocess

import pytest

from conftest import FIXTURES, build_exe, build_shared_lib

from staticer.elf_embedder import ElfEmbedder, list_elf_imports

pytestmark = pytest.mark.skipif(platform.system() != "Linux", reason="ELF embedding is Linux-only")

# x64 only (matches the hook's own scope -- see elf_stub.py's docstring).
_BITS = 64


def test_dlopen_dlsym_hook_resolves_against_embedded_dependency(tmp_path, c_compiler):
    """After a real embed() run, an explicit runtime dlopen()+dlsym() call
    for the embedded dependency's own name must resolve against the
    already-embedded copy and actually work -- even once the real
    on-disk .so is deleted, proving no real dlopen happened."""
    # -soname=lib.so: without an explicit SONAME, GNU ld records DT_NEEDED
    # using the exact (tmp_path-prefixed, so non-reproducible across test
    # runs) path given on its own link command line -- confirmed via a
    # real build+readelf -d check -- instead of a short, stable name a
    # dlopen() call could plausibly hardcode. Every real system .so (e.g.
    # the fallthrough test's libm.so.6, below) already has a proper
    # SONAME for exactly this reason; this just makes the synthetic
    # fixture realistic the same way.
    so = build_shared_lib(
        tmp_path, FIXTURES / "lib.c", "lib.so", pic=True, bits=_BITS,
        extra_flags=["-Wl,-soname=lib.so"],
    )
    exe = build_exe(
        tmp_path, FIXTURES / "main_dlopen.c", "main_dlopen", [so], pic=True, bits=_BITS,
        extra_flags=["-ldl"],
    )
    out = tmp_path / "static"

    ElfEmbedder(exe, out, exclude=set(), lib_dir=tmp_path).embed()
    out.chmod(0o755)

    assert "lib.so" not in list_elf_imports(out)

    # Strongest proof (mirroring the Windows-side hook test): delete the
    # real dependency from disk. A real dlopen("lib.so", ...) would now
    # fail outright (ENOENT, and it was never on dlopen's own search path
    # to begin with -- it only ever lived in tmp_path) -- if the embedded
    # output still succeeds, the hook (not a real load) resolved it.
    so.unlink()

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 0, f"stderr: {result.stderr!r}"


def test_dlopen_dlsym_hook_falls_through_for_non_embedded_name(tmp_path, c_compiler):
    """With the hook installed (an embedded dependency is present), an
    ordinary dlopen/dlsym call against a real, unrelated, genuinely-
    still-on-disk system library (libm.so.6) must still behave exactly
    like the real, unhooked APIs."""
    so = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.so", pic=True, bits=_BITS)
    exe = build_exe(
        tmp_path, FIXTURES / "main_dlopen_fallthrough.c", "main_dlopen_fallthrough", [so],
        pic=True, bits=_BITS, extra_flags=["-ldl", "-lm"],
    )
    out = tmp_path / "static"

    ElfEmbedder(exe, out, exclude=set(), lib_dir=tmp_path).embed()
    out.chmod(0o755)

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 0, f"stderr: {result.stderr!r}"

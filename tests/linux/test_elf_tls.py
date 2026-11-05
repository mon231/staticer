"""ELF TLS segment + relocation merge (Task 3, phase 1): adopting a
dependency's own PT_TLS segment as a TLS-less host's own, mirroring
tests/windows/test_pe_tls.py's PE counterpart.

Per .superpowers/findings/2026-11-04-frida-gadget-tls-shape.md (Task 1),
frida-gadget's real .so carries ONLY R_X86_64_DTPMOD64 (type 16)
relocations in its own .rela.dyn -- no R_X86_64_TLSGD/TLSLD (types
19/20, the call-site General/Local-Dynamic relaxation model) anywhere.
So this task's scope is a pure data-patch merge: a combined PT_TLS
segment, DTPMOD64 slots resolved to the single merged module's id, and
DTPOFF64/TPOFF64 slots resolved to the static offset within that
combined block -- no instruction-level code relaxation needed.

Step 1 (synthetic fixture, `lib_tls_simple.c` -- shared with Task 2's PE
fixture, same source, built here via the GNU/ELF toolchain instead) proves
the mechanism actually works end to end: a __thread counter, embedded
into a TLS-less host, increments and reads back correctly across real
calls after a real embed()+run, not just "doesn't crash". Step 2 (the
real, genuine frida-gadget .so, fetched the same way every other
frida-gadget test in this project does) proves the real binary's shape
is handled too -- that second test only asserts embed() no longer
raises.
"""

import platform
import subprocess

import pytest

from conftest import FIXTURES, build_exe, build_shared_lib

from staticer.elf_embedder import ElfEmbedder

pytestmark = [
    pytest.mark.skipif(platform.system() != "Linux", reason="ELF embedding is Linux-only"),
    pytest.mark.slow,
]


def test_tls_dependency_merges_into_tls_less_host(tmp_path, c_compiler):
    """The real, positive case this task implements: a dependency .so
    carrying its own PT_TLS segment (one __thread counter) is adopted as
    a TLS-less host's own PT_TLS, rather than raising
    "unsupported relocation type 16". The embedded counter must actually
    increment and read back correctly across three real calls (proves the
    GOT-slot-data-patch mechanism works), not just avoid crashing."""
    so = build_shared_lib(tmp_path, FIXTURES / "lib_tls_simple.c", "lib_tls_simple.so", pic=True, bits=64)
    exe = build_exe(tmp_path, FIXTURES / "main_tls_simple.c", "main_tls_simple", [so], pic=True, bits=64)
    out = tmp_path / "static_tls_simple"

    ElfEmbedder(exe, out, exclude=set(), lib_dir=tmp_path).embed()
    out.chmod(0o755)

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 3, (
        f"embedded TLS counter didn't read back 3; stderr={result.stderr!r}"
    )


def test_host_with_own_tls_directory_fails_loudly(tmp_path, c_compiler):
    """The genuinely still-unsupported case (phase 2): the HOST itself
    already carries its own PT_TLS segment (`main_host_own_tls.c`'s own
    `host_counter`), and also imports a dependency that carries its own,
    separate PT_TLS (`lib_tls_dep.c`'s `dep_tls_counter`) -- merging two
    real TLS directories into one combined block isn't implemented yet.
    Mirrors tests/windows/test_pe_final_review_fixes.py's
    test_host_with_own_tls_directory_fails_loudly."""
    dll = build_shared_lib(tmp_path, FIXTURES / "lib_tls_dep.c", "lib_tls_dep.so", pic=True, bits=64)
    exe = build_exe(
        tmp_path, FIXTURES / "main_host_own_tls.c", "main_host_own_tls", [dll], pic=True, bits=64,
    )
    out = tmp_path / "static_host_own_tls"

    with pytest.raises(ValueError, match="(?i)lib_tls_dep.so.*tls|tls.*lib_tls_dep.so"):
        ElfEmbedder(exe, out, exclude=set(), lib_dir=tmp_path).embed()
